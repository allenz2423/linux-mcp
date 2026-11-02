"""Bounded inventory and confirmed selection of Debian pam-auth-update profiles."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    PAMProfileActionResponse,
    PAMProfileEntry,
    PAMProfileListResponse,
)
from wayland_mcp.session import get_sanitized_env

PROFILE_DIRECTORY = Path("/usr/share/pam-configs")
PAM_DIRECTORY = Path("/etc/pam.d")
PAM_STATE_DIRECTORY = Path("/var/lib/pam")
COMMON_FILES = (
    "common-auth",
    "common-account",
    "common-password",
    "common-session",
    "common-session-noninteractive",
)
MAX_PROFILE_COUNT = 256
MAX_PROFILE_BYTES = 128 * 1024
MAX_TOTAL_PROFILE_BYTES = 4 * 1024 * 1024
MAX_COMMON_FILE_BYTES = 1024 * 1024
MAX_STATE_FILE_BYTES = 128 * 1024
MAX_EXECUTABLE_BYTES = 2 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 128 * 1024
COMMAND_TIMEOUT_SECONDS = 30
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
PROFILE_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]{0,63}):[ \t]*(.*?)[ \t]*$")
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_LOCK = threading.RLock()
_CONFIRMATION_SECRET = secrets.token_bytes(32)

PAMProfileAction = Literal["enable", "disable"]


@dataclass(frozen=True, slots=True)
class _Metadata:
    device: int
    inode: int
    mode: int
    owner_uid: int
    owner_gid: int
    link_count: int
    size: int
    modified_ns: int
    changed_ns: int


def _metadata(info: os.stat_result) -> _Metadata:
    return _Metadata(
        device=info.st_dev,
        inode=info.st_ino,
        mode=info.st_mode,
        owner_uid=info.st_uid,
        owner_gid=info.st_gid,
        link_count=info.st_nlink,
        size=info.st_size,
        modified_ns=info.st_mtime_ns,
        changed_ns=info.st_ctime_ns,
    )


def _directory_binding(info: _Metadata) -> list[int]:
    return [info.device, info.inode, info.mode, info.owner_uid, info.owner_gid]


@dataclass(frozen=True, slots=True)
class _Profile:
    name: str
    title: str
    default: bool
    priority: int
    stack_types: tuple[str, ...]
    metadata: _Metadata
    content: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class _BoundFile:
    name: str
    metadata: _Metadata
    content: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class _Snapshot:
    profile_directory: _Metadata
    pam_directory: _Metadata
    state_directory: _Metadata
    profiles: tuple[_Profile, ...]
    selected_profiles: tuple[str, ...]
    selected_raw: str
    common_files: tuple[_BoundFile, ...]
    seen_file: _BoundFile | None
    pam_update_path: str
    pam_update_metadata: _Metadata
    pam_update_content: bytes = field(repr=False)
    debconf_path: str
    debconf_metadata: _Metadata


@dataclass(frozen=True, slots=True)
class _Target:
    action: PAMProfileAction
    profile: _Profile
    snapshot: _Snapshot
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env.update({
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "DEBIAN_FRONTEND": "noninteractive",
        "DEBIAN_PRIORITY": "critical",
    })
    return env


def _trusted_directory(info: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and info.st_gid == 0
        and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _open_directory(path: Path) -> tuple[int | None, _Metadata | None]:
    descriptors: list[int] = []
    try:
        root_fd = os.open("/", _DIR_FLAGS)
        descriptors.append(root_fd)
        root_info = os.fstat(root_fd)
        if not _trusted_directory(root_info):
            return None, None
        current_fd = root_fd
        for component in path.parts[1:]:
            next_fd = os.open(component, _DIR_FLAGS, dir_fd=current_fd)
            descriptors.append(next_fd)
            info = os.fstat(next_fd)
            if not _trusted_directory(info):
                return None, None
            current_fd = next_fd
        descriptors.remove(current_fd)
        return current_fd, _metadata(os.fstat(current_fd))
    except OSError:
        return None, None
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_file_at(directory_fd: int, name: str, maximum: int) -> tuple[_Metadata | None, bytes | None]:
    try:
        descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    except OSError:
        return None, None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or before.st_nlink != 1
            or before.st_size > maximum
        ):
            return None, None
        content = bytearray()
        while len(content) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        try:
            path_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return None, None
        if (
            len(content) > maximum
            or _metadata(before) != _metadata(after)
            or (path_info.st_dev, path_info.st_ino) != (after.st_dev, after.st_ino)
        ):
            return None, None
        return _metadata(after), bytes(content)
    except OSError:
        return None, None
    finally:
        os.close(descriptor)


def _parse_profile(name: str, metadata: _Metadata, content: bytes) -> _Profile | None:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeError:
        return None
    if "\x00" in text or "\r" in text.replace("\r\n", ""):
        return None
    fields: dict[str, str] = {}
    stack_types: set[str] = set()
    for line in text.splitlines():
        if not line or line.lstrip().startswith(("#", ";")) or line[0].isspace():
            continue
        match = PROFILE_HEADER_RE.fullmatch(line)
        if match is None:
            return None
        key, value = match.group(1).casefold(), match.group(2)
        if key in {"name", "default", "priority"}:
            if key in fields:
                return None
            fields[key] = value
        if key in {"auth", "account", "password", "session", "session-noninteractive", "session-interactive"}:
            stack_types.add(key)
    title = fields.get("name", "").strip()
    priority_raw = fields.get("priority", "").strip()
    default_raw = fields.get("default", "no").strip().casefold()
    if (
        not title
        or len(title) > 256
        or not priority_raw.isascii()
        or not priority_raw.isdecimal()
        or len(priority_raw) > 5
        or not 0 <= int(priority_raw) <= 10000
        or default_raw not in {"yes", "no"}
    ):
        return None
    return _Profile(
        name=name,
        title=title,
        default=default_raw == "yes",
        priority=int(priority_raw),
        stack_types=tuple(sorted(stack_types)),
        metadata=metadata,
        content=content,
    )


def _program_file(path: str) -> tuple[_Metadata | None, bytes | None]:
    candidate = Path(path)
    parent_fd, parent_metadata = _open_directory(candidate.parent)
    if parent_fd is None or parent_metadata is None:
        return None, None
    try:
        metadata, content = _read_file_at(parent_fd, candidate.name, MAX_EXECUTABLE_BYTES)
        if metadata is None or content is None:
            return None, None
        if not metadata.mode & 0o111:
            return None, None
        return metadata, content
    finally:
        os.close(parent_fd)


def _program_paths() -> tuple[str, str] | None:
    pam_path: str | None = None
    for candidate in ("/usr/sbin/pam-auth-update", "/usr/bin/pam-auth-update"):
        metadata, content = _program_file(candidate)
        if metadata is None or content is None:
            continue
        try:
            source = content.decode("utf-8", errors="strict")
        except UnicodeError:
            continue
        if re.search(r"\beq\s+['\"]--enable['\"]", source) and re.search(r"\beq\s+['\"]--disable['\"]", source):
            pam_path = candidate
            break
    debconf_path = next(
        (
            candidate for candidate in ("/usr/bin/debconf-communicate", "/usr/sbin/debconf-communicate")
            if _program_file(candidate)[0] is not None
        ),
        None,
    )
    if pam_path is None or debconf_path is None:
        return None
    return pam_path, debconf_path


def _read_debconf_selection(debconf_path: str) -> tuple[str, tuple[str, ...]] | None:
    try:
        result = subprocess.run(
            [debconf_path],
            input=b"GET libpam-runtime/profiles\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if (
        result.returncode != 0
        or len(result.stdout) > MAX_STATE_FILE_BYTES
        or len(result.stderr) > MAX_COMMAND_OUTPUT_BYTES
    ):
        return None
    try:
        output = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeError:
        return None
    match = re.fullmatch(r"0(?:[ \t]+(.*))?", output)
    if match is None:
        return None
    raw = (match.group(1) or "").strip()
    selected_items = [item.strip() for item in raw.split(",") if item.strip()]
    if len(set(selected_items)) != len(selected_items):
        return None
    selected = tuple(sorted(selected_items))
    if any(not PROFILE_NAME_RE.fullmatch(item) for item in selected):
        return None
    return raw, selected


def _load_snapshot() -> tuple[_Snapshot | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "PAM profile control is available only on Linux."
    profiles_fd, profile_directory_metadata = _open_directory(PROFILE_DIRECTORY)
    if profiles_fd is None or profile_directory_metadata is None:
        return None, "A safe root-owned /usr/share/pam-configs directory is required."
    pam_fd, pam_directory_metadata = _open_directory(PAM_DIRECTORY)
    if pam_fd is None or pam_directory_metadata is None:
        os.close(profiles_fd)
        return None, "A safe root-owned /etc/pam.d directory is required."
    state_fd, state_directory_metadata = _open_directory(PAM_STATE_DIRECTORY)
    if state_fd is None or state_directory_metadata is None:
        os.close(profiles_fd)
        os.close(pam_fd)
        return None, "A safe root-owned /var/lib/pam directory is required."
    try:
        names = sorted(os.listdir(profiles_fd))
        if not names or len(names) > MAX_PROFILE_COUNT or any(not PROFILE_NAME_RE.fullmatch(name) for name in names):
            return None, "The packaged PAM profile inventory is empty or outside the bounded filename/count limits."
        profiles: list[_Profile] = []
        total_bytes = 0
        for name in names:
            metadata, content = _read_file_at(profiles_fd, name, MAX_PROFILE_BYTES)
            if metadata is None or content is None:
                return None, "Every packaged PAM profile must be a safe root-owned regular file within the size limit."
            total_bytes += len(content)
            if total_bytes > MAX_TOTAL_PROFILE_BYTES:
                return None, "The packaged PAM profile inventory exceeds the bounded total size."
            profile = _parse_profile(name, metadata, content)
            if profile is None:
                return None, f"The packaged PAM profile {name!r} is outside the supported bounded descriptor format."
            profiles.append(profile)
        common_files: list[_BoundFile] = []
        for name in COMMON_FILES:
            metadata, content = _read_file_at(pam_fd, name, MAX_COMMON_FILE_BYTES)
            if metadata is None or content is None:
                return None, f"A safe root-owned /etc/pam.d/{name} file is required for state binding."
            common_files.append(_BoundFile(name=name, metadata=metadata, content=content))
        seen_metadata, seen_content = _read_file_at(state_fd, "seen", MAX_STATE_FILE_BYTES)
        if (seen_metadata is None) != (seen_content is None):
            return None, "The PAM profile seen-state file exists but cannot be safely read."
        seen_file = (
            _BoundFile(name="seen", metadata=seen_metadata, content=seen_content)
            if seen_metadata is not None and seen_content is not None else None
        )
        paths = _program_paths()
        if paths is None:
            return None, "Root-owned pam-auth-update with --enable/--disable support and debconf-communicate are required."
        pam_update_path, debconf_path = paths
        pam_update_metadata, pam_update_content = _program_file(pam_update_path)
        debconf_metadata, _ = _program_file(debconf_path)
        if pam_update_metadata is None or pam_update_content is None or debconf_metadata is None:
            return None, "The PAM utility identity changed during inventory."
        debconf = _read_debconf_selection(debconf_path)
        if debconf is None:
            return None, "The configured PAM profile selection could not be read from debconf."
        raw_selection, selected_profiles = debconf
        try:
            profiles_after = sorted(os.listdir(profiles_fd))
        except OSError:
            return None, "The packaged PAM profile directory changed during inventory."
        if names != profiles_after:
            return None, "The packaged PAM profile directory changed during inventory."
        return _Snapshot(
            profile_directory=profile_directory_metadata,
            pam_directory=pam_directory_metadata,
            state_directory=state_directory_metadata,
            profiles=tuple(profiles),
            selected_profiles=selected_profiles,
            selected_raw=raw_selection,
            common_files=tuple(common_files),
            seen_file=seen_file,
            pam_update_path=pam_update_path,
            pam_update_metadata=pam_update_metadata,
            pam_update_content=pam_update_content,
            debconf_path=debconf_path,
            debconf_metadata=debconf_metadata,
        ), None
    except OSError:
        return None, "The PAM configuration changed during inventory."
    finally:
        os.close(profiles_fd)
        os.close(pam_fd)
        os.close(state_fd)


def _file_binding(item: _BoundFile) -> dict[str, object]:
    return {
        "name": item.name,
        "metadata": [item.metadata.device, item.metadata.inode, item.metadata.mode, item.metadata.owner_uid, item.metadata.owner_gid, item.metadata.link_count, item.metadata.size, item.metadata.modified_ns, item.metadata.changed_ns],
        "sha256": hashlib.sha256(item.content).hexdigest(),
    }


def _profile_binding(profile: _Profile) -> dict[str, object]:
    return {
        "name": profile.name,
        "metadata": [profile.metadata.device, profile.metadata.inode, profile.metadata.mode, profile.metadata.owner_uid, profile.metadata.owner_gid, profile.metadata.link_count, profile.metadata.size, profile.metadata.modified_ns, profile.metadata.changed_ns],
        "sha256": hashlib.sha256(profile.content).hexdigest(),
    }


def _prepare_target(action: str, profile_name: str) -> tuple[_Target | None, str | None]:
    if action not in {"enable", "disable"} or not isinstance(profile_name, str) or not PROFILE_NAME_RE.fullmatch(profile_name):
        return None, "Select enable or disable and one packaged PAM profile name."
    if os.geteuid() != 0:
        return None, "PAM profile changes require the MCP server to already run as root; no elevation is requested."
    snapshot, error = _load_snapshot()
    if error or snapshot is None:
        return None, error or "The packaged PAM profile state could not be safely inspected."
    profiles = {item.name: item for item in snapshot.profiles}
    profile = profiles.get(profile_name)
    if profile is None:
        return None, "The requested profile must exactly match one currently packaged PAM profile."
    selected = set(snapshot.selected_profiles)
    if action == "enable" and profile_name in selected:
        return None, "The selected PAM profile is already enabled in the debconf profile selection."
    if action == "disable" and profile_name not in selected:
        return None, "The selected PAM profile is not enabled in the debconf profile selection."
    material = {
        "action": action,
        "profile": profile_name,
        "selected_profiles": snapshot.selected_profiles,
        "selected_raw": snapshot.selected_raw,
        "profile_directory": _directory_binding(snapshot.profile_directory),
        "pam_directory": _directory_binding(snapshot.pam_directory),
        "state_directory": _directory_binding(snapshot.state_directory),
        "profiles": [_profile_binding(item) for item in snapshot.profiles],
        "common_files": [_file_binding(item) for item in snapshot.common_files],
        "seen_file": _file_binding(snapshot.seen_file) if snapshot.seen_file else None,
        "pam_auth_update": [snapshot.pam_update_path, snapshot.pam_update_metadata.device, snapshot.pam_update_metadata.inode, snapshot.pam_update_metadata.mode, snapshot.pam_update_metadata.owner_uid, snapshot.pam_update_metadata.owner_gid, snapshot.pam_update_metadata.size, hashlib.sha256(snapshot.pam_update_content).hexdigest()],
        "debconf_communicate": [snapshot.debconf_path, snapshot.debconf_metadata.device, snapshot.debconf_metadata.inode, snapshot.debconf_metadata.mode, snapshot.debconf_metadata.owner_uid, snapshot.debconf_metadata.owner_gid, snapshot.debconf_metadata.size],
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hmac.new(_CONFIRMATION_SECRET, encoded, hashlib.sha256).hexdigest()
    return _Target(action=action, profile=profile, snapshot=snapshot, state_digest=digest), None


def pam_profile_inventory_available() -> bool:
    if os.geteuid() != 0:
        return False
    snapshot, error = _load_snapshot()
    return snapshot is not None and error is None


def pam_profile_control_available() -> bool:
    if os.geteuid() != 0:
        return False
    snapshot, error = _load_snapshot()
    return snapshot is not None and error is None


def list_pam_profiles() -> PAMProfileListResponse:
    if os.geteuid() != 0:
        return PAMProfileListResponse(
            available=False,
            path=str(PROFILE_DIRECTORY),
            profiles=[],
            message="PAM profile inventory requires the MCP server to already run as root to read and verify the system profile-selection state.",
        )
    snapshot, error = _load_snapshot()
    if error or snapshot is None:
        return PAMProfileListResponse(
            available=False,
            path=str(PROFILE_DIRECTORY),
            profiles=[],
            message=error or "The packaged PAM profile state could not be safely inspected.",
        )
    selected = set(snapshot.selected_profiles)
    return PAMProfileListResponse(
        available=True,
        path=str(PROFILE_DIRECTORY),
        profiles=[
            PAMProfileEntry(
                name=profile.name,
                title=profile.title,
                selected=profile.name in selected,
                default=profile.default,
                priority=profile.priority,
                stack_types=list(profile.stack_types),
            )
            for profile in snapshot.profiles
        ],
        message="Selection state comes from debconf's libpam-runtime/profiles value; it does not prove local edits to /etc/pam.d/common-* match the generated selection. Profile contents and authentication arguments are omitted.",
    )


def pam_profile_confirmation_details(action: str, profile_name: str) -> tuple[str | None, str | None, str | None]:
    target, error = _prepare_target(action, profile_name)
    if error or target is None:
        return None, None, error or "The PAM profile request could not be verified."
    phrase = "PAM-PROFILE-" + target.state_digest[:16].upper()
    return target.profile.title, phrase, None


def _snapshot_matches_before_action(snapshot: _Snapshot) -> bool:
    current, error = _load_snapshot()
    if error or current is None:
        return False
    return (
        current.profile_directory == snapshot.profile_directory
        and current.pam_directory == snapshot.pam_directory
        and current.state_directory == snapshot.state_directory
        and current.profiles == snapshot.profiles
        and current.selected_profiles == snapshot.selected_profiles
        and current.selected_raw == snapshot.selected_raw
        and current.common_files == snapshot.common_files
        and current.seen_file == snapshot.seen_file
        and current.pam_update_path == snapshot.pam_update_path
        and current.pam_update_metadata == snapshot.pam_update_metadata
        and current.pam_update_content == snapshot.pam_update_content
        and current.debconf_path == snapshot.debconf_path
        and current.debconf_metadata == snapshot.debconf_metadata
    )


def _run_profile_action(target: _Target) -> tuple[bool, str, tuple[str, ...]]:
    if not _snapshot_matches_before_action(target.snapshot):
        return False, "The profile catalogue, selected state, generated PAM files, or utility identity changed after confirmation.", target.snapshot.selected_profiles
    try:
        result = subprocess.run(
            [target.snapshot.pam_update_path, f"--{target.action}", target.profile.name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except subprocess.TimeoutExpired:
        current, error = _load_snapshot()
        selected = current.selected_profiles if current is not None and error is None else target.snapshot.selected_profiles
        return False, "pam-auth-update timed out; inspect the selected profile state and /etc/pam.d/common-* before retrying.", selected
    except OSError as exc:
        return False, exc.strerror or "pam-auth-update could not be started.", target.snapshot.selected_profiles
    if len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES or len(result.stderr) > MAX_COMMAND_OUTPUT_BYTES:
        current, error = _load_snapshot()
        selected = current.selected_profiles if current is not None and error is None else target.snapshot.selected_profiles
        return False, "pam-auth-update exceeded the output limit; inspect the selected profile state and common PAM files.", selected
    current, error = _load_snapshot()
    if error or current is None:
        return False, error or "The resulting PAM profile state could not be verified; inspect /etc/pam.d/common-*.", target.snapshot.selected_profiles
    before = set(target.snapshot.selected_profiles)
    expected = before | {target.profile.name} if target.action == "enable" else before - {target.profile.name}
    if set(current.selected_profiles) != expected:
        return False, "pam-auth-update did not produce the requested profile selection; inspect /etc/pam.d/common-* and retry only after reviewing the active state.", current.selected_profiles
    if result.returncode != 0:
        return False, "The profile selection changed although pam-auth-update returned an error; inspect the active PAM files before retrying.", current.selected_profiles
    return True, "The packaged PAM profile selection changed. No --force option was used; verify authentication through a separate session before closing the current one. Local edits to common PAM files are not semantically validated.", current.selected_profiles


def perform_pam_profile_action(
    action: PAMProfileAction,
    profile_name: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> PAMProfileActionResponse:
    safe_action: PAMProfileAction = action if action in {"enable", "disable"} else "enable"
    if confirmed is not True:
        return PAMProfileActionResponse(
            success=False,
            action=safe_action,
            profile=profile_name if isinstance(profile_name, str) and PROFILE_NAME_RE.fullmatch(profile_name) else None,
            selected_profiles=[],
            user_confirmed=False,
            message="Explicit client confirmation is required; no PAM profile was changed.",
        )
    target, error = _prepare_target(action, profile_name)
    if error or target is None:
        return PAMProfileActionResponse(
            success=False,
            action=safe_action,
            profile=profile_name if isinstance(profile_name, str) and PROFILE_NAME_RE.fullmatch(profile_name) else None,
            selected_profiles=[],
            user_confirmed=True,
            message=error or "The PAM profile request could not be verified.",
        )
    phrase = "PAM-PROFILE-" + target.state_digest[:16].upper()
    if not isinstance(confirmation_phrase, str) or not hmac.compare_digest(confirmation_phrase, phrase):
        return PAMProfileActionResponse(
            success=False,
            action=target.action,
            profile=target.profile.name,
            selected_profiles=list(target.snapshot.selected_profiles),
            user_confirmed=True,
            message="Confirmation did not match the requested profile, packaged profile inventory, selected state, or current PAM files.",
        )
    with _LOCK:
        current, error = _prepare_target(action, profile_name)
        if error or current is None or current.state_digest != target.state_digest:
            return PAMProfileActionResponse(
                success=False,
                action=target.action,
                profile=target.profile.name,
                selected_profiles=list(target.snapshot.selected_profiles),
                user_confirmed=True,
                message=error or "The PAM profile state changed after confirmation; no profile was changed.",
            )
        success, message, selected_profiles = _run_profile_action(target)
    return PAMProfileActionResponse(
        success=success,
        action=target.action,
        profile=target.profile.name,
        selected_profiles=list(selected_profiles),
        user_confirmed=True,
        message=message,
    )
