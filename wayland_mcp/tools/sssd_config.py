"""Bounded, confirmed activation control for existing SSSD domains."""

from __future__ import annotations

import configparser
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

from wayland_mcp.models import SSSDDomainActionResponse, SSSDDomainEntry, SSSDDomainListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env

SSSD_ROOT = Path("/etc/sssd")
SSSD_CONFIG_NAME = "sssd.conf"
SSSD_CONFIG = SSSD_ROOT / SSSD_CONFIG_NAME
SSSD_SNIPPETS_NAME = "conf.d"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_SNIPPET_ENTRIES = 256
COMMAND_TIMEOUT_SECONDS = 20
DOMAIN_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
SECTION_RE = re.compile(r"^[ \t]*\[([^]\r\n]+)\][ \t]*(?:[#;].*)?(?:\r?\n)?$")
DOMAIN_LINE_RE = re.compile(r"^(\s*domains\s*=\s*)(.*?)(\r?\n)?$", re.IGNORECASE)
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_LOCK = threading.RLock()

SSSDDomainAction = Literal["enable", "disable"]


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
    # Temporary validation files are created in /etc/sssd, changing its
    # timestamps. The directory identity and permissions still bind the path.
    return [info.device, info.inode, info.mode, info.owner_uid, info.owner_gid]


@dataclass(frozen=True, slots=True)
class _ConfigSnapshot:
    directory_metadata: _Metadata
    snippets_metadata: _Metadata | None
    config_metadata: _Metadata
    config_content: bytes = field(repr=False)
    configured_domains: tuple[str, ...]
    active_domains: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _DomainTarget:
    action: SSSDDomainAction
    domain: str
    snapshot: _ConfigSnapshot
    sssctl_path: str
    sssctl_metadata: _Metadata
    replacement_content: bytes = field(repr=False)
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def _trusted_directory(info: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _open_sssd_directory() -> tuple[int | None, _Metadata | None]:
    if not sys.platform.startswith("linux"):
        return None, None
    descriptors: list[int] = []
    try:
        root_fd = os.open("/", _DIRECTORY_FLAGS)
        descriptors.append(root_fd)
        root_info = os.fstat(root_fd)
        if not _trusted_directory(root_info):
            return None, None
        etc_fd = os.open("etc", _DIRECTORY_FLAGS, dir_fd=root_fd)
        descriptors.append(etc_fd)
        etc_info = os.fstat(etc_fd)
        if not _trusted_directory(etc_info):
            return None, None
        sssd_fd = os.open("sssd", _DIRECTORY_FLAGS, dir_fd=etc_fd)
        descriptors.append(sssd_fd)
        sssd_info = os.fstat(sssd_fd)
        if not _trusted_directory(sssd_info):
            return None, None
        descriptors.remove(sssd_fd)
        return sssd_fd, _metadata(sssd_info)
    except OSError:
        return None, None
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_config(directory_fd: int) -> tuple[_Metadata | None, bytes | None]:
    try:
        descriptor = os.open(SSSD_CONFIG_NAME, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    except OSError:
        return None, None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > MAX_CONFIG_BYTES
        ):
            return None, None
        content = bytearray()
        while len(content) <= MAX_CONFIG_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_CONFIG_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        path_info = os.stat(SSSD_CONFIG_NAME, dir_fd=directory_fd, follow_symlinks=False)
        if (
            len(content) > MAX_CONFIG_BYTES
            or _metadata(before) != _metadata(after)
            or (path_info.st_dev, path_info.st_ino) != (after.st_dev, after.st_ino)
        ):
            return None, None
        return _metadata(after), bytes(content)
    except OSError:
        return None, None
    finally:
        os.close(descriptor)


def _snippets_state(directory_fd: int) -> tuple[_Metadata | None, str | None]:
    try:
        snippets_fd = os.open(SSSD_SNIPPETS_NAME, _DIRECTORY_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, "The SSSD conf.d path is not a safe directory."
    try:
        info = os.fstat(snippets_fd)
        if not _trusted_directory(info):
            return None, "The SSSD conf.d directory must be root-owned and not group/world writable."
        names = sorted(os.listdir(snippets_fd))
        if len(names) > MAX_SNIPPET_ENTRIES:
            return None, "The SSSD conf.d directory exceeds the bounded entry limit."
        if names:
            return None, "SSSD conf.d snippets are present; this control only edits standalone sssd.conf configurations."
        return _metadata(info), None
    finally:
        os.close(snippets_fd)


def _parse_config(content: bytes) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeError:
        return None
    if "\x00" in text or ("\r" in text and "\r\n" not in text):
        return None
    if "\r\n" in text and "\n" in text.replace("\r\n", ""):
        return None
    parser = configparser.RawConfigParser(
        interpolation=None,
        strict=True,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
        inline_comment_prefixes=("#", ";"),
    )
    parser.optionxform = str.lower
    try:
        parser.read_string(text)
    except (configparser.Error, ValueError):
        return None
    if parser.defaults() or "sssd" not in parser:
        return None
    configured: list[str] = []
    for section in parser.sections():
        if section.lower().startswith("domain/"):
            name = section[len("domain/"):]
            if not DOMAIN_RE.fullmatch(name):
                return None
            configured.append(name)
    if not configured or len({name.casefold() for name in configured}) != len(configured):
        return None
    raw_domains = parser.get("sssd", "domains", fallback="")
    active = []
    if raw_domains.strip():
        active = [value.strip() for value in raw_domains.split(",")]
        if any(not DOMAIN_RE.fullmatch(name) for name in active):
            return None
        if len({name.casefold() for name in active}) != len(active):
            return None
        configured_folded = {name.casefold() for name in configured}
        if any(name.casefold() not in configured_folded for name in active):
            return None
    return tuple(configured), tuple(active)


def _load_snapshot() -> tuple[_ConfigSnapshot | None, str | None]:
    directory_fd, directory_metadata = _open_sssd_directory()
    if directory_fd is None or directory_metadata is None:
        return None, "A safe root-owned /etc/sssd directory is required."
    try:
        snippets_metadata, snippet_error = _snippets_state(directory_fd)
        if snippet_error:
            return None, snippet_error
        config_metadata, content = _read_config(directory_fd)
        if config_metadata is None or content is None:
            return None, "A root-owned mode-0600 regular /etc/sssd/sssd.conf with one link and bounded size is required."
        parsed = _parse_config(content)
        if parsed is None:
            return None, "The SSSD configuration is outside the supported bounded domain format."
        configured, active = parsed
        return _ConfigSnapshot(
            directory_metadata=directory_metadata,
            snippets_metadata=snippets_metadata,
            config_metadata=config_metadata,
            config_content=content,
            configured_domains=configured,
            active_domains=active,
        ), None
    finally:
        os.close(directory_fd)


def _rewrite_domains(content: bytes, new_domains: tuple[str, ...]) -> bytes | None:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeError:
        return None
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(keepends=True)
    section = ""
    sssd_headers: list[int] = []
    domain_lines: list[int] = []
    for index, line in enumerate(lines):
        match = SECTION_RE.fullmatch(line)
        if match:
            section = match.group(1).strip()
            if section.casefold() == "sssd":
                sssd_headers.append(index)
            continue
        if section.casefold() == "sssd":
            line_match = DOMAIN_LINE_RE.fullmatch(line)
            if line_match:
                domain_lines.append(index)
                value = line_match.group(2)
                if "#" in value or ";" in value:
                    return None
    if len(sssd_headers) != 1 or len(domain_lines) > 1:
        return None
    formatted = ", ".join(new_domains)
    if domain_lines:
        index = domain_lines[0]
        match = DOMAIN_LINE_RE.fullmatch(lines[index])
        if match is None:
            return None
        ending = match.group(3) or ""
        lines[index] = f"{match.group(1)}{formatted}{ending}"
    else:
        index = sssd_headers[0]
        if not lines[index].endswith(("\n", "\r")):
            lines[index] += newline
        lines.insert(index + 1, f"domains = {formatted}{newline}")
    candidate = "".join(lines).encode("utf-8")
    if len(candidate) > MAX_CONFIG_BYTES or _parse_config(candidate) is None:
        return None
    return candidate


def _sssctl_identity(env: dict[str, str]) -> tuple[str | None, _Metadata | None]:
    binary = find_session_binary("sssctl", env)
    if not binary:
        return None, None
    try:
        info = os.stat(binary)
    except OSError:
        return None, None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not info.st_mode & 0o111
    ):
        return None, None
    return binary, _metadata(info)


def _run_config_check(binary: str, config_path: Path) -> bool:
    try:
        result = subprocess.run(
            [binary, "config-check", "--config", str(config_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0 or len(result.stdout) > MAX_CONFIG_BYTES or len(result.stderr) > MAX_CONFIG_BYTES:
        return False
    output = (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="replace")
    issues = re.search(r"Issues identified by validators:\s*(\d+)", output)
    return issues is None or int(issues.group(1)) == 0


def _stage_candidate(directory_fd: int, content: bytes, binary: str) -> tuple[str | None, tuple[int, int] | None]:
    stage_name = f".linux-mcp-sssd-stage-{secrets.token_hex(12)}.conf"
    descriptor = -1
    path_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            stage_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        created_info = os.fstat(descriptor)
        path_identity = (created_info.st_dev, created_info.st_ino)
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("The SSSD candidate accepted no bytes.")
            view = view[written:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            (info.st_dev, info.st_ino) != path_identity
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != len(content)
        ):
            raise OSError("The staged SSSD candidate could not be verified.")
    except OSError:
        if path_identity is not None:
            _unlink_matching_stage(directory_fd, stage_name, path_identity)
        return None, None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    stage_path = SSSD_ROOT / stage_name
    if not _run_config_check(binary, stage_path):
        _unlink_matching_stage(directory_fd, stage_name, path_identity)
        return None, None
    return stage_name, path_identity


def _unlink_matching_stage(directory_fd: int, name: str, identity: tuple[int, int]) -> bool:
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if (info.st_dev, info.st_ino) != identity or not stat.S_ISREG(info.st_mode):
        return False
    try:
        os.unlink(name, dir_fd=directory_fd)
        return True
    except OSError:
        return False


def _prepare_target(action: str, domain: str) -> tuple[_DomainTarget | None, str | None]:
    if action not in {"enable", "disable"} or not isinstance(domain, str) or not DOMAIN_RE.fullmatch(domain):
        return None, "Select enable or disable and one simple configured SSSD domain name."
    if os.geteuid() != 0:
        return None, "SSSD domain changes require the MCP server to already run as root; no elevation is requested."
    snapshot, error = _load_snapshot()
    if error or snapshot is None:
        return None, error or "The SSSD configuration could not be safely inspected."
    configured_by_fold = {item.casefold(): item for item in snapshot.configured_domains}
    canonical_domain = configured_by_fold.get(domain.casefold())
    if canonical_domain is None:
        return None, "The requested domain must already have a matching [domain/NAME] section."
    active_folded = {item.casefold() for item in snapshot.active_domains}
    if action == "enable":
        if canonical_domain.casefold() in active_folded:
            return None, "The selected SSSD domain is already enabled."
        new_domains = snapshot.active_domains + (canonical_domain,)
    else:
        if canonical_domain.casefold() not in active_folded:
            return None, "The selected SSSD domain is not enabled."
        if len(snapshot.active_domains) <= 1:
            return None, "The last enabled SSSD domain cannot be disabled."
        new_domains = tuple(item for item in snapshot.active_domains if item.casefold() != canonical_domain.casefold())
    replacement = _rewrite_domains(snapshot.config_content, new_domains)
    if replacement is None:
        return None, "The SSSD domains line could not be rewritten without changing unrelated configuration."
    env = _environment()
    binary, binary_metadata = _sssctl_identity(env)
    if binary is None or binary_metadata is None:
        return None, "A safe root-owned sssctl executable is required to validate the candidate configuration."
    directory_fd, directory_metadata = _open_sssd_directory()
    if directory_fd is None or directory_metadata != snapshot.directory_metadata:
        if directory_fd is not None:
            os.close(directory_fd)
        return None, "The SSSD configuration directory changed during planning."
    try:
        latest_meta, latest_content = _read_config(directory_fd)
        latest_snippets, snippet_error = _snippets_state(directory_fd)
        if (
            snippet_error
            or latest_meta != snapshot.config_metadata
            or latest_content != snapshot.config_content
            or latest_snippets != snapshot.snippets_metadata
        ):
            return None, snippet_error or "The SSSD configuration changed during planning."
        stage_name, stage_identity = _stage_candidate(directory_fd, replacement, binary)
        if stage_name is None or stage_identity is None:
            return None, "sssctl config-check rejected the candidate or could not validate it."
        if not _unlink_matching_stage(directory_fd, stage_name, stage_identity):
            return None, None
    finally:
        os.close(directory_fd)
    material = {
        "action": action,
        "domain": canonical_domain,
        "directory": _directory_binding(snapshot.directory_metadata),
        "snippets": None if snapshot.snippets_metadata is None else [snapshot.snippets_metadata.device, snapshot.snippets_metadata.inode, snapshot.snippets_metadata.mode, snapshot.snippets_metadata.owner_uid, snapshot.snippets_metadata.owner_gid, snapshot.snippets_metadata.link_count, snapshot.snippets_metadata.size, snapshot.snippets_metadata.modified_ns, snapshot.snippets_metadata.changed_ns],
        "config": [snapshot.config_metadata.device, snapshot.config_metadata.inode, snapshot.config_metadata.mode, snapshot.config_metadata.owner_uid, snapshot.config_metadata.owner_gid, snapshot.config_metadata.link_count, snapshot.config_metadata.size, snapshot.config_metadata.modified_ns, snapshot.config_metadata.changed_ns],
        "config_sha256": hashlib.sha256(snapshot.config_content).hexdigest(),
        "candidate_sha256": hashlib.sha256(replacement).hexdigest(),
        "active_domains": snapshot.active_domains,
        "sssctl": [binary, binary_metadata.device, binary_metadata.inode, binary_metadata.mode, binary_metadata.owner_uid, binary_metadata.owner_gid, binary_metadata.size, binary_metadata.modified_ns, binary_metadata.changed_ns],
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return _DomainTarget(
        action=action,
        domain=canonical_domain,
        snapshot=snapshot,
        sssctl_path=binary,
        sssctl_metadata=binary_metadata,
        replacement_content=replacement,
        state_digest=digest,
    ), None


def sssd_domain_inventory_available() -> bool:
    snapshot, error = _load_snapshot()
    return snapshot is not None and error is None


def sssd_domain_control_available() -> bool:
    if os.geteuid() != 0:
        return False
    snapshot, error = _load_snapshot()
    if error or snapshot is None:
        return False
    binary, metadata = _sssctl_identity(_environment())
    return binary is not None and metadata is not None


def list_sssd_domains() -> SSSDDomainListResponse:
    snapshot, error = _load_snapshot()
    if error or snapshot is None:
        return SSSDDomainListResponse(
            available=False,
            path=str(SSSD_CONFIG),
            domains=[],
            message=error or "The SSSD configuration could not be safely inspected.",
        )
    active = {item.casefold() for item in snapshot.active_domains}
    return SSSDDomainListResponse(
        available=True,
        path=str(SSSD_CONFIG),
        domains=[SSSDDomainEntry(name=name, enabled=name.casefold() in active) for name in snapshot.configured_domains],
        message="Only existing [domain/NAME] sections and their membership in [sssd] domains are reported; configuration values and credentials are omitted.",
    )


def sssd_domain_confirmation_details(action: str, domain: str) -> tuple[str | None, str | None, str | None]:
    target, error = _prepare_target(action, domain)
    if error or target is None:
        return None, None, error or "The SSSD domain request could not be verified."
    phrase = "SSSD-DOMAIN-" + target.state_digest[:16].upper()
    return target.domain, phrase, None


def _read_installed(directory_fd: int) -> tuple[os.stat_result | None, bytes | None]:
    try:
        descriptor = os.open(SSSD_CONFIG_NAME, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    except OSError:
        return None, None
    try:
        info = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= MAX_CONFIG_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_CONFIG_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        path_info = os.stat(SSSD_CONFIG_NAME, dir_fd=directory_fd, follow_symlinks=False)
        if len(data) > MAX_CONFIG_BYTES or _metadata(info) != _metadata(after) or (path_info.st_dev, path_info.st_ino) != (after.st_dev, after.st_ino):
            return None, None
        return after, bytes(data)
    except OSError:
        return None, None
    finally:
        os.close(descriptor)


def _write_stage_file(directory_fd: int, stage_name: str, content: bytes) -> tuple[int, int] | None:
    descriptor = -1
    path_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            stage_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        created_info = os.fstat(descriptor)
        path_identity = (created_info.st_dev, created_info.st_ino)
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("The SSSD stage file accepted no bytes.")
            view = view[written:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            (info.st_dev, info.st_ino) != path_identity
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != len(content)
        ):
            raise OSError("The SSSD stage file could not be verified.")
        return path_identity
    except OSError:
        if path_identity is not None:
            _unlink_matching_stage(directory_fd, stage_name, path_identity)
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _apply_target(target: _DomainTarget) -> tuple[bool, str, tuple[str, ...]]:
    directory_fd, directory_metadata = _open_sssd_directory()
    if directory_fd is None or directory_metadata is None or _directory_binding(directory_metadata) != _directory_binding(target.snapshot.directory_metadata):
        if directory_fd is not None:
            os.close(directory_fd)
        return False, "The SSSD directory changed after confirmation.", target.snapshot.active_domains
    stage_name = f".linux-mcp-sssd-stage-{secrets.token_hex(12)}.conf"
    backup_name = f".linux-mcp-sssd-backup-{secrets.token_hex(12)}.conf"
    backup_created = False
    preserve_backup = False
    published = False
    stage_identity: tuple[int, int] | None = None
    backup_identity: tuple[int, int] | None = None
    try:
        latest_meta, latest_content = _read_installed(directory_fd)
        snippets_metadata, snippet_error = _snippets_state(directory_fd)
        try:
            binary_info = _metadata(os.stat(target.sssctl_path))
        except OSError:
            binary_info = None
        if (
            latest_meta is None
            or latest_content != target.snapshot.config_content
            or latest_meta != target.snapshot.config_metadata
            or snippet_error
            or snippets_metadata != target.snapshot.snippets_metadata
            or binary_info != target.sssctl_metadata
        ):
            return False, snippet_error or "The SSSD config, snippets, or validator executable changed after confirmation.", target.snapshot.active_domains
        stage_identity = _write_stage_file(directory_fd, stage_name, target.replacement_content)
        if stage_identity is None:
            return False, "A root-owned mode-0600 SSSD candidate file could not be staged.", target.snapshot.active_domains
        if not _run_config_check(target.sssctl_path, SSSD_ROOT / stage_name):
            _unlink_matching_stage(directory_fd, stage_name, stage_identity)
            return False, "sssctl config-check rejected the candidate; the active configuration was not changed.", target.snapshot.active_domains
        before_info, before_content = _read_installed(directory_fd)
        if before_info is None or before_content != target.snapshot.config_content or _metadata(before_info) != target.snapshot.config_metadata:
            _unlink_matching_stage(directory_fd, stage_name, stage_identity)
            return False, "The active SSSD configuration changed before publication.", target.snapshot.active_domains
        try:
            os.link(SSSD_CONFIG_NAME, backup_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
            backup_created = True
            backup_info = os.stat(backup_name, dir_fd=directory_fd, follow_symlinks=False)
            backup_identity = (backup_info.st_dev, backup_info.st_ino)
            current_info, current_content = _read_installed(directory_fd)
            if (
                current_info is None
                or current_content != target.snapshot.config_content
                or (current_info.st_dev, current_info.st_ino) != (target.snapshot.config_metadata.device, target.snapshot.config_metadata.inode)
                or (backup_info.st_dev, backup_info.st_ino) != (current_info.st_dev, current_info.st_ino)
            ):
                raise OSError("The original SSSD configuration changed before the backup was bound.")
            os.replace(stage_name, SSSD_CONFIG_NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            published = True
            os.fsync(directory_fd)
        except OSError as exc:
            if stage_identity is not None:
                _unlink_matching_stage(directory_fd, stage_name, stage_identity)
            if backup_created and backup_identity is not None:
                if published:
                    preserve_backup = True
                else:
                    _unlink_matching_stage(directory_fd, backup_name, backup_identity)
                    try:
                        os.fsync(directory_fd)
                    except OSError:
                        pass
            elif backup_created:
                preserve_backup = True
            if published:
                return False, "The SSSD file was replaced but directory sync failed; inspect the active file and hidden backup in /etc/sssd.", target.snapshot.active_domains
            if preserve_backup:
                return False, "The SSSD configuration was not published; a hidden backup may remain in /etc/sssd for inspection.", target.snapshot.active_domains
            return False, exc.strerror or str(exc) or "The SSSD configuration could not be atomically replaced.", target.snapshot.active_domains
        installed_info, installed_content = _read_installed(directory_fd)
        installed_identity = (installed_info.st_dev, installed_info.st_ino) if installed_info is not None else None
        final_check_failed = (
            installed_info is None
            or installed_content != target.replacement_content
            or installed_info.st_uid != 0
            or installed_info.st_gid != 0
            or installed_info.st_nlink != 1
            or stat.S_IMODE(installed_info.st_mode) != 0o600
        )
        if not final_check_failed:
            final_check_failed = not _run_config_check(target.sssctl_path, SSSD_CONFIG)
        if not final_check_failed:
            validated_info, validated_content = _read_installed(directory_fd)
            final_check_failed = not (
                validated_info is not None
                and installed_identity == (validated_info.st_dev, validated_info.st_ino)
                and validated_content == target.replacement_content
            )
        if final_check_failed:
            try:
                latest_info, latest_content = _read_installed(directory_fd)
                backup_info = os.stat(backup_name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    latest_info is not None
                    and latest_content == target.replacement_content
                    and installed_identity == (latest_info.st_dev, latest_info.st_ino)
                    and backup_identity == (backup_info.st_dev, backup_info.st_ino)
                ):
                    os.replace(backup_name, SSSD_CONFIG_NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    backup_created = False
                    os.fsync(directory_fd)
                    return False, "Final SSSD validation failed; the original configuration was restored.", target.snapshot.active_domains
            except OSError:
                pass
            preserve_backup = backup_created
            return False, "The SSSD file was replaced but final validation failed; inspect the active file and the hidden backup in /etc/sssd.", target.snapshot.active_domains
        validated_info, validated_content = _read_installed(directory_fd)
        if (
            validated_info is None
            or installed_identity != (validated_info.st_dev, validated_info.st_ino)
            or validated_content != target.replacement_content
        ):
            preserve_backup = backup_created
            return False, "The active SSSD file changed during final validation; inspect it and the hidden backup in /etc/sssd.", target.snapshot.active_domains
        backup_info = os.stat(backup_name, dir_fd=directory_fd, follow_symlinks=False)
        if backup_identity != (backup_info.st_dev, backup_info.st_ino):
            preserve_backup = backup_created
            return False, "The temporary SSSD backup changed before cleanup; inspect /etc/sssd.", target.snapshot.active_domains
        try:
            os.unlink(backup_name, dir_fd=directory_fd)
            backup_created = False
            os.fsync(directory_fd)
        except OSError:
            return False, "The SSSD change was validated, but its temporary hard-link backup could not be removed.", target.snapshot.active_domains
        parsed = _parse_config(installed_content)
        if parsed is None:
            return False, "The SSSD file changed unexpectedly after validation; inspect the active configuration.", target.snapshot.active_domains
        return True, "The configured SSSD domain list was updated and passed sssctl config-check. No service restart was requested.", parsed[1]
    finally:
        if stage_identity is not None:
            _unlink_matching_stage(directory_fd, stage_name, stage_identity)
        if backup_created and not preserve_backup and backup_identity is not None:
            _unlink_matching_stage(directory_fd, backup_name, backup_identity)
            try:
                os.fsync(directory_fd)
            except OSError:
                pass
        os.close(directory_fd)


def perform_sssd_domain_action(
    action: SSSDDomainAction,
    domain: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> SSSDDomainActionResponse:
    safe_action: SSSDDomainAction = action if action in {"enable", "disable"} else "enable"
    if confirmed is not True:
        return SSSDDomainActionResponse(
            success=False,
            action=safe_action,
            domain=domain if isinstance(domain, str) and DOMAIN_RE.fullmatch(domain) else None,
            enabled_domains=[],
            user_confirmed=False,
            message="Explicit client confirmation is required; no SSSD configuration was changed.",
        )
    target, error = _prepare_target(action, domain)
    if error or target is None:
        return SSSDDomainActionResponse(
            success=False,
            action=safe_action,
            domain=domain if isinstance(domain, str) and DOMAIN_RE.fullmatch(domain) else None,
            enabled_domains=[],
            user_confirmed=True,
            message=error or "The SSSD domain request could not be verified.",
        )
    phrase = "SSSD-DOMAIN-" + target.state_digest[:16].upper()
    if not isinstance(confirmation_phrase, str) or not hmac.compare_digest(confirmation_phrase, phrase):
        return SSSDDomainActionResponse(
            success=False,
            action=target.action,
            domain=target.domain,
            enabled_domains=list(target.snapshot.active_domains),
            user_confirmed=True,
            message="Confirmation did not match the SSSD domain, config content, validator, and current enabled-domain state.",
        )
    with _LOCK:
        current, error = _prepare_target(action, domain)
        if error or current is None or current.state_digest != target.state_digest:
            return SSSDDomainActionResponse(
                success=False,
                action=target.action,
                domain=target.domain,
                enabled_domains=list(target.snapshot.active_domains),
                user_confirmed=True,
                message=error or "The SSSD state changed after confirmation; no configuration was changed.",
            )
        success, message, enabled_domains = _apply_target(target)
    return SSSDDomainActionResponse(
        success=success,
        action=target.action,
        domain=target.domain,
        enabled_domains=list(enabled_domains),
        user_confirmed=True,
        message=message,
    )
