"""Confirmed exact-command sudoers drop-ins with visudo validation."""

from __future__ import annotations

import errno
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

from wayland_mcp.models import SudoPolicyActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.accounts_control import LOCAL_NAME_RE, _parse_local_state

SudoPolicyAction = Literal["grant", "revoke"]
SUDOERS_FILE = Path("/etc/sudoers")
SUDOERS_DIR = Path("/etc/sudoers.d")
MAX_SUDOERS_BYTES = 1024 * 1024
MAX_DROPIN_BYTES = 16 * 1024
MAX_SUDOERS_ENTRY_BYTES = 1024 * 1024
MAX_SUDOERS_TOTAL_BYTES = 8 * 1024 * 1024
MAX_SUDOERS_ENTRIES = 512
MAX_COMMAND_PATH_BYTES = 1024
MAX_ARGUMENT_BYTES = 512
COMMAND_PATH_RE = re.compile(r"^/[A-Za-z0-9_./+-]+$")
ARGUMENTS_RE = re.compile(r"^[A-Za-z0-9_./+=@%-]+(?: [A-Za-z0-9_./+=@%-]+)*$")
INCLUDEDIR_RE = re.compile(r'^\s*(?:@includedir|#includedir)\s+("?)(/etc/sudoers\.d)\1\s*(?:#.*)?$')
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_LOCK = threading.RLock()
COMMAND_TIMEOUT_SECONDS = 15


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


@dataclass(frozen=True, slots=True)
class _PolicyTarget:
    action: SudoPolicyAction
    username: str | None
    group_name: str | None
    principal: str
    identity_digest: str
    command_path: str
    arguments: str
    filename: str
    file_content: bytes = field(repr=False)
    sudoers_metadata: _Metadata
    sudoers_digest: str
    directory_metadata: _Metadata
    includedir_digest: str
    command_metadata: _Metadata
    command_path_digest: str
    policy_metadata: _Metadata | None
    policy_digest: str | None
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def _read_fd(descriptor: int, maximum: int) -> bytes | None:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        return None
    content = bytearray()
    while len(content) <= maximum:
        chunk = os.read(descriptor, min(65536, maximum + 1 - len(content)))
        if not chunk:
            break
        content.extend(chunk)
    after = os.fstat(descriptor)
    if len(content) > maximum or _metadata(before) != _metadata(after):
        return None
    return bytes(content)


def _safe_root_file(path: Path, *, maximum: int) -> tuple[_Metadata, bytes] | None:
    flags = os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or info.st_nlink != 1
            ):
                return None
            content = _read_fd(descriptor, maximum)
            after = _metadata(os.fstat(descriptor))
        finally:
            os.close(descriptor)
    except OSError:
        return None
    if content is None or _metadata(info) != after:
        return None
    return after, content


def _sudoers_directory_metadata() -> _Metadata | None:
    try:
        info = SUDOERS_DIR.lstat()
    except OSError:
        return None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        return None
    return _metadata(info)


def _includedir_digest(directory_fd: int) -> str | None:
    try:
        before = _metadata(os.fstat(directory_fd))
        names = sorted(os.listdir(directory_fd))
    except OSError:
        return None
    if len(names) > MAX_SUDOERS_ENTRIES:
        return None
    material: list[tuple[str, list[int], str]] = []
    total_bytes = 0
    for name in names:
        if not name or name in {".", ".."} or "/" in name:
            return None
        try:
            descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != 0
                    or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    or info.st_nlink != 1
                ):
                    return None
                content = _read_fd(descriptor, MAX_SUDOERS_ENTRY_BYTES)
                after = _metadata(os.fstat(descriptor))
                path_after = _metadata(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
            finally:
                os.close(descriptor)
        except OSError:
            return None
        if content is None or after != _metadata(info) or path_after != after:
            return None
        total_bytes += len(content)
        if total_bytes > MAX_SUDOERS_TOTAL_BYTES:
            return None
        fields = [after.device, after.inode, after.mode, after.owner_uid, after.owner_gid, after.link_count, after.size, after.modified_ns, after.changed_ns]
        material.append((name, fields, hashlib.sha256(content).hexdigest()))
    try:
        after_directory = _metadata(os.fstat(directory_fd))
    except OSError:
        return None
    if before != after_directory:
        return None
    return hashlib.sha256(json.dumps(material, separators=(",", ":")).encode("utf-8")).hexdigest()


def _includedir_present(content: bytes) -> bool:
    try:
        lines = content.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        return False
    return any(INCLUDEDIR_RE.fullmatch(line) is not None for line in lines)


def _run_visudo(path: Path) -> bool:
    binary = find_session_binary("visudo", _environment())
    if not binary:
        return False
    try:
        result = subprocess.run(
            [binary, "-c", "-f", str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def sudo_policy_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    main = _safe_root_file(SUDOERS_FILE, maximum=MAX_SUDOERS_BYTES)
    directory = _sudoers_directory_metadata()
    return (
        main is not None
        and directory is not None
        and _includedir_present(main[1])
        and find_session_binary("visudo", selected) is not None
    )


def _command_metadata(command_path: object) -> tuple[str | None, _Metadata | None, str | None]:
    if not isinstance(command_path, str) or not command_path.startswith("/") or len(command_path.encode("utf-8", errors="ignore")) > MAX_COMMAND_PATH_BYTES:
        return None, None, "command_path must be an absolute executable path of at most 1024 bytes."
    if not COMMAND_PATH_RE.fullmatch(command_path):
        return None, None, "command_path may contain only absolute path characters without spaces or sudoers metacharacters."
    try:
        resolved = Path(command_path).resolve(strict=True)
        if str(resolved) != command_path:
            return None, None, "command_path must name its canonical path without symlink components."
        info = resolved.stat(follow_symlinks=False)
    except (OSError, RuntimeError):
        return None, None, "The exact command path could not be resolved."
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not info.st_mode & stat.S_IXUSR
    ):
        return None, None, "The command must be a root-owned regular executable not writable by group or other users."
    if _command_path_digest(command_path) is None:
        return None, None, "The executable path must have root-owned, non-writable directory components and no extended access ACL."
    return command_path, _metadata(info), None


def _command_path_digest(command_path: str) -> str | None:
    """Bind every path component and reject directories that let users replace the executable."""
    path = Path(command_path)
    components = [Path("/")]
    current = Path("/")
    for part in path.parts[1:-1]:
        current = current / part
        components.append(current)
    try:
        before: list[tuple[str, list[int]]] = []
        for directory in components:
            info = directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                return None
            before.append((str(directory), [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_mtime_ns, info.st_ctime_ns]))
        descriptor = os.open(command_path, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            command_info = os.fstat(descriptor)
            named_info = path.lstat()
            if (command_info.st_dev, command_info.st_ino) != (named_info.st_dev, named_info.st_ino):
                return None
            try:
                access_acl = os.getxattr(command_path, "system.posix_acl_access", follow_symlinks=False)
            except OSError as exc:
                if exc.errno not in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
                    return None
                access_acl = None
            if access_acl:
                return None
            after: list[tuple[str, list[int]]] = []
            for directory in components:
                info = directory.lstat()
                after.append((str(directory), [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_mtime_ns, info.st_ctime_ns]))
            if before != after:
                return None
            command_after = os.fstat(descriptor)
            if _metadata(command_info) != _metadata(command_after):
                return None
        finally:
            os.close(descriptor)
    except OSError:
        return None
    material = {"components": before, "access_acl_sha256": hashlib.sha256(access_acl).hexdigest() if access_acl else None}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _arguments_value(arguments: object) -> tuple[str | None, str | None]:
    if not isinstance(arguments, str) or len(arguments.encode("utf-8", errors="ignore")) > MAX_ARGUMENT_BYTES:
        return None, f"arguments must be text no larger than {MAX_ARGUMENT_BYTES} bytes; use an empty string to allow no arguments."
    if not arguments:
        return "", None
    if arguments != arguments.strip() or not ARGUMENTS_RE.fullmatch(arguments):
        return None, "arguments must be one exact space-separated string using letters, digits, and /._+=@%-; sudoers wildcards and shell metacharacters are not accepted."
    if len(arguments.split()) > 32:
        return None, "arguments may contain at most 32 exact tokens."
    return arguments, None


def _read_policy_at(directory_fd: int, filename: str) -> tuple[_Metadata | None, bytes | None, str | None]:
    try:
        descriptor = os.open(filename, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    except FileNotFoundError:
        return None, None, None
    except OSError:
        return None, None, "The managed sudoers drop-in could not be opened safely."
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or info.st_nlink != 1
        ):
            return None, None, "The managed sudoers path is not a safe root-owned regular file."
        content = _read_fd(descriptor, MAX_DROPIN_BYTES)
        after = _metadata(os.fstat(descriptor))
        path_after = _metadata(os.stat(filename, dir_fd=directory_fd, follow_symlinks=False))
    except OSError:
        return None, None, "The managed sudoers drop-in changed while being read."
    finally:
        os.close(descriptor)
    if content is None or _metadata(info) != after or path_after != after:
        return None, None, "The managed sudoers drop-in changed or exceeded its size limit."
    return after, content, None


def _prepare_target(
    action: str,
    username: str | None,
    command_path: str,
    arguments: str,
    group_name: str | None = None,
) -> tuple[_PolicyTarget | None, str | None]:
    if not isinstance(action, str) or action not in {"grant", "revoke"}:
        return None, "action must be grant or revoke."
    if group_name is None:
        if not isinstance(username, str) or not LOCAL_NAME_RE.fullmatch(username):
            return None, "username must be one exact local account name."
        users, _groups, account_digest, error = _parse_local_state()
        if error or username not in users:
            return None, error or "The exact local user does not exist."
        principal = username
        subject_type = "user"
        subject_name = username
    else:
        if username is not None and username != "":
            return None, "Supply either username or group_name, not both."
        if not isinstance(group_name, str) or not LOCAL_NAME_RE.fullmatch(group_name):
            return None, "group_name must be one exact local group name."
        _users, groups, account_digest, error = _parse_local_state()
        if error or group_name not in groups:
            return None, error or "The exact local group does not exist."
        principal = f"%{group_name}"
        subject_type = "group"
        subject_name = group_name
    if os.geteuid() != 0:
        return None, "The MCP server must already run as root to change sudoers; this tool does not invoke sudo."
    if not sudo_policy_control_available():
        return None, "Safe /etc/sudoers and /etc/sudoers.d paths, an includedir directive, and visudo are required."
    normalized_path, command_metadata, error = _command_metadata(command_path)
    if error or normalized_path is None or command_metadata is None:
        return None, error or "The exact command could not be verified."
    normalized_arguments, error = _arguments_value(arguments)
    if error or normalized_arguments is None:
        return None, error or "The exact command arguments could not be verified."
    command_path_digest = _command_path_digest(normalized_path)
    if command_path_digest is None:
        return None, "The executable path changed or failed its directory and access-ACL checks."
    main_snapshot = _safe_root_file(SUDOERS_FILE, maximum=MAX_SUDOERS_BYTES)
    directory_metadata = _sudoers_directory_metadata()
    if main_snapshot is None or directory_metadata is None:
        return None, "The exact sudoers configuration or drop-in directory changed while being checked."
    main_metadata, main_content = main_snapshot
    if not _includedir_present(main_content):
        return None, "The main sudoers file must include /etc/sudoers.d before managed policy can be added."
    if not _run_visudo(SUDOERS_FILE):
        return None, "The current sudoers configuration does not pass visudo validation."
    policy_id = hashlib.sha256(
        f"{subject_type}\x00{subject_name}\x00{normalized_path}\x00{normalized_arguments}".encode("utf-8")
    ).hexdigest()[:24]
    filename = f"linux-mcp-{subject_type}-{subject_name}-{policy_id}"
    rendered_arguments = normalized_arguments if normalized_arguments else '""'
    file_content = (
        f"# Managed by linux-mcp; rule {policy_id}\n"
        f"{principal} ALL=(root) PASSWD: {normalized_path} {rendered_arguments}\n"
    ).encode("utf-8")
    if len(file_content) > MAX_DROPIN_BYTES:
        return None, "The generated sudoers rule exceeds its file-size limit."
    flags = _DIRECTORY_FLAGS
    try:
        directory_fd = os.open(SUDOERS_DIR, flags)
        try:
            if _metadata(os.fstat(directory_fd)) != directory_metadata:
                return None, "The sudoers drop-in directory changed while being checked."
            includedir_digest = _includedir_digest(directory_fd)
            if includedir_digest is None:
                return None, "The sudoers drop-in directory contains unsafe, unstable, or oversized entries."
            policy_metadata, current_content, error = _read_policy_at(directory_fd, filename)
        finally:
            os.close(directory_fd)
    except OSError:
        return None, "The sudoers drop-in directory could not be opened safely."
    if error:
        return None, error
    if action == "grant":
        if policy_metadata is not None:
            return None, "The managed rule already exists or its target path is occupied."
    elif policy_metadata is None or current_content != file_content:
        return None, "The exact managed sudoers rule does not exist or has been changed outside this tool."
    details = {
        "action": action,
        "username": username,
        "group_name": group_name,
        "principal": principal,
        "identity_digest": account_digest,
        "command_path": normalized_path,
        "arguments": normalized_arguments,
        "filename": filename,
        "sudoers_metadata": [main_metadata.device, main_metadata.inode, main_metadata.mode, main_metadata.owner_uid, main_metadata.owner_gid, main_metadata.link_count, main_metadata.size, main_metadata.modified_ns, main_metadata.changed_ns],
        "sudoers_sha256": hashlib.sha256(main_content).hexdigest(),
        "directory_metadata": [directory_metadata.device, directory_metadata.inode, directory_metadata.mode, directory_metadata.owner_uid, directory_metadata.owner_gid, directory_metadata.link_count, directory_metadata.size, directory_metadata.modified_ns, directory_metadata.changed_ns],
        "includedir_digest": includedir_digest,
        "command_metadata": [command_metadata.device, command_metadata.inode, command_metadata.mode, command_metadata.owner_uid, command_metadata.owner_gid, command_metadata.link_count, command_metadata.size, command_metadata.modified_ns, command_metadata.changed_ns],
        "command_path_digest": command_path_digest,
        "policy_metadata": [policy_metadata.device, policy_metadata.inode, policy_metadata.mode, policy_metadata.owner_uid, policy_metadata.owner_gid, policy_metadata.link_count, policy_metadata.size, policy_metadata.modified_ns, policy_metadata.changed_ns] if policy_metadata else None,
        "policy_sha256": hashlib.sha256(current_content).hexdigest() if current_content is not None else None,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return _PolicyTarget(
        action=action,  # type: ignore[arg-type]
        username=username,
        group_name=group_name,
        principal=principal,
        identity_digest=account_digest,
        command_path=normalized_path,
        arguments=normalized_arguments,
        filename=filename,
        file_content=file_content,
        sudoers_metadata=main_metadata,
        sudoers_digest=hashlib.sha256(main_content).hexdigest(),
        directory_metadata=directory_metadata,
        includedir_digest=includedir_digest,
        command_metadata=command_metadata,
        command_path_digest=command_path_digest,
        policy_metadata=policy_metadata,
        policy_digest=hashlib.sha256(current_content).hexdigest() if current_content is not None else None,
        state_digest=digest,
    ), None


def sudo_policy_confirmation_details(
    action: str,
    username: str,
    command_path: str,
    arguments: str = "",
) -> tuple[str | None, str | None, str | None]:
    target, error = _prepare_target(action, username, command_path, arguments)
    if error or target is None:
        return None, None, error or "The sudo policy request could not be verified."
    phrase = "SUDO-POLICY-" + target.state_digest[:16].upper()
    return target.username, phrase, None


def sudo_group_policy_confirmation_details(
    action: str,
    group_name: str,
    command_path: str,
    arguments: str = "",
) -> tuple[str | None, str | None, str | None]:
    target, error = _prepare_target(action, None, command_path, arguments, group_name)
    if error or target is None:
        return None, None, error or "The sudo group policy request could not be verified."
    phrase = "SUDO-POLICY-" + target.state_digest[:16].upper()
    return f"%{target.group_name}", phrase, None


def _run_visudo_for_path(path: Path) -> bool:
    return _run_visudo(path)


def _write_stage(directory_fd: int, stage_name: str, content: bytes) -> tuple[int, int] | None:
    descriptor = -1
    try:
        descriptor = os.open(
            stage_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o440,
            dir_fd=directory_fd,
        )
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o440)
        view = memoryview(content)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("The sudoers stage file accepted no bytes.")
            view = view[count:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o440 or info.st_size != len(content):
            raise OSError("The sudoers stage file could not be verified.")
        return info.st_dev, info.st_ino
    except OSError:
        try:
            os.unlink(stage_name, dir_fd=directory_fd)
        except OSError:
            pass
        return None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_named(directory_fd: int, filename: str) -> tuple[os.stat_result | None, bytes | None]:
    try:
        descriptor = os.open(filename, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    except OSError:
        return None, None
    try:
        info = os.fstat(descriptor)
        content = _read_fd(descriptor, MAX_DROPIN_BYTES)
        path_info = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        if content is None or (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino):
            return None, None
        return info, content
    except OSError:
        return None, None
    finally:
        os.close(descriptor)


def _remove_created_grant(directory_fd: int, target: _PolicyTarget, identity: tuple[int, int]) -> bool:
    info, content = _read_named(directory_fd, target.filename)
    if info is None or content != target.file_content or (info.st_dev, info.st_ino) != identity:
        return False
    try:
        os.unlink(target.filename, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return True
    except OSError:
        return False


def _apply_grant(directory_fd: int, target: _PolicyTarget) -> tuple[bool, str]:
    stage_name = f".linux-mcp-stage-{secrets.token_hex(12)}"
    identity = _write_stage(directory_fd, stage_name, target.file_content)
    if identity is None:
        return False, "A root-owned mode-0440 sudoers stage file could not be created."
    stage_path = SUDOERS_DIR / stage_name
    try:
        if not _run_visudo_for_path(stage_path):
            return False, "visudo rejected the exact candidate rule; no active rule was installed."
        try:
            os.link(stage_name, target.filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return False, "The managed sudoers target became occupied before installation."
        try:
            os.unlink(stage_name, dir_fd=directory_fd)
        except OSError:
            _remove_created_grant(directory_fd, target, identity)
            return False, "The sudoers staging entry could not be removed; the generated rule was rolled back where possible."
        os.fsync(directory_fd)
        if not _run_visudo_for_path(SUDOERS_FILE):
            _remove_created_grant(directory_fd, target, identity)
            _run_visudo_for_path(SUDOERS_FILE)
            return False, "The full sudoers configuration rejected the new rule; the generated drop-in was rolled back."
        info, content = _read_named(directory_fd, target.filename)
        if info is None or content != target.file_content or (info.st_dev, info.st_ino) != identity or stat.S_IMODE(info.st_mode) != 0o440:
            _remove_created_grant(directory_fd, target, identity)
            _run_visudo_for_path(SUDOERS_FILE)
            return False, "The installed sudoers rule changed during verification and was rolled back where possible."
        return True, "The exact PASSWD-tagged sudoers rule was installed and visudo-validated."
    finally:
        try:
            os.unlink(stage_name, dir_fd=directory_fd)
        except OSError:
            pass


def _apply_revoke(directory_fd: int, target: _PolicyTarget) -> tuple[bool, str]:
    backup_name = f".linux-mcp-revoke-{secrets.token_hex(12)}"
    try:
        current_info, current_content = _read_named(directory_fd, target.filename)
        if (
            current_info is None
            or current_content != target.file_content
            or target.policy_metadata is None
            or _metadata(current_info) != target.policy_metadata
        ):
            return False, "The exact managed sudoers file identity changed after confirmation."
        os.link(target.filename, backup_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        original_info, original_content = _read_named(directory_fd, target.filename)
        backup_info, backup_content = _read_named(directory_fd, backup_name)
        if (
            original_info is None
            or backup_info is None
            or original_content != target.file_content
            or backup_content != target.file_content
            or (original_info.st_dev, original_info.st_ino) != (backup_info.st_dev, backup_info.st_ino)
        ):
            os.unlink(backup_name, dir_fd=directory_fd)
            return False, "The exact managed sudoers file changed before it could be disabled."
        os.unlink(target.filename, dir_fd=directory_fd)
        os.fsync(directory_fd)
        if not _run_visudo_for_path(SUDOERS_FILE):
            try:
                os.link(backup_name, target.filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
                os.fsync(directory_fd)
                os.unlink(backup_name, dir_fd=directory_fd)
            except OSError:
                pass
            _run_visudo_for_path(SUDOERS_FILE)
            return False, "The remaining sudoers configuration failed validation; the rule was restored where possible."
        os.unlink(backup_name, dir_fd=directory_fd)
        os.fsync(directory_fd)
        if _read_named(directory_fd, target.filename)[0] is not None or not _run_visudo_for_path(SUDOERS_FILE):
            return False, "The sudoers rule was removed but final configuration verification failed; inspect sudoers before further changes."
        return True, "The exact managed sudoers rule was removed and the remaining configuration passed visudo."
    except OSError:
        try:
            backup_info, backup_content = _read_named(directory_fd, backup_name)
            if backup_info is not None and backup_content == target.file_content:
                target_info, target_content = _read_named(directory_fd, target.filename)
                if target_info is not None and target_content == target.file_content and (target_info.st_dev, target_info.st_ino) == (backup_info.st_dev, backup_info.st_ino):
                    pass
                elif target_info is None:
                    os.link(backup_name, target.filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
                    os.fsync(directory_fd)
                else:
                    os.unlink(backup_name, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                    return False, "The managed sudoers rule could not be restored because its target path was occupied."
                os.unlink(backup_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        except OSError:
            pass
        return False, "The managed sudoers rule could not be removed safely; inspect the drop-in directory."


def perform_sudo_policy_action(
    action: SudoPolicyAction,
    username: str | None,
    command_path: str,
    arguments: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
    group_name: str | None = None,
) -> SudoPolicyActionResponse:
    safe_action: SudoPolicyAction = action if action in {"grant", "revoke"} else "grant"
    safe_username = username if isinstance(username, str) and LOCAL_NAME_RE.fullmatch(username) else None
    safe_group = group_name if isinstance(group_name, str) and LOCAL_NAME_RE.fullmatch(group_name) else None
    if confirmed is not True:
        return SudoPolicyActionResponse(
            success=False,
            action=safe_action,
            username=safe_username,
            group_name=safe_group,
            command_path=command_path if isinstance(command_path, str) else None,
            user_confirmed=False,
            message="Explicit client confirmation is required; no sudoers file was changed.",
        )
    target, error = _prepare_target(action, username, command_path, arguments, group_name)
    if error or target is None:
        return SudoPolicyActionResponse(
            success=False,
            action=safe_action,
            username=safe_username,
            group_name=safe_group,
            command_path=command_path if isinstance(command_path, str) else None,
            user_confirmed=True,
            message=error or "The exact sudo policy request could not be verified.",
        )
    phrase = "SUDO-POLICY-" + target.state_digest[:16].upper()
    if not isinstance(confirmation_phrase, str) or not hmac.compare_digest(confirmation_phrase, phrase):
        return SudoPolicyActionResponse(
            success=False,
            action=target.action,
            username=target.username,
            group_name=target.group_name,
            command_path=target.command_path,
            user_confirmed=True,
            message="Confirmation did not match the exact local user/group, executable, arguments, and sudoers state.",
        )
    with _LOCK:
        current, error = _prepare_target(action, username, command_path, arguments, group_name)
        if error or current is None or current.state_digest != target.state_digest:
            return SudoPolicyActionResponse(
                success=False,
                action=target.action,
                username=target.username,
                group_name=target.group_name,
                command_path=target.command_path,
                user_confirmed=True,
                message=error or "The sudoers, command, or drop-in state changed after confirmation; no rule was changed.",
            )
        try:
            directory_fd = os.open(SUDOERS_DIR, _DIRECTORY_FLAGS)
            try:
                if _metadata(os.fstat(directory_fd)) != target.directory_metadata:
                    raise OSError("The sudoers drop-in directory identity changed after confirmation.")
                if _includedir_digest(directory_fd) != target.includedir_digest:
                    raise OSError("An included sudoers drop-in changed after confirmation.")
                latest_main = _safe_root_file(SUDOERS_FILE, maximum=MAX_SUDOERS_BYTES)
                if latest_main is None or latest_main[0] != target.sudoers_metadata or hashlib.sha256(latest_main[1]).hexdigest() != target.sudoers_digest:
                    raise OSError("The main sudoers configuration changed after confirmation.")
                latest_command, latest_command_metadata, command_error = _command_metadata(target.command_path)
                latest_command_path_digest = _command_path_digest(target.command_path)
                if command_error or latest_command != target.command_path or latest_command_metadata != target.command_metadata or latest_command_path_digest != target.command_path_digest:
                    raise OSError("The exact executable changed after confirmation.")
                if target.action == "grant":
                    success, detail = _apply_grant(directory_fd, target)
                else:
                    success, detail = _apply_revoke(directory_fd, target)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            success, detail = False, exc.strerror or str(exc) or "The sudoers directory could not be safely accessed."
    return SudoPolicyActionResponse(
        success=success,
        action=target.action,
        username=target.username,
        group_name=target.group_name,
        command_path=target.command_path,
        user_confirmed=True,
        message=detail,
    )
