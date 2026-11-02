"""Confirmed local user/group administration using fixed shadow-utils calls."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import LocalIdentityActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.filesystem import _open_resolved_path
from wayland_mcp.tools.filesystem_path_admin import _snapshot_tree_fd

LocalIdentityAction = Literal[
    "create_user", "delete_user", "lock_user", "unlock_user", "set_shell",
    "move_home", "create_group", "delete_group", "add_user_to_group", "remove_user_from_group",
]
LOCAL_NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SHELL_PATH_RE = re.compile(r"^/[A-Za-z0-9_./+-]{1,255}$")
PASSWD_PATH = Path("/etc/passwd")
GROUP_PATH = Path("/etc/group")
SHELLS_PATH = Path("/etc/shells")
LOGIN_DEFS_PATH = Path("/etc/login.defs")
DEFAULT_USERADD_PATH = Path("/etc/default/useradd")
HOME_SKELETON_PATH = Path("/etc/skel")
HOME_BASE_PATHS = (Path("/home"), Path("/var/home"))
HOME_PARENT_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
MOUNT_INFO_PATH = Path("/proc/self/mountinfo")
SHADOW_HOOKS_ROOT = Path("/etc/shadow-maint")
SHADOW_PATH = Path("/etc/shadow")
MAX_IDENTITY_FILE_BYTES = 4 * 1024 * 1024
MAX_SHELLS_FILE_BYTES = 256 * 1024
MAX_HOME_SKELETON_BYTES = 8 * 1024 * 1024
MAX_HOME_SKELETON_ENTRIES = 2_048
COMMAND_TIMEOUT_SECONDS = 30
HOME_MOVE_TIMEOUT_SECONDS = 1800
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
LOCKED_PASSWORD_STATES = {"L", "LK"}


@dataclass(frozen=True, slots=True)
class LocalIdentityTarget:
    action: LocalIdentityAction
    username: str | None
    group_name: str | None
    login_shell: str | None
    current_user: tuple[str, int, int, str, str] | None
    current_group: tuple[str, int, tuple[str, ...]] | None
    password_state: str | None
    side_effect_notes: tuple[str, ...]
    files_digest: str
    state_digest: str
    create_home: bool = False
    home_directory: str | None = None
    source_home_directory: str | None = None
    source_home_identity: tuple[int, ...] | None = None
    source_parent_identity: tuple[int, ...] | None = None
    home_parent_path: str | None = None
    home_parent_identity: tuple[int, ...] | None = None
    remove_home: bool = False
    home_tree_sha256: str | None = None
    home_tree_entries: int = 0
    home_tree_bytes: int = 0


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def _read_file(path: Path, maximum: int) -> tuple[bytes | None, str | None]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                return None, f"{path} is not a bounded regular file."
            content = bytearray()
            while len(content) <= maximum:
                chunk = os.read(descriptor, min(65536, maximum + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        return None, f"Could not read {path}: {exc.strerror or 'read error'}."
    if len(content) > maximum or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ):
        return None, f"{path} changed while it was being read."
    return bytes(content), None


def _home_skeleton_digest() -> tuple[str | None, str | None]:
    try:
        root_info = HOME_SKELETON_PATH.lstat()
    except OSError:
        return None, "The /etc/skel home template could not be inspected."
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or root_info.st_uid != 0
        or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        return None, "The /etc/skel template must be a root-owned directory without group/world write access."
    digest = hashlib.sha256()
    digest.update(repr((root_info.st_dev, root_info.st_ino, root_info.st_mode, root_info.st_mtime_ns, root_info.st_ctime_ns)).encode("ascii"))
    pending = [(HOME_SKELETON_PATH, "")]
    entries_seen = 0
    total_bytes = 0
    while pending:
        directory, relative_directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            return None, "The /etc/skel template changed or could not be read."
        for entry in entries:
            entries_seen += 1
            if entries_seen > MAX_HOME_SKELETON_ENTRIES:
                return None, "The /etc/skel template exceeds its entry limit."
            relative = f"{relative_directory}/{entry.name}" if relative_directory else entry.name
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                return None, "The /etc/skel template changed during inspection."
            if (
                stat.S_ISLNK(info.st_mode)
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                return None, "Symlinks and special files in /etc/skel are not copied by this account tool."
            digest.update(os.fsencode(relative) + b"\x00")
            digest.update(repr((info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)).encode("ascii"))
            if stat.S_ISDIR(info.st_mode):
                pending.append((Path(entry.path), relative))
                continue
            total_bytes += info.st_size
            if total_bytes > MAX_HOME_SKELETON_BYTES:
                return None, "The /etc/skel template exceeds its byte limit."
            descriptor: int | None = None
            try:
                descriptor = _open_resolved_path(Path(entry.path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
                before = os.fstat(descriptor)
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns
                ):
                    return None, "The /etc/skel template changed during inspection."
                content = bytearray()
                while len(content) <= MAX_HOME_SKELETON_BYTES:
                    chunk = os.read(descriptor, min(64 * 1024, MAX_HOME_SKELETON_BYTES + 1 - len(content)))
                    if not chunk:
                        break
                    content.extend(chunk)
                after = os.fstat(descriptor)
            except OSError:
                return None, "The /etc/skel template file could not be read safely."
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if len(content) != info.st_size or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns
            ):
                return None, "The /etc/skel template changed during inspection."
            digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest(), None


def _parse_local_state() -> tuple[dict[str, tuple[str, int, int, str, str]], dict[str, tuple[str, int, tuple[str, ...]]], str | None, str | None]:
    passwd_data, error = _read_file(PASSWD_PATH, MAX_IDENTITY_FILE_BYTES)
    if error or passwd_data is None:
        return {}, {}, None, error or "Local passwd state is unavailable."
    group_data, error = _read_file(GROUP_PATH, MAX_IDENTITY_FILE_BYTES)
    if error or group_data is None:
        return {}, {}, None, error or "Local group state is unavailable."
    try:
        passwd_lines = passwd_data.decode("utf-8", errors="strict").splitlines()
        group_lines = group_data.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        return {}, {}, None, "Local account files are not valid UTF-8."
    users: dict[str, tuple[str, int, int, str, str]] = {}
    groups: dict[str, tuple[str, int, tuple[str, ...]]] = {}
    duplicate_users: set[str] = set()
    duplicate_groups: set[str] = set()
    for line in passwd_lines:
        fields = line.split(":")
        if len(fields) != 7 or not LOCAL_NAME_RE.fullmatch(fields[0]):
            continue
        try:
            uid, gid = int(fields[2], 10), int(fields[3], 10)
        except ValueError:
            continue
        if uid < 0 or gid < 0:
            continue
        record = (fields[0], uid, gid, fields[5], fields[6])
        if fields[0] in users:
            duplicate_users.add(fields[0])
        users[fields[0]] = record
    for line in group_lines:
        fields = line.split(":")
        if len(fields) != 4 or not LOCAL_NAME_RE.fullmatch(fields[0]):
            continue
        try:
            gid = int(fields[2], 10)
        except ValueError:
            continue
        if gid < 0:
            continue
        members = tuple(sorted(set(item for item in fields[3].split(",") if LOCAL_NAME_RE.fullmatch(item))))
        record = (fields[0], gid, members)
        if fields[0] in groups:
            duplicate_groups.add(fields[0])
        groups[fields[0]] = record
    if duplicate_users or duplicate_groups:
        return {}, {}, None, "Duplicate local user or group names make exact identity control unsafe."
    file_digest = hashlib.sha256(passwd_data + b"\x00" + group_data).hexdigest()
    return users, groups, file_digest, None


def _password_state(username: str) -> str | None:
    passwd = find_session_binary("passwd", _environment())
    if not passwd:
        return None
    result = _run([passwd, "-S", username])
    if result is None or result[0] != 0:
        return None
    fields = result[1].split()
    if len(fields) < 2 or fields[0] != username or fields[1] not in {"P", "L", "LK", "NP"}:
        return None
    return fields[1]


def _shadow_password_hash_usable(username: str) -> bool | None:
    """Inspect only whether the local shadow entry contains an unlockable hash."""
    if not LOCAL_NAME_RE.fullmatch(username):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(SHADOW_PATH, flags)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != 0
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or before.st_size > MAX_IDENTITY_FILE_BYTES
            ):
                return None
            content = bytearray()
            while len(content) <= MAX_IDENTITY_FILE_BYTES:
                chunk = os.read(descriptor, min(65536, MAX_IDENTITY_FILE_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        return None
    if len(content) > MAX_IDENTITY_FILE_BYTES or (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
    ) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ):
        return None
    wanted = username.encode("ascii")
    matches = [line.split(b":") for line in content.splitlines() if line.split(b":", 1)[0] == wanted]
    if len(matches) != 1 or len(matches[0]) != 9:
        return None
    password_field = matches[0][1]
    if password_field.startswith(b"!"):
        password_field = password_field.lstrip(b"!")
    return bool(password_field and not password_field.startswith(b"*"))


def _run(command: list[str], *, timeout_seconds: int = COMMAND_TIMEOUT_SECONDS) -> tuple[int, str] | None:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if len(completed.stdout) > MAX_COMMAND_OUTPUT_BYTES:
        return None
    try:
        return completed.returncode, completed.stdout.decode("utf-8", errors="strict")
    except UnicodeError:
        return None


def local_identity_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    return all(
        find_session_binary(binary, selected)
        for binary in ("useradd", "userdel", "usermod", "groupadd", "groupdel", "gpasswd", "passwd")
    ) and PASSWD_PATH.is_file() and GROUP_PATH.is_file()


def _config_values(content: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in content.decode("utf-8", errors="replace").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        fields = line.split(None, 1)
        if len(fields) == 2:
            values[fields[0].upper()] = fields[1].strip()
    return values


def _side_effect_policy(action: str, *, include_home_skeleton: bool = False) -> tuple[str | None, tuple[str, ...], str | None]:
    login_defs, error = _read_file(LOGIN_DEFS_PATH, 512 * 1024)
    if error or login_defs is None:
        return None, (), error or "The shadow-utils configuration could not be read."
    values = _config_values(login_defs)
    if action == "delete_user" and values.get("USERDEL_CMD", ""):
        return None, (), "A configured USERDEL_CMD would run an additional host command during user deletion; that policy is not exposed by this tool."
    command_by_action = {
        "create_user": "useradd",
        "delete_user": "userdel",
        "lock_user": "usermod",
        "unlock_user": "usermod",
        "set_shell": "usermod",
        "move_home": "usermod",
        "create_group": "groupadd",
        "delete_group": "groupdel",
        "add_user_to_group": "gpasswd",
        "remove_user_from_group": "gpasswd",
    }
    hook_state: list[tuple[str, int | None, int | None, int | None, int | None]] = []
    command = command_by_action[action]
    for phase in ("pre", "post"):
        directory = SHADOW_HOOKS_ROOT / f"{command}-{phase}.d"
        try:
            info = directory.lstat()
        except FileNotFoundError:
            hook_state.append((str(directory), None, None, None, None))
            continue
        except OSError:
            return None, (), "Shadow-utils lifecycle hook state could not be inspected."
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return None, (), "Shadow-utils lifecycle hook paths must be real directories."
        try:
            with os.scandir(directory) as entries:
                names = [entry.name for entry in entries]
        except OSError:
            return None, (), "Shadow-utils lifecycle hook state could not be inspected."
        if names:
            return None, (), "Configured shadow-utils lifecycle hooks may run additional host commands; this action is refused while hooks are present."
        hook_state.append((str(directory), info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns))

    notes: list[str] = []
    policy_material: dict[str, object] = {
        "login_defs_digest": hashlib.sha256(login_defs).hexdigest(),
        "hook_state": hook_state,
    }
    if action == "delete_user" and values.get("USERGROUPS_ENAB", "").casefold() != "no":
        notes.append("The host's USERGROUPS_ENAB setting may also remove this user's same-name empty private group.")
    if action == "create_user":
        try:
            DEFAULT_USERADD_PATH.lstat()
        except FileNotFoundError:
            defaults = b""
        except OSError:
            return None, (), "The useradd defaults file could not be inspected."
        else:
            defaults, error = _read_file(DEFAULT_USERADD_PATH, 256 * 1024)
            if error or defaults is None:
                return None, (), error or "The useradd defaults file could not be read."
        default_values = _config_values(defaults)
        mail_spool = default_values.get("CREATE_MAIL_SPOOL", "").casefold() == "yes"
        policy_material["useradd_defaults_digest"] = hashlib.sha256(defaults).hexdigest()
        policy_material["create_mail_spool"] = mail_spool
        if mail_spool:
            notes.append("The host's CREATE_MAIL_SPOOL setting may create a mail spool in addition to the requested account changes.")
        if include_home_skeleton:
            skeleton_digest, error = _home_skeleton_digest()
            if error or skeleton_digest is None:
                return None, (), error or "The /etc/skel template could not be verified."
            policy_material["home_skeleton_digest"] = skeleton_digest
            notes.append("The requested home directory will copy the confirmed bounded /etc/skel template.")
    digest = hashlib.sha256(json.dumps(policy_material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return digest, tuple(notes), None


def _validated_shell(shell: object, *, allow_default: bool = False) -> tuple[str | None, str | None]:
    if shell is None and allow_default:
        for candidate in ("/usr/sbin/nologin", "/sbin/nologin"):
            path = Path(candidate)
            if path.is_file() and os.access(path, os.X_OK):
                return str(path), None
        return None, "No standard nologin shell is installed; supply an executable shell listed in /etc/shells."
    if not isinstance(shell, str) or not SHELL_PATH_RE.fullmatch(shell):
        return None, "login_shell must be an exact absolute executable path from /etc/shells."
    shells_data, error = _read_file(SHELLS_PATH, MAX_SHELLS_FILE_BYTES)
    if error or shells_data is None:
        return None, error or "The local /etc/shells file is unavailable."
    try:
        allowed = {line.strip() for line in shells_data.decode("utf-8", errors="strict").splitlines() if line.strip() and not line.lstrip().startswith("#")}
        shell_path = Path(shell)
        shell_info = shell_path.stat()
    except (OSError, RuntimeError, UnicodeError):
        return None, "login_shell must be an existing executable listed in /etc/shells."
    if not stat.S_ISREG(shell_info.st_mode) or shell not in allowed or not os.access(shell, os.X_OK):
        return None, "login_shell must be an existing executable listed exactly in /etc/shells."
    return shell, None


def _planned_home_directory(username: str) -> tuple[Path | None, tuple[int, ...] | None, str | None]:
    useradd = find_session_binary("useradd", _environment())
    if not useradd:
        return None, None, "The useradd command is unavailable."
    result = _run([useradd, "-D"])
    if result is None or result[0] != 0:
        return None, None, "The effective useradd defaults could not be read."
    values: dict[str, str] = {}
    for line in result[1].splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip().upper()] = value.strip()
    home_base = values.get("HOME")
    if not home_base:
        return None, None, "The effective useradd home base could not be determined."
    base = Path(home_base)
    login_defs, login_error = _read_file(LOGIN_DEFS_PATH, 512 * 1024)
    if login_error or login_defs is None:
        return None, None, login_error or "The account home-mode policy could not be read."
    login_values = _config_values(login_defs)
    home_mode_value = login_values.get("HOME_MODE")
    if home_mode_value is not None:
        try:
            configured_home_mode = int(home_mode_value, 8)
        except ValueError:
            return None, None, "The configured HOME_MODE is malformed."
    else:
        try:
            configured_umask = int(login_values.get("UMASK", "022"), 8)
        except ValueError:
            return None, None, "The configured UMASK is malformed."
        configured_home_mode = 0o777 & ~configured_umask
    if configured_home_mode < 0 or configured_home_mode > 0o777 or configured_home_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return None, None, "The configured home mode allows group/world writes, so home creation is refused."
    blocked_roots = (Path("/proc"), Path("/sys"), Path("/dev"), Path("/run"))
    if (
        not base.is_absolute()
        or ".." in base.parts
        or any(ord(character) < 32 or ord(character) == 127 for character in home_base)
        or any(base == root or root in base.parents for root in blocked_roots)
    ):
        return None, None, "The effective useradd home base is not an allowed absolute directory."
    current = Path("/")
    base_info: os.stat_result | None = None
    try:
        for component in base.parts[1:]:
            current = current / component
            info = current.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                return None, None, "The useradd home base path must use root-owned real directories without symlinks or group/world write access."
            base_info = info
        if base_info is None:
            return None, None, "The filesystem root cannot be the useradd home base."
        if base_info.st_uid != 0 or base_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return None, None, "The useradd home base must be root-owned and not group/world writable."
        home = base / username
        try:
            home.lstat()
        except FileNotFoundError:
            pass
        else:
            return None, None, "The requested user's default home path already exists."
    except OSError:
        return None, None, "The effective useradd home base could not be inspected safely."
    identity = (
        base_info.st_dev,
        base_info.st_ino,
        base_info.st_mode,
        base_info.st_uid,
        base_info.st_gid,
        base_info.st_mtime_ns,
        base_info.st_ctime_ns,
    )
    return home, identity, None


def _path_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _safe_home_parent(path: Path, label: str) -> tuple[tuple[int, ...] | None, str | None]:
    if (
        not path.is_absolute()
        or ".." in path.parts
        or not any(base == path or base in path.parents for base in HOME_BASE_PATHS)
    ):
        return None, f"The {label} must be beneath /home or /var/home."
    current = Path("/")
    identity: tuple[int, ...] | None = None
    try:
        for component in path.parts[1:]:
            current = current / component
            info = current.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                return None, f"Every directory in the {label} path must be a real root-owned directory without group/world write access."
            identity = _path_identity(info)
    except OSError:
        return None, f"The {label} path could not be inspected safely."
    return identity, None


def _home_has_nested_mount(path: Path) -> tuple[bool | None, str | None]:
    contents, error = _read_file(MOUNT_INFO_PATH, MAX_IDENTITY_FILE_BYTES)
    if error or contents is None:
        return None, error or "The current mount table could not be inspected."
    try:
        lines = contents.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        return None, "The current mount table is not valid UTF-8."
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            return None, "The current mount table contains a malformed entry."
        raw_mountpoint = fields[4]
        decoded = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), raw_mountpoint)
        mountpoint = Path(decoded)
        if not mountpoint.is_absolute():
            return None, "The current mount table contains a non-absolute mountpoint."
        if mountpoint == path or path in mountpoint.parents:
            return True, None
    return False, None


def _planned_home_removal(
    uid: int,
    current_home: str,
) -> tuple[Path | None, tuple[int, ...] | None, Path | None, tuple[int, ...] | None, str | None, int, int, str | None]:
    if uid == 0:
        return None, None, None, None, None, 0, 0, "The root account's home directory cannot be removed by this tool."
    if not isinstance(current_home, str) or not current_home or len(current_home) > 4096:
        return None, None, None, None, None, 0, 0, "The existing user home path could not be verified."
    home = Path(current_home)
    if (
        not home.is_absolute()
        or str(home) != current_home
        or home.name in {"", ".", ".."}
        or any(ord(character) < 32 or ord(character) == 127 for character in current_home)
        or not any(base != home and base in home.parents for base in HOME_BASE_PATHS)
    ):
        return None, None, None, None, None, 0, 0, "The existing home must be one canonical path beneath /home or /var/home."
    parent = home.parent
    parent_identity, error = _safe_home_parent(parent, "current home parent")
    if error or parent_identity is None:
        return None, None, None, None, None, 0, 0, error or "The current home parent could not be verified."
    try:
        home_info = home.lstat()
        parent_info = parent.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(home_info.st_mode)
            or stat.S_ISLNK(home_info.st_mode)
            or home_info.st_uid != uid
            or home_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or home_info.st_dev != parent_info.st_dev
        ):
            return None, None, None, None, None, 0, 0, "The existing home must be a real, non-shared-writable directory owned by this user and not a mountpoint."
    except OSError:
        return None, None, None, None, None, 0, 0, "The existing home directory could not be inspected safely."
    nested_mount, error = _home_has_nested_mount(home)
    if error or nested_mount is None:
        return None, None, None, None, None, 0, 0, error or "The current home mount state could not be verified."
    if nested_mount:
        return None, None, None, None, None, 0, 0, "The current home contains a mounted filesystem; removing it is refused."
    parent_fd: int | None = None
    home_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(parent, HOME_PARENT_FLAGS)
        opened_parent = os.fstat(parent_fd)
        if _path_identity(opened_parent) != parent_identity:
            return None, None, None, None, None, 0, 0, "The current home parent changed during inspection."
        entry = os.stat(home.name, dir_fd=parent_fd, follow_symlinks=False)
        if _path_identity(entry) != _path_identity(home_info) or not stat.S_ISDIR(entry.st_mode):
            return None, None, None, None, None, 0, 0, "The current home changed during inspection."
        if not shutil.rmtree.avoids_symlink_attacks:
            return None, None, None, None, None, 0, 0, "This Python build does not provide symlink-resistant recursive deletion."
        home_fd = os.open(home.name, HOME_PARENT_FLAGS, dir_fd=parent_fd)
        if _path_identity(os.fstat(home_fd)) != _path_identity(entry):
            return None, None, None, None, None, 0, 0, "The current home changed while it was opened."
        tree_sha, entries, total_bytes, error = _snapshot_tree_fd(home_fd)
        if error or tree_sha is None:
            return None, None, None, None, None, 0, 0, error or "The current home tree could not be inspected completely."
        if _path_identity(os.fstat(home_fd)) != _path_identity(entry):
            return None, None, None, None, None, 0, 0, "The current home changed while it was inspected."
        return (
            home,
            _path_identity(home_info),
            parent,
            parent_identity,
            tree_sha,
            entries,
            total_bytes,
            None,
        )
    except OSError:
        return None, None, None, None, None, 0, 0, "The current home tree could not be inspected safely."
    finally:
        for descriptor in (home_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _planned_home_move(
    uid: int,
    current_home: str,
    requested_home: str | None,
) -> tuple[Path | None, Path | None, tuple[int, ...] | None, tuple[int, ...] | None, tuple[int, ...] | None, str | None]:
    if uid == 0:
        return None, None, None, None, None, "The root account's home directory cannot be moved by this tool."
    if not isinstance(requested_home, str) or not requested_home or len(requested_home) > 4096:
        return None, None, None, None, None, "home_directory must be one exact absolute destination path."
    source = Path(current_home)
    destination = Path(requested_home)
    if (
        not source.is_absolute()
        or str(source) != current_home
        or not destination.is_absolute()
        or str(destination) != requested_home
        or any(ord(character) < 32 or ord(character) == 127 for character in current_home + requested_home)
        or source.name in {"", ".", ".."}
        or destination.name in {"", ".", ".."}
    ):
        return None, None, None, None, None, "The current and requested home paths must be canonical absolute paths."
    if source == destination or source in destination.parents or destination in source.parents:
        return None, None, None, None, None, "The requested home path must be separate from the current home tree."
    source_parent_identity, error = _safe_home_parent(source.parent, "current home parent")
    if error or source_parent_identity is None:
        return None, None, None, None, None, error or "The current home parent could not be verified."
    destination_parent_identity, error = _safe_home_parent(destination.parent, "destination parent")
    if error or destination_parent_identity is None:
        return None, None, None, None, None, error or "The destination parent could not be verified."
    try:
        source_info = source.lstat()
        if (
            not stat.S_ISDIR(source_info.st_mode)
            or stat.S_ISLNK(source_info.st_mode)
            or source_info.st_uid != uid
            or source_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or source_info.st_dev != source.parent.stat(follow_symlinks=False).st_dev
        ):
            return None, None, None, None, None, "The existing home must be a real, non-shared-writable directory owned by this user and not a mountpoint."
    except OSError:
        return None, None, None, None, None, "The existing home directory could not be inspected safely."
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        return None, None, None, None, None, "The requested destination could not be inspected safely."
    else:
        return None, None, None, None, None, "The requested home destination already exists."
    nested_mount, error = _home_has_nested_mount(source)
    if error or nested_mount is None:
        return None, None, None, None, None, error or "The current home mount state could not be verified."
    if nested_mount:
        return None, None, None, None, None, "The current home contains a mounted filesystem; moving it is refused."
    return (
        source,
        destination,
        _path_identity(source_info),
        source_parent_identity,
        destination_parent_identity,
        None,
    )


def local_identity_action_confirmation_details(
    action: str,
    username: str | None = None,
    group_name: str | None = None,
    login_shell: str | None = None,
    create_home: bool = False,
    home_directory: str | None = None,
    remove_home: bool = False,
) -> tuple[LocalIdentityTarget | None, str | None, str | None]:
    actions = {"create_user", "delete_user", "lock_user", "unlock_user", "set_shell", "move_home", "create_group", "delete_group", "add_user_to_group", "remove_user_from_group"}
    if not sys.platform.startswith("linux"):
        return None, None, "Local account administration is available only on Linux."
    if not isinstance(action, str) or action not in actions:
        return None, None, "The requested local identity action is unsupported."
    if not isinstance(create_home, bool):
        return None, None, "create_home must be a boolean."
    if not isinstance(remove_home, bool):
        return None, None, "remove_home must be a boolean."
    if action != "create_user" and create_home:
        return None, None, "create_home applies only to create_user."
    if action != "delete_user" and remove_home:
        return None, None, "remove_home applies only to delete_user."
    if action != "move_home" and home_directory is not None:
        return None, None, "home_directory applies only to move_home."
    requested_home_directory = home_directory
    if not local_identity_control_available():
        return None, None, "The shadow-utils user/group commands and local passwd/group files are required."
    require_user = action in {"create_user", "delete_user", "lock_user", "unlock_user", "set_shell", "move_home", "add_user_to_group", "remove_user_from_group"}
    require_group = action in {"create_group", "delete_group", "add_user_to_group", "remove_user_from_group", "create_user"}
    if require_user:
        if not isinstance(username, str) or not LOCAL_NAME_RE.fullmatch(username):
            return None, None, "username must be one exact local name using lowercase letters, digits, underscores, or hyphens."
    elif username is not None:
        return None, None, "username is not used for this action."
    if require_group:
        if not isinstance(group_name, str) or not LOCAL_NAME_RE.fullmatch(group_name):
            return None, None, "group_name must be one exact local name using lowercase letters, digits, underscores, or hyphens."
    elif group_name is not None:
        return None, None, "group_name is not used for this action."

    selected_shell: str | None = None
    home_directory: Path | None = None
    home_base_identity: tuple[int, ...] | None = None
    source_home_directory: Path | None = None
    source_home_identity: tuple[int, ...] | None = None
    source_parent_identity: tuple[int, ...] | None = None
    home_parent_path: Path | None = None
    home_parent_identity: tuple[int, ...] | None = None
    home_tree_sha256: str | None = None
    home_tree_entries = 0
    home_tree_bytes = 0
    if action == "create_user":
        selected_shell, error = _validated_shell(login_shell, allow_default=True)
        if error or selected_shell is None:
            return None, None, error or "The login shell could not be verified."
        if create_home:
            home_directory, home_base_identity, error = _planned_home_directory(username or "")
            if error or home_directory is None or home_base_identity is None:
                return None, None, error or "The requested user home directory could not be verified."
    elif action == "set_shell":
        selected_shell, error = _validated_shell(login_shell)
        if error or selected_shell is None:
            return None, None, error or "The login shell could not be verified."
    elif login_shell is not None:
        return None, None, "login_shell is used only for create_user or set_shell."

    side_effect_digest, side_effect_notes, error = _side_effect_policy(
        action,
        include_home_skeleton=action == "create_user" and create_home,
    )
    if error or side_effect_digest is None:
        return None, None, error or "Shadow-utils side effects could not be bounded."
    users, groups, files_digest, error = _parse_local_state()
    if error or files_digest is None:
        return None, None, error or "Local account state could not be read safely."
    current_user = users.get(username or "")
    current_group = groups.get(group_name or "")
    password_state: str | None = None
    if action == "create_user":
        if current_user is not None:
            return None, None, "The exact local username already exists."
        if current_group is None:
            return None, None, "The selected primary group must already exist in /etc/group."
    elif action == "delete_user":
        if current_user is None:
            return None, None, "The exact local user does not exist."
        if current_user[1] == 0:
            return None, None, "The root account cannot be deleted by this tool."
        if remove_home:
            (
                source_home_directory,
                source_home_identity,
                home_parent_path,
                home_parent_identity,
                home_tree_sha256,
                home_tree_entries,
                home_tree_bytes,
                error,
            ) = _planned_home_removal(current_user[1], current_user[3])
            if error or source_home_directory is None or source_home_identity is None or home_parent_path is None or home_parent_identity is None or home_tree_sha256 is None:
                return None, None, error or "The existing home directory could not be verified for removal."
    elif action == "move_home":
        if current_user is None:
            return None, None, "The exact local user does not exist."
        (
            source_home_directory,
            home_directory,
            source_home_identity,
            source_parent_identity,
            home_parent_identity,
            error,
        ) = _planned_home_move(current_user[1], current_user[3], requested_home_directory)
        if error or source_home_directory is None or home_directory is None:
            return None, None, error or "The existing home move could not be verified."
        home_parent_path = home_directory.parent
    elif action in {"lock_user", "unlock_user", "set_shell"}:
        if current_user is None:
            return None, None, "The exact local user does not exist."
        if current_user[1] == 0 and action == "set_shell":
            return None, None, "The root account's shell cannot be changed by this tool."
        if action == "lock_user":
            password_state = _password_state(username or "")
            if password_state is None:
                return None, None, "The current account password state could not be checked."
            if password_state in LOCKED_PASSWORD_STATES:
                return None, None, "The account password is already locked."
        elif action == "unlock_user":
            password_state = _password_state(username or "")
            if password_state is None:
                return None, None, "The current account password state could not be checked."
            if password_state not in LOCKED_PASSWORD_STATES:
                return None, None, "The account password is not currently locked."
            if _shadow_password_hash_usable(username or "") is not True:
                return None, None, "The account has no verifiable local password hash to unlock; set a password first."
    elif action == "create_group":
        if current_group is not None:
            return None, None, "The exact local group already exists."
    elif action == "delete_group":
        if current_group is None:
            return None, None, "The exact local group does not exist."
        primary_users = [record[0] for record in users.values() if record[2] == current_group[1]]
        if primary_users or current_group[2]:
            return None, None, "A group used as a primary group or containing secondary members cannot be deleted."
    else:
        if current_user is None or current_group is None:
            return None, None, "The exact local user and group must both exist."
        primary_member = current_user[2] == current_group[1]
        is_secondary = username in current_group[2]
        if action == "add_user_to_group" and (is_secondary or primary_member):
            return None, None, "The user is already a member of this group."
        if action == "remove_user_from_group" and primary_member:
            return None, None, "A user's primary group cannot be removed as a secondary membership."
        if action == "remove_user_from_group" and not is_secondary:
            return None, None, "The user is not a secondary member of this group."

    details = {
        "action": action,
        "username": username,
        "group_name": group_name,
        "login_shell": selected_shell,
        "create_home": create_home,
        "home_directory": str(home_directory) if home_directory is not None else None,
        "home_base_identity": home_base_identity,
        "source_home_directory": str(source_home_directory) if source_home_directory is not None else None,
        "source_home_identity": source_home_identity,
        "source_parent_identity": source_parent_identity,
        "home_parent_path": str(home_parent_path) if home_parent_path is not None else None,
        "home_parent_identity": home_parent_identity,
        "remove_home": remove_home,
        "home_tree_sha256": home_tree_sha256,
        "home_tree_entries": home_tree_entries,
        "home_tree_bytes": home_tree_bytes,
        "current_user": current_user,
        "current_group": current_group,
        "password_state": password_state,
        "side_effect_digest": side_effect_digest,
        "side_effect_notes": side_effect_notes,
        "files_digest": files_digest,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = LocalIdentityTarget(
        action=action,  # type: ignore[arg-type]
        username=username,
        group_name=group_name,
        login_shell=selected_shell,
        current_user=current_user,
        current_group=current_group,
        password_state=password_state,
        side_effect_notes=side_effect_notes,
        files_digest=hashlib.sha256((files_digest + side_effect_digest).encode("ascii")).hexdigest(),
        state_digest=digest,
        create_home=create_home,
        home_directory=str(home_directory) if home_directory is not None else None,
        source_home_directory=str(source_home_directory) if source_home_directory is not None else None,
        source_home_identity=source_home_identity,
        source_parent_identity=source_parent_identity,
        home_parent_path=str(home_parent_path) if home_parent_path is not None else None,
        home_parent_identity=home_parent_identity,
        remove_home=remove_home,
        home_tree_sha256=home_tree_sha256,
        home_tree_entries=home_tree_entries,
        home_tree_bytes=home_tree_bytes,
    )
    phrase = hashlib.sha256((action + ":" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"identity {phrase}", None


def _action_command(target: LocalIdentityTarget) -> list[str] | None:
    env = _environment()
    action, username, group_name = target.action, target.username, target.group_name
    if action == "create_user":
        binary = find_session_binary("useradd", env)
        if not binary or not group_name or not target.current_group or not target.login_shell:
            return None
        home_args = ["--create-home", "--home-dir", target.home_directory] if target.create_home and target.home_directory else ["--no-create-home"]
        return [binary, *home_args, "--gid", str(target.current_group[1]), "--shell", target.login_shell, "--password", "!", username or ""]
    if action == "delete_user":
        binary = find_session_binary("userdel", env)
        return [binary, username or ""] if binary else None
    if action == "lock_user":
        binary = find_session_binary("usermod", env)
        return [binary, "--lock", username or ""] if binary else None
    if action == "unlock_user":
        binary = find_session_binary("usermod", env)
        return [binary, "--unlock", username or ""] if binary else None
    if action == "set_shell":
        binary = find_session_binary("usermod", env)
        return [binary, "--shell", target.login_shell or "", username or ""] if binary else None
    if action == "move_home":
        binary = find_session_binary("usermod", env)
        if not binary or not target.home_directory or not target.source_home_directory:
            return None
        return [binary, "--home", target.home_directory, "--move-home", username or ""]
    if action == "create_group":
        binary = find_session_binary("groupadd", env)
        return [binary, group_name or ""] if binary else None
    if action == "delete_group":
        binary = find_session_binary("groupdel", env)
        return [binary, group_name or ""] if binary else None
    binary = find_session_binary("gpasswd", env)
    if not binary:
        return None
    verb = "--add" if action == "add_user_to_group" else "--delete"
    return [binary, verb, username or "", group_name or ""]


def _remove_confirmed_home(target: LocalIdentityTarget) -> tuple[bool, str | None]:
    if (
        not target.remove_home
        or not target.username
        or target.current_user is None
        or target.current_user[0] != target.username
        or target.current_user[1] == 0
        or not target.source_home_directory
        or target.source_home_identity is None
        or not target.home_parent_path
        or target.home_parent_identity is None
        or target.home_tree_sha256 is None
    ):
        return False, "The confirmed home-tree removal target is incomplete."
    users, _groups, _digest, state_error = _parse_local_state()
    if state_error or users.get(target.username) is not None:
        return False, state_error or "The local user still exists after the account-delete command."
    home = Path(target.source_home_directory)
    parent = Path(target.home_parent_path)
    if home.parent != parent or not shutil.rmtree.avoids_symlink_attacks:
        return False, "The confirmed home path or symlink-resistant deletion support could not be revalidated."
    nested_mount, error = _home_has_nested_mount(home)
    if error or nested_mount is None or nested_mount:
        return False, error or "A mounted filesystem appeared in the home tree; removal was stopped."
    parent_fd: int | None = None
    home_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(parent, HOME_PARENT_FLAGS)
        if _path_identity(os.fstat(parent_fd)) != target.home_parent_identity:
            return False, "The home parent changed after account deletion; the home tree was left in place."
        entry = os.stat(home.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            _path_identity(entry) != target.source_home_identity
            or not stat.S_ISDIR(entry.st_mode)
            or stat.S_ISLNK(entry.st_mode)
            or entry.st_uid != target.current_user[1]
            or entry.st_dev != os.fstat(parent_fd).st_dev
        ):
            return False, "The home directory identity changed after account deletion; the home tree was left in place."
        home_fd = os.open(home.name, HOME_PARENT_FLAGS, dir_fd=parent_fd)
        if _path_identity(os.fstat(home_fd)) != target.source_home_identity:
            return False, "The opened home directory changed after account deletion; the home tree was left in place."
        tree_sha, entries, total_bytes, error = _snapshot_tree_fd(home_fd)
        if error or tree_sha != target.home_tree_sha256 or entries != target.home_tree_entries or total_bytes != target.home_tree_bytes:
            return False, error or "The confirmed home tree changed after account deletion; the home tree was left in place."
        if _path_identity(os.fstat(home_fd)) != target.source_home_identity:
            return False, "The home directory changed during final verification; the home tree was left in place."
        nested_mount, error = _home_has_nested_mount(home)
        if error or nested_mount is None or nested_mount:
            return False, error or "A mounted filesystem appeared in the home tree; removal was stopped."
        os.close(home_fd)
        home_fd = None
        shutil.rmtree(home.name, dir_fd=parent_fd)
        try:
            os.stat(home.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            return False, "The account was deleted, but the home path remains after recursive removal."
        os.fsync(parent_fd)
        return True, None
    except OSError as exc:
        return False, f"The account was deleted, but home-tree removal failed: {exc.strerror or type(exc).__name__}."
    finally:
        for descriptor in (home_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _verify_action(target: LocalIdentityTarget) -> bool:
    users, groups, _digest, error = _parse_local_state()
    if error:
        return False
    action, username, group_name = target.action, target.username, target.group_name
    user = users.get(username or "")
    group = groups.get(group_name or "")
    if action == "create_user":
        home_matches = True
        if target.create_home and target.home_directory:
            try:
                home_info = os.lstat(target.home_directory)
                home_matches = (
                    stat.S_ISDIR(home_info.st_mode)
                    and not stat.S_ISLNK(home_info.st_mode)
                    and user is not None
                    and home_info.st_uid == user[1]
                    and home_info.st_gid == user[2]
                    and not (home_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
                    and user[3] == target.home_directory
                )
            except OSError:
                home_matches = False
        return (
            user is not None
            and target.current_group is not None
            and user[2] == target.current_group[1]
            and user[4] == target.login_shell
            and _password_state(username or "") in LOCKED_PASSWORD_STATES
            and home_matches
        )
    if action == "delete_user":
        if user is not None:
            return False
        if not target.remove_home or not target.source_home_directory:
            return True
        try:
            os.lstat(target.source_home_directory)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return False
    if action == "move_home":
        if (
            user is None
            or target.home_directory is None
            or target.source_home_directory is None
            or user[3] != target.home_directory
        ):
            return False
        try:
            destination_info = os.lstat(target.home_directory)
            if (
                not stat.S_ISDIR(destination_info.st_mode)
                or stat.S_ISLNK(destination_info.st_mode)
                or destination_info.st_uid != user[1]
                or destination_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                return False
            try:
                with os.scandir(target.source_home_directory) as entries:
                    if next(entries, None) is not None:
                        return False
            except FileNotFoundError:
                pass
            except OSError:
                return False
        except OSError:
            return False
        return True
    if action == "create_group":
        return group is not None
    if action == "delete_group":
        return group is None
    if action == "set_shell":
        return user is not None and user[4] == target.login_shell
    if action == "lock_user":
        return _password_state(username or "") in LOCKED_PASSWORD_STATES
    if action == "unlock_user":
        return _password_state(username or "") == "P"
    if user is None or group is None:
        return False
    member = username in group[2]
    return member if action == "add_user_to_group" else not member


def perform_local_identity_action(
    action: LocalIdentityAction,
    username: str | None = None,
    group_name: str | None = None,
    login_shell: str | None = None,
    create_home: bool = False,
    home_directory: str | None = None,
    remove_home: bool = False,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> LocalIdentityActionResponse:
    target, phrase, error = local_identity_action_confirmation_details(action, username, group_name, login_shell, create_home, home_directory, remove_home)
    if error or target is None or phrase is None:
        return LocalIdentityActionResponse(success=False, action=action, username=username, group_name=group_name, user_confirmed=confirmed is True, message=error or "The local identity request could not be verified.")
    if confirmed is not True:
        return LocalIdentityActionResponse(success=False, action=action, username=username, group_name=group_name, user_confirmed=False, message="Explicit client confirmation is required; no account command was run.")
    if confirmation_phrase != phrase:
        return LocalIdentityActionResponse(success=False, action=action, username=username, group_name=group_name, user_confirmed=True, message="Confirmation did not match the exact local account/group state and requested change.")
    current, current_phrase, error = local_identity_action_confirmation_details(action, username, group_name, login_shell, create_home, home_directory, remove_home)
    if error or current is None or current_phrase != phrase:
        return LocalIdentityActionResponse(success=False, action=action, username=username, group_name=group_name, user_confirmed=True, message=error or "Local account state changed after confirmation; no command was run.")
    command = _action_command(target)
    if not command:
        return LocalIdentityActionResponse(success=False, action=action, username=username, group_name=group_name, user_confirmed=True, message="The exact local account command is unavailable.")
    result = _run(
        command,
        timeout_seconds=HOME_MOVE_TIMEOUT_SECONDS if action == "move_home" else COMMAND_TIMEOUT_SECONDS,
    )
    if result is None or result[0] != 0:
        return LocalIdentityActionResponse(success=False, action=action, username=username, group_name=group_name, user_confirmed=True, message="The local account command did not complete successfully; inspect account state before retrying.")
    if target.remove_home:
        removed, removal_error = _remove_confirmed_home(target)
        if not removed:
            return LocalIdentityActionResponse(success=False, action=action, username=username, group_name=group_name, user_confirmed=True, message=removal_error or "The account was deleted, but its confirmed home tree was not fully removed; inspect the path before retrying.")
    if not _verify_action(target):
        return LocalIdentityActionResponse(success=False, action=action, username=username, group_name=group_name, user_confirmed=True, message="The account command returned successfully, but the resulting local identity state could not be verified.")
    message = (
        f"Created and verified the confirmed local user and home directory at {target.home_directory}."
        if action == "create_user" and target.create_home and target.home_directory
        else f"Moved and verified the home directory for local user {username!r} to {target.home_directory}."
        if action == "move_home" and target.home_directory
        else f"Deleted the confirmed local user and removed the bounded home tree at {target.source_home_directory}."
        if action == "delete_user" and target.remove_home and target.source_home_directory
        else "Applied and verified the confirmed local identity change."
    )
    return LocalIdentityActionResponse(success=True, action=action, username=username, group_name=group_name, user_confirmed=True, message=message)
