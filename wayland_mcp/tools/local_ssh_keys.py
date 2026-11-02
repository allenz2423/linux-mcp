"""Confirmed management of plain local OpenSSH authorized_keys entries."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from wayland_mcp.models import LocalSSHKeyActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.accounts_control import (
    LOCAL_NAME_RE,
    MAX_IDENTITY_FILE_BYTES,
    PASSWD_PATH,
    _parse_local_state,
    _read_file,
)
from wayland_mcp.tools.filesystem_write import (
    MAX_TEXT_FILE_BYTES,
    _protected_xattr_error,
    _read_fd_limited,
    _replace_fd_contents,
    _write_fd_all,
)

SSHKeyAction = Literal["add", "remove"]
_KEY_TYPE_RE = re.compile(r"^[A-Za-z0-9@._+-]{1,128}$")
_MAX_KEY_LINE_BYTES = 16 * 1024
_MAX_AUTHORIZED_KEYS_LINES = 4096
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_LOCK = threading.RLock()


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
class _SSHKeyTarget:
    action: SSHKeyAction
    username: str
    uid: int
    gid: int
    home_path: str
    passwd_digest: str
    home_metadata: _Metadata
    ssh_metadata: _Metadata | None
    authorized_keys_metadata: _Metadata | None
    authorized_keys_content: bytes | None = field(repr=False)
    new_content: bytes = field(repr=False)
    key_type: str
    key_base64: str
    key_blob: bytes = field(repr=False)
    fingerprint: str
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def local_ssh_key_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    try:
        info = PASSWD_PATH.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and not (info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
        and find_session_binary("ssh-keygen", selected) is not None
    )


def _fingerprint_key(public_key: object) -> tuple[str | None, str | None, bytes | None, str | None, str | None]:
    if not isinstance(public_key, str) or not public_key or len(public_key.encode("utf-8", errors="ignore")) > _MAX_KEY_LINE_BYTES:
        return None, None, None, None, "public_key must be one OpenSSH public-key line no larger than 16 KiB."
    if any(ord(character) < 32 or ord(character) == 127 for character in public_key):
        return None, None, None, None, "public_key cannot contain control characters or line breaks."
    fields = public_key.split()
    if len(fields) < 2 or not _KEY_TYPE_RE.fullmatch(fields[0]):
        return None, None, None, None, "public_key must start with one OpenSSH key type and base64 key blob; key options are not accepted."
    try:
        blob = base64.b64decode(fields[1].encode("ascii"), validate=True)
    except (UnicodeError, ValueError):
        return None, None, None, None, "public_key does not contain a valid base64 key blob."
    if not blob or len(blob) > _MAX_KEY_LINE_BYTES:
        return None, None, None, None, "The decoded public key is empty or too large."
    binary = find_session_binary("ssh-keygen", _environment())
    if not binary:
        return None, None, None, None, "The local ssh-keygen command is unavailable."
    descriptor = -1
    path: str | None = None
    try:
        descriptor, path = tempfile.mkstemp(prefix="linux-mcp-public-key-", suffix=".pub")
        os.fchmod(descriptor, 0o600)
        content = f"{fields[0]} {fields[1]}\n".encode("ascii")
        _write_fd_all(descriptor, content)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        result = subprocess.run(
            [binary, "-lf", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            env=_environment(),
            close_fds=True,
        )
        if result.returncode != 0 or len(result.stdout) > 4096:
            return None, None, None, None, "ssh-keygen could not validate the supplied OpenSSH public key."
        try:
            output = result.stdout.decode("utf-8", errors="strict").split()
        except UnicodeError:
            return None, None, None, None, "ssh-keygen returned an invalid fingerprint response."
        if len(output) < 2 or not output[1].startswith("SHA256:"):
            return None, None, None, None, "ssh-keygen did not return a SHA256 fingerprint for the supplied key."
        return fields[0], fields[1], blob, output[1], None
    except (OSError, subprocess.TimeoutExpired):
        return None, None, None, None, "The supplied public key could not be checked with ssh-keygen."
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                pass


def _open_directory_chain(path: Path) -> int:
    if not path.is_absolute():
        raise OSError("The local home directory is not absolute.")
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("The local home directory is not a directory.")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _account_home(username: str) -> tuple[int, int, str, str, _Metadata]:
    users, _groups, passwd_group_digest, error = _parse_local_state()
    if error or passwd_group_digest is None:
        raise ValueError(error or "Local account files could not be read safely.")
    account = users.get(username)
    if account is None:
        raise ValueError("The exact local user does not exist.")
    passwd_data, error = _read_file(PASSWD_PATH, MAX_IDENTITY_FILE_BYTES)
    if error or passwd_data is None:
        raise ValueError(error or "The local passwd file could not be read safely.")
    try:
        records = [line.split(":") for line in passwd_data.decode("utf-8", errors="strict").splitlines() if line.split(":", 1)[0] == username]
    except UnicodeError as exc:
        raise ValueError("The local passwd file is not valid UTF-8.") from exc
    if len(records) != 1 or len(records[0]) != 7:
        raise ValueError("The exact local passwd entry could not be verified.")
    fields = records[0]
    if fields[0] != username or fields[5] == "/" or not fields[5].startswith("/") or len(fields[5]) > 4096:
        raise ValueError("The local account must have a bounded absolute home directory other than '/'.")
    if any(component in {".", ".."} for component in fields[5].split("/")):
        raise ValueError("The local account home path contains a dot or parent component.")
    try:
        uid, gid = int(fields[2], 10), int(fields[3], 10)
        if (uid == 0) != (username == "root"):
            raise ValueError("UID 0 SSH keys are supported only for the exact root account entry.")
        if (uid, gid) != (account[1], account[2]):
            raise ValueError("The local account changed while its home directory was being resolved.")
        users_after, _groups_after, digest_after, error_after = _parse_local_state()
        if error_after or digest_after != passwd_group_digest or users_after.get(username) != account:
            raise ValueError("The local account files changed while its home directory was being resolved.")
        home = Path(fields[5]).resolve(strict=True)
        if home == Path("/") or any(home == blocked or blocked in home.parents for blocked in (Path("/proc"), Path("/sys"), Path("/dev"), Path("/run"))):
            raise ValueError("Home directories under /proc, /sys, /dev, or /run are not supported.")
        descriptor = _open_directory_chain(home)
        try:
            info = os.fstat(descriptor)
            metadata = _metadata(info)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in {uid, 0}
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise ValueError("The home directory must be owned by the account or root and not writable by group or other users.")
        finally:
            os.close(descriptor)
    except (OSError, RuntimeError, ValueError) as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("The exact local home directory could not be safely opened.") from exc
    passwd_digest = hashlib.sha256(passwd_data + b"\x00" + passwd_group_digest.encode("ascii")).hexdigest()
    return uid, gid, str(home), passwd_digest, metadata


def _authorized_keys_snapshot(
    home_path: str,
    uid: int,
    home_metadata: _Metadata,
) -> tuple[_Metadata | None, _Metadata | None, bytes | None]:
    home_fd = _open_directory_chain(Path(home_path))
    try:
        if _metadata(os.fstat(home_fd)) != home_metadata:
            raise ValueError("The home directory changed while the key request was being checked.")
        try:
            ssh_info = os.stat(".ssh", dir_fd=home_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None, None, None
        ssh_metadata = _metadata(ssh_info)
        if (
            not stat.S_ISDIR(ssh_info.st_mode)
            or ssh_info.st_uid not in {uid, 0}
            or ssh_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError("The account .ssh path must be a real directory, owned by the account or root, and not writable by group or other users.")
        ssh_fd = os.open(".ssh", _DIRECTORY_FLAGS, dir_fd=home_fd)
        try:
            if _metadata(os.fstat(ssh_fd)) != ssh_metadata:
                raise ValueError("The account .ssh directory changed while the key request was being checked.")
            try:
                key_info = os.stat("authorized_keys", dir_fd=ssh_fd, follow_symlinks=False)
            except FileNotFoundError:
                return ssh_metadata, None, None
            key_metadata = _metadata(key_info)
            if (
                not stat.S_ISREG(key_info.st_mode)
                or key_info.st_nlink != 1
                or key_info.st_uid not in {uid, 0}
                or key_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
                or key_info.st_size > MAX_TEXT_FILE_BYTES
            ):
                raise ValueError("authorized_keys must be a bounded, single-link regular file owned by the account or root and not writable by group or other users.")
            key_fd = os.open("authorized_keys", os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=ssh_fd)
            try:
                opened = _metadata(os.fstat(key_fd))
                if opened != key_metadata:
                    raise ValueError("authorized_keys changed while the key request was being checked.")
                content = bytearray()
                while len(content) <= MAX_TEXT_FILE_BYTES:
                    chunk = os.read(key_fd, min(65536, MAX_TEXT_FILE_BYTES + 1 - len(content)))
                    if not chunk:
                        break
                    content.extend(chunk)
                after = _metadata(os.fstat(key_fd))
                path_after = _metadata(os.stat("authorized_keys", dir_fd=ssh_fd, follow_symlinks=False))
            finally:
                os.close(key_fd)
            if len(content) > MAX_TEXT_FILE_BYTES or after != key_metadata or path_after != key_metadata:
                raise ValueError("authorized_keys changed or exceeded its size limit while being read.")
            try:
                text = bytes(content).decode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise ValueError("authorized_keys is not valid UTF-8 and cannot be edited safely.") from exc
            if any((ord(character) < 32 and character not in "\t\n\r") or ord(character) == 127 for character in text):
                raise ValueError("authorized_keys contains unsupported control characters.")
            if len(text.splitlines()) > _MAX_AUTHORIZED_KEYS_LINES:
                raise ValueError("authorized_keys exceeds the supported line limit.")
            return ssh_metadata, key_metadata, bytes(content)
        finally:
            os.close(ssh_fd)
    finally:
        os.close(home_fd)


def _line_identity(line: bytes) -> tuple[str, bytes] | None:
    if line.lstrip().startswith(b"#"):
        return None
    tokens = line.strip().split()
    for index, token in enumerate(tokens[:-1]):
        try:
            key_type = token.decode("ascii", errors="strict")
        except UnicodeError:
            continue
        if not _KEY_TYPE_RE.fullmatch(key_type):
            continue
        if not key_type.startswith(("ssh-", "ecdsa-", "sk-")):
            continue
        try:
            blob = base64.b64decode(tokens[index + 1], validate=True)
        except (ValueError, UnicodeError):
            continue
        if blob:
            return key_type, blob
    return None


def _prepare_target(
    action: str,
    username: str,
    public_key: str,
) -> tuple[_SSHKeyTarget | None, str | None]:
    if not isinstance(action, str) or action not in {"add", "remove"}:
        return None, "The SSH key action must be add or remove."
    if not isinstance(username, str) or not LOCAL_NAME_RE.fullmatch(username):
        return None, "username must be one exact local account name."
    if not local_ssh_key_control_available():
        return None, "Local SSH key management requires Linux, a safe local /etc/passwd, and ssh-keygen."
    key_type, key_base64, key_blob, fingerprint, key_error = _fingerprint_key(public_key)
    if key_error is not None or key_type is None or key_base64 is None or key_blob is None or fingerprint is None:
        return None, key_error or "The public key could not be validated."
    try:
        uid, gid, home_path, passwd_digest, home_metadata = _account_home(username)
        ssh_metadata, auth_metadata, original = _authorized_keys_snapshot(home_path, uid, home_metadata)
    except (OSError, ValueError) as exc:
        return None, str(exc) or "Local account SSH-key state could not be checked."
    if action == "remove" and (ssh_metadata is None or auth_metadata is None or original is None):
        return None, "The exact account has no existing authorized_keys entry to remove."
    original = original or b""
    matching = [_line_identity(line) == (key_type, key_blob) for line in original.splitlines(keepends=True)]
    if action == "add":
        if any(matching):
            return None, "That public key is already present in this account's authorized_keys file."
        separator = b"" if not original or original.endswith((b"\n", b"\r")) else b"\n"
        new_content = original + separator + f"{key_type} {key_base64}\n".encode("ascii")
    else:
        if not any(matching):
            return None, "The exact public key is not present in this account's authorized_keys file."
        new_content = b"".join(line for line, is_match in zip(original.splitlines(keepends=True), matching) if not is_match)
    if len(new_content) > MAX_TEXT_FILE_BYTES:
        return None, f"The updated authorized_keys file would exceed {MAX_TEXT_FILE_BYTES} bytes."
    if os.geteuid() not in {0, uid}:
        return None, "The current server identity must be root or the exact target account to manage its SSH keys."
    details = {
        "action": action,
        "username": username,
        "uid": uid,
        "gid": gid,
        "home_path": home_path,
        "passwd_digest": passwd_digest,
        "home_metadata": asdict(home_metadata),
        "ssh_metadata": asdict(ssh_metadata) if ssh_metadata else None,
        "authorized_keys_metadata": asdict(auth_metadata) if auth_metadata else None,
        "authorized_keys_sha256": hashlib.sha256(original).hexdigest() if auth_metadata else None,
        "key_type": key_type,
        "key_blob_sha256": hashlib.sha256(key_blob).hexdigest(),
        "fingerprint": fingerprint,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = _SSHKeyTarget(
        action=action,  # type: ignore[arg-type]
        username=username,
        uid=uid,
        gid=gid,
        home_path=home_path,
        passwd_digest=passwd_digest,
        home_metadata=home_metadata,
        ssh_metadata=ssh_metadata,
        authorized_keys_metadata=auth_metadata,
        authorized_keys_content=original if auth_metadata else None,
        new_content=new_content,
        key_type=key_type,
        key_base64=key_base64,
        key_blob=key_blob,
        fingerprint=fingerprint,
        state_digest=digest,
    )
    return target, None


def local_ssh_key_confirmation_details(
    action: str,
    username: str,
    public_key: str,
) -> tuple[str | None, str | None, str | None, str | None]:
    target, error = _prepare_target(action, username, public_key)
    if error or target is None:
        return None, None, None, error or "The local SSH key request could not be verified."
    phrase = "SSH-KEY-" + target.state_digest[:16].upper()
    return target.username, target.fingerprint, phrase, None


def _verify_directory(fd: int, expected: _Metadata) -> bool:
    return _metadata(os.fstat(fd)) == expected


def _verify_directory_path(target: _SSHKeyTarget, home_fd: int, ssh_fd: int) -> None:
    home_info = os.fstat(home_fd)
    expected_home = target.home_metadata
    if (home_info.st_dev, home_info.st_ino, home_info.st_uid, home_info.st_gid, home_info.st_mode) != (
        expected_home.device,
        expected_home.inode,
        expected_home.owner_uid,
        expected_home.owner_gid,
        expected_home.mode,
    ):
        raise OSError("The account home directory identity changed during the key operation.")
    reopened_home = _open_directory_chain(Path(target.home_path))
    try:
        reopened_info = os.fstat(reopened_home)
        if (reopened_info.st_dev, reopened_info.st_ino) != (home_info.st_dev, home_info.st_ino):
            raise OSError("The account home path no longer names the confirmed directory.")
    finally:
        os.close(reopened_home)
    ssh_info = os.fstat(ssh_fd)
    path_info = os.stat(".ssh", dir_fd=home_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(path_info.st_mode)
        or (path_info.st_dev, path_info.st_ino) != (ssh_info.st_dev, ssh_info.st_ino)
    ):
        raise OSError("The account .ssh path changed during the key operation.")


def _apply_target(target: _SSHKeyTarget) -> tuple[bool, str]:
    home_fd: int | None = None
    ssh_fd: int | None = None
    key_fd: int | None = None
    created_ssh = False
    created_key = False
    created_key_identity: tuple[int, int] | None = None
    success = False
    try:
        uid, gid, home_path, passwd_digest, home_metadata = _account_home(target.username)
        if (uid, gid, home_path, passwd_digest, home_metadata) != (
            target.uid,
            target.gid,
            target.home_path,
            target.passwd_digest,
            target.home_metadata,
        ):
            raise OSError("The local account or home-directory state changed immediately before the key operation.")
        home_fd = _open_directory_chain(Path(target.home_path))
        home_info = os.fstat(home_fd)
        if (home_info.st_dev, home_info.st_ino, home_info.st_uid, home_info.st_gid, home_info.st_mode) != (
            target.home_metadata.device,
            target.home_metadata.inode,
            target.home_metadata.owner_uid,
            target.home_metadata.owner_gid,
            target.home_metadata.mode,
        ):
            raise OSError("The account home directory identity changed after confirmation.")
        if target.ssh_metadata is None:
            if target.action != "add":
                raise OSError("The .ssh directory is missing; no key was removed.")
            os.mkdir(".ssh", 0o700, dir_fd=home_fd)
            created_ssh = True
            ssh_fd = os.open(".ssh", _DIRECTORY_FLAGS, dir_fd=home_fd)
            if os.geteuid() == 0:
                os.fchown(ssh_fd, target.uid, target.gid)
            os.fchmod(ssh_fd, 0o700)
            os.fsync(ssh_fd)
        else:
            ssh_fd = os.open(".ssh", _DIRECTORY_FLAGS, dir_fd=home_fd)
            if not _verify_directory(ssh_fd, target.ssh_metadata):
                raise OSError("The account .ssh directory identity changed after confirmation.")
        _verify_directory_path(target, home_fd, ssh_fd)

        if target.authorized_keys_metadata is None:
            if target.action != "add":
                raise OSError("authorized_keys is missing; no key was removed.")
            key_fd = os.open(
                "authorized_keys",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=ssh_fd,
            )
            created_key = True
            created_info = os.fstat(key_fd)
            created_key_identity = (created_info.st_dev, created_info.st_ino)
            if os.geteuid() == 0:
                os.fchown(key_fd, target.uid, target.gid)
            elif os.geteuid() != target.uid:
                raise OSError("The current server identity cannot own the new authorized_keys file.")
            os.fchmod(key_fd, 0o600)
            _write_fd_all(key_fd, target.new_content)
            os.fsync(key_fd)
            created_info = os.fstat(key_fd)
            path_info = os.stat("authorized_keys", dir_fd=ssh_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(created_info.st_mode)
                or created_info.st_nlink != 1
                or created_info.st_uid != target.uid
                or stat.S_IMODE(created_info.st_mode) != 0o600
                or (path_info.st_dev, path_info.st_ino) != (created_info.st_dev, created_info.st_ino)
                or _read_fd_limited(key_fd) != target.new_content
            ):
                raise OSError("The new authorized_keys file could not be verified.")
        else:
            key_fd = os.open("authorized_keys", os.O_RDWR | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=ssh_fd)
            if _metadata(os.fstat(key_fd)) != target.authorized_keys_metadata:
                raise OSError("authorized_keys identity changed after confirmation.")
            fcntl.flock(key_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            attr_error = _protected_xattr_error(key_fd, operation="SSH authorized_keys replacement")
            if attr_error:
                raise OSError(attr_error)
            current = _read_fd_limited(key_fd)
            opened = os.fstat(key_fd)
            path_info = os.stat("authorized_keys", dir_fd=ssh_fd, follow_symlinks=False)
            if (
                current != target.authorized_keys_content
                or len(current) != opened.st_size
                or _metadata(opened) != target.authorized_keys_metadata
                or (path_info.st_dev, path_info.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise OSError("authorized_keys content or identity changed after confirmation.")
            try:
                _replace_fd_contents(key_fd, target.new_content)
                updated = os.fstat(key_fd)
                path_after = os.stat("authorized_keys", dir_fd=ssh_fd, follow_symlinks=False)
                if (
                    (updated.st_dev, updated.st_ino) != (target.authorized_keys_metadata.device, target.authorized_keys_metadata.inode)
                    or updated.st_nlink != 1
                    or (path_after.st_dev, path_after.st_ino) != (updated.st_dev, updated.st_ino)
                    or _read_fd_limited(key_fd) != target.new_content
                ):
                    raise OSError("The updated authorized_keys file could not be verified.")
                _verify_directory_path(target, home_fd, ssh_fd)
            except OSError as exc:
                restored = False
                try:
                    _replace_fd_contents(key_fd, target.authorized_keys_content or b"")
                    restored_info = os.fstat(key_fd)
                    restored_path = os.stat("authorized_keys", dir_fd=ssh_fd, follow_symlinks=False)
                    restored = (
                        (restored_info.st_dev, restored_info.st_ino)
                        == (target.authorized_keys_metadata.device, target.authorized_keys_metadata.inode)
                        and (restored_path.st_dev, restored_path.st_ino)
                        == (restored_info.st_dev, restored_info.st_ino)
                        and _read_fd_limited(key_fd) == target.authorized_keys_content
                    )
                except OSError:
                    pass
                suffix = "The prior authorized_keys content was restored." if restored else "The prior authorized_keys content could not be verified after rollback."
                raise OSError(f"Could not verify the key-file update. {suffix}") from exc
        if target.authorized_keys_metadata is None:
            _verify_directory_path(target, home_fd, ssh_fd)
        os.fsync(ssh_fd)
        if created_ssh:
            os.fsync(home_fd)
        success = True
        return True, "The exact authorized_keys change was applied and verified."
    except (BlockingIOError, OSError, ValueError) as exc:
        return False, exc.strerror or str(exc) or "The SSH key operation could not be completed."
    finally:
        if key_fd is not None:
            if created_key and not success and ssh_fd is not None and created_key_identity is not None:
                try:
                    path_info = os.stat("authorized_keys", dir_fd=ssh_fd, follow_symlinks=False)
                    if (path_info.st_dev, path_info.st_ino) == created_key_identity:
                        os.unlink("authorized_keys", dir_fd=ssh_fd)
                except OSError:
                    pass
            try:
                os.close(key_fd)
            except OSError:
                pass
        if ssh_fd is not None:
            try:
                os.close(ssh_fd)
            except OSError:
                pass
        if created_ssh and not success and home_fd is not None:
            try:
                os.rmdir(".ssh", dir_fd=home_fd)
            except OSError:
                pass
        if home_fd is not None:
            try:
                os.close(home_fd)
            except OSError:
                pass


def perform_local_ssh_key_action(
    action: SSHKeyAction,
    username: str,
    public_key: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> LocalSSHKeyActionResponse:
    safe_action: SSHKeyAction = action if action in {"add", "remove"} else "add"
    safe_username = username if isinstance(username, str) and LOCAL_NAME_RE.fullmatch(username) else None
    if confirmed is not True:
        return LocalSSHKeyActionResponse(
            success=False,
            action=safe_action,
            username=safe_username,
            user_confirmed=False,
            message="Explicit client confirmation is required; no SSH key file was changed.",
        )
    target, error = _prepare_target(action, username, public_key)
    if error or target is None:
        return LocalSSHKeyActionResponse(
            success=False,
            action=safe_action,
            username=safe_username,
            user_confirmed=True,
            message=error or "The local SSH key request could not be verified.",
        )
    phrase = "SSH-KEY-" + target.state_digest[:16].upper()
    if not isinstance(confirmation_phrase, str) or not hmac.compare_digest(confirmation_phrase, phrase):
        return LocalSSHKeyActionResponse(
            success=False,
            action=target.action,
            username=target.username,
            fingerprint=target.fingerprint,
            user_confirmed=True,
            message="Confirmation did not match the exact account, key fingerprint, file state, and requested action.",
        )
    with _LOCK:
        current, error = _prepare_target(action, username, public_key)
        if error or current is None or current.state_digest != target.state_digest:
            return LocalSSHKeyActionResponse(
                success=False,
                action=target.action,
                username=target.username,
                fingerprint=target.fingerprint,
                user_confirmed=True,
                message=error or "The account home or authorized_keys state changed after confirmation; no key command was run.",
            )
        success, detail = _apply_target(current)
    if not success:
        return LocalSSHKeyActionResponse(
            success=False,
            action=target.action,
            username=target.username,
            fingerprint=target.fingerprint,
            user_confirmed=True,
            message=f"The SSH key file was not verified after the requested operation: {detail}",
        )
    verb = "added to" if target.action == "add" else "removed from"
    return LocalSSHKeyActionResponse(
        success=True,
        action=target.action,
        username=target.username,
        fingerprint=target.fingerprint,
        user_confirmed=True,
        message=f"Public key {target.fingerprint} was {verb} the exact local account's authorized_keys file. This does not change sshd configuration or guarantee that SSH login is enabled.",
    )
