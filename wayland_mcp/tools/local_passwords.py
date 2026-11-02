"""Confirmed local account password changes without argv or prompt disclosure."""

from __future__ import annotations

import hmac
import os
import secrets
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from wayland_mcp.models import LocalPasswordSetResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.accounts_control import (
    LOCAL_NAME_RE,
    LOCKED_PASSWORD_STATES,
    _parse_local_state,
    _password_state,
    _shadow_password_hash_usable,
)

SHADOW_PATH = Path("/etc/shadow")
PASSWORD_MAX_BYTES = 1024
PENDING_TTL_SECONDS = 180
MAX_PENDING_CHANGES = 64
COMMAND_TIMEOUT_SECONDS = 30


@dataclass(frozen=True, slots=True)
class _ShadowMetadata:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(slots=True)
class _PendingPasswordSet:
    phrase: str
    username: str
    account: tuple[str, int, int, str]
    account_files_digest: str
    password_state: str
    shadow_metadata: _ShadowMetadata
    password: bytearray = field(repr=False)
    expires_at: float = 0.0
    timer: threading.Timer | None = field(default=None, repr=False)
    claimed: bool = False


_PENDING: dict[str, _PendingPasswordSet] = {}
_LOCK = threading.Lock()


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def _encode_password(password: object) -> bytes | None:
    if not isinstance(password, str):
        return None
    try:
        encoded = password.encode("utf-8", errors="strict")
    except UnicodeError:
        return None
    if (
        not encoded
        or len(encoded) > PASSWORD_MAX_BYTES
        or any(byte in encoded for byte in (0, 10, 13, 58))
        or not password.strip()
    ):
        return None
    return encoded


def local_password_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    try:
        shadow = SHADOW_PATH.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(shadow.st_mode)
        and shadow.st_uid == 0
        and not shadow.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        and Path("/etc/passwd").is_file()
        and Path("/etc/group").is_file()
        and find_session_binary("chpasswd", selected) is not None
        and find_session_binary("passwd", selected) is not None
        and find_session_binary("usermod", selected) is not None
    )


def _shadow_metadata() -> _ShadowMetadata | None:
    try:
        info = SHADOW_PATH.lstat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        return None
    return _ShadowMetadata(
        device=info.st_dev,
        inode=info.st_ino,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
    )


def _wipe(record: _PendingPasswordSet) -> None:
    for index in range(len(record.password)):
        record.password[index] = 0
    record.password.clear()
    if record.timer is not None:
        record.timer.cancel()
        record.timer = None


def _expire(phrase: str, expected: _PendingPasswordSet) -> None:
    with _LOCK:
        if _PENDING.get(phrase) is expected:
            _PENDING.pop(phrase, None)
            _wipe(expected)


def _prune_locked(now: float) -> None:
    expired = [phrase for phrase, record in _PENDING.items() if record.expires_at <= now]
    for phrase in expired:
        record = _PENDING.pop(phrase, None)
        if record is not None:
            _wipe(record)


def _clear_matching_password(username: str, password: bytes) -> None:
    with _LOCK:
        _prune_locked(time.monotonic())
        for phrase, record in list(_PENDING.items()):
            if record.username == username and hmac.compare_digest(bytes(record.password), password):
                _PENDING.pop(phrase, None)
                _wipe(record)


def local_password_set_confirmation_details(
    username: str,
    password: str,
) -> tuple[str | None, str | None, str | None]:
    """Reserve a short-lived password and return its non-secret target and phrase."""
    if not isinstance(username, str) or not LOCAL_NAME_RE.fullmatch(username):
        return None, None, "username must be one exact local account name."
    password_bytes = _encode_password(password)
    if password_bytes is None:
        return None, None, f"password must be non-empty text up to {PASSWORD_MAX_BYTES} UTF-8 bytes, without NUL, colon, or line breaks."
    if not local_password_control_available():
        return None, None, "Local password changes require Linux, a root-owned non-group/world-writable /etc/shadow, and the chpasswd, passwd, and usermod commands."
    users, _groups, files_digest, error = _parse_local_state()
    if error or files_digest is None:
        return None, None, error or "Local account state could not be checked."
    account = users.get(username)
    if account is None:
        return None, None, "The exact local user does not exist."
    if (account[1] == 0) != (username == "root"):
        return None, None, "UID 0 password changes are supported only for the exact root account entry."
    password_state = _password_state(username)
    if password_state is None:
        return None, None, "The current local password state could not be checked."
    shadow_metadata = _shadow_metadata()
    if shadow_metadata is None:
        return None, None, "The local shadow file identity could not be verified."

    phrase = f"PASSWORD-CHANGE-{secrets.token_hex(8).upper()}"
    now = time.monotonic()
    record = _PendingPasswordSet(
        phrase=phrase,
        username=username,
        account=account,
        account_files_digest=files_digest,
        password_state=password_state,
        shadow_metadata=shadow_metadata,
        password=bytearray(password_bytes),
        expires_at=now + PENDING_TTL_SECONDS,
    )
    with _LOCK:
        _prune_locked(now)
        if len(_PENDING) >= MAX_PENDING_CHANGES:
            _wipe(record)
            return None, None, "Too many pending password confirmations; retry after one expires or is completed."
        _PENDING[phrase] = record
        timer = threading.Timer(PENDING_TTL_SECONDS, _expire, args=(phrase, record))
        timer.daemon = True
        record.timer = timer
        timer.start()
    return username, phrase, None


def _write_password(username: str, password: bytearray) -> bool:
    binary = find_session_binary("chpasswd", _environment())
    if not binary:
        return False
    payload = bytearray(username.encode("ascii"))
    payload.extend(b":")
    payload.extend(password)
    payload.extend(b"\n")
    try:
        completed = subprocess.run(
            [binary],
            input=bytes(payload),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
        )
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        for index in range(len(payload)):
            payload[index] = 0
        payload.clear()


def _lock_password(username: str) -> bool:
    binary = find_session_binary("usermod", _environment())
    if not binary:
        return False
    try:
        completed = subprocess.run(
            [binary, "--lock", username],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
        )
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _take_pending(phrase: str, username: str, password: bytes) -> _PendingPasswordSet | None:
    with _LOCK:
        _prune_locked(time.monotonic())
        record = _PENDING.get(phrase)
        if record is None:
            return None
        matches = (
            record.username == username
            and hmac.compare_digest(bytes(record.password), password)
            and not record.claimed
        )
        if not matches:
            _PENDING.pop(phrase, None)
            _wipe(record)
            return None
        record.claimed = True
        if record.timer is not None:
            record.timer.cancel()
            record.timer = None
        return record


def _remove_pending(record: _PendingPasswordSet) -> None:
    with _LOCK:
        if _PENDING.get(record.phrase) is record:
            _PENDING.pop(record.phrase, None)
        _wipe(record)


def perform_local_password_set(
    username: str,
    password: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> LocalPasswordSetResponse:
    safe_username = username if isinstance(username, str) and LOCAL_NAME_RE.fullmatch(username) else None
    password_bytes = _encode_password(password)
    if password_bytes is None:
        return LocalPasswordSetResponse(success=False, username=safe_username, user_confirmed=confirmed is True, message="The submitted password could not be verified; no password command was run.")
    if confirmed is not True:
        if safe_username is not None:
            _clear_matching_password(safe_username, password_bytes)
        return LocalPasswordSetResponse(success=False, username=safe_username, user_confirmed=False, message="Explicit client confirmation is required; no password command was run.")
    if safe_username is None or not isinstance(confirmation_phrase, str):
        if safe_username is not None:
            _clear_matching_password(safe_username, password_bytes)
        return LocalPasswordSetResponse(success=False, username=safe_username, user_confirmed=True, message="The exact local password confirmation could not be verified.")
    record = _take_pending(confirmation_phrase, safe_username, password_bytes)
    if record is None:
        _clear_matching_password(safe_username, password_bytes)
        return LocalPasswordSetResponse(success=False, username=safe_username, user_confirmed=True, message="The password confirmation expired or did not match this exact request; no password command was run.")
    try:
        users, _groups, files_digest, error = _parse_local_state()
        current_user = users.get(record.username)
        current_password_state = _password_state(record.username)
        current_shadow_metadata = _shadow_metadata()
        if (
            error
            or files_digest != record.account_files_digest
            or current_user != record.account
            or current_password_state != record.password_state
            or current_shadow_metadata != record.shadow_metadata
        ):
            return LocalPasswordSetResponse(success=False, username=safe_username, user_confirmed=True, message="The local account or password state changed after confirmation; no password command was run.")
        if not _write_password(record.username, record.password):
            return LocalPasswordSetResponse(success=False, username=safe_username, user_confirmed=True, message="The local password command failed or timed out; inspect account state before retrying.")
        status_after_set = _password_state(record.username)
        if record.password_state in LOCKED_PASSWORD_STATES and status_after_set not in LOCKED_PASSWORD_STATES:
            if not _lock_password(record.username):
                return LocalPasswordSetResponse(success=False, username=safe_username, user_confirmed=True, message="The password was set, but the account's existing password lock could not be restored; inspect and lock the account before permitting password login.")
            status_after_set = _password_state(record.username)
        users_after, _groups_after, _digest_after, error_after = _parse_local_state()
        metadata_after = _shadow_metadata()
        expected_status = (
            status_after_set in LOCKED_PASSWORD_STATES
            if record.password_state in LOCKED_PASSWORD_STATES
            else status_after_set == "P"
        )
        verified = (
            error_after is None
            and users_after.get(record.username) == record.account
            and expected_status
            and _shadow_password_hash_usable(record.username) is True
            and metadata_after is not None
            and metadata_after != record.shadow_metadata
        )
        if not verified:
            return LocalPasswordSetResponse(success=False, username=safe_username, user_confirmed=True, message="The password command returned, but the local password state could not be verified; inspect the account before retrying.")
        if record.password_state in LOCKED_PASSWORD_STATES:
            message = "The local account password was set and its prior password lock was preserved. Use the separate unlock action when password login should be enabled. The response contains no password or hash."
        else:
            message = "The local account password was set and the updated password state was verified. The response contains no password or hash."
        return LocalPasswordSetResponse(success=True, username=safe_username, user_confirmed=True, message=message)
    finally:
        _remove_pending(record)
