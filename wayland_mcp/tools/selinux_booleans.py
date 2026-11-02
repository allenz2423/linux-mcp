"""Bounded, read-only inventory of current and pending SELinux booleans."""

from __future__ import annotations

import os
import re
import hashlib
import json
import sys
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    SELinuxBooleanActionResponse,
    SELinuxBooleanInfo,
    SELinuxBooleanListResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

SELINUX_BOOLEAN_ROOT = Path("/sys/fs/selinux/booleans")
MAX_BOOLEAN_ENTRIES = 4096
MAX_RETURNED_BOOLEANS = 200
MAX_BOOLEAN_NAME_LENGTH = 128
MAX_VALUE_BYTES = 32
BOOLEAN_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
BOOLEAN_VALUE_RE = re.compile(r"^([01])\s+([01])\s*$")
SETSEBOOL_TIMEOUT_SECONDS = 300
SETSEBOOL_OUTPUT_BYTES = 16 * 1024


@dataclass(frozen=True, slots=True)
class _BooleanActionTarget:
    name: str
    enabled: bool
    persistent: bool
    current: bool
    pending: bool
    binary: str
    binary_identity: tuple[int, int, int, int, int]
    state_digest: str


def _setsebool_identity(binary: str) -> tuple[int, int, int, int, int] | None:
    try:
        info = os.stat(binary, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or not os.access(binary, os.X_OK):
        return None
    return (info.st_dev, info.st_ino, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)


def selinux_boolean_control_available() -> bool:
    if not selinux_booleans_available():
        return False
    env = get_sanitized_env(dict(os.environ))
    return bool(find_session_binary("setsebool", env))


def selinux_boolean_confirmation_details(
    name: str,
    enabled: bool,
    persistent: bool,
) -> tuple[_BooleanActionTarget | None, str | None, str | None]:
    """Read one exact boolean and bind its current state to a confirmation phrase."""
    if not sys.platform.startswith("linux"):
        return None, None, "SELinux boolean control is available only on Linux."
    if not isinstance(name, str) or not BOOLEAN_NAME_RE.fullmatch(name):
        return None, None, "name must be one exact SELinux boolean name from list_selinux_booleans."
    if type(enabled) is not bool or type(persistent) is not bool:
        return None, None, "enabled and persistent must be booleans."
    if not SELINUX_BOOLEAN_ROOT.is_dir():
        return None, None, "The SELinux boolean directory is not visible in selinuxfs."
    env = get_sanitized_env(dict(os.environ))
    binary = find_session_binary("setsebool", env)
    if not binary:
        return None, None, "The optional setsebool command is unavailable."
    try:
        binary = str(Path(binary).resolve(strict=True))
    except (OSError, RuntimeError):
        return None, None, "The selected setsebool executable could not be resolved safely."
    identity = _setsebool_identity(binary)
    if identity is None:
        return None, None, "The selected setsebool executable identity could not be verified."
    boolean = _read_boolean(name)
    if boolean.current is None or boolean.pending is None:
        return None, None, boolean.unavailable_reason or "The exact SELinux boolean could not be read."
    material = {
        "name": name,
        "enabled": enabled,
        "persistent": persistent,
        "current": boolean.current,
        "pending": boolean.pending,
        "binary": binary,
        "binary_identity": identity,
    }
    state_digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    target = _BooleanActionTarget(
        name=name,
        enabled=enabled,
        persistent=persistent,
        current=boolean.current,
        pending=boolean.pending,
        binary=binary,
        binary_identity=identity,
        state_digest=state_digest,
    )
    phrase = hashlib.sha256(("selinux-boolean:" + state_digest).encode("ascii")).hexdigest()[:16]
    return target, f"set boolean {phrase}", None


def perform_selinux_boolean_action(
    name: str,
    enabled: bool,
    persistent: bool,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> SELinuxBooleanActionResponse:
    target, phrase, error = selinux_boolean_confirmation_details(name, enabled, persistent)
    if error or target is None or phrase is None:
        return SELinuxBooleanActionResponse(
            success=False,
            name=name if isinstance(name, str) and BOOLEAN_NAME_RE.fullmatch(name) else None,
            enabled=enabled if type(enabled) is bool else None,
            persistent=persistent if type(persistent) is bool else None,
            user_confirmed=confirmed is True,
            message=error or "The exact SELinux boolean could not be verified.",
        )
    if confirmed is not True:
        return SELinuxBooleanActionResponse(
            success=False,
            name=target.name,
            enabled=target.enabled,
            persistent=target.persistent,
            current_before=target.current,
            pending_before=target.pending,
            user_confirmed=False,
            message="Explicit client confirmation is required; no SELinux boolean was changed.",
        )
    if confirmation_phrase != phrase:
        return SELinuxBooleanActionResponse(
            success=False,
            name=target.name,
            enabled=target.enabled,
            persistent=target.persistent,
            current_before=target.current,
            pending_before=target.pending,
            user_confirmed=True,
            message="Confirmation did not match the exact boolean state, requested value, persistence choice, or executable identity.",
        )
    if _setsebool_identity(target.binary) != target.binary_identity:
        return SELinuxBooleanActionResponse(
            success=False,
            name=target.name,
            enabled=target.enabled,
            persistent=target.persistent,
            current_before=target.current,
            pending_before=target.pending,
            user_confirmed=True,
            message="The setsebool executable changed after confirmation; no change was run.",
        )
    before = _read_boolean(target.name)
    if before.current != target.current or before.pending != target.pending:
        return SELinuxBooleanActionResponse(
            success=False,
            name=target.name,
            enabled=target.enabled,
            persistent=target.persistent,
            current_before=target.current,
            pending_before=target.pending,
            user_confirmed=True,
            message="The SELinux boolean changed after confirmation; list booleans again before retrying.",
        )
    if not target.persistent and target.current is target.enabled:
        return SELinuxBooleanActionResponse(
            success=True,
            name=target.name,
            enabled=target.enabled,
            persistent=False,
            current_before=target.current,
            pending_before=target.pending,
            current_after=target.current,
            pending_after=target.pending,
            user_confirmed=True,
            message="The SELinux boolean already has the requested runtime value; no command was run.",
        )

    env = get_sanitized_env(dict(os.environ))
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    command = [target.binary]
    if target.persistent:
        command.append("-P")
    command.extend([target.name, "on" if target.enabled else "off"])
    _output, command_error, command_truncated = run_bounded_command(
        command,
        env,
        command_label="SELinux boolean update",
        timeout_seconds=SETSEBOOL_TIMEOUT_SECONDS,
        max_output_bytes=SETSEBOOL_OUTPUT_BYTES,
        kill_process_group=True,
    )
    if command_error or command_truncated:
        after = _read_boolean(target.name)
        return SELinuxBooleanActionResponse(
            success=False,
            name=target.name,
            enabled=target.enabled,
            persistent=target.persistent,
            current_before=target.current,
            pending_before=target.pending,
            current_after=after.current,
            pending_after=after.pending,
            user_confirmed=True,
            message="setsebool failed, timed out, or exceeded its output limit; the action may be incomplete, so inspect the boolean and local policy before retrying.",
        )
    after = _read_boolean(target.name)
    if after.current is not target.enabled:
        return SELinuxBooleanActionResponse(
            success=False,
            name=target.name,
            enabled=target.enabled,
            persistent=target.persistent,
            current_before=target.current,
            pending_before=target.pending,
            current_after=after.current,
            pending_after=after.pending,
            user_confirmed=True,
            message="setsebool returned successfully, but the requested runtime boolean value was not visible afterward.",
        )
    return SELinuxBooleanActionResponse(
        success=True,
        name=target.name,
        enabled=target.enabled,
        persistent=target.persistent,
        current_before=target.current,
        pending_before=target.pending,
        current_after=after.current,
        pending_after=after.pending,
        user_confirmed=True,
        message=(
            "The SELinux boolean runtime value was updated and setsebool completed the persistent policy update."
            if target.persistent
            else "The SELinux boolean runtime value was updated; its boot-time default was not changed."
        ),
    )


def selinux_booleans_available() -> bool:
    """Return whether the fixed SELinux boolean directory is visible."""
    return sys.platform.startswith("linux") and SELINUX_BOOLEAN_ROOT.is_dir()


def _read_boolean(name: str) -> SELinuxBooleanInfo:
    try:
        with (SELINUX_BOOLEAN_ROOT / name).open("rb") as stream:
            raw = stream.read(MAX_VALUE_BYTES + 1)
    except OSError as exc:
        return SELinuxBooleanInfo(
            name=name,
            unavailable_reason=exc.strerror or "read error",
        )
    if len(raw) > MAX_VALUE_BYTES:
        return SELinuxBooleanInfo(name=name, unavailable_reason="value exceeded the 32-byte cap")
    try:
        value = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return SELinuxBooleanInfo(name=name, unavailable_reason="value was not ASCII")
    match = BOOLEAN_VALUE_RE.fullmatch(value)
    if match is None:
        return SELinuxBooleanInfo(name=name, unavailable_reason="value did not contain current and pending 0/1 fields")
    return SELinuxBooleanInfo(name=name, current=match.group(1) == "1", pending=match.group(2) == "1")


def list_selinux_booleans(
    query: str = "",
    offset: int = 0,
    limit: int = 100,
) -> SELinuxBooleanListResponse:
    """Return a bounded page of current and pending SELinux boolean values."""
    if not sys.platform.startswith("linux"):
        return SELinuxBooleanListResponse(success=False, message="SELinux boolean inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > MAX_BOOLEAN_NAME_LENGTH:
        return SELinuxBooleanListResponse(success=False, message="Query must be text with at most 128 characters.")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > MAX_BOOLEAN_ENTRIES:
        safe_offset = offset if isinstance(offset, int) and not isinstance(offset, bool) else 0
        return SELinuxBooleanListResponse(
            success=False,
            query=query,
            offset=safe_offset,
            message=f"Offset must be an integer from 0 through {MAX_BOOLEAN_ENTRIES}.",
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        return SELinuxBooleanListResponse(success=False, query=query, offset=offset, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_BOOLEANS))

    names: list[str] = []
    scan_truncated = False
    try:
        with os.scandir(SELINUX_BOOLEAN_ROOT) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_BOOLEAN_ENTRIES:
                    scan_truncated = True
                    break
                if entry.name not in {".", ".."} and BOOLEAN_NAME_RE.fullmatch(entry.name):
                    names.append(entry.name)
    except FileNotFoundError:
        return SELinuxBooleanListResponse(
            success=False,
            query=query,
            offset=offset,
            limit=limit,
            unavailable_sources=["/sys/fs/selinux/booleans"],
            partial=True,
            message="The SELinux boolean directory is not present; SELinux may be disabled or selinuxfs unavailable.",
        )
    except PermissionError:
        return SELinuxBooleanListResponse(
            success=False,
            query=query,
            offset=offset,
            limit=limit,
            unavailable_sources=["/sys/fs/selinux/booleans"],
            partial=True,
            message="The SELinux boolean directory is not readable with current permissions.",
        )
    except OSError as exc:
        return SELinuxBooleanListResponse(
            success=False,
            query=query,
            offset=offset,
            limit=limit,
            unavailable_sources=["/sys/fs/selinux/booleans"],
            partial=True,
            message=f"Could not enumerate SELinux booleans: {exc.strerror or 'read error'}.",
        )

    names.sort(key=lambda name: (name.casefold(), name))
    needle = query.strip().casefold()
    matching_names = [name for name in names if not needle or needle in name.casefold()]
    page_names = matching_names[offset : offset + limit]
    booleans = [_read_boolean(name) for name in page_names]
    unavailable = [item.name for item in booleans if item.unavailable_reason is not None]
    page_end = offset + len(booleans)
    has_more: bool | None
    next_offset: int | None
    if page_end < len(matching_names):
        has_more = True
        next_offset = page_end
    elif scan_truncated:
        has_more = None
        next_offset = None
    else:
        has_more = False
        next_offset = None

    partial = scan_truncated or bool(unavailable)
    return SELinuxBooleanListResponse(
        success=True,
        query=query,
        offset=offset,
        next_offset=next_offset,
        has_more=has_more,
        total_booleans=len(matching_names),
        returned_booleans=len(booleans),
        booleans=booleans,
        limit=limit,
        unavailable_sources=unavailable,
        truncated=scan_truncated,
        partial=partial,
        message=(
            "Read-only SELinux boolean snapshot; values are current and pending kernel settings. No boolean values were changed."
            + (" The directory scan reached its 4,096-entry cap." if scan_truncated else "")
        ),
    )
