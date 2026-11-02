"""Confirmation-gated mount and unmount actions for exact fstab targets."""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import Literal

from wayland_mcp.models import FstabEntryInfo, MountActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.fstab import MAX_RETURNED_ENTRIES, PSEUDO_FILESYSTEMS, list_fstab_entries

MountAction = Literal["mount", "unmount"]
MOUNTINFO_PATH = Path("/proc/self/mountinfo")
MAX_MOUNTINFO_BYTES = 4 * 1024 * 1024
MAX_MOUNTINFO_LINES = 20_000
MAX_MOUNT_COMMAND_OUTPUT_BYTES = 128 * 1024
MOUNT_COMMAND_TIMEOUT_SECONDS = 45
OCTAL_ESCAPE_RE = re.compile(r"\\([0-7]{3})")


def _mount_binaries_available(env: dict[str, str]) -> bool:
    return bool(find_session_binary("mount", env) and find_session_binary("umount", env))


def mount_control_available(env: dict[str, str] | None = None) -> bool:
    """Return whether current-scope mount control prerequisites are visible."""
    if not sys.platform.startswith("linux") or not MOUNTINFO_PATH.is_file():
        return False
    child_env = env if env is not None else get_sanitized_env()
    return _mount_binaries_available(child_env)


def _safe_mount_point(value: object) -> tuple[Path | None, str | None]:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None, "Mount point must be one absolute path of at most 4096 characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None, "Mount point cannot contain control characters."
    path = Path(value)
    if value.startswith("//") or not path.is_absolute() or path.as_posix() != value:
        return None, "Mount point must use a normalized absolute path."
    if value == "/":
        return None, "The root filesystem cannot be mounted or unmounted through this tool."
    if path == Path("/proc") or path.is_relative_to("/proc"):
        return None, "Mount points under /proc are not supported."
    if path == Path("/sys") or path.is_relative_to("/sys"):
        return None, "Mount points under /sys are not supported."
    if path == Path("/dev") or path.is_relative_to("/dev"):
        return None, "Mount points under /dev are not supported."
    if "\\t" in value or "\\n" in value:
        return None, "Mount points containing escaped control characters are not supported."

    current = Path("/")
    components = path.parts[1:]
    if not components:
        return None, "The root filesystem cannot be mounted or unmounted through this tool."
    for component in components:
        if component in {".", ".."}:
            return None, "Mount point cannot contain dot or parent components."
        current = current / component
        try:
            info = os.lstat(current)
        except OSError:
            return None, "Mount point and its parent directories must already exist and be accessible."
        if stat.S_ISLNK(info.st_mode):
            return None, "Mount points containing symbolic links are not supported."
        if not stat.S_ISDIR(info.st_mode):
            return None, "Mount point and each parent component must be directories."
        shared_write = bool(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
        root_sticky_directory = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if shared_write and not root_sticky_directory:
            return None, "Mount-point paths cannot traverse group/world-writable directories without a root-owned sticky bit."
        if os.geteuid() == 0 and info.st_uid != 0 and info.st_mode & stat.S_IWUSR:
            return None, "A root-run server cannot mount through directories writable by another user."
    return path, None


def _fstab_entry_for_mount_point(mount_point: str) -> tuple[FstabEntryInfo | None, str | None]:
    inventory = list_fstab_entries(limit=MAX_RETURNED_ENTRIES)
    if not inventory.success:
        return None, "The bounded /etc/fstab inventory is unavailable."
    if inventory.truncated or inventory.malformed_lines:
        return None, "The bounded /etc/fstab inventory is incomplete or contains malformed entries."
    matches = [entry for entry in inventory.entries if entry.mount_point == mount_point]
    if len(matches) != 1:
        return None, "Mount point must match exactly one valid /etc/fstab entry."
    entry = matches[0]
    if entry.source_kind == "pseudo" or entry.filesystem_type.casefold() in PSEUDO_FILESYSTEMS:
        return None, "Pseudo-filesystem and swap entries are not supported by this mount control."
    return entry, None


def _decode_mountinfo_path(value: str) -> str:
    return OCTAL_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _active_mount_counts() -> tuple[dict[str, int] | None, str | None]:
    try:
        with MOUNTINFO_PATH.open("rb") as stream:
            raw = stream.read(MAX_MOUNTINFO_BYTES + 1)
    except OSError:
        return None, "Current mount-namespace information is unavailable."
    if len(raw) > MAX_MOUNTINFO_BYTES:
        return None, "Current mount-namespace information exceeded its size limit."
    text = raw.decode("utf-8", errors="surrogateescape")
    counts: dict[str, int] = {}
    lines = text.splitlines()
    if len(lines) > MAX_MOUNTINFO_LINES:
        return None, "Current mount-namespace information exceeded its entry limit."
    for line in lines:
        before, separator, after = line.partition(" - ")
        fields = before.split()
        filesystem_fields = after.split()
        if not separator or len(fields) < 6 or not filesystem_fields:
            return None, "Current mount-namespace information contains an invalid entry."
        mount_point = _decode_mountinfo_path(fields[4])
        counts[mount_point] = counts.get(mount_point, 0) + 1
    return counts, None


def mount_action_confirmation_details(
    action: MountAction,
    mount_point: str,
) -> tuple[FstabEntryInfo | None, str | None]:
    """Validate the exact fstab target and current mount state before elicitation."""
    if action not in ("mount", "unmount"):
        return None, "Action must be 'mount' or 'unmount'."
    if not sys.platform.startswith("linux"):
        return None, "Mount control is available only on Linux."
    path, error = _safe_mount_point(mount_point)
    if path is None:
        return None, error
    entry, error = _fstab_entry_for_mount_point(str(path))
    if entry is None:
        return None, error
    env = get_sanitized_env()
    if not _mount_binaries_available(env):
        return None, "The util-linux mount and umount commands are required."
    active_mounts, error = _active_mount_counts()
    if active_mounts is None:
        return None, error
    active_count = active_mounts.get(str(path), 0)
    if action == "mount" and active_count != 0:
        return None, "The exact mount point is already mounted; inspect current mounts before retrying."
    if action == "unmount" and active_count != 1:
        return None, "Unmount requires exactly one active mount at this fstab target."
    return entry, None


def perform_mount_action(
    action: MountAction,
    mount_point: str,
    *,
    confirmed: bool,
) -> MountActionResponse:
    """Mount or unmount one exact, preconfigured fstab target after confirmation."""
    safe_target = mount_point if isinstance(mount_point, str) else ""
    if not confirmed:
        return MountActionResponse(
            success=False,
            action=action if action in ("mount", "unmount") else "mount",
            mount_point=safe_target,
            user_confirmed=False,
            message="Explicit client confirmation is required; no mount command was run.",
        )
    entry, validation_error = mount_action_confirmation_details(action, mount_point)
    if entry is None:
        return MountActionResponse(
            success=False,
            action=action if action in ("mount", "unmount") else "mount",
            mount_point=safe_target,
            user_confirmed=True,
            message=validation_error or "Mount target validation failed; no command was run.",
        )

    env = dict(get_sanitized_env())
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    binary_name = "mount" if action == "mount" else "umount"
    executable = find_session_binary(binary_name, env)
    if not executable:
        return MountActionResponse(
            success=False,
            action=action,
            mount_point=mount_point,
            filesystem_type=entry.filesystem_type,
            user_confirmed=True,
            message=f"The {binary_name} command became unavailable before execution.",
        )
    command = [executable, "--target", mount_point] if action == "mount" else [executable, mount_point]
    _output, error, output_truncated = run_bounded_command(
        command,
        env,
        command_label=f"{binary_name} action",
        timeout_seconds=MOUNT_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_MOUNT_COMMAND_OUTPUT_BYTES,
        kill_process_group=True,
    )

    active_mounts, state_error = _active_mount_counts()
    state_read = active_mounts is not None
    active_count = active_mounts.get(mount_point, 0) if active_mounts is not None else None
    state_matches = active_count == (1 if action == "mount" else 0)
    if state_matches:
        if error or output_truncated:
            message = "The requested mount state is present after a command timeout or output limit; inspect it before retrying."
        else:
            message = "The requested mount state was verified in the current mount namespace."
        return MountActionResponse(
            success=True,
            action=action,
            mount_point=mount_point,
            filesystem_type=entry.filesystem_type,
            user_confirmed=True,
            state_verified=state_read,
            message=f"{message} The server did not invoke sudo, polkit, or interactive elevation.",
        )

    if error and "timed out" in error.casefold():
        failure_message = "The mount command timed out; the resulting state may be incomplete or uncertain. Inspect current mounts before retrying."
    elif state_error:
        failure_message = f"The command finished, but current mount state could not be checked: {state_error}"
    elif output_truncated:
        failure_message = "The mount command exceeded its output limit and the requested state was not verified. Inspect current mounts before retrying."
    else:
        failure_message = "The requested mount state was not reached. Command output is withheld because it can contain configured source identifiers."
    return MountActionResponse(
        success=False,
        action=action,
        mount_point=mount_point,
        filesystem_type=entry.filesystem_type,
        user_confirmed=True,
        state_verified=state_read,
        message=failure_message,
    )
