"""Explicitly confirmed, exact-name Snap package transactions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import stat
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import SnapPackageActionResponse
from wayland_mcp.session import get_sanitized_env
from wayland_mcp.tools.application_packages import detect_application_package_tools
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.package_control import (
    PACKAGE_ACTION_TIMEOUT_SECONDS,
    _run_transaction_command,
)

SnapPackageAction = Literal[
    "install", "update", "switch_channel", "remove", "enable", "disable", "revert", "hold", "unhold", "hold_all", "unhold_all"
]
SNAP_ACTIONS = {"install", "update", "switch_channel", "remove", "enable", "disable", "revert", "hold", "unhold", "hold_all", "unhold_all"}
SNAP_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
SNAP_CHANNEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*(?:/[A-Za-z0-9][A-Za-z0-9._+-]*){0,2}$")
SNAP_CHANNEL_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
SNAP_CHANNEL_RISKS = {"stable", "candidate", "beta", "edge"}
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
SNAP_STATUS_TIMEOUT_SECONDS = 15
SNAP_STATUS_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_LOCAL_SNAP_FILE_BYTES = 1024 * 1024 * 1024
MAX_LOCAL_SNAP_PATH_CHARS = 4096
SNAP_REVISION_RE = re.compile(r"^(?:[1-9][0-9]*|x[1-9][0-9]*)$")
SNAP_HOLD_DURATION_RE = re.compile(r"^(?:[1-9][0-9]*(?:h|m|s))+$")
MAX_SNAP_HOLD_SECONDS = 90 * 24 * 60 * 60


@dataclass(frozen=True)
class SnapPackageSnapshot:
    action: SnapPackageAction
    package_name: str
    binary: str
    installed_rows: tuple[str, ...]
    active_revision: str | None
    version: str | None
    tracking: str | None
    target_channel: str | None
    target_revision: str | None
    hold_duration: str | None
    installed_revision: str | None
    held: bool
    any_held: bool
    classic: bool
    devmode: bool
    target_confinement: str | None
    snap_file_path: str
    local_file_digest: str | None
    local_file_fingerprint: str | None
    local_file_size: int | None
    dangerous: bool
    uid: int
    euid: int
    state_token: str


def snap_package_control_available(env: dict[str, str] | None = None) -> bool:
    return sys.platform.startswith("linux") and bool(
        detect_application_package_tools(env).get("snap")
    )


def _environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["TERM"] = "dumb"
    return env


def _installed_rows(
    binary: str,
    package_name: str,
    env: dict[str, str],
) -> tuple[tuple[str, ...] | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "list", "--all"],
        env,
        command_label="Snap installed-package inventory",
        timeout_seconds=SNAP_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=SNAP_STATUS_OUTPUT_BYTES,
    )
    if output is None or error or truncated:
        return None, "The installed Snap package state could not be inspected exactly."
    rows: list[str] = []
    for line in output.splitlines():
        fields = line.split()
        if not fields or (
            len(fields) >= 6
            and [field.casefold() for field in fields[:6]]
            == ["name", "version", "rev", "tracking", "publisher", "notes"]
        ):
            continue
        if not package_name or fields[0] == package_name:
            if any(ord(char) < 32 or ord(char) == 127 for char in line):
                return None, "Snap returned an invalid exact-name inventory row."
            rows.append(line)
    return tuple(rows), None


def _active_row(rows: tuple[str, ...]) -> tuple[str | None, str | None, str | None]:
    for row in rows:
        fields = row.split()
        if len(fields) < 6 or "disabled" in _notes_from_fields(fields[5:]):
            continue
        return fields[2], fields[1], fields[3]
    return None, None, None


def _notes_from_fields(fields: list[str]) -> set[str]:
    return {
        note.casefold()
        for field in fields
        for note in field.split(",")
        if note
    }


def _active_notes(rows: tuple[str, ...], revision: str | None) -> set[str]:
    if not revision:
        return set()
    for row in rows:
        fields = row.split()
        if len(fields) >= 6 and fields[2] == revision and not any(
            note == "disabled" for note in _notes_from_fields(fields[5:])
        ):
            return _notes_from_fields(fields[5:])
    return set()


def _notes_for_revision(rows: tuple[str, ...], revision: str | None) -> set[str]:
    if not revision:
        return set()
    matches = [
        row.split()
        for row in rows
        if len(row.split()) >= 6 and row.split()[2] == revision
    ]
    if len(matches) != 1:
        return set()
    return _notes_from_fields(matches[0][5:])


def _installed_revision_from_info(
    binary: str,
    package_name: str,
    env: dict[str, str],
) -> tuple[str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "info", "--verbose", package_name],
        env,
        command_label="Snap installed revision inspection",
        timeout_seconds=SNAP_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=SNAP_STATUS_OUTPUT_BYTES,
    )
    if output is None or error or truncated:
        return None, "The exact installed Snap revision could not be inspected."
    revisions = re.findall(
        r"(?mi)^[ \t]*installed:[^\r\n]*?\(([0-9]+|x[0-9]+)\)(?=[ \t]|$)[^\r\n]*$",
        output,
    )
    if len(revisions) != 1 or not SNAP_REVISION_RE.fullmatch(revisions[0]):
        return None, "Snap did not return one unambiguous installed revision."
    return revisions[0], None


def _revision_ids(rows: tuple[str, ...]) -> tuple[str, ...]:
    revisions = [row.split()[2] for row in rows if len(row.split()) >= 6]
    return tuple(sorted(revisions))


def _package_revision_state(rows: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    state: list[tuple[str, ...]] = []
    for row in rows:
        fields = row.split()
        if len(fields) < 6:
            continue
        notes = _notes_from_fields(fields[5:])
        state.append((
            fields[0], fields[1], fields[2], fields[3],
            "disabled" if "disabled" in notes else "active",
            "classic" if "classic" in notes else "",
            "devmode" if "devmode" in notes else "",
        ))
    return tuple(sorted(state))


def _hold_duration_seconds(value: str) -> int | None:
    if value == "forever":
        return None
    if not isinstance(value, str) or not SNAP_HOLD_DURATION_RE.fullmatch(value):
        return -1
    units = {"h": 3600, "m": 60, "s": 1}
    total = 0
    for amount, unit in re.findall(r"([1-9][0-9]*)([hms])", value):
        total += int(amount) * units[unit]
        if total > MAX_SNAP_HOLD_SECONDS:
            return -1
    return total if total > 0 else -1


def _candidate_confinement(
    binary: str,
    package_name: str,
    env: dict[str, str],
) -> tuple[str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "info", "--verbose", package_name],
        env,
        command_label="Snap candidate confinement inspection",
        timeout_seconds=SNAP_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=SNAP_STATUS_OUTPUT_BYTES,
    )
    if output is None or error or truncated:
        return None, "The candidate Snap confinement could not be inspected safely."
    values = re.findall(r"(?m)^[ \t]*confinement:[ \t]*(classic|strict|devmode)[ \t]*$", output)
    if len(values) != 1:
        return None, "Snap did not return one unambiguous candidate confinement mode."
    return values[0], None


def _hash_local_snap_file(path: str) -> tuple[str | None, str | None, int | None, str | None]:
    if (
        not isinstance(path, str)
        or not path
        or len(path) > MAX_LOCAL_SNAP_PATH_CHARS
        or not os.path.isabs(path)
        or not path.casefold().endswith(".snap")
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
    ):
        return None, None, None, "A local Snap source must be one absolute .snap file path without control characters."
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, None, None, "The local Snap file could not be opened safely."
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_mode & 0o022
            or before.st_size <= 0
            or before.st_size > MAX_LOCAL_SNAP_FILE_BYTES
        ):
            return None, None, None, "The local Snap file must be a current-user-owned, non-writable regular file within the size limit."
        digest = hashlib.sha256()
        total = 0
        while total <= MAX_LOCAL_SNAP_FILE_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_LOCAL_SNAP_FILE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_LOCAL_SNAP_FILE_BYTES:
                return None, None, None, "The local Snap file grew beyond the size limit."
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_uid, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_uid, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if total != before.st_size or identity_before != identity_after:
            return None, None, None, "The local Snap file changed while its contents were being inspected."
    except OSError:
        return None, None, None, "The local Snap file could not be read safely."
    finally:
        os.close(descriptor)
    content_digest = digest.hexdigest()
    identity_payload = json.dumps(
        {
            "dev": before.st_dev,
            "ino": before.st_ino,
            "uid": before.st_uid,
            "mode": before.st_mode,
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns,
            "sha256": content_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return content_digest, hashlib.sha256(identity_payload).hexdigest(), before.st_size, None


def _local_snap_metadata(
    binary: str,
    path: str,
    env: dict[str, str],
) -> tuple[str | None, str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "info", "--verbose", path],
        env,
        command_label="Local Snap metadata inspection",
        timeout_seconds=SNAP_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=SNAP_STATUS_OUTPUT_BYTES,
    )
    if output is None or error or truncated:
        return None, None, "The local Snap package metadata could not be inspected safely."
    names = re.findall(r"(?m)^[ \t]*name:[ \t]*([a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?)[ \t]*$", output)
    confinements = re.findall(r"(?m)^[ \t]*confinement:[ \t]*(classic|strict|devmode)[ \t]*$", output)
    if len(names) != 1 or len(confinements) != 1:
        return None, None, "Snap did not return unambiguous name and confinement metadata for the local file."
    return names[0], confinements[0], None


def _canonical_channel(channel: str | None) -> str | None:
    if (
        not isinstance(channel, str)
        or len(channel) > 160
        or not SNAP_CHANNEL_RE.fullmatch(channel)
    ):
        return None
    parts = channel.split("/")
    if not all(SNAP_CHANNEL_SEGMENT_RE.fullmatch(part) for part in parts):
        return None
    if len(parts) == 1:
        return f"latest/{parts[0]}" if parts[0] in SNAP_CHANNEL_RISKS else None
    if len(parts) == 2:
        if parts[0] in SNAP_CHANNEL_RISKS:
            return f"latest/{parts[0]}/{parts[1]}"
        if parts[1] in SNAP_CHANNEL_RISKS:
            return channel
        return None
    if parts[1] not in SNAP_CHANNEL_RISKS:
        return None
    return channel


def _channels_match(left: str | None, right: str | None) -> bool:
    return _canonical_channel(left) is not None and _canonical_channel(left) == _canonical_channel(right)


def _capture_snapshot(
    action: SnapPackageAction,
    package_name: str,
    target_channel: str | None = None,
    classic: bool = False,
    snap_file_path: str = "",
    dangerous: bool = False,
    devmode: bool = False,
    *,
    target_revision: str | None = None,
    hold_duration: str | None = None,
    inspect_source: bool = True,
) -> tuple[SnapPackageSnapshot | None, str | None]:
    binary = detect_application_package_tools().get("snap")
    if not binary:
        return None, "The optional snap command is unavailable."
    env = _environment()
    rows, error = _installed_rows(binary, package_name, env)
    if error or rows is None:
        return None, error or "The installed Snap state could not be confirmed."
    revision, version, tracking = _active_row(rows)
    if not rows:
        revision = version = tracking = None
    installed_revision: str | None = None
    if action in {"enable", "disable"} and rows:
        installed_revision, error = _installed_revision_from_info(binary, package_name, env)
        if error or installed_revision is None:
            return None, error or "The Snap's installed revision could not be verified."
        installed_rows = [row.split() for row in rows if len(row.split()) >= 6 and row.split()[2] == installed_revision]
        if len(installed_rows) != 1:
            return None, "The installed revision reported by snap info is absent from the exact installed revision inventory."
        if revision is not None and installed_revision != revision:
            return None, "The active row and snap info disagree about the exact installed Snap revision."
        if revision is None:
            version, tracking = installed_rows[0][1], installed_rows[0][3]
    active_rows = [
        row.split()
        for row in rows
        if len(row.split()) >= 6 and "disabled" not in _notes_from_fields(row.split()[5:])
    ]
    if package_name:
        held = "held" in _notes_for_revision(rows, revision)
        any_held = held
    else:
        active_hold_states = ["held" in _notes_from_fields(fields[5:]) for fields in active_rows]
        held = bool(active_hold_states) and all(active_hold_states)
        any_held = any(active_hold_states)
    target_confinement: str | None = None
    local_file_digest: str | None = None
    local_file_fingerprint: str | None = None
    local_file_size: int | None = None
    if action == "install" and snap_file_path and inspect_source:
        local_file_digest, local_file_fingerprint, local_file_size, file_error = _hash_local_snap_file(snap_file_path)
        if file_error:
            return None, file_error
        local_name, target_confinement, metadata_error = _local_snap_metadata(binary, snap_file_path, env)
        if metadata_error:
            return None, metadata_error
        digest_after, fingerprint_after, size_after, file_error = _hash_local_snap_file(snap_file_path)
        if file_error or digest_after != local_file_digest or fingerprint_after != local_file_fingerprint or size_after != local_file_size:
            return None, file_error or "The local Snap file changed during metadata inspection."
        if local_name != package_name:
            return None, "The local Snap file's exact package name does not match package_name."
        if target_confinement == "classic" and not classic:
            return None, "The local Snap file uses classic confinement; explicitly select classic=true to proceed."
        if classic and target_confinement != "classic":
            return None, "The local Snap file is not published for classic confinement."
        if target_confinement == "devmode" and not devmode:
            return None, "The local Snap file requires developer mode; explicitly select devmode=true to proceed."
        if devmode and target_confinement != "devmode":
            return None, "The local Snap file is not published for developer mode."
    elif action == "install" and classic and inspect_source:
        if rows:
            if "classic" not in _active_notes(rows, revision):
                return None, "The installed Snap does not report classic confinement in its active revision."
            target_confinement = "classic"
        else:
            target_confinement, confinement_error = _candidate_confinement(binary, package_name, env)
            if confinement_error:
                return None, confinement_error
            if target_confinement != "classic":
                return None, "The selected stable-channel Snap is not published for classic confinement."

    uid = os.getuid()
    euid = os.geteuid()
    context = {
        "action": action,
        "package_name": package_name,
        "target_channel": target_channel,
        "target_revision": target_revision,
        "hold_duration": hold_duration,
        "installed_revision": installed_revision,
        "held": held,
        "any_held": any_held,
        "classic": classic,
        "devmode": devmode,
        "target_confinement": target_confinement,
        "snap_file_path": snap_file_path,
        "local_file_digest": local_file_digest,
        "local_file_fingerprint": local_file_fingerprint,
        "local_file_size": local_file_size,
        "dangerous": dangerous,
        "binary": binary,
        "rows": rows,
        "uid": uid,
        "euid": euid,
    }
    encoded = json.dumps(context, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return SnapPackageSnapshot(
        action=action,
        package_name=package_name,
        binary=binary,
        installed_rows=rows,
        active_revision=revision,
        version=version,
        tracking=tracking,
        target_channel=target_channel,
        target_revision=target_revision,
        hold_duration=hold_duration,
        installed_revision=installed_revision,
        held=held,
        any_held=any_held,
        classic=classic,
        devmode=devmode,
        target_confinement=target_confinement,
        snap_file_path=snap_file_path,
        local_file_digest=local_file_digest,
        local_file_fingerprint=local_file_fingerprint,
        local_file_size=local_file_size,
        dangerous=dangerous,
        uid=uid,
        euid=euid,
        state_token=hashlib.sha256(encoded).hexdigest(),
    ), None


def snap_action_confirmation_details(
    action: str,
    package_name: str,
    target_channel: str = "",
    classic: bool = False,
    snap_file_path: str = "",
    dangerous: bool = False,
    devmode: bool = False,
    revision: int | None = None,
    hold_duration: str = "",
) -> SnapPackageSnapshot | str:
    if not sys.platform.startswith("linux"):
        return "Snap package operations are available only on Linux."
    if not isinstance(action, str) or action not in SNAP_ACTIONS:
        return "Action must be install, update, switch_channel, remove, enable, disable, revert, hold, unhold, hold_all, or unhold_all."
    if not isinstance(package_name, str):
        return "package_name must be text."
    if action in {"hold_all", "unhold_all"}:
        if package_name:
            return "package_name must be empty for a system-wide refresh hold action."
    elif not SNAP_NAME_RE.fullmatch(package_name):
        return "Package name must be one exact Snap Store name containing lowercase letters, numbers, or internal hyphens."
    if type(classic) is not bool:
        return "classic must be a boolean."
    if classic and action != "install":
        return "Classic confinement can be selected only for installation."
    if type(devmode) is not bool:
        return "devmode must be a boolean."
    if devmode and action != "install":
        return "Developer mode can be selected only for installation."
    if devmode and not snap_file_path:
        return "Developer mode is available only for a local Snap file."
    if devmode and classic:
        return "Classic and developer confinement modes cannot be selected together."
    if type(dangerous) is not bool:
        return "dangerous must be a boolean."
    if not isinstance(snap_file_path, str):
        return "snap_file_path must be text."
    if snap_file_path and action != "install":
        return "A local Snap file can be selected only for installation."
    if dangerous and not snap_file_path:
        return "dangerous=true is available only for a local Snap file."
    if snap_file_path and target_channel:
        return "A local Snap file cannot be combined with a target channel."
    if action == "remove" and package_name == "snapd":
        return "Removing the snapd control-plane package is not supported."

    normalized_channel: str | None = None
    if action == "switch_channel":
        normalized_channel = _canonical_channel(target_channel)
        if normalized_channel is None:
            return "A valid Snap channel is required: stable, candidate, beta, edge, risk/branch, track/risk, or track/risk/branch."
    elif target_channel:
        return "A target channel is accepted only for switch_channel."

    target_revision: str | None = None
    if action == "revert":
        if type(revision) is not int or not 1 <= revision <= 2_147_483_647:
            return "revert requires one installed numeric revision from 1 through 2147483647."
        target_revision = str(revision)
    elif revision is not None:
        return "revision is used only for revert."

    normalized_hold_duration: str | None = None
    if action in {"hold", "hold_all"}:
        requested_hold_duration = "forever" if action == "hold_all" and hold_duration == "" else hold_duration
        seconds = _hold_duration_seconds(requested_hold_duration)
        if seconds == -1:
            return "hold_duration must be 'forever' or an integer duration such as 30m, 12h, or 1h30m, with a maximum of 90 days."
        normalized_hold_duration = requested_hold_duration
    elif hold_duration:
        return "hold_duration is used only for hold or hold_all."

    snapshot, error = _capture_snapshot(
        action,
        package_name,
        normalized_channel,
        classic,
        snap_file_path,
        dangerous,
        devmode,
        target_revision=target_revision,
        hold_duration=normalized_hold_duration,
    )
    if snapshot is None:
        return error or "The exact Snap package state could not be inspected."
    if action == "install" and snapshot.installed_rows:
        return "The exact Snap name is already installed; no install was prepared."
    if action in {"hold_all", "unhold_all"} and not snapshot.installed_rows:
        return "No installed Snaps were found for a system-wide refresh hold action."
    if action == "hold_all" and snapshot.active_revision is None:
        return "No active installed Snap was found for a system-wide refresh hold action."
    if action in {"update", "switch_channel", "remove", "enable", "disable", "revert", "hold", "unhold"} and not snapshot.installed_rows:
        return "The exact Snap name is not installed."
    if action in {"update", "switch_channel"} and not snapshot.active_revision:
        return "The exact Snap has no active revision that can be refreshed."
    if action == "update" and (not snapshot.tracking or not SNAP_CHANNEL_RE.fullmatch(snapshot.tracking)):
        return "The exact Snap has no recognized tracking channel to refresh safely."
    if action == "switch_channel" and not _channels_match(snapshot.tracking, normalized_channel):
        if not snapshot.tracking or _canonical_channel(snapshot.tracking) is None:
            return "The exact Snap has no recognized current tracking channel to switch safely."
    elif action == "switch_channel":
        return "The exact Snap already tracks the requested channel; no change was prepared."
    if action == "enable":
        if snapshot.active_revision is not None:
            return "The exact Snap is already enabled."
        if snapshot.installed_revision is None or "disabled" not in _notes_for_revision(snapshot.installed_rows, snapshot.installed_revision):
            return "The exact Snap disabled state and installed revision could not be verified safely."
    if action == "disable" and snapshot.active_revision is None:
        return "The exact Snap is already disabled or has no active revision."
    if action == "revert":
        if snapshot.active_revision is None:
            return "The exact Snap must be enabled before it can be reverted."
        if target_revision == snapshot.active_revision:
            return "The requested revision is already active."
        if "disabled" not in _notes_for_revision(snapshot.installed_rows, target_revision):
            return "The requested revert revision is not present as a retained inactive revision for this Snap."
    if action in {"hold", "unhold"} and snapshot.active_revision is None:
        return "Refresh holds can be changed only for an enabled Snap with an active revision."
    if action == "unhold" and not snapshot.held:
        return "The exact Snap does not currently report a refresh hold."
    if action == "unhold_all" and not snapshot.any_held:
        return "No installed Snap currently reports a refresh hold to remove."
    if action == "hold_all" and snapshot.held:
        return "All active installed Snaps already report a refresh hold."
    return snapshot


def _command_for_snapshot(snapshot: SnapPackageSnapshot) -> list[str]:
    if snapshot.action == "install":
        if snapshot.snap_file_path:
            command = [snapshot.binary, "install"]
            if snapshot.classic:
                command.append("--classic")
            if snapshot.devmode:
                command.append("--devmode")
            if snapshot.dangerous:
                command.append("--dangerous")
            return command + [snapshot.snap_file_path]
        command = [snapshot.binary, "install", "--channel=stable"]
        if snapshot.classic:
            command.append("--classic")
        return command + [snapshot.package_name]
    if snapshot.action == "update":
        return [snapshot.binary, "refresh", f"--channel={snapshot.tracking}", snapshot.package_name]
    if snapshot.action == "switch_channel":
        return [snapshot.binary, "refresh", f"--channel={snapshot.target_channel}", snapshot.package_name]
    if snapshot.action == "remove":
        return [snapshot.binary, "remove", snapshot.package_name]
    if snapshot.action == "enable":
        return [snapshot.binary, "enable", snapshot.package_name]
    if snapshot.action == "disable":
        return [snapshot.binary, "disable", snapshot.package_name]
    if snapshot.action == "revert":
        return [snapshot.binary, "revert", snapshot.package_name, "--revision", snapshot.target_revision or ""]
    if snapshot.action in {"hold", "hold_all"}:
        command = [snapshot.binary, "refresh", "--hold"]
        if snapshot.hold_duration != "forever":
            command[-1] = f"--hold={snapshot.hold_duration}"
        return command + ([snapshot.package_name] if snapshot.package_name else [])
    if snapshot.action == "unhold_all":
        return [snapshot.binary, "refresh", "--unhold"]
    return [snapshot.binary, "refresh", "--unhold", snapshot.package_name]


def _response(
    action: SnapPackageAction,
    package_name: str,
    *,
    success: bool,
    confirmed: bool,
    classic: bool = False,
    local_file: bool = False,
    dangerous: bool = False,
    devmode: bool = False,
    target_channel: str | None = None,
    revision: str | None = None,
    hold_duration: str | None = None,
    enabled: bool | None = None,
    held: bool | None = None,
    state_verified: bool = False,
    return_code: int | None = None,
    timed_out: bool = False,
    message: str,
) -> SnapPackageActionResponse:
    return SnapPackageActionResponse(
        success=success,
        action=action,
        package_name=package_name,
        target_channel=target_channel,
        revision=revision,
        hold_duration=hold_duration,
        enabled=enabled,
        held=held,
        classic=classic,
        devmode=devmode,
        local_file=local_file,
        dangerous=dangerous,
        state_verified=state_verified,
        return_code=return_code,
        timed_out=timed_out,
        user_confirmed=confirmed,
        message=message,
    )


def perform_snap_package_action(
    action: SnapPackageAction,
    package_name: str,
    expected_state_token: str,
    *,
    target_channel: str = "",
    classic: bool = False,
    snap_file_path: str = "",
    dangerous: bool = False,
    devmode: bool = False,
    revision: int | None = None,
    hold_duration: str = "",
    confirmed: bool = False,
) -> SnapPackageActionResponse:
    valid_action = isinstance(action, str) and action in SNAP_ACTIONS
    safe_action: SnapPackageAction = action if valid_action else "install"
    safe_name = (
        "all"
        if isinstance(package_name, str) and not package_name and action in {"hold_all", "unhold_all"}
        else package_name[:40] if isinstance(package_name, str) else ""
    )
    safe_channel = target_channel[:160] if isinstance(target_channel, str) and target_channel else None
    safe_classic = classic if type(classic) is bool else False
    safe_file_path = snap_file_path if isinstance(snap_file_path, str) else ""
    safe_local_file = bool(safe_file_path)
    safe_dangerous = dangerous if type(dangerous) is bool else False
    safe_devmode = devmode if type(devmode) is bool else False
    safe_revision = str(revision) if type(revision) is int and 1 <= revision <= 2_147_483_647 else None
    safe_hold_duration = hold_duration if isinstance(hold_duration, str) and len(hold_duration) <= 16 else ""
    initial_revision = safe_revision
    initial_hold_duration = safe_hold_duration or ("forever" if safe_action == "hold_all" else None)

    def respond(**kwargs) -> SnapPackageActionResponse:
        kwargs.setdefault("revision", initial_revision)
        kwargs.setdefault("hold_duration", initial_hold_duration)
        return _response(
            safe_action,
            safe_name,
            target_channel=safe_channel,
            classic=safe_classic,
            local_file=safe_local_file,
            dangerous=safe_dangerous,
            devmode=safe_devmode,
            **kwargs,
        )

    if not valid_action:
        return respond(success=False, confirmed=False, message="Unsupported Snap action; no command was run.")
    if type(classic) is not bool:
        return respond(success=False, confirmed=False, message="classic must be a boolean; no command was run.")
    if type(dangerous) is not bool:
        return respond(success=False, confirmed=False, message="dangerous must be a boolean; no command was run.")
    if type(devmode) is not bool:
        return respond(success=False, confirmed=False, message="devmode must be a boolean; no command was run.")
    if revision is not None and type(revision) is not int:
        return respond(success=False, confirmed=False, message="revision must be an integer when provided; no command was run.")
    if not isinstance(hold_duration, str):
        return respond(success=False, confirmed=False, message="hold_duration must be text; no command was run.")
    if confirmed is not True:
        return respond(success=False, confirmed=False, message="Explicit MCP client confirmation is required; no Snap command was run.")

    target_or_error = snap_action_confirmation_details(
        action,
        package_name,
        target_channel,
        classic,
        safe_file_path,
        dangerous,
        devmode,
        revision,
        hold_duration,
    )
    target = target_or_error if isinstance(target_or_error, SnapPackageSnapshot) else None
    if target is None:
        return respond(success=False, confirmed=True, message=str(target_or_error))
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return respond(success=False, confirmed=True, message="A valid state token from the exact Snap confirmation is required; no change was made.")
    if target.state_token != expected_state_token:
        return respond(success=False, confirmed=True, message="The selected Snap name, target channel, local-file digest, assertion-bypass mode, classic/developer mode, or installed revision state changed after confirmation; review and confirm again.")

    command = _command_for_snapshot(target)
    env = _environment()
    deadline = time.monotonic() + PACKAGE_ACTION_TIMEOUT_SECONDS
    return_code, timed_out, error = _run_transaction_command(command, env, deadline)
    if error:
        return respond(success=False, confirmed=True, message=f"{error} Snap output was withheld; inspect package state before retrying.")
    if timed_out:
        return respond(success=False, confirmed=True, timed_out=True, message=f"The Snap operation exceeded {PACKAGE_ACTION_TIMEOUT_SECONDS} seconds and was asked to stop. Package state may be incomplete; inspect it before retrying.")
    if return_code != 0:
        return respond(success=False, confirmed=True, return_code=return_code, message=f"Snap exited with status {return_code}. Output was withheld; inspect Snap history and current package state.")

    post_snapshot, verify_error = _capture_snapshot(
        action,
        package_name,
        target.target_channel,
        classic,
        safe_file_path,
        dangerous,
        devmode,
        target_revision=target.target_revision,
        hold_duration=target.hold_duration,
        inspect_source=False,
    )
    if post_snapshot is None:
        return respond(success=False, confirmed=True, return_code=return_code, message=verify_error or "The Snap result could not be verified; inspect package state.")
    same_context = (
        post_snapshot.binary == target.binary
        and post_snapshot.uid == target.uid
        and post_snapshot.euid == target.euid
        and post_snapshot.classic == target.classic
        and post_snapshot.devmode == target.devmode
        and post_snapshot.snap_file_path == target.snap_file_path
        and post_snapshot.dangerous == target.dangerous
        and post_snapshot.target_revision == target.target_revision
        and post_snapshot.hold_duration == target.hold_duration
        and post_snapshot.installed_revision == target.installed_revision
        and (
            bool(target.package_name)
            or _package_revision_state(post_snapshot.installed_rows) == _package_revision_state(target.installed_rows)
        )
    )
    if action == "install":
        if target.snap_file_path:
            notes = _active_notes(post_snapshot.installed_rows, post_snapshot.active_revision)
            verified = (
                bool(post_snapshot.installed_rows)
                and bool(post_snapshot.active_revision)
                and (not classic or "classic" in notes)
                and (not devmode or "devmode" in notes)
            )
        else:
            verified = (
                bool(post_snapshot.installed_rows)
                and bool(post_snapshot.active_revision)
                and post_snapshot.tracking in {"latest/stable", "stable"}
                and (not classic or "classic" in _active_notes(post_snapshot.installed_rows, post_snapshot.active_revision))
            )
    elif action == "update":
        verified = (
            bool(post_snapshot.installed_rows)
            and bool(post_snapshot.active_revision)
            and post_snapshot.tracking == target.tracking
        )
    elif action == "switch_channel":
        verified = (
            bool(post_snapshot.installed_rows)
            and bool(post_snapshot.active_revision)
            and _channels_match(post_snapshot.tracking, target.target_channel)
        )
    elif action == "remove":
        verified = not post_snapshot.installed_rows
    elif action == "enable":
        verified = (
            post_snapshot.active_revision == target.installed_revision
            and _revision_ids(post_snapshot.installed_rows) == _revision_ids(target.installed_rows)
            and post_snapshot.tracking == target.tracking
        )
    elif action == "disable":
        verified = (
            bool(post_snapshot.installed_rows)
            and post_snapshot.active_revision is None
            and _revision_ids(post_snapshot.installed_rows) == _revision_ids(target.installed_rows)
            and post_snapshot.tracking == target.tracking
        )
    elif action == "revert":
        verified = (
            post_snapshot.active_revision == target.target_revision
            and _revision_ids(post_snapshot.installed_rows) == _revision_ids(target.installed_rows)
            and post_snapshot.tracking == target.tracking
        )
    elif action == "hold":
        verified = (
            post_snapshot.active_revision == target.active_revision
            and post_snapshot.held
            and _revision_ids(post_snapshot.installed_rows) == _revision_ids(target.installed_rows)
        )
    elif action == "hold_all":
        verified = (
            post_snapshot.held
            and _package_revision_state(post_snapshot.installed_rows) == _package_revision_state(target.installed_rows)
        )
    elif action == "unhold_all":
        verified = (
            not post_snapshot.any_held
            and _package_revision_state(post_snapshot.installed_rows) == _package_revision_state(target.installed_rows)
        )
    else:
        verified = (
            post_snapshot.active_revision == target.active_revision
            and not post_snapshot.held
            and _revision_ids(post_snapshot.installed_rows) == _revision_ids(target.installed_rows)
        )
    if not (verified and same_context):
        return respond(success=False, confirmed=True, return_code=return_code, message="Snap exited successfully but the requested exact-name state, confinement mode, or installation context did not verify; inspect package state.")
    state = {
        "install": "installed",
        "update": "updated",
        "switch_channel": "switched and refreshed",
        "remove": "removed",
        "enable": "enabled",
        "disable": "disabled",
        "revert": f"reverted to revision {target.target_revision}",
        "hold": f"held from automatic/general refreshes ({target.hold_duration})",
        "unhold": "unheld from Snap refreshes",
        "hold_all": f"held from automatic refreshes ({target.hold_duration})",
        "unhold_all": "unheld from automatic refreshes",
    }[action]
    mode = " in developer mode" if action == "install" and devmode else ""
    if action in {"hold", "unhold"}:
        message = f"The exact Snap package was {state}, and its per-Snap hold state was verified."
    elif action in {"hold_all", "unhold_all"}:
        message = f"Automatic refreshes for all installed Snaps were {state}, and the complete installed package state was verified."
    else:
        message = f"The exact Snap package was {state}{mode} and the resulting system state was verified."
    if action == "remove":
        message += " The command did not use --purge; automatic data snapshots depend on snapd version and host policy."
    if action == "revert":
        message += " Snap restores the revision-specific configuration data associated with the selected revision; shared data may remain changed."
    if action == "hold":
        message += " The post-action check verifies the held note but does not inspect or verify the hold's expiration time. A per-Snap hold does not block a specifically targeted refresh, and snapd limits finite holds to 90 days."
    if action == "hold_all":
        message += " The global hold affects automatic refreshes only; general or specifically targeted refresh requests can still proceed. The post-action check verifies held notes but does not inspect the hold's expiration time."
    if action == "disable":
        message += " The Snap's commands become unavailable and its services do not start while it is disabled."
    return respond(
        success=True,
        confirmed=True,
        state_verified=True,
        revision=target.target_revision or target.installed_revision or target.active_revision,
        enabled=post_snapshot.active_revision is not None if target.package_name else None,
        held=post_snapshot.held,
        return_code=return_code,
        message=message,
    )
