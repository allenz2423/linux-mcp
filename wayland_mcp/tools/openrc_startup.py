"""Bounded OpenRC runlevel inventory and exact confirmed startup changes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    OpenRCRunlevelInfo,
    OpenRCRunlevelListResponse,
    OpenRCServiceStartupResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.host import _detect_init_system

OpenRCStartupAction = Literal["enable", "disable"]
RUNLEVEL_ROOT = Path("/etc/runlevels")
SERVICE_ROOTS = (Path("/etc/init.d"), Path("/usr/local/etc/init.d"))
RUNLEVEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:+-]{0,127}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:+-]{0,254}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_RUNLEVEL_SCAN_ENTRIES = 4096
MAX_SERVICE_SCAN_ENTRIES = 20_000
MAX_SERVICES_PER_RUNLEVEL = 1000
MAX_TOTAL_SERVICE_LINKS = 4000
MAX_TOTAL_SERVICE_SCAN_ENTRIES = 50_000
MAX_RETURNED_RUNLEVELS = 64
COMMAND_TIMEOUT_SECONDS = 30
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024


@dataclass(frozen=True)
class OpenRCStartupSnapshot:
    unit: str
    runlevel: str
    enabled: bool
    state_token: str


def openrc_startup_control_available() -> bool:
    if not sys.platform.startswith("linux") or _detect_init_system() != "openrc":
        return False
    env = get_sanitized_env()
    return (
        bool(find_session_binary("rc-update", env))
        and RUNLEVEL_ROOT.is_dir()
        and any(root.is_dir() for root in SERVICE_ROOTS)
    )


def _resolved_runlevel_root() -> tuple[Path | None, str | None]:
    try:
        root = RUNLEVEL_ROOT.resolve(strict=True)
        if not root.is_dir():
            return None, "The OpenRC runlevel configuration directory is unavailable."
        return root, None
    except (OSError, RuntimeError):
        return None, "The OpenRC runlevel configuration directory is unavailable."


def _list_runlevels(query: str = "", limit: int = 64) -> OpenRCRunlevelListResponse:
    if not sys.platform.startswith("linux"):
        return OpenRCRunlevelListResponse(success=False, message="OpenRC runlevels are available only on Linux.")
    if _detect_init_system() != "openrc":
        return OpenRCRunlevelListResponse(success=False, message="OpenRC runlevels require OpenRC as the active init system.")
    if not isinstance(query, str) or len(query) > 128:
        return OpenRCRunlevelListResponse(success=False, message="Query must be a string up to 128 characters.")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_RETURNED_RUNLEVELS:
        return OpenRCRunlevelListResponse(success=False, message=f"Limit must be between 1 and {MAX_RETURNED_RUNLEVELS}.")
    root, error = _resolved_runlevel_root()
    if root is None:
        return OpenRCRunlevelListResponse(success=False, message=error)

    entries: list[Path] = []
    scan_truncated = False
    try:
        with os.scandir(root) as iterator:
            for index, entry in enumerate(iterator, start=1):
                if index > MAX_RUNLEVEL_SCAN_ENTRIES:
                    scan_truncated = True
                    break
                entries.append(root / entry.name)
    except OSError as exc:
        return OpenRCRunlevelListResponse(
            success=False,
            message=f"Could not read OpenRC runlevels: {exc.strerror or 'read error'}.",
        )
    entries.sort(key=lambda path: path.name.casefold())

    runlevels: list[OpenRCRunlevelInfo] = []
    service_scan_truncated = False
    total_service_links = 0
    total_service_scan_entries = 0
    needle = query.strip().casefold()
    for entry_index, entry in enumerate(entries, start=1):
        if not RUNLEVEL_RE.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir():
            continue
        if needle and needle not in entry.name.casefold():
            continue
        service_names: list[str] = []
        runlevel_service_truncated = False
        try:
            for index, service_entry in enumerate(entry.iterdir(), start=1):
                total_service_scan_entries += 1
                if total_service_scan_entries > MAX_TOTAL_SERVICE_SCAN_ENTRIES:
                    service_scan_truncated = True
                    runlevel_service_truncated = True
                    break
                if index > MAX_SERVICE_SCAN_ENTRIES:
                    service_scan_truncated = True
                    runlevel_service_truncated = True
                    break
                if not SERVICE_RE.fullmatch(service_entry.name) or not service_entry.is_symlink():
                    continue
                if (
                    len(service_names) >= MAX_SERVICES_PER_RUNLEVEL
                    or total_service_links >= MAX_TOTAL_SERVICE_LINKS
                ):
                    service_scan_truncated = True
                    runlevel_service_truncated = True
                    break
                service_names.append(service_entry.name)
                total_service_links += 1
        except OSError:
            service_scan_truncated = True
            runlevel_service_truncated = True
        service_names.sort(key=str.casefold)
        runlevels.append(OpenRCRunlevelInfo(
            name=entry.name,
            services=service_names,
            service_count=len(service_names),
            truncated=runlevel_service_truncated,
        ))
        if len(runlevels) >= MAX_RETURNED_RUNLEVELS:
            if entry_index < len(entries):
                scan_truncated = True
            break
        if total_service_scan_entries >= MAX_TOTAL_SERVICE_SCAN_ENTRIES:
            service_scan_truncated = True
            break

    return OpenRCRunlevelListResponse(
        success=True,
        total_runlevels=len(runlevels),
        returned_runlevels=min(len(runlevels), limit),
        runlevels=runlevels[:limit],
        limit=limit,
        truncated=scan_truncated or service_scan_truncated or len(runlevels) > limit,
        message=(
            "OpenRC runlevels are read from existing /etc/runlevels directories; only service-link names are returned."
            if runlevels
            else "No matching existing OpenRC runlevel directories were found."
        ),
    )


def list_openrc_runlevels(query: str = "", limit: int = 64) -> OpenRCRunlevelListResponse:
    """List existing OpenRC runlevel directories and their service-link names."""
    return _list_runlevels(query=query, limit=limit)


def _service_script(unit: str) -> tuple[Path | None, str | None]:
    candidates: list[Path] = []
    for root in SERVICE_ROOTS:
        candidate = root / unit
        try:
            if candidate.is_file():
                resolved = candidate.resolve(strict=True)
                if resolved.is_file() and resolved not in candidates:
                    candidates.append(resolved)
        except (OSError, RuntimeError):
            continue
    if not candidates:
        return None, "The exact OpenRC service script was not found in a standard init.d directory."
    if len(candidates) != 1:
        return None, "The exact OpenRC service resolves to multiple scripts; no startup change is available."
    return candidates[0], None


def _read_startup_snapshot(
    unit: str,
    runlevel: str,
) -> tuple[OpenRCStartupSnapshot | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "OpenRC startup control is available only on Linux."
    if _detect_init_system() != "openrc":
        return None, "OpenRC startup control requires OpenRC as the active init system."
    if not isinstance(unit, str) or len(unit) > 255 or not SERVICE_RE.fullmatch(unit):
        return None, "Service must be one exact OpenRC service name."
    if not isinstance(runlevel, str) or len(runlevel) > 128 or not RUNLEVEL_RE.fullmatch(runlevel):
        return None, "Runlevel must be one exact existing OpenRC runlevel name."

    env = get_sanitized_env()
    rc_update = find_session_binary("rc-update", env)
    if not rc_update:
        return None, "rc-update is unavailable on this OpenRC host."
    service_script, service_error = _service_script(unit)
    if service_script is None:
        return None, service_error
    root, root_error = _resolved_runlevel_root()
    if root is None:
        return None, root_error
    try:
        root_stat = root.stat()
        runlevel_dir = root / runlevel
        if runlevel_dir.is_symlink() or not runlevel_dir.is_dir():
            return None, "The exact OpenRC runlevel does not exist as a regular runlevel directory."
        runlevel_stat = runlevel_dir.stat()
        entry = runlevel_dir / unit
        try:
            entry_stat = entry.lstat()
        except FileNotFoundError:
            enabled = False
            link_target = None
        else:
            if not stat.S_ISLNK(entry_stat.st_mode):
                return None, "The exact runlevel service entry is not a symlink; no startup change is available."
            link_target = os.readlink(entry)
            resolved_entry = entry.resolve(strict=True)
            if resolved_entry != service_script:
                return None, "The exact runlevel entry points to a different service script; no startup change is available."
            enabled = True
        script_stat = service_script.stat()
    except FileNotFoundError:
        return None, "OpenRC runlevel or service state changed while it was being read."
    except (OSError, RuntimeError):
        return None, "Could not safely read the exact OpenRC runlevel service state."

    state = {
        "unit": unit,
        "runlevel": runlevel,
        "enabled": enabled,
        "link_target": link_target,
        "runlevel_root": str(root),
        "runlevel_root_identity": [root_stat.st_dev, root_stat.st_ino],
        "runlevel_identity": [runlevel_stat.st_dev, runlevel_stat.st_ino],
        "service_script": str(service_script),
        "service_identity": [script_stat.st_dev, script_stat.st_ino],
    }
    encoded = json.dumps(state, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return OpenRCStartupSnapshot(
        unit=unit,
        runlevel=runlevel,
        enabled=enabled,
        state_token=hashlib.sha256(encoded).hexdigest(),
    ), None


def openrc_startup_confirmation_details(
    action: str,
    unit: str,
    runlevel: str,
) -> tuple[OpenRCStartupSnapshot | None, str | None]:
    if not isinstance(action, str) or action not in {"enable", "disable"}:
        return None, "Action must be enable or disable."
    return _read_startup_snapshot(unit, runlevel)


def _response(
    action: OpenRCStartupAction,
    unit: str,
    runlevel: str,
    *,
    confirmed: bool,
    snapshot: OpenRCStartupSnapshot | None,
    success: bool,
    verified: bool = False,
    message: str,
) -> OpenRCServiceStartupResponse:
    return OpenRCServiceStartupResponse(
        success=success,
        action=action,
        unit=unit,
        runlevel=runlevel,
        runlevel_membership=("present" if snapshot.enabled else "absent") if snapshot else None,
        state_verified=verified,
        user_confirmed=confirmed,
        message=message,
    )


def perform_openrc_startup_action(
    action: OpenRCStartupAction,
    unit: str,
    runlevel: str,
    expected_state_token: str,
    *,
    confirmed: bool = False,
) -> OpenRCServiceStartupResponse:
    valid_action = isinstance(action, str) and action in {"enable", "disable"}
    safe_action: OpenRCStartupAction = action if valid_action else "enable"
    safe_unit = unit[:255] if isinstance(unit, str) else ""
    safe_runlevel = runlevel[:128] if isinstance(runlevel, str) else ""
    if not valid_action:
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=False, snapshot=None, success=False,
            message="Unsupported OpenRC startup action supplied; no command was run.",
        )
    if not isinstance(unit, str) or len(unit) > 255 or not SERVICE_RE.fullmatch(unit):
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=False, snapshot=None, success=False,
            message="Service must be one exact OpenRC service name; no command was run.",
        )
    if not isinstance(runlevel, str) or len(runlevel) > 128 or not RUNLEVEL_RE.fullmatch(runlevel):
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=False, snapshot=None, success=False,
            message="Runlevel must be one exact OpenRC runlevel name; no command was run.",
        )
    if confirmed is not True:
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=False, snapshot=None, success=False,
            message="Explicit client confirmation is required; no OpenRC startup change was run.",
        )
    snapshot, error = _read_startup_snapshot(safe_unit, safe_runlevel)
    if snapshot is None:
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=True, snapshot=None, success=False,
            message=error or "The exact OpenRC startup state could not be revalidated; no command was run.",
        )
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=True, snapshot=snapshot, success=False,
            message="A valid state token from the exact OpenRC startup confirmation is required; no command was run.",
        )
    if snapshot.state_token != expected_state_token:
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=True, snapshot=snapshot, success=False,
            message="OpenRC runlevel or service state changed after confirmation; no command was run. Review and confirm again.",
        )

    desired_enabled = safe_action == "enable"
    desired_state = "enabled" if desired_enabled else "disabled"
    if snapshot.enabled == desired_enabled:
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=True, snapshot=snapshot, success=True,
            verified=True, message=f"{safe_unit} was already {desired_state} in OpenRC runlevel {safe_runlevel}; no change was needed.",
        )

    env = get_sanitized_env()
    rc_update = find_session_binary("rc-update", env)
    if not rc_update:
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=True, snapshot=snapshot, success=False,
            message="rc-update became unavailable; no startup change was run.",
        )
    subcommand = "add" if desired_enabled else "delete"
    _output, command_error, command_truncated = run_bounded_command(
        [rc_update, subcommand, safe_unit, safe_runlevel],
        env,
        command_label="OpenRC startup action",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
        kill_process_group=True,
    )
    if command_error or command_truncated:
        current, _read_error = _read_startup_snapshot(safe_unit, safe_runlevel)
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=True, snapshot=current or snapshot, success=False,
            verified=bool(current and current.enabled == desired_enabled),
            message="rc-update did not report success; startup membership may have changed. Inspect the runlevel before retrying.",
        )

    after, verify_error = _read_startup_snapshot(safe_unit, safe_runlevel)
    if after is None:
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=True, snapshot=None, success=False,
            message=f"rc-update accepted the request, but startup membership could not be verified ({verify_error or 'unknown read error'}). Inspect the runlevel before retrying.",
        )
    verified = after.enabled == desired_enabled
    if not verified:
        return _response(
            safe_action, safe_unit, safe_runlevel, confirmed=True, snapshot=after, success=False,
            message="The action completed, but the requested startup membership was not observed. Inspect OpenRC runlevel state before retrying.",
        )
    return _response(
        safe_action, safe_unit, safe_runlevel, confirmed=True, snapshot=after, success=True,
        verified=True,
        message=(
            f"{safe_unit} was added to OpenRC runlevel {safe_runlevel} and membership was verified. "
            "OpenRC may act on it when switching to that runlevel; this request does not change the running service."
        ) if desired_enabled else (
            f"{safe_unit} was removed from OpenRC runlevel {safe_runlevel} and membership was verified. "
            "OpenRC may act on it when switching to that runlevel; this request does not stop the running service."
        ),
    )
