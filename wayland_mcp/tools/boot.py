"""Systemd boot-target inventory and confirmed default-target changes."""

from __future__ import annotations

import re
import sys

from wayland_mcp.models import BootTargetActionResponse, BootTargetInfo, BootTargetListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.host import _detect_init_system

MAX_TARGETS = 10_000
MAX_RETURNED_TARGETS = 200
MAX_SYSTEMCTL_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_BOOT_ACTION_OUTPUT_BYTES = 64 * 1024
BOOT_ACTION_TIMEOUT_SECONDS = 30
TARGET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:+-]{0,247}\.target$")


def _run_systemctl(systemctl: str, arguments: list[str], env: dict[str, str]):
    return run_bounded_command(
        [systemctl, *arguments],
        env,
        command_label="systemctl",
        timeout_seconds=5,
        max_output_bytes=MAX_SYSTEMCTL_OUTPUT_BYTES,
    )


def _parse_unit_files(output: str) -> dict[str, tuple[str | None, str | None]]:
    targets: dict[str, tuple[str | None, str | None]] = {}
    for line in output.splitlines()[:MAX_TARGETS]:
        fields = line.split()
        if len(fields) < 2 or not TARGET_NAME_RE.fullmatch(fields[0]):
            continue
        targets[fields[0]] = (fields[1][:64], fields[2][:64] if len(fields) > 2 else None)
    return targets


def _parse_loaded_units(output: str) -> dict[str, tuple[str | None, str | None, str | None]]:
    targets: dict[str, tuple[str | None, str | None, str | None]] = {}
    for line in output.splitlines()[:MAX_TARGETS]:
        fields = line.split(None, 4)
        if not fields or not TARGET_NAME_RE.fullmatch(fields[0]):
            continue
        description = fields[4][:512] if len(fields) > 4 else None
        if description:
            description = "".join(character for character in description if ord(character) >= 32 and ord(character) != 127)
        targets[fields[0]] = (
            fields[2][:64] if len(fields) > 2 else None,
            fields[3][:64] if len(fields) > 3 else None,
            description,
        )
    return targets


def list_boot_targets(query: str = "", limit: int = 100) -> BootTargetListResponse:
    """List installed systemd target units, runtime state, and the default target."""
    if not sys.platform.startswith("linux"):
        return BootTargetListResponse(success=False, message="Boot target inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return BootTargetListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return BootTargetListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return BootTargetListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_TARGETS))

    manager = _detect_init_system()
    if manager != "systemd":
        return BootTargetListResponse(
            success=False,
            limit=limit,
            message=f"Boot target inventory requires systemd; detected {manager or 'an unknown init system'}.",
        )
    env = get_sanitized_env()
    systemctl = find_session_binary("systemctl", env)
    if not systemctl:
        return BootTargetListResponse(success=False, limit=limit, message="systemctl is unavailable on this systemd host.")

    files_output, files_error, files_truncated = _run_systemctl(
        systemctl,
        ["list-unit-files", "--type=target", "--no-legend", "--no-pager"],
        env,
    )
    loaded_output, loaded_error, loaded_truncated = _run_systemctl(
        systemctl,
        ["list-units", "--all", "--type=target", "--no-legend", "--no-pager", "--plain", "--full"],
        env,
    )
    default_output, default_error, default_truncated = _run_systemctl(
        systemctl,
        ["get-default"],
        env,
    )
    if files_output is None and loaded_output is None:
        reason = "; ".join(item for item in (files_error, loaded_error) if item)
        return BootTargetListResponse(
            success=False,
            limit=limit,
            message=reason or "systemctl could not list target units.",
        )

    unit_files = _parse_unit_files(files_output or "")
    loaded_units = _parse_loaded_units(loaded_output or "")
    default_target = (default_output or "").strip().splitlines()[0] if default_output and (default_output or "").strip() else None
    if default_target and not TARGET_NAME_RE.fullmatch(default_target):
        default_target = None

    names = set(unit_files) | set(loaded_units)
    if default_target:
        names.add(default_target)
    needle = query.strip().casefold()
    targets: list[BootTargetInfo] = []
    for name in names:
        unit_file_state, preset_state = unit_files.get(name, (None, None))
        active_state, sub_state, description = loaded_units.get(name, (None, None, None))
        if needle and needle not in name.casefold() and needle not in (description or "").casefold():
            continue
        targets.append(BootTargetInfo(
            name=name,
            unit_file_state=unit_file_state,
            preset_state=preset_state,
            active_state=active_state,
            sub_state=sub_state,
            description=description,
            is_default=name == default_target,
        ))
    targets.sort(key=lambda item: item.name.casefold())

    errors = [item for item in (files_error, loaded_error, default_error) if item]
    truncated = (
        files_truncated or loaded_truncated or default_truncated
        or len(unit_files) >= MAX_TARGETS or len(loaded_units) >= MAX_TARGETS
        or len(targets) > limit
    )
    messages = [f"Target inventory partially unavailable: {'; '.join(errors)}"] if errors else []
    if truncated:
        messages.append("Target inventory was capped by output, scan, or result limits.")
    return BootTargetListResponse(
        success=True,
        default_target=default_target,
        total_targets=len(targets),
        returned_targets=min(limit, len(targets)),
        targets=targets[:limit],
        limit=limit,
        truncated=truncated,
        message=" ".join(messages) or None,
    )


def validate_default_boot_target(target: str) -> str | None:
    """Validate an installed systemd target for a persistent default change."""
    if not isinstance(target, str) or len(target) > 255 or not TARGET_NAME_RE.fullmatch(target):
        return "Target must be one exact systemd target name ending in '.target'."
    if target == "default.target":
        return "Choose an installed target instead of the default.target alias."
    if not sys.platform.startswith("linux"):
        return "Default boot-target changes are available only on Linux."
    if _detect_init_system() != "systemd":
        return "Default boot-target changes require systemd."
    env = get_sanitized_env()
    systemctl = find_session_binary("systemctl", env)
    if not systemctl:
        return "systemctl is unavailable on this systemd host."
    output, error, _truncated = _run_systemctl(
        systemctl,
        ["list-unit-files", "--type=target", "--no-legend", "--no-pager"],
        env,
    )
    if output is None:
        return error or "systemctl could not verify installed target units."
    if target not in _parse_unit_files(output):
        return "Target is not present in the installed systemd target inventory."
    return None


def set_default_boot_target(
    target: str,
    *,
    confirmed: bool,
) -> BootTargetActionResponse:
    """Set the next-boot default target after explicit client confirmation."""
    if not confirmed:
        return BootTargetActionResponse(
            success=False,
            target=target if isinstance(target, str) else "",
            message="Explicit client confirmation is required; no command was run.",
        )
    validation_error = validate_default_boot_target(target)
    if validation_error:
        return BootTargetActionResponse(
            success=False,
            target=target if isinstance(target, str) else "",
            user_confirmed=True,
            message=validation_error,
        )
    env = get_sanitized_env()
    systemctl = find_session_binary("systemctl", env)
    if not systemctl:
        return BootTargetActionResponse(
            success=False,
            target=target,
            user_confirmed=True,
            message="systemctl became unavailable before the target change could run.",
        )
    _output, error, output_truncated = run_bounded_command(
        [systemctl, "--no-pager", "--quiet", "set-default", target],
        env,
        command_label="systemctl default target change",
        timeout_seconds=BOOT_ACTION_TIMEOUT_SECONDS,
        max_output_bytes=MAX_BOOT_ACTION_OUTPUT_BYTES,
    )
    if error:
        message = error[:400]
        if "timed out" in error.casefold():
            message += " The default target may have changed; verify it before retrying."
        return BootTargetActionResponse(
            success=False,
            target=target,
            user_confirmed=True,
            message=message,
        )
    if output_truncated:
        return BootTargetActionResponse(
            success=False,
            target=target,
            user_confirmed=True,
            message="systemctl output exceeded the cap; verify the configured default target before retrying.",
        )
    return BootTargetActionResponse(
        success=_output is not None,
        target=target,
        user_confirmed=True,
        message=f"The default boot target is now {target}; the running session was not changed.",
    )
