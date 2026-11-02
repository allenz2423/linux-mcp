"""Exact, confirmation-gated systemd timer controls."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import SystemdTimerActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.host import _detect_init_system

TimerAction = Literal["start", "stop", "enable", "disable"]
TimerScope = Literal["system", "user"]

UNIT_NAME_BASE = r"[A-Za-z0-9][A-Za-z0-9_.@:+-]*(?:\\x[0-9A-Fa-f]{2}[A-Za-z0-9_.@:+-]*)*"
TIMER_UNIT_RE = re.compile(rf"^{UNIT_NAME_BASE}\.timer$")
SERVICE_UNIT_RE = re.compile(rf"^{UNIT_NAME_BASE}\.service$")
SYSTEMD_UNIT_RE = re.compile(rf"^{UNIT_NAME_BASE}\.[A-Za-z0-9][A-Za-z0-9-]*$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_STATE_OUTPUT_BYTES = 32 * 1024
MAX_STATE_LINE_CHARS = 8192
MAX_ACTION_OUTPUT_BYTES = 16 * 1024
STATE_TIMEOUT_SECONDS = 5
ACTION_TIMEOUT_SECONDS = 30

STATE_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "UnitFileState",
    "Unit",
    "Triggers",
    "Persistent",
    "TimersCalendar",
    "TimersMonotonic",
)
DIRECT_ENABLEMENT_STATES = {"enabled", "disabled"}


@dataclass(frozen=True)
class SystemdTimerSnapshot:
    unit: str
    scope: TimerScope
    load_state: str
    active_state: str
    unit_file_state: str
    trigger_units: tuple[str, ...]
    configured_unit: str | None
    persistent: bool | None
    on_calendar: bool | None
    state_token: str


def _valid_unit_name(unit: str) -> bool:
    return (
        isinstance(unit, str)
        and len(unit) <= 255
        and TIMER_UNIT_RE.fullmatch(unit) is not None
        and not any(ord(character) < 32 or ord(character) == 127 for character in unit)
    )


def _parse_properties(output: str) -> dict[str, list[str]] | None:
    allowed = set(STATE_PROPERTIES)
    properties: dict[str, list[str]] = {}
    for line in output.splitlines():
        if not line:
            continue
        if len(line) > MAX_STATE_LINE_CHARS or "=" not in line:
            return None
        key, value = line.split("=", 1)
        if key in allowed:
            properties.setdefault(key, []).append(value.strip()[:MAX_STATE_LINE_CHARS])
    return properties


def _one(properties: dict[str, list[str]], key: str) -> str | None:
    values = properties.get(key, [])
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return " ".join(value for value in values if value)


def _state_token(
    unit: str,
    scope: str,
    properties: dict[str, list[str]],
) -> str:
    state = {
        "unit": unit,
        "scope": scope,
        "properties": {key: properties.get(key, []) for key in STATE_PROPERTIES},
    }
    encoded = json.dumps(state, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_timer_snapshot(
    unit: str,
    scope: TimerScope,
) -> tuple[SystemdTimerSnapshot | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Systemd timer control is available only on Linux."
    if not isinstance(scope, str) or scope not in {"system", "user"}:
        return None, "Scope must be 'system' or 'user'."
    if not _valid_unit_name(unit):
        return None, "Timer must be one exact systemd unit name ending in '.timer'."
    if _detect_init_system() != "systemd":
        return None, "Systemd timer control requires systemd as the active init system."

    env = get_sanitized_env()
    systemctl = find_session_binary("systemctl", env)
    if not systemctl:
        return None, "systemctl is unavailable in the sanitized session PATH."
    command = [systemctl]
    if scope == "user":
        command.append("--user")
    command.extend(("--no-pager", "--property=" + ",".join(STATE_PROPERTIES), "show", unit))
    output, _error, truncated = run_bounded_command(
        command,
        env,
        command_label="systemd timer state",
        timeout_seconds=STATE_TIMEOUT_SECONDS,
        max_output_bytes=MAX_STATE_OUTPUT_BYTES,
    )
    if output is None or truncated:
        return None, "Could not read the exact timer state from the selected systemd manager."
    properties = _parse_properties(output)
    if properties is None:
        return None, "systemctl returned an invalid timer state response."
    if _one(properties, "Id") != unit:
        return None, "The selected manager did not resolve the exact requested timer unit."
    load_state = _one(properties, "LoadState") or ""
    if load_state != "loaded":
        return None, "The exact timer unit is not currently loaded by the selected manager."
    active_state = _one(properties, "ActiveState") or "unknown"
    unit_file_state = _one(properties, "UnitFileState") or "unknown"
    if active_state not in {"active", "inactive", "activating", "deactivating", "failed"}:
        return None, "The selected manager returned an unsupported timer activity state."

    configured_unit = _one(properties, "Unit")
    if configured_unit and (len(configured_unit) > 255 or not SYSTEMD_UNIT_RE.fullmatch(configured_unit)):
        configured_unit = None
    trigger_values = _one(properties, "Triggers") or ""
    trigger_units = tuple(sorted({
        item
        for item in trigger_values.split()
        if len(item) <= 255 and SYSTEMD_UNIT_RE.fullmatch(item)
    })[:32])
    persistent_value = _one(properties, "Persistent")
    persistent = True if persistent_value == "yes" else False if persistent_value == "no" else None
    calendar_timers = _one(properties, "TimersCalendar")
    on_calendar = None if calendar_timers is None else "OnCalendar=" in calendar_timers
    if not trigger_units and configured_unit:
        trigger_units = (configured_unit,)
    if not trigger_units:
        default_service = unit[:-len(".timer")] + ".service"
        if len(default_service) <= 255 and SERVICE_UNIT_RE.fullmatch(default_service):
            trigger_units = (default_service,)

    return SystemdTimerSnapshot(
        unit=unit,
        scope=scope,
        load_state=load_state,
        active_state=active_state,
        unit_file_state=unit_file_state,
        trigger_units=trigger_units,
        configured_unit=configured_unit,
        persistent=persistent,
        on_calendar=on_calendar,
        state_token=_state_token(unit, scope, properties),
    ), None


def _validate_action_state(action: str, snapshot: SystemdTimerSnapshot) -> str | None:
    if not isinstance(action, str) or action not in {"start", "stop", "enable", "disable"}:
        return "Action must be start, stop, enable, or disable."
    if action in {"enable", "disable"} and snapshot.unit_file_state not in DIRECT_ENABLEMENT_STATES:
        return (
            "Persistent enable/disable control is limited to timers whose unit-file state is "
            "currently 'enabled' or 'disabled'."
        )
    return None


def timer_action_confirmation_details(
    action: TimerAction,
    unit: str,
    scope: TimerScope,
) -> tuple[SystemdTimerSnapshot | None, str | None]:
    if not isinstance(action, str) or action not in {"start", "stop", "enable", "disable"}:
        return None, "Action must be start, stop, enable, or disable."
    snapshot, error = _read_timer_snapshot(unit, scope)
    if snapshot is None:
        return None, error
    action_error = _validate_action_state(action, snapshot)
    if action_error:
        return None, action_error
    return snapshot, None


def _expected_state(action: TimerAction, snapshot: SystemdTimerSnapshot) -> bool:
    if action == "start":
        return snapshot.active_state == "active"
    if action == "stop":
        return snapshot.active_state == "inactive"
    if action == "enable":
        return snapshot.unit_file_state == "enabled"
    return snapshot.unit_file_state in {"disabled", "static"}


def _response(
    action: TimerAction,
    unit: str,
    scope: TimerScope,
    *,
    confirmed: bool,
    snapshot: SystemdTimerSnapshot | None,
    success: bool,
    verified: bool = False,
    message: str,
) -> SystemdTimerActionResponse:
    return SystemdTimerActionResponse(
        success=success,
        action=action,
        unit=unit,
        scope=scope,
        active_state=snapshot.active_state if snapshot else None,
        unit_file_state=snapshot.unit_file_state if snapshot else None,
        state_verified=verified,
        user_confirmed=confirmed,
        message=message,
    )


def perform_systemd_timer_action(
    action: TimerAction,
    unit: str,
    scope: TimerScope,
    expected_state_token: str,
    *,
    confirmed: bool = False,
) -> SystemdTimerActionResponse:
    safe_action: TimerAction = (
        action if isinstance(action, str) and action in {"start", "stop", "enable", "disable"} else "start"
    )
    safe_scope: TimerScope = scope if isinstance(scope, str) and scope in {"system", "user"} else "system"
    safe_unit = unit[:255] if isinstance(unit, str) else ""
    if not isinstance(action, str) or action not in {"start", "stop", "enable", "disable"}:
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=False, snapshot=None, success=False,
            message="Unsupported timer action supplied; no command was run.",
        )
    if not isinstance(scope, str) or scope not in {"system", "user"}:
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=False, snapshot=None, success=False,
            message="Invalid timer scope supplied; no command was run.",
        )
    if not _valid_unit_name(safe_unit):
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=False, snapshot=None, success=False,
            message="Invalid exact timer name supplied; no command was run.",
        )
    if confirmed is not True:
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=False, snapshot=None, success=False,
            message="Explicit client confirmation is required; no timer action was run.",
        )
    snapshot, error = timer_action_confirmation_details(safe_action, safe_unit, safe_scope)
    if snapshot is None:
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=True, snapshot=None, success=False,
            message=error or "The exact timer could not be revalidated; no command was run.",
        )
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=True, snapshot=snapshot, success=False,
            message="A valid state token from the exact timer confirmation is required; no command was run.",
        )
    if snapshot.state_token != expected_state_token:
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=True, snapshot=snapshot, success=False,
            message="Timer state or trigger configuration changed after confirmation; no command was run. Review the timer and confirm again.",
        )

    env = get_sanitized_env()
    systemctl = find_session_binary("systemctl", env)
    if not systemctl:
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=True, snapshot=snapshot, success=False,
            message="systemctl is no longer available; no timer command was run.",
        )
    command = [systemctl, "--no-pager", "--quiet", "--no-ask-password"]
    if safe_scope == "user":
        command.append("--user")
    command.extend((safe_action, safe_unit))
    _output, command_error, command_truncated = run_bounded_command(
        command,
        env,
        command_label="systemd timer action",
        timeout_seconds=ACTION_TIMEOUT_SECONDS,
        max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
        kill_process_group=True,
    )
    if command_error or command_truncated:
        current, _read_error = _read_timer_snapshot(safe_unit, safe_scope)
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=True, snapshot=current or snapshot, success=False,
            message="systemctl did not report success; timer state may have changed. Inspect the timer before retrying.",
        )

    after, verify_error = _read_timer_snapshot(safe_unit, safe_scope)
    if after is None:
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=True, snapshot=None, success=False,
            message=f"systemctl accepted the action, but timer state could not be verified ({verify_error or 'unknown read error'}). Inspect the timer before retrying.",
        )
    verified = _expected_state(safe_action, after)
    if not verified:
        return _response(
            safe_action, safe_unit, safe_scope, confirmed=True, snapshot=after, success=False,
            verified=False,
            message="The action completed, but the requested timer state was not observed. Inspect timer state before retrying.",
        )
    effects = {
        "start": "Timer activation was changed and verified.",
        "stop": "Timer deactivation was changed and verified; an already-triggered service is not stopped by this action.",
        "enable": "Persistent timer enablement was changed and verified; the timer was not started by this action.",
        "disable": "Persistent timer enablement was removed and verified; an active timer was not stopped by this action.",
    }
    return _response(
        safe_action, safe_unit, safe_scope, confirmed=True, snapshot=after, success=True,
        verified=True, message=effects[safe_action],
    )
