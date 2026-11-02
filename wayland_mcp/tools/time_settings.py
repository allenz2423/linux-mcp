"""Bounded systemd time configuration inventory and exact confirmed changes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import (
    TimeActionResponse,
    TimeSettingsResponse,
    TimeZoneListResponse,
    TimeZoneInfo,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.host import _detect_init_system

TimeAction = Literal["set_timezone", "set_ntp"]
TIME_PROPERTIES = (
    "Timezone",
    "LocalRTC",
    "CanNTP",
    "NTP",
    "NTPSynchronized",
    "TimeUSec",
    "RTCTimeUSec",
)
TIME_STATE_PROPERTIES = ("Timezone", "LocalRTC", "CanNTP", "NTP", "NTPSynchronized")
TIMEZONE_STATE_PROPERTIES = ("Timezone", "LocalRTC")
NTP_STATE_PROPERTIES = ("CanNTP", "NTP")
TIMEOUT_SECONDS = 10
MAX_STATUS_BYTES = 16 * 1024
MAX_TIMEZONE_BYTES = 256 * 1024
MAX_TIMEZONE_SCAN = 10_000
MAX_TIMEZONE_RETURN = 200
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
TIMEZONE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class TimeSnapshot:
    timezone: str
    local_rtc: bool | None
    can_ntp: bool | None
    ntp_enabled: bool | None
    ntp_synchronized: bool | None
    system_time: str | None
    rtc_time: str | None
    state_token: str


@dataclass(frozen=True)
class TimeActionTarget:
    action: TimeAction
    timezone: str | None
    ntp_enabled: bool | None
    current_timezone: str
    current_ntp_enabled: bool | None
    current_can_ntp: bool | None
    current_ntp_synchronized: bool | None
    local_rtc: bool | None
    state_token: str


def timedatectl_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux") or _detect_init_system() != "systemd":
        return False
    return find_session_binary("timedatectl", env or get_sanitized_env()) is not None


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().casefold()
    if normalized in {"yes", "true", "1"}:
        return True
    if normalized in {"no", "false", "0"}:
        return False
    return None


def _parse_properties(output: str) -> tuple[dict[str, str] | None, str | None]:
    properties: dict[str, str] = {}
    allowed = set(TIME_PROPERTIES)
    for line in output.splitlines()[:64]:
        key, separator, value = line.partition("=")
        if not separator or key not in allowed:
            continue
        if key in properties:
            return None, f"timedatectl returned duplicate {key} fields."
        value = value.strip()
        if len(value) > 256 or any(ord(character) < 32 or ord(character) == 127 for character in value):
            return None, f"timedatectl returned an invalid {key} field."
        properties[key] = value
    if "Timezone" not in properties:
        return None, "timedatectl did not report a timezone."
    return properties, None


def _settings_token(
    properties: dict[str, str],
    fields: tuple[str, ...] = TIME_STATE_PROPERTIES,
) -> str:
    encoded = json.dumps(
        {key: properties.get(key) for key in fields},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_properties() -> tuple[dict[str, str] | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Time settings are available only on Linux."
    manager = _detect_init_system()
    if manager != "systemd":
        return None, manager, f"Time settings require systemd timedated; detected {manager or 'an unknown init system'}."
    env = get_sanitized_env()
    timedatectl = find_session_binary("timedatectl", env)
    if not timedatectl:
        return None, manager, "timedatectl is unavailable on this systemd host."
    command = [timedatectl, "--no-pager", "show"]
    command.extend(f"--property={name}" for name in TIME_PROPERTIES)
    output, error, truncated = run_bounded_command(
        command,
        env,
        command_label="timedatectl status query",
        timeout_seconds=TIMEOUT_SECONDS,
        max_output_bytes=MAX_STATUS_BYTES,
    )
    if error or truncated or output is None:
        return None, manager, error or "timedatectl status output exceeded the configured limit."
    properties, parse_error = _parse_properties(output)
    if properties is None:
        return None, manager, parse_error
    return properties, manager, None


def _snapshot_from_properties(properties: dict[str, str]) -> TimeSnapshot:
    return TimeSnapshot(
        timezone=properties["Timezone"],
        local_rtc=_parse_bool(properties.get("LocalRTC")),
        can_ntp=_parse_bool(properties.get("CanNTP")),
        ntp_enabled=_parse_bool(properties.get("NTP")),
        ntp_synchronized=_parse_bool(properties.get("NTPSynchronized")),
        system_time=properties.get("TimeUSec"),
        rtc_time=properties.get("RTCTimeUSec"),
        state_token=_settings_token(properties),
    )


def get_time_settings() -> TimeSettingsResponse:
    """Return fixed, machine-readable systemd clock and synchronization fields."""
    properties, manager, error = _read_properties()
    if properties is None:
        return TimeSettingsResponse(success=False, init_system=manager, message=error)
    snapshot = _snapshot_from_properties(properties)
    return TimeSettingsResponse(
        success=True,
        init_system=manager,
        timezone=snapshot.timezone,
        local_rtc=snapshot.local_rtc,
        can_ntp=snapshot.can_ntp,
        ntp_enabled=snapshot.ntp_enabled,
        ntp_synchronized=snapshot.ntp_synchronized,
        system_time=snapshot.system_time,
        rtc_time=snapshot.rtc_time,
    )


def _valid_timezone_name(value: str) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or value.startswith(("/", "-"))
    ):
        return False
    components = value.split("/")
    return all(
        component not in {".", ".."} and TIMEZONE_COMPONENT_RE.fullmatch(component)
        for component in components
    )


def _read_timezones() -> tuple[list[str] | None, str | None, bool]:
    if not sys.platform.startswith("linux") or _detect_init_system() != "systemd":
        return None, "Timezone listing requires Linux systemd timedatectl.", False
    env = get_sanitized_env()
    timedatectl = find_session_binary("timedatectl", env)
    if not timedatectl:
        return None, "timedatectl is unavailable on this systemd host.", False
    output, error, truncated = run_bounded_command(
        [timedatectl, "--no-pager", "list-timezones"],
        env,
        command_label="timedatectl timezone query",
        timeout_seconds=TIMEOUT_SECONDS,
        max_output_bytes=MAX_TIMEZONE_BYTES,
    )
    if output is None or error or truncated:
        return None, error or "timedatectl timezone output exceeded the configured limit.", False
    zones: list[str] = []
    seen: set[str] = set()
    lines = output.splitlines()
    source_truncated = len(lines) > MAX_TIMEZONE_SCAN
    for line in lines[:MAX_TIMEZONE_SCAN]:
        zone = line.strip()
        if _valid_timezone_name(zone) and zone not in seen:
            zones.append(zone)
            seen.add(zone)
    return zones, None, source_truncated


def list_time_zones(query: str = "", offset: int = 0, limit: int = 100) -> TimeZoneListResponse:
    """List bounded timezone identifiers reported by the local systemd host."""
    if not isinstance(query, str) or len(query) > 128:
        return TimeZoneListResponse(success=False, message="Query must be text with at most 128 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return TimeZoneListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > MAX_TIMEZONE_SCAN:
        return TimeZoneListResponse(success=False, message=f"Offset must be an integer from 0 through {MAX_TIMEZONE_SCAN}.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return TimeZoneListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_TIMEZONE_RETURN))
    zones, error, source_capped = _read_timezones()
    if zones is None:
        return TimeZoneListResponse(success=False, limit=limit, message=error)
    needle = query.strip().casefold()
    matches = [zone for zone in zones if not needle or needle in zone.casefold()]
    page = matches[offset:offset + limit]
    next_offset = offset + len(page) if offset + len(page) < len(matches) else None
    return TimeZoneListResponse(
        success=True,
        total_time_zones=len(matches),
        returned_time_zones=len(page),
        time_zones=[TimeZoneInfo(name=zone) for zone in page],
        offset=offset,
        limit=limit,
        next_offset=next_offset,
        truncated=next_offset is not None or source_capped,
        message="Timezone source was capped by the scan limit." if source_capped else None,
    )


def time_action_confirmation_details(
    action: str,
    timezone: str | None,
    ntp_enabled: bool | None,
) -> tuple[TimeActionTarget | None, str | None]:
    if not isinstance(action, str) or action not in {"set_timezone", "set_ntp"}:
        return None, "Action must be set_timezone or set_ntp."
    if action == "set_timezone":
        if not isinstance(timezone, str) or not _valid_timezone_name(timezone) or ntp_enabled is not None:
            return None, "set_timezone requires one exact timezone name and ntp_enabled must be null."
        zones, zones_error, _source_capped = _read_timezones()
        if zones is None:
            return None, zones_error or "The timezone database could not be read."
        if timezone not in zones:
            return None, "Timezone must exactly match an entry from list_time_zones."
    else:
        if timezone is not None or not isinstance(ntp_enabled, bool):
            return None, "set_ntp requires a boolean ntp_enabled value and timezone must be null."

    properties, _manager, read_error = _read_properties()
    if properties is None:
        return None, read_error or "Current time settings could not be read."
    snapshot = _snapshot_from_properties(properties)
    if action == "set_ntp" and ntp_enabled is True and snapshot.can_ntp is False:
        return None, "This system reports that network time synchronization cannot be enabled."
    relevant_properties = TIMEZONE_STATE_PROPERTIES if action == "set_timezone" else NTP_STATE_PROPERTIES
    payload = {
        "action": action,
        "timezone": timezone,
        "ntp_enabled": ntp_enabled,
        "current_state_token": _settings_token(properties, relevant_properties),
        "uid": os.getuid(),
        "euid": os.geteuid(),
    }
    token = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return TimeActionTarget(
        action=action,  # type: ignore[arg-type]
        timezone=timezone,
        ntp_enabled=ntp_enabled,
        current_timezone=snapshot.timezone,
        current_ntp_enabled=snapshot.ntp_enabled,
        current_can_ntp=snapshot.can_ntp,
        current_ntp_synchronized=snapshot.ntp_synchronized,
        local_rtc=snapshot.local_rtc,
        state_token=token,
    ), None


def perform_time_action(
    action: str,
    timezone: str | None,
    ntp_enabled: bool | None,
    expected_state_token: str,
    *,
    confirmed: bool = False,
) -> TimeActionResponse:
    if not isinstance(action, str) or action not in {"set_timezone", "set_ntp"}:
        return TimeActionResponse(success=False, action="set_timezone", timezone=timezone[:255] if isinstance(timezone, str) else None, ntp_enabled=ntp_enabled, message="Unsupported time-setting action; no command was run.")
    safe_action: TimeAction = action
    safe_timezone = timezone[:255] if isinstance(timezone, str) else None
    if confirmed is not True:
        return TimeActionResponse(success=False, action=safe_action, timezone=safe_timezone, ntp_enabled=ntp_enabled, message="Explicit client confirmation is required; no command was run.")
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return TimeActionResponse(success=False, action=safe_action, timezone=safe_timezone, ntp_enabled=ntp_enabled, user_confirmed=True, message="A valid state token from the exact time-setting confirmation is required; no command was run.")

    target, validation_error = time_action_confirmation_details(action, timezone, ntp_enabled)
    if target is None:
        return TimeActionResponse(success=False, action=safe_action, timezone=safe_timezone, ntp_enabled=ntp_enabled, user_confirmed=True, message=validation_error or "The requested time setting could not be verified.")
    if target.state_token != expected_state_token:
        return TimeActionResponse(success=False, action=safe_action, timezone=safe_timezone, ntp_enabled=ntp_enabled, user_confirmed=True, message="The time configuration changed after confirmation; review the current settings and confirm again.")

    if action == "set_timezone" and target.current_timezone == timezone:
        return TimeActionResponse(success=True, action=safe_action, timezone=safe_timezone, ntp_enabled=None, state_verified=True, user_confirmed=True, message="The system already uses the requested timezone; no command was needed.")
    if action == "set_ntp" and target.current_ntp_enabled is ntp_enabled:
        return TimeActionResponse(success=True, action=safe_action, timezone=None, ntp_enabled=ntp_enabled, state_verified=True, user_confirmed=True, message="Network time synchronization already has the requested enabled state; no command was needed.")

    env = get_sanitized_env()
    timedatectl = find_session_binary("timedatectl", env)
    if not timedatectl:
        return TimeActionResponse(success=False, action=safe_action, timezone=safe_timezone, ntp_enabled=ntp_enabled, user_confirmed=True, message="timedatectl is unavailable; no command was run.")
    if action == "set_timezone":
        command = [timedatectl, "--no-ask-password", "set-timezone", timezone]
    else:
        command = [timedatectl, "--no-ask-password", "set-ntp", "true" if ntp_enabled else "false"]
    _output, command_error, command_truncated = run_bounded_command(
        command,
        env,
        command_label="timedatectl time-setting action",
        timeout_seconds=TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
    )
    if command_truncated:
        command_error = command_error or "timedatectl output exceeded the configured limit."

    properties, _manager, verify_error = _read_properties()
    verified = False
    if properties is not None:
        if action == "set_timezone":
            verified = properties.get("Timezone") == timezone
        else:
            verified = _parse_bool(properties.get("NTP")) is ntp_enabled
    if command_error:
        message = f"timedatectl reported an error: {command_error[:500]}"
        if verified:
            message += " The requested state is visible now; inspect the current settings before retrying."
        elif verify_error:
            message += f" {verify_error}"
        return TimeActionResponse(success=False, action=safe_action, timezone=safe_timezone, ntp_enabled=ntp_enabled, state_verified=verified, user_confirmed=True, message=message)
    if not verified:
        return TimeActionResponse(success=False, action=safe_action, timezone=safe_timezone, ntp_enabled=ntp_enabled, user_confirmed=True, message=verify_error or "The requested time setting was not visible after the command; inspect current settings before retrying.")
    return TimeActionResponse(
        success=True,
        action=safe_action,
        timezone=safe_timezone,
        ntp_enabled=ntp_enabled,
        state_verified=True,
        user_confirmed=True,
        message=(
            "The system timezone is set to the requested zone."
            if action == "set_timezone"
            else "Network time synchronization is enabled."
            if ntp_enabled
            else "Network time synchronization is disabled."
        ),
    )
