"""Exact, confirmed firewalld service membership changes for one zone."""

from __future__ import annotations

import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import FirewalldServiceActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

FirewalldServiceAction = Literal["add_service", "remove_service"]
FirewalldConfiguration = Literal["runtime", "permanent"]
ZONE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,100}$")
TOKEN_TTL_SECONDS = 180
MAX_PENDING_TOKENS = 1_024
COMMAND_TIMEOUT_SECONDS = 5
MAX_COMMAND_OUTPUT_BYTES = 128 * 1024
MAX_ZONES = 256
MAX_SERVICES = 4_096
MAX_ZONE_LINE_LENGTH = 1_024
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _FirewalldServiceSnapshot:
    configuration: str
    zone: str
    zone_active: bool | None
    service: str
    service_present: bool


@dataclass(slots=True)
class _FirewalldServiceToken:
    action: str
    configuration: str
    zone: str
    zone_active: bool | None
    service: str
    service_present: bool
    expires_at: float
    claimed: bool = False


@dataclass(frozen=True, slots=True)
class FirewalldServiceActionTarget:
    action: str
    configuration: str
    zone: str
    zone_active: bool | None
    service: str
    service_present: bool
    confirmation_token: str


_TOKENS: dict[str, _FirewalldServiceToken] = {}


def _normalize_request(
    action: object,
    configuration: object,
    zone: object,
    service: object,
) -> str | None:
    if not isinstance(action, str) or action not in {"add_service", "remove_service"}:
        return "Choose add_service or remove_service."
    if not isinstance(configuration, str) or configuration not in {"runtime", "permanent"}:
        return "Choose runtime or permanent configuration."
    if not isinstance(zone, str) or not ZONE_NAME_RE.fullmatch(zone):
        return "Use one exact existing firewalld zone name from the frontend inventory."
    if not isinstance(service, str) or not SERVICE_NAME_RE.fullmatch(service):
        return "Use one exact firewalld service name from firewall-cmd --get-services."
    return None


def _command(
    binary: str,
    arguments: list[str],
    env: dict[str, str],
    *,
    label: str,
    accept_nonzero_exit: bool = False,
) -> tuple[str | None, str | None, bool]:
    return run_bounded_command(
        [binary, *arguments],
        env,
        command_label=label,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
        accept_nonzero_exit=accept_nonzero_exit,
    )


def _read_names(
    binary: str,
    env: dict[str, str],
    arguments: list[str],
    *,
    label: str,
    pattern: re.Pattern[str],
    maximum: int,
) -> tuple[set[str] | None, str | None]:
    output, error, truncated = _command(binary, arguments, env, label=label)
    if error or output is None or truncated:
        return None, f"{label.capitalize()} could not be read completely."
    values = output.split()
    if len(values) > maximum or any(not pattern.fullmatch(value) for value in values):
        return None, f"Firewalld returned an invalid or oversized result for {label}."
    return set(values), None


def _read_active_zones(
    binary: str,
    env: dict[str, str],
) -> tuple[set[str] | None, str | None]:
    output, error, truncated = _command(
        binary,
        ["--get-active-zones"],
        env,
        label="firewalld active-zone inventory",
    )
    if error or output is None or truncated:
        return None, "Firewalld active zones could not be read."
    lines = output.splitlines()
    if len(lines) > MAX_ZONES * 16:
        return None, "Firewalld returned an oversized active-zone inventory."
    active: set[str] = set()
    for line in lines:
        if len(line) > MAX_ZONE_LINE_LENGTH:
            return None, "Firewalld returned an oversized active-zone record."
        if not line or line[0].isspace():
            continue
        name = line.strip()
        if name.endswith(":"):
            name = name[:-1]
        if not ZONE_NAME_RE.fullmatch(name):
            return None, "Firewalld returned an invalid active-zone name."
        active.add(name)
        if len(active) > MAX_ZONES:
            return None, "Firewalld returned too many active zones."
    return active, None


def _read_service_snapshot(
    configuration: str,
    zone: str,
    service: str,
    binary: str,
    env: dict[str, str],
) -> tuple[_FirewalldServiceSnapshot | None, str | None]:
    state, error, truncated = _command(
        binary,
        ["--state"],
        env,
        label="firewalld daemon state query",
        accept_nonzero_exit=True,
    )
    if error or state is None or truncated or state.strip().casefold() != "running":
        return None, "Firewalld is not running or its state could not be verified."

    zone_arguments = ["--get-zones"]
    service_arguments = ["--get-services"]
    if configuration == "permanent":
        zone_arguments.insert(0, "--permanent")
        service_arguments.insert(0, "--permanent")
    zones, error = _read_names(
        binary,
        env,
        zone_arguments,
        label=f"firewalld {configuration} zone inventory",
        pattern=ZONE_NAME_RE,
        maximum=MAX_ZONES,
    )
    if error or zones is None:
        return None, error or "The selected firewalld zone inventory could not be read."
    if zone not in zones:
        return None, "The exact zone is not present in the selected firewalld configuration."

    services, error = _read_names(
        binary,
        env,
        service_arguments,
        label=f"firewalld {configuration} service inventory",
        pattern=SERVICE_NAME_RE,
        maximum=MAX_SERVICES,
    )
    if error or services is None:
        return None, error or "The firewalld service inventory could not be read."
    if service not in services:
        return None, "The exact service is not present in firewall-cmd's service inventory."

    zone_active: bool | None = None
    if configuration == "runtime":
        active_zones, error = _read_active_zones(binary, env)
        if error or active_zones is None:
            return None, error or "Firewalld active-zone state could not be read."
        zone_active = zone in active_zones
        if not zone_active:
            return None, "Runtime service changes require an exact zone currently bound to an interface or source."

    arguments = [f"--zone={zone}", "--list-services"]
    if configuration == "permanent":
        arguments.insert(0, "--permanent")
    output, error, truncated = _command(
        binary,
        arguments,
        env,
        label=f"firewalld {configuration} zone service inventory",
    )
    if error or output is None or truncated:
        return None, "The firewalld zone service list could not be read completely."
    entries = output.split()
    if len(entries) > MAX_SERVICES or any(not SERVICE_NAME_RE.fullmatch(item) for item in entries):
        return None, "Firewalld returned an invalid or oversized zone service list."
    return _FirewalldServiceSnapshot(
        configuration=configuration,
        zone=zone,
        zone_active=zone_active,
        service=service,
        service_present=service in entries,
    ), None


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env


def _binary(env: dict[str, str]) -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    return find_session_binary("firewall-cmd", env)


def _validate_desired_state(action: str, snapshot: _FirewalldServiceSnapshot) -> str | None:
    should_exist = action == "remove_service"
    if snapshot.service_present is not should_exist:
        if snapshot.service_present:
            return "That exact service already exists in the selected zone configuration."
        return "That exact service is not present in the selected zone configuration."
    return None


def firewalld_service_action_confirmation_details(
    action: str,
    configuration: str,
    zone: str,
    service: str,
) -> tuple[FirewalldServiceActionTarget | None, str | None]:
    validation_error = _normalize_request(action, configuration, zone, service)
    if validation_error:
        return None, validation_error
    env = _environment()
    binary = _binary(env)
    if not binary:
        return None, "The optional firewall-cmd tool is unavailable on this Linux host."
    snapshot, error = _read_service_snapshot(configuration, zone, service, binary, env)
    if error or snapshot is None:
        return None, error or "The exact firewalld service state could not be verified."
    error = _validate_desired_state(action, snapshot)
    if error:
        return None, error

    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _FirewalldServiceToken(
        action=action,
        configuration=configuration,
        zone=zone,
        zone_active=snapshot.zone_active,
        service=service,
        service_present=snapshot.service_present,
        expires_at=now + TOKEN_TTL_SECONDS,
    )
    with _ACTION_LOCK:
        for key in [key for key, item in _TOKENS.items() if item.expires_at <= now]:
            _TOKENS.pop(key, None)
        if len(_TOKENS) >= MAX_PENDING_TOKENS:
            return None, "Too many pending firewalld confirmations; retry after existing prompts expire."
        _TOKENS[token] = record
    return FirewalldServiceActionTarget(
        action=action,
        configuration=configuration,
        zone=zone,
        zone_active=snapshot.zone_active,
        service=service,
        service_present=snapshot.service_present,
        confirmation_token=token,
    ), None


def _action_response(
    *,
    success: bool,
    action: str,
    configuration: str,
    zone: str,
    service: str,
    zone_active: bool | None,
    service_present: bool | None,
    state_verified: bool,
    user_confirmed: bool,
    message: str,
) -> FirewalldServiceActionResponse:
    return FirewalldServiceActionResponse(
        success=success,
        action=action if action in {"add_service", "remove_service"} else "add_service",
        configuration=configuration if configuration in {"runtime", "permanent"} else "runtime",
        zone=zone[:64] if isinstance(zone, str) else None,
        service=service[:64] if isinstance(service, str) else None,
        zone_active=zone_active,
        service_present=service_present,
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_firewalld_service_action(
    action: str,
    configuration: str,
    zone: str,
    service: str,
    expected_state_token: str,
    *,
    confirmed: bool,
) -> FirewalldServiceActionResponse:
    safe_action = action if isinstance(action, str) else "add_service"
    safe_configuration = configuration if isinstance(configuration, str) else "runtime"
    safe_zone = zone if isinstance(zone, str) else ""
    safe_service = service if isinstance(service, str) else ""

    with _ACTION_LOCK:
        record = (
            _TOKENS.get(expected_state_token)
            if isinstance(expected_state_token, str)
            and len(expected_state_token) <= 100
            and TOKEN_RE.fullmatch(expected_state_token)
            else None
        )
        if record is None or record.expires_at <= time.monotonic():
            if isinstance(expected_state_token, str) and len(expected_state_token) <= 100:
                _TOKENS.pop(expected_state_token, None)
            return _action_response(
                success=False,
                action=safe_action,
                configuration=safe_configuration,
                zone=safe_zone,
                service=safe_service,
                zone_active=None,
                service_present=None,
                state_verified=False,
                user_confirmed=confirmed is True,
                message="A fresh firewalld confirmation token is required; inspect the exact service and try again.",
            )
        if record.claimed:
            return _action_response(
                success=False,
                action=safe_action,
                configuration=safe_configuration,
                zone=safe_zone,
                service=safe_service,
                zone_active=record.zone_active,
                service_present=record.service_present,
                state_verified=False,
                user_confirmed=confirmed is True,
                message="This firewalld confirmation token is already in use; request a fresh confirmation.",
            )
        record.claimed = True

    try:
        if confirmed is not True:
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                service=record.service,
                zone_active=record.zone_active,
                service_present=record.service_present,
                state_verified=False,
                user_confirmed=False,
                message="Explicit client confirmation is required; no firewalld command was run.",
            )
        if (
            _normalize_request(action, configuration, zone, service)
            or action != record.action
            or configuration != record.configuration
            or zone != record.zone
            or service != record.service
        ):
            return _action_response(
                success=False,
                action=safe_action,
                configuration=safe_configuration,
                zone=safe_zone,
                service=safe_service,
                zone_active=record.zone_active,
                service_present=record.service_present,
                state_verified=False,
                user_confirmed=True,
                message="Confirmation did not match the exact action, configuration, zone, and service; no command was run.",
            )

        env = _environment()
        binary = _binary(env)
        if not binary:
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                service=record.service,
                zone_active=record.zone_active,
                service_present=record.service_present,
                state_verified=False,
                user_confirmed=True,
                message="The optional firewall-cmd tool became unavailable; no firewall command was run.",
            )

        current, error = _read_service_snapshot(
            record.configuration,
            record.zone,
            record.service,
            binary,
            env,
        )
        if error or current is None:
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                service=record.service,
                zone_active=None,
                service_present=None,
                state_verified=False,
                user_confirmed=True,
                message=error or "The firewalld state could not be revalidated; no command was run.",
            )
        if (
            current.zone_active != record.zone_active
            or current.service_present != record.service_present
        ):
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                service=record.service,
                zone_active=current.zone_active,
                service_present=current.service_present,
                state_verified=False,
                user_confirmed=True,
                message="The exact zone binding or service membership changed after confirmation; inspect it and confirm again.",
            )

        command_name = "--add-service" if record.action == "add_service" else "--remove-service"
        arguments = [f"--zone={record.zone}", f"{command_name}={record.service}"]
        if record.configuration == "permanent":
            arguments.insert(0, "--permanent")
        _output, command_error, command_truncated = _command(
            binary,
            arguments,
            env,
            label=f"firewalld {record.configuration} service update",
        )
        after, verify_error = _read_service_snapshot(
            record.configuration,
            record.zone,
            record.service,
            binary,
            env,
        )
        expected_present = record.action == "add_service"
        verified = (
            after is not None
            and after.zone_active == record.zone_active
            and after.service_present is expected_present
        )
        if command_error or command_truncated:
            message = (
                "The firewalld command timed out; inspect the selected configuration before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "Firewalld reported a service-update error; inspect the selected configuration before retrying."
            )
            if verified:
                message += " The requested service state is visible."
            elif verify_error:
                message += " The resulting state could not be verified."
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                service=record.service,
                zone_active=after.zone_active if after is not None else None,
                service_present=after.service_present if after is not None else None,
                state_verified=verified,
                user_confirmed=True,
                message=message,
            )
        if not verified:
            message = "Firewalld returned from the update, but the requested exact service state is not visible."
            if verify_error:
                message += " The resulting state could not be read."
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                service=record.service,
                zone_active=after.zone_active if after is not None else None,
                service_present=after.service_present if after is not None else None,
                state_verified=False,
                user_confirmed=True,
                message=message,
            )
        effect = "added" if expected_present else "removed"
        if record.configuration == "runtime":
            persistence = " This change lasts only until firewalld reloads, restarts, or the host reboots."
        else:
            persistence = " This updates saved configuration only; runtime rules change after firewalld reloads or restarts."
        return _action_response(
            success=True,
            action=record.action,
            configuration=record.configuration,
            zone=record.zone,
            service=record.service,
            zone_active=after.zone_active,
            service_present=after.service_present,
            state_verified=True,
            user_confirmed=True,
            message=f"The firewalld service {record.service} was {effect} in zone {record.zone}.{persistence}",
        )
    finally:
        with _ACTION_LOCK:
            _TOKENS.pop(expected_state_token, None)
