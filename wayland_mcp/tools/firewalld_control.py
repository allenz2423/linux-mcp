"""Exact, confirmed firewalld TCP/UDP source or destination port rules for one zone."""

from __future__ import annotations

import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import FirewalldPortActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

FirewalldPortAction = Literal["add_port", "remove_port"]
FirewalldConfiguration = Literal["runtime", "permanent"]
ZONE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,100}$")
TOKEN_TTL_SECONDS = 180
MAX_PENDING_TOKENS = 1_024
COMMAND_TIMEOUT_SECONDS = 5
MAX_COMMAND_OUTPUT_BYTES = 128 * 1024
MAX_ZONES = 256
MAX_ZONE_LINE_LENGTH = 1_024
MAX_PORT_ENTRIES = 4_096
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _FirewalldPortSnapshot:
    configuration: str
    zone: str
    zone_active: bool | None
    protocol: str
    port_position: str
    port: int
    rule_present: bool


@dataclass(slots=True)
class _FirewalldPortToken:
    action: str
    configuration: str
    zone: str
    zone_active: bool | None
    protocol: str
    port_position: str
    port: int
    rule_present: bool
    expires_at: float
    claimed: bool = False


@dataclass(frozen=True, slots=True)
class FirewalldPortActionTarget:
    action: str
    configuration: str
    zone: str
    zone_active: bool | None
    protocol: str
    port_position: str
    port: int
    rule_present: bool
    confirmation_token: str


_TOKENS: dict[str, _FirewalldPortToken] = {}


def _normalize_request(
    action: object,
    configuration: object,
    zone: object,
    protocol: object,
    port: object,
    port_position: object = "destination",
) -> str | None:
    if not isinstance(action, str) or action not in {"add_port", "remove_port"}:
        return "Choose add_port or remove_port."
    if not isinstance(configuration, str) or configuration not in {"runtime", "permanent"}:
        return "Choose runtime or permanent configuration."
    if not isinstance(zone, str) or not ZONE_NAME_RE.fullmatch(zone):
        return "Use one exact existing firewalld zone name from the frontend inventory."
    if not isinstance(protocol, str) or protocol not in {"tcp", "udp"}:
        return "Protocol must be tcp or udp."
    if not isinstance(port_position, str) or port_position not in {"destination", "source"}:
        return "port_position must be destination or source."
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65_535:
        return "Port must be an integer from 1 through 65535."
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


def _read_zone_names(
    binary: str,
    env: dict[str, str],
    configuration: str,
) -> tuple[set[str] | None, str | None]:
    arguments = ["--get-zones"]
    if configuration == "permanent":
        arguments.insert(0, "--permanent")
    output, error, truncated = _command(
        binary,
        arguments,
        env,
        label=f"firewalld {configuration} zone inventory",
    )
    if error or output is None or truncated:
        return None, "Firewalld zones could not be read completely."
    values = output.split()
    if len(values) > MAX_ZONES or any(not ZONE_NAME_RE.fullmatch(value) for value in values):
        return None, "Firewalld returned an invalid or oversized zone inventory."
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


def _read_port_snapshot(
    configuration: str,
    zone: str,
    protocol: str,
    port: int,
    port_position: str,
    binary: str,
    env: dict[str, str],
) -> tuple[_FirewalldPortSnapshot | None, str | None]:
    state, error, truncated = _command(
        binary,
        ["--state"],
        env,
        label="firewalld daemon state query",
        accept_nonzero_exit=True,
    )
    if error or state is None or truncated or state.strip().casefold() != "running":
        return None, "Firewalld is not running or its state could not be verified."

    zones, error = _read_zone_names(binary, env, configuration)
    if error or zones is None:
        return None, error or "The selected firewalld configuration could not be read."
    if zone not in zones:
        return None, "The exact zone is not present in the selected firewalld configuration."

    zone_active: bool | None = None
    if configuration == "runtime":
        active_zones, error = _read_active_zones(binary, env)
        if error or active_zones is None:
            return None, error or "Firewalld active-zone state could not be read."
        zone_active = zone in active_zones
        if not zone_active:
            return None, "Runtime port changes require an exact zone currently bound to an interface or source."

    port_list_option = "--list-ports" if port_position == "destination" else "--list-source-ports"
    arguments = [f"--zone={zone}", port_list_option]
    if configuration == "permanent":
        arguments.insert(0, "--permanent")
    output, error, truncated = _command(
        binary,
        arguments,
        env,
        label=f"firewalld {configuration} zone port inventory",
    )
    if error or output is None or truncated:
        return None, "The firewalld zone port list could not be read completely."
    entries = output.split()
    if len(entries) > MAX_PORT_ENTRIES:
        return None, "The firewalld zone contains too many zone port-list entries to inspect safely."
    exact_present = False
    overlaps_requested = False
    for entry in entries:
        match = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?/([A-Za-z][A-Za-z0-9_-]{0,31})", entry)
        if not match:
            return None, "Firewalld returned an invalid zone port-list entry."
        first = int(match.group(1))
        last = int(match.group(2) or match.group(1))
        entry_protocol = match.group(3).casefold()
        if not 1 <= first <= last <= 65_535:
            return None, "Firewalld returned an invalid port range."
        if entry_protocol not in {"tcp", "udp", "sctp", "dccp"}:
            return None, "Firewalld returned an unsupported port protocol."
        if entry_protocol != protocol:
            continue
        if match.group(2) is None and first == port:
            exact_present = True
        elif first <= port <= last:
            overlaps_requested = True
    if overlaps_requested:
        return None, "The requested port is covered by a range entry; this tool changes only exact single-port entries."
    return _FirewalldPortSnapshot(
        configuration=configuration,
        zone=zone,
        zone_active=zone_active,
        protocol=protocol,
        port_position=port_position,
        port=port,
        rule_present=exact_present,
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


def _validate_desired_state(action: str, snapshot: _FirewalldPortSnapshot) -> str | None:
    should_exist = action == "remove_port"
    if snapshot.rule_present is not should_exist:
        if snapshot.rule_present:
            return "That exact port rule already exists in the selected configuration."
        return "That exact port rule is not present in the selected configuration."
    return None


def firewalld_port_action_confirmation_details(
    action: str,
    configuration: str,
    zone: str,
    protocol: str,
    port: int,
    port_position: str = "destination",
) -> tuple[FirewalldPortActionTarget | None, str | None]:
    validation_error = _normalize_request(action, configuration, zone, protocol, port, port_position)
    if validation_error:
        return None, validation_error
    env = _environment()
    binary = _binary(env)
    if not binary:
        return None, "The optional firewall-cmd tool is unavailable on this Linux host."
    snapshot, error = _read_port_snapshot(configuration, zone, protocol, port, port_position, binary, env)
    if error or snapshot is None:
        return None, error or "The exact firewalld port state could not be verified."
    error = _validate_desired_state(action, snapshot)
    if error:
        return None, error

    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _FirewalldPortToken(
        action=action,
        configuration=configuration,
        zone=zone,
        zone_active=snapshot.zone_active,
        protocol=protocol,
        port_position=port_position,
        port=port,
        rule_present=snapshot.rule_present,
        expires_at=now + TOKEN_TTL_SECONDS,
    )
    with _ACTION_LOCK:
        for key in [key for key, item in _TOKENS.items() if item.expires_at <= now]:
            _TOKENS.pop(key, None)
        if len(_TOKENS) >= MAX_PENDING_TOKENS:
            return None, "Too many pending firewalld confirmations; retry after existing prompts expire."
        _TOKENS[token] = record
    return FirewalldPortActionTarget(
        action=action,
        configuration=configuration,
        zone=zone,
        zone_active=snapshot.zone_active,
        protocol=protocol,
        port_position=port_position,
        port=port,
        rule_present=snapshot.rule_present,
        confirmation_token=token,
    ), None


def _action_response(
    *,
    success: bool,
    action: str,
    configuration: str,
    zone: str,
    protocol: str,
    port: int,
    port_position: str,
    zone_active: bool | None,
    rule_present: bool | None,
    state_verified: bool,
    user_confirmed: bool,
    message: str,
) -> FirewalldPortActionResponse:
    return FirewalldPortActionResponse(
        success=success,
        action=action if action in {"add_port", "remove_port"} else "add_port",
        configuration=configuration if configuration in {"runtime", "permanent"} else "runtime",
        zone=zone[:64] if isinstance(zone, str) else None,
        protocol=protocol if protocol in {"tcp", "udp"} else None,
        port_position=port_position if port_position in {"destination", "source"} else None,
        port=port if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65_535 else None,
        zone_active=zone_active,
        rule_present=rule_present,
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_firewalld_port_action(
    action: str,
    configuration: str,
    zone: str,
    protocol: str,
    port: int,
    expected_state_token: str,
    *,
    confirmed: bool,
    port_position: str = "destination",
) -> FirewalldPortActionResponse:
    safe_action = action if isinstance(action, str) else "add_port"
    safe_configuration = configuration if isinstance(configuration, str) else "runtime"
    safe_zone = zone if isinstance(zone, str) else ""
    safe_protocol = protocol if isinstance(protocol, str) else ""
    safe_port = port if isinstance(port, int) and not isinstance(port, bool) else 0
    safe_port_position = port_position if isinstance(port_position, str) else "destination"

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
                protocol=safe_protocol,
                port_position=safe_port_position,
                port=safe_port,
                zone_active=None,
                rule_present=None,
                state_verified=False,
                user_confirmed=confirmed is True,
                message="A fresh firewalld confirmation token is required; inspect the exact rule and try again.",
            )
        if record.claimed:
            return _action_response(
                success=False,
                action=safe_action,
                configuration=safe_configuration,
                zone=safe_zone,
                protocol=safe_protocol,
                port_position=safe_port_position,
                port=safe_port,
                zone_active=record.zone_active,
                rule_present=record.rule_present,
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
                protocol=record.protocol,
                port_position=record.port_position,
                port=record.port,
                zone_active=record.zone_active,
                rule_present=record.rule_present,
                state_verified=False,
                user_confirmed=False,
                message="Explicit client confirmation is required; no firewalld command was run.",
            )
        if (
            _normalize_request(action, configuration, zone, protocol, port, port_position)
            or action != record.action
            or configuration != record.configuration
            or zone != record.zone
            or protocol != record.protocol
            or port != record.port
            or port_position != record.port_position
        ):
            return _action_response(
                success=False,
                action=safe_action,
                configuration=safe_configuration,
                zone=safe_zone,
                protocol=safe_protocol,
                port_position=safe_port_position,
                port=safe_port,
                zone_active=record.zone_active,
                rule_present=record.rule_present,
                state_verified=False,
                user_confirmed=True,
                message="Confirmation did not match the exact action, configuration, zone, protocol, port position, and port; no command was run.",
            )

        env = _environment()
        binary = _binary(env)
        if not binary:
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                protocol=record.protocol,
                port_position=record.port_position,
                port=record.port,
                zone_active=record.zone_active,
                rule_present=record.rule_present,
                state_verified=False,
                user_confirmed=True,
                message="The optional firewall-cmd tool became unavailable; no firewall command was run.",
            )

        current, error = _read_port_snapshot(
            record.configuration,
            record.zone,
            record.protocol,
            record.port,
            record.port_position,
            binary,
            env,
        )
        if error or current is None:
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                protocol=record.protocol,
                port_position=record.port_position,
                port=record.port,
                zone_active=None,
                rule_present=None,
                state_verified=False,
                user_confirmed=True,
                message=error or "The firewalld state could not be revalidated; no command was run.",
            )
        if (
            current.zone_active != record.zone_active
            or current.rule_present != record.rule_present
        ):
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                protocol=record.protocol,
                port_position=record.port_position,
                port=record.port,
                zone_active=current.zone_active,
                rule_present=current.rule_present,
                state_verified=False,
                user_confirmed=True,
                message="The exact zone binding or port-rule state changed after confirmation; inspect it and confirm again.",
            )

        command_prefix = "--add" if record.action == "add_port" else "--remove"
        command_element = "port" if record.port_position == "destination" else "source-port"
        command_name = f"{command_prefix}-{command_element}"
        port_id = f"{record.port}/{record.protocol}"
        arguments = [f"--zone={record.zone}", f"{command_name}={port_id}"]
        if record.configuration == "permanent":
            arguments.insert(0, "--permanent")
        _output, command_error, command_truncated = _command(
            binary,
            arguments,
            env,
            label=f"firewalld {record.configuration} port-rule update",
        )
        after, verify_error = _read_port_snapshot(
            record.configuration,
            record.zone,
            record.protocol,
            record.port,
            record.port_position,
            binary,
            env,
        )
        expected_present = record.action == "add_port"
        verified = (
            after is not None
            and after.zone_active == record.zone_active
            and after.rule_present is expected_present
        )
        if command_error or command_truncated:
            message = (
                "The firewalld command timed out; inspect the selected configuration before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "Firewalld reported a rule-update error; inspect the selected configuration before retrying."
            )
            if verified:
                message += " The requested rule state is visible."
            elif verify_error:
                message += " The resulting state could not be verified."
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                protocol=record.protocol,
                port_position=record.port_position,
                port=record.port,
                zone_active=after.zone_active if after is not None else None,
                rule_present=after.rule_present if after is not None else None,
                state_verified=verified,
                user_confirmed=True,
                message=message,
            )
        if not verified:
            message = "Firewalld returned from the update, but the requested exact rule state is not visible."
            if verify_error:
                message += " The resulting state could not be read."
            return _action_response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                protocol=record.protocol,
                port_position=record.port_position,
                port=record.port,
                zone_active=after.zone_active if after is not None else None,
                rule_present=after.rule_present if after is not None else None,
                state_verified=False,
                user_confirmed=True,
                message=message,
            )
        effect = "added" if expected_present else "removed"
        if record.configuration == "runtime":
            persistence = " This change lasts only until firewalld reloads, restarts, or the host reboots."
        else:
            persistence = " This updates saved configuration only; it does not alter runtime rules until firewalld reloads or restarts."
        return _action_response(
            success=True,
            action=record.action,
            configuration=record.configuration,
            zone=record.zone,
            protocol=record.protocol,
            port_position=record.port_position,
            port=record.port,
            zone_active=after.zone_active,
            rule_present=after.rule_present,
            state_verified=True,
            user_confirmed=True,
            message=f"The exact {record.port_position} {record.protocol}/{record.port} rule was {effect} in firewalld zone {record.zone}.{persistence}",
        )
    finally:
        with _ACTION_LOCK:
            _TOKENS.pop(expected_state_token, None)
