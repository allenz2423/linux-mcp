"""Typed, confirmed firewalld rich rules for one exact zone."""

from __future__ import annotations

import ipaddress
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import FirewalldRichRuleActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

FirewalldRichRuleAction = Literal["add", "remove"]
FirewalldRichRuleVerdict = Literal["accept", "reject", "drop"]
FirewalldRichRuleLogLevel = Literal["emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"]
FirewalldConfiguration = Literal["runtime", "permanent"]
ZONE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,100}$")
LOG_PREFIX_RE = re.compile(r"^[A-Za-z0-9 _.:/-]{1,127}$")
TOKEN_TTL_SECONDS = 180
MAX_PENDING_TOKENS = 1_024
COMMAND_TIMEOUT_SECONDS = 5
MAX_COMMAND_OUTPUT_BYTES = 128 * 1024
MAX_ZONES = 256
MAX_ZONE_LINE_LENGTH = 2_048
MAX_RICH_RULES = 4_096
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _RichRuleSnapshot:
    configuration: str
    zone: str
    zone_active: bool | None
    rich_rule: str
    matching_count: int


@dataclass(slots=True)
class _RichRuleToken:
    action: str
    configuration: str
    zone: str
    zone_active: bool | None
    protocol: str
    port_position: str
    port: int
    port_end: int | None
    source_cidr: str | None
    destination_cidr: str | None
    verdict: str
    log_enabled: bool
    log_prefix: str | None
    log_level: str | None
    audit_enabled: bool
    priority: int | None
    rich_rule: str
    matching_count: int
    expires_at: float
    claimed: bool = False


@dataclass(frozen=True, slots=True)
class FirewalldRichRuleActionTarget:
    action: str
    configuration: str
    zone: str
    zone_active: bool | None
    protocol: str
    port_position: str
    port: int
    port_end: int | None
    source_cidr: str | None
    destination_cidr: str | None
    verdict: str
    log_enabled: bool
    log_prefix: str | None
    log_level: str | None
    audit_enabled: bool
    priority: int | None
    rich_rule: str
    matching_count: int
    confirmation_token: str


_TOKENS: dict[str, _RichRuleToken] = {}


def _normalize_request(
    action: object,
    configuration: object,
    zone: object,
    protocol: object,
    port: object,
    source_cidr: object,
    verdict: object,
    port_end: object = None,
    destination_cidr: object = None,
    log_enabled: object = False,
    log_prefix: object = None,
    log_level: object = None,
    audit_enabled: object = False,
    priority: object = None,
    port_position: object = "destination",
) -> tuple[tuple[object, ...] | None, str | None]:
    if not isinstance(action, str) or action not in {"add", "remove"}:
        return None, "Choose add or remove."
    if not isinstance(configuration, str) or configuration not in {"runtime", "permanent"}:
        return None, "Choose runtime or permanent configuration."
    if not isinstance(zone, str) or not ZONE_NAME_RE.fullmatch(zone):
        return None, "Use one exact existing firewalld zone name from the frontend inventory."
    if not isinstance(protocol, str) or protocol not in {"tcp", "udp"}:
        return None, "Protocol must be tcp or udp."
    if not isinstance(port_position, str) or port_position not in {"destination", "source"}:
        return None, "port_position must be destination or source."
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65_535:
        return None, "Port must be an integer from 1 through 65535."
    if port_end is not None and (
        not isinstance(port_end, int)
        or isinstance(port_end, bool)
        or not port < port_end <= 65_535
    ):
        return None, "port_end must be an integer greater than port and no greater than 65535."
    if not isinstance(verdict, str) or verdict not in {"accept", "reject", "drop"}:
        return None, "Verdict must be accept, reject, or drop."
    if not isinstance(log_enabled, bool) or not isinstance(audit_enabled, bool):
        return None, "log_enabled and audit_enabled must be booleans."
    if not log_enabled and (log_prefix is not None or log_level is not None):
        return None, "log_prefix and log_level require log_enabled=true."
    normalized_log_prefix: str | None = None
    if log_prefix is not None:
        if not isinstance(log_prefix, str) or not LOG_PREFIX_RE.fullmatch(log_prefix):
            return None, "log_prefix must contain 1-127 safe printable characters."
        normalized_log_prefix = log_prefix
    allowed_log_levels = {"emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"}
    if log_level is not None and (not isinstance(log_level, str) or log_level not in allowed_log_levels):
        return None, "log_level must be one of emerg, alert, crit, error, warning, notice, info, or debug."
    if priority is not None and (
        not isinstance(priority, int)
        or isinstance(priority, bool)
        or not -32_768 <= priority <= 32_767
    ):
        return None, "priority must be an integer from -32768 through 32767, or omitted."

    def normalize_cidr(value: object, field: str) -> tuple[str | None, str | None]:
        if value is None or value == "":
            return None, None
        if not isinstance(value, str) or len(value) > 64:
            return None, f"{field} must be a canonical IPv4/IPv6 address or CIDR, or empty."
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            return None, f"{field} must use canonical IP address or network notation."
        if str(network) != value:
            return None, f"{field} must use canonical IP address or network notation."
        return str(network), None

    normalized_source, source_error = normalize_cidr(source_cidr, "source_cidr")
    if source_error:
        return None, source_error
    normalized_destination, destination_error = normalize_cidr(destination_cidr, "destination_cidr")
    if destination_error:
        return None, destination_error
    address_families = {
        "ipv6" if ":" in address else "ipv4"
        for address in (normalized_source, normalized_destination)
        if address is not None
    }
    if len(address_families) > 1:
        return None, "source_cidr and destination_cidr must use the same IP version."
    family_clause = ""
    priority_clause = ""
    source_clause = ""
    destination_clause = ""
    if address_families:
        family = next(iter(address_families))
        family_clause = f' family="{family}"'
    if priority is not None:
        priority_clause = f' priority="{priority}"'
    if normalized_source is not None:
        source_clause = f' source address="{normalized_source}"'
    if normalized_destination is not None:
        destination_clause = f' destination address="{normalized_destination}"'
    rich_port = str(port) if port_end is None else f"{port}-{port_end}"
    log_clause = ""
    if log_enabled:
        log_attributes = ""
        if normalized_log_prefix is not None:
            log_attributes += f' prefix="{normalized_log_prefix}"'
        if log_level is not None:
            log_attributes += f' level="{log_level}"'
        log_clause = f'{log_attributes} limit value="1/m"'
        log_clause = f" log{log_clause}"
    audit_clause = ' audit limit value="1/m"' if audit_enabled else ""
    port_element = "port" if port_position == "destination" else "source-port"
    rich_rule = (
        f'rule{family_clause}{priority_clause}{source_clause}{destination_clause} '
        f'{port_element} port="{rich_port}" protocol="{protocol}"{log_clause}{audit_clause} {verdict}'
    )
    return (
        (
            action, configuration, zone, protocol, port, port_end,
            normalized_source, normalized_destination, verdict, log_enabled,
            normalized_log_prefix, log_level, audit_enabled, priority, rich_rule,
            port_position,
        ),
        None,
    )


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
        name = line.strip().removesuffix(":")
        if not ZONE_NAME_RE.fullmatch(name):
            return None, "Firewalld returned an invalid active-zone name."
        active.add(name)
        if len(active) > MAX_ZONES:
            return None, "Firewalld returned too many active zones."
    return active, None


def _read_snapshot(
    configuration: str,
    zone: str,
    rich_rule: str,
    binary: str,
    env: dict[str, str],
) -> tuple[_RichRuleSnapshot | None, str | None]:
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
            return None, "Runtime rich-rule changes require an exact zone currently bound to an interface or source."

    arguments = [f"--zone={zone}", "--list-rich-rules"]
    if configuration == "permanent":
        arguments.insert(0, "--permanent")
    output, error, truncated = _command(
        binary,
        arguments,
        env,
        label=f"firewalld {configuration} zone rich-rule inventory",
    )
    if error or output is None or truncated:
        return None, "The firewalld zone rich-rule list could not be read completely."
    lines = output.splitlines()
    if len(lines) > MAX_RICH_RULES or any(
        len(line) > MAX_ZONE_LINE_LENGTH
        or any(ord(character) < 32 and character != "\t" for character in line)
        for line in lines
    ):
        return None, "Firewalld returned an invalid or oversized rich-rule inventory."
    matching_count = sum(line.strip() == rich_rule for line in lines)
    if matching_count > 1:
        return None, "Firewalld returned duplicate copies of the exact rich rule; inspect the zone before changing it."
    return _RichRuleSnapshot(
        configuration=configuration,
        zone=zone,
        zone_active=zone_active,
        rich_rule=rich_rule,
        matching_count=matching_count,
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


def firewalld_rich_rule_confirmation_details(
    action: str,
    configuration: str,
    zone: str,
    protocol: str,
    port: int,
    source_cidr: str | None,
    verdict: str,
    port_end: int | None = None,
    destination_cidr: str | None = None,
    log_enabled: bool = False,
    log_prefix: str | None = None,
    log_level: str | None = None,
    audit_enabled: bool = False,
    priority: int | None = None,
    port_position: str = "destination",
) -> tuple[FirewalldRichRuleActionTarget | None, str | None]:
    normalized, validation_error = _normalize_request(
        action, configuration, zone, protocol, port, source_cidr, verdict,
        port_end, destination_cidr, log_enabled, log_prefix, log_level,
        audit_enabled, priority, port_position,
    )
    if validation_error or normalized is None:
        return None, validation_error or "The rich-rule request is invalid."
    (
        action, configuration, zone, protocol, port, normalized_port_end,
        normalized_source, normalized_destination, verdict, normalized_log_enabled,
        normalized_log_prefix, normalized_log_level, normalized_audit_enabled,
        normalized_priority, rich_rule, normalized_port_position,
    ) = normalized
    env = _environment()
    binary = _binary(env)
    if not binary:
        return None, "The optional firewall-cmd tool is unavailable on this Linux host."
    snapshot, error = _read_snapshot(configuration, zone, rich_rule, binary, env)
    if error or snapshot is None:
        return None, error or "The exact firewalld rich-rule state could not be verified."
    desired_count = 0 if action == "add" else 1
    if snapshot.matching_count != desired_count:
        return None, (
            "That exact rich rule already exists in the selected configuration."
            if snapshot.matching_count
            else "That exact rich rule is not present in the selected configuration."
        )

    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _RichRuleToken(
        action=action,
        configuration=configuration,
        zone=zone,
        zone_active=snapshot.zone_active,
        protocol=protocol,
        port_position=normalized_port_position,
        port=port,
        port_end=normalized_port_end,
        source_cidr=normalized_source,
        destination_cidr=normalized_destination,
        verdict=verdict,
        log_enabled=normalized_log_enabled,
        log_prefix=normalized_log_prefix,
        log_level=normalized_log_level,
        audit_enabled=normalized_audit_enabled,
        priority=normalized_priority,
        rich_rule=rich_rule,
        matching_count=snapshot.matching_count,
        expires_at=now + TOKEN_TTL_SECONDS,
    )
    with _ACTION_LOCK:
        for key in [key for key, item in _TOKENS.items() if item.expires_at <= now]:
            _TOKENS.pop(key, None)
        if len(_TOKENS) >= MAX_PENDING_TOKENS:
            return None, "Too many pending firewalld confirmations; retry after existing prompts expire."
        _TOKENS[token] = record
    return FirewalldRichRuleActionTarget(
        action=action,
        configuration=configuration,
        zone=zone,
        zone_active=snapshot.zone_active,
        protocol=protocol,
        port_position=normalized_port_position,
        port=port,
        port_end=normalized_port_end,
        source_cidr=normalized_source,
        destination_cidr=normalized_destination,
        verdict=verdict,
        log_enabled=normalized_log_enabled,
        log_prefix=normalized_log_prefix,
        log_level=normalized_log_level,
        audit_enabled=normalized_audit_enabled,
        priority=normalized_priority,
        rich_rule=rich_rule,
        matching_count=snapshot.matching_count,
        confirmation_token=token,
    ), None


def _response(
    *,
    success: bool,
    action: str,
    configuration: str,
    zone: str,
    protocol: str,
    port: int,
    source_cidr: str | None,
    verdict: str,
    rule_present: bool | None,
    state_verified: bool,
    user_confirmed: bool,
    message: str,
    port_end: int | None = None,
    destination_cidr: str | None = None,
    port_position: str = "destination",
) -> FirewalldRichRuleActionResponse:
    return FirewalldRichRuleActionResponse(
        success=success,
        action=action if action in {"add", "remove"} else "add",
        configuration=configuration if configuration in {"runtime", "permanent"} else "runtime",
        zone=zone[:64] if isinstance(zone, str) else None,
        protocol=protocol if protocol in {"tcp", "udp"} else None,
        port_position=port_position if port_position in {"destination", "source"} else None,
        port=port if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65_535 else None,
        port_end=(
            port_end
            if isinstance(port_end, int)
            and not isinstance(port_end, bool)
            and isinstance(port, int)
            and not isinstance(port, bool)
            and port < port_end <= 65_535
            else None
        ),
        source_cidr=source_cidr[:64] if isinstance(source_cidr, str) else None,
        destination_cidr=destination_cidr[:64] if isinstance(destination_cidr, str) else None,
        verdict=verdict if verdict in {"accept", "reject", "drop"} else None,
        rule_present=rule_present,
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_firewalld_rich_rule_action(
    action: str,
    configuration: str,
    zone: str,
    protocol: str,
    port: int,
    source_cidr: str | None,
    verdict: str,
    expected_state_token: str,
    *,
    confirmed: bool,
    port_end: int | None = None,
    destination_cidr: str | None = None,
    log_enabled: bool = False,
    log_prefix: str | None = None,
    log_level: FirewalldRichRuleLogLevel | None = None,
    audit_enabled: bool = False,
    priority: int | None = None,
    port_position: str = "destination",
) -> FirewalldRichRuleActionResponse:
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
            return _response(
                success=False, action=action, configuration=configuration, zone=zone,
                protocol=protocol, port=port, source_cidr=source_cidr, verdict=verdict,
                rule_present=None, state_verified=False, user_confirmed=confirmed is True,
                message="A fresh firewalld confirmation token is required; inspect the exact rule and try again.",
                port_end=port_end, destination_cidr=destination_cidr, port_position=port_position,
            )
        if record.claimed:
            return _response(
                success=False, action=record.action, configuration=record.configuration,
                zone=record.zone, protocol=record.protocol, port=record.port,
                port_position=record.port_position,
                source_cidr=record.source_cidr, verdict=record.verdict,
                rule_present=record.matching_count == 1, state_verified=False,
                user_confirmed=confirmed is True,
                message="This firewalld confirmation token is already in use; request a fresh confirmation.",
                port_end=record.port_end, destination_cidr=record.destination_cidr,
            )
        record.claimed = True

    try:
        normalized, validation_error = _normalize_request(
            action, configuration, zone, protocol, port, source_cidr, verdict,
            port_end, destination_cidr, log_enabled, log_prefix, log_level,
            audit_enabled, priority, port_position,
        )
        if confirmed is not True:
            message = "Explicit client confirmation is required; no firewalld command was run."
            valid = False
        elif validation_error or normalized is None:
            message = validation_error or "The rich-rule request is invalid."
            valid = False
        elif normalized != (
            record.action, record.configuration, record.zone, record.protocol,
            record.port, record.port_end, record.source_cidr, record.destination_cidr,
            record.verdict, record.log_enabled, record.log_prefix, record.log_level,
            record.audit_enabled, record.priority, record.rich_rule, record.port_position,
        ):
            message = "Confirmation did not match the exact rich rule, modifiers, and configuration; no command was run."
            valid = False
        else:
            message = ""
            valid = True
        if not valid:
            return _response(
                success=False, action=record.action, configuration=record.configuration,
                zone=record.zone, protocol=record.protocol, port=record.port,
                port_position=record.port_position,
                source_cidr=record.source_cidr, verdict=record.verdict,
                rule_present=record.matching_count == 1, state_verified=False,
                user_confirmed=confirmed is True, message=message,
                port_end=record.port_end, destination_cidr=record.destination_cidr,
            )

        env = _environment()
        binary = _binary(env)
        if not binary:
            return _response(
                success=False, action=record.action, configuration=record.configuration,
                zone=record.zone, protocol=record.protocol, port=record.port,
                port_position=record.port_position,
                source_cidr=record.source_cidr, verdict=record.verdict,
                rule_present=record.matching_count == 1, state_verified=False,
                user_confirmed=True, message="The optional firewall-cmd tool became unavailable; no firewall command was run.",
                port_end=record.port_end, destination_cidr=record.destination_cidr,
            )

        current, error = _read_snapshot(
            record.configuration, record.zone, record.rich_rule, binary, env
        )
        if error or current is None:
            return _response(
                success=False, action=record.action, configuration=record.configuration,
                zone=record.zone, protocol=record.protocol, port=record.port,
                port_position=record.port_position,
                source_cidr=record.source_cidr, verdict=record.verdict,
                rule_present=None, state_verified=False, user_confirmed=True,
                message=error or "The firewalld state could not be revalidated; no command was run.",
                port_end=record.port_end, destination_cidr=record.destination_cidr,
            )
        if current.zone_active != record.zone_active or current.matching_count != record.matching_count:
            return _response(
                success=False, action=record.action, configuration=record.configuration,
                zone=record.zone, protocol=record.protocol, port=record.port,
                port_position=record.port_position,
                source_cidr=record.source_cidr, verdict=record.verdict,
                rule_present=current.matching_count == 1, state_verified=False,
                user_confirmed=True,
                message="The exact zone binding or rich-rule state changed after confirmation; inspect it and confirm again.",
                port_end=record.port_end, destination_cidr=record.destination_cidr,
            )

        command_name = "--add-rich-rule" if record.action == "add" else "--remove-rich-rule"
        arguments = [f"--zone={record.zone}", f"{command_name}={record.rich_rule}"]
        if record.configuration == "permanent":
            arguments.insert(0, "--permanent")
        _output, command_error, command_truncated = _command(
            binary, arguments, env,
            label=f"firewalld {record.configuration} rich-rule update",
        )
        after, verify_error = _read_snapshot(
            record.configuration, record.zone, record.rich_rule, binary, env
        )
        expected_present = record.action == "add"
        verified = (
            after is not None
            and after.zone_active == record.zone_active
            and (after.matching_count == 1) is expected_present
        )
        if command_error or command_truncated:
            message = (
                "The firewalld command timed out; inspect the selected configuration before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "Firewalld reported a rich-rule update error; inspect the selected configuration before retrying."
            )
            if verified:
                message += " The requested rule state is visible."
            elif verify_error:
                message += " The resulting state could not be verified."
            return _response(
                success=False, action=record.action, configuration=record.configuration,
                zone=record.zone, protocol=record.protocol, port=record.port,
                port_position=record.port_position,
                source_cidr=record.source_cidr, verdict=record.verdict,
                rule_present=(after.matching_count == 1) if after is not None else None,
                state_verified=verified, user_confirmed=True, message=message,
                port_end=record.port_end, destination_cidr=record.destination_cidr,
            )
        if not verified:
            message = "Firewalld returned from the update, but the requested exact rich-rule state is not visible."
            if verify_error:
                message += " The resulting state could not be read."
            return _response(
                success=False, action=record.action, configuration=record.configuration,
                zone=record.zone, protocol=record.protocol, port=record.port,
                port_position=record.port_position,
                source_cidr=record.source_cidr, verdict=record.verdict,
                rule_present=(after.matching_count == 1) if after is not None else None,
                state_verified=False, user_confirmed=True, message=message,
                port_end=record.port_end, destination_cidr=record.destination_cidr,
            )
        effect = "added" if expected_present else "removed"
        persistence = (
            " This runtime-only change lasts until firewalld reloads, restarts, or the host reboots."
            if record.configuration == "runtime"
            else " This changes saved configuration only; runtime rules change after a firewalld reload or restart."
        )
        return _response(
            success=True, action=record.action, configuration=record.configuration,
            zone=record.zone, protocol=record.protocol, port=record.port,
            port_position=record.port_position,
            source_cidr=record.source_cidr, verdict=record.verdict,
            rule_present=after.matching_count == 1, state_verified=True,
            user_confirmed=True,
            message=(
                f"The exact firewalld rich rule {record.rich_rule!r} was {effect} "
                f"in zone {record.zone}.{persistence}"
            ),
            port_end=record.port_end, destination_cidr=record.destination_cidr,
        )
    finally:
        with _ACTION_LOCK:
            _TOKENS.pop(expected_state_token, None)
