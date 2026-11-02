"""Exact confirmed UFW TCP/UDP port allow/deny/reject/limit rules."""

from __future__ import annotations

import ipaddress
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import UFWPortRuleActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

UFWPortRuleAction = Literal[
    "add_allow", "add_deny", "add_reject", "add_limit",
    "remove_allow", "remove_deny", "remove_reject", "remove_limit",
]
UFWProtocol = Literal["tcp", "udp"]
UFWDirection = Literal["in", "out"]
UFWPolicy = Literal["allow", "deny", "reject", "limit"]
UFW_POLICIES: tuple[UFWPolicy, ...] = ("allow", "deny", "reject", "limit")
ACTION_RE = re.compile(r"^\[\s*([0-9]{1,5})\]\s+(.+)$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,100}$")
TOKEN_TTL_SECONDS = 180
MAX_PENDING_TOKENS = 1_024
COMMAND_TIMEOUT_SECONDS = 5
MAX_COMMAND_OUTPUT_BYTES = 256 * 1024
MAX_UFW_RULES = 1_000
ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _UFWPortSnapshot:
    active: bool
    allow_ipv4_number: int | None
    allow_ipv6_number: int | None
    deny_ipv4_number: int | None
    deny_ipv6_number: int | None
    reject_ipv4_number: int | None
    reject_ipv6_number: int | None
    limit_ipv4_number: int | None
    limit_ipv6_number: int | None

    def counts(self, policy: str) -> tuple[int, int]:
        ipv4_number, ipv6_number = self.numbers(policy)
        return int(ipv4_number is not None), int(ipv6_number is not None)

    def numbers(self, policy: str) -> tuple[int | None, int | None]:
        if policy not in UFW_POLICIES:
            raise ValueError("Unknown UFW rule action.")
        return getattr(self, f"{policy}_ipv4_number"), getattr(self, f"{policy}_ipv6_number")

    def counts_except(self, policy: str) -> tuple[tuple[int, int], ...]:
        return tuple(self.counts(other) for other in UFW_POLICIES if other != policy)


@dataclass(slots=True)
class _UFWPortToken:
    action: str
    protocol: str
    port: int
    port_end: int | None
    additional_ports: tuple[int, ...]
    direction: UFWDirection
    source_address: str
    destination_address: str
    active: bool
    allow_ipv4_number: int | None
    allow_ipv6_number: int | None
    deny_ipv4_number: int | None
    deny_ipv6_number: int | None
    reject_ipv4_number: int | None
    reject_ipv6_number: int | None
    limit_ipv4_number: int | None
    limit_ipv6_number: int | None
    expires_at: float
    claimed: bool = False


@dataclass(frozen=True, slots=True)
class UFWPortRuleTarget:
    action: str
    protocol: str
    port: int
    port_end: int | None
    additional_ports: tuple[int, ...]
    direction: UFWDirection
    source_address: str
    destination_address: str
    active: bool
    ipv4_count: int
    ipv6_count: int
    ipv4_rule_number: int | None
    ipv6_rule_number: int | None
    other_actions_ipv4_count: int
    other_actions_ipv6_count: int
    confirmation_token: str


_TOKENS: dict[str, _UFWPortToken] = {}


def _normalize_request(
    action: object,
    protocol: object,
    port: object,
    direction: object = "in",
    source_address: object = "any",
    destination_address: object = "any",
    port_end: object = None,
    additional_ports: object = None,
) -> str | None:
    if not isinstance(action, str) or action not in {
        "add_allow", "add_deny", "add_reject", "add_limit",
        "remove_allow", "remove_deny", "remove_reject", "remove_limit",
    }:
        return "Choose add_allow, add_deny, add_reject, add_limit, remove_allow, remove_deny, remove_reject, or remove_limit."
    if not isinstance(protocol, str) or protocol not in {"tcp", "udp"}:
        return "Protocol must be tcp or udp."
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65_535:
        return "Port must be an integer from 1 through 65535."
    if port_end is not None and (
        not isinstance(port_end, int)
        or isinstance(port_end, bool)
        or not port < port_end <= 65_535
    ):
        return "port_end must be an integer greater than port and no greater than 65535."
    if additional_ports is not None:
        if not isinstance(additional_ports, (list, tuple)):
            return "additional_ports must be a list of numeric ports."
        if len(additional_ports) > 14:
            return "A UFW port list can contain at most 15 ports including port."
        if additional_ports and port_end is not None:
            return "Use either port_end for one range or additional_ports for a numeric list, not both."
        previous_port = port
        for extra_port in additional_ports:
            if (
                not isinstance(extra_port, int)
                or isinstance(extra_port, bool)
                or not 1 <= extra_port <= 65_535
            ):
                return "Every additional port must be an integer from 1 through 65535."
            if extra_port <= previous_port:
                return "additional_ports must be strictly increasing and greater than port."
            previous_port = extra_port
    if not isinstance(direction, str) or direction not in {"in", "out"}:
        return "Direction must be in or out."
    source, error = _normalize_address(source_address, field="source_address")
    if error:
        return error
    destination, error = _normalize_address(destination_address, field="destination_address")
    if error:
        return error
    address_families = {
        address.version
        for address in (source, destination)
        if address is not None
    }
    if len(address_families) > 1:
        return "source_address and destination_address must use the same IP version."
    return None


def _port_spec(
    port: int,
    port_end: int | None,
    additional_ports: tuple[int, ...] | list[int] | None = None,
) -> str:
    if additional_ports:
        return ",".join(str(item) for item in (port, *additional_ports))
    return str(port) if port_end is None else f"{port}:{port_end}"


def _normalize_address(
    value: object,
    *,
    field: str,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network | None, str | None]:
    if not isinstance(value, str) or not value or len(value) > 64 or "\x00" in value:
        return None, f"{field} must be 'any' or one IPv4/IPv6 address or CIDR."
    if value.casefold() == "any":
        return None, None
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None, f"{field} must be 'any' or one IPv4/IPv6 address or CIDR; hostnames and interface zones are not accepted."
    return network, None


def _canonical_address(value: object, *, field: str) -> tuple[str | None, str | None]:
    network, error = _normalize_address(value, field=field)
    if error:
        return None, error
    if network is None:
        return "any", None
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address), None
    return str(network), None


def _status_address(network: ipaddress.IPv4Network | ipaddress.IPv6Network | None) -> str:
    if network is None or network.prefixlen == 0:
        return "anywhere"
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env


def _command(
    binary: str,
    arguments: list[str],
    env: dict[str, str],
    *,
    label: str,
) -> tuple[str | None, str | None, bool]:
    return run_bounded_command(
        [binary, *arguments],
        env,
        command_label=label,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
    )


def _parse_status(
    output: str,
    protocol: str,
    port: int,
    direction: UFWDirection = "in",
    source_address: str = "any",
    destination_address: str = "any",
    port_end: int | None = None,
    additional_ports: tuple[int, ...] | None = None,
) -> tuple[_UFWPortSnapshot | None, str | None]:
    lines = output.splitlines()
    if len(lines) > MAX_UFW_RULES + 32:
        return None, "UFW returned too many numbered rules to inspect safely."
    active: bool | None = None
    in_rules = False
    header_found = False
    rule_count = 0
    previous_number = 0
    numbers: dict[str, int | None] = {
        "allow_ipv4": None,
        "allow_ipv6": None,
        "deny_ipv4": None,
        "deny_ipv6": None,
        "reject_ipv4": None,
        "reject_ipv6": None,
        "limit_ipv4": None,
        "limit_ipv6": None,
    }
    wanted_to = f"{_port_spec(port, port_end, additional_ports)}/{protocol}"
    wanted_direction = direction
    source_network, source_error = _normalize_address(source_address, field="source_address")
    destination_network, destination_error = _normalize_address(destination_address, field="destination_address")
    if source_error or destination_error:
        return None, source_error or destination_error
    explicit_network = source_network if source_network is not None else destination_network
    requested_family = f"ipv{explicit_network.version}" if explicit_network is not None else None
    wanted_source = _status_address(source_network)
    wanted_destination = _status_address(destination_network) if destination_network is not None else None

    for line in lines:
        if len(line) > 2_048:
            return None, "UFW returned an oversized status line."
        stripped = line.strip()
        if not stripped:
            continue
        if not in_rules and stripped.casefold().startswith("status:"):
            if active is not None:
                return None, "UFW returned multiple status headers."
            state = stripped.split(":", 1)[1].strip().casefold()
            if state not in {"active", "inactive"}:
                return None, "UFW returned an unrecognized active state."
            active = state == "active"
            continue
        columns = [part.casefold() for part in re.split(r"\s+", stripped)]
        if not in_rules and "to" in columns and "action" in columns and "from" in columns:
            in_rules = True
            header_found = True
            continue
        if not in_rules:
            return None, "UFW returned an unrecognized status record."
        if set(stripped) <= {"-", " "}:
            continue
        match = ACTION_RE.fullmatch(stripped)
        if not match:
            return None, "UFW returned an unsupported numbered-rule record."
        rule_count += 1
        if rule_count > MAX_UFW_RULES:
            return None, "UFW returned too many numbered rules to inspect safely."
        number = int(match.group(1))
        if number != previous_number + 1:
            return None, "UFW returned a nonsequential numbered-rule inventory."
        previous_number = number
        tokens = match.group(2).split()
        action_index = next(
            (index for index, token in enumerate(tokens) if token.upper() in {"ALLOW", "DENY", "REJECT", "LIMIT"}),
            None,
        )
        if action_index is None or action_index <= 0 or action_index + 1 >= len(tokens):
            return None, "UFW returned an unsupported numbered-rule format."
        to_tokens = [token.casefold() for token in tokens[:action_index]]
        rule_action = tokens[action_index].casefold()
        if rule_action not in UFW_POLICIES:
            continue
        direction_index = action_index + 1
        if direction_index < len(tokens) and tokens[direction_index].upper() in {"IN", "OUT", "FWD"}:
            from_start = direction_index + 1
        else:
            from_start = direction_index
        from_tokens = [token.casefold() for token in tokens[from_start:]]
        ipv6_marker = "(v6)" in to_tokens or "(v6)" in from_tokens
        core_to = [token for token in to_tokens if token != "(v6)"]
        core_from = [token for token in from_tokens if token != "(v6)"]
        observed_direction = direction_index < len(tokens) and tokens[direction_index].upper() in {"IN", "OUT", "FWD"}
        status_direction = tokens[direction_index].casefold() if observed_direction else "in"
        if status_direction != wanted_direction:
            continue
        expected_to = [wanted_to] if wanted_destination is None else [wanted_destination, wanted_to]
        alternative_to = [wanted_to, wanted_destination] if wanted_destination is not None else None
        any_destination_alternative = (
            core_to == [wanted_to]
            if destination_network is not None and destination_network.prefixlen == 0
            else False
        )
        if core_to != expected_to and core_to != alternative_to and not any_destination_alternative:
            continue
        if core_from != [wanted_source]:
            continue
        family = "ipv6" if ipv6_marker else "ipv4"
        if requested_family is not None and family != requested_family:
            continue
        key = f"{rule_action}_{family}"
        if numbers[key] is not None:
            return None, "UFW contains duplicate matching entries; inspect its numbered rules before changing them."
        numbers[key] = number

    if active is None or (not header_found and rule_count):
        return None, "UFW did not return a complete active-state and numbered-rule status."
    return _UFWPortSnapshot(
        active=active,
        allow_ipv4_number=numbers["allow_ipv4"],
        allow_ipv6_number=numbers["allow_ipv6"],
        deny_ipv4_number=numbers["deny_ipv4"],
        deny_ipv6_number=numbers["deny_ipv6"],
        reject_ipv4_number=numbers["reject_ipv4"],
        reject_ipv6_number=numbers["reject_ipv6"],
        limit_ipv4_number=numbers["limit_ipv4"],
        limit_ipv6_number=numbers["limit_ipv6"],
    ), None


def _read_status_snapshot(
    protocol: str,
    port: int,
    binary: str,
    env: dict[str, str],
    direction: UFWDirection = "in",
    source_address: str = "any",
    destination_address: str = "any",
    port_end: int | None = None,
    additional_ports: tuple[int, ...] | None = None,
) -> tuple[_UFWPortSnapshot | None, str | None]:
    output, error, truncated = _command(
        binary,
        ["status", "numbered"],
        env,
        label="UFW active status and numbered-rule query",
    )
    if error or output is None or truncated:
        return None, "UFW status could not be read completely."
    snapshot, error = _parse_status(
        output, protocol, port, direction, source_address, destination_address, port_end, additional_ports
    )
    if error or snapshot is None:
        return None, error or "UFW status could not be parsed safely."
    if not snapshot.active:
        return None, "UFW must be active before this tool changes an inbound or outbound rule."
    return snapshot, None


def _policy_for_action(action: str) -> str:
    return action.split("_", 1)[1]


def _is_add(action: str) -> bool:
    return action.startswith("add_")


def _read_policy_snapshot(
    action: str,
    protocol: str,
    port: int,
    binary: str,
    env: dict[str, str],
    direction: UFWDirection = "in",
    source_address: str = "any",
    destination_address: str = "any",
    port_end: int | None = None,
    additional_ports: tuple[int, ...] | None = None,
) -> tuple[_UFWPortSnapshot | None, str | None]:
    snapshot, error = _read_status_snapshot(
        protocol,
        port,
        binary,
        env,
        direction,
        source_address,
        destination_address,
        port_end,
        additional_ports,
    )
    if error or snapshot is None:
        return None, error or "UFW status could not be parsed safely."
    policy = _policy_for_action(action)
    ipv4_count, ipv6_count = snapshot.counts(policy)
    present = ipv4_count > 0 or ipv6_count > 0
    if _is_add(action) and present:
        return None, f"That exact UFW {direction} {policy} port rule already exists."
    if not _is_add(action) and not present:
        return None, f"That exact UFW {direction} {policy} port rule is not present."
    return snapshot, None


def ufw_port_rule_confirmation_details(
    action: str,
    protocol: str,
    port: int,
    direction: str = "in",
    source_address: str = "any",
    destination_address: str = "any",
    port_end: int | None = None,
    additional_ports: list[int] | tuple[int, ...] | None = None,
) -> tuple[UFWPortRuleTarget | None, str | None]:
    validation_error = _normalize_request(
        action, protocol, port, direction, source_address, destination_address, port_end, additional_ports
    )
    if validation_error:
        return None, validation_error
    canonical_source, error = _canonical_address(source_address, field="source_address")
    if error or canonical_source is None:
        return None, error or "source_address could not be normalized."
    canonical_destination, error = _canonical_address(destination_address, field="destination_address")
    if error or canonical_destination is None:
        return None, error or "destination_address could not be normalized."
    env = _environment()
    binary = find_session_binary("ufw", env) if sys.platform.startswith("linux") else None
    if not binary:
        return None, "The optional ufw command is unavailable on this Linux host."
    snapshot, error = _read_policy_snapshot(
        action,
        protocol,
        port,
        binary,
        env,
        direction,
        canonical_source,
        canonical_destination,
        port_end,
        tuple(additional_ports or ()),
    )
    if error or snapshot is None:
        return None, error or "The exact UFW port-rule state could not be verified."
    policy = _policy_for_action(action)
    ipv4_count, ipv6_count = snapshot.counts(policy)
    other_policies = tuple(other for other in UFW_POLICIES if other != policy)
    other_ipv4_count = sum(snapshot.counts(other)[0] for other in other_policies)
    other_ipv6_count = sum(snapshot.counts(other)[1] for other in other_policies)
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _UFWPortToken(
        action=action,
        protocol=protocol,
        port=port,
        port_end=port_end,
        additional_ports=tuple(additional_ports or ()),
        direction=direction,  # type: ignore[arg-type]
        source_address=canonical_source,
        destination_address=canonical_destination,
        active=snapshot.active,
        allow_ipv4_number=snapshot.allow_ipv4_number,
        allow_ipv6_number=snapshot.allow_ipv6_number,
        deny_ipv4_number=snapshot.deny_ipv4_number,
        deny_ipv6_number=snapshot.deny_ipv6_number,
        reject_ipv4_number=snapshot.reject_ipv4_number,
        reject_ipv6_number=snapshot.reject_ipv6_number,
        limit_ipv4_number=snapshot.limit_ipv4_number,
        limit_ipv6_number=snapshot.limit_ipv6_number,
        expires_at=now + TOKEN_TTL_SECONDS,
    )
    with ACTION_LOCK:
        for key in [key for key, item in _TOKENS.items() if item.expires_at <= now]:
            _TOKENS.pop(key, None)
        if len(_TOKENS) >= MAX_PENDING_TOKENS:
            return None, "Too many pending UFW confirmations; retry after existing prompts expire."
        _TOKENS[token] = record
    return UFWPortRuleTarget(
        action=action,
        protocol=protocol,
        port=port,
        port_end=port_end,
        additional_ports=tuple(additional_ports or ()),
        direction=direction,  # type: ignore[arg-type]
        source_address=canonical_source,
        destination_address=canonical_destination,
        active=snapshot.active,
        ipv4_count=ipv4_count,
        ipv6_count=ipv6_count,
        ipv4_rule_number=snapshot.numbers(policy)[0],
        ipv6_rule_number=snapshot.numbers(policy)[1],
        other_actions_ipv4_count=other_ipv4_count,
        other_actions_ipv6_count=other_ipv6_count,
        confirmation_token=token,
    ), None


def _response(
    *,
    success: bool,
    action: object,
    protocol: object,
    port: object,
    port_end: object = None,
    additional_ports: object = None,
    direction: object = None,
    source_address: object = None,
    destination_address: object = None,
    rule_present: bool | None,
    state_verified: bool,
    user_confirmed: bool,
    message: str,
) -> UFWPortRuleActionResponse:
    return UFWPortRuleActionResponse(
        success=success,
        action=action if isinstance(action, str) and action in {
            "add_allow", "add_deny", "add_reject", "add_limit",
            "remove_allow", "remove_deny", "remove_reject", "remove_limit",
        } else "add_allow",
        protocol=protocol if isinstance(protocol, str) and protocol in {"tcp", "udp"} else None,
        port=port if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65_535 else None,
        port_end=port_end if isinstance(port_end, int) and not isinstance(port_end, bool) and 1 <= port_end <= 65_535 else None,
        additional_ports=(
            [
                item
                for item in additional_ports
                if isinstance(item, int) and not isinstance(item, bool) and 1 <= item <= 65_535
            ][:14]
            if isinstance(additional_ports, (list, tuple))
            else None
        ),
        direction=direction if isinstance(direction, str) and direction in {"in", "out"} else None,
        source_address=source_address if isinstance(source_address, str) else None,
        destination_address=destination_address if isinstance(destination_address, str) else None,
        rule_present=rule_present,
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def _record_response(
    record: _UFWPortToken,
    *,
    success: bool,
    rule_present: bool | None,
    state_verified: bool,
    user_confirmed: bool,
    message: str,
) -> UFWPortRuleActionResponse:
    return _response(
        success=success,
        action=record.action,
        protocol=record.protocol,
        port=record.port,
        port_end=record.port_end,
        additional_ports=list(record.additional_ports) or None,
        direction=record.direction,
        source_address=record.source_address,
        destination_address=record.destination_address,
        rule_present=rule_present,
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_ufw_port_rule_action(
    action: str,
    protocol: str,
    port: int,
    expected_state_token: str,
    direction: str = "in",
    source_address: str = "any",
    destination_address: str = "any",
    port_end: int | None = None,
    additional_ports: list[int] | tuple[int, ...] | None = None,
    *,
    confirmed: bool,
) -> UFWPortRuleActionResponse:
    safe_action = action if isinstance(action, str) else "add_allow"
    safe_protocol = protocol if isinstance(protocol, str) else ""
    safe_port = port if isinstance(port, int) and not isinstance(port, bool) else 0
    canonical_source, _source_error = _canonical_address(source_address, field="source_address")
    canonical_destination, _destination_error = _canonical_address(destination_address, field="destination_address")
    safe_direction = direction if isinstance(direction, str) and direction in {"in", "out"} else "in"
    with ACTION_LOCK:
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
            return _response(success=False, action=safe_action, protocol=safe_protocol, port=safe_port,
                port_end=port_end,
                additional_ports=additional_ports,
                direction=safe_direction, source_address=canonical_source, destination_address=canonical_destination,
                rule_present=None, state_verified=False, user_confirmed=confirmed is True,
                message="A fresh UFW confirmation token is required; inspect the exact rule and try again.")
        if record.claimed:
            return _record_response(record, success=False,
                rule_present=None, state_verified=False, user_confirmed=confirmed is True,
                message="This UFW confirmation token is already in use; request a fresh confirmation.")
        record.claimed = True
    try:
        if confirmed is not True:
            return _record_response(record, success=False,
                rule_present=None, state_verified=False, user_confirmed=False,
                message="Explicit client confirmation is required; no UFW command was run.")
        if (
            _normalize_request(
                action, protocol, port, direction, source_address, destination_address, port_end, additional_ports
            )
            or action != record.action
            or protocol != record.protocol
            or port != record.port
            or port_end != record.port_end
            or tuple(additional_ports or ()) != record.additional_ports
            or direction != record.direction
            or canonical_source != record.source_address
            or canonical_destination != record.destination_address
        ):
            return _response(success=False, action=safe_action, protocol=safe_protocol, port=safe_port,
                port_end=port_end,
                additional_ports=additional_ports,
                direction=safe_direction, source_address=canonical_source, destination_address=canonical_destination,
                rule_present=None, state_verified=False, user_confirmed=True,
                message="Confirmation did not match the exact action, protocol, port selector, direction, or addresses; no command was run.")

        env = _environment()
        binary = find_session_binary("ufw", env) if sys.platform.startswith("linux") else None
        if not binary:
            return _record_response(record, success=False,
                rule_present=None, state_verified=False, user_confirmed=True,
                message="The optional ufw command became unavailable; no command was run.")
        current, error = _read_policy_snapshot(
            record.action,
            record.protocol,
            record.port,
            binary,
            env,
            record.direction,
            record.source_address,
            record.destination_address,
            record.port_end,
            record.additional_ports,
        )
        if error or current is None:
            return _record_response(record, success=False,
                rule_present=None, state_verified=False, user_confirmed=True,
                message=error or "UFW state could not be revalidated; no command was run.")
        if (
            current.active != record.active
            or current.allow_ipv4_number != record.allow_ipv4_number
            or current.allow_ipv6_number != record.allow_ipv6_number
            or current.deny_ipv4_number != record.deny_ipv4_number
            or current.deny_ipv6_number != record.deny_ipv6_number
            or current.reject_ipv4_number != record.reject_ipv4_number
            or current.reject_ipv6_number != record.reject_ipv6_number
            or current.limit_ipv4_number != record.limit_ipv4_number
            or current.limit_ipv6_number != record.limit_ipv6_number
        ):
            return _record_response(record, success=False,
                rule_present=None, state_verified=False, user_confirmed=True,
                message="UFW state or the exact port rule changed after confirmation; inspect it and confirm again.")

        policy = _policy_for_action(record.action)
        is_add = _is_add(record.action)
        command_error: str | None = None
        command_truncated = False
        step_error: str | None = None
        if is_add:
            _output, command_error, command_truncated = _command(
                binary,
                [
                    policy,
                    record.direction,
                    "proto",
                    record.protocol,
                    "from",
                    record.source_address,
                    "to",
                    record.destination_address,
                    "port",
                    _port_spec(record.port, record.port_end, record.additional_ports),
                ],
                env,
                label=f"UFW {record.direction} port-rule add",
            )
        else:
            original_numbers = current.numbers(policy)
            original_other_counts = current.counts_except(policy)
            removed_families: set[str] = set()
            for family, family_index in (("ipv4", 0), ("ipv6", 1)):
                if original_numbers[family_index] is None:
                    continue
                before, before_error = _read_status_snapshot(
                    record.protocol,
                    record.port,
                    binary,
                    env,
                    record.direction,
                    record.source_address,
                    record.destination_address,
                    record.port_end,
                    record.additional_ports,
                )
                if before_error or before is None:
                    step_error = before_error or "UFW state could not be read before removing the next IP-family entry."
                    break
                before_numbers = before.numbers(policy)
                expected_target_presence = tuple(
                    original_numbers[index] is not None and family_name not in removed_families
                    for index, family_name in enumerate(("ipv4", "ipv6"))
                )
                if (
                    tuple(number is not None for number in before_numbers) != expected_target_presence
                    or before.counts_except(policy) != original_other_counts
                    or before_numbers[family_index] is None
                ):
                    step_error = "UFW rule state changed during removal; inspect the numbered status before retrying."
                    break
                rule_number = before_numbers[family_index]
                _output, command_error, command_truncated = _command(
                    binary,
                    ["--force", "delete", str(rule_number)],
                    env,
                    label=f"UFW {record.direction} {family} port-rule removal",
                )
                after_step, after_step_error = _read_status_snapshot(
                    record.protocol,
                    record.port,
                    binary,
                    env,
                    record.direction,
                    record.source_address,
                    record.destination_address,
                    record.port_end,
                    record.additional_ports,
                )
                if after_step_error or after_step is None:
                    step_error = after_step_error or "UFW state could not be verified after removing a numbered entry."
                    break
                after_numbers = after_step.numbers(policy)
                expected_after_presence = tuple(
                    original_numbers[index] is not None
                    and family_name not in {*removed_families, family}
                    for index, family_name in enumerate(("ipv4", "ipv6"))
                )
                if (
                    tuple(number is not None for number in after_numbers) != expected_after_presence
                    or after_step.counts_except(policy) != original_other_counts
                ):
                    step_error = "UFW did not preserve the expected exact rule state after numbered removal."
                else:
                    removed_families.add(family)
                if command_error or command_truncated or step_error:
                    break
        after, verify_error = _read_status_snapshot(
            record.protocol,
            record.port,
            binary,
            env,
            record.direction,
            record.source_address,
            record.destination_address,
            record.port_end,
            record.additional_ports,
        )
        expected_present = is_add
        after_count = None
        if after is not None:
            after_count = sum(after.counts(policy))
        verified = after is not None and ((after_count > 0) is expected_present)
        if command_error or command_truncated or step_error:
            msg = (
                "The UFW command timed out; inspect the numbered status before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "UFW reported a rule-update error; inspect the numbered status before retrying."
            )
            if step_error:
                msg = step_error
            if verified:
                msg += " The requested rule state is visible."
            elif verify_error:
                msg += " The resulting state could not be verified."
            return _record_response(record, success=False,
                rule_present=(after_count > 0) if after_count is not None else None,
                state_verified=verified, user_confirmed=True, message=msg)
        if not verified:
            msg = "UFW returned from the update, but the requested exact rule state is not visible."
            if verify_error:
                msg += " The resulting state could not be read."
            return _record_response(record, success=False,
                rule_present=(after_count > 0) if after_count is not None else None,
                state_verified=False, user_confirmed=True, message=msg)
        effect = "added" if expected_present else "removed"
        return _record_response(record, success=True,
            rule_present=expected_present, state_verified=True, user_confirmed=True,
            message=f"The exact UFW {record.direction} {policy} rule for {record.protocol}/{_port_spec(record.port, record.port_end, record.additional_ports)} from {record.source_address} to {record.destination_address} was {effect}. Other firewall rules and default policies continue to apply.")
    finally:
        with ACTION_LOCK:
            _TOKENS.pop(expected_state_token, None)
