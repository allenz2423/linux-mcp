"""Exact, explicitly confirmed transient static-route changes via iproute2."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import NetworkRouteActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.network_control import InterfaceSnapshot, capture_interface

RouteAction = Literal["add", "remove"]
ROUTE_ACTIONS = {"add", "remove"}
MAX_ROUTE_OUTPUT_BYTES = 512 * 1024
MAX_EXACT_ROUTE_ROWS = 2_048
ROUTE_QUERY_TIMEOUT_SECONDS = 5
ROUTE_ACTION_TIMEOUT_SECONDS = 10
ROUTE_TABLE_MAX = 0xFFFFFFFF
RESERVED_ROUTE_TABLES = {0, 253, 255}


@dataclass(frozen=True, slots=True)
class NormalizedRouteRequest:
    action: RouteAction
    family: Literal["ipv4", "ipv6"]
    family_flag: str
    destination: str
    gateway: str | None
    interface: str
    table: int
    metric: int


@dataclass(frozen=True, slots=True)
class RouteSpec:
    action: RouteAction
    family: Literal["ipv4", "ipv6"]
    family_flag: str
    destination: str
    gateway: str | None
    interface: str
    table: int
    metric: int
    interface_snapshot: InterfaceSnapshot


@dataclass(frozen=True, slots=True)
class RouteEntry:
    destination: str
    gateway: str | None
    interface: str | None
    table: int
    metric: int
    protocol: str | int
    route_type: str
    scope: str | None
    preferred_source: str | None
    preference: str | None
    unsupported_attributes: bool


@dataclass(frozen=True, slots=True)
class RouteActionTarget:
    spec: RouteSpec
    existing_route: RouteEntry | None


def iproute2_route_control_available() -> bool:
    return sys.platform.startswith("linux") and bool(
        find_session_binary("ip", get_sanitized_env(dict(os.environ)))
    )


def _safe_response_action(action: object) -> RouteAction:
    return action if isinstance(action, str) and action in ROUTE_ACTIONS else "add"


def _parse_destination(value: object) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network | None, str | None]:
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 128
        or "/" not in value
        or value != value.strip()
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        return None, "destination must be an explicit canonical IPv4/IPv6 CIDR."
    try:
        parsed = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return None, "destination must be a canonical IPv4/IPv6 network prefix with no host bits set."
    if parsed.network_address.is_multicast:
        return None, "Multicast route destinations are not supported by this action."
    if str(parsed) != value:
        return None, f"Use the canonical destination CIDR {parsed}."
    return parsed, None


def _parse_gateway(value: object, version: int) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or len(value) > 64 or value != value.strip():
        return None, "gateway must be an IP address, or an empty string for a direct route."
    if not value:
        return None, None
    if "%" in value or any(ord(character) < 33 or ord(character) == 127 for character in value):
        return None, "gateway must not contain a zone identifier or control characters."
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None, "gateway must be a valid IPv4/IPv6 address."
    if address.version != version:
        return None, "gateway and destination must use the same address family."
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        return None, "An unspecified, multicast, or loopback address cannot be used as a gateway."
    if str(address) != value:
        return None, f"Use the canonical gateway address {address}."
    return str(address), None


def _normalize_request(
    action: object,
    destination: object,
    gateway: object,
    interface: object,
    table: object,
    metric: object,
) -> tuple[NormalizedRouteRequest | None, str | None]:
    if not isinstance(action, str) or action not in ROUTE_ACTIONS:
        return None, "Choose one supported route action: add or remove."
    network, error = _parse_destination(destination)
    if error or network is None:
        return None, error
    normalized_gateway, error = _parse_gateway(gateway, network.version)
    if error:
        return None, error
    if not isinstance(interface, str) or not 1 <= len(interface) <= 15:
        return None, "interface must be one exact current network-interface name."
    if not isinstance(table, int) or isinstance(table, bool) or not 1 <= table <= ROUTE_TABLE_MAX:
        return None, f"table must be an integer from 1 through {ROUTE_TABLE_MAX}."
    if table in RESERVED_ROUTE_TABLES:
        return None, "The unspecified, default, and local routing tables cannot be changed by this tool."
    if not isinstance(metric, int) or isinstance(metric, bool) or not 0 <= metric <= ROUTE_TABLE_MAX:
        return None, f"metric must be an integer from 0 through {ROUTE_TABLE_MAX}."
    family: Literal["ipv4", "ipv6"] = "ipv4" if network.version == 4 else "ipv6"
    family_flag = "-4" if network.version == 4 else "-6"
    return NormalizedRouteRequest(
        action=action,
        family=family,
        family_flag=family_flag,
        destination=str(network),
        gateway=normalized_gateway,
        interface=interface,
        table=table,
        metric=metric,
    ), None


def _route_table_id(value: object, fallback: int) -> int | None:
    if value is None:
        return fallback
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        aliases = {"unspec": 0, "default": 253, "main": 254, "local": 255}
        if value.casefold() in aliases:
            return aliases[value.casefold()]
        try:
            return int(value, 10)
        except ValueError:
            # The command queried one numeric table explicitly; iproute2 may
            # render that ID using a host-specific name from rt_tables.
            return fallback
    return None


def _parse_route_entry(raw: dict[str, object], spec: RouteSpec) -> RouteEntry | None:
    raw_destination = raw.get("dst", "default")
    if raw_destination == "default":
        destination = "0.0.0.0/0" if spec.family == "ipv4" else "::/0"
    elif isinstance(raw_destination, str):
        try:
            parsed = ipaddress.ip_network(raw_destination, strict=False)
        except ValueError:
            return None
        if parsed.version != (4 if spec.family == "ipv4" else 6):
            return None
        destination = str(parsed)
    else:
        return None

    raw_gateway = raw.get("gateway", raw.get("via"))
    if isinstance(raw_gateway, dict):
        raw_gateway = raw_gateway.get("host")
    if raw_gateway is not None:
        if not isinstance(raw_gateway, str):
            return None
        try:
            parsed_gateway = ipaddress.ip_address(raw_gateway)
        except ValueError:
            return None
        if parsed_gateway.version != (4 if spec.family == "ipv4" else 6):
            return None
        gateway = str(parsed_gateway)
    else:
        gateway = None

    raw_interface = raw.get("dev")
    if raw_interface is not None and not isinstance(raw_interface, str):
        return None
    table = _route_table_id(raw.get("table"), spec.table)
    raw_metric = raw.get("metric", 0)
    if isinstance(raw_metric, str):
        try:
            raw_metric = int(raw_metric, 10)
        except ValueError:
            return None
    if (
        table is None
        or not isinstance(raw_metric, int)
        or isinstance(raw_metric, bool)
        or not 0 <= raw_metric <= ROUTE_TABLE_MAX
    ):
        return None

    protocol = raw.get("protocol", raw.get("proto", "boot"))
    if isinstance(protocol, str):
        protocol = protocol.casefold()
    elif not isinstance(protocol, int) or isinstance(protocol, bool):
        return None
    route_type = raw.get("type", "unicast")
    if not isinstance(route_type, str):
        return None
    scope = raw.get("scope")
    if scope is not None and not isinstance(scope, str):
        return None
    source = raw.get("prefsrc", raw.get("src"))
    if source is not None:
        if not isinstance(source, str):
            return None
        try:
            parsed_source = ipaddress.ip_address(source)
        except ValueError:
            return None
        if parsed_source.version != (4 if spec.family == "ipv4" else 6):
            return None
        source = str(parsed_source)
    preference = raw.get("pref")
    if preference is not None:
        if not isinstance(preference, str) or preference.casefold() not in {"low", "medium", "high"}:
            return None
        preference = preference.casefold()
    flags = raw.get("flags", [])
    if not isinstance(flags, list):
        return None
    supported_keys = {
        "dst", "gateway", "via", "dev", "table", "type", "scope", "metric",
        "protocol", "proto", "prefsrc", "src", "pref", "flags",
    }
    unsupported = bool(set(raw) - supported_keys or flags or preference in {"low", "high"})
    return RouteEntry(
        destination=destination,
        gateway=gateway,
        interface=raw_interface,
        table=table,
        metric=raw_metric,
        protocol=protocol,
        route_type=route_type.casefold(),
        scope=scope.casefold() if isinstance(scope, str) else None,
        preferred_source=source,
        preference=preference,
        unsupported_attributes=unsupported,
    )


def _read_exact_routes(spec: RouteSpec) -> tuple[list[RouteEntry] | None, str | None]:
    env = get_sanitized_env(dict(os.environ))
    ip_binary = find_session_binary("ip", env)
    if not ip_binary:
        return None, "The iproute2 'ip' command is unavailable."
    command = [
        ip_binary, "-j", spec.family_flag, "route", "show", "table", str(spec.table),
        "exact", spec.destination,
    ]
    output, error, truncated = run_bounded_command(
        command,
        env,
        command_label="Exact route inventory",
        timeout_seconds=ROUTE_QUERY_TIMEOUT_SECONDS,
        max_output_bytes=MAX_ROUTE_OUTPUT_BYTES,
    )
    if error:
        return None, "The exact route state could not be read in the current network namespace."
    if truncated:
        return None, "The exact route response exceeded its output limit."
    try:
        rows = json.loads(output or "", parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
    except (json.JSONDecodeError, ValueError):
        return None, "iproute2 returned malformed JSON for the exact route query."
    if not isinstance(rows, list) or len(rows) > MAX_EXACT_ROUTE_ROWS:
        return None, "iproute2 returned an unexpected or oversized exact route response."
    entries: list[RouteEntry] = []
    for row in rows:
        if not isinstance(row, dict):
            return None, "iproute2 returned a malformed route entry."
        parsed = _parse_route_entry(row, spec)
        if parsed is None:
            return None, "An exact route entry could not be safely interpreted."
        if parsed.destination != spec.destination or parsed.table != spec.table:
            return None, "iproute2 returned a route outside the requested destination/table."
        entries.append(parsed)
    return entries, None


def _route_matches_spec(entry: RouteEntry, spec: RouteSpec) -> bool:
    return (
        entry.destination == spec.destination
        and entry.gateway == spec.gateway
        and entry.interface == spec.interface
        and entry.table == spec.table
        and entry.metric == spec.metric
    )


def _resolve_target(
    action: object,
    destination: object,
    gateway: object,
    interface: object,
    table: object,
    metric: object,
) -> tuple[RouteActionTarget | None, str | None]:
    normalized, error = _normalize_request(action, destination, gateway, interface, table, metric)
    if error or normalized is None:
        return None, error
    snapshot, error = capture_interface(normalized.interface)
    if error or snapshot is None:
        return None, error or "The exact network interface could not be verified."
    if normalized.action == "add" and not snapshot.administrative_up:
        return None, "The selected interface is administratively down; bring it up and inspect it before adding a route."
    spec = RouteSpec(
        action=normalized.action,
        family=normalized.family,
        family_flag=normalized.family_flag,
        destination=normalized.destination,
        gateway=normalized.gateway,
        interface=normalized.interface,
        table=normalized.table,
        metric=normalized.metric,
        interface_snapshot=snapshot,
    )
    entries, error = _read_exact_routes(spec)
    if error or entries is None:
        return None, error or "The exact route state could not be read."
    same_prefix_metric = [
        entry for entry in entries
        if entry.destination == spec.destination and entry.table == spec.table and entry.metric == spec.metric
    ]
    matching = [entry for entry in entries if _route_matches_spec(entry, spec)]
    if safe_action == "add":
        if same_prefix_metric:
            return None, "A route for this exact destination, table, and metric already exists; this tool does not replace or create multipath routes."
        return RouteActionTarget(spec=spec, existing_route=None), None
    static_matches = [
        entry for entry in matching
        if entry.protocol in {"static", 4, "4"} and entry.route_type == "unicast"
    ]
    if len(static_matches) != 1:
        return None, "Remove requires one exact unicast route tagged static (protocol 4) with this destination, gateway, interface, table, and metric."
    existing = static_matches[0]
    if existing.unsupported_attributes:
        return None, "This route has advanced attributes not supported by the exact removal operation."
    return RouteActionTarget(spec=spec, existing_route=existing), None


def route_action_confirmation_details(
    action: str,
    destination: str,
    gateway: str,
    interface: str,
    table: int,
    metric: int,
) -> tuple[RouteActionTarget | None, str | None]:
    """Validate one route change and capture its current interface/route state."""
    if not iproute2_route_control_available():
        return None, "Route control requires Linux and the iproute2 'ip' command."
    return _resolve_target(action, destination, gateway, interface, table, metric)


def _safe_response_values(
    action: object,
    destination: object,
    gateway: object,
    interface: object,
    table: object,
    metric: object,
) -> dict[str, object]:
    family = None
    if isinstance(destination, str):
        try:
            family = "ipv4" if ipaddress.ip_network(destination, strict=False).version == 4 else "ipv6"
        except ValueError:
            pass
    return {
        "action": _safe_response_action(action),
        "family": family,
        "destination": destination[:128] if isinstance(destination, str) else None,
        "gateway": gateway[:64] if isinstance(gateway, str) and gateway else None,
        "interface": interface[:15] if isinstance(interface, str) else None,
        "table": table if isinstance(table, int) and not isinstance(table, bool) else None,
        "metric": metric if isinstance(metric, int) and not isinstance(metric, bool) else None,
    }


def _command_for_target(target: RouteActionTarget) -> tuple[str, list[str]] | None:
    spec = target.spec
    env = get_sanitized_env(dict(os.environ))
    ip_binary = find_session_binary("ip", env)
    if not ip_binary:
        return None
    operation = "add" if spec.action == "add" else "del"
    command = [ip_binary, spec.family_flag, "route", operation, "unicast", spec.destination]
    if spec.gateway:
        command.extend(("via", spec.gateway))
    command.extend((
        "dev", spec.interface,
        "table", str(spec.table),
        "metric", str(spec.metric),
        "proto", "4",
    ))
    if spec.action == "add":
        command.extend(("scope", "global" if spec.gateway else "link"))
        if spec.family == "ipv6":
            command.extend(("pref", "medium"))
    else:
        route = target.existing_route
        if route is None:
            return None
        if route.scope:
            command.extend(("scope", route.scope))
        if route.preferred_source:
            command.extend(("src", route.preferred_source))
        if spec.family == "ipv6":
            if route.preference not in {None, "medium"}:
                return None
            command.extend(("pref", "medium"))
    return ip_binary, command


def perform_route_action(
    action: str,
    destination: str,
    gateway: str,
    interface: str,
    table: int,
    metric: int,
    *,
    confirmed: bool,
    expected_interface_index: int | None = None,
) -> NetworkRouteActionResponse:
    values = _safe_response_values(action, destination, gateway, interface, table, metric)
    if not confirmed:
        return NetworkRouteActionResponse(
            success=False,
            **values,
            message="Explicit client confirmation is required; no route change was run.",
        )
    target, error = _resolve_target(action, destination, gateway, interface, table, metric)
    if error or target is None:
        return NetworkRouteActionResponse(
            success=False,
            **values,
            user_confirmed=True,
            message=error or "The exact route could not be revalidated; no route change was run.",
        )
    spec = target.spec
    response_values = {
        "action": spec.action,
        "family": spec.family,
        "destination": spec.destination,
        "gateway": spec.gateway,
        "interface": spec.interface,
        "interface_index": spec.interface_snapshot.index,
        "table": spec.table,
        "metric": spec.metric,
        "preferred_source": target.existing_route.preferred_source if target.existing_route else None,
    }
    if expected_interface_index != spec.interface_snapshot.index:
        return NetworkRouteActionResponse(
            success=False,
            **response_values,
            user_confirmed=True,
            message="The interface index no longer matches the one shown for confirmation; no route change was run. List interfaces again.",
        )
    current_interface, error = capture_interface(spec.interface)
    if error or current_interface != spec.interface_snapshot:
        return NetworkRouteActionResponse(
            success=False,
            **response_values,
            user_confirmed=True,
            message="The interface identity or state changed after confirmation; no route change was run. List interfaces again.",
        )
    command_data = _command_for_target(target)
    if command_data is None:
        return NetworkRouteActionResponse(
            success=False,
            **response_values,
            user_confirmed=True,
            message="The iproute2 command became unavailable before the route change could run.",
        )
    _ip_binary, command = command_data
    env = get_sanitized_env(dict(os.environ))
    _output, error, truncated = run_bounded_command(
        command,
        env,
        command_label="iproute2 route control",
        timeout_seconds=ROUTE_ACTION_TIMEOUT_SECONDS,
        max_output_bytes=16 * 1024,
    )
    if error or truncated:
        message = (
            "The route command timed out; it may have changed routing state. Inspect list_network_policy before retrying."
            if error and "timed out" in error.casefold()
            else "iproute2 rejected the route change or its response was incomplete; inspect list_network_policy before retrying."
        )
        return NetworkRouteActionResponse(
            success=False,
            **response_values,
            user_confirmed=True,
            message=message,
        )

    updated_interface, interface_error = capture_interface(spec.interface)
    if interface_error or updated_interface is None or updated_interface != spec.interface_snapshot:
        return NetworkRouteActionResponse(
            success=False,
            **response_values,
            user_confirmed=True,
            message="The route command completed, but the interface changed; inspect list_network_policy before retrying.",
        )
    updated_routes, read_error = _read_exact_routes(spec)
    if read_error or updated_routes is None:
        return NetworkRouteActionResponse(
            success=False,
            **response_values,
            user_confirmed=True,
            message="The route command completed, but current routing state could not be verified; inspect list_network_policy.",
        )
    static_matches = [
        entry for entry in updated_routes
        if _route_matches_spec(entry, spec)
        and entry.protocol in {"static", 4, "4"}
        and entry.route_type == "unicast"
    ]
    expected = len(static_matches) == 1 if spec.action == "add" else not static_matches
    if not expected:
        return NetworkRouteActionResponse(
            success=False,
            **response_values,
            user_confirmed=True,
            message="The command completed, but the exact static route is not in the requested state; inspect list_network_policy.",
        )
    action_word = "Added" if spec.action == "add" else "Removed"
    return NetworkRouteActionResponse(
        success=True,
        **response_values,
        user_confirmed=True,
        message=(
            f"{action_word} and verified the exact static route in table {spec.table} in the current network namespace. "
            "This route change is temporary and is not persisted across reboot."
        ),
    )
