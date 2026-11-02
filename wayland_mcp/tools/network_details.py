"""Bounded read-only address and policy-routing inventory via iproute2 JSON."""

from __future__ import annotations

import ipaddress
import json
import math
import sys
from typing import Any, Literal

from wayland_mcp.models import (
    NetworkAddressDetail,
    NetworkAddressListResponse,
    NetworkPolicyRoute,
    NetworkPolicyRule,
    NetworkPolicySnapshotResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_IP_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_IP_ROWS = 20_000
MAX_ADDRESS_RESULTS = 500
MAX_POLICY_RESULTS = 500
COMMAND_TIMEOUT_SECONDS = 5

AddressFamily = Literal["all", "ipv4", "ipv6"]


def _safe_text(value: object, max_length: int = 512) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(character for character in value if ord(character) >= 32 and ord(character) != 127)
    return cleaned[:max_length]


def _safe_json_value(value: object, depth: int = 0) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _safe_text(value, 512)
    if depth >= 3:
        return None
    if isinstance(value, list):
        return [_safe_json_value(item, depth + 1) for item in value[:32]]
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in list(value.items())[:64]:
            safe_key = _safe_text(key, 64)
            if safe_key:
                cleaned[safe_key] = _safe_json_value(item, depth + 1)
        return cleaned
    return None


def _json_array(output: str, *, label: str) -> tuple[list[dict[str, Any]] | None, str | None, bool]:
    try:
        value = json.loads(output, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
    except (json.JSONDecodeError, ValueError):
        return None, f"{label} returned invalid JSON.", True
    if not isinstance(value, list):
        return None, f"{label} returned an unexpected JSON shape.", True
    rows = [item for item in value[:MAX_IP_ROWS] if isinstance(item, dict)]
    truncated = len(value) > MAX_IP_ROWS
    return rows, (f"{label} exceeded the {MAX_IP_ROWS}-row scan limit." if truncated else None), truncated


def _run_ip_json(
    ip_binary: str,
    env: dict[str, str],
    arguments: list[str],
    *,
    label: str,
) -> tuple[list[dict[str, Any]] | None, str | None, bool]:
    output, error, output_truncated = run_bounded_command(
        [ip_binary, "-j", *arguments],
        env,
        command_label=label,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_IP_OUTPUT_BYTES,
    )
    if output is None:
        return None, error or f"{label} could not be read.", output_truncated
    if output_truncated:
        return None, f"{label} exceeded the {MAX_IP_OUTPUT_BYTES}-byte output limit.", True
    rows, parse_error, row_truncated = _json_array(output, label=label)
    return rows, parse_error, row_truncated


def _lifetime(value: object) -> str | int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, str) and value.casefold() == "forever":
        return "forever"
    return None


def list_network_addresses(
    query: str = "",
    limit: int = 256,
) -> NetworkAddressListResponse:
    """List all visible IPv4/IPv6 addresses, including secondary addresses."""
    if not sys.platform.startswith("linux"):
        return NetworkAddressListResponse(success=False, message="Address inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return NetworkAddressListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return NetworkAddressListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return NetworkAddressListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_ADDRESS_RESULTS))
    env = get_sanitized_env()
    ip_binary = find_session_binary("ip", env)
    if not ip_binary:
        return NetworkAddressListResponse(success=False, limit=limit, message="The iproute2 'ip' command is unavailable.")

    raw_interfaces, error, command_truncated = _run_ip_json(
        ip_binary,
        env,
        ["address", "show"],
        label="ip address inventory",
    )
    if raw_interfaces is None:
        return NetworkAddressListResponse(
            success=False,
            limit=limit,
            truncated=command_truncated,
            message=error or "Could not read network addresses.",
        )

    query_key = query.strip().casefold()
    addresses: list[NetworkAddressDetail] = []
    malformed_rows = 0
    nested_scan_truncated = False
    for interface_record in raw_interfaces:
        interface = _safe_text(interface_record.get("ifname"), 64)
        if not interface:
            malformed_rows += 1
            continue
        index = interface_record.get("ifindex")
        index = index if isinstance(index, int) and not isinstance(index, bool) and index > 0 else None
        entries = interface_record.get("addr_info", [])
        if not isinstance(entries, list):
            malformed_rows += 1
            continue
        nested_scan_truncated = nested_scan_truncated or len(entries) > MAX_IP_ROWS
        for entry in entries[:MAX_IP_ROWS]:
            if not isinstance(entry, dict):
                malformed_rows += 1
                continue
            family_value = entry.get("family")
            family = "ipv4" if family_value == "inet" else "ipv6" if family_value == "inet6" else None
            raw_address = entry.get("local")
            if not family or not isinstance(raw_address, str):
                malformed_rows += 1
                continue
            try:
                parsed_address = ipaddress.ip_address(raw_address)
            except ValueError:
                malformed_rows += 1
                continue
            if parsed_address.version != (4 if family == "ipv4" else 6):
                malformed_rows += 1
                continue
            prefix = entry.get("prefixlen")
            max_prefix = 32 if family == "ipv4" else 128
            if not isinstance(prefix, int) or isinstance(prefix, bool) or not 0 <= prefix <= max_prefix:
                malformed_rows += 1
                continue
            scope = _safe_text(entry.get("scope"), 64)
            label = _safe_text(entry.get("label"), 64)
            raw_flags = entry.get("flags", [])
            flags = (
                [safe for flag in raw_flags if (safe := _safe_text(flag, 64))]
                if isinstance(raw_flags, list) else []
            )
            address = NetworkAddressDetail(
                interface=interface,
                interface_index=index,
                family=family,
                address=str(parsed_address),
                prefix_length=prefix,
                peer_address=_safe_text(entry.get("peer"), 128),
                broadcast_address=_safe_text(entry.get("broadcast"), 128),
                anycast_address=_safe_text(entry.get("anycast"), 128),
                scope=scope,
                label=label,
                protocol=_safe_text(entry.get("protocol"), 64),
                flags=flags,
                preferred_lifetime=_lifetime(entry.get("preferred_life_time")),
                valid_lifetime=_lifetime(entry.get("valid_life_time")),
            )
            searchable = " ".join((interface, family, address.address, scope or "", label or "", *flags)).casefold()
            if not query_key or query_key in searchable:
                addresses.append(address)

    addresses.sort(key=lambda item: (item.interface, item.family, item.address, item.prefix_length))
    truncated = command_truncated or nested_scan_truncated or malformed_rows > 0 or len(addresses) > limit
    message_parts = ["Addresses are read from the current network namespace; this tool is read-only."]
    if error:
        message_parts.append(error)
    if malformed_rows:
        message_parts.append(f"{malformed_rows} malformed address records were skipped.")
    if nested_scan_truncated:
        message_parts.append(f"An interface address scan was capped at {MAX_IP_ROWS} entries.")
    if len(raw_interfaces) >= MAX_IP_ROWS:
        truncated = True
        message_parts.append(f"Interface scan capped at {MAX_IP_ROWS} entries.")
    if truncated and len(addresses) > limit:
        message_parts.append(f"Address results capped at {limit} entries.")
    return NetworkAddressListResponse(
        success=True,
        total_addresses=len(addresses),
        returned_addresses=min(len(addresses), limit),
        addresses=addresses[:limit],
        limit=limit,
        truncated=truncated,
        message=" ".join(message_parts),
    )


def _integer(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value, 10)
        except ValueError:
            return None
    return None


def _number_or_text(value: object) -> str | int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return _safe_text(value, 256)


def _network_policy_rule(raw: dict[str, Any], family: str) -> NetworkPolicyRule:
    known = {
        "priority", "pref", "src", "from", "dst", "to", "table", "action", "type",
        "fwmark", "iif", "iifname", "oif", "oifname", "uidrange", "ipproto",
        "sport", "dport", "protocol", "family",
    }
    return NetworkPolicyRule(
        family=family,
        priority=_integer(raw.get("priority", raw.get("pref"))),
        source=_safe_text(raw.get("src", raw.get("from")), 256),
        destination=_safe_text(raw.get("dst", raw.get("to")), 256),
        table=_number_or_text(raw.get("table")),
        action=_safe_text(raw.get("action", raw.get("type")), 64),
        firewall_mark=_number_or_text(raw.get("fwmark")),
        incoming_interface=_safe_text(raw.get("iifname", raw.get("iif")), 64),
        outgoing_interface=_safe_text(raw.get("oifname", raw.get("oif")), 64),
        uid_range=_safe_text(raw.get("uidrange"), 128),
        ip_protocol=_number_or_text(raw.get("ipproto")),
        source_port=_number_or_text(raw.get("sport")),
        destination_port=_number_or_text(raw.get("dport")),
        protocol=_number_or_text(raw.get("protocol")),
        attributes={
            safe_key: _safe_json_value(value)
            for key, value in raw.items()
            if key not in known and (safe_key := _safe_text(key, 64))
        },
    )


def _network_policy_route(raw: dict[str, Any], family: str) -> NetworkPolicyRoute:
    known = {
        "dst", "gateway", "via", "dev", "table", "type", "scope", "metric",
        "protocol", "proto", "prefsrc", "src",
    }
    via = raw.get("via") or raw.get("gateway")
    gateway_family = None
    if isinstance(via, dict):
        gateway_family = _safe_text(via.get("family"), 32)
        via = via.get("host")
    return NetworkPolicyRoute(
        family=family,
        destination=_safe_text(raw.get("dst"), 256) or "default",
        gateway=_safe_text(via, 128),
        gateway_family=gateway_family,
        interface=_safe_text(raw.get("dev"), 64),
        table=_number_or_text(raw.get("table")),
        route_type=_safe_text(raw.get("type"), 64),
        scope=_safe_text(raw.get("scope"), 64),
        metric=_integer(raw.get("metric")),
        protocol=_number_or_text(raw.get("protocol", raw.get("proto"))),
        preferred_source=_safe_text(raw.get("prefsrc", raw.get("src")), 128),
        attributes={
            safe_key: _safe_json_value(value)
            for key, value in raw.items()
            if key not in known and (safe_key := _safe_text(key, 64))
        },
    )


def list_network_policy(
    family: AddressFamily = "all",
    limit: int = 200,
) -> NetworkPolicySnapshotResponse:
    """Read IPv4/IPv6 policy rules and routes from every table in this namespace."""
    if not sys.platform.startswith("linux"):
        safe_family = family if isinstance(family, str) and family in {"all", "ipv4", "ipv6"} else "all"
        return NetworkPolicySnapshotResponse(success=False, family=safe_family, message="Policy routing inventory is available only on Linux.")
    if not isinstance(family, str) or family not in {"all", "ipv4", "ipv6"}:
        return NetworkPolicySnapshotResponse(success=False, message="family must be 'all', 'ipv4', or 'ipv6'.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return NetworkPolicySnapshotResponse(success=False, family=family, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_POLICY_RESULTS))
    env = get_sanitized_env()
    ip_binary = find_session_binary("ip", env)
    if not ip_binary:
        return NetworkPolicySnapshotResponse(success=False, family=family, limit=limit, message="The iproute2 'ip' command is unavailable.")

    families = [("ipv4", "-4"), ("ipv6", "-6")]
    if family != "all":
        families = [item for item in families if item[0] == family]
    rules: list[NetworkPolicyRule] = []
    routes: list[NetworkPolicyRoute] = []
    errors: list[str] = []
    truncated = False
    any_command_succeeded = False

    for family_name, option in families:
        raw_rules, rule_error, rule_truncated = _run_ip_json(
            ip_binary,
            env,
            [option, "rule", "show"],
            label=f"ip {family_name} rule inventory",
        )
        truncated = truncated or rule_truncated
        if raw_rules is None:
            if rule_error:
                errors.append(rule_error)
        else:
            any_command_succeeded = True
            rules.extend(_network_policy_rule(row, family_name) for row in raw_rules)
            if rule_error:
                errors.append(rule_error)

        raw_routes, route_error, route_truncated = _run_ip_json(
            ip_binary,
            env,
            [option, "route", "show", "table", "all"],
            label=f"ip {family_name} all-table route inventory",
        )
        truncated = truncated or route_truncated
        if raw_routes is None:
            if route_error:
                errors.append(route_error)
        else:
            any_command_succeeded = True
            routes.extend(_network_policy_route(row, family_name) for row in raw_routes)
            if route_error:
                errors.append(route_error)

    rules.sort(key=lambda item: (item.family, item.priority if item.priority is not None else 2**32, str(item.table or "")))
    routes.sort(key=lambda item: (item.family, str(item.table or ""), item.destination, item.metric or 0, item.interface or ""))
    total_rules = len(rules)
    total_routes = len(routes)
    truncated = truncated or bool(errors) or total_rules > limit or total_routes > limit
    message_parts = ["Policy rules and all-table route snapshots use fixed, read-only iproute2 queries in the current network namespace."]
    if errors:
        message_parts.append("Some inventory was incomplete: " + " ".join(errors))
    if total_rules > limit or total_routes > limit:
        message_parts.append(f"Rule and route results are each capped at {limit} entries.")
    if not any_command_succeeded:
        return NetworkPolicySnapshotResponse(
            success=False,
            family=family,
            limit=limit,
            truncated=truncated,
            message=" ".join(message_parts),
        )
    return NetworkPolicySnapshotResponse(
        success=True,
        family=family,
        total_rules=total_rules,
        returned_rules=min(total_rules, limit),
        rules=rules[:limit],
        total_routes=total_routes,
        returned_routes=min(total_routes, limit),
        routes=routes[:limit],
        limit=limit,
        truncated=truncated,
        message=" ".join(message_parts),
    )
