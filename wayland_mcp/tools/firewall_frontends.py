"""Read-only status and selected policy inventory for firewalld and UFW."""

from __future__ import annotations

import re
import sys
from typing import Literal

from wayland_mcp.models import (
    FirewalldZoneInfo,
    FirewallFrontendInventoryResponse,
    FirewallFrontendSourceStatus,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

FirewallFrontend = Literal["firewalld", "ufw"]
FIREWALL_FRONTEND_COMMANDS: dict[FirewallFrontend, str] = {
    "firewalld": "firewall-cmd",
    "ufw": "ufw",
}
ZONE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DEFAULT_POLICY_RE = re.compile(r"\b(allow|deny|reject|disabled)\s+\((incoming|outgoing|routed)\)", re.IGNORECASE)
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_COMMAND_SECONDS = 3
MAX_SCAN_LINES = 20_000
MAX_ZONES = 256
MAX_ZONE_PROPERTIES = 64
MAX_PROPERTY_VALUES = 64
MAX_VALUE_LENGTH = 1024
MAX_UFW_RULES = 1_000
MAX_RESULTS = 200


def detect_firewall_frontends(env: dict[str, str] | None = None) -> dict[FirewallFrontend, str | None]:
    """Locate optional frontend clients using the sanitized child environment."""
    child_env = env if env is not None else get_sanitized_env()
    return {
        frontend: find_session_binary(command, child_env)
        for frontend, command in FIREWALL_FRONTEND_COMMANDS.items()
    }


def _run(
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
        timeout_seconds=MAX_COMMAND_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
        accept_nonzero_exit=accept_nonzero_exit,
    )


def _clean(value: str, limit: int = MAX_VALUE_LENGTH) -> tuple[str, bool]:
    cleaned = "".join(
        " " if character == "\t" else character
        for character in value
        if character == "\t" or character.isprintable()
    ).strip()
    return cleaned[:limit], len(cleaned) > limit


def _zone_name(value: str) -> str | None:
    candidate = value.strip().split(maxsplit=1)[0] if value.strip() else ""
    if candidate.endswith(":"):
        candidate = candidate[:-1]
    if ZONE_NAME_RE.fullmatch(candidate):
        return candidate
    return None


def _parse_active_zones(output: str) -> tuple[set[str], int, bool]:
    active: set[str] = set()
    malformed = 0
    truncated = False
    lines = output.splitlines()
    if len(lines) > MAX_SCAN_LINES:
        lines = lines[:MAX_SCAN_LINES]
        truncated = True
    current: str | None = None
    for line in lines:
        if len(line) > MAX_VALUE_LENGTH:
            truncated = True
            continue
        if line and not line[0].isspace():
            current = _zone_name(line)
            if current is None:
                malformed += 1
            elif len(active) < MAX_ZONES:
                active.add(current)
            else:
                truncated = True
    return active, malformed, truncated


def _parse_zone_inventory(
    output: str,
    *,
    default_zone: str | None,
    active_zones: set[str],
) -> tuple[list[FirewalldZoneInfo], int, bool]:
    mutable_zones: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    pending_list_property: str | None = None
    malformed = 0
    truncated = False
    lines = output.splitlines()
    if len(lines) > MAX_SCAN_LINES:
        lines = lines[:MAX_SCAN_LINES]
        truncated = True

    for line in lines:
        if not line:
            continue
        if len(line) > MAX_VALUE_LENGTH * 4:
            truncated = True
            continue
        indentation = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indentation == 0:
            zone_name = _zone_name(stripped)
            if zone_name is None:
                current = None
                malformed += 1
                continue
            if len(mutable_zones) >= MAX_ZONES:
                truncated = True
                current = None
                continue
            current = {"name": zone_name, "properties": {}}
            mutable_zones.append(current)
            pending_list_property = None
            continue
        if current is None:
            malformed += 1
            continue
        properties = current["properties"]
        if not isinstance(properties, dict):
            malformed += 1
            continue
        if indentation >= 4 and pending_list_property:
            value, clipped = _clean(stripped)
            truncated = truncated or clipped
            if value:
                property_values = properties.setdefault(pending_list_property, [])
                if len(property_values) < MAX_PROPERTY_VALUES:
                    property_values.append(value)
                else:
                    truncated = True
            continue
        if ":" not in stripped:
            pending_list_property = None
            malformed += 1
            continue
        key, raw_value = stripped.split(":", 1)
        key, key_clipped = _clean(key, 64)
        raw_value, value_clipped = _clean(raw_value)
        if not key or not re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]{0,63}", key):
            pending_list_property = None
            malformed += 1
            continue
        truncated = truncated or key_clipped or value_clipped
        if key not in properties and len(properties) >= MAX_ZONE_PROPERTIES:
            truncated = True
            pending_list_property = None
            continue
        values = properties.setdefault(key, [])
        if raw_value:
            items = [raw_value] if key.casefold() == "rich rules" else raw_value.split()
            for item in items[:MAX_PROPERTY_VALUES]:
                item, item_clipped = _clean(item)
                truncated = truncated or item_clipped
                if item and len(values) < MAX_PROPERTY_VALUES:
                    values.append(item)
                elif item:
                    truncated = True
            if len(items) > MAX_PROPERTY_VALUES:
                truncated = True
        pending_list_property = key if key.casefold() in {"rich rules", "forward-ports"} else None

    zones: list[FirewalldZoneInfo] = []
    for entry in mutable_zones:
        name = entry["name"]
        raw_properties = entry["properties"]
        if not isinstance(name, str) or not isinstance(raw_properties, dict):
            malformed += 1
            continue
        properties = {
            key: list(values[:MAX_PROPERTY_VALUES])
            for key, values in raw_properties.items()
            if isinstance(key, str) and isinstance(values, list)
        }
        zones.append(FirewalldZoneInfo(
            name=name,
            is_default=name == default_zone,
            is_active=name in active_zones,
            properties=properties,
        ))
    known_names = {zone.name for zone in zones}
    for name in sorted(active_zones - known_names):
        zones.append(FirewalldZoneInfo(
            name=name,
            is_default=name == default_zone,
            is_active=True,
        ))
    if default_zone and default_zone not in known_names:
        zones.append(FirewalldZoneInfo(
            name=default_zone,
            is_default=True,
            is_active=default_zone in active_zones,
        ))
    zones.sort(key=lambda zone: zone.name.casefold())
    return zones, malformed, truncated


def _firewalld_status(
    binary: str | None,
    env: dict[str, str],
    *,
    query: str,
    limit: int,
) -> FirewallFrontendSourceStatus:
    if not binary:
        return FirewallFrontendSourceStatus(
            frontend="firewalld",
            available=False,
            success=False,
            message="The firewall-cmd command is unavailable.",
        )

    state_output, state_error, state_truncated = _run(
        binary,
        ["--state"],
        env,
        label="firewalld state query",
        accept_nonzero_exit=True,
    )
    if state_output is None:
        return FirewallFrontendSourceStatus(
            frontend="firewalld",
            available=True,
            success=False,
            truncated=state_truncated,
            message=state_error or "firewalld state could not be read.",
        )
    state_value = state_output.strip().casefold()
    if state_value == "not running":
        return FirewallFrontendSourceStatus(
            frontend="firewalld",
            available=True,
            success=True,
            active=False,
            message="firewalld is installed but not running; runtime zones are unavailable.",
        )
    if state_value != "running":
        return FirewallFrontendSourceStatus(
            frontend="firewalld",
            available=True,
            success=False,
            truncated=state_truncated,
            message="firewalld returned an unrecognized state response.",
        )

    default_output, default_error, default_truncated = _run(
        binary, ["--get-default-zone"], env, label="firewalld default-zone query",
    )
    active_output, active_error, active_truncated = _run(
        binary, ["--get-active-zones"], env, label="firewalld active-zone query",
    )
    zones_output, zones_error, zones_truncated = _run(
        binary, ["--list-all-zones"], env, label="firewalld runtime-zone inventory",
    )
    default_zone = _zone_name(default_output) if default_output is not None else None
    active_zones: set[str] = set()
    malformed = 0
    parse_truncated = False
    if active_output is not None:
        active_zones, bad_active, active_scan_truncated = _parse_active_zones(active_output)
        malformed += bad_active
        parse_truncated = parse_truncated or active_scan_truncated
    zones: list[FirewalldZoneInfo] = []
    if zones_output is not None:
        zones, bad_zones, zones_scan_truncated = _parse_zone_inventory(
            zones_output,
            default_zone=default_zone,
            active_zones=active_zones,
        )
        malformed += bad_zones
        parse_truncated = parse_truncated or zones_scan_truncated

    needle = query.strip().casefold()
    if needle:
        zones = [
            zone for zone in zones
            if needle in zone.name.casefold()
            or any(needle in value.casefold() for values in zone.properties.values() for value in values)
        ]
        active_zones = {zone.name for zone in zones if zone.is_active}
    total_zones = len(zones)
    zones = zones[:limit]
    truncated = state_truncated or default_truncated or active_truncated or zones_truncated or parse_truncated or len(zones) < total_zones
    errors = [error for error in (default_error, active_error, zones_error) if error]
    successful_queries = sum(output is not None for output in (default_output, active_output, zones_output))
    success = successful_queries > 0
    source_partial = (
        successful_queries < 3
        or malformed > 0
        or parse_truncated
        or default_truncated
        or active_truncated
        or zones_truncated
    )
    return FirewallFrontendSourceStatus(
        frontend="firewalld",
        available=True,
        success=success,
        partial=source_partial,
        active=True,
        default_zone=default_zone,
        active_zones=sorted(active_zones, key=str.casefold)[:limit],
        total_zones=total_zones,
        returned_zones=len(zones),
        zones=zones,
        malformed_records=malformed,
        truncated=truncated,
        message=" ".join(errors) if errors else None,
    )


def _ufw_status(
    binary: str | None,
    env: dict[str, str],
    *,
    query: str,
    limit: int,
) -> FirewallFrontendSourceStatus:
    if not binary:
        return FirewallFrontendSourceStatus(
            frontend="ufw",
            available=False,
            success=False,
            message="The ufw command is unavailable.",
        )
    output, error, output_truncated = _run(
        binary,
        ["status", "verbose"],
        env,
        label="UFW status inventory",
    )
    if output is None:
        return FirewallFrontendSourceStatus(
            frontend="ufw",
            available=True,
            success=False,
            truncated=output_truncated,
            message=error or "UFW status could not be read.",
        )

    lines = output.splitlines()
    truncated = output_truncated or len(lines) > MAX_SCAN_LINES
    lines = lines[:MAX_SCAN_LINES]
    active: bool | None = None
    logging: str | None = None
    default_policies: dict[str, str] = {}
    rules: list[str] = []
    malformed = 0
    in_rules = False
    for raw_line in lines:
        line, clipped = _clean(raw_line)
        truncated = truncated or clipped
        if not line:
            continue
        if not in_rules and line.casefold().startswith("status:"):
            state = line.split(":", 1)[1].strip().casefold()
            if state in {"active", "inactive"}:
                active = state == "active"
            else:
                malformed += 1
            continue
        if not in_rules and line.casefold().startswith("logging:"):
            logging = line.split(":", 1)[1].strip()[:128]
            continue
        if not in_rules and line.casefold().startswith("default:"):
            policy_values = DEFAULT_POLICY_RE.findall(line.split(":", 1)[1])
            for policy, direction in policy_values:
                default_policies[direction.casefold()] = policy.casefold()
            if not policy_values:
                malformed += 1
            continue
        tokens = re.split(r"\s+", line.casefold())
        if tokens and tokens[0] == "to" and "action" in tokens and "from" in tokens:
            in_rules = True
            continue
        if in_rules:
            if re.fullmatch(r"[-\s]+", line):
                continue
            if len(rules) < MAX_UFW_RULES:
                rules.append(line[:MAX_VALUE_LENGTH])
            else:
                truncated = True
            continue
    needle = query.strip().casefold()
    if needle:
        rules = [rule for rule in rules if needle in rule.casefold()]
    total_rules = len(rules)
    rules = rules[:limit]
    truncated = truncated or len(rules) < total_rules
    success = active is not None
    return FirewallFrontendSourceStatus(
        frontend="ufw",
        available=True,
        success=success,
        partial=malformed > 0 or output_truncated,
        active=active,
        logging=logging,
        default_policies=default_policies,
        total_rules=total_rules,
        returned_rules=len(rules),
        rules=rules,
        malformed_records=malformed,
        truncated=truncated,
        message=error or (None if success else "UFW returned an unrecognized status response."),
    )


def list_firewall_frontends(
    query: str = "",
    limit: int = 100,
) -> FirewallFrontendInventoryResponse:
    """Read current firewalld zones and UFW status without changing firewall state."""
    if not sys.platform.startswith("linux"):
        return FirewallFrontendInventoryResponse(
            success=False,
            message="Firewall frontend inventory is available only on Linux.",
        )
    if not isinstance(query, str) or len(query) > 256:
        return FirewallFrontendInventoryResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(not character.isprintable() for character in query):
        return FirewallFrontendInventoryResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return FirewallFrontendInventoryResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RESULTS))

    env = get_sanitized_env()
    env["LC_ALL"] = "C"
    commands = detect_firewall_frontends(env)
    firewalld = _firewalld_status(commands["firewalld"], env, query=query, limit=limit)
    ufw = _ufw_status(commands["ufw"], env, query=query, limit=limit)
    sources = [firewalld, ufw]
    available_sources = [source for source in sources if source.available]
    successful_sources = [source for source in sources if source.success]
    partial = (
        any(source.partial or (source.available and not source.success) for source in sources)
        or (bool(successful_sources) and len(available_sources) < len(sources))
    )
    truncated = any(source.truncated for source in sources)
    return FirewallFrontendInventoryResponse(
        success=bool(successful_sources),
        partial=partial,
        sources=sources,
        limit=limit,
        truncated=truncated,
        message=(
            "Runtime firewalld zone bindings and UFW status are read-only frontend snapshots; frontend availability and permissions vary by host."
            if successful_sources else "Neither firewalld nor UFW frontend state could be read."
        ),
    )
