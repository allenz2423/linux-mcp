"""Bounded read-only route selection for one literal IP destination."""

from __future__ import annotations

import ipaddress
import json
import sys
from typing import Any

from wayland_mcp.models import NetworkRouteLookupResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_OUTPUT_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 5


def _safe_text(value: object, max_length: int = 128) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(character for character in value if ord(character) >= 32 and ord(character) != 127)
    return cleaned[:max_length] or None


def _integer(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value if 0 <= value <= 0xFFFFFFFF else None
    if isinstance(value, str) and value.isdecimal():
        try:
            parsed = int(value, 10)
        except ValueError:
            return None
        return parsed if parsed <= 0xFFFFFFFF else None
    return None


def _number_or_text(value: object) -> str | int | None:
    number = _integer(value)
    if number is not None:
        return number
    return _safe_text(value, 64)


def lookup_network_route(destination: str) -> NetworkRouteLookupResponse:
    """Return the kernel-selected local route for one literal IP address."""
    if not sys.platform.startswith("linux"):
        return NetworkRouteLookupResponse(success=False, message="Route lookup is available only on Linux.")
    if not isinstance(destination, str) or len(destination) > 64:
        return NetworkRouteLookupResponse(success=False, message="Destination must be one literal IP address of at most 64 characters.")
    if any(ord(character) < 33 or ord(character) == 127 for character in destination):
        return NetworkRouteLookupResponse(success=False, message="Destination cannot contain whitespace or control characters.")
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        return NetworkRouteLookupResponse(success=False, message="Destination must be a literal IPv4 or IPv6 address; hostnames and prefixes are not accepted.")
    if getattr(address, "scope_id", None) is not None:
        return NetworkRouteLookupResponse(success=False, message="Scoped IPv6 destinations are not supported.")

    family = "ipv4" if address.version == 4 else "ipv6"
    canonical_destination = str(address)
    env = get_sanitized_env()
    ip_binary = find_session_binary("ip", env)
    if not ip_binary:
        return NetworkRouteLookupResponse(
            success=False,
            family=family,
            destination=canonical_destination,
            message="The iproute2 'ip' command is unavailable.",
        )

    output, error, truncated = run_bounded_command(
        [ip_binary, "-j", "-4" if address.version == 4 else "-6", "route", "get", canonical_destination],
        env,
        command_label="ip route lookup",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if output is None:
        return NetworkRouteLookupResponse(
            success=False,
            family=family,
            destination=canonical_destination,
            truncated=truncated,
            message=error or "Could not look up the selected route.",
        )
    if truncated:
        return NetworkRouteLookupResponse(
            success=False,
            family=family,
            destination=canonical_destination,
            truncated=True,
            message=f"The route lookup exceeded the {MAX_OUTPUT_BYTES}-byte output limit.",
        )

    try:
        rows: Any = json.loads(output, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
    except (json.JSONDecodeError, ValueError):
        return NetworkRouteLookupResponse(
            success=False,
            family=family,
            destination=canonical_destination,
            truncated=True,
            message="The iproute2 route lookup returned invalid JSON.",
        )
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return NetworkRouteLookupResponse(
            success=False,
            family=family,
            destination=canonical_destination,
            truncated=True,
            message="The iproute2 route lookup returned an unexpected result shape.",
        )

    row = rows[0]
    via = row.get("via") or row.get("gateway")
    if isinstance(via, dict):
        via = via.get("host")
    return NetworkRouteLookupResponse(
        success=True,
        family=family,
        destination=canonical_destination,
        source=_safe_text(row.get("src"), 128),
        preferred_source=_safe_text(row.get("prefsrc"), 128),
        gateway=_safe_text(via, 128),
        device=_safe_text(row.get("dev"), 64),
        table=_number_or_text(row.get("table")),
        metric=_integer(row.get("metric")),
        protocol=_number_or_text(row.get("protocol", row.get("proto"))),
        route_type=_safe_text(row.get("type"), 64),
        scope=_safe_text(row.get("scope"), 64),
        message=(
            "Kernel route selection for locally originated traffic in the current network namespace; "
            "the lookup sends no packets. It does not model an incoming interface, firewall mark, "
            "protocol, or port."
        ),
    )
