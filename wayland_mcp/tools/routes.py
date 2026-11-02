"""Bounded IPv4/IPv6 routing-table inventory from Linux procfs."""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

from wayland_mcp.models import NetworkRouteInfo, NetworkRouteListResponse

PROC_NET = Path("/proc/net")
MAX_ROUTE_TABLE_BYTES = 2 * 1024 * 1024
MAX_ROUTE_TABLE_ROWS = 20_000
MAX_ROUTE_LINE_BYTES = 4096
MAX_ROUTE_RESULTS = 20_000
MAX_RETURNED_ROUTES = 200


def _read_route_table(path: Path) -> tuple[list[str], bool, str | None]:
    lines: list[str] = []
    bytes_read = 0
    truncated = False
    try:
        with path.open("rb") as stream:
            for _ in range(MAX_ROUTE_TABLE_ROWS):
                remaining = MAX_ROUTE_TABLE_BYTES - bytes_read
                if remaining <= 0:
                    truncated = bool(stream.read(1))
                    break
                raw_line = stream.readline(min(MAX_ROUTE_LINE_BYTES + 1, remaining + 1))
                if not raw_line:
                    break
                if len(raw_line) > remaining or len(raw_line) > MAX_ROUTE_LINE_BYTES:
                    truncated = True
                    break
                bytes_read += len(raw_line)
                lines.append(raw_line.decode("ascii", errors="replace"))
            if bytes_read == MAX_ROUTE_TABLE_BYTES:
                truncated = truncated or bool(stream.read(1))
            if len(lines) == MAX_ROUTE_TABLE_ROWS and stream.read(1):
                truncated = True
    except FileNotFoundError:
        return [], False, "missing"
    except OSError as exc:
        return [], False, exc.strerror or "read error"
    return lines, truncated, None


def _ipv4_address(raw_hex: str) -> str | None:
    try:
        if len(raw_hex) != 8:
            return None
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(raw_hex, 16)))
    except (ValueError, OSError, struct.error):
        return None


def _ipv6_address(raw_hex: str) -> str | None:
    try:
        packed = bytes.fromhex(raw_hex)
        if len(packed) != 16:
            return None
        return socket.inet_ntop(socket.AF_INET6, packed)
    except (ValueError, OSError):
        return None


def _prefix_from_mask(mask_hex: str) -> int | None:
    try:
        mask = struct.pack("<I", int(mask_hex, 16))
    except (ValueError, struct.error):
        return None
    bits = "".join(f"{value:08b}" for value in mask)
    if "01" in bits:
        return None
    return bits.count("1")


def _parse_ipv4_routes(lines: list[str]) -> list[NetworkRouteInfo]:
    routes: list[NetworkRouteInfo] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 8 or fields[0].casefold() == "iface":
            continue
        destination = _ipv4_address(fields[1])
        gateway = _ipv4_address(fields[2])
        prefix = _prefix_from_mask(fields[7])
        if destination is None or gateway is None or prefix is None:
            continue
        try:
            flags = int(fields[3], 16)
            metric = int(fields[6], 10)
        except ValueError:
            continue
        routes.append(NetworkRouteInfo(
            family="ipv4",
            destination=destination,
            prefix_length=prefix,
            gateway=None if gateway == "0.0.0.0" else gateway,
            interface=fields[0][:64],
            metric=max(0, metric),
            flags=flags,
        ))
    return routes


def _parse_ipv6_routes(lines: list[str]) -> list[NetworkRouteInfo]:
    routes: list[NetworkRouteInfo] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 10:
            continue
        destination = _ipv6_address(fields[0])
        source = _ipv6_address(fields[2])
        gateway = _ipv6_address(fields[4])
        try:
            prefix = int(fields[1], 16)
            source_prefix = int(fields[3], 16)
            metric = int(fields[5], 16)
            flags = int(fields[8], 16)
        except ValueError:
            continue
        if destination is None or source is None or gateway is None or prefix > 128 or source_prefix > 128:
            continue
        routes.append(NetworkRouteInfo(
            family="ipv6",
            destination=destination,
            prefix_length=prefix,
            gateway=None if gateway == "::" else gateway,
            interface=fields[9][:64],
            metric=metric,
            flags=flags,
            source=source,
            source_prefix_length=source_prefix,
        ))
    return routes


def list_network_routes(query: str = "", limit: int = 100) -> NetworkRouteListResponse:
    if not sys.platform.startswith("linux"):
        return NetworkRouteListResponse(success=False, message="Route inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return NetworkRouteListResponse(success=False, message="Query must be text with at most 256 characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return NetworkRouteListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_ROUTES))
    needle = query.strip().casefold()

    routes: list[NetworkRouteInfo] = []
    available_tables = 0
    missing_tables = 0
    errors: list[str] = []
    truncated = False
    for filename, parser in (("route", _parse_ipv4_routes), ("ipv6_route", _parse_ipv6_routes)):
        lines, table_truncated, error = _read_route_table(PROC_NET / filename)
        truncated = truncated or table_truncated
        if error:
            if error == "missing":
                missing_tables += 1
            else:
                errors.append(f"{filename}: {error}")
            continue
        available_tables += 1
        for route in parser(lines):
            searchable = " ".join((
                route.family,
                route.destination,
                str(route.prefix_length),
                route.gateway or "",
                route.interface,
                str(route.metric),
                route.source or "",
                str(route.source_prefix_length or ""),
            )).casefold()
            if not needle or needle in searchable:
                routes.append(route)
            if len(routes) >= MAX_ROUTE_RESULTS:
                truncated = True
                break
        if len(routes) >= MAX_ROUTE_RESULTS:
            break

    if available_tables == 0:
        detail = "; ".join(errors) if errors else "No IPv4 or IPv6 procfs route tables were found."
        return NetworkRouteListResponse(success=False, limit=limit, message=f"Could not read Linux route inventory: {detail}")
    routes.sort(key=lambda item: (item.family, item.destination, item.prefix_length, item.metric, item.interface))
    message = "Kernel route-table snapshot from the current network namespace; policy rules, every routing table, and destination-specific route selection are reported by separate tools."
    if errors:
        message += " Some procfs route tables could not be read."
    if missing_tables:
        message += " Some address-family route tables are absent or disabled."
    if truncated:
        message += " The route scan reached its byte, line, or result limit."
    return NetworkRouteListResponse(
        success=True,
        total_routes=len(routes),
        returned_routes=min(len(routes), limit),
        routes=routes[:limit],
        limit=limit,
        truncated=truncated or len(routes) > limit,
        message=message,
    )
