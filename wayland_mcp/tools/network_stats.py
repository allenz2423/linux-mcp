"""Bounded Linux network protocol counters from current-namespace procfs."""

from __future__ import annotations

import sys
from pathlib import Path

from wayland_mcp.models import (
    NetworkProtocolCounterGroup,
    NetworkProtocolStatsResponse,
)

PROC_NET = Path("/proc/net")
MAX_TABLE_BYTES = 1024 * 1024
MAX_TABLE_ROWS = 4096
MAX_LINE_BYTES = 4096
MAX_COUNTERS_PER_GROUP = 512
MAX_RETURNED_GROUPS = 128
TABLES = ("snmp", "netstat", "snmp6")


def _read_table(name: str) -> tuple[list[str], bool, str | None]:
    path = PROC_NET / name
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_TABLE_BYTES + 1)
    except FileNotFoundError:
        return [], False, "missing"
    except OSError as exc:
        return [], False, exc.strerror or "read error"
    truncated = len(raw) > MAX_TABLE_BYTES
    text = raw[:MAX_TABLE_BYTES].decode("ascii", errors="replace")
    lines = text.splitlines()
    if len(lines) > MAX_TABLE_ROWS:
        lines = lines[:MAX_TABLE_ROWS]
        truncated = True
    if any(len(line) > MAX_LINE_BYTES for line in lines):
        truncated = True
        lines = [line if len(line) <= MAX_LINE_BYTES else "" for line in lines]
    return lines, truncated, None


def _counter_value(value: str) -> int | None:
    try:
        parsed = int(value, 10)
    except ValueError:
        return None
    # TCP MaxConn is the signed RFC 2012 counter and uses -1 for unlimited.
    return parsed if -(2**63) <= parsed <= 2**64 - 1 else None


def _parse_paired_table(
    source: str,
    lines: list[str],
) -> tuple[list[NetworkProtocolCounterGroup], int, bool]:
    groups: list[NetworkProtocolCounterGroup] = []
    malformed = 0
    truncated = False
    if len(lines) % 2:
        malformed += 1
        truncated = True
    for index in range(0, len(lines) - 1, 2):
        header = lines[index].split()
        values = lines[index + 1].split()
        if not header or not values or not header[0].endswith(":") or header[0] != values[0]:
            malformed += 1
            continue
        protocol = header[0][:-1]
        names = header[1:]
        raw_values = values[1:]
        if not names or len(names) != len(raw_values):
            malformed += 1
            truncated = True
            continue
        counters: dict[str, int] = {}
        for name, raw_value in zip(names, raw_values):
            value = _counter_value(raw_value)
            if value is None:
                malformed += 1
                continue
            if len(counters) >= MAX_COUNTERS_PER_GROUP:
                truncated = True
                break
            counters[name] = value
        if counters:
            groups.append(NetworkProtocolCounterGroup(
                source=source,
                protocol=protocol,
                counters=counters,
            ))
    return groups, malformed, truncated


def _parse_snmp6(lines: list[str]) -> tuple[list[NetworkProtocolCounterGroup], int, bool]:
    counters: dict[str, int] = {}
    malformed = 0
    truncated = False
    for line in lines:
        fields = line.split()
        if len(fields) != 2:
            malformed += 1
            continue
        value = _counter_value(fields[1])
        if value is None:
            malformed += 1
            continue
        if len(counters) >= MAX_COUNTERS_PER_GROUP:
            truncated = True
            break
        counters[fields[0]] = value
    if not counters:
        return [], malformed, truncated
    return [NetworkProtocolCounterGroup(
        source="snmp6",
        protocol="IPv6",
        counters=counters,
    )], malformed, truncated


def list_network_protocol_stats(query: str = "", limit: int = 64) -> NetworkProtocolStatsResponse:
    """List cumulative protocol counters from bounded current-namespace procfs tables."""
    if not sys.platform.startswith("linux"):
        return NetworkProtocolStatsResponse(success=False, message="Network protocol statistics are available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return NetworkProtocolStatsResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return NetworkProtocolStatsResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return NetworkProtocolStatsResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_GROUPS))
    needle = query.strip().casefold()

    groups: list[NetworkProtocolCounterGroup] = []
    errors: list[str] = []
    missing_tables = 0
    available_tables = 0
    malformed_rows = 0
    truncated = False
    for table_name in TABLES:
        lines, table_truncated, error = _read_table(table_name)
        truncated = truncated or table_truncated
        if error:
            if error == "missing":
                missing_tables += 1
            else:
                errors.append(f"{table_name}: {error}")
            continue
        available_tables += 1
        if table_name == "snmp6":
            parsed_groups, malformed, parse_truncated = _parse_snmp6(lines)
        else:
            parsed_groups, malformed, parse_truncated = _parse_paired_table(table_name, lines)
        malformed_rows += malformed
        truncated = truncated or parse_truncated
        for group in parsed_groups:
            searchable = " ".join((group.source, group.protocol, *group.counters)).casefold()
            if not needle or needle in searchable:
                groups.append(group)

    if available_tables == 0:
        detail = "; ".join(errors) if errors else "No Linux protocol-statistics procfs tables were found."
        return NetworkProtocolStatsResponse(
            success=False,
            limit=limit,
            truncated=truncated,
            message=f"Could not read Linux network protocol statistics: {detail}",
        )

    groups.sort(key=lambda group: (group.source, group.protocol))
    total_groups = len(groups)
    truncated = truncated or bool(errors) or malformed_rows > 0 or total_groups > limit
    messages = ["Cumulative protocol counters are read from procfs in the current network namespace; these are snapshots, not rate measurements."]
    if missing_tables:
        messages.append("Some protocol-statistics tables are absent or disabled.")
    if errors:
        messages.append("Some procfs tables could not be read.")
    if malformed_rows:
        messages.append(f"{malformed_rows} malformed counter rows or values were skipped.")
    if total_groups > limit:
        messages.append(f"The result is capped at {limit} counter groups.")
    if truncated:
        messages.append("The scan reached a byte, row, line, counter, malformed-record, or result limit.")
    return NetworkProtocolStatsResponse(
        success=True,
        total_groups=total_groups,
        returned_groups=min(total_groups, limit),
        groups=groups[:limit],
        limit=limit,
        truncated=truncated,
        message=" ".join(messages),
    )
