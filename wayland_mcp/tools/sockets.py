"""Bounded TCP/UDP socket inventory from Linux procfs."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

from wayland_mcp.models import (
    NetworkSocketInfo,
    NetworkSocketListResponse,
    RawSocketInfo,
    UnixDomainSocketInfo,
    UnixRawSocketResponse,
)

PROC_NET = Path("/proc/net")
MAX_TABLE_BYTES = 2 * 1024 * 1024
MAX_TABLE_ROWS = 20_000
MAX_LINE_BYTES = 4096
MAX_SOCKET_RESULTS = 20_000
MAX_RETURNED_SOCKETS = 200
TABLES = (
    ("tcp", "ipv4"),
    ("tcp6", "ipv6"),
    ("udp", "ipv4"),
    ("udp6", "ipv6"),
)
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}


def _parse_endpoint(value: str, family: str) -> tuple[str, int] | None:
    address_hex, separator, port_hex = value.partition(":")
    if not separator:
        return None
    try:
        port = int(port_hex, 16)
        if not 0 <= port <= 65535:
            return None
        if family == "ipv4" and len(address_hex) == 8:
            packed = int(address_hex, 16).to_bytes(4, "little")
            address = socket.inet_ntop(socket.AF_INET, packed)
        elif family == "ipv6" and len(address_hex) == 32:
            packed = b"".join(
                int(address_hex[index:index + 8], 16).to_bytes(4, "little")
                for index in range(0, 32, 8)
            )
            address = socket.inet_ntop(socket.AF_INET6, packed)
        else:
            return None
    except (ValueError, OSError):
        return None
    return address, port


def _read_table(path: Path, *, include_header: bool = False) -> tuple[list[str], bool, str | None]:
    lines: list[str] = []
    bytes_read = 0
    truncated = False
    try:
        with path.open("rb") as stream:
            header = stream.readline(MAX_LINE_BYTES + 1)
            if len(header) > MAX_LINE_BYTES:
                return lines, True, None
            bytes_read += len(header)
            if include_header and header:
                lines.append(header.decode("ascii", errors="replace"))
            for _ in range(MAX_TABLE_ROWS):
                remaining = MAX_TABLE_BYTES - bytes_read
                if remaining <= 0:
                    truncated = bool(stream.read(1))
                    break
                raw_line = stream.readline(min(MAX_LINE_BYTES + 1, remaining + 1))
                if not raw_line:
                    break
                if len(raw_line) > remaining or len(raw_line) > MAX_LINE_BYTES:
                    truncated = True
                    break
                bytes_read += len(raw_line)
                lines.append(raw_line.decode("ascii", errors="replace"))
            if bytes_read == MAX_TABLE_BYTES:
                truncated = truncated or bool(stream.read(1))
            data_rows = len(lines) - (1 if include_header and header else 0)
            if data_rows == MAX_TABLE_ROWS and stream.read(1):
                truncated = True
    except FileNotFoundError:
        return [], False, "missing"
    except OSError as exc:
        return [], False, f"{exc.strerror or 'read error'}"
    return lines, truncated, None


def list_network_sockets(query: str = "", limit: int = 100) -> NetworkSocketListResponse:
    if not sys.platform.startswith("linux"):
        return NetworkSocketListResponse(success=False, message="Socket inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return NetworkSocketListResponse(success=False, message="Query must be text with at most 256 characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return NetworkSocketListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_SOCKETS))
    needle = query.strip().casefold()

    sockets: list[NetworkSocketInfo] = []
    errors: list[str] = []
    available_tables = 0
    missing_tables = 0
    truncated = False
    scan_capped = False
    for table_name, family in TABLES:
        lines, table_truncated, error = _read_table(PROC_NET / table_name, include_header=True)
        truncated = truncated or table_truncated
        if error:
            if error == "missing":
                missing_tables += 1
            else:
                errors.append(f"{table_name}: {error}")
            continue
        available_tables += 1
        if not lines:
            missing_tables += 1
            available_tables -= 1
            continue
        columns = _column_indices(lines[0])
        required_columns = ("local_address", "rem_address", "st")
        if not all(name in columns for name in required_columns):
            errors.append(f"{table_name}: unrecognized procfs header")
            available_tables -= 1
            continue
        required_indices = [columns[name] for name in required_columns]
        for line in lines[1:]:
            if len(sockets) >= MAX_SOCKET_RESULTS:
                truncated = True
                scan_capped = True
                break
            fields = line.split()
            if len(fields) <= max(required_indices):
                continue
            local = _parse_endpoint(fields[columns["local_address"]], family)
            remote = _parse_endpoint(fields[columns["rem_address"]], family)
            if local is None or remote is None:
                continue
            protocol = "tcp" if table_name.startswith("tcp") else "udp"
            state_code = fields[columns["st"]].upper()
            state = TCP_STATES.get(state_code, f"UNKNOWN_{state_code}")
            uid_index = columns.get("uid")
            inode_index = columns.get("inode")
            uid = (
                _integer_field(fields[uid_index], maximum=4_294_967_295)
                if uid_index is not None and uid_index < len(fields) else None
            )
            raw_inode = (
                _integer_field(fields[inode_index])
                if inode_index is not None and inode_index < len(fields) else None
            )
            inode = raw_inode if raw_inode is not None and raw_inode > 0 else None
            item = NetworkSocketInfo(
                protocol=protocol,
                family=family,
                local_address=local[0],
                local_port=local[1],
                remote_address=remote[0],
                remote_port=remote[1],
                state=state,
                uid=uid,
                inode=inode,
            )
            searchable = " ".join((
                protocol,
                family,
                item.local_address,
                str(item.local_port),
                item.remote_address,
                str(item.remote_port),
                state,
                str(item.uid) if item.uid is not None else "",
                str(item.inode) if item.inode is not None else "",
            )).casefold()
            if not needle or needle in searchable:
                sockets.append(item)
        if scan_capped:
            break

    if available_tables == 0:
        detail = "; ".join(errors) if errors else "No TCP or UDP procfs tables were found."
        return NetworkSocketListResponse(success=False, limit=limit, message=f"Could not read Linux socket inventory: {detail}")
    sockets.sort(key=lambda item: (item.protocol, item.family, item.local_address, item.local_port, item.remote_address, item.remote_port))
    message = "Snapshot covers TCP and UDP sockets visible in the current network namespace; kernel-visible UIDs and inodes are included where available, and visible process associations can be resolved separately by inode. UNIX/raw sockets use a separate inventory."
    if errors:
        message += " Some procfs tables could not be read."
    if missing_tables:
        message += " Some protocol-family tables are absent or disabled."
    if truncated:
        message += " The socket scan reached its byte, line, or result limit."
    return NetworkSocketListResponse(
        success=True,
        total_sockets=len(sockets),
        returned_sockets=min(len(sockets), limit),
        sockets=sockets[:limit],
        limit=limit,
        truncated=truncated or len(sockets) > limit,
        message=message,
    )


def _integer_field(value: str, base: int = 10, maximum: int = 2**64 - 1) -> int | None:
    try:
        parsed = int(value, base)
    except ValueError:
        return None
    return parsed if 0 <= parsed <= maximum else None


def _clean_socket_path(value: str, maximum: int = 2048) -> str:
    return "".join(character for character in value if ord(character) >= 32 and ord(character) != 127)[:maximum]


def _column_indices(header: str) -> dict[str, int]:
    columns: dict[str, int] = {}
    collapsed_pairs = 0
    # Procfs headers split queue/timer pairs that each occupy one row token.
    for index, raw_name in enumerate(header.split()):
        name = raw_name.casefold()
        if name == "remote_address":
            name = "rem_address"
        if name in {"rx_queue", "tm->when"}:
            columns[name] = index - collapsed_pairs - 1
            collapsed_pairs += 1
        else:
            columns[name] = index - collapsed_pairs
    return columns


def list_unix_raw_sockets(query: str = "", limit: int = 100) -> UnixRawSocketResponse:
    """List bounded UNIX-domain and IPv4/IPv6 raw sockets from current-namespace procfs."""
    if not sys.platform.startswith("linux"):
        return UnixRawSocketResponse(success=False, message="UNIX/raw socket inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return UnixRawSocketResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return UnixRawSocketResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return UnixRawSocketResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_SOCKETS))
    needle = query.strip().casefold()

    errors: list[str] = []
    missing_tables = 0
    available_tables = 0
    truncated = False
    malformed_rows = 0
    unix_sockets: list[UnixDomainSocketInfo] = []
    unix_lines, unix_truncated, unix_error = _read_table(PROC_NET / "unix", include_header=True)
    truncated = truncated or unix_truncated
    if unix_error:
        if unix_error == "missing":
            missing_tables += 1
        else:
            errors.append(f"unix: {unix_error}")
    elif unix_lines:
        available_tables += 1
        columns = _column_indices(unix_lines[0])
        required = ("refcount", "flags", "type", "st", "inode")
        if not all(name in columns for name in required):
            errors.append("unix: unrecognized procfs header")
            available_tables -= 1
        else:
            for line in unix_lines[1:]:
                fields = line.split(None, 7)
                if len(fields) <= max(columns[name] for name in required):
                    malformed_rows += 1
                    continue
                refcount = _integer_field(fields[columns["refcount"]], 16)
                flags = _integer_field(fields[columns["flags"]], 16)
                socket_type_code = _integer_field(fields[columns["type"]], 16, 0xFFFF)
                state_code = _integer_field(fields[columns["st"]], 16, 0xFFFF)
                inode = _integer_field(fields[columns["inode"]])
                if None in (refcount, flags, socket_type_code, state_code, inode):
                    malformed_rows += 1
                    continue
                path_index = columns.get("path")
                path = _clean_socket_path(fields[path_index]) if path_index is not None and path_index < len(fields) else None
                if path == "":
                    path = None
                type_names = {1: "stream", 2: "datagram", 5: "seqpacket"}
                socket_type = type_names.get(socket_type_code, f"unknown-0x{socket_type_code:04x}")
                state = f"0x{state_code:02x}"
                item = UnixDomainSocketInfo(
                    inode=inode,
                    socket_type=socket_type,
                    state=state,
                    flags=flags,
                    reference_count=refcount,
                    path=path,
                )
                searchable = " ".join((item.socket_type, item.state, item.path or "", str(item.inode))).casefold()
                if not needle or needle in searchable:
                    unix_sockets.append(item)
    else:
        missing_tables += 1

    raw_sockets: list[RawSocketInfo] = []
    for table_name, family in (("raw", "ipv4"), ("raw6", "ipv6")):
        lines, table_truncated, error = _read_table(PROC_NET / table_name, include_header=True)
        truncated = truncated or table_truncated
        if error:
            if error == "missing":
                missing_tables += 1
            else:
                errors.append(f"{table_name}: {error}")
            continue
        if not lines:
            missing_tables += 1
            continue
        available_tables += 1
        columns = _column_indices(lines[0])
        if not {"local_address", "rem_address", "st"}.issubset(columns):
            errors.append(f"{table_name}: unrecognized procfs header")
            available_tables -= 1
            continue
        required_indices = [columns[name] for name in ("local_address", "rem_address", "st")]
        for line in lines[1:]:
            fields = line.split()
            if len(fields) <= max(required_indices):
                malformed_rows += 1
                continue
            local = _parse_endpoint(fields[columns["local_address"]], family)
            remote = _parse_endpoint(fields[columns["rem_address"]], family)
            if local is None or remote is None:
                malformed_rows += 1
                continue
            state_value = _integer_field(fields[columns["st"]], 16, 0xFFFF)
            if state_value is None:
                malformed_rows += 1
                continue
            uid_index = columns.get("uid")
            inode_index = columns.get("inode")
            uid = (
                _integer_field(fields[uid_index], maximum=4_294_967_295)
                if uid_index is not None and uid_index < len(fields) else None
            )
            raw_inode = (
                _integer_field(fields[inode_index])
                if inode_index is not None and inode_index < len(fields) else None
            )
            inode = raw_inode if raw_inode is not None and raw_inode > 0 else None
            remote_unspecified = remote[0] in {"0.0.0.0", "::"}
            item = RawSocketInfo(
                family=family,
                local_address=local[0],
                local_protocol_number=local[1],
                remote_address=None if remote_unspecified else remote[0],
                state=f"0x{state_value:02x}",
                uid=uid,
                inode=inode,
            )
            searchable = " ".join((
                family,
                item.local_address,
                str(item.local_protocol_number),
                item.remote_address or "",
                item.state,
                str(item.uid) if item.uid is not None else "",
                str(item.inode) if item.inode is not None else "",
            )).casefold()
            if not needle or needle in searchable:
                raw_sockets.append(item)

    if available_tables == 0:
        detail = "; ".join(errors) if errors else "No UNIX or raw socket procfs tables were found."
        return UnixRawSocketResponse(success=False, limit=limit, truncated=truncated, message=f"Could not read UNIX/raw socket inventory: {detail}")

    unix_sockets.sort(key=lambda item: (item.path or "", item.socket_type, item.inode))
    raw_sockets.sort(key=lambda item: (
        item.family,
        item.local_address,
        item.local_protocol_number,
        item.remote_address or "",
        item.state,
        item.inode or 0,
    ))
    total_unix = len(unix_sockets)
    total_raw = len(raw_sockets)
    truncated = truncated or bool(errors) or malformed_rows > 0 or total_unix > limit or total_raw > limit
    messages = ["UNIX-domain and raw sockets are read from procfs in the current network namespace; visible process associations can be resolved separately by inode."]
    if missing_tables:
        messages.append("Some protocol-family tables are absent or disabled.")
    if errors:
        messages.append("Some procfs tables could not be read or parsed.")
    if malformed_rows:
        messages.append(f"{malformed_rows} malformed socket rows were skipped.")
    if total_unix > limit or total_raw > limit:
        messages.append(f"Each socket family is capped at {limit} returned entries.")
    if truncated:
        messages.append("The socket scan reached a byte, row, malformed-record, or result limit.")
    return UnixRawSocketResponse(
        success=True,
        total_unix_sockets=total_unix,
        returned_unix_sockets=min(total_unix, limit),
        unix_sockets=unix_sockets[:limit],
        total_raw_sockets=total_raw,
        returned_raw_sockets=min(total_raw, limit),
        raw_sockets=raw_sockets[:limit],
        limit=limit,
        truncated=truncated,
        message=" ".join(messages),
    )
