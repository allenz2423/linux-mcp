"""Linux network interface, address, route, and counter inventory."""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

from wayland_mcp.models import (
    NetworkAddress,
    NetworkInterfaceInfo,
    NetworkInterfaceListResponse,
)
from wayland_mcp.tools.network_control import InterfaceSnapshot, capture_interface, issue_interface_token

SYS_CLASS_NET = Path("/sys/class/net")
PROC_NET = Path("/proc/net")
MAX_INTERFACES = 128


def _read_text(path: Path, max_bytes: int = 16 * 1024) -> str:
    with path.open("rb") as stream:
        return stream.read(max_bytes).decode("utf-8", errors="replace").strip()


def _read_integer(path: Path) -> int | None:
    try:
        return int(_read_text(path, 128), 0)
    except (OSError, ValueError):
        return None


def _ipv4_address(sock: socket.socket, interface: str, request: int) -> bytes | None:
    try:
        import fcntl

        name = interface.encode("utf-8", errors="ignore")[:15]
        response = fcntl.ioctl(sock.fileno(), request, struct.pack("256s", name))
        return response[20:24]
    except (ImportError, OSError, struct.error):
        return None


def _mask_prefix(mask: bytes) -> int | None:
    bits = "".join(f"{value:08b}" for value in mask)
    if "01" in bits:
        return None
    return bits.count("1")


def _read_ipv6_addresses() -> dict[str, list[NetworkAddress]]:
    result: dict[str, list[NetworkAddress]] = {}
    try:
        content = _read_text(PROC_NET / "if_inet6", 256 * 1024)
    except OSError:
        return result
    scope_names = {0x00: "global", 0x10: "loopback", 0x20: "link", 0x40: "site", 0x80: "compat"}
    for line in content.splitlines():
        fields = line.split()
        if len(fields) != 6:
            continue
        address_hex, _index, prefix_hex, scope_hex, _flags, interface = fields
        try:
            packed = bytes.fromhex(address_hex)
            prefix = int(prefix_hex, 16)
            scope_code = int(scope_hex, 16)
            if len(packed) != 16 or prefix > 128:
                continue
            address = socket.inet_ntop(socket.AF_INET6, packed)
        except (ValueError, OSError):
            continue
        result.setdefault(interface, []).append(NetworkAddress(
            address=address,
            prefix_length=prefix,
            scope=scope_names.get(scope_code, f"0x{scope_code:02x}"),
        ))
    return result


def _read_default_gateways() -> tuple[dict[str, tuple[int, str]], dict[str, tuple[int, str]]]:
    ipv4: dict[str, tuple[int, str]] = {}
    try:
        route_table = _read_text(PROC_NET / "route", 256 * 1024)
    except OSError:
        route_table = ""
    for line in route_table.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8 or fields[1] != "00000000":
            continue
        try:
            flags = int(fields[3], 16)
            metric = int(fields[6])
            gateway = socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
        except (ValueError, OSError, struct.error):
            continue
        if flags & 0x1 and gateway != "0.0.0.0":
            current = ipv4.get(fields[0])
            if current is None or metric < current[0]:
                ipv4[fields[0]] = (metric, gateway)

    ipv6: dict[str, tuple[int, str]] = {}
    try:
        route_table = _read_text(PROC_NET / "ipv6_route", 512 * 1024)
    except OSError:
        route_table = ""
    for line in route_table.splitlines():
        fields = line.split()
        if len(fields) < 10 or fields[0] != "0" * 32 or fields[1] != "00":
            continue
        try:
            gateway_bytes = bytes.fromhex(fields[4])
            metric = int(fields[5], 16)
            flags = int(fields[8], 16)
            gateway = socket.inet_ntop(socket.AF_INET6, gateway_bytes)
        except (ValueError, OSError):
            continue
        if flags & 0x1 and gateway != "::":
            interface = fields[9]
            current = ipv6.get(interface)
            if current is None or metric < current[0]:
                ipv6[interface] = (metric, gateway)
    return ipv4, ipv6


def _interface_counters(name: str) -> dict[str, int | None]:
    base = SYS_CLASS_NET / name / "statistics"
    return {
        key: _read_integer(base / filename)
        for key, filename in {
            "rx_bytes": "rx_bytes",
            "tx_bytes": "tx_bytes",
            "rx_packets": "rx_packets",
            "tx_packets": "tx_packets",
            "rx_errors": "rx_errors",
            "tx_errors": "tx_errors",
        }.items()
    }


def list_network_interfaces(query: str = "", limit: int = 64) -> NetworkInterfaceListResponse:
    if not sys.platform.startswith("linux"):
        return NetworkInterfaceListResponse(success=False, message="Network interface inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 128:
        return NetworkInterfaceListResponse(success=False, message="Query must be text with at most 128 characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return NetworkInterfaceListResponse(success=False, message="limit must be an integer.")
    limit = max(1, min(limit, MAX_INTERFACES))
    try:
        names = sorted(entry.name for entry in SYS_CLASS_NET.iterdir() if entry.name)
    except OSError as exc:
        return NetworkInterfaceListResponse(success=False, limit=limit, message=f"Could not read network interfaces: {exc.strerror or 'read error'}.")

    query_key = query.strip().casefold()
    names = [name for name in names if not query_key or query_key in name.casefold()]
    names_truncated = len(names) > MAX_INTERFACES
    names = names[:MAX_INTERFACES]
    ipv6_by_interface = _read_ipv6_addresses()
    gateways_v4, gateways_v6 = _read_default_gateways()
    interfaces: list[tuple[NetworkInterfaceInfo, InterfaceSnapshot | None]] = []
    try:
        ipv4_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        ipv4_socket = None

    try:
        for name in names:
            interface_dir = SYS_CLASS_NET / name
            snapshot, _snapshot_error = capture_interface(name)
            try:
                operational_state = _read_text(interface_dir / "operstate", 64)
            except OSError:
                operational_state = None
            flags = _read_integer(interface_dir / "flags")
            is_loopback = bool(flags & 0x8) if flags is not None else name == "lo"
            addresses = list(ipv6_by_interface.get(name, []))
            if ipv4_socket is not None:
                packed_address = _ipv4_address(ipv4_socket, name, 0x8915)  # SIOCGIFADDR
                if packed_address and packed_address != b"\x00" * 4:
                    mask = _ipv4_address(ipv4_socket, name, 0x891B)  # SIOCGIFNETMASK
                    prefix_length = _mask_prefix(mask) if mask else 32
                    addresses.insert(0, NetworkAddress(
                        address=socket.inet_ntoa(packed_address),
                        prefix_length=prefix_length,
                        scope="loopback" if is_loopback else "global",
                    ))
            counters = _interface_counters(name)
            info = NetworkInterfaceInfo(
                name=name,
                index=snapshot.index if snapshot else None,
                operational_state=operational_state,
                administrative_up=snapshot.administrative_up if snapshot else None,
                mtu=snapshot.mtu if snapshot else _read_integer(interface_dir / "mtu"),
                is_loopback=is_loopback,
                addresses=addresses,
                default_gateway_ipv4=gateways_v4.get(name, (0, None))[1],
                default_gateway_ipv6=gateways_v6.get(name, (0, None))[1],
                **counters,
            )
            interfaces.append((info, snapshot))
    finally:
        if ipv4_socket is not None:
            ipv4_socket.close()

    message_parts: list[str] = []
    if names_truncated:
        message_parts.append(f"Interface enumeration capped at {MAX_INTERFACES} entries.")
    if not (PROC_NET / "if_inet6").is_file():
        message_parts.append("IPv6 address data is unavailable from procfs.")
    selected_interfaces = [
        info.model_copy(update={"identity_token": issue_interface_token(snapshot)}) if snapshot else info
        for info, snapshot in interfaces[:limit]
    ]
    return NetworkInterfaceListResponse(
        success=True,
        total_interfaces=len(interfaces),
        returned_interfaces=len(selected_interfaces),
        interfaces=selected_interfaces,
        limit=limit,
        truncated=names_truncated or len(interfaces) > limit,
        message=" ".join(message_parts) or None,
    )
