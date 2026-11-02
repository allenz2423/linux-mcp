"""Confirmed definition of persistent, inactive local libvirt networks."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from wayland_mcp.models import LibvirtNetworkCreateResponse, LibvirtNetworkIPv4ConfigurationResponse
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.libvirt_common import SCOPED_URIS, virsh_environment
from wayland_mcp.tools.libvirt_resources import (
    COMMAND_TIMEOUT_SECONDS,
    _read_resource_info,
    _read_table,
)

MAX_XML_BYTES = 128 * 1024
MAX_IP_OUTPUT_BYTES = 2 * 1024 * 1024
NETWORK_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
BRIDGE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_LOCK = threading.RLock()

LibvirtNetworkForwardMode = Literal["isolated", "nat", "route", "bridge"]


@dataclass(frozen=True, slots=True)
class _NetworkDefinition:
    forward_mode: LibvirtNetworkForwardMode
    bridge_name: str | None = None
    ipv4_cidr: str | None = None
    dhcp_start: str | None = None
    dhcp_end: str | None = None
    mac_address: str | None = None
    nat_element_present: bool = False
    nat_ipv6: str | None = None
    nat_port_range: tuple[str, str] | None = None


@dataclass(frozen=True, slots=True)
class _NetworkTarget:
    scope: str
    name: str
    definition: _NetworkDefinition
    state_digest: str
    confirmation_phrase: str


@dataclass(frozen=True, slots=True)
class _NetworkIPv4ConfigurationTarget:
    scope: str
    name: str
    uuid: str
    forward_mode: Literal["nat", "route"]
    bridge_name: str
    current_definition: _NetworkDefinition
    definition: _NetworkDefinition
    autostart: bool | None
    state_digest: str
    confirmation_phrase: str


def _validate_request(scope: object, name: object) -> str | None:
    if not isinstance(scope, str) or scope not in SCOPED_URIS:
        return "Choose the local system or user-session libvirt scope."
    if not isinstance(name, str) or not NETWORK_NAME_RE.fullmatch(name):
        return "Network names must start with a letter or digit and contain at most 64 letters, digits, dots, underscores, or hyphens."
    return None


def _build_definition(
    forward_mode: object,
    bridge_name: object,
    ipv4_cidr: object,
    dhcp_start: object,
    dhcp_end: object,
) -> tuple[_NetworkDefinition | None, str | None]:
    if not isinstance(forward_mode, str) or forward_mode not in {"isolated", "nat", "route", "bridge"}:
        return None, "Forward mode must be isolated, nat, route, or bridge."
    fields = (bridge_name, ipv4_cidr, dhcp_start, dhcp_end)
    if any(not isinstance(value, str) for value in fields):
        return None, "Bridge and IPv4 network settings must be text."
    if any(value != value.strip() for value in fields):
        return None, "Bridge and IPv4 network settings cannot have leading or trailing whitespace."

    if forward_mode == "isolated":
        if bridge_name or ipv4_cidr or dhcp_start or dhcp_end:
            return None, "Isolated networks do not accept a host bridge, IPv4 address, or DHCP range."
        return _NetworkDefinition("isolated"), None

    if forward_mode == "bridge":
        if not bridge_name or not BRIDGE_NAME_RE.fullmatch(bridge_name):
            return None, "Bridge mode requires the name of an existing Linux bridge (1-15 safe interface-name characters)."
        if ipv4_cidr or dhcp_start or dhcp_end:
            return None, "Bridge mode uses the existing bridge directly and does not accept libvirt IPv4 or DHCP settings."
        return _NetworkDefinition("bridge", bridge_name=bridge_name), None

    if bridge_name:
        return None, "NAT and routed networks use a libvirt-assigned bridge name; omit bridge_name."
    if not ipv4_cidr or len(ipv4_cidr) > 64:
        return None, "NAT and routed networks require an IPv4 bridge address with prefix, such as 192.168.122.1/24."
    try:
        interface = ipaddress.ip_interface(ipv4_cidr)
    except ValueError:
        return None, "The IPv4 bridge address and prefix are invalid."
    if not isinstance(interface, ipaddress.IPv4Interface):
        return None, "Only IPv4 addresses are supported for NAT and routed networks."
    network = interface.network
    if not 1 <= network.prefixlen <= 30 or interface.ip in {network.network_address, network.broadcast_address}:
        return None, "The IPv4 network must have a prefix from /1 through /30 and a usable bridge address."
    if bool(dhcp_start) != bool(dhcp_end):
        return None, "Provide both DHCP range endpoints, or leave both empty."

    normalized_start: str | None = None
    normalized_end: str | None = None
    if dhcp_start:
        try:
            start = ipaddress.IPv4Address(dhcp_start)
            end = ipaddress.IPv4Address(dhcp_end)
        except ipaddress.AddressValueError:
            return None, "DHCP range endpoints must be IPv4 addresses."
        if (
            start not in network
            or end not in network
            or start in {network.network_address, network.broadcast_address}
            or end in {network.network_address, network.broadcast_address}
            or int(start) > int(end)
            or int(start) <= int(interface.ip) <= int(end)
        ):
            return None, "The ordered DHCP range must stay inside the network, exclude network/broadcast addresses, and not include the bridge address."
        normalized_start, normalized_end = str(start), str(end)

    return _NetworkDefinition(
        forward_mode,  # type: ignore[arg-type]
        ipv4_cidr=str(interface),
        dhcp_start=normalized_start,
        dhcp_end=normalized_end,
    ), None


def _read_network_names(
    scope: str,
    binary: str,
    env: dict[str, str],
) -> tuple[list[str] | None, str | None]:
    rows, error, truncated = _read_table(
        scope,
        ["net-list", "--all", "--table"],
        {"name", "state", "autostart", "persistent"},
        f"local libvirt {scope} network definitions",
        binary,
        env,
    )
    if error or rows is None or truncated:
        return None, "The complete local virtual-network inventory could not be inspected."
    names = [row.get("name", "") for row in rows]
    if any(not name or len(name) > 256 or any(ord(ch) < 32 or ord(ch) == 127 for ch in name) for name in names):
        return None, "The virtual-network inventory contained an invalid name."
    if len(names) != len(set(names)):
        return None, "The virtual-network inventory contained duplicate names."
    return names, None


def _ip_json(
    ip_binary: str,
    env: dict[str, str],
    args: list[str],
    label: str,
) -> tuple[list[dict[str, object]] | None, str | None]:
    output, error, truncated = run_bounded_command(
        [ip_binary, "-j", "-4", *args],
        env,
        command_label=label,
        timeout_seconds=5,
        max_output_bytes=MAX_IP_OUTPUT_BYTES,
    )
    if output is None or error or truncated:
        return None, f"{label} could not be checked completely."
    try:
        value = json.loads(output)
    except json.JSONDecodeError:
        return None, f"{label} returned invalid JSON."
    if not isinstance(value, list) or len(value) > 20_000 or any(not isinstance(row, dict) for row in value):
        return None, f"{label} returned an unsupported or oversized result."
    return value, None  # type: ignore[return-value]


def _read_host_ipv4_networks(
    env: dict[str, str],
) -> tuple[set[str] | None, str | None]:
    ip_binary = find_session_binary("ip", env)
    if not ip_binary:
        return None, "NAT and routed network definitions require iproute2 for subnet-conflict checks."
    routes, error = _ip_json(ip_binary, env, ["route", "show", "table", "all"], "IPv4 route inventory")
    if error or routes is None:
        return None, error or "The IPv4 route inventory could not be checked."
    addresses, error = _ip_json(ip_binary, env, ["address", "show"], "IPv4 address inventory")
    if error or addresses is None:
        return None, error or "The IPv4 address inventory could not be checked."

    networks: set[str] = set()
    for row in routes:
        destination = row.get("dst")
        if destination is None or destination == "default":
            continue
        if not isinstance(destination, str):
            return None, "The IPv4 route inventory contained an invalid destination."
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            return None, "The IPv4 route inventory contained an unrecognized destination."
        if not isinstance(network, ipaddress.IPv4Network):
            return None, "The IPv4 route inventory returned a non-IPv4 route."
        if network.prefixlen:
            networks.add(str(network))

    for interface_record in addresses:
        entries = interface_record.get("addr_info", [])
        if not isinstance(entries, list):
            return None, "The IPv4 address inventory contained malformed interface data."
        for entry in entries:
            if not isinstance(entry, dict):
                return None, "The IPv4 address inventory contained malformed address data."
            if entry.get("family") != "inet":
                continue
            local = entry.get("local")
            prefix = entry.get("prefixlen")
            if not isinstance(local, str) or not isinstance(prefix, int) or isinstance(prefix, bool):
                return None, "The IPv4 address inventory contained an invalid address or prefix."
            try:
                interface = ipaddress.ip_interface(f"{local}/{prefix}")
            except ValueError:
                return None, "The IPv4 address inventory contained an unrecognized address."
            if not isinstance(interface, ipaddress.IPv4Interface):
                return None, "The IPv4 address inventory returned a non-IPv4 address."
            networks.add(str(interface.network))
    return networks, None


def _bridge_identity(name: str) -> tuple[dict[str, object] | None, str | None]:
    interface = Path("/sys/class/net") / name
    try:
        if not interface.exists() or not (interface / "bridge").is_dir():
            return None, "Bridge mode requires an existing Linux bridge visible under /sys/class/net."
        raw_ifindex = (interface / "ifindex").read_text(encoding="ascii", errors="strict").strip()
        if not raw_ifindex.isascii() or not raw_ifindex.isdigit() or int(raw_ifindex) <= 0:
            return None, "The selected host bridge identity could not be read safely."
        identity: dict[str, object] = {
            "ifindex": int(raw_ifindex),
            "syspath": os.path.realpath(interface),
        }
    except (OSError, UnicodeError):
        return None, "The selected host bridge identity could not be inspected."
    return identity, None


def _observe_target(
    scope: str,
    name: str,
    forward_mode: object = "isolated",
    bridge_name: object = "",
    ipv4_cidr: object = "",
    dhcp_start: object = "",
    dhcp_end: object = "",
) -> tuple[_NetworkTarget | None, str | None]:
    error = _validate_request(scope, name)
    if error:
        return None, error
    definition, error = _build_definition(forward_mode, bridge_name, ipv4_cidr, dhcp_start, dhcp_end)
    if error or definition is None:
        return None, error or "The virtual-network configuration is invalid."
    if not sys.platform.startswith("linux"):
        return None, "Libvirt virtual-network creation is available only on Linux."
    env = virsh_environment()
    binary = find_session_binary("virsh", env)
    if not binary:
        return None, "The optional virsh command is unavailable."
    names, error = _read_network_names(scope, binary, env)
    if error or names is None:
        return None, error or "The exact local virtual-network state could not be verified."
    if name in names:
        return None, "A virtual network with that exact name already exists in the selected libvirt scope."

    host_state_digest: str | None = None
    if definition.forward_mode in {"nat", "route"}:
        host_networks, error = _read_host_ipv4_networks(env)
        if error or host_networks is None:
            return None, error or "The host IPv4 network state could not be inspected."
        requested_network = ipaddress.ip_interface(definition.ipv4_cidr or "").network
        if any(requested_network.overlaps(ipaddress.ip_network(value)) for value in host_networks):
            return None, "The requested IPv4 subnet overlaps a current host route or interface address; choose a non-overlapping subnet."
        host_material: object = sorted(host_networks)
        host_state_digest = hashlib.sha256(
            json.dumps(host_material, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    elif definition.forward_mode == "bridge":
        bridge_state, error = _bridge_identity(definition.bridge_name or "")
        if error or bridge_state is None:
            return None, error or "The selected host bridge could not be verified."
        host_state_digest = hashlib.sha256(
            json.dumps(bridge_state, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    names_digest = hashlib.sha256(
        json.dumps(sorted(names), separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if definition.forward_mode == "isolated":
        # Preserve the existing isolated tool's state and confirmation phrase format.
        material = {
            "scope": scope,
            "name": name,
            "network_names_digest": names_digest,
            "uid": os.getuid(),
            "euid": os.geteuid(),
        }
    else:
        material = {
            "scope": scope,
            "name": name,
            "definition": {
                "forward_mode": definition.forward_mode,
                "bridge_name": definition.bridge_name,
                "ipv4_cidr": definition.ipv4_cidr,
                "dhcp_start": definition.dhcp_start,
                "dhcp_end": definition.dhcp_end,
            },
            "network_names_digest": names_digest,
            "host_state_digest": host_state_digest,
            "uid": os.getuid(),
            "euid": os.geteuid(),
        }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    prefix = "CREATE-ISOLATED-NET-" if definition.forward_mode == "isolated" else "CREATE-LIBVIRT-NET-"
    return _NetworkTarget(
        scope=scope,
        name=name,
        definition=definition,
        state_digest=digest,
        confirmation_phrase=prefix + digest[:16].upper(),
    ), None


def libvirt_network_create_confirmation_details(
    scope: str,
    name: str,
) -> tuple[_NetworkTarget | None, str | None, str | None]:
    return libvirt_network_definition_confirmation_details(scope, name)


def libvirt_network_definition_confirmation_details(
    scope: str,
    name: str,
    forward_mode: str = "isolated",
    bridge_name: str = "",
    ipv4_cidr: str = "",
    dhcp_start: str = "",
    dhcp_end: str = "",
) -> tuple[_NetworkTarget | None, str | None, str | None]:
    target, error = _observe_target(scope, name, forward_mode, bridge_name, ipv4_cidr, dhcp_start, dhcp_end)
    if error or target is None:
        return None, None, error or "The exact virtual-network request could not be verified."
    return target, target.confirmation_phrase, None


def _network_xml(
    name: str,
    definition: _NetworkDefinition,
    *,
    uuid: str | None = None,
    existing_bridge_name: str | None = None,
) -> bytes:
    root = ET.Element("network")
    ET.SubElement(root, "name").text = name
    if uuid is not None:
        ET.SubElement(root, "uuid").text = uuid
    if definition.forward_mode != "isolated":
        forward = ET.SubElement(root, "forward", {"mode": definition.forward_mode})
        if definition.forward_mode == "nat" and definition.nat_element_present:
            nat_attributes = {"ipv6": definition.nat_ipv6} if definition.nat_ipv6 is not None else {}
            nat_node = ET.SubElement(forward, "nat", nat_attributes)
            if definition.nat_port_range is not None:
                ET.SubElement(nat_node, "port", {"start": definition.nat_port_range[0], "end": definition.nat_port_range[1]})
    if definition.forward_mode == "bridge":
        ET.SubElement(root, "bridge", {"name": definition.bridge_name or ""})
    else:
        bridge_attributes = {"stp": "on", "delay": "0"}
        if existing_bridge_name is not None:
            bridge_attributes["name"] = existing_bridge_name
        ET.SubElement(root, "bridge", bridge_attributes)
    if definition.mac_address is not None:
        ET.SubElement(root, "mac", {"address": definition.mac_address})
    if definition.forward_mode in {"nat", "route"}:
        interface = ipaddress.ip_interface(definition.ipv4_cidr or "")
        ip_node = ET.SubElement(
            root,
            "ip",
            {
                "family": "ipv4",
                "address": str(interface.ip),
                "prefix": str(interface.network.prefixlen),
            },
        )
        if definition.dhcp_start and definition.dhcp_end:
            dhcp = ET.SubElement(ip_node, "dhcp")
            ET.SubElement(dhcp, "range", {"start": definition.dhcp_start, "end": definition.dhcp_end})
    xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    if len(xml) > MAX_XML_BYTES:
        raise ValueError("The generated virtual-network definition exceeded its size limit.")
    return xml


def _write_xml(xml: bytes, directory: str) -> str | None:
    descriptor = -1
    try:
        descriptor, path = tempfile.mkstemp(prefix="network-", suffix=".xml", dir=directory)
        os.fchmod(descriptor, 0o600)
        view = memoryview(xml)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("The network XML file accepted no bytes.")
            view = view[written:]
        os.fsync(descriptor)
        return path
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _prefix_from_ip_element(ip_node: ET.Element) -> int | None:
    raw_prefix = ip_node.get("prefix")
    if raw_prefix is not None:
        if not raw_prefix.isascii() or not raw_prefix.isdigit():
            return None
        prefix = int(raw_prefix)
        return prefix if 0 <= prefix <= 32 else None
    netmask = ip_node.get("netmask")
    if not netmask:
        return None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except ValueError:
        return None


def _ip_definition_matches(ip_node: ET.Element, definition: _NetworkDefinition) -> bool:
    if ip_node.get("family", "ipv4").casefold() != "ipv4":
        return False
    expected = ipaddress.ip_interface(definition.ipv4_cidr or "")
    actual_address = ip_node.get("address")
    actual_prefix = _prefix_from_ip_element(ip_node)
    if actual_address != str(expected.ip) or actual_prefix != expected.network.prefixlen:
        return False
    allowed_attributes = {"family", "address", "prefix", "netmask"}
    if set(ip_node.attrib) - allowed_attributes:
        return False
    if ip_node.get("prefix") is not None and ip_node.get("netmask") is not None:
        return False
    children = list(ip_node)
    dhcp_node = ip_node.find("dhcp")
    if definition.dhcp_start and definition.dhcp_end:
        if len(children) != 1 or dhcp_node is None or len(dhcp_node) != 1:
            return False
        range_node = dhcp_node.find("range")
        return bool(
            range_node is not None
            and len(range_node) == 0
            and range_node.attrib == {"start": definition.dhcp_start, "end": definition.dhcp_end}
            and len(dhcp_node.attrib) == 0
        )
    return not children


def _verify_network(
    scope: str,
    name: str,
    definition: _NetworkDefinition,
    binary: str,
    env: dict[str, str],
) -> tuple[str | None, str | None, str | None]:
    info, error = _read_resource_info("network", scope, name, binary, env)
    if error or info is None:
        return None, None, error or "The defined network could not be inspected."
    if info.persistent is not True or info.active:
        return None, None, "The defined network is not persistent and inactive."
    output, error, truncated = run_bounded_command(
        [binary, "--quiet", "--no-pkttyagent", "--connect", SCOPED_URIS[scope], "--readonly", "net-dumpxml", "--inactive", info.uuid],
        env,
        command_label=f"local libvirt {scope} network definition verification",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_XML_BYTES,
    )
    if error or output is None or truncated or "<!doctype" in output.casefold() or "<!entity" in output.casefold():
        return None, None, "The saved virtual-network XML could not be verified safely."
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return None, None, "Libvirt returned malformed saved virtual-network XML."
    bridge = root.find("bridge")
    forward = root.find("forward")
    ip_nodes = root.findall("ip")
    mac = root.find("mac")
    expected_ip_count = 1 if definition.forward_mode in {"nat", "route"} else 0
    expected_forward_count = 0 if definition.forward_mode == "isolated" else 1
    if (
        root.tag != "network"
        or len(root.findall("name")) != 1
        or len(root.findall("uuid")) != 1
        or len(root.findall("bridge")) != 1
        or len(root.findall("forward")) != expected_forward_count
        or len(ip_nodes) != expected_ip_count
        or len(root.findall("mac")) > 1
        or root.findtext("name") != name
        or root.findtext("uuid", "").casefold() != info.uuid
        or bridge is None
        or root.find("dns") is not None
        or root.findall("portgroup")
        or root.find("bandwidth") is not None
        or root.find("vlan") is not None
        or root.find("mtu") is not None
        or root.find("domain") is not None
        or root.find("route") is not None
        or (mac is not None and (set(mac.attrib) != {"address"} or len(mac) != 0 or not re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", mac.get("address", ""))))
        or (definition.mac_address is not None and (mac is None or mac.get("address") != definition.mac_address))
    ):
        return None, None, "The saved network contains unexpected fields or identity."
    allowed_children = {"name", "uuid", "forward", "bridge", "ip", "mac"}
    if any(child.tag not in allowed_children for child in root):
        return None, None, "The saved network contains unsupported configuration fields."
    bridge_value = bridge.get("name")
    if definition.forward_mode == "bridge":
        if (
            forward is None
            or forward.get("mode") != "bridge"
            or forward.attrib != {"mode": "bridge"}
            or list(forward)
            or bridge_value != definition.bridge_name
            or bridge.get("stp") is not None
            or bridge.get("delay") is not None
            or bridge.attrib != {"name": definition.bridge_name}
            or len(bridge) != 0
            or ip_nodes
        ):
            return None, None, "The saved network differs from the requested existing-bridge configuration."
    else:
        if (
            bridge.get("stp", "on").casefold() not in {"on", "yes", "1"}
            or bridge.get("delay", "0") not in {"", "0"}
            or bridge.attrib.keys() - {"name", "stp", "delay"}
            or not bridge_value
            or not BRIDGE_NAME_RE.fullmatch(bridge_value)
            or len(bridge) != 0
        ):
            return None, None, "The saved network bridge settings differ from the requested configuration."
        if definition.forward_mode == "isolated":
            if forward is not None or ip_nodes:
                return None, None, "The saved network is not isolated."
        else:
            if (
                forward is None
                or forward.get("mode") != definition.forward_mode
                or set(forward.attrib) - {"mode"}
                or len(ip_nodes) != 1
                or not _ip_definition_matches(ip_nodes[0], definition)
            ):
                return None, None, "The saved network differs from the requested forwarding or IPv4/DHCP configuration."
            forward_children = list(forward)
            if definition.forward_mode == "route" and forward_children:
                return None, None, "The saved routed network contains unsupported forwarding options."
            if definition.forward_mode == "nat":
                if any(child.tag != "nat" for child in forward_children) or len(forward_children) > 1:
                    return None, None, "The saved NAT network contains unsupported forwarding options."
                if definition.nat_element_present and not forward_children:
                    return None, None, "The saved NAT network is missing its existing NAT settings."
                if forward_children:
                    nat_node = forward_children[0]
                    nat_ports = list(nat_node)
                    if (
                        set(nat_node.attrib) - {"ipv6"}
                        or nat_node.get("ipv6", "no").casefold() not in {"no", "false", "0"}
                        or any(child.tag != "port" for child in nat_ports)
                        or len(nat_ports) > 1
                        or (
                            nat_ports
                            and (
                                set(nat_ports[0].attrib) != {"start", "end"}
                                or len(nat_ports[0]) != 0
                                or nat_ports[0].get("start") != "1024"
                                or nat_ports[0].get("end") != "65535"
                            )
                        )
                    ):
                        return None, None, "The saved NAT network contains unsupported NAT options."
                    if definition.nat_ipv6 is not None and nat_node.get("ipv6") != definition.nat_ipv6:
                        return None, None, "The saved NAT IPv6 setting differs from the existing configuration."
                    if definition.nat_port_range is not None and (
                        len(nat_ports) != 1
                        or nat_ports[0].get("start") != definition.nat_port_range[0]
                        or nat_ports[0].get("end") != definition.nat_port_range[1]
                    ):
                        return None, None, "The saved NAT port range differs from the existing configuration."
    return info.uuid, bridge_value, None


def _parse_existing_ipv4_definition(
    scope: str,
    name: str,
    uuid: str,
    xml_text: str,
) -> tuple[_NetworkDefinition | None, str | None, str | None]:
    if len(xml_text.encode("utf-8")) > MAX_XML_BYTES or "<!doctype" in xml_text.casefold() or "<!entity" in xml_text.casefold():
        return None, None, "The saved network XML cannot be inspected safely."
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None, None, "Libvirt returned malformed saved virtual-network XML."
    forward = root.find("forward")
    bridge = root.find("bridge")
    ip_nodes = root.findall("ip")
    if (
        root.tag != "network"
        or root.attrib
        or len(root.findall("name")) != 1
        or len(root.findall("uuid")) != 1
        or len(root.findall("forward")) != 1
        or len(root.findall("bridge")) != 1
        or len(ip_nodes) != 1
        or root.findtext("name") != name
        or root.findtext("uuid", "").casefold() != uuid
        or forward is None
        or forward.get("mode") not in {"nat", "route"}
        or bridge is None
    ):
        return None, None, "Only supported persistent IPv4 NAT or routed networks can be configured by this tool."
    bridge_name = bridge.get("name", "")
    if (
        not BRIDGE_NAME_RE.fullmatch(bridge_name)
        or bridge.get("stp", "on").casefold() not in {"on", "yes", "1"}
        or bridge.get("delay", "0") not in {"", "0"}
        or set(bridge.attrib) - {"name", "stp", "delay"}
        or len(bridge) != 0
    ):
        return None, None, "The existing network bridge settings are outside the supported configuration subset."
    ip_node = ip_nodes[0]
    address = ip_node.get("address")
    prefix = _prefix_from_ip_element(ip_node)
    if address is None or prefix is None:
        return None, None, "The existing network IPv4 address or prefix is invalid."
    try:
        normalized_address = str(ipaddress.IPv4Address(address))
    except ipaddress.AddressValueError:
        return None, None, "The existing network is not using a literal IPv4 address."
    dhcp_node = ip_node.find("dhcp")
    dhcp_start = ""
    dhcp_end = ""
    if dhcp_node is not None:
        children = list(dhcp_node)
        if len(children) != 1 or children[0].tag != "range" or dhcp_node.attrib:
            return None, None, "The existing DHCP configuration includes unsupported host, boot, or range settings."
        range_node = children[0]
        if len(range_node) != 0 or set(range_node.attrib) != {"start", "end"}:
            return None, None, "The existing DHCP range is outside the supported configuration subset."
        dhcp_start = range_node.get("start", "")
        dhcp_end = range_node.get("end", "")
        if list(ip_node) != [dhcp_node]:
            return None, None, "The existing IPv4 definition contains unsupported child elements."
    elif list(ip_node):
        return None, None, "The existing IPv4 definition contains unsupported child elements."
    mode = forward.get("mode", "")
    definition, error = _build_definition(
        mode,
        "",
        f"{normalized_address}/{prefix}",
        dhcp_start,
        dhcp_end,
    )
    if error or definition is None:
        return None, None, error or "The existing IPv4 network definition could not be normalized."
    if not _ip_definition_matches(ip_node, definition):
        return None, None, "The existing IPv4 definition contains unsupported address or DHCP fields."
    mac_node = root.find("mac")
    mac_address = mac_node.get("address") if mac_node is not None else None
    nat_node = forward.find("nat") if mode == "nat" else None
    nat_ipv6 = nat_node.get("ipv6") if nat_node is not None else None
    nat_port_range: tuple[str, str] | None = None
    if nat_node is not None:
        port_node = nat_node.find("port")
        if port_node is not None:
            nat_port_range = (port_node.get("start", ""), port_node.get("end", ""))
    definition = replace(
        definition,
        mac_address=mac_address,
        nat_element_present=nat_node is not None,
        nat_ipv6=nat_ipv6,
        nat_port_range=nat_port_range,
    )
    return definition, bridge_name, None


def _observe_network_ipv4_configuration_target(
    scope: object,
    name: object,
    ipv4_cidr: object,
    dhcp_action: object,
    dhcp_start: object,
    dhcp_end: object,
) -> tuple[_NetworkIPv4ConfigurationTarget | None, str | None]:
    error = _validate_request(scope, name)
    if error:
        return None, error
    if not isinstance(ipv4_cidr, str):
        return None, "ipv4_cidr must be an IPv4 bridge address with prefix."
    if not isinstance(dhcp_action, str) or dhcp_action not in {"keep", "set", "disable"}:
        return None, "dhcp_action must be keep, set, or disable."
    if not isinstance(dhcp_start, str) or not isinstance(dhcp_end, str):
        return None, "DHCP range endpoints must be text."
    if dhcp_action == "set":
        if not dhcp_start or not dhcp_end:
            return None, "dhcp_action='set' requires both DHCP range endpoints."
    elif dhcp_start or dhcp_end:
        return None, "DHCP endpoints are accepted only when dhcp_action is set."
    if not sys.platform.startswith("linux"):
        return None, "Libvirt virtual-network configuration is available only on Linux."
    env = virsh_environment()
    binary = find_session_binary("virsh", env)
    if not binary:
        return None, "The optional virsh command is unavailable."
    info, error = _read_resource_info("network", scope, name, binary, env)
    if error or info is None:
        return None, error or "The selected libvirt network could not be inspected."
    if info.persistent is not True or info.active:
        return None, "Only persistent inactive virtual networks can be reconfigured. Stop the network separately before changing its definition."
    output, error, truncated = run_bounded_command(
        [binary, "--quiet", "--no-pkttyagent", "--connect", SCOPED_URIS[scope], "--readonly", "net-dumpxml", "--inactive", info.uuid],
        env,
        command_label=f"local libvirt {scope} network configuration inspection",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_XML_BYTES,
    )
    if error or output is None or truncated:
        return None, "The complete inactive network definition could not be read."
    current_definition, bridge_name, error = _parse_existing_ipv4_definition(scope, name, info.uuid, output)
    if error or current_definition is None or bridge_name is None:
        return None, error or "The existing virtual-network definition is outside the supported subset."
    verified_uuid, verified_bridge, error = _verify_network(scope, name, current_definition, binary, env)
    if error or verified_uuid != info.uuid or verified_bridge != bridge_name:
        return None, error or "The current virtual-network definition changed while it was being inspected."

    if dhcp_action == "keep":
        requested_start = current_definition.dhcp_start or ""
        requested_end = current_definition.dhcp_end or ""
    elif dhcp_action == "set":
        requested_start = dhcp_start
        requested_end = dhcp_end
    else:
        requested_start = ""
        requested_end = ""
    definition, error = _build_definition(
        current_definition.forward_mode,
        "",
        ipv4_cidr,
        requested_start,
        requested_end,
    )
    if error or definition is None:
        return None, error or "The requested IPv4 network settings are invalid."
    definition = replace(
        definition,
        mac_address=current_definition.mac_address,
        nat_element_present=current_definition.nat_element_present,
        nat_ipv6=current_definition.nat_ipv6,
        nat_port_range=current_definition.nat_port_range,
    )
    if definition == current_definition:
        return None, "The requested IPv4 and DHCP settings already match the saved network definition."
    host_networks, error = _read_host_ipv4_networks(env)
    if error or host_networks is None:
        return None, error or "The host IPv4 network state could not be inspected."
    requested_network = ipaddress.ip_interface(definition.ipv4_cidr or "").network
    if any(requested_network.overlaps(ipaddress.ip_network(value)) for value in host_networks):
        return None, "The requested IPv4 subnet overlaps a current host route or interface address; choose a non-overlapping subnet."
    host_state_digest = hashlib.sha256(
        json.dumps(sorted(host_networks), ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    current_xml_digest = hashlib.sha256(output.encode("utf-8")).hexdigest()
    material = {
        "scope": scope,
        "name": name,
        "uuid": info.uuid,
        "active": info.active,
        "persistent": info.persistent,
        "autostart": info.autostart,
        "current_xml_digest": current_xml_digest,
        "requested_definition": {
            "forward_mode": definition.forward_mode,
            "ipv4_cidr": definition.ipv4_cidr,
            "dhcp_start": definition.dhcp_start,
            "dhcp_end": definition.dhcp_end,
        },
        "dhcp_action": dhcp_action,
        "host_state_digest": host_state_digest,
        "uid": os.getuid(),
        "euid": os.geteuid(),
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return _NetworkIPv4ConfigurationTarget(
        scope=scope,
        name=name,
        uuid=info.uuid,
        forward_mode=current_definition.forward_mode,
        bridge_name=bridge_name,
        current_definition=current_definition,
        definition=definition,
        autostart=info.autostart,
        state_digest=digest,
        confirmation_phrase="CONFIGURE-LIBVIRT-NET-IP-" + digest[:16].upper(),
    ), None


def libvirt_network_ipv4_configuration_confirmation_details(
    scope: str,
    name: str,
    ipv4_cidr: str,
    dhcp_action: str = "keep",
    dhcp_start: str = "",
    dhcp_end: str = "",
) -> tuple[_NetworkIPv4ConfigurationTarget | None, str | None, str | None]:
    target, error = _observe_network_ipv4_configuration_target(
        scope,
        name,
        ipv4_cidr,
        dhcp_action,
        dhcp_start,
        dhcp_end,
    )
    if error or target is None:
        return None, None, error or "The exact libvirt network configuration request could not be verified."
    return target, target.confirmation_phrase, None


def _perform_network_definition(
    scope: str,
    name: str,
    forward_mode: str,
    bridge_name: str,
    ipv4_cidr: str,
    dhcp_start: str,
    dhcp_end: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> LibvirtNetworkCreateResponse:
    target, error = _observe_target(scope, name, forward_mode, bridge_name, ipv4_cidr, dhcp_start, dhcp_end)
    if error or target is None:
        safe_scope = scope if isinstance(scope, str) and scope in SCOPED_URIS else None
        return LibvirtNetworkCreateResponse(
            success=False,
            scope=safe_scope,
            name=name if isinstance(name, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The exact virtual-network state could not be verified.",
        )
    if confirmed is not True:
        return LibvirtNetworkCreateResponse(success=False, scope=scope, name=name, user_confirmed=False, message="Explicit client confirmation is required; no network definition was changed.")
    if not isinstance(confirmation_phrase, str) or not hmac.compare_digest(confirmation_phrase, target.confirmation_phrase):
        return LibvirtNetworkCreateResponse(success=False, scope=scope, name=name, user_confirmed=True, message="Confirmation did not match the exact network configuration and current state.")
    with _LOCK:
        current, error = _observe_target(scope, name, forward_mode, bridge_name, ipv4_cidr, dhcp_start, dhcp_end)
        if error or current is None or current.state_digest != target.state_digest:
            return LibvirtNetworkCreateResponse(success=False, scope=scope, name=name, user_confirmed=True, message=error or "The local network or host IPv4 state changed after confirmation; inspect it and confirm again.")
        env = virsh_environment()
        binary = find_session_binary("virsh", env)
        if not binary:
            return LibvirtNetworkCreateResponse(success=False, scope=scope, name=name, user_confirmed=True, message="The optional virsh command became unavailable; no network was defined.")
        try:
            xml = _network_xml(name, target.definition)
        except ValueError:
            return LibvirtNetworkCreateResponse(success=False, scope=scope, name=name, user_confirmed=True, message="A bounded network definition could not be generated.")
        command_error: str | None = None
        output: str | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="linux-mcp-network-") as temp_dir:
                os.chmod(temp_dir, 0o700)
                xml_path = _write_xml(xml, temp_dir)
                if xml_path is None:
                    return LibvirtNetworkCreateResponse(success=False, scope=scope, name=name, user_confirmed=True, message="A private temporary network definition could not be written.")
                output, command_error, truncated = run_bounded_command(
                    [binary, "--quiet", "--no-pkttyagent", "--connect", SCOPED_URIS[scope], "net-define", "--validate", xml_path],
                    env,
                    command_label=f"local libvirt {scope} {target.definition.forward_mode} network definition",
                    timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                    max_output_bytes=16 * 1024,
                )
                if truncated:
                    command_error = command_error or "virsh network-definition output exceeded its limit"
        except OSError:
            command_error = "a private temporary directory could not be created"
        uuid, actual_bridge, verification_error = _verify_network(scope, name, target.definition, binary, env)
        if command_error:
            message = "The network command reported an error; inspect the local libvirt networks before retrying."
        elif uuid is not None:
            message = f"The persistent inactive {target.definition.forward_mode} libvirt network was defined and verified; starting it is a separate confirmed action."
        else:
            message = "The network definition was attempted but could not be verified; inspect libvirt before retrying."
        if target.definition.forward_mode == "bridge":
            message += " The selected host bridge is not created or managed by libvirt."
        return LibvirtNetworkCreateResponse(
            success=command_error is None and output is not None and uuid is not None,
            scope=scope,
            uuid=uuid,
            name=name,
            active=False if uuid is not None else None,
            persistent=True if uuid is not None else None,
            forward_mode=target.definition.forward_mode,
            bridge_name=actual_bridge,
            ipv4_cidr=target.definition.ipv4_cidr,
            dhcp_start=target.definition.dhcp_start,
            dhcp_end=target.definition.dhcp_end,
            state_verified=uuid is not None,
            user_confirmed=True,
            message=message if verification_error is None else f"{message} {verification_error[:240]}",
        )


def perform_libvirt_network_ipv4_configuration(
    scope: str,
    name: str,
    ipv4_cidr: str,
    dhcp_action: str,
    dhcp_start: str,
    dhcp_end: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> LibvirtNetworkIPv4ConfigurationResponse:
    target, error = _observe_network_ipv4_configuration_target(
        scope,
        name,
        ipv4_cidr,
        dhcp_action,
        dhcp_start,
        dhcp_end,
    )
    safe_scope = scope if isinstance(scope, str) and scope in SCOPED_URIS else None
    if error or target is None:
        return LibvirtNetworkIPv4ConfigurationResponse(
            success=False,
            scope=safe_scope,
            name=name if isinstance(name, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The exact virtual-network state could not be verified.",
        )
    previous = target.current_definition
    requested = target.definition
    response_fields = {
        "scope": target.scope,
        "uuid": target.uuid,
        "name": target.name,
        "forward_mode": target.forward_mode,
        "bridge_name": target.bridge_name,
        "previous_ipv4_cidr": previous.ipv4_cidr,
        "ipv4_cidr": requested.ipv4_cidr,
        "previous_dhcp_start": previous.dhcp_start,
        "previous_dhcp_end": previous.dhcp_end,
        "dhcp_start": requested.dhcp_start,
        "dhcp_end": requested.dhcp_end,
    }
    if confirmed is not True:
        return LibvirtNetworkIPv4ConfigurationResponse(
            success=False,
            **response_fields,
            active=False,
            persistent=True,
            user_confirmed=False,
            message="Explicit client confirmation is required; the network definition was not changed.",
        )
    if not isinstance(confirmation_phrase, str) or not hmac.compare_digest(confirmation_phrase, target.confirmation_phrase):
        return LibvirtNetworkIPv4ConfigurationResponse(
            success=False,
            **response_fields,
            active=False,
            persistent=True,
            user_confirmed=True,
            message="Confirmation did not match the exact existing network and requested IPv4/DHCP settings.",
        )

    with _LOCK:
        current, error = _observe_network_ipv4_configuration_target(
            scope,
            name,
            ipv4_cidr,
            dhcp_action,
            dhcp_start,
            dhcp_end,
        )
        if error or current is None or current.state_digest != target.state_digest:
            return LibvirtNetworkIPv4ConfigurationResponse(
                success=False,
                **response_fields,
                active=False,
                persistent=True,
                user_confirmed=True,
                message=error or "The existing network or host IPv4 state changed after confirmation; inspect it and confirm again.",
            )
        env = virsh_environment()
        binary = find_session_binary("virsh", env)
        if not binary:
            return LibvirtNetworkIPv4ConfigurationResponse(
                success=False,
                **response_fields,
                active=False,
                persistent=True,
                user_confirmed=True,
                message="The optional virsh command became unavailable; no network definition was changed.",
            )
        try:
            xml = _network_xml(
                target.name,
                target.definition,
                uuid=target.uuid,
                existing_bridge_name=target.bridge_name,
            )
        except ValueError:
            return LibvirtNetworkIPv4ConfigurationResponse(
                success=False,
                **response_fields,
                active=False,
                persistent=True,
                user_confirmed=True,
                message="A bounded network definition could not be generated.",
            )
        command_error: str | None = None
        output: str | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="linux-mcp-network-") as temp_dir:
                os.chmod(temp_dir, 0o700)
                xml_path = _write_xml(xml, temp_dir)
                if xml_path is None:
                    return LibvirtNetworkIPv4ConfigurationResponse(
                        success=False,
                        **response_fields,
                        active=False,
                        persistent=True,
                        user_confirmed=True,
                        message="A private temporary network definition could not be written.",
                    )
                output, command_error, truncated = run_bounded_command(
                    [binary, "--quiet", "--no-pkttyagent", "--connect", SCOPED_URIS[scope], "net-define", "--validate", xml_path],
                    env,
                    command_label=f"local libvirt {scope} IPv4 network reconfiguration",
                    timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                    max_output_bytes=16 * 1024,
                )
                if truncated:
                    command_error = command_error or "virsh network-reconfiguration output exceeded its limit"
        except OSError:
            command_error = "a private temporary directory could not be created"

        verified_uuid, actual_bridge, verification_error = _verify_network(
            scope,
            name,
            target.definition,
            binary,
            env,
        )
        final_info, final_info_error = _read_resource_info("network", scope, name, binary, env)
        state_verified = bool(
            verified_uuid == target.uuid
            and actual_bridge == target.bridge_name
            and final_info is not None
            and final_info.uuid == target.uuid
            and final_info.active is False
            and final_info.persistent is True
            and final_info.autostart == target.autostart
        )
        if command_error:
            message = "The network redefinition command reported an error; inspect the local libvirt network before retrying."
        elif state_verified:
            message = "The inactive persistent libvirt network's IPv4/DHCP definition was updated and verified; its forwarding mode and bridge were preserved."
        else:
            message = "The network definition was attempted but could not be fully verified; inspect libvirt before retrying."
        verify_error = verification_error or final_info_error
        if verify_error:
            message += f" {verify_error[:240]}"
        return LibvirtNetworkIPv4ConfigurationResponse(
            success=command_error is None and output is not None and state_verified,
            **response_fields,
            active=final_info.active if final_info is not None else None,
            persistent=final_info.persistent if final_info is not None else None,
            state_verified=state_verified,
            user_confirmed=True,
            message=message,
        )


def perform_libvirt_network_create(
    scope: str,
    name: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> LibvirtNetworkCreateResponse:
    """Preserve the isolated-network tool while sharing the exact validator."""
    return _perform_network_definition(
        scope,
        name,
        "isolated",
        "",
        "",
        "",
        "",
        confirmation_phrase,
        confirmed=confirmed,
    )


def perform_libvirt_network_definition(
    scope: str,
    name: str,
    forward_mode: str,
    bridge_name: str,
    ipv4_cidr: str,
    dhcp_start: str,
    dhcp_end: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> LibvirtNetworkCreateResponse:
    return _perform_network_definition(
        scope,
        name,
        forward_mode,
        bridge_name,
        ipv4_cidr,
        dhcp_start,
        dhcp_end,
        confirmation_phrase,
        confirmed=confirmed,
    )
