"""Confirmed, bounded systemd-networkd .network profile creation, edits, and deletion."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    SystemdNetworkProfileConfigResponse,
    SystemdNetworkProfileCreateResponse,
    SystemdNetworkProfileDeleteResponse,
)
from wayland_mcp.tools.filesystem_write import (
    TextFileReplacementTarget,
    TextFileDeletionTarget,
    replace_text_file,
    text_file_replacement_confirmation_details,
    delete_text_file,
    text_file_deletion_confirmation_details,
    TextFileCreationTarget,
    create_text_file,
    text_file_creation_confirmation_details,
)
from wayland_mcp.tools.systemd_network_profiles import (
    NETWORK_CONFIG_ROOTS,
    _ProfileCandidate,
    _collect_candidates,
    _is_dev_null_symlink,
)

NetworkDHCP = Literal["yes", "no", "ipv4", "ipv6"]
MAX_NETWORK_PROFILE_BYTES = 64 * 1024
MAX_NETWORK_TOTAL_BYTES = 8 * 1024 * 1024
MAX_NETWORK_CANDIDATES = 1024
MAX_LIST_VALUES = 32
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
PROFILE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.@+-]{1,247}\.network$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9_.~+*-]{1,253}$")
SECTION_RE = re.compile(r"^\s*\[([^\]\r\n]+)\]\s*(?:[#;].*)?$")
ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*=(.*)$")
MANAGED_DIRECTIVE_SETTINGS = {
    "dhcp": "dhcp",
    "address": "addresses",
    "gateway": "gateway",
    "dns": "dns_servers",
    "domains": "domains",
    "dnsdefaultroute": "dns_default_route",
    "bridge": "bridge",
    "bond": "bond",
    "vlan": "vlans",
}
MANAGED_KEYS = frozenset(MANAGED_DIRECTIVE_SETTINGS)
SOURCE_ORDER = {name: index for index, (name, _path) in enumerate(NETWORK_CONFIG_ROOTS)}
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _ConfigFileState:
    path: str
    source: str
    filename: str
    profile_filename: str | None
    file_type: str
    is_drop_in: bool
    identity: tuple[int, ...]
    sha256: str
    contents: bytes


@dataclass(frozen=True, slots=True)
class _ParsedNetwork:
    text: str
    lines: tuple[str, ...]
    sections: tuple[str | None, ...]
    assignments: tuple[tuple[int, str, str, str], ...]
    match_names: tuple[str, ...]
    match_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SystemdNetworkProfileTarget:
    filename: str
    interface: str
    dhcp: str | None
    addresses: tuple[str, ...] | None
    gateway: str | None
    clear_gateway: bool
    dns_servers: tuple[str, ...] | None
    domains: tuple[str, ...] | None
    dns_default_route: bool | None
    bridge: str | None
    clear_bridge_membership: bool
    bond: str | None
    clear_bond_membership: bool
    vlans: tuple[str, ...] | None
    changed_settings: tuple[str, ...]
    previous_settings: tuple[tuple[str, object], ...]
    current_text: str
    replacement_text: str
    file_target: TextFileReplacementTarget
    state_token: str


@dataclass(frozen=True, slots=True)
class SystemdNetworkProfileCreationTarget:
    filename: str
    interface: str
    settings: tuple[tuple[str, object], ...]
    changed_settings: tuple[str, ...]
    content: str
    file_target: TextFileCreationTarget
    directory_identity: tuple[int, ...]
    network_state_sha256: str
    state_token: str


@dataclass(frozen=True, slots=True)
class SystemdNetworkProfileDeletionTarget:
    filename: str
    interface: str
    file_target: TextFileDeletionTarget
    directory_identity: tuple[int, ...]
    network_state_sha256: str
    remaining_network_state_sha256: str
    state_token: str


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _safe_systemd_network_directory() -> tuple[int, ...] | None:
    path = Path("/etc/systemd/network")
    try:
        if path.resolve(strict=True) != path:
            return None
        info = path.stat(follow_symlinks=False)
        for parent in reversed(path.parents):
            parent_info = parent.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != 0
                or parent_info.st_mode & 0o022
            ):
                return None
    except (OSError, RuntimeError, ValueError):
        return None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or not os.access(path, os.W_OK)
    ):
        return None
    return _file_identity(info)


def _safe_candidate_parent(path: Path) -> bool:
    try:
        parent = path.parent
        if parent.resolve(strict=True) != parent:
            return False
        current = parent
        while True:
            info = current.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o022
            ):
                return False
            if current == current.parent:
                return True
            current = current.parent
    except (OSError, RuntimeError, ValueError):
        return False


def _read_candidate(candidate: _ProfileCandidate) -> tuple[_ConfigFileState | None, str | None]:
    if not _safe_candidate_parent(candidate.path):
        return None, "A systemd network configuration directory has unsafe ownership, permissions, or symlinked components."
    if candidate.is_symlink:
        if _is_dev_null_symlink(candidate.path):
            try:
                info = candidate.path.lstat()
                target = os.readlink(candidate.path)
                after = candidate.path.lstat()
                after_target = os.readlink(candidate.path)
            except OSError:
                return None, "A masked systemd network profile changed while it was inspected."
            if _file_identity(info) != _file_identity(after) or target != after_target:
                return None, "A masked systemd network profile changed while it was inspected."
            material = f"symlink:{target}".encode("utf-8", errors="surrogateescape")
            return _ConfigFileState(
                path=str(candidate.path),
                source=candidate.source,
                filename=candidate.filename,
                profile_filename=candidate.profile_filename,
                file_type=candidate.file_type,
                is_drop_in=candidate.is_drop_in,
                identity=_file_identity(info),
                sha256=hashlib.sha256(material).hexdigest(),
                contents=b"",
            ), None
        return None, "A non-mask symlink in systemd network configuration prevents safe precedence checking."

    descriptor: int | None = None
    try:
        path = candidate.path
        if path.resolve(strict=True) != path:
            return None, "A systemd network profile has a symlinked path component."
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or before.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
            or before.st_size > MAX_NETWORK_PROFILE_BYTES
        ):
            return None, "A systemd network profile is not a bounded, root-owned, single-link regular file protected from group/other writes."
        contents = bytearray()
        while len(contents) <= MAX_NETWORK_PROFILE_BYTES:
            chunk = os.read(descriptor, min(32 * 1024, MAX_NETWORK_PROFILE_BYTES + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
        after = os.fstat(descriptor)
        if len(contents) > MAX_NETWORK_PROFILE_BYTES or _file_identity(before) != _file_identity(after):
            return None, "A systemd network profile changed or exceeded its read bound."
        path_info = path.lstat()
        if not stat.S_ISREG(path_info.st_mode) or _file_identity(after) != _file_identity(path_info):
            return None, "A systemd network profile path changed while it was inspected."
        raw = bytes(contents)
        return _ConfigFileState(
            path=str(path),
            source=candidate.source,
            filename=candidate.filename,
            profile_filename=candidate.profile_filename,
            file_type=candidate.file_type,
            is_drop_in=candidate.is_drop_in,
            identity=_file_identity(after),
            sha256=hashlib.sha256(raw).hexdigest(),
            contents=raw,
        ), None
    except (OSError, RuntimeError, ValueError):
        return None, "A systemd network profile could not be safely read."
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _collect_network_state() -> tuple[tuple[_ConfigFileState, ...] | None, str | None]:
    candidates, partial, truncated = _collect_candidates()
    if partial or truncated or len(candidates) > MAX_NETWORK_CANDIDATES:
        return None, "The systemd network profile inventory is partial or over its scan bound; refusing to edit an ambiguous configuration."
    states: list[_ConfigFileState] = []
    total_bytes = 0
    for candidate in candidates:
        if candidate.file_type not in {"network", "netdev"}:
            continue
        state, error = _read_candidate(candidate)
        if error or state is None:
            return None, error or "A systemd network profile could not be inspected."
        total_bytes += len(state.contents)
        if total_bytes > MAX_NETWORK_TOTAL_BYTES:
            return None, "The systemd network profile inventory exceeds its total byte bound."
        states.append(state)
    states.sort(key=lambda item: (item.filename, SOURCE_ORDER.get(item.source, len(SOURCE_ORDER)), item.is_drop_in, item.path))
    return tuple(states), None


def _parse_network_profile(
    contents: bytes,
    *,
    require_match: bool = True,
) -> tuple[_ParsedNetwork | None, str | None]:
    try:
        text = contents.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, "The selected .network profile is not valid UTF-8."
    lines = text.splitlines(keepends=True)
    sections: list[str | None] = []
    assignments: list[tuple[int, str, str, str]] = []
    section: str | None = None
    match_names: list[str] = []
    match_keys: list[str] = []
    for index, raw_line in enumerate(lines):
        body = raw_line.rstrip("\r\n")
        if len(body) > 4096:
            return None, "The selected .network profile contains a line longer than 4096 characters."
        stripped = body.strip()
        if not stripped or stripped.startswith(("#", ";")):
            sections.append(section)
            continue
        section_match = SECTION_RE.fullmatch(body)
        if section_match:
            section = section_match.group(1).strip().casefold()
            if not section:
                return None, "The selected .network profile contains an empty section name."
            sections.append(section)
            continue
        assignment_match = ASSIGNMENT_RE.fullmatch(body)
        if not assignment_match:
            return None, "The selected .network profile contains unsupported INI syntax."
        if section is None:
            return None, "The selected network profile contains an assignment outside a section."
        key = assignment_match.group(1)
        normalized_key = key.casefold()
        raw_value = assignment_match.group(2).strip()
        if section == "match":
            match_keys.append(normalized_key)
            if normalized_key == "name":
                match_names.extend(raw_value.split())
        assignments.append((index, section or "", normalized_key, raw_value))
        sections.append(section)
    if require_match and "match" not in sections:
        return None, "The selected .network profile must have a [Match] section."
    return _ParsedNetwork(text, tuple(lines), tuple(sections), tuple(assignments), tuple(match_names), tuple(match_keys)), None


def _parse_bool(value: str) -> bool | None:
    normalized = value.casefold()
    if normalized in {"yes", "true", "1", "on"}:
        return True
    if normalized in {"no", "false", "0", "off"}:
        return False
    return None


def _canonical_address(value: object, *, require_prefix: bool = False) -> str | None:
    if not isinstance(value, str) or len(value) > 128:
        return None
    if require_prefix and "/" not in value:
        return None
    try:
        return str(ipaddress.ip_interface(value))
    except ValueError:
        return None


def _canonical_ip(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    if parsed.is_unspecified or parsed.is_multicast:
        return None
    return str(parsed)


def _safe_interface(value: object) -> str | None:
    return value if isinstance(value, str) and INTERFACE_RE.fullmatch(value) else None


def _parse_current_settings(parsed: _ParsedNetwork) -> tuple[dict[str, object] | None, str | None]:
    current: dict[str, list[str]] = {key: [] for key in MANAGED_KEYS}
    for _index, section, key, raw_value in parsed.assignments:
        if section != "network" or key not in current:
            continue
        if "#" in raw_value or ";" in raw_value:
            return None, f"The selected profile has an inline comment or unsupported value on {key}; refusing an ambiguous rewrite."
        current[key].append(raw_value)
    result: dict[str, object] = {}
    if len(current["dhcp"]) > 1:
        return None, "The selected profile repeats DHCP=; refusing ambiguous scalar semantics."
    dhcp = current["dhcp"][0].casefold() if current["dhcp"] else None
    if dhcp not in {None, "", "yes", "no", "ipv4", "ipv6"}:
        return None, "The selected profile has an unsupported DHCP= value."
    result["dhcp"] = dhcp or None

    addresses: list[str] = []
    for value in current["address"]:
        if not value:
            addresses.clear()
            continue
        for token in value.split():
            address = _canonical_address(token)
            if address is None:
                return None, "The selected profile has an unsupported Address= value."
            if address not in addresses:
                addresses.append(address)
            if len(addresses) > MAX_LIST_VALUES:
                return None, "The selected profile has too many Address= values."
    result["addresses"] = tuple(addresses)

    gateways: list[str] = []
    for value in current["gateway"]:
        if not value:
            gateways.clear()
            continue
        for token in value.split():
            gateway = _canonical_ip(token)
            if gateway is None:
                return None, "The selected profile has an unsupported Gateway= value."
            gateways.append(gateway)
    if len(gateways) > 1:
        return None, "The selected profile has more than one Gateway= value; refusing an ambiguous gateway update."
    result["gateway"] = gateways[0] if gateways else None

    for key, output_name in (("dns", "dns_servers"), ("domains", "domains")):
        values: list[str] = []
        for raw in current[key]:
            if not raw:
                values.clear()
                continue
            for token in raw.split():
                if key == "dns":
                    value = _canonical_ip(token)
                else:
                    value = token if DOMAIN_RE.fullmatch(token) else None
                if value is None:
                    return None, f"The selected profile has an unsupported {key} value."
                if value not in values:
                    values.append(value)
                if len(values) > MAX_LIST_VALUES:
                    return None, f"The selected profile has too many {key} values."
        result[output_name] = tuple(values)

    if len(current["dnsdefaultroute"]) > 1:
        return None, "The selected profile repeats DNSDefaultRoute=; refusing ambiguous scalar semantics."
    if current["dnsdefaultroute"]:
        parsed_bool = _parse_bool(current["dnsdefaultroute"][0])
        if parsed_bool is None:
            return None, "The selected profile has an unsupported DNSDefaultRoute= value."
    else:
        parsed_bool = None
    result["dns_default_route"] = parsed_bool

    for key in ("bridge", "bond"):
        if len(current[key]) > 1:
            return None, f"The selected profile repeats {key}=; refusing ambiguous virtual-link membership."
        value = current[key][0] if current[key] else ""
        if value and _safe_interface(value) is None:
            return None, f"The selected profile has an unsupported {key}= interface name."
        result[key] = value or None
    vlans: list[str] = []
    for raw in current["vlan"]:
        if not raw:
            vlans.clear()
            continue
        for token in raw.split():
            value = _safe_interface(token)
            if value is None:
                return None, "The selected profile has an unsupported VLAN= interface name."
            if value not in vlans:
                vlans.append(value)
            if len(vlans) > MAX_LIST_VALUES:
                return None, "The selected profile has too many VLAN= assignments."
    result["vlans"] = tuple(vlans)
    return result, None


def _parse_netdev(contents: bytes) -> tuple[str, str] | None:
    parsed, _error = _parse_network_profile(contents, require_match=False)
    if parsed is None or parsed.match_keys:
        return None
    name_values = [value for _idx, section, key, value in parsed.assignments if section == "netdev" and key == "name"]
    kind_values = [value for _idx, section, key, value in parsed.assignments if section == "netdev" and key == "kind"]
    if len(name_values) != 1 or len(kind_values) != 1:
        return None
    name = _safe_interface(name_values[0])
    kind = kind_values[0].casefold()
    if name is None or kind not in {"bridge", "bond", "vlan"}:
        return None
    return name, kind


def _validate_setting_scope(parsed: _ParsedNetwork, requested: dict[str, object]) -> str | None:
    if requested["addresses"] is not None and "address" in parsed.sections:
        return "The profile has separate [Address] sections; address editing is limited to unambiguous [Network] Address= entries."
    if (requested["gateway"] is not None or requested["clear_gateway"]) and "route" in parsed.sections:
        return "The profile has separate [Route] sections; gateway editing is limited to unambiguous [Network] Gateway= entries."
    return None


def _effective_network_files(states: tuple[_ConfigFileState, ...]) -> tuple[_ConfigFileState, ...]:
    by_name: dict[str, list[_ConfigFileState]] = {}
    for state in states:
        if state.file_type == "network" and not state.is_drop_in:
            by_name.setdefault(state.filename, []).append(state)
    result = []
    for name, candidates in by_name.items():
        candidates.sort(key=lambda item: SOURCE_ORDER.get(item.source, len(SOURCE_ORDER)))
        winner = candidates[0]
        if winner.contents:
            result.append(winner)
    return tuple(sorted(result, key=lambda item: item.filename))


def _verify_profile_precedence(
    states: tuple[_ConfigFileState, ...],
    filename: str,
    interface: str,
) -> str | None:
    if any(state.is_drop_in and state.profile_filename == filename for state in states):
        return "The selected .network profile has drop-ins; edit the effective drop-in set separately before using this bounded profile editor."
    files = _effective_network_files(states)
    target = next((item for item in files if item.filename == filename and item.source == "etc"), None)
    if target is None:
        return "The selected .network file is not the effective /etc profile for its filename."
    try:
        parsed, error = _parse_network_profile(target.contents)
    except (UnicodeDecodeError, ValueError):
        return "The selected .network profile could not be parsed safely."
    if error or parsed is None:
        return error or "The selected .network profile could not be parsed safely."
    if parsed.match_keys != ("name",) or parsed.match_names != (interface,):
        return "The selected profile must match exactly one literal interface name and have no other [Match] criteria."
    for candidate in files:
        if candidate.filename >= filename:
            break
        has_dropin = any(state.is_drop_in and state.profile_filename == candidate.filename for state in states)
        if has_dropin:
            return f"An earlier .network profile ({candidate.filename}) has drop-ins; its effective matching cannot be proven safe."
        candidate_parsed, candidate_error = _parse_network_profile(candidate.contents)
        if candidate_error or candidate_parsed is None:
            return f"An earlier .network profile ({candidate.filename}) cannot be parsed for precedence."
        names = candidate_parsed.match_names
        if not names:
            return f"An earlier .network profile ({candidate.filename}) has no provably disjoint Name= match."
        if any(name.startswith("!") or any(character in name for character in "*?[]") for name in names):
            return f"An earlier .network profile ({candidate.filename}) uses a non-literal Name= pattern that may match this interface."
        if interface in names:
            return f"An earlier .network profile ({candidate.filename}) may match this interface first."
    return None


def _verify_new_profile_precedence(
    states: tuple[_ConfigFileState, ...],
    filename: str,
    interface: str,
    *,
    created_sha256: str | None = None,
) -> str | None:
    same_name = [
        state for state in states
        if (state.file_type == "network" and not state.is_drop_in and state.filename == filename)
    ]
    target_dropins = [
        state for state in states
        if state.is_drop_in and state.file_type == "network" and state.profile_filename == filename
    ]
    if target_dropins:
        return "The target .network filename has drop-ins; this bounded creator does not merge or edit drop-ins."
    if created_sha256 is None:
        if same_name:
            return "A .network file with this filename already exists in a system configuration root."
    elif (
        len(same_name) != 1
        or same_name[0].source != "etc"
        or same_name[0].sha256 != created_sha256
    ):
        return "The created .network file is no longer the sole exact file with this filename."

    for candidate in _effective_network_files(states):
        if candidate.filename >= filename:
            break
        if any(
            state.is_drop_in and state.file_type == "network" and state.profile_filename == candidate.filename
            for state in states
        ):
            return f"An earlier .network profile ({candidate.filename}) has drop-ins; its effective matching cannot be proven safe."
        candidate_parsed, candidate_error = _parse_network_profile(candidate.contents)
        if candidate_error or candidate_parsed is None:
            return f"An earlier .network profile ({candidate.filename}) cannot be parsed for precedence."
        names = candidate_parsed.match_names
        if not names:
            return f"An earlier .network profile ({candidate.filename}) has no provably disjoint Name= match."
        if any(name.startswith("!") or any(character in name for character in "*?[]") for name in names):
            return f"An earlier .network profile ({candidate.filename}) uses a non-literal Name= pattern that may match this interface."
        if interface in names:
            return f"An earlier .network profile ({candidate.filename}) may match this interface first."
    return None


def _network_state_material(states: tuple[_ConfigFileState, ...]) -> list[dict[str, object]]:
    return [
        {
            "path": item.path,
            "source": item.source,
            "filename": item.filename,
            "profile_filename": item.profile_filename,
            "file_type": item.file_type,
            "is_drop_in": item.is_drop_in,
            "identity": list(item.identity),
            "sha256": item.sha256,
        }
        for item in states
    ]


def _network_state_sha256(states: tuple[_ConfigFileState, ...]) -> str:
    encoded = json.dumps(
        _network_state_material(states),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _networkd_virtual_devices(states: tuple[_ConfigFileState, ...]) -> dict[str, set[str]]:
    """Return only unambiguous effective bridge/bond/VLAN definitions."""
    by_filename: dict[str, list[_ConfigFileState]] = {}
    for state in states:
        if state.file_type == "netdev" and not state.is_drop_in:
            by_filename.setdefault(state.filename, []).append(state)

    effective: list[_ConfigFileState] = []
    for filename, candidates in by_filename.items():
        candidates.sort(key=lambda item: SOURCE_ORDER.get(item.source, len(SOURCE_ORDER)))
        winner = candidates[0]
        if winner.contents:
            effective.append(winner)

    definitions: dict[str, list[str]] = {}
    for state in effective:
        if any(item.is_drop_in and item.profile_filename == state.filename for item in states):
            continue
        parsed = _parse_netdev(state.contents)
        if parsed is not None:
            name, kind = parsed
            definitions.setdefault(name, []).append(kind)
    devices: dict[str, set[str]] = {}
    for name, kinds in definitions.items():
        devices[name] = {kinds[0]} if len(kinds) == 1 else set(kinds) | {"__ambiguous__"}
    return devices


def _rewrite_profile(
    parsed: _ParsedNetwork,
    settings: dict[str, object],
    changed_fields: set[str],
) -> str | None:
    generated: list[str] = []
    scalar_fields = (
        ("dhcp", "DHCP"),
        ("gateway", "Gateway"),
        ("dns_default_route", "DNSDefaultRoute"),
        ("bridge", "Bridge"),
        ("bond", "Bond"),
    )
    for key, directive in scalar_fields:
        if key not in changed_fields:
            continue
        value = settings.get(key)
        if value is not None and value != "":
            if isinstance(value, bool):
                encoded = "yes" if value else "no"
            else:
                encoded = str(value)
            generated.append(f"{directive}={encoded}\n")
    for key, directive in (("addresses", "Address"), ("dns_servers", "DNS"), ("domains", "Domains"), ("vlans", "VLAN")):
        if key not in changed_fields:
            continue
        value = settings.get(key)
        if value is None:
            continue
        for item in value:  # type: ignore[union-attr]
            generated.append(f"{directive}={item}\n")

    target_line_indexes = {
        index for index, section, key, _value in parsed.assignments
        if section == "network" and key in MANAGED_DIRECTIVE_SETTINGS
        and MANAGED_DIRECTIVE_SETTINGS[key] in changed_fields
    }
    first_target = min(target_line_indexes) if target_line_indexes else None
    network_section_header = next(
        (index for index, line in enumerate(parsed.lines) if SECTION_RE.fullmatch(line.rstrip("\r\n")) and SECTION_RE.fullmatch(line.rstrip("\r\n")).group(1).strip().casefold() == "network"),
        None,
    )
    if first_target is None and generated and network_section_header is None:
        separator = "" if not parsed.text or parsed.text.endswith(("\n", "\r")) else "\n"
        suffix = "" if not parsed.text else separator
        return f"{parsed.text}{suffix}[Network]\n{''.join(generated)}"
    insertion = first_target if first_target is not None else (network_section_header + 1 if network_section_header is not None else None)
    output: list[str] = []
    for index, line in enumerate(parsed.lines):
        if index == insertion:
            output.extend(generated)
        if index in target_line_indexes:
            continue
        output.append(line)
    if insertion is None and generated:
        if output and not output[-1].endswith(("\n", "\r")):
            output[-1] += "\n"
        output.append("[Network]\n")
        output.extend(generated)
    return "".join(output)


def _normalize_inputs(
    filename: object,
    interface: object,
    dhcp: object,
    addresses: object,
    gateway: object,
    clear_gateway: object,
    dns_servers: object,
    domains: object,
    dns_default_route: object,
    bridge: object,
    clear_bridge_membership: object,
    bond: object,
    clear_bond_membership: object,
    vlans: object,
) -> tuple[dict[str, object] | None, str | None]:
    if not isinstance(filename, str) or not PROFILE_FILENAME_RE.fullmatch(filename):
        return None, "filename must be one safe .network filename, without a path."
    safe_interface = _safe_interface(interface)
    if safe_interface is None:
        return None, "interface must be a literal Linux interface name of at most 15 characters."
    if dhcp is not None and (not isinstance(dhcp, str) or dhcp not in {"yes", "no", "ipv4", "ipv6"}):
        return None, "dhcp must be yes, no, ipv4, or ipv6."
    if not isinstance(clear_gateway, bool) or not isinstance(clear_bridge_membership, bool) or not isinstance(clear_bond_membership, bool):
        return None, "clear flags must be booleans."
    if clear_gateway and gateway is not None:
        return None, "gateway and clear_gateway cannot be used together."
    if clear_bridge_membership and bridge is not None:
        return None, "bridge and clear_bridge_membership cannot be used together."
    if clear_bond_membership and bond is not None:
        return None, "bond and clear_bond_membership cannot be used together."
    normalized: dict[str, object] = {
        "filename": filename,
        "interface": safe_interface,
        "dhcp": dhcp,
        "addresses": None,
        "gateway": None,
        "clear_gateway": clear_gateway,
        "dns_servers": None,
        "domains": None,
        "dns_default_route": dns_default_route,
        "bridge": None,
        "clear_bridge_membership": clear_bridge_membership,
        "bond": None,
        "clear_bond_membership": clear_bond_membership,
        "vlans": None,
    }
    for name, values in (("addresses", addresses), ("dns_servers", dns_servers), ("domains", domains), ("vlans", vlans)):
        if values is None:
            continue
        if not isinstance(values, list) or len(values) > MAX_LIST_VALUES:
            return None, f"{name} must be omitted or contain at most {MAX_LIST_VALUES} values."
        output: list[str] = []
        for raw in values:
            if name == "addresses":
                value = _canonical_address(raw, require_prefix=True)
            elif name == "dns_servers":
                value = _canonical_ip(raw)
            elif name == "domains":
                value = raw if isinstance(raw, str) and DOMAIN_RE.fullmatch(raw) else None
            else:
                value = _safe_interface(raw)
            if value is None:
                return None, f"{name} contains a malformed or unsupported value."
            if value in output:
                return None, f"{name} cannot repeat a value."
            output.append(value)
        normalized[name] = tuple(output)
    if gateway is not None:
        normalized_gateway = _canonical_ip(gateway)
        if normalized_gateway is None:
            return None, "gateway must be one literal IPv4 or IPv6 address."
        normalized["gateway"] = normalized_gateway
    if dns_default_route is not None and not isinstance(dns_default_route, bool):
        return None, "dns_default_route must be a boolean or omitted."
    for name, value in (("bridge", bridge), ("bond", bond)):
        if value is not None:
            safe = _safe_interface(value)
            if safe is None:
                return None, f"{name} must be one literal Linux virtual interface name."
            normalized[name] = safe
    if not (
        normalized["dhcp"] is not None
        or normalized["addresses"] is not None
        or normalized["gateway"] is not None
        or normalized["clear_gateway"]
        or normalized["dns_servers"] is not None
        or normalized["domains"] is not None
        or normalized["dns_default_route"] is not None
        or normalized["bridge"] is not None
        or normalized["clear_bridge_membership"]
        or normalized["bond"] is not None
        or normalized["clear_bond_membership"]
        or normalized["vlans"] is not None
    ):
        return None, "At least one supported network setting must be supplied."
    return normalized, None


def _prepare_target(
    filename: object,
    interface: object,
    dhcp: object = None,
    addresses: object = None,
    gateway: object = None,
    clear_gateway: object = False,
    dns_servers: object = None,
    domains: object = None,
    dns_default_route: object = None,
    bridge: object = None,
    clear_bridge_membership: object = False,
    bond: object = None,
    clear_bond_membership: object = False,
    vlans: object = None,
) -> tuple[SystemdNetworkProfileTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "systemd-networkd profile control is available only on Linux."
    normalized, error = _normalize_inputs(
        filename, interface, dhcp, addresses, gateway, clear_gateway,
        dns_servers, domains, dns_default_route, bridge, clear_bridge_membership,
        bond, clear_bond_membership, vlans,
    )
    if error or normalized is None:
        return None, error
    directory_identity = _safe_systemd_network_directory()
    if directory_identity is None:
        return None, "The root-owned /etc/systemd/network directory must be available and writable with current permissions."
    states, error = _collect_network_state()
    if error or states is None:
        return None, error or "The systemd network profile state could not be inspected."
    filename_text = str(normalized["filename"])
    interface_text = str(normalized["interface"])
    precedence_error = _verify_profile_precedence(states, filename_text, interface_text)
    if precedence_error:
        return None, precedence_error
    target_state = next((state for state in states if state.file_type == "network" and not state.is_drop_in and state.source == "etc" and state.filename == filename_text), None)
    if target_state is None:
        return None, "The exact existing profile file was not found in /etc/systemd/network."
    parsed, error = _parse_network_profile(target_state.contents)
    if error or parsed is None:
        return None, error or "The exact existing profile could not be parsed."
    if parsed.match_keys != ("name",) or parsed.match_names != (interface_text,):
        return None, "The selected profile does not match exactly the supplied interface name."
    scope_error = _validate_setting_scope(parsed, normalized)
    if scope_error:
        return None, scope_error
    current_settings, error = _parse_current_settings(parsed)
    if error or current_settings is None:
        return None, error or "The existing selected network settings are ambiguous."

    new_settings = dict(current_settings)
    changed: list[str] = []
    for key in ("dhcp", "addresses", "dns_servers", "domains", "dns_default_route", "vlans"):
        value = normalized[key]
        if value is not None and value != current_settings[key]:
            new_settings[key] = value
            changed.append(key)
    if normalized["clear_gateway"]:
        if current_settings["gateway"] is not None:
            new_settings["gateway"] = None
            changed.append("gateway")
    elif normalized["gateway"] is not None and normalized["gateway"] != current_settings["gateway"]:
        new_settings["gateway"] = normalized["gateway"]
        changed.append("gateway")
    if normalized["clear_bridge_membership"]:
        if current_settings["bridge"] is not None:
            new_settings["bridge"] = None
            changed.append("bridge")
    elif normalized["bridge"] is not None and normalized["bridge"] != current_settings["bridge"]:
        new_settings["bridge"] = normalized["bridge"]
        changed.append("bridge")
    if normalized["clear_bond_membership"]:
        if current_settings["bond"] is not None:
            new_settings["bond"] = None
            changed.append("bond")
    elif normalized["bond"] is not None and normalized["bond"] != current_settings["bond"]:
        new_settings["bond"] = normalized["bond"]
        changed.append("bond")
    if not changed:
        return None, "The requested values already match the saved profile."
    if any(new_settings[key] == interface_text for key in ("bridge", "bond")):
        return None, "The interface cannot be attached to itself as a bridge or bond member."
    if interface_text in new_settings["vlans"]:
        return None, "The interface cannot declare itself as a VLAN device."
    if new_settings["bridge"] and new_settings["bond"]:
        return None, "A networkd link cannot be assigned to both a bridge and a bond in this operation."
    devices = _networkd_virtual_devices(states)
    for kind_key, kind in (("bridge", "bridge"), ("bond", "bond")):
        name = new_settings[kind_key]
        if name and devices.get(str(name)) != {kind}:
            return None, f"The selected {kind_key} does not resolve to an existing systemd .netdev of kind {kind}."
    for vlan_name in new_settings["vlans"]:
        if devices.get(str(vlan_name)) != {"vlan"}:
            return None, f"VLAN {vlan_name!r} does not resolve to an existing systemd .netdev of kind vlan."

    replacement_text = _rewrite_profile(parsed, new_settings, set(changed))
    if replacement_text is None or replacement_text == parsed.text:
        return None, "The requested change could not be represented as a bounded profile update."
    path = str(Path("/etc/systemd/network") / filename_text)
    file_target, error = text_file_replacement_confirmation_details(path, replacement_text)
    if error or file_target is None:
        return None, error or "The exact existing .network file could not be bound to confirmation."
    if hashlib.sha256(file_target.original).hexdigest() != target_state.sha256:
        return None, "The selected .network file changed while it was being prepared."
    if (file_target.device, file_target.inode) != target_state.identity[:2]:
        return None, "The selected .network file identity changed while it was being prepared."
    request_material = {
        "filename": filename_text,
        "interface": interface_text,
        "requested": normalized,
        "changed": sorted(changed),
        "target_identity": list(target_state.identity),
        "target_sha256": target_state.sha256,
        "replacement_sha256": file_target.replacement_sha256,
        "directory_identity": list(directory_identity),
        "networkd_state": [
            {
                "path": item.path,
                "source": item.source,
                "filename": item.filename,
                "profile_filename": item.profile_filename,
                "file_type": item.file_type,
                "is_drop_in": item.is_drop_in,
                "identity": list(item.identity),
                "sha256": item.sha256,
            }
            for item in states
        ],
    }
    state_token = hashlib.sha256(
        json.dumps(request_material, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("ascii")
    ).hexdigest()
    return SystemdNetworkProfileTarget(
        filename=filename_text,
        interface=interface_text,
        dhcp=new_settings["dhcp"] if "dhcp" in changed else None,
        addresses=new_settings["addresses"] if "addresses" in changed else None,
        gateway=new_settings["gateway"] if "gateway" in changed else None,
        clear_gateway=normalized["clear_gateway"],
        dns_servers=new_settings["dns_servers"] if "dns_servers" in changed else None,
        domains=new_settings["domains"] if "domains" in changed else None,
        dns_default_route=new_settings["dns_default_route"] if "dns_default_route" in changed else None,
        bridge=new_settings["bridge"] if "bridge" in changed else None,
        clear_bridge_membership=normalized["clear_bridge_membership"],
        bond=new_settings["bond"] if "bond" in changed else None,
        clear_bond_membership=normalized["clear_bond_membership"],
        vlans=new_settings["vlans"] if "vlans" in changed else None,
        changed_settings=tuple(sorted(changed)),
        previous_settings=tuple(sorted((key, current_settings[key]) for key in changed)),
        current_text=parsed.text,
        replacement_text=replacement_text,
        file_target=file_target,
        state_token=state_token,
    ), None


def _prepare_creation_target(
    filename: object,
    interface: object,
    dhcp: object = None,
    addresses: object = None,
    gateway: object = None,
    clear_gateway: object = False,
    dns_servers: object = None,
    domains: object = None,
    dns_default_route: object = None,
    bridge: object = None,
    clear_bridge_membership: object = False,
    bond: object = None,
    clear_bond_membership: object = False,
    vlans: object = None,
) -> tuple[SystemdNetworkProfileCreationTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "systemd-networkd profile creation is available only on Linux."
    if os.geteuid() != 0:
        return None, "Creating a systemd network profile requires the MCP server to already run as root; no privilege elevation is requested."
    normalized, error = _normalize_inputs(
        filename, interface, dhcp, addresses, gateway, clear_gateway,
        dns_servers, domains, dns_default_route, bridge, clear_bridge_membership,
        bond, clear_bond_membership, vlans,
    )
    if error or normalized is None:
        return None, error
    if normalized["dhcp"] is None:
        return None, "A new profile must set DHCP explicitly to yes, no, ipv4, or ipv6."
    if normalized["clear_gateway"] or normalized["clear_bridge_membership"] or normalized["clear_bond_membership"]:
        return None, "Clear flags apply only to editing an existing profile and are not accepted during creation."
    for name in ("addresses", "dns_servers", "domains", "vlans"):
        if normalized[name] == ():
            return None, f"{name} must contain at least one value when supplied during profile creation."
    extra_settings = (
        "addresses", "gateway", "dns_servers", "domains", "dns_default_route",
        "bridge", "bond", "vlans",
    )
    if not any(normalized[name] is not None for name in extra_settings):
        return None, "Supply at least one concrete setting in addition to the required DHCP value."

    filename_text = str(normalized["filename"])
    interface_text = str(normalized["interface"])
    if normalized["bridge"] == interface_text or normalized["bond"] == interface_text:
        return None, "The interface cannot be attached to itself as a bridge or bond member."
    if normalized["vlans"] is not None and interface_text in normalized["vlans"]:
        return None, "The interface cannot declare itself as a VLAN device."
    if normalized["bridge"] and normalized["bond"]:
        return None, "A networkd link cannot be assigned to both a bridge and a bond in this operation."

    directory_identity = _safe_systemd_network_directory()
    if directory_identity is None:
        return None, "The root-owned /etc/systemd/network directory must be available and writable with current permissions."
    states, error = _collect_network_state()
    if error or states is None:
        return None, error or "The systemd network profile state could not be inspected."
    precedence_error = _verify_new_profile_precedence(states, filename_text, interface_text)
    if precedence_error:
        return None, precedence_error

    devices = _networkd_virtual_devices(states)
    for kind_key, kind in (("bridge", "bridge"), ("bond", "bond")):
        name = normalized[kind_key]
        if name and devices.get(str(name)) != {kind}:
            return None, f"The selected {kind_key} does not resolve to an existing systemd .netdev of kind {kind}."
    for vlan_name in normalized["vlans"] or ():
        if devices.get(str(vlan_name)) != {"vlan"}:
            return None, f"VLAN {vlan_name!r} does not resolve to an existing systemd .netdev of kind vlan."

    lines = ["[Match]", f"Name={interface_text}", "", "[Network]", f"DHCP={normalized['dhcp']}"]
    for field, directive in (
        ("addresses", "Address"),
        ("gateway", "Gateway"),
        ("dns_servers", "DNS"),
        ("domains", "Domains"),
        ("dns_default_route", "DNSDefaultRoute"),
        ("bridge", "Bridge"),
        ("bond", "Bond"),
        ("vlans", "VLAN"),
    ):
        value = normalized[field]
        if value is None:
            continue
        if field == "dns_default_route":
            lines.append(f"{directive}={'yes' if value else 'no'}")
        elif isinstance(value, tuple):
            lines.extend(f"{directive}={item}" for item in value)
        else:
            lines.append(f"{directive}={value}")
    content = "\n".join(lines) + "\n"
    path = str(Path("/etc/systemd/network") / filename_text)
    file_target, error = text_file_creation_confirmation_details(path, content)
    if error or file_target is None:
        return None, error or "The exact new .network file could not be bound to confirmation."
    if file_target.path != Path(path) or (file_target.parent_device, file_target.parent_inode) != directory_identity[:2]:
        return None, "The profile directory or canonical target path changed while creation was prepared."

    changed_settings = tuple(sorted(name for name in ("dhcp", *extra_settings) if normalized[name] is not None))
    normalized_settings = tuple(sorted((name, normalized[name]) for name in ("dhcp", *extra_settings) if normalized[name] is not None))
    network_state_sha = _network_state_sha256(states)
    request_material = {
        "filename": filename_text,
        "interface": interface_text,
        "settings": normalized_settings,
        "content_sha256": file_target.content_sha256,
        "directory_identity": list(directory_identity),
        "network_state": _network_state_material(states),
    }
    state_token = hashlib.sha256(
        json.dumps(request_material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return SystemdNetworkProfileCreationTarget(
        filename=filename_text,
        interface=interface_text,
        settings=normalized_settings,
        changed_settings=changed_settings,
        content=content,
        file_target=file_target,
        directory_identity=directory_identity,
        network_state_sha256=network_state_sha,
        state_token=state_token,
    ), None


def systemd_network_profile_creation_confirmation_details(
    filename: str,
    interface: str,
    dhcp: str,
    addresses: list[str] | None = None,
    gateway: str | None = None,
    dns_servers: list[str] | None = None,
    domains: list[str] | None = None,
    dns_default_route: bool | None = None,
    bridge: str | None = None,
    bond: str | None = None,
    vlans: list[str] | None = None,
) -> tuple[SystemdNetworkProfileCreationTarget | None, str | None]:
    return _prepare_creation_target(
        filename, interface, dhcp, addresses, gateway, False,
        dns_servers, domains, dns_default_route, bridge, False, bond, False, vlans,
    )


def create_systemd_network_profile(
    filename: str,
    interface: str,
    dhcp: str,
    addresses: list[str] | None = None,
    gateway: str | None = None,
    dns_servers: list[str] | None = None,
    domains: list[str] | None = None,
    dns_default_route: bool | None = None,
    bridge: str | None = None,
    bond: str | None = None,
    vlans: list[str] | None = None,
    *,
    confirmed: bool,
    confirmed_filename: str | None = None,
    confirmed_interface: str | None = None,
    state_token: str | None = None,
) -> SystemdNetworkProfileCreateResponse:
    target, error = systemd_network_profile_creation_confirmation_details(
        filename, interface, dhcp, addresses, gateway, dns_servers, domains,
        dns_default_route, bridge, bond, vlans,
    )
    if error or target is None:
        return SystemdNetworkProfileCreateResponse(
            success=False,
            filename=filename if isinstance(filename, str) else None,
            interface=interface if isinstance(interface, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The systemd network profile could not be verified.",
        )
    if not confirmed:
        return SystemdNetworkProfileCreateResponse(
            success=False,
            filename=target.filename,
            interface=target.interface,
            configured_settings=list(target.changed_settings),
            user_confirmed=False,
            message="Explicit client confirmation is required; no profile was created.",
        )
    if (
        confirmed_filename != target.filename
        or confirmed_interface != target.interface
        or state_token != target.state_token
    ):
        return SystemdNetworkProfileCreateResponse(
            success=False,
            filename=target.filename,
            interface=target.interface,
            configured_settings=list(target.changed_settings),
            user_confirmed=True,
            message="The confirmation did not repeat the exact filename, interface, and state token; no profile was created.",
        )

    with _ACTION_LOCK:
        current, error = systemd_network_profile_creation_confirmation_details(
            filename, interface, dhcp, addresses, gateway, dns_servers, domains,
            dns_default_route, bridge, bond, vlans,
        )
        if error or current is None or current.state_token != state_token:
            return SystemdNetworkProfileCreateResponse(
                success=False,
                filename=target.filename,
                interface=target.interface,
                configured_settings=list(target.changed_settings),
                user_confirmed=True,
                message=error or "The profile directory or networkd configuration changed after confirmation; no profile was created.",
            )
        file_result = create_text_file(
            str(target.file_target.path),
            target.content,
            confirmed=True,
            confirmed_path=str(target.file_target.path),
            confirmed_content_sha256=target.file_target.content_sha256,
        )
        if not file_result.success:
            return SystemdNetworkProfileCreateResponse(
                success=False,
                created=file_result.created,
                filename=target.filename,
                interface=target.interface,
                configured_settings=list(target.changed_settings),
                settings_sha256=target.file_target.content_sha256,
                user_confirmed=True,
                message=file_result.message,
            )

        created_states, state_error = _collect_network_state()
        if state_error or created_states is None:
            return SystemdNetworkProfileCreateResponse(
                success=False,
                created=True,
                filename=target.filename,
                interface=target.interface,
                configured_settings=list(target.changed_settings),
                settings_sha256=target.file_target.content_sha256,
                user_confirmed=True,
                message="The profile was created, but the networkd state could not be rechecked; inspect the file before applying it.",
            )
        created_path = str(target.file_target.path)
        created_state = next((
            item for item in created_states
            if item.file_type == "network" and not item.is_drop_in and item.source == "etc"
            and item.filename == target.filename and item.path == created_path
        ), None)
        filtered_states = tuple(
            item for item in created_states
            if not (item.file_type == "network" and not item.is_drop_in and item.source == "etc"
                    and item.filename == target.filename and item.path == created_path)
        )
        precedence_error = _verify_new_profile_precedence(
            created_states, target.filename, target.interface,
            created_sha256=target.file_target.content_sha256,
        )
        directory_after = _safe_systemd_network_directory()
        directory_identity_ok = (
            directory_after is not None
            and directory_after[:2] == target.directory_identity[:2]
            and directory_after[2:6] == target.directory_identity[2:6]
        )
        if (
            created_state is None
            or created_state.sha256 != target.file_target.content_sha256
            or not directory_identity_ok
            or _network_state_sha256(filtered_states) != target.network_state_sha256
            or precedence_error
        ):
            return SystemdNetworkProfileCreateResponse(
                success=False,
                created=True,
                filename=target.filename,
                interface=target.interface,
                configured_settings=list(target.changed_settings),
                settings_sha256=target.file_target.content_sha256,
                user_confirmed=True,
                message=(
                    "The profile was created, but the networkd state changed during post-write verification; "
                    "inspect the file and current precedence before applying it."
                ),
            )
    return SystemdNetworkProfileCreateResponse(
        success=True,
        created=True,
        filename=target.filename,
        interface=target.interface,
        configured_settings=list(target.changed_settings),
        settings_sha256=target.file_target.content_sha256,
        user_confirmed=True,
        message="Created the exact root-owned systemd-networkd profile and verified its content and precedence. No networkd reload or reconfigure was requested.",
    )


def _prepare_deletion_target(
    filename: object,
    interface: object,
) -> tuple[SystemdNetworkProfileDeletionTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "systemd-networkd profile deletion is available only on Linux."
    if not isinstance(filename, str) or not PROFILE_FILENAME_RE.fullmatch(filename):
        return None, "filename must be one exact safe .network filename, without a path."
    safe_interface = _safe_interface(interface)
    if safe_interface is None:
        return None, "interface must be a literal Linux interface name of at most 15 characters."
    directory_identity = _safe_systemd_network_directory()
    if directory_identity is None:
        return None, "The root-owned /etc/systemd/network directory must be available and writable with current permissions."
    states, error = _collect_network_state()
    if error or states is None:
        return None, error or "The systemd network profile state could not be inspected."
    path = str(Path("/etc/systemd/network") / filename)
    matches = [
        state for state in states
        if state.file_type == "network" and not state.is_drop_in and state.source == "etc"
        and state.filename == filename and state.path == path
    ]
    if len(matches) != 1:
        return None, "The exact /etc/systemd/network profile is missing or ambiguous."
    fallback_profiles = [
        state for state in states
        if state.file_type == "network" and not state.is_drop_in and state.filename == filename
        and state.path != path
    ]
    if fallback_profiles:
        return None, "A same-named profile exists in another systemd network directory; deletion could expose that fallback profile."
    precedence_error = _verify_profile_precedence(states, filename, safe_interface)
    if precedence_error:
        return None, precedence_error
    state = matches[0]
    if (
        len(state.identity) < 6
        or state.identity[4] != 0
        or state.identity[3] != 1
        or state.identity[2] & 0o022
    ):
        return None, "The exact profile must be root-owned, single-link, and not writable by group or other."
    deletion_target, error = text_file_deletion_confirmation_details(path)
    if error or deletion_target is None:
        return None, error or "The exact profile file could not be safely bound to deletion."
    if (
        deletion_target.path != Path(path)
        or (deletion_target.parent_device, deletion_target.parent_inode) != directory_identity[:2]
        or deletion_target.current_sha256 != state.sha256
    ):
        return None, "The canonical profile path, parent directory, or file digest changed during deletion preparation."
    remaining_states = tuple(item for item in states if item.path != path)
    remaining_sha = _network_state_sha256(remaining_states)
    material = {
        "filename": filename,
        "interface": safe_interface,
        "file_sha256": state.sha256,
        "file_identity": list(state.identity),
        "directory_identity": list(directory_identity),
        "network_state": _network_state_material(states),
    }
    state_token = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return SystemdNetworkProfileDeletionTarget(
        filename=filename,
        interface=safe_interface,
        file_target=deletion_target,
        directory_identity=directory_identity,
        network_state_sha256=_network_state_sha256(states),
        remaining_network_state_sha256=remaining_sha,
        state_token=state_token,
    ), None


def systemd_network_profile_deletion_confirmation_details(
    filename: str,
    interface: str,
) -> tuple[SystemdNetworkProfileDeletionTarget | None, str | None]:
    return _prepare_deletion_target(filename, interface)


def delete_systemd_network_profile(
    filename: str,
    interface: str,
    *,
    confirmed: bool,
    confirmed_filename: str | None = None,
    confirmed_interface: str | None = None,
    state_token: str | None = None,
) -> SystemdNetworkProfileDeleteResponse:
    target, error = systemd_network_profile_deletion_confirmation_details(filename, interface)
    if error or target is None:
        return SystemdNetworkProfileDeleteResponse(
            success=False,
            filename=filename if isinstance(filename, str) else None,
            interface=interface if isinstance(interface, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The exact systemd network profile could not be verified.",
        )
    if confirmed is not True:
        return SystemdNetworkProfileDeleteResponse(
            success=False,
            filename=target.filename,
            interface=target.interface,
            user_confirmed=False,
            message="Explicit client confirmation is required; no profile was deleted.",
        )
    if (
        confirmed_filename != target.filename
        or confirmed_interface != target.interface
        or state_token != target.state_token
    ):
        return SystemdNetworkProfileDeleteResponse(
            success=False,
            filename=target.filename,
            interface=target.interface,
            user_confirmed=True,
            message="Confirmation did not repeat the exact profile filename, interface, and state token; no profile was deleted.",
        )

    with _ACTION_LOCK:
        current, error = systemd_network_profile_deletion_confirmation_details(filename, interface)
        if error or current is None or current.state_token != target.state_token:
            return SystemdNetworkProfileDeleteResponse(
                success=False,
                filename=target.filename,
                interface=target.interface,
                user_confirmed=True,
                message=error or "The profile or networkd configuration changed after confirmation; no profile was deleted.",
            )
        result = delete_text_file(
            str(target.file_target.path),
            confirmed=True,
            confirmed_path=str(target.file_target.path),
            confirmed_current_sha256=target.file_target.current_sha256,
        )
        if not result.deleted:
            return SystemdNetworkProfileDeleteResponse(
                success=False,
                deleted=False,
                filename=target.filename,
                interface=target.interface,
                user_confirmed=True,
                message=result.message,
            )
        after, state_error = _collect_network_state()
        directory_after = _safe_systemd_network_directory()
        verified = (
            state_error is None
            and after is not None
            and not any(item.path == str(target.file_target.path) for item in after)
            and _network_state_sha256(after) == target.remaining_network_state_sha256
            and directory_after is not None
            and directory_after[:2] == target.directory_identity[:2]
        )
        if not verified:
            detail = state_error or "the file remains visible or another network profile changed"
            return SystemdNetworkProfileDeleteResponse(
                success=False,
                deleted=True,
                filename=target.filename,
                interface=target.interface,
                state_verified=False,
                user_confirmed=True,
                message=f"The profile path was deleted, but networkd configuration verification failed ({detail[:300]}). Inspect the profile directories before retrying.",
            )
    return SystemdNetworkProfileDeleteResponse(
        success=True,
        deleted=True,
        filename=target.filename,
        interface=target.interface,
        state_verified=True,
        user_confirmed=True,
        message="Deleted the exact confirmed /etc/systemd/network profile and verified its absence. Networkd was not reloaded or reconfigured.",
    )


def systemd_network_profile_control_available() -> bool:
    return sys.platform.startswith("linux") and _safe_systemd_network_directory() is not None


def systemd_network_profile_confirmation_details(
    filename: str,
    interface: str,
    dhcp: str | None = None,
    addresses: list[str] | None = None,
    gateway: str | None = None,
    clear_gateway: bool = False,
    dns_servers: list[str] | None = None,
    domains: list[str] | None = None,
    dns_default_route: bool | None = None,
    bridge: str | None = None,
    clear_bridge_membership: bool = False,
    bond: str | None = None,
    clear_bond_membership: bool = False,
    vlans: list[str] | None = None,
) -> tuple[SystemdNetworkProfileTarget | None, str | None]:
    return _prepare_target(
        filename, interface, dhcp, addresses, gateway, clear_gateway,
        dns_servers, domains, dns_default_route, bridge, clear_bridge_membership,
        bond, clear_bond_membership, vlans,
    )


def configure_systemd_network_profile(
    filename: str,
    interface: str,
    dhcp: str | None,
    addresses: list[str] | None,
    gateway: str | None,
    clear_gateway: bool,
    dns_servers: list[str] | None,
    domains: list[str] | None,
    dns_default_route: bool | None,
    bridge: str | None,
    clear_bridge_membership: bool,
    bond: str | None,
    clear_bond_membership: bool,
    vlans: list[str] | None,
    *,
    confirmed: bool,
    confirmed_filename: str | None = None,
    confirmed_interface: str | None = None,
    state_token: str | None = None,
) -> SystemdNetworkProfileConfigResponse:
    target, error = systemd_network_profile_confirmation_details(
        filename, interface, dhcp, addresses, gateway, clear_gateway,
        dns_servers, domains, dns_default_route, bridge, clear_bridge_membership,
        bond, clear_bond_membership, vlans,
    )
    if error or target is None:
        return SystemdNetworkProfileConfigResponse(
            success=False,
            filename=filename if isinstance(filename, str) else None,
            interface=interface if isinstance(interface, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The systemd network profile could not be verified.",
        )
    if not confirmed:
        return SystemdNetworkProfileConfigResponse(
            success=False,
            filename=target.filename,
            interface=target.interface,
            changed_settings=list(target.changed_settings),
            user_confirmed=False,
            message="Explicit client confirmation is required; the saved profile was not changed.",
        )
    if (
        confirmed_filename != target.filename
        or confirmed_interface != target.interface
        or state_token != target.state_token
    ):
        return SystemdNetworkProfileConfigResponse(
            success=False,
            filename=target.filename,
            interface=target.interface,
            changed_settings=list(target.changed_settings),
            user_confirmed=True,
            message="Confirmation did not repeat the exact profile filename, interface, and state token.",
        )

    with _ACTION_LOCK:
        current, error = systemd_network_profile_confirmation_details(
            filename, interface, dhcp, addresses, gateway, clear_gateway,
            dns_servers, domains, dns_default_route, bridge, clear_bridge_membership,
            bond, clear_bond_membership, vlans,
        )
        if error or current is None or current.state_token != target.state_token:
            return SystemdNetworkProfileConfigResponse(
                success=False,
                filename=target.filename,
                interface=target.interface,
                changed_settings=list(target.changed_settings),
                user_confirmed=True,
                message=error or "The profile, precedence, virtual-device, or configuration-root state changed after confirmation.",
            )
        response = replace_text_file(
            str(target.file_target.path),
            target.replacement_text,
            confirmed=True,
            confirmed_path=str(target.file_target.path),
            confirmed_current_sha256=target.file_target.current_sha256,
            confirmed_replacement_sha256=target.file_target.replacement_sha256,
        )
        if not response.success:
            return SystemdNetworkProfileConfigResponse(
                success=False,
                filename=target.filename,
                interface=target.interface,
                changed_settings=list(target.changed_settings),
                user_confirmed=True,
                message=response.message,
            )
        return SystemdNetworkProfileConfigResponse(
            success=True,
            filename=target.filename,
            interface=target.interface,
            changed_settings=list(target.changed_settings),
            settings_sha256=response.sha256,
            user_confirmed=True,
            message=(
                "Updated the exact persistent systemd .network profile and verified its contents. "
                "The tool did not run networkctl reload or reconfigure; applying saved settings later may change routes or disconnect this client."
            ),
        )
