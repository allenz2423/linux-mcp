"""Confirmed, bounded systemd-networkd virtual-device profile administration."""

from __future__ import annotations

import hashlib
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    SystemdNetDevConfigResponse,
    SystemdNetDevCreateResponse,
    SystemdNetDevDeleteResponse,
)
from wayland_mcp.tools.filesystem_write import (
    TextFileCreationTarget,
    TextFileDeletionTarget,
    TextFileReplacementTarget,
    create_text_file,
    delete_text_file,
    replace_text_file,
    text_file_creation_confirmation_details,
    text_file_deletion_confirmation_details,
    text_file_replacement_confirmation_details,
)
from wayland_mcp.tools.systemd_network_profile_control import (
    _ACTION_LOCK,
    _ConfigFileState,
    _collect_network_state,
    _parse_network_profile,
    _parse_netdev,
    _network_state_sha256,
    _networkd_virtual_devices,
    _safe_systemd_network_directory,
)

NETDEV_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.@+-]{1,247}\.netdev$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
NETDEV_SYSFS_ROOT = Path("/sys/class/net")
BondMode = Literal[
    "balance-rr",
    "active-backup",
    "balance-xor",
    "broadcast",
    "802.3ad",
    "balance-tlb",
    "balance-alb",
]
DeviceKind = Literal["bridge", "bond", "vlan"]


@dataclass(frozen=True, slots=True)
class SystemdNetDevCreationTarget:
    filename: str
    name: str
    kind: DeviceKind
    configured_settings: tuple[str, ...]
    content: str
    file_target: TextFileCreationTarget
    directory_identity: tuple[int, ...]
    network_state_sha256: str
    state_token: str


@dataclass(frozen=True, slots=True)
class SystemdNetDevConfigTarget:
    filename: str
    name: str
    kind: DeviceKind
    changed_settings: tuple[str, ...]
    previous_settings: tuple[tuple[str, str], ...]
    new_settings: tuple[tuple[str, str], ...]
    replacement_text: str
    file_target: TextFileReplacementTarget
    directory_identity: tuple[int, ...]
    network_state_sha256: str
    other_network_state_sha256: str
    state_token: str


@dataclass(frozen=True, slots=True)
class SystemdNetDevDeletionTarget:
    filename: str
    name: str
    kind: DeviceKind
    file_target: TextFileDeletionTarget
    directory_identity: tuple[int, ...]
    network_state_sha256: str
    remaining_network_state_sha256: str
    state_token: str


def _normalize_request(
    filename: object,
    name: object,
    kind: object,
    bridge_stp: object,
    vlan_filtering: object,
    bond_mode: object,
    vlan_id: object,
) -> tuple[dict[str, object] | None, str | None]:
    if not isinstance(filename, str) or not NETDEV_FILENAME_RE.fullmatch(filename):
        return None, "filename must be one exact safe .netdev filename, without a path."
    if not isinstance(name, str) or not INTERFACE_RE.fullmatch(name):
        return None, "name must be a literal Linux interface name of at most 15 characters."
    if not isinstance(kind, str) or kind not in {"bridge", "bond", "vlan"}:
        return None, "kind must be bridge, bond, or vlan."
    if bridge_stp is not None and type(bridge_stp) is not bool:
        return None, "bridge_stp must be a boolean when supplied."
    if vlan_filtering is not None and type(vlan_filtering) is not bool:
        return None, "vlan_filtering must be a boolean when supplied."
    if kind != "bridge" and (bridge_stp is not None or vlan_filtering is not None):
        return None, "bridge_stp and vlan_filtering apply only to bridge devices."
    if kind == "bridge" and (bond_mode is not None or vlan_id is not None):
        return None, "bond_mode and vlan_id do not apply to bridge devices."
    if kind == "bond" and (bridge_stp is not None or vlan_filtering is not None or vlan_id is not None):
        return None, "Only bond_mode applies to bond devices."
    if kind == "vlan" and (bridge_stp is not None or vlan_filtering is not None or bond_mode is not None):
        return None, "Only vlan_id applies to VLAN devices."
    if kind == "bond" and (
        not isinstance(bond_mode, str) or bond_mode not in {
        "balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb",
        }
    ):
        return None, "bond_mode must be one supported Linux bonding mode."
    if kind != "bond" and bond_mode is not None:
        return None, "bond_mode applies only to bond devices."
    if kind == "vlan" and (
        not isinstance(vlan_id, int)
        or isinstance(vlan_id, bool)
        or not 1 <= vlan_id <= 4094
    ):
        return None, "vlan_id must be an integer from 1 through 4094 for a VLAN device."
    if kind != "vlan" and vlan_id is not None:
        return None, "vlan_id applies only to VLAN devices."

    settings: list[str] = []
    lines = ["[NetDev]", f"Name={name}", f"Kind={kind}"]
    if kind == "bridge":
        if bridge_stp is not None or vlan_filtering is not None:
            lines.extend(["", "[Bridge]"])
        if bridge_stp is not None:
            lines.append(f"STP={'yes' if bridge_stp else 'no'}")
            settings.append("STP")
        if vlan_filtering is not None:
            lines.append(f"VLANFiltering={'yes' if vlan_filtering else 'no'}")
            settings.append("VLANFiltering")
    elif kind == "bond":
        lines.extend(["", "[Bond]", f"Mode={bond_mode}"])
        settings.append("Mode")
    else:
        lines.extend(["", "[VLAN]", f"Id={vlan_id}"])
        settings.append("Id")
    return {
        "filename": filename,
        "name": name,
        "kind": kind,
        "configured_settings": tuple(settings),
        "content": "\n".join(lines) + "\n",
    }, None


def systemd_netdev_creation_confirmation_details(
    filename: object,
    name: object,
    kind: object,
    bridge_stp: object = None,
    vlan_filtering: object = None,
    bond_mode: object = None,
    vlan_id: object = None,
) -> tuple[SystemdNetDevCreationTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "systemd-networkd virtual-device profile creation is available only on Linux."
    if os.geteuid() != 0:
        return None, "Creating a systemd .netdev profile requires the MCP server to already run as root; no privilege elevation is requested."
    normalized, error = _normalize_request(
        filename, name, kind, bridge_stp, vlan_filtering, bond_mode, vlan_id,
    )
    if error or normalized is None:
        return None, error
    directory_identity = _safe_systemd_network_directory()
    if directory_identity is None:
        return None, "The root-owned /etc/systemd/network directory must be available and writable with current permissions."
    states, error = _collect_network_state()
    if error or states is None:
        return None, error or "The bounded systemd network profile state could not be inspected."
    target_filename = str(normalized["filename"])
    target_name = str(normalized["name"])
    same_filename = [
        state for state in states
        if state.file_type == "netdev" and state.filename == target_filename
    ]
    if same_filename:
        return None, "A .netdev profile with this filename or a matching drop-in already exists in a system configuration root."
    if any(
        state.file_type == "netdev" and state.is_drop_in and state.profile_filename == target_filename
        for state in states
    ):
        return None, "The target .netdev filename has drop-ins; this bounded creator does not merge or edit drop-ins."
    existing_devices = _networkd_virtual_devices(states)
    if target_name in existing_devices:
        return None, "A systemd-networkd .netdev already defines this virtual-device name."
    if (NETDEV_SYSFS_ROOT / target_name).exists():
        return None, "A live Linux network interface already uses this virtual-device name."

    content = str(normalized["content"])
    path = Path("/etc/systemd/network") / target_filename
    file_target, file_error = text_file_creation_confirmation_details(str(path), content)
    if file_error or file_target is None:
        return None, file_error or "The exact .netdev destination could not be verified for creation."
    state_sha = _network_state_sha256(states)
    request_material = {
        "filename": target_filename,
        "name": target_name,
        "kind": normalized["kind"],
        "configured_settings": list(normalized["configured_settings"]),
        "content_sha256": file_target.content_sha256,
        "directory_identity": list(directory_identity),
        "network_state_sha256": state_sha,
    }
    token = hashlib.sha256(
        json.dumps(request_material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return SystemdNetDevCreationTarget(
        filename=target_filename,
        name=target_name,
        kind=normalized["kind"],
        configured_settings=normalized["configured_settings"],
        content=content,
        file_target=file_target,
        directory_identity=directory_identity,
        network_state_sha256=state_sha,
        state_token=token,
    ), None


def create_systemd_netdev_profile(
    filename: str,
    name: str,
    kind: DeviceKind,
    bridge_stp: bool | None = None,
    vlan_filtering: bool | None = None,
    bond_mode: BondMode | None = None,
    vlan_id: int | None = None,
    *,
    confirmed: bool,
    confirmed_filename: str | None = None,
    confirmed_name: str | None = None,
    confirmed_kind: str | None = None,
    state_token: str | None = None,
) -> SystemdNetDevCreateResponse:
    args = (filename, name, kind, bridge_stp, vlan_filtering, bond_mode, vlan_id)
    target, error = systemd_netdev_creation_confirmation_details(*args)
    if error or target is None:
        return SystemdNetDevCreateResponse(
            success=False,
            filename=filename if isinstance(filename, str) else None,
            name=name if isinstance(name, str) else None,
            kind=kind if isinstance(kind, str) and kind in {"bridge", "bond", "vlan"} else None,
            user_confirmed=confirmed is True,
            message=error or "The systemd .netdev profile could not be verified.",
        )
    if not confirmed:
        return SystemdNetDevCreateResponse(
            success=False,
            filename=target.filename,
            name=target.name,
            kind=target.kind,
            configured_settings=list(target.configured_settings),
            user_confirmed=False,
            message="Explicit client confirmation is required; no .netdev file was created.",
        )
    if (
        confirmed_filename != target.filename
        or confirmed_name != target.name
        or confirmed_kind != target.kind
        or state_token != target.state_token
    ):
        return SystemdNetDevCreateResponse(
            success=False,
            filename=target.filename,
            name=target.name,
            kind=target.kind,
            configured_settings=list(target.configured_settings),
            user_confirmed=True,
            message="The confirmation did not repeat the exact filename, name, kind, and state token; no file was created.",
        )

    with _ACTION_LOCK:
        current, error = systemd_netdev_creation_confirmation_details(*args)
        if error or current is None or current.state_token != state_token:
            return SystemdNetDevCreateResponse(
                success=False,
                filename=target.filename,
                name=target.name,
                kind=target.kind,
                configured_settings=list(target.configured_settings),
                user_confirmed=True,
                message=error or "The networkd profile state changed after confirmation; no .netdev file was created.",
            )
        result = create_text_file(
            str(target.file_target.path),
            target.content,
            confirmed=True,
            confirmed_path=str(target.file_target.path),
            confirmed_content_sha256=target.file_target.content_sha256,
        )
        if not result.success:
            return SystemdNetDevCreateResponse(
                success=False,
                created=result.created,
                filename=target.filename,
                name=target.name,
                kind=target.kind,
                configured_settings=list(target.configured_settings),
                settings_sha256=target.file_target.content_sha256,
                user_confirmed=True,
                message=result.message,
            )

        after, state_error = _collect_network_state()
        if state_error or after is None:
            return SystemdNetDevCreateResponse(
                success=False,
                created=True,
                filename=target.filename,
                name=target.name,
                kind=target.kind,
                configured_settings=list(target.configured_settings),
                settings_sha256=target.file_target.content_sha256,
                user_confirmed=True,
                message="The .netdev file was created, but the networkd state could not be rechecked; inspect it before applying the profile.",
            )
        created_path = str(target.file_target.path)
        created_state = next((
            state for state in after
            if state.file_type == "netdev" and not state.is_drop_in
            and state.source == "etc" and state.filename == target.filename
            and state.path == created_path
        ), None)
        filtered = tuple(
            state for state in after
            if not (state.file_type == "netdev" and not state.is_drop_in
                    and state.source == "etc" and state.filename == target.filename
                    and state.path == created_path)
        )
        directory_after = _safe_systemd_network_directory()
        directory_matches = (
            directory_after is not None
            and directory_after[:2] == target.directory_identity[:2]
            and directory_after[2:6] == target.directory_identity[2:6]
        )
        device_definitions = _networkd_virtual_devices(after)
        if (
            created_state is None
            or created_state.sha256 != target.file_target.content_sha256
            or not directory_matches
            or _network_state_sha256(filtered) != target.network_state_sha256
            or device_definitions.get(target.name) != {target.kind}
        ):
            return SystemdNetDevCreateResponse(
                success=False,
                created=True,
                filename=target.filename,
                name=target.name,
                kind=target.kind,
                configured_settings=list(target.configured_settings),
                settings_sha256=target.file_target.content_sha256,
                user_confirmed=True,
                message="The .netdev file was created, but post-write state verification found a change; inspect it before applying the profile.",
            )
    return SystemdNetDevCreateResponse(
        success=True,
        created=True,
        filename=target.filename,
        name=target.name,
        kind=target.kind,
        configured_settings=list(target.configured_settings),
        settings_sha256=target.file_target.content_sha256,
        user_confirmed=True,
        message="Created the exact root-owned systemd-networkd .netdev profile and verified its content and virtual-device definition. No networkd reload or reconfigure was requested.",
    )


_SECTION_HEADER_RE = re.compile(r"^\s*\[([^\]\r\n]+)\]\s*(?:[#;].*)?$")


def _normalize_edit_values(
    filename: object,
    name: object,
    kind: object,
    bridge_stp: object,
    vlan_filtering: object,
    bond_mode: object,
    vlan_id: object,
) -> tuple[dict[str, object] | None, str | None]:
    if not isinstance(filename, str) or not NETDEV_FILENAME_RE.fullmatch(filename):
        return None, "filename must be one exact safe .netdev filename, without a path."
    if not isinstance(name, str) or not INTERFACE_RE.fullmatch(name):
        return None, "name must be a literal Linux interface name of at most 15 characters."
    if not isinstance(kind, str) or kind not in {"bridge", "bond", "vlan"}:
        return None, "kind must be bridge, bond, or vlan."
    if bridge_stp is not None and type(bridge_stp) is not bool:
        return None, "bridge_stp must be a boolean when supplied."
    if vlan_filtering is not None and type(vlan_filtering) is not bool:
        return None, "vlan_filtering must be a boolean when supplied."
    if kind != "bridge" and (bridge_stp is not None or vlan_filtering is not None):
        return None, "bridge_stp and vlan_filtering apply only to bridge devices."
    if kind == "bridge" and (bond_mode is not None or vlan_id is not None):
        return None, "bond_mode and vlan_id do not apply to bridge devices."
    if kind == "bond" and (bridge_stp is not None or vlan_filtering is not None or vlan_id is not None):
        return None, "Only bond_mode applies to bond devices."
    if kind == "vlan" and (bridge_stp is not None or vlan_filtering is not None or bond_mode is not None):
        return None, "Only vlan_id applies to VLAN devices."
    if kind == "bond" and (
        not isinstance(bond_mode, str) or bond_mode not in {
            "balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad",
            "balance-tlb", "balance-alb",
        }
    ):
        return None, "bond_mode must be one supported Linux bonding mode."
    if kind != "bond" and bond_mode is not None:
        return None, "bond_mode applies only to bond devices."
    if kind == "vlan" and (
        not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 1 <= vlan_id <= 4094
    ):
        return None, "vlan_id must be an integer from 1 through 4094 for a VLAN device."
    if kind != "vlan" and vlan_id is not None:
        return None, "vlan_id applies only to VLAN devices."
    requested: dict[str, object] = {}
    if bridge_stp is not None:
        requested["STP"] = "yes" if bridge_stp else "no"
    if vlan_filtering is not None:
        requested["VLANFiltering"] = "yes" if vlan_filtering else "no"
    if bond_mode is not None:
        requested["Mode"] = bond_mode
    if vlan_id is not None:
        requested["Id"] = str(vlan_id)
    if not requested:
        return None, "Supply at least one supported setting to change."
    return {"filename": filename, "name": name, "kind": kind, "requested": requested}, None


def _setting_section(kind: str) -> str:
    return {"bridge": "bridge", "bond": "bond", "vlan": "vlan"}[kind]


def _canonical_existing_setting(key: str, value: str) -> str | None:
    if key in {"stp", "vlanfiltering"}:
        normalized = value.casefold()
        return normalized if normalized in {"yes", "no"} else None
    if key == "mode":
        supported = {
            "balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad",
            "balance-tlb", "balance-alb",
        }
        return value if value in supported else None
    if key == "id":
        if not value.isdecimal():
            return None
        number = int(value)
        return str(number) if 1 <= number <= 4094 else None
    return None


def _rewrite_netdev(
    parsed: object,
    kind: str,
    requested: dict[str, object],
) -> tuple[str | None, tuple[str, ...], tuple[tuple[str, str], ...], str | None]:
    # _ParsedNetwork is shared with the .network editor; keeping this local
    # rewrite narrow means unrelated .netdev sections and directives survive.
    lines = parsed.lines
    assignments = parsed.assignments
    section_headers: dict[str, list[int]] = {}
    for index, raw_line in enumerate(lines):
        match = _SECTION_HEADER_RE.fullmatch(raw_line.rstrip("\r\n"))
        if match:
            section_headers.setdefault(match.group(1).strip().casefold(), []).append(index)
    if len(section_headers.get("netdev", [])) != 1:
        return None, (), (), "The selected .netdev must contain exactly one [NetDev] section."

    target_section = _setting_section(kind)
    directive_for = {
        "stp": "STP",
        "vlanfiltering": "VLANFiltering",
        "mode": "Mode",
        "id": "Id",
    }
    requested_assignments = {
        key.casefold(): (key, str(value)) for key, value in requested.items()
    }
    matching_sections = section_headers.get(target_section, [])
    if len(matching_sections) > 1:
        return None, (), (), f"The selected .netdev repeats [{target_section.title()}]; refusing an ambiguous edit."

    changed: list[str] = []
    previous: list[tuple[str, str]] = []
    replacements: dict[int, str] = {}
    insert_values: list[tuple[str, str]] = []
    for key, (display_key, new_value) in requested_assignments.items():
        matches = [
            (index, value)
            for index, section, parsed_key, value in assignments
            if section == target_section and parsed_key == key
        ]
        if len(matches) > 1:
            return None, (), (), f"The selected .netdev repeats {display_key}=; refusing an ambiguous edit."
        if matches:
            index, old_value = matches[0]
            canonical_old = _canonical_existing_setting(key, old_value)
            if canonical_old is None:
                return None, (), (), f"The existing {display_key}= value is outside the supported format."
            if canonical_old == new_value:
                continue
            previous.append((display_key, old_value))
            raw_line = lines[index]
            body = raw_line.rstrip("\r\n")
            newline = raw_line[len(body):] or "\n"
            indent = body[: len(body) - len(body.lstrip())]
            replacements[index] = f"{indent}{directive_for[key]}={new_value}{newline}"
            changed.append(display_key)
        else:
            previous.append((display_key, "(unset)"))
            insert_values.append((directive_for[key], new_value))
            changed.append(display_key)

    if not changed:
        return None, (), (), "The requested values already match the saved .netdev profile."

    output: list[str] = []
    if insert_values and matching_sections:
        section_start = matching_sections[0]
        next_section = next(
            (index for index in range(section_start + 1, len(lines))
             if _SECTION_HEADER_RE.fullmatch(lines[index].rstrip("\r\n"))),
            len(lines),
        )
        insertion = next_section
    else:
        insertion = None

    for index, line in enumerate(lines):
        if insertion == index:
            if output and not output[-1].endswith(("\n", "\r")):
                output[-1] += "\n"
            output.extend(f"{directive}={value}\n" for directive, value in insert_values)
        output.append(replacements.get(index, line))
    if insertion == len(lines):
        if output and not output[-1].endswith(("\n", "\r")):
            output[-1] += "\n"
        output.extend(f"{directive}={value}\n" for directive, value in insert_values)
    elif insert_values and not matching_sections:
        if output and output[-1] and not output[-1].endswith(("\n", "\r")):
            output[-1] += "\n"
        if output and output[-1].strip():
            output.append("\n")
        output.append(f"[{target_section.title()}]\n")
        output.extend(f"{directive}={value}\n" for directive, value in insert_values)
    return "".join(output), tuple(sorted(changed)), tuple(sorted(previous)), None


def _netdev_state_target(
    filename: str,
    name: str,
    kind: str,
    states: tuple[_ConfigFileState, ...],
) -> tuple[_ConfigFileState | None, str | None]:
    path = str(Path("/etc/systemd/network") / filename)
    matches = [
        state for state in states
        if state.file_type == "netdev" and not state.is_drop_in
        and state.source == "etc" and state.filename == filename and state.path == path
    ]
    if len(matches) != 1:
        return None, "The exact /etc/systemd/network .netdev file is missing or ambiguous."
    if any(
        state.file_type == "netdev" and state.filename == filename and state.path != path
        for state in states
    ):
        return None, "A same-named .netdev exists in another network configuration root; refusing an ambiguous precedence edit."
    if any(
        state.file_type == "netdev" and state.is_drop_in and state.profile_filename == filename
        for state in states
    ):
        return None, "The selected .netdev has drop-ins; this bounded editor does not merge or edit drop-ins."
    state = matches[0]
    if _parse_netdev(state.contents) != (name, kind):
        return None, "The exact .netdev does not define the supplied name and supported device kind."
    if _networkd_virtual_devices(states).get(name) != {kind}:
        return None, "The virtual-device definition is ambiguous or conflicts with another .netdev."
    if (
        len(state.identity) < 6
        or state.identity[4] != 0
        or state.identity[3] != 1
        or state.identity[2] & (0o022 | 0o6000)
    ):
        return None, "The selected .netdev must be root-owned, single-link, and protected from group/other writes and set-id bits."
    return state, None


def systemd_netdev_config_confirmation_details(
    filename: object,
    name: object,
    kind: object,
    bridge_stp: object = None,
    vlan_filtering: object = None,
    bond_mode: object = None,
    vlan_id: object = None,
) -> tuple[SystemdNetDevConfigTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "systemd-networkd .netdev editing is available only on Linux."
    normalized, error = _normalize_edit_values(
        filename, name, kind, bridge_stp, vlan_filtering, bond_mode, vlan_id,
    )
    if error or normalized is None:
        return None, error
    directory_identity = _safe_systemd_network_directory()
    if directory_identity is None:
        return None, "The root-owned /etc/systemd/network directory must be available and writable with current permissions."
    states, error = _collect_network_state()
    if error or states is None:
        return None, error or "The bounded systemd network configuration state could not be inspected."
    filename_text = str(normalized["filename"])
    name_text = str(normalized["name"])
    kind_text = str(normalized["kind"])
    state, error = _netdev_state_target(filename_text, name_text, kind_text, states)
    if error or state is None:
        return None, error
    parsed, parse_error = _parse_network_profile(state.contents, require_match=False)
    if parse_error or parsed is None or parsed.match_keys:
        return None, parse_error or "The selected .netdev contains unsupported match directives."
    replacement, changed, previous, error = _rewrite_netdev(parsed, kind_text, normalized["requested"])
    if error or replacement is None:
        return None, error
    path = state.path
    file_target, error = text_file_replacement_confirmation_details(path, replacement)
    if error or file_target is None:
        return None, error or "The exact .netdev replacement could not be bound to confirmation."
    if (
        file_target.path != Path(path)
        or (file_target.device, file_target.inode) != state.identity[:2]
        or file_target.current_sha256 != state.sha256
        or (file_target.parent_device, file_target.parent_inode) != directory_identity[:2]
    ):
        return None, "The canonical .netdev path, file identity, content, or parent changed during edit preparation."
    other_states = tuple(item for item in states if item.path != path)
    material = {
        "filename": filename_text,
        "name": name_text,
        "kind": kind_text,
        "changed": list(changed),
        "previous": list(previous),
        "replacement_sha256": file_target.replacement_sha256,
        "directory_identity": list(directory_identity),
        "network_state": [
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
    token = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return SystemdNetDevConfigTarget(
        filename=filename_text,
        name=name_text,
        kind=kind_text,
        changed_settings=changed,
        previous_settings=previous,
        new_settings=tuple(sorted(
            (key, str(value)) for key, value in normalized["requested"].items()
            if key in changed
        )),
        replacement_text=replacement,
        file_target=file_target,
        directory_identity=directory_identity,
        network_state_sha256=_network_state_sha256(states),
        other_network_state_sha256=_network_state_sha256(other_states),
        state_token=token,
    ), None


def configure_systemd_netdev_profile(
    filename: str,
    name: str,
    kind: DeviceKind,
    bridge_stp: bool | None = None,
    vlan_filtering: bool | None = None,
    bond_mode: BondMode | None = None,
    vlan_id: int | None = None,
    *,
    confirmed: bool,
    confirmed_filename: str | None = None,
    confirmed_name: str | None = None,
    confirmed_kind: str | None = None,
    state_token: str | None = None,
) -> SystemdNetDevConfigResponse:
    args = (filename, name, kind, bridge_stp, vlan_filtering, bond_mode, vlan_id)
    target, error = systemd_netdev_config_confirmation_details(*args)
    if error or target is None:
        return SystemdNetDevConfigResponse(
            success=False,
            filename=filename if isinstance(filename, str) else None,
            name=name if isinstance(name, str) else None,
            kind=kind if isinstance(kind, str) and kind in {"bridge", "bond", "vlan"} else None,
            user_confirmed=confirmed is True,
            message=error or "The systemd .netdev profile could not be verified.",
        )
    if not confirmed:
        return SystemdNetDevConfigResponse(
            success=False, filename=target.filename, name=target.name, kind=target.kind,
            changed_settings=list(target.changed_settings), user_confirmed=False,
            message="Explicit client confirmation is required; the .netdev file was not changed.",
        )
    if (
        confirmed_filename != target.filename or confirmed_name != target.name
        or confirmed_kind != target.kind or state_token != target.state_token
    ):
        return SystemdNetDevConfigResponse(
            success=False, filename=target.filename, name=target.name, kind=target.kind,
            changed_settings=list(target.changed_settings), user_confirmed=True,
            message="Confirmation did not repeat the exact filename, interface name, kind, and state token; the .netdev file was not changed.",
        )
    with _ACTION_LOCK:
        current, error = systemd_netdev_config_confirmation_details(*args)
        if error or current is None or current.state_token != target.state_token:
            return SystemdNetDevConfigResponse(
                success=False, filename=target.filename, name=target.name, kind=target.kind,
                changed_settings=list(target.changed_settings), user_confirmed=True,
                message=error or "The networkd configuration changed after confirmation; the .netdev file was not changed.",
            )
        result = replace_text_file(
            str(target.file_target.path), target.replacement_text,
            confirmed=True,
            confirmed_path=str(target.file_target.path),
            confirmed_current_sha256=target.file_target.current_sha256,
            confirmed_replacement_sha256=target.file_target.replacement_sha256,
        )
        if not result.success:
            return SystemdNetDevConfigResponse(
                success=False, filename=target.filename, name=target.name, kind=target.kind,
                changed_settings=list(target.changed_settings),
                settings_sha256=target.file_target.replacement_sha256,
                user_confirmed=True, message=result.message,
            )
        after, state_error = _collect_network_state()
        directory_after = _safe_systemd_network_directory()
        changed_state = next((
            item for item in after or ()
            if item.file_type == "netdev" and not item.is_drop_in
            and item.source == "etc" and item.filename == target.filename
            and item.path == str(target.file_target.path)
        ), None)
        other_after = tuple(item for item in after or () if item.path != str(target.file_target.path))
        directory_ok = (
            directory_after is not None
            and directory_after[:2] == target.directory_identity[:2]
            and directory_after[2:6] == target.directory_identity[2:6]
        )
        if (
            state_error or after is None or changed_state is None
            or changed_state.sha256 != target.file_target.replacement_sha256
            or _parse_netdev(changed_state.contents) != (target.name, target.kind)
            or _network_state_sha256(other_after) != target.other_network_state_sha256
            or not directory_ok
            or _networkd_virtual_devices(after).get(target.name) != {target.kind}
        ):
            return SystemdNetDevConfigResponse(
                success=False, filename=target.filename, name=target.name, kind=target.kind,
                changed_settings=list(target.changed_settings),
                settings_sha256=target.file_target.replacement_sha256,
                user_confirmed=True,
                message="The .netdev file was updated, but post-write verification found a concurrent change; inspect networkd state before applying it.",
            )
    return SystemdNetDevConfigResponse(
        success=True, filename=target.filename, name=target.name, kind=target.kind,
        changed_settings=list(target.changed_settings),
        settings_sha256=target.file_target.replacement_sha256, user_confirmed=True,
        message="Updated the exact typed .netdev settings and verified the bounded networkd state. No reload or reconfigure was requested.",
    )


def _netdev_reference_error(name: str, states: tuple[_ConfigFileState, ...]) -> str | None:
    for state in states:
        if state.file_type != "network":
            continue
        parsed, error = _parse_network_profile(state.contents, require_match=False)
        if error or parsed is None:
            return "A .network profile cannot be parsed safely, so references to this virtual device cannot be ruled out."
        if any(key != "name" for key in parsed.match_keys):
            return "A .network profile has Match= criteria beyond literal interface names; its applicability to this virtual device cannot be ruled out."
        if not parsed.match_names:
            return "A .network profile has no literal Name= constraint; its applicability to this virtual device cannot be ruled out."
        positive_patterns = [pattern for pattern in parsed.match_names if not pattern.startswith("!")]
        negative_patterns = [pattern[1:] for pattern in parsed.match_names if pattern.startswith("!")]
        excluded = any(fnmatch.fnmatchcase(name, pattern) for pattern in negative_patterns)
        included = any(fnmatch.fnmatchcase(name, pattern) for pattern in positive_patterns)
        if not excluded and (included if positive_patterns else True):
            return f"A .network profile match may select virtual interface {name!r}; remove or change that profile first."
        for _index, section, key, value in parsed.assignments:
            if section == "network" and key in {"bridge", "bond", "vlan"} and name in value.split():
                return f"A .network profile references virtual interface {name!r}; remove or change that reference first."
    return None


def systemd_netdev_deletion_confirmation_details(
    filename: object,
    name: object,
    kind: object,
) -> tuple[SystemdNetDevDeletionTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "systemd-networkd .netdev deletion is available only on Linux."
    if not isinstance(filename, str) or not NETDEV_FILENAME_RE.fullmatch(filename):
        return None, "filename must be one exact safe .netdev filename, without a path."
    if not isinstance(name, str) or not INTERFACE_RE.fullmatch(name):
        return None, "name must be a literal Linux interface name of at most 15 characters."
    if not isinstance(kind, str) or kind not in {"bridge", "bond", "vlan"}:
        return None, "kind must be bridge, bond, or vlan."
    directory_identity = _safe_systemd_network_directory()
    if directory_identity is None:
        return None, "The root-owned /etc/systemd/network directory must be available and writable with current permissions."
    states, error = _collect_network_state()
    if error or states is None:
        return None, error or "The bounded systemd network configuration state could not be inspected."
    state, error = _netdev_state_target(filename, name, kind, states)
    if error or state is None:
        return None, error
    if (NETDEV_SYSFS_ROOT / name).exists():
        return None, "The virtual interface is currently present; deletion is limited to an inactive definition."
    reference_error = _netdev_reference_error(name, states)
    if reference_error:
        return None, reference_error
    path = state.path
    deletion_target, error = text_file_deletion_confirmation_details(path)
    if error or deletion_target is None:
        return None, error or "The exact .netdev file could not be bound to deletion."
    if (
        deletion_target.path != Path(path)
        or deletion_target.current_sha256 != state.sha256
        or (deletion_target.device, deletion_target.inode) != state.identity[:2]
        or (deletion_target.parent_device, deletion_target.parent_inode) != directory_identity[:2]
    ):
        return None, "The .netdev path, file identity, content, or parent changed during deletion preparation."
    remaining = tuple(item for item in states if item.path != path)
    material = {
        "filename": filename,
        "name": name,
        "kind": kind,
        "file_sha256": state.sha256,
        "file_identity": list(state.identity),
        "directory_identity": list(directory_identity),
        "network_state": [
            {
                "path": item.path, "source": item.source, "filename": item.filename,
                "profile_filename": item.profile_filename, "file_type": item.file_type,
                "is_drop_in": item.is_drop_in, "identity": list(item.identity),
                "sha256": item.sha256,
            }
            for item in states
        ],
    }
    token = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return SystemdNetDevDeletionTarget(
        filename=filename, name=name, kind=kind, file_target=deletion_target,
        directory_identity=directory_identity,
        network_state_sha256=_network_state_sha256(states),
        remaining_network_state_sha256=_network_state_sha256(remaining),
        state_token=token,
    ), None


def delete_systemd_netdev_profile(
    filename: str,
    name: str,
    kind: DeviceKind,
    *,
    confirmed: bool,
    confirmed_filename: str | None = None,
    confirmed_name: str | None = None,
    confirmed_kind: str | None = None,
    state_token: str | None = None,
) -> SystemdNetDevDeleteResponse:
    target, error = systemd_netdev_deletion_confirmation_details(filename, name, kind)
    if error or target is None:
        return SystemdNetDevDeleteResponse(
            success=False, filename=filename if isinstance(filename, str) else None,
            name=name if isinstance(name, str) else None,
            kind=kind if isinstance(kind, str) and kind in {"bridge", "bond", "vlan"} else None,
            user_confirmed=confirmed is True,
            message=error or "The exact systemd .netdev profile could not be verified.",
        )
    if not confirmed:
        return SystemdNetDevDeleteResponse(
            success=False, filename=target.filename, name=target.name, kind=target.kind,
            user_confirmed=False, message="Explicit client confirmation is required; no .netdev file was deleted.",
        )
    if (
        confirmed_filename != target.filename or confirmed_name != target.name
        or confirmed_kind != target.kind or state_token != target.state_token
    ):
        return SystemdNetDevDeleteResponse(
            success=False, filename=target.filename, name=target.name, kind=target.kind,
            user_confirmed=True,
            message="Confirmation did not repeat the exact filename, interface name, kind, and state token; no .netdev file was deleted.",
        )
    with _ACTION_LOCK:
        current, error = systemd_netdev_deletion_confirmation_details(filename, name, kind)
        if error or current is None or current.state_token != target.state_token:
            return SystemdNetDevDeleteResponse(
                success=False, filename=target.filename, name=target.name, kind=target.kind,
                user_confirmed=True,
                message=error or "The networkd state changed after confirmation; no .netdev file was deleted.",
            )
        result = delete_text_file(
            str(target.file_target.path), confirmed=True,
            confirmed_path=str(target.file_target.path),
            confirmed_current_sha256=target.file_target.current_sha256,
        )
        if not result.deleted:
            return SystemdNetDevDeleteResponse(
                success=False, filename=target.filename, name=target.name, kind=target.kind,
                user_confirmed=True, message=result.message,
            )
        after, state_error = _collect_network_state()
        directory_after = _safe_systemd_network_directory()
        verified = (
            state_error is None and after is not None
            and not any(item.path == str(target.file_target.path) for item in after)
            and _network_state_sha256(after) == target.remaining_network_state_sha256
            and directory_after is not None
            and directory_after[:2] == target.directory_identity[:2]
        )
        return SystemdNetDevDeleteResponse(
            success=verified, deleted=True, filename=target.filename, name=target.name,
            kind=target.kind, state_verified=verified, user_confirmed=True,
            message=(
                "Deleted the exact inactive .netdev file and verified the remaining bounded networkd state. No reload or reconfigure was requested."
                if verified else
                "The .netdev file was deleted, but post-delete state verification found a concurrent change; inspect networkd configuration."
            ),
        )
