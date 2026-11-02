"""Confirmed NetworkManager bridge/bond/VLAN creation and port-membership changes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import threading
import uuid as uuid_module
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import (
    NetworkManagerPortMembershipResponse,
    NetworkManagerPortProfileCreateResponse,
    NetworkManagerVirtualProfileCreateResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.network_manager import UUID_PATTERN

VirtualProfileKind = Literal["bridge", "bond", "vlan"]
BondMode = Literal[
    "active-backup",
    "balance-rr",
    "balance-xor",
    "broadcast",
    "802.3ad",
    "balance-tlb",
    "balance-alb",
]
PROFILE_KINDS = frozenset({"bridge", "bond", "vlan"})
BOND_MODES = frozenset({
    "active-backup", "balance-rr", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb",
})
PROFILE_FIELDS = "UUID,NAME,TYPE,DEVICE,AUTOCONNECT,connection.interface-name"
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_PROFILE_ROWS = 5_000
QUERY_TIMEOUT_SECONDS = 6
ACTION_TIMEOUT_SECONDS = 18
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class ProfileRow:
    uuid: str
    name: str
    connection_type: str
    device: str | None
    autoconnect: bool | None
    interface_name: str | None

    def payload(self) -> dict[str, object]:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "connection_type": self.connection_type,
            "device": self.device,
            "autoconnect": self.autoconnect,
            "interface_name": self.interface_name,
        }


@dataclass(frozen=True, slots=True)
class NetworkManagerVirtualProfileSnapshot:
    profiles: tuple[ProfileRow, ...]
    interface_index: int | None
    parent_index: int | None

    def payload(self) -> dict[str, object]:
        return {
            "profiles": [profile.payload() for profile in self.profiles],
            "interface_index": self.interface_index,
            "parent_index": self.parent_index,
        }


@dataclass(frozen=True, slots=True)
class NetworkManagerVirtualProfileTarget:
    kind: VirtualProfileKind
    profile_name: str
    interface_name: str
    parent_interface: str | None
    vlan_id: int | None
    bond_mode: BondMode | None
    before: NetworkManagerVirtualProfileSnapshot
    confirmation_phrase: str


@dataclass(frozen=True, slots=True)
class NetworkManagerPortProfileTarget:
    controller_uuid: str
    controller_name: str
    controller_type: Literal["bridge", "bond"]
    profile_name: str
    interface_name: str
    interface_index: int
    before: tuple[ProfileRow, ...]
    confirmation_phrase: str


@dataclass(frozen=True, slots=True)
class NetworkManagerPortMembershipTarget:
    action: Literal["add", "remove"]
    profile_uuid: str
    profile_name: str
    interface_name: str
    profile_active: bool
    controller_uuid: str
    controller_name: str
    controller_type: Literal["bridge", "bond"]
    before: tuple[ProfileRow, ...]
    before_membership: tuple[str, ...]
    confirmation_phrase: str


def network_manager_virtual_profile_control_available() -> bool:
    return sys.platform.startswith("linux") and bool(
        find_session_binary("nmcli", get_sanitized_env(dict(os.environ)))
    )


def _environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env


def _split_terse_row(row: str, expected_fields: int = 6) -> list[str] | None:
    fields: list[str] = []
    field: list[str] = []
    escaped = False
    for character in row:
        if escaped:
            if character not in {"\\", ":"}:
                return None
            field.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(field))
            field.clear()
        elif not character.isprintable():
            return None
        else:
            field.append(character)
    if escaped:
        return None
    fields.append("".join(field))
    return fields if len(fields) == expected_fields else None


def _parse_profile(row: str) -> ProfileRow | None:
    fields = _split_terse_row(row)
    if fields is None:
        return None
    raw_uuid, name, connection_type, device, autoconnect, interface_name = fields
    if not UUID_PATTERN.fullmatch(raw_uuid) or not name or not connection_type:
        return None
    try:
        normalized_uuid = str(uuid_module.UUID(raw_uuid))
    except ValueError:
        return None
    if len(name) > 256 or len(connection_type) > 64 or len(device) > 64 or len(interface_name) > 64:
        return None
    auto_key = autoconnect.casefold()
    parsed_autoconnect = True if auto_key in {"yes", "true"} else False if auto_key in {"no", "false"} else None
    return ProfileRow(
        uuid=normalized_uuid,
        name=name,
        connection_type=connection_type,
        device=None if device in {"", "--"} else device,
        autoconnect=parsed_autoconnect,
        interface_name=None if interface_name in {"", "--"} else interface_name,
    )


def _read_profiles(binary: str, env: dict[str, str]) -> tuple[tuple[ProfileRow, ...] | None, str | None]:
    output, error, truncated = run_bounded_command(
        [
            binary,
            "--wait", str(QUERY_TIMEOUT_SECONDS),
            "--terse", "--escape", "yes", "--fields", PROFILE_FIELDS,
            "connection", "show",
        ],
        env,
        command_label="NetworkManager profile inventory for topology creation",
        timeout_seconds=QUERY_TIMEOUT_SECONDS + 1,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if error or output is None:
        return None, "The complete NetworkManager profile inventory could not be read."
    if truncated:
        return None, "The NetworkManager profile inventory exceeded its output limit."
    rows = [row for row in output.splitlines() if row]
    if len(rows) > MAX_PROFILE_ROWS:
        return None, "The NetworkManager profile inventory exceeded its row limit."
    profiles: list[ProfileRow] = []
    seen: set[str] = set()
    for row in rows:
        profile = _parse_profile(row)
        if profile is None:
            return None, "NetworkManager returned an incomplete or malformed profile row; no profile was created."
        if profile.uuid in seen:
            return None, "NetworkManager returned a duplicate profile UUID; no profile was created."
        seen.add(profile.uuid)
        profiles.append(profile)
    profiles.sort(key=lambda profile: (profile.uuid, profile.name.casefold()))
    return tuple(profiles), None


def _normalize_uuid(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not UUID_PATTERN.fullmatch(value):
        return None, "controller_uuid must be one exact NetworkManager UUID from list_network_manager_profiles."
    try:
        return str(uuid_module.UUID(value)), None
    except ValueError:
        return None, "controller_uuid is not a valid UUID."


def _read_ethernet_device_type(
    binary: str,
    env: dict[str, str],
    interface_name: str,
) -> tuple[str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [
            binary,
            "--wait", str(QUERY_TIMEOUT_SECONDS),
            "--get-values", "GENERAL.TYPE,GENERAL.MANAGED",
            "device", "show", interface_name,
        ],
        env,
        command_label="NetworkManager Ethernet-port type inspection",
        timeout_seconds=QUERY_TIMEOUT_SECONDS + 1,
        max_output_bytes=8 * 1024,
    )
    if error or output is None or truncated:
        return None, "NetworkManager could not verify the selected port device type."
    values = [line.strip().casefold() for line in output.splitlines() if line.strip()]
    if len(values) != 2 or values[0] != "ethernet" or values[1] not in {"yes", "true"}:
        return None, "Only a NetworkManager-managed Ethernet device can be selected as a bridge/bond port."
    return values[0], None


def network_manager_port_profile_confirmation_details(
    controller_uuid: str,
    profile_name: str,
    interface_name: str,
) -> tuple[NetworkManagerPortProfileTarget | None, str | None]:
    normalized_uuid, error = _normalize_uuid(controller_uuid)
    if error or normalized_uuid is None:
        return None, error
    if (
        not isinstance(profile_name, str)
        or not profile_name.strip()
        or len(profile_name) > 128
        or profile_name.startswith("-")
        or any(not character.isprintable() for character in profile_name)
    ):
        return None, "profile_name must be 1-128 printable characters and cannot start with a dash."
    if not isinstance(interface_name, str) or not _INTERFACE_NAME.fullmatch(interface_name):
        return None, "interface_name must be a Linux interface name with 1-15 letters, digits, dots, underscores, or hyphens."
    if not network_manager_virtual_profile_control_available():
        return None, "NetworkManager port-profile creation requires Linux and nmcli."
    env = _environment()
    binary = find_session_binary("nmcli", env)
    if not binary:
        return None, "NetworkManager's nmcli command is unavailable."
    profiles, error = _read_profiles(binary, env)
    if error or profiles is None:
        return None, error or "The complete NetworkManager profile inventory could not be read."
    controller = next((profile for profile in profiles if profile.uuid == normalized_uuid), None)
    if controller is None:
        return None, "The exact NetworkManager controller UUID is not present in the current profile inventory."
    controller_type = controller.connection_type.casefold()
    if controller_type not in {"bridge", "bond"}:
        return None, "The selected controller profile must be a NetworkManager bridge or bond."
    if any(profile.name == profile_name for profile in profiles):
        return None, "A NetworkManager profile already uses that exact port-profile name."
    interface_index, _ = _interface_index(interface_name)
    if interface_index is None:
        return None, "The selected Ethernet port does not exist in the current network namespace."
    device_type, error = _read_ethernet_device_type(binary, env, interface_name)
    if error or device_type is None:
        return None, error or "The selected port device type could not be verified."
    material = {
        "profiles": [profile.payload() for profile in profiles],
        "interface_name": interface_name,
        "interface_index": interface_index,
        "device_type": device_type,
        "requested": {
            "controller_uuid": normalized_uuid,
            "controller_type": controller_type,
            "profile_name": profile_name,
        },
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()[:16]
    return NetworkManagerPortProfileTarget(
        controller_uuid=normalized_uuid,
        controller_name=controller.name,
        controller_type=controller_type,  # type: ignore[arg-type]
        profile_name=profile_name,
        interface_name=interface_name,
        interface_index=interface_index,
        before=profiles,
        confirmation_phrase=f"ADD {controller_type.upper()} PORT {interface_name} {digest}",
    ), None


def _read_port_membership(
    binary: str,
    env: dict[str, str],
    profile_uuid: str,
) -> tuple[tuple[str, ...] | None, str | None]:
    fields = (
        "connection.uuid,connection.interface-name,connection.autoconnect,connection.controller,connection.port-type,"
        "ipv4.method,ipv6.method"
    )
    output, error, truncated = run_bounded_command(
        [
            binary,
            "--wait", str(QUERY_TIMEOUT_SECONDS),
            "--terse", "--escape", "yes", "--fields", fields,
            "connection", "show", "uuid", profile_uuid,
        ],
        env,
        command_label="Verify saved NetworkManager port membership",
        timeout_seconds=QUERY_TIMEOUT_SECONDS + 1,
        max_output_bytes=64 * 1024,
    )
    if error or output is None or truncated:
        return None, "The new NetworkManager port profile could not be read back."
    rows = [line for line in output.splitlines() if line]
    if len(rows) != 1:
        return None, "NetworkManager did not return exactly one port-profile row."
    values = _split_terse_row(rows[0], 7)
    if values is None:
        return None, "NetworkManager returned a malformed port-profile row."
    return tuple(values), None


def network_manager_port_membership_confirmation_details(
    action: str,
    profile_uuid: str,
    controller_uuid: str,
) -> tuple[NetworkManagerPortMembershipTarget | None, str | None]:
    if action not in {"add", "remove"}:
        return None, "action must be add or remove."
    selected_profile_uuid, error = _normalize_uuid(profile_uuid)
    if error or selected_profile_uuid is None:
        return None, "profile_uuid must be one exact Ethernet profile UUID."
    selected_controller_uuid, error = _normalize_uuid(controller_uuid)
    if error or selected_controller_uuid is None:
        return None, "controller_uuid must be one exact NetworkManager UUID from list_network_manager_profiles."
    if not network_manager_virtual_profile_control_available():
        return None, "NetworkManager port membership control requires Linux and nmcli."
    env = _environment()
    binary = find_session_binary("nmcli", env)
    if not binary:
        return None, "NetworkManager's nmcli command is unavailable."
    profiles, error = _read_profiles(binary, env)
    if error or profiles is None:
        return None, error or "The complete NetworkManager profile inventory could not be read."
    port = next((row for row in profiles if row.uuid == selected_profile_uuid), None)
    controller = next((row for row in profiles if row.uuid == selected_controller_uuid), None)
    if port is None or controller is None:
        return None, "The exact port and controller UUIDs must both exist in the current profile inventory."
    if port.connection_type.casefold() not in {"ethernet", "802-3-ethernet"}:
        return None, "Only an Ethernet connection profile can be attached as a bridge or bond port."
    controller_type = controller.connection_type.casefold()
    if controller_type not in {"bridge", "bond"}:
        return None, "The selected controller profile must be a bridge or bond."
    if not port.interface_name:
        return None, "The Ethernet profile must be pinned to one interface before membership can change."
    if port.device is not None and port.device != port.interface_name:
        return None, "The selected Ethernet profile is active on a different interface than its saved interface name."
    interface_index, _ = _interface_index(port.interface_name)
    if interface_index is None:
        return None, "The Ethernet profile's interface does not exist in the current network namespace."
    _device_type, error = _read_ethernet_device_type(binary, env, port.interface_name)
    if error:
        return None, error
    membership, error = _read_port_membership(binary, env, port.uuid)
    if error or membership is None:
        return None, error or "The selected Ethernet profile's saved settings could not be verified."
    if (
        membership[0] != port.uuid
        or membership[1] != port.interface_name
        or membership[2].casefold() not in {"yes", "no", "true", "false"}
        or len(membership[5]) > 64
        or len(membership[6]) > 64
    ):
        return None, "The Ethernet profile's UUID, pinned interface, or autoconnect setting could not be read unambiguously."
    controller_values = {controller.uuid}
    if controller.interface_name:
        controller_values.add(controller.interface_name)
    current_controller = None if membership[3] in {"", "--"} else membership[3]
    current_port_type = None if membership[4] in {"", "--"} else membership[4].casefold()
    if action == "add" and (current_controller is not None or current_port_type is not None):
        return None, "The Ethernet profile is already assigned to a controller; detach it explicitly before reassigning."
    if action == "remove" and (
        current_controller not in controller_values or current_port_type != controller_type
    ):
        return None, "The Ethernet profile is not attached to the selected bridge or bond."
    material = {
        "profiles": [row.payload() for row in profiles],
        "interface_index": interface_index,
        "port_membership": list(membership),
        "requested": {
            "action": action,
            "profile_uuid": port.uuid,
            "controller_uuid": controller.uuid,
            "controller_type": controller_type,
        },
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()[:16]
    return NetworkManagerPortMembershipTarget(
        action=action,  # type: ignore[arg-type]
        profile_uuid=port.uuid,
        profile_name=port.name,
        interface_name=port.interface_name,
        profile_active=port.device is not None,
        controller_uuid=controller.uuid,
        controller_name=controller.name,
        controller_type=controller_type,  # type: ignore[arg-type]
        before=profiles,
        before_membership=membership,
        confirmation_phrase=f"{action.upper()} {controller_type.upper()} PORT {port.interface_name} {digest}",
    ), None


def perform_network_manager_port_membership_action(
    action: str,
    profile_uuid: str,
    controller_uuid: str,
    *,
    confirmed: bool,
    confirmed_action: str | None = None,
    confirmed_profile_uuid: str | None = None,
    confirmed_controller_uuid: str | None = None,
    confirmed_phrase: str | None = None,
) -> NetworkManagerPortMembershipResponse:
    values: dict[str, object] = {
        "action": action if action in {"add", "remove"} else None,
        "profile_uuid": profile_uuid if isinstance(profile_uuid, str) else None,
        "profile_name": None,
        "interface_name": None,
        "controller_uuid": controller_uuid if isinstance(controller_uuid, str) else None,
        "controller_name": None,
        "controller_type": None,
    }
    target, error = network_manager_port_membership_confirmation_details(action, profile_uuid, controller_uuid)
    if error or target is None:
        return NetworkManagerPortMembershipResponse(
            success=False, **values, user_confirmed=confirmed is True,
            message=error or "The requested NetworkManager port membership could not be verified.",
        )
    values.update({
        "profile_uuid": target.profile_uuid,
        "profile_name": target.profile_name,
        "interface_name": target.interface_name,
        "controller_uuid": target.controller_uuid,
        "controller_name": target.controller_name,
        "controller_type": target.controller_type,
    })
    if not confirmed:
        return NetworkManagerPortMembershipResponse(
            success=False, **values, user_confirmed=False,
            message="Explicit client confirmation is required; no profile membership was changed.",
        )
    repeated_profile, profile_error = _normalize_uuid(confirmed_profile_uuid)
    repeated_controller, controller_error = _normalize_uuid(confirmed_controller_uuid)
    if (
        confirmed_action != target.action
        or profile_error
        or controller_error
        or repeated_profile != target.profile_uuid
        or repeated_controller != target.controller_uuid
        or confirmed_phrase != target.confirmation_phrase
    ):
        return NetworkManagerPortMembershipResponse(
            success=False, **values, user_confirmed=True,
            message="Confirmation did not repeat the exact action, port, controller, and state-bound phrase.",
        )
    with _ACTION_LOCK:
        current, error = network_manager_port_membership_confirmation_details(action, profile_uuid, controller_uuid)
        if error or current is None or current.confirmation_phrase != target.confirmation_phrase:
            return NetworkManagerPortMembershipResponse(
                success=False, **values, user_confirmed=True,
                message=error or "NetworkManager profile or interface state changed after confirmation; no membership change was run.",
            )
        env = _environment()
        binary = find_session_binary("nmcli", env)
        if not binary:
            return NetworkManagerPortMembershipResponse(
                success=False, **values, user_confirmed=True,
                message="NetworkManager's nmcli command became unavailable; no membership change was run.",
            )
        controller_value = target.controller_uuid if target.action == "add" else ""
        port_type_value = target.controller_type if target.action == "add" else ""
        _output, command_error, truncated = run_bounded_command(
            [
                binary, "--wait", "12", "connection", "modify", "uuid", target.profile_uuid,
                "connection.controller", controller_value,
                "connection.port-type", port_type_value,
            ],
            env,
            command_label="Change confirmed NetworkManager bridge/bond port membership",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_OUTPUT_BYTES,
        )
        if command_error or _output is None or truncated:
            return NetworkManagerPortMembershipResponse(
                success=False, **values, user_confirmed=True,
                message="NetworkManager did not complete the profile membership change. Inspect saved settings before retrying; command output is withheld.",
            )
        profiles, read_error = _read_profiles(binary, env)
        membership, membership_error = _read_port_membership(binary, env, target.profile_uuid)
        expected_controller = {target.controller_uuid}
        selected_controller = next((row for row in current.before if row.uuid == target.controller_uuid), None)
        if selected_controller and selected_controller.interface_name:
            expected_controller.add(selected_controller.interface_name)
        expected_saved_state = (
            membership is not None
            and membership[0] == current.before_membership[0]
            and membership[1] == current.before_membership[1]
            and membership[2] == current.before_membership[2]
            and membership[5] == current.before_membership[5]
            and membership[6] == current.before_membership[6]
            and (
                membership[3] in expected_controller
                and membership[4].casefold() == target.controller_type
                if target.action == "add"
                else membership[3] in {"", "--"}
                and membership[4] in {"", "--"}
            )
        )
        if (
            read_error or profiles is None or tuple(row.payload() for row in profiles)
            != tuple(row.payload() for row in current.before) or not expected_saved_state
        ):
            return NetworkManagerPortMembershipResponse(
                success=False, **values, user_confirmed=True,
                message=membership_error or "NetworkManager accepted the command, but the exact saved port membership could not be verified; inspect the profile before retrying.",
            )
        verb = "attached to" if target.action == "add" else "detached from"
        return NetworkManagerPortMembershipResponse(
            success=True, **values, user_confirmed=True,
            message=(
                f"Saved Ethernet profile {target.profile_name!r} {verb} the selected NetworkManager "
                f"{target.controller_type}. The saved membership was verified without activating, deactivating, or reapplying the profile. "
                "Existing autoconnect and IPv4/IPv6 settings were preserved; a later activation or reapply may change traffic."
            ),
        )


def perform_network_manager_port_profile_creation(
    controller_uuid: str,
    profile_name: str,
    interface_name: str,
    *,
    confirmed: bool,
    confirmed_controller_uuid: str | None = None,
    confirmed_profile_name: str | None = None,
    confirmed_interface_name: str | None = None,
    confirmed_phrase: str | None = None,
) -> NetworkManagerPortProfileCreateResponse:
    values: dict[str, object] = {
        "controller_uuid": controller_uuid if isinstance(controller_uuid, str) else None,
        "profile_name": profile_name if isinstance(profile_name, str) else None,
        "interface_name": interface_name if isinstance(interface_name, str) else None,
        "controller_name": None,
        "controller_type": None,
        "profile_uuid": None,
    }
    target, error = network_manager_port_profile_confirmation_details(controller_uuid, profile_name, interface_name)
    if error or target is None:
        return NetworkManagerPortProfileCreateResponse(
            success=False,
            **values,
            user_confirmed=confirmed is True,
            message=error or "The requested NetworkManager port profile could not be verified.",
        )
    values.update({
        "controller_uuid": target.controller_uuid,
        "controller_name": target.controller_name,
        "controller_type": target.controller_type,
    })
    if not confirmed:
        return NetworkManagerPortProfileCreateResponse(
            success=False,
            **values,
            user_confirmed=False,
            message="Explicit client confirmation is required; no port profile was created.",
        )
    repeated_controller, uuid_error = _normalize_uuid(confirmed_controller_uuid)
    if (
        uuid_error
        or repeated_controller != target.controller_uuid
        or confirmed_profile_name != target.profile_name
        or confirmed_interface_name != target.interface_name
        or confirmed_phrase != target.confirmation_phrase
    ):
        return NetworkManagerPortProfileCreateResponse(
            success=False,
            **values,
            user_confirmed=True,
            message="Confirmation did not repeat the exact controller, port request, and state-bound phrase.",
        )
    with _ACTION_LOCK:
        current, error = network_manager_port_profile_confirmation_details(
            controller_uuid,
            profile_name,
            interface_name,
        )
        if error or current is None or current.confirmation_phrase != target.confirmation_phrase:
            return NetworkManagerPortProfileCreateResponse(
                success=False,
                **values,
                user_confirmed=True,
                message=error or "NetworkManager profile or interface state changed after confirmation; no port profile was created.",
            )
        env = _environment()
        binary = find_session_binary("nmcli", env)
        if not binary:
            return NetworkManagerPortProfileCreateResponse(
                success=False,
                **values,
                user_confirmed=True,
                message="NetworkManager's nmcli command became unavailable; no port profile was created.",
            )
        output, command_error, truncated = run_bounded_command(
            [
                binary,
                "--wait", "12", "connection", "add", "type", "ethernet",
                "con-name", current.profile_name,
                "ifname", current.interface_name,
                "connection.controller", current.controller_uuid,
                "connection.port-type", current.controller_type,
                "connection.autoconnect", "no",
                "ipv4.method", "disabled",
                "ipv6.method", "disabled",
            ],
            env,
            command_label="Create confirmed inactive NetworkManager bridge/bond port profile",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_OUTPUT_BYTES,
        )
        if command_error or output is None or truncated:
            message = (
                "The NetworkManager command timed out; saved state may be partial. Inspect profiles before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "NetworkManager rejected port-profile creation. Inspect the profile inventory before retrying."
            )
            return NetworkManagerPortProfileCreateResponse(
                success=False,
                **values,
                user_confirmed=True,
                message=message,
            )
        profiles, read_error = _read_profiles(binary, env)
        if read_error or profiles is None:
            return NetworkManagerPortProfileCreateResponse(
                success=False,
                **values,
                user_confirmed=True,
                message="NetworkManager accepted the command, but the port profile could not be verified; inspect profiles before retrying.",
            )
        matches = [
            profile for profile in profiles
            if profile.name == current.profile_name
            and profile.connection_type.casefold() in {"ethernet", "802-3-ethernet"}
            and profile.interface_name == current.interface_name
        ]
        old_uuids = {profile.uuid for profile in current.before}
        if len(matches) != 1 or any(
            profile.uuid not in old_uuids and profile.uuid != matches[0].uuid
            for profile in profiles
        ):
            return NetworkManagerPortProfileCreateResponse(
                success=False,
                **values,
                user_confirmed=True,
                message="NetworkManager changed profile state outside the exact requested port addition; inspect the profile inventory.",
            )
        created = matches[0]
        old_rows = tuple(profile.payload() for profile in current.before)
        new_old_rows = tuple(profile.payload() for profile in profiles if profile.uuid != created.uuid)
        membership, membership_error = _read_port_membership(binary, env, created.uuid)
        controller_values = {current.controller_uuid}
        for row in current.before:
            if row.uuid == current.controller_uuid and row.interface_name:
                controller_values.add(row.interface_name)
        verified = (
            created.autoconnect is False
            and created.device is None
            and old_rows == new_old_rows
            and len(profiles) == len(current.before) + 1
            and membership is not None
            and membership[0] == created.uuid
            and membership[1] == current.interface_name
            and membership[2].casefold() in {"no", "false"}
            and membership[3] in controller_values
            and membership[4].casefold() == current.controller_type
            and membership[5].casefold() == "disabled"
            and membership[6].casefold() == "disabled"
        )
        if not verified:
            return NetworkManagerPortProfileCreateResponse(
                success=False,
                **(values | {"profile_uuid": created.uuid}),
                user_confirmed=True,
                message=membership_error or "The profile exists, but saved controller, port, or inactive-state values did not match; inspect it before activation.",
            )
        return NetworkManagerPortProfileCreateResponse(
            success=True,
            **(values | {"profile_uuid": created.uuid}),
            user_confirmed=True,
            message=(
                "Created and verified an inactive Ethernet port profile attached to the selected NetworkManager "
                f"{current.controller_type} profile. Autoconnect and IPv4/IPv6 are disabled. The live interface "
                "was not switched; activating this port profile later can interrupt traffic on that interface."
            ),
        )


def _interface_index(name: str) -> tuple[int | None, str | None]:
    try:
        return socket.if_nametoindex(name), None
    except OSError:
        return None, None


def _normalize_request(
    kind: object,
    profile_name: object,
    interface_name: object,
    parent_interface: object,
    vlan_id: object,
    bond_mode: object,
) -> tuple[VirtualProfileKind | None, str | None, str | None, str | None, int | None, BondMode | None, str | None]:
    if not isinstance(kind, str) or kind not in PROFILE_KINDS:
        return None, None, None, None, None, None, "kind must be bridge, bond, or vlan."
    if (
        not isinstance(profile_name, str)
        or not profile_name.strip()
        or len(profile_name) > 128
        or profile_name.startswith("-")
        or any(not character.isprintable() for character in profile_name)
    ):
        return None, None, None, None, None, None, "profile_name must be 1-128 printable characters and cannot start with a dash."
    if not isinstance(interface_name, str) or not _INTERFACE_NAME.fullmatch(interface_name):
        return None, None, None, None, None, None, "interface_name must be a Linux interface name with 1-15 letters, digits, dots, underscores, or hyphens."
    if kind == "vlan":
        if not isinstance(parent_interface, str) or not _INTERFACE_NAME.fullmatch(parent_interface):
            return None, None, None, None, None, None, "VLAN profiles require one existing parent_interface name."
        if parent_interface == interface_name:
            return None, None, None, None, None, None, "A VLAN interface cannot be its own parent."
        if not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 1 <= vlan_id <= 4094:
            return None, None, None, None, None, None, "vlan_id must be an integer from 1 through 4094."
        if bond_mode is not None:
            return None, None, None, None, None, None, "bond_mode applies only to bond profiles."
        return kind, profile_name, interface_name, parent_interface, vlan_id, None, None
    if parent_interface is not None or vlan_id is not None:
        return None, None, None, None, None, None, "parent_interface and vlan_id apply only to VLAN profiles."
    if kind == "bond":
        selected_mode = "active-backup" if bond_mode is None else bond_mode
        if not isinstance(selected_mode, str) or selected_mode not in BOND_MODES:
            return None, None, None, None, None, None, "bond_mode must be an allowed NetworkManager mode."
        return kind, profile_name, interface_name, None, None, selected_mode, None
    if bond_mode is not None:
        return None, None, None, None, None, None, "bond_mode applies only to bond profiles."
    return kind, profile_name, interface_name, None, None, None, None


def _read_snapshot(
    kind: VirtualProfileKind,
    profile_name: str,
    interface_name: str,
    parent_interface: str | None,
    binary: str,
    env: dict[str, str],
) -> tuple[NetworkManagerVirtualProfileSnapshot | None, str | None]:
    profiles, error = _read_profiles(binary, env)
    if error or profiles is None:
        return None, error
    if any(profile.name == profile_name for profile in profiles):
        return None, "A NetworkManager profile already uses that exact profile name."
    if any(
        profile.interface_name == interface_name or profile.device == interface_name
        for profile in profiles
    ):
        return None, "A NetworkManager profile already targets that interface name."
    interface_index, _ = _interface_index(interface_name)
    if interface_index is not None:
        return None, "The requested interface name already exists in the current network namespace."
    parent_index: int | None = None
    if parent_interface is not None:
        parent_index, _ = _interface_index(parent_interface)
        if parent_index is None:
            return None, "The requested VLAN parent interface does not exist in the current network namespace."
    return NetworkManagerVirtualProfileSnapshot(
        profiles=profiles,
        interface_index=interface_index,
        parent_index=parent_index,
    ), None


def network_manager_virtual_profile_confirmation_details(
    kind: str,
    profile_name: str,
    interface_name: str,
    parent_interface: str | None = None,
    vlan_id: int | None = None,
    bond_mode: str | None = None,
) -> tuple[NetworkManagerVirtualProfileTarget | None, str | None]:
    normalized = _normalize_request(kind, profile_name, interface_name, parent_interface, vlan_id, bond_mode)
    selected_kind, selected_name, selected_interface, selected_parent, selected_vlan, selected_bond, error = normalized
    if error or selected_kind is None or selected_name is None or selected_interface is None:
        return None, error or "The requested NetworkManager profile could not be validated."
    if not network_manager_virtual_profile_control_available():
        return None, "NetworkManager profile creation is available only on Linux with nmcli."
    env = _environment()
    binary = find_session_binary("nmcli", env)
    if not binary:
        return None, "NetworkManager's nmcli command is unavailable."
    before, error = _read_snapshot(selected_kind, selected_name, selected_interface, selected_parent, binary, env)
    if error or before is None:
        return None, error or "NetworkManager profile state could not be verified."
    material = {
        "before": before.payload(),
        "requested": {
            "kind": selected_kind,
            "profile_name": selected_name,
            "interface_name": selected_interface,
            "parent_interface": selected_parent,
            "vlan_id": selected_vlan,
            "bond_mode": selected_bond,
        },
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()[:16]
    return NetworkManagerVirtualProfileTarget(
        kind=selected_kind,
        profile_name=selected_name,
        interface_name=selected_interface,
        parent_interface=selected_parent,
        vlan_id=selected_vlan,
        bond_mode=selected_bond,
        before=before,
        confirmation_phrase=f"CREATE {selected_kind.upper()} {selected_interface} {digest}",
    ), None


def _response_values(
    kind: object,
    profile_name: object,
    interface_name: object,
    parent_interface: object,
    vlan_id: object,
    bond_mode: object,
    target: NetworkManagerVirtualProfileTarget | None = None,
) -> dict[str, object]:
    return {
        "kind": target.kind if target else kind if isinstance(kind, str) and kind in PROFILE_KINDS else None,
        "profile_name": target.profile_name if target else profile_name if isinstance(profile_name, str) else None,
        "interface_name": target.interface_name if target else interface_name if isinstance(interface_name, str) else None,
        "parent_interface": target.parent_interface if target else parent_interface if isinstance(parent_interface, str) else None,
        "vlan_id": target.vlan_id if target else vlan_id if isinstance(vlan_id, int) and not isinstance(vlan_id, bool) else None,
        "bond_mode": target.bond_mode if target else bond_mode if isinstance(bond_mode, str) else None,
        "profile_uuid": None,
    }


def _failure(values: dict[str, object], message: str, *, user_confirmed: bool) -> NetworkManagerVirtualProfileCreateResponse:
    return NetworkManagerVirtualProfileCreateResponse(
        success=False,
        **(values | {"profile_uuid": None}),
        user_confirmed=user_confirmed,
        message=message,
    )


def _command_arguments(target: NetworkManagerVirtualProfileTarget) -> list[str]:
    arguments = [
        "--wait", "12", "connection", "add", "type", target.kind,
        "con-name", target.profile_name,
        "ifname", target.interface_name,
        "connection.autoconnect", "no",
        "ipv4.method", "disabled",
        "ipv6.method", "disabled",
    ]
    if target.kind == "bridge":
        arguments.extend(("bridge.stp", "yes"))
    elif target.kind == "bond" and target.bond_mode is not None:
        arguments.extend(("mode", target.bond_mode))
    elif target.kind == "vlan" and target.parent_interface is not None and target.vlan_id is not None:
        arguments.extend(("dev", target.parent_interface, "id", str(target.vlan_id)))
    return arguments


def perform_network_manager_virtual_profile_creation(
    kind: str,
    profile_name: str,
    interface_name: str,
    parent_interface: str | None = None,
    vlan_id: int | None = None,
    bond_mode: str | None = None,
    *,
    confirmed: bool,
    confirmed_kind: str | None = None,
    confirmed_profile_name: str | None = None,
    confirmed_interface_name: str | None = None,
    confirmed_parent_interface: str | None = None,
    confirmed_vlan_id: int | None = None,
    confirmed_bond_mode: str | None = None,
    confirmed_phrase: str | None = None,
) -> NetworkManagerVirtualProfileCreateResponse:
    values = _response_values(kind, profile_name, interface_name, parent_interface, vlan_id, bond_mode)
    target, error = network_manager_virtual_profile_confirmation_details(
        kind, profile_name, interface_name, parent_interface, vlan_id, bond_mode,
    )
    if error or target is None:
        return _failure(values, error or "The requested NetworkManager profile could not be verified.", user_confirmed=confirmed is True)
    values = _response_values(kind, profile_name, interface_name, parent_interface, vlan_id, bond_mode, target)
    if not confirmed:
        return _failure(values, "Explicit client confirmation is required; no profile was created.", user_confirmed=False)
    confirmed_request = (
        confirmed_kind == target.kind
        and confirmed_profile_name == target.profile_name
        and confirmed_interface_name == target.interface_name
        and confirmed_parent_interface == target.parent_interface
        and confirmed_vlan_id == target.vlan_id
        and confirmed_bond_mode == target.bond_mode
        and confirmed_phrase == target.confirmation_phrase
    )
    if not confirmed_request:
        return _failure(values, "Confirmation did not repeat the exact request and profile-state phrase.", user_confirmed=True)

    with _ACTION_LOCK:
        current, error = network_manager_virtual_profile_confirmation_details(
            kind, profile_name, interface_name, parent_interface, vlan_id, bond_mode,
        )
        if error or current is None or current.confirmation_phrase != target.confirmation_phrase:
            return _failure(
                values,
                error or "NetworkManager profile or interface state changed after confirmation; no profile was created.",
                user_confirmed=True,
            )
        env = _environment()
        binary = find_session_binary("nmcli", env)
        if not binary:
            return _failure(values, "NetworkManager's nmcli command became unavailable; no profile was created.", user_confirmed=True)
        output, command_error, truncated = run_bounded_command(
            [binary, *_command_arguments(current)],
            env,
            command_label="Create confirmed inactive NetworkManager virtual profile",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_OUTPUT_BYTES,
        )
        if command_error or output is None or truncated:
            message = (
                "The NetworkManager command timed out; saved state may be partial. Inspect profiles before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "NetworkManager rejected profile creation. Inspect the profile inventory before retrying."
            )
            return _failure(values, message, user_confirmed=True)
        profiles, read_error = _read_profiles(binary, env)
        if read_error or profiles is None:
            return _failure(
                values,
                "NetworkManager accepted the command, but the new profile could not be verified; inspect profiles before retrying.",
                user_confirmed=True,
            )
        matches = [
            profile for profile in profiles
            if profile.name == current.profile_name
            and profile.connection_type.casefold() == current.kind
            and profile.interface_name == current.interface_name
        ]
        old_uuids = {profile.uuid for profile in current.before.profiles}
        if len(matches) != 1 or any(profile.uuid not in old_uuids and profile.uuid != matches[0].uuid for profile in profiles):
            return _failure(
                values,
                "NetworkManager changed profile state outside the exact requested addition; inspect the profile inventory.",
                user_confirmed=True,
            )
        created = matches[0]
        old_rows = tuple(profile.payload() for profile in current.before.profiles)
        new_old_rows = tuple(profile.payload() for profile in profiles if profile.uuid != created.uuid)
        verified = (
            created.autoconnect is False
            and created.device is None
            and old_rows == new_old_rows
            and len(profiles) == len(current.before.profiles) + 1
        )
        if not verified:
            return NetworkManagerVirtualProfileCreateResponse(
                success=False,
                **(values | {"profile_uuid": created.uuid}),
                user_confirmed=True,
                message="The profile exists, but the full resulting state did not match the confirmed inactive request; inspect it before activation.",
            )
        return NetworkManagerVirtualProfileCreateResponse(
            success=True,
            **(values | {"profile_uuid": created.uuid}),
            user_confirmed=True,
            message=(
                "Created and verified the persistent NetworkManager profile. It is inactive, autoconnect is disabled, "
                "and IPv4/IPv6 are disabled. Bridge and bond profiles have no ports attached; use a separate port "
                "profile before activation."
                if current.kind in {"bridge", "bond"}
                else "Created and verified the persistent inactive VLAN profile with autoconnect disabled and IPv4/IPv6 disabled."
            ),
        )
