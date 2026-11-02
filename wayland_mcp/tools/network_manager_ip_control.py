"""State-bound persistent IPv4/IPv6 settings for NetworkManager profiles."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sys
import threading
import uuid as uuid_module
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import (
    NetworkManagerProfileIPConfigResponse,
    NetworkManagerProfileIPResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.network_manager import UUID_PATTERN

IPFamily = Literal["ipv4", "ipv6"]
IPMethod = Literal["auto", "manual"]
MAX_OUTPUT_BYTES = 64 * 1024
MAX_ADDRESSES = 16
QUERY_TIMEOUT_SECONDS = 6
ACTION_TIMEOUT_SECONDS = 15
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class NetworkManagerProfileIPState:
    profile_uuid: str
    profile_name: str
    connection_type: str
    family: IPFamily
    method: str
    addresses: tuple[str, ...]
    gateway: str | None

    def as_payload(self) -> dict[str, object]:
        return {
            "profile_uuid": self.profile_uuid,
            "profile_name": self.profile_name,
            "connection_type": self.connection_type,
            "family": self.family,
            "method": self.method,
            "addresses": list(self.addresses),
            "gateway": self.gateway,
        }


@dataclass(frozen=True, slots=True)
class NetworkManagerProfileIPTarget:
    before: NetworkManagerProfileIPState
    method: IPMethod
    addresses: tuple[str, ...]
    gateway: str | None
    confirmation_phrase: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env


def _normalized_uuid(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not UUID_PATTERN.fullmatch(value):
        return None, "profile_uuid must be one exact NetworkManager UUID from list_network_manager_profiles."
    try:
        return str(uuid_module.UUID(value)), None
    except ValueError:
        return None, "profile_uuid is not a valid NetworkManager UUID."


def _split_multiline_property(row: str, expected_keys: set[str]) -> tuple[str, str] | None:
    """Parse nmcli multiline output, whose values may contain literal colons."""
    separator = row.find(":")
    if separator <= 0:
        return None
    key = row[:separator]
    if key not in expected_keys:
        return None
    value: list[str] = []
    escaped = False
    for character in row[separator + 1:]:
        if escaped:
            if character not in {"\\", ":"}:
                return None
            value.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif not character.isprintable():
            return None
        else:
            value.append(character)
    if escaped:
        return None
    return key, "".join(value)


def _empty_value(value: str) -> bool:
    return value.strip() in {"", "--", "-"}


def _canonical_addresses(raw: str, family: IPFamily) -> tuple[str, ...] | None:
    if _empty_value(raw):
        return ()
    values = [item.strip() for item in raw.split(",")]
    if not values or len(values) > MAX_ADDRESSES:
        return None
    normalized: list[str] = []
    for value in values:
        try:
            address = ipaddress.ip_interface(value)
        except ValueError:
            return None
        if address.version != (4 if family == "ipv4" else 6):
            return None
        canonical = str(address)
        if canonical not in normalized:
            normalized.append(canonical)
    return tuple(normalized)


def _canonical_gateway(raw: str, family: IPFamily) -> str | None | Literal[False]:
    if _empty_value(raw):
        return None
    try:
        address = ipaddress.ip_address(raw.strip())
    except ValueError:
        return False
    if address.version != (4 if family == "ipv4" else 6):
        return False
    return str(address)


def _read_profile_snapshot(
    profile_uuid: object,
    family: object,
) -> tuple[NetworkManagerProfileIPState | None, str | None]:
    normalized_uuid, error = _normalized_uuid(profile_uuid)
    if error or normalized_uuid is None:
        return None, error
    if not isinstance(family, str) or family not in {"ipv4", "ipv6"}:
        return None, "family must be ipv4 or ipv6."
    if not sys.platform.startswith("linux"):
        return None, "NetworkManager saved IP profile inspection is available only on Linux."
    env = _environment()
    binary = find_session_binary("nmcli", env)
    if not binary:
        return None, "NetworkManager saved IP profile inspection requires nmcli."
    fields = [
        "connection.uuid",
        "connection.id",
        "connection.type",
        f"{family}.method",
        f"{family}.addresses",
        f"{family}.gateway",
    ]
    output, error, truncated = run_bounded_command(
        [
            binary,
            "--wait", str(QUERY_TIMEOUT_SECONDS),
            "--terse", "--escape", "yes", "--mode", "multiline", "--fields", ",".join(fields),
            "connection", "show", "uuid", normalized_uuid,
        ],
        env,
        command_label="Read saved NetworkManager IP profile settings",
        timeout_seconds=QUERY_TIMEOUT_SECONDS + 1,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if error or output is None:
        return None, "The exact NetworkManager profile could not be read."
    if truncated:
        return None, "The NetworkManager IP profile response exceeded its output limit."
    rows = [line for line in output.splitlines() if line]
    values: dict[str, str] = {}
    malformed = False
    expected_keys = set(fields)
    for row in rows:
        parsed = _split_multiline_property(row, expected_keys)
        if parsed is None:
            malformed = True
            continue
        key, value = parsed
        if key not in fields or key in values:
            malformed = True
            continue
        values[key] = value
    if malformed or set(values) != set(fields):
        return None, "NetworkManager did not return exactly one complete saved profile row."
    returned_uuid = values["connection.uuid"]
    name = values["connection.id"]
    connection_type = values["connection.type"]
    method = values[f"{family}.method"]
    raw_addresses = values[f"{family}.addresses"]
    raw_gateway = values[f"{family}.gateway"]
    try:
        returned_uuid = str(uuid_module.UUID(returned_uuid))
    except ValueError:
        return None, "NetworkManager returned a malformed profile UUID."
    if returned_uuid != normalized_uuid or not name or len(name) > 256 or not connection_type or len(connection_type) > 64:
        return None, "NetworkManager returned a mismatched or malformed connection-profile identity."
    if not method or len(method) > 32 or not re.fullmatch(r"[A-Za-z0-9_-]+", method):
        return None, "The saved IP configuration method could not be verified."
    addresses = _canonical_addresses(raw_addresses, family)
    gateway = _canonical_gateway(raw_gateway, family)
    if addresses is None or gateway is False:
        return None, "The saved IP addresses or gateway are outside the supported literal-address format."
    return NetworkManagerProfileIPState(
        profile_uuid=returned_uuid,
        profile_name=name,
        connection_type=connection_type,
        family=family,  # type: ignore[arg-type]
        method=method,
        addresses=addresses,
        gateway=gateway,
    ), None


def get_network_manager_profile_ip(
    profile_uuid: str,
    family: IPFamily,
) -> NetworkManagerProfileIPResponse:
    safe_family = family if isinstance(family, str) and family in {"ipv4", "ipv6"} else None
    state, error = _read_profile_snapshot(profile_uuid, family)
    if state is None:
        return NetworkManagerProfileIPResponse(success=False, family=safe_family, message=error or "Saved IP settings could not be read.")
    return NetworkManagerProfileIPResponse(
        success=True,
        profile_uuid=state.profile_uuid,
        profile_name=state.profile_name,
        connection_type=state.connection_type,
        family=state.family,
        method=state.method,
        addresses=list(state.addresses),
        gateway=state.gateway,
        message="These are saved profile values. Runtime addresses may differ until NetworkManager applies the profile.",
    )


def _normalize_request(
    profile_uuid: object,
    family: object,
    method: object,
    addresses: object,
    gateway: object,
) -> tuple[str | None, IPFamily | None, IPMethod | None, tuple[str, ...] | None, str | None, str | None]:
    normalized_uuid, error = _normalized_uuid(profile_uuid)
    if error or normalized_uuid is None:
        return None, None, None, None, None, error
    if not isinstance(family, str) or family not in {"ipv4", "ipv6"}:
        return None, None, None, None, None, "family must be ipv4 or ipv6."
    if not isinstance(method, str) or method not in {"auto", "manual"}:
        return None, None, None, None, None, "method must be auto or manual."
    selected_family: IPFamily = family  # type: ignore[assignment]
    selected_method: IPMethod = method  # type: ignore[assignment]
    if selected_method == "auto":
        if addresses not in (None, []) or gateway is not None:
            return None, None, None, None, None, "Auto configuration clears static addresses and gateway; omit addresses and gateway."
        return normalized_uuid, selected_family, selected_method, (), None, None
    if not isinstance(addresses, list) or not 1 <= len(addresses) <= MAX_ADDRESSES:
        return None, None, None, None, None, f"Manual configuration requires 1 through {MAX_ADDRESSES} address/prefix values."
    normalized_addresses: list[str] = []
    expected_version = 4 if selected_family == "ipv4" else 6
    for value in addresses:
        if not isinstance(value, str) or len(value) > 64 or "/" not in value or "%" in value:
            return None, None, None, None, None, "Each address must be one literal IP address with a prefix length."
        try:
            address = ipaddress.ip_interface(value)
        except ValueError:
            return None, None, None, None, None, "Each address must be one literal IP address with a prefix length."
        if address.version != expected_version:
            return None, None, None, None, None, f"Every address must be IPv{expected_version}."
        canonical = str(address)
        if canonical not in normalized_addresses:
            normalized_addresses.append(canonical)
    normalized_gateway: str | None = None
    if gateway is not None:
        if not isinstance(gateway, str) or len(gateway) > 64 or "%" in gateway:
            return None, None, None, None, None, "gateway must be one literal IP address or omitted."
        try:
            parsed_gateway = ipaddress.ip_address(gateway)
        except ValueError:
            return None, None, None, None, None, "gateway must be one literal IP address or omitted."
        if parsed_gateway.version != expected_version:
            return None, None, None, None, None, f"gateway must be an IPv{expected_version} address."
        normalized_gateway = str(parsed_gateway)
    return normalized_uuid, selected_family, selected_method, tuple(normalized_addresses), normalized_gateway, None


def network_manager_profile_ip_confirmation_details(
    profile_uuid: str,
    family: IPFamily,
    method: IPMethod,
    addresses: list[str] | None = None,
    gateway: str | None = None,
) -> tuple[NetworkManagerProfileIPTarget | None, str | None]:
    normalized = _normalize_request(profile_uuid, family, method, addresses, gateway)
    normalized_uuid, selected_family, selected_method, selected_addresses, selected_gateway, error = normalized
    if error or normalized_uuid is None or selected_family is None or selected_method is None or selected_addresses is None:
        return None, error or "The requested IP profile change could not be validated."
    state, error = _read_profile_snapshot(normalized_uuid, selected_family)
    if error or state is None:
        return None, error or "The exact NetworkManager profile could not be read."
    expected = NetworkManagerProfileIPState(
        profile_uuid=state.profile_uuid,
        profile_name=state.profile_name,
        connection_type=state.connection_type,
        family=state.family,
        method=selected_method,
        addresses=selected_addresses,
        gateway=selected_gateway,
    )
    if state.as_payload() == expected.as_payload():
        return None, "The saved IP profile already matches the requested method, addresses, and gateway."
    material = {
        "before": state.as_payload(),
        "requested": expected.as_payload(),
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()[:16]
    return NetworkManagerProfileIPTarget(
        before=state,
        method=selected_method,
        addresses=selected_addresses,
        gateway=selected_gateway,
        confirmation_phrase=f"SET {selected_family.upper()} {state.profile_uuid} {digest}",
    ), None


def perform_network_manager_profile_ip_configuration(
    profile_uuid: str,
    family: IPFamily,
    method: IPMethod,
    addresses: list[str] | None = None,
    gateway: str | None = None,
    *,
    confirmed: bool,
    confirmed_profile_uuid: str | None = None,
    confirmed_phrase: str | None = None,
) -> NetworkManagerProfileIPConfigResponse:
    normalized = _normalize_request(profile_uuid, family, method, addresses, gateway)
    normalized_uuid, selected_family, selected_method, selected_addresses, selected_gateway, error = normalized
    if error or normalized_uuid is None or selected_family is None or selected_method is None or selected_addresses is None:
        return NetworkManagerProfileIPConfigResponse(
            success=False,
            family=family if isinstance(family, str) and family in {"ipv4", "ipv6"} else None,
            user_confirmed=confirmed is True,
            message=error or "The requested IP profile change could not be validated.",
        )
    target, error = network_manager_profile_ip_confirmation_details(
        normalized_uuid,
        selected_family,
        selected_method,
        list(selected_addresses),
        selected_gateway,
    )
    if error or target is None:
        return NetworkManagerProfileIPConfigResponse(
            success=False,
            profile_uuid=normalized_uuid,
            profile_name=None,
            connection_type=None,
            family=selected_family,
            method=selected_method,
            addresses=list(selected_addresses),
            gateway=selected_gateway,
            user_confirmed=confirmed is True,
            message=error or "The saved IP profile could not be verified.",
        )
    before = target.before
    if not confirmed:
        return NetworkManagerProfileIPConfigResponse(
            success=False,
            profile_uuid=before.profile_uuid,
            profile_name=before.profile_name,
            connection_type=before.connection_type,
            family=selected_family,
            method=selected_method,
            previous_method=before.method,
            previous_addresses=list(before.addresses),
            previous_gateway=before.gateway,
            addresses=list(selected_addresses),
            gateway=selected_gateway,
            user_confirmed=False,
            message="Explicit client confirmation is required; no saved profile change was made.",
        )
    repeated_uuid, uuid_error = _normalized_uuid(confirmed_profile_uuid)
    if uuid_error or repeated_uuid != normalized_uuid or confirmed_phrase != target.confirmation_phrase:
        return NetworkManagerProfileIPConfigResponse(
            success=False,
            profile_uuid=before.profile_uuid,
            profile_name=before.profile_name,
            connection_type=before.connection_type,
            family=selected_family,
            method=selected_method,
            previous_method=before.method,
            previous_addresses=list(before.addresses),
            previous_gateway=before.gateway,
            addresses=list(selected_addresses),
            gateway=selected_gateway,
            user_confirmed=True,
            message="Confirmation did not match the exact profile UUID and saved IP state.",
        )
    with _ACTION_LOCK:
        current, current_error = network_manager_profile_ip_confirmation_details(
            normalized_uuid,
            selected_family,
            selected_method,
            list(selected_addresses),
            selected_gateway,
        )
        if current_error or current is None or current.confirmation_phrase != target.confirmation_phrase:
            return NetworkManagerProfileIPConfigResponse(
                success=False,
                profile_uuid=before.profile_uuid,
                profile_name=before.profile_name,
                connection_type=before.connection_type,
                family=selected_family,
                method=selected_method,
                previous_method=before.method,
                previous_addresses=list(before.addresses),
                previous_gateway=before.gateway,
                addresses=list(selected_addresses),
                gateway=selected_gateway,
                user_confirmed=True,
                message=current_error or "The saved IP profile changed after confirmation; no update was run.",
            )
        env = _environment()
        binary = find_session_binary("nmcli", env)
        if not binary:
            return NetworkManagerProfileIPConfigResponse(
                success=False,
                profile_uuid=before.profile_uuid,
                profile_name=before.profile_name,
                connection_type=before.connection_type,
                family=selected_family,
                method=selected_method,
                addresses=list(selected_addresses),
                gateway=selected_gateway,
                user_confirmed=True,
                message="NetworkManager's nmcli command became unavailable; no update was run.",
            )
        arguments = [
            "--wait", "12", "connection", "modify", "uuid", normalized_uuid,
            f"{selected_family}.method", selected_method,
            f"{selected_family}.addresses", ",".join(selected_addresses),
            f"{selected_family}.gateway", selected_gateway or "",
        ]
        _output, command_error, truncated = run_bounded_command(
            [binary, *arguments],
            env,
            command_label="Update confirmed NetworkManager saved IP profile settings",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_OUTPUT_BYTES,
        )
        response_values = {
            "profile_uuid": before.profile_uuid,
            "profile_name": before.profile_name,
            "connection_type": before.connection_type,
            "family": selected_family,
            "method": selected_method,
            "previous_method": before.method,
            "previous_addresses": list(before.addresses),
            "previous_gateway": before.gateway,
            "addresses": list(selected_addresses),
            "gateway": selected_gateway,
            "user_confirmed": True,
        }
        if command_error or _output is None or truncated:
            message = (
                "The NetworkManager update timed out; saved profile state may be partial. Inspect the profile before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "NetworkManager rejected or could not complete the IP profile update. Inspect the profile before retrying."
            )
            return NetworkManagerProfileIPConfigResponse(success=False, **response_values, message=message)
        updated, read_error = _read_profile_snapshot(normalized_uuid, selected_family)
        if read_error or updated is None:
            return NetworkManagerProfileIPConfigResponse(
                success=False,
                **response_values,
                message="NetworkManager changed the profile, but its saved IP result could not be verified; inspect it before retrying.",
            )
        verified = (
            updated.profile_uuid == normalized_uuid
            and updated.method == selected_method
            and updated.addresses == selected_addresses
            and updated.gateway == selected_gateway
        )
        if not verified:
            return NetworkManagerProfileIPConfigResponse(
                success=False,
                **response_values,
                message="The saved IP profile did not reach the requested values; inspect it before retrying.",
            )
        return NetworkManagerProfileIPConfigResponse(
            success=True,
            **response_values,
            message="Updated and verified the saved NetworkManager IP settings. No activation or reapply command was run.",
        )
