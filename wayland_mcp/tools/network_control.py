"""Identity-checked, explicitly confirmed Linux link state and MTU changes."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import NetworkAddressActionResponse, NetworkInterfaceActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

NetworkInterfaceAction = Literal["set_up", "set_down", "set_mtu"]
NetworkAddressAction = Literal["add", "remove"]
SYS_CLASS_NET = Path("/sys/class/net")
IFNAME_RE = re.compile(r"^[A-Za-z0-9_.:@+-]{1,15}$")
ALLOWED_ACTIONS = {"set_up", "set_down", "set_mtu"}
TOKEN_TTL_SECONDS = 300
MAX_TOKENS = 1_024
COMMAND_TIMEOUT_SECONDS = 5
MAX_ADDRESS_OUTPUT_BYTES = 512 * 1024
MAX_INTERFACE_ADDRESS_ROWS = 4_096


@dataclass(frozen=True, slots=True)
class InterfaceSnapshot:
    name: str
    index: int
    address: str
    mtu: int
    administrative_up: bool
    is_loopback: bool


@dataclass(slots=True)
class _TokenRecord:
    snapshot: InterfaceSnapshot
    expires_at: float
    claimed: bool = False
    action: str | None = None
    mtu: int | None = None
    address: str | None = None


_TOKENS: dict[str, _TokenRecord] = {}
_TOKEN_LOCK = threading.Lock()


def _read_sysfs_value(path: Path, max_bytes: int = 256) -> str:
    with path.open("rb") as stream:
        return stream.read(max_bytes).decode("ascii").strip()


def capture_interface(name: str) -> tuple[InterfaceSnapshot | None, str | None]:
    """Capture the link identity and mutable state used for stale-token checks."""
    if not sys.platform.startswith("linux"):
        return None, "Network interface control is available only on Linux."
    if not isinstance(name, str) or not IFNAME_RE.fullmatch(name):
        return None, "The interface name is not supported for link control."
    interface_dir = SYS_CLASS_NET / name
    try:
        index = socket.if_nametoindex(name)
        address = _read_sysfs_value(interface_dir / "address").casefold()
        mtu = int(_read_sysfs_value(interface_dir / "mtu"))
        flags = int(_read_sysfs_value(interface_dir / "flags"), 0)
    except (OSError, UnicodeError, ValueError):
        return None, "The interface is unavailable or its current state could not be read."
    if index <= 0 or not address or not 68 <= mtu <= 0xFFFFFFFF:
        return None, "The interface identity or current MTU could not be verified."
    return InterfaceSnapshot(
        name=name,
        index=index,
        address=address,
        mtu=mtu,
        administrative_up=bool(flags & 0x1),
        is_loopback=bool(flags & 0x8) or name == "lo",
    ), None


def iproute2_available() -> bool:
    return bool(find_session_binary("ip", get_sanitized_env(dict(os.environ))))


def _prune_tokens_locked() -> None:
    now = time.monotonic()
    expired = [token for token, record in _TOKENS.items() if record.expires_at <= now]
    for token in expired:
        _TOKENS.pop(token, None)
    if len(_TOKENS) >= MAX_TOKENS:
        oldest = sorted(_TOKENS, key=lambda token: _TOKENS[token].expires_at)
        for token in oldest[: len(_TOKENS) - MAX_TOKENS + 1]:
            _TOKENS.pop(token, None)


def issue_interface_token(snapshot: InterfaceSnapshot) -> str:
    token = secrets.token_urlsafe(32)
    with _TOKEN_LOCK:
        _prune_tokens_locked()
        _TOKENS[token] = _TokenRecord(snapshot=snapshot, expires_at=time.monotonic() + TOKEN_TTL_SECONDS)
    return token


def _token_record(identity_token: str) -> tuple[_TokenRecord | None, str | None]:
    if not isinstance(identity_token, str) or not 32 <= len(identity_token) <= 100:
        return None, "A fresh identity token from list_network_interfaces is required."
    with _TOKEN_LOCK:
        _prune_tokens_locked()
        record = _TOKENS.get(identity_token)
    if record is None:
        return None, "The interface identity token is unknown or expired; list interfaces again."
    return record, None


def _run_ip_command(
    arguments: list[str],
    *,
    label: str,
    max_output_bytes: int = 16 * 1024,
) -> tuple[str | None, str | None, bool]:
    env = get_sanitized_env(dict(os.environ))
    ip_binary = find_session_binary("ip", env)
    if not ip_binary:
        return None, "The iproute2 'ip' command is unavailable.", False
    return run_bounded_command(
        [ip_binary, *arguments],
        env,
        command_label=label,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=max_output_bytes,
    )


def _normalize_address(value: str) -> tuple[ipaddress.IPv4Interface | ipaddress.IPv6Interface | None, str | None]:
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 64
        or "/" not in value
        or "%" in value
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        return None, "address must be an explicit IPv4/IPv6 CIDR without a zone identifier."
    try:
        parsed = ipaddress.ip_interface(value)
    except ValueError:
        return None, "address must be a valid IPv4/IPv6 CIDR."
    if parsed.ip.is_unspecified or parsed.ip.is_multicast:
        return None, "Unspecified and multicast addresses are not supported."
    return parsed, None


def _read_interface_addresses(
    snapshot: InterfaceSnapshot,
) -> tuple[list[tuple[str, int, bool]] | None, str | None]:
    output, error, truncated = _run_ip_command(
        ["-j", "address", "show", "dev", snapshot.name],
        label="iproute2 interface address inventory",
        max_output_bytes=MAX_ADDRESS_OUTPUT_BYTES,
    )
    if error:
        return None, "Current interface addresses could not be read."
    if truncated:
        return None, "The interface address response exceeded the output limit."
    try:
        rows = json.loads(output or "", parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
    except (json.JSONDecodeError, ValueError):
        return None, "iproute2 returned malformed JSON for the interface address inventory."
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return None, "iproute2 returned an unexpected interface address response."
    interface = rows[0]
    raw_index = interface.get("ifindex")
    if (
        interface.get("ifname") != snapshot.name
        or not isinstance(raw_index, int)
        or isinstance(raw_index, bool)
        or raw_index != snapshot.index
    ):
        return None, "The interface identity changed while its addresses were read."
    raw_addresses = interface.get("addr_info")
    if not isinstance(raw_addresses, list) or len(raw_addresses) > MAX_INTERFACE_ADDRESS_ROWS:
        return None, "The interface address response was missing or exceeded the scan limit."
    addresses: list[tuple[str, int, bool]] = []
    for item in raw_addresses:
        if not isinstance(item, dict):
            return None, "iproute2 returned a malformed interface address entry."
        family = item.get("family")
        local = item.get("local")
        prefix = item.get("prefixlen")
        peer = item.get("peer")
        if not isinstance(family, str) or family not in {"inet", "inet6"} or not isinstance(local, str):
            return None, "iproute2 returned an unsupported interface address entry."
        if not isinstance(prefix, int) or isinstance(prefix, bool) or not 0 <= prefix <= (32 if family == "inet" else 128):
            return None, "iproute2 returned an invalid interface address prefix."
        try:
            parsed_local = ipaddress.ip_address(local)
        except ValueError:
            return None, "iproute2 returned an invalid interface address."
        if parsed_local.version != (4 if family == "inet" else 6):
            return None, "iproute2 returned an address with a mismatched family."
        if peer is not None and not isinstance(peer, str):
            return None, "iproute2 returned an invalid peer address."
        addresses.append((str(parsed_local), prefix, peer is not None))
    return addresses, None


def _address_precondition_error(
    action: str,
    parsed: ipaddress.IPv4Interface | ipaddress.IPv6Interface,
    addresses: list[tuple[str, int, bool]],
) -> str | None:
    local = str(parsed.ip)
    prefix = parsed.network.prefixlen
    matching_local = [entry for entry in addresses if entry[0] == local]
    matching_exact = [entry for entry in matching_local if entry[1] == prefix]
    if action == "add":
        if matching_local:
            return "That address is already configured on the interface; use its current address inventory before changing it."
        return None
    if not matching_exact:
        return "That exact address and prefix are not currently configured on the interface."
    if len(matching_local) != 1 or len(matching_exact) != 1 or matching_exact[0][2]:
        return "Peer or duplicate address entries are not supported by this removal action."
    return None


def _validate_request(action: str, mtu: int | None) -> str | None:
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        return "Choose one supported interface action: set_up, set_down, or set_mtu."
    if action == "set_mtu":
        if not isinstance(mtu, int) or isinstance(mtu, bool) or not 68 <= mtu <= 65_535:
            return "mtu must be an integer from 68 through 65535 for set_mtu."
    elif mtu is not None:
        return "mtu is accepted only with the set_mtu action."
    return None


def interface_action_confirmation_details(
    action: str,
    identity_token: str,
    mtu: int | None,
) -> tuple[InterfaceSnapshot | None, str | None]:
    error = _validate_request(action, mtu)
    if error:
        return None, error
    if not iproute2_available():
        return None, "The iproute2 'ip' command is unavailable."
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, error
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.expires_at <= time.monotonic():
            _TOKENS.pop(identity_token, None)
            return None, "The interface identity token expired; list interfaces again."
        if record.claimed:
            return None, "This interface token is already being used for an action. List interfaces again."
        record.claimed = True
        record.action = action
        record.mtu = mtu
    current, error = capture_interface(record.snapshot.name)
    if error or current is None or current != record.snapshot:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, "The interface identity or state changed since it was listed; list interfaces again before acting."
    if action == "set_down" and current.is_loopback:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, "Taking the loopback interface down is not supported."
    return current, None


def _run_ip(action: str, snapshot: InterfaceSnapshot, mtu: int | None) -> tuple[str | None, str | None, bool]:
    if action == "set_mtu":
        arguments = ["link", "set", "dev", snapshot.name, "mtu", str(mtu)]
    else:
        state = "up" if action == "set_up" else "down"
        arguments = ["link", "set", "dev", snapshot.name, state]
    return _run_ip_command(
        arguments,
        label="iproute2 interface control",
        max_output_bytes=16 * 1024,
    )


def perform_interface_action(
    action: str,
    identity_token: str,
    *,
    mtu: int | None,
    confirmed: bool,
) -> NetworkInterfaceActionResponse:
    safe_action = action if isinstance(action, str) and action in ALLOWED_ACTIONS else "set_up"
    record, error = _token_record(identity_token)
    if error or record is None:
        return NetworkInterfaceActionResponse(success=False, action=safe_action, message=error or "A fresh interface identity token is required.")
    snapshot = record.snapshot
    response_info = {
        "action": safe_action,
        "interface": snapshot.name,
        "interface_index": snapshot.index,
        "mtu": mtu if safe_action == "set_mtu" and isinstance(mtu, int) and not isinstance(mtu, bool) else None,
    }
    try:
        if not confirmed:
            return NetworkInterfaceActionResponse(
                success=False,
                **response_info,
                message="Explicit client confirmation is required; no network change was run.",
            )
        validation_error = _validate_request(action, mtu)
        if validation_error:
            return NetworkInterfaceActionResponse(success=False, **response_info, message=validation_error)
        with _TOKEN_LOCK:
            token_current = _TOKENS.get(identity_token) is record and record.expires_at > time.monotonic()
            action_confirmed = record.claimed and record.action == action and record.mtu == mtu
        if not token_current or not action_confirmed:
            return NetworkInterfaceActionResponse(
                success=False,
                **response_info,
                message="The action was not confirmed from a fresh interface identity token.",
            )
        current, error = capture_interface(snapshot.name)
        if error or current != snapshot:
            return NetworkInterfaceActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="The interface identity or state changed after confirmation; no network change was run. List interfaces again.",
            )
        if action == "set_down" and snapshot.is_loopback:
            return NetworkInterfaceActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="Taking the loopback interface down is not supported.",
            )
        _output, error, truncated = _run_ip(action, snapshot, mtu)
        if error or truncated:
            message = (
                "The interface command may have changed network state before timing out; list interfaces to verify before retrying."
                if error and "timed out" in error.casefold()
                else "iproute2 rejected or could not confirm the interface change; list interfaces to verify current state."
            )
            return NetworkInterfaceActionResponse(success=False, **response_info, user_confirmed=True, message=message)
        updated, error = capture_interface(snapshot.name)
        if error or updated is None:
            return NetworkInterfaceActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="The interface command completed, but current state could not be verified; list interfaces before retrying.",
            )
        if updated.index != snapshot.index or updated.address != snapshot.address:
            return NetworkInterfaceActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="The interface identity changed during the request; list interfaces to verify current state.",
            )
        expected = (
            updated.mtu == mtu
            if action == "set_mtu"
            else updated.administrative_up is (action == "set_up")
        )
        if not expected:
            return NetworkInterfaceActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="The request completed, but the interface is not in the requested state; a network manager may have changed it. List interfaces to verify.",
            )
        return NetworkInterfaceActionResponse(
            success=True,
            **response_info,
            user_confirmed=True,
            message="The interface change was applied and verified in the current network namespace; it is not persisted across reboot.",
        )
    finally:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)


def address_action_confirmation_details(
    action: str,
    identity_token: str,
    address: str,
) -> tuple[InterfaceSnapshot | None, str | None, str | None]:
    if not isinstance(action, str) or action not in {"add", "remove"}:
        return None, None, "Choose one supported address action: add or remove."
    parsed, error = _normalize_address(address)
    if error or parsed is None:
        return None, None, error
    canonical_address = str(parsed)
    if not iproute2_available():
        return None, None, "The iproute2 'ip' command is unavailable."
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, None, error
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.expires_at <= time.monotonic():
            _TOKENS.pop(identity_token, None)
            return None, None, "The interface identity token expired; list interfaces again."
        if record.claimed:
            return None, None, "This interface token is already being used for an action. List interfaces again."
        record.claimed = True
        record.action = f"{action}_address"
        record.mtu = None
        record.address = canonical_address
    snapshot = record.snapshot
    current, error = capture_interface(snapshot.name)
    if error or current is None or current != snapshot:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, None, "The interface identity or state changed since it was listed; list interfaces again before acting."
    if parsed.ip.is_loopback and not current.is_loopback:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, None, "Loopback addresses can be added only to a loopback interface."
    if action == "remove" and current.is_loopback and parsed.ip in {
        ipaddress.IPv4Address("127.0.0.1"),
        ipaddress.IPv6Address("::1"),
    }:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, None, "Removing the standard loopback address is not supported."
    addresses, error = _read_interface_addresses(current)
    if error or addresses is None:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, None, error or "The interface address inventory could not be read."
    precondition_error = _address_precondition_error(action, parsed, addresses)
    if precondition_error:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, None, precondition_error
    return current, canonical_address, None


def perform_address_action(
    action: str,
    identity_token: str,
    address: str,
    *,
    confirmed: bool,
) -> NetworkAddressActionResponse:
    safe_action = action if isinstance(action, str) and action in {"add", "remove"} else "add"
    record, error = _token_record(identity_token)
    if error or record is None:
        return NetworkAddressActionResponse(
            success=False,
            action=safe_action,
            message=error or "A fresh interface identity token is required.",
        )
    snapshot = record.snapshot
    parsed, address_error = _normalize_address(address)
    canonical_address = str(parsed) if parsed is not None else None
    response_info = {
        "action": safe_action,
        "interface": snapshot.name,
        "interface_index": snapshot.index,
        "address": canonical_address,
    }
    try:
        if not confirmed:
            return NetworkAddressActionResponse(
                success=False,
                **response_info,
                message="Explicit client confirmation is required; no address change was run.",
            )
        if not isinstance(action, str) or action not in {"add", "remove"}:
            return NetworkAddressActionResponse(success=False, **response_info, message="Choose one supported address action: add or remove.")
        if address_error or parsed is None or canonical_address is None:
            return NetworkAddressActionResponse(success=False, **response_info, message=address_error or "A valid address is required.")
        with _TOKEN_LOCK:
            token_current = _TOKENS.get(identity_token) is record and record.expires_at > time.monotonic()
            action_confirmed = (
                record.claimed
                and record.action == f"{action}_address"
                and record.address == canonical_address
                and record.mtu is None
            )
        if not token_current or not action_confirmed:
            return NetworkAddressActionResponse(
                success=False,
                **response_info,
                message="The address change was not confirmed for this fresh interface identity token.",
            )
        current, error = capture_interface(snapshot.name)
        if error or current is None or current != snapshot:
            return NetworkAddressActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="The interface identity or state changed after confirmation; no address change was run. List interfaces again.",
            )
        if parsed.ip.is_loopback and not current.is_loopback:
            return NetworkAddressActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="Loopback addresses can be added only to a loopback interface.",
            )
        if action == "remove" and current.is_loopback and parsed.ip in {
            ipaddress.IPv4Address("127.0.0.1"),
            ipaddress.IPv6Address("::1"),
        }:
            return NetworkAddressActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="Removing the standard loopback address is not supported.",
            )
        addresses, error = _read_interface_addresses(current)
        if error or addresses is None:
            return NetworkAddressActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message=error or "The interface address inventory could not be read.",
            )
        precondition_error = _address_precondition_error(action, parsed, addresses)
        if precondition_error:
            return NetworkAddressActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message=f"{precondition_error} No address change was run.",
            )
        verb = "add" if action == "add" else "del"
        _output, error, truncated = _run_ip_command(
            ["address", verb, canonical_address, "dev", snapshot.name],
            label="iproute2 interface address control",
            max_output_bytes=16 * 1024,
        )
        if error or truncated:
            message = (
                "The address command may have completed before timing out; inspect current interface addresses before retrying."
                if error and "timed out" in error.casefold()
                else "iproute2 rejected or could not confirm the address change; inspect current interface addresses before retrying."
            )
            return NetworkAddressActionResponse(success=False, **response_info, user_confirmed=True, message=message)
        updated, error = capture_interface(snapshot.name)
        if error or updated is None or updated.index != snapshot.index or updated.address != snapshot.address:
            return NetworkAddressActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="The address command completed, but the interface identity changed or could not be verified; inspect current network state.",
            )
        updated_addresses, error = _read_interface_addresses(updated)
        if error or updated_addresses is None:
            return NetworkAddressActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="The address command completed, but the result could not be verified; inspect current interface addresses.",
            )
        exact_address_entries = [
            (local, prefix, peer)
            for local, prefix, peer in updated_addresses
            if local == str(parsed.ip) and prefix == parsed.network.prefixlen
        ]
        expected = (
            len(exact_address_entries) == 1 and not exact_address_entries[0][2]
            if action == "add"
            else not exact_address_entries
        )
        if not expected:
            return NetworkAddressActionResponse(
                success=False,
                **response_info,
                user_confirmed=True,
                message="The request completed, but the exact address state did not match; a network manager may have changed it. Inspect current interface addresses.",
            )
        return NetworkAddressActionResponse(
            success=True,
            **response_info,
            user_confirmed=True,
            message="The address change was applied and verified in the current network namespace; it is not persisted across reboot.",
        )
    finally:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
