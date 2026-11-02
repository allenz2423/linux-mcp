"""Bounded BlueZ device inventory and explicit-confirmation pairing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import (
    BluetoothDeviceInfo,
    BluetoothDeviceListResponse,
    BluetoothPairingResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

DEVICE_ADDRESS_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
DEVICE_LINE_RE = re.compile(r"^\s*Device\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?:\s+(.*))?\s*$")
INFO_FIELD_RE = re.compile(r"^\s*(Address|Name|Alias|Paired|Trusted|Connected|Blocked):\s*(.*?)\s*$", re.IGNORECASE)
SYSTEM_BUS_PATHS = (Path("/run/dbus/system_bus_socket"), Path("/var/run/dbus/system_bus_socket"))
MAX_SCANNED_DEVICES = 512
MAX_RETURNED_DEVICES = 128
MAX_OUTPUT_BYTES = 64 * 1024
MAX_NAME_LENGTH = 128
MAX_TOKENS = 4096
TOKEN_TTL_SECONDS = 180
INVENTORY_TIMEOUT_SECONDS = 8
INFO_TIMEOUT_SECONDS = 10
PAIR_TIMEOUT_SECONDS = 90


@dataclass(frozen=True, slots=True)
class _DeviceState:
    address: str
    name: str | None
    paired: bool
    trusted: bool | None
    connected: bool | None
    blocked: bool | None


@dataclass(slots=True)
class _DeviceToken:
    address: str
    listed_name: str | None
    expires_at: float
    claimed: bool = False
    executing: bool = False
    state: _DeviceState | None = None
    state_token: str | None = None


@dataclass(frozen=True, slots=True)
class BluetoothPairingTarget:
    address: str
    name: str | None
    paired: bool
    trusted: bool | None
    connected: bool | None
    state_token: str


_TOKENS: dict[str, _DeviceToken] = {}
_TOKEN_LOCK = threading.Lock()
_PAIR_LOCK = threading.Lock()


def _environment() -> dict[str, str]:
    return get_sanitized_env()


def _bluetoothctl(env: dict[str, str] | None = None) -> str | None:
    return find_session_binary("bluetoothctl", env or _environment())


def bluetooth_tools_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux") or not _bluetoothctl(env):
        return False
    return any(path.exists() for path in SYSTEM_BUS_PATHS)


def _run_bluetoothctl(
    arguments: list[str],
    *,
    timeout_seconds: float,
    env: dict[str, str] | None = None,
) -> tuple[str | None, str | None, bool]:
    current_env = env or _environment()
    binary = _bluetoothctl(current_env)
    if not binary:
        return None, "The bluetoothctl command is unavailable.", False
    return run_bounded_command(
        [binary, "-t", str(max(1, min(int(timeout_seconds), 120))), *arguments],
        current_env,
        command_label="bluetoothctl",
        timeout_seconds=timeout_seconds + 2,
        max_output_bytes=MAX_OUTPUT_BYTES,
        kill_process_group=True,
    )


def _clean_name(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = "".join(
        " " if ord(character) < 32 or ord(character) == 127 else character
        for character in value
    )[:MAX_NAME_LENGTH].strip()
    return cleaned or None


def _parse_device_list(output: str) -> dict[str, str | None]:
    devices: dict[str, str | None] = {}
    for line in output.splitlines()[:MAX_SCANNED_DEVICES]:
        match = DEVICE_LINE_RE.fullmatch(line)
        if not match:
            continue
        address = match.group(1).upper()
        devices[address] = _clean_name(match.group(2))
    return devices


def _prune_tokens_locked(now: float) -> None:
    expired = [key for key, value in _TOKENS.items() if value.expires_at <= now]
    for key in expired:
        _TOKENS.pop(key, None)
    if len(_TOKENS) >= MAX_TOKENS:
        oldest = sorted(_TOKENS, key=lambda key: _TOKENS[key].expires_at)
        for key in oldest[: len(_TOKENS) - MAX_TOKENS + 1]:
            _TOKENS.pop(key, None)


def _issue_token(address: str, name: str | None) -> str:
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _TOKEN_LOCK:
        _prune_tokens_locked(now)
        _TOKENS[token] = _DeviceToken(
            address=address,
            listed_name=name,
            expires_at=now + TOKEN_TTL_SECONDS,
        )
    return token


def list_bluetooth_devices(
    query: str = "",
    limit: int = 64,
) -> BluetoothDeviceListResponse:
    """List cached BlueZ devices without starting a scan."""
    if not sys.platform.startswith("linux"):
        return BluetoothDeviceListResponse(success=False, message="Bluetooth inventory is available only on Linux.")
    if not bluetooth_tools_available():
        return BluetoothDeviceListResponse(
            success=False,
            message="bluetoothctl and the system D-Bus socket are required for BlueZ device inventory.",
        )
    if not isinstance(query, str) or len(query) > 256:
        return BluetoothDeviceListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return BluetoothDeviceListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return BluetoothDeviceListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_DEVICES))

    output, error, truncated = _run_bluetoothctl(
        ["devices"], timeout_seconds=INVENTORY_TIMEOUT_SECONDS
    )
    if output is None or truncated:
        return BluetoothDeviceListResponse(
            success=False,
            limit=limit,
            message=error or "The bounded BlueZ device list could not be read completely.",
        )
    paired_output, paired_error, paired_truncated = _run_bluetoothctl(
        ["devices", "Paired"], timeout_seconds=INVENTORY_TIMEOUT_SECONDS
    )
    paired_names = _parse_device_list(paired_output or "") if paired_output is not None and not paired_truncated else {}
    paired_known = paired_output is not None and not paired_truncated

    all_devices = _parse_device_list(output)
    if len(output.splitlines()) > MAX_SCANNED_DEVICES:
        truncated = True
    needle = query.strip().casefold()
    filtered = [
        (address, name)
        for address, name in all_devices.items()
        if not needle or needle in address.casefold() or needle in (name or "").casefold()
    ]
    filtered.sort(key=lambda item: ((item[1] or "").casefold(), item[0]))
    shown = filtered[:limit]
    devices = [
        BluetoothDeviceInfo(
            address=address,
            name=name,
            paired=(address in paired_names) if paired_known else None,
            identity_token=_issue_token(address, name),
        )
        for address, name in shown
    ]
    result_truncated = truncated or len(filtered) > limit
    messages: list[str] = []
    if paired_error or paired_truncated:
        messages.append("Paired state could not be read for every device.")
    if result_truncated:
        messages.append("The BlueZ device inventory was capped by scan or result limits.")
    return BluetoothDeviceListResponse(
        success=True,
        total_devices=len(filtered),
        returned_devices=len(devices),
        devices=devices,
        limit=limit,
        partial=bool(messages),
        truncated=result_truncated,
        message=" ".join(messages) or None,
    )


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.casefold()
    if normalized in {"yes", "true", "1"}:
        return True
    if normalized in {"no", "false", "0"}:
        return False
    return None


def _read_device(address: str) -> tuple[_DeviceState | None, str | None]:
    if not DEVICE_ADDRESS_RE.fullmatch(address):
        return None, "Device address must be one exact six-octet Bluetooth address."
    output, error, truncated = _run_bluetoothctl(
        ["info", address], timeout_seconds=INFO_TIMEOUT_SECONDS
    )
    if output is None or truncated:
        return None, error or "The exact BlueZ device state could not be read completely."
    fields: dict[str, str] = {}
    observed_address: str | None = None
    for line in output.splitlines()[:256]:
        device_match = DEVICE_LINE_RE.fullmatch(line)
        if device_match:
            observed_address = device_match.group(1).upper()
        field_match = INFO_FIELD_RE.fullmatch(line)
        if field_match:
            fields[field_match.group(1).casefold()] = field_match.group(2)
    field_address = fields.get("address")
    if field_address and DEVICE_ADDRESS_RE.fullmatch(field_address):
        observed_address = field_address.upper()
    if observed_address != address.upper():
        return None, "BlueZ did not return the requested device address."
    paired = _parse_bool(fields.get("paired"))
    if paired is None:
        return None, "BlueZ did not report a parseable paired state for this device."
    name = _clean_name(fields.get("alias") or fields.get("name"))
    return _DeviceState(
        address=observed_address,
        name=name,
        paired=paired,
        trusted=_parse_bool(fields.get("trusted")),
        connected=_parse_bool(fields.get("connected")),
        blocked=_parse_bool(fields.get("blocked")),
    ), None


def _state_token(state: _DeviceState) -> str:
    payload = {
        "address": state.address,
        "name": state.name,
        "paired": state.paired,
        "trusted": state.trusted,
        "connected": state.connected,
        "blocked": state.blocked,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _token_record(identity_token: str) -> tuple[_DeviceToken | None, str | None]:
    if not isinstance(identity_token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,100}", identity_token):
        return None, "A fresh identity token from list_bluetooth_devices is required."
    with _TOKEN_LOCK:
        _prune_tokens_locked(time.monotonic())
        record = _TOKENS.get(identity_token)
    if record is None:
        return None, "The Bluetooth device token is unknown or expired; list devices again."
    return record, None


def bluetooth_pairing_confirmation_details(
    identity_token: str,
) -> tuple[BluetoothPairingTarget | None, str | None]:
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, error
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.claimed or record.expires_at <= time.monotonic():
            return None, "The Bluetooth device token is expired or already in use; list devices again."
        record.claimed = True
    state, error = _read_device(record.address)
    if error or state is None:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, error or "The BlueZ device state could not be verified."
    if record.listed_name and state.name and record.listed_name != state.name:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, "The device name changed after inventory; list Bluetooth devices again."
    if state.paired:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, "This device is already paired; no pairing action was prepared."
    if state.blocked:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, "This device is blocked in BlueZ and cannot be paired by this tool."
    state_token = _state_token(state)
    record.state = state
    record.state_token = state_token
    return BluetoothPairingTarget(
        address=state.address,
        name=state.name,
        paired=state.paired,
        trusted=state.trusted,
        connected=state.connected,
        state_token=state_token,
    ), None


def perform_bluetooth_pairing(
    identity_token: str,
    expected_state_token: str,
    confirmed_address: str,
    confirmed_name: str,
    *,
    confirmed: bool,
) -> BluetoothPairingResponse:
    record, error = _token_record(identity_token)
    if error or record is None:
        return BluetoothPairingResponse(success=False, message=error or "A fresh Bluetooth device token is required.")
    response_name = record.state.name if record.state else record.listed_name
    if confirmed is not True:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return BluetoothPairingResponse(
            success=False,
            address=record.address,
            name=response_name,
            user_confirmed=False,
            message="Explicit client confirmation is required; no Bluetooth pairing command was run.",
        )
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.executing:
            return BluetoothPairingResponse(
                success=False,
                address=record.address,
                name=response_name,
                user_confirmed=True,
                message="The Bluetooth device token is expired or already being used.",
            )
        record.executing = True
    try:
        if (
            not record.claimed
            or record.state is None
            or record.state_token is None
            or expected_state_token != record.state_token
            or confirmed_address != record.address
            or (confirmed_name or "") != (record.state.name or "")
        ):
            return BluetoothPairingResponse(
                success=False,
                address=record.address,
                name=response_name,
                user_confirmed=True,
                message="Confirmation did not match the exact device and observed unpaired state.",
            )
        with _PAIR_LOCK:
            current, error = _read_device(record.address)
            if error or current is None or current != record.state or current.paired or current.blocked:
                return BluetoothPairingResponse(
                    success=False,
                    address=record.address,
                    name=response_name,
                    user_confirmed=True,
                    message=error or "The device identity or pairing state changed after confirmation; no pairing was attempted.",
                )
            _output, command_error, command_truncated = _run_bluetoothctl(
                ["pair", record.address], timeout_seconds=PAIR_TIMEOUT_SECONDS
            )
            after, after_error = _read_device(record.address)
        if after is None:
            return BluetoothPairingResponse(
                success=False,
                address=record.address,
                name=response_name,
                user_confirmed=True,
                message="The pairing command ended but BlueZ could not verify the resulting state; inspect the device before retrying.",
            )
        if not after.paired:
            detail = "timed out" if command_error and "timed out" in command_error.casefold() else "did not complete"
            if command_truncated:
                detail = "produced more output than allowed"
            return BluetoothPairingResponse(
                success=False,
                address=after.address,
                name=after.name,
                paired=False,
                connected=after.connected,
                user_confirmed=True,
                message=f"Bluetooth pairing {detail}; check device proximity, authentication prompts, BlueZ agent availability, and adapter state.",
            )
        return BluetoothPairingResponse(
            success=True,
            address=after.address,
            name=after.name,
            paired=True,
            connected=after.connected,
            user_confirmed=True,
            message=(
                "BlueZ reports the device paired. Pairing initiated a Bluetooth connection; the current connected state is reported separately."
                if not command_error and not after_error
                else "BlueZ verifies the device is paired despite an incomplete command response; inspect its connection state."
            ),
        )
    finally:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
