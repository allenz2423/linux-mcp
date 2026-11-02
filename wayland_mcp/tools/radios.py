"""Bounded Linux rfkill inventory and explicitly confirmed per-radio soft blocks."""

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
from typing import Literal

from wayland_mcp.models import (
    RadioDeviceActionResponse,
    RadioDeviceInfo,
    RadioDeviceListResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

RadioDeviceAction = Literal["block", "unblock"]
RFKILL_ROOT = Path("/sys/class/rfkill")
SYS_DEVICES_ROOT = Path("/sys/devices")
RFKILL_ENTRY_RE = re.compile(r"^rfkill(0|[1-9][0-9]{0,9})$")
TYPE_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,100}$")
ACTIONS = {"block", "unblock"}
MAX_SCANNED_RADIOS = 512
MAX_DIRECTORY_ENTRIES = 2_048
MAX_RETURNED_RADIOS = 128
MAX_ATTRIBUTE_BYTES = 512
MAX_TOKENS = 4_096
TOKEN_TTL_SECONDS = 180
COMMAND_TIMEOUT_SECONDS = 10
MAX_COMMAND_OUTPUT_BYTES = 8 * 1024


@dataclass(frozen=True, slots=True)
class _Radio:
    index: int
    name: str
    radio_type: str
    soft_blocked: bool
    hard_blocked: bool
    sysfs_path: str


@dataclass(slots=True)
class _ActionToken:
    radio: _Radio
    rfkill: str | None
    expires_at: float
    claimed: bool = False
    executing: bool = False
    action: str | None = None
    confirmation_token: str | None = None


@dataclass(frozen=True, slots=True)
class RadioDeviceTarget:
    radio_index: int
    name: str
    radio_type: str
    soft_blocked: bool
    hard_blocked: bool
    confirmation_token: str


_TOKENS: dict[str, _ActionToken] = {}
_TOKEN_LOCK = threading.Lock()


def radio_inventory_available() -> bool:
    return sys.platform.startswith("linux") and RFKILL_ROOT.is_dir()


def rfkill_available(env: dict[str, str] | None = None) -> bool:
    return sys.platform.startswith("linux") and find_session_binary(
        "rfkill", env or get_sanitized_env()
    ) is not None


def _read_attribute(path: Path) -> str:
    with path.open("rb") as stream:
        value = stream.read(MAX_ATTRIBUTE_BYTES + 1)
    if len(value) > MAX_ATTRIBUTE_BYTES:
        raise ValueError("sysfs attribute exceeded its size limit")
    return value.decode("utf-8").strip()


def _read_radio(index: int) -> tuple[_Radio | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Radio-device inventory is available only on Linux."
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index <= 2_147_483_647:
        return None, "The rfkill device index is invalid."
    entry = RFKILL_ROOT / f"rfkill{index}"
    try:
        resolved_path = entry.resolve(strict=True)
        if not resolved_path.is_relative_to(SYS_DEVICES_ROOT):
            return None, "The rfkill device did not resolve to a kernel device path."
        if not resolved_path.is_dir():
            return None, "The rfkill device is no longer available."
        name_value = _read_attribute(entry / "name")
        type_value = _read_attribute(entry / "type").casefold()
        soft_value = _read_attribute(entry / "soft")
        hard_value = _read_attribute(entry / "hard")
        if entry.resolve(strict=True) != resolved_path:
            return None, "The rfkill device changed while its state was being read."
    except (OSError, RuntimeError, UnicodeError, ValueError):
        return None, "The rfkill device is unavailable or its sysfs state could not be read."
    name = "".join(
        " " if ord(character) < 32 or ord(character) == 127 else character
        for character in name_value
    )[:128].strip()
    if (
        not name
        or not TYPE_RE.fullmatch(type_value)
        or soft_value not in {"0", "1"}
        or hard_value not in {"0", "1"}
    ):
        return None, "The rfkill device has incomplete or unsupported sysfs attributes."
    return _Radio(
        index=index,
        name=name,
        radio_type=type_value,
        soft_blocked=soft_value == "1",
        hard_blocked=hard_value == "1",
        sysfs_path=str(resolved_path),
    ), None


def _prune_tokens_locked(now: float) -> None:
    expired = [
        token for token, record in _TOKENS.items()
        if record.expires_at <= now
    ]
    for token in expired:
        _TOKENS.pop(token, None)
    if len(_TOKENS) >= MAX_TOKENS:
        oldest = sorted(_TOKENS, key=lambda token: _TOKENS[token].expires_at)
        for token in oldest[: len(_TOKENS) - MAX_TOKENS + 1]:
            _TOKENS.pop(token, None)


def _issue_token(radio: _Radio, rfkill: str | None) -> str:
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _ActionToken(radio=radio, rfkill=rfkill, expires_at=now + TOKEN_TTL_SECONDS)
    with _TOKEN_LOCK:
        _prune_tokens_locked(now)
        _TOKENS[token] = record
    return token


def _token_record(identity_token: str) -> tuple[_ActionToken | None, str | None]:
    if not isinstance(identity_token, str) or not TOKEN_RE.fullmatch(identity_token):
        return None, "A fresh identity token from list_radio_devices is required."
    with _TOKEN_LOCK:
        _prune_tokens_locked(time.monotonic())
        record = _TOKENS.get(identity_token)
    if record is None:
        return None, "The radio-device identity token is unknown or expired; list radio devices again."
    return record, None


def _same_identity(left: _Radio, right: _Radio) -> bool:
    return (
        left.index == right.index
        and left.name == right.name
        and left.radio_type == right.radio_type
        and left.sysfs_path == right.sysfs_path
    )


def _same_radio(left: _Radio, right: _Radio) -> bool:
    return (
        _same_identity(left, right)
        and left.soft_blocked == right.soft_blocked
        and left.hard_blocked == right.hard_blocked
    )


def list_radio_devices(
    query: str = "",
    limit: int = 64,
) -> RadioDeviceListResponse:
    """List bounded radio identity and soft/hard block state from sysfs."""
    if not sys.platform.startswith("linux"):
        return RadioDeviceListResponse(success=False, message="Radio-device inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return RadioDeviceListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return RadioDeviceListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return RadioDeviceListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_RADIOS))
    if not RFKILL_ROOT.is_dir():
        return RadioDeviceListResponse(
            success=False,
            limit=limit,
            message="Linux rfkill sysfs is unavailable.",
        )
    entries: list[str] = []
    truncated = False
    try:
        with os.scandir(RFKILL_ROOT) as iterator:
            for position, entry in enumerate(iterator):
                if position >= MAX_DIRECTORY_ENTRIES:
                    truncated = True
                    break
                if RFKILL_ENTRY_RE.fullmatch(entry.name):
                    entries.append(entry.name)
                    if len(entries) > MAX_SCANNED_RADIOS:
                        truncated = True
                        break
    except OSError:
        return RadioDeviceListResponse(
            success=False,
            limit=limit,
            message="Linux rfkill sysfs could not be read.",
        )
    entries.sort()
    candidates = entries[:MAX_SCANNED_RADIOS]
    errors = 0
    radios: list[_Radio] = []
    for entry in candidates:
        match = RFKILL_ENTRY_RE.fullmatch(entry)
        if match is None:
            continue
        radio, error = _read_radio(int(match.group(1)))
        if error or radio is None:
            errors += 1
        else:
            radios.append(radio)
    needle = query.strip().casefold()
    filtered = [
        radio for radio in radios
        if not needle
        or needle in radio.name.casefold()
        or needle in radio.radio_type
        or needle == str(radio.index)
    ]
    filtered.sort(key=lambda radio: (radio.radio_type, radio.name.casefold(), radio.index))
    selected = filtered[:limit]
    rfkill = find_session_binary("rfkill", get_sanitized_env())
    devices = [
        RadioDeviceInfo(
            radio_index=radio.index,
            name=radio.name,
            radio_type=radio.radio_type,
            soft_blocked=radio.soft_blocked,
            hard_blocked=radio.hard_blocked,
            blocked=radio.soft_blocked or radio.hard_blocked,
            identity_token=_issue_token(radio, rfkill),
        )
        for radio in selected
    ]
    truncated |= len(filtered) > limit
    messages = []
    if errors:
        messages.append(f"{errors} rfkill device entr{'y' if errors == 1 else 'ies'} could not be read.")
    if truncated:
        messages.append("The radio inventory was capped by scan or result limits.")
    return RadioDeviceListResponse(
        success=True,
        total_radios=len(filtered),
        returned_radios=len(devices),
        devices=devices,
        limit=limit,
        truncated=truncated,
        partial=bool(errors or truncated),
        message=" ".join(messages) or None,
    )


def radio_action_confirmation_details(
    action: str,
    identity_token: str,
) -> tuple[RadioDeviceTarget | None, str | None]:
    if not isinstance(action, str) or action not in ACTIONS:
        return None, "Choose block or unblock."
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, error
    with _TOKEN_LOCK:
        if (
            _TOKENS.get(identity_token) is not record
            or record.expires_at <= time.monotonic()
            or record.claimed
        ):
            return None, "The radio identity token is expired or already in use; list radio devices again."
        if not record.rfkill:
            _TOKENS.pop(identity_token, None)
            return None, "The optional rfkill command is unavailable; no radio change was made."
        record.claimed = True
    current, error = _read_radio(record.radio.index)
    if error or current is None or not _same_radio(record.radio, current):
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, error or "The radio device or its state changed; list radio devices again."
    if action == "unblock" and current.hard_blocked:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, "The radio is hard-blocked by a hardware or platform switch; software cannot unblock it."
    token_payload = {
        "action": action,
        "index": current.index,
        "name": current.name,
        "type": current.radio_type,
        "soft_blocked": current.soft_blocked,
        "hard_blocked": current.hard_blocked,
        "sysfs_path": current.sysfs_path,
    }
    confirmation_token = hashlib.sha256(
        json.dumps(token_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    record.action = action
    record.confirmation_token = confirmation_token
    return RadioDeviceTarget(
        radio_index=current.index,
        name=current.name,
        radio_type=current.radio_type,
        soft_blocked=current.soft_blocked,
        hard_blocked=current.hard_blocked,
        confirmation_token=confirmation_token,
    ), None


def perform_radio_device_action(
    action: str,
    identity_token: str,
    expected_state_token: str,
    confirmed_index: int,
    confirmed_name: str,
    confirmed_type: str,
    *,
    confirmed: bool,
) -> RadioDeviceActionResponse:
    safe_action: RadioDeviceAction = action if isinstance(action, str) and action in ACTIONS else "block"  # type: ignore[assignment]
    record, error = _token_record(identity_token)
    if error or record is None:
        return RadioDeviceActionResponse(success=False, action=safe_action, message=error or "A fresh radio identity token is required.")
    response_radio = {
        "radio_index": record.radio.index,
        "name": record.radio.name,
        "radio_type": record.radio.radio_type,
    }
    if confirmed is not True:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return RadioDeviceActionResponse(
            success=False,
            action=safe_action,
            **response_radio,
            message="Explicit client confirmation is required; no radio command was run.",
        )
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.executing:
            return RadioDeviceActionResponse(
                success=False,
                action=safe_action,
                **response_radio,
                user_confirmed=True,
                message="The radio identity token is expired or already being used.",
            )
        record.executing = True
    try:
        if not isinstance(action, str) or action not in ACTIONS:
            return RadioDeviceActionResponse(
                success=False,
                action=safe_action,
                **response_radio,
                user_confirmed=True,
                message="Unsupported radio action; no command was run.",
            )
        if not record.claimed or record.action != action or not record.rfkill:
            return RadioDeviceActionResponse(
                success=False,
                action=safe_action,
                **response_radio,
                user_confirmed=True,
                message="The action was not confirmed from a fresh radio-device token.",
            )
        if (
            confirmed_index != record.radio.index
            or confirmed_name != record.radio.name
            or confirmed_type != record.radio.radio_type
            or expected_state_token != record.confirmation_token
        ):
            return RadioDeviceActionResponse(
                success=False,
                action=safe_action,
                **response_radio,
                user_confirmed=True,
                message="Confirmation did not match the exact radio, action, or state token; no command was run.",
            )
        current, error = _read_radio(record.radio.index)
        if error or current is None or not _same_radio(record.radio, current):
            return RadioDeviceActionResponse(
                success=False,
                action=safe_action,
                **response_radio,
                user_confirmed=True,
                message=error or "The radio device or its state changed after confirmation; list radio devices again.",
            )
        if action == "unblock" and current.hard_blocked:
            return RadioDeviceActionResponse(
                success=False,
                action=safe_action,
                **response_radio,
                soft_blocked=current.soft_blocked,
                hard_blocked=current.hard_blocked,
                user_confirmed=True,
                message="The radio became hard-blocked after confirmation; no command was run.",
            )
        already_reached = (
            action == "block" and current.soft_blocked
            or action == "unblock" and not current.soft_blocked
        )
        if already_reached:
            return RadioDeviceActionResponse(
                success=True,
                action=safe_action,
                **response_radio,
                soft_blocked=current.soft_blocked,
                hard_blocked=current.hard_blocked,
                state_verified=True,
                user_confirmed=True,
                message=f"Radio {current.radio_type} device {current.name!r} already has the requested soft-block state; no command was needed.",
            )
        env = get_sanitized_env()
        env["LANG"] = "C"
        env["LC_ALL"] = "C"
        _output, command_error, output_truncated = run_bounded_command(
            [record.rfkill, action, str(record.radio.index)],
            env,
            command_label=f"rfkill {action}",
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
        )
        if output_truncated:
            command_error = command_error or "rfkill output exceeded the configured limit."
        after, verify_error = _read_radio(record.radio.index)
        same_instance = after is not None and _same_identity(record.radio, after)
        soft_blocked = after.soft_blocked if same_instance and after is not None else None
        hard_blocked = after.hard_blocked if same_instance and after is not None else None
        verified = soft_blocked == (action == "block")
        if command_error:
            message = f"rfkill reported an error: {command_error[:400]}"
            if verify_error:
                message += f" {verify_error}"
            if verified:
                message += " The requested software state is visible; inspect the radio before retrying."
            return RadioDeviceActionResponse(
                success=False,
                action=safe_action,
                **response_radio,
                soft_blocked=soft_blocked,
                hard_blocked=hard_blocked,
                state_verified=verified,
                user_confirmed=True,
                message=message,
            )
        if not same_instance or after is None:
            return RadioDeviceActionResponse(
                success=False,
                action=safe_action,
                **response_radio,
                user_confirmed=True,
                message=verify_error or "The radio device changed during the command; inspect the inventory before retrying.",
            )
        if not verified:
            return RadioDeviceActionResponse(
                success=False,
                action=safe_action,
                **response_radio,
                soft_blocked=after.soft_blocked,
                hard_blocked=after.hard_blocked,
                user_confirmed=True,
                message=f"The rfkill command returned successfully, but the requested soft-block state was not verified. Current state: soft_blocked={after.soft_blocked}, hard_blocked={after.hard_blocked}.",
            )
        state = "blocked" if after.soft_blocked else "unblocked"
        message = f"Radio {after.radio_type} device {after.name!r} is now software {state}."
        if action == "unblock":
            message += " This does not connect to a network; a network manager may react to the radio becoming available."
        return RadioDeviceActionResponse(
            success=True,
            action=safe_action,
            **response_radio,
            soft_blocked=after.soft_blocked,
            hard_blocked=after.hard_blocked,
            state_verified=True,
            user_confirmed=True,
            message=message,
        )
    finally:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
