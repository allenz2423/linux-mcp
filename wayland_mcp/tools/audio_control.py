"""Confirmation-gated controls for exact current-session audio endpoints."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Literal

from wayland_mcp.models import AudioEndpointActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.audio_server import (
    _pactl_info,
    _run_pactl_direction,
    _run_wpctl_direction,
)
from wayland_mcp.tools.commands import run_bounded_command

AudioAction = Literal["set_volume", "set_mute", "set_default"]
AudioDirection = Literal["sink", "source"]

OBJECT_ID_RE = re.compile(r"^[0-9]{1,10}$")
WPCTL_VOLUME_RE = re.compile(r"^Volume:\s*([0-9]+(?:\.[0-9]+)?)(?:\s+(\[MUTED\]))?$", re.IGNORECASE)
PERCENT_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)%$")
MAX_NAME_LENGTH = 256
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class AudioEndpointSnapshot:
    backend: Literal["pactl", "wpctl"]
    manager: str | None
    direction: AudioDirection
    object_id: str
    name: str
    volume_channels: tuple[tuple[str, str], ...]
    muted: bool | None
    is_default: bool | None
    state_token: str


def _valid_target(
    action: str,
    direction: str,
    object_id: str,
    endpoint_name: str,
    volume_percent: int | None,
    muted: bool | None,
) -> str | None:
    if action not in {"set_volume", "set_mute", "set_default"}:
        return "Audio action must be set_volume, set_mute, or set_default."
    if direction not in {"sink", "source"}:
        return "Audio direction must be sink or source."
    if not isinstance(object_id, str) or not OBJECT_ID_RE.fullmatch(object_id):
        return "Endpoint ID must be a numeric ID from the current audio endpoint inventory."
    if (
        not isinstance(endpoint_name, str)
        or not endpoint_name
        or len(endpoint_name) > MAX_NAME_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in endpoint_name)
    ):
        return "Endpoint name must be the exact printable name from the current audio endpoint inventory."
    if action == "set_volume":
        if not isinstance(volume_percent, int) or isinstance(volume_percent, bool) or not 0 <= volume_percent <= 100:
            return "Volume must be an integer percentage from 0 through 100."
        if muted is not None:
            return "Mute state must be omitted for set_volume."
    elif action == "set_mute":
        if not isinstance(muted, bool):
            return "Mute state must be true or false for set_mute."
        if volume_percent is not None:
            return "Volume must be omitted for set_mute."
    elif volume_percent is not None or muted is not None:
        return "Volume and mute values must be omitted for set_default."
    return None


def _state_token(
    backend: str,
    manager: str | None,
    direction: str,
    object_id: str,
    name: str,
    volume_channels: tuple[tuple[str, str], ...],
    muted: bool | None,
    is_default: bool | None,
) -> str:
    state = {
        "backend": backend,
        "manager": manager,
        "direction": direction,
        "object_id": object_id,
        "name": name,
        "volume_channels": volume_channels,
        "muted": muted,
        "is_default": is_default,
    }
    encoded = json.dumps(state, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _make_snapshot(
    *,
    backend: Literal["pactl", "wpctl"],
    manager: str | None,
    direction: AudioDirection,
    object_id: str,
    name: str,
    volume_channels: dict[str, str],
    muted: bool | None,
    is_default: bool | None,
) -> AudioEndpointSnapshot:
    channels = tuple(sorted(volume_channels.items()))
    token = _state_token(backend, manager, direction, object_id, name, channels, muted, is_default)
    return AudioEndpointSnapshot(
        backend=backend,
        manager=manager,
        direction=direction,
        object_id=object_id,
        name=name,
        volume_channels=channels,
        muted=muted,
        is_default=is_default,
        state_token=token,
    )


def _read_pactl_endpoint(
    pactl: str,
    env: dict[str, str],
    direction: AudioDirection,
    object_id: str,
    endpoint_name: str,
) -> tuple[AudioEndpointSnapshot | None, str | None]:
    info_output, _info_error, info_truncated = run_bounded_command(
        [pactl, "info"],
        env,
        command_label="pactl audio-server info",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
    )
    manager = default_sink = default_source = None
    if info_output is not None and not info_truncated:
        manager, default_sink, default_source = _pactl_info(info_output)

    devices, _partial = _run_pactl_direction(pactl, direction, env)
    if devices is None:
        return None, f"Could not read the current {direction} endpoints through pactl."
    matches = [
        device for device in devices
        if device.object_id == object_id and device.name == endpoint_name and device.direction == direction
    ]
    if len(matches) != 1:
        return None, "The confirmed audio endpoint ID/name no longer identifies exactly one current endpoint."
    device = matches[0]
    default_name = default_sink if direction == "sink" else default_source
    is_default = device.name == default_name if default_name is not None else None
    return _make_snapshot(
        backend="pactl",
        manager=manager,
        direction=direction,
        object_id=object_id,
        name=endpoint_name,
        volume_channels=device.volume_channels,
        muted=device.muted,
        is_default=is_default,
    ), None


def _wpctl_volume_state(
    wpctl: str,
    env: dict[str, str],
    object_id: str,
) -> tuple[str | None, bool | None, str | None]:
    output, error, truncated = run_bounded_command(
        [wpctl, "get-volume", object_id],
        env,
        command_label="wpctl endpoint state",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=4096,
    )
    if output is None or truncated:
        return None, None, error or "wpctl returned truncated endpoint state."
    line = output.strip()
    if len(line) > 256 or "\n" in line:
        return None, None, "wpctl returned an unexpected endpoint-state format."
    match = WPCTL_VOLUME_RE.fullmatch(line)
    if not match:
        return None, None, "wpctl returned an unexpected endpoint-state format."
    try:
        percentage = Decimal(match.group(1)) * Decimal(100)
    except InvalidOperation:
        return None, None, "wpctl returned an invalid endpoint volume."
    if not percentage.is_finite() or percentage < 0 or percentage > 10000:
        return None, None, "wpctl returned an out-of-range endpoint volume."
    displayed = format(percentage.normalize(), "f")
    return f"{displayed}%", bool(match.group(2)), None


def _read_wpctl_endpoint(
    wpctl: str,
    env: dict[str, str],
    direction: AudioDirection,
    object_id: str,
    endpoint_name: str,
) -> tuple[AudioEndpointSnapshot | None, str | None]:
    devices, _partial = _run_wpctl_direction(wpctl, direction, env)
    if devices is None:
        return None, f"Could not read the current {direction} endpoints through wpctl."
    matches = [
        device for device in devices
        if device.object_id == object_id and device.name == endpoint_name and device.direction == direction
    ]
    if len(matches) != 1:
        return None, "The confirmed audio endpoint ID/name no longer identifies exactly one current endpoint."
    volume, muted, error = _wpctl_volume_state(wpctl, env, object_id)
    if error or volume is None:
        return None, error or "Could not read the current endpoint volume."
    device = matches[0]
    return _make_snapshot(
        backend="wpctl",
        manager="wireplumber",
        direction=direction,
        object_id=object_id,
        name=endpoint_name,
        volume_channels={"overall": volume},
        muted=muted,
        is_default=device.is_default,
    ), None


def _read_audio_endpoint(
    direction: AudioDirection,
    object_id: str,
    endpoint_name: str,
    *,
    backend_hint: Literal["pactl", "wpctl"] | None = None,
) -> tuple[AudioEndpointSnapshot | None, str | None]:
    env = get_sanitized_env()
    pactl = find_session_binary("pactl", env) if backend_hint in {None, "pactl"} else None
    wpctl = find_session_binary("wpctl", env) if backend_hint in {None, "wpctl"} else None
    first_error: str | None = None
    if pactl:
        snapshot, error = _read_pactl_endpoint(pactl, env, direction, object_id, endpoint_name)
        if snapshot is not None or backend_hint == "pactl":
            return snapshot, error
        first_error = error
    if wpctl:
        snapshot, error = _read_wpctl_endpoint(wpctl, env, direction, object_id, endpoint_name)
        if snapshot is not None or backend_hint == "wpctl":
            return snapshot, error
        return None, error or first_error
    if first_error:
        return None, first_error
    return None, "Neither pactl nor wpctl is available in the current session PATH."


def audio_action_confirmation_details(
    action: AudioAction,
    direction: AudioDirection,
    object_id: str,
    endpoint_name: str,
    volume_percent: int | None = None,
    muted: bool | None = None,
) -> tuple[AudioEndpointSnapshot | None, str | None]:
    error = _valid_target(action, direction, object_id, endpoint_name, volume_percent, muted)
    if error:
        return None, error
    snapshot, error = _read_audio_endpoint(direction, object_id, endpoint_name)
    if error or snapshot is None:
        return None, error or "Could not verify the current audio endpoint."
    if action == "set_volume" and not snapshot.volume_channels:
        return None, "Current endpoint volume is unavailable; no volume change was made."
    if action == "set_mute" and snapshot.muted is None:
        return None, "Current endpoint mute state is unavailable; no mute change was made."
    if action == "set_default" and snapshot.is_default is None:
        return None, "Current default endpoint state is unavailable; no default-device change was made."
    return snapshot, None


def _volume_matches(snapshot: AudioEndpointSnapshot, requested_percent: int) -> bool:
    if not snapshot.volume_channels:
        return False
    requested = Decimal(requested_percent)
    for _channel, raw_value in snapshot.volume_channels:
        match = PERCENT_RE.fullmatch(raw_value)
        if not match:
            return False
        try:
            current = Decimal(match.group(1))
        except InvalidOperation:
            return False
        if abs(current - requested) > Decimal("0.6"):
            return False
    return True


def _action_command(
    snapshot: AudioEndpointSnapshot,
    action: AudioAction,
    volume_percent: int | None,
    muted: bool | None,
) -> list[str]:
    if snapshot.backend == "pactl":
        if action == "set_volume":
            return [
                "pactl",
                f"set-{snapshot.direction}-volume",
                snapshot.object_id,
                f"{volume_percent}%",
            ]
        if action == "set_mute":
            return [
                "pactl",
                f"set-{snapshot.direction}-mute",
                snapshot.object_id,
                "1" if muted else "0",
            ]
        return ["pactl", f"set-default-{snapshot.direction}", snapshot.object_id]
    if action == "set_volume":
        return ["wpctl", "set-volume", snapshot.object_id, f"{volume_percent}%"]
    if action == "set_mute":
        return ["wpctl", "set-mute", snapshot.object_id, "1" if muted else "0"]
    return ["wpctl", "set-default", snapshot.object_id]


def perform_audio_endpoint_action(
    action: AudioAction,
    direction: AudioDirection,
    object_id: str,
    endpoint_name: str,
    expected_state_token: str,
    volume_percent: int | None = None,
    muted: bool | None = None,
    *,
    confirmed: bool = False,
) -> AudioEndpointActionResponse:
    safe_action: AudioAction = action if action in {"set_volume", "set_mute", "set_default"} else "set_volume"
    safe_direction: AudioDirection = direction if direction in {"sink", "source"} else "sink"
    response = AudioEndpointActionResponse(
        success=False,
        action=safe_action,
        direction=safe_direction,
        endpoint_id=object_id if isinstance(object_id, str) else None,
        endpoint_name=endpoint_name if isinstance(endpoint_name, str) else None,
        volume_percent=volume_percent,
        muted=muted,
        user_confirmed=confirmed,
        message="Audio endpoint action was not performed.",
    )
    if not sys.platform.startswith("linux"):
        response.message = "Audio endpoint control is available only on Linux."
        return response
    if not confirmed:
        response.message = "Explicit client confirmation is required; no audio setting was changed."
        return response
    error = _valid_target(action, direction, object_id, endpoint_name, volume_percent, muted)
    if error:
        response.message = error
        return response
    if not isinstance(expected_state_token, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_state_token):
        response.message = "A valid confirmed endpoint state token is required."
        return response

    before, error = audio_action_confirmation_details(
        action,
        direction,
        object_id,
        endpoint_name,
        volume_percent,
        muted,
    )
    if before is None:
        response.message = error or "Could not verify the current audio endpoint."
        return response
    if before.state_token != expected_state_token:
        response.message = "The endpoint state changed after confirmation; no audio command was run. Review the current endpoint and confirm again."
        return response

    env = get_sanitized_env()
    binary_name = before.backend
    binary = find_session_binary(binary_name, env)
    if not binary:
        response.message = f"The confirmed {binary_name} command is no longer available."
        return response
    command = _action_command(before, action, volume_percent, muted)
    command[0] = binary
    _output, command_error, command_truncated = run_bounded_command(
        command,
        env,
        command_label=f"{binary_name} audio endpoint control",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
        kill_process_group=True,
    )
    if command_error or command_truncated:
        response.message = (
            "The audio command did not report success. The setting may still have changed; "
            "inspect the endpoint before retrying."
        )
        return response

    after, verify_error = _read_audio_endpoint(
        direction,
        object_id,
        endpoint_name,
        backend_hint=before.backend,
    )
    if after is None:
        response.message = (
            "The audio server accepted the command, but the selected endpoint could not be re-read "
            f"for verification ({verify_error or 'unknown read error'}). Inspect current audio state before retrying."
        )
        return response
    if action == "set_volume":
        verified = _volume_matches(after, volume_percent if volume_percent is not None else -1)
    elif action == "set_mute":
        verified = after.muted is muted
    else:
        verified = after.is_default is True
    response.state_verified = verified
    response.is_default = after.is_default
    if action == "set_mute":
        response.muted = after.muted
    if not verified:
        response.message = "The audio command completed, but the requested endpoint state was not observed. Inspect current audio state before retrying."
        return response
    response.success = True
    response.message = (
        "Audio endpoint volume was changed and verified."
        if action == "set_volume"
        else "Audio endpoint mute state was changed and verified."
        if action == "set_mute"
        else "The default audio endpoint was changed and verified."
    )
    return response
