"""Read-only inventory of current-session userspace audio endpoints."""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from wayland_mcp.models import AudioServerDeviceInfo, AudioServerInventoryResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_OUTPUT_BYTES = 1024 * 1024
MAX_ENDPOINTS = 1000
MAX_RETURNED = 200
MAX_LINE_CHARS = 16 * 1024
MAX_VOLUME_CHANNELS = 16
CHANNEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
OBJECT_ID_RE = re.compile(r"^[0-9]{1,10}$")


def _clean_text(value: Any, max_length: int = 256) -> str | None:
    if not isinstance(value, (str, int, float)):
        return None
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in str(value)).split())
    return text[:max_length] or None


def _bool_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0"}:
            return False
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    return None


def _parse_volume(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for channel, details in list(value.items())[:MAX_VOLUME_CHANNELS]:
        if not isinstance(channel, str) or not CHANNEL_RE.fullmatch(channel) or not isinstance(details, dict):
            continue
        percentage = _clean_text(details.get("value_percent"), 32)
        if percentage is not None and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?%", percentage):
            result[channel] = percentage
    return result


def _from_pactl_json(output: str, direction: str) -> tuple[list[AudioServerDeviceInfo] | None, bool]:
    if len(output) > MAX_OUTPUT_BYTES or any(len(line) > MAX_LINE_CHARS for line in output.splitlines()):
        return None, True
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, RecursionError):
        return None, False
    if not isinstance(payload, list):
        return None, False

    partial = len(payload) > MAX_ENDPOINTS
    result: list[AudioServerDeviceInfo] = []
    for entry in payload[:MAX_ENDPOINTS]:
        if not isinstance(entry, dict):
            partial = True
            continue
        name = _clean_text(entry.get("name"))
        if name is None:
            partial = True
            continue
        object_id = _clean_text(entry.get("index"), 10)
        if object_id is not None and not OBJECT_ID_RE.fullmatch(object_id):
            object_id = None
        result.append(AudioServerDeviceInfo(
            object_id=object_id,
            direction=direction,
            name=name,
            description=_clean_text(entry.get("description"), 512),
            driver=_clean_text(entry.get("driver"), 128),
            state=_clean_text(entry.get("state"), 64),
            muted=_bool_value(entry.get("mute")),
            volume_channels=_parse_volume(entry.get("volume")),
        ))
    return result, partial


def _from_pactl_short(output: str, direction: str) -> tuple[list[AudioServerDeviceInfo] | None, bool]:
    if len(output) > MAX_OUTPUT_BYTES:
        return None, True
    lines = output.splitlines()
    partial = len(lines) > MAX_ENDPOINTS
    result: list[AudioServerDeviceInfo] = []
    for line in lines[:MAX_ENDPOINTS]:
        if len(line) > MAX_LINE_CHARS:
            partial = True
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            fields = line.split(None, 4)
        if len(fields) < 2 or not OBJECT_ID_RE.fullmatch(fields[0].strip()):
            partial = True
            continue
        name = _clean_text(fields[1])
        if name is None:
            partial = True
            continue
        result.append(AudioServerDeviceInfo(
            object_id=fields[0].strip(),
            direction=direction,
            name=name,
            state=_clean_text(fields[-1], 64) if len(fields) > 3 else None,
        ))
    return result, partial


def _from_wpctl(output: str, direction: str) -> tuple[list[AudioServerDeviceInfo] | None, bool]:
    if len(output) > MAX_OUTPUT_BYTES:
        return None, True
    lines = output.splitlines()
    partial = len(lines) > MAX_ENDPOINTS + 1
    result: list[AudioServerDeviceInfo] = []
    for line in lines[:MAX_ENDPOINTS + 1]:
        if len(line) > MAX_LINE_CHARS:
            partial = True
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        marker = (
            "*" in fields[0]
            or (len(fields) > 1 and "*" in fields[1])
            or any(field.strip() == "*" or field.strip().endswith("*") for field in fields[2:])
        )
        object_id = fields[0].strip().strip("*").strip()
        if not OBJECT_ID_RE.fullmatch(object_id):
            continue
        name = _clean_text(fields[1].strip().strip("*").strip())
        if name is None:
            partial = True
            continue
        result.append(AudioServerDeviceInfo(
            object_id=object_id,
            direction=direction,
            name=name,
            is_default=marker,
        ))
    return result, partial


def _pactl_info(output: str) -> tuple[str | None, str | None, str | None]:
    values: dict[str, str] = {}
    for line in output.splitlines()[:256]:
        if len(line) > 2048 or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip() in {"Server Name", "Default Sink", "Default Source"}:
            cleaned = _clean_text(value, 256)
            if cleaned:
                values[key.strip()] = cleaned
    server_name = values.get("Server Name", "").casefold()
    manager = "pipewire_pulse" if "pipewire" in server_name else "pulseaudio" if server_name else None
    return manager, values.get("Default Sink"), values.get("Default Source")


def _mark_defaults(
    devices: list[AudioServerDeviceInfo], default_name: str | None,
) -> str | None:
    if default_name is None:
        marked = [device.name for device in devices if device.is_default]
        return marked[0] if marked else None
    for device in devices:
        device.is_default = device.name == default_name
    return default_name


def _query_matches(query: str, device: AudioServerDeviceInfo) -> bool:
    return not query or any(
        query in value.casefold()
        for value in (device.name, device.description, device.driver, device.state)
        if value is not None
    )


def _run(binary: str, args: list[str], env: dict[str, str], label: str) -> tuple[str | None, bool]:
    output, _error, truncated = run_bounded_command(
        [binary, *args],
        env,
        command_label=label,
        timeout_seconds=4.0,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    return output, truncated


def _run_pactl_direction(
    pactl: str, direction: str, env: dict[str, str],
) -> tuple[list[AudioServerDeviceInfo] | None, bool]:
    output, truncated = _run(pactl, ["-f", "json", "list", direction + "s"], env, f"pactl {direction} inventory")
    if output is not None and not truncated:
        devices, partial = _from_pactl_json(output, direction)
        if devices is not None:
            return devices, partial

    output, short_truncated = _run(pactl, ["list", "short", direction + "s"], env, f"pactl short {direction} inventory")
    if output is not None and not short_truncated:
        devices, _partial = _from_pactl_short(output, direction)
        if devices is not None:
            return devices, True
    return None, truncated or short_truncated


def _run_wpctl_direction(
    wpctl: str, direction: str, env: dict[str, str],
) -> tuple[list[AudioServerDeviceInfo] | None, bool]:
    output, truncated = _run(wpctl, ["list", "audio", direction + "s"], env, f"wpctl {direction} inventory")
    if output is None or truncated:
        return None, truncated
    devices, _partial = _from_wpctl(output, direction)
    return devices, True


def list_audio_server_devices(query: str = "", limit: int = 50) -> AudioServerInventoryResponse:
    """List current-session audio sinks and sources without enumerating streams."""
    if not sys.platform.startswith("linux"):
        return AudioServerInventoryResponse(success=False, message="Userspace audio-server inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return AudioServerInventoryResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return AudioServerInventoryResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return AudioServerInventoryResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED))
    query = query.casefold().strip()

    env = get_sanitized_env()
    pactl = find_session_binary("pactl", env)
    wpctl = find_session_binary("wpctl", env)
    if not pactl and not wpctl:
        return AudioServerInventoryResponse(
            success=False,
            limit=limit,
            message="Neither pactl nor wpctl is available in the sanitized session PATH.",
        )

    manager: str | None = None
    default_sink: str | None = None
    default_source: str | None = None
    sinks: list[AudioServerDeviceInfo] | None = None
    sources: list[AudioServerDeviceInfo] | None = None
    partial = False

    if pactl:
        info_output, info_truncated = _run(pactl, ["info"], env, "pactl audio-server info")
        if info_output is not None and not info_truncated:
            manager, default_sink, default_source = _pactl_info(info_output)
            if manager is None:
                partial = True
        else:
            partial = True
        sinks, sinks_partial = _run_pactl_direction(pactl, "sink", env)
        sources, sources_partial = _run_pactl_direction(pactl, "source", env)
        partial = partial or sinks_partial or sources_partial

    if wpctl and sinks is None and sources is None:
        sinks, _sinks_partial = _run_wpctl_direction(wpctl, "sink", env)
        sources, _sources_partial = _run_wpctl_direction(wpctl, "source", env)
        partial = True
        if sinks is not None or sources is not None:
            manager = "wireplumber"
            default_sink = None
            default_source = None

    sink_read = sinks is not None
    source_read = sources is not None
    if not sink_read and not source_read:
        return AudioServerInventoryResponse(
            success=False,
            partial=True,
            manager=manager,
            limit=limit,
            message="Could not query audio sinks or sources from the current user session. The audio server may be stopped or inaccessible.",
        )

    sinks = sinks or []
    sources = sources or []
    if not sink_read or not source_read:
        partial = True
    default_sink = _mark_defaults(sinks, default_sink)
    default_source = _mark_defaults(sources, default_source)
    matching_sinks = [device for device in sinks if _query_matches(query, device)]
    matching_sources = [device for device in sources if _query_matches(query, device)]
    total_sinks = len(matching_sinks)
    total_sources = len(matching_sources)
    returned_sinks = matching_sinks[:limit]
    returned_sources = matching_sources[:limit]
    truncated = len(returned_sinks) < total_sinks or len(returned_sources) < total_sources
    partial = partial or truncated

    return AudioServerInventoryResponse(
        success=True,
        partial=partial,
        manager=manager,
        default_sink=default_sink,
        default_source=default_source,
        total_sinks=total_sinks,
        returned_sinks=len(returned_sinks),
        sinks=returned_sinks,
        total_sources=total_sources,
        returned_sources=len(returned_sources),
        sources=returned_sources,
        limit=limit,
        truncated=truncated,
        message=(
            "Only one endpoint direction was available from the current session."
            if not sink_read or not source_read else None
        ),
    )
