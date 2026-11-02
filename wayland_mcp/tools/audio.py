"""Read-only ALSA card and PCM endpoint inventory from procfs."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from wayland_mcp.models import AudioCardInfo, AudioInventoryResponse, AudioPCMDeviceInfo

ASOUND_CARDS = Path("/proc/asound/cards")
ASOUND_PCM = Path("/proc/asound/pcm")
MAX_PROC_BYTES = 64 * 1024
MAX_PROC_LINES = 1024
MAX_LINE_CHARS = 2048
MAX_CARDS = 32
MAX_PCM_ENTRIES = 512
MAX_RETURNED = 200
CARD_LINE_RE = re.compile(r"^\s*(\d{1,2})\s+\[([^\]\r\n]{1,64})\]\s*:\s*(.*?)\s+-\s*(.*?)\s*$")
PCM_LINE_RE = re.compile(r"^\s*(\d{1,2})-(\d{1,3}):\s*(.*?)\s*$")
PCM_DIRECTION_RE = re.compile(r"\b(playback|capture)\s+([0-9]+)\b", re.IGNORECASE)


def _clean_text(value: str, max_length: int = 256) -> str:
    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())[:max_length]


def _read_lines(path: Path) -> tuple[list[str], bool, str | None]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_PROC_BYTES + 1)
    except OSError as exc:
        return [], False, exc.strerror or "read error"
    truncated = len(raw) > MAX_PROC_BYTES
    lines = raw[:MAX_PROC_BYTES].decode("utf-8", errors="replace").splitlines()
    if len(lines) > MAX_PROC_LINES:
        lines = lines[:MAX_PROC_LINES]
        truncated = True
    bounded: list[str] = []
    for line in lines:
        if len(line) > MAX_LINE_CHARS:
            line = line[:MAX_LINE_CHARS]
            truncated = True
        bounded.append(line)
    return bounded, truncated, None


def _query_matches(query: str, values: tuple[object, ...]) -> bool:
    if not query:
        return True
    return any(query in str(value).casefold() for value in values if value is not None)


def list_audio_devices(query: str = "", limit: int = 50) -> AudioInventoryResponse:
    """List ALSA cards and playback/capture PCM endpoints visible in procfs."""
    if not sys.platform.startswith("linux"):
        return AudioInventoryResponse(success=False, message="ALSA device inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return AudioInventoryResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return AudioInventoryResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return AudioInventoryResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED))

    existing_files = [path for path in (ASOUND_CARDS, ASOUND_PCM) if path.is_file()]
    if not existing_files:
        return AudioInventoryResponse(
            success=False,
            limit=limit,
            message="ALSA procfs card and PCM inventories are unavailable.",
        )

    truncated = False
    unreadable = 0
    readable_sources = 0
    cards_by_index: dict[int, AudioCardInfo] = {}
    if ASOUND_CARDS in existing_files:
        lines, was_truncated, error = _read_lines(ASOUND_CARDS)
        truncated = truncated or was_truncated
        if error:
            unreadable += 1
        else:
            readable_sources += 1
            for line in lines:
                match = CARD_LINE_RE.fullmatch(line)
                if not match:
                    continue
                try:
                    card_index = int(match.group(1), 10)
                except ValueError:
                    truncated = True
                    continue
                card_id = _clean_text(match.group(2))
                driver = _clean_text(match.group(3)) or None
                name = _clean_text(match.group(4)) or card_id
                if not card_id or card_index < 0 or card_index >= MAX_CARDS:
                    truncated = True
                    continue
                if card_index in cards_by_index:
                    truncated = True
                    continue
                cards_by_index[card_index] = AudioCardInfo(
                    card_index=card_index,
                    card_id=card_id,
                    driver=driver,
                    name=name,
                )

    pcm_devices: list[AudioPCMDeviceInfo] = []
    if ASOUND_PCM in existing_files:
        lines, was_truncated, error = _read_lines(ASOUND_PCM)
        truncated = truncated or was_truncated
        if error:
            unreadable += 1
        else:
            readable_sources += 1
            for line in lines:
                match = PCM_LINE_RE.fullmatch(line)
                if not match:
                    continue
                try:
                    card_index = int(match.group(1), 10)
                    device_index = int(match.group(2), 10)
                except ValueError:
                    truncated = True
                    continue
                if card_index >= MAX_CARDS or device_index >= MAX_PCM_ENTRIES:
                    truncated = True
                    continue
                detail = match.group(3)
                fields = [part.strip() for part in detail.split(":") if part.strip()]
                direction_matches = list(PCM_DIRECTION_RE.finditer(detail))
                non_direction_fields = [
                    field for field in fields
                    if not PCM_DIRECTION_RE.fullmatch(field)
                ]
                if len(non_direction_fields) >= 2:
                    pcm_name = non_direction_fields[1]
                elif non_direction_fields:
                    pcm_name = non_direction_fields[0]
                else:
                    pcm_name = f"PCM {device_index}"
                pcm_name = _clean_text(pcm_name) or f"PCM {device_index}"
                card = cards_by_index.get(card_index)
                for direction_match in direction_matches:
                    direction = direction_match.group(1).casefold()
                    try:
                        substreams = int(direction_match.group(2), 10)
                    except ValueError:
                        truncated = True
                        continue
                    if substreams > 2**31 - 1:
                        truncated = True
                        continue
                    pcm_devices.append(AudioPCMDeviceInfo(
                        card_index=card_index,
                        card_id=card.card_id if card else None,
                        card_name=card.name if card else None,
                        device_index=device_index,
                        name=pcm_name,
                        direction=direction,
                        substreams=substreams,
                    ))
                    if len(pcm_devices) >= MAX_PCM_ENTRIES:
                        truncated = True
                        break
                if len(pcm_devices) >= MAX_PCM_ENTRIES:
                    break

    if readable_sources == 0:
        return AudioInventoryResponse(
            success=False,
            limit=limit,
            truncated=True,
            message=f"Could not read ALSA procfs inventory ({unreadable} source files unavailable).",
        )

    needle = query.strip().casefold()
    selected_pcm = [
        item for item in pcm_devices
        if _query_matches(needle, (
            item.card_index,
            item.card_id,
            item.card_name,
            item.device_index,
            item.name,
            item.direction,
        ))
    ]
    pcm_card_indexes = {item.card_index for item in selected_pcm}
    selected_cards = [
        card for card in cards_by_index.values()
        if _query_matches(needle, (card.card_index, card.card_id, card.driver, card.name))
        or card.card_index in pcm_card_indexes
    ]
    selected_cards.sort(key=lambda item: item.card_index)
    selected_pcm.sort(key=lambda item: (item.card_index, item.device_index, item.direction))
    if len(selected_cards) > limit or len(selected_pcm) > limit:
        truncated = True
    message = "Kernel ALSA card and PCM endpoint inventory only; userspace sound-server sinks, volumes, active streams, and audio content are not inspected."
    if unreadable:
        message += f" {unreadable} ALSA procfs source files were unavailable."
    if truncated:
        message += " Results may be partial because an input or response cap was reached."

    return AudioInventoryResponse(
        success=True,
        total_cards=len(selected_cards),
        returned_cards=min(len(selected_cards), limit),
        cards=selected_cards[:limit],
        total_pcm_devices=len(selected_pcm),
        returned_pcm_devices=min(len(selected_pcm), limit),
        pcm_devices=selected_pcm[:limit],
        limit=limit,
        truncated=truncated,
        message=message,
    )
