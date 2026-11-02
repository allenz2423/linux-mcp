"""Bounded cumulative Linux block-device I/O statistics from sysfs."""

from __future__ import annotations

import heapq
import sys
from pathlib import Path

from wayland_mcp.models import BlockDeviceIOStats, BlockDeviceIOStatsResponse
from wayland_mcp.tools.storage import DEVICE_NAME_RE, SYS_CLASS_BLOCK

MAX_BLOCK_DEVICES = 1024
MAX_RETURNED_DEVICES = 200
MAX_STAT_BYTES = 512
MAX_STAT_FIELDS = 17
MIN_STAT_FIELDS = 11
STAT_FIELDS = (
    "reads_completed",
    "reads_merged",
    "sectors_read_512",
    "read_time_ms",
    "writes_completed",
    "writes_merged",
    "sectors_written_512",
    "write_time_ms",
    "in_flight",
    "io_time_ms",
    "weighted_io_time_ms",
    "discards_completed",
    "discards_merged",
    "sectors_discarded_512",
    "discard_time_ms",
    "flushes_completed",
    "flush_time_ms",
)


def _read_stat(name: str) -> tuple[list[int] | None, bool, str | None]:
    try:
        with (SYS_CLASS_BLOCK / name / "stat").open("rb") as stream:
            raw = stream.read(MAX_STAT_BYTES + 1)
    except FileNotFoundError:
        return None, False, "missing"
    except OSError as exc:
        return None, False, exc.strerror or "read error"
    if len(raw) > MAX_STAT_BYTES:
        return None, True, "oversized"
    fields = raw.decode("ascii", errors="replace").split()
    if len(fields) < MIN_STAT_FIELDS:
        return None, False, "malformed"
    values: list[int] = []
    try:
        for field in fields[:MAX_STAT_FIELDS]:
            value = int(field, 10)
            if value < 0 or value > 2**64 - 1:
                return None, False, "malformed"
            values.append(value)
    except ValueError:
        return None, False, "malformed"
    return values, len(fields) > MAX_STAT_FIELDS, None


def list_block_device_stats(query: str = "", limit: int = 100) -> BlockDeviceIOStatsResponse:
    """List cumulative read/write/discard/flush counters for visible block devices."""
    if not sys.platform.startswith("linux"):
        return BlockDeviceIOStatsResponse(success=False, message="Block-device statistics are available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return BlockDeviceIOStatsResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return BlockDeviceIOStatsResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return BlockDeviceIOStatsResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_DEVICES))
    if not SYS_CLASS_BLOCK.is_dir():
        return BlockDeviceIOStatsResponse(success=False, limit=limit, message="Linux sysfs block-device statistics are unavailable.")

    needle = query.strip().casefold()
    try:
        names = heapq.nsmallest(
            MAX_BLOCK_DEVICES + 1,
            (entry.name for entry in SYS_CLASS_BLOCK.iterdir()),
            key=str.casefold,
        )
    except OSError as exc:
        return BlockDeviceIOStatsResponse(success=False, limit=limit, message=f"Could not enumerate block devices: {exc.strerror or 'read error'}.")

    truncated = len(names) > MAX_BLOCK_DEVICES
    devices: list[BlockDeviceIOStats] = []
    unreadable = 0
    scanned = 0
    for name in names[:MAX_BLOCK_DEVICES]:
        if not DEVICE_NAME_RE.fullmatch(name) or (needle and needle not in name.casefold()):
            continue
        scanned += 1
        values, extra_fields, error = _read_stat(name)
        if error:
            unreadable += 1
            truncated = True
            continue
        if values is None:
            unreadable += 1
            truncated = True
            continue
        if extra_fields:
            truncated = True
        row: dict[str, int | None] = {
            field: values[index] if index < len(values) else None
            for index, field in enumerate(STAT_FIELDS)
        }
        devices.append(BlockDeviceIOStats(name=name, **row))

    devices.sort(key=lambda item: item.name.casefold())
    if scanned > 0 and not devices:
        return BlockDeviceIOStatsResponse(
            success=False,
            limit=limit,
            truncated=True,
            message="No readable block-device I/O statistics were found in sysfs.",
        )
    if len(devices) > limit:
        truncated = True
    message = "Counters are cumulative snapshots; sector fields use 512-byte sectors. Layered devices may account for the same I/O at more than one layer."
    if unreadable:
        message += f" {unreadable} device statistics files were unavailable or malformed."
    if truncated:
        message += " Some devices or newer stat fields were omitted by a configured cap or unavailable data."
    return BlockDeviceIOStatsResponse(
        success=True,
        total_devices=len(devices),
        returned_devices=min(len(devices), limit),
        devices=devices[:limit],
        limit=limit,
        truncated=truncated,
        message=message,
    )
