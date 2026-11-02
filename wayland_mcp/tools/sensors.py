"""Bounded read-only Linux hwmon and thermal-zone sensor snapshots."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from wayland_mcp.models import SensorReading, SensorReadingListResponse

SYS_CLASS_HWMON = Path("/sys/class/hwmon")
SYS_CLASS_THERMAL = Path("/sys/class/thermal")
MAX_SENSOR_DIRECTORIES = 256
MAX_SENSOR_DIRECTORY_ENTRIES = 2048
MAX_SENSOR_FILE_READS = 2048
MAX_RETURNED_READINGS = 256
MAX_ATTRIBUTE_BYTES = 128
HWMON_ENTRY_RE = re.compile(r"^hwmon[0-9]+$")
THERMAL_ENTRY_RE = re.compile(r"^thermal_zone[0-9]+$")
HWMON_ATTRIBUTE_RE = re.compile(r"^(temp|fan|in|curr|power|energy|humidity)([0-9]+)_(input|label)$")
INTEGER_MIN = -(2**63)
INTEGER_MAX = 2**64 - 1

NORMALIZATION: dict[str, tuple[str, float, str, str, str]] = {
    "temp": ("temperature", 1000.0, "millidegrees_celsius_or_millivolts", "°C", "driver_specific_possible"),
    "fan": ("fan_speed", 1.0, "revolutions_per_minute", "RPM", "standard"),
    "in": ("voltage", 1000.0, "millivolts", "V", "standard"),
    "curr": ("current", 1000.0, "milliamps", "A", "standard"),
    "power": ("power", 1_000_000.0, "microwatts", "W", "standard"),
    "energy": ("energy", 1_000_000.0, "microjoules", "J", "standard"),
    "humidity": ("humidity", 1.0, "driver_defined", "driver_defined", "driver_defined"),
}


def _bounded_names(directory: Path, limit: int) -> tuple[list[str], bool, str | None]:
    """Read at most limit+1 directory names to detect a scan cap."""
    names: list[str] = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > limit:
                    break
    except OSError as exc:
        return [], False, exc.strerror or "read error"
    truncated = len(names) > limit
    return sorted(names[:limit], key=str.casefold), truncated, None


def _read_small_text(path: Path) -> tuple[str | None, str | None]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_ATTRIBUTE_BYTES + 1)
    except OSError as exc:
        return None, exc.strerror or "read error"
    if len(raw) > MAX_ATTRIBUTE_BYTES:
        return None, "oversized"
    return raw.decode("utf-8", errors="replace").strip(), None


def _clean_label(value: str | None, max_length: int = 128) -> str | None:
    if not value:
        return None
    printable = "".join(character if character.isprintable() else " " for character in value)
    cleaned = " ".join(printable.split())[:max_length]
    return cleaned or None


def _read_integer(path: Path, file_reads: int) -> tuple[int | None, int, str | None]:
    text, error = _read_small_text(path)
    file_reads += 1
    if error:
        return None, file_reads, error
    try:
        if text is None or not text or len(text) > 64 or not text.isascii():
            return None, file_reads, "malformed"
        value = int(text, 10)
    except ValueError:
        return None, file_reads, "malformed"
    if value < INTEGER_MIN or value > INTEGER_MAX:
        return None, file_reads, "malformed"
    return value, file_reads, None


def _query_matches(query: str, *, source: str, device: str, channel: str, kind: str, label: str | None) -> bool:
    if not query:
        return True
    fields = (source, device, channel, kind, label or "")
    return any(query in field.casefold() for field in fields)


def _make_reading(
    *, source: str, device: str, channel: str, kind: str, raw_value: int,
    raw_unit: str, divisor: float, unit: str, normalization_status: str,
    label: str | None,
) -> SensorReading:
    return SensorReading(
        source=source,
        device=device,
        channel=channel,
        kind=kind,
        label=label,
        raw_value=raw_value,
        raw_unit=raw_unit,
        value=raw_value / divisor,
        unit=unit,
        normalization_status=normalization_status,
    )


def list_sensor_readings(query: str = "", limit: int = 100) -> SensorReadingListResponse:
    """List bounded temperature and hwmon input snapshots, without controls."""
    if not sys.platform.startswith("linux"):
        return SensorReadingListResponse(success=False, message="Sensor inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return SensorReadingListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return SensorReadingListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return SensorReadingListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_READINGS))

    roots = [
        ("hwmon", SYS_CLASS_HWMON, HWMON_ENTRY_RE),
        ("thermal_zone", SYS_CLASS_THERMAL, THERMAL_ENTRY_RE),
    ]
    available_roots = [(source, root, entry_re) for source, root, entry_re in roots if root.is_dir()]
    if not available_roots:
        return SensorReadingListResponse(
            success=False,
            limit=limit,
            message="Linux hwmon and thermal-zone sysfs interfaces are unavailable.",
        )

    needle = query.strip().casefold()
    readings: list[SensorReading] = []
    truncated = False
    unreadable = 0
    directories_seen = 0
    directory_entries_seen = 0
    file_reads = 0
    stop_scan = False

    for source, root, entry_re in available_roots:
        remaining_directories = MAX_SENSOR_DIRECTORIES - directories_seen
        if remaining_directories <= 0:
            truncated = True
            break
        device_names, root_truncated, root_error = _bounded_names(root, remaining_directories)
        truncated = truncated or root_truncated
        if root_error:
            unreadable += 1
            truncated = True
            continue

        for entry_name in device_names:
            if not entry_re.fullmatch(entry_name):
                continue
            if directories_seen >= MAX_SENSOR_DIRECTORIES:
                truncated = True
                stop_scan = True
                break
            directory = root / entry_name
            try:
                is_directory = directory.is_dir()
            except OSError:
                is_directory = False
            if not is_directory:
                continue
            directories_seen += 1

            remaining_entries = MAX_SENSOR_DIRECTORY_ENTRIES - directory_entries_seen
            if remaining_entries <= 0:
                truncated = True
                stop_scan = True
                break
            attributes, attributes_truncated, attributes_error = _bounded_names(directory, remaining_entries)
            directory_entries_seen += len(attributes)
            truncated = truncated or attributes_truncated
            if attributes_error:
                unreadable += 1
                truncated = True
                continue

            if source == "hwmon":
                chip_name = None
                if file_reads < MAX_SENSOR_FILE_READS:
                    raw_name, error = _read_small_text(directory / "name")
                    file_reads += 1
                    if error:
                        unreadable += 1
                        truncated = True
                    else:
                        chip_name = _clean_label(raw_name)
                else:
                    truncated = True
                device = f"{entry_name} ({chip_name})" if chip_name else entry_name
                labels = {
                    match.group(1) + match.group(2): attribute
                    for attribute in attributes
                    if (match := HWMON_ATTRIBUTE_RE.fullmatch(attribute)) and match.group(3) == "label"
                }
                for attribute in attributes:
                    match = HWMON_ATTRIBUTE_RE.fullmatch(attribute)
                    if not match or match.group(3) != "input":
                        continue
                    if file_reads >= MAX_SENSOR_FILE_READS:
                        truncated = True
                        stop_scan = True
                        break
                    raw_value, file_reads, error = _read_integer(directory / attribute, file_reads)
                    if error or raw_value is None:
                        unreadable += 1
                        truncated = True
                        continue
                    prefix, number = match.group(1), match.group(2)
                    kind, divisor, raw_unit, unit, normalization_status = NORMALIZATION[prefix]
                    channel = prefix + number
                    label = None
                    label_attribute = labels.get(channel)
                    if label_attribute:
                        if file_reads < MAX_SENSOR_FILE_READS:
                            raw_label, error = _read_small_text(directory / label_attribute)
                            file_reads += 1
                            if error:
                                unreadable += 1
                                truncated = True
                            else:
                                label = _clean_label(raw_label)
                        else:
                            truncated = True
                    if _query_matches(needle, source=source, device=device, channel=channel, kind=kind, label=label):
                        readings.append(_make_reading(
                            source=source,
                            device=device,
                            channel=channel,
                            kind=kind,
                            raw_value=raw_value,
                            raw_unit=raw_unit,
                            divisor=divisor,
                            unit=unit,
                            normalization_status=normalization_status,
                            label=label,
                        ))
            else:
                if "temp" not in attributes:
                    continue
                if file_reads >= MAX_SENSOR_FILE_READS:
                    truncated = True
                    stop_scan = True
                    break
                raw_value, file_reads, error = _read_integer(directory / "temp", file_reads)
                if error or raw_value is None:
                    unreadable += 1
                    truncated = True
                    continue
                label = None
                if file_reads < MAX_SENSOR_FILE_READS:
                    raw_label, error = _read_small_text(directory / "type")
                    file_reads += 1
                    if error:
                        unreadable += 1
                        truncated = True
                    else:
                        label = _clean_label(raw_label)
                else:
                    truncated = True
                if _query_matches(needle, source=source, device=entry_name, channel="temp", kind="temperature", label=label):
                    readings.append(_make_reading(
                        source=source,
                        device=entry_name,
                        channel="temp",
                        kind="temperature",
                        raw_value=raw_value,
                        raw_unit="millidegrees_celsius",
                        divisor=1000.0,
                        unit="°C",
                        normalization_status="standard",
                        label=label,
                    ))

            if stop_scan:
                break
        if stop_scan:
            break

    if len(readings) > limit:
        truncated = True
    message = (
        "Read-only sysfs input snapshots; hwmon temperature channels normally use millidegrees Celsius, "
        "but some drivers use millivolts, so those readings flag driver-specific interpretation and retain the raw value. "
        "Hwmon humidity values retain driver-defined units because the ABI does not specify a common unit. "
        "Other standard input values are converted to common units. "
        "Thresholds, alarms, and sensor controls are excluded."
    )
    if unreadable:
        message += f" {unreadable} sensor attributes or directories were unavailable or malformed."
    if truncated:
        message += " Results may be partial because a scan, read, or response cap was reached."

    return SensorReadingListResponse(
        success=True,
        total_readings=len(readings),
        returned_readings=min(len(readings), limit),
        readings=readings[:limit],
        limit=limit,
        truncated=truncated,
        message=message,
    )
