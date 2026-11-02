"""Bounded read-only power-supply snapshots from Linux sysfs."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from wayland_mcp.models import PowerSupplyInfo, PowerSupplyListResponse

SYS_CLASS_POWER_SUPPLY = Path("/sys/class/power_supply")
MAX_SUPPLY_DIRECTORIES = 256
MAX_DIRECTORY_ENTRIES = 4096
MAX_FILE_READS = 4096
MAX_ATTRIBUTE_BYTES = 128
MAX_RETURNED_SUPPLIES = 200
SUPPLY_NAME_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,128}$")
INTEGER_MIN = -(2**63)
INTEGER_MAX = 2**64 - 1
TEXT_ATTRIBUTES = ("type", "status", "health")
BOOLEAN_ATTRIBUTES = ("present",)
INTEGER_ATTRIBUTES = (
    "online",
    "capacity",
    "energy_now",
    "energy_full",
    "energy_full_design",
    "charge_now",
    "charge_full",
    "charge_full_design",
    "voltage_now",
    "current_now",
    "power_now",
    "temp",
    "cycle_count",
)
ALLOWED_ATTRIBUTES = set(TEXT_ATTRIBUTES + BOOLEAN_ATTRIBUTES + INTEGER_ATTRIBUTES)


def _bounded_names(directory: Path, limit: int) -> tuple[list[str], bool, str | None]:
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


def _read_attribute(path: Path) -> tuple[str | None, str | None]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_ATTRIBUTE_BYTES + 1)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, exc.strerror or "read error"
    if len(raw) > MAX_ATTRIBUTE_BYTES:
        return None, "oversized"
    value = raw.decode("utf-8", errors="replace").strip()
    if not value:
        return None, None
    return value, None


def _clean_text(value: str | None, max_length: int = 128) -> str | None:
    if not value:
        return None
    printable = "".join(character if character.isprintable() else " " for character in value)
    cleaned = " ".join(printable.split())[:max_length]
    return cleaned or None


def _parse_integer(value: str | None) -> tuple[int | None, bool]:
    if value is None or len(value) > 64 or not value.isascii():
        return None, False
    try:
        parsed = int(value, 10)
    except ValueError:
        return None, False
    if parsed < INTEGER_MIN or parsed > INTEGER_MAX:
        return None, False
    return parsed, True


def _query_matches(query: str, supply: PowerSupplyInfo) -> bool:
    if not query:
        return True
    return any(
        query in value.casefold()
        for value in (supply.name, supply.type or "", supply.status or "", supply.health or "")
    )


def list_power_supplies(query: str = "", limit: int = 100) -> PowerSupplyListResponse:
    """List safe, read-only power-supply state and common telemetry values."""
    if not sys.platform.startswith("linux"):
        return PowerSupplyListResponse(success=False, message="Power-supply inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return PowerSupplyListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return PowerSupplyListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return PowerSupplyListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_SUPPLIES))
    if not SYS_CLASS_POWER_SUPPLY.is_dir():
        return PowerSupplyListResponse(
            success=False,
            limit=limit,
            message="Linux sysfs power-supply inventory is unavailable.",
        )

    names, root_truncated, root_error = _bounded_names(SYS_CLASS_POWER_SUPPLY, MAX_SUPPLY_DIRECTORIES)
    if root_error:
        return PowerSupplyListResponse(
            success=False,
            limit=limit,
            truncated=True,
            message=f"Could not enumerate power supplies: {root_error}.",
        )

    supplies: list[PowerSupplyInfo] = []
    truncated = root_truncated
    unreadable = 0
    directory_entries_seen = 0
    file_reads = 0
    stop_scan = False
    needle = query.strip().casefold()

    for name in names:
        if not SUPPLY_NAME_RE.fullmatch(name):
            continue
        supply_dir = SYS_CLASS_POWER_SUPPLY / name
        try:
            if not supply_dir.is_dir():
                continue
        except OSError:
            unreadable += 1
            truncated = True
            continue

        remaining_entries = MAX_DIRECTORY_ENTRIES - directory_entries_seen
        if remaining_entries <= 0:
            truncated = True
            break
        attributes, attrs_truncated, attrs_error = _bounded_names(supply_dir, remaining_entries)
        directory_entries_seen += len(attributes)
        truncated = truncated or attrs_truncated
        if attrs_error:
            unreadable += 1
            truncated = True
            continue

        values: dict[str, str] = {}
        for attribute in attributes:
            if attribute not in ALLOWED_ATTRIBUTES:
                continue
            if file_reads >= MAX_FILE_READS:
                truncated = True
                stop_scan = True
                break
            value, error = _read_attribute(supply_dir / attribute)
            file_reads += 1
            if error:
                unreadable += 1
                truncated = True
            elif value is not None:
                values[attribute] = value
        if stop_scan:
            break

        numbers: dict[str, int | None] = {}
        for attribute in INTEGER_ATTRIBUTES:
            if attribute not in values:
                continue
            parsed, valid = _parse_integer(values[attribute])
            if not valid:
                unreadable += 1
                truncated = True
            else:
                numbers[attribute] = parsed

        present_missing = "present" not in values
        present_value = None
        if not present_missing:
            present_value, valid = _parse_integer(values["present"])
            if not valid or present_value not in {0, 1}:
                unreadable += 1
                truncated = True
                present_value = None

        online_value = numbers.get("online")
        supply_type = _clean_text(values.get("type"), 64)
        present_state = bool(present_value) if present_value in {0, 1} else None
        if present_missing and supply_type and supply_type.casefold() == "battery":
            present_state = True
        info = PowerSupplyInfo(
            name=name,
            type=supply_type,
            present=present_state,
            online=(online_value > 0 if online_value is not None else None),
            online_value=online_value,
            status=_clean_text(values.get("status"), 64),
            health=_clean_text(values.get("health"), 64),
            capacity_percent=(float(numbers["capacity"]) if numbers.get("capacity") is not None and 0 <= numbers["capacity"] <= 100 else None),
            energy_now_wh=(numbers["energy_now"] / 1_000_000 if numbers.get("energy_now") is not None else None),
            energy_full_wh=(numbers["energy_full"] / 1_000_000 if numbers.get("energy_full") is not None else None),
            energy_full_design_wh=(numbers["energy_full_design"] / 1_000_000 if numbers.get("energy_full_design") is not None else None),
            charge_now_ah=(numbers["charge_now"] / 1_000_000 if numbers.get("charge_now") is not None else None),
            charge_full_ah=(numbers["charge_full"] / 1_000_000 if numbers.get("charge_full") is not None else None),
            charge_full_design_ah=(numbers["charge_full_design"] / 1_000_000 if numbers.get("charge_full_design") is not None else None),
            voltage_now_v=(numbers["voltage_now"] / 1_000_000 if numbers.get("voltage_now") is not None else None),
            current_now_a=(numbers["current_now"] / 1_000_000 if numbers.get("current_now") is not None else None),
            power_now_w=(numbers["power_now"] / 1_000_000 if numbers.get("power_now") is not None else None),
            temperature_c=(numbers["temp"] / 10 if numbers.get("temp") is not None else None),
            cycle_count=(numbers["cycle_count"] if numbers.get("cycle_count") is not None and numbers["cycle_count"] > 0 else None),
        )
        if "capacity" in numbers and not 0 <= numbers["capacity"] <= 100:
            unreadable += 1
            truncated = True
        if "cycle_count" in numbers and numbers["cycle_count"] < 0:
            unreadable += 1
            truncated = True
        if _query_matches(needle, info):
            supplies.append(info)

    supplies.sort(key=lambda item: item.name.casefold())
    if len(supplies) > limit:
        truncated = True
    message = (
        "Read-only power-supply snapshots; energy is converted from micro-watt-hours to watt-hours, "
        "charge from microamp-hours to amp-hours, voltage/current/power to SI units, and temperature from tenths of a degree Celsius. "
        "Only an allowlist of attributes is read; manufacturer, model, serial number, and writable charge controls are excluded."
    )
    if unreadable:
        message += f" {unreadable} attributes or directories were unavailable or malformed."
    if truncated:
        message += " Results may be partial because a scan, read, or response cap was reached."

    return PowerSupplyListResponse(
        success=True,
        total_supplies=len(supplies),
        returned_supplies=min(len(supplies), limit),
        supplies=supplies[:limit],
        limit=limit,
        truncated=truncated,
        message=message,
    )
