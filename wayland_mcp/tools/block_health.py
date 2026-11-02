"""On-demand, bounded SMART health snapshots for one whole block device."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from wayland_mcp.models import (
    BlockDeviceHealthResponse,
    BlockDeviceSmartAttribute,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.storage import DEVICE_NAME_RE, SYS_CLASS_BLOCK

DEV_ROOT = Path("/dev")
SMARTCTL_TIMEOUT_SECONDS = 8
MAX_SMARTCTL_OUTPUT_BYTES = 512 * 1024
MAX_SMART_ATTRIBUTES = 64
MAX_JSON_TOP_LEVEL_KEYS = 512
DEVICE_ID_RE = re.compile(r"^([0-9]{1,10}):([0-9]{1,10})$")
ATTRIBUTE_NAME_RE = re.compile(r"^[A-Za-z0-9 _-]{1,64}$")
ATTRIBUTE_RAW_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.,:+/-]{0,63}$")


def _bounded_uint(value: Any, maximum: int = 2**128 - 1) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        return None
    return value


def _bounded_temperature(value: Any) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        temperature = float(value)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(temperature) or not -273.15 <= temperature <= 1_000:
        return None
    return temperature


def _block_device_identity(name: str) -> tuple[Path | None, tuple[int, int, int] | None, str | None]:
    if not isinstance(name, str) or not DEVICE_NAME_RE.fullmatch(name):
        return None, None, "Provide one exact block-device name from list_block_devices."
    sysfs_entry = SYS_CLASS_BLOCK / name
    try:
        if not sysfs_entry.is_dir():
            return None, None, "That block device is not currently present in sysfs."
        if (sysfs_entry / "partition").is_file():
            return None, None, "Choose a whole block device; partition health is reported by its parent device."
        with (sysfs_entry / "dev").open("rb") as stream:
            raw_identity = stream.read(64).decode("ascii").strip()
        match = DEVICE_ID_RE.fullmatch(raw_identity)
        if not match:
            return None, None, "The block-device major/minor identity could not be verified."
        expected_major, expected_minor = int(match.group(1)), int(match.group(2))
        device_path = DEV_ROOT / name
        device_stat = device_path.stat()
    except (OSError, UnicodeError, ValueError):
        return None, None, "The block device or its device node is unavailable to the current user."
    if not stat.S_ISBLK(device_stat.st_mode):
        return None, None, "The matching /dev entry is not a block-device node."
    actual_major = os.major(device_stat.st_rdev)
    actual_minor = os.minor(device_stat.st_rdev)
    if (actual_major, actual_minor) != (expected_major, expected_minor):
        return None, None, "The /dev node no longer matches the selected sysfs block device."
    return device_path, (expected_major, expected_minor, device_stat.st_ino), None


def smartctl_available() -> bool:
    env = get_sanitized_env(dict(os.environ))
    return bool(find_session_binary("smartctl", env))


def _safe_device_name(name: Any) -> str:
    return name if isinstance(name, str) and DEVICE_NAME_RE.fullmatch(name) else ""


def _read_smartctl(name: str, device_path: Path) -> tuple[str | None, str | None, bool]:
    env = get_sanitized_env(dict(os.environ))
    smartctl = find_session_binary("smartctl", env)
    if not smartctl:
        return None, "smartctl is unavailable.", False
    return run_bounded_command(
        [
            smartctl,
            "--json",
            "--health",
            "--attributes",
            "--nocheck=standby",
            "--",
            str(device_path),
        ],
        env,
        command_label="SMART block-device health query",
        timeout_seconds=SMARTCTL_TIMEOUT_SECONDS,
        max_output_bytes=MAX_SMARTCTL_OUTPUT_BYTES,
        accept_nonzero_exit=True,
    )


def _parse_smart_attributes(payload: dict[str, Any]) -> tuple[list[BlockDeviceSmartAttribute], bool]:
    section = payload.get("ata_smart_attributes")
    rows = section.get("table") if isinstance(section, dict) else None
    if not isinstance(rows, list):
        return [], False
    truncated = len(rows) > MAX_SMART_ATTRIBUTES
    attributes: list[BlockDeviceSmartAttribute] = []
    for row in rows[:MAX_SMART_ATTRIBUTES]:
        if not isinstance(row, dict):
            continue
        attribute_id = _bounded_uint(row.get("id"), 255)
        name = row.get("name")
        if attribute_id is None or not isinstance(name, str) or not ATTRIBUTE_NAME_RE.fullmatch(name):
            continue
        raw = row.get("raw")
        raw_value: str | None = None
        if isinstance(raw, dict):
            candidate = raw.get("value")
            if isinstance(candidate, int) and not isinstance(candidate, bool) and 0 <= candidate <= 2**128 - 1:
                raw_value = str(candidate)
            elif isinstance(candidate, str) and ATTRIBUTE_RAW_RE.fullmatch(candidate):
                raw_value = candidate
        when_failed = row.get("when_failed")
        if not isinstance(when_failed, str) or when_failed not in {"", "-", "now", "past"} or not when_failed:
            when_failed = None
        attributes.append(BlockDeviceSmartAttribute(
            attribute_id=attribute_id,
            name=name,
            current=_bounded_uint(row.get("value"), 255),
            worst=_bounded_uint(row.get("worst"), 255),
            threshold=_bounded_uint(row.get("thresh"), 255),
            when_failed=when_failed,
            raw_value=raw_value,
        ))
    return attributes, truncated


def _response_from_payload(name: str, payload: dict[str, Any]) -> BlockDeviceHealthResponse:
    smartctl = payload.get("smartctl")
    smartctl = smartctl if isinstance(smartctl, dict) else {}
    exit_status = _bounded_uint(smartctl.get("exit_status"), 255)
    device_info = payload.get("device")
    protocol = device_info.get("protocol") if isinstance(device_info, dict) else None
    if not isinstance(protocol, str) or protocol not in {"ATA", "SCSI", "NVMe"}:
        protocol = None

    smart_status = payload.get("smart_status")
    smart_status = smart_status if isinstance(smart_status, dict) else {}
    nvme = payload.get("nvme_smart_health_information_log")
    nvme = nvme if isinstance(nvme, dict) else {}
    critical_warning = _bounded_uint(nvme.get("critical_warning"), 255)
    passed = smart_status.get("passed")
    attributes, attributes_truncated = _parse_smart_attributes(payload)
    exit_reports_current_failure = exit_status is not None and bool(exit_status & 0x18)
    attribute_reports_current_failure = any(attribute.when_failed == "now" for attribute in attributes)
    if (
        exit_reports_current_failure
        or attribute_reports_current_failure
        or passed is False
        or (critical_warning is not None and critical_warning != 0)
    ):
        health_status = "failed"
    elif passed is True or critical_warning == 0:
        health_status = "passed"
    else:
        health_status = "unknown"

    temperature_data = payload.get("temperature")
    temperature = (
        _bounded_temperature(temperature_data.get("current"))
        if isinstance(temperature_data, dict)
        else None
    )
    if temperature is None:
        temperature = _bounded_temperature(nvme.get("temperature"))
    power_on_time = payload.get("power_on_time")
    power_on_hours = (
        _bounded_uint(power_on_time.get("hours"))
        if isinstance(power_on_time, dict)
        else _bounded_uint(nvme.get("power_on_hours"))
    )
    power_cycles = _bounded_uint(payload.get("power_cycle_count"))
    if power_cycles is None:
        power_cycles = _bounded_uint(nvme.get("power_cycles"))
    spare = _bounded_uint(nvme.get("available_spare"), 100)
    spare_threshold = _bounded_uint(nvme.get("available_spare_threshold"), 100)
    percentage_used = _bounded_uint(nvme.get("percentage_used"), 255)
    data_units_read = _bounded_uint(nvme.get("data_units_read"))
    data_units_written = _bounded_uint(nvme.get("data_units_written"))
    media_errors = _bounded_uint(nvme.get("media_errors"))
    error_log_entries = _bounded_uint(nvme.get("num_err_log_entries"))
    has_health_data = (
        isinstance(passed, bool)
        or critical_warning is not None
        or exit_reports_current_failure
        or attribute_reports_current_failure
        or temperature is not None
        or power_on_hours is not None
        or power_cycles is not None
        or spare is not None
        or percentage_used is not None
        or media_errors is not None
        or error_log_entries is not None
        or data_units_read is not None
        or data_units_written is not None
        or bool(attributes)
    )
    if not has_health_data:
        return BlockDeviceHealthResponse(
            success=False,
            name=name,
            health_status="unavailable",
            protocol=protocol,
            smartctl_exit_status=exit_status,
            message=(
                "SMART health data is unavailable; the device may not support SMART or the current user may lack device access. "
                "The query does not run SMART health commands on ATA/SCSI devices reported in standby."
            ),
        )
    message = (
        "SMART health data was read without starting a self-test; raw attribute meanings vary by device vendor."
        if exit_status in {None, 0}
        else "Partial SMART data was read; review the health status and current device permissions/support. No self-test was started."
    )
    return BlockDeviceHealthResponse(
        success=True,
        name=name,
        health_status=health_status,
        protocol=protocol,
        smartctl_exit_status=exit_status,
        temperature_celsius=temperature,
        power_on_hours=power_on_hours,
        power_cycle_count=power_cycles,
        nvme_critical_warning=critical_warning,
        nvme_available_spare_percent=spare,
        nvme_available_spare_threshold_percent=spare_threshold,
        nvme_percentage_used=percentage_used,
        nvme_data_units_read=data_units_read,
        nvme_data_units_written=data_units_written,
        nvme_media_errors=media_errors,
        nvme_error_log_entries=error_log_entries,
        ata_attributes=attributes,
        ata_attributes_truncated=attributes_truncated,
        message=message,
    )


def get_block_device_health(name: str) -> BlockDeviceHealthResponse:
    """Read one exact whole-device SMART snapshot; never starts a test or writes state."""
    if not sys.platform.startswith("linux"):
        return BlockDeviceHealthResponse(
            success=False,
            name=_safe_device_name(name),
            health_status="unavailable",
            message="Block-device health inspection is available only on Linux.",
        )
    if not smartctl_available():
        return BlockDeviceHealthResponse(
            success=False,
            name=_safe_device_name(name),
            health_status="unavailable",
            message="The optional smartmontools 'smartctl' command is unavailable.",
        )
    device_path, original_identity, error = _block_device_identity(name)
    if error or device_path is None or original_identity is None:
        return BlockDeviceHealthResponse(
            success=False,
            name=_safe_device_name(name),
            health_status="unavailable",
            message=error or "The exact block-device identity could not be verified.",
        )
    output, error, truncated = _read_smartctl(name, device_path)
    if error or truncated:
        message = (
            "The SMART query exceeded its output limit."
            if truncated
            else "The SMART query timed out."
            if error and "timed out" in error.casefold()
            else "The SMART query could not be run with current device permissions or support."
        )
        return BlockDeviceHealthResponse(
            success=False,
            name=name,
            health_status="unavailable",
            message=message,
        )
    current_path, current_identity, identity_error = _block_device_identity(name)
    if identity_error or current_path != device_path or current_identity != original_identity:
        return BlockDeviceHealthResponse(
            success=False,
            name=name,
            health_status="unavailable",
            message="The block-device identity changed during the query; no SMART results are returned.",
        )
    try:
        payload = json.loads(
            output or "",
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (json.JSONDecodeError, RecursionError, ValueError):
        return BlockDeviceHealthResponse(
            success=False,
            name=name,
            health_status="unavailable",
            message="smartctl returned malformed or unsupported JSON; no SMART results are returned.",
        )
    if not isinstance(payload, dict) or len(payload) > MAX_JSON_TOP_LEVEL_KEYS:
        return BlockDeviceHealthResponse(
            success=False,
            name=name,
            health_status="unavailable",
            message="smartctl returned an unexpected JSON structure; no SMART results are returned.",
        )
    return _response_from_payload(name, payload)
