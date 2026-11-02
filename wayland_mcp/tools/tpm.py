"""Bounded read-only inventory of TPM devices through documented sysfs fields."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from wayland_mcp.models import TPMDeviceInfo, TPMInventoryResponse

TPM_CLASS_ROOT = Path("/sys/class/tpm")
TPM_NAME_RE = re.compile(r"^tpm([0-9]{1,5})$")
MAX_CLASS_ENTRIES = 256
MAX_TPM_DEVICES = 64
MAX_ATTRIBUTE_BYTES = 128
MAX_TPM_DEVICE_INDEX = 65_535
DRIVER_NAME_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")


def _read_attribute(path: Path) -> tuple[str | None, bool]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_ATTRIBUTE_BYTES + 1)
    except OSError:
        return None, False
    if len(raw) > MAX_ATTRIBUTE_BYTES:
        return None, True
    try:
        return raw.decode("ascii", errors="strict").strip(), False
    except UnicodeDecodeError:
        return None, False


def _read_device(name: str) -> tuple[TPMDeviceInfo, bool]:
    root = TPM_CLASS_ROOT / name
    unavailable: list[str] = []
    truncated = False

    version_raw, value_truncated = _read_attribute(root / "tpm_version_major")
    truncated = truncated or value_truncated
    version: int | None = None
    if version_raw is not None and version_raw.isascii() and version_raw.isdecimal():
        parsed = int(version_raw, 10)
        if 1 <= parsed <= 255:
            version = parsed
    if version is None:
        unavailable.append("tpm_version_major")

    driver: str | None = None
    driver_partial = False
    try:
        driver_target = (root / "device" / "driver").readlink()
    except FileNotFoundError:
        pass
    except OSError:
        driver_partial = True
        unavailable.append("device/driver")
    else:
        driver_candidate = driver_target.name
        if DRIVER_NAME_RE.fullmatch(driver_candidate):
            driver = driver_candidate
        else:
            driver_partial = True
            unavailable.append("device/driver")

    return TPMDeviceInfo(
        name=name,
        tpm_version_major=version,
        driver=driver,
        unavailable_attributes=unavailable,
        partial=bool(unavailable) or driver_partial,
    ), truncated


def list_tpm_devices() -> TPMInventoryResponse:
    """List visible TPM class devices and a strict fixed set of metadata fields."""
    if not sys.platform.startswith("linux"):
        return TPMInventoryResponse(
            success=False,
            message="TPM sysfs inventory is available only on Linux.",
        )
    names: list[tuple[int, str]] = []
    scan_truncated = False
    try:
        with os.scandir(TPM_CLASS_ROOT) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_CLASS_ENTRIES:
                    scan_truncated = True
                    break
                match = TPM_NAME_RE.fullmatch(entry.name)
                if match is None:
                    continue
                device_index = int(match.group(1), 10)
                if device_index > MAX_TPM_DEVICE_INDEX:
                    continue
                if len(names) >= MAX_TPM_DEVICES:
                    scan_truncated = True
                    break
                names.append((device_index, entry.name))
    except FileNotFoundError:
        return TPMInventoryResponse(
            success=True,
            message="No TPM devices are exposed through /sys/class/tpm.",
        )
    except OSError as exc:
        return TPMInventoryResponse(
            success=False,
            message=f"Could not enumerate TPM sysfs devices: {exc.strerror or 'read error'}.",
        )

    names.sort(key=lambda item: (item[0], item[1]))
    devices: list[TPMDeviceInfo] = []
    any_partial = scan_truncated
    any_truncated = scan_truncated
    for _device_index, name in names:
        device, truncated = _read_device(name)
        devices.append(device)
        any_partial = any_partial or device.partial
        any_truncated = any_truncated or truncated

    if any_truncated:
        any_partial = True
    return TPMInventoryResponse(
        success=True,
        total_devices=len(names),
        returned_devices=len(devices),
        devices=devices,
        truncated=any_truncated,
        partial=any_partial,
        message=(
            "Reads the kernel-reported tpm_version_major attribute and optional "
            "bound-driver symlink only. It issues no TPM commands and does not "
            "read status attributes, PCRs, or endorsement keys."
        ),
    )
