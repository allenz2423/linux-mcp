"""Bounded, privacy-filtered device inventory from the udev database."""

from __future__ import annotations

import re
import sys

from wayland_mcp.models import UdevDeviceInfo, UdevDeviceListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_UDEV_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_UDEV_RECORDS = 20_000
MAX_RETURNED_UDEV_DEVICES = 200
MAX_UDEV_LINE_CHARS = 4096
SAFE_COMPONENT_RE = re.compile(r"^[^\x00-\x20\x7f/\\]{1,256}$")
SAFE_NAME_RE = re.compile(r"^[^\x00-\x20\x7f/\\]{1,256}$")
SAFE_SUBSYSTEM_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,128}$")
HEX_ID_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{4}$")
DEVICE_NUMBER_RE = re.compile(r"^[bc] ([0-9]{1,10}):([0-9]{1,10})$")
PROPERTY_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
ALLOWED_PROPERTIES = {
    "DEVPATH",
    "SUBSYSTEM",
    "DEVTYPE",
    "DRIVER",
    "ID_VENDOR_ID",
    "ID_MODEL_ID",
    "PCI_ID",
}


def _safe_sysfs_path(value: str | None) -> str | None:
    if not value or len(value) > 1024 or not value.startswith("/"):
        return None
    components = value[1:].split("/")
    if not components or any(
        component in {"", ".", ".."} or not SAFE_COMPONENT_RE.fullmatch(component)
        for component in components
    ):
        return None
    return value


def _safe_name(value: str | None, pattern: re.Pattern[str]) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value if pattern.fullmatch(value) else None


def _parse_device_number(value: str | None) -> tuple[int, int] | None:
    if value is None:
        return None
    match = DEVICE_NUMBER_RE.fullmatch(value.strip())
    if not match:
        return None
    major, minor = (int(part, 10) for part in match.groups())
    if major > 4_294_967_295 or minor > 4_294_967_295:
        return None
    return major, minor


def _parse_export_db(output: str) -> tuple[list[UdevDeviceInfo], bool]:
    """Parse udevadm's per-device records while retaining only allowlisted fields."""
    records: list[dict[str, object]] = []
    current: dict[str, object] = {"properties": {}}
    partial = False

    def finish_record() -> None:
        nonlocal current, partial
        if current.get("path") or current.get("properties"):
            records.append(current)
        current = {"properties": {}}

    for line in output.splitlines():
        if len(line) > MAX_UDEV_LINE_CHARS:
            partial = True
            continue
        if not line:
            finish_record()
            if len(records) >= MAX_UDEV_RECORDS:
                partial = True
                break
            continue
        if len(line) < 3 or line[1:3] != ": ":
            partial = True
            continue

        prefix, value = line[0], line[3:]
        if prefix == "P":
            if current.get("path"):
                finish_record()
                if len(records) >= MAX_UDEV_RECORDS:
                    partial = True
                    break
            current["path"] = value
        elif prefix in {"M", "U", "B", "T", "D", "N", "V"}:
            current[prefix] = value
        elif prefix == "E":
            key, separator, property_value = value.partition("=")
            if not separator:
                partial = True
                continue
            if key not in ALLOWED_PROPERTIES:
                continue
            if not PROPERTY_KEY_RE.fullmatch(key):
                partial = True
                continue
            properties = current["properties"]
            assert isinstance(properties, dict)
            properties[key] = property_value
        # Symlink, sequence, device-ID, and priority records are intentionally ignored.

    else:
        finish_record()

    if len(records) >= MAX_UDEV_RECORDS and output:
        partial = True

    devices: list[UdevDeviceInfo] = []
    for record in records:
        properties = record.get("properties")
        if not isinstance(properties, dict):
            partial = True
            continue
        devpath = _safe_sysfs_path(
            str(record.get("path") or properties.get("DEVPATH") or "")
        )
        subsystem = _safe_name(
            str(properties.get("SUBSYSTEM") or record.get("U") or ""),
            SAFE_SUBSYSTEM_RE,
        )
        sysname = _safe_name(
            str(record.get("M") or (devpath.rsplit("/", 1)[-1] if devpath else "")),
            SAFE_NAME_RE,
        )
        if devpath is None or subsystem is None or sysname is None:
            partial = True
            continue

        devtype = _safe_name(
            str(properties.get("DEVTYPE") or record.get("T") or ""),
            SAFE_SUBSYSTEM_RE,
        )
        driver = _safe_name(
            str(properties.get("DRIVER") or record.get("V") or ""),
            SAFE_NAME_RE,
        )
        vendor_id = properties.get("ID_VENDOR_ID")
        product_id = properties.get("ID_MODEL_ID")
        if vendor_id is None or product_id is None:
            pci_id = properties.get("PCI_ID")
            if isinstance(pci_id, str) and re.fullmatch(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{4}", pci_id):
                pci_vendor, pci_product = pci_id.split(":", 1)
                vendor_id = vendor_id or pci_vendor
                product_id = product_id or pci_product
        vendor = str(vendor_id) if vendor_id is not None else None
        product = str(product_id) if product_id is not None else None
        vendor = vendor.removeprefix("0x").lower() if vendor and HEX_ID_RE.fullmatch(vendor) else None
        product = product.removeprefix("0x").lower() if product and HEX_ID_RE.fullmatch(product) else None
        device_number = _parse_device_number(
            str(record.get("D")) if record.get("D") is not None else None
        )
        if record.get("D") is not None and device_number is None:
            partial = True
        devices.append(UdevDeviceInfo(
            sysfs_path=devpath,
            sysname=sysname,
            subsystem=subsystem,
            devtype=devtype,
            driver=driver,
            vendor_id=vendor,
            product_id=product,
            major=device_number[0] if device_number else None,
            minor=device_number[1] if device_number else None,
        ))

    devices.sort(key=lambda item: (item.subsystem.casefold(), item.sysname.casefold(), item.sysfs_path))
    return devices, partial


def list_udev_devices(
    query: str = "",
    subsystem: str = "",
    limit: int = 100,
) -> UdevDeviceListResponse:
    """List generic kernel devices using only allowlisted structural and numeric udev fields."""
    if not sys.platform.startswith("linux"):
        return UdevDeviceListResponse(success=False, message="udev device inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return UdevDeviceListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return UdevDeviceListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(subsystem, str) or len(subsystem) > 128:
        return UdevDeviceListResponse(success=False, message="Subsystem must be text with at most 128 characters.")
    subsystem = subsystem.strip()
    if subsystem and not SAFE_SUBSYSTEM_RE.fullmatch(subsystem):
        return UdevDeviceListResponse(success=False, message="Subsystem must be a simple Linux subsystem name.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return UdevDeviceListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_UDEV_DEVICES))

    env = get_sanitized_env()
    udevadm = find_session_binary("udevadm", env)
    if not udevadm:
        return UdevDeviceListResponse(
            success=False,
            limit=limit,
            message="udevadm is unavailable in the sanitized session PATH.",
        )
    output, _error, output_truncated = run_bounded_command(
        [udevadm, "info", "--export-db"],
        env,
        command_label="udev device inventory",
        timeout_seconds=6.0,
        max_output_bytes=MAX_UDEV_OUTPUT_BYTES,
    )
    if output is None:
        return UdevDeviceListResponse(
            success=False,
            partial=True,
            limit=limit,
            message="The udev database is unavailable or unreadable.",
        )

    devices, parse_partial = _parse_export_db(output)
    needle = query.strip().casefold()
    requested_subsystem = subsystem.casefold()
    selected = [
        device for device in devices
        if (not requested_subsystem or device.subsystem.casefold() == requested_subsystem)
        and (
            not needle
            or needle in " ".join(
                value or ""
                for value in (
                    device.sysfs_path,
                    device.sysname,
                    device.subsystem,
                    device.devtype,
                    device.driver,
                    device.vendor_id,
                    device.product_id,
                    str(device.major) if device.major is not None else None,
                    str(device.minor) if device.minor is not None else None,
                )
            ).casefold()
        )
    ]
    returned = selected[:limit]
    truncated = output_truncated or len(devices) >= MAX_UDEV_RECORDS or len(selected) > len(returned)
    partial = parse_partial or output_truncated or len(devices) >= MAX_UDEV_RECORDS
    message = None
    if output_truncated:
        message = f"udevadm output exceeded the {MAX_UDEV_OUTPUT_BYTES}-byte bound; results may be incomplete."
    elif len(devices) >= MAX_UDEV_RECORDS:
        message = f"The udev database scan was capped at {MAX_UDEV_RECORDS} records."
    elif parse_partial:
        message = "Some udev records were malformed or contained fields outside the supported format."

    return UdevDeviceListResponse(
        success=True,
        total_devices=len(selected),
        returned_devices=len(returned),
        devices=returned,
        limit=limit,
        truncated=truncated,
        partial=partial,
        message=message,
    )
