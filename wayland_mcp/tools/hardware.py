"""Bounded PCI, USB, and selected system DMI inventory from Linux sysfs."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from wayland_mcp.models import FirmwareInfo, HardwareDeviceInfo, HardwareDeviceListResponse

SYSFS_BUSES = {
    "pci": Path("/sys/bus/pci/devices"),
    "usb": Path("/sys/bus/usb/devices"),
}
DMI_ID_ROOT = Path("/sys/class/dmi/id")
DMI_ATTRIBUTES = {
    "system_vendor": "sys_vendor",
    "product_name": "product_name",
    "product_version": "product_version",
    "board_vendor": "board_vendor",
    "board_name": "board_name",
    "board_version": "board_version",
    "chassis_vendor": "chassis_vendor",
    "chassis_type": "chassis_type",
    "chassis_version": "chassis_version",
    "bios_vendor": "bios_vendor",
    "bios_version": "bios_version",
    "bios_date": "bios_date",
    "bios_release": "bios_release",
}
MAX_HARDWARE_DEVICES = 10_000
MAX_RETURNED_DEVICES = 200
MAX_ATTRIBUTE_BYTES = 128
PCI_ID_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
USB_ID_RE = re.compile(r"^[0-9]+-[0-9]+(?:\.[0-9]+)*$")
HEX_ID_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{2,8}$")
DRIVER_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,128}$")


def _read_attribute(path: Path, pattern: re.Pattern[str] | None = None) -> str | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_ATTRIBUTE_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_ATTRIBUTE_BYTES:
        return None
    try:
        value = raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        return None
    if pattern and not pattern.fullmatch(value):
        return None
    return value or None


def _driver_name(path: Path) -> str | None:
    try:
        name = path.resolve(strict=True).name
    except (OSError, RuntimeError):
        return None
    return name if DRIVER_RE.fullmatch(name) else None


def firmware_identity_available() -> bool:
    """Check whether the kernel exposes any allowlisted DMI identity fields."""
    return sys.platform.startswith("linux") and any(
        _read_attribute(DMI_ID_ROOT / attribute) for attribute in DMI_ATTRIBUTES.values()
    )


def _firmware_info() -> FirmwareInfo | None:
    if not firmware_identity_available():
        return None
    values: dict[str, str] = {}
    for field, attribute in DMI_ATTRIBUTES.items():
        value = _read_attribute(DMI_ID_ROOT / attribute)
        if value:
            safe_value = "".join(character for character in value if character.isprintable())
            if safe_value:
                values[field] = safe_value[:MAX_ATTRIBUTE_BYTES]
    return FirmwareInfo(**values) if values else None


def _pci_device(path: Path) -> HardwareDeviceInfo | None:
    name = path.name
    if not PCI_ID_RE.fullmatch(name):
        return None
    class_value = _read_attribute(path / "class", HEX_ID_RE)
    class_value = class_value.removeprefix("0x").casefold() if class_value else None
    return HardwareDeviceInfo(
        bus="pci",
        device_id=name,
        vendor_id=_read_attribute(path / "vendor", HEX_ID_RE),
        product_id=_read_attribute(path / "device", HEX_ID_RE),
        class_code=class_value[:2] if class_value and len(class_value) >= 2 else None,
        subclass_code=class_value[2:4] if class_value and len(class_value) >= 4 else None,
        protocol_code=class_value[4:6] if class_value and len(class_value) >= 6 else None,
        driver=_driver_name(path / "driver"),
    )


def _usb_device(path: Path) -> HardwareDeviceInfo | None:
    name = path.name
    # Interface names contain ':', while root-hub names start with 'usb'.
    if not USB_ID_RE.fullmatch(name):
        return None
    return HardwareDeviceInfo(
        bus="usb",
        device_id=name,
        vendor_id=_read_attribute(path / "idVendor", HEX_ID_RE),
        product_id=_read_attribute(path / "idProduct", HEX_ID_RE),
        class_code=_read_attribute(path / "bDeviceClass", HEX_ID_RE),
        subclass_code=_read_attribute(path / "bDeviceSubClass", HEX_ID_RE),
        protocol_code=_read_attribute(path / "bDeviceProtocol", HEX_ID_RE),
        driver=_driver_name(path / "driver"),
    )


def list_hardware_devices(query: str = "", limit: int = 100) -> HardwareDeviceListResponse:
    if not sys.platform.startswith("linux"):
        return HardwareDeviceListResponse(success=False, message="Hardware inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return HardwareDeviceListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return HardwareDeviceListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return HardwareDeviceListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_DEVICES))
    needle = query.strip().casefold()
    firmware_info = _firmware_info()
    firmware_available = firmware_info is not None
    returned_firmware = firmware_info
    if needle and firmware_info:
        firmware_searchable = " ".join(value for value in firmware_info.model_dump().values() if value).casefold()
        if needle not in firmware_searchable:
            returned_firmware = None

    devices: list[HardwareDeviceInfo] = []
    available_buses = 0
    errors: list[str] = []
    scan_truncated = False
    for bus, root in SYSFS_BUSES.items():
        if not root.is_dir():
            continue
        available_buses += 1
        try:
            paths = []
            for path in root.iterdir():
                if len(paths) > MAX_HARDWARE_DEVICES:
                    break
                paths.append(path)
        except OSError as exc:
            errors.append(f"{bus}: {exc.strerror or 'read error'}")
            continue
        paths.sort(key=lambda path: path.name.casefold())
        if len(paths) > MAX_HARDWARE_DEVICES:
            paths = paths[:MAX_HARDWARE_DEVICES]
            scan_truncated = True
        parser = _pci_device if bus == "pci" else _usb_device
        for path in paths:
            device = parser(path)
            if device is None:
                continue
            searchable = " ".join(
                value or ""
                for value in (
                    device.bus, device.device_id, device.vendor_id, device.product_id,
                    device.class_code, device.subclass_code, device.protocol_code, device.driver,
                )
            ).casefold()
            if not needle or needle in searchable:
                devices.append(device)

    if available_buses == 0 and not firmware_available:
        return HardwareDeviceListResponse(success=False, limit=limit, message="PCI, USB, and DMI sysfs inventory sources are unavailable.")
    devices.sort(key=lambda item: (item.bus, item.device_id.casefold()))
    returned = devices[:limit]
    messages = [f"Some device data could not be read: {'; '.join(errors)}"] if errors else []
    truncated = scan_truncated or len(devices) > limit
    if scan_truncated:
        messages.append(f"Device scan capped at {MAX_HARDWARE_DEVICES} entries per bus.")
    return HardwareDeviceListResponse(
        success=True,
        total_devices=len(devices),
        returned_devices=len(returned),
        devices=returned,
        firmware=returned_firmware,
        limit=limit,
        truncated=truncated,
        message=" ".join(messages) or None,
    )
