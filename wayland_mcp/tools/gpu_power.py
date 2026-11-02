"""State-bound GPU power-cap inventory and confirmation-gated hwmon updates."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import GPUPowerLimitInfo, GPUPowerLimitListResponse, GPUPowerLimitActionResponse

DRM_ROOT = Path("/sys/class/drm")
SYS_DEVICES = Path("/sys/devices")
CARD_RE = re.compile(r"^card[0-9]{1,5}$")
HWMON_RE = re.compile(r"^hwmon[0-9]{1,5}$")
PCI_ADDRESS_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
DRIVER_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,128}$")
POWER_CAP_RE = re.compile(r"^power([1-9][0-9]{0,2})_cap$")
SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9_.+:/ -]{1,128}$")
MAX_GPU_CARDS = 128
MAX_HWMON_CONTROLLERS = 32
MAX_SCANNED_CONTROLLERS = 128
MAX_POWER_INDEX = 256
MAX_SCANNED_LIMITS = 4096
MAX_DIRECTORY_SCAN_ENTRIES = 1024
MAX_LIMITS = 100
MAX_POWER_MICROWATTS = 1_000_000_000_000

GPUPowerLimitAction = Literal["set_limit"]


@dataclass(frozen=True, slots=True)
class PowerTarget:
    drm_card: str
    pci_address: str
    driver: str
    controller: str
    controller_path: str
    chip_name: str
    power_index: int
    current_limit_micro_watts: int
    minimum_limit_micro_watts: int
    maximum_limit_micro_watts: int
    label: str | None
    device_identity: tuple[int, int]
    controller_identity: tuple[int, int]
    cap_identity: tuple[int, int]
    digest: str


def _read_text(path: Path, maximum_bytes: int = 256) -> str | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(maximum_bytes + 1)
        if len(raw) > maximum_bytes:
            return None
        value = raw.decode("ascii", errors="strict").strip()
        if any(ord(char) < 32 and char not in "\t" for char in value):
            return None
        return value
    except (OSError, UnicodeError):
        return None


def _read_uint(path: Path) -> int | None:
    raw = _read_text(path, 64)
    if raw is None or not re.fullmatch(r"[0-9]{1,15}", raw):
        return None
    value = int(raw, 10)
    return value if 0 <= value <= MAX_POWER_MICROWATTS else None


def _attribute_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return info.st_dev, info.st_ino


def _matching_names(
    root: Path,
    pattern: re.Pattern[str],
    limit: int,
) -> tuple[list[str], bool]:
    names: list[str] = []
    partial = False
    try:
        with os.scandir(root) as entries:
            for scanned, entry in enumerate(entries):
                if scanned >= MAX_DIRECTORY_SCAN_ENTRIES:
                    partial = True
                    break
                if pattern.fullmatch(entry.name):
                    names.append(entry.name)
    except FileNotFoundError:
        return [], False
    except OSError:
        return [], True
    names.sort()
    if len(names) > limit:
        names = names[:limit]
        partial = True
    return names, partial


def _gpu_identity(drm_card: str) -> tuple[Path | None, str | None, str | None, tuple[int, int] | None, str | None]:
    if not isinstance(drm_card, str) or not CARD_RE.fullmatch(drm_card):
        return None, None, None, None, "drm_card must be one exact cardN name from list_gpu_devices."
    try:
        device = (DRM_ROOT / drm_card / "device").resolve(strict=True)
        device.relative_to(SYS_DEVICES.resolve(strict=True))
        info = device.stat()
    except (OSError, RuntimeError, ValueError):
        return None, None, None, None, "The GPU device sysfs identity could not be verified beneath /sys/devices."
    pci_address = device.name.lower()
    if not PCI_ADDRESS_RE.fullmatch(pci_address):
        return None, None, None, None, "This control supports PCI DRM GPUs only."
    try:
        driver = (device / "driver").resolve(strict=True).name
    except (OSError, RuntimeError):
        return None, None, None, None, "The GPU driver identity could not be verified."
    if not DRIVER_RE.fullmatch(driver):
        return None, None, None, None, "The GPU driver name is outside the supported format."
    return device, pci_address, driver, (info.st_dev, info.st_ino), None


def _controller_path(device: Path, controller: str) -> Path | None:
    if not isinstance(controller, str) or not HWMON_RE.fullmatch(controller):
        return None
    try:
        root = (device / "hwmon" / controller).resolve(strict=True)
        root.relative_to(device)
    except (OSError, RuntimeError, ValueError):
        return None
    return root


def _target(
    drm_card: str,
    controller: str,
    power_index: int,
    target_micro_watts: int,
    action: str,
) -> tuple[PowerTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "GPU power-cap control is available only on Linux."
    if not isinstance(action, str) or action != "set_limit":
        return None, None, "action must be set_limit."
    if type(power_index) is not int or not 1 <= power_index <= MAX_POWER_INDEX:
        return None, None, f"power_index must be an integer from 1 through {MAX_POWER_INDEX}."
    if type(target_micro_watts) is not int or not 0 < target_micro_watts <= MAX_POWER_MICROWATTS:
        return None, None, "target_micro_watts must be a positive integer power cap in microWatts."
    device, pci_address, driver, device_identity, error = _gpu_identity(drm_card)
    if error or device is None or pci_address is None or driver is None or device_identity is None:
        return None, None, error or "The exact GPU identity could not be verified."
    controller_path = _controller_path(device, controller)
    if controller_path is None:
        return None, None, "The selected hwmon controller is not beneath the exact GPU device."
    try:
        controller_info = controller_path.stat()
    except OSError:
        return None, None, "The selected GPU hwmon controller identity could not be verified."
    if not stat.S_ISDIR(controller_info.st_mode):
        return None, None, "The selected GPU hwmon controller is not a directory."
    controller_identity = (controller_info.st_dev, controller_info.st_ino)
    chip_name = _read_text(controller_path / "name")
    if chip_name is None or len(chip_name) > 128:
        return None, None, "The GPU hwmon chip name could not be verified."
    cap_path = controller_path / f"power{power_index}_cap"
    cap_identity = _attribute_identity(cap_path)
    if cap_identity is None:
        return None, None, "The selected GPU power-cap attribute is unavailable or not a sysfs file."
    current = _read_uint(cap_path)
    minimum = _read_uint(controller_path / f"power{power_index}_cap_min")
    maximum = _read_uint(controller_path / f"power{power_index}_cap_max")
    if current is None or minimum is None or maximum is None or not 0 < minimum <= current <= maximum:
        return None, None, "The GPU power-cap range or current value could not be verified."
    if not minimum <= target_micro_watts <= maximum:
        return None, None, f"target_micro_watts must be within the driver-reported range {minimum}..{maximum}."
    if target_micro_watts == current:
        return None, None, "The requested power cap already matches the current limit."
    label = _read_text(controller_path / f"power{power_index}_label", 128)
    if label is not None and not SAFE_LABEL_RE.fullmatch(label):
        label = None
    material = {
        "drm_card": drm_card,
        "pci_address": pci_address,
        "driver": driver,
        "controller": controller,
        "controller_path": str(controller_path),
        "chip_name": chip_name,
        "power_index": power_index,
        "current": current,
        "minimum": minimum,
        "maximum": maximum,
        "target": target_micro_watts,
        "label": label,
        "device_identity": device_identity,
        "controller_identity": controller_identity,
        "cap_identity": cap_identity,
        "action": action,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return PowerTarget(
        drm_card, pci_address, driver, controller, str(controller_path), chip_name,
        power_index, current, minimum, maximum, label, device_identity, controller_identity, cap_identity, digest,
    ), f"GPU power {digest[:16]}", None


def gpu_power_limit_confirmation_details(
    drm_card: str,
    controller: str,
    power_index: int,
    target_micro_watts: int,
    action: str = "set_limit",
) -> tuple[PowerTarget | None, str | None, str | None]:
    return _target(drm_card, controller, power_index, target_micro_watts, action)


def list_gpu_power_limits(query: str = "", limit: int = 64) -> GPUPowerLimitListResponse:
    if not sys.platform.startswith("linux"):
        return GPUPowerLimitListResponse(success=False, message="GPU power-cap inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256 or any(ord(char) < 32 for char in query):
        return GPUPowerLimitListResponse(success=False, message="query must be text with at most 256 characters and no control characters.")
    if type(limit) is not int or not 1 <= limit <= MAX_LIMITS:
        return GPUPowerLimitListResponse(success=False, message=f"limit must be an integer from 1 through {MAX_LIMITS}.")
    if not DRM_ROOT.is_dir():
        return GPUPowerLimitListResponse(success=False, message="The Linux DRM sysfs inventory is unavailable.")
    cards, partial = _matching_names(DRM_ROOT, CARD_RE, MAX_GPU_CARDS)
    if not DRM_ROOT.is_dir():
        return GPUPowerLimitListResponse(success=False, message="The DRM card inventory could not be read.")
    items: list[GPUPowerLimitInfo] = []
    scanned = 0
    scanned_controllers = 0
    for drm_card in cards:
        if scanned >= MAX_SCANNED_LIMITS:
            partial = True
            break
        device, pci_address, driver, _identity, error = _gpu_identity(drm_card)
        if error or device is None or pci_address is None or driver is None:
            partial = True
            continue
        controllers, controller_partial = _matching_names(device / "hwmon", HWMON_RE, MAX_HWMON_CONTROLLERS)
        partial |= controller_partial
        for controller in controllers:
            if scanned_controllers >= MAX_SCANNED_CONTROLLERS:
                partial = True
                break
            scanned_controllers += 1
            root = _controller_path(device, controller)
            if root is None:
                partial = True
                continue
            chip_name = _read_text(root / "name")
            if chip_name is None:
                partial = True
                continue
            cap_names, cap_partial = _matching_names(root, POWER_CAP_RE, MAX_SCANNED_LIMITS)
            partial |= cap_partial
            for cap_name in cap_names:
                if scanned >= MAX_SCANNED_LIMITS:
                    partial = True
                    break
                scanned += 1
                match = POWER_CAP_RE.fullmatch(cap_name)
                assert match is not None
                power_index = int(match.group(1), 10)
                if power_index > MAX_POWER_INDEX:
                    partial = True
                    continue
                cap_path = root / cap_name
                current = _read_uint(cap_path)
                minimum = _read_uint(root / f"power{power_index}_cap_min")
                maximum = _read_uint(root / f"power{power_index}_cap_max")
                if current is None or minimum is None or maximum is None or not 0 < minimum <= current <= maximum:
                    partial = True
                    continue
                label = _read_text(root / f"power{power_index}_label", 128)
                if label is not None and not SAFE_LABEL_RE.fullmatch(label):
                    label = None
                item = GPUPowerLimitInfo(
                    drm_card=drm_card,
                    pci_address=pci_address,
                    driver=driver,
                    controller=controller,
                    chip_name=chip_name,
                    power_index=power_index,
                    current_limit_micro_watts=current,
                    minimum_limit_micro_watts=minimum,
                    maximum_limit_micro_watts=maximum,
                    label=label,
                )
                query_material = " ".join((drm_card, pci_address, driver, controller, chip_name, label or "", str(power_index)))
                if not query or query.casefold() in query_material.casefold():
                    items.append(item)
            if scanned >= MAX_SCANNED_LIMITS:
                break
    items.sort(key=lambda item: (item.drm_card, item.controller, item.power_index))
    total = len(items)
    return GPUPowerLimitListResponse(
        success=True,
        total_limits=total,
        returned_limits=min(total, limit),
        limits=items[:limit],
        limit=limit,
        truncated=total > limit,
        partial=partial,
        message="Some GPU power-cap channels could not be fully read." if partial else None,
    )


def _write_cap(path: Path, expected_identity: tuple[int, int], value: int) -> None:
    fd: int | None = None
    try:
        fd = os.open(path, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != expected_identity:
            raise OSError("The GPU power-cap attribute identity changed before writing.")
        data = f"{value}\n".encode("ascii")
        if os.write(fd, data) != len(data):
            raise OSError("The GPU power-cap write was incomplete.")
    finally:
        if fd is not None:
            os.close(fd)


def perform_gpu_power_limit_action(
    drm_card: str,
    controller: str,
    power_index: int,
    target_micro_watts: int,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
    action: GPUPowerLimitAction = "set_limit",
) -> GPUPowerLimitActionResponse:
    target, phrase, error = _target(drm_card, controller, power_index, target_micro_watts, action)
    if error or target is None or phrase is None:
        return GPUPowerLimitActionResponse(success=False, action=action, drm_card=drm_card, controller=controller, power_index=power_index, target_micro_watts=target_micro_watts, user_confirmed=confirmed is True, message=error or "The GPU power-limit request could not be verified.")
    if confirmed is not True:
        return GPUPowerLimitActionResponse(success=False, action=action, drm_card=drm_card, controller=controller, power_index=power_index, target_micro_watts=target_micro_watts, user_confirmed=False, message="Explicit client confirmation is required; no GPU power setting was changed.")
    if confirmation_phrase != phrase:
        return GPUPowerLimitActionResponse(success=False, action=action, drm_card=drm_card, controller=controller, power_index=power_index, target_micro_watts=target_micro_watts, user_confirmed=True, message="Confirmation did not match the exact GPU, hwmon channel, and current power-cap state.")
    current, current_phrase, error = _target(drm_card, controller, power_index, target_micro_watts, action)
    if error or current is None or current_phrase != phrase:
        return GPUPowerLimitActionResponse(success=False, action=action, drm_card=drm_card, controller=controller, power_index=power_index, target_micro_watts=target_micro_watts, user_confirmed=True, message=error or "GPU identity or power-cap state changed after confirmation; no write was performed.")
    device, pci_address, driver, device_identity, error = _gpu_identity(drm_card)
    if error or device is None or pci_address != target.pci_address or driver != target.driver or device_identity != target.device_identity:
        return GPUPowerLimitActionResponse(success=False, action=action, drm_card=drm_card, controller=controller, power_index=power_index, target_micro_watts=target_micro_watts, user_confirmed=True, message=error or "The exact GPU identity changed immediately before the write.")
    controller_path = _controller_path(device, controller)
    if controller_path is None or str(controller_path) != target.controller_path:
        return GPUPowerLimitActionResponse(success=False, action=action, drm_card=drm_card, controller=controller, power_index=power_index, target_micro_watts=target_micro_watts, user_confirmed=True, message="The GPU hwmon controller path changed immediately before the write.")
    try:
        controller_info = controller_path.stat()
        if not stat.S_ISDIR(controller_info.st_mode):
            raise OSError("The GPU hwmon controller is no longer a directory.")
        controller_identity = (controller_info.st_dev, controller_info.st_ino)
    except OSError:
        controller_identity = None
    if controller_identity != target.controller_identity:
        return GPUPowerLimitActionResponse(success=False, action=action, drm_card=drm_card, controller=controller, power_index=power_index, target_micro_watts=target_micro_watts, user_confirmed=True, message="The GPU hwmon controller identity changed immediately before the write.")
    cap_path = controller_path / f"power{power_index}_cap"
    try:
        _write_cap(cap_path, target.cap_identity, target_micro_watts)
    except OSError as exc:
        return GPUPowerLimitActionResponse(success=False, action=action, drm_card=drm_card, controller=controller, power_index=power_index, target_micro_watts=target_micro_watts, user_confirmed=True, message=f"The GPU power cap could not be written with current permissions: {exc.strerror or str(exc) or type(exc).__name__}.")
    device_after, pci_after, driver_after, device_identity_after, verify_error = _gpu_identity(drm_card)
    controller_after = _controller_path(device_after, controller) if device_after is not None else None
    try:
        controller_info_after = controller_after.stat() if controller_after is not None else None
        controller_identity_after = (controller_info_after.st_dev, controller_info_after.st_ino) if controller_info_after is not None and stat.S_ISDIR(controller_info_after.st_mode) else None
    except OSError:
        controller_identity_after = None
    cap_identity_after = _attribute_identity(cap_path)
    resulting = _read_uint(cap_path)
    if (
        verify_error
        or device_after is None
        or pci_after != target.pci_address
        or driver_after != target.driver
        or device_identity_after != target.device_identity
        or controller_identity_after != target.controller_identity
        or cap_identity_after != target.cap_identity
        or resulting != target_micro_watts
    ):
        return GPUPowerLimitActionResponse(success=False, action=action, drm_card=drm_card, controller=controller, power_index=power_index, target_micro_watts=target_micro_watts, resulting_micro_watts=resulting, user_confirmed=True, message="The power cap was written, but the requested value could not be verified; inspect the GPU driver state.")
    return GPUPowerLimitActionResponse(success=True, action=action, drm_card=drm_card, controller=controller, power_index=power_index, target_micro_watts=target_micro_watts, resulting_micro_watts=resulting, user_confirmed=True, message="Set and verified the driver-reported GPU power cap. Power and thermal behavior depend on the driver and hardware.")
