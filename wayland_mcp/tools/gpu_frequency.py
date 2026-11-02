"""Bounded inventory and confirmed controls for Intel Xe GT frequency limits."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import (
    GPUFrequencyLimitActionResponse,
    GPUFrequencyLimitConfirmation,
    GPUFrequencyLimitInfo,
    GPUFrequencyLimitListResponse,
)

DRM_ROOT = Path("/sys/class/drm")
SYS_DEVICES = Path("/sys/devices")
CARD_RE = re.compile(r"^card([0-9]{1,5})$")
PCI_ADDRESS_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
TILE_RE = re.compile(r"^tile([0-9]{1,5})$")
GT_RE = re.compile(r"^gt([0-9]{1,5})$")
MAX_GPU_CARDS = 128
MAX_TILES_PER_GPU = 64
MAX_GT_PER_TILE = 128
MAX_SCANNED_TILES = 128
MAX_SCANNED_GT = 256
MAX_SCANNED_DIRECTORY_ENTRIES = 256
MAX_FREQUENCY_MHZ = 100_000
MAX_RESULTS = 256


@dataclass(frozen=True, slots=True)
class XeFrequencyState:
    drm_card: str
    pci_address: str
    tile_id: int
    gt_id: int
    device_path: str
    frequency_path: str
    current_min_mhz: int
    current_max_mhz: int
    hardware_min_mhz: int
    hardware_max_mhz: int
    device_identity: tuple[int, int]
    gt_identity: tuple[int, int]
    frequency_identity: tuple[int, int]
    max_attribute_identity: tuple[int, int]


@dataclass(frozen=True, slots=True)
class XeFrequencyTarget:
    state: XeFrequencyState
    target_max_mhz: int
    digest: str


def _read_uint(path: Path) -> int | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(32)
        value = raw.decode("ascii", errors="strict").strip()
    except (OSError, UnicodeError):
        return None
    if not re.fullmatch(r"[0-9]{1,6}", value):
        return None
    result = int(value, 10)
    return result if 0 < result <= MAX_FREQUENCY_MHZ else None


def _directory_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.stat()
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        return None
    return info.st_dev, info.st_ino


def _attribute_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return info.st_dev, info.st_ino


def _matching_names(root: Path, pattern: re.Pattern[str], maximum: int) -> tuple[list[str], bool]:
    names: list[str] = []
    partial = False
    try:
        with os.scandir(root) as entries:
            for scanned, entry in enumerate(entries):
                if scanned >= MAX_SCANNED_DIRECTORY_ENTRIES:
                    partial = True
                    break
                if pattern.fullmatch(entry.name):
                    names.append(entry.name)
    except FileNotFoundError:
        return [], False
    except OSError:
        return [], True
    names.sort(key=lambda name: int(pattern.fullmatch(name).group(1)))
    if len(names) > maximum:
        names = names[:maximum]
        partial = True
    return names, partial


def _gpu_identity(
    drm_card: str,
) -> tuple[Path | None, str | None, tuple[int, int] | None, str | None]:
    if not isinstance(drm_card, str) or not CARD_RE.fullmatch(drm_card):
        return None, None, None, "drm_card must be one exact cardN name from list_gpu_devices."
    try:
        device = (DRM_ROOT / drm_card / "device").resolve(strict=True)
        device.relative_to(SYS_DEVICES.resolve(strict=True))
        info = device.stat()
    except (OSError, RuntimeError, ValueError):
        return None, None, None, "The GPU sysfs identity could not be verified beneath /sys/devices."
    if not stat.S_ISDIR(info.st_mode):
        return None, None, None, "The resolved GPU device is not a sysfs directory."
    pci_address = device.name.lower()
    if not PCI_ADDRESS_RE.fullmatch(pci_address):
        return None, None, None, "Xe frequency controls support PCI DRM GPUs only."
    try:
        driver = (device / "driver").resolve(strict=True).name
    except (OSError, RuntimeError):
        return None, pci_address, None, "The GPU driver identity could not be verified."
    if driver != "xe":
        return None, pci_address, None, "The selected GPU is not using the Intel Xe driver."
    return device, pci_address, (info.st_dev, info.st_ino), None


def _frequency_path(
    device: Path,
    tile_id: int,
    gt_id: int,
) -> tuple[Path | None, tuple[int, int] | None, tuple[int, int] | None, str | None]:
    if type(tile_id) is not int or not 0 <= tile_id <= 65_535:
        return None, None, None, "tile_id must be an integer from 0 through 65535."
    if type(gt_id) is not int or not 0 <= gt_id <= 65_535:
        return None, None, None, "gt_id must be an integer from 0 through 65535."
    try:
        tile = (device / f"tile{tile_id}").resolve(strict=True)
        tile.relative_to(device)
        gt = (tile / f"gt{gt_id}").resolve(strict=True)
        gt.relative_to(tile)
        frequency = (gt / "freq0").resolve(strict=True)
        frequency.relative_to(gt)
    except (OSError, RuntimeError, ValueError):
        return None, None, None, "The selected Xe tile/GT frequency directory is unavailable beneath the GPU."
    gt_identity = _directory_identity(gt)
    frequency_identity = _directory_identity(frequency)
    if gt_identity is None or frequency_identity is None:
        return None, None, None, "The selected Xe GT frequency directory identity could not be verified."
    return frequency, gt_identity, frequency_identity, None


def _read_state(
    drm_card: str,
    tile_id: int,
    gt_id: int,
) -> tuple[XeFrequencyState | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Xe GPU frequency control is available only on Linux."
    device, pci_address, device_identity, error = _gpu_identity(drm_card)
    if error or device is None or pci_address is None or device_identity is None:
        return None, error or "The exact Xe GPU identity could not be verified."
    frequency, gt_identity, frequency_identity, error = _frequency_path(device, tile_id, gt_id)
    if error or frequency is None or gt_identity is None or frequency_identity is None:
        return None, error or "The exact Xe GT frequency path could not be verified."
    current_min = _read_uint(frequency / "min_freq")
    current_max = _read_uint(frequency / "max_freq")
    hardware_min = _read_uint(frequency / "rpn_freq")
    hardware_max = _read_uint(frequency / "rp0_freq")
    if (
        current_min is None
        or current_max is None
        or hardware_min is None
        or hardware_max is None
        or not hardware_min < hardware_max
        or not hardware_min <= current_min < current_max <= hardware_max
    ):
        return None, "The Xe GT current or hardware frequency range could not be verified."
    max_attribute_identity = _attribute_identity(frequency / "max_freq")
    if max_attribute_identity is None:
        return None, "The Xe max_freq attribute is unavailable or not a sysfs file."
    return XeFrequencyState(
        drm_card=drm_card,
        pci_address=pci_address,
        tile_id=tile_id,
        gt_id=gt_id,
        device_path=str(device),
        frequency_path=str(frequency),
        current_min_mhz=current_min,
        current_max_mhz=current_max,
        hardware_min_mhz=hardware_min,
        hardware_max_mhz=hardware_max,
        device_identity=device_identity,
        gt_identity=gt_identity,
        frequency_identity=frequency_identity,
        max_attribute_identity=max_attribute_identity,
    ), None


def _target(
    drm_card: str,
    tile_id: int,
    gt_id: int,
    target_max_mhz: int,
) -> tuple[XeFrequencyTarget | None, str | None, str | None]:
    if type(target_max_mhz) is not int or not 0 < target_max_mhz <= MAX_FREQUENCY_MHZ:
        return None, None, f"target_max_frequency_mhz must be an integer from 1 through {MAX_FREQUENCY_MHZ}."
    state, error = _read_state(drm_card, tile_id, gt_id)
    if error or state is None:
        return None, None, error or "The exact Xe GT state could not be verified."
    if not state.current_min_mhz < target_max_mhz <= state.hardware_max_mhz:
        return None, None, (
            "target_max_frequency_mhz must remain above the current minimum and at or below "
            f"the hardware maximum ({state.current_min_mhz}..{state.hardware_max_mhz} MHz)."
        )
    if target_max_mhz == state.current_max_mhz:
        return None, None, "The requested maximum frequency already matches the current limit."
    material = {
        "drm_card": state.drm_card,
        "pci_address": state.pci_address,
        "tile_id": tile_id,
        "gt_id": gt_id,
        "device_identity": state.device_identity,
        "gt_identity": state.gt_identity,
        "frequency_identity": state.frequency_identity,
        "max_attribute_identity": state.max_attribute_identity,
        "current_min_mhz": state.current_min_mhz,
        "current_max_mhz": state.current_max_mhz,
        "hardware_min_mhz": state.hardware_min_mhz,
        "hardware_max_mhz": state.hardware_max_mhz,
        "target_max_mhz": target_max_mhz,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return XeFrequencyTarget(state, target_max_mhz, digest), f"Xe max frequency {digest[:16]}", None


def gpu_frequency_limit_confirmation_details(
    drm_card: str,
    tile_id: int,
    gt_id: int,
    target_max_frequency_mhz: int,
) -> tuple[XeFrequencyTarget | None, str | None, str | None]:
    return _target(drm_card, tile_id, gt_id, target_max_frequency_mhz)


def list_gpu_frequency_limits(query: str = "", limit: int = 128) -> GPUFrequencyLimitListResponse:
    if not sys.platform.startswith("linux"):
        return GPUFrequencyLimitListResponse(success=False, message="Xe GPU frequency inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256 or any(ord(char) < 32 for char in query):
        return GPUFrequencyLimitListResponse(success=False, message="query must be text with at most 256 characters and no control characters.")
    if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
        return GPUFrequencyLimitListResponse(success=False, message=f"limit must be an integer from 1 through {MAX_RESULTS}.")
    if not DRM_ROOT.is_dir():
        return GPUFrequencyLimitListResponse(success=False, message="The Linux DRM sysfs inventory is unavailable.")
    cards, partial = _matching_names(DRM_ROOT, CARD_RE, MAX_GPU_CARDS)
    items: list[GPUFrequencyLimitInfo] = []
    scanned_tiles = 0
    scanned_gt = 0
    for drm_card in cards:
        if scanned_gt >= MAX_SCANNED_GT:
            partial = True
            break
        device, _pci_address, _identity, error = _gpu_identity(drm_card)
        if error:
            if "not using the Intel Xe driver" not in error and "support PCI DRM GPUs only" not in error:
                partial = True
            continue
        if device is None:
            partial = True
            continue
        tiles, tile_partial = _matching_names(device, TILE_RE, MAX_TILES_PER_GPU)
        partial |= tile_partial
        for tile_name in tiles:
            if scanned_tiles >= MAX_SCANNED_TILES:
                partial = True
                break
            scanned_tiles += 1
            tile_match = TILE_RE.fullmatch(tile_name)
            assert tile_match is not None
            tile_id = int(tile_match.group(1), 10)
            if tile_id > 65_535:
                partial = True
                continue
            try:
                tile_path = (device / tile_name).resolve(strict=True)
                tile_path.relative_to(device)
                if _directory_identity(tile_path) is None:
                    raise OSError("Not a directory")
            except (OSError, RuntimeError, ValueError):
                partial = True
                continue
            gt_names, gt_partial = _matching_names(tile_path, GT_RE, MAX_GT_PER_TILE)
            partial |= gt_partial
            for gt_name in gt_names:
                if scanned_gt >= MAX_SCANNED_GT:
                    partial = True
                    break
                scanned_gt += 1
                gt_match = GT_RE.fullmatch(gt_name)
                assert gt_match is not None
                gt_id = int(gt_match.group(1), 10)
                state, state_error = _read_state(drm_card, tile_id, gt_id)
                if state_error or state is None:
                    partial = True
                    continue
                item = GPUFrequencyLimitInfo(
                    drm_card=state.drm_card,
                    pci_address=state.pci_address,
                    tile_id=state.tile_id,
                    gt_id=state.gt_id,
                    current_min_frequency_mhz=state.current_min_mhz,
                    current_max_frequency_mhz=state.current_max_mhz,
                    hardware_min_frequency_mhz=state.hardware_min_mhz,
                    hardware_max_frequency_mhz=state.hardware_max_mhz,
                )
                query_material = f"{state.drm_card} {state.pci_address} {state.tile_id} {state.gt_id}"
                if not query or query.casefold() in query_material.casefold():
                    items.append(item)
            if scanned_gt >= MAX_SCANNED_GT:
                break
        if scanned_tiles >= MAX_SCANNED_TILES or scanned_gt >= MAX_SCANNED_GT:
            partial = True
            break
    items.sort(key=lambda item: (item.drm_card, item.tile_id, item.gt_id))
    total = len(items)
    return GPUFrequencyLimitListResponse(
        success=True,
        total_limits=total,
        returned_limits=min(total, limit),
        limits=items[:limit],
        limit=limit,
        truncated=total > limit,
        partial=partial,
        message="Some Xe GT frequency ranges could not be fully read." if partial else None,
    )


def _write_max_frequency(
    frequency_path: Path,
    expected_directory_identity: tuple[int, int],
    expected_attribute_identity: tuple[int, int],
    value: int,
) -> None:
    directory_fd: int | None = None
    attribute_fd: int | None = None
    try:
        directory_fd = os.open(
            frequency_path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        directory_info = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_info.st_mode) or (directory_info.st_dev, directory_info.st_ino) != expected_directory_identity:
            raise OSError("The Xe GT frequency directory identity changed before writing.")
        attribute_fd = os.open(
            "max_freq",
            os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        attribute_info = os.fstat(attribute_fd)
        if not stat.S_ISREG(attribute_info.st_mode) or (attribute_info.st_dev, attribute_info.st_ino) != expected_attribute_identity:
            raise OSError("The Xe max_freq attribute identity changed before writing.")
        payload = f"{value}\n".encode("ascii")
        if os.write(attribute_fd, payload) != len(payload):
            raise OSError("The Xe max_freq write was incomplete.")
    finally:
        if attribute_fd is not None:
            os.close(attribute_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def perform_gpu_frequency_limit_action(
    drm_card: str,
    tile_id: int,
    gt_id: int,
    target_max_frequency_mhz: int,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> GPUFrequencyLimitActionResponse:
    target, phrase, error = _target(drm_card, tile_id, gt_id, target_max_frequency_mhz)
    if error or target is None or phrase is None:
        return GPUFrequencyLimitActionResponse(
            success=False,
            drm_card=drm_card,
            tile_id=tile_id,
            gt_id=gt_id,
            target_max_frequency_mhz=target_max_frequency_mhz,
            user_confirmed=confirmed is True,
            message=error or "The Xe GT frequency-limit request could not be verified.",
        )
    if confirmed is not True:
        return GPUFrequencyLimitActionResponse(
            success=False,
            drm_card=drm_card,
            tile_id=tile_id,
            gt_id=gt_id,
            target_max_frequency_mhz=target_max_frequency_mhz,
            user_confirmed=False,
            message="Explicit client confirmation is required; no GPU frequency setting was changed.",
        )
    if confirmation_phrase != phrase:
        return GPUFrequencyLimitActionResponse(
            success=False,
            drm_card=drm_card,
            tile_id=tile_id,
            gt_id=gt_id,
            target_max_frequency_mhz=target_max_frequency_mhz,
            user_confirmed=True,
            message="Confirmation did not match the exact GPU, tile, GT, current range, and requested maximum.",
        )
    current, current_phrase, error = _target(drm_card, tile_id, gt_id, target_max_frequency_mhz)
    if error or current is None or current_phrase != phrase:
        return GPUFrequencyLimitActionResponse(
            success=False,
            drm_card=drm_card,
            tile_id=tile_id,
            gt_id=gt_id,
            target_max_frequency_mhz=target_max_frequency_mhz,
            user_confirmed=True,
            message=error or "The Xe GT identity or frequency range changed after confirmation; no write was performed.",
        )
    state = target.state
    try:
        _write_max_frequency(
            Path(state.frequency_path),
            state.frequency_identity,
            state.max_attribute_identity,
            target_max_frequency_mhz,
        )
    except OSError as exc:
        return GPUFrequencyLimitActionResponse(
            success=False,
            drm_card=drm_card,
            tile_id=tile_id,
            gt_id=gt_id,
            target_max_frequency_mhz=target_max_frequency_mhz,
            user_confirmed=True,
            message=f"The Xe max frequency could not be written with current permissions: {exc.strerror or str(exc) or type(exc).__name__}.",
        )
    resulting_state, verify_error = _read_state(drm_card, tile_id, gt_id)
    if (
        verify_error
        or resulting_state is None
        or resulting_state.pci_address != state.pci_address
        or resulting_state.device_identity != state.device_identity
        or resulting_state.gt_identity != state.gt_identity
        or resulting_state.frequency_identity != state.frequency_identity
        or resulting_state.max_attribute_identity != state.max_attribute_identity
        or resulting_state.current_min_mhz != state.current_min_mhz
        or resulting_state.hardware_min_mhz != state.hardware_min_mhz
        or resulting_state.hardware_max_mhz != state.hardware_max_mhz
        or resulting_state.current_max_mhz != target_max_frequency_mhz
    ):
        return GPUFrequencyLimitActionResponse(
            success=False,
            drm_card=drm_card,
            tile_id=tile_id,
            gt_id=gt_id,
            target_max_frequency_mhz=target_max_frequency_mhz,
            resulting_max_frequency_mhz=(resulting_state.current_max_mhz if resulting_state else None),
            user_confirmed=True,
            message="The max frequency was written, but the requested Xe GT state could not be verified; inspect the driver state.",
        )
    return GPUFrequencyLimitActionResponse(
        success=True,
        drm_card=drm_card,
        tile_id=tile_id,
        gt_id=gt_id,
        target_max_frequency_mhz=target_max_frequency_mhz,
        resulting_max_frequency_mhz=resulting_state.current_max_mhz,
        user_confirmed=True,
        message="Set and verified the Xe GT maximum frequency request. The driver and hardware may still run below the requested maximum.",
    )
