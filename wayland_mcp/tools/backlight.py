"""Bounded Linux backlight inventory and confirmed brightness changes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import (
    DisplayBacklightInfo,
    DisplayBacklightListResponse,
    DisplayBrightnessResponse,
)

BACKLIGHT_ROOT = Path("/sys/class/backlight")
SYS_DEVICES_ROOT = Path("/sys/devices")
MAX_DEVICES = 64
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_ACTION_LOCK = threading.Lock()
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_WRITE_FLAGS = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True, slots=True)
class BacklightState:
    name: str
    canonical_path: Path
    directory_identity: tuple[int, ...]
    brightness: int
    actual_brightness: int | None
    max_brightness: int
    brightness_identity: tuple[int, ...]

    def material(self) -> dict[str, object]:
        return {
            "name": self.name,
            "canonical_path": str(self.canonical_path),
            "directory_identity": list(self.directory_identity),
            "brightness": self.brightness,
            "actual_brightness": self.actual_brightness,
            "max_brightness": self.max_brightness,
            "brightness_identity": list(self.brightness_identity),
        }


@dataclass(frozen=True, slots=True)
class BacklightTarget:
    before: BacklightState
    requested_brightness: int
    confirmation_phrase: str


def backlight_control_available() -> bool:
    return sys.platform.startswith("linux") and BACKLIGHT_ROOT.is_dir()


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_integer(path: Path) -> tuple[int | None, tuple[int, ...] | None, str | None]:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, _READ_FLAGS)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None, None, "A backlight attribute is not a regular sysfs value."
        raw = os.read(descriptor, 65)
        if len(raw) > 64:
            return None, None, "A backlight attribute exceeded its read limit."
        after = os.fstat(descriptor)
        if _stat_identity(info) != _stat_identity(after):
            return None, None, "A backlight attribute changed while it was read."
        try:
            text = raw.decode("ascii", errors="strict").strip()
            value = int(text, 10)
        except (UnicodeError, ValueError):
            return None, None, "A backlight attribute was not a decimal integer."
        return value, _stat_identity(after), None
    except OSError as exc:
        return None, None, f"A backlight attribute could not be read: {exc.strerror or 'read error'}."
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _device_path(name: object) -> tuple[Path | None, tuple[int, ...] | None, str | None]:
    if not isinstance(name, str) or not _NAME_PATTERN.fullmatch(name):
        return None, None, "device_name must be one exact backlight name from list_display_backlights."
    selected = BACKLIGHT_ROOT / name
    try:
        resolved = selected.resolve(strict=True)
        root = SYS_DEVICES_ROOT.resolve(strict=True)
        resolved.relative_to(root)
        directory_info = resolved.stat()
    except (OSError, RuntimeError, ValueError):
        return None, None, "The exact backlight device could not be resolved beneath /sys/devices."
    if not stat.S_ISDIR(directory_info.st_mode):
        return None, None, "The exact backlight target is not a device directory."
    return resolved, _stat_identity(directory_info), None


def _read_state(name: object) -> tuple[BacklightState | None, str | None]:
    canonical_path, directory_identity, error = _device_path(name)
    if error or canonical_path is None or directory_identity is None:
        return None, error or "The backlight device could not be verified."
    brightness, brightness_identity, error = _read_integer(canonical_path / "brightness")
    if error or brightness is None or brightness_identity is None:
        return None, error or "The configured brightness could not be read."
    maximum, _maximum_identity, error = _read_integer(canonical_path / "max_brightness")
    if error or maximum is None:
        return None, error or "The maximum brightness could not be read."
    if maximum < 1 or not 0 <= brightness <= maximum:
        return None, "The kernel backlight brightness range is invalid."
    actual, _actual_identity, actual_error = _read_integer(canonical_path / "actual_brightness")
    if actual_error or actual is None or not 0 <= actual <= maximum:
        actual = None
    try:
        after = canonical_path.stat()
    except OSError:
        return None, "The backlight device disappeared during inspection."
    if _stat_identity(after) != directory_identity:
        return None, "The backlight device changed during inspection."
    return BacklightState(
        name=str(name),
        canonical_path=canonical_path,
        directory_identity=directory_identity,
        brightness=brightness,
        actual_brightness=actual,
        max_brightness=maximum,
        brightness_identity=brightness_identity,
    ), None


def list_display_backlights() -> DisplayBacklightListResponse:
    if not sys.platform.startswith("linux"):
        return DisplayBacklightListResponse(success=False, message="Display backlight inventory is available only on Linux.")
    try:
        names = sorted(entry.name for entry in BACKLIGHT_ROOT.iterdir() if _NAME_PATTERN.fullmatch(entry.name))
    except OSError:
        return DisplayBacklightListResponse(success=False, message="Linux backlight sysfs is unavailable or unreadable.")
    devices: list[DisplayBacklightInfo] = []
    for name in names[:MAX_DEVICES]:
        state, _error = _read_state(name)
        if state is None:
            continue
        devices.append(DisplayBacklightInfo(
            name=state.name,
            brightness=state.brightness,
            actual_brightness=state.actual_brightness,
            max_brightness=state.max_brightness,
        ))
    truncated = len(names) > MAX_DEVICES
    return DisplayBacklightListResponse(
        success=True,
        total_devices=len(devices),
        devices=devices,
        truncated=truncated,
        message=(
            f"Read {len(devices)} backlight device(s) from bounded Linux sysfs."
            if not truncated else f"Read the first {MAX_DEVICES} backlight devices; additional entries were omitted."
        ),
    )


def display_brightness_confirmation_details(
    device_name: str,
    brightness: int,
) -> tuple[BacklightTarget | None, str | None]:
    if not isinstance(brightness, int) or isinstance(brightness, bool) or brightness < 0:
        return None, "brightness must be a non-negative integer."
    if not backlight_control_available():
        return None, "Linux backlight sysfs is unavailable."
    state, error = _read_state(device_name)
    if error or state is None:
        return None, error or "The exact backlight state could not be verified."
    if brightness > state.max_brightness:
        return None, f"brightness must be between 0 and {state.max_brightness} for this device."
    material = {"before": state.material(), "requested_brightness": brightness}
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()[:16]
    return BacklightTarget(
        before=state,
        requested_brightness=brightness,
        confirmation_phrase=f"SET BRIGHTNESS {state.name} {brightness}/{state.max_brightness} {digest}",
    ), None


def _response(
    success: bool,
    target: BacklightTarget | None,
    user_confirmed: bool,
    message: str,
    *,
    current_state: BacklightState | None = None,
) -> DisplayBrightnessResponse:
    state = current_state or (target.before if target else None)
    return DisplayBrightnessResponse(
        success=success,
        device_name=state.name if state else None,
        brightness=state.brightness if state else None,
        actual_brightness=state.actual_brightness if state else None,
        max_brightness=state.max_brightness if state else None,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_display_brightness_change(
    device_name: str,
    brightness: int,
    *,
    confirmed: bool,
    confirmed_device_name: str | None = None,
    confirmed_brightness: int | None = None,
    confirmed_phrase: str | None = None,
) -> DisplayBrightnessResponse:
    target, error = display_brightness_confirmation_details(device_name, brightness)
    if error or target is None:
        return _response(False, None, confirmed is True, error or "The requested brightness change could not be verified.")
    if not confirmed:
        return _response(False, target, False, "Explicit client confirmation is required; no brightness change was made.")
    if (
        confirmed_device_name != target.before.name
        or confirmed_brightness != target.requested_brightness
        or confirmed_phrase != target.confirmation_phrase
    ):
        return _response(False, target, True, "Confirmation did not repeat the exact device, requested brightness, and state-bound phrase.")
    with _ACTION_LOCK:
        current, error = display_brightness_confirmation_details(device_name, brightness)
        if error or current is None or current.confirmation_phrase != target.confirmation_phrase:
            return _response(False, target, True, error or "The backlight state changed after confirmation; no brightness change was made.")
        descriptor: int | None = None
        try:
            descriptor = os.open(current.before.canonical_path / "brightness", _WRITE_FLAGS)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or _stat_identity(info) != current.before.brightness_identity:
                return _response(False, target, True, "The exact brightness sysfs attribute changed after confirmation; no write was made.")
            written = os.write(descriptor, f"{brightness}\n".encode("ascii"))
            if written != len(f"{brightness}\n"):
                return _response(False, target, True, "The brightness sysfs write was incomplete; inspect the device state.")
        except OSError as exc:
            return _response(False, target, True, f"The brightness change failed: {exc.strerror or 'write error'}.")
        finally:
            if descriptor is not None:
                os.close(descriptor)
        verified, verify_error = _read_state(device_name)
        if verify_error or verified is None:
            return _response(False, target, True, verify_error or "The brightness change ran but could not be verified.")
        if verified.brightness != brightness:
            return _response(
                False, target, True,
                "The brightness write completed, but the configured value did not match; inspect the device state.",
                current_state=verified,
            )
        return _response(
            True, target, True,
            "Updated and verified the configured backlight brightness. A hardware-reported actual value may differ.",
            current_state=verified,
        )
