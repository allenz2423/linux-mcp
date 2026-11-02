"""Confirmation-gated maximum-speed and automatic-mode hwmon fan control."""

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

from wayland_mcp.models import FanControlActionResponse, FanControlInfo, FanControlListResponse

SYS_CLASS_HWMON = Path("/sys/class/hwmon")
SYS_DEVICES = Path("/sys/devices")
HWMON_RE = re.compile(r"^hwmon[0-9]{1,5}$")
PWM_RE = re.compile(r"^pwm([1-9][0-9]{0,2})$")
NAME_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,128}$")
MAX_CONTROLLERS = 256
MAX_PWM_INDEX = 256
MAX_SCANNED_CONTROLS = 4096
MAX_LIMIT = 100

FanControlAction = Literal["set_full", "restore_auto"]


@dataclass(frozen=True, slots=True)
class FanTarget:
    controller_name: str
    controller_path: str
    chip_name: str
    pwm_index: int
    pwm_value: int
    control_mode: int
    fan_rpm: int | None
    fan_label: str | None
    pwm_identity: tuple[int, int]
    enable_identity: tuple[int, int]
    digest: str


def _read_text(path: Path, limit: int = 256) -> str | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            return None
        value = raw.decode("utf-8", errors="strict").strip()
        if any(ord(char) < 32 and char not in "\t" for char in value):
            return None
        return value
    except (OSError, UnicodeError):
        return None


def _read_number(path: Path, low: int, high: int) -> int | None:
    raw = _read_text(path, 64)
    if raw is None or not re.fullmatch(r"[0-9]{1,12}", raw):
        return None
    value = int(raw, 10)
    return value if low <= value <= high else None


def _attribute_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return info.st_dev, info.st_ino


def _controller(name: str) -> tuple[Path | None, str | None]:
    if not isinstance(name, str) or not HWMON_RE.fullmatch(name):
        return None, "controller must be an exact hwmonN name returned by list_fan_controls."
    try:
        path = (SYS_CLASS_HWMON / name).resolve(strict=True)
        path.relative_to(SYS_DEVICES.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return None, "The hwmon controller identity could not be verified beneath /sys/devices."
    return path, None


def _target(
    controller_name: str,
    pwm_index: int,
    action: str,
) -> tuple[FanTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Fan control is available only on Linux."
    if not isinstance(action, str) or action not in {"set_full", "restore_auto"}:
        return None, None, "action must be set_full or restore_auto."
    if type(pwm_index) is not int or not 1 <= pwm_index <= MAX_PWM_INDEX:
        return None, None, f"pwm_index must be an integer from 1 through {MAX_PWM_INDEX}."
    root, error = _controller(controller_name)
    if error or root is None:
        return None, None, error or "The fan controller could not be verified."
    chip_name = _read_text(root / "name")
    if chip_name is None or not NAME_RE.fullmatch(chip_name):
        return None, None, "The hwmon chip name could not be verified."
    pwm_path = root / f"pwm{pwm_index}"
    enable_path = root / f"pwm{pwm_index}_enable"
    pwm_identity = _attribute_identity(pwm_path)
    enable_identity = _attribute_identity(enable_path)
    if pwm_identity is None or enable_identity is None:
        return None, None, "This PWM channel does not expose readable and writable value and mode attributes."
    pwm_value = _read_number(pwm_path, 0, 255)
    control_mode = _read_number(enable_path, 0, 255)
    if pwm_value is None or control_mode is None:
        return None, None, "The PWM value or control mode could not be read in the standard Linux hwmon range."
    if control_mode == 0:
        return None, None, "The fan controller is in no-control mode; this tool does not take over a mode that may already mean full speed."
    fan_rpm = _read_number(root / f"fan{pwm_index}_input", 0, 10_000_000)
    fan_label = _read_text(root / f"fan{pwm_index}_label", 128)
    if fan_label is not None and len(fan_label) > 128:
        fan_label = None
    material = {
        "controller_name": controller_name,
        "controller_path": str(root),
        "chip_name": chip_name,
        "pwm_index": pwm_index,
        "pwm_value": pwm_value,
        "control_mode": control_mode,
        "fan_rpm": fan_rpm,
        "fan_label": fan_label,
        "pwm_identity": pwm_identity,
        "enable_identity": enable_identity,
        "action": action,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return FanTarget(
        controller_name, str(root), chip_name, pwm_index, pwm_value, control_mode,
        fan_rpm, fan_label, pwm_identity, enable_identity, digest,
    ), f"fan control {digest[:16]}", None


def fan_control_confirmation_details(
    controller: str,
    pwm_index: int,
    action: str,
) -> tuple[FanTarget | None, str | None, str | None]:
    return _target(controller, pwm_index, action)


def _write_attribute(path: Path, expected_identity: tuple[int, int], value: int) -> None:
    fd: int | None = None
    try:
        fd = os.open(path, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != expected_identity:
            raise OSError("The hwmon attribute identity changed before writing.")
        data = f"{value}\n".encode("ascii")
        if os.write(fd, data) != len(data):
            raise OSError("The hwmon attribute write was incomplete.")
    finally:
        if fd is not None:
            os.close(fd)


def list_fan_controls(query: str = "", limit: int = 100) -> FanControlListResponse:
    if not sys.platform.startswith("linux"):
        return FanControlListResponse(success=False, message="Fan control inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256 or any(ord(char) < 32 for char in query):
        return FanControlListResponse(success=False, message="query must be text with at most 256 characters and no control characters.")
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        return FanControlListResponse(success=False, message=f"limit must be an integer from 1 through {MAX_LIMIT}.")
    if not SYS_CLASS_HWMON.is_dir():
        return FanControlListResponse(success=False, message="The Linux hwmon sysfs interface is unavailable.")
    items: list[FanControlInfo] = []
    partial = False
    try:
        controllers = sorted(
            (entry for entry in SYS_CLASS_HWMON.iterdir() if HWMON_RE.fullmatch(entry.name)),
            key=lambda item: item.name,
        )
    except OSError:
        return FanControlListResponse(success=False, message="The hwmon controller inventory could not be read.")
    if len(controllers) > MAX_CONTROLLERS:
        partial = True
        controllers = controllers[:MAX_CONTROLLERS]
    scanned_controls = 0
    for controller_entry in controllers:
        if scanned_controls >= MAX_SCANNED_CONTROLS:
            partial = True
            break
        root, error = _controller(controller_entry.name)
        if error or root is None:
            partial = True
            continue
        chip_name = _read_text(root / "name")
        if chip_name is None:
            partial = True
            continue
        try:
            pwm_paths = sorted((path for path in root.iterdir() if PWM_RE.fullmatch(path.name)), key=lambda path: path.name)
        except OSError:
            partial = True
            continue
        for pwm_path in pwm_paths:
            if scanned_controls >= MAX_SCANNED_CONTROLS:
                partial = True
                break
            scanned_controls += 1
            match = PWM_RE.fullmatch(pwm_path.name)
            assert match is not None
            index = int(match.group(1), 10)
            if index > MAX_PWM_INDEX:
                partial = True
                continue
            value = _read_number(pwm_path, 0, 255)
            mode = _read_number(root / f"pwm{index}_enable", 0, 255)
            if value is None or mode is None:
                partial = True
                continue
            fan_rpm = _read_number(root / f"fan{index}_input", 0, 10_000_000)
            label = _read_text(root / f"fan{index}_label", 128)
            item = FanControlInfo(
                controller=controller_entry.name,
                controller_path=str(root),
                chip_name=chip_name,
                pwm_index=index,
                pwm_value=value,
                control_mode=mode,
                fan_rpm=fan_rpm,
                fan_label=label,
                controllable=mode != 0 and _attribute_identity(root / f"pwm{index}_enable") is not None,
            )
            if not query or query.casefold() in " ".join((item.controller, item.controller_path, item.chip_name, item.fan_label or "", str(index))).casefold():
                items.append(item)
    items.sort(key=lambda item: (item.controller, item.pwm_index))
    total = len(items)
    return FanControlListResponse(
        success=True,
        total_controls=total,
        returned_controls=min(total, limit),
        controls=items[:limit],
        limit=limit,
        truncated=total > limit,
        partial=partial,
        message="Some hwmon entries could not be read." if partial else None,
    )


def perform_fan_control(
    controller: str,
    pwm_index: int,
    action: FanControlAction,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> FanControlActionResponse:
    target, phrase, error = _target(controller, pwm_index, action)
    if error or target is None or phrase is None:
        return FanControlActionResponse(success=False, action=action, controller=controller, pwm_index=pwm_index, user_confirmed=confirmed is True, message=error or "The fan controller could not be verified.")
    if confirmed is not True:
        return FanControlActionResponse(success=False, action=action, controller=target.controller_name, pwm_index=pwm_index, user_confirmed=False, message="Explicit client confirmation is required; no fan control attribute was changed.")
    if confirmation_phrase != phrase:
        return FanControlActionResponse(success=False, action=action, controller=target.controller_name, pwm_index=pwm_index, user_confirmed=True, message="Confirmation did not match the exact controller, channel, and current fan state.")
    current, current_phrase, error = _target(controller, pwm_index, action)
    if error or current is None or current_phrase != phrase:
        return FanControlActionResponse(success=False, action=action, controller=target.controller_name, pwm_index=pwm_index, user_confirmed=True, message=error or "Fan controller state changed after confirmation; no attribute was changed.")

    root = Path(target.controller_path)
    enable_path = root / f"pwm{pwm_index}_enable"
    pwm_path = root / f"pwm{pwm_index}"
    checked_fds: list[int] = []
    write_error: str | None = None
    try:
        for path, expected_identity in ((enable_path, target.enable_identity), (pwm_path, target.pwm_identity)):
            fd = os.open(path, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
            checked_fds.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != expected_identity:
                raise OSError("A fan control attribute identity changed before writing.")
        if action == "set_full":
            _write_attribute(enable_path, target.enable_identity, 1)
            try:
                _write_attribute(pwm_path, target.pwm_identity, 255)
            except OSError:
                try:
                    _write_attribute(enable_path, target.enable_identity, 2)
                except OSError:
                    pass
                raise
        else:
            _write_attribute(enable_path, target.enable_identity, 2)
    except OSError as exc:
        write_error = exc.strerror or str(exc) or type(exc).__name__
    finally:
        for fd in checked_fds:
            try:
                os.close(fd)
            except OSError:
                pass

    after_mode = _read_number(enable_path, 0, 255)
    after_pwm = _read_number(pwm_path, 0, 255)
    after_rpm = _read_number(root / f"fan{pwm_index}_input", 0, 10_000_000)
    if write_error:
        return FanControlActionResponse(success=False, action=action, controller=target.controller_name, pwm_index=pwm_index, pwm_value=after_pwm, control_mode=after_mode, fan_rpm=after_rpm, user_confirmed=True, message=f"The hwmon write failed: {write_error}. Current reported mode/value are {after_mode}/{after_pwm}; inspect fan RPM and temperatures immediately.")
    verified = (after_mode == 1 and after_pwm == 255) if action == "set_full" else (after_mode is not None and after_mode >= 2)
    if not verified:
        return FanControlActionResponse(success=False, action=action, controller=target.controller_name, pwm_index=pwm_index, pwm_value=after_pwm, control_mode=after_mode, fan_rpm=after_rpm, user_confirmed=True, message="The fan mode was written, but the requested resulting state could not be verified. Inspect fan and temperature readings immediately.")
    message = (
        "Requested maximum PWM fan speed. The controller reports the target value; verify fan RPM and temperatures because hardware may not follow the request."
        if action == "set_full"
        else "Returned the fan controller to automatic mode. Verify fan RPM and temperatures."
    )
    return FanControlActionResponse(success=True, action=action, controller=target.controller_name, pwm_index=pwm_index, pwm_value=after_pwm, control_mode=after_mode, fan_rpm=after_rpm, user_confirmed=True, message=message)
