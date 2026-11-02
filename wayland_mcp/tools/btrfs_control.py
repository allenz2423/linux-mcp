"""Confirmation-gated Btrfs filesystem creation and single-device resize."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import BtrfsFilesystemActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env

BtrfsFilesystemAction = Literal["create", "grow", "shrink"]
SYS_DEV_BLOCK = Path("/sys/dev/block")
SYS_CLASS_BLOCK = Path("/sys/class/block")
BTRFS_SYSFS = Path("/sys/fs/btrfs")
MOUNTINFO = Path("/proc/self/mountinfo")
SWAPS = Path("/proc/swaps")
MAX_PATH_LENGTH = 4096
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
MAX_PROC_MOUNTINFO_BYTES = 4 * 1024 * 1024
MAX_DEVICE_SIZE_BYTES = 1 << 60
READ_TIMEOUT_SECONDS = 20
ACTION_TIMEOUT_SECONDS = 300
SHRINK_TIMEOUT_SECONDS = 3600
DEVICE_SIZE_RE = re.compile(
    r"(?m)^\s*devid\s+([0-9]+)\s+size\s+([0-9]+)\s+used\s+([0-9]+)\s+path\s+(.+?)\s*$"
)
TOTAL_DEVICES_RE = re.compile(r"(?m)^\s*Total devices\s+([0-9]+)\b")
UUID_RE = re.compile(r"(?m)^\s*Label:.*?\buuid:\s*([0-9a-fA-F-]{36})\s*$")
MINIMUM_DEVICE_SIZE_RE = re.compile(r"([0-9]+)\s+bytes(?:\s+\([^()\r\n]*\))?")
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class BtrfsFilesystemState:
    filesystem_uuid: str
    device_count: int
    device_id: int
    device_path: str
    filesystem_device_size_bytes: int


@dataclass(frozen=True, slots=True)
class BtrfsFilesystemTarget:
    action: BtrfsFilesystemAction
    target_path: str
    device_path: str
    device_major: int
    device_minor: int
    device_capacity_bytes: int
    filesystem_uuid: str | None
    filesystem_device_id: int | None
    filesystem_device_size_bytes: int | None
    filesystem_sector_size_bytes: int | None
    minimum_device_size_bytes: int | None
    target_size_bytes: int | None
    mountpoint: str | None
    mount_identity: tuple[int, ...] | None
    mount_read_only: bool | None
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def btrfs_filesystem_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    return all(find_session_binary(name, selected) for name in ("btrfs", "mkfs.btrfs", "wipefs"))


def _run_read(command: list[str], *, timeout: int = READ_TIMEOUT_SECONDS) -> tuple[int, str] | None:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if len(completed.stdout) > MAX_COMMAND_OUTPUT_BYTES:
        return None
    try:
        return completed.returncode, completed.stdout.decode("utf-8", errors="strict")
    except UnicodeError:
        return None


def _run_mutation(
    command: list[str],
    *,
    device_fd: int | None = None,
    timeout: int = ACTION_TIMEOUT_SECONDS,
) -> bool:
    options = {"pass_fds": (device_fd,)} if device_fd is not None else {}
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env=_environment(),
            close_fds=True,
            **options,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _resolve_device(value: object) -> tuple[Path | None, os.stat_result | None, str | None]:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > MAX_PATH_LENGTH:
        return None, None, "For create, target_path must be an absolute path to one block device under /dev."
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None, None, "The device path cannot contain control characters."
    try:
        path = Path(value).resolve(strict=True)
        path.relative_to(Path("/dev"))
        info = path.stat()
    except (OSError, RuntimeError, ValueError):
        return None, None, "target_path must resolve to an existing block device under /dev."
    if not stat.S_ISBLK(info.st_mode):
        return None, None, "target_path must resolve to a block device for create."
    return path, info, None


def _device_state(info: os.stat_result) -> tuple[int | None, bool | None, bool | None]:
    device = SYS_DEV_BLOCK / f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    try:
        sectors = int((device / "size").read_text(encoding="ascii").strip(), 10)
        readonly_raw = (device / "ro").read_text(encoding="ascii").strip()
        holders = device / "holders"
        if sectors <= 0 or sectors > MAX_DEVICE_SIZE_BYTES // 512 or readonly_raw not in {"0", "1"}:
            return None, None, None
        has_holders = any(holders.iterdir())
    except (OSError, UnicodeError, ValueError):
        return None, None, None
    return sectors * 512, readonly_raw == "1", has_holders


def _has_child_partitions(info: os.stat_result) -> bool | None:
    identity = SYS_DEV_BLOCK / f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    try:
        target = identity.resolve(strict=True)
        with os.scandir(SYS_CLASS_BLOCK) as entries:
            for entry in entries:
                candidate = Path(entry.path)
                if not (candidate / "partition").is_file():
                    continue
                try:
                    if candidate.resolve(strict=True).parent == target:
                        return True
                except (OSError, RuntimeError):
                    continue
    except OSError:
        return None
    return False


def _decode_mount_field(value: str) -> str | None:
    result: list[str] = []
    index = 0
    allowed = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    while index < len(value):
        if value[index] != "\\":
            result.append(value[index])
            index += 1
            continue
        replacement = allowed.get(value[index + 1:index + 4])
        if replacement is None:
            return None
        result.append(replacement)
        index += 4
    decoded = "".join(result)
    if "\x00" in decoded or len(decoded) > MAX_PATH_LENGTH:
        return None
    return decoded


def _mount_state(mountpoint: Path) -> tuple[bool | None, tuple[int, ...] | None, str | None]:
    try:
        raw = MOUNTINFO.read_bytes()
        if len(raw) > MAX_PROC_MOUNTINFO_BYTES:
            return None, None, "The current mount table exceeded its safety limit."
        text = raw.decode("utf-8", errors="strict")
        mount_info = mountpoint.stat()
    except (OSError, UnicodeError):
        return None, None, "The current mount table or Btrfs mountpoint could not be read safely."
    if not stat.S_ISDIR(mount_info.st_mode):
        return None, None, "For grow or shrink, target_path must be a mounted directory."
    matches: list[bool] = []
    for line in text.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if len(fields) < separator + 3 or len(fields) < 6:
            continue
        decoded = _decode_mount_field(fields[4])
        if decoded != str(mountpoint):
            continue
        if fields[separator + 1] != "btrfs":
            return None, None, "The exact target path is not a Btrfs mountpoint."
        options = set(fields[5].split(","))
        matches.append("ro" in options)
    if len(matches) != 1:
        return None, None, "For grow or shrink, target_path must identify one unambiguous Btrfs mountpoint in the current namespace."
    identity = (
        mount_info.st_dev,
        mount_info.st_ino,
        mount_info.st_mode,
        mount_info.st_ctime_ns,
        mount_info.st_mtime_ns,
    )
    return matches[0], identity, None


def _signature_types(device_path: str) -> tuple[str, ...] | None:
    binary = find_session_binary("wipefs", _environment())
    if not binary:
        return None
    result = _run_read([binary, "--no-act", "--noheadings", "--output", "TYPE", device_path])
    if result is None or result[0] != 0:
        return None
    return tuple(sorted(line.strip() for line in result[1].splitlines() if line.strip()))


def _filesystem_state(path: str) -> BtrfsFilesystemState | None:
    binary = find_session_binary("btrfs", _environment())
    if not binary:
        return None
    result = _run_read([binary, "filesystem", "show", "--raw", path])
    if result is None or result[0] != 0:
        return None
    uuid_matches = UUID_RE.findall(result[1])
    count_matches = TOTAL_DEVICES_RE.findall(result[1])
    devices = DEVICE_SIZE_RE.findall(result[1])
    if len(uuid_matches) != 1 or len(count_matches) != 1 or len(devices) != 1:
        return None
    try:
        device_count = int(count_matches[0], 10)
        device_id = int(devices[0][0], 10)
        device_size = int(devices[0][1], 10)
        int(devices[0][2], 10)
    except ValueError:
        return None
    if device_count != 1 or device_id != 1 or not 0 < device_size <= MAX_DEVICE_SIZE_BYTES:
        return None
    device_value = devices[0][3]
    if not device_value.startswith("/dev/") or any(ord(char) < 32 or ord(char) == 127 for char in device_value):
        return None
    try:
        device_path = str(Path(device_value).resolve(strict=True))
        info = Path(device_path).stat()
    except (OSError, RuntimeError):
        return None
    if not stat.S_ISBLK(info.st_mode):
        return None
    return BtrfsFilesystemState(
        filesystem_uuid=uuid_matches[0].lower(),
        device_count=device_count,
        device_id=device_id,
        device_path=device_path,
        filesystem_device_size_bytes=device_size,
    )


def _filesystem_sector_size(filesystem_uuid: str) -> int | None:
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", filesystem_uuid):
        return None
    try:
        raw = (BTRFS_SYSFS / filesystem_uuid.lower() / "sectorsize").read_text(encoding="ascii").strip()
        if not raw.isdecimal() or len(raw) > 10:
            return None
        sector_size = int(raw, 10)
    except (OSError, UnicodeError, ValueError):
        return None
    if sector_size < 512 or sector_size > 65536 or sector_size & (sector_size - 1):
        return None
    return sector_size


def _minimum_device_size(path: str, device_id: int) -> int | None:
    binary = find_session_binary("btrfs", _environment())
    if not binary:
        return None
    result = _run_read([binary, "inspect-internal", "min-dev-size", "--id", str(device_id), path])
    if result is None or result[0] != 0:
        return None
    output = result[1].strip()
    match = MINIMUM_DEVICE_SIZE_RE.fullmatch(output)
    if match is None:
        return None
    try:
        size = int(match.group(1), 10)
    except ValueError:
        return None
    if not 0 < size <= MAX_DEVICE_SIZE_BYTES:
        return None
    return size


def btrfs_action_confirmation_details(
    action: str,
    target_path: str,
    target_size_bytes: int | None = None,
) -> tuple[BtrfsFilesystemTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Btrfs filesystem administration is available only on Linux."
    if not isinstance(action, str) or action not in {"create", "grow", "shrink"}:
        return None, None, "action must be create, grow, or shrink."
    if action == "shrink":
        if isinstance(target_size_bytes, bool) or not isinstance(target_size_bytes, int):
            return None, None, "For shrink, target_size_bytes must be an integer byte size."
        if not 0 < target_size_bytes <= MAX_DEVICE_SIZE_BYTES:
            return None, None, "target_size_bytes must be between 1 byte and the supported device-size limit."
        if os.geteuid() != 0:
            return None, None, "Btrfs shrink requires the server to already run as root; no elevation is requested."
    elif target_size_bytes is not None:
        return None, None, "target_size_bytes is accepted only for the shrink action."
    if not all(find_session_binary(name, _environment()) for name in ("btrfs", "mkfs.btrfs", "wipefs")):
        return None, None, "The btrfs-progs btrfs/mkfs.btrfs and util-linux wipefs commands are required."
    if not isinstance(target_path, str) or not target_path.startswith("/") or len(target_path) > MAX_PATH_LENGTH:
        return None, None, "target_path must be an absolute device path for create or mountpoint for grow/shrink."
    if any(ord(character) < 32 or ord(character) == 127 for character in target_path):
        return None, None, "target_path cannot contain control characters."

    signatures: tuple[str, ...] = ()
    filesystem_uuid: str | None = None
    filesystem_device_id: int | None = None
    filesystem_device_size: int | None = None
    filesystem_sector_size: int | None = None
    minimum_device_size: int | None = None
    mountpoint: str | None = None
    mount_identity: tuple[int, ...] | None = None
    mount_read_only: bool | None = None
    if action == "create":
        device, info, error = _resolve_device(target_path)
        if error or device is None or info is None:
            return None, None, error or "The Btrfs target block device could not be verified."
        capacity, readonly, has_holders = _device_state(info)
        if capacity is None or readonly is None or has_holders is None:
            return None, None, "The block-device capacity, read-only state, or holder relationships could not be verified."
        if readonly:
            return None, None, "The block device is read-only."
        mounted, swapped = _device_usage(info)
        if mounted is None or swapped is None:
            return None, None, "Mounted and swap usage could not be checked safely."
        signature_result = _signature_types(str(device))
        if signature_result is None:
            return None, None, "The device's existing signatures could not be read safely."
        signatures = signature_result
        if signatures:
            return None, None, "Btrfs creation refuses recognized filesystem, RAID, or partition signatures; it never forces formatting."
        if mounted or swapped:
            return None, None, "Btrfs creation is refused on a mounted or active swap device."
        if has_holders:
            return None, None, "Btrfs creation is refused while another device-mapper layer holds this block device."
        if _has_child_partitions(info) is not False:
            return None, None, "Btrfs creation is refused when child partitions exist or partition state cannot be read."
        device_path = str(device)
        device_major, device_minor = os.major(info.st_rdev), os.minor(info.st_rdev)
        target = str(device)
    else:
        supplied = Path(target_path)
        if ".." in supplied.parts:
            return None, None, "target_path cannot contain '..'."
        try:
            mount_path = supplied.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            return None, None, "The Btrfs mountpoint could not be resolved safely."
        if mount_path != supplied:
            return None, None, "Symbolic links in the Btrfs mountpoint are not accepted."
        mount_read_only, mount_identity, mount_error = _mount_state(mount_path)
        if mount_error or mount_read_only is None or mount_identity is None:
            return None, None, mount_error or "The Btrfs mountpoint could not be verified."
        if mount_read_only:
            return None, None, "Btrfs resize is refused on a read-only mount."
        filesystem = _filesystem_state(str(mount_path))
        if filesystem is None:
            return None, None, "Btrfs resize requires a readable single-device filesystem."
        device_path = filesystem.device_path
        filesystem_uuid = filesystem.filesystem_uuid
        filesystem_device_id = filesystem.device_id
        filesystem_device_size = filesystem.filesystem_device_size_bytes
        try:
            device_info = Path(device_path).stat()
        except OSError:
            return None, None, "The mounted Btrfs device identity could not be verified."
        capacity, readonly, _has_holders_state = _device_state(device_info)
        if capacity is None or readonly is None:
            return None, None, "The mounted Btrfs device capacity or read-only state could not be verified."
        if readonly:
            return None, None, "The underlying Btrfs block device is read-only."
        if filesystem_device_size > capacity:
            return None, None, "The mounted Btrfs device size exceeds the current backing-device capacity; resize is refused."
        if action == "grow":
            if filesystem_device_size >= capacity:
                return None, None, "The Btrfs filesystem already uses the available device capacity."
        else:
            if target_size_bytes is None or target_size_bytes >= filesystem_device_size:
                return None, None, "The requested Btrfs shrink size must be smaller than the current filesystem device size."
            minimum_device_size = _minimum_device_size(str(mount_path), filesystem.device_id)
            if minimum_device_size is None:
                return None, None, "The minimum safe Btrfs device size could not be read; shrink is refused."
            if target_size_bytes < minimum_device_size:
                return None, None, f"The requested size is below Btrfs's current minimum device size of {minimum_device_size} bytes."
            filesystem_sector_size = _filesystem_sector_size(filesystem.filesystem_uuid)
            if filesystem_sector_size is None:
                return None, None, "The Btrfs sector size could not be read safely; shrink is refused."
            if target_size_bytes % filesystem_sector_size:
                return None, None, f"target_size_bytes must be aligned to the Btrfs sector size ({filesystem_sector_size} bytes)."
        device_major, device_minor = os.major(device_info.st_rdev), os.minor(device_info.st_rdev)
        target = str(mount_path)
        capacity_value = capacity

    if action == "create":
        capacity_value = capacity
    details = {
        "action": action,
        "target_path": target,
        "device_path": device_path,
        "device_major": device_major,
        "device_minor": device_minor,
        "device_capacity_bytes": capacity_value,
        "filesystem_uuid": filesystem_uuid,
        "filesystem_device_id": filesystem_device_id,
        "filesystem_device_size_bytes": filesystem_device_size,
        "filesystem_sector_size_bytes": filesystem_sector_size,
        "minimum_device_size_bytes": minimum_device_size,
        "target_size_bytes": target_size_bytes,
        "mountpoint": target if action in {"grow", "shrink"} else None,
        "mount_identity": mount_identity,
        "mount_read_only": mount_read_only,
        "signatures": signatures,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target_info = BtrfsFilesystemTarget(
        action=action,  # type: ignore[arg-type]
        target_path=target,
        device_path=device_path,
        device_major=device_major,
        device_minor=device_minor,
        device_capacity_bytes=capacity_value,
        filesystem_uuid=filesystem_uuid,
        filesystem_device_id=filesystem_device_id,
        filesystem_device_size_bytes=filesystem_device_size,
        filesystem_sector_size_bytes=filesystem_sector_size,
        minimum_device_size_bytes=minimum_device_size,
        target_size_bytes=target_size_bytes,
        mountpoint=target if action in {"grow", "shrink"} else None,
        mount_identity=mount_identity,
        mount_read_only=mount_read_only,
        state_digest=digest,
    )
    phrase = hashlib.sha256((action + ":" + digest).encode("utf-8")).hexdigest()[:16]
    return target_info, f"btrfs {phrase}", None


def _device_usage(info: os.stat_result) -> tuple[bool | None, bool | None]:
    expected = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    try:
        mount_data = MOUNTINFO.read_bytes()
        swap_data = SWAPS.read_bytes()
        if len(mount_data) > MAX_PROC_MOUNTINFO_BYTES or len(swap_data) > 1024 * 1024:
            return None, None
        mounted = any(
            len(fields := line.split()) >= 3 and fields[2] == expected
            for line in mount_data.decode("utf-8", errors="strict").splitlines()
        )
        swapped = False
        for line in swap_data.decode("utf-8", errors="strict").splitlines()[1:]:
            fields = line.split()
            if not fields or not fields[0].startswith("/"):
                continue
            try:
                source = Path(fields[0]).stat()
            except OSError:
                continue
            if stat.S_ISBLK(source.st_mode) and source.st_rdev == info.st_rdev:
                swapped = True
                break
        return mounted, swapped
    except (OSError, UnicodeError):
        return None, None


def perform_btrfs_filesystem_action(
    action: BtrfsFilesystemAction,
    target_path: str,
    *,
    target_size_bytes: int | None = None,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> BtrfsFilesystemActionResponse:
    target, phrase, error = btrfs_action_confirmation_details(action, target_path, target_size_bytes)
    if error or target is None or phrase is None:
        return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target_path, user_confirmed=confirmed is True, message=error or "The Btrfs filesystem request could not be verified.")
    if confirmed is not True:
        return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=target.filesystem_uuid, user_confirmed=False, message="Explicit client confirmation is required; no filesystem command was run.")
    if confirmation_phrase != phrase:
        return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=target.filesystem_uuid, user_confirmed=True, message="Confirmation did not match the exact Btrfs device or mountpoint and current filesystem state.")

    with _ACTION_LOCK:
        current, current_phrase, error = btrfs_action_confirmation_details(action, target_path, target_size_bytes)
        if error or current is None or current_phrase != phrase:
            return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=target.filesystem_uuid, user_confirmed=True, message=error or "Btrfs device or filesystem state changed after confirmation; no command was run.")
        descriptor = -1
        try:
            command: list[str]
            if action == "create":
                descriptor = os.open(target.device_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
                opened = os.fstat(descriptor)
                if not stat.S_ISBLK(opened.st_mode) or (os.major(opened.st_rdev), os.minor(opened.st_rdev)) != (target.device_major, target.device_minor):
                    return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, user_confirmed=True, message="The opened block-device identity changed after confirmation; no filesystem command was run.")
                argument = f"/proc/self/fd/{descriptor}"
                binary = find_session_binary("mkfs.btrfs", _environment())
                if not binary:
                    return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, user_confirmed=True, message="The mkfs.btrfs command is unavailable.")
                command = [binary, "--nodiscard", "--quiet", argument]
                success = _run_mutation(command, device_fd=descriptor)
            elif action == "grow":
                binary = find_session_binary("btrfs", _environment())
                if not binary:
                    return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=target.filesystem_uuid, user_confirmed=True, message="The btrfs command is unavailable.")
                command = [binary, "filesystem", "resize", "max", target.target_path]
                success = _run_mutation(command)
            else:
                binary = find_session_binary("btrfs", _environment())
                if not binary or target.target_size_bytes is None:
                    return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=target.filesystem_uuid, user_confirmed=True, message="The btrfs command or confirmed shrink size is unavailable.")
                if target.filesystem_device_id is None:
                    return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=target.filesystem_uuid, user_confirmed=True, message="The confirmed Btrfs device ID is unavailable.")
                command = [binary, "filesystem", "resize", f"{target.filesystem_device_id}:{target.target_size_bytes}", target.target_path]
                success = _run_mutation(command, timeout=SHRINK_TIMEOUT_SECONDS)
        except OSError:
            return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=target.filesystem_uuid, user_confirmed=True, message="The Btrfs target could not be opened with current permissions; no elevation was requested.")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not success:
            return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=target.filesystem_uuid, user_confirmed=True, message="The Btrfs command did not complete successfully; inspect the device and filesystem before retrying.")

        verification_path = target.device_path if action == "create" else target.target_path
        result = _filesystem_state(verification_path)
        if result is None:
            return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=target.filesystem_uuid, user_confirmed=True, message="The Btrfs command returned successfully, but the resulting filesystem could not be verified; inspect storage before retrying.")
        if result.device_path != target.device_path or result.device_count != 1:
            return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=result.filesystem_uuid, user_confirmed=True, filesystem_size_bytes=result.filesystem_device_size_bytes, message="The Btrfs command returned, but the resulting filesystem device identity did not match the confirmed target.")
        if action == "create":
            verified = result.filesystem_device_size_bytes <= target.device_capacity_bytes
        elif action == "grow":
            verified = (
                result.filesystem_uuid == target.filesystem_uuid
                and target.filesystem_device_size_bytes is not None
                and result.filesystem_device_size_bytes > target.filesystem_device_size_bytes
                and result.filesystem_device_size_bytes <= target.device_capacity_bytes
            )
        else:
            verified = (
                result.filesystem_uuid == target.filesystem_uuid
                and target.target_size_bytes is not None
                and result.filesystem_device_size_bytes == target.target_size_bytes
            )
        if not verified:
            return BtrfsFilesystemActionResponse(success=False, action=action, target_path=target.target_path, filesystem_uuid=result.filesystem_uuid, user_confirmed=True, filesystem_size_bytes=result.filesystem_device_size_bytes, message="The Btrfs command returned, but the filesystem size did not match the requested action.")
        if action == "create":
            message = "Created and verified the Btrfs filesystem."
        elif action == "grow":
            message = "Grew and verified the single-device Btrfs filesystem."
        else:
            message = "Shrank and verified the single-device Btrfs filesystem. The backing device was not resized."
        return BtrfsFilesystemActionResponse(success=True, action=action, target_path=target.target_path, filesystem_uuid=result.filesystem_uuid, filesystem_size_bytes=result.filesystem_device_size_bytes, user_confirmed=True, message=message)
