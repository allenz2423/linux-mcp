"""Confirmation-gated Linux MD array and member management."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import MDRaidActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env

MDRaidAction = Literal["create", "assemble", "add_spare", "remove_spare", "replace_member", "mark_faulty", "remove_faulty", "check", "stop"]
SYS_DEV_BLOCK = Path("/sys/dev/block")
SYS_CLASS_BLOCK = Path("/sys/class/block")
MOUNTINFO = Path("/proc/self/mountinfo")
SWAPS = Path("/proc/swaps")
ARRAY_PATH_RE = re.compile(r"^/dev/md[0-9]{1,4}$")
DEVICE_NAME_RE = re.compile(r"^[A-Za-z0-9._+-]{1,255}$")
RAID_LEVELS = {"raid0", "raid1", "raid4", "raid5", "raid6", "raid10"}
MIN_ARRAY_DEVICES = 2
MAX_ARRAY_DEVICES = 16
MAX_DEVICE_SIZE_BYTES = 1 << 60
MAX_PROC_BYTES = 4 * 1024 * 1024
MAX_SWAP_BYTES = 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 180
MD_UUID_RE = re.compile(r"^(?:[0-9a-fA-F]{8}:){3}[0-9a-fA-F]{8}$")


@dataclass(frozen=True, slots=True)
class BlockDevice:
    path: str
    name: str
    major: int
    minor: int
    size_bytes: int
    physical_parent: str
    is_partition: bool
    signatures: tuple[str, ...]
    mounted: bool
    swapped: bool
    read_only: bool
    has_holders: bool
    holders: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ArrayMember:
    name: str
    state: tuple[str, ...]
    major: int
    minor: int


@dataclass(frozen=True, slots=True)
class MDArray:
    path: str
    name: str
    major: int
    minor: int
    level: str
    raid_devices: int
    degraded: int
    array_state: str
    sync_action: str
    mismatch_count: int | None
    members: tuple[ArrayMember, ...]


@dataclass(frozen=True, slots=True)
class MDComponentMetadata:
    array_uuid: str
    component_uuid: str
    raid_level: str
    raid_devices: int
    events: int
    role: int
    metadata_version: str
    state: str
    array_state: str
    metadata_digest: str


@dataclass(frozen=True, slots=True)
class MDRaidTarget:
    action: MDRaidAction
    array_path: str
    raid_level: str | None
    raid_devices: int | None
    chunk_size_kib: int | None
    devices: tuple[BlockDevice, ...]
    array: MDArray | None
    array_device: BlockDevice | None
    component_metadata: tuple[MDComponentMetadata, ...]
    read_only: bool
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def md_raid_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    return all(find_session_binary(binary, selected) for binary in ("mdadm", "wipefs")) and SYS_CLASS_BLOCK.is_dir()


def _run_read(
    command: list[str], *, timeout: int = 15, pass_fds: tuple[int, ...] = ()
) -> tuple[int, str] | None:
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
            pass_fds=pass_fds,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if len(completed.stdout) > MAX_COMMAND_OUTPUT_BYTES:
        return None
    try:
        return completed.returncode, completed.stdout.decode("utf-8", errors="strict")
    except UnicodeError:
        return None


def _read_small(path: Path, maximum: int = 512) -> str | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            return None
        return raw.decode("ascii", errors="strict").strip()
    except (OSError, UnicodeError):
        return None


def _usage_state(major: int, minor: int) -> tuple[bool | None, bool | None]:
    expected = f"{major}:{minor}"
    try:
        with MOUNTINFO.open("rb") as stream:
            mount_data = stream.read(MAX_PROC_BYTES + 1)
        if len(mount_data) > MAX_PROC_BYTES:
            return None, None
        mounted = any(
            len(fields := line.split()) >= 3 and fields[2] == expected
            for line in mount_data.decode("utf-8", errors="strict").splitlines()
        )
        with SWAPS.open("rb") as stream:
            swap_data = stream.read(MAX_SWAP_BYTES + 1)
        if len(swap_data) > MAX_SWAP_BYTES:
            return None, None
        swapped = False
        for line in swap_data.decode("utf-8", errors="strict").splitlines()[1:]:
            fields = line.split()
            if not fields or not fields[0].startswith("/"):
                continue
            try:
                swap_path = Path(fields[0]).resolve(strict=True)
                swap_info = swap_path.stat()
            except (OSError, RuntimeError):
                continue
            if stat.S_ISBLK(swap_info.st_mode) and (os.major(swap_info.st_rdev), os.minor(swap_info.st_rdev)) == (major, minor):
                swapped = True
                break
        # An active child layer is reported in sysfs holders; this direct usage
        # check covers filesystems or swap placed on the device itself.
        return mounted, swapped
    except (OSError, UnicodeError):
        return None, None


def _signature_types(device_path: str) -> tuple[str, ...] | None:
    wipefs = find_session_binary("wipefs", _environment())
    if not wipefs:
        return None
    result = _run_read([wipefs, "--no-act", "--noheadings", "--output", "TYPE", device_path])
    if result is None or result[0] != 0:
        return None
    return tuple(sorted({line.strip() for line in result[1].splitlines() if line.strip()}))


def _has_child_partitions(sysfs_path: Path) -> bool | None:
    try:
        with os.scandir(SYS_CLASS_BLOCK) as entries:
            for entry in entries:
                candidate = Path(entry.path)
                try:
                    if not (candidate / "partition").is_file():
                        continue
                    if candidate.resolve(strict=True).parent == sysfs_path:
                        return True
                except (OSError, RuntimeError):
                    continue
    except OSError:
        return None
    return False


def _resolve_block_device(value: object) -> tuple[BlockDevice | None, str | None]:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096:
        return None, "Each device_path must be one absolute path to a block device under /dev."
    try:
        path = Path(value).resolve(strict=True)
        path.relative_to(Path("/dev"))
        info = path.stat()
    except (OSError, RuntimeError, ValueError):
        return None, "Each device_path must resolve to an existing block device under /dev."
    if not stat.S_ISBLK(info.st_mode):
        return None, "Each device_path must resolve to a block device."
    major, minor = os.major(info.st_rdev), os.minor(info.st_rdev)
    sysfs = SYS_DEV_BLOCK / f"{major}:{minor}"
    try:
        sysfs_path = sysfs.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "The block-device sysfs identity could not be verified."
    name = sysfs_path.name
    if not DEVICE_NAME_RE.fullmatch(name):
        return None, "The kernel block-device name is outside the supported character set."
    size_text = _read_small(sysfs / "size")
    readonly_text = _read_small(sysfs / "ro")
    if size_text is None or not size_text.isdigit() or readonly_text not in {"0", "1"}:
        return None, "Block-device size and read-only state could not be verified."
    sectors = int(size_text, 10)
    size_bytes = sectors * 512
    if sectors <= 0 or size_bytes > MAX_DEVICE_SIZE_BYTES:
        return None, "Block-device capacity is empty or outside the supported limit."
    try:
        holder_names = tuple(sorted(item.name for item in (sysfs / "holders").iterdir()))
    except OSError:
        return None, "Block-device holder relationships could not be verified."
    has_holders = bool(holder_names)
    is_partition = (sysfs / "partition").is_file()
    if is_partition:
        physical_parent = str(sysfs_path.parent)
    else:
        physical_parent = str(sysfs_path)
        child_partitions = _has_child_partitions(sysfs_path)
        if child_partitions is None:
            return None, "Child-partition state could not be verified."
        if child_partitions:
            return None, "A whole block device with child partitions cannot be used; select a partition instead."
    mounted, swapped = _usage_state(major, minor)
    if mounted is None or swapped is None:
        return None, "Mounted and swap usage could not be checked safely."
    signatures = _signature_types(str(path))
    if signatures is None:
        return None, "Existing block-device signatures could not be checked safely."
    return BlockDevice(
        path=str(path),
        name=name,
        major=major,
        minor=minor,
        size_bytes=size_bytes,
        physical_parent=physical_parent,
        is_partition=is_partition,
        signatures=signatures,
        mounted=mounted,
        swapped=swapped,
        read_only=readonly_text == "1",
        has_holders=has_holders,
        holders=holder_names,
    ), None


def _read_md_component_metadata(
    device: BlockDevice, descriptor: int | None = None
) -> tuple[MDComponentMetadata | None, str | None]:
    opened_here = descriptor is None
    try:
        if descriptor is None:
            descriptor = os.open(
                device.path,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            )
        info = os.fstat(descriptor)
        if not stat.S_ISBLK(info.st_mode) or (os.major(info.st_rdev), os.minor(info.st_rdev)) != (device.major, device.minor):
            return None, "An MD component's block-device identity changed while examining it."
        mdadm = find_session_binary("mdadm", _environment())
        if not mdadm:
            return None, "The mdadm command is unavailable."
        result = _run_read(
            [mdadm, "--config=none", "--examine", f"/proc/self/fd/{descriptor}"],
            pass_fds=(descriptor,),
        )
        if result is None or result[0] != 0:
            return None, "The exact block device does not expose readable MD component metadata."
        report = result[1]

        def one_value(label: str) -> str | None:
            values = re.findall(
                rf"^\s*{re.escape(label)}\s*:\s*(.*?)\s*$",
                report,
                flags=re.MULTILINE,
            )
            return values[0] if len(values) == 1 else None

        version = one_value("Version")
        level = one_value("Raid Level")
        raid_devices_text = one_value("Raid Devices")
        array_uuid = one_value("UUID")
        component_uuid = one_value("Device UUID")
        events_text = one_value("Events")
        role_text = one_value("Device Role")
        state = one_value("State")
        array_state_match = re.findall(
            r"^\s*Array State\s*:\s*([A.R?]+)(?:\s+\(|\s*$)",
            report,
            flags=re.MULTILINE,
        )
        if (
            version not in {"1.0", "1.1", "1.2"}
            or level not in RAID_LEVELS
            or raid_devices_text is None
            or not raid_devices_text.isdigit()
            or array_uuid is None
            or not MD_UUID_RE.fullmatch(array_uuid)
            or component_uuid is None
            or not MD_UUID_RE.fullmatch(component_uuid)
            or events_text is None
            or not events_text.isdigit()
            or role_text is None
            or not re.fullmatch(r"Active device [0-9]{1,2}", role_text)
            or state != "clean"
            or len(array_state_match) != 1
            or re.search(r"^\s*(?:Reshape pos'n|Recovery Offset)\s*:", report, flags=re.MULTILINE)
        ):
            return None, "MD assembly requires clean, non-reshaping version-1 metadata with one exact active-device role per member."
        raid_devices = int(raid_devices_text, 10)
        role_match = re.fullmatch(r"Active device ([0-9]{1,2})", role_text)
        assert role_match is not None
        lines = report.splitlines()
        if lines and lines[0].rstrip().endswith(":"):
            lines = lines[1:]
        metadata_digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
        return MDComponentMetadata(
            array_uuid=array_uuid.lower(),
            component_uuid=component_uuid.lower(),
            raid_level=level,
            raid_devices=raid_devices,
            events=int(events_text, 10),
            role=int(role_match.group(1), 10),
            metadata_version=version,
            state=state,
            array_state=array_state_match[0],
            metadata_digest=metadata_digest,
        ), None
    except OSError as exc:
        return None, f"An MD component could not be opened with current permissions: {exc.strerror or type(exc).__name__}."
    finally:
        if opened_here and descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_md_array(array_path: str) -> tuple[MDArray | None, str | None]:
    try:
        path = Path(array_path).resolve(strict=True)
        path.relative_to(Path("/dev"))
        info = path.stat()
    except (OSError, RuntimeError, ValueError):
        return None, "The exact MD array path does not resolve to a local block device."
    if not stat.S_ISBLK(info.st_mode):
        return None, "The selected path is not an active block device."
    major, minor = os.major(info.st_rdev), os.minor(info.st_rdev)
    sysfs = SYS_DEV_BLOCK / f"{major}:{minor}"
    try:
        sysfs_path = sysfs.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "The MD array sysfs identity could not be verified."
    md_dir = sysfs_path / "md"
    if not md_dir.is_dir():
        return None, "The selected block device is not an active Linux MD array."
    level = _read_small(md_dir / "level")
    raid_devices_text = _read_small(md_dir / "raid_disks")
    degraded_text = _read_small(md_dir / "degraded")
    array_state = _read_small(md_dir / "array_state")
    sync_action = _read_small(md_dir / "sync_action")
    mismatch_count_text = _read_small(md_dir / "mismatch_cnt")
    if (
        level is None or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", level)
        or raid_devices_text is None or not raid_devices_text.isdigit()
        or degraded_text is None or not degraded_text.isdigit()
        or array_state is None or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", array_state)
        or sync_action is None or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", sync_action)
    ):
        return None, "The active MD array configuration or sync state could not be read safely."
    mismatch_count = int(mismatch_count_text, 10) if mismatch_count_text and mismatch_count_text.isdigit() else None
    members: list[ArrayMember] = []
    try:
        with os.scandir(md_dir) as entries:
            member_names = sorted(
                (entry.name for entry in entries if entry.name.startswith("dev-")),
                key=str.casefold,
            )
    except OSError:
        return None, "The MD array member list could not be scanned."
    if len(member_names) > MAX_ARRAY_DEVICES * 4:
        return None, "The MD array exposes too many member entries for bounded control."
    for member_entry_name in member_names:
        member_dir = md_dir / member_entry_name
        name = member_entry_name.removeprefix("dev-")
        if not DEVICE_NAME_RE.fullmatch(name):
            return None, "The MD array contains a member with an unsupported kernel name."
        state_text = _read_small(member_dir / "state")
        member_dev = _read_small(member_dir / "block" / "dev")
        if state_text is None or member_dev is None or not re.fullmatch(r"[0-9]+:[0-9]+", member_dev):
            return None, "One MD member's identity or state could not be verified."
        state_parts = state_text.split(",")
        if not state_parts or any(not re.fullmatch(r"[a-z_]{1,32}", part) for part in state_parts):
            return None, "One MD member's state was empty or malformed."
        states = tuple(sorted(state_parts))
        member_major_text, member_minor_text = member_dev.split(":", 1)
        members.append(ArrayMember(name, states, int(member_major_text, 10), int(member_minor_text, 10)))
    array = MDArray(
        path=str(path),
        name=sysfs_path.name,
        major=major,
        minor=minor,
        level=level,
        raid_devices=int(raid_devices_text, 10),
        degraded=int(degraded_text, 10),
        array_state=array_state,
        sync_action=sync_action,
        mismatch_count=mismatch_count,
        members=tuple(members),
    )
    return array, None


def _device_material(device: BlockDevice) -> dict[str, object]:
    return {
        "path": device.path,
        "name": device.name,
        "major": device.major,
        "minor": device.minor,
        "size_bytes": device.size_bytes,
        "physical_parent": device.physical_parent,
        "is_partition": device.is_partition,
        "signatures": list(device.signatures),
        "mounted": device.mounted,
        "swapped": device.swapped,
        "read_only": device.read_only,
        "has_holders": device.has_holders,
        "holders": list(device.holders),
    }


def _array_material(array: MDArray) -> dict[str, object]:
    return {
        "path": array.path,
        "name": array.name,
        "major": array.major,
        "minor": array.minor,
        "level": array.level,
        "raid_devices": array.raid_devices,
        "degraded": array.degraded,
        "array_state": array.array_state,
        "sync_action": array.sync_action,
        "mismatch_count": array.mismatch_count,
        "members": [
            {"name": member.name, "state": list(member.state), "major": member.major, "minor": member.minor}
            for member in array.members
        ],
    }


def _component_metadata_material(metadata: MDComponentMetadata) -> dict[str, object]:
    return {
        "array_uuid": metadata.array_uuid,
        "component_uuid": metadata.component_uuid,
        "raid_level": metadata.raid_level,
        "raid_devices": metadata.raid_devices,
        "events": metadata.events,
        "role": metadata.role,
        "metadata_version": metadata.metadata_version,
        "state": metadata.state,
        "array_state": metadata.array_state,
        "metadata_digest": metadata.metadata_digest,
    }


def _geometry_error(level: str, count: int) -> str | None:
    if level == "raid0" and not 2 <= count <= MAX_ARRAY_DEVICES:
        return f"raid0 requires 2 through {MAX_ARRAY_DEVICES} devices."
    if level == "raid1" and not 2 <= count <= MAX_ARRAY_DEVICES:
        return f"raid1 requires 2 through {MAX_ARRAY_DEVICES} devices."
    if level in {"raid4", "raid5"} and not 3 <= count <= MAX_ARRAY_DEVICES:
        return f"{level} requires 3 through {MAX_ARRAY_DEVICES} devices."
    if level == "raid6" and not 4 <= count <= MAX_ARRAY_DEVICES:
        return f"raid6 requires 4 through {MAX_ARRAY_DEVICES} devices."
    if level == "raid10" and (not 4 <= count <= MAX_ARRAY_DEVICES or count % 2 != 0):
        return f"raid10 requires an even number of 4 through {MAX_ARRAY_DEVICES} devices."
    return None


def md_raid_action_confirmation_details(
    action: str,
    array_path: str,
    device_paths: list[str],
    raid_level: str | None = None,
    chunk_size_kib: int | None = None,
    read_only: bool = True,
) -> tuple[MDRaidTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "MD RAID administration is available only on Linux."
    if not md_raid_control_available():
        return None, None, "The mdadm command, util-linux wipefs command, and Linux sysfs block-device inventory are required."
    valid_actions = {"create", "assemble", "add_spare", "remove_spare", "replace_member", "mark_faulty", "remove_faulty", "check", "stop"}
    if not isinstance(action, str) or action not in valid_actions:
        return None, None, "action must be create, assemble, add_spare, remove_spare, replace_member, mark_faulty, remove_faulty, check, or stop."
    if not isinstance(read_only, bool):
        return None, None, "read_only must be a boolean."
    if not isinstance(device_paths, list):
        return None, None, "device_paths must be a list of exact block-device paths."
    if action in {"check", "stop"} and device_paths:
        return None, None, f"{action} requires an empty device_paths list."
    if action not in {"check", "stop"} and not 1 <= len(device_paths) <= MAX_ARRAY_DEVICES:
        return None, None, f"device_paths must contain 1 through {MAX_ARRAY_DEVICES} exact block-device paths."

    array: MDArray | None = None
    array_device: BlockDevice | None = None
    component_metadata: tuple[MDComponentMetadata, ...] = ()
    if action == "create":
        if not isinstance(array_path, str) or not ARRAY_PATH_RE.fullmatch(array_path):
            return None, None, "Creating an array requires one unused /dev/mdN path with N from 0 through 9999."
        requested_md_name = Path(array_path).name
        if os.path.lexists(array_path) or (SYS_CLASS_BLOCK / requested_md_name).exists():
            return None, None, "The requested MD array path already exists; choose an unused /dev/mdN path."
        if not isinstance(raid_level, str) or raid_level not in RAID_LEVELS:
            return None, None, "raid_level must be raid0, raid1, raid4, raid5, raid6, or raid10."
        if len(device_paths) < MIN_ARRAY_DEVICES:
            return None, None, "Creating an MD array requires at least two member devices."
        geometry_error = _geometry_error(raid_level, len(device_paths))
        if geometry_error:
            return None, None, geometry_error
        if raid_level == "raid0":
            if chunk_size_kib is None:
                return None, None, "raid0 creation requires chunk_size_kib from 64 through 1024, as a power of two."
        elif raid_level in {"raid4", "raid5", "raid6", "raid10"} and chunk_size_kib is None:
            # Bind and show the upstream mdadm create default explicitly.
            chunk_size_kib = 512
        elif chunk_size_kib is not None:
            if raid_level == "raid1":
                return None, None, "chunk_size_kib is not used for raid1."
        if chunk_size_kib is not None and (
            isinstance(chunk_size_kib, bool)
            or not isinstance(chunk_size_kib, int)
            or chunk_size_kib < 64
            or chunk_size_kib > 1024
            or chunk_size_kib & (chunk_size_kib - 1)
        ):
            return None, None, "chunk_size_kib must be a power of two from 64 through 1024."
    elif action == "assemble":
        if not isinstance(array_path, str) or not ARRAY_PATH_RE.fullmatch(array_path):
            return None, None, "Assembling an array requires one unused /dev/mdN path with N from 0 through 9999."
        if os.path.lexists(array_path) or (SYS_CLASS_BLOCK / Path(array_path).name).exists():
            return None, None, "The requested MD array path already exists; choose an unused /dev/mdN path."
        if raid_level is not None or chunk_size_kib is not None:
            return None, None, "raid_level and chunk_size_kib are used only when creating an array."
        if not MIN_ARRAY_DEVICES <= len(device_paths) <= MAX_ARRAY_DEVICES:
            return None, None, f"Assembly requires 2 through {MAX_ARRAY_DEVICES} exact component-device paths."
    else:
        if raid_level is not None or chunk_size_kib is not None:
            return None, None, "raid_level and chunk_size_kib are used only when creating an array."
        expected_paths = 2 if action == "replace_member" else 0 if action in {"check", "stop"} else 1
        if len(device_paths) != expected_paths:
            return None, None, (
                "replace_member requires the active member path followed by one blank replacement-device path."
                if action == "replace_member"
                else f"{action} requires an empty device_paths list." if action in {"check", "stop"}
                else f"{action} requires exactly one member-device path."
            )
        array, error = _read_md_array(array_path)
        if error or array is None:
            return None, None, error or "The active MD array could not be verified."
        if action == "stop":
            if array.array_state not in {"active", "clean", "active-idle"} or array.sync_action != "idle":
                return None, None, "Stopping requires an active, idle MD array with no resync, recovery, check, or reshape in progress."
            array_device, error = _resolve_block_device(array_path)
            if error or array_device is None:
                return None, None, error or "The exact MD array block device could not be verified."
            if (array_device.major, array_device.minor) != (array.major, array.minor):
                return None, None, "The MD array block-device identity changed during inspection."
            if array_device.mounted or array_device.swapped or array_device.has_holders or array_device.read_only:
                return None, None, "The MD array is mounted, used by swap, held by another block layer, or read-only; it cannot be stopped safely."
        else:
            if array.level not in {"raid1", "raid4", "raid5", "raid6", "raid10"}:
                return None, None, (
                    "A consistency check requires an active redundant MD array."
                    if action == "check"
                    else "Member replacement and spare management require an active redundant MD array."
                )
            if array.array_state not in {"active", "clean", "active-idle"} or array.sync_action != "idle":
                return None, None, "The MD array must be active and idle, with no resync, recovery, check, or reshape in progress."
            if action != "remove_faulty" and array.degraded != 0:
                return None, None, (
                    "A consistency check requires a non-degraded MD array."
                    if action == "check"
                    else "Member replacement, failure marking, and spare changes are refused while the MD array is degraded."
                )

    devices: list[BlockDevice] = []
    for raw_path in device_paths:
        device, error = _resolve_block_device(raw_path)
        if error or device is None:
            return None, None, error or "A member-device identity could not be verified."
        allowed_holders = (
            {array.name}
            if array is not None and (
                action in {"remove_spare", "mark_faulty", "remove_faulty"}
                or (action == "replace_member" and len(devices) == 0)
            )
            else set()
        )
        if action == "assemble":
            if (
                (device.read_only and not read_only)
                or device.has_holders
                or device.mounted
                or device.swapped
            ):
                return None, None, f"{device.path} is mounted, used by swap, held by another block layer, or not writable for read-write assembly."
            if set(device.signatures) != {"linux_raid_member"}:
                return None, None, f"{device.path} must contain only an MD RAID member signature; other or missing signatures are refused."
        elif device.read_only or (device.has_holders and not set(device.holders).issubset(allowed_holders)) or device.mounted or device.swapped:
            return None, None, f"{device.path} is read-only, mounted, used by swap, or held by another block layer."
        if len(device.signatures) > 0 and (
            action in {"create", "add_spare"}
            or (action == "replace_member" and len(devices) == 1)
        ):
            return None, None, f"{device.path} has recognized signatures ({', '.join(device.signatures)}); existing metadata will not be erased."
        devices.append(device)

    if len({(device.major, device.minor) for device in devices}) != len(devices):
        return None, None, "The same block-device identity cannot be selected more than once."
    if action == "assemble":
        examined: list[MDComponentMetadata] = []
        for device in devices:
            metadata, error = _read_md_component_metadata(device)
            if error or metadata is None:
                return None, None, error or "An MD component's metadata could not be verified."
            examined.append(metadata)
        first = examined[0]
        geometry_error = _geometry_error(first.raid_level, first.raid_devices)
        if geometry_error:
            return None, None, geometry_error
        if len(examined) != first.raid_devices:
            return None, None, "Assembly requires exactly one selected component for every configured RAID member role."
        if any(
            metadata.array_uuid != first.array_uuid
            or metadata.raid_level != first.raid_level
            or metadata.raid_devices != first.raid_devices
            or metadata.metadata_version != first.metadata_version
            or metadata.events != first.events
            or metadata.state != "clean"
            or metadata.array_state != "A" * first.raid_devices
            for metadata in examined
        ):
            return None, None, "All selected components must belong to the same clean, complete, non-degraded array generation."
        if {metadata.role for metadata in examined} != set(range(first.raid_devices)):
            return None, None, "Selected components must cover every active RAID role exactly once; spares and duplicate roles are refused."
        if len({metadata.component_uuid for metadata in examined}) != len(examined):
            return None, None, "Every selected component must have a distinct MD component UUID."
        component_metadata = tuple(examined)
    elif action == "create":
        if len({device.physical_parent for device in devices}) != len(devices):
            return None, None, "Each new array member must be on a separate physical disk."
    elif array is not None and action != "stop":
        if any((device.major, device.minor) in {(member.major, member.minor) for member in array.members} for device in devices):
            if action == "add_spare":
                return None, None, "The requested device is already a member of this MD array."
        array_parents: set[str] = set()
        for member in array.members:
            member_sysfs = SYS_DEV_BLOCK / f"{member.major}:{member.minor}"
            try:
                member_real = member_sysfs.resolve(strict=True)
            except (OSError, RuntimeError):
                return None, None, "The physical identity of every existing MD member must be readable."
            array_parents.add(str(member_real.parent if (member_sysfs / "partition").is_file() else member_real))
        if action == "add_spare" and any(device.physical_parent in array_parents for device in devices):
            return None, None, "The spare must be on a separate physical disk from every existing array member."
        member_matches = [
            member for member in array.members
            if devices and (member.major, member.minor) == (devices[0].major, devices[0].minor)
        ]
        if action == "remove_spare":
            if len(member_matches) != 1 or "spare" not in member_matches[0].state:
                return None, None, "Only an exact member currently marked spare and not active can be removed."
        if action == "mark_faulty":
            if (
                len(member_matches) != 1
                or "in_sync" not in member_matches[0].state
                or {"spare", "faulty", "blocked"} & set(member_matches[0].state)
            ):
                return None, None, "Only one exact healthy, in-sync active member can be marked faulty."
        if action == "remove_faulty":
            if len(member_matches) != 1 or "faulty" not in member_matches[0].state or "in_sync" in member_matches[0].state:
                return None, None, "Only one exact member already marked faulty and no longer in-sync can be removed."
        if action == "replace_member":
            old_member = next(
                (member for member in array.members if (member.major, member.minor) == (devices[0].major, devices[0].minor)),
                None,
            )
            replacement = devices[1]
            if old_member is None or "in_sync" not in old_member.state or {"spare", "faulty", "blocked"} & set(old_member.state):
                return None, None, "The first device must be one exact healthy, in-sync active array member."
            if replacement.signatures:
                return None, None, "The replacement device must be blank; existing signatures will not be overwritten."
            if replacement.size_bytes < devices[0].size_bytes:
                return None, None, "The replacement device must be at least as large as the active member it replaces."
            if replacement.physical_parent in array_parents:
                return None, None, "The replacement must be on a separate physical disk from every current array member."

    material = {
        "action": action,
        "array_path": array.path if array else array_path,
        "raid_level": raid_level,
        "raid_devices": len(devices) if action == "create" else None,
        "chunk_size_kib": chunk_size_kib,
        "read_only": read_only if action == "assemble" else None,
        "devices": [_device_material(device) for device in devices],
        "array": _array_material(array) if array else None,
        "array_device": _device_material(array_device) if array_device else None,
        "component_metadata": [_component_metadata_material(item) for item in component_metadata],
    }
    state_digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    target = MDRaidTarget(
        action=action,  # type: ignore[arg-type]
        array_path=array.path if array else array_path,
        raid_level=raid_level if action == "create" else (component_metadata[0].raid_level if action == "assemble" else (array.level if array else None)),
        raid_devices=len(devices) if action == "create" else (component_metadata[0].raid_devices if action == "assemble" else None),
        chunk_size_kib=chunk_size_kib,
        devices=tuple(devices),
        array=array,
        array_device=array_device,
        component_metadata=component_metadata,
        read_only=read_only if action == "assemble" else True,
        state_digest=state_digest,
    )
    phrase_material = {"digest": state_digest, "action": action, "array_path": target.array_path}
    phrase = hashlib.sha256(
        json.dumps(phrase_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    return target, f"MD RAID {phrase}", None


def _run_mutation(command: list[str], pass_fds: tuple[int, ...]) -> bool:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
            pass_fds=pass_fds,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _md_sync_action_path(array: MDArray) -> tuple[Path | None, tuple[int, int] | None, str | None]:
    sysfs_entry = SYS_DEV_BLOCK / f"{array.major}:{array.minor}"
    try:
        resolved = sysfs_entry.resolve(strict=True)
        if resolved.name != array.name:
            return None, None, "The MD array sysfs identity changed."
        md_directory = resolved / "md"
        directory_info = md_directory.stat()
        if not stat.S_ISDIR(directory_info.st_mode):
            return None, None, "The MD sysfs directory is unavailable."
        sync_path = md_directory / "sync_action"
        sync_info = sync_path.lstat()
        if not stat.S_ISREG(sync_info.st_mode):
            return None, None, "The MD sync_action sysfs attribute is not a regular sysfs attribute."
        return sync_path, (sync_info.st_dev, sync_info.st_ino), None
    except (OSError, RuntimeError):
        return None, None, "The MD sync_action sysfs attribute could not be verified."


def _wait_for_md_array(array_path: str, timeout: float = 3.0) -> tuple[MDArray | None, str | None]:
    deadline = time.monotonic() + timeout
    last_error: str | None = None
    while True:
        array, error = _read_md_array(array_path)
        if array is not None:
            return array, None
        last_error = error
        if time.monotonic() >= deadline:
            return None, last_error
        time.sleep(0.05)


def _perform_md_assemble(target: MDRaidTarget) -> MDRaidActionResponse:
    if not target.component_metadata or len(target.component_metadata) != len(target.devices):
        return MDRaidActionResponse(
            success=False,
            action="assemble",
            array_path=target.array_path,
            raid_level=target.raid_level,
            device_paths=[device.path for device in target.devices],
            read_only=target.read_only,
            user_confirmed=True,
            message="The exact MD component metadata is unavailable; no array was assembled.",
        )
    if os.path.lexists(target.array_path) or (SYS_CLASS_BLOCK / Path(target.array_path).name).exists():
        return MDRaidActionResponse(
            success=False,
            action="assemble",
            array_path=target.array_path,
            raid_level=target.raid_level,
            device_paths=[device.path for device in target.devices],
            read_only=target.read_only,
            user_confirmed=True,
            message="The requested MD array path became occupied; no assembly was attempted.",
        )

    opened: list[int] = []
    try:
        fd_paths: list[str] = []
        for device, expected_metadata in zip(target.devices, target.component_metadata, strict=True):
            flags = os.O_RDONLY if target.read_only else os.O_RDWR
            descriptor = os.open(
                device.path,
                flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            )
            opened.append(descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISBLK(info.st_mode) or (os.major(info.st_rdev), os.minor(info.st_rdev)) != (device.major, device.minor):
                return MDRaidActionResponse(
                    success=False,
                    action="assemble",
                    array_path=target.array_path,
                    raid_level=target.raid_level,
                    device_paths=[item.path for item in target.devices],
                    read_only=target.read_only,
                    user_confirmed=True,
                    message="An MD component-device identity changed while opening it; no assembly was attempted.",
                )
            current_device, device_error = _resolve_block_device(device.path)
            if (
                device_error
                or current_device is None
                or _device_material(current_device) != _device_material(device)
                or current_device.mounted
                or current_device.swapped
                or current_device.has_holders
                or (current_device.read_only and not target.read_only)
            ):
                return MDRaidActionResponse(
                    success=False,
                    action="assemble",
                    array_path=target.array_path,
                    raid_level=target.raid_level,
                    device_paths=[item.path for item in target.devices],
                    read_only=target.read_only,
                    user_confirmed=True,
                    message=device_error or "An MD component became mounted, held, or otherwise changed; no assembly was attempted.",
                )
            metadata, metadata_error = _read_md_component_metadata(device, descriptor)
            if metadata_error or metadata != expected_metadata:
                return MDRaidActionResponse(
                    success=False,
                    action="assemble",
                    array_path=target.array_path,
                    raid_level=target.raid_level,
                    device_paths=[item.path for item in target.devices],
                    read_only=target.read_only,
                    user_confirmed=True,
                    message=metadata_error or "An MD component's metadata changed after confirmation; no assembly was attempted.",
                )
            fd_paths.append(f"/proc/self/fd/{descriptor}")

        mdadm = find_session_binary("mdadm", _environment())
        if not mdadm:
            return MDRaidActionResponse(
                success=False,
                action="assemble",
                array_path=target.array_path,
                raid_level=target.raid_level,
                device_paths=[device.path for device in target.devices],
                read_only=target.read_only,
                user_confirmed=True,
                message="The mdadm command is unavailable; no array was assembled.",
            )
        if os.path.lexists(target.array_path) or (SYS_CLASS_BLOCK / Path(target.array_path).name).exists():
            return MDRaidActionResponse(
                success=False,
                action="assemble",
                array_path=target.array_path,
                raid_level=target.raid_level,
                device_paths=[device.path for device in target.devices],
                read_only=target.read_only,
                user_confirmed=True,
                message="The requested MD array path became occupied; no assembly was attempted.",
            )
        command = [mdadm, "--assemble", "--config=none"]
        if target.read_only:
            command.append("--readonly")
        command.extend([f"--uuid={target.component_metadata[0].array_uuid}", target.array_path])
        command.extend(fd_paths)
        if not _run_mutation(command, tuple(opened)):
            return MDRaidActionResponse(
                success=False,
                action="assemble",
                array_path=target.array_path,
                raid_level=target.raid_level,
                device_paths=[device.path for device in target.devices],
                read_only=target.read_only,
                user_confirmed=True,
                message="mdadm did not complete successfully; inspect /proc/mdstat and the exact component metadata before retrying.",
            )
    except OSError as exc:
        return MDRaidActionResponse(
            success=False,
            action="assemble",
            array_path=target.array_path,
            raid_level=target.raid_level,
            device_paths=[device.path for device in target.devices],
            read_only=target.read_only,
            user_confirmed=True,
            message=f"A component could not be opened with current permissions: {exc.strerror or type(exc).__name__}.",
        )
    finally:
        for descriptor in opened:
            try:
                os.close(descriptor)
            except OSError:
                pass

    result_array, verify_error = _wait_for_md_array(target.array_path)
    expected_members = {(device.major, device.minor) for device in target.devices}
    actual_members = {(member.major, member.minor) for member in result_array.members} if result_array else set()
    allowed_states = {"readonly"} if target.read_only else {"active", "clean", "active-idle"}
    verified = bool(
        result_array
        and result_array.level == target.raid_level
        and result_array.raid_devices == len(target.devices)
        and result_array.degraded == 0
        and result_array.sync_action == "idle"
        and actual_members == expected_members
        and result_array.array_state in allowed_states
    )
    if not verified:
        detail = f" {verify_error}" if verify_error else ""
        return MDRaidActionResponse(
            success=False,
            action="assemble",
            array_path=target.array_path,
            raid_level=target.raid_level,
            device_paths=[device.path for device in target.devices],
            read_only=target.read_only,
            sync_action=result_array.sync_action if result_array else None,
            user_confirmed=True,
            message=f"mdadm returned success, but the assembled array state could not be verified; inspect storage before retrying.{detail}",
        )
    mode = "read-only" if target.read_only else "read-write"
    return MDRaidActionResponse(
        success=True,
        action="assemble",
        array_path=target.array_path,
        raid_level=target.raid_level,
        device_paths=[device.path for device in target.devices],
        read_only=target.read_only,
        sync_action=result_array.sync_action if result_array else None,
        user_confirmed=True,
        message=f"Assembled the complete, clean MD array in {mode} mode. No force, scan, metadata update, or degraded start was requested.",
    )


def _perform_md_check(target: MDRaidTarget) -> MDRaidActionResponse:
    array = target.array
    if array is None:
        return MDRaidActionResponse(
            success=False,
            action="check",
            array_path=target.array_path,
            raid_level=target.raid_level,
            user_confirmed=True,
            message="The exact MD array state is unavailable; no check was requested.",
        )
    current, error = _read_md_array(target.array_path)
    if (
        error
        or current is None
        or _array_material(current) != _array_material(array)
        or current.level not in {"raid1", "raid4", "raid5", "raid6", "raid10"}
        or current.array_state not in {"active", "clean", "active-idle"}
        or current.sync_action != "idle"
        or current.degraded != 0
    ):
        return MDRaidActionResponse(
            success=False,
            action="check",
            array_path=target.array_path,
            raid_level=target.raid_level,
            user_confirmed=True,
            message=error or "The array changed or is no longer healthy and idle; no check was requested.",
        )
    sync_path, expected_identity, error = _md_sync_action_path(current)
    if error or sync_path is None or expected_identity is None:
        return MDRaidActionResponse(
            success=False,
            action="check",
            array_path=target.array_path,
            raid_level=target.raid_level,
            user_confirmed=True,
            message=error or "The exact MD sync_action attribute could not be verified.",
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            sync_path,
            os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != expected_identity:
            raise OSError("The MD sync_action attribute changed before writing.")
        written = os.write(descriptor, b"check\n")
        if written != len(b"check\n"):
            raise OSError("The MD check request was not fully written.")
    except OSError as exc:
        return MDRaidActionResponse(
            success=False,
            action="check",
            array_path=target.array_path,
            raid_level=target.raid_level,
            user_confirmed=True,
            message=f"The MD check request could not be written with current permissions: {exc.strerror or str(exc) or type(exc).__name__}.",
        )
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    resulting, verify_error = _read_md_array(target.array_path)
    if (
        resulting is None
        or (resulting.major, resulting.minor) != (array.major, array.minor)
        or resulting.sync_action not in {"check", "idle"}
    ):
        detail = f" {verify_error}" if verify_error else ""
        return MDRaidActionResponse(
            success=False,
            action="check",
            array_path=target.array_path,
            raid_level=target.raid_level,
            user_confirmed=True,
            message=f"The check request was written, but post-action state is ambiguous; inspect the array before retrying.{detail}",
        )
    return MDRaidActionResponse(
        success=True,
        action="check",
        array_path=target.array_path,
        raid_level=target.raid_level,
        sync_action=resulting.sync_action,
        mismatch_count=resulting.mismatch_count,
        user_confirmed=True,
        message=(
            "Started the MD consistency check. It reads every array block, runs in the background, and may already have finished; "
            "mismatches are recorded but not corrected. Read errors can still trigger MD's normal member recovery writes."
        ),
    )


def _perform_md_stop(target: MDRaidTarget) -> MDRaidActionResponse:
    array = target.array
    array_device = target.array_device
    if array is None or array_device is None:
        return MDRaidActionResponse(
            success=False,
            action="stop",
            array_path=target.array_path,
            raid_level=target.raid_level,
            user_confirmed=True,
            message="The exact MD array and block-device state are unavailable; no stop was requested.",
        )

    current, error = _read_md_array(target.array_path)
    current_device, device_error = _resolve_block_device(target.array_path)
    if (
        error
        or current is None
        or _array_material(current) != _array_material(array)
        or device_error
        or current_device is None
        or _device_material(current_device) != _device_material(array_device)
        or current.array_state not in {"active", "clean", "active-idle"}
        or current.sync_action != "idle"
        or current_device.mounted
        or current_device.swapped
        or current_device.has_holders
        or current_device.read_only
    ):
        detail = error or device_error
        return MDRaidActionResponse(
            success=False,
            action="stop",
            array_path=target.array_path,
            raid_level=target.raid_level,
            user_confirmed=True,
            message=detail or "The array changed, became busy, or is no longer idle; no stop was requested.",
        )

    mdadm = find_session_binary("mdadm", _environment())
    if not mdadm:
        return MDRaidActionResponse(
            success=False,
            action="stop",
            array_path=target.array_path,
            raid_level=target.raid_level,
            user_confirmed=True,
            message="The mdadm command is unavailable; no stop was requested.",
        )

    descriptor: int | None = None
    try:
        descriptor = os.open(
            array_device.path,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        info = os.fstat(descriptor)
        if not stat.S_ISBLK(info.st_mode) or (os.major(info.st_rdev), os.minor(info.st_rdev)) != (array_device.major, array_device.minor):
            raise OSError("The MD array block-device identity changed before stopping.")
        device_argument = f"/proc/self/fd/{descriptor}"
        if not _run_mutation([mdadm, "--stop", device_argument], (descriptor,)):
            return MDRaidActionResponse(
                success=False,
                action="stop",
                array_path=target.array_path,
                raid_level=target.raid_level,
                user_confirmed=True,
                message="mdadm did not stop the array successfully; inspect array and member state before retrying.",
            )
    except OSError as exc:
        return MDRaidActionResponse(
            success=False,
            action="stop",
            array_path=target.array_path,
            raid_level=target.raid_level,
            user_confirmed=True,
            message=f"The MD array device could not be opened or stopped with current permissions: {exc.strerror or str(exc) or type(exc).__name__}.",
        )
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    if (SYS_CLASS_BLOCK / array.name).exists():
        return MDRaidActionResponse(
            success=False,
            action="stop",
            array_path=target.array_path,
            raid_level=target.raid_level,
            user_confirmed=True,
            message="mdadm returned success, but the exact MD array remains active; inspect state before retrying.",
        )
    return MDRaidActionResponse(
        success=True,
        action="stop",
        array_path=target.array_path,
        raid_level=target.raid_level,
        user_confirmed=True,
        message="Stopped the idle MD array. Member data and RAID metadata remain on the member devices; the array is unavailable until assembled again.",
    )


def perform_md_raid_action(
    action: MDRaidAction,
    array_path: str,
    device_paths: list[str],
    raid_level: str | None = None,
    chunk_size_kib: int | None = None,
    read_only: bool = True,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> MDRaidActionResponse:
    target, phrase, error = md_raid_action_confirmation_details(action, array_path, device_paths, raid_level, chunk_size_kib, read_only)
    if error or target is None or phrase is None:
        return MDRaidActionResponse(
            success=False,
            action=action,
            array_path=array_path,
            raid_level=raid_level,
            device_paths=device_paths if isinstance(device_paths, list) else [],
            read_only=read_only if action == "assemble" and isinstance(read_only, bool) else None,
            user_confirmed=confirmed is True,
            message=error or "The MD RAID request could not be verified.",
        )
    if confirmed is not True:
        return MDRaidActionResponse(
            success=False,
            action=action,
            array_path=target.array_path,
            raid_level=target.raid_level,
            device_paths=[device.path for device in target.devices],
            read_only=target.read_only if action == "assemble" else None,
            user_confirmed=False,
            message="Explicit client confirmation is required; no mdadm command was run.",
        )
    if confirmation_phrase != phrase:
        return MDRaidActionResponse(
            success=False,
            action=action,
            array_path=target.array_path,
            raid_level=target.raid_level,
            device_paths=[device.path for device in target.devices],
            read_only=target.read_only if action == "assemble" else None,
            user_confirmed=True,
            message="Confirmation did not match the exact array, block-device identities, and current storage state.",
        )
    current, current_phrase, error = md_raid_action_confirmation_details(action, array_path, device_paths, raid_level, chunk_size_kib, read_only)
    if error or current is None or current_phrase != phrase:
        return MDRaidActionResponse(
            success=False,
            action=action,
            array_path=target.array_path,
            raid_level=target.raid_level,
            device_paths=[device.path for device in target.devices],
            read_only=target.read_only if action == "assemble" else None,
            user_confirmed=True,
            message=error or "Storage state changed after confirmation; no mdadm command was run.",
        )

    if action == "check":
        return _perform_md_check(target)
    if action == "stop":
        return _perform_md_stop(target)
    if action == "assemble":
        return _perform_md_assemble(target)

    opened: list[int] = []
    try:
        fd_paths: list[str] = []
        for device in target.devices:
            descriptor = os.open(
                device.path,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            )
            opened.append(descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISBLK(info.st_mode) or (os.major(info.st_rdev), os.minor(info.st_rdev)) != (device.major, device.minor):
                return MDRaidActionResponse(
                    success=False,
                    action=action,
                    array_path=target.array_path,
                    raid_level=target.raid_level,
                    device_paths=[item.path for item in target.devices],
                    user_confirmed=True,
                    message="A member-device identity changed while opening it; no mdadm command was run.",
                )
            fd_paths.append(f"/proc/self/fd/{descriptor}")
        mdadm = find_session_binary("mdadm", _environment())
        if not mdadm:
            return MDRaidActionResponse(success=False, action=action, array_path=target.array_path, raid_level=target.raid_level, device_paths=[item.path for item in target.devices], user_confirmed=True, message="The mdadm command is unavailable.")
        if action == "create":
            command = [mdadm, "--create", target.array_path, "--metadata=1.2", f"--level={target.raid_level}", f"--raid-devices={target.raid_devices}"]
            if target.chunk_size_kib is not None:
                command.append(f"--chunk={target.chunk_size_kib}")
            command.extend(fd_paths)
        elif action == "add_spare":
            command = [mdadm, target.array_path, "--add-spare", fd_paths[0]]
        elif action == "mark_faulty":
            command = [mdadm, target.array_path, "--fail", fd_paths[0]]
        elif action == "remove_faulty":
            command = [mdadm, target.array_path, "--remove", fd_paths[0]]
        elif action == "replace_member":
            spare_command = [mdadm, target.array_path, "--add-spare", fd_paths[1]]
            if not _run_mutation(spare_command, tuple(opened)):
                return MDRaidActionResponse(
                    success=False,
                    action=action,
                    array_path=target.array_path,
                    raid_level=target.raid_level,
                    device_paths=[item.path for item in target.devices],
                    user_confirmed=True,
                    message="The replacement disk could not be added as a spare; inspect array state before retrying.",
                )
            prepared_array, _prepare_error = _read_md_array(target.array_path)
            old_member = target.devices[0]
            replacement = target.devices[1]
            prepared_old = next(
                (
                    member for member in prepared_array.members
                    if (member.major, member.minor) == (old_member.major, old_member.minor)
                ),
                None,
            ) if prepared_array else None
            if (
                not prepared_array
                or prepared_array.degraded != 0
                or prepared_array.sync_action != "idle"
                or prepared_old is None
                or "in_sync" not in prepared_old.state
                or {"spare", "faulty", "blocked"} & set(prepared_old.state)
                or not any(
                (member.major, member.minor) == (replacement.major, replacement.minor) and "spare" in member.state
                for member in prepared_array.members
                )
            ):
                return MDRaidActionResponse(
                    success=False,
                    action=action,
                    array_path=target.array_path,
                    raid_level=target.raid_level,
                    device_paths=[item.path for item in target.devices],
                    user_confirmed=True,
                    message="The replacement disk was added as a spare, but array health or member state changed; inspect the array before retrying. The replacement remains a spare.",
                )
            command = [mdadm, target.array_path, "--replace", fd_paths[0], "--with", fd_paths[1]]
        else:
            command = [mdadm, target.array_path, "--remove", fd_paths[0]]
        if not _run_mutation(command, tuple(opened)):
            return MDRaidActionResponse(
                success=False,
                action=action,
                array_path=target.array_path,
                raid_level=target.raid_level,
                device_paths=[item.path for item in target.devices],
                user_confirmed=True,
                message="mdadm did not complete successfully; inspect array and member state before retrying.",
            )
    except OSError:
        return MDRaidActionResponse(
            success=False,
            action=action,
            array_path=target.array_path,
            raid_level=target.raid_level,
            device_paths=[item.path for item in target.devices],
            user_confirmed=True,
            message="A block device could not be opened with current permissions; no elevation was requested.",
        )
    finally:
        for descriptor in opened:
            try:
                os.close(descriptor)
            except OSError:
                pass

    if action == "create":
        result_array, verify_error = _read_md_array(target.array_path)
        verified = bool(
            result_array
            and result_array.level == target.raid_level
            and result_array.raid_devices == target.raid_devices
            and {(member.major, member.minor) for member in result_array.members}
            == {(device.major, device.minor) for device in target.devices}
        )
    else:
        result_array, verify_error = _read_md_array(target.array_path)
        if not result_array:
            verified = False
        elif action == "add_spare":
            added = target.devices[0]
            verified = any(
                (member.major, member.minor) == (added.major, added.minor) and "spare" in member.state
                for member in result_array.members
            )
        elif action == "remove_spare":
            removed = target.devices[0]
            verified = all((member.major, member.minor) != (removed.major, removed.minor) for member in result_array.members)
        elif action == "mark_faulty":
            failed = target.devices[0]
            failed_member = next(
                (
                    member for member in result_array.members
                    if (member.major, member.minor) == (failed.major, failed.minor)
                ),
                None,
            )
            verified = bool(
                failed_member
                and "faulty" in failed_member.state
                and "in_sync" not in failed_member.state
                and result_array.sync_action in {"idle", "recover", "resync"}
            )
        elif action == "remove_faulty":
            removed = target.devices[0]
            verified = all(
                (member.major, member.minor) != (removed.major, removed.minor)
                for member in result_array.members
            )
        else:
            replaced, replacement = target.devices
            replacement_member = next(
                (
                    member for member in result_array.members
                    if (member.major, member.minor) == (replacement.major, replacement.minor)
                ),
                None,
            )
            verified = bool(
                replacement_member
                and (
                    "in_sync" in replacement_member.state
                    or result_array.sync_action in {"recover", "resync"}
                )
                and result_array.degraded == 0
            )
    if not verified:
        suffix = f" {verify_error}" if verify_error else ""
        return MDRaidActionResponse(
            success=False,
            action=action,
            array_path=target.array_path,
            raid_level=target.raid_level,
            device_paths=[item.path for item in target.devices],
            user_confirmed=True,
            message=f"mdadm returned success, but the resulting array state could not be verified; inspect storage before retrying.{suffix}",
        )
    messages = {
        "create": "Created the MD RAID array. Initialization or resync may continue in the background; no boot-time assembly configuration was changed.",
        "add_spare": "Added the verified blank device as an MD spare. No existing member was marked faulty or removed.",
        "remove_spare": "Removed the exact inactive spare from the MD array. Its on-device RAID metadata was not erased.",
        "mark_faulty": "Marked the exact active MD member faulty. The array may be degraded, and a configured spare may begin recovery; inspect array health and replace the member as appropriate.",
        "remove_faulty": "Removed the exact already-faulty member from the running MD array. This does not restore redundancy or erase the member's on-device RAID metadata.",
        "replace_member": "Started replacement of the exact in-sync member using the verified spare. Recovery may continue in the background; the old member remains in service until replacement recovery completes.",
    }
    return MDRaidActionResponse(
        success=True,
        action=action,
        array_path=target.array_path,
        raid_level=target.raid_level,
        device_paths=[item.path for item in target.devices],
        user_confirmed=True,
        message=messages[action],
    )
