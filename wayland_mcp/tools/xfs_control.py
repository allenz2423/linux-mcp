"""Confirmation-gated XFS creation and mounted-filesystem growth."""

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

from wayland_mcp.models import XFSFilesystemActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env

XFSFilesystemAction = Literal["create", "grow"]
SYS_DEV_BLOCK = Path("/sys/dev/block")
SYS_CLASS_BLOCK = Path("/sys/class/block")
MOUNTINFO = Path("/proc/self/mountinfo")
SWAPS = Path("/proc/swaps")
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
MAX_DEVICE_SIZE_BYTES = 1 << 60
COMMAND_TIMEOUT_SECONDS = 120
XFS_GEOMETRY_RE = re.compile(r"(?m)^\s*data\s*=\s*(?:\S+\s+)?bsize=([0-9]+)\s+blocks=([0-9]+)(?:,|\s|$)")
XFS_REALTIME_RE = re.compile(r"(?m)^\s*realtime\s*=\s*(\S+).*?\bblocks=([0-9]+)(?:,|\s|$)")
XFS_UUID_RE = re.compile(r"^[0-9a-fA-F-]{16,64}$")
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class XFSTarget:
    action: XFSFilesystemAction
    device_path: str
    device_major: int
    device_minor: int
    device_size_bytes: int
    block_count: int | None
    block_size_bytes: int | None
    filesystem_uuid: str | None
    mounted: bool
    mountpoint: str | None
    mount_read_only: bool | None
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def xfs_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    return all(
        find_session_binary(binary, selected)
        for binary in ("wipefs", "blkid", "mkfs.xfs", "xfs_info", "xfs_growfs")
    )


def _run(command: list[str], *, timeout: int = COMMAND_TIMEOUT_SECONDS) -> tuple[int, str] | None:
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


def _resolve_device(value: object) -> tuple[Path | None, os.stat_result | None, str | None]:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096:
        return None, None, "device_path must be one absolute path to a block device under /dev."
    try:
        path = Path(value).resolve(strict=True)
        path.relative_to(Path("/dev"))
        info = path.stat()
    except (OSError, RuntimeError, ValueError):
        return None, None, "device_path must resolve to an existing block device under /dev."
    if not stat.S_ISBLK(info.st_mode):
        return None, None, "device_path must resolve to a block device."
    return path, info, None


def _device_state(info: os.stat_result) -> tuple[int | None, bool | None, bool | None]:
    device = SYS_DEV_BLOCK / f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    try:
        sectors = int((device / "size").read_text(encoding="ascii").strip(), 10)
        readonly_raw = (device / "ro").read_text(encoding="ascii").strip()
        if sectors <= 0 or sectors > (MAX_DEVICE_SIZE_BYTES // 512) or readonly_raw not in {"0", "1"}:
            return None, None, None
        has_holders = any((device / "holders").iterdir())
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


def _usage_state(info: os.stat_result) -> tuple[bool | None, bool | None]:
    expected = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    try:
        with MOUNTINFO.open("rb") as stream:
            mount_data = stream.read(4 * 1024 * 1024 + 1)
        if len(mount_data) > 4 * 1024 * 1024:
            return None, None
        mounted = any(
            len(fields := line.split()) >= 3 and fields[2] == expected
            for line in mount_data.decode("utf-8", errors="strict").splitlines()
        )
        with SWAPS.open("rb") as stream:
            swap_data = stream.read(1024 * 1024 + 1)
        if len(swap_data) > 1024 * 1024:
            return None, None
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


def _decode_mount_field(value: str) -> str | None:
    result: list[str] = []
    index = 0
    allowed = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    while index < len(value):
        if value[index] != "\\":
            result.append(value[index])
            index += 1
            continue
        octal = value[index + 1:index + 4]
        replacement = allowed.get(octal)
        if replacement is None:
            return None
        result.append(replacement)
        index += 4
    decoded = "".join(result)
    return decoded if decoded.startswith("/") and "\x00" not in decoded and len(decoded) <= 4096 else None


def _xfs_mountpoint(info: os.stat_result) -> tuple[str | None, bool | None, str | None]:
    expected = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    try:
        with MOUNTINFO.open("rb") as stream:
            data = stream.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            return None, None, "The mount table exceeded its safety limit."
        text = data.decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None, None, "The current mount table could not be read safely."

    matches: list[tuple[str, bool]] = []
    for line in text.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if len(fields) <= separator + 2 or len(fields) < 6 or fields[2] != expected:
            continue
        if fields[separator + 1] != "xfs":
            continue
        mountpoint = _decode_mount_field(fields[4])
        if mountpoint is None:
            return None, None, "The XFS mountpoint has an unsupported or malformed encoding."
        mount_options = set(fields[5].split(","))
        matches.append((mountpoint, "ro" in mount_options))
    unique = sorted(set(matches))
    if len(unique) != 1:
        if not unique:
            return None, None, "The XFS filesystem must be mounted in the current namespace before it can be grown."
        return None, None, "The exact XFS device has multiple current-namespace mountpoints; growth is ambiguous and was refused."
    mountpoint, read_only = unique[0]
    try:
        mount_info = Path(mountpoint).stat()
    except OSError:
        return None, None, "The exact XFS mountpoint could not be verified."
    if not stat.S_ISDIR(mount_info.st_mode) or (os.major(mount_info.st_dev), os.minor(mount_info.st_dev)) != (
        os.major(info.st_rdev), os.minor(info.st_rdev)
    ):
        return None, None, "The XFS mountpoint no longer identifies the requested block device."
    return mountpoint, read_only, None


def _signature_types(device_path: str) -> tuple[str, ...] | None:
    binary = find_session_binary("wipefs", _environment())
    if not binary:
        return None
    result = _run([binary, "--no-act", "--noheadings", "--output", "TYPE", device_path])
    if result is None or result[0] != 0:
        return None
    return tuple(sorted(line.strip() for line in result[1].splitlines() if line.strip()))


def _filesystem_state(
    device_path: str,
    info_target: str,
) -> tuple[int, int, str | None] | None:
    blkid = find_session_binary("blkid", _environment())
    xfs_info = find_session_binary("xfs_info", _environment())
    if not blkid or not xfs_info:
        return None
    type_result = _run([blkid, "-p", "-s", "TYPE", "-o", "value", device_path])
    uuid_result = _run([blkid, "-p", "-s", "UUID", "-o", "value", device_path])
    info_result = _run([xfs_info, info_target])
    realtime = XFS_REALTIME_RE.search(info_result[1]) if info_result is not None else None
    if (
        type_result is None or type_result[0] != 0 or type_result[1].strip() != "xfs"
        or uuid_result is None or uuid_result[0] != 0
        or info_result is None or info_result[0] != 0
        or realtime is None
    ):
        return None
    try:
        realtime_blocks = int(realtime.group(2), 10)
    except ValueError:
        return None
    if realtime_blocks:
        return None
    geometry = XFS_GEOMETRY_RE.search(info_result[1])
    if not geometry:
        return None
    try:
        block_size = int(geometry.group(1), 10)
        block_count = int(geometry.group(2), 10)
    except ValueError:
        return None
    if not 0 < block_count <= (1 << 52) or block_size not in {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}:
        return None
    fs_uuid = uuid_result[1].strip()
    if fs_uuid and not XFS_UUID_RE.fullmatch(fs_uuid):
        return None
    return block_count, block_size, fs_uuid or None


def xfs_action_confirmation_details(
    action: str,
    device_path: str,
) -> tuple[XFSTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "XFS block-device administration is available only on Linux."
    if not isinstance(action, str) or action not in {"create", "grow"}:
        return None, None, "action must be create or grow."
    required = ("wipefs", "blkid", "mkfs.xfs", "xfs_info", "xfs_growfs")
    if not all(find_session_binary(name, _environment()) for name in required):
        return None, None, "The util-linux wipefs/blkid and xfsprogs utilities are required."
    resolved, info, error = _resolve_device(device_path)
    if error or resolved is None or info is None:
        return None, None, error or "The block-device identity could not be verified."
    size_bytes, readonly, has_holders = _device_state(info)
    if size_bytes is None or readonly is None or has_holders is None:
        return None, None, "The block-device capacity, read-only state, or holder relationships could not be verified."
    if readonly:
        return None, None, "The block device is read-only."
    if has_holders:
        return None, None, "XFS administration is refused while another block-device layer holds this device."
    mounted, swapped = _usage_state(info)
    if mounted is None or swapped is None:
        return None, None, "Mounted and swap usage could not be checked safely."
    if swapped:
        return None, None, "XFS administration is refused while the block device is in active swap use."

    block_count: int | None = None
    block_size: int | None = None
    fs_uuid: str | None = None
    mountpoint: str | None = None
    mount_read_only: bool | None = None
    if action == "create":
        signatures = _signature_types(str(resolved))
        partitions = _has_child_partitions(info)
        if signatures is None:
            return None, None, "The device's existing signatures could not be read safely."
        if signatures:
            return None, None, "XFS creation is refused because recognized filesystem, RAID, or partition signatures exist."
        if mounted:
            return None, None, "XFS creation is refused on a mounted block device."
        if partitions is not False:
            return None, None, "XFS creation is refused when child partitions exist or partition state cannot be read."
    else:
        mountpoint, mount_read_only, mount_error = _xfs_mountpoint(info)
        if mount_error or mountpoint is None or mount_read_only is None:
            return None, None, mount_error or "The mounted XFS filesystem could not be verified."
        if mount_read_only:
            return None, None, "XFS growth is refused on a read-only mount."
        state = _filesystem_state(str(resolved), mountpoint)
        if state is None:
            return None, None, "The requested block device is not a readable XFS filesystem with supported geometry."
        block_count, block_size, fs_uuid = state
        if block_count * block_size >= size_bytes:
            return None, None, "The XFS filesystem has no verified growth available on the block device."
        signatures = ()

    details = {
        "action": action,
        "device_path": str(resolved),
        "device_major": os.major(info.st_rdev),
        "device_minor": os.minor(info.st_rdev),
        "device_size_bytes": size_bytes,
        "block_count": block_count,
        "block_size_bytes": block_size,
        "filesystem_uuid": fs_uuid,
        "mounted": mounted,
        "mountpoint": mountpoint,
        "mount_read_only": mount_read_only,
        "swapped": swapped,
        "signatures": signatures,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = XFSTarget(
        action=action,  # type: ignore[arg-type]
        device_path=str(resolved),
        device_major=os.major(info.st_rdev),
        device_minor=os.minor(info.st_rdev),
        device_size_bytes=size_bytes,
        block_count=block_count,
        block_size_bytes=block_size,
        filesystem_uuid=fs_uuid,
        mounted=mounted,
        mountpoint=mountpoint,
        mount_read_only=mount_read_only,
        state_digest=digest,
    )
    phrase = hashlib.sha256((action + ":" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"xfs {phrase}", None


def perform_xfs_action(
    action: XFSFilesystemAction,
    device_path: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> XFSFilesystemActionResponse:
    target, phrase, error = xfs_action_confirmation_details(action, device_path)
    if error or target is None or phrase is None:
        return XFSFilesystemActionResponse(
            success=False,
            action=action,
            device_path=device_path,
            user_confirmed=confirmed is True,
            message=error or "The XFS request could not be verified.",
        )
    if confirmed is not True:
        return XFSFilesystemActionResponse(
            success=False,
            action=action,
            device_path=target.device_path,
            user_confirmed=False,
            message="Explicit client confirmation is required; no filesystem command was run.",
        )
    if confirmation_phrase != phrase:
        return XFSFilesystemActionResponse(
            success=False,
            action=action,
            device_path=target.device_path,
            user_confirmed=True,
            message="Confirmation did not match the exact block-device identity and current filesystem state.",
        )

    with _ACTION_LOCK:
        current, current_phrase, error = xfs_action_confirmation_details(action, device_path)
        if error or current is None or current_phrase != phrase:
            return XFSFilesystemActionResponse(
                success=False,
                action=action,
                device_path=target.device_path,
                user_confirmed=True,
                message=error or "Storage state changed after confirmation; no filesystem command was run.",
            )
        descriptor = -1
        try:
            open_flags = os.O_RDONLY if action == "grow" else os.O_RDWR
            descriptor = os.open(
                current.device_path,
                open_flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            )
            opened = os.fstat(descriptor)
            if not stat.S_ISBLK(opened.st_mode) or (
                os.major(opened.st_rdev), os.minor(opened.st_rdev)
            ) != (current.device_major, current.device_minor):
                return XFSFilesystemActionResponse(
                    success=False,
                    action=action,
                    device_path=current.device_path,
                    user_confirmed=True,
                    message="The opened block-device identity changed after confirmation; no filesystem command was run.",
                )
            if action == "create":
                open_size, open_readonly, open_holders = _device_state(opened)
                open_mounted, open_swapped = _usage_state(opened)
                open_signatures = _signature_types(current.device_path)
                open_partitions = _has_child_partitions(opened)
                if (
                    open_size != current.device_size_bytes
                    or open_readonly is not False
                    or open_holders is not False
                    or open_mounted is not False
                    or open_swapped is not False
                    or open_signatures != ()
                    or open_partitions is not False
                ):
                    return XFSFilesystemActionResponse(
                        success=False,
                        action=action,
                        device_path=current.device_path,
                        user_confirmed=True,
                        message="The blank-device state changed immediately before formatting; no XFS command was run.",
                    )
                binary = find_session_binary("mkfs.xfs", _environment())
                command = [binary, "-q", f"/proc/self/fd/{descriptor}"] if binary else []
                run_ok = _run_mutation(command, descriptor) if command else False
            else:
                open_mountpoint, open_readonly, mount_error = _xfs_mountpoint(opened)
                open_state = (
                    _filesystem_state(current.device_path, open_mountpoint)
                    if open_mountpoint is not None and not mount_error
                    else None
                )
                if (
                    open_mountpoint != current.mountpoint
                    or open_readonly is not False
                    or open_state != (current.block_count, current.block_size_bytes, current.filesystem_uuid)
                ):
                    return XFSFilesystemActionResponse(
                        success=False,
                        action=action,
                        device_path=current.device_path,
                        user_confirmed=True,
                        message="The mounted XFS filesystem changed immediately before growth; no xfs_growfs command was run.",
                    )
                binary = find_session_binary("xfs_growfs", _environment())
                command = [binary, "-d", current.mountpoint] if binary and current.mountpoint else []
                run_ok = _run_mutation(command) if command else False
            if not command:
                return XFSFilesystemActionResponse(
                    success=False,
                    action=action,
                    device_path=current.device_path,
                    user_confirmed=True,
                    message="The required XFS utility or verified mountpoint is unavailable.",
                )
            if not run_ok:
                return XFSFilesystemActionResponse(
                    success=False,
                    action=action,
                    device_path=current.device_path,
                    user_confirmed=True,
                    message="The XFS command did not complete successfully; inspect the filesystem before retrying.",
                )
        except OSError:
            return XFSFilesystemActionResponse(
                success=False,
                action=action,
                device_path=current.device_path,
                user_confirmed=True,
                message="The block device could not be opened with current permissions; no elevation was requested.",
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    if action == "create":
        state = _filesystem_state(current.device_path, current.device_path)
    else:
        try:
            current_info = os.stat(current.device_path)
        except OSError:
            current_info = None
        if current_info is not None:
            latest, _, mount_error = _xfs_mountpoint(current_info)
            state = _filesystem_state(current.device_path, latest) if latest and not mount_error else None
        else:
            state = None
    if state is None:
        return XFSFilesystemActionResponse(
            success=False,
            action=action,
            device_path=current.device_path,
            user_confirmed=True,
            message="The XFS utility returned successfully, but the resulting filesystem could not be verified; inspect storage before retrying.",
        )
    result_blocks, result_block_size, result_uuid = state
    result_bytes = result_blocks * result_block_size
    if action == "create":
        verified = result_uuid is not None and result_bytes <= current.device_size_bytes
    else:
        verified = (
            current.block_count is not None
            and current.block_size_bytes is not None
            and result_bytes > current.block_count * current.block_size_bytes
            and (current.filesystem_uuid is None or result_uuid == current.filesystem_uuid)
        )
    if not verified:
        return XFSFilesystemActionResponse(
            success=False,
            action=action,
            device_path=current.device_path,
            user_confirmed=True,
            filesystem_size_bytes=result_bytes,
            message="The XFS command returned, but the resulting filesystem size did not match the requested action.",
        )
    message = "Created and verified the XFS filesystem." if action == "create" else "Grew and verified the XFS filesystem."
    return XFSFilesystemActionResponse(
        success=True,
        action=action,
        device_path=current.device_path,
        filesystem_size_bytes=result_bytes,
        user_confirmed=True,
        message=message,
    )


def _run_mutation(command: list[str], device_fd: int | None = None) -> bool:
    options = {"pass_fds": (device_fd,)} if device_fd is not None else {}
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
            **options,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0
