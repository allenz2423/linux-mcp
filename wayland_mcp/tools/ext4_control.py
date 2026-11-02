"""Confirmation-gated ext4 creation, growth, and offline shrinking."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import Ext4FilesystemActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env

Ext4FilesystemAction = Literal["create", "grow", "shrink"]
SYS_DEV_BLOCK = Path("/sys/dev/block")
SYS_CLASS_BLOCK = Path("/sys/class/block")
MOUNTINFO = Path("/proc/self/mountinfo")
SWAPS = Path("/proc/swaps")
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
MAX_DEVICE_SIZE_BYTES = 1 << 60
COMMAND_TIMEOUT_SECONDS = 90
SHRINK_TIMEOUT_SECONDS = 60 * 60
BLOCK_COUNT_RE = re.compile(r"(?m)^Block count:\s*([0-9]+)\s*$")
BLOCK_SIZE_RE = re.compile(r"(?m)^Block size:\s*([0-9]+)\s*$")


@dataclass(frozen=True, slots=True)
class Ext4Target:
    action: Ext4FilesystemAction
    device_path: str
    target_size_bytes: int | None
    device_major: int
    device_minor: int
    device_size_bytes: int
    block_count: int | None
    block_size_bytes: int | None
    filesystem_uuid: str | None
    mounted: bool
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def ext4_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    return all(
        find_session_binary(binary, selected)
        for binary in ("wipefs", "blkid", "dumpe2fs", "mkfs.ext4", "resize2fs")
    )


def _run(
    command: list[str],
    *,
    input_data: bytes | None = None,
    pass_fds: tuple[int, ...] = (),
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> tuple[int, str] | None:
    options = {"input": input_data} if input_data is not None else {"stdin": subprocess.DEVNULL}
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env=_environment(),
            close_fds=True,
            pass_fds=pass_fds,
            **options,
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
        holders = device / "holders"
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


def _signature_types(device_path: str) -> tuple[str, ...] | None:
    binary = find_session_binary("wipefs", _environment())
    if not binary:
        return None
    result = _run([binary, "--no-act", "--noheadings", "--output", "TYPE", device_path])
    if result is None or result[0] != 0:
        return None
    return tuple(sorted(line.strip() for line in result[1].splitlines() if line.strip()))


def _filesystem_state(device_path: str) -> tuple[int, int, str | None] | None:
    blkid = find_session_binary("blkid", _environment())
    dumpe2fs = find_session_binary("dumpe2fs", _environment())
    if not blkid or not dumpe2fs:
        return None
    type_result = _run([blkid, "-p", "-s", "TYPE", "-o", "value", device_path])
    uuid_result = _run([blkid, "-p", "-s", "UUID", "-o", "value", device_path])
    header_result = _run([dumpe2fs, "-h", device_path])
    if (
        type_result is None or type_result[0] != 0 or type_result[1].strip() != "ext4"
        or uuid_result is None or uuid_result[0] != 0
        or header_result is None or header_result[0] != 0
    ):
        return None
    block_count_match = BLOCK_COUNT_RE.search(header_result[1])
    block_size_match = BLOCK_SIZE_RE.search(header_result[1])
    if not block_count_match or not block_size_match:
        return None
    try:
        block_count = int(block_count_match.group(1), 10)
        block_size = int(block_size_match.group(1), 10)
    except ValueError:
        return None
    if not 0 < block_count <= (1 << 48) or block_size not in {1024, 2048, 4096, 8192, 16384, 32768, 65536}:
        return None
    fs_uuid = uuid_result[1].strip()
    if fs_uuid and not re.fullmatch(r"[0-9a-fA-F-]{16,64}", fs_uuid):
        return None
    return block_count, block_size, fs_uuid or None


def ext4_action_confirmation_details(
    action: str,
    device_path: str,
    target_size_bytes: int | None = None,
) -> tuple[Ext4Target | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "ext4 block-device administration is available only on Linux."
    if not isinstance(action, str) or action not in {"create", "grow", "shrink"}:
        return None, None, "action must be create, grow, or shrink."
    if action == "shrink":
        if type(target_size_bytes) is not int or not 0 < target_size_bytes <= MAX_DEVICE_SIZE_BYTES:
            return None, None, "shrink requires target_size_bytes as a positive byte count."
    elif target_size_bytes is not None:
        return None, None, "target_size_bytes is used only when shrinking ext4."
    if not all(find_session_binary(name, _environment()) for name in ("wipefs", "blkid", "dumpe2fs", "mkfs.ext4", "resize2fs")):
        return None, None, "The util-linux wipefs/blkid and e2fsprogs ext4 utilities are required."
    if action == "shrink" and not find_session_binary("e2fsck", _environment()):
        return None, None, "The e2fsck utility is required for offline ext4 shrinking."
    resolved, info, error = _resolve_device(device_path)
    if error or resolved is None or info is None:
        return None, None, error or "The block-device identity could not be verified."
    size_bytes, readonly, has_holders = _device_state(info)
    if size_bytes is None or readonly is None or has_holders is None:
        return None, None, "The block-device capacity, read-only state, or holder relationships could not be verified."
    if readonly:
        return None, None, "The block device is read-only."
    mounted, swapped = _usage_state(info)
    if mounted is None or swapped is None:
        return None, None, "Mounted and swap usage could not be checked safely."

    block_count: int | None = None
    block_size: int | None = None
    fs_uuid: str | None = None
    signatures: tuple[str, ...]
    if action == "create":
        signatures = _signature_types(str(resolved))
        partitions = _has_child_partitions(info)
        if signatures is None:
            return None, None, "The device's existing signatures could not be read safely."
        if signatures:
            return None, None, "ext4 creation is refused because recognized filesystem, RAID, or partition signatures exist."
        if mounted or swapped:
            return None, None, "ext4 creation is refused on a mounted or active swap device."
        if has_holders:
            return None, None, "ext4 creation is refused while another device-mapper layer holds this block device."
        if partitions is not False:
            return None, None, "ext4 creation is refused when child partitions exist or partition state cannot be read."
    else:
        state = _filesystem_state(str(resolved))
        if state is None:
            return None, None, "The requested block device is not a readable ext4 filesystem."
        block_count, block_size, fs_uuid = state
        current_bytes = block_count * block_size
        if action == "grow":
            if current_bytes >= size_bytes:
                return None, None, "The ext4 filesystem has no verified growth available on the block device."
        else:
            if mounted or swapped:
                return None, None, "ext4 shrinking is refused while the filesystem is mounted in this namespace or active as swap."
            if has_holders:
                return None, None, "ext4 shrinking is refused while another device-mapper layer holds this block device."
            assert target_size_bytes is not None
            if target_size_bytes >= current_bytes:
                return None, None, "The requested ext4 size must be smaller than the current filesystem size."
            if target_size_bytes % block_size:
                return None, None, f"target_size_bytes must be aligned to the ext4 block size of {block_size} bytes."
        signatures = ()

    details = {
        "action": action,
        "device_path": str(resolved),
        "target_size_bytes": target_size_bytes,
        "device_major": os.major(info.st_rdev),
        "device_minor": os.minor(info.st_rdev),
        "device_size_bytes": size_bytes,
        "block_count": block_count,
        "block_size_bytes": block_size,
        "filesystem_uuid": fs_uuid,
        "mounted": mounted,
        "swapped": swapped,
        "signatures": signatures,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = Ext4Target(
        action=action,  # type: ignore[arg-type]
        device_path=str(resolved),
        target_size_bytes=target_size_bytes,
        device_major=os.major(info.st_rdev),
        device_minor=os.minor(info.st_rdev),
        device_size_bytes=size_bytes,
        block_count=block_count,
        block_size_bytes=block_size,
        filesystem_uuid=fs_uuid,
        mounted=mounted,
        state_digest=digest,
    )
    phrase = hashlib.sha256((action + ":" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"ext4 {phrase}", None


def perform_ext4_action(
    action: Ext4FilesystemAction,
    device_path: str,
    *,
    confirmed: bool,
    target_size_bytes: int | None = None,
    confirmation_phrase: str | None = None,
) -> Ext4FilesystemActionResponse:
    target, phrase, error = ext4_action_confirmation_details(action, device_path, target_size_bytes)
    if error or target is None or phrase is None:
        return Ext4FilesystemActionResponse(success=False, action=action, device_path=device_path, target_size_bytes=target_size_bytes, user_confirmed=confirmed is True, message=error or "The ext4 request could not be verified.")
    if confirmed is not True:
        return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, user_confirmed=False, message="Explicit client confirmation is required; no filesystem command was run.")
    if confirmation_phrase != phrase:
        return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, user_confirmed=True, message="Confirmation did not match the exact block-device identity and current filesystem state.")
    current, current_phrase, error = ext4_action_confirmation_details(action, device_path, target_size_bytes)
    if error or current is None or current_phrase != phrase:
        return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, user_confirmed=True, message=error or "Storage state changed after confirmation; no filesystem command was run.")

    descriptor = -1
    try:
        descriptor = os.open(target.device_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        opened = os.fstat(descriptor)
        if not stat.S_ISBLK(opened.st_mode) or (os.major(opened.st_rdev), os.minor(opened.st_rdev)) != (target.device_major, target.device_minor):
            return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, user_confirmed=True, message="The opened block-device identity changed after confirmation; no filesystem command was run.")
        argument = f"/proc/self/fd/{descriptor}"
        if action == "shrink":
            if _filesystem_state(argument) != (target.block_count, target.block_size_bytes, target.filesystem_uuid):
                return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, user_confirmed=True, message="The ext4 filesystem changed before its offline consistency check; no resize was run.")
            e2fsck = find_session_binary("e2fsck", _environment())
            if not e2fsck or not _check_ext4_clean(e2fsck, argument, descriptor):
                return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, user_confirmed=True, message="The offline read-only e2fsck check did not confirm a clean filesystem; no resize was run. Inspect or repair it offline, then request a new confirmation.")
            current, current_phrase, error = ext4_action_confirmation_details(action, device_path, target_size_bytes)
            if error or current is None or current_phrase != phrase:
                return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, user_confirmed=True, message=error or "Storage state changed during the offline check; no resize was run.")
        if action == "create":
            binary = find_session_binary("mkfs.ext4", _environment())
            command = [binary, "-F", "-q", argument] if binary else []
            timeout = COMMAND_TIMEOUT_SECONDS
        elif action == "shrink":
            binary = find_session_binary("resize2fs", _environment())
            assert target.block_size_bytes is not None and target_size_bytes is not None
            target_blocks = target_size_bytes // target.block_size_bytes
            command = [binary, argument, str(target_blocks)] if binary else []
            timeout = SHRINK_TIMEOUT_SECONDS
        else:
            binary = find_session_binary("resize2fs", _environment())
            command = [binary, argument] if binary else []
            timeout = COMMAND_TIMEOUT_SECONDS
        if not command:
            return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, user_confirmed=True, message="The required ext4 utility is unavailable.")
        result = _run_mutation(command, descriptor, timeout=timeout)
        if not result:
            return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, user_confirmed=True, message="The ext4 command did not complete successfully; inspect the filesystem before retrying.")
        state = _filesystem_state(argument)
        if state is None:
            return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, user_confirmed=True, message="The ext4 utility returned successfully, but the resulting filesystem could not be verified; inspect storage before retrying.")
        result_blocks, result_block_size, result_uuid = state
        result_bytes = result_blocks * result_block_size
        if action == "create":
            verified = result_bytes <= target.device_size_bytes
        elif action == "grow":
            verified = (
                target.block_count is not None
                and target.block_size_bytes == result_block_size
                and result_bytes > target.block_count * target.block_size_bytes
                and result_uuid == target.filesystem_uuid
            )
        else:
            verified = (
                target.block_size_bytes == result_block_size
                and result_bytes == target_size_bytes
                and result_uuid == target.filesystem_uuid
            )
        if not verified:
            return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, filesystem_size_bytes=result_bytes, user_confirmed=True, message="The ext4 command returned, but the resulting filesystem size or identity did not match the requested action.")
        if action == "shrink":
            e2fsck = find_session_binary("e2fsck", _environment())
            if not e2fsck or not _check_ext4_clean(e2fsck, argument, descriptor):
                return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, filesystem_size_bytes=result_bytes, user_confirmed=True, message="The filesystem was resized to the requested size, but the post-resize read-only e2fsck check did not confirm it is clean; inspect or repair it offline before use.")
    except OSError:
        return Ext4FilesystemActionResponse(success=False, action=action, device_path=target.device_path, user_confirmed=True, message="The block device could not be opened with current permissions; no elevation was requested.")
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    message = {
        "create": "Created and verified the ext4 filesystem.",
        "grow": "Grew and verified the ext4 filesystem.",
        "shrink": "Shrank the offline ext4 filesystem to the exact requested size and verified it clean.",
    }[action]
    return Ext4FilesystemActionResponse(success=True, action=action, device_path=target.device_path, target_size_bytes=target_size_bytes, filesystem_size_bytes=result_bytes, user_confirmed=True, message=message)


def _check_ext4_clean(e2fsck: str, device_argument: str, device_fd: int) -> bool:
    result = _run(
        [e2fsck, "-f", "-n", device_argument],
        pass_fds=(device_fd,),
        timeout=SHRINK_TIMEOUT_SECONDS,
    )
    return result is not None and result[0] == 0


def _run_mutation(command: list[str], device_fd: int, *, timeout: int = COMMAND_TIMEOUT_SECONDS) -> bool:
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
            pass_fds=(device_fd,),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0
