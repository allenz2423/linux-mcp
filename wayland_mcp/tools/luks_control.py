"""Confirmation-gated LUKS1/LUKS2 mapping, format, and header operations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import LUKSActionResponse, LUKSHeaderActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env

LUKSAction = Literal["format", "open", "close", "resize", "add_key", "remove_key"]
LUKSVersion = Literal["luks1", "luks2"]
LUKSHeaderAction = Literal["backup", "restore"]
MAPPING_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]{0,126}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEADER_BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,255}$")
MAX_KEY_FILE_BYTES = 1024 * 1024
MAX_HEADER_BACKUP_BYTES = 128 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 90
SYS_DEV_BLOCK = Path("/sys/dev/block")
SYS_CLASS_BLOCK = Path("/sys/class/block")
MOUNTINFO = Path("/proc/self/mountinfo")
SWAPS = Path("/proc/swaps")


@dataclass(frozen=True, slots=True)
class LUKSTarget:
    action: LUKSAction
    luks_version: LUKSVersion
    device_path: str
    device_major: int
    device_minor: int
    device_size_bytes: int
    mapping_name: str | None
    key_file_digest: str | None
    luks_uuid: str | None
    mapping_size_sectors: int | None
    mapping_offset_sectors: int | None
    key_slot: int | None
    new_key_file: str | None
    new_key_file_digest: str | None
    active_keyslots: tuple[int, ...]
    keyslot_tokens: tuple[tuple[int, tuple[int, ...]], ...]
    state_digest: str


@dataclass(frozen=True, slots=True)
class LUKSHeaderTarget:
    action: LUKSHeaderAction
    device_path: str
    device_major: int
    device_minor: int
    device_size_bytes: int
    luks_version: LUKSVersion
    luks_uuid: str
    backup_file: str
    backup_parent_identity: tuple[int, int]
    backup_file_identity: tuple[int, int] | None
    backup_file_size_bytes: int | None
    backup_file_digest: str | None
    header_keyslots: tuple[int, ...]
    header_tokens: tuple[tuple[int, tuple[int, ...]], ...]
    current_header_present: bool
    current_keyslots: tuple[int, ...]
    current_tokens: tuple[tuple[int, tuple[int, ...]], ...]
    signatures: tuple[str, ...] | None
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def luks_control_available(env: dict[str, str] | None = None) -> bool:
    return sys.platform.startswith("linux") and all(
        find_session_binary(binary, env or _environment())
        for binary in ("cryptsetup", "wipefs")
    )


def _run_readonly(
    command: list[str],
    *,
    limit: int = MAX_COMMAND_OUTPUT_BYTES,
    pass_fds: tuple[int, ...] = (),
) -> tuple[int, str] | None:
    env = _environment()
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=env,
            close_fds=True,
            pass_fds=pass_fds,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if len(completed.stdout) > limit:
        return None
    try:
        return completed.returncode, completed.stdout.decode("utf-8", errors="strict")
    except UnicodeError:
        return None


def _run_mutation(
    command: list[str],
    key_data: bytes | None,
    *,
    device_fd: int,
    extra_fds: tuple[int, ...] = (),
    umask: int | None = None,
) -> bool:
    env = _environment()
    input_options = {"input": key_data} if key_data is not None else {"stdin": subprocess.DEVNULL}
    process_options = {"umask": umask} if umask is not None else {}
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=env,
            close_fds=True,
            pass_fds=(device_fd, *extra_fds),
            **input_options,
            **process_options,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _resolve_block_device(device_path: object) -> tuple[Path | None, os.stat_result | None, str | None]:
    if not isinstance(device_path, str) or not device_path.startswith("/") or len(device_path) > 4096:
        return None, None, "device_path must be one absolute path to a block device under /dev."
    supplied = Path(device_path)
    try:
        resolved = supplied.resolve(strict=True)
        resolved.relative_to(Path("/dev"))
        info = resolved.stat()
    except (OSError, ValueError, RuntimeError):
        return None, None, "device_path must resolve to an existing block device under /dev."
    if not stat.S_ISBLK(info.st_mode):
        return None, None, "device_path must resolve to a block device."
    return resolved, info, None


def _device_size_bytes(info: os.stat_result) -> int | None:
    major = os.major(info.st_rdev)
    minor = os.minor(info.st_rdev)
    try:
        text = (SYS_DEV_BLOCK / f"{major}:{minor}" / "size").read_text(encoding="ascii").strip()
        sectors = int(text, 10)
    except (OSError, UnicodeError, ValueError):
        return None
    if sectors <= 0 or sectors > (1 << 54):
        return None
    return sectors * 512


def _device_readonly(info: os.stat_result) -> bool | None:
    major = os.major(info.st_rdev)
    minor = os.minor(info.st_rdev)
    try:
        value = (SYS_DEV_BLOCK / f"{major}:{minor}" / "ro").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return None
    return value == "1" if value in {"0", "1"} else None


def _device_has_relations(info: os.stat_result) -> bool | None:
    major = os.major(info.st_rdev)
    minor = os.minor(info.st_rdev)
    base = SYS_DEV_BLOCK / f"{major}:{minor}"
    for relation in ("holders", "slaves"):
        try:
            if any((base / relation).iterdir()):
                return True
        except FileNotFoundError:
            return None
        except OSError:
            return None
    return False


def _has_child_partitions(info: os.stat_result) -> bool | None:
    major = os.major(info.st_rdev)
    minor = os.minor(info.st_rdev)
    try:
        target = (SYS_DEV_BLOCK / f"{major}:{minor}").resolve(strict=True)
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


def _is_mounted_or_swap(info: os.stat_result) -> bool | None:
    wanted = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    try:
        with MOUNTINFO.open("rb") as stream:
            mount_data = stream.read(4 * 1024 * 1024 + 1)
        if len(mount_data) > 4 * 1024 * 1024:
            return None
        for line in mount_data.decode("utf-8", errors="strict").splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[2] == wanted:
                return True
        with SWAPS.open("rb") as stream:
            swap_data = stream.read(1024 * 1024 + 1)
        if len(swap_data) > 1024 * 1024:
            return None
        for line in swap_data.decode("utf-8", errors="strict").splitlines()[1:]:
            source = line.split()[0] if line.split() else ""
            if not source.startswith("/"):
                continue
            try:
                source_info = Path(source).stat()
            except OSError:
                continue
            if stat.S_ISBLK(source_info.st_mode) and source_info.st_rdev == info.st_rdev:
                return True
    except (OSError, UnicodeError):
        return None
    return False


def _key_file_identity(key_file: object) -> tuple[str | None, str | None]:
    if not isinstance(key_file, str) or not key_file.startswith("/") or len(key_file) > 4096:
        return None, "key_file must be one absolute path to a private regular file."
    supplied = Path(key_file)
    try:
        resolved = supplied.resolve(strict=True)
        if resolved != supplied:
            return None, "key_file may not contain symlink components."
        descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, RuntimeError):
        return None, "key_file must be readable without following symlinks."
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or not 1 <= info.st_size <= MAX_KEY_FILE_BYTES
    ):
        return None, "key_file must be a single-link regular file owned by the server identity, mode 0600 or stricter, and at most 1 MiB."
    identity = {
        "path": str(resolved),
        "device": info.st_dev,
        "inode": info.st_ino,
        "size": info.st_size,
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), None


def _read_key_file(key_file: str, expected_digest: str) -> bytes | None:
    identity, error = _key_file_identity(key_file)
    if error or identity != expected_digest:
        return None
    try:
        resolved = Path(key_file)
        descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            data = bytearray()
            while len(data) <= MAX_KEY_FILE_BYTES:
                chunk = os.read(descriptor, min(65536, MAX_KEY_FILE_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        return None
    stable_fields_before = (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_uid, before.st_mtime_ns, before.st_ctime_ns)
    stable_fields_after = (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_uid, after.st_mtime_ns, after.st_ctime_ns)
    if len(data) > MAX_KEY_FILE_BYTES or stable_fields_before != stable_fields_after:
        return None
    current_digest, error = _key_file_identity(key_file)
    if error or current_digest != expected_digest:
        return None
    return bytes(data)


def _anonymous_key_file(data: bytes) -> int | None:
    create = getattr(os, "memfd_create", None)
    if create is None:
        return None
    descriptor = -1
    try:
        descriptor = create("linux-mcp-luks-key", getattr(os, "MFD_CLOEXEC", 0))
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short write to anonymous key file")
            offset += written
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        return None


def _wipefs_signatures(device_path: str, *, pass_fds: tuple[int, ...] = ()) -> tuple[str, ...] | None:
    binary = find_session_binary("wipefs", _environment())
    if not binary:
        return None
    result = _run_readonly(
        [binary, "--no-act", "--noheadings", "--output", "TYPE", device_path],
        pass_fds=pass_fds,
    )
    if result is None or result[0] != 0:
        return None
    return tuple(sorted(line.strip() for line in result[1].splitlines() if line.strip()))


def _luks_uuid(device_path: str, luks_version: LUKSVersion) -> str | None:
    binary = find_session_binary("cryptsetup", _environment())
    if not binary:
        return None
    is_luks = _run_readonly([binary, "isLuks", "--type", luks_version, device_path])
    if is_luks is None or is_luks[0] != 0:
        return None
    result = _run_readonly([binary, "luksUUID", device_path])
    if result is None or result[0] != 0:
        return None
    value = result[1].strip()
    return value if UUID_RE.fullmatch(value) else None


def _active_luks2_header_state(
    device_path: str,
) -> tuple[tuple[int, ...], tuple[tuple[int, tuple[int, ...]], ...]] | None:
    cryptsetup = find_session_binary("cryptsetup", _environment())
    if not cryptsetup:
        return None
    result = _run_readonly([cryptsetup, "luksDump", "--type", "luks2", "--dump-json-metadata", device_path])
    if result is None or result[0] != 0:
        return None
    try:
        metadata = json.loads(result[1])
    except (json.JSONDecodeError, UnicodeError):
        return None
    slots = metadata.get("keyslots") if isinstance(metadata, dict) else None
    tokens = metadata.get("tokens") if isinstance(metadata, dict) else None
    if not isinstance(slots, dict) or not isinstance(tokens, dict):
        return None
    identifiers: list[int] = []
    for identifier, record in slots.items():
        if not isinstance(identifier, str) or not identifier.isdecimal() or not isinstance(record, dict):
            return None
        identifiers.append(int(identifier, 10))
    if len(set(identifiers)) != len(identifiers):
        return None

    token_bindings: list[tuple[int, tuple[int, ...]]] = []
    seen_token_ids: set[int] = set()
    for token_identifier, record in tokens.items():
        if not isinstance(token_identifier, str) or not token_identifier.isdecimal() or not isinstance(record, dict):
            return None
        token_id = int(token_identifier, 10)
        if token_id in seen_token_ids:
            return None
        seen_token_ids.add(token_id)
        bound_slots = record.get("keyslots", [])
        if not isinstance(bound_slots, list):
            return None
        normalized_slots: list[int] = []
        for slot in bound_slots:
            if not isinstance(slot, str) or not slot.isdecimal():
                return None
            slot_number = int(slot, 10)
            if slot_number > 31:
                return None
            normalized_slots.append(slot_number)
        if len(set(normalized_slots)) != len(normalized_slots):
            return None
        token_bindings.append((token_id, tuple(sorted(normalized_slots))))
    return tuple(sorted(identifiers)), tuple(sorted(token_bindings))


def _active_keyslots(device_path: str, luks_version: LUKSVersion) -> tuple[int, ...] | None:
    cryptsetup = find_session_binary("cryptsetup", _environment())
    if not cryptsetup:
        return None
    if luks_version == "luks2":
        state = _active_luks2_header_state(device_path)
        return state[0] if state is not None else None

    result = _run_readonly([cryptsetup, "luksDump", "--type", "luks1", device_path])
    if result is None or result[0] != 0:
        return None
    found: dict[int, bool] = {}
    for match in re.finditer(r"(?m)^\s*Key Slot\s+(\d+):\s*(ENABLED|DISABLED)\s*$", result[1], re.IGNORECASE):
        identifier = int(match.group(1), 10)
        if identifier in found or identifier > 7:
            return None
        found[identifier] = match.group(2).upper() == "ENABLED"
    if len(found) != 8:
        return None
    return tuple(identifier for identifier, enabled in sorted(found.items()) if enabled)


def _status_sectors(text: str, field: str) -> int | None:
    match = re.search(
        rf"(?m)^\s*{re.escape(field)}:\s*(\d+)\s*(sectors|\[512-byte units\])"
        r"(?:\s+\((\d+)\s+\[bytes\]\))?\s*$",
        text,
    )
    if not match:
        return None
    units = int(match.group(1), 10)
    if match.group(3) is not None:
        byte_count = int(match.group(3), 10)
        if byte_count % 512 or byte_count // 512 != units:
            return None
    return units


def _mapping_status(mapping_name: str) -> tuple[LUKSVersion, str, int, int] | None:
    binary = find_session_binary("cryptsetup", _environment())
    if not binary:
        return None
    result = _run_readonly([binary, "status", mapping_name])
    if result is None or result[0] != 0:
        return None
    text = result[1]
    type_match = re.search(r"(?m)^\s*type:\s*(LUKS1|LUKS2)\s*$", text)
    if not type_match:
        return None
    luks_version: LUKSVersion = "luks1" if type_match.group(1) == "LUKS1" else "luks2"
    source_match = re.search(r"(?m)^\s*device:\s*(\S+)\s*$", text)
    size_sectors = _status_sectors(text, "size")
    offset_sectors = _status_sectors(text, "offset")
    if not source_match or size_sectors is None or offset_sectors is None:
        return None
    try:
        source, info, error = _resolve_block_device(source_match.group(1))
        if error or source is None or info is None:
            return None
    except (OSError, ValueError):
        return None
    return luks_version, f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}", size_sectors, offset_sectors


def luks_action_confirmation_details(
    action: str,
    device_path: str,
    mapping_name: str | None = None,
    key_file: str | None = None,
    luks_version: LUKSVersion = "luks2",
    new_key_file: str | None = None,
    key_slot: int | None = None,
) -> tuple[LUKSTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "LUKS administration is available only on Linux."
    if not isinstance(action, str) or action not in {"format", "open", "close", "resize", "add_key", "remove_key"}:
        return None, None, "action must be format, open, close, resize, add_key, or remove_key."
    if not isinstance(luks_version, str) or luks_version not in {"luks1", "luks2"}:
        return None, None, "luks_version must be luks1 or luks2."
    selected_luks_version: LUKSVersion = "luks1" if luks_version == "luks1" else "luks2"
    needs_mapping = action in {"open", "close", "resize"}
    if needs_mapping:
        if not isinstance(mapping_name, str) or not MAPPING_NAME_RE.fullmatch(mapping_name) or mapping_name in {".", ".."}:
            return None, None, "mapping_name must be one exact simple device-mapper name."
    elif mapping_name is not None:
        return None, None, "mapping_name is used only for open, close, or resize."
    needs_key = action in {"format", "open", "add_key", "remove_key"}
    may_use_key = needs_key or action == "resize"
    key_digest: str | None = None
    if needs_key:
        key_digest, error = _key_file_identity(key_file)
        if error or key_digest is None:
            return None, None, error or "A private key file is required."
    elif may_use_key and key_file is not None:
        key_digest, error = _key_file_identity(key_file)
        if error or key_digest is None:
            return None, None, error or "The optional private key file could not be verified."
    elif not may_use_key and key_file is not None:
        return None, None, "key_file is used only for format, open, resize, add_key, or remove_key."
    new_key_digest: str | None = None
    if action == "add_key":
        new_key_digest, error = _key_file_identity(new_key_file)
        if error or new_key_digest is None:
            return None, None, error or "A separate private new-key file is required for add_key."
        if new_key_digest == key_digest:
            return None, None, "The existing unlock key and new key must use different private files."
    elif new_key_file is not None:
        return None, None, "new_key_file is accepted only for add_key."
    if action == "remove_key":
        if isinstance(key_slot, bool) or not isinstance(key_slot, int) or not 0 <= key_slot <= 31:
            return None, None, "key_slot must be an integer from 0 through 31 for remove_key."
    elif key_slot is not None:
        return None, None, "key_slot is accepted only for remove_key."
    if not luks_control_available():
        return None, None, "The cryptsetup and util-linux wipefs commands are required."

    resolved, info, error = _resolve_block_device(device_path)
    if error or resolved is None or info is None:
        return None, None, error or "The block device could not be verified."
    readonly = _device_readonly(info)
    if readonly is None:
        return None, None, "The block device read-only state could not be verified."
    if readonly:
        return None, None, "The block device is read-only."
    size_bytes = _device_size_bytes(info)
    if size_bytes is None:
        return None, None, "The block device size could not be verified in sysfs."

    luks_uuid: str | None = None
    mapping_size: int | None = None
    mapping_offset: int | None = None
    active_keyslots: tuple[int, ...] = ()
    keyslot_tokens: tuple[tuple[int, tuple[int, ...]], ...] = ()
    signatures: tuple[str, ...] | None = None
    if action == "format":
        in_use = _is_mounted_or_swap(info)
        relations = _device_has_relations(info)
        partitions = _has_child_partitions(info)
        signatures = _wipefs_signatures(str(resolved))
        if in_use is not False:
            return None, None, "Formatting is refused unless the device is verified as unused and unmounted."
        if relations is not False:
            return None, None, "Formatting is refused when the block device has holders or backing-device relations."
        if partitions is not False:
            return None, None, "Formatting is refused when the device has child partitions or partition state cannot be read."
        if signatures is None:
            return None, None, "Existing block-device signatures could not be read safely."
        if signatures:
            return None, None, "Formatting is refused because the device contains recognized filesystem, RAID, or partition signatures."
        # isLuks also catches LUKS headers that a util-linux build does not
        # classify in its current signature inventory.
        cryptsetup = find_session_binary("cryptsetup", _environment())
        if not cryptsetup:
            return None, None, "The device's LUKS state could not be verified as blank."
        for version in ("luks1", "luks2"):
            check = _run_readonly([cryptsetup, "isLuks", "--type", version, str(resolved)])
            if check is None or check[0] != 1:
                return None, None, "The device's LUKS state could not be verified as blank."
    else:
        luks_uuid = _luks_uuid(str(resolved), selected_luks_version)
        if luks_uuid is None:
            return None, None, f"The exact device is not a verified {selected_luks_version.upper()} device."
    if action in {"add_key", "remove_key"}:
        if selected_luks_version == "luks2":
            header_state = _active_luks2_header_state(str(resolved))
            slots = header_state[0] if header_state is not None else None
            keyslot_tokens = header_state[1] if header_state is not None else ()
        else:
            slots = _active_keyslots(str(resolved), selected_luks_version)
        if slots is None:
            return None, None, "The active LUKS keyslot inventory could not be read completely."
        slot_capacity = 8 if selected_luks_version == "luks1" else 32
        if any(slot < 0 or slot >= slot_capacity for slot in slots):
            return None, None, "The LUKS keyslot inventory contains an unsupported slot number."
        if not slots:
            return None, None, "The LUKS device has no active keyslot; key management is refused."
        active_keyslots = slots
        if action == "add_key" and len(slots) >= slot_capacity:
            return None, None, "No free LUKS keyslot is available for adding a key."
        if action == "remove_key":
            if key_slot not in slots:
                return None, None, "The requested keyslot is not currently active on this LUKS device."
            if len(slots) <= 1:
                return None, None, "Removing the last active LUKS keyslot is refused."
            if any(key_slot in bound_slots for _token_id, bound_slots in keyslot_tokens):
                return None, None, "The selected LUKS2 keyslot is referenced by a token; use manage_luks_token to remove that token or unassign its keyslot binding first."

    if action == "open":
        mapper_path = Path("/dev/mapper") / str(mapping_name)
        status = _mapping_status(str(mapping_name))
        if mapper_path.exists() or status is not None:
            return None, None, "The requested device-mapper name is already active."
        # A failed status query is expected for an inactive name; command
        # availability is checked separately and no raw diagnostics escape.
    elif action in {"close", "resize"}:
        status = _mapping_status(str(mapping_name))
        if status is None:
            return None, None, "The exact LUKS mapping is not active or its backing device could not be verified."
        device_id = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
        if status[0] != selected_luks_version or status[1] != device_id:
            return None, None, "The active mapping is not the requested LUKS version backed by the exact requested block device."
        mapping_size, mapping_offset = status[2], status[3]
        if action == "resize":
            available_sectors = size_bytes // 512 - mapping_offset
            if available_sectors <= mapping_size:
                return None, None, "The active mapping has no verified growth available on the requested device."

    details = {
        "action": action,
        "luks_version": selected_luks_version,
        "device_path": str(resolved),
        "device_major": os.major(info.st_rdev),
        "device_minor": os.minor(info.st_rdev),
        "device_size_bytes": size_bytes,
        "mapping_name": mapping_name,
        "key_file_digest": key_digest,
        "luks_uuid": luks_uuid,
        "mapping_size_sectors": mapping_size,
        "mapping_offset_sectors": mapping_offset,
        "key_slot": key_slot,
        "new_key_file": new_key_file,
        "new_key_file_digest": new_key_digest,
        "active_keyslots": active_keyslots,
        "keyslot_tokens": keyslot_tokens,
        "signatures": signatures,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = LUKSTarget(
        action=action,  # type: ignore[arg-type]
        luks_version=selected_luks_version,
        device_path=str(resolved),
        device_major=os.major(info.st_rdev),
        device_minor=os.minor(info.st_rdev),
        device_size_bytes=size_bytes,
        mapping_name=mapping_name,
        key_file_digest=key_digest,
        luks_uuid=luks_uuid,
        mapping_size_sectors=mapping_size,
        mapping_offset_sectors=mapping_offset,
        key_slot=key_slot,
        new_key_file=new_key_file,
        new_key_file_digest=new_key_digest,
        active_keyslots=active_keyslots,
        keyslot_tokens=keyslot_tokens,
        state_digest=digest,
    )
    phrase_hash = hashlib.sha256((action + ":" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"LUKS {phrase_hash}", None


def perform_luks_action(
    action: LUKSAction,
    device_path: str,
    mapping_name: str | None = None,
    key_file: str | None = None,
    luks_version: LUKSVersion = "luks2",
    new_key_file: str | None = None,
    key_slot: int | None = None,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> LUKSActionResponse:
    target, phrase, error = luks_action_confirmation_details(
        action, device_path, mapping_name, key_file, luks_version, new_key_file, key_slot
    )
    if error or target is None or phrase is None:
        return LUKSActionResponse(success=False, action=action, device_path=device_path, mapping_name=mapping_name, user_confirmed=confirmed is True, message=error or "The LUKS request could not be verified.")
    if confirmed is not True:
        return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=False, message="Explicit client confirmation is required; no LUKS command was run.")
    if confirmation_phrase != phrase:
        return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, key_slot=key_slot, user_confirmed=True, message="Confirmation did not match the exact device, mapping, key-file identity, keyslot selection, and current storage state.")

    current, current_phrase, error = luks_action_confirmation_details(
        action, device_path, mapping_name, key_file, luks_version, new_key_file, key_slot
    )
    if error or current is None or current_phrase != phrase:
        return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=True, message=error or "Storage state changed after confirmation; no LUKS command was run.")
    key_data: bytes | None = None
    if target.key_file_digest is not None:
        key_data = _read_key_file(key_file or "", target.key_file_digest)
        if key_data is None:
            return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=True, message="The private key file changed after confirmation; no LUKS command was run.")
    new_key_data: bytes | None = None
    new_key_fd = -1
    if target.new_key_file_digest is not None:
        new_key_data = _read_key_file(new_key_file or "", target.new_key_file_digest)
        if new_key_data is None:
            return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=True, message="The private new-key file changed after confirmation; no LUKS command was run.")
        if key_data == new_key_data:
            return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=True, message="The new key is identical to the existing unlock key; no LUKS command was run.")
        prepared_key_fd = _anonymous_key_file(new_key_data)
        if prepared_key_fd is None:
            return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=True, message="An anonymous in-memory key file could not be prepared; no LUKS command was run.")
        new_key_fd = prepared_key_fd

    descriptor = -1
    try:
        descriptor = os.open(target.device_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        current_info = os.fstat(descriptor)
        if (
            not stat.S_ISBLK(current_info.st_mode)
            or os.major(current_info.st_rdev) != target.device_major
            or os.minor(current_info.st_rdev) != target.device_minor
        ):
            return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=True, message="The opened block device identity changed after confirmation; no command was run.")
        device_argument = f"/proc/self/fd/{descriptor}"
        cryptsetup = find_session_binary("cryptsetup", _environment())
        if not cryptsetup:
            return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=True, message="The cryptsetup command is unavailable.")
        if action == "format":
            command = [cryptsetup, "luksFormat", "--type", target.luks_version, "--batch-mode", "--key-file", "-", device_argument]
        elif action == "open":
            command = [cryptsetup, "open", "--type", target.luks_version, "--key-file", "-", device_argument, str(mapping_name)]
        elif action == "close":
            command = [cryptsetup, "close", str(mapping_name)]
        elif action == "add_key":
            command = [
                cryptsetup,
                "luksAddKey",
                "--type",
                target.luks_version,
                "--key-file",
                "-",
                device_argument,
                f"/proc/self/fd/{new_key_fd}",
            ]
        elif action == "remove_key":
            command = [
                cryptsetup,
                "luksKillSlot",
                "--type",
                target.luks_version,
                "--key-file",
                "-",
                device_argument,
                str(target.key_slot),
            ]
        else:
            command = [cryptsetup, "resize", "--type", target.luks_version]
            if key_data is not None:
                command.extend(["--key-file", "-"])
            command.append(str(mapping_name))
        extra_fds = (new_key_fd,) if new_key_fd >= 0 else ()
        if not _run_mutation(command, key_data, device_fd=descriptor, extra_fds=extra_fds):
            return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=True, message="cryptsetup did not complete successfully; inspect the current mapping and device state before retrying.")
    except OSError:
        return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=True, message="The block device could not be opened with current permissions; no elevation was requested.")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if new_key_fd >= 0:
            os.close(new_key_fd)

    verified = False
    result_size: int | None = None
    result_key_slot: int | None = target.key_slot
    result_keyslots: tuple[int, ...] = ()
    if action == "format":
        verified = _luks_uuid(target.device_path, target.luks_version) is not None
    elif action == "open":
        status = _mapping_status(str(mapping_name))
        verified = status is not None and status[0] == target.luks_version and status[1] == f"{target.device_major}:{target.device_minor}"
        if verified and status:
            result_size = status[2] * 512
    elif action == "close":
        mapper_path = Path("/dev/mapper") / str(mapping_name)
        verified = not mapper_path.exists() and _mapping_status(str(mapping_name)) is None
    elif action in {"add_key", "remove_key"}:
        slots = _active_keyslots(target.device_path, target.luks_version)
        if slots is not None:
            before_slots = set(target.active_keyslots)
            after_slots = set(slots)
            if action == "add_key":
                added_slots = after_slots - before_slots
                verified = before_slots.issubset(after_slots) and len(added_slots) == 1 and len(after_slots) == len(before_slots) + 1
                if verified:
                    result_key_slot = next(iter(added_slots))
            else:
                expected_slots = before_slots - {int(target.key_slot)}
                verified = after_slots == expected_slots
            result_keyslots = slots
    else:
        status = _mapping_status(str(mapping_name))
        verified = status is not None and status[0] == target.luks_version and status[1] == f"{target.device_major}:{target.device_minor}" and target.mapping_size_sectors is not None and status[2] > target.mapping_size_sectors
        if verified and status:
            result_size = status[2] * 512
    if not verified:
        return LUKSActionResponse(success=False, action=action, device_path=target.device_path, mapping_name=mapping_name, user_confirmed=True, message="cryptsetup returned successfully, but the resulting LUKS state could not be verified; inspect storage before retrying.")
    labels = {
        "format": f"Created and verified a {target.luks_version.upper()} header.",
        "open": f"Opened and verified the {target.luks_version.upper()} mapping.",
        "close": f"Closed and verified the {target.luks_version.upper()} mapping.",
        "resize": f"Grew and verified the active {target.luks_version.upper()} mapping.",
        "add_key": f"Added and verified a new {target.luks_version.upper()} keyslot.",
        "remove_key": f"Removed and verified {target.luks_version.upper()} keyslot {target.key_slot}.",
    }
    return LUKSActionResponse(
        success=True,
        action=action,
        device_path=target.device_path,
        mapping_name=mapping_name,
        mapped_size_bytes=result_size,
        key_slot=result_key_slot,
        active_keyslots=list(result_keyslots),
        user_confirmed=True,
        message=labels[action],
    )


def _safe_header_parent(backup_file: object) -> tuple[Path | None, str | None, tuple[int, int] | None, str | None]:
    if not isinstance(backup_file, str) or not backup_file.startswith("/") or len(backup_file) > 4096 or "\x00" in backup_file:
        return None, None, None, "backup_file must be one absolute path."
    supplied = Path(backup_file)
    name = supplied.name
    if not name or name in {".", ".."} or len(name.encode("utf-8", errors="ignore")) > 255:
        return None, None, None, "backup_file must end with one valid filename."
    parent_input = Path(os.path.abspath(str(supplied.parent)))
    try:
        parent = parent_input.resolve(strict=True)
        if parent != parent_input:
            return None, None, None, "The backup directory path may not contain symlink components."
        directory_fd = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except (OSError, RuntimeError):
        return None, None, None, "The backup directory must be an existing directory without symlink components."
    try:
        info = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
        ):
            return None, None, None, "The backup directory must be owned by the server identity and not writable by group or other users."
        return parent, name, (info.st_dev, info.st_ino), None
    finally:
        os.close(directory_fd)


def _fingerprint_header_fd(descriptor: int) -> tuple[dict[str, int | str] | None, str | None]:
    try:
        before = os.fstat(descriptor)
    except OSError:
        return None, "The LUKS header backup identity could not be read."
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or before.st_mode & 0o077
        or not 1 <= before.st_size <= MAX_HEADER_BACKUP_BYTES
    ):
        return None, f"The header backup must be a private single-link regular file owned by the server identity and no larger than {MAX_HEADER_BACKUP_BYTES} bytes."
    digest = hashlib.sha256()
    total = 0
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while total <= MAX_HEADER_BACKUP_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_HEADER_BACKUP_BYTES + 1 - total))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
    except OSError:
        return None, "The LUKS header backup could not be read consistently."
    stable_before = (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_uid, before.st_nlink, before.st_mtime_ns, before.st_ctime_ns)
    stable_after = (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_uid, after.st_nlink, after.st_mtime_ns, after.st_ctime_ns)
    if total != before.st_size or total > MAX_HEADER_BACKUP_BYTES or stable_before != stable_after:
        return None, "The LUKS header backup changed while it was being read or exceeds the size limit."
    return {
        "device": before.st_dev,
        "inode": before.st_ino,
        "size": before.st_size,
        "mode": stat.S_IMODE(before.st_mode),
        "uid": before.st_uid,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
        "sha256": digest.hexdigest(),
    }, None


def _secure_header_file(
    backup_file: str,
) -> tuple[Path | None, tuple[int, int] | None, dict[str, int | str] | None, str | None]:
    parent, name, parent_identity, error = _safe_header_parent(backup_file)
    if error or parent is None or name is None or parent_identity is None:
        return None, None, None, error or "The backup path could not be verified."
    directory_fd = -1
    descriptor = -1
    try:
        directory_fd = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        directory_info = os.fstat(directory_fd)
        if (directory_info.st_dev, directory_info.st_ino) != parent_identity:
            return None, None, None, "The backup directory identity changed."
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        info, error = _fingerprint_header_fd(descriptor)
        if error or info is None:
            return None, None, None, error or "The header backup could not be fingerprinted."
        path_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (path_info.st_dev, path_info.st_ino) != (info["device"], info["inode"]):
            return None, None, None, "The header backup path identity changed while it was being read."
        return parent / name, parent_identity, info, None
    except OSError:
        return None, None, None, "backup_file must be a readable private regular file without symlink components."
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            os.close(directory_fd)


def _probe_luks_header(
    device_path: str,
    header_file: str | None = None,
    *,
    pass_fds: tuple[int, ...] = (),
) -> tuple[LUKSVersion | None, str | None, str | None]:
    cryptsetup = find_session_binary("cryptsetup", _environment())
    if not cryptsetup:
        return None, None, "The cryptsetup command is unavailable."
    recognized: list[LUKSVersion] = []
    for version in ("luks1", "luks2"):
        command = [cryptsetup]
        if header_file is not None:
            command.extend(["--header", header_file])
        command.extend(["isLuks", "--type", version, device_path])
        result = _run_readonly(command, pass_fds=pass_fds)
        if result is None or result[0] not in {0, 1}:
            return None, None, "The LUKS header state could not be verified."
        if result[0] == 0:
            recognized.append(version)  # type: ignore[arg-type]
    if not recognized:
        return None, None, None
    if len(recognized) != 1:
        return None, None, "The device reports an ambiguous LUKS header version."
    version = recognized[0]
    command = [cryptsetup]
    if header_file is not None:
        command.extend(["--header", header_file])
    command.extend(["luksUUID", device_path])
    result = _run_readonly(command, pass_fds=pass_fds)
    if result is None or result[0] != 0:
        return None, None, "The LUKS UUID could not be read from the selected header."
    value = result[1].strip()
    if not UUID_RE.fullmatch(value):
        return None, None, "The selected LUKS header returned an invalid UUID."
    return version, value.lower(), None


def _header_key_state(
    luks_version: LUKSVersion,
    device_path: str,
    header_file: str | None = None,
    *,
    pass_fds: tuple[int, ...] = (),
) -> tuple[tuple[int, ...], tuple[tuple[int, tuple[int, ...]], ...]] | None:
    cryptsetup = find_session_binary("cryptsetup", _environment())
    if not cryptsetup:
        return None
    command = [cryptsetup]
    if header_file is not None:
        command.extend(["--header", header_file])
    command.extend(["luksDump", "--type", luks_version])
    if luks_version == "luks2":
        command.append("--dump-json-metadata")
    command.append(device_path)
    result = _run_readonly(command, pass_fds=pass_fds)
    if result is None or result[0] != 0:
        return None
    if luks_version == "luks1":
        found: dict[int, bool] = {}
        for match in re.finditer(r"(?m)^\s*Key Slot\s+(\d+):\s*(ENABLED|DISABLED)\s*$", result[1], re.IGNORECASE):
            identifier = int(match.group(1), 10)
            if identifier in found or identifier > 7:
                return None
            found[identifier] = match.group(2).upper() == "ENABLED"
        if len(found) != 8:
            return None
        return tuple(identifier for identifier, enabled in sorted(found.items()) if enabled), ()
    try:
        metadata = json.loads(result[1])
    except (json.JSONDecodeError, UnicodeError):
        return None
    slots = metadata.get("keyslots") if isinstance(metadata, dict) else None
    tokens = metadata.get("tokens") if isinstance(metadata, dict) else None
    if not isinstance(slots, dict) or not isinstance(tokens, dict):
        return None
    slot_ids: list[int] = []
    for identifier, record in slots.items():
        if not isinstance(identifier, str) or not identifier.isdecimal() or not isinstance(record, dict):
            return None
        slot_ids.append(int(identifier, 10))
    if len(set(slot_ids)) != len(slot_ids):
        return None
    token_bindings: list[tuple[int, tuple[int, ...]]] = []
    for identifier, record in tokens.items():
        if not isinstance(identifier, str) or not identifier.isdecimal() or not isinstance(record, dict):
            return None
        bound = record.get("keyslots", [])
        if not isinstance(bound, list):
            return None
        normalized: list[int] = []
        for slot in bound:
            if not isinstance(slot, str) or not slot.isdecimal() or int(slot, 10) > 31:
                return None
            normalized.append(int(slot, 10))
        if len(set(normalized)) != len(normalized):
            return None
        token_bindings.append((int(identifier, 10), tuple(sorted(normalized))))
    return tuple(sorted(slot_ids)), tuple(sorted(token_bindings))


def luks_header_action_confirmation_details(
    action: str,
    device_path: str,
    backup_file: str,
    expected_luks_uuid: str | None = None,
) -> tuple[LUKSHeaderTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "LUKS header administration is available only on Linux."
    if action not in {"backup", "restore"}:
        return None, None, "action must be backup or restore."
    if not luks_control_available():
        return None, None, "The cryptsetup and util-linux wipefs commands are required."
    if action == "backup" and expected_luks_uuid is not None:
        return None, None, "expected_luks_uuid is accepted only for restore."
    if action == "restore" and expected_luks_uuid is not None and (
        not isinstance(expected_luks_uuid, str)
        or not UUID_RE.fullmatch(expected_luks_uuid)
    ):
        return None, None, "expected_luks_uuid must be a valid UUID when supplied."

    resolved_device, info, error = _resolve_block_device(device_path)
    if error or resolved_device is None or info is None:
        return None, None, error or "The block device could not be verified."
    readonly = _device_readonly(info)
    if action == "restore" and readonly is not False:
        return None, None, "The block-device read-only state could not be verified as writable."
    if action == "backup" and readonly is None:
        return None, None, "The block-device read-only state could not be verified."
    size_bytes = _device_size_bytes(info)
    if size_bytes is None:
        return None, None, "The block-device size could not be verified in sysfs."

    parent, backup_name, parent_identity, error = _safe_header_parent(backup_file)
    if error or parent is None or backup_name is None or parent_identity is None:
        return None, None, error or "The backup-file directory could not be verified."
    resolved_backup = parent / backup_name
    if not HEADER_BACKUP_NAME_RE.fullmatch(backup_name):
        return None, None, "backup_file must end with a simple filename using letters, digits, dot, underscore, plus, or hyphen."

    target_version: LUKSVersion | None = None
    target_uuid: str | None = None
    target_keyslots: tuple[int, ...] = ()
    target_tokens: tuple[tuple[int, tuple[int, ...]], ...] = ()
    file_identity: tuple[int, int] | None = None
    file_size: int | None = None
    file_digest: str | None = None
    current_header_present = False
    current_keyslots: tuple[int, ...] = ()
    current_tokens: tuple[tuple[int, tuple[int, ...]], ...] = ()
    signatures: tuple[str, ...] | None = None

    if action == "backup":
        try:
            output_directory_fd = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError:
            return None, None, "The output backup directory could not be opened safely."
        try:
            output_directory_info = os.fstat(output_directory_fd)
            if (output_directory_info.st_dev, output_directory_info.st_ino) != parent_identity:
                return None, None, "The backup directory identity changed while checking the output path."
            try:
                os.stat(backup_name, dir_fd=output_directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError:
                return None, None, "The output backup path could not be checked safely."
            else:
                return None, None, "Refusing to overwrite an existing LUKS header backup."
        except OSError:
            return None, None, "The output backup path could not be checked safely."
        finally:
            os.close(output_directory_fd)
        target_version, target_uuid, error = _probe_luks_header(str(resolved_device))
        if error or target_version is None or target_uuid is None:
            return None, None, error or "The exact block device is not a verified LUKS1/LUKS2 device."
        key_state = _header_key_state(target_version, str(resolved_device))
        if key_state is None:
            return None, None, "The LUKS keyslot/token state could not be read completely."
        target_keyslots, target_tokens = key_state
    else:
        resolved_backup, parent_identity, file_state, error = _secure_header_file(backup_file)
        if error or resolved_backup is None or parent_identity is None or file_state is None:
            return None, None, error or "The LUKS header backup could not be verified."
        file_identity = (int(file_state["device"]), int(file_state["inode"]))
        file_size = int(file_state["size"])
        file_digest = str(file_state["sha256"])
        target_version, target_uuid, error = _probe_luks_header(str(resolved_device), str(resolved_backup))
        if error or target_version is None or target_uuid is None:
            return None, None, error or "The backup file does not contain a valid LUKS header for this block device."
        target_key_state = _header_key_state(target_version, str(resolved_device), str(resolved_backup))
        if target_key_state is None:
            return None, None, "The backup header keyslot/token state could not be read completely."
        target_keyslots, target_tokens = target_key_state

        current_version, current_uuid, error = _probe_luks_header(str(resolved_device))
        if error:
            return None, None, error
        current_header_present = current_version is not None
        if current_header_present:
            if current_version != target_version or current_uuid != target_uuid:
                return None, None, "The current device header is present but does not match the selected backup version and UUID."
            if expected_luks_uuid is not None and target_uuid.casefold() != expected_luks_uuid.casefold():
                return None, None, "The backup header UUID does not match expected_luks_uuid."
            current_state = _header_key_state(current_version, str(resolved_device))
            if current_state is None:
                return None, None, "The current LUKS keyslot/token state could not be read completely."
            current_keyslots, current_tokens = current_state
        elif expected_luks_uuid is None:
            return None, None, "Restoring onto a device without a readable current LUKS header requires expected_luks_uuid from a trusted prior inventory."
        elif target_uuid.casefold() != expected_luks_uuid.casefold():
            return None, None, "The backup header UUID does not match expected_luks_uuid."
        signatures = _wipefs_signatures(str(resolved_device))
        if signatures is None or any(signature.casefold() != "crypto_luks" for signature in signatures):
            return None, None, "Header restore is refused when signatures other than the selected LUKS header are present or cannot be read."
        if _is_mounted_or_swap(info) is not False:
            return None, None, "Header restore requires the exact block device to be verified as unmounted and not used as swap."
        if _device_has_relations(info) is not False:
            return None, None, "Header restore is refused while the block device has holders/backing relations or their state cannot be read."
        if _has_child_partitions(info) is not False:
            return None, None, "Header restore is refused for a whole device with child partitions or unreadable partition state."

    material = {
        "action": action,
        "device_path": str(resolved_device),
        "device_major": os.major(info.st_rdev),
        "device_minor": os.minor(info.st_rdev),
        "device_size_bytes": size_bytes,
        "luks_version": target_version,
        "luks_uuid": target_uuid,
        "backup_file": str(resolved_backup),
        "backup_parent_identity": parent_identity,
        "backup_file_identity": file_identity,
        "backup_file_size_bytes": file_size,
        "backup_file_digest": file_digest,
        "header_keyslots": target_keyslots,
        "header_tokens": target_tokens,
        "current_header_present": current_header_present,
        "current_keyslots": current_keyslots,
        "current_tokens": current_tokens,
        "signatures": signatures,
        "expected_luks_uuid": expected_luks_uuid.casefold() if expected_luks_uuid else None,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = LUKSHeaderTarget(
        action=action,  # type: ignore[arg-type]
        device_path=str(resolved_device),
        device_major=os.major(info.st_rdev),
        device_minor=os.minor(info.st_rdev),
        device_size_bytes=size_bytes,
        luks_version=target_version,
        luks_uuid=target_uuid,
        backup_file=str(resolved_backup),
        backup_parent_identity=parent_identity,
        backup_file_identity=file_identity,
        backup_file_size_bytes=file_size,
        backup_file_digest=file_digest,
        header_keyslots=target_keyslots,
        header_tokens=target_tokens,
        current_header_present=current_header_present,
        current_keyslots=current_keyslots,
        current_tokens=current_tokens,
        signatures=signatures,
        state_digest=digest,
    )
    phrase = hashlib.sha256((action + ":" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"LUKS header {action} {phrase}", None


def _open_verified_block_device(target: LUKSHeaderTarget) -> int | None:
    flags = (os.O_RDONLY if target.action == "backup" else os.O_RDWR)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = -1
    try:
        descriptor = os.open(target.device_path, flags)
        info = os.fstat(descriptor)
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        return None
    if (
        not stat.S_ISBLK(info.st_mode)
        or os.major(info.st_rdev) != target.device_major
        or os.minor(info.st_rdev) != target.device_minor
        or _device_size_bytes(info) != target.device_size_bytes
    ):
        os.close(descriptor)
        return None
    return descriptor


def _open_verified_header_file(target: LUKSHeaderTarget) -> tuple[int | None, int | None, str | None]:
    parent, name, parent_identity, error = _safe_header_parent(target.backup_file)
    if error or parent is None or name is None or parent_identity != target.backup_parent_identity:
        return None, None, error or "The backup directory identity changed after confirmation."
    directory_fd = -1
    descriptor = -1
    try:
        directory_fd = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        directory_info = os.fstat(directory_fd)
        if (directory_info.st_dev, directory_info.st_ino) != target.backup_parent_identity:
            return None, None, "The backup directory identity changed after confirmation."
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        file_info, error = _fingerprint_header_fd(descriptor)
        if error or file_info is None:
            return None, None, error or "The header backup could not be verified."
        if (
            (int(file_info["device"]), int(file_info["inode"])) != target.backup_file_identity
            or int(file_info["size"]) != target.backup_file_size_bytes
            or str(file_info["sha256"]) != target.backup_file_digest
        ):
            return None, None, "The header backup changed after confirmation."
        result_descriptor, result_directory_fd = descriptor, directory_fd
        descriptor = directory_fd = -1
        return result_descriptor, result_directory_fd, None
    except OSError:
        return None, None, "The header backup could not be opened safely with current permissions."
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            os.close(directory_fd)


def perform_luks_header_action(
    action: LUKSHeaderAction,
    device_path: str,
    backup_file: str,
    expected_luks_uuid: str | None = None,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> LUKSHeaderActionResponse:
    target, phrase, error = luks_header_action_confirmation_details(
        action, device_path, backup_file, expected_luks_uuid
    )
    if error or target is None or phrase is None:
        return LUKSHeaderActionResponse(
            success=False,
            action=action,
            device_path=device_path,
            backup_file=backup_file,
            user_confirmed=confirmed is True,
            message=error or "The LUKS header request could not be verified.",
        )
    if confirmed is not True:
        return LUKSHeaderActionResponse(
            success=False,
            action=action,
            device_path=target.device_path,
            backup_file=target.backup_file,
            luks_version=target.luks_version,
            luks_uuid=target.luks_uuid,
            user_confirmed=False,
            message="Explicit client confirmation is required; no LUKS header command was run.",
        )
    if confirmation_phrase != phrase:
        return LUKSHeaderActionResponse(
            success=False,
            action=action,
            device_path=target.device_path,
            backup_file=target.backup_file,
            luks_version=target.luks_version,
            luks_uuid=target.luks_uuid,
            user_confirmed=True,
            message="Confirmation did not match the exact block device, LUKS header, and backup-file state.",
        )
    current, current_phrase, error = luks_header_action_confirmation_details(
        action, device_path, backup_file, expected_luks_uuid
    )
    if error or current is None or current_phrase != phrase:
        return LUKSHeaderActionResponse(
            success=False,
            action=action,
            device_path=target.device_path,
            backup_file=target.backup_file,
            luks_version=target.luks_version,
            luks_uuid=target.luks_uuid,
            user_confirmed=True,
            message=error or "The block device or header backup changed after confirmation; no command was run.",
        )

    device_fd = _open_verified_block_device(target)
    if device_fd is None:
        return LUKSHeaderActionResponse(
            success=False,
            action=action,
            device_path=target.device_path,
            backup_file=target.backup_file,
            luks_version=target.luks_version,
            luks_uuid=target.luks_uuid,
            user_confirmed=True,
            message="The exact block device could not be opened with current permissions or its identity changed.",
        )
    cryptsetup = find_session_binary("cryptsetup", _environment())
    if not cryptsetup:
        os.close(device_fd)
        return LUKSHeaderActionResponse(
            success=False,
            action=action,
            device_path=target.device_path,
            backup_file=target.backup_file,
            luks_version=target.luks_version,
            luks_uuid=target.luks_uuid,
            user_confirmed=True,
            message="The cryptsetup command is unavailable.",
        )
    device_argument = f"/proc/self/fd/{device_fd}"
    if action == "backup":
        live_version, live_uuid, live_error = _probe_luks_header(
            device_argument,
            pass_fds=(device_fd,),
        )
        live_key_state = (
            _header_key_state(target.luks_version, device_argument, pass_fds=(device_fd,))
            if live_version == target.luks_version and live_uuid == target.luks_uuid
            else None
        )
        if (
            live_error
            or live_version != target.luks_version
            or live_uuid != target.luks_uuid
            or live_key_state != (target.header_keyslots, target.header_tokens)
        ):
            os.close(device_fd)
            return LUKSHeaderActionResponse(success=False, action=action, device_path=target.device_path, backup_file=target.backup_file, luks_version=target.luks_version, luks_uuid=target.luks_uuid, user_confirmed=True, message="The opened block device no longer has the confirmed LUKS header and keyslot/token state.")
        parent, name, parent_identity, error = _safe_header_parent(target.backup_file)
        if error or parent is None or name is None or parent_identity != target.backup_parent_identity:
            os.close(device_fd)
            return LUKSHeaderActionResponse(success=False, action=action, device_path=target.device_path, backup_file=target.backup_file, luks_version=target.luks_version, luks_uuid=target.luks_uuid, user_confirmed=True, message=error or "The backup directory identity changed after confirmation.")
        parent_fd = -1
        staging_fd = -1
        staging_name: str | None = None
        staging_identity: tuple[int, int] | None = None
        published = False
        published_identity: tuple[int, int] | None = None
        result_info: dict[str, int | str] | None = None
        try:
            parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
            parent_info = os.fstat(parent_fd)
            if (parent_info.st_dev, parent_info.st_ino) != target.backup_parent_identity:
                raise OSError("The backup directory identity changed before creation.")
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError("Refusing to overwrite an existing LUKS header backup.")
            for _ in range(16):
                candidate = f".linux-mcp-luks-header-{secrets.token_hex(16)}"
                try:
                    os.stat(candidate, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    staging_name = candidate
                    break
                else:
                    continue
            if staging_name is None:
                raise OSError("Could not allocate a private staging path in the verified backup directory.")
            staging_path = f"/proc/self/fd/{parent_fd}/{staging_name}"
            command = [
                cryptsetup,
                "luksHeaderBackup",
                "--batch-mode",
                "--header-backup-file",
                staging_path,
                device_argument,
            ]
            mutation_succeeded = _run_mutation(
                command,
                None,
                device_fd=device_fd,
                extra_fds=(parent_fd,),
                umask=0o077,
            )
            try:
                staging_fd = os.open(
                    staging_name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                if not mutation_succeeded:
                    raise RuntimeError("cryptsetup did not complete the header backup.")
                raise OSError("cryptsetup reported success without creating a header backup.")
            staging_info = os.fstat(staging_fd)
            staging_identity = (staging_info.st_dev, staging_info.st_ino)
            if not mutation_succeeded:
                raise RuntimeError("cryptsetup did not complete the header backup.")
            os.fsync(staging_fd)
            staging_fd_path = f"/proc/self/fd/{staging_fd}"
            result_info, error = _fingerprint_header_fd(staging_fd)
            if error or result_info is None:
                raise OSError(error or "The output backup could not be verified.")
            if (int(result_info["device"]), int(result_info["inode"])) != staging_identity:
                raise OSError("The staged backup file identity changed during creation.")
            device_fd_path = f"/proc/self/fd/{device_fd}"
            staged_pass_fds = (device_fd, staging_fd)
            staged_version, staged_uuid, probe_error = _probe_luks_header(
                device_fd_path,
                staging_fd_path,
                pass_fds=staged_pass_fds,
            )
            if probe_error or staged_version != target.luks_version or staged_uuid != target.luks_uuid:
                raise OSError(probe_error or "The staged backup header does not match the selected LUKS device.")
            staged_key_state = _header_key_state(
                target.luks_version,
                device_fd_path,
                staging_fd_path,
                pass_fds=staged_pass_fds,
            )
            if staged_key_state != (target.header_keyslots, target.header_tokens):
                raise OSError("The staged backup keyslot/token state differs from the confirmed device state.")
            live_after_version, live_after_uuid, live_after_error = _probe_luks_header(
                device_fd_path,
                pass_fds=(device_fd,),
            )
            live_after_state = (
                _header_key_state(target.luks_version, device_fd_path, pass_fds=(device_fd,))
                if live_after_version == target.luks_version and live_after_uuid == target.luks_uuid
                else None
            )
            if (
                live_after_error
                or live_after_version != target.luks_version
                or live_after_uuid != target.luks_uuid
                or live_after_state != (target.header_keyslots, target.header_tokens)
            ):
                raise OSError("The block-device LUKS state changed while the backup was being created.")
            staged_path_info = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
            if (staged_path_info.st_dev, staged_path_info.st_ino) != staging_identity:
                raise OSError("The staged backup path identity changed during creation.")
            os.link(staging_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            published_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            published_identity = (published_info.st_dev, published_info.st_ino)
            published = True
            if (published_info.st_dev, published_info.st_ino) != staging_identity:
                raise OSError("The published backup path identity could not be verified.")
            os.unlink(staging_name, dir_fd=parent_fd)
            staging_name = None
            os.fsync(parent_fd)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            if published and parent_fd >= 0 and published_identity is not None:
                try:
                    published_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if (published_info.st_dev, published_info.st_ino) == published_identity:
                        os.unlink(name, dir_fd=parent_fd)
                except OSError:
                    pass
            if staging_name is not None and staging_identity is not None and parent_fd >= 0:
                try:
                    staged_path_info = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
                    if (staged_path_info.st_dev, staged_path_info.st_ino) == staging_identity:
                        os.unlink(staging_name, dir_fd=parent_fd)
                except OSError:
                    pass
            if staging_fd >= 0:
                os.close(staging_fd)
            if parent_fd >= 0:
                os.close(parent_fd)
            os.close(device_fd)
            return LUKSHeaderActionResponse(success=False, action=action, device_path=target.device_path, backup_file=target.backup_file, luks_version=target.luks_version, luks_uuid=target.luks_uuid, user_confirmed=True, message=f"LUKS header backup failed: {str(exc)[:300]}")
        if staging_fd >= 0:
            os.close(staging_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(device_fd)
        if result_info is None:
            return LUKSHeaderActionResponse(success=False, action=action, device_path=target.device_path, backup_file=target.backup_file, luks_version=target.luks_version, luks_uuid=target.luks_uuid, user_confirmed=True, message="The backup was created but its digest could not be verified.")
        return LUKSHeaderActionResponse(success=True, action=action, device_path=target.device_path, backup_file=target.backup_file, luks_version=target.luks_version, luks_uuid=target.luks_uuid, backup_sha256=str(result_info["sha256"]), backup_size_bytes=int(result_info["size"]), user_confirmed=True, message="Created and verified a private LUKS header backup. Protect the file like a passphrase: it can restore keyslots from the backup date.")

    backup_fd, parent_fd, error = _open_verified_header_file(target)
    if error or backup_fd is None or parent_fd is None:
        os.close(device_fd)
        return LUKSHeaderActionResponse(success=False, action=action, device_path=target.device_path, backup_file=target.backup_file, luks_version=target.luks_version, luks_uuid=target.luks_uuid, backup_sha256=target.backup_file_digest, backup_size_bytes=target.backup_file_size_bytes, user_confirmed=True, message=error or "The confirmed header backup could not be opened.")
    restore_error: str | None = None
    restored = False
    result_version: LUKSVersion | None = None
    result_uuid: str | None = None
    verify_error: str | None = None
    result_key_state: tuple[tuple[int, ...], tuple[tuple[int, tuple[int, ...]], ...]] | None = None
    backup_after_info: dict[str, int | str] | None = None
    backup_after_error: str | None = None
    backup_path_matches = False
    try:
        backup_fd_path = f"/proc/self/fd/{backup_fd}"
        inherited_fds = (device_fd, backup_fd)
        backup_version, backup_uuid, backup_probe_error = _probe_luks_header(
            device_argument,
            backup_fd_path,
            pass_fds=inherited_fds,
        )
        backup_key_state = (
            _header_key_state(
                target.luks_version,
                device_argument,
                backup_fd_path,
                pass_fds=inherited_fds,
            )
            if backup_version == target.luks_version and backup_uuid == target.luks_uuid
            else None
        )
        current_version, current_uuid, current_probe_error = _probe_luks_header(
            device_argument,
            pass_fds=(device_fd,),
        )
        current_is_present = current_version is not None
        current_state = (
            _header_key_state(current_version, device_argument, pass_fds=(device_fd,))
            if current_version is not None
            else ((), ())
        )
        device_info = os.fstat(device_fd)
        live_signatures = _wipefs_signatures(device_argument, pass_fds=(device_fd,))
        if (
            backup_probe_error
            or backup_version != target.luks_version
            or backup_uuid != target.luks_uuid
            or backup_key_state != (target.header_keyslots, target.header_tokens)
            or current_probe_error
            or current_is_present != target.current_header_present
            or (current_is_present and (current_version != target.luks_version or current_uuid != target.luks_uuid))
            or current_state != (target.current_keyslots, target.current_tokens)
            or live_signatures != target.signatures
            or _device_readonly(device_info) is not False
            or _is_mounted_or_swap(device_info) is not False
            or _device_has_relations(device_info) is not False
            or _has_child_partitions(device_info) is not False
        ):
            restore_error = "The opened device or backup no longer matches the confirmed header and restore-safety state; no restore command was run."
        else:
            os.lseek(backup_fd, 0, os.SEEK_SET)
            command = [cryptsetup, "luksHeaderRestore", "--batch-mode", "--header-backup-file", backup_fd_path, device_argument]
            if _run_mutation(command, None, device_fd=device_fd, extra_fds=(backup_fd,)):
                restored = True
                device_fd_path = f"/proc/self/fd/{device_fd}"
                result_version, result_uuid, verify_error = _probe_luks_header(
                    device_fd_path,
                    pass_fds=(device_fd,),
                )
                result_key_state = (
                    _header_key_state(target.luks_version, device_fd_path, pass_fds=(device_fd,))
                    if result_version == target.luks_version and result_uuid == target.luks_uuid
                    else None
                )
                backup_after_info, backup_after_error = _fingerprint_header_fd(backup_fd)
                backup_name = Path(target.backup_file).name
                backup_path_info = os.stat(backup_name, dir_fd=parent_fd, follow_symlinks=False)
                backup_path_matches = (
                    (backup_path_info.st_dev, backup_path_info.st_ino) == target.backup_file_identity
                    and backup_after_info is not None
                    and (int(backup_after_info["device"]), int(backup_after_info["inode"])) == target.backup_file_identity
                )
            else:
                restore_error = "cryptsetup did not complete header restore; the device may require inspection before retrying."
    except OSError:
        restore_error = "The LUKS header could not be restored with current permissions; inspect the device before retrying."
    finally:
        os.close(backup_fd)
        os.close(parent_fd)
        os.close(device_fd)

    if (
        not restored
        or verify_error
        or result_version != target.luks_version
        or result_uuid != target.luks_uuid
        or result_key_state != (target.header_keyslots, target.header_tokens)
        or backup_after_info is None
        or backup_after_error
        or str(backup_after_info["sha256"]) != target.backup_file_digest
        or int(backup_after_info["size"]) != target.backup_file_size_bytes
        or not backup_path_matches
    ):
        return LUKSHeaderActionResponse(success=False, action=action, device_path=target.device_path, backup_file=target.backup_file, luks_version=target.luks_version, luks_uuid=target.luks_uuid, backup_sha256=target.backup_file_digest, backup_size_bytes=target.backup_file_size_bytes, user_confirmed=True, message=restore_error or "cryptsetup returned, but the restored LUKS header/keyslot state could not be fully verified; inspect the device before retrying.")
    return LUKSHeaderActionResponse(success=True, action=action, device_path=target.device_path, backup_file=target.backup_file, luks_version=target.luks_version, luks_uuid=target.luks_uuid, backup_sha256=target.backup_file_digest, backup_size_bytes=target.backup_file_size_bytes, user_confirmed=True, message="Restored and verified the LUKS header and keyslot state. All keyslots were replaced; only credentials from the backup now apply.")
