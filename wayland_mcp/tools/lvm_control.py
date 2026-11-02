"""Confirmed LVM logical-volume changes and constrained classic COW snapshot restoration."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Literal

from wayland_mcp.models import LVMVolumeActionResponse, LVMVolumeGroupActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.storage import _lvm_integer, _run_lvm_report
# Share the same read-only block-device, signature, mount, and swap preflight
# used by ext4 creation; no command from that module is invoked here.
from wayland_mcp.tools.ext4_control import (
    _device_state,
    _has_child_partitions,
    _resolve_device,
    _filesystem_state,
    _signature_types,
    _usage_state,
)

LVMVolumeAction = Literal["create", "resize", "shrink", "create_snapshot", "remove_snapshot", "restore_snapshot"]
LVMVolumeGroupAction = Literal["create", "add_pv", "remove_pv", "move_pv"]
LVM_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9+_.-]{0,126}$")
MIN_LV_SIZE_BYTES = 1024 * 1024
MAX_LV_SIZE_BYTES = 1 << 50
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 30
FILESYSTEM_SHRINK_TIMEOUT_SECONDS = 1800
MAX_GROUP_PHYSICAL_VOLUMES = 16
MAX_GROUP_DEVICE_SIZE_BYTES = 1 << 60
PV_MOVE_TIMEOUT_SECONDS = 1800
SNAPSHOT_MERGE_TIMEOUT_SECONDS = 1800
SYS_DEV_BLOCK = Path("/sys/dev/block")


@dataclass(frozen=True, slots=True)
class LVMVolumeActionTarget:
    action: LVMVolumeAction
    volume_group: str
    logical_volume: str
    snapshot_origin: str | None
    size_bytes: int | None
    current_size_bytes: int | None
    target_extents: int | None
    normalized_size_bytes: int | None
    filesystem_type: str | None
    filesystem_size_bytes: int | None
    free_bytes: int
    state_digest: str


@dataclass(frozen=True, slots=True)
class LVMGroupDevice:
    path: str
    major: int
    minor: int
    size_bytes: int
    physical_parent: str
    signatures: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LVMGroupActionTarget:
    action: LVMVolumeGroupAction
    volume_group: str
    devices: tuple[LVMGroupDevice, ...]
    lvm_state_digest: str
    state_digest: str
    expected_pv_count: int
    expected_pv_identities: tuple[tuple[int, int], ...]
    source_allocated_extents: int | None
    destination_free_extents: int | None
    destination_allocated_extents: int | None
    move_bytes: int | None


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def lvm_volume_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    return all(
        find_session_binary(binary, selected)
        for binary in ("vgs", "lvs", "lvcreate", "lvextend", "lvremove")
    )


def lvm_group_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    return all(find_session_binary(binary, selected) for binary in ("vgs", "pvs", "vgcreate", "vgextend", "vgreduce", "wipefs"))


def _valid_name(value: object, kind: str) -> str | None:
    if not isinstance(value, str) or not LVM_NAME_RE.fullmatch(value):
        return f"{kind} must be one exact LVM name containing only letters, digits, '+', '_', '.', or '-'."
    if value in {".", ".."}:
        return f"{kind} cannot be '.' or '..'."
    return None


def _lvm_percentage(row: dict[str, object]) -> Decimal | None:
    value = row.get("data_percent")
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return None
    try:
        raw = str(value).strip()
        if len(raw) > 32 or not re.fullmatch(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)", raw):
            return None
        percentage = Decimal(raw)
    except (InvalidOperation, ValueError):
        return None
    if not percentage.is_finite() or percentage < 0 or percentage > 100:
        return None
    return percentage


def _read_lvm_state(volume_group: str) -> tuple[dict[str, object] | None, list[dict[str, object]] | None, str | None]:
    env = _environment()
    vgs = find_session_binary("vgs", env)
    lvs = find_session_binary("lvs", env)
    if not vgs or not lvs:
        return None, None, "LVM2 vgs and lvs commands are required for logical-volume administration."
    group_rows, _truncated, error = _run_lvm_report(
        vgs,
        ("vg_name", "vg_size", "vg_free", "vg_extent_size"),
        env,
        "vg",
    )
    if error or group_rows is None:
        return None, None, error or "The volume-group state could not be read."
    groups = [row for row in group_rows if row.get("vg_name") == volume_group]
    if len(groups) != 1:
        return None, None, "The exact volume group was not found uniquely."
    group = groups[0]
    free_bytes, free_partial = _lvm_integer(group, "vg_free")
    extent_bytes, extent_partial = _lvm_integer(group, "vg_extent_size")
    if free_partial or extent_partial or free_bytes is None or extent_bytes is None or free_bytes < 0 or extent_bytes < 1:
        return None, None, "The volume group's free capacity could not be verified."
    lv_rows, _truncated, error = _run_lvm_report(
        lvs,
        ("vg_name", "lv_name", "lv_size", "lv_attr", "origin", "lv_layout", "data_percent"),
        env,
        "lv",
    )
    if error or lv_rows is None:
        return None, None, error or "Logical-volume state could not be read."
    volumes = [row for row in lv_rows if row.get("vg_name") == volume_group]
    state_material = {
        "group": group,
        "logical_volumes": sorted(volumes, key=lambda row: str(row.get("lv_name", ""))),
    }
    digest = hashlib.sha256(
        json.dumps(state_material, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {"row": group, "free_bytes": free_bytes, "extent_bytes": extent_bytes, "digest": digest}, volumes, None


def _lv_shrink_preflight(
    volume_group: str,
    logical_volume: str,
    expected_size_bytes: int,
) -> tuple[str | None, int | None, str | None, str | None]:
    if os.geteuid() != 0:
        return None, None, None, "LV shrinking requires effective root to check all visible block-device users; no elevation is requested."
    env = _environment()
    fuser = find_session_binary("fuser", env)
    if not fuser or not find_session_binary("lvreduce", env) or not find_session_binary("wipefs", env):
        return None, None, None, "LVM shrinking requires lvreduce, util-linux wipefs, and psmisc fuser."
    lv_path = Path("/dev") / volume_group / logical_volume
    resolved, info, error = _resolve_device(str(lv_path))
    if error or resolved is None or info is None:
        return None, None, None, error or "The logical-volume block-device identity could not be verified."
    device_size, readonly, has_holders = _device_state(info)
    if device_size is None or readonly is None or has_holders is None or device_size != expected_size_bytes:
        return None, None, None, "The logical-volume capacity, read-only state, or holder relationships could not be verified against LVM."
    if readonly or has_holders:
        return None, None, None, "LV shrinking is refused for a read-only volume or one held by another block layer."
    mounted, swapped = _usage_state(info)
    if mounted is None or swapped is None:
        return None, None, None, "Mounted and swap usage could not be checked safely."
    if mounted or swapped:
        return None, None, None, "LV shrinking requires an unmounted volume that is not active swap."
    try:
        opened = subprocess.run(
            [fuser, "-s", str(resolved)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            env=env,
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, None, None, "Open block-device users could not be checked safely."
    if opened.returncode == 0:
        return None, None, None, "LV shrinking is refused while a process has the block device open."
    if opened.returncode != 1:
        return None, None, None, "Open block-device users could not be checked safely."
    signatures = _signature_types(str(resolved))
    if signatures is None:
        return None, None, None, "Logical-volume signatures could not be checked safely."
    filesystem_type: str | None = None
    filesystem_size_bytes: int | None = None
    filesystem_material: dict[str, object] | None = None
    if signatures == ("ext4",):
        if not all(find_session_binary(binary, env) for binary in ("fsadm", "e2fsck", "resize2fs", "blkid", "dumpe2fs")):
            return None, None, None, "Shrinking an ext4 LV requires LVM fsadm and e2fsprogs check/resize utilities."
        filesystem_state = _filesystem_state(str(resolved))
        if filesystem_state is None:
            return None, None, None, "The ext4 filesystem geometry could not be verified."
        block_count, block_size, filesystem_uuid = filesystem_state
        filesystem_type = "ext4"
        filesystem_size_bytes = block_count * block_size
        if filesystem_size_bytes > expected_size_bytes:
            return None, None, None, "The ext4 filesystem reports a size larger than its logical volume."
        filesystem_material = {
            "type": filesystem_type,
            "size_bytes": filesystem_size_bytes,
            "uuid": filesystem_uuid,
        }
    elif signatures:
        return None, None, None, "LV shrinking supports only a raw volume without signatures or a verified ext4 filesystem; other filesystem and encryption layers are refused."
    material = {
        "major": os.major(info.st_rdev),
        "minor": os.minor(info.st_rdev),
        "device_size_bytes": device_size,
        "signatures": list(signatures),
        "filesystem": filesystem_material,
        "mounted": mounted,
        "swapped": swapped,
        "open_block_device": False,
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return filesystem_type, filesystem_size_bytes, digest, None


def _snapshot_merge_preflight(
    volume_group: str,
    snapshot_name: str,
    expected_snapshot_size_bytes: int,
    origin_name: str,
    expected_origin_size_bytes: int,
) -> tuple[str | None, str | None]:
    if os.geteuid() != 0:
        return None, "Restoring an LVM snapshot requires the server to already run as root so open-device use can be checked; no elevation is requested."
    env = _environment()
    fuser = find_session_binary("fuser", env)
    dmsetup = find_session_binary("dmsetup", env)
    if not fuser or not dmsetup or not find_session_binary("lvconvert", env):
        return None, "LVM snapshot restoration requires LVM2 lvconvert, device-mapper dmsetup, and psmisc fuser."
    resolved_devices: dict[str, tuple[Path, os.stat_result]] = {}
    for label, logical_volume, _expected_size in (
        ("snapshot", snapshot_name, expected_snapshot_size_bytes),
        ("origin", origin_name, expected_origin_size_bytes),
    ):
        resolved, info, error = _resolve_device(f"/dev/{volume_group}/{logical_volume}")
        if error or resolved is None or info is None:
            return None, error or f"The exact LVM {label} block device could not be verified."
        resolved_devices[label] = (resolved, info)
    snapshot_info = resolved_devices["snapshot"][1]
    snapshot_identity = (os.major(snapshot_info.st_rdev), os.minor(snapshot_info.st_rdev))
    device_states: list[dict[str, object]] = []
    for label, logical_volume, expected_size in (
        ("snapshot", snapshot_name, expected_snapshot_size_bytes),
        ("origin", origin_name, expected_origin_size_bytes),
    ):
        resolved, info = resolved_devices[label]
        device_size, readonly, has_holders = _device_state(info)
        if device_size is None or readonly is None or has_holders is None or device_size != expected_size:
            return None, f"The LVM {label} capacity, read-only state, or holder relationships could not be verified."
        holder_identities = _device_holder_identities(info)
        if holder_identities is None:
            return None, f"LVM {label} block-device holders could not be identified safely."
        if bool(holder_identities) != has_holders:
            return None, f"LVM {label} block-device holders changed during preflight."
        expected_holders = () if label == "snapshot" else (snapshot_identity,)
        if readonly or any(identity not in expected_holders for identity in holder_identities):
            return None, f"LVM snapshot restoration is refused while the {label} device is read-only or has an unrelated block-layer holder."
        mounted, swapped = _usage_state(info)
        if mounted is None or swapped is None:
            return None, f"The LVM {label} mounted and swap state could not be checked safely."
        if mounted or swapped:
            return None, f"LVM snapshot restoration requires both the snapshot and origin to be unmounted and not active swap."
        try:
            opened = subprocess.run(
                [fuser, "-s", str(resolved)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
                env=env,
                close_fds=True,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None, f"Open LVM {label} device users could not be checked safely."
        if opened.returncode == 0:
            return None, f"LVM snapshot restoration is refused while a process has the {label} block device open."
        if opened.returncode != 1:
            return None, f"Open LVM {label} device users could not be checked safely."
        device_states.append(
            {
                "role": label,
                "major": os.major(info.st_rdev),
                "minor": os.minor(info.st_rdev),
                "size_bytes": device_size,
                "readonly": readonly,
                "holders": [list(identity) for identity in holder_identities],
                "mounted": mounted,
                "swapped": swapped,
                "open_block_device": False,
            }
        )
        output, command_error, truncated = run_bounded_command(
            [dmsetup, "info", "--columns", "--noheadings", "--options", "open", str(resolved)],
            env,
            command_label="Read LVM snapshot merge open count",
            timeout_seconds=5,
            max_output_bytes=256,
        )
        if command_error or output is None or truncated or not re.fullmatch(r"\s*[0-9]+\s*", output):
            return None, f"The device-mapper open count for the LVM {label} could not be verified."
        open_count = int(output.strip(), 10)
        if open_count != 0:
            return None, f"LVM snapshot restoration requires the {label} device-mapper volume to be closed."
        device_states[-1]["device_mapper_open_count"] = open_count
    digest = hashlib.sha256(
        json.dumps(device_states, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return digest, None


def _device_holder_identities(info: os.stat_result) -> tuple[tuple[int, int], ...] | None:
    holder_directory = SYS_DEV_BLOCK / f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}" / "holders"
    try:
        names = sorted(os.listdir(holder_directory))
        if len(names) > 128:
            return None
        identities: list[tuple[int, int]] = []
        for name in names:
            raw_identity = (holder_directory / name / "dev").read_text(encoding="ascii").strip()
            match = re.fullmatch(r"([0-9]{1,10}):([0-9]{1,10})", raw_identity)
            if not match:
                return None
            identities.append((int(match.group(1)), int(match.group(2))))
        if len(identities) != len(set(identities)):
            return None
        return tuple(sorted(identities))
    except (OSError, UnicodeError, ValueError):
        return None


def lvm_volume_action_confirmation_details(
    action: str,
    volume_group: str,
    logical_volume: str,
    size_bytes: int | None = None,
    snapshot_origin: str | None = None,
) -> tuple[LVMVolumeActionTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "LVM logical-volume administration is available only on Linux."
    if not isinstance(action, str) or action not in {"create", "resize", "shrink", "create_snapshot", "remove_snapshot", "restore_snapshot"}:
        return None, None, "action must be create, resize, shrink, create_snapshot, remove_snapshot, or restore_snapshot."
    error = _valid_name(volume_group, "volume_group")
    if error:
        return None, None, error
    error = _valid_name(logical_volume, "logical_volume")
    if error:
        return None, None, error
    if action in {"create_snapshot", "restore_snapshot"}:
        error = _valid_name(snapshot_origin, "snapshot_origin")
        if error:
            return None, None, error
    elif snapshot_origin is not None:
        return None, None, "snapshot_origin is used only when creating or restoring a snapshot."
    if action in {"create", "resize", "shrink", "create_snapshot"}:
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or not MIN_LV_SIZE_BYTES <= size_bytes <= MAX_LV_SIZE_BYTES:
            return None, None, f"size_bytes must be from {MIN_LV_SIZE_BYTES} through {MAX_LV_SIZE_BYTES}."
    elif size_bytes is not None:
        return None, None, "size_bytes is used only when creating, resizing, or shrinking a logical volume or creating a snapshot."

    state, volumes, error = _read_lvm_state(volume_group)
    if error or state is None or volumes is None:
        return None, None, error or "LVM state could not be verified."
    found = [row for row in volumes if row.get("lv_name") == logical_volume]
    free_bytes = int(state["free_bytes"])
    extent_bytes = int(state["extent_bytes"])
    current_size: int | None = None
    target_extents: int | None = None
    normalized_size_bytes: int | None = None
    filesystem_type: str | None = None
    filesystem_size_bytes: int | None = None
    state_digest = str(state["digest"])
    if action == "create":
        if found:
            return None, None, "The requested logical-volume name already exists in this volume group."
        if size_bytes is None or ((size_bytes + extent_bytes - 1) // extent_bytes) * extent_bytes > free_bytes:
            return None, None, "The requested size exceeds the verified free capacity in the volume group."
    elif action == "create_snapshot":
        origins = [row for row in volumes if row.get("lv_name") == snapshot_origin]
        if found:
            return None, None, "The requested snapshot name already exists in this volume group."
        if len(origins) != 1:
            return None, None, "The exact snapshot origin LV was not found uniquely."
        if size_bytes is None or ((size_bytes + extent_bytes - 1) // extent_bytes) * extent_bytes > free_bytes:
            return None, None, "The requested snapshot size exceeds the verified free capacity in the volume group."
    elif action == "resize":
        if len(found) != 1:
            return None, None, "The exact logical volume was not found uniquely."
        current_size, partial = _lvm_integer(found[0], "lv_size")
        if partial or current_size is None:
            return None, None, "The current logical-volume size could not be verified."
        if size_bytes is None or size_bytes <= current_size:
            return None, None, "resize grows a logical volume only; size_bytes must exceed its current size."
        growth_bytes = ((size_bytes + extent_bytes - 1) // extent_bytes) * extent_bytes - current_size
        if growth_bytes > free_bytes:
            return None, None, "The requested growth exceeds the verified free capacity in the volume group."
    elif action == "shrink":
        if len(found) != 1:
            return None, None, "The exact logical volume was not found uniquely."
        current_size, partial = _lvm_integer(found[0], "lv_size")
        if partial or current_size is None:
            return None, None, "The current logical-volume size could not be verified."
        layout = found[0].get("lv_layout")
        origin = found[0].get("origin")
        if layout != "linear" or (origin is not None and str(origin).strip() not in {"", "-"}):
            return None, None, "Only a linear, non-snapshot logical volume can be shrunk by this action."
        if size_bytes is None:
            return None, None, "size_bytes is required for LV shrinking."
        target_extents = (size_bytes + extent_bytes - 1) // extent_bytes
        normalized_size_bytes = target_extents * extent_bytes
        if normalized_size_bytes > MAX_LV_SIZE_BYTES:
            return None, None, "The requested shrink target exceeds the supported logical-volume size limit after extent rounding."
        if current_size % extent_bytes != 0:
            return None, None, "The current logical-volume size is not aligned to its verified VG extent size."
        if target_extents < 1 or normalized_size_bytes >= current_size:
            return None, None, "The requested shrink target, rounded to a VG extent boundary, must be smaller than the current LV size."
        filesystem_type, filesystem_size_bytes, filesystem_digest, filesystem_error = _lv_shrink_preflight(
            volume_group,
            logical_volume,
            current_size,
        )
        if filesystem_error or filesystem_digest is None:
            return None, None, filesystem_error or "The logical-volume shrink state could not be verified."
        state_digest = hashlib.sha256(
            json.dumps(
                {
                    "lvm_state_digest": state_digest,
                    "filesystem_state_digest": filesystem_digest,
                    "requested_size_bytes": size_bytes,
                    "target_extents": target_extents,
                    "normalized_size_bytes": normalized_size_bytes,
                },
                sort_keys=True,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    elif action == "remove_snapshot":
        if len(found) != 1:
            return None, None, "The exact snapshot logical volume was not found uniquely."
        origin = found[0].get("origin")
        if not isinstance(origin, str) or not origin.strip():
            return None, None, "Only an LVM snapshot with a reported origin can be removed by this operation."
        current_size, partial = _lvm_integer(found[0], "lv_size")
        if partial:
            return None, None, "The snapshot size could not be verified."
    elif action == "restore_snapshot":
        if len(found) != 1:
            return None, None, "The exact snapshot logical volume was not found uniquely."
        snapshot_row = found[0]
        origin_name = snapshot_row.get("origin")
        attributes = snapshot_row.get("lv_attr")
        if origin_name != snapshot_origin:
            return None, None, "The selected logical volume is not a snapshot of the exact requested origin."
        if (
            not isinstance(attributes, str)
            or len(attributes) < 9
            or attributes[0] != "s"
            or attributes[4] != "a"
            or attributes[5] != "-"
            or attributes[6] != "s"
            or attributes[8] != "-"
        ):
            return None, None, "Restore supports only an active, closed, healthy classic copy-on-write LVM snapshot; thin, invalid, merging, partial, or unknown-state snapshots are refused."
        snapshot_data_percent = _lvm_percentage(snapshot_row)
        if snapshot_data_percent is None or snapshot_data_percent >= 100:
            return None, None, "The classic snapshot's allocated COW percentage is unknown or full; restoration is refused."
        origins = [row for row in volumes if row.get("lv_name") == snapshot_origin]
        if len(origins) != 1:
            return None, None, "The exact snapshot origin LV was not found uniquely."
        origin_attributes = origins[0].get("lv_attr")
        if (
            not isinstance(origin_attributes, str)
            or len(origin_attributes) < 9
            or origin_attributes[0] != "o"
            or origin_attributes[4] != "a"
            or origin_attributes[5] != "-"
            or origin_attributes[8] != "-"
        ):
            return None, None, "The requested LV is not an active, closed, healthy LVM snapshot origin or is already merging another snapshot."
        moving, move_error = _pvmove_in_progress(volume_group)
        if move_error or moving is None:
            return None, None, move_error or "LVM physical-volume migration state could not be verified."
        if moving:
            return None, None, "LVM snapshot restoration is refused while physical-volume migration is active."
        current_size, partial = _lvm_integer(origins[0], "lv_size")
        if partial or current_size is None:
            return None, None, "The snapshot origin size could not be verified."
        snapshot_size, partial = _lvm_integer(snapshot_row, "lv_size")
        if partial or snapshot_size is None:
            return None, None, "The snapshot LV size could not be verified."
        device_digest, error = _snapshot_merge_preflight(
            volume_group,
            logical_volume,
            snapshot_size,
            snapshot_origin,
            current_size,
        )
        if error or device_digest is None:
            return None, None, error or "The snapshot and origin use state could not be verified."
        state_digest = hashlib.sha256(
            json.dumps(
                {"lvm_state_digest": state_digest, "device_state_digest": device_digest},
                sort_keys=True,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    target = LVMVolumeActionTarget(
        action=action,  # type: ignore[arg-type]
        volume_group=volume_group,
        logical_volume=logical_volume,
        snapshot_origin=snapshot_origin,
        size_bytes=size_bytes,
        current_size_bytes=current_size,
        free_bytes=free_bytes,
        state_digest=state_digest,
        target_extents=target_extents,
        normalized_size_bytes=normalized_size_bytes,
        filesystem_type=filesystem_type,
        filesystem_size_bytes=filesystem_size_bytes,
    )
    phrase_material = {
        "action": action,
        "volume_group": volume_group,
        "logical_volume": logical_volume,
        "snapshot_origin": snapshot_origin,
        "size_bytes": size_bytes,
        "current_size_bytes": current_size,
        "free_bytes": free_bytes,
        "state_digest": target.state_digest,
        "target_extents": target.target_extents,
        "normalized_size_bytes": target.normalized_size_bytes,
        "filesystem_type": target.filesystem_type,
        "filesystem_size_bytes": target.filesystem_size_bytes,
    }
    phrase_hash = hashlib.sha256(
        json.dumps(phrase_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    return target, f"LVM {phrase_hash}", None


def _run_lvm_mutation(
    command: list[str],
    label: str,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
) -> tuple[bool, str]:
    env = _environment()
    output, error, truncated = run_bounded_command(
        command,
        env,
        command_label=label,
        timeout_seconds=timeout_seconds,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
    )
    if error or output is None or truncated:
        return False, "The LVM command did not complete cleanly; inspect LVM state before retrying."
    return True, ""


def perform_lvm_volume_action(
    action: LVMVolumeAction,
    volume_group: str,
    logical_volume: str,
    size_bytes: int | None = None,
    snapshot_origin: str | None = None,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> LVMVolumeActionResponse:
    target, phrase, error = lvm_volume_action_confirmation_details(action, volume_group, logical_volume, size_bytes, snapshot_origin)
    if error or target is None or phrase is None:
        return LVMVolumeActionResponse(success=False, action=action, volume_group=volume_group, logical_volume=logical_volume, size_bytes=size_bytes, user_confirmed=confirmed is True, message=error or "The LVM request could not be verified.")
    if confirmed is not True:
        return LVMVolumeActionResponse(success=False, action=action, volume_group=volume_group, logical_volume=logical_volume, size_bytes=size_bytes, current_size_bytes=target.current_size_bytes, user_confirmed=False, message="Explicit client confirmation is required; no LVM command was run.")
    if confirmation_phrase != phrase:
        return LVMVolumeActionResponse(success=False, action=action, volume_group=volume_group, logical_volume=logical_volume, size_bytes=size_bytes, current_size_bytes=target.current_size_bytes, user_confirmed=True, message="Confirmation did not match the exact LVM request and current volume-group state.")

    # Repeat the complete read-only preflight after the client decision. This
    # binds the command to the same capacity, target, and LV inventory shown.
    current, current_phrase, error = lvm_volume_action_confirmation_details(action, volume_group, logical_volume, size_bytes, snapshot_origin)
    if error or current is None or current_phrase != phrase:
        return LVMVolumeActionResponse(success=False, action=action, volume_group=volume_group, logical_volume=logical_volume, size_bytes=size_bytes, current_size_bytes=target.current_size_bytes, user_confirmed=True, message=error or "LVM state changed after confirmation; no command was run.")
    env = _environment()
    if action == "create":
        binary = find_session_binary("lvcreate", env)
        command = [binary, "--yes", "--size", f"{size_bytes}B", "--name", logical_volume, volume_group] if binary else []
        label = "Create LVM logical volume"
    elif action == "resize":
        binary = find_session_binary("lvextend", env)
        command = [binary, "--yes", "--size", f"{size_bytes}B", f"{volume_group}/{logical_volume}"] if binary else []
        label = "Grow LVM logical volume"
    elif action == "shrink":
        binary = find_session_binary("lvreduce", env)
        command = (
            [binary, "--yes"]
            + (["--resizefs"] if target.filesystem_type == "ext4" else [])
            + ["--extents", str(target.target_extents), f"{volume_group}/{logical_volume}"]
            if binary and target.target_extents is not None else []
        )
        label = "Shrink LVM logical volume and supported filesystem"
    elif action == "create_snapshot":
        binary = find_session_binary("lvcreate", env)
        command = [binary, "--yes", "--snapshot", "--size", f"{size_bytes}B", "--name", logical_volume, f"{volume_group}/{snapshot_origin}"] if binary else []
        label = "Create LVM snapshot"
    elif action == "remove_snapshot":
        binary = find_session_binary("lvremove", env)
        command = [binary, "--yes", f"{volume_group}/{logical_volume}"] if binary else []
        label = "Remove LVM snapshot"
    elif action == "restore_snapshot":
        binary = find_session_binary("lvconvert", env)
        command = [binary, "--yes", "--merge", f"{volume_group}/{logical_volume}"] if binary else []
        label = "Merge LVM copy-on-write snapshot into origin"
    if not command:
        return LVMVolumeActionResponse(success=False, action=action, volume_group=volume_group, logical_volume=logical_volume, size_bytes=size_bytes, current_size_bytes=target.current_size_bytes, filesystem_type=target.filesystem_type, filesystem_size_bytes=target.filesystem_size_bytes, user_confirmed=True, message=f"The required {action} LVM command or verified target size is unavailable.")
    success, message = _run_lvm_mutation(
        command,
        label,
        FILESYSTEM_SHRINK_TIMEOUT_SECONDS
        if action == "shrink"
        else SNAPSHOT_MERGE_TIMEOUT_SECONDS
        if action == "restore_snapshot"
        else COMMAND_TIMEOUT_SECONDS,
    )
    if not success:
        return LVMVolumeActionResponse(success=False, action=action, volume_group=volume_group, logical_volume=logical_volume, size_bytes=size_bytes, current_size_bytes=target.current_size_bytes, user_confirmed=True, message=message)

    _state, resulting_volumes, error = _read_lvm_state(volume_group)
    if error or resulting_volumes is None:
        return LVMVolumeActionResponse(success=False, action=action, volume_group=volume_group, logical_volume=logical_volume, size_bytes=size_bytes, current_size_bytes=target.current_size_bytes, user_confirmed=True, message="The LVM command returned success, but resulting state could not be verified; inspect LVM before retrying.")
    resulting = [row for row in resulting_volumes if row.get("lv_name") == logical_volume]
    resulting_filesystem_size: int | None = None
    if action == "remove_snapshot":
        verified = not resulting
        actual_size = None
    elif action == "restore_snapshot":
        restored_origins = [row for row in resulting_volumes if row.get("lv_name") == target.snapshot_origin]
        actual_size = None
        if len(restored_origins) == 1:
            actual_size, partial = _lvm_integer(restored_origins[0], "lv_size")
            if partial:
                actual_size = None
        verified = not resulting and len(restored_origins) == 1 and actual_size == target.current_size_bytes
    else:
        actual_size = None
        if len(resulting) == 1:
            actual_size, partial = _lvm_integer(resulting[0], "lv_size")
            if partial:
                actual_size = None
        if action == "shrink":
            verified = (
                len(resulting) == 1
                and actual_size is not None
                and actual_size == target.normalized_size_bytes
            )
            resolved, info, device_error = _resolve_device(f"/dev/{volume_group}/{logical_volume}")
            if device_error or resolved is None or info is None:
                filesystem_verified = False
            else:
                signatures = _signature_types(str(resolved))
                if target.filesystem_type == "ext4":
                    filesystem_state = _filesystem_state(str(resolved)) if signatures == ("ext4",) else None
                    if filesystem_state is None:
                        filesystem_verified = False
                    else:
                        block_count, block_size, _filesystem_uuid = filesystem_state
                        resulting_filesystem_size = block_count * block_size
                        filesystem_verified = bool(actual_size is not None and resulting_filesystem_size <= actual_size)
                else:
                    filesystem_verified = signatures == ()
            verified = verified and filesystem_verified
        else:
            verified = len(resulting) == 1 and actual_size is not None and actual_size >= (size_bytes or 0)
        if action == "create_snapshot":
            verified = verified and resulting[0].get("origin") == snapshot_origin
    if not verified:
        return LVMVolumeActionResponse(success=False, action=action, volume_group=volume_group, logical_volume=logical_volume, snapshot_origin=target.snapshot_origin, size_bytes=size_bytes, current_size_bytes=target.current_size_bytes, actual_size_bytes=actual_size, filesystem_type=target.filesystem_type, filesystem_size_bytes=resulting_filesystem_size, user_confirmed=True, message="The LVM command completed, but the requested resulting LV/filesystem state was not verified; inspect storage before retrying.")
    message = (
        "The confirmed LVM copy-on-write snapshot merge completed; the snapshot LV is gone and the origin LV size is unchanged. Block contents are not independently read back."
        if action == "restore_snapshot"
        else
        "Shrank the logical volume and verified the ext4 filesystem was resized first and remains within the new LV."
        if action == "shrink" and target.filesystem_type == "ext4"
        else "Shrank and verified the raw logical volume; trailing data may have been discarded."
        if action == "shrink"
        else "The LVM action completed and its resulting state was verified."
    )
    return LVMVolumeActionResponse(success=True, action=action, volume_group=volume_group, logical_volume=logical_volume, snapshot_origin=target.snapshot_origin, size_bytes=size_bytes, current_size_bytes=target.current_size_bytes, actual_size_bytes=actual_size, filesystem_type=target.filesystem_type, filesystem_size_bytes=resulting_filesystem_size, user_confirmed=True, message=message)


def _read_volume_group_rows() -> tuple[list[dict[str, object]] | None, str | None]:
    env = _environment()
    vgs = find_session_binary("vgs", env)
    if not vgs:
        return None, "The LVM2 vgs command is unavailable."
    rows, truncated, error = _run_lvm_report(
        vgs,
        ("vg_name", "vg_uuid", "vg_size", "vg_free", "vg_extent_size", "pv_count"),
        env,
        "vg",
    )
    if error or rows is None:
        return None, error or "The LVM volume-group inventory could not be read."
    if truncated:
        return None, "The LVM volume-group inventory exceeded its scan limit; unique group names cannot be guaranteed."
    return rows, None


def _read_physical_volume_rows() -> tuple[list[dict[str, object]] | None, str | None]:
    env = _environment()
    pvs = find_session_binary("pvs", env)
    if not pvs:
        return None, "The LVM2 pvs command is unavailable."
    rows, truncated, error = _run_lvm_report(
        pvs,
        ("pv_name", "pv_uuid", "vg_name", "pv_size", "pv_free", "pv_pe_count", "pv_pe_alloc_count", "pv_missing"),
        env,
        "pv",
    )
    if error or rows is None:
        return None, error or "The LVM physical-volume inventory could not be read."
    if truncated:
        return None, "The LVM physical-volume inventory exceeded its scan limit; unique device identities cannot be guaranteed."
    return rows, None


def _pvmove_in_progress(volume_group: str) -> tuple[bool | None, str | None]:
    env = _environment()
    lvs = find_session_binary("lvs", env)
    if not lvs:
        return None, "The LVM2 lvs command is unavailable."
    rows, _truncated, error = _run_lvm_report(
        lvs,
        ("vg_name", "lv_name", "lv_attr", "lv_layout"),
        env,
        "lv",
        extra_args=("--all",),
    )
    if error or rows is None:
        return None, error or "LVM move-operation state could not be read."
    for row in rows:
        if row.get("vg_name") != volume_group:
            continue
        name = str(row.get("lv_name", "")).casefold()
        attributes = str(row.get("lv_attr", "")).casefold()
        layout = str(row.get("lv_layout", "")).casefold()
        if name.startswith("pvmove") or attributes.startswith("p") or "pvmove" in layout:
            return True, None
    return False, None


def _pv_identity(row: dict[str, object]) -> tuple[int, int] | None:
    raw_path = row.get("pv_name")
    if not isinstance(raw_path, str) or not raw_path.startswith("/") or len(raw_path) > 4096:
        return None
    try:
        path = Path(raw_path).resolve(strict=True)
        path.relative_to(Path("/dev"))
        info = path.stat()
    except (OSError, RuntimeError, ValueError):
        return None
    if not stat.S_ISBLK(info.st_mode):
        return None
    return os.major(info.st_rdev), os.minor(info.st_rdev)


def _existing_pv_device(value: object) -> tuple[LVMGroupDevice | None, str | None]:
    resolved, info, error = _resolve_device(value)
    if error or resolved is None or info is None:
        return None, error or "The physical-volume block-device identity could not be verified."
    size_bytes, readonly, has_holders = _device_state(info)
    if size_bytes is None or readonly is None or has_holders is None:
        return None, "The physical-volume capacity, read-only state, or holder relationships could not be verified."
    if size_bytes > MAX_GROUP_DEVICE_SIZE_BYTES:
        return None, "The physical-volume device exceeds the supported capacity limit."
    if readonly or has_holders:
        return None, "Physical-volume removal requires a writable device with no active block-layer holders."
    mounted, swapped = _usage_state(info)
    if mounted is None or swapped is None:
        return None, "Mounted and swap usage could not be checked safely."
    if mounted or swapped:
        return None, "Physical-volume removal is refused on a mounted or active swap device."
    major, minor = os.major(info.st_rdev), os.minor(info.st_rdev)
    sysfs = SYS_DEV_BLOCK / f"{major}:{minor}"
    try:
        sysfs_path = sysfs.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "The physical-volume sysfs identity could not be verified."
    physical_parent = str(sysfs_path.parent if (sysfs / "partition").is_file() else sysfs_path)
    return LVMGroupDevice(
        path=str(resolved),
        major=major,
        minor=minor,
        size_bytes=size_bytes,
        physical_parent=physical_parent,
        signatures=("LVM2_member",),
    ), None


def _member_pv_device(value: object) -> tuple[LVMGroupDevice | None, str | None]:
    """Validate a PV identity for online migration while permitting active LV holders."""
    resolved, info, error = _resolve_device(value)
    if error or resolved is None or info is None:
        return None, error or "The physical-volume block-device identity could not be verified."
    size_bytes, readonly, has_holders = _device_state(info)
    if size_bytes is None or readonly is None or has_holders is None:
        return None, "The physical-volume capacity and device state could not be verified."
    if size_bytes > MAX_GROUP_DEVICE_SIZE_BYTES:
        return None, "The physical-volume device exceeds the supported capacity limit."
    if readonly:
        return None, "Physical-volume migration requires writable source and destination devices."
    mounted, swapped = _usage_state(info)
    if mounted is None or swapped is None:
        return None, "Physical-volume mount and swap use could not be checked safely."
    if mounted or swapped:
        return None, "A PV mounted directly or used as swap cannot be moved by this operation."
    major, minor = os.major(info.st_rdev), os.minor(info.st_rdev)
    sysfs = SYS_DEV_BLOCK / f"{major}:{minor}"
    try:
        sysfs_path = sysfs.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "The physical-volume sysfs identity could not be verified."
    physical_parent = str(sysfs_path.parent if (sysfs / "partition").is_file() else sysfs_path)
    return LVMGroupDevice(
        path=str(resolved),
        major=major,
        minor=minor,
        size_bytes=size_bytes,
        physical_parent=physical_parent,
        signatures=("LVM2_member",),
    ), None


def _lvm_group_device(value: object) -> tuple[LVMGroupDevice | None, str | None]:
    resolved, info, error = _resolve_device(value)
    if error or resolved is None or info is None:
        return None, error or "The physical-volume block-device identity could not be verified."
    size_bytes, readonly, has_holders = _device_state(info)
    if size_bytes is None or readonly is None or has_holders is None:
        return None, "The physical-volume capacity, read-only state, or holder relationships could not be verified."
    if size_bytes > MAX_GROUP_DEVICE_SIZE_BYTES:
        return None, "The physical-volume device exceeds the supported capacity limit."
    if readonly or has_holders:
        return None, "Physical-volume creation requires a writable device with no active block-layer holders."
    mounted, swapped = _usage_state(info)
    if mounted is None or swapped is None:
        return None, "Mounted and swap usage could not be checked safely."
    if mounted or swapped:
        return None, "Physical-volume creation is refused on a mounted or active swap device."
    signatures = _signature_types(str(resolved))
    if signatures is None:
        return None, "Existing physical-device signatures could not be checked safely."
    if signatures:
        return None, f"{resolved} has recognized signatures ({', '.join(signatures)}); existing metadata will not be erased."
    major, minor = os.major(info.st_rdev), os.minor(info.st_rdev)
    sysfs = SYS_DEV_BLOCK / f"{major}:{minor}"
    try:
        sysfs_path = sysfs.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "The physical-volume sysfs identity could not be verified."
    if (sysfs / "partition").is_file():
        physical_parent = str(sysfs_path.parent)
    else:
        child_partitions = _has_child_partitions(info)
        if child_partitions is None:
            return None, "Child-partition state could not be checked safely."
        if child_partitions:
            return None, "A whole disk with child partitions cannot be initialized; select one partition instead."
        physical_parent = str(sysfs_path)
    return LVMGroupDevice(
        path=str(resolved),
        major=major,
        minor=minor,
        size_bytes=size_bytes,
        physical_parent=physical_parent,
        signatures=signatures,
    ), None


def _group_pv_records(
    pv_rows: list[dict[str, object]],
    volume_group: str,
) -> tuple[list[tuple[dict[str, object], tuple[int, int]]], str | None]:
    members: list[tuple[dict[str, object], tuple[int, int]]] = []
    seen: set[tuple[int, int]] = set()
    for row in pv_rows:
        if str(row.get("vg_name") or "").strip() != volume_group:
            continue
        missing_raw = row.get("pv_missing")
        if missing_raw in (None, "", "-", "0", 0):
            missing = 0
            missing_partial = False
        elif missing_raw in ("1", 1, "missing"):
            missing = 1
            missing_partial = False
        else:
            missing = None
            missing_partial = True
        allocated, allocated_partial = _lvm_integer(row, "pv_pe_alloc_count")
        if missing_partial or allocated_partial or missing is None or allocated is None:
            return [], "Every physical volume in the group must have readable missing-device and allocated-extent state."
        if missing != 0:
            return [], "The volume group has a missing physical volume; membership changes are refused."
        identity = _pv_identity(row)
        if identity is None:
            return [], "Every physical volume in the group must resolve to an exact block-device identity."
        if identity in seen:
            return [], "The LVM report contains duplicate physical-volume device identities."
        seen.add(identity)
        members.append((row, identity))
    return members, None


def lvm_group_action_confirmation_details(
    action: str,
    volume_group: str,
    physical_device_paths: list[str],
) -> tuple[LVMGroupActionTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "LVM volume-group administration is available only on Linux."
    if not isinstance(action, str) or action not in {"create", "add_pv", "remove_pv", "move_pv"}:
        return None, None, "action must be create, add_pv, remove_pv, or move_pv."
    if not lvm_group_control_available():
        return None, None, "LVM2 vgs, pvs, vgcreate, vgextend, vgreduce, and util-linux wipefs commands are required."
    if action == "move_pv" and not find_session_binary("pvmove", _environment()):
        return None, None, "LVM2 pvmove is required to migrate allocated physical extents."
    error = _valid_name(volume_group, "volume_group")
    if error:
        return None, None, error
    valid_path_count = (
        isinstance(physical_device_paths, list)
        and (len(physical_device_paths) == 2 if action == "move_pv" else 1 <= len(physical_device_paths) <= MAX_GROUP_PHYSICAL_VOLUMES)
    )
    if not valid_path_count:
        if action == "move_pv":
            return None, None, "move_pv requires exactly two paths, ordered as source PV then destination PV."
        return None, None, f"physical_device_paths must contain 1 through {MAX_GROUP_PHYSICAL_VOLUMES} exact block-device paths."

    group_rows, error = _read_volume_group_rows()
    if error or group_rows is None:
        return None, None, error or "The volume-group inventory could not be verified."
    pv_rows, error = _read_physical_volume_rows()
    if error or pv_rows is None:
        return None, None, error or "The physical-volume inventory could not be verified."
    group_matches = [row for row in group_rows if row.get("vg_name") == volume_group]
    if action == "create":
        if group_matches:
            return None, None, "The requested volume-group name already exists."
        existing_count = 0
        group_members: list[tuple[dict[str, object], tuple[int, int]]] = []
    else:
        if len(group_matches) != 1:
            return None, None, "The exact existing volume group was not found uniquely."
        group_members, error = _group_pv_records(pv_rows, volume_group)
        if error:
            return None, None, error
        existing_count, count_partial = _lvm_integer(group_matches[0], "pv_count")
        if count_partial or existing_count is None or existing_count != len(group_members):
            return None, None, "The reported physical-volume count does not match the exact readable group membership."
    if action == "remove_pv" and len(physical_device_paths) >= existing_count:
        return None, None, "At least one physical volume must remain in the volume group."

    lvm_state_material = {
        "volume_groups": sorted(group_rows, key=lambda row: str(row.get("vg_name", ""))),
        "physical_volumes": sorted(
            pv_rows,
            key=lambda row: (str(row.get("vg_name", "")), str(row.get("pv_name", "")), str(row.get("pv_uuid", ""))),
        ),
    }
    lvm_state_digest = hashlib.sha256(
        json.dumps(lvm_state_material, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    devices: list[LVMGroupDevice] = []
    member_by_identity = {identity: row for row, identity in group_members}
    source_allocated_extents: int | None = None
    destination_free_extents: int | None = None
    destination_allocated_extents: int | None = None
    move_bytes: int | None = None
    if action in {"create", "add_pv"}:
        for raw_path in physical_device_paths:
            device, error = _lvm_group_device(raw_path)
            if error or device is None:
                return None, None, error or "A blank physical-volume device could not be verified."
            devices.append(device)
    elif action == "remove_pv":
        for raw_path in physical_device_paths:
            device, error = _existing_pv_device(raw_path)
            if error or device is None:
                return None, None, error or "A physical-volume device could not be verified."
            member = member_by_identity.get((device.major, device.minor))
            if member is None:
                return None, None, f"{device.path} is not a member of the selected volume group."
            allocated, partial = _lvm_integer(member, "pv_pe_alloc_count")
            if partial or allocated is None or allocated != 0:
                return None, None, f"{device.path} has allocated physical extents; data migration is required before it can be removed."
            devices.append(device)
    else:
        move_active, error = _pvmove_in_progress(volume_group)
        if error or move_active is None:
            return None, None, error or "LVM move-operation state could not be verified."
        if move_active:
            return None, None, "An LVM pvmove operation is already present in this group; inspect or resume it before starting another migration."
        for raw_path in physical_device_paths:
            device, error = _member_pv_device(raw_path)
            if error or device is None:
                return None, None, error or "A source or destination PV could not be verified."
            if (device.major, device.minor) not in member_by_identity:
                return None, None, f"{device.path} is not a physical-volume member of the selected group."
            devices.append(device)
        source_row = member_by_identity[(devices[0].major, devices[0].minor)]
        destination_row = member_by_identity[(devices[1].major, devices[1].minor)]
        source_allocated_extents, source_partial = _lvm_integer(source_row, "pv_pe_alloc_count")
        destination_total_extents, total_partial = _lvm_integer(destination_row, "pv_pe_count")
        destination_allocated_extents, destination_alloc_partial = _lvm_integer(destination_row, "pv_pe_alloc_count")
        extent_bytes, extent_partial = _lvm_integer(group_matches[0], "vg_extent_size")
        if (
            source_partial or total_partial or destination_alloc_partial or extent_partial
            or source_allocated_extents is None or destination_total_extents is None
            or destination_allocated_extents is None or extent_bytes is None
        ):
            return None, None, "The source allocation, destination free extents, or volume-group extent size could not be verified."
        if source_allocated_extents < 1:
            return None, None, "The source PV has no allocated extents to move."
        destination_free_extents = destination_total_extents - destination_allocated_extents
        if destination_free_extents < source_allocated_extents * 2:
            return None, None, "Atomic migration requires at least twice the source's allocated extent count free on the selected destination PV."
        move_bytes = source_allocated_extents * extent_bytes

    identities = {(device.major, device.minor) for device in devices}
    if len(identities) != len(devices):
        return None, None, "A block-device identity cannot appear more than once in one volume-group action."
    if action == "add_pv":
        existing_identities = set(member_by_identity)
        if identities & existing_identities:
            return None, None, "A selected block-device identity is already a member of the volume group."
    if action == "create":
        parents = {device.physical_parent for device in devices}
        if len(parents) != len(devices):
            return None, None, "Select at most one physical volume from each physical disk."

    if action == "add_pv" and existing_count + len(devices) > MAX_GROUP_PHYSICAL_VOLUMES:
        return None, None, f"The volume group may contain at most {MAX_GROUP_PHYSICAL_VOLUMES} PVs through this control."
    expected_pv_count = (
        len(devices)
        if action == "create"
        else existing_count + len(devices)
        if action == "add_pv"
        else existing_count
        if action == "move_pv"
        else existing_count - len(devices)
    )
    existing_identities = set(member_by_identity)
    if action == "create":
        expected_identities = identities
    elif action == "add_pv":
        expected_identities = existing_identities | identities
    elif action == "move_pv":
        expected_identities = existing_identities
    else:
        expected_identities = existing_identities - identities

    device_material = [
        {
            "path": device.path,
            "major": device.major,
            "minor": device.minor,
            "size_bytes": device.size_bytes,
            "physical_parent": device.physical_parent,
            "signatures": list(device.signatures),
        }
        for device in devices
    ]
    material = {
        "action": action,
        "volume_group": volume_group,
        "lvm_state_digest": lvm_state_digest,
        "expected_pv_count": expected_pv_count,
        "expected_pv_identities": sorted(expected_identities),
        "devices": device_material,
        "source_allocated_extents": source_allocated_extents,
        "destination_free_extents": destination_free_extents,
        "destination_allocated_extents": destination_allocated_extents,
        "move_bytes": move_bytes,
    }
    state_digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    target = LVMGroupActionTarget(
        action=action,  # type: ignore[arg-type]
        volume_group=volume_group,
        devices=tuple(devices),
        lvm_state_digest=lvm_state_digest,
        state_digest=state_digest,
        expected_pv_count=expected_pv_count,
        expected_pv_identities=tuple(sorted(expected_identities)),
        source_allocated_extents=source_allocated_extents,
        destination_free_extents=destination_free_extents,
        destination_allocated_extents=destination_allocated_extents,
        move_bytes=move_bytes,
    )
    phrase_hash = hashlib.sha256((action + ":" + volume_group + ":" + state_digest).encode("utf-8")).hexdigest()[:16]
    return target, f"LVM VG {phrase_hash}", None


def perform_lvm_group_action(
    action: LVMVolumeGroupAction,
    volume_group: str,
    physical_device_paths: list[str],
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> LVMVolumeGroupActionResponse:
    safe_action = action if isinstance(action, str) and action in {"create", "add_pv", "remove_pv", "move_pv"} else "create"
    safe_paths = [path for path in physical_device_paths if isinstance(path, str)] if isinstance(physical_device_paths, list) else []
    target, phrase, error = lvm_group_action_confirmation_details(action, volume_group, physical_device_paths)
    if error or target is None or phrase is None:
        return LVMVolumeGroupActionResponse(
            success=False,
            action=safe_action,
            volume_group=volume_group,
            physical_devices=safe_paths,
            user_confirmed=confirmed is True,
            message=error or "The LVM volume-group action could not be verified.",
        )
    if confirmed is not True:
        return LVMVolumeGroupActionResponse(
            success=False,
            action=target.action,
            volume_group=target.volume_group,
            physical_devices=[device.path for device in target.devices],
            physical_volume_count=target.expected_pv_count,
            user_confirmed=False,
            message="Explicit client confirmation is required; no LVM command was run.",
        )
    if confirmation_phrase != phrase:
        return LVMVolumeGroupActionResponse(
            success=False,
            action=target.action,
            volume_group=target.volume_group,
            physical_devices=[device.path for device in target.devices],
            physical_volume_count=target.expected_pv_count,
            user_confirmed=True,
            message="Confirmation did not match the exact volume-group action, block devices, and current LVM state.",
        )
    current, current_phrase, error = lvm_group_action_confirmation_details(action, volume_group, physical_device_paths)
    if error or current is None or current_phrase != phrase:
        return LVMVolumeGroupActionResponse(
            success=False,
            action=target.action,
            volume_group=target.volume_group,
            physical_devices=[device.path for device in target.devices],
            physical_volume_count=target.expected_pv_count,
            user_confirmed=True,
            message=error or "LVM or block-device state changed after confirmation; no command was run.",
        )

    env = _environment()
    binary_name = {"create": "vgcreate", "add_pv": "vgextend", "remove_pv": "vgreduce", "move_pv": "pvmove"}[target.action]
    binary = find_session_binary(binary_name, env)
    if not binary:
        return LVMVolumeGroupActionResponse(
            success=False,
            action=target.action,
            volume_group=target.volume_group,
            physical_devices=[device.path for device in target.devices],
            user_confirmed=True,
            message=f"The LVM2 {binary_name} command is unavailable.",
        )
    if target.action == "move_pv":
        command = [binary, "--yes", "--atomic", target.devices[0].path, target.devices[1].path]
    elif target.action == "create":
        command = [binary, "--yes", target.volume_group, *(device.path for device in target.devices)]
    elif target.action == "add_pv":
        command = [binary, "--yes", target.volume_group, *(device.path for device in target.devices)]
    else:
        command = [binary, "--yes", target.volume_group, *(device.path for device in target.devices)]
    labels = {
        "create": "Create LVM volume group",
        "add_pv": "Add physical volumes to LVM volume group",
        "remove_pv": "Remove unused physical volumes from LVM volume group",
        "move_pv": "Atomically move allocated extents between LVM physical volumes",
    }
    success, message = _run_lvm_mutation(
        command,
        labels[target.action],
        PV_MOVE_TIMEOUT_SECONDS if target.action == "move_pv" else COMMAND_TIMEOUT_SECONDS,
    )
    if not success:
        if target.action == "move_pv":
            message += " Keep both PVs in place and inspect LVM move state before retrying or removing either device."
        return LVMVolumeGroupActionResponse(
            success=False,
            action=target.action,
            volume_group=target.volume_group,
            physical_devices=[device.path for device in target.devices],
            physical_volume_count=target.expected_pv_count,
            user_confirmed=True,
            message=message,
        )

    result_groups, group_error = _read_volume_group_rows()
    result_pvs, pv_error = _read_physical_volume_rows()
    matches = [row for row in result_groups or [] if row.get("vg_name") == target.volume_group]
    actual_count, count_partial = _lvm_integer(matches[0], "pv_count") if len(matches) == 1 else (None, True)
    result_members, member_error = _group_pv_records(result_pvs or [], target.volume_group)
    actual_identities = {identity for _, identity in result_members}
    verified = bool(
        not group_error
        and not pv_error
        and not member_error
        and len(matches) == 1
        and not count_partial
        and actual_count == target.expected_pv_count
        and len(result_members) == target.expected_pv_count
        and actual_identities == set(target.expected_pv_identities)
    )
    if verified and target.action == "move_pv":
        source_rows = [row for row, identity in result_members if identity == (target.devices[0].major, target.devices[0].minor)]
        destination_rows = [row for row, identity in result_members if identity == (target.devices[1].major, target.devices[1].minor)]
        source_allocated, source_partial = _lvm_integer(source_rows[0], "pv_pe_alloc_count") if len(source_rows) == 1 else (None, True)
        destination_allocated, destination_partial = _lvm_integer(destination_rows[0], "pv_pe_alloc_count") if len(destination_rows) == 1 else (None, True)
        move_active, move_error = _pvmove_in_progress(target.volume_group)
        verified = bool(
            not source_partial
            and not destination_partial
            and source_allocated == 0
            and destination_allocated == (target.destination_allocated_extents or 0) + (target.source_allocated_extents or 0)
            and move_error is None
            and move_active is False
        )
    if not verified:
        verification_message = (
            "The pvmove command returned, but completion and exact source/destination allocation counts could not be verified. Keep both PVs in place and inspect LVM state before retrying or removing either device."
            if target.action == "move_pv"
            else "The LVM command returned success, but the exact group membership could not be verified; inspect LVM before retrying."
        )
        return LVMVolumeGroupActionResponse(
            success=False,
            action=target.action,
            volume_group=target.volume_group,
            physical_devices=[device.path for device in target.devices],
            physical_volume_count=actual_count,
            user_confirmed=True,
            message=verification_message,
        )
    messages = {
        "create": "Created and verified the LVM volume group and its physical-volume members.",
        "add_pv": "Added and verified the blank physical-volume members in the existing LVM volume group.",
        "remove_pv": "Removed and verified only unused physical volumes; their LVM labels remain in place.",
        "move_pv": "Moved and verified all allocated extents from the source PV to the selected destination PV.",
    }
    return LVMVolumeGroupActionResponse(
        success=True,
        action=target.action,
        volume_group=target.volume_group,
        physical_devices=[device.path for device in target.devices],
        physical_volume_count=actual_count,
        source_allocated_extents=target.source_allocated_extents,
        destination_free_extents=target.destination_free_extents,
        move_bytes=target.move_bytes,
        user_confirmed=True,
        message=messages[target.action],
    )
