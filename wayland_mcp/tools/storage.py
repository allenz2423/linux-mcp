"""Read-only Linux block-device inventory from sysfs."""

from __future__ import annotations

import heapq
import json
import os
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    BlockDeviceInfo,
    BlockDeviceListResponse,
    LVMInventoryResponse,
    LVMLogicalVolumeInfo,
    LVMVolumeGroupInfo,
    StorageTopologyNode,
    StorageTopologyResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

SYS_CLASS_BLOCK = Path("/sys/class/block")
MAX_BLOCK_DEVICES = 1024
MAX_RETURNED_BLOCK_DEVICES = 200
DEVICE_NAME_RE = re.compile(r"^[A-Za-z0-9._+-]{1,255}$")
MAX_TOPOLOGY_DEVICES = 2048
MAX_RETURNED_TOPOLOGY_DEVICES = 500
MAX_RELATIONS_PER_DIRECTORY = 128
MAX_TOTAL_RELATIONS = 8192
MAX_SYSFS_TEXT_BYTES = 512
MAX_LVM_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_LVM_ROWS = 10_000
MAX_RETURNED_LVM_OBJECTS = 200
LVM_TIMEOUT_SECONDS = 15
LVM_NAME_RE = re.compile(r"^[A-Za-z0-9+_.-]{1,127}$")
LVM_LAYOUT_RE = re.compile(r"^[A-Za-z0-9_,.+-]{1,128}$")
LVM_UNSIGNED_RE = re.compile(r"^[0-9]{1,20}$")
StorageStackKind = Literal[
    "block_device", "partition", "loop", "device_mapper", "dm_crypt", "lvm_logical_volume", "multipath", "md_raid"
]


def _read_integer(path: Path) -> int | None:
    try:
        value = path.read_text(encoding="ascii", errors="strict").strip()
        number = int(value, 10)
        return number if number >= 0 else None
    except (OSError, UnicodeError, ValueError):
        return None


def _read_boolean(path: Path) -> bool | None:
    value = _read_integer(path)
    return bool(value) if value in {0, 1} else None


def _read_small_text(path: Path, maximum: int = MAX_SYSFS_TEXT_BYTES) -> str | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            return None
        return raw.decode("ascii", errors="strict").strip()
    except (OSError, UnicodeError):
        return None


def _read_small_integer(path: Path, maximum: int = 64) -> int | None:
    value = _read_small_text(path, maximum)
    if value is None or not value.isascii() or not value.isdigit():
        return None
    try:
        parsed = int(value, 10)
    except ValueError:
        return None
    return parsed if parsed <= 9_223_372_036_854_775_807 else None


def _relation_names(directory: Path) -> tuple[list[str], bool, bool]:
    names: list[str] = []
    truncated = False
    partial = False
    try:
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries, start=1):
                if index > MAX_RELATIONS_PER_DIRECTORY:
                    truncated = True
                    break
                if DEVICE_NAME_RE.fullmatch(entry.name):
                    names.append(entry.name)
    except FileNotFoundError:
        # Empty relation directories are optional on some block-device classes.
        pass
    except OSError:
        partial = True
    return sorted(set(names), key=str.casefold), truncated, partial


def _storage_stack_type(
    entry: Path,
) -> tuple[StorageStackKind, str | None, str | None, int | None, int | None, bool]:
    dm_directory = entry / "dm"
    if dm_directory.is_dir():
        dm_uuid = _read_small_text(dm_directory / "uuid", 256)
        mapped_name = _read_small_text(dm_directory / "name", 256)
        dm_type: StorageStackKind = "device_mapper"
        if dm_uuid:
            normalized_uuid = dm_uuid.upper()
            if normalized_uuid.startswith("CRYPT-"):
                dm_type = "dm_crypt"
            elif normalized_uuid.startswith("LVM-"):
                dm_type = "lvm_logical_volume"
            elif normalized_uuid.startswith("MPATH-"):
                dm_type = "multipath"
        if mapped_name is not None:
            mapped_name = "".join(character for character in mapped_name if character.isprintable())[:256].strip() or None
        return dm_type, mapped_name, None, None, None, dm_uuid is None or mapped_name is None

    md_directory = entry / "md"
    if md_directory.is_dir():
        level = _read_small_text(md_directory / "level", 64)
        if level is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", level):
            level = None
        raid_devices = _read_small_integer(md_directory / "raid_disks")
        degraded = _read_small_integer(md_directory / "degraded")
        incomplete = level is None or raid_devices is None or degraded is None
        return "md_raid", None, level, raid_devices, degraded, incomplete

    if (entry / "loop").is_dir():
        return "loop", None, None, None, None, False
    if (entry / "partition").is_file():
        return "partition", None, None, None, None, False
    return "block_device", None, None, None, None, False


def list_block_devices(query: str = "", limit: int = 100) -> BlockDeviceListResponse:
    if not sys.platform.startswith("linux"):
        return BlockDeviceListResponse(success=False, message="Block-device inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return BlockDeviceListResponse(success=False, message="Query must be text with at most 256 characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return BlockDeviceListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_BLOCK_DEVICES))
    if not SYS_CLASS_BLOCK.is_dir():
        return BlockDeviceListResponse(success=False, limit=limit, message="Linux sysfs block-device inventory is unavailable.")

    needle = query.strip().casefold()
    devices: list[BlockDeviceInfo] = []
    truncated = False
    try:
        names = heapq.nsmallest(MAX_BLOCK_DEVICES + 1, (item.name for item in SYS_CLASS_BLOCK.iterdir()), key=str.casefold)
    except OSError as exc:
        return BlockDeviceListResponse(success=False, limit=limit, message=f"Could not read sysfs block devices: {exc.strerror or 'read error'}.")

    truncated = len(names) > MAX_BLOCK_DEVICES
    for name in names[:MAX_BLOCK_DEVICES]:
        if not DEVICE_NAME_RE.fullmatch(name) or (needle and needle not in name.casefold()):
            continue
        entry = SYS_CLASS_BLOCK / name
        sectors = _read_integer(entry / "size")
        logical_block_size = _read_integer(entry / "queue" / "logical_block_size")
        devices.append(BlockDeviceInfo(
            name=name,
            size_bytes=sectors * 512 if sectors is not None else None,
            is_partition=(entry / "partition").is_file(),
            removable=_read_boolean(entry / "removable"),
            read_only=_read_boolean(entry / "ro"),
            rotational=_read_boolean(entry / "queue" / "rotational"),
            logical_block_size_bytes=logical_block_size,
        ))
    return BlockDeviceListResponse(
        success=True,
        total_devices=len(devices),
        returned_devices=min(len(devices), limit),
        devices=devices[:limit],
        limit=limit,
        truncated=truncated or len(devices) > limit,
        message="Capacity is derived from sysfs size values in 512-byte sectors; device identifiers, serial numbers, and health data are not included.",
    )


def list_storage_topology(query: str = "", limit: int = 100) -> StorageTopologyResponse:
    """Read active block-device layering and selected MD/device-mapper metadata from sysfs."""
    if not sys.platform.startswith("linux"):
        return StorageTopologyResponse(success=False, message="Storage topology inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return StorageTopologyResponse(success=False, message="Query must be text with at most 256 characters.")
    if isinstance(limit, bool) or not isinstance(limit, int):
        return StorageTopologyResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_TOPOLOGY_DEVICES))
    if not SYS_CLASS_BLOCK.is_dir():
        return StorageTopologyResponse(success=False, limit=limit, message="Linux sysfs block-device inventory is unavailable.")

    names: list[str] = []
    scan_truncated = False
    invalid_device_names = False
    try:
        with os.scandir(SYS_CLASS_BLOCK) as entries:
            for index, item in enumerate(entries, start=1):
                if index > MAX_TOPOLOGY_DEVICES:
                    scan_truncated = True
                    break
                if DEVICE_NAME_RE.fullmatch(item.name):
                    names.append(item.name)
                else:
                    invalid_device_names = True
    except OSError as exc:
        return StorageTopologyResponse(
            success=False,
            limit=limit,
            message=f"Could not scan sysfs block devices: {exc.strerror or 'read error'}.",
        )

    names.sort(key=str.casefold)
    known_names = set(names)
    nodes: list[StorageTopologyNode] = []
    partial = invalid_device_names
    total_relations = 0
    for name in sorted(known_names, key=str.casefold):
        entry = SYS_CLASS_BLOCK / name
        identity_before = _read_small_text(entry / "dev", 64)
        stack_type, mapped_name, raid_level, raid_devices, degraded, metadata_partial = _storage_stack_type(entry)
        raid_sync_action: str | None = None
        raid_sync_completed_sectors: int | None = None
        raid_sync_total_sectors: int | None = None
        raid_mismatch_count: int | None = None
        if stack_type == "md_raid":
            sync_action = _read_small_text(entry / "md" / "sync_action", 64)
            if sync_action is not None and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", sync_action):
                raid_sync_action = sync_action
            elif sync_action is not None:
                metadata_partial = True
            sync_completed = _read_small_text(entry / "md" / "sync_completed", 64)
            if sync_completed is not None and sync_completed != "none":
                completed_match = re.fullmatch(r"([0-9]+)\s*/\s*([0-9]+)", sync_completed)
                if completed_match:
                    completed_sectors = int(completed_match.group(1), 10)
                    total_sectors = int(completed_match.group(2), 10)
                    if (
                        completed_sectors <= total_sectors
                        and total_sectors <= 9_223_372_036_854_775_807
                    ):
                        raid_sync_completed_sectors = completed_sectors
                        raid_sync_total_sectors = total_sectors
                    else:
                        metadata_partial = True
                else:
                    metadata_partial = True
            mismatch_text = _read_small_text(entry / "md" / "mismatch_cnt", 64)
            if mismatch_text is not None and mismatch_text.isascii() and mismatch_text.isdigit():
                raid_mismatch_count = int(mismatch_text, 10)
                if raid_mismatch_count > 9_223_372_036_854_775_807:
                    raid_mismatch_count = None
                    metadata_partial = True
            elif mismatch_text is not None:
                metadata_partial = True
            if raid_sync_action is None:
                metadata_partial = True
        components, components_truncated, components_partial = _relation_names(entry / "slaves")
        holders, holders_truncated, holders_partial = _relation_names(entry / "holders")
        identity_after = _read_small_text(entry / "dev", 64)
        relation_partial = metadata_partial or components_partial or holders_partial
        if identity_before is None or identity_after != identity_before:
            components = []
            holders = []
            relation_partial = True
        unknown_relations = [relation for relation in (*components, *holders) if relation not in known_names]
        if unknown_relations:
            relation_partial = True
            components = [relation for relation in components if relation in known_names]
            holders = [relation for relation in holders if relation in known_names]

        remaining_relations = max(0, MAX_TOTAL_RELATIONS - total_relations)
        if len(components) + len(holders) > remaining_relations:
            allowed_components = min(len(components), remaining_relations)
            components = components[:allowed_components]
            holders = holders[:max(0, remaining_relations - allowed_components)]
            scan_truncated = True
        total_relations += len(components) + len(holders)
        scan_truncated |= components_truncated or holders_truncated
        partial |= relation_partial
        nodes.append(StorageTopologyNode(
            name=name,
            size_bytes=(sectors * 512) if (sectors := _read_small_integer(entry / "size")) is not None else None,
            stack_type=stack_type,
            mapped_name=mapped_name,
            component_devices=components,
            holder_devices=holders,
            raid_level=raid_level,
            raid_device_count=raid_devices,
            raid_degraded_count=degraded,
            raid_sync_action=raid_sync_action,
            raid_sync_completed_sectors=raid_sync_completed_sectors,
            raid_sync_total_sectors=raid_sync_total_sectors,
            raid_mismatch_count=raid_mismatch_count,
            relation_data_partial=relation_partial,
        ))

    needle = query.strip().casefold()
    selected = [
        node for node in nodes
        if not needle or needle in " ".join((
            node.name,
            node.mapped_name or "",
            node.stack_type,
            node.raid_level or "",
            node.raid_sync_action or "",
            *node.component_devices,
            *node.holder_devices,
        )).casefold()
    ]
    return StorageTopologyResponse(
        success=True,
        total_devices=len(selected),
        returned_devices=min(len(selected), limit),
        devices=selected[:limit],
        limit=limit,
        partial=partial,
        truncated=scan_truncated or len(selected) > limit,
        message=(
            "Device layering comes from sysfs slave/holder links. Device-mapper UUIDs, serial numbers, and loop backing-file paths are omitted."
        ),
    )


def lvm_inventory_available(env: dict[str, str] | None = None) -> bool:
    """Return whether both fixed LVM report commands are available."""
    if not sys.platform.startswith("linux"):
        return False
    child_env = env if env is not None else get_sanitized_env()
    return bool(find_session_binary("vgs", child_env) and find_session_binary("lvs", child_env))


def _lvm_report_rows(output: str, section: str) -> tuple[list[dict[str, object]] | None, bool]:
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return None, False
    if not isinstance(payload, dict) or not isinstance(payload.get("report"), list):
        return None, False

    rows: list[dict[str, object]] = []
    section_found = False
    truncated = False
    for report in payload["report"]:
        if not isinstance(report, dict) or section not in report:
            continue
        section_found = True
        section_rows = report[section]
        if not isinstance(section_rows, list):
            return None, False
        for row in section_rows:
            if not isinstance(row, dict):
                truncated = True
                continue
            if len(rows) >= MAX_LVM_ROWS:
                truncated = True
                break
            rows.append(row)
        if truncated and len(rows) >= MAX_LVM_ROWS:
            break
    return (rows, truncated) if section_found else (None, False)


def _lvm_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if LVM_NAME_RE.fullmatch(value) else None


def _lvm_optional_name(row: dict[str, object], field: str) -> tuple[str | None, bool]:
    if field not in row:
        return None, True
    raw = row[field]
    if raw is None or raw == "" or raw == "-" or raw == "unknown":
        return None, False
    value = _lvm_name(raw)
    return value, value is None


def _lvm_integer(row: dict[str, object], field: str) -> tuple[int | None, bool]:
    if field not in row:
        return None, True
    raw = row[field]
    if isinstance(raw, bool):
        return None, True
    if isinstance(raw, int):
        value = raw
    elif isinstance(raw, str) and LVM_UNSIGNED_RE.fullmatch(raw.strip()):
        try:
            value = int(raw.strip(), 10)
        except ValueError:
            return None, True
    else:
        return None, True
    if value < 0 or value > 9_223_372_036_854_775_807:
        return None, True
    return value, False


def _lvm_percent(row: dict[str, object], field: str) -> tuple[float | None, bool]:
    if field not in row:
        return None, True
    raw = row[field]
    if raw is None or raw == "" or raw == "-" or raw == "unknown":
        return None, False
    if not isinstance(raw, (str, int, float)) or isinstance(raw, bool):
        return None, True
    try:
        value = Decimal(str(raw).strip())
    except (InvalidOperation, ValueError):
        return None, True
    if not value.is_finite() or value < 0 or value > Decimal("1000000"):
        return None, True
    return float(value), False


def _run_lvm_report(
    executable: str,
    fields: tuple[str, ...],
    env: dict[str, str],
    section: str,
    *,
    extra_args: tuple[str, ...] = (),
) -> tuple[list[dict[str, object]] | None, bool, str | None]:
    command = [
        executable,
        *extra_args,
        "--readonly",
        "--reportformat", "json",
        "--units", "b",
        "--nosuffix",
        "--config", "report { compact_output=0 }",
        "--options", ",".join(fields),
    ]
    output, error, output_truncated = run_bounded_command(
        command,
        env,
        command_label="LVM report",
        timeout_seconds=LVM_TIMEOUT_SECONDS,
        max_output_bytes=MAX_LVM_OUTPUT_BYTES,
    )
    if output is None:
        if error and "timed out" in error:
            return None, output_truncated, "The read-only LVM report timed out."
        return None, output_truncated, "The read-only LVM report could not be completed; current-user access or LVM metadata may be unavailable."
    if output_truncated:
        return None, True, "The read-only LVM report exceeded its output limit."
    rows, rows_truncated = _lvm_report_rows(output, section)
    if rows is None:
        return None, False, "The read-only LVM command returned an unexpected report format."
    return rows, rows_truncated, None


def list_lvm_inventory(query: str = "", limit: int = 100) -> LVMInventoryResponse:
    """Read bounded volume-group and logical-volume metadata with LVM's read-only mode."""
    if not sys.platform.startswith("linux"):
        return LVMInventoryResponse(success=False, message="LVM inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return LVMInventoryResponse(success=False, message="Query must be text with at most 256 characters.")
    if isinstance(limit, bool) or not isinstance(limit, int):
        return LVMInventoryResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_LVM_OBJECTS))

    env = dict(get_sanitized_env())
    vgs = find_session_binary("vgs", env)
    lvs = find_session_binary("lvs", env)
    if not vgs or not lvs:
        return LVMInventoryResponse(
            success=False,
            limit=limit,
            message="Both the LVM2 vgs and lvs commands are required for this inventory.",
        )
    env["LANG"] = "C"
    env["LC_ALL"] = "C"

    group_rows, groups_truncated, error = _run_lvm_report(
        vgs,
        (
            "vg_name", "vg_size", "vg_free", "pv_count", "lv_count",
            "vg_extent_size", "vg_extent_count", "vg_free_count",
        ),
        env,
        "vg",
    )
    if group_rows is None:
        return LVMInventoryResponse(success=False, limit=limit, truncated=groups_truncated, message=error)
    volume_rows, volumes_truncated, error = _run_lvm_report(
        lvs,
        (
            "vg_name", "lv_name", "lv_size", "lv_layout", "pool_lv", "origin",
            "data_percent", "metadata_percent",
        ),
        env,
        "lv",
    )
    if volume_rows is None:
        return LVMInventoryResponse(success=False, limit=limit, truncated=volumes_truncated, message=error)

    partial = False
    volume_groups: list[LVMVolumeGroupInfo] = []
    for row in group_rows:
        name = _lvm_name(row.get("vg_name"))
        if name is None:
            partial = True
            continue
        size_bytes, size_partial = _lvm_integer(row, "vg_size")
        free_bytes, free_partial = _lvm_integer(row, "vg_free")
        pv_count, pv_partial = _lvm_integer(row, "pv_count")
        lv_count, lv_partial = _lvm_integer(row, "lv_count")
        extent_size, extent_size_partial = _lvm_integer(row, "vg_extent_size")
        extent_count, extent_count_partial = _lvm_integer(row, "vg_extent_count")
        free_extent_count, free_extent_partial = _lvm_integer(row, "vg_free_count")
        partial |= any((size_partial, free_partial, pv_partial, lv_partial, extent_size_partial, extent_count_partial, free_extent_partial))
        volume_groups.append(LVMVolumeGroupInfo(
            name=name,
            size_bytes=size_bytes,
            free_bytes=free_bytes,
            physical_volume_count=pv_count,
            logical_volume_count=lv_count,
            extent_size_bytes=extent_size,
            extent_count=extent_count,
            free_extent_count=free_extent_count,
        ))

    logical_volumes: list[LVMLogicalVolumeInfo] = []
    for row in volume_rows:
        vg_name = _lvm_name(row.get("vg_name"))
        name = _lvm_name(row.get("lv_name"))
        if vg_name is None or name is None:
            partial = True
            continue
        size_bytes, size_partial = _lvm_integer(row, "lv_size")
        layout_raw = row.get("lv_layout")
        if not isinstance(layout_raw, str):
            layout = None
            layout_partial = True
        else:
            layout_raw = layout_raw.strip()
            layout = layout_raw if layout_raw and LVM_LAYOUT_RE.fullmatch(layout_raw) else None
            layout_partial = bool(layout_raw and layout is None)
        pool, pool_partial = _lvm_optional_name(row, "pool_lv")
        origin, origin_partial = _lvm_optional_name(row, "origin")
        data_percent, data_partial = _lvm_percent(row, "data_percent")
        metadata_percent, metadata_partial = _lvm_percent(row, "metadata_percent")
        partial |= any((size_partial, layout_partial, pool_partial, origin_partial, data_partial, metadata_partial))
        logical_volumes.append(LVMLogicalVolumeInfo(
            volume_group=vg_name,
            name=name,
            size_bytes=size_bytes,
            layout=layout,
            pool=pool,
            origin=origin,
            data_percent=data_percent,
            metadata_percent=metadata_percent,
        ))

    needle = query.strip().casefold()
    if needle:
        volume_groups = [item for item in volume_groups if needle in item.name.casefold()]
        logical_volumes = [
            item for item in logical_volumes
            if any(needle in value.casefold() for value in (
                item.volume_group, item.name, item.layout or "", item.pool or "", item.origin or "",
            ))
        ]
    volume_groups.sort(key=lambda item: item.name.casefold())
    logical_volumes.sort(key=lambda item: (item.volume_group.casefold(), item.name.casefold()))

    truncated = groups_truncated or volumes_truncated
    return LVMInventoryResponse(
        success=True,
        total_volume_groups=len(volume_groups),
        returned_volume_groups=min(len(volume_groups), limit),
        volume_groups=volume_groups[:limit],
        total_logical_volumes=len(logical_volumes),
        returned_logical_volumes=min(len(logical_volumes), limit),
        logical_volumes=logical_volumes[:limit],
        limit=limit,
        partial=partial,
        truncated=truncated or len(volume_groups) > limit or len(logical_volumes) > limit,
        message=(
            "Read-only LVM metadata from vgs and lvs. Physical-volume device paths and UUIDs are omitted. "
            "The separate reports are not atomic. LVM --readonly does not communicate with the device-mapper driver, "
            "so active/in-use state is not reported."
        ),
    )
