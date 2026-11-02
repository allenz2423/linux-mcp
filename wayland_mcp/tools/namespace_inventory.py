"""Bounded read-only inventory of visible process namespace references."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from wayland_mcp.models import (
    NamespaceInstanceInfo,
    NamespaceInventoryResponse,
    NamespaceTypeInfo,
)
from wayland_mcp.tools.process_context import (
    MAX_PID,
    MAX_STAT_BYTES,
    NAMESPACE_NAMES,
    _parse_namespace_link_target,
)

PROC = Path("/proc")
MAX_NAMESPACE_PROCESS_SCAN = 5000
MAX_NAMESPACE_INSTANCES_PER_TYPE = 256


def _process_start_ticks(pid: int) -> int | None:
    try:
        with (PROC / str(pid) / "stat").open("rb") as stream:
            raw = stream.read(MAX_STAT_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_STAT_BYTES:
        return None
    content = raw.decode("utf-8", errors="replace")
    closing_paren = content.rfind(")")
    if closing_paren < 0:
        return None
    prefix = content[:closing_paren].split()
    fields = content[closing_paren + 1 :].split()
    if not prefix or prefix[0] != str(pid) or len(fields) <= 19:
        return None
    raw_start_ticks = fields[19]
    if not raw_start_ticks.isascii() or not raw_start_ticks.isdecimal():
        return None
    start_ticks = int(raw_start_ticks, 10)
    return start_ticks if 0 <= start_ticks <= 2**64 - 1 else None


def _supported_namespace_types() -> tuple[dict[str, bool], dict[str, bool]]:
    supported: dict[str, bool] = {}
    partial: dict[str, bool] = {}
    for name in NAMESPACE_NAMES:
        try:
            target = str((PROC / "self" / "ns" / name).readlink())
        except FileNotFoundError:
            supported[name] = False
            partial[name] = False
            continue
        except OSError:
            supported[name] = False
            partial[name] = True
            continue
        supported[name] = True
        try:
            _parse_namespace_link_target(name, target)
        except ValueError:
            partial[name] = True
        else:
            partial[name] = False
    return supported, partial


def list_namespace_inventory() -> NamespaceInventoryResponse:
    """Group visible procfs process entries by namespace type and inode."""
    if not sys.platform.startswith("linux"):
        return NamespaceInventoryResponse(
            success=False,
            message="Linux namespace inventory is available only on Linux.",
        )
    pids: list[int] = []
    scan_truncated = False
    try:
        with os.scandir(PROC) as entries:
            for entry in entries:
                name = entry.name
                if not name.isascii() or not name.isdecimal():
                    continue
                pid = int(name, 10)
                if not 0 < pid <= MAX_PID:
                    continue
                if len(pids) >= MAX_NAMESPACE_PROCESS_SCAN:
                    scan_truncated = True
                    break
                pids.append(pid)
    except OSError as exc:
        return NamespaceInventoryResponse(
            success=False,
            message=f"Could not enumerate procfs: {exc.strerror or 'read error'}.",
        )

    scan_pids = sorted(pids)
    truncated = scan_truncated
    supported, type_partial = _supported_namespace_types()
    if truncated:
        for name in NAMESPACE_NAMES:
            if supported[name]:
                type_partial[name] = True

    # Store at most a fixed number of namespace inodes for each type. Existing
    # groups continue accumulating counts after the output cap is reached.
    groups: dict[str, dict[int, dict[str, int]]] = {
        name: {} for name in NAMESPACE_NAMES
    }
    type_truncated = {name: False for name in NAMESPACE_NAMES}
    skipped_processes = 0
    any_partial = truncated or any(type_partial.values())

    for pid in scan_pids:
        start_before = _process_start_ticks(pid)
        if start_before is None:
            skipped_processes += 1
            any_partial = True
            for name in NAMESPACE_NAMES:
                if supported[name]:
                    type_partial[name] = True
            continue

        observed: dict[str, int] = {}
        process_incomplete = False
        for name in NAMESPACE_NAMES:
            if not supported[name]:
                continue
            try:
                target = str((PROC / str(pid) / "ns" / name).readlink())
            except OSError:
                process_incomplete = True
                type_partial[name] = True
                continue
            try:
                inode = _parse_namespace_link_target(name, target)
            except ValueError:
                process_incomplete = True
                type_partial[name] = True
                continue
            if inode is not None:
                observed[name] = inode

        start_after = _process_start_ticks(pid)
        if start_after is None or start_after != start_before or process_incomplete:
            skipped_processes += 1
            any_partial = True
            for name in NAMESPACE_NAMES:
                if supported[name]:
                    type_partial[name] = True
            continue

        for name, inode in observed.items():
            type_groups = groups[name]
            group = type_groups.get(inode)
            if group is None:
                if len(type_groups) >= MAX_NAMESPACE_INSTANCES_PER_TYPE:
                    type_truncated[name] = True
                    type_partial[name] = True
                    any_partial = True
                    continue
                group = {"reference_count": 0, "representative_pid": pid}
                type_groups[inode] = group
            group["reference_count"] += 1

    namespace_types: list[NamespaceTypeInfo] = []
    for name in NAMESPACE_NAMES:
        type_groups = groups[name]
        ordered = sorted(
            type_groups.items(),
            key=lambda item: (-item[1]["reference_count"], item[0]),
        )
        namespace_types.append(
            NamespaceTypeInfo(
                namespace_type=name,
                supported=supported[name],
                available=bool(type_groups),
                namespace_count=len(ordered),
                namespaces=[
                    NamespaceInstanceInfo(
                        namespace_inode=inode,
                        reference_count=group["reference_count"],
                        representative_pid=group["representative_pid"],
                    )
                    for inode, group in ordered
                ],
                truncated=type_truncated[name],
                partial=type_partial[name],
            )
        )

    return NamespaceInventoryResponse(
        success=True,
        scanned_processes=len(scan_pids),
        skipped_processes=skipped_processes,
        scan_limit=MAX_NAMESPACE_PROCESS_SCAN,
        namespace_types=namespace_types,
        truncated=truncated or any(type_truncated.values()),
        partial=any_partial or any(type_partial.values()),
        message=(
            "Counts cover accessible, stable PID entries from this procfs view. "
            "The snapshot is not atomic; process visibility may be restricted, "
            "and child namespace entries describe targets for future children."
        ),
    )
