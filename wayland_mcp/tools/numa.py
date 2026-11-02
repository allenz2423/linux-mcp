"""Bounded read-only NUMA topology and per-node memory snapshots from sysfs."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from wayland_mcp.models import NUMANodeDistance, NUMANodeInfo, NUMANodeListResponse

SYS_NODE_ROOT = Path("/sys/devices/system/node")
NODE_DIRECTORY_RE = re.compile(r"^node([0-9]+)$")
ID_RANGE_RE = re.compile(r"^([0-9]+)(?:-([0-9]+))?$")
MEMINFO_RE = re.compile(r"^Node\s+([0-9]+)\s+(MemTotal|MemFree):\s*([0-9]+)\s+kB\s*$")

MAX_NODE_ID = 65_535
MAX_NODES_SCAN = 1024
MAX_RETURNED_NODES = 128
MAX_CPU_ID = 65_535
MAX_CPU_MEMBERSHIPS_PER_NODE = 16_384
MAX_RETURNED_CPU_MEMBERSHIPS = 16_384
MAX_RETURNED_DISTANCE_ENTRIES = 16_384
MAX_SYSFS_TEXT_BYTES = 64 * 1024
MAX_MEMORY_BYTES = (1 << 63) - 1
MAX_DISTANCE = 65_535


def _read_text(path: Path, limit: int = MAX_SYSFS_TEXT_BYTES) -> str | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError:
        return None
    if len(raw) > limit:
        return None
    try:
        return raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        return None


def _parse_id_list(value: str, *, maximum_id: int, maximum_count: int) -> set[int] | None:
    value = value.strip()
    if not value:
        return set()
    result: set[int] = set()
    for raw_chunk in value.split(","):
        chunk = raw_chunk.strip()
        match = ID_RANGE_RE.fullmatch(chunk)
        if match is None:
            return None
        first_text, last_text = match.groups()
        if len(first_text) > 5 or (last_text is not None and len(last_text) > 5):
            return None
        first = int(first_text, 10)
        last = int(last_text, 10) if last_text is not None else first
        if first > maximum_id or last > maximum_id or last < first:
            return None
        if last - first + 1 > maximum_count:
            return None
        result.update(range(first, last + 1))
        if len(result) > maximum_count:
            return None
    return result


def _scan_node_directories() -> tuple[list[tuple[int, Path]], bool]:
    nodes: list[tuple[int, Path]] = []
    truncated = False
    try:
        with os.scandir(SYS_NODE_ROOT) as entries:
            for entry in entries:
                match = NODE_DIRECTORY_RE.fullmatch(entry.name)
                if match is None:
                    continue
                raw_id = match.group(1)
                if len(raw_id) > 5:
                    truncated = True
                    continue
                node_id = int(raw_id, 10)
                if node_id > MAX_NODE_ID:
                    truncated = True
                    continue
                if len(nodes) >= MAX_NODES_SCAN:
                    truncated = True
                    break
                try:
                    if entry.is_dir(follow_symlinks=True):
                        nodes.append((node_id, SYS_NODE_ROOT / entry.name))
                except OSError:
                    continue
    except OSError:
        return [], False
    nodes.sort(key=lambda item: item[0])
    return nodes, truncated


def _online_node_ids() -> set[int] | None:
    value = _read_text(SYS_NODE_ROOT / "online", 16 * 1024)
    if value is None:
        return None
    return _parse_id_list(
        value,
        maximum_id=MAX_NODE_ID,
        maximum_count=MAX_NODES_SCAN,
    )


def _cpu_ids(value: str) -> set[int] | None:
    return _parse_id_list(
        value,
        maximum_id=MAX_CPU_ID,
        maximum_count=MAX_CPU_MEMBERSHIPS_PER_NODE,
    )


def _node_memory_bytes(path: Path, node_id: int) -> tuple[int | None, int | None]:
    value = _read_text(path)
    if value is None:
        return None, None
    values: dict[str, int] = {}
    for line in value.splitlines():
        match = MEMINFO_RE.fullmatch(line)
        if match is None:
            continue
        raw_node_id, field, raw_kib = match.groups()
        if len(raw_node_id) > 5 or len(raw_kib) > 20:
            continue
        if int(raw_node_id, 10) != node_id:
            continue
        kib = int(raw_kib, 10)
        if kib > MAX_MEMORY_BYTES // 1024:
            continue
        values[field] = kib * 1024
    return values.get("MemTotal"), values.get("MemFree")


def _node_distances(
    path: Path,
    online_node_ids: set[int],
) -> list[NUMANodeDistance] | None:
    value = _read_text(path, 16 * 1024)
    if value is None:
        return None
    raw_distances = value.split()
    targets = sorted(online_node_ids)
    if len(raw_distances) != len(targets):
        return None
    result: list[NUMANodeDistance] = []
    for target_node_id, raw_distance in zip(targets, raw_distances):
        if len(raw_distance) > 5 or not raw_distance.isdecimal():
            return None
        distance = int(raw_distance, 10)
        if distance > MAX_DISTANCE:
            return None
        result.append(NUMANodeDistance(target_node_id=target_node_id, distance=distance))
    return result


def list_numa_nodes(limit: int = 128) -> NUMANodeListResponse:
    if not sys.platform.startswith("linux"):
        return NUMANodeListResponse(success=False, message="NUMA node inventory is available only on Linux.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return NUMANodeListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_NODES))

    node_directories, scan_truncated = _scan_node_directories()
    if not node_directories:
        return NUMANodeListResponse(
            success=False,
            limit=limit,
            message="Linux NUMA node sysfs inventory is unavailable.",
        )

    online_ids = _online_node_ids()
    returned_nodes: list[NUMANodeInfo] = []
    returned_cpu_memberships = 0
    returned_distance_entries = 0
    partial = online_ids is None
    cpu_ids_truncated = False
    distances_truncated = False

    for node_id, directory in node_directories[:limit]:
        cpu_text = _read_text(directory / "cpulist")
        parsed_cpu_ids = _cpu_ids(cpu_text) if cpu_text is not None else None
        if parsed_cpu_ids is None:
            partial = True
            cpu_ids: list[int] = []
            cpu_count = None
            node_cpu_ids_truncated = False
        else:
            cpu_count = len(parsed_cpu_ids)
            remaining_budget = max(0, MAX_RETURNED_CPU_MEMBERSHIPS - returned_cpu_memberships)
            cpu_ids = sorted(parsed_cpu_ids)[:remaining_budget]
            returned_cpu_memberships += len(cpu_ids)
            node_cpu_ids_truncated = len(cpu_ids) < cpu_count
            cpu_ids_truncated = cpu_ids_truncated or node_cpu_ids_truncated

        total_bytes, free_bytes = _node_memory_bytes(directory / "meminfo", node_id)
        if total_bytes is None or free_bytes is None:
            partial = True

        online = node_id in online_ids if online_ids is not None else None
        distances: list[NUMANodeDistance] = []
        node_distances_truncated = False
        if online is True and online_ids is not None:
            parsed_distances = _node_distances(directory / "distance", online_ids)
            if parsed_distances is None:
                partial = True
            else:
                remaining_distance_budget = max(
                    0,
                    MAX_RETURNED_DISTANCE_ENTRIES - returned_distance_entries,
                )
                distances = parsed_distances[:remaining_distance_budget]
                returned_distance_entries += len(distances)
                node_distances_truncated = len(distances) < len(parsed_distances)
                distances_truncated = distances_truncated or node_distances_truncated

        returned_nodes.append(NUMANodeInfo(
            node_id=node_id,
            online=online,
            cpu_ids=cpu_ids,
            cpu_count=cpu_count,
            cpu_ids_truncated=node_cpu_ids_truncated,
            memory_total_bytes=total_bytes,
            memory_free_bytes=free_bytes,
            distances_to_online_nodes=distances,
            distances_truncated=node_distances_truncated,
        ))

    truncated = (
        scan_truncated
        or len(node_directories) > limit
        or cpu_ids_truncated
        or distances_truncated
    )
    messages: list[str] = []
    if scan_truncated:
        messages.append("The NUMA node scan reached its safety limit or found out-of-range node IDs.")
    if len(node_directories) > limit:
        messages.append("More NUMA nodes exist than the requested result limit.")
    if cpu_ids_truncated:
        messages.append("CPU membership IDs were shortened by the response-size cap.")
    if distances_truncated:
        messages.append("NUMA distance entries were shortened by the response-size cap.")
    if partial:
        messages.append("Some online-state, CPU, memory, or distance fields were unavailable or malformed.")

    return NUMANodeListResponse(
        success=True,
        node_count=len(node_directories),
        online_node_count=len(online_ids) if online_ids is not None else None,
        returned_nodes=len(returned_nodes),
        nodes=returned_nodes,
        limit=limit,
        partial=partial,
        truncated=truncated,
        message=" ".join(messages) or None,
    )
