"""Read-only Linux host, process, resource, and filesystem inspection."""

from __future__ import annotations

import hashlib
import os
import platform
import pwd
import re
import socket
import sys
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    FilesystemInfo,
    FilesystemListResponse,
    LinuxSystemInfoResponse,
    ProcessDetailResponse,
    ProcessInfo,
    ProcessListResponse,
    ProcessTreeNode,
    ProcessTreeResponse,
    ResourceUsageResponse,
)

PROC = Path("/proc")
MAX_PROCESS_SCAN = 10_000
MAX_PROCESS_RESULTS = 200
MAX_PROCESS_TREE_RESULTS = 500
MAX_FILESYSTEM_RESULTS = 200
PSEUDO_FILESYSTEMS = {
    "autofs", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts",
    "devtmpfs", "fusectl", "hugetlbfs", "mqueue", "proc", "pstore", "securityfs",
    "sysfs", "tracefs",
}


def _read_text(path: Path, max_bytes: int = 128 * 1024) -> str:
    with path.open("rb") as stream:
        return stream.read(max_bytes).decode("utf-8", errors="replace")


def _read_uptime() -> float | None:
    try:
        value = _read_text(PROC / "uptime", 128).split()[0]
        uptime = float(value)
        return uptime if uptime >= 0 else None
    except (OSError, ValueError, IndexError):
        return None


def _read_os_release() -> dict[str, str]:
    for path in (Path("/etc/os-release"), Path("/usr/lib/os-release")):
        try:
            content = _read_text(path, 64 * 1024)
        except OSError:
            continue
        values: dict[str, str] = {}
        for line in content.splitlines():
            key, separator, raw_value = line.partition("=")
            if not separator or not re.fullmatch(r"[A-Z0-9_]+", key):
                continue
            raw_value = raw_value.strip()
            if raw_value.startswith(('"', "'")):
                quote = raw_value[0]
                if raw_value.endswith(quote) and len(raw_value) >= 2:
                    raw_value = raw_value[1:-1]
            values[key] = raw_value
        return values
    return {}


def _detect_init_system() -> str | None:
    try:
        comm = _read_text(PROC / "1" / "comm", 256).strip().lower()
    except OSError:
        comm = ""
    try:
        executable = (PROC / "1" / "exe").resolve(strict=True).name.lower()
    except OSError:
        executable = ""
    identity = f"{comm} {executable}"
    for candidate in ("systemd", "openrc", "runit", "s6-svscan", "busybox", "tini", "dumb-init"):
        if candidate in identity:
            return candidate
    return comm or executable or None


def get_linux_system_info() -> LinuxSystemInfoResponse:
    if not sys.platform.startswith("linux"):
        return LinuxSystemInfoResponse(success=False, message="Host inspection is available only on Linux.")

    release = _read_os_release()
    return LinuxSystemInfoResponse(
        success=True,
        hostname=socket.gethostname(),
        distribution=release.get("PRETTY_NAME") or release.get("NAME"),
        distribution_id=release.get("ID"),
        distribution_version=release.get("VERSION_ID"),
        kernel_release=platform.release(),
        architecture=platform.machine(),
        init_system=_detect_init_system(),
        uptime_seconds=_read_uptime(),
        message=None if release else "Distribution details were unavailable from os-release.",
    )


def _read_meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        content = _read_text(PROC / "meminfo", 64 * 1024)
    except OSError:
        return values
    for line in content.splitlines():
        key, separator, raw_value = line.partition(":")
        if not separator:
            continue
        parts = raw_value.split()
        if not parts:
            continue
        try:
            amount = int(parts[0])
        except ValueError:
            continue
        if len(parts) > 1 and parts[1].lower() == "kb":
            amount *= 1024
        values[key] = amount
    return values


def get_resource_usage() -> ResourceUsageResponse:
    if not sys.platform.startswith("linux"):
        return ResourceUsageResponse(success=False, message="Resource inspection is available only on Linux.")

    memory = _read_meminfo()
    available = memory.get("MemAvailable")
    if available is None and "MemFree" in memory:
        available = memory["MemFree"] + memory.get("Buffers", 0) + memory.get("Cached", 0)
    total = memory.get("MemTotal")
    swap_total = memory.get("SwapTotal")
    swap_free = memory.get("SwapFree")
    load_average: list[float] = []
    try:
        load_average = [float(value) for value in _read_text(PROC / "loadavg", 256).split()[:3]]
    except (OSError, ValueError):
        load_average = []

    return ResourceUsageResponse(
        success=bool(memory or load_average),
        logical_cpu_count=os.cpu_count(),
        load_average_1m=load_average[0] if len(load_average) > 0 else None,
        load_average_5m=load_average[1] if len(load_average) > 1 else None,
        load_average_15m=load_average[2] if len(load_average) > 2 else None,
        memory_total_bytes=total,
        memory_available_bytes=available,
        memory_used_bytes=max(0, total - available) if total is not None and available is not None else None,
        swap_total_bytes=swap_total,
        swap_free_bytes=swap_free,
        uptime_seconds=_read_uptime(),
        message=None if memory or load_average else "Linux procfs memory and load data were unavailable.",
    )


def _status_bytes(value: str | None) -> int | None:
    if not value:
        return None
    parts = value.split()
    try:
        amount = int(parts[0])
    except (ValueError, IndexError):
        return None
    if len(parts) > 1 and parts[1].lower() in {"kb", "kib"}:
        amount *= 1024
    return amount


def _process_info(pid: int) -> ProcessInfo | None:
    try:
        status = _read_text(PROC / str(pid) / "status", 128 * 1024)
    except (OSError, ValueError):
        return None

    fields: dict[str, str] = {}
    wanted = {"Name", "State", "PPid", "Uid", "VmRSS", "VmSize", "Threads"}
    for line in status.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in wanted:
            fields[key] = value.strip()

    def _int_field(key: str, index: int = 0) -> int | None:
        parts = fields.get(key, "").split()
        try:
            return int(parts[index])
        except (ValueError, IndexError):
            return None

    uid = _int_field("Uid")
    username: str | None = None
    if uid is not None:
        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            username = str(uid)

    return ProcessInfo(
        pid=pid,
        parent_pid=_int_field("PPid"),
        name=fields.get("Name", "")[:256],
        state=fields.get("State", "")[:64] or None,
        uid=uid,
        username=username,
        thread_count=_int_field("Threads"),
        resident_memory_bytes=_status_bytes(fields.get("VmRSS")),
        virtual_memory_bytes=_status_bytes(fields.get("VmSize")),
    )


def _process_stat_identity(pid: int) -> tuple[int, int] | None:
    """Read the parent PID and start-time fields despite spaces or ')' in comm."""
    try:
        stat = _read_text(PROC / str(pid) / "stat", 8192)
    except (OSError, ValueError):
        return None
    closing_paren = stat.rfind(")")
    if closing_paren < 0:
        return None
    prefix = stat[:closing_paren].split()
    fields = stat[closing_paren + 1:].split()
    if not prefix or prefix[0] != str(pid) or len(fields) <= 19:
        return None
    try:
        parent_pid = int(fields[1], 10)
        start_ticks = int(fields[19], 10)
    except ValueError:
        return None
    if parent_pid < 0 or start_ticks < 0:
        return None
    return parent_pid, start_ticks


def _process_start_ticks(pid: int) -> int | None:
    identity = _process_stat_identity(pid)
    return identity[1] if identity is not None else None


def _process_instance_token(pid: int, process: ProcessInfo, start_ticks: int) -> str | None:
    if process.uid is None:
        return None
    identity = f"{pid}\0{process.uid}\0{process.name}\0{start_ticks}".encode("utf-8", errors="replace")
    return hashlib.sha256(identity).hexdigest()


def _stable_process_info(
    pid: int,
    expected_start_ticks: int | None = None,
) -> tuple[ProcessInfo, int] | None:
    start_before = _process_start_ticks(pid)
    if start_before is None or (expected_start_ticks is not None and start_before != expected_start_ticks):
        return None
    process = _process_info(pid)
    start_after = _process_start_ticks(pid)
    if process is None or start_before != start_after:
        return None
    return process, start_before


def get_process_detail(pid: int) -> ProcessDetailResponse:
    if not sys.platform.startswith("linux"):
        return ProcessDetailResponse(success=False, message="Process inspection is available only on Linux.")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or pid > 2**31 - 1:
        return ProcessDetailResponse(success=False, message="PID must be a positive Linux process ID.")
    stable = _stable_process_info(pid)
    if stable is None:
        return ProcessDetailResponse(success=False, message="The process no longer exists or its status is not readable.")
    process, start_ticks = stable
    identity_token = _process_instance_token(pid, process, start_ticks)
    if identity_token is None:
        return ProcessDetailResponse(success=False, message="A stable process identity token could not be created.")
    return ProcessDetailResponse(success=True, process=process, identity_token=identity_token)


def get_process_tree(
    root_pid: int = 1,
    max_depth: int = 8,
    limit: int = 200,
) -> ProcessTreeResponse:
    """Return a bounded process subtree rooted at one exact PID."""
    if not sys.platform.startswith("linux"):
        return ProcessTreeResponse(success=False, message="Process trees are available only on Linux.")
    if not isinstance(root_pid, int) or isinstance(root_pid, bool) or root_pid <= 0 or root_pid > 2**31 - 1:
        return ProcessTreeResponse(success=False, message="root_pid must be a positive Linux process ID.")
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 0:
        return ProcessTreeResponse(success=False, root_pid=root_pid, message="max_depth must be a non-negative integer.")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return ProcessTreeResponse(success=False, root_pid=root_pid, message="limit must be a positive integer.")
    max_depth = min(max_depth, 64)
    limit = min(limit, MAX_PROCESS_TREE_RESULTS)

    try:
        pids = sorted(
            int(entry.name) for entry in PROC.iterdir()
            if entry.name.isdecimal() and int(entry.name) <= 2**31 - 1
        )
    except OSError as exc:
        return ProcessTreeResponse(
            success=False,
            root_pid=root_pid,
            max_depth=max_depth,
            limit=limit,
            message=f"Could not enumerate procfs: {exc.strerror or 'read error'}.",
        )

    scan_pids = pids[:MAX_PROCESS_SCAN]
    scan_cap_reached = len(pids) > len(scan_pids)
    if root_pid not in scan_pids:
        scan_pids.append(root_pid)

    process_stat: dict[int, tuple[int, int]] = {}
    skipped = 0
    for pid in scan_pids:
        identity = _process_stat_identity(pid)
        if identity is None:
            skipped += 1
            continue
        process_stat[pid] = identity

    root_identity = process_stat.get(root_pid)
    if root_identity is None:
        return ProcessTreeResponse(
            success=False,
            root_pid=root_pid,
            max_depth=max_depth,
            limit=limit,
            scan_cap_reached=scan_cap_reached,
            skipped_processes=skipped,
            message="The root process no longer exists or its status is not readable.",
        )

    children: dict[int, list[int]] = {}
    for pid, (parent_pid, _start_ticks) in process_stat.items():
        if pid != root_pid:
            children.setdefault(parent_pid, []).append(pid)
    for siblings in children.values():
        siblings.sort()

    ordered: list[tuple[int, int]] = []
    pending = [(root_pid, 0)]
    visited: set[int] = set()
    depth_truncated = False
    while pending:
        pid, depth = pending.pop()
        if pid in visited:
            continue
        visited.add(pid)
        ordered.append((pid, depth))
        descendants = [child for child in children.get(pid, ()) if child not in visited]
        if depth >= max_depth:
            depth_truncated = depth_truncated or bool(descendants)
            continue
        pending.extend((child, depth + 1) for child in reversed(descendants))

    selected = ordered[:limit]
    nodes: list[ProcessTreeNode] = []
    skipped_metadata = 0
    for pid, depth in selected:
        stable = _stable_process_info(pid, expected_start_ticks=process_stat[pid][1])
        if stable is None:
            skipped_metadata += 1
            continue
        nodes.append(ProcessTreeNode(**stable[0].model_dump(), depth=depth))
    if not nodes or nodes[0].pid != root_pid:
        return ProcessTreeResponse(
            success=False,
            root_pid=root_pid,
            max_depth=max_depth,
            limit=limit,
            scan_cap_reached=scan_cap_reached,
            skipped_processes=skipped + skipped_metadata,
            message="The root process changed or became unreadable while the tree was being assembled.",
        )
    result_truncated = len(ordered) > limit
    skipped += skipped_metadata
    truncated = result_truncated or depth_truncated or scan_cap_reached or skipped > 0
    messages: list[str] = []
    if depth_truncated:
        messages.append(f"Descendants deeper than max_depth={max_depth} were omitted.")
    if result_truncated:
        messages.append(f"Tree results capped at {limit} processes.")
    if scan_cap_reached:
        messages.append(f"Procfs scan capped at {MAX_PROCESS_SCAN} processes; some descendants may be absent.")
    if skipped:
        messages.append(f"{skipped} process entries disappeared or were unreadable during observation.")
    return ProcessTreeResponse(
        success=True,
        root_pid=root_pid,
        total_processes=len(ordered),
        returned_processes=len(nodes),
        nodes=nodes,
        max_depth=max_depth,
        limit=limit,
        truncated=truncated,
        scan_cap_reached=scan_cap_reached,
        skipped_processes=skipped,
        message=" ".join(messages) or None,
    )


def list_processes(
    query: str = "",
    limit: int = 50,
    sort_by: Literal["pid", "memory"] = "pid",
) -> ProcessListResponse:
    if not sys.platform.startswith("linux"):
        return ProcessListResponse(success=False, message="Process inspection is available only on Linux.")
    if not isinstance(query, str) or len(query) > 128:
        return ProcessListResponse(success=False, message="Query must be text with at most 128 characters.")
    if sort_by not in {"pid", "memory"}:
        return ProcessListResponse(success=False, message="sort_by must be 'pid' or 'memory'.")
    limit = max(1, min(int(limit), MAX_PROCESS_RESULTS))
    query_key = query.strip().casefold()
    try:
        pids = sorted(
            int(entry.name) for entry in PROC.iterdir()
            if entry.name.isdecimal() and int(entry.name) <= 2**31 - 1
        )
    except OSError as exc:
        return ProcessListResponse(success=False, limit=limit, sort_by=sort_by, message=f"Could not enumerate procfs: {exc.strerror or 'read error'}.")

    scan_pids = pids[:MAX_PROCESS_SCAN]
    processes: list[ProcessInfo] = []
    skipped = 0
    for pid in scan_pids:
        process = _process_info(pid)
        if process is None:
            skipped += 1
            continue
        if query_key and query_key not in process.name.casefold():
            continue
        processes.append(process)

    if sort_by == "memory":
        processes.sort(key=lambda item: (item.resident_memory_bytes or 0, -item.pid), reverse=True)
    else:
        processes.sort(key=lambda item: item.pid)

    total_matches = len(processes)
    truncated = total_matches > limit or len(pids) > len(scan_pids)
    selected = processes[:limit]
    messages: list[str] = []
    if len(pids) > len(scan_pids):
        messages.append(f"Procfs scan capped at {MAX_PROCESS_SCAN} processes.")
    if skipped:
        messages.append(f"{skipped} process entries disappeared or were unreadable during observation.")
    return ProcessListResponse(
        success=True,
        total_matches=total_matches,
        returned_processes=len(selected),
        processes=selected,
        limit=limit,
        sort_by=sort_by,
        truncated=truncated,
        skipped_processes=skipped,
        message=" ".join(messages) or None,
    )


def _unescape_mount_field(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _read_mounts() -> list[tuple[str, str]]:
    try:
        content = _read_text(PROC / "self" / "mounts", 2 * 1024 * 1024)
    except OSError:
        return []
    mounts: dict[str, str] = {}
    for line in content.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        mount_point = _unescape_mount_field(fields[1])
        filesystem_type = fields[2]
        if not mount_point.startswith("/") or filesystem_type in PSEUDO_FILESYSTEMS:
            continue
        if filesystem_type == "tmpfs" and mount_point.startswith(("/run/", "/dev/")):
            continue
        mounts[mount_point] = filesystem_type
    return sorted(mounts.items(), key=lambda item: (item[0] != "/", item[0]))


def _filesystem_info(mount_point: str, filesystem_type: str) -> FilesystemInfo | None:
    try:
        stats = os.statvfs(mount_point)
        unit = stats.f_frsize or stats.f_bsize
        total = stats.f_blocks * unit
        free = stats.f_bfree * unit
        available = stats.f_bavail * unit
    except OSError:
        return None
    used = max(0, total - free)
    used_percent = (used / total * 100) if total > 0 else 0.0
    return FilesystemInfo(
        mount_point=mount_point,
        filesystem_type=filesystem_type,
        total_bytes=total,
        used_bytes=used,
        free_bytes=free,
        available_bytes=available,
        used_percent=round(used_percent, 2),
    )


def list_filesystems(query: str = "", limit: int = 100) -> FilesystemListResponse:
    if not sys.platform.startswith("linux"):
        return FilesystemListResponse(success=False, message="Filesystem inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return FilesystemListResponse(success=False, message="Query must be text with at most 256 characters.")
    limit = max(1, min(int(limit), MAX_FILESYSTEM_RESULTS))
    query_key = query.strip().casefold()
    mounts = _read_mounts()
    if not mounts:
        return FilesystemListResponse(success=False, limit=limit, message="Could not read Linux mount information from procfs.")

    filesystems: list[FilesystemInfo] = []
    for mount_point, filesystem_type in mounts:
        if query_key and query_key not in mount_point.casefold() and query_key not in filesystem_type.casefold():
            continue
        info = _filesystem_info(mount_point, filesystem_type)
        if info is not None:
            filesystems.append(info)

    return FilesystemListResponse(
        success=True,
        total_filesystems=len(filesystems),
        returned_filesystems=min(len(filesystems), limit),
        filesystems=filesystems[:limit],
        limit=limit,
        truncated=len(filesystems) > limit,
        message=None if filesystems else "No matching mounted filesystems were readable.",
    )
