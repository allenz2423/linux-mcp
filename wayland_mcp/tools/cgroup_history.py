"""Bounded cgroup-v2 CPU and resource history for explicit Linux PIDs."""

from __future__ import annotations

import asyncio
import math
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from wayland_mcp.models import (
    ProcessCgroupHistory,
    ProcessCgroupHistoryResponse,
    ProcessCgroupHistorySample,
    ProcessCgroupV2Resources,
)
from wayland_mcp.tools.process_context import (
    MAX_CGROUP_BYTES,
    MAX_STAT_BYTES,
    MAX_STATUS_BYTES,
    _parse_stat,
    _read_limited,
    _read_cgroup_v2_group,
    _resolve_cgroup_v2_path,
    _same_cgroup_namespace,
)
from wayland_mcp.tools.process_history import (
    MAX_REQUESTED_PIDS,
    MAX_SAMPLE_COUNT,
    MAX_TOTAL_SECONDS,
    MIN_INTERVAL_SECONDS,
    MAX_INTERVAL_SECONDS,
)

PROC = Path("/proc")


@dataclass(frozen=True, slots=True)
class _CgroupSnapshot:
    start_ticks: int
    process_name: str | None
    cgroup_path: str
    resources: ProcessCgroupV2Resources
    partial: bool


@dataclass(slots=True)
class _HistoryState:
    pid: int
    process_name: str | None
    start_ticks: int | None
    cgroup_path: str | None
    previous_cpu_usage_usec: int | None
    previous_throttled_usec: int | None
    previous_at: float | None
    state: str
    samples: list[ProcessCgroupHistorySample] = field(default_factory=list)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _process_stat(pid: int) -> tuple[int, str] | None:
    try:
        text, truncated = _read_limited(PROC / str(pid) / "stat", MAX_STAT_BYTES)
    except OSError:
        return None
    parsed = _parse_stat(pid, text)
    if truncated or parsed is None:
        return None
    return int(parsed["start_ticks"]), str(parsed["state"])


def _process_name(pid: int) -> tuple[str | None, bool]:
    try:
        text, truncated = _read_limited(PROC / str(pid) / "status", MAX_STATUS_BYTES)
    except OSError:
        return None, True
    name = None
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key == "Name":
            name = "".join(ch for ch in value.strip() if ord(ch) >= 32 and ord(ch) != 127)[:256]
            break
    return name, truncated or name is None


def _read_snapshot(
    pid: int,
    expected_start_ticks: int | None = None,
    expected_cgroup_path: str | None = None,
) -> tuple[_CgroupSnapshot | None, str]:
    before = _process_stat(pid)
    if before is None:
        return None, "unavailable"
    start_ticks = before[0]
    if expected_start_ticks is not None and start_ticks != expected_start_ticks:
        return None, "process_changed"

    try:
        cgroup_before, cgroup_truncated = _read_limited(PROC / str(pid) / "cgroup", MAX_CGROUP_BYTES)
    except OSError:
        return None, "unavailable"
    if cgroup_truncated:
        return None, "unavailable"
    _root, leaf, cgroup_path, error = _resolve_cgroup_v2_path(pid, cgroup_before)
    if error or leaf is None or cgroup_path is None:
        return None, "unavailable"
    if expected_cgroup_path is not None and cgroup_path != expected_cgroup_path:
        return None, "cgroup_changed"

    resources, resource_partial = _read_cgroup_v2_group(leaf, cgroup_path, 0)
    process_name, name_partial = _process_name(pid)

    try:
        cgroup_after, cgroup_after_truncated = _read_limited(PROC / str(pid) / "cgroup", MAX_CGROUP_BYTES)
    except OSError:
        return None, "cgroup_changed"
    same_namespace, namespace_error = _same_cgroup_namespace(pid)
    if (
        cgroup_after_truncated
        or cgroup_after != cgroup_before
        or namespace_error
        or not same_namespace
    ):
        return None, "cgroup_changed"
    after = _process_stat(pid)
    if after is None or after[0] != start_ticks:
        return None, "process_changed"
    if expected_start_ticks is not None and after[0] != expected_start_ticks:
        return None, "process_changed"

    has_data = any(
        value is not None
        for value in resources.model_dump(
            exclude={"cgroup_path", "level_from_process", "memory_events"}
        ).values()
    ) or bool(resources.memory_events)
    return _CgroupSnapshot(
        start_ticks=start_ticks,
        process_name=process_name,
        cgroup_path=cgroup_path,
        resources=resources,
        partial=resource_partial or name_partial or not has_data or resources.cpu_usage_usec is None,
    ), "ready"


async def sample_cgroup_history(
    pids: list[int],
    sample_count: int = 5,
    interval_seconds: float = 1.0,
) -> ProcessCgroupHistoryResponse:
    """Sample cgroup-v2 CPU and resource snapshots for explicitly selected PIDs."""
    safe_count = sample_count if isinstance(sample_count, int) and not isinstance(sample_count, bool) else 0
    safe_interval = 0.0
    if isinstance(interval_seconds, (int, float)) and not isinstance(interval_seconds, bool):
        try:
            converted_interval = float(interval_seconds)
        except (OverflowError, ValueError):
            converted_interval = 0.0
        if math.isfinite(converted_interval):
            safe_interval = converted_interval
    if not sys.platform.startswith("linux"):
        return ProcessCgroupHistoryResponse(
            success=False,
            requested_pids=[],
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message="Cgroup-v2 resource history is available only on Linux.",
        )
    if not isinstance(pids, list) or not pids:
        return ProcessCgroupHistoryResponse(
            success=False,
            requested_pids=[],
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message="Provide at least one Linux process ID.",
        )
    if len(pids) > MAX_REQUESTED_PIDS:
        return ProcessCgroupHistoryResponse(
            success=False,
            requested_pids=[],
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"At most {MAX_REQUESTED_PIDS} process IDs may be sampled.",
        )
    if any(not isinstance(pid, int) or isinstance(pid, bool) or not 1 <= pid <= 2**31 - 1 for pid in pids):
        return ProcessCgroupHistoryResponse(
            success=False,
            requested_pids=[],
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message="Process IDs must be positive signed 32-bit integers.",
        )
    requested_pids = sorted(set(pids))
    if not 2 <= safe_count <= MAX_SAMPLE_COUNT:
        return ProcessCgroupHistoryResponse(
            success=False,
            requested_pids=requested_pids,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"sample_count must be between 2 and {MAX_SAMPLE_COUNT}.",
        )
    if not MIN_INTERVAL_SECONDS <= safe_interval <= MAX_INTERVAL_SECONDS:
        return ProcessCgroupHistoryResponse(
            success=False,
            requested_pids=requested_pids,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"interval_seconds must be between {MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS}.",
        )
    if safe_count * safe_interval > MAX_TOTAL_SECONDS:
        return ProcessCgroupHistoryResponse(
            success=False,
            requested_pids=requested_pids,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"The requested sampling period exceeds {MAX_TOTAL_SECONDS:g} seconds.",
        )

    states: list[_HistoryState] = []
    for pid in requested_pids:
        baseline, read_state = _read_snapshot(pid)
        now = time.monotonic()
        states.append(_HistoryState(
            pid=pid,
            process_name=baseline.process_name if baseline else None,
            start_ticks=baseline.start_ticks if baseline else None,
            cgroup_path=baseline.cgroup_path if baseline else None,
            previous_cpu_usage_usec=baseline.resources.cpu_usage_usec if baseline else None,
            previous_throttled_usec=baseline.resources.cpu_throttled_usec if baseline else None,
            previous_at=now if baseline else None,
            state=("partially_available" if baseline and baseline.partial else "ready") if baseline else read_state,
        ))

    started = time.monotonic()
    partial = any(state.state != "ready" for state in states)
    for sample_number in range(safe_count):
        next_sample_at = started + (sample_number + 1) * safe_interval
        sleep_seconds = max(0.0, next_sample_at - time.monotonic())
        if sleep_seconds:
            await asyncio.sleep(sleep_seconds)
        sampled_at = time.monotonic()
        timestamp = _timestamp()
        elapsed = sampled_at - started
        for state in states:
            if state.start_ticks is None or state.state in {"unavailable", "process_changed", "cgroup_changed"}:
                state.samples.append(ProcessCgroupHistorySample(
                    timestamp_utc=timestamp,
                    elapsed_seconds=round(elapsed, 3),
                ))
                continue
            current, read_state = _read_snapshot(
                state.pid,
                expected_start_ticks=state.start_ticks,
                expected_cgroup_path=state.cgroup_path,
            )
            if current is None:
                if read_state in {"process_changed", "cgroup_changed"}:
                    state.state = read_state
                else:
                    state.state = "partially_available"
                partial = True
                state.samples.append(ProcessCgroupHistorySample(
                    timestamp_utc=timestamp,
                    elapsed_seconds=round(elapsed, 3),
                ))
                continue

            interval = sampled_at - state.previous_at if state.previous_at is not None else None
            cpu_percent: float | None = None
            throttled_rate: float | None = None
            current_cpu = current.resources.cpu_usage_usec
            if (
                interval is not None and interval > 0
                and current_cpu is not None
                and state.previous_cpu_usage_usec is not None
            ):
                delta = current_cpu - state.previous_cpu_usage_usec
                if delta >= 0:
                    cpu_percent = round(delta / (10_000 * interval), 2)
                else:
                    partial = True
                    state.state = "partially_available"
            current_throttled = current.resources.cpu_throttled_usec
            if (
                interval is not None and interval > 0
                and current_throttled is not None
                and state.previous_throttled_usec is not None
            ):
                delta = current_throttled - state.previous_throttled_usec
                if delta >= 0:
                    throttled_rate = round(delta / interval, 2)
                else:
                    partial = True
                    state.state = "partially_available"
            if current.partial:
                partial = True
                state.state = "partially_available"
            state.process_name = current.process_name or state.process_name
            state.previous_cpu_usage_usec = current_cpu
            state.previous_throttled_usec = current_throttled
            state.previous_at = sampled_at
            state.samples.append(ProcessCgroupHistorySample(
                timestamp_utc=timestamp,
                elapsed_seconds=round(elapsed, 3),
                cpu_interval_seconds=round(interval, 3) if interval is not None and interval > 0 else None,
                cpu_utilization_percent=cpu_percent,
                cpu_throttled_usec_per_second=throttled_rate,
                resources=current.resources,
            ))

    processes = [ProcessCgroupHistory(
        pid=state.pid,
        process_name=state.process_name,
        cgroup_path=state.cgroup_path,
        state=state.state,
        samples=state.samples,
    ) for state in states]
    has_data = any(
        sample.resources is not None and (
            any(
                value is not None
                for value in sample.resources.model_dump(
                    exclude={"cgroup_path", "level_from_process", "memory_events"}
                ).values()
            )
            or bool(sample.resources.memory_events)
        )
        for process in processes
        for sample in process.samples
    )
    return ProcessCgroupHistoryResponse(
        success=has_data,
        requested_pids=requested_pids,
        requested_samples=safe_count,
        returned_samples=safe_count,
        interval_seconds=safe_interval,
        processes=processes,
        partial=partial or not has_data,
        message=(
            "Cgroup CPU utilization is relative to one CPU and may exceed 100% for multi-core cgroups. Memory, swap, PID, and cumulative CPU counters are cgroup-v2 snapshots; the target's process start time and cgroup membership are checked around each sample. Only a same-namespace cgroup-v2 hierarchy rooted at /sys/fs/cgroup is sampled."
            if has_data else "No cgroup-v2 resource samples were available; the process may use cgroup v1 or the hierarchy may be hidden or permission-limited."
        ),
    )
