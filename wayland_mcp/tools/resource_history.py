"""Short, bounded CPU and memory history sampling from Linux procfs."""

from __future__ import annotations

import asyncio
import math
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from wayland_mcp.models import (
    CPUUtilization,
    ResourceHistoryResponse,
    ResourceHistorySample,
    ResourceUsageResponse,
)
from wayland_mcp.tools.host import get_resource_usage

PROC_STAT = Path("/proc/stat")
MAX_PROC_STAT_BYTES = 1024 * 1024
MAX_CPU_ROWS = 4096
MAX_RETURNED_CPUS = 256
MAX_SAMPLE_COUNT = 20
MIN_INTERVAL_SECONDS = 0.25
MAX_INTERVAL_SECONDS = 30.0
MAX_TOTAL_SECONDS = 60.0
CPU_ROW_RE = re.compile(r"^cpu([0-9]+)$")


def _read_cpu_counters() -> tuple[dict[str, tuple[int, ...]], bool] | None:
    try:
        with PROC_STAT.open("rb") as stream:
            raw = stream.read(MAX_PROC_STAT_BYTES + 1)
    except OSError:
        return None

    truncated = len(raw) > MAX_PROC_STAT_BYTES
    text = raw[:MAX_PROC_STAT_BYTES].decode("ascii", errors="replace")
    counters: dict[str, tuple[int, ...]] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or (fields[0] != "cpu" and not CPU_ROW_RE.fullmatch(fields[0])):
            continue
        values: list[int] = []
        for raw_value in fields[1:9]:
            try:
                value = int(raw_value, 10)
            except ValueError:
                values = []
                break
            if value < 0:
                values = []
                break
            values.append(value)
        if len(values) < 4:
            continue
        counters[fields[0]] = tuple(values)
        if len(counters) >= MAX_CPU_ROWS + 1:
            truncated = True
            break
    if "cpu" not in counters:
        return None
    return counters, truncated


def _usage_percent(previous: tuple[int, ...], current: tuple[int, ...]) -> float | None:
    field_count = min(len(previous), len(current), 8)
    if field_count < 4:
        return None
    deltas: list[int] = []
    for index in range(field_count):
        delta = current[index] - previous[index]
        if delta < 0:
            if index == 4:  # Linux documents that the iowait counter may decrease.
                delta = 0
            else:
                return None
        deltas.append(delta)
    total_delta = sum(deltas)
    if total_delta <= 0:
        return None
    idle_delta = deltas[3] + (deltas[4] if field_count > 4 else 0)
    busy_delta = max(0, total_delta - idle_delta)
    return round(min(100.0, 100.0 * busy_delta / total_delta), 2)


def _per_cpu_usage(
    previous: dict[str, tuple[int, ...]],
    current: dict[str, tuple[int, ...]],
) -> list[CPUUtilization]:
    rows: list[tuple[int, float]] = []
    for label, current_values in current.items():
        match = CPU_ROW_RE.fullmatch(label)
        previous_values = previous.get(label)
        if not match or previous_values is None:
            continue
        percent = _usage_percent(previous_values, current_values)
        if percent is not None:
            rows.append((int(match.group(1)), percent))
    rows.sort(key=lambda item: item[0])
    return [CPUUtilization(logical_cpu=cpu, utilization_percent=percent) for cpu, percent in rows]


def _sample(
    usage: ResourceUsageResponse,
    *,
    elapsed_seconds: float,
    cpu_percent: float | None,
    per_cpu: list[CPUUtilization],
) -> ResourceHistorySample:
    return ResourceHistorySample(
        timestamp_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        elapsed_seconds=round(elapsed_seconds, 3),
        cpu_utilization_percent=cpu_percent,
        per_cpu=per_cpu,
        memory_total_bytes=usage.memory_total_bytes,
        memory_available_bytes=usage.memory_available_bytes,
        memory_used_bytes=usage.memory_used_bytes,
        swap_total_bytes=usage.swap_total_bytes,
        swap_free_bytes=usage.swap_free_bytes,
        load_average_1m=usage.load_average_1m,
        load_average_5m=usage.load_average_5m,
        load_average_15m=usage.load_average_15m,
        uptime_seconds=usage.uptime_seconds,
    )


async def sample_resource_history(
    sample_count: int = 5,
    interval_seconds: float = 1.0,
) -> ResourceHistoryResponse:
    """Collect bounded CPU utilization and system resource snapshots over time."""
    safe_count = sample_count if isinstance(sample_count, int) and not isinstance(sample_count, bool) else 0
    safe_interval = (
        float(interval_seconds)
        if isinstance(interval_seconds, (int, float)) and not isinstance(interval_seconds, bool)
        and math.isfinite(interval_seconds)
        else 0.0
    )
    if not sys.platform.startswith("linux"):
        return ResourceHistoryResponse(
            success=False,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message="Resource history is available only on Linux.",
        )
    if not 2 <= safe_count <= MAX_SAMPLE_COUNT:
        return ResourceHistoryResponse(
            success=False,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"sample_count must be between 2 and {MAX_SAMPLE_COUNT}.",
        )
    if not MIN_INTERVAL_SECONDS <= safe_interval <= MAX_INTERVAL_SECONDS:
        return ResourceHistoryResponse(
            success=False,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"interval_seconds must be between {MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS}.",
        )
    if safe_count * safe_interval > MAX_TOTAL_SECONDS:
        return ResourceHistoryResponse(
            success=False,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"The requested sampling period exceeds {MAX_TOTAL_SECONDS:g} seconds.",
        )

    baseline = _read_cpu_counters()
    if baseline is None:
        return ResourceHistoryResponse(
            success=False,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message="Could not read aggregate CPU counters from Linux procfs.",
        )
    previous, was_truncated = baseline
    started = time.monotonic()
    samples: list[ResourceHistorySample] = []
    partial_cpu_data = False
    truncated_cpu_list = was_truncated

    for sample_number in range(safe_count):
        next_sample_at = started + (sample_number + 1) * safe_interval
        sleep_seconds = max(0.0, next_sample_at - time.monotonic())
        if sleep_seconds:
            await asyncio.sleep(sleep_seconds)
        current_snapshot = _read_cpu_counters()
        usage = get_resource_usage()
        elapsed = time.monotonic() - started
        if current_snapshot is None:
            cpu_percent = None
            per_cpu: list[CPUUtilization] = []
            partial_cpu_data = True
        else:
            current, sample_truncated = current_snapshot
            truncated_cpu_list = truncated_cpu_list or sample_truncated or (
                sum(1 for label in current if CPU_ROW_RE.fullmatch(label)) > MAX_RETURNED_CPUS
            )
            cpu_percent = (
                _usage_percent(previous["cpu"], current["cpu"])
                if "cpu" in previous and "cpu" in current else None
            )
            per_cpu = _per_cpu_usage(previous, current)[:MAX_RETURNED_CPUS]
            if cpu_percent is None:
                partial_cpu_data = True
            previous = current

        if not usage.success:
            partial_cpu_data = True
        samples.append(_sample(
            usage,
            elapsed_seconds=elapsed,
            cpu_percent=cpu_percent,
            per_cpu=per_cpu,
        ))

    messages = [
        "CPU percentages are estimates from /proc/stat counter deltas; the kernel documents that iowait counters can be unreliable."
    ]
    if partial_cpu_data:
        messages.append("Some CPU or memory/load fields were unavailable in one or more samples.")
    if truncated_cpu_list:
        messages.append(f"Per-CPU results were capped at {MAX_RETURNED_CPUS} logical CPUs.")
    return ResourceHistoryResponse(
        success=any(
            sample.cpu_utilization_percent is not None
            or sample.memory_total_bytes is not None
            or sample.load_average_1m is not None
            for sample in samples
        ),
        requested_samples=safe_count,
        returned_samples=len(samples),
        interval_seconds=safe_interval,
        samples=samples,
        truncated_cpu_list=truncated_cpu_list,
        message=" ".join(messages),
    )
