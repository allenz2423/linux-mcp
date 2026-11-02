"""Bounded per-process CPU, memory, and storage-I/O history from Linux procfs."""

from __future__ import annotations

import asyncio
import math
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from wayland_mcp.models import (
    ProcessResourceHistory,
    ProcessResourceHistoryResponse,
    ProcessResourceSample,
)

PROC = Path("/proc")
MAX_REQUESTED_PIDS = 32
MAX_STAT_BYTES = 8192
MAX_STATUS_BYTES = 32 * 1024
MAX_IO_BYTES = 8192
MAX_SAMPLE_COUNT = 20
MIN_INTERVAL_SECONDS = 0.25
MAX_INTERVAL_SECONDS = 30.0
MAX_TOTAL_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class _ProcessSnapshot:
    start_ticks: int
    cpu_ticks: int
    name: str
    resident_memory_bytes: int | None
    virtual_memory_bytes: int | None
    thread_count: int | None
    storage_read_bytes: int | None
    storage_write_bytes: int | None
    partial: bool


@dataclass(slots=True)
class _ProcessHistoryState:
    pid: int
    process_name: str | None
    start_ticks: int | None
    previous_cpu_ticks: int | None
    previous_at: float | None
    previous_storage_read_bytes: int | None
    previous_storage_write_bytes: int | None
    state: str
    samples: list[ProcessResourceSample] = field(default_factory=list)


def _read_stat(pid: int) -> tuple[int, int, str] | None:
    try:
        with (PROC / str(pid) / "stat").open("rb") as stream:
            raw = stream.read(MAX_STAT_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_STAT_BYTES:
        return None
    value = raw.decode("utf-8", errors="replace")
    opening_paren = value.find("(")
    closing_paren = value.rfind(")")
    if opening_paren < 0 or closing_paren <= opening_paren:
        return None
    prefix = value[:opening_paren].split()
    fields = value[closing_paren + 1:].split()
    if not prefix or prefix[0] != str(pid) or len(fields) <= 19:
        return None
    try:
        user_ticks = int(fields[11], 10)
        system_ticks = int(fields[12], 10)
        start_ticks = int(fields[19], 10)
    except (IndexError, ValueError):
        return None
    if min(user_ticks, system_ticks, start_ticks) < 0:
        return None
    name = "".join(
        character
        for character in value[opening_paren + 1:closing_paren]
        if ord(character) >= 32 and ord(character) != 127
    )[:256]
    return start_ticks, user_ticks + system_ticks, name


def _parse_kibibytes(value: str) -> int | None:
    fields = value.split()
    try:
        amount = int(fields[0], 10)
    except (IndexError, ValueError):
        return None
    if amount < 0:
        return None
    if len(fields) > 1 and fields[1].casefold() in {"kb", "kib"}:
        amount *= 1024
    return amount


def _read_status(pid: int) -> tuple[str | None, int | None, int | None, int | None, bool]:
    try:
        with (PROC / str(pid) / "status").open("rb") as stream:
            raw = stream.read(MAX_STATUS_BYTES + 1)
    except OSError:
        return None, None, None, None, True
    partial = len(raw) > MAX_STATUS_BYTES
    fields: dict[str, str] = {}
    for line in raw[:MAX_STATUS_BYTES].decode("utf-8", errors="replace").splitlines():
        key, separator, value = line.partition(":")
        if separator and key in {"Name", "VmRSS", "VmSize", "Threads"}:
            fields[key] = value.strip()
    name = fields.get("Name")
    if name:
        name = "".join(character for character in name if ord(character) >= 32 and ord(character) != 127)[:256]
    resident = _parse_kibibytes(fields["VmRSS"]) if "VmRSS" in fields else None
    virtual = _parse_kibibytes(fields["VmSize"]) if "VmSize" in fields else None
    try:
        threads = int(fields["Threads"], 10) if "Threads" in fields else None
    except ValueError:
        threads = None
        partial = True
    return name, resident, virtual, threads, partial


def _read_io(pid: int) -> tuple[int | None, int | None, bool]:
    try:
        with (PROC / str(pid) / "io").open("rb") as stream:
            raw = stream.read(MAX_IO_BYTES + 1)
    except OSError:
        return None, None, True
    if len(raw) > MAX_IO_BYTES:
        return None, None, True
    values: dict[str, int] = {}
    partial = False
    for line in raw.decode("ascii", errors="replace").splitlines():
        key, separator, value = line.partition(":")
        if not separator or key not in {"read_bytes", "write_bytes"}:
            continue
        try:
            count = int(value.strip(), 10)
        except ValueError:
            partial = True
            continue
        if count < 0 or count > 2**64 - 1:
            partial = True
            continue
        values[key] = count
    read_bytes = values.get("read_bytes")
    write_bytes = values.get("write_bytes")
    if read_bytes is None or write_bytes is None:
        partial = True
    return read_bytes, write_bytes, partial


def _read_snapshot(pid: int, expected_start_ticks: int | None = None) -> tuple[_ProcessSnapshot | None, str]:
    before = _read_stat(pid)
    if before is None:
        return None, "unavailable"
    start_ticks, _cpu_ticks, comm = before
    if expected_start_ticks is not None and start_ticks != expected_start_ticks:
        return None, "process_changed"
    status_name, resident, virtual, threads, partial = _read_status(pid)
    storage_read_bytes, storage_write_bytes, io_partial = _read_io(pid)
    after = _read_stat(pid)
    if after is None or after[0] != start_ticks:
        return None, "process_changed"
    if expected_start_ticks is not None and after[0] != expected_start_ticks:
        return None, "process_changed"
    name = status_name or comm or f"pid-{pid}"
    return _ProcessSnapshot(
        start_ticks=start_ticks,
        cpu_ticks=after[1],
        name=name,
        resident_memory_bytes=resident,
        virtual_memory_bytes=virtual,
        thread_count=threads,
        storage_read_bytes=storage_read_bytes,
        storage_write_bytes=storage_write_bytes,
        partial=partial or io_partial,
    ), "ready"


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def sample_process_history(
    pids: list[int],
    sample_count: int = 5,
    interval_seconds: float = 1.0,
) -> ProcessResourceHistoryResponse:
    """Sample explicitly selected process CPU time and memory with start-time identity checks."""
    safe_count = sample_count if isinstance(sample_count, int) and not isinstance(sample_count, bool) else 0
    safe_interval = (
        float(interval_seconds)
        if isinstance(interval_seconds, (int, float)) and not isinstance(interval_seconds, bool)
        and math.isfinite(interval_seconds)
        else 0.0
    )
    if not sys.platform.startswith("linux"):
        return ProcessResourceHistoryResponse(
            success=False,
            requested_pids=[],
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message="Per-process resource history is available only on Linux.",
        )
    if not isinstance(pids, list) or not pids:
        return ProcessResourceHistoryResponse(
            success=False,
            requested_pids=[],
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message="Provide at least one Linux process ID.",
        )
    if len(pids) > MAX_REQUESTED_PIDS:
        return ProcessResourceHistoryResponse(
            success=False,
            requested_pids=[],
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"At most {MAX_REQUESTED_PIDS} process IDs may be sampled.",
        )
    if any(not isinstance(pid, int) or isinstance(pid, bool) or not 1 <= pid <= 2**31 - 1 for pid in pids):
        return ProcessResourceHistoryResponse(
            success=False,
            requested_pids=[],
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message="Process IDs must be positive signed 32-bit integers.",
        )
    requested_pids = sorted(set(pids))
    if not 2 <= safe_count <= MAX_SAMPLE_COUNT:
        return ProcessResourceHistoryResponse(
            success=False,
            requested_pids=requested_pids,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"sample_count must be between 2 and {MAX_SAMPLE_COUNT}.",
        )
    if not MIN_INTERVAL_SECONDS <= safe_interval <= MAX_INTERVAL_SECONDS:
        return ProcessResourceHistoryResponse(
            success=False,
            requested_pids=requested_pids,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"interval_seconds must be between {MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS}.",
        )
    if safe_count * safe_interval > MAX_TOTAL_SECONDS:
        return ProcessResourceHistoryResponse(
            success=False,
            requested_pids=requested_pids,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message=f"The requested sampling period exceeds {MAX_TOTAL_SECONDS:g} seconds.",
        )
    try:
        clock_ticks = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError):
        clock_ticks = 0
    if not isinstance(clock_ticks, int) or clock_ticks <= 0:
        return ProcessResourceHistoryResponse(
            success=False,
            requested_pids=requested_pids,
            requested_samples=safe_count,
            interval_seconds=safe_interval,
            message="Could not read the Linux clock-tick rate.",
        )

    states: list[_ProcessHistoryState] = []
    for pid in requested_pids:
        baseline, status = _read_snapshot(pid)
        now = time.monotonic()
        states.append(_ProcessHistoryState(
            pid=pid,
            process_name=baseline.name if baseline else None,
            start_ticks=baseline.start_ticks if baseline else None,
            previous_cpu_ticks=baseline.cpu_ticks if baseline else None,
            previous_at=now if baseline else None,
            previous_storage_read_bytes=baseline.storage_read_bytes if baseline else None,
            previous_storage_write_bytes=baseline.storage_write_bytes if baseline else None,
            state=("partially_available" if baseline and baseline.partial else "ready") if baseline else "unavailable",
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
            if state.start_ticks is None or state.state in {"unavailable", "process_changed"}:
                state.samples.append(ProcessResourceSample(
                    timestamp_utc=timestamp,
                    elapsed_seconds=round(elapsed, 3),
                ))
                continue
            current, _read_state = _read_snapshot(state.pid, state.start_ticks)
            if current is None:
                state.state = "process_changed"
                partial = True
                state.samples.append(ProcessResourceSample(
                    timestamp_utc=timestamp,
                    elapsed_seconds=round(elapsed, 3),
                ))
                continue
            cpu_window: float | None = None
            cpu_percent: float | None = None
            storage_read_rate: float | None = None
            storage_write_rate: float | None = None
            if state.previous_cpu_ticks is not None and state.previous_at is not None:
                cpu_window = sampled_at - state.previous_at
                delta_ticks = current.cpu_ticks - state.previous_cpu_ticks
                if cpu_window > 0 and delta_ticks >= 0:
                    cpu_percent = round(100.0 * delta_ticks / (clock_ticks * cpu_window), 2)
                else:
                    partial = True
                    state.state = "partially_available"
                if current.storage_read_bytes is not None and state.previous_storage_read_bytes is not None:
                    read_delta = current.storage_read_bytes - state.previous_storage_read_bytes
                    if cpu_window > 0 and read_delta >= 0:
                        storage_read_rate = round(read_delta / cpu_window, 2)
                    else:
                        partial = True
                        state.state = "partially_available"
                if current.storage_write_bytes is not None and state.previous_storage_write_bytes is not None:
                    write_delta = current.storage_write_bytes - state.previous_storage_write_bytes
                    if cpu_window > 0 and write_delta >= 0:
                        storage_write_rate = round(write_delta / cpu_window, 2)
                    else:
                        partial = True
                        state.state = "partially_available"
            state.previous_cpu_ticks = current.cpu_ticks
            state.previous_at = sampled_at
            state.previous_storage_read_bytes = current.storage_read_bytes
            state.previous_storage_write_bytes = current.storage_write_bytes
            if current.partial:
                partial = True
                state.state = "partially_available"
            state.samples.append(ProcessResourceSample(
                timestamp_utc=timestamp,
                elapsed_seconds=round(elapsed, 3),
                cpu_interval_seconds=round(cpu_window, 3) if cpu_window is not None and cpu_window > 0 else None,
                cpu_utilization_percent=cpu_percent,
                resident_memory_bytes=current.resident_memory_bytes,
                virtual_memory_bytes=current.virtual_memory_bytes,
                thread_count=current.thread_count,
                storage_read_bytes=current.storage_read_bytes,
                storage_write_bytes=current.storage_write_bytes,
                storage_read_bytes_per_second=storage_read_rate,
                storage_write_bytes_per_second=storage_write_rate,
            ))

    processes = [ProcessResourceHistory(
        pid=state.pid,
        process_name=state.process_name,
        state=state.state,
        samples=state.samples,
    ) for state in states]
    has_data = any(
        sample.cpu_utilization_percent is not None
        or sample.resident_memory_bytes is not None
        or sample.virtual_memory_bytes is not None
        or sample.storage_read_bytes is not None
        or sample.storage_write_bytes is not None
        for process in processes
        for sample in process.samples
    )
    message = (
        "CPU percentages are per-process scheduled time relative to one CPU and may exceed 100% for multithreaded processes. "
        "Each PID is checked against its procfs start time to avoid mixing a replacement process into the history. "
        "Storage-layer read/write rates are deltas of /proc/PID/io counters and may be unavailable under procfs permission rules. "
        "Command lines, environments, working directories, and file descriptors are not read."
    )
    if partial:
        message += " Some samples were unavailable, permission-limited, or ended after the process exited or changed identity."
    return ProcessResourceHistoryResponse(
        success=has_data,
        requested_pids=requested_pids,
        requested_samples=safe_count,
        returned_samples=safe_count,
        interval_seconds=safe_interval,
        processes=processes,
        partial=partial,
        message=message,
    )
