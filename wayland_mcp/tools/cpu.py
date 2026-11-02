"""Bounded logical CPU topology and frequency snapshot from procfs/sysfs."""

from __future__ import annotations

import os
import platform
import re
import sys
from pathlib import Path

from wayland_mcp.models import CPUInfo, CPUInventoryResponse

PROC_CPUINFO = Path("/proc/cpuinfo")
SYS_CPU_ROOT = Path("/sys/devices/system/cpu")
MAX_CPUINFO_BYTES = 2 * 1024 * 1024
MAX_CPUINFO_RECORDS = 4096
MAX_CPU_SCAN = 4096
MAX_RETURNED_CPUS = 256
CPU_DIRECTORY_RE = re.compile(r"^cpu([0-9]+)$")
MODEL_FIELD_NAMES = ("model name", "hardware", "model")
CPUINFO_FIELDS = set(MODEL_FIELD_NAMES) | {"processor", "vendor_id"}


def _read_text(path: Path, limit: int = 256) -> str | None:
    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        return None
    if len(data) > limit:
        return None
    return data.decode("utf-8", errors="replace").strip()


def _read_integer(path: Path) -> int | None:
    value = _read_text(path, 64)
    if value is None:
        return None
    try:
        parsed = int(value, 10)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _read_frequency(path: Path) -> float | None:
    value = _read_integer(path)
    if value is None:
        return None
    return round(value / 1000, 3)


def _cpuinfo_records() -> tuple[dict[int, dict[str, str]], bool]:
    try:
        with PROC_CPUINFO.open("rb") as stream:
            raw = stream.read(MAX_CPUINFO_BYTES + 1)
    except OSError:
        return {}, False
    truncated = len(raw) > MAX_CPUINFO_BYTES
    if len(raw) > MAX_CPUINFO_BYTES:
        raw = raw[:MAX_CPUINFO_BYTES]
    text = raw.decode("utf-8", errors="replace")
    records: dict[int, dict[str, str]] = {}
    blocks = text.split("\n\n")
    truncated = truncated or len(blocks) > MAX_CPUINFO_RECORDS
    for block in blocks[:MAX_CPUINFO_RECORDS]:
        values: dict[str, str] = {}
        for line in block.splitlines():
            key, separator, value = line.partition(":")
            if not separator:
                continue
            key = key.strip().casefold()
            if key in CPUINFO_FIELDS:
                cleaned = " ".join(value.strip().split())[:256]
                if cleaned:
                    values[key] = cleaned
        raw_id = values.get("processor")
        if raw_id is not None:
            try:
                cpu_id = int(raw_id, 10)
            except ValueError:
                continue
            if 0 <= cpu_id < MAX_CPU_SCAN:
                records[cpu_id] = values
    return records, truncated


def _cpu_directories() -> tuple[list[tuple[int, Path]], bool]:
    cpus: list[tuple[int, Path]] = []
    truncated = False
    try:
        with os.scandir(SYS_CPU_ROOT) as entries:
            for entry in entries:
                match = CPU_DIRECTORY_RE.fullmatch(entry.name)
                if not match:
                    continue
                if len(cpus) >= MAX_CPU_SCAN:
                    truncated = True
                    break
                try:
                    cpu_id = int(match.group(1), 10)
                except ValueError:
                    continue
                if cpu_id >= MAX_CPU_SCAN:
                    continue
                cpus.append((cpu_id, SYS_CPU_ROOT / entry.name))
    except OSError:
        return [], False
    cpus.sort(key=lambda item: item[0])
    return cpus, truncated


def _online_cpu_ids() -> set[int] | None:
    value = _read_text(SYS_CPU_ROOT / "online", 16 * 1024)
    if value is None:
        return None
    ids: set[int] = set()
    for chunk in value.split(","):
        left, separator, right = chunk.partition("-")
        try:
            start = int(left, 10)
            end = int(right, 10) if separator else start
        except ValueError:
            return None
        if start < 0 or end < start or end >= MAX_CPU_SCAN:
            return None
        ids.update(range(start, end + 1))
    return ids


def _safe_identity(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = " ".join(value.split())
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        return None
    return cleaned[:256] or None


def list_cpu_inventory(limit: int = 128) -> CPUInventoryResponse:
    if not sys.platform.startswith("linux"):
        return CPUInventoryResponse(success=False, message="CPU inventory is available only on Linux.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return CPUInventoryResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_CPUS))

    records, cpuinfo_truncated = _cpuinfo_records()
    cpu_dirs, scan_truncated = _cpu_directories()
    if not cpu_dirs and records:
        cpu_dirs = [(cpu_id, SYS_CPU_ROOT / f"cpu{cpu_id}") for cpu_id in sorted(records)[:MAX_CPU_SCAN]]
    if not cpu_dirs and not records:
        return CPUInventoryResponse(success=False, limit=limit, message="Linux CPU procfs and sysfs inventory are unavailable.")

    online_ids = _online_cpu_ids()
    fallback_online: dict[int, bool | None] = {}
    if online_ids is None:
        for cpu_id, directory in cpu_dirs:
            value = _read_text(directory / "online", 16)
            if value in {"0", "1"}:
                fallback_online[cpu_id] = value == "1"
            elif cpu_id == 0 or cpu_id in records:
                # CPU 0 is normally online; procfs records only active logical CPUs.
                fallback_online[cpu_id] = True
            else:
                fallback_online[cpu_id] = None

    cpus: list[CPUInfo] = []
    model_name = None
    vendor_id = None
    for cpu_id, directory in cpu_dirs:
        record = records.get(cpu_id, {})
        cpu_model = next((record.get(key) for key in MODEL_FIELD_NAMES if record.get(key)), None)
        cpu_vendor = record.get("vendor_id")
        model_name = model_name or _safe_identity(cpu_model)
        vendor_id = vendor_id or _safe_identity(cpu_vendor)
        topology = directory / "topology"
        cpufreq = directory / "cpufreq"
        cpus.append(CPUInfo(
            logical_cpu=cpu_id,
            online=cpu_id in online_ids if online_ids is not None else fallback_online.get(cpu_id),
            physical_package_id=_read_integer(topology / "physical_package_id"),
            core_id=_read_integer(topology / "core_id"),
            vendor_id=_safe_identity(cpu_vendor) or vendor_id,
            model_name=_safe_identity(cpu_model) or model_name,
            scaling_frequency_mhz=_read_frequency(cpufreq / "scaling_cur_freq"),
            hardware_frequency_mhz=_read_frequency(cpufreq / "cpuinfo_cur_freq"),
            minimum_frequency_mhz=_read_frequency(cpufreq / "cpuinfo_min_freq"),
            maximum_frequency_mhz=_read_frequency(cpufreq / "cpuinfo_max_freq"),
        ))
    returned = cpus[:limit]
    online_count = (
        sum(1 for cpu in cpus if cpu.online is True)
        if all(cpu.online is not None for cpu in cpus) else None
    )
    messages: list[str] = []
    if any(cpu.scaling_frequency_mhz is not None for cpu in cpus):
        messages.append("Scaling frequency is a requested value and may differ from the measured hardware clock.")
    if scan_truncated or cpuinfo_truncated:
        messages.append("CPU inventory reached its scan or procfs input cap.")
    if len(cpus) > limit:
        messages.append("More logical CPUs exist than the requested result limit.")
    return CPUInventoryResponse(
        success=True,
        architecture=platform.machine(),
        logical_cpu_count=len(cpus),
        online_cpu_count=online_count,
        vendor_id=vendor_id,
        model_name=model_name,
        returned_cpus=len(returned),
        cpus=returned,
        limit=limit,
        truncated=scan_truncated or cpuinfo_truncated or len(cpus) > limit,
        message=" ".join(messages) or None,
    )
