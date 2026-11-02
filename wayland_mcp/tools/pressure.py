"""Bounded read-only CPU, memory, and I/O Pressure Stall Information (PSI)."""

from __future__ import annotations

import math
import re
import sys
from pathlib import Path

from wayland_mcp.models import PressureStallInfoResponse, PressureStallMetric, PressureStallResource

PROC_PRESSURE = Path("/proc/pressure")
RESOURCES = ("cpu", "memory", "io")
MAX_PRESSURE_FILE_BYTES = 4096
MAX_TOTAL_MICROSECONDS = (1 << 64) - 1
DECIMAL_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")


def _parse_metric_line(line: str) -> tuple[str, PressureStallMetric] | None:
    fields = line.split()
    if len(fields) != 5 or fields[0] not in {"some", "full"}:
        return None
    values: dict[str, str] = {}
    for field in fields[1:]:
        key, separator, value = field.partition("=")
        if not separator or key not in {"avg10", "avg60", "avg300", "total"} or key in values:
            return None
        values[key] = value
    if set(values) != {"avg10", "avg60", "avg300", "total"}:
        return None

    averages: dict[str, float] = {}
    for key in ("avg10", "avg60", "avg300"):
        raw_value = values[key]
        if len(raw_value) > 24 or not DECIMAL_RE.fullmatch(raw_value):
            return None
        try:
            value = float(raw_value)
        except ValueError:
            return None
        if not math.isfinite(value) or value < 0 or value > 100:
            return None
        averages[key] = value

    raw_total = values["total"]
    if len(raw_total) > 20 or not raw_total.isdecimal():
        return None
    total = int(raw_total, 10)
    if total > MAX_TOTAL_MICROSECONDS:
        return None
    return fields[0], PressureStallMetric(
        avg10_percent=averages["avg10"],
        avg60_percent=averages["avg60"],
        avg300_percent=averages["avg300"],
        total_microseconds=total,
    )


def _read_resource(resource: str) -> tuple[PressureStallResource, bool]:
    try:
        with (PROC_PRESSURE / resource).open("rb") as stream:
            raw = stream.read(MAX_PRESSURE_FILE_BYTES + 1)
    except OSError:
        return PressureStallResource(resource=resource, available=False, partial=True), True
    if len(raw) > MAX_PRESSURE_FILE_BYTES:
        return PressureStallResource(resource=resource, available=False, partial=True), True
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return PressureStallResource(resource=resource, available=False, partial=True), True

    metrics: dict[str, PressureStallMetric] = {}
    malformed = False
    lines = text.splitlines()
    if len(lines) > 4:
        lines = lines[:4]
        malformed = True
    for line in lines:
        if not line.strip():
            continue
        parsed = _parse_metric_line(line)
        if parsed is None:
            malformed = True
            continue
        label, metric = parsed
        if label in metrics:
            malformed = True
            continue
        metrics[label] = metric

    some = metrics.get("some")
    full = metrics.get("full")
    if some is None or (resource in {"memory", "io"} and full is None):
        malformed = True
    resource_info = PressureStallResource(
        resource=resource,
        available=some is not None,
        some=some,
        full=full,
        partial=malformed,
    )
    return resource_info, malformed


def get_pressure_stall_info() -> PressureStallInfoResponse:
    if not sys.platform.startswith("linux"):
        return PressureStallInfoResponse(
            success=False,
            message="Pressure Stall Information is available only on Linux.",
        )

    resources: list[PressureStallResource] = []
    any_partial = False
    for resource in RESOURCES:
        info, partial = _read_resource(resource)
        resources.append(info)
        any_partial = any_partial or partial
    available_count = sum(1 for resource in resources if resource.available)
    if available_count == 0:
        return PressureStallInfoResponse(
            success=False,
            resources=resources,
            partial=True,
            message="Linux Pressure Stall Information files are unavailable or malformed.",
        )
    return PressureStallInfoResponse(
        success=True,
        available_resources=available_count,
        resources=resources,
        partial=any_partial,
        message="PSI averages are recent stall-time percentages, not CPU utilization; total values are cumulative stall microseconds.",
    )
