"""Bounded loaded-kernel-module inventory from procfs."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from wayland_mcp.models import KernelModuleInfo, KernelModuleListResponse

PROC_MODULES = Path("/proc/modules")
MAX_MODULE_FILE_BYTES = 2 * 1024 * 1024
MAX_MODULE_RECORDS = 20_000
MAX_MODULE_LINE_BYTES = 4096
MAX_RETURNED_MODULES = 200
MODULE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


def list_kernel_modules(query: str = "", limit: int = 100) -> KernelModuleListResponse:
    if not sys.platform.startswith("linux"):
        return KernelModuleListResponse(success=False, message="Kernel module inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return KernelModuleListResponse(success=False, message="Query must be text with at most 256 characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return KernelModuleListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_MODULES))

    modules: list[KernelModuleInfo] = []
    truncated = False
    bytes_read = 0
    records_read = 0
    needle = query.strip().casefold()
    try:
        with PROC_MODULES.open("rb") as stream:
            for _ in range(MAX_MODULE_RECORDS):
                remaining = MAX_MODULE_FILE_BYTES - bytes_read
                if remaining <= 0:
                    truncated = bool(stream.read(1))
                    break
                raw_line = stream.readline(min(MAX_MODULE_LINE_BYTES + 1, remaining + 1))
                if not raw_line:
                    break
                if len(raw_line) > remaining or len(raw_line) > MAX_MODULE_LINE_BYTES:
                    truncated = True
                    break
                bytes_read += len(raw_line)
                records_read += 1
                fields = raw_line.decode("ascii", errors="replace").split()
                if len(fields) < 6 or not MODULE_NAME_RE.fullmatch(fields[0]):
                    continue
                try:
                    size_bytes = int(fields[1], 10)
                    reference_count = int(fields[2], 10)
                except ValueError:
                    continue
                if size_bytes < 0 or reference_count < 0:
                    continue
                if needle and needle not in fields[0].casefold():
                    continue
                modules.append(KernelModuleInfo(
                    name=fields[0],
                    size_bytes=size_bytes,
                    reference_count=reference_count,
                    state=fields[4][:32],
                ))
            if bytes_read == MAX_MODULE_FILE_BYTES:
                truncated = truncated or bool(stream.read(1))
            if records_read == MAX_MODULE_RECORDS and stream.read(1):
                truncated = True
    except OSError as exc:
        return KernelModuleListResponse(success=False, limit=limit, message=f"Could not read /proc/modules: {exc.strerror or 'read error'}.")

    modules.sort(key=lambda item: item.name.casefold())
    message = "Module addresses and dependency strings are omitted."
    if truncated:
        message += " The procfs scan reached its size, line, or record limit."
    return KernelModuleListResponse(
        success=True,
        total_modules=len(modules),
        returned_modules=min(len(modules), limit),
        modules=modules[:limit],
        limit=limit,
        truncated=truncated or len(modules) > limit,
        message=message,
    )
