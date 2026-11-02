"""Read-only CUPS printer queue inventory."""

from __future__ import annotations

import re
import sys

from wayland_mcp.models import PrinterInfo, PrinterListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_CUPS_OUTPUT_BYTES = 512 * 1024
MAX_CUPS_LINES = 8192
MAX_LINE_CHARS = 2048
MAX_PRINTERS = 4096
MAX_RETURNED_PRINTERS = 200
PRINTER_STATUS_RE = re.compile(r"^printer\s+(\S{1,255})\s+(.*)$", re.IGNORECASE)
ACCEPTANCE_RE = re.compile(r"^(\S{1,255})\s+(not accepting|accepting) requests\b", re.IGNORECASE)
DEFAULT_RE = re.compile(r"^system default destination:\s*(.*?)\s*$", re.IGNORECASE)


def _safe_queue_name(value: str) -> str | None:
    if not value or len(value) > 255 or any(not character.isprintable() or character.isspace() or character in "/#" for character in value):
        return None
    return value


def _printer_record(records: dict[str, dict[str, object]], name: str) -> dict[str, object]:
    return records.setdefault(name, {"state": "unknown", "enabled": None, "accepting_jobs": None})


def list_printers(query: str = "", limit: int = 100) -> PrinterListResponse:
    """List configured CUPS queues and operational state without reading print jobs or device URIs."""
    if not sys.platform.startswith("linux"):
        return PrinterListResponse(success=False, message="Printer inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return PrinterListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return PrinterListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return PrinterListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_PRINTERS))

    env = get_sanitized_env()
    lpstat = find_session_binary("lpstat", env)
    if not lpstat:
        return PrinterListResponse(
            success=False,
            limit=limit,
            message="The CUPS lpstat command is unavailable.",
        )

    output, error, command_truncated = run_bounded_command(
        [lpstat, "-p", "-a", "-d"],
        env,
        command_label="lpstat",
        timeout_seconds=5,
        max_output_bytes=MAX_CUPS_OUTPUT_BYTES,
    )
    if output is None:
        return PrinterListResponse(
            success=False,
            limit=limit,
            truncated=command_truncated,
            message=error or "Could not query CUPS printer queues.",
        )

    records: dict[str, dict[str, object]] = {}
    default_destination: str | None = None
    truncated = command_truncated
    lines = output.splitlines()
    if len(lines) > MAX_CUPS_LINES:
        lines = lines[:MAX_CUPS_LINES]
        truncated = True
    for line in lines:
        if len(line) > MAX_LINE_CHARS:
            truncated = True
            continue
        default_match = DEFAULT_RE.fullmatch(line.strip())
        if default_match:
            destination = default_match.group(1).strip()
            if destination and destination.casefold() != "none":
                default_destination = _safe_queue_name(destination)
                if default_destination is None:
                    truncated = True
            continue
        if "no system default destination" in line.casefold():
            default_destination = None
            continue

        printer_match = PRINTER_STATUS_RE.fullmatch(line.strip())
        if printer_match:
            name = _safe_queue_name(printer_match.group(1))
            if name is None:
                truncated = True
                continue
            record = _printer_record(records, name)
            detail = printer_match.group(2)
            state_text = detail.split(".", 1)[0].casefold()
            if "disabled" in state_text:
                record["state"] = "disabled"
                record["enabled"] = False
            elif "printing" in state_text:
                record["state"] = "printing"
                record["enabled"] = True
            elif "idle" in state_text:
                record["state"] = "idle"
                record["enabled"] = True
            else:
                record["state"] = "other"
                if "enabled since" in detail.casefold():
                    record["enabled"] = True
            if len(records) > MAX_PRINTERS:
                truncated = True
                break
            continue

        acceptance_match = ACCEPTANCE_RE.match(line.strip())
        if acceptance_match:
            name = _safe_queue_name(acceptance_match.group(1))
            if name is None:
                truncated = True
                continue
            record = _printer_record(records, name)
            record["accepting_jobs"] = acceptance_match.group(2).casefold() == "accepting"
            if len(records) > MAX_PRINTERS:
                truncated = True
                break

    if len(records) > MAX_PRINTERS:
        records = dict(sorted(records.items(), key=lambda item: item[0].casefold())[:MAX_PRINTERS])
        truncated = True

    needle = query.strip().casefold()
    printers = [
        PrinterInfo(name=name, **values)
        for name, values in records.items()
        if not needle or needle in name.casefold() or needle in str(values.get("state", "")).casefold()
    ]
    printers.sort(key=lambda item: item.name.casefold())
    if len(printers) > limit:
        truncated = True

    message = (
        "CUPS queue inventory only. Print jobs, user names, document titles, printer device URIs, and unconfigured network devices are not queried."
    )
    if truncated:
        message += " Results may be partial because an output, line, queue, or response cap was reached."
    return PrinterListResponse(
        success=True,
        total_printers=len(printers),
        returned_printers=min(len(printers), limit),
        printers=printers[:limit],
        default_destination=default_destination,
        limit=limit,
        truncated=truncated,
        message=message,
    )
