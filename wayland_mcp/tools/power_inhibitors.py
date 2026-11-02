"""Read-only inventory of active logind power inhibitors."""

from __future__ import annotations

import re
import shlex
import sys

from wayland_mcp.models import PowerInhibitorInfo, PowerInhibitorListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_OUTPUT_BYTES = 1024 * 1024
MAX_INHIBITORS = 2000
MAX_RETURNED_INHIBITORS = 200
INHIBITED_OPERATION_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
INHIBITOR_MODES = {"block", "block-weak", "delay"}


def _clean_text(value: str, max_length: int = 512) -> tuple[str, bool]:
    cleaned = " ".join("".join(ch if ch.isprintable() else " " for ch in value).split())
    return cleaned[:max_length], len(cleaned) > max_length


def _parse_inhibitors(output: str) -> tuple[int, list[PowerInhibitorInfo], bool] | None:
    """Parse busctl's a(ssssuu) result and retain only logind inhibitor fields."""
    try:
        fields = shlex.split(output, posix=True)
    except ValueError:
        return None
    if len(fields) < 2 or fields[0] != "a(ssssuu)":
        return None
    try:
        total = int(fields[1], 10)
    except ValueError:
        return None
    if total < 0:
        return None
    if len(fields) != 2 + total * 6:
        return None

    partial = total > MAX_INHIBITORS
    inhibitors: list[PowerInhibitorInfo] = []
    for index in range(min(total, MAX_INHIBITORS)):
        offset = 2 + index * 6
        what = fields[offset]
        who, who_truncated = _clean_text(fields[offset + 1])
        why, why_truncated = _clean_text(fields[offset + 2])
        mode = fields[offset + 3]
        partial = partial or who_truncated or why_truncated
        try:
            uid = int(fields[offset + 4], 10)
            pid = int(fields[offset + 5], 10)
        except ValueError:
            partial = True
            continue
        if not (0 <= uid <= 4_294_967_295 and 0 <= pid <= 4_294_967_295):
            partial = True
            continue
        if len(what) > 512:
            partial = True
            continue
        raw_operations = what.split(":")
        valid_operations = [
            operation for operation in raw_operations
            if INHIBITED_OPERATION_RE.fullmatch(operation)
        ]
        if len(valid_operations) != len(raw_operations):
            partial = True
        operations = tuple(sorted(set(valid_operations)))
        if not operations or mode not in INHIBITOR_MODES:
            partial = True
            continue
        inhibitors.append(PowerInhibitorInfo(
            who=who,
            operations=list(operations),
            why=why,
            mode=mode,
            uid=uid,
            pid=pid,
        ))

    inhibitors.sort(key=lambda entry: (tuple(entry.operations), entry.mode, entry.who.casefold(), entry.uid, entry.pid))
    return total, inhibitors, partial


def list_power_inhibitors(limit: int = 50) -> PowerInhibitorListResponse:
    """Return bounded inhibitor owner/reason and operation fields, without process names or command lines."""
    if not sys.platform.startswith("linux"):
        return PowerInhibitorListResponse(
            success=False,
            message="Power-inhibitor inventory is available only on Linux.",
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        return PowerInhibitorListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_INHIBITORS))

    env = get_sanitized_env()
    busctl = find_session_binary("busctl", env)
    if not busctl:
        return PowerInhibitorListResponse(
            success=False,
            limit=limit,
            message="busctl is unavailable in the sanitized session PATH.",
        )
    output, _error, output_truncated = run_bounded_command(
        [
            busctl,
            "--system",
            "--timeout=4s",
            "call",
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "ListInhibitors",
        ],
        env,
        command_label="logind inhibitor inventory",
        timeout_seconds=5.0,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if output is None:
        return PowerInhibitorListResponse(
            success=False,
            partial=True,
            limit=limit,
            message="The system logind inhibitor interface is unavailable or unreadable.",
        )
    if output_truncated:
        return PowerInhibitorListResponse(
            success=False,
            partial=True,
            limit=limit,
            message="The system logind inhibitor response exceeded the output bound.",
        )
    parsed = _parse_inhibitors(output)
    if parsed is None:
        return PowerInhibitorListResponse(
            success=False,
            partial=True,
            limit=limit,
            message="busctl returned an unrecognized logind inhibitor response.",
        )

    total_inhibitors, inhibitors, partial = parsed
    returned = inhibitors[:limit]
    truncated = total_inhibitors > len(returned) or total_inhibitors > MAX_INHIBITORS
    return PowerInhibitorListResponse(
        success=True,
        partial=partial or truncated,
        total_inhibitors=total_inhibitors,
        returned_inhibitors=len(returned),
        inhibitors=returned,
        limit=limit,
        truncated=truncated,
        message=(
            "Some inhibitor rows were malformed or exceeded the inventory bound."
            if partial else None
        ),
    )
