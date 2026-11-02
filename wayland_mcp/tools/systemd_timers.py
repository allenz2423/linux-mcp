"""Bounded, read-only systemd timer inventory for system and user scopes."""

from __future__ import annotations

import re
import sys
from typing import Literal

from wayland_mcp.models import SystemdTimerInfo, SystemdTimerListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.host import _detect_init_system

MAX_TIMERS = 10_000
MAX_RETURNED_TIMERS = 200
MAX_SYSTEMCTL_OUTPUT_BYTES = 2 * 1024 * 1024
SYSTEMCTL_TIMEOUT_SECONDS = 10


def _parse_timer_line(line: str) -> SystemdTimerInfo | None:
    """Parse one aligned `systemctl list-timers` data row under the C locale."""
    fields = re.split(r"\s{2,}", line.strip())
    if len(fields) != 6:
        return None
    unit = fields[4].strip()
    if not unit.endswith(".timer") or len(unit) > 255:
        return None
    values = [None if value.strip() in {"", "-"} else value.strip() for value in fields]
    return SystemdTimerInfo(
        next_run=values[0],
        time_until_next=values[1],
        last_run=values[2],
        time_since_last=values[3],
        unit=unit,
        activates=values[5],
    )


def list_systemd_timers(
    query: str = "",
    limit: int = 100,
    scope: Literal["system", "user"] = "system",
) -> SystemdTimerListResponse:
    """List timer units loaded by one systemd manager without changing state."""
    if not sys.platform.startswith("linux"):
        return SystemdTimerListResponse(
            success=False,
            scope=scope if scope in {"system", "user"} else "system",
            limit=limit,
            message="Systemd timer inventory is available only on Linux.",
        )
    if scope not in {"system", "user"}:
        return SystemdTimerListResponse(success=False, limit=limit, message="Scope must be 'system' or 'user'.")
    if not isinstance(query, str) or len(query) > 256:
        return SystemdTimerListResponse(success=False, scope=scope, limit=limit, message="Query must be text with at most 256 characters.")
    try:
        bounded_limit = max(1, min(int(limit), MAX_RETURNED_TIMERS))
    except (TypeError, ValueError, OverflowError):
        return SystemdTimerListResponse(success=False, scope=scope, message="Limit must be an integer from 1 to 200.")
    if _detect_init_system() != "systemd":
        return SystemdTimerListResponse(
            success=False,
            scope=scope,
            limit=bounded_limit,
            message="Systemd timer inventory requires systemd as the active init system.",
        )

    env = dict(get_sanitized_env())
    systemctl = find_session_binary("systemctl", env)
    if not systemctl:
        return SystemdTimerListResponse(
            success=False,
            scope=scope,
            limit=bounded_limit,
            message="systemctl is unavailable in the sanitized session PATH.",
        )
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    env["SYSTEMD_COLORS"] = "0"
    env["SYSTEMD_URLIFY"] = "0"
    env["TERM"] = "dumb"
    command = [systemctl]
    if scope == "user":
        command.append("--user")
    command.extend(("--no-pager", "--all", "--plain", "--full", "--no-legend", "list-timers"))
    output, error, output_truncated = run_bounded_command(
        command,
        env,
        command_label="systemd timer inventory",
        timeout_seconds=SYSTEMCTL_TIMEOUT_SECONDS,
        max_output_bytes=MAX_SYSTEMCTL_OUTPUT_BYTES,
    )
    if output is None:
        return SystemdTimerListResponse(
            success=False,
            scope=scope,
            limit=bounded_limit,
            message=error or "systemctl could not list timers for the selected manager.",
        )

    needle = query.strip().casefold()
    timers: list[SystemdTimerInfo] = []
    malformed_rows = 0
    scan_truncated = False
    for line_number, line in enumerate(output.splitlines(), start=1):
        if line_number > MAX_TIMERS:
            scan_truncated = True
            break
        if not line.strip() or re.fullmatch(r"\d+ timers? listed\.", line.strip()):
            continue
        timer = _parse_timer_line(line)
        if timer is None:
            malformed_rows += 1
            continue
        if needle and needle not in timer.unit.casefold() and needle not in (timer.activates or "").casefold():
            continue
        timers.append(timer)

    messages = [
        "Only timer units currently loaded by the selected systemd manager are included; --all includes loaded inactive timers."
    ]
    if malformed_rows:
        messages.append(f"Skipped {malformed_rows} output lines that did not match the timer format.")
    if output_truncated or scan_truncated:
        messages.append(f"Timer scan was capped at {MAX_TIMERS} rows or {MAX_SYSTEMCTL_OUTPUT_BYTES} bytes.")
    return SystemdTimerListResponse(
        success=True,
        scope=scope,
        total_timers=len(timers),
        returned_timers=min(len(timers), bounded_limit),
        timers=timers[:bounded_limit],
        limit=bounded_limit,
        truncated=len(timers) > bounded_limit or output_truncated or scan_truncated,
        message=" ".join(messages),
    )
