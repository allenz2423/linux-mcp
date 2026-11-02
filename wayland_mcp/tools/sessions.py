"""Bounded read-only logind session inventory."""

from __future__ import annotations

import re

from wayland_mcp.models import LoginSessionInfo, LoginSessionListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_SESSIONS = 10_000
MAX_RETURNED_SESSIONS = 200
MAX_LOGINCTL_OUTPUT_BYTES = 2 * 1024 * 1024
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")


def _clean_token(value: str) -> str:
    return "".join(character for character in value if ord(character) >= 32 and ord(character) != 127)[:256]


def list_login_sessions(query: str = "", limit: int = 50) -> LoginSessionListResponse:
    """List bounded active logind sessions without remote host or process details."""
    if not isinstance(query, str) or len(query) > 256:
        return LoginSessionListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return LoginSessionListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return LoginSessionListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_SESSIONS))
    env = get_sanitized_env()
    loginctl = find_session_binary("loginctl", env)
    if not loginctl:
        return LoginSessionListResponse(
            success=False,
            limit=limit,
            message="loginctl is unavailable; logind session inventory cannot be read.",
        )
    output, error, output_truncated = run_bounded_command(
        [loginctl, "--no-pager", "list-sessions"],
        env,
        command_label="loginctl session inventory",
        timeout_seconds=5,
        max_output_bytes=MAX_LOGINCTL_OUTPUT_BYTES,
    )
    if output is None:
        return LoginSessionListResponse(
            success=False,
            limit=limit,
            message=error or "loginctl could not list sessions.",
        )

    lines = output.splitlines()
    header_index = next(
        (
            index for index, line in enumerate(lines)
            if {"SESSION", "UID", "USER"}.issubset(set(line.split()))
        ),
        None,
    )
    if header_index is None and output.strip():
        return LoginSessionListResponse(
            success=False,
            limit=limit,
            message="loginctl returned an unrecognized session-list format.",
        )
    columns = (
        {name: index for index, name in enumerate(lines[header_index].split())}
        if header_index is not None else {}
    )
    row_lines = lines[header_index + 1:header_index + 1 + MAX_SESSIONS] if header_index is not None else []
    sessions: list[LoginSessionInfo] = []
    for line in row_lines:
        fields = line.split()
        if not fields:
            continue
        required_indices = (columns["SESSION"], columns["UID"], columns["USER"])
        if len(fields) <= max(required_indices):
            continue
        session_id = fields[columns["SESSION"]]
        if not SESSION_ID_RE.fullmatch(session_id):
            continue
        try:
            uid = int(fields[columns["UID"]], 10)
        except ValueError:
            continue
        if uid < 0 or uid > 4_294_967_295:
            continue
        username = _clean_token(fields[columns["USER"]])
        if not username:
            continue

        def optional_column(name: str) -> str | None:
            index = columns.get(name)
            if index is None or index >= len(fields) or fields[index] == "-":
                return None
            return _clean_token(fields[index]) or None

        seat = optional_column("SEAT")
        tty = optional_column("TTY")
        state = optional_column("STATE")
        idle_token = (optional_column("IDLE") or "-").casefold()
        idle = idle_token == "yes" if idle_token in {"yes", "no"} else None
        sessions.append(LoginSessionInfo(
            session_id=session_id,
            uid=uid,
            username=username,
            seat=seat,
            tty=tty,
            state=state,
            idle=idle,
        ))

    needle = query.strip().casefold()
    if needle:
        sessions = [
            session for session in sessions
            if needle in session.session_id.casefold()
            or needle in session.username.casefold()
            or needle in (session.seat or "").casefold()
            or needle in (session.tty or "").casefold()
            or needle in (session.state or "").casefold()
        ]
    sessions.sort(key=lambda item: (item.uid, item.session_id))
    scan_truncated = output_truncated or len(lines) > MAX_SESSIONS + 1
    truncated = scan_truncated or len(sessions) > limit
    return LoginSessionListResponse(
        success=True,
        total_sessions=len(sessions),
        returned_sessions=min(len(sessions), limit),
        sessions=sessions[:limit],
        limit=limit,
        truncated=truncated,
        message=(
            f"Session scan was capped at {MAX_SESSIONS} entries or {MAX_LOGINCTL_OUTPUT_BYTES} bytes."
            if scan_truncated else None
        ),
    )
