"""Confirmed one-shot job control for the current user's at queue."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from wayland_mcp.models import AtJobActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

AtJobAction = Literal["add", "remove"]
MAX_COMMAND_BYTES = 4096
MAX_QUEUE_BYTES = 1024 * 1024
MAX_JOB_BYTES = 512 * 1024
COMMAND_TIMEOUT_SECONDS = 10
_COMMAND_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_JOB_ID = re.compile(r"^[0-9]{1,20}$")
_RUN_AT = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}$")
_AT_OUTPUT_JOB = re.compile(r"\bjob\s+([0-9]{1,20})\s+at\b", re.IGNORECASE)
_AT_TIME = re.compile(r"^[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$")
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass(frozen=True, slots=True)
class AtQueueRow:
    job_id: str
    scheduled_text: str
    scheduled_at: datetime
    queue: str
    username: str
    raw_line: str


@dataclass(frozen=True, slots=True)
class AtJobTarget:
    action: AtJobAction
    username: str
    uid: int
    run_at: datetime | None
    command: str | None
    job_id: str | None
    job_content_digest: str | None
    queue_digest: str
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    timezone = os.environ.get("TZ")
    if timezone and len(timezone) <= 128 and not _COMMAND_CONTROL.search(timezone):
        env["TZ"] = timezone
    try:
        identity = pwd.getpwuid(os.geteuid())
    except (KeyError, OSError):
        pass
    else:
        env["USER"] = identity.pw_name
        env["LOGNAME"] = identity.pw_name
        env["HOME"] = identity.pw_dir
    return env


def at_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    search_env = env or _environment()
    return all(find_session_binary(name, search_env) for name in ("at", "atq", "atrm"))


def _current_identity() -> tuple[str | None, int | None, str | None]:
    try:
        record = pwd.getpwuid(os.geteuid())
    except (KeyError, OSError):
        return None, None, "The server identity has no local passwd record for at-job control."
    if not record.pw_name or any(character in record.pw_name for character in "\r\n\x00"):
        return None, None, "The current server identity name is invalid for at-job control."
    return record.pw_name, record.pw_uid, None


def _run_bounded(
    binary_name: str,
    arguments: list[str],
    *,
    input_data: bytes | None = None,
    output_limit: int = MAX_QUEUE_BYTES,
) -> tuple[bytes | None, str | None]:
    binary = find_session_binary(binary_name, _environment())
    if not binary:
        return None, f"The {binary_name} command is unavailable."
    env = _environment()
    if input_data is None:
        output, error, truncated = run_bounded_command(
            [binary, *arguments],
            env,
            command_label=f"{binary_name} command",
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            max_output_bytes=output_limit,
        )
        if truncated:
            return None, f"The {binary_name} output exceeded its bounded size."
        if error or output is None:
            return None, f"The {binary_name} command could not be completed safely."
        if "\ufffd" in output:
            return None, f"The {binary_name} output is not valid UTF-8."
        return output.encode("utf-8"), None
    try:
        run_options = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "timeout": COMMAND_TIMEOUT_SECONDS,
            "check": False,
            "env": env,
            "close_fds": True,
        }
        if input_data is None:
            run_options["stdin"] = subprocess.DEVNULL
        else:
            run_options["input"] = input_data
        result = subprocess.run([binary, *arguments], **run_options)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None, f"The {binary_name} command could not be completed safely."
    if len(result.stdout) > output_limit or len(result.stderr) > 16 * 1024:
        return None, f"The {binary_name} output exceeded its bounded size."
    if result.returncode != 0:
        return None, f"The {binary_name} command did not complete successfully."
    return result.stdout, None


def _parse_at_time(value: str) -> tuple[datetime | None, str | None]:
    if not isinstance(value, str) or not _RUN_AT.fullmatch(value):
        return None, "run_at must be local time in YYYY-MM-DDTHH:MM format."
    try:
        requested = datetime.strptime(value, "%Y-%m-%dT%H:%M")
    except ValueError:
        return None, "run_at must be a valid local date and time."
    if requested.strftime("%Y-%m-%dT%H:%M") != value:
        return None, "run_at must be a valid local date and time."

    # Reject nonexistent and ambiguous local wall times around DST transitions.
    valid_timestamps: set[float] = set()
    local_fields = requested.timetuple()
    for is_dst in (0, 1):
        try:
            timestamp = time.mktime(local_fields[:8] + (is_dst,))
            if datetime.fromtimestamp(timestamp) == requested:
                valid_timestamps.add(timestamp)
        except (OverflowError, OSError, ValueError):
            continue
    if not valid_timestamps:
        return None, "run_at falls in a local-time transition gap and cannot be scheduled exactly."
    if len(valid_timestamps) > 1:
        return None, "run_at is ambiguous during a local-time transition; choose a different time."
    now = datetime.now()
    if requested <= now + timedelta(minutes=2):
        return None, "run_at must be at least two minutes in the future."
    if requested > now + timedelta(days=365):
        return None, "run_at must be within 365 days."
    return requested, None


def _validate_command(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value:
        return None, f"command must be one non-empty line of at most {MAX_COMMAND_BYTES} UTF-8 bytes."
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return None, "command must contain valid UTF-8 text."
    if len(encoded) > MAX_COMMAND_BYTES:
        return None, f"command must be one non-empty line of at most {MAX_COMMAND_BYTES} UTF-8 bytes."
    if _COMMAND_CONTROL.search(value):
        return None, "command may not contain newline, tab, NUL, or other control characters."
    if value != value.strip() or value.endswith("\\"):
        return None, "command may not have surrounding whitespace or end with a continuation backslash."
    return value, None


def _parse_at_queue(text: str) -> tuple[list[AtQueueRow] | None, str | None]:
    rows: list[AtQueueRow] = []
    ids: set[str] = set()
    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        fields = raw_line.split()
        if len(fields) < 8 or not _JOB_ID.fullmatch(fields[0]):
            return None, "The at queue contains a line that cannot be identified safely."
        job_id = fields[0]
        if job_id in ids:
            return None, "The at queue contains duplicate job identifiers."
        ids.add(job_id)
        scheduled_text = " ".join(fields[1:-2])
        match = _AT_TIME.fullmatch(scheduled_text)
        if not match:
            return None, "The at queue contains an unsupported time format."
        month_text, day_text, hour_text, minute_text, second_text, year_text = match.groups()
        month = _MONTHS.get(month_text.title())
        if month is None:
            return None, "The at queue contains an unsupported month name."
        try:
            scheduled_at = datetime(
                int(year_text), month, int(day_text), int(hour_text), int(minute_text), int(second_text)
            )
        except ValueError:
            return None, "The at queue contains an invalid scheduled date."
        rows.append(AtQueueRow(
            job_id=job_id,
            scheduled_text=scheduled_text,
            scheduled_at=scheduled_at,
            queue=fields[-2],
            username=fields[-1],
            raw_line=raw_line,
        ))
        if len(rows) > 10_000:
            return None, "The at queue exceeded the bounded row limit."
    return rows, None


def _read_queue(username: str) -> tuple[list[AtQueueRow] | None, str | None, str | None]:
    output, error = _run_bounded("atq", [], output_limit=MAX_QUEUE_BYTES)
    if error or output is None:
        return None, None, error or "The at queue could not be read."
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeError:
        return None, None, "The at queue is not valid UTF-8."
    all_rows, error = _parse_at_queue(text)
    if error or all_rows is None:
        return None, None, error or "The at queue could not be parsed safely."
    owned = [row for row in all_rows if row.username == username]
    queue_digest = hashlib.sha256("\n".join(sorted(row.raw_line for row in owned)).encode("utf-8")).hexdigest()
    return owned, queue_digest, None


def _job_content_digest(job_id: str) -> tuple[str | None, str | None]:
    output, error = _run_bounded("at", ["-c", job_id], output_limit=MAX_JOB_BYTES)
    if error or output is None:
        return None, error or "The selected at job could not be inspected safely."
    return hashlib.sha256(output).hexdigest(), None


def at_job_confirmation_details(
    action: str,
    run_at: str = "",
    command: str = "",
    job_id: str = "",
) -> tuple[AtJobTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "One-shot at-job control is available only on Linux."
    if not isinstance(action, str) or action not in {"add", "remove"}:
        return None, None, "action must be add or remove."
    username, uid, error = _current_identity()
    if error or username is None or uid is None:
        return None, None, error or "The current server identity could not be verified."
    if not find_session_binary("atq", _environment()):
        return None, None, "The atq command is required to bind this action to the current queue."
    rows, queue_digest, error = _read_queue(username)
    if error or rows is None or queue_digest is None:
        return None, None, error or "The current user's at queue could not be read."

    parsed_run_at: datetime | None = None
    validated_command: str | None = None
    validated_job_id: str | None = None
    content_digest: str | None = None
    if action == "add":
        if job_id:
            return None, None, "job_id is only valid when removing an at job."
        parsed_run_at, error = _parse_at_time(run_at)
        if error or parsed_run_at is None:
            return None, None, error or "The at schedule could not be validated."
        validated_command, error = _validate_command(command)
        if error or validated_command is None:
            return None, None, error or "The command could not be validated."
        if not find_session_binary("at", _environment()):
            return None, None, "The at command is unavailable."
    else:
        if run_at or command:
            return None, None, "run_at and command are only valid when adding an at job."
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id) or int(job_id) < 1:
            return None, None, "job_id must be a positive decimal identifier from the visible at queue."
        matches = [row for row in rows if row.job_id == job_id]
        if len(matches) != 1:
            return None, None, "The exact at job is not uniquely present in the current user's queue."
        if matches[0].queue == "=":
            return None, None, "The selected at job is already running and cannot be removed as a queued job."
        validated_job_id = job_id
        parsed_run_at = matches[0].scheduled_at
        content_digest, error = _job_content_digest(job_id)
        if error or content_digest is None:
            return None, None, error or "The at job contents could not be bound safely."
        if not find_session_binary("atrm", _environment()):
            return None, None, "The atrm command is unavailable."

    details = {
        "action": action,
        "username": username,
        "uid": uid,
        "run_at": parsed_run_at.isoformat(timespec="minutes") if parsed_run_at else None,
        "command": validated_command,
        "job_id": validated_job_id,
        "job_content_digest": content_digest,
        "queue_digest": queue_digest,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = AtJobTarget(
        action=action,  # type: ignore[arg-type]
        username=username,
        uid=uid,
        run_at=parsed_run_at,
        command=validated_command,
        job_id=validated_job_id,
        job_content_digest=content_digest,
        queue_digest=queue_digest,
        state_digest=digest,
    )
    phrase = hashlib.sha256((action + ":" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"at {phrase}", None


def perform_at_job_action(
    action: AtJobAction,
    run_at: str = "",
    command: str = "",
    job_id: str = "",
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> AtJobActionResponse:
    target, phrase, error = at_job_confirmation_details(action, run_at, command, job_id)
    fallback_time = run_at[:32] if isinstance(run_at, str) and run_at else None
    fallback_job_id = job_id if isinstance(job_id, str) and _JOB_ID.fullmatch(job_id) else None
    if error or target is None or phrase is None:
        return AtJobActionResponse(success=False, action=action, username="", job_id=fallback_job_id, run_at=fallback_time, user_confirmed=confirmed is True, message=error or "The at-job request could not be verified.")
    if confirmed is not True:
        return AtJobActionResponse(success=False, action=action, username=target.username, job_id=target.job_id, run_at=target.run_at.isoformat(timespec="minutes") if target.run_at else None, user_confirmed=False, message="Explicit client confirmation is required; no at job was changed.")
    if confirmation_phrase != phrase:
        return AtJobActionResponse(success=False, action=action, username=target.username, job_id=target.job_id, run_at=target.run_at.isoformat(timespec="minutes") if target.run_at else None, user_confirmed=True, message="Confirmation did not match the exact current-user at job and queue state.")

    current, current_phrase, error = at_job_confirmation_details(action, run_at, command, job_id)
    if error or current is None or current_phrase != phrase:
        return AtJobActionResponse(success=False, action=action, username=target.username, job_id=target.job_id, run_at=target.run_at.isoformat(timespec="minutes") if target.run_at else None, user_confirmed=True, message=error or "The at queue changed after confirmation; no job was changed.")
    rows, queue_digest, error = _read_queue(target.username)
    if error or rows is None or queue_digest != target.queue_digest:
        return AtJobActionResponse(success=False, action=action, username=target.username, job_id=target.job_id, run_at=target.run_at.isoformat(timespec="minutes") if target.run_at else None, user_confirmed=True, message=error or "The at queue changed immediately before the action; no job was changed.")

    if action == "add":
        assert target.run_at is not None and target.command is not None
        stamp = target.run_at.strftime("%Y%m%d%H%M")
        command_bytes = (target.command + "\n").encode("utf-8")
        output, error = _run_bounded("at", ["-M", "-t", stamp], input_data=command_bytes, output_limit=64 * 1024)
        if error or output is None:
            return AtJobActionResponse(success=False, action=action, username=target.username, run_at=target.run_at.isoformat(timespec="minutes"), user_confirmed=True, message=error or "The at command did not accept the job.")
        output_text = output.decode("utf-8", errors="replace")
        job_match = _AT_OUTPUT_JOB.search(output_text)
        after_rows, _after_digest, read_error = _read_queue(target.username)
        if read_error or after_rows is None:
            return AtJobActionResponse(success=False, action=action, username=target.username, run_at=target.run_at.isoformat(timespec="minutes"), user_confirmed=True, message="at accepted the job, but the current-user queue could not be verified.")
        if job_match:
            new_id = job_match.group(1)
            prior_ids = {row.job_id for row in rows}
            matches = [row for row in after_rows if row.job_id == new_id and row.job_id not in prior_ids and row.scheduled_at == target.run_at]
        else:
            prior_ids = {row.job_id for row in rows}
            matches = [row for row in after_rows if row.job_id not in prior_ids and row.scheduled_at == target.run_at]
        if len(matches) != 1:
            return AtJobActionResponse(success=False, action=action, username=target.username, run_at=target.run_at.isoformat(timespec="minutes"), user_confirmed=True, message="at accepted the command, but the exact new queue entry could not be verified; inspect the at queue before retrying.")
        return AtJobActionResponse(success=True, action=action, username=target.username, job_id=matches[0].job_id, run_at=target.run_at.isoformat(timespec="minutes"), user_confirmed=True, message="Added the confirmed one-shot command to the current user's at queue.")

    assert target.job_id is not None and target.job_content_digest is not None
    content_digest, error = _job_content_digest(target.job_id)
    if error or content_digest != target.job_content_digest:
        return AtJobActionResponse(success=False, action=action, username=target.username, job_id=target.job_id, run_at=target.run_at.isoformat(timespec="minutes") if target.run_at else None, user_confirmed=True, message=error or "The selected at job changed immediately before removal; no job was removed.")
    output, error = _run_bounded("atrm", [target.job_id], output_limit=64 * 1024)
    if error or output is None:
        return AtJobActionResponse(success=False, action=action, username=target.username, job_id=target.job_id, run_at=target.run_at.isoformat(timespec="minutes") if target.run_at else None, user_confirmed=True, message=error or "atrm did not accept the removal.")
    after_rows, _after_digest, read_error = _read_queue(target.username)
    if read_error or after_rows is None:
        return AtJobActionResponse(success=False, action=action, username=target.username, job_id=target.job_id, run_at=target.run_at.isoformat(timespec="minutes") if target.run_at else None, user_confirmed=True, message="atrm returned, but the current-user queue could not be read back.")
    verified = all(row.job_id != target.job_id for row in after_rows)
    if not verified:
        return AtJobActionResponse(success=False, action=action, username=target.username, job_id=target.job_id, run_at=target.run_at.isoformat(timespec="minutes") if target.run_at else None, user_confirmed=True, message="atrm returned, but the selected job is still in the current user's queue.")
    return AtJobActionResponse(success=True, action=action, username=target.username, job_id=target.job_id, run_at=target.run_at.isoformat(timespec="minutes") if target.run_at else None, user_confirmed=True, message="Removed the exact confirmed job from the current user's at queue.")
