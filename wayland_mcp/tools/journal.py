"""Bounded, read-only systemd journal snapshots."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from typing import Any

from wayland_mcp.models import JournalEntryInfo, JournalEntryListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_JOURNAL_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_SCAN_ENTRIES = 2_000
MAX_RETURNED_ENTRIES = 200
MAX_QUERY_LENGTH = 256
MAX_UNIT_LENGTH = 256
MAX_MESSAGE_LENGTH = 8_192
JOURNAL_TIMEOUT_SECONDS = 15
UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9_.:@%+-]{1,256}$")


def _bounded_text(value: Any, limit: int, *, multiline: bool = False) -> tuple[str | None, bool]:
    if not isinstance(value, str):
        return None, False
    value = value.replace("\x00", "")
    value = "".join(
        character for character in value
        if ord(character) >= 32 and not 127 <= ord(character) <= 159
        or multiline and character in "\n\t"
    )
    if len(value) > limit:
        return value[:limit], True
    return value, False


def _entry_from_json(line: str, query: str) -> tuple[JournalEntryInfo | None, bool, bool]:
    try:
        raw = json.loads(line)
    except (json.JSONDecodeError, RecursionError):
        return None, False, False
    if not isinstance(raw, dict):
        return None, False, False

    timestamp = None
    raw_timestamp = raw.get("__REALTIME_TIMESTAMP")
    if isinstance(raw_timestamp, (str, int)) and not isinstance(raw_timestamp, bool):
        try:
            timestamp_value = int(raw_timestamp)
            if 0 <= timestamp_value <= 253402300799999999:
                seconds, microseconds = divmod(timestamp_value, 1_000_000)
                timestamp = datetime.fromtimestamp(
                    seconds, tz=timezone.utc
                ).replace(microsecond=microseconds).isoformat(timespec="microseconds")
        except (ValueError, OverflowError, OSError):
            timestamp = None

    priority = None
    raw_priority = raw.get("PRIORITY")
    if isinstance(raw_priority, (str, int)) and not isinstance(raw_priority, bool):
        try:
            candidate = int(raw_priority)
            if 0 <= candidate <= 7:
                priority = candidate
        except ValueError:
            pass

    unit = None
    for key in ("_SYSTEMD_UNIT", "_SYSTEMD_USER_UNIT", "UNIT"):
        value, _ = _bounded_text(raw.get(key), MAX_UNIT_LENGTH)
        if value:
            unit = value
            break

    identifier = None
    for key in ("SYSLOG_IDENTIFIER", "_COMM"):
        value, _ = _bounded_text(raw.get(key), 256)
        if value:
            identifier = value
            break

    raw_message = raw.get("MESSAGE")
    searchable_message = raw_message.casefold() if isinstance(raw_message, str) else ""
    message, message_truncated = _bounded_text(raw_message, MAX_MESSAGE_LENGTH, multiline=True)
    matches_query = not query or any(
        query.casefold() in value.casefold()
        for value in (unit or "", identifier or "", searchable_message)
    )
    return JournalEntryInfo(
        timestamp=timestamp,
        priority=priority,
        unit=unit,
        identifier=identifier,
        message=message,
    ), message_truncated, matches_query


def list_journal_entries(
    query: str = "",
    limit: int = 50,
    scope: str = "system",
    boot_offset: int = 0,
    unit: str = "",
    priority: int | None = None,
) -> JournalEntryListResponse:
    """Return a bounded snapshot of recent entries from the systemd journal."""
    if not sys.platform.startswith("linux"):
        return JournalEntryListResponse(success=False, message="Journal inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > MAX_QUERY_LENGTH:
        return JournalEntryListResponse(success=False, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return JournalEntryListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return JournalEntryListResponse(success=False, message="Limit must be an integer.")
    if scope not in ("system", "user"):
        return JournalEntryListResponse(success=False, message="Scope must be 'system' or 'user'.")
    if not isinstance(boot_offset, int) or isinstance(boot_offset, bool) or not -100 <= boot_offset <= 0:
        return JournalEntryListResponse(success=False, message="Boot offset must be an integer from -100 through 0.")
    if not isinstance(unit, str) or len(unit) > MAX_UNIT_LENGTH:
        return JournalEntryListResponse(success=False, message="Unit must be text with at most 256 characters.")
    unit = unit.strip()
    if unit and (unit.startswith("-") or not UNIT_NAME_RE.fullmatch(unit)):
        return JournalEntryListResponse(success=False, message="Unit contains unsupported characters.")
    if priority is not None and (
        not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 7
    ):
        return JournalEntryListResponse(success=False, message="Priority must be an integer from 0 through 7.")

    limit = max(1, min(limit, MAX_RETURNED_ENTRIES))
    query = query.strip()
    scan_limit = min(MAX_SCAN_ENTRIES, max(limit, limit * 10)) if query else limit
    request_count = scan_limit + 1

    env = get_sanitized_env()
    journalctl = find_session_binary("journalctl", env)
    if not journalctl:
        return JournalEntryListResponse(
            success=False,
            scope=scope,
            boot_offset=boot_offset,
            limit=limit,
            message="journalctl is unavailable on this system.",
        )

    command = [
        journalctl,
        "--no-pager",
        "--quiet",
        "--output=json",
        f"--lines={request_count}",
        "--reverse",
        f"--boot={boot_offset}",
        f"--{scope}",
    ]
    if unit:
        command.append(f"--unit={unit}")
    if priority is not None:
        command.append(f"--priority={priority}")

    output, error, output_truncated = run_bounded_command(
        command,
        env,
        command_label="journalctl",
        timeout_seconds=JOURNAL_TIMEOUT_SECONDS,
        max_output_bytes=MAX_JOURNAL_OUTPUT_BYTES,
    )
    if error:
        return JournalEntryListResponse(
            success=False,
            scope=scope,
            boot_offset=boot_offset,
            limit=limit,
            message=f"Could not read journal entries: {error[:400]}",
        )

    lines = (output or "").splitlines()
    has_more = len(lines) > scan_limit
    lines = lines[:scan_limit]
    matching: list[JournalEntryInfo] = []
    malformed = False
    clipped_message = False
    for line in lines:
        entry, was_clipped, matches_query = _entry_from_json(line, query)
        if entry is None:
            malformed = True
            continue
        if matches_query:
            matching.append(entry)
        clipped_message = clipped_message or was_clipped

    returned = matching[:limit]
    truncated = output_truncated or has_more or malformed or clipped_message or len(matching) > limit
    message = None
    if output_truncated:
        message = "Journal output reached the 4 MiB safety limit; the snapshot may be incomplete."
    elif query and has_more:
        message = f"The text search scanned the newest {scan_limit} entries; older entries were not searched."
    elif not query and has_more:
        message = "More recent entries exist beyond the requested result limit."
    elif len(matching) > limit:
        message = "More matching entries were found than the requested result limit."
    elif malformed:
        message = "Some journal records could not be parsed and were omitted."
    elif clipped_message:
        message = "One or more message fields were shortened to the 8192-character limit."

    return JournalEntryListResponse(
        success=True,
        scope=scope,
        boot_offset=boot_offset,
        scanned_entries=len(lines),
        matching_entries=len(matching),
        returned_entries=len(returned),
        entries=returned,
        limit=limit,
        truncated=truncated,
        message=message,
    )
