"""Bounded, read-only snapshots from fixed traditional Linux log files."""

from __future__ import annotations

import os
import stat
import sys

from wayland_mcp.models import SystemLogEntryInfo, SystemLogListResponse, SystemLogSource

LOG_DIRECTORY = "/var/log"
LOG_FILES: dict[SystemLogSource, str] = {
    "syslog": "syslog",
    "messages": "messages",
    "kern": "kern.log",
    "dmesg": "dmesg",
    "auth": "auth.log",
    "secure": "secure",
}
MAX_LOG_BYTES = 1 * 1024 * 1024
MAX_SCAN_ENTRIES = 20_000
MAX_RETURNED_ENTRIES = 200
MAX_QUERY_LENGTH = 256
MAX_LINE_LENGTH = 8_192
READ_CHUNK_BYTES = 64 * 1024


def _open_log_directory() -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(LOG_DIRECTORY, flags)


def _open_log_file(source: SystemLogSource) -> int:
    filename = LOG_FILES[source]
    directory_fd = _open_log_directory()
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        return os.open(filename, flags, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def system_log_source_readiness() -> tuple[tuple[SystemLogSource, ...], tuple[SystemLogSource, ...], bool]:
    """Return readable sources, source-level permission blocks, and a directory block."""
    if not sys.platform.startswith("linux"):
        return (), (), False
    try:
        directory_fd = _open_log_directory()
    except PermissionError:
        return (), (), True
    except OSError:
        return (), (), False

    available: list[SystemLogSource] = []
    permission_blocked: list[SystemLogSource] = []
    try:
        for source, filename in LOG_FILES.items():
            try:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(filename, flags, dir_fd=directory_fd)
            except PermissionError:
                permission_blocked.append(source)
                continue
            except OSError:
                continue
            try:
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    available.append(source)
            except OSError:
                continue
            finally:
                os.close(fd)
    finally:
        os.close(directory_fd)
    return tuple(available), tuple(permission_blocked), False


def _read_tail(source: SystemLogSource) -> tuple[list[str], bool, bool]:
    fd = _open_log_file(source)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("selected source is not a regular file")
        start = max(0, info.st_size - MAX_LOG_BYTES)
        remaining = min(MAX_LOG_BYTES, max(0, info.st_size - start))
        if start:
            os.lseek(fd, start, os.SEEK_SET)
        chunks: list[bytes] = []
        read_bytes = 0
        while read_bytes < remaining:
            chunk = os.read(fd, min(READ_CHUNK_BYTES, remaining - read_bytes))
            if not chunk:
                break
            chunks.append(chunk)
            read_bytes += len(chunk)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        lines = text.splitlines()
        if start and lines:
            # The first line begins in the middle of a record cut by the byte cap.
            lines = lines[1:]
        scan_truncated = len(lines) > MAX_SCAN_ENTRIES
        if scan_truncated:
            lines = lines[-MAX_SCAN_ENTRIES:]
        return lines, bool(start), scan_truncated
    finally:
        os.close(fd)


def _sanitize_line(value: str) -> tuple[str, bool]:
    value = "".join(
        character for character in value
        if character == "\t" or (ord(character) >= 32 and not 127 <= ord(character) <= 159)
    )
    if len(value) > MAX_LINE_LENGTH:
        return value[:MAX_LINE_LENGTH], True
    return value, False


def list_system_log_entries(
    source: SystemLogSource,
    query: str = "",
    limit: int = 50,
) -> SystemLogListResponse:
    """Return a bounded snapshot from one fixed /var/log text source."""
    if not isinstance(source, str) or source not in LOG_FILES:
        return SystemLogListResponse(success=False, source="syslog", message="Unsupported source; choose syslog, messages, kern, dmesg, auth, or secure.")
    if not sys.platform.startswith("linux"):
        return SystemLogListResponse(success=False, source=source, message="Traditional system log files are available only on Linux.")
    if not isinstance(query, str) or len(query) > MAX_QUERY_LENGTH:
        return SystemLogListResponse(success=False, source=source, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in query):
        return SystemLogListResponse(success=False, source=source, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return SystemLogListResponse(success=False, source=source, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_ENTRIES))

    try:
        lines, byte_truncated, scan_truncated = _read_tail(source)
    except FileNotFoundError:
        return SystemLogListResponse(success=False, source=source, limit=limit, message="The selected log source is not present.")
    except PermissionError:
        return SystemLogListResponse(success=False, source=source, limit=limit, message="The selected log source is not readable with current permissions.")
    except (OSError, ValueError):
        return SystemLogListResponse(success=False, source=source, limit=limit, message="The selected log source could not be read as a regular file.")

    folded_query = query.strip().casefold()
    entries: list[SystemLogEntryInfo] = []
    matching = 0
    clipped = False
    for line in reversed(lines):
        if folded_query and folded_query not in line.casefold():
            continue
        matching += 1
        if len(entries) < limit:
            sanitized, was_clipped = _sanitize_line(line)
            entries.append(SystemLogEntryInfo(source=source, line=sanitized))
            clipped = clipped or was_clipped

    truncated = byte_truncated or scan_truncated or matching > limit or clipped
    message = None
    if byte_truncated:
        message = "Only the most recent 1 MiB of the source was scanned; older lines were omitted."
    elif scan_truncated:
        message = f"Only the newest {MAX_SCAN_ENTRIES} lines in the bounded byte window were scanned."
    elif matching > limit:
        message = "More matching lines were found than the requested result limit."
    elif clipped:
        message = "One or more lines were shortened to the 8192-character limit."

    return SystemLogListResponse(
        success=True,
        source=source,
        scanned_entries=len(lines),
        matching_entries=matching,
        returned_entries=len(entries),
        entries=entries,
        limit=limit,
        truncated=truncated,
        message=message,
    )
