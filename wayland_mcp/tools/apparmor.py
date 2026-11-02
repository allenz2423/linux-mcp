"""Bounded, read-only inventory of loaded AppArmor profile names and modes."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import BinaryIO

from wayland_mcp.models import AppArmorProfileInfo, AppArmorProfileListResponse

APPARMOR_PROFILES = Path("/sys/kernel/security/apparmor/profiles")
MAX_PAGE_LIMIT = 100
MAX_SCAN_BYTES = 1024 * 1024
MAX_ENTRY_LINE_BYTES = 16 * 1024
MAX_BYTE_OFFSET = 64 * 1024 * 1024
MODE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def apparmor_profiles_available() -> bool:
    """Return whether the fixed AppArmor profile-list interface is present."""
    return sys.platform.startswith("linux") and APPARMOR_PROFILES.is_file()


def _escape_control_characters(value: str) -> str:
    escaped: list[str] = []
    for character in value:
        codepoint = ord(character)
        if codepoint < 32 or 127 <= codepoint <= 159:
            if codepoint <= 255:
                escaped.append(f"\\x{codepoint:02x}")
            else:
                escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def _align_to_entry(stream: BinaryIO, offset: int) -> tuple[int, bool, bool]:
    """Seek to an entry boundary; return actual offset, skipped-midline, and hard truncation."""
    if offset == 0:
        return 0, False, False
    stream.seek(offset)
    stream.seek(offset - 1)
    previous = stream.read(1)
    stream.seek(offset)
    if previous == b"\n":
        return offset, False, False
    discarded = stream.readline(MAX_ENTRY_LINE_BYTES + 1)
    if len(discarded) > MAX_ENTRY_LINE_BYTES:
        return stream.tell(), True, True
    return stream.tell(), bool(discarded), False


def _parse_entry(raw_line: bytes, byte_offset: int) -> AppArmorProfileInfo | None:
    entry = raw_line.rstrip(b"\r\n").decode("utf-8", errors="replace")
    profile_name, separator, mode_with_close = entry.rpartition(" (")
    if not separator or not profile_name or not mode_with_close.endswith(")"):
        return None
    mode = mode_with_close[:-1]
    if not MODE_RE.fullmatch(mode):
        return None
    return AppArmorProfileInfo(name=_escape_control_characters(profile_name), mode=mode)


def list_apparmor_profiles(offset: int = 0, limit: int = 100) -> AppArmorProfileListResponse:
    """Return a bounded page of kernel-reported loaded AppArmor profiles."""
    if not sys.platform.startswith("linux"):
        return AppArmorProfileListResponse(success=False, message="AppArmor profile inventory is available only on Linux.")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > MAX_BYTE_OFFSET:
        safe_offset = offset if isinstance(offset, int) and not isinstance(offset, bool) else 0
        return AppArmorProfileListResponse(
            success=False,
            offset=safe_offset,
            start_offset=safe_offset,
            message=f"Offset must be an integer from 0 through {MAX_BYTE_OFFSET} bytes.",
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        return AppArmorProfileListResponse(
            success=False,
            offset=offset,
            start_offset=offset,
            message="Limit must be an integer.",
        )
    limit = max(1, min(limit, MAX_PAGE_LIMIT))

    profiles: list[AppArmorProfileInfo] = []
    unavailable: list[str] = []
    scanned_bytes = 0
    start_offset = offset
    next_offset: int | None = None
    has_more: bool | None = None
    truncated = False
    partial = False
    stop_message: str | None = None

    try:
        with APPARMOR_PROFILES.open("rb") as stream:
            start_offset, midline_skipped, align_truncated = _align_to_entry(stream, offset)
            if midline_skipped:
                partial = True
                stop_message = "The supplied byte offset was inside an entry; scanning resumed at the next profile boundary."
            if align_truncated:
                truncated = True
                partial = True
                stop_message = f"A profile entry exceeded the {MAX_ENTRY_LINE_BYTES}-byte line cap while aligning the requested offset."
            else:
                eof = False
                while len(profiles) < limit:
                    record_offset = stream.tell()
                    remaining_offset = MAX_BYTE_OFFSET - record_offset
                    if remaining_offset <= 0:
                        truncated = True
                        partial = True
                        has_more = bool(stream.read(1))
                        stop_message = f"The page reached the {MAX_BYTE_OFFSET}-byte continuation-offset cap."
                        break
                    remaining_scan = MAX_SCAN_BYTES - scanned_bytes
                    if remaining_scan <= 0:
                        truncated = True
                        partial = True
                        next_offset = record_offset
                        stop_message = f"The page scan reached its {MAX_SCAN_BYTES}-byte read cap."
                        break
                    raw_line = stream.readline(min(MAX_ENTRY_LINE_BYTES + 1, remaining_scan + 1, remaining_offset + 1))
                    if not raw_line:
                        eof = True
                        break
                    if len(raw_line) > remaining_offset:
                        truncated = True
                        partial = True
                        has_more = True
                        stop_message = f"The page reached the {MAX_BYTE_OFFSET}-byte continuation-offset cap before this entry."
                        break
                    if len(raw_line) > MAX_ENTRY_LINE_BYTES:
                        truncated = True
                        partial = True
                        stop_message = f"A profile entry exceeded the {MAX_ENTRY_LINE_BYTES}-byte line cap; later entries were not scanned."
                        break
                    if len(raw_line) > remaining_scan:
                        truncated = True
                        partial = True
                        next_offset = record_offset
                        stop_message = f"The page scan reached its {MAX_SCAN_BYTES}-byte read cap before this entry."
                        break

                    scanned_bytes += len(raw_line)
                    profile = _parse_entry(raw_line, record_offset)
                    if profile is None:
                        partial = True
                        stop_message = "An unrecognized profile entry was skipped."
                        continue
                    profiles.append(profile)

                if eof:
                    has_more = False
                elif len(profiles) >= limit and next_offset is None:
                    candidate_offset = stream.tell()
                    has_more = bool(stream.read(1))
                    if has_more:
                        if candidate_offset < MAX_BYTE_OFFSET:
                            next_offset = candidate_offset
                        else:
                            truncated = True
                            partial = True
                            stop_message = f"The page reached the {MAX_BYTE_OFFSET}-byte continuation-offset cap."
                elif next_offset is not None:
                    has_more = bool(stream.read(1))
                    if not has_more:
                        next_offset = None
    except FileNotFoundError:
        unavailable.append("apparmor/profiles")
        return AppArmorProfileListResponse(
            success=False,
            offset=offset,
            start_offset=offset,
            limit=limit,
            unavailable_sources=unavailable,
            partial=True,
            message="The AppArmor securityfs profile list is not present; AppArmor may be disabled or securityfs unavailable.",
        )
    except PermissionError:
        unavailable.append("apparmor/profiles")
        return AppArmorProfileListResponse(
            success=False,
            offset=offset,
            start_offset=offset,
            limit=limit,
            unavailable_sources=unavailable,
            partial=True,
            message="The AppArmor securityfs profile list is not readable with current permissions.",
        )
    except (OSError, ValueError) as exc:
        return AppArmorProfileListResponse(
            success=False,
            offset=offset,
            start_offset=offset,
            limit=limit,
            unavailable_sources=["apparmor/profiles"],
            partial=True,
            message=f"The AppArmor profile list could not be read or seeked: {getattr(exc, 'strerror', None) or str(exc) or 'read error'}.",
        )

    if truncated:
        partial = True
    message_parts = [
        "Read-only inventory of loaded AppArmor profile names and kernel-reported modes. It does not return profile rules, assess policy completeness, or change profile state."
    ]
    if stop_message:
        message_parts.append(stop_message)
    return AppArmorProfileListResponse(
        success=True,
        offset=offset,
        start_offset=start_offset,
        next_offset=next_offset,
        has_more=has_more,
        scanned_bytes=scanned_bytes,
        returned_profiles=len(profiles),
        profiles=profiles,
        limit=limit,
        unavailable_sources=unavailable,
        truncated=truncated,
        partial=partial,
        message=" ".join(message_parts),
    )
