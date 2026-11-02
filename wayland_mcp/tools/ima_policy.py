"""Bounded, read-only access to the active Linux IMA policy when exposed."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import BinaryIO

from wayland_mcp.models import IMAPolicyListResponse, IMAPolicyRuleInfo

IMA_POLICY = Path("/sys/kernel/security/ima/policy")
MAX_PAGE_LIMIT = 100
MAX_SCAN_BYTES = 1024 * 1024
MAX_RULE_LINE_BYTES = 64 * 1024
MAX_BYTE_OFFSET = 64 * 1024 * 1024


def ima_policy_available() -> bool:
    """Return whether the fixed IMA policy readback path is present."""
    return sys.platform.startswith("linux") and IMA_POLICY.is_file()


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


def _align_to_rule(stream: BinaryIO, offset: int) -> tuple[int, bool, bool]:
    """Seek to a rule boundary; return actual offset, skipped-midline, and hard truncation."""
    if offset == 0:
        return 0, False, False
    stream.seek(offset)
    stream.seek(offset - 1)
    previous = stream.read(1)
    stream.seek(offset)
    if previous == b"\n":
        return offset, False, False
    discarded = stream.readline(MAX_RULE_LINE_BYTES + 1)
    if len(discarded) > MAX_RULE_LINE_BYTES:
        return stream.tell(), True, True
    return stream.tell(), bool(discarded), False


def list_ima_policy(offset: int = 0, limit: int = 50) -> IMAPolicyListResponse:
    """Return a bounded page of raw active IMA policy rules, if readable."""
    if not sys.platform.startswith("linux"):
        return IMAPolicyListResponse(success=False, message="IMA policy readback is available only on Linux.")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > MAX_BYTE_OFFSET:
        safe_offset = offset if isinstance(offset, int) and not isinstance(offset, bool) else 0
        return IMAPolicyListResponse(
            success=False,
            offset=safe_offset,
            start_offset=safe_offset,
            message=f"Offset must be an integer from 0 through {MAX_BYTE_OFFSET} bytes.",
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        return IMAPolicyListResponse(success=False, offset=offset, start_offset=offset, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_PAGE_LIMIT))

    rules: list[IMAPolicyRuleInfo] = []
    unavailable: list[str] = []
    scanned_bytes = 0
    start_offset = offset
    next_offset: int | None = None
    has_more: bool | None = None
    truncated = False
    partial = False
    stop_message: str | None = None

    try:
        with IMA_POLICY.open("rb") as stream:
            start_offset, midline_skipped, align_truncated = _align_to_rule(stream, offset)
            if midline_skipped:
                partial = True
                stop_message = "The supplied byte offset was inside a rule; scanning resumed at the next rule boundary."
            if align_truncated:
                truncated = True
                partial = True
                stop_message = f"A rule exceeded the {MAX_RULE_LINE_BYTES}-byte line cap while aligning the requested offset."
            else:
                eof = False
                while len(rules) < limit:
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
                    raw_line = stream.readline(min(MAX_RULE_LINE_BYTES + 1, remaining_scan + 1, remaining_offset + 1))
                    if not raw_line:
                        eof = True
                        break
                    if len(raw_line) > remaining_offset:
                        truncated = True
                        partial = True
                        has_more = True
                        stop_message = f"The page reached the {MAX_BYTE_OFFSET}-byte continuation-offset cap before this rule."
                        break
                    if len(raw_line) > MAX_RULE_LINE_BYTES:
                        truncated = True
                        partial = True
                        stop_message = f"A policy rule exceeded the {MAX_RULE_LINE_BYTES}-byte line cap; later rules were not scanned."
                        break
                    if len(raw_line) > remaining_scan:
                        truncated = True
                        partial = True
                        next_offset = record_offset
                        stop_message = f"The page scan reached its {MAX_SCAN_BYTES}-byte read cap before this rule."
                        break

                    scanned_bytes += len(raw_line)
                    rule = _escape_control_characters(raw_line.rstrip(b"\r\n").decode("utf-8", errors="replace"))
                    if rule.strip():
                        rules.append(IMAPolicyRuleInfo(byte_offset=record_offset, rule=rule))

                if eof:
                    has_more = False
                elif len(rules) >= limit and next_offset is None:
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
        unavailable.append("ima/policy")
        return IMAPolicyListResponse(
            success=False,
            offset=offset,
            start_offset=offset,
            limit=limit,
            unavailable_sources=unavailable,
            partial=True,
            message="The active IMA policy readback path is not present; kernel read-policy support or securityfs may be unavailable.",
        )
    except PermissionError:
        unavailable.append("ima/policy")
        return IMAPolicyListResponse(
            success=False,
            offset=offset,
            start_offset=offset,
            limit=limit,
            unavailable_sources=unavailable,
            partial=True,
            message="The active IMA policy cannot be read with current permissions; kernel policy readback may require CAP_SYS_ADMIN.",
        )
    except (OSError, ValueError) as exc:
        return IMAPolicyListResponse(
            success=False,
            offset=offset,
            start_offset=offset,
            limit=limit,
            unavailable_sources=["ima/policy"],
            partial=True,
            message=f"The active IMA policy could not be read or seeked: {getattr(exc, 'strerror', None) or str(exc) or 'read error'}.",
        )

    if truncated:
        partial = True
    message_parts = [
        "Read-only snapshot of raw active IMA policy rules. Readback depends on kernel configuration and may require CAP_SYS_ADMIN; rules can contain filesystem identifiers or security labels. No policy changes were made."
    ]
    if stop_message:
        message_parts.append(stop_message)
    return IMAPolicyListResponse(
        success=True,
        offset=offset,
        start_offset=start_offset,
        next_offset=next_offset,
        has_more=has_more,
        scanned_bytes=scanned_bytes,
        returned_rules=len(rules),
        rules=rules,
        limit=limit,
        unavailable_sources=unavailable,
        truncated=truncated,
        partial=partial,
        message=" ".join(message_parts),
    )
