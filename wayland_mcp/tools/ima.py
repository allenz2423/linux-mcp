"""Bounded, read-only access to the Linux IMA ASCII measurement interface."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import BinaryIO

from wayland_mcp.models import IMAMeasurementInfo, IMAMeasurementListResponse

IMA_ROOT = Path("/sys/kernel/security/ima")
IMA_ASCII_MEASUREMENTS = IMA_ROOT / "ascii_runtime_measurements"
IMA_RUNTIME_MEASUREMENTS_COUNT = IMA_ROOT / "runtime_measurements_count"
IMA_VIOLATIONS = IMA_ROOT / "violations"

MAX_PAGE_LIMIT = 100
MAX_SCAN_BYTES = 2 * 1024 * 1024
MAX_RECORD_LINE_BYTES = 256 * 1024
MAX_TEMPLATE_DATA_BYTES = 4096
MAX_BYTE_OFFSET = 64 * 1024 * 1024
MAX_COUNTER_BYTES = 32

COUNTER_RE = re.compile(r"^\d{1,20}$")
PCR_RE = re.compile(r"^\d{1,3}$")
HEX_DIGEST_RE = re.compile(r"^[0-9a-fA-F]{2,256}$")
TEMPLATE_NAME_RE = re.compile(r"^[A-Za-z0-9_.:+|\-]{1,256}$")


def ima_measurements_available() -> bool:
    """Return whether the fixed ASCII IMA measurement interface is present."""
    return sys.platform.startswith("linux") and IMA_ASCII_MEASUREMENTS.is_file()


def _read_counter(path: Path) -> int | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_COUNTER_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_COUNTER_BYTES:
        return None
    try:
        value = raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        return None
    if not COUNTER_RE.fullmatch(value):
        return None
    try:
        return int(value, 10)
    except ValueError:
        return None


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


def _parse_measurement(raw_line: bytes, byte_offset: int) -> tuple[IMAMeasurementInfo | None, bool]:
    line = raw_line.rstrip(b"\r\n").decode("utf-8", errors="replace")
    fields = line.split(None, 3)
    if len(fields) < 3 or not PCR_RE.fullmatch(fields[0]):
        return None, False
    if not HEX_DIGEST_RE.fullmatch(fields[1]) or len(fields[1]) % 2:
        return None, False
    if not TEMPLATE_NAME_RE.fullmatch(fields[2]):
        return None, False
    try:
        pcr_index = int(fields[0], 10)
    except ValueError:
        return None, False
    if pcr_index > 255:
        return None, False

    template_data = _escape_control_characters(fields[3] if len(fields) == 4 else "")
    encoded_data = template_data.encode("utf-8")
    data_truncated = len(encoded_data) > MAX_TEMPLATE_DATA_BYTES
    if data_truncated:
        template_data = encoded_data[:MAX_TEMPLATE_DATA_BYTES].decode("utf-8", errors="ignore")
    return IMAMeasurementInfo(
        byte_offset=byte_offset,
        pcr_index=pcr_index,
        template_digest=fields[1],
        template_name=fields[2],
        template_data=template_data,
        template_data_truncated=data_truncated,
    ), data_truncated


def _align_to_record(stream: BinaryIO, offset: int) -> tuple[int, bool, bool]:
    """Seek to a record boundary; return actual offset, skipped-midline, and hard truncation."""
    if offset == 0:
        return 0, False, False
    stream.seek(offset)
    stream.seek(offset - 1)
    previous = stream.read(1)
    stream.seek(offset)
    if previous == b"\n":
        return offset, False, False
    discarded = stream.readline(MAX_RECORD_LINE_BYTES + 1)
    if len(discarded) > MAX_RECORD_LINE_BYTES:
        return stream.tell(), True, True
    return stream.tell(), bool(discarded), False


def list_ima_measurements(offset: int = 0, limit: int = 50) -> IMAMeasurementListResponse:
    """Return a bounded page from the fixed, ASCII IMA runtime-measurement log."""
    if not sys.platform.startswith("linux"):
        return IMAMeasurementListResponse(success=False, message="IMA measurements are available only on Linux.")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > MAX_BYTE_OFFSET:
        return IMAMeasurementListResponse(success=False, message=f"Offset must be an integer from 0 through {MAX_BYTE_OFFSET} bytes.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return IMAMeasurementListResponse(success=False, offset=offset, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_PAGE_LIMIT))

    runtime_count = _read_counter(IMA_RUNTIME_MEASUREMENTS_COUNT)
    violations = _read_counter(IMA_VIOLATIONS)
    unavailable: list[str] = []
    if runtime_count is None:
        unavailable.append("runtime_measurements_count")
    if violations is None:
        unavailable.append("violations")

    measurements: list[IMAMeasurementInfo] = []
    scanned_bytes = 0
    truncated = False
    partial = bool(unavailable)
    start_offset = offset
    next_offset: int | None = None
    has_more: bool | None = None
    stop_message: str | None = None

    try:
        with IMA_ASCII_MEASUREMENTS.open("rb") as stream:
            start_offset, midline_skipped, align_truncated = _align_to_record(stream, offset)
            if midline_skipped:
                partial = True
                stop_message = "The supplied byte offset was inside a record; scanning resumed at the next record boundary."
            if align_truncated:
                truncated = True
                partial = True
                stop_message = "A record exceeded the 256 KiB line cap while aligning the requested offset."
                next_offset = None
            else:
                eof = False
                while len(measurements) < limit:
                    record_offset = stream.tell()
                    remaining_offset = MAX_BYTE_OFFSET - record_offset
                    if remaining_offset <= 0:
                        truncated = True
                        partial = True
                        has_more = bool(stream.read(1))
                        stop_message = f"The page reached the {MAX_BYTE_OFFSET}-byte continuation-offset cap."
                        break
                    remaining = MAX_SCAN_BYTES - scanned_bytes
                    if remaining <= 0:
                        truncated = True
                        partial = True
                        next_offset = record_offset
                        stop_message = f"The page scan reached its {MAX_SCAN_BYTES}-byte read cap."
                        break
                    raw_line = stream.readline(min(MAX_RECORD_LINE_BYTES + 1, remaining + 1, remaining_offset + 1))
                    if not raw_line:
                        eof = True
                        break
                    if len(raw_line) > remaining_offset:
                        truncated = True
                        partial = True
                        has_more = True
                        stop_message = f"The page reached the {MAX_BYTE_OFFSET}-byte continuation-offset cap before this record."
                        break
                    if len(raw_line) > MAX_RECORD_LINE_BYTES:
                        truncated = True
                        partial = True
                        stop_message = "A measurement record exceeded the 256 KiB line cap; later records were not scanned."
                        next_offset = None
                        break
                    if len(raw_line) > remaining:
                        truncated = True
                        partial = True
                        next_offset = record_offset
                        stop_message = f"The page scan reached its {MAX_SCAN_BYTES}-byte read cap before this record."
                        break
                    scanned_bytes += len(raw_line)
                    measurement, data_truncated = _parse_measurement(raw_line, record_offset)
                    if measurement is None:
                        partial = True
                        continue
                    measurements.append(measurement)
                    if data_truncated:
                        truncated = True
                        partial = True

                if eof:
                    has_more = False
                elif len(measurements) >= limit and next_offset is None:
                    candidate_offset = stream.tell()
                    has_more = bool(stream.read(1))
                    if has_more:
                        if candidate_offset < MAX_BYTE_OFFSET:
                            next_offset = candidate_offset
                        else:
                            truncated = True
                            partial = True
                            stop_message = f"The page reached the {MAX_BYTE_OFFSET}-byte continuation-offset cap."
                    else:
                        next_offset = None
                elif next_offset is not None:
                    has_more = bool(stream.read(1))
                    if not has_more:
                        next_offset = None
    except FileNotFoundError:
        return IMAMeasurementListResponse(
            success=False,
            offset=offset,
            start_offset=offset,
            limit=limit,
            runtime_measurements_count=runtime_count,
            violations=violations,
            unavailable_sources=[*unavailable, "ascii_runtime_measurements"],
            partial=True,
            message="The IMA ASCII runtime-measurement interface is not present; IMA or securityfs may be unavailable.",
        )
    except PermissionError:
        return IMAMeasurementListResponse(
            success=False,
            offset=offset,
            start_offset=offset,
            limit=limit,
            runtime_measurements_count=runtime_count,
            violations=violations,
            unavailable_sources=[*unavailable, "ascii_runtime_measurements"],
            partial=True,
            message="The IMA ASCII runtime-measurement interface is not readable with current permissions.",
        )
    except (OSError, ValueError):
        return IMAMeasurementListResponse(
            success=False,
            offset=offset,
            start_offset=offset,
            limit=limit,
            runtime_measurements_count=runtime_count,
            violations=violations,
            unavailable_sources=[*unavailable, "ascii_runtime_measurements"],
            partial=True,
            message="The IMA ASCII runtime-measurement interface could not be read or seeked.",
        )

    message = (
        "Read-only IMA log snapshot. Template data may include event names, file paths, signatures, or event payloads. "
        "This tool does not read TPM PCR values or verify an attestation."
    )
    if stop_message:
        message += f" {stop_message}"
    if unavailable:
        message += " One or more optional IMA counters were unavailable."
    return IMAMeasurementListResponse(
        success=True,
        runtime_measurements_count=runtime_count,
        violations=violations,
        offset=offset,
        start_offset=start_offset,
        next_offset=next_offset,
        has_more=has_more,
        scanned_bytes=scanned_bytes,
        returned_measurements=len(measurements),
        measurements=measurements,
        limit=limit,
        unavailable_sources=unavailable,
        truncated=truncated,
        partial=partial,
        message=message,
    )
