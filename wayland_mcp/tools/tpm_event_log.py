"""Bounded, read-only parsing of the kernel-exported TPM firmware event log."""

from __future__ import annotations

import os
import re
import struct
import sys
from pathlib import Path
from typing import BinaryIO

from wayland_mcp.models import (
    TPMEventDigest,
    TPMEventDigestAlgorithm,
    TPMEventInfo,
    TPMEventLogResponse,
)

TPM_CLASS_ROOT = Path("/sys/class/tpm")
TPM_SECURITY_ROOT = Path("/sys/kernel/security")
TPM_NAME_RE = re.compile(r"^tpm([0-9]{1,5})$")
MAX_CLASS_ENTRIES = 256
MAX_TPM_DEVICES = 64
MAX_TPM_DEVICE_INDEX = 65_535
MAX_PAGE_LIMIT = 100
MAX_SCAN_BYTES = 2 * 1024 * 1024
MAX_EVENT_DATA_BYTES = 256 * 1024
MAX_SPEC_ID_BYTES = 4096
MAX_ALGORITHMS = 64
MAX_DIGEST_BYTES = 128
MAX_BYTE_OFFSET = 64 * 1024 * 1024
EVENT_DATA_PREVIEW_BYTES = 128
SPEC_ID_SIGNATURE = b"Spec ID Event03\x00"
LEGACY_EVENT_HEADER = struct.Struct("<II20sI")

ALGORITHM_NAMES = {
    0x0004: "SHA1",
    0x000B: "SHA256",
    0x000C: "SHA384",
    0x000D: "SHA512",
    0x0012: "SM3_256",
    0x0027: "SHA3_256",
    0x0028: "SHA3_384",
    0x0029: "SHA3_512",
}
EVENT_TYPE_NAMES = {
    0x00000000: "EV_PREBOOT_CERT",
    0x00000001: "EV_POST_CODE",
    0x00000002: "EV_UNUSED",
    0x00000003: "EV_NO_ACTION",
    0x00000004: "EV_SEPARATOR",
    0x00000005: "EV_ACTION",
    0x00000006: "EV_EVENT_TAG",
    0x00000007: "EV_S_CRTM_CONTENTS",
    0x00000008: "EV_S_CRTM_VERSION",
    0x00000009: "EV_CPU_MICROCODE",
    0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
    0x0000000B: "EV_TABLE_OF_DEVICES",
    0x0000000C: "EV_COMPACT_HASH",
    0x0000000D: "EV_IPL",
    0x0000000E: "EV_IPL_PARTITION_DATA",
    0x0000000F: "EV_NONHOST_CODE",
    0x00000010: "EV_NONHOST_CONFIG",
    0x00000011: "EV_NONHOST_INFO",
    0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
}


class _EventLogError(ValueError):
    """Raised when an event-log header or record is malformed or incomplete."""


class _PageScanLimit(ValueError):
    """Raised before a record would exceed the per-page byte cap."""


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    if size < 0:
        raise _EventLogError("Negative field size")
    raw = stream.read(size)
    if len(raw) != size:
        raise _EventLogError("Incomplete event-log record")
    return raw


def _algorithm_name(algorithm_id: int) -> str:
    return ALGORITHM_NAMES.get(algorithm_id, f"algorithm_0x{algorithm_id:04x}")


def _enumerate_tpm_names() -> tuple[list[str], bool, str | None]:
    names: list[tuple[int, str]] = []
    truncated = False
    try:
        with os.scandir(TPM_CLASS_ROOT) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_CLASS_ENTRIES:
                    truncated = True
                    break
                match = TPM_NAME_RE.fullmatch(entry.name)
                if match is None:
                    continue
                device_index = int(match.group(1), 10)
                if device_index > MAX_TPM_DEVICE_INDEX:
                    continue
                if len(names) >= MAX_TPM_DEVICES:
                    truncated = True
                    break
                names.append((device_index, entry.name))
    except FileNotFoundError:
        return [], False, None
    except OSError as exc:
        return [], False, exc.strerror or "read error"
    names.sort(key=lambda item: (item[0], item[1]))
    return [name for _index, name in names], truncated, None


def _event_log_path(device_name: str) -> Path:
    return TPM_SECURITY_ROOT / device_name / "binary_bios_measurements"


def tpm_event_log_available() -> bool:
    """Return whether a bounded scan finds a kernel-exported event-log file."""
    if not sys.platform.startswith("linux"):
        return False
    names, _truncated, error = _enumerate_tpm_names()
    if error is not None:
        return False
    return any(_event_log_path(name).is_file() for name in names)


def _parse_spec_id(payload: bytes) -> tuple[dict[int, int], str]:
    if len(payload) < 29 or not payload.startswith(SPEC_ID_SIGNATURE):
        raise _EventLogError("Invalid SpecID event")
    cursor = len(SPEC_ID_SIGNATURE)
    cursor += 4  # platformClass
    minor, major, _errata, uintn_size = payload[cursor : cursor + 4]
    cursor += 4
    if uintn_size not in (1, 2):
        raise _EventLogError("Invalid SpecID UINTN size")
    algorithm_count = struct.unpack_from("<I", payload, cursor)[0]
    cursor += 4
    if algorithm_count < 1 or algorithm_count > MAX_ALGORITHMS:
        raise _EventLogError("SpecID algorithm count is outside the supported bound")

    algorithms: dict[int, int] = {}
    for _ in range(algorithm_count):
        if cursor + 4 > len(payload):
            raise _EventLogError("Incomplete SpecID algorithm table")
        algorithm_id, digest_size = struct.unpack_from("<HH", payload, cursor)
        cursor += 4
        if digest_size < 1 or digest_size > MAX_DIGEST_BYTES or algorithm_id in algorithms:
            raise _EventLogError("Invalid SpecID digest algorithm")
        algorithms[algorithm_id] = digest_size

    if cursor >= len(payload):
        raise _EventLogError("Missing SpecID vendor-info size")
    vendor_info_size = payload[cursor]
    cursor += 1
    if cursor + vendor_info_size != len(payload):
        raise _EventLogError("SpecID vendor-info length does not match the record")
    return algorithms, f"{major}.{minor}"


def _detect_log_format(
    stream: BinaryIO,
) -> tuple[str, dict[int, int], str | None, int, TPMEventInfo | None]:
    stream.seek(0)
    header = stream.read(LEGACY_EVENT_HEADER.size)
    if not header:
        return "legacy_sha1", {0x0004: 20}, None, 0, None
    if len(header) != LEGACY_EVENT_HEADER.size:
        raise _EventLogError("Incomplete first event header")
    pcr_index, event_type, digest, event_size = LEGACY_EVENT_HEADER.unpack(header)
    if event_size > MAX_EVENT_DATA_BYTES:
        raise _EventLogError("First event data exceeds the 256 KiB record cap")
    if event_size < len(SPEC_ID_SIGNATURE):
        return "legacy_sha1", {0x0004: 20}, None, 0, None

    signature = _read_exact(stream, len(SPEC_ID_SIGNATURE))
    if signature != SPEC_ID_SIGNATURE:
        return "legacy_sha1", {0x0004: 20}, None, 0, None
    if pcr_index != 0 or event_type != 0x00000003 or digest != bytes(20):
        raise _EventLogError("SpecID signature has an invalid legacy event header")
    if event_size > MAX_SPEC_ID_BYTES:
        raise _EventLogError("SpecID event exceeds the 4 KiB header cap")
    payload = signature + _read_exact(stream, event_size - len(signature))
    algorithms, spec_version = _parse_spec_id(payload)
    header_end = LEGACY_EVENT_HEADER.size + event_size
    spec_event = TPMEventInfo(
        byte_offset=0,
        pcr_index=pcr_index,
        event_type=event_type,
        event_type_name=EVENT_TYPE_NAMES[event_type],
        digests=[TPMEventDigest(algorithm_id=0x0004, algorithm="SHA1", digest=digest.hex())],
        event_data_size_bytes=event_size,
        event_data_preview_hex=payload[:EVENT_DATA_PREVIEW_BYTES].hex(),
        event_data_truncated=event_size > EVENT_DATA_PREVIEW_BYTES,
    )
    return "crypto_agile", algorithms, spec_version, header_end, spec_event


def _read_event(
    stream: BinaryIO,
    log_format: str,
    algorithms: dict[int, int],
    byte_offset: int,
    page_start_offset: int,
) -> TPMEventInfo | None:
    if log_format == "legacy_sha1":
        header = stream.read(LEGACY_EVENT_HEADER.size)
        if not header:
            return None
        if len(header) != LEGACY_EVENT_HEADER.size:
            raise _EventLogError("Incomplete legacy event header")
        pcr_index, event_type, digest, event_size = LEGACY_EVENT_HEADER.unpack(header)
        digests = [TPMEventDigest(algorithm_id=0x0004, algorithm="SHA1", digest=digest.hex())]
    else:
        fixed = stream.read(12)
        if not fixed:
            return None
        if len(fixed) != 12:
            raise _EventLogError("Incomplete crypto-agile event header")
        pcr_index, event_type, digest_count = struct.unpack("<III", fixed)
        if digest_count > MAX_ALGORITHMS:
            raise _EventLogError("Event digest count exceeds the supported bound")
        digests = []
        for _ in range(digest_count):
            algorithm_id = struct.unpack("<H", _read_exact(stream, 2))[0]
            digest_size = algorithms.get(algorithm_id)
            if digest_size is None:
                raise _EventLogError("Event references an algorithm absent from SpecID")
            digest = _read_exact(stream, digest_size)
            digests.append(
                TPMEventDigest(
                    algorithm_id=algorithm_id,
                    algorithm=_algorithm_name(algorithm_id),
                    digest=digest.hex(),
                )
            )
        event_size = struct.unpack("<I", _read_exact(stream, 4))[0]

    if event_size > MAX_EVENT_DATA_BYTES:
        raise _EventLogError("Event data exceeds the 256 KiB record cap")
    if stream.tell() - page_start_offset + event_size > MAX_SCAN_BYTES:
        raise _PageScanLimit
    event_data = _read_exact(stream, event_size)
    return TPMEventInfo(
        byte_offset=byte_offset,
        pcr_index=pcr_index,
        event_type=event_type,
        event_type_name=EVENT_TYPE_NAMES.get(event_type, "unknown"),
        digests=digests,
        event_data_size_bytes=event_size,
        event_data_preview_hex=event_data[:EVENT_DATA_PREVIEW_BYTES].hex(),
        event_data_truncated=event_size > EVENT_DATA_PREVIEW_BYTES,
    )


def _response(
    *,
    success: bool,
    device_name: str | None = None,
    offset: int = 0,
    limit: int = 50,
    unavailable_sources: list[str] | None = None,
    message: str | None = None,
    partial: bool = False,
) -> TPMEventLogResponse:
    return TPMEventLogResponse(
        success=success,
        device_name=device_name,
        offset=offset,
        limit=limit,
        unavailable_sources=unavailable_sources or [],
        partial=partial,
        message=message,
    )


def list_tpm_event_log(
    device_name: str = "",
    offset: int = 0,
    limit: int = 50,
) -> TPMEventLogResponse:
    """Return a bounded page from one kernel-exported TPM firmware event log.

    An empty device name selects the lowest-numbered visible TPM class device.
    """
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > MAX_BYTE_OFFSET:
        return _response(
            success=False,
            offset=0 if not isinstance(offset, int) or isinstance(offset, bool) else offset,
            message=f"Offset must be an integer from 0 through {MAX_BYTE_OFFSET} bytes.",
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        return _response(success=False, offset=offset, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_PAGE_LIMIT))
    if not sys.platform.startswith("linux"):
        return _response(success=False, offset=offset, limit=limit, message="TPM firmware event logs are available only on Linux.")
    if not isinstance(device_name, str):
        return _response(success=False, offset=offset, limit=limit, message="device_name must be a string TPM class name.")
    if device_name:
        match = TPM_NAME_RE.fullmatch(device_name)
        if match is None or int(match.group(1), 10) > MAX_TPM_DEVICE_INDEX:
            return _response(success=False, offset=offset, limit=limit, message="device_name must be an exact TPM class name such as tpm0.")

    names, scan_truncated, scan_error = _enumerate_tpm_names()
    if scan_error is not None:
        return _response(
            success=False,
            offset=offset,
            unavailable_sources=["/sys/class/tpm"],
            message=f"Could not enumerate TPM devices: {scan_error}.",
            partial=True,
        )
    if device_name:
        selected_name = device_name
    elif names:
        selected_name = names[0]
    else:
        return _response(
            success=True,
            offset=offset,
            partial=scan_truncated,
            message="No TPM class devices are exposed through /sys/class/tpm.",
        )

    path = _event_log_path(selected_name)
    events: list[TPMEventInfo] = []
    unavailable: list[str] = []
    truncated = scan_truncated
    partial = scan_truncated
    next_offset: int | None = None
    has_more: bool | None = None
    scanned_bytes = 0
    stop_message: str | None = None
    log_format: str | None = None
    algorithms: dict[int, int] = {}
    spec_version: str | None = None
    start_offset = offset

    try:
        with path.open("rb") as stream:
            log_format, algorithms, spec_version, header_end, spec_event = _detect_log_format(stream)
            if log_format == "crypto_agile" and 0 < offset < header_end:
                return _response(
                    success=False,
                    device_name=selected_name,
                    offset=offset,
                    limit=limit,
                    message="For a crypto-agile log, offset must be zero or a record boundary at or after the SpecID header.",
                )

            if offset == 0 and spec_event is not None:
                events.append(spec_event)
                scanned_bytes = header_end
                stream.seek(header_end)
            else:
                stream.seek(offset)

            while len(events) < limit:
                record_offset = stream.tell()
                if record_offset - start_offset >= MAX_SCAN_BYTES:
                    truncated = True
                    partial = True
                    next_offset = record_offset
                    has_more = bool(stream.read(1))
                    stop_message = f"The page reached its {MAX_SCAN_BYTES}-byte scan cap."
                    break

                try:
                    event = _read_event(stream, log_format, algorithms, record_offset, start_offset)
                except _PageScanLimit:
                    stream.seek(record_offset)
                    truncated = True
                    partial = True
                    next_offset = record_offset
                    has_more = bool(stream.read(1))
                    stop_message = f"The page reached its {MAX_SCAN_BYTES}-byte scan cap before this record."
                    break
                except _EventLogError:
                    partial = True
                    stop_message = "A malformed or incomplete event was encountered; later records were not parsed."
                    break
                if event is None:
                    has_more = False
                    break

                record_end = stream.tell()
                if record_end - start_offset > MAX_SCAN_BYTES:
                    stream.seek(record_offset)
                    truncated = True
                    partial = True
                    next_offset = record_offset
                    has_more = bool(stream.read(1))
                    stop_message = f"The page reached its {MAX_SCAN_BYTES}-byte scan cap before this record."
                    break
                events.append(event)
                scanned_bytes = record_end - start_offset

            else:
                candidate_offset = stream.tell()
                has_more = bool(stream.read(1))
                if has_more:
                    if candidate_offset <= MAX_BYTE_OFFSET:
                        next_offset = candidate_offset
                    else:
                        truncated = True
                        partial = True
                        stop_message = f"The page reached its {MAX_BYTE_OFFSET}-byte continuation-offset cap."

            if next_offset is not None and next_offset > MAX_BYTE_OFFSET:
                next_offset = None
                truncated = True
                partial = True
                stop_message = f"The page reached its {MAX_BYTE_OFFSET}-byte continuation-offset cap."
    except FileNotFoundError:
        unavailable.append("binary_bios_measurements")
        return _response(
            success=False,
            device_name=selected_name,
            offset=offset,
            limit=limit,
            unavailable_sources=unavailable,
            message="The kernel-exported TPM event log is not present; securityfs may be unavailable or firmware supplied no log.",
            partial=True,
        )
    except PermissionError:
        unavailable.append("binary_bios_measurements")
        return _response(
            success=False,
            device_name=selected_name,
            offset=offset,
            limit=limit,
            unavailable_sources=unavailable,
            message="The kernel-exported TPM event log is not readable with current permissions.",
            partial=True,
        )
    except (OSError, ValueError) as exc:
        return _response(
            success=False,
            device_name=selected_name,
            offset=offset,
            limit=limit,
            unavailable_sources=["binary_bios_measurements"],
            message=f"The kernel-exported TPM event log could not be read or seeked: {getattr(exc, 'strerror', None) or str(exc) or 'read error'}.",
            partial=True,
        )

    if truncated:
        partial = True
    message_parts = [
        "Read-only snapshot of the kernel-exported firmware event log. Event data previews may include paths or firmware details. "
        "The log is not authenticated by this tool and does not verify current TPM PCR values or attest boot integrity. "
        "No TPM commands were issued."
    ]
    if stop_message:
        message_parts.append(stop_message)
    return TPMEventLogResponse(
        success=True,
        device_name=selected_name,
        log_format=log_format,
        spec_version=spec_version,
        algorithms=[
            TPMEventDigestAlgorithm(
                algorithm_id=algorithm_id,
                algorithm=_algorithm_name(algorithm_id),
                digest_size_bytes=digest_size,
            )
            for algorithm_id, digest_size in algorithms.items()
        ],
        offset=offset,
        next_offset=next_offset,
        has_more=has_more,
        scanned_bytes=scanned_bytes,
        returned_events=len(events),
        events=events,
        limit=limit,
        unavailable_sources=unavailable,
        truncated=truncated,
        partial=partial,
        message=" ".join(message_parts),
    )
