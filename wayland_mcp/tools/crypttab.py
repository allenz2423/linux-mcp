"""Bounded, read-only metadata inventory for /etc/crypttab."""

from __future__ import annotations

import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Literal, cast

from wayland_mcp.models import CrypttabEntryInfo, CrypttabEntryListResponse

CRYPTTAB_PATH = Path("/etc/crypttab")
MAX_CRYPTTAB_BYTES = 512 * 1024
MAX_SCAN_LINES = 10_000
MAX_RETURNED_ENTRIES = 500
MAX_OPTION_FLAGS = 64
VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9_.+@:-]{1,128}$")
DEVICE_KINDS: dict[str, Literal["uuid", "label", "partition_uuid", "partition_label"]] = {
    "uuid=": "uuid",
    "label=": "label",
    "partuuid=": "partition_uuid",
    "partlabel=": "partition_label",
}
ENCRYPTION_MODES = frozenset({"luks", "plain", "tcrypt", "bitlk", "fvault2"})
SAFE_OPTION_FLAGS = frozenset({
    "_netdev", "discard", "headless", "noauto", "nofail", "read-only", "readonly",
    "same-cpu-crypt", "submit-from-crypt-cpus", "swap", "tmp", "tcrypt-hidden",
    "tcrypt-system", "tcrypt-veracrypt", "x-initrd.attach",
})
TCRYPT_IMPLYING_FLAGS = frozenset({"tcrypt-hidden", "tcrypt-system", "tcrypt-veracrypt"})


def _open_crypttab() -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    return os.open(CRYPTTAB_PATH, flags)


def crypttab_inventory_available() -> bool:
    """Check that the fixed crypttab source is a bounded readable regular file."""
    if not sys.platform.startswith("linux"):
        return False
    descriptor: int | None = None
    try:
        descriptor = _open_crypttab()
        info = os.fstat(descriptor)
        return stat.S_ISREG(info.st_mode) and info.st_size <= MAX_CRYPTTAB_BYTES
    except OSError:
        return False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_crypttab() -> tuple[str | None, str | None]:
    descriptor: int | None = None
    try:
        descriptor = _open_crypttab()
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None, "The crypttab source is not a regular file."
        if info.st_size > MAX_CRYPTTAB_BYTES:
            return None, "The crypttab source exceeds the bounded read size."
        contents = bytearray()
        while len(contents) <= MAX_CRYPTTAB_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_CRYPTTAB_BYTES + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
        if len(contents) > MAX_CRYPTTAB_BYTES:
            return None, "The crypttab source grew beyond the bounded read size."
        return contents.decode("utf-8", errors="replace"), None
    except FileNotFoundError:
        return None, "The fixed /etc/crypttab source is unavailable."
    except OSError as exc:
        return None, f"Could not read /etc/crypttab: {exc.strerror or type(exc).__name__}."
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _safe_text(value: str, maximum: int) -> str:
    return "".join(
        character
        for character in value
        if unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
    )[:maximum]


def _device_source_kind(value: str) -> Literal[
    "uuid", "label", "partition_uuid", "partition_label", "path", "other"
]:
    normalized = value.casefold()
    for prefix, kind in DEVICE_KINDS.items():
        if normalized.startswith(prefix):
            return kind
    if value.startswith("/"):
        return "path"
    return "other"


def _key_source_kind(value: str | None) -> Literal["implicit", "random_device", "path_or_socket", "other"]:
    if value is None or value.casefold() in {"none", "-"}:
        return "implicit"
    if value in {"/dev/random", "/dev/urandom"}:
        return "random_device"
    if value.startswith("/"):
        return "path_or_socket"
    return "other"


def _split_options(value: str) -> list[str]:
    """Split comma options without treating escaped commas inside values as delimiters."""
    tokens: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ",":
            tokens.append("".join(current).strip())
            current.clear()
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    tokens.append("".join(current).strip())
    return tokens


def _encryption_mode(options: list[str]) -> Literal["luks", "plain", "tcrypt", "bitlk", "fvault2"] | None:
    normalized = {option.casefold() for option in options}
    candidates = normalized & ENCRYPTION_MODES
    if normalized & TCRYPT_IMPLYING_FLAGS:
        candidates.add("tcrypt")
    if normalized & {"swap", "tmp"}:
        candidates.add("plain")
    if len(candidates) != 1:
        return None
    return cast(Literal["luks", "plain", "tcrypt", "bitlk", "fvault2"], next(iter(candidates)))


def _parse_entries(text: str) -> tuple[list[CrypttabEntryInfo], int, bool]:
    entries: list[CrypttabEntryInfo] = []
    malformed = 0
    truncated = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if line_number > MAX_SCAN_LINES:
            truncated = True
            break
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) > 16 * 1024:
            malformed += 1
            continue
        fields = line.split()
        if len(fields) < 2 or len(fields) > 4:
            malformed += 1
            continue
        volume_name, device = fields[:2]
        if not VOLUME_NAME_RE.fullmatch(volume_name):
            malformed += 1
            continue
        key_file = fields[2] if len(fields) >= 3 else None
        raw_options = fields[3] if len(fields) >= 4 else ""
        options = _split_options(raw_options)
        option_flags: list[str] = []
        seen_flags: set[str] = set()
        for option in options:
            normalized = option.casefold()
            if normalized in SAFE_OPTION_FLAGS and normalized not in seen_flags:
                option_flags.append(normalized)
                seen_flags.add(normalized)
            if len(option_flags) >= MAX_OPTION_FLAGS:
                break
        entries.append(CrypttabEntryInfo(
            line_number=line_number,
            volume_name=_safe_text(volume_name, 128),
            device_source_kind=_device_source_kind(device),
            key_source_kind=_key_source_kind(key_file),
            encryption_mode=_encryption_mode(options),
            option_flags=option_flags,
            formats_on_activation=any(option.casefold() in {"swap", "tmp"} for option in options),
            pkcs11_configured=any(option.casefold().startswith("pkcs11-uri=") for option in options),
            fido2_configured=any(option.casefold().startswith("fido2-device=") for option in options),
            tpm2_configured=any(option.casefold().startswith("tpm2-device=") for option in options),
            custom_keyscript_configured=any(option.casefold().startswith("keyscript=") for option in options),
        ))
        if len(entries) >= MAX_SCAN_LINES:
            truncated = True
            break
    return entries, malformed, truncated


def _matches(entry: CrypttabEntryInfo, query: str) -> bool:
    needle = query.strip().casefold()
    if not needle:
        return True
    searchable = " ".join((
        entry.volume_name,
        entry.device_source_kind,
        entry.key_source_kind,
        entry.encryption_mode or "",
        *entry.option_flags,
        str(entry.line_number),
        str(entry.pkcs11_configured),
        str(entry.fido2_configured),
        str(entry.tpm2_configured),
        str(entry.custom_keyscript_configured),
    )).casefold()
    return needle in searchable


def list_crypttab_entries(query: str = "", limit: int = 100) -> CrypttabEntryListResponse:
    """Read bounded crypttab metadata without exposing source, key, or option values."""
    if not sys.platform.startswith("linux"):
        return CrypttabEntryListResponse(success=False, message="Encrypted-device configuration inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return CrypttabEntryListResponse(success=False, message="Query must be text with at most 256 characters.")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RETURNED_ENTRIES:
        return CrypttabEntryListResponse(success=False, message="Limit must be an integer from 1 to 500.")

    contents, error = _read_crypttab()
    if contents is None:
        return CrypttabEntryListResponse(success=False, limit=limit, message=error)
    entries, malformed, scan_truncated = _parse_entries(contents)
    selected = [entry for entry in entries if _matches(entry, query)]
    messages = []
    if malformed:
        messages.append(f"Skipped {malformed} lines that did not match the supported crypttab format.")
    if not selected:
        messages.append("No matching encrypted-device entries were found.")
    else:
        messages.append("Encrypted-device identifiers, key paths, and arbitrary option values are omitted.")
    if scan_truncated:
        messages.append("The bounded crypttab scan stopped before reaching the end of the source.")
    return CrypttabEntryListResponse(
        success=True,
        total_entries=len(selected),
        returned_entries=min(len(selected), limit),
        entries=selected[:limit],
        malformed_lines=malformed,
        limit=limit,
        truncated=len(selected) > limit or scan_truncated,
        message=" ".join(messages),
    )
