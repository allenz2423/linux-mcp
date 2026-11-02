"""Bounded, read-only inventory of configured filesystems in /etc/fstab."""

from __future__ import annotations

import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Literal

from wayland_mcp.models import FstabEntryInfo, FstabEntryListResponse

FSTAB_PATH = Path("/etc/fstab")
MAX_FSTAB_BYTES = 512 * 1024
MAX_SCAN_LINES = 10_000
MAX_RETURNED_ENTRIES = 500
MAX_OPTIONS_PER_ENTRY = 64
FSTAB_TYPE_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,64}(?:,[A-Za-z0-9_.+-]{1,64})*$")
OCTAL_ESCAPE_RE = re.compile(r"\\([0-7]{3})")
ALLOWED_OPTION_FLAGS = frozenset({
    "auto", "async", "bind", "defaults", "dev", "discard", "exec", "lazytime",
    "noatime", "noauto", "nodev", "noexec", "nofail", "nosuid", "relatime",
    "remount", "ro", "rbind", "rw", "strictatime", "suid", "sync", "user",
    "users", "owner", "_netdev", "x-systemd.automount",
})
PSEUDO_FILESYSTEMS = frozenset({
    "autofs", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts",
    "devtmpfs", "efivarfs", "fusectl", "mqueue", "none", "overlay", "proc",
    "pstore", "securityfs", "sysfs", "tmpfs", "tracefs",
})
NETWORK_FILESYSTEMS = frozenset({"9p", "ceph", "cifs", "davfs", "glusterfs", "nfs", "nfs4", "smb3", "sshfs"})
MAX_MESSAGES = 8


def _open_fstab() -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    return os.open(FSTAB_PATH, flags)


def fstab_inventory_available() -> bool:
    """Return whether the fixed fstab source is an accessible regular file."""
    if not sys.platform.startswith("linux"):
        return False
    descriptor: int | None = None
    try:
        descriptor = _open_fstab()
        info = os.fstat(descriptor)
        return stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FSTAB_BYTES
    except OSError:
        return False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_fstab() -> tuple[str | None, str | None]:
    descriptor: int | None = None
    try:
        descriptor = _open_fstab()
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None, "The fstab source is not a regular file."
        if info.st_size > MAX_FSTAB_BYTES:
            return None, "The fstab source exceeds the bounded read size."
        contents = bytearray()
        while len(contents) <= MAX_FSTAB_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_FSTAB_BYTES + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
        if len(contents) > MAX_FSTAB_BYTES:
            return None, "The fstab source grew beyond the bounded read size."
        return contents.decode("utf-8", errors="replace"), None
    except FileNotFoundError:
        return None, "The fixed /etc/fstab source is unavailable."
    except OSError as exc:
        return None, f"Could not read /etc/fstab: {exc.strerror or type(exc).__name__}."
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


def _decode_mount_point(value: str) -> str:
    def replace_escape(match: re.Match[str]) -> str:
        escaped = match.group(1)
        replacements = {"040": " ", "011": r"\t", "012": r"\n", "134": "\\"}
        return replacements.get(escaped, match.group(0))

    return _safe_text(OCTAL_ESCAPE_RE.sub(replace_escape, value), 4096)


def _source_kind(source: str, filesystem_type: str) -> Literal[
    "uuid", "label", "partition_uuid", "partition_label", "device", "network", "pseudo", "other"
]:
    normalized = source.casefold()
    if normalized.startswith("uuid="):
        return "uuid"
    if normalized.startswith("label="):
        return "label"
    if normalized.startswith("partuuid="):
        return "partition_uuid"
    if normalized.startswith("partlabel="):
        return "partition_label"
    fs_types = {item.casefold() for item in filesystem_type.split(",")}
    if fs_types & NETWORK_FILESYSTEMS or (":" in source and not source.startswith("/")):
        return "network"
    if normalized in {"none", "swap", "tmpfs", "proc", "sysfs"} or fs_types & PSEUDO_FILESYSTEMS:
        return "pseudo"
    if source.startswith("/dev/") or source.startswith("/"):
        return "device"
    return "other"


def _option_flags(raw_options: str) -> list[str]:
    flags: list[str] = []
    seen: set[str] = set()
    for raw_option in raw_options.split(","):
        option = raw_option.strip()
        if option in ALLOWED_OPTION_FLAGS and option not in seen:
            flags.append(option)
            seen.add(option)
        if len(flags) >= MAX_OPTIONS_PER_ENTRY:
            break
    return flags


def _positive_integer(value: str) -> int | None:
    if not value or len(value) > 10 or not value.isascii() or not value.isdigit():
        return None
    try:
        parsed = int(value, 10)
    except ValueError:
        return None
    return parsed if parsed <= 2_147_483_647 else None


def _parse_entries(text: str) -> tuple[list[FstabEntryInfo], int, bool]:
    entries: list[FstabEntryInfo] = []
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
        if len(fields) < 4 or len(fields) > 6:
            malformed += 1
            continue
        source, raw_mount_point, filesystem_type, raw_options = fields[:4]
        if not FSTAB_TYPE_RE.fullmatch(filesystem_type):
            malformed += 1
            continue
        dump_frequency = 0
        fsck_pass_number = 0
        if len(fields) >= 5:
            parsed_dump = _positive_integer(fields[4])
            if parsed_dump is None:
                malformed += 1
                continue
            dump_frequency = parsed_dump
        if len(fields) >= 6:
            parsed_pass = _positive_integer(fields[5])
            if parsed_pass is None:
                malformed += 1
                continue
            fsck_pass_number = parsed_pass
        entries.append(FstabEntryInfo(
            line_number=line_number,
            mount_point=_decode_mount_point(raw_mount_point),
            filesystem_type=filesystem_type,
            source_kind=_source_kind(source, filesystem_type),
            option_flags=_option_flags(raw_options),
            dump_frequency=dump_frequency,
            fsck_pass_number=fsck_pass_number,
        ))
        if len(entries) >= MAX_SCAN_LINES:
            truncated = True
            break
    return entries, malformed, truncated


def _matches(entry: FstabEntryInfo, query: str) -> bool:
    needle = query.strip().casefold()
    if not needle:
        return True
    searchable = " ".join((
        entry.mount_point,
        entry.filesystem_type,
        entry.source_kind,
        *entry.option_flags,
        str(entry.dump_frequency),
        str(entry.fsck_pass_number),
        str(entry.line_number),
    )).casefold()
    return needle in searchable


def list_fstab_entries(query: str = "", limit: int = 100) -> FstabEntryListResponse:
    """Read bounded filesystem configuration metadata without exposing raw sources/options."""
    if not sys.platform.startswith("linux"):
        return FstabEntryListResponse(success=False, message="Filesystem configuration inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return FstabEntryListResponse(success=False, message="Query must be text with at most 256 characters.")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RETURNED_ENTRIES:
        return FstabEntryListResponse(success=False, message="Limit must be an integer from 1 to 500.")

    contents, error = _read_fstab()
    if contents is None:
        return FstabEntryListResponse(success=False, limit=limit, message=error)

    entries, malformed, scan_truncated = _parse_entries(contents)
    selected = [entry for entry in entries if _matches(entry, query)]
    messages = []
    if malformed:
        messages.append(f"Skipped {malformed} lines that did not match the supported fstab format.")
    if not selected:
        messages.append("No matching configured filesystem entries were found.")
    else:
        messages.append("Raw source identifiers and arbitrary mount-option values are omitted.")
    if scan_truncated:
        messages.append("The bounded fstab scan stopped before reaching the end of the source.")
    if len(messages) > MAX_MESSAGES:
        messages = messages[:MAX_MESSAGES]
    return FstabEntryListResponse(
        success=True,
        total_entries=len(selected),
        returned_entries=min(len(selected), limit),
        entries=selected[:limit],
        malformed_lines=malformed,
        limit=limit,
        truncated=len(selected) > limit or scan_truncated,
        message=" ".join(messages),
    )
