"""Bounded read-only path metadata, xattr/ACL inventory, directory listing, and text access."""

from __future__ import annotations

import base64
import os
import stat
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

from wayland_mcp.models import (
    DirectoryEntryInfo,
    DirectoryListResponse,
    ExtendedAttributeInfo,
    FilesystemPathInfo,
    PathExtendedAttributeResponse,
    PathMetadataResponse,
    POSIXACLEntry,
    TextFileReadResponse,
)

MAX_PATH_LENGTH = 4096
MAX_DIRECTORY_SCAN = 5_000
MAX_DIRECTORY_DEPTH = 128
MAX_RETURNED_ENTRIES = 200
MAX_FILE_READ_BYTES = 64 * 1024
MAX_XATTR_NAMES = 8192
MAX_XATTRS_PER_PAGE = 128
MAX_XATTR_VALUE_PREVIEW_BYTES = 4096
MAX_XATTR_PAGE_VALUE_BYTES = 32 * 1024
MAX_ACL_ENTRIES = 256
BLOCKED_FILESYSTEM_ROOTS = (Path("/proc"), Path("/sys"), Path("/dev"), Path("/run"))
POSIX_ACL_XATTRS = {"system.posix_acl_access", "system.posix_acl_default"}
POSIX_ACL_XATTR_VERSION = 0x0002
POSIX_ACL_TAGS = {
    0x01: "user_obj",
    0x02: "user",
    0x04: "group_obj",
    0x08: "group",
    0x10: "mask",
    0x20: "other",
}
POSIX_ACL_QUALIFIER_TAGS = {0x02, 0x08}
ACL_UNDEFINED_ID = 0xFFFFFFFF
SECURITY_LABEL_XATTRS = {"security.selinux", "security.SMACK64"}


def _is_blocked_path(path: Path) -> bool:
    return any(path == root or root in path.parents for root in BLOCKED_FILESYSTEM_ROOTS)


def _resolve_path(raw_path: str) -> tuple[Path | None, str | None]:
    if not isinstance(raw_path, str) or not raw_path.strip() or len(raw_path) > MAX_PATH_LENGTH:
        return None, "Path must be non-empty text with at most 4096 characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in raw_path):
        return None, "Path cannot contain control characters."
    try:
        input_path = Path(raw_path).expanduser()
        if not input_path.is_absolute():
            return None, "Path must be absolute; '~' is expanded to the current user's home directory."
        lexical_path = Path(os.path.abspath(input_path))
        if _is_blocked_path(lexical_path):
            return None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."
        target = input_path.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"Path could not be resolved: {getattr(exc, 'strerror', None) or type(exc).__name__}."
    if _is_blocked_path(target):
        return None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."
    return target, None


def _open_resolved_path(path: Path, flags: int) -> int:
    """Open a resolved absolute path without following any changed symlink component."""
    directory_flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    components = path.parts[1:]
    if not components:
        return os.open(path, flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))

    directory_fd = os.open("/", directory_flags)
    try:
        for component in components[:-1]:
            next_fd = os.open(
                component,
                directory_flags,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(
            components[-1],
            flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
        return "device"
    return "other"


def _metadata(path: str, info: os.stat_result) -> FilesystemPathInfo:
    return FilesystemPathInfo(path=path, **_metadata_values(info))


def _metadata_values(info: os.stat_result) -> dict[str, object]:
    kind = _kind(info.st_mode)
    try:
        modified_at = datetime.fromtimestamp(info.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        modified_at = "unavailable"
    return {
        "kind": kind,
        "size_bytes": info.st_size if kind in ("file", "symlink") else None,
        "mode_octal": f"{stat.S_IMODE(info.st_mode):04o}",
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "modified_at": modified_at,
    }


def _safe_name(name: str) -> str:
    result: list[str] = []
    for character in name:
        value = ord(character)
        if value < 32 or 127 <= value <= 159 or 0xD800 <= value <= 0xDFFF:
            result.append(f"\\x{value:02x}" if value <= 255 else f"\\u{value:04x}")
        else:
            result.append(character)
    return "".join(result)


def inspect_path(path: str) -> PathMetadataResponse:
    if not sys.platform.startswith("linux"):
        return PathMetadataResponse(success=False, message="Filesystem path inspection is available only on Linux.")
    target, error = _resolve_path(path)
    if error or target is None:
        return PathMetadataResponse(success=False, message=error)
    try:
        info = target.stat()
    except OSError as exc:
        return PathMetadataResponse(success=False, message=f"Could not inspect path: {exc.strerror or 'metadata unavailable'}.")
    return PathMetadataResponse(success=True, metadata=_metadata(str(target), info))


def _permission_text(value: int) -> str:
    return "".join(letter if value & bit else "-" for letter, bit in (("r", 4), ("w", 2), ("x", 1)))


def _parse_posix_acl(raw: bytes) -> tuple[list[POSIXACLEntry], int, bool, str | None]:
    if len(raw) < 4:
        return [], 0, False, "ACL value is shorter than its version header."
    version, = struct.unpack_from("<I", raw)
    if version != POSIX_ACL_XATTR_VERSION:
        return [], 0, False, "ACL value uses an unsupported format version."
    entry_bytes = len(raw) - 4
    if entry_bytes % 8:
        return [], 0, False, "ACL value has an incomplete entry."

    entry_count = entry_bytes // 8
    if entry_count < 3:
        return [], entry_count, False, "ACL value is missing required owner, group, or other entries."
    parsed: list[tuple[int, int, int]] = []
    mask_permissions: int | None = None
    tag_counts: dict[int, int] = {}
    user_ids: set[int] = set()
    group_ids: set[int] = set()
    for index in range(entry_count):
        tag, permissions, qualifier_id = struct.unpack_from("<HHI", raw, 4 + index * 8)
        if tag not in POSIX_ACL_TAGS:
            return [], entry_count, False, "ACL value contains an unknown entry tag."
        if permissions & ~0x07:
            return [], entry_count, False, "ACL value contains unsupported permission bits."
        if tag in POSIX_ACL_QUALIFIER_TAGS:
            if qualifier_id == ACL_UNDEFINED_ID:
                return [], entry_count, False, "Named ACL entry has no numeric qualifier."
            qualifiers = user_ids if tag == 0x02 else group_ids
            if qualifier_id in qualifiers:
                return [], entry_count, False, "ACL value contains a duplicate named qualifier."
            qualifiers.add(qualifier_id)
        elif qualifier_id != ACL_UNDEFINED_ID:
            return [], entry_count, False, "Unqualified ACL entry has an unexpected numeric qualifier."
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
        if tag == 0x10:
            mask_permissions = permissions
        if index < MAX_ACL_ENTRIES:
            parsed.append((tag, permissions, qualifier_id))

    if any(tag_counts.get(tag, 0) != 1 for tag in (0x01, 0x04, 0x20)):
        return [], entry_count, False, "ACL value must contain exactly one owner, group, and other entry."
    if tag_counts.get(0x10, 0) > 1:
        return [], entry_count, False, "ACL value contains more than one mask entry."
    if (user_ids or group_ids) and tag_counts.get(0x10, 0) != 1:
        return [], entry_count, False, "ACL value with named entries is missing its mask."

    entries = [
        POSIXACLEntry(
            tag=POSIX_ACL_TAGS[tag],
            qualifier_id=qualifier_id if tag in POSIX_ACL_QUALIFIER_TAGS else None,
            permissions=_permission_text(permissions),
            effective_permissions=(
                _permission_text(permissions & mask_permissions)
                if mask_permissions is not None and tag in {0x02, 0x04, 0x08}
                else None
            ),
        )
        for tag, permissions, qualifier_id in parsed
    ]
    return entries, entry_count, entry_count > MAX_ACL_ENTRIES, None


def _render_xattr_value(name: str, raw: bytes, *, complete: bool) -> tuple[str | None, str | None, bool]:
    display_bytes = raw
    null_terminated = False
    if complete and name in SECURITY_LABEL_XATTRS and display_bytes.endswith(b"\x00"):
        display_bytes = display_bytes[:-1]
        null_terminated = True
    try:
        text_value = display_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text_value = None
    if text_value is not None and all(character in "\n\r\t" or character.isprintable() for character in text_value):
        return text_value, None, null_terminated
    return None, base64.b64encode(raw).decode("ascii"), null_terminated


def list_path_extended_attributes(
    path: str,
    offset: int = 0,
    limit: int = 64,
) -> PathExtendedAttributeResponse:
    """List bounded extended attributes for one explicit path without changing it."""
    if not sys.platform.startswith("linux"):
        return PathExtendedAttributeResponse(success=False, message="Extended-attribute inspection is available only on Linux.")
    if not hasattr(os, "listxattr") or not hasattr(os, "getxattr"):
        return PathExtendedAttributeResponse(success=False, message="Python extended-attribute interfaces are unavailable.")
    target, error = _resolve_path(path)
    if error or target is None:
        return PathExtendedAttributeResponse(success=False, message=error)
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_XATTR_NAMES:
        return PathExtendedAttributeResponse(success=False, path=str(target), message=f"offset must be an integer from 0 through {MAX_XATTR_NAMES}.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return PathExtendedAttributeResponse(success=False, path=str(target), offset=offset, message="limit must be an integer.")
    limit = max(1, min(limit, MAX_XATTRS_PER_PAGE))

    try:
        names = sorted(os.listxattr(target, follow_symlinks=False), key=str.casefold)
    except (OSError, NotImplementedError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) else None
        return PathExtendedAttributeResponse(
            success=False,
            path=str(target),
            offset=offset,
            limit=limit,
            message=f"Could not list extended attributes: {reason or 'interface unavailable'}.",
        )

    scanned_names = names[:MAX_XATTR_NAMES]
    page_names = scanned_names[offset : offset + limit]
    next_offset = offset + len(page_names)
    has_more = next_offset < len(scanned_names)
    if not has_more:
        next_offset = None

    attributes: list[ExtendedAttributeInfo] = []
    returned_value_bytes = 0
    value_truncated = False
    read_errors = 0
    for name in page_names:
        safe_name = _safe_name(name)
        try:
            raw = os.getxattr(target, name, follow_symlinks=False)
        except (OSError, NotImplementedError) as exc:
            read_errors += 1
            reason = exc.strerror if isinstance(exc, OSError) else None
            attributes.append(
                ExtendedAttributeInfo(
                    name=safe_name,
                    unavailable_reason=f"Current permissions or filesystem state prevented reading the value: {reason or 'interface unavailable'}.",
                )
            )
            continue

        budget = max(0, MAX_XATTR_PAGE_VALUE_BYTES - returned_value_bytes)
        preview_size = min(len(raw), MAX_XATTR_VALUE_PREVIEW_BYTES, budget)
        preview = raw[:preview_size]
        returned_value_bytes += len(preview)
        attribute_truncated = len(preview) < len(raw)
        value_truncated = value_truncated or attribute_truncated
        text_value, base64_value, null_terminated = _render_xattr_value(
            safe_name,
            preview,
            complete=not attribute_truncated,
        )

        acl_entries: list[POSIXACLEntry] = []
        acl_entry_count: int | None = None
        acl_entries_truncated = False
        acl_parse_error = None
        if name in POSIX_ACL_XATTRS:
            acl_entries, acl_entry_count, acl_entries_truncated, acl_parse_error = _parse_posix_acl(raw)

        attributes.append(
            ExtendedAttributeInfo(
                name=safe_name,
                size_bytes=len(raw),
                text_value=text_value,
                base64_value=base64_value,
                null_terminated=null_terminated,
                value_truncated=attribute_truncated,
                acl_entries=acl_entries,
                acl_entry_count=acl_entry_count,
                acl_entries_truncated=acl_entries_truncated,
                acl_parse_error=acl_parse_error,
            )
        )

    names_truncated = len(names) > MAX_XATTR_NAMES
    acl_truncated = any(attribute.acl_entries_truncated for attribute in attributes)
    acl_parse_errors = any(attribute.acl_parse_error is not None for attribute in attributes)
    messages: list[str] = []
    if read_errors:
        messages.append("Some attribute values could not be read with current permissions or filesystem state.")
    if names_truncated:
        messages.append(f"Attribute-name scanning was capped at {MAX_XATTR_NAMES} names.")
    if value_truncated:
        messages.append("Some attribute values were capped by the preview or page byte limit.")
    if acl_truncated:
        messages.append(f"Decoded ACL entries were capped at {MAX_ACL_ENTRIES} per attribute.")
    if acl_parse_errors:
        messages.append("At least one POSIX ACL xattr could not be decoded as a valid ACL.")
    messages.append("Only attributes visible to the current process are reported; no ACL or security-policy changes are made.")
    return PathExtendedAttributeResponse(
        success=True,
        path=str(target),
        offset=offset,
        next_offset=next_offset,
        has_more=has_more,
        total_attributes=len(names),
        returned_attributes=len(attributes),
        attributes=attributes,
        limit=limit,
        partial=bool(read_errors or names_truncated or value_truncated or acl_truncated or acl_parse_errors),
        truncated=names_truncated or value_truncated or acl_truncated,
        message=" ".join(messages),
    )


def list_directory(path: str, query: str = "", limit: int = 100, recursive: bool = False) -> DirectoryListResponse:
    if not sys.platform.startswith("linux"):
        return DirectoryListResponse(success=False, path=path if isinstance(path, str) else "", message="Directory listing is available only on Linux.")
    target, error = _resolve_path(path)
    if error or target is None:
        return DirectoryListResponse(success=False, path="", message=error)
    if not isinstance(query, str) or len(query) > 256:
        return DirectoryListResponse(success=False, path=str(target), message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return DirectoryListResponse(success=False, path=str(target), message="Query cannot contain control characters.")
    if not isinstance(recursive, bool):
        return DirectoryListResponse(success=False, path=str(target), message="recursive must be a boolean.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return DirectoryListResponse(success=False, path=str(target), message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_ENTRIES))
    needle = query.strip().casefold()
    entries: list[DirectoryEntryInfo] = []
    scanned = 0
    scan_truncated = False
    skipped = 0
    enumeration_error = None
    try:
        directory_fd = _open_resolved_path(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        return DirectoryListResponse(
            success=False,
            path=str(target),
            limit=limit,
            message=f"Could not open directory: {exc.strerror or 'not a readable directory'}.",
        )
    def scan(directory: int, prefix: str, depth: int) -> None:
        nonlocal scanned, scan_truncated, skipped, enumeration_error
        if recursive and depth > MAX_DIRECTORY_DEPTH:
            scan_truncated = True
            return
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    if scanned >= MAX_DIRECTORY_SCAN:
                        scan_truncated = True
                        return
                    scanned += 1
                    safe_name = _safe_name(entry.name)
                    relative_name = f"{prefix}/{safe_name}" if prefix else safe_name
                    try:
                        info = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                    except OSError:
                        skipped += 1
                        continue
                    if not needle or needle in relative_name.casefold():
                        entries.append(DirectoryEntryInfo(name=relative_name, **_metadata_values(info)))
                    if recursive and stat.S_ISDIR(info.st_mode):
                        child_fd: int | None = None
                        try:
                            child_fd = os.open(
                                entry.name,
                                os.O_RDONLY
                                | getattr(os, "O_DIRECTORY", 0)
                                | getattr(os, "O_CLOEXEC", 0)
                                | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=directory,
                            )
                            child_info = os.fstat(child_fd)
                            if (child_info.st_dev, child_info.st_ino) != (info.st_dev, info.st_ino):
                                skipped += 1
                                continue
                            scan(child_fd, relative_name, depth + 1)
                        except OSError as exc:
                            enumeration_error = exc.strerror or "nested directory read error"
                        finally:
                            if child_fd is not None:
                                os.close(child_fd)
                        if scan_truncated:
                            return
        except OSError as exc:
            enumeration_error = exc.strerror or "directory read error"

    try:
        scan(directory_fd, "", 0)
    finally:
        os.close(directory_fd)

    entries.sort(key=lambda item: item.name.casefold())
    returned = entries[:limit]
    truncated = scan_truncated or len(entries) > limit or enumeration_error is not None
    messages: list[str] = []
    if scan_truncated:
        cap = f"{MAX_DIRECTORY_SCAN} entries" if scanned >= MAX_DIRECTORY_SCAN else f"{MAX_DIRECTORY_DEPTH} levels"
        messages.append(f"Directory scan stopped at the {cap} safety limit.")
    if skipped:
        messages.append(f"Skipped {skipped} entries whose metadata could not be read.")
    if enumeration_error:
        messages.append(f"Directory scan ended early: {enumeration_error}.")
    elif len(entries) > limit:
        messages.append("More matching entries exist than the requested result limit.")
    return DirectoryListResponse(
        success=True,
        path=str(target),
        scanned_entries=scanned,
        total_entries=len(entries),
        returned_entries=len(returned),
        entries=returned,
        limit=limit,
        truncated=truncated,
        message=" ".join(messages) or None,
    )


def read_text_file(path: str, max_bytes: int = 64 * 1024) -> TextFileReadResponse:
    if not sys.platform.startswith("linux"):
        return TextFileReadResponse(success=False, message="Text-file reading is available only on Linux.")
    target, error = _resolve_path(path)
    if error or target is None:
        return TextFileReadResponse(success=False, message=error)
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_FILE_READ_BYTES:
        return TextFileReadResponse(success=False, path=str(target), message="max_bytes must be an integer from 1 through 65536.")
    try:
        initial = target.stat()
    except OSError as exc:
        return TextFileReadResponse(success=False, path=str(target), message=f"Could not inspect file: {exc.strerror or 'metadata unavailable'}.")
    if not stat.S_ISREG(initial.st_mode):
        return TextFileReadResponse(success=False, path=str(target), message="Only regular files can be read.")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = _open_resolved_path(target, flags)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                return TextFileReadResponse(success=False, path=str(target), message="Only regular files can be read.")
            data = stream.read(max_bytes + 1)
    except OSError as exc:
        return TextFileReadResponse(success=False, path=str(target), message=f"Could not read file: {exc.strerror or 'read error'}.")

    if b"\x00" in data:
        return TextFileReadResponse(success=False, path=str(target), size_bytes=info.st_size, message="Binary files are not returned by the text-file tool.")
    truncated = len(data) > max_bytes or info.st_size > max_bytes
    content_bytes = data[:max_bytes]
    try:
        content = content_bytes.decode("utf-8", errors="strict")
        replacements = False
    except UnicodeDecodeError:
        content = content_bytes.decode("utf-8", errors="replace")
        replacements = True
    return TextFileReadResponse(
        success=True,
        path=str(target),
        size_bytes=info.st_size,
        bytes_returned=len(content_bytes),
        content=content,
        truncated=truncated,
        encoding_replacements=replacements,
        message=(
            "File content was truncated at the requested byte limit."
            if truncated else "Invalid UTF-8 bytes were replaced during decoding."
            if replacements else None
        ),
    )
