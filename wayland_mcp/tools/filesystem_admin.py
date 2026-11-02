"""Paged binary reads and explicitly confirmed, metadata-preserving file writes."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import BinaryFileReadResponse, BinaryFileWriteResponse, PathAdminResponse
from wayland_mcp.tools.filesystem import (
    MAX_PATH_LENGTH,
    _is_blocked_path,
    _open_resolved_path,
    _resolve_path,
)

MAX_BINARY_READ_BYTES = 1024 * 1024
MAX_BINARY_WRITE_BYTES = 4 * 1024 * 1024
MAX_PRESERVED_XATTR_BYTES = 1024 * 1024
PROTECTED_SECURITY_XATTRS = {"security.capability", "security.ima", "security.evm"}
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


@dataclass(frozen=True, slots=True)
class BinaryFileWriteTarget:
    path: Path
    action: Literal["create", "replace", "append"]
    payload: bytes
    payload_sha256: str
    parent_device: int
    parent_inode: int
    current_snapshot: tuple[int, ...] | None


@dataclass(frozen=True, slots=True)
class BinaryFileDeleteTarget:
    path: Path
    parent_device: int
    parent_inode: int
    current_snapshot: tuple[int, ...]


def _snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _decode_payload(value: object) -> tuple[bytes | None, str | None]:
    if not isinstance(value, str):
        return None, "data_base64 must be a base64-encoded string."
    if len(value) > ((MAX_BINARY_WRITE_BYTES + 2) // 3) * 4:
        return None, f"Decoded file data cannot exceed {MAX_BINARY_WRITE_BYTES} bytes per call."
    try:
        encoded = value.encode("ascii", errors="strict")
        payload = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        return None, f"data_base64 is invalid: {type(exc).__name__}."
    if len(payload) > MAX_BINARY_WRITE_BYTES:
        return None, f"Decoded file data cannot exceed {MAX_BINARY_WRITE_BYTES} bytes per call."
    return payload, None


def _prepare_binary_write(
    path: object,
    data_base64: object,
    action: object,
) -> tuple[BinaryFileWriteTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Binary file writing is available only on Linux."
    if not isinstance(action, str) or action not in {"create", "replace", "append"}:
        return None, "action must be 'create', 'replace', or 'append'."
    if not isinstance(path, str) or not path.strip() or len(path) > MAX_PATH_LENGTH:
        return None, f"Path must be non-empty text with at most {MAX_PATH_LENGTH} characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return None, "Path cannot contain control characters."
    payload, error = _decode_payload(data_base64)
    if error or payload is None:
        return None, error
    if action == "append" and not payload:
        return None, "Append requires at least one data byte."

    try:
        input_path = Path(path).expanduser()
        if not input_path.is_absolute():
            return None, "Path must be absolute; '~' is expanded to the current user's home directory."
        lexical_path = Path(os.path.abspath(input_path))
        if _is_blocked_path(lexical_path):
            return None, "Paths under /proc, /sys, /dev, and /run are excluded from general filesystem tools."
        if not lexical_path.name or lexical_path.name in {".", ".."}:
            return None, "Path must name one regular file inside an existing directory."
        parent = lexical_path.parent.resolve(strict=True)
        if _is_blocked_path(parent):
            return None, "Paths under /proc, /sys, /dev, and /run are excluded from general filesystem tools."
        target_path = parent / lexical_path.name
        parent_fd = _open_resolved_path(parent, _DIRECTORY_FLAGS)
        try:
            parent_info = os.fstat(parent_fd)
            if not stat.S_ISDIR(parent_info.st_mode):
                return None, "The target parent is not a directory."
            current_snapshot: tuple[int, ...] | None = None
            try:
                entry = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                if action != "create":
                    return None, f"The target must already exist for action {action!r}."
            else:
                if action == "create":
                    return None, "The destination already exists; create never overwrites a path."
                if not stat.S_ISREG(entry.st_mode):
                    return None, "Replace and append operate only on regular files and never follow symlinks."
                fd = os.open(target_path.name, _READ_FLAGS, dir_fd=parent_fd)
                try:
                    opened = os.fstat(fd)
                    if _snapshot(opened) != _snapshot(entry) or not stat.S_ISREG(opened.st_mode):
                        return None, "The target changed while its identity was checked."
                    if action == "append" and opened.st_nlink != 1:
                        return None, "Append refuses multiply linked files because it would change every hard-link path."
                    current_snapshot = _snapshot(opened)
                finally:
                    os.close(fd)
        finally:
            os.close(parent_fd)
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"The binary file destination could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."

    return BinaryFileWriteTarget(
        path=target_path,
        action=action,
        payload=payload,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        parent_device=parent_info.st_dev,
        parent_inode=parent_info.st_ino,
        current_snapshot=current_snapshot,
    ), None


def binary_file_write_confirmation_details(
    path: str,
    data_base64: str,
    action: Literal["create", "replace", "append"],
) -> tuple[BinaryFileWriteTarget | None, str | None, str | None]:
    target, error = _prepare_binary_write(path, data_base64, action)
    if target is None:
        return None, None, error
    material = json.dumps(
        {
            "path": str(target.path),
            "action": target.action,
            "payload_sha256": target.payload_sha256,
            "payload_bytes": len(target.payload),
            "parent_device": target.parent_device,
            "parent_inode": target.parent_inode,
            "current_snapshot": target.current_snapshot,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    phrase = f"WRITE {hashlib.sha256(material).hexdigest()[:16]}"
    return target, phrase, None


def _prepare_binary_delete(path: object) -> tuple[BinaryFileDeleteTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Binary file deletion is available only on Linux."
    if not isinstance(path, str) or not path.strip() or len(path) > MAX_PATH_LENGTH:
        return None, f"Path must be non-empty text with at most {MAX_PATH_LENGTH} characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return None, "Path cannot contain control characters."
    try:
        raw = Path(path).expanduser()
        if not raw.is_absolute():
            return None, "Path must be absolute; '~' is expanded to the current user's home directory."
        lexical = Path(os.path.abspath(raw))
        if not lexical.name or lexical.name in {".", ".."} or _is_blocked_path(lexical):
            return None, "Path must name one regular file outside /proc, /sys, /dev, and /run."
        parent = lexical.parent.resolve(strict=True)
        if _is_blocked_path(parent):
            return None, "Paths under /proc, /sys, /dev, and /run are excluded from general filesystem tools."
        target_path = parent / lexical.name
        parent_fd = _open_resolved_path(parent, _DIRECTORY_FLAGS)
        try:
            parent_info = os.fstat(parent_fd)
            entry = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(entry.st_mode):
                return None, "Binary-file deletion operates only on regular files and never follows symlinks."
            file_fd = os.open(target_path.name, _READ_FLAGS, dir_fd=parent_fd)
            try:
                opened = os.fstat(file_fd)
                if not stat.S_ISREG(opened.st_mode) or _snapshot(opened) != _snapshot(entry):
                    return None, "The file changed while its identity was checked."
                snapshot = _snapshot(opened)
            finally:
                os.close(file_fd)
        finally:
            os.close(parent_fd)
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"The binary file could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."
    return BinaryFileDeleteTarget(
        path=target_path,
        parent_device=parent_info.st_dev,
        parent_inode=parent_info.st_ino,
        current_snapshot=snapshot,
    ), None


def binary_file_delete_confirmation_details(
    path: str,
) -> tuple[BinaryFileDeleteTarget | None, str | None, str | None]:
    target, error = _prepare_binary_delete(path)
    if target is None:
        return None, None, error
    material = json.dumps(
        {
            "path": str(target.path),
            "parent_device": target.parent_device,
            "parent_inode": target.parent_inode,
            "current_snapshot": target.current_snapshot,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    phrase = f"DELETE BINARY {hashlib.sha256(material).hexdigest()[:16]}"
    return target, phrase, None


def delete_binary_file(
    path: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> PathAdminResponse:

    target, expected_phrase, error = binary_file_delete_confirmation_details(path)
    if error or target is None or expected_phrase is None:
        return PathAdminResponse(success=False, path=path, action="delete_binary", user_confirmed=confirmed is True, message=error or "The file deletion could not be verified.")
    size_bytes = target.current_snapshot[6]
    if confirmed is not True:
        return PathAdminResponse(success=False, path=str(target.path), action="delete_binary", bytes_affected=size_bytes, message="Explicit client confirmation is required; the file was not deleted.")
    if confirmation_phrase != expected_phrase:
        return PathAdminResponse(success=False, path=str(target.path), action="delete_binary", bytes_affected=size_bytes, user_confirmed=True, message="Confirmation did not match this exact file identity and current state; the file was not deleted.")

    parent_fd: int | None = None
    file_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(target.path.parent, _DIRECTORY_FLAGS)
        parent_info = os.fstat(parent_fd)
        if (parent_info.st_dev, parent_info.st_ino) != (target.parent_device, target.parent_inode):
            raise OSError("The parent directory changed after confirmation.")
        entry = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(entry.st_mode) or _snapshot(entry) != target.current_snapshot:
            raise OSError("The file identity or metadata changed after confirmation.")
        file_fd = os.open(target.path.name, _READ_FLAGS, dir_fd=parent_fd)
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode) or _snapshot(opened) != target.current_snapshot:
            raise OSError("The opened file changed after confirmation.")
        os.unlink(target.path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return PathAdminResponse(success=True, path=str(target.path), action="delete_binary", bytes_affected=size_bytes, link_count=target.current_snapshot[3], user_confirmed=True, message="The regular file was unlinked. This is not secure erasure; other hard links, backups, and storage snapshots may retain data.")
    except OSError as exc:
        return PathAdminResponse(success=False, path=str(target.path), action="delete_binary", bytes_affected=size_bytes, user_confirmed=True, message=f"Binary-file deletion failed: {exc.strerror or str(exc) or type(exc).__name__}.")
    finally:
        for fd in (file_fd, parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def read_binary_file(path: str, *, offset: int = 0, max_bytes: int = 262144) -> BinaryFileReadResponse:
    if not sys.platform.startswith("linux"):
        return BinaryFileReadResponse(success=False, message="Binary file reading is available only on Linux.")
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= (1 << 63) - 1:
        return BinaryFileReadResponse(success=False, message="offset must be a nonnegative signed 64-bit integer.")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= MAX_BINARY_READ_BYTES:
        return BinaryFileReadResponse(success=False, message=f"max_bytes must be from 1 through {MAX_BINARY_READ_BYTES}.")
    target, error = _resolve_path(path)
    if error or target is None:
        return BinaryFileReadResponse(success=False, message=error)
    try:
        fd = _open_resolved_path(target, _READ_FLAGS)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                return BinaryFileReadResponse(success=False, path=str(target), message="Only regular files can be read as binary data.")
            payload = os.pread(fd, max_bytes, offset)
            after = os.fstat(fd)
            if _snapshot(before) != _snapshot(after):
                return BinaryFileReadResponse(success=False, path=str(target), message="The file changed while the requested byte range was read; retry from the desired offset.")
        finally:
            os.close(fd)
    except OSError as exc:
        return BinaryFileReadResponse(success=False, path=str(target), message=f"Could not read binary file: {exc.strerror or 'access failed'}.")
    next_offset = offset + len(payload)
    return BinaryFileReadResponse(
        success=True,
        path=str(target),
        offset=offset,
        size_bytes=before.st_size,
        bytes_returned=len(payload),
        data_base64=base64.b64encode(payload).decode("ascii"),
        next_offset=next_offset if next_offset < before.st_size else None,
        truncated=next_offset < before.st_size,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        try:
            count = os.write(fd, view)
        except OSError as exc:
            exc.bytes_written = len(payload) - len(view)
            raise
        if count <= 0:
            exc = OSError("The filesystem accepted no bytes while writing.")
            exc.bytes_written = len(payload) - len(view)
            raise exc
        view = view[count:]


def _preserve_xattrs(source_fd: int, destination_fd: int) -> None:
    names = os.listxattr(source_fd)
    if PROTECTED_SECURITY_XATTRS.intersection(names):
        raise OSError("Replace refuses files with visible capability, IMA, or EVM security attributes.")
    total = 0
    for name in names:
        value = os.getxattr(source_fd, name)
        total += len(name.encode("utf-8")) + len(value)
        if total > MAX_PRESERVED_XATTR_BYTES:
            raise OSError("Extended attributes exceed the 1 MiB preservation limit.")
        os.setxattr(destination_fd, name, value)


def write_binary_file(
    path: str,
    data_base64: str,
    action: Literal["create", "replace", "append"],
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> BinaryFileWriteResponse:
    target, expected_phrase, error = binary_file_write_confirmation_details(path, data_base64, action)
    if error or target is None or expected_phrase is None:
        return BinaryFileWriteResponse(success=False, path=path if isinstance(path, str) else None, action=action if action in {"create", "replace", "append"} else None, user_confirmed=confirmed is True, message=error or "The write request could not be verified.")
    if confirmed is not True:
        return BinaryFileWriteResponse(success=False, path=str(target.path), action=target.action, sha256=target.payload_sha256, message="Explicit client confirmation is required; no bytes were written.")
    if confirmation_phrase != expected_phrase:
        return BinaryFileWriteResponse(success=False, path=str(target.path), action=target.action, sha256=target.payload_sha256, user_confirmed=True, message="Confirmation did not match this exact file request and current state; no bytes were written.")

    parent_fd: int | None = None
    source_fd: int | None = None
    temp_fd: int | None = None
    temp_name: str | None = None
    bytes_written = 0
    try:
        parent_fd = _open_resolved_path(target.path.parent, _DIRECTORY_FLAGS)
        parent_info = os.fstat(parent_fd)
        if (parent_info.st_dev, parent_info.st_ino) != (target.parent_device, target.parent_inode):
            raise OSError("Destination directory identity changed after confirmation.")
        current_snapshot: tuple[int, ...] | None = None
        if target.action != "create":
            source_fd = os.open(target.path.name, _READ_FLAGS, dir_fd=parent_fd)
            if target.action == "append":
                fcntl.flock(source_fd, fcntl.LOCK_EX)
            source_info = os.fstat(source_fd)
            current_snapshot = _snapshot(source_info)
            if current_snapshot != target.current_snapshot:
                raise OSError("The target changed after confirmation.")
        if target.action == "append":
            assert source_fd is not None and source_info is not None
            append_fd = os.open(
                target.path.name,
                os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            try:
                append_info = os.fstat(append_fd)
                if _snapshot(append_info) != target.current_snapshot:
                    raise OSError("The target changed before append began.")
                _write_all(append_fd, target.payload)
                bytes_written = len(target.payload)
                os.fsync(append_fd)
                final_size = os.fstat(append_fd).st_size
            finally:
                os.close(append_fd)
        else:
            temp_name = f".linux-mcp-{secrets.token_hex(12)}.tmp"
            if target.action == "replace":
                assert source_fd is not None
                mode = stat.S_IMODE(source_info.st_mode)
                uid, gid = source_info.st_uid, source_info.st_gid
            else:
                mode, uid, gid = 0o600, os.geteuid(), os.getegid()
            temp_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=parent_fd,
            )
            if target.action == "replace":
                if (os.fstat(temp_fd).st_uid, os.fstat(temp_fd).st_gid) != (uid, gid):
                    os.fchown(temp_fd, uid, gid)
                _preserve_xattrs(source_fd, temp_fd)
            os.fchmod(temp_fd, mode)
            _write_all(temp_fd, target.payload)
            bytes_written = len(target.payload)
            os.fsync(temp_fd)
            temp_info = os.fstat(temp_fd)
            final_size = temp_info.st_size
            if target.action == "create":
                os.link(temp_name, target.path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
                created_info = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
                if (created_info.st_dev, created_info.st_ino) != (temp_info.st_dev, temp_info.st_ino):
                    raise OSError("The new path changed while the file was being linked.")
                os.unlink(temp_name, dir_fd=parent_fd)
            else:
                current_entry = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
                if _snapshot(current_entry) != target.current_snapshot:
                    raise OSError("The target changed before atomic replacement.")
                os.replace(temp_name, target.path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                replaced_info = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
                if (replaced_info.st_dev, replaced_info.st_ino) != (temp_info.st_dev, temp_info.st_ino):
                    raise OSError("The destination changed during atomic replacement.")
            temp_name = None
            os.close(temp_fd)
            temp_fd = None
            os.fsync(parent_fd)
        if source_fd is not None:
            os.close(source_fd)
            source_fd = None
        if target.action == "append":
            expected_size = target.current_snapshot[6] + len(target.payload)
        else:
            expected_size = len(target.payload)
        if final_size != expected_size:
            raise OSError("Written file size did not match the requested byte count.")
        return BinaryFileWriteResponse(
            success=True,
            path=str(target.path),
            action=target.action,
            bytes_written=len(target.payload),
            file_size_bytes=final_size,
            sha256=target.payload_sha256,
            user_confirmed=True,
            message="Binary data was written and the resulting file size was verified.",
        )
    except OSError as exc:
        return BinaryFileWriteResponse(
            success=False,
            path=str(target.path),
            action=target.action,
            bytes_written=(getattr(exc, "bytes_written", 0) if target.action == "append" else 0),
            sha256=target.payload_sha256,
            user_confirmed=True,
            message=f"Binary write failed: {exc.strerror or str(exc) or type(exc).__name__}. Inspect the destination before retrying.",
        )
    finally:
        if parent_fd is not None and temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:
                pass
        for fd in (source_fd, temp_fd, parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
