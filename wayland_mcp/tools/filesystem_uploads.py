"""Confirmed, bounded, chunked binary-file creation and atomic replacement."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import BinaryFileUploadResponse
from wayland_mcp.tools.filesystem import MAX_PATH_LENGTH, _is_blocked_path, _open_resolved_path
from wayland_mcp.tools.filesystem_admin import (
    MAX_BINARY_WRITE_BYTES,
    MAX_PRESERVED_XATTR_BYTES,
    PROTECTED_SECURITY_XATTRS,
    _decode_payload,
    _preserve_xattrs,
    _snapshot,
    _write_all,
)

BinaryUploadAction = Literal["create", "replace"]
MAX_BINARY_UPLOAD_BYTES = 64 * 1024 * 1024 * 1024
MAX_ACTIVE_BINARY_UPLOADS = 4
MAX_RESERVED_BINARY_UPLOAD_BYTES = 128 * 1024 * 1024 * 1024
BINARY_UPLOAD_TTL_SECONDS = 60 * 60
_UPLOAD_ID_RE = re.compile(r"^[A-Za-z0-9_-]{40,60}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
_LOCK = threading.RLock()


@dataclass(frozen=True, slots=True)
class BinaryFileUploadTarget:
    path: Path
    action: BinaryUploadAction
    expected_size: int
    expected_sha256: str
    parent_device: int
    parent_inode: int
    current_snapshot: tuple[int, ...] | None
    confirmation_phrase: str


@dataclass(slots=True)
class _UploadSession:
    upload_id: str
    path: Path
    action: BinaryUploadAction
    expected_size: int
    expected_sha256: str
    parent_fd: int
    parent_device: int
    parent_inode: int
    temp_fd: int
    temp_name: str
    temp_device: int
    temp_inode: int
    current_snapshot: tuple[int, ...] | None
    uploaded_bytes: int
    expires_at: float
    committing: bool = False


_UPLOADS: dict[str, _UploadSession] = {}


def _scan_source_xattrs(fd: int) -> str | None:
    try:
        names = os.listxattr(fd)
        if PROTECTED_SECURITY_XATTRS.intersection(names):
            return "Replacement refuses files with visible capability, IMA, or EVM security attributes."
        total = 0
        for name in names:
            total += len(name.encode("utf-8", errors="strict")) + len(os.getxattr(fd, name))
            if total > MAX_PRESERVED_XATTR_BYTES:
                return "Extended attributes exceed the 1 MiB preservation limit."
    except OSError as exc:
        return f"The existing file's extended attributes could not be checked: {exc.strerror or type(exc).__name__}."
    return None


def _prepare_binary_file_upload(
    path: object,
    action: object,
    expected_size: object,
    expected_sha256: object,
) -> tuple[BinaryFileUploadTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Chunked binary-file operations are available only on Linux."
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "pread"):
        return None, "The required no-follow and positioned-read file interfaces are unavailable."
    if not isinstance(action, str) or action not in {"create", "replace"}:
        return None, "action must be 'create' or 'replace'."
    if isinstance(expected_size, bool) or not isinstance(expected_size, int):
        return None, "expected_size must be an integer."
    if not MAX_BINARY_WRITE_BYTES < expected_size <= MAX_BINARY_UPLOAD_BYTES:
        return None, f"Chunked uploads must exceed {MAX_BINARY_WRITE_BYTES} bytes and cannot exceed {MAX_BINARY_UPLOAD_BYTES} bytes."
    if not isinstance(expected_sha256, str) or not _DIGEST_RE.fullmatch(expected_sha256):
        return None, "expected_sha256 must be a lowercase 64-character SHA-256 digest."
    if not isinstance(path, str) or not path.strip() or len(path) > MAX_PATH_LENGTH:
        return None, f"Path must be non-empty text with at most {MAX_PATH_LENGTH} characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return None, "Path cannot contain control characters."

    parent_fd: int | None = None
    source_fd: int | None = None
    try:
        raw = Path(path).expanduser()
        if not raw.is_absolute():
            return None, "Path must be absolute; '~' is expanded to the current user's home directory."
        lexical = Path(os.path.abspath(raw))
        if not lexical.name or lexical.name in {".", ".."} or _is_blocked_path(lexical):
            return None, "Path must name a regular file outside /proc, /sys, /dev, and /run."
        parent = lexical.parent.resolve(strict=True)
        if _is_blocked_path(parent):
            return None, "Paths under /proc, /sys, /dev, and /run are excluded from general filesystem tools."
        target_path = parent / lexical.name
        parent_fd = _open_resolved_path(parent, _DIRECTORY_FLAGS)
        parent_info = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_info.st_mode):
            return None, "The target parent is not a directory."

        current_snapshot: tuple[int, ...] | None = None
        try:
            entry = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if action == "replace":
                return None, "The target must already exist for replacement."
        else:
            if action == "create":
                return None, "The destination already exists; create never overwrites a path."
            if not stat.S_ISREG(entry.st_mode):
                return None, "Replacement operates only on regular files and never follows symlinks."
            source_fd = os.open(target_path.name, _READ_FLAGS, dir_fd=parent_fd)
            source_info = os.fstat(source_fd)
            if _snapshot(source_info) != _snapshot(entry) or not stat.S_ISREG(source_info.st_mode):
                return None, "The target changed while its identity was checked."
            xattr_error = _scan_source_xattrs(source_fd)
            if xattr_error:
                return None, xattr_error
            current_snapshot = _snapshot(source_info)

        target_material = {
            "path": str(target_path),
            "action": action,
            "expected_size": expected_size,
            "expected_sha256": expected_sha256,
            "parent_device": parent_info.st_dev,
            "parent_inode": parent_info.st_ino,
            "current_snapshot": current_snapshot,
        }
        digest = hashlib.sha256(
            json.dumps(target_material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()
        target = BinaryFileUploadTarget(
            path=target_path,
            action=action,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            parent_device=parent_info.st_dev,
            parent_inode=parent_info.st_ino,
            current_snapshot=current_snapshot,
            confirmation_phrase=f"UPLOAD {digest[:16]}",
        )
        return target, None
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        return None, f"The binary-file upload destination could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."
    finally:
        for descriptor in (source_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def binary_file_upload_confirmation_details(
    path: str,
    action: BinaryUploadAction,
    expected_size: int,
    expected_sha256: str,
) -> tuple[BinaryFileUploadTarget | None, str | None]:
    return _prepare_binary_file_upload(path, action, expected_size, expected_sha256)


def _close_upload(upload: _UploadSession, *, unlink: bool) -> None:
    if unlink:
        try:
            info = os.stat(upload.temp_name, dir_fd=upload.parent_fd, follow_symlinks=False)
            if (info.st_dev, info.st_ino) == (upload.temp_device, upload.temp_inode):
                os.unlink(upload.temp_name, dir_fd=upload.parent_fd)
        except OSError:
            pass
    for descriptor in (upload.temp_fd, upload.parent_fd):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _expire_uploads_locked(now: float) -> None:
    for upload_id, upload in tuple(_UPLOADS.items()):
        if upload.expires_at <= now and not upload.committing:
            _UPLOADS.pop(upload_id, None)
            _close_upload(upload, unlink=True)


def expire_binary_file_uploads() -> None:
    """Discard expired upload sessions and their staging files."""
    with _LOCK:
        _expire_uploads_locked(time.monotonic())


def _response(
    *,
    success: bool,
    state: Literal["started", "uploading", "committed", "aborted", "failed"],
    upload: _UploadSession | None = None,
    user_confirmed: bool = False,
    file_size: int | None = None,
    file_changed: bool = False,
    message: str,
) -> BinaryFileUploadResponse:
    return BinaryFileUploadResponse(
        success=success,
        state=state,
        upload_id=upload.upload_id if upload is not None else None,
        path=str(upload.path) if upload is not None else None,
        action=upload.action if upload is not None else None,
        expected_size_bytes=upload.expected_size if upload is not None else None,
        uploaded_bytes=upload.uploaded_bytes if upload is not None else 0,
        file_size_bytes=file_size,
        sha256=upload.expected_sha256 if upload is not None else None,
        file_changed=file_changed,
        user_confirmed=user_confirmed,
        message=message,
    )


def begin_binary_file_upload(
    path: str,
    action: BinaryUploadAction,
    expected_size: int,
    expected_sha256: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> BinaryFileUploadResponse:
    target, error = _prepare_binary_file_upload(path, action, expected_size, expected_sha256)
    if error or target is None:
        safe_action = action if isinstance(action, str) and action in {"create", "replace"} else None
        return BinaryFileUploadResponse(success=False, path=path if isinstance(path, str) else None, action=safe_action, user_confirmed=confirmed is True, message=error or "The upload request could not be verified.")
    if confirmed is not True:
        return BinaryFileUploadResponse(success=False, path=str(target.path), action=target.action, expected_size_bytes=target.expected_size, sha256=target.expected_sha256, message="Explicit client confirmation is required; no staging file was created.")
    if confirmation_phrase != target.confirmation_phrase:
        return BinaryFileUploadResponse(success=False, path=str(target.path), action=target.action, expected_size_bytes=target.expected_size, sha256=target.expected_sha256, user_confirmed=True, message="Confirmation did not match the exact path, expected content digest, and current target state.")

    with _LOCK:
        _expire_uploads_locked(time.monotonic())
        reserved = sum(upload.expected_size for upload in _UPLOADS.values())
        if len(_UPLOADS) >= MAX_ACTIVE_BINARY_UPLOADS or reserved + target.expected_size > MAX_RESERVED_BINARY_UPLOAD_BYTES:
            return BinaryFileUploadResponse(success=False, path=str(target.path), action=target.action, expected_size_bytes=target.expected_size, sha256=target.expected_sha256, user_confirmed=True, message="The server's bounded concurrent-upload capacity is full; no staging file was created.")

        current, error = _prepare_binary_file_upload(path, action, expected_size, expected_sha256)
        if error or current is None or current != target:
            return BinaryFileUploadResponse(success=False, path=str(target.path), action=target.action, expected_size_bytes=target.expected_size, sha256=target.expected_sha256, user_confirmed=True, message=error or "The target directory or file changed after confirmation; no staging file was created.")

        parent_fd: int | None = None
        temp_fd: int | None = None
        temp_name: str | None = None
        try:
            parent_fd = _open_resolved_path(target.path.parent, _DIRECTORY_FLAGS)
            parent_info = os.fstat(parent_fd)
            if (parent_info.st_dev, parent_info.st_ino) != (target.parent_device, target.parent_inode):
                raise OSError("Destination directory identity changed after confirmation.")
            space = os.fstatvfs(parent_fd)
            available_bytes = space.f_bavail * (space.f_frsize or space.f_bsize)
            outstanding_on_filesystem = sum(
                max(0, upload.expected_size - upload.uploaded_bytes)
                for upload in _UPLOADS.values()
                if upload.parent_device == target.parent_device
            )
            if available_bytes < outstanding_on_filesystem + target.expected_size:
                raise OSError("The destination filesystem does not have enough currently available space for this upload and active reservations.")
            if target.action == "replace":
                source_fd = os.open(target.path.name, _READ_FLAGS, dir_fd=parent_fd)
                try:
                    if _snapshot(os.fstat(source_fd)) != target.current_snapshot:
                        raise OSError("The target changed after confirmation.")
                    xattr_error = _scan_source_xattrs(source_fd)
                    if xattr_error:
                        raise OSError(xattr_error)
                finally:
                    os.close(source_fd)

            for _attempt in range(4):
                candidate = f".linux-mcp-upload-{secrets.token_hex(16)}.part"
                try:
                    temp_fd = os.open(
                        candidate,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=parent_fd,
                    )
                except FileExistsError:
                    continue
                temp_name = candidate
                break
            if temp_fd is None or temp_name is None:
                raise OSError("A unique staging filename could not be created.")
            os.fchmod(temp_fd, 0o600)
            os.fsync(parent_fd)
            temp_info = os.fstat(temp_fd)
            upload_id = secrets.token_urlsafe(32)
            upload = _UploadSession(
                upload_id=upload_id,
                path=target.path,
                action=target.action,
                expected_size=target.expected_size,
                expected_sha256=target.expected_sha256,
                parent_fd=parent_fd,
                parent_device=target.parent_device,
                parent_inode=target.parent_inode,
                temp_fd=temp_fd,
                temp_name=temp_name,
                temp_device=temp_info.st_dev,
                temp_inode=temp_info.st_ino,
                current_snapshot=target.current_snapshot,
                uploaded_bytes=0,
                expires_at=time.monotonic() + BINARY_UPLOAD_TTL_SECONDS,
            )
            _UPLOADS[upload_id] = upload
            parent_fd = None
            temp_fd = None
            return _response(success=True, state="started", upload=upload, user_confirmed=True, message="A private staging file was created. Append chunks at the reported offset, then commit before the upload expires.")
        except OSError as exc:
            if parent_fd is not None and temp_name is not None:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except OSError:
                    pass
            return BinaryFileUploadResponse(success=False, path=str(target.path), action=target.action, expected_size_bytes=target.expected_size, sha256=target.expected_sha256, user_confirmed=True, message=f"Could not start the binary-file upload: {exc.strerror or str(exc) or type(exc).__name__}.")
        finally:
            for descriptor in (temp_fd, parent_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass


def append_binary_file_upload(
    upload_id: str,
    offset: int,
    data_base64: str,
) -> BinaryFileUploadResponse:
    if not isinstance(upload_id, str) or not _UPLOAD_ID_RE.fullmatch(upload_id):
        return BinaryFileUploadResponse(success=False, message="upload_id is invalid or expired.")
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= MAX_BINARY_UPLOAD_BYTES:
        return BinaryFileUploadResponse(success=False, message="offset must be a nonnegative upload byte offset.")
    payload, error = _decode_payload(data_base64)
    if error or payload is None:
        return BinaryFileUploadResponse(success=False, message=error or "The chunk could not be decoded.")
    if not payload:
        return BinaryFileUploadResponse(success=False, message="Each chunk must contain at least one byte.")

    with _LOCK:
        _expire_uploads_locked(time.monotonic())
        upload = _UPLOADS.get(upload_id)
        if upload is None:
            return BinaryFileUploadResponse(success=False, message="The upload token is invalid, expired, or already completed.")
        if upload.committing:
            return _response(success=False, state="failed", upload=upload, message="This upload is being committed and no longer accepts chunks.")
        if offset != upload.uploaded_bytes:
            return _response(success=False, state="failed", upload=upload, message="offset must match the exact next byte position; no bytes were appended.")
        if upload.uploaded_bytes + len(payload) > upload.expected_size:
            return _response(success=False, state="failed", upload=upload, message="The chunk would exceed the confirmed total size; no bytes were appended.")
        try:
            info = os.fstat(upload.temp_fd)
            if (info.st_dev, info.st_ino) != (upload.temp_device, upload.temp_inode) or not stat.S_ISREG(info.st_mode):
                raise OSError("The staging file identity changed.")
            os.lseek(upload.temp_fd, upload.uploaded_bytes, os.SEEK_SET)
            _write_all(upload.temp_fd, payload)
            upload.uploaded_bytes += len(payload)
            upload.expires_at = time.monotonic() + BINARY_UPLOAD_TTL_SECONDS
            return _response(success=True, state="uploading", upload=upload, user_confirmed=True, message="The chunk was appended to the private staging file; the destination has not changed.")
        except OSError as exc:
            _UPLOADS.pop(upload_id, None)
            _close_upload(upload, unlink=True)
            return BinaryFileUploadResponse(success=False, path=str(upload.path), action=upload.action, expected_size_bytes=upload.expected_size, uploaded_bytes=upload.uploaded_bytes, sha256=upload.expected_sha256, user_confirmed=True, message=f"Chunk write failed and the private staging file was discarded: {exc.strerror or str(exc) or type(exc).__name__}.")


def _hash_staged_file(upload: _UploadSession) -> tuple[str | None, str | None]:
    try:
        info = os.fstat(upload.temp_fd)
        if (info.st_dev, info.st_ino) != (upload.temp_device, upload.temp_inode) or not stat.S_ISREG(info.st_mode):
            return None, "The staging file identity changed."
        if info.st_size != upload.expected_size or upload.uploaded_bytes != upload.expected_size:
            return None, "The staged byte count does not match the confirmed total size."
        digest = hashlib.sha256()
        offset = 0
        while offset < upload.expected_size:
            chunk = os.pread(upload.temp_fd, min(1024 * 1024, upload.expected_size - offset), offset)
            if not chunk:
                return None, "The staging file ended before the confirmed byte count."
            digest.update(chunk)
            offset += len(chunk)
        return digest.hexdigest(), None
    except OSError as exc:
        return None, f"The staging file could not be verified: {exc.strerror or type(exc).__name__}."


def commit_binary_file_upload(upload_id: str) -> BinaryFileUploadResponse:
    if not isinstance(upload_id, str) or not _UPLOAD_ID_RE.fullmatch(upload_id):
        return BinaryFileUploadResponse(success=False, message="upload_id is invalid or expired.")
    with _LOCK:
        _expire_uploads_locked(time.monotonic())
        upload = _UPLOADS.get(upload_id)
        if upload is None:
            return BinaryFileUploadResponse(success=False, message="The upload token is invalid, expired, or already completed.")
        if upload.committing:
            return _response(success=False, state="failed", upload=upload, message="The upload is already being committed.")
        if upload.uploaded_bytes != upload.expected_size:
            return _response(success=False, state="uploading", upload=upload, user_confirmed=True, message="The confirmed byte count has not been uploaded yet; the destination has not changed.")
        upload.committing = True

    file_changed = False
    final_size: int | None = None
    try:
        digest, error = _hash_staged_file(upload)
        if error or digest != upload.expected_sha256:
            raise OSError(error or "The staged data does not match the confirmed SHA-256 digest.")

        visible_parent_fd = _open_resolved_path(upload.path.parent, _DIRECTORY_FLAGS)
        try:
            visible_parent = os.fstat(visible_parent_fd)
            if (visible_parent.st_dev, visible_parent.st_ino) != (upload.parent_device, upload.parent_inode):
                raise OSError("The destination directory changed after confirmation.")
            held_parent = os.fstat(upload.parent_fd)
            if (held_parent.st_dev, held_parent.st_ino) != (upload.parent_device, upload.parent_inode) or not stat.S_ISDIR(held_parent.st_mode):
                raise OSError("The open destination directory identity changed.")

            source_fd: int | None = None
            try:
                if upload.action == "replace":
                    source_fd = os.open(upload.path.name, _READ_FLAGS, dir_fd=upload.parent_fd)
                    source_info = os.fstat(source_fd)
                    if not stat.S_ISREG(source_info.st_mode) or _snapshot(source_info) != upload.current_snapshot:
                        raise OSError("The target file changed after confirmation; the staged file was not published.")
                    xattr_error = _scan_source_xattrs(source_fd)
                    if xattr_error:
                        raise OSError(xattr_error)
                    temp_info = os.fstat(upload.temp_fd)
                    if (temp_info.st_uid, temp_info.st_gid) != (source_info.st_uid, source_info.st_gid):
                        os.fchown(upload.temp_fd, source_info.st_uid, source_info.st_gid)
                    _preserve_xattrs(source_fd, upload.temp_fd)
                    os.fchmod(upload.temp_fd, stat.S_IMODE(source_info.st_mode))
                else:
                    try:
                        os.stat(upload.path.name, dir_fd=upload.parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise OSError("The destination now exists; create never overwrites a path.")

                staged = os.fstat(upload.temp_fd)
                if (staged.st_dev, staged.st_ino) != (upload.temp_device, upload.temp_inode) or not stat.S_ISREG(staged.st_mode) or staged.st_size != upload.expected_size:
                    raise OSError("The staging file identity or size changed before publication.")
                os.fsync(upload.temp_fd)
                staged_entry = os.stat(upload.temp_name, dir_fd=upload.parent_fd, follow_symlinks=False)
                if (
                    (staged_entry.st_dev, staged_entry.st_ino) != (upload.temp_device, upload.temp_inode)
                    or not stat.S_ISREG(staged_entry.st_mode)
                ):
                    raise OSError("The private staging path no longer names the verified staging file.")

                if upload.action == "create":
                    os.link(upload.temp_name, upload.path.name, src_dir_fd=upload.parent_fd, dst_dir_fd=upload.parent_fd, follow_symlinks=False)
                    file_changed = True
                    published = os.stat(upload.path.name, dir_fd=upload.parent_fd, follow_symlinks=False)
                    if (published.st_dev, published.st_ino) != (upload.temp_device, upload.temp_inode):
                        raise OSError("The new target path changed while it was being published.")
                    os.unlink(upload.temp_name, dir_fd=upload.parent_fd)
                else:
                    current_entry = os.stat(upload.path.name, dir_fd=upload.parent_fd, follow_symlinks=False)
                    if _snapshot(current_entry) != upload.current_snapshot:
                        raise OSError("The target changed before atomic replacement; the staged file was not published.")
                    os.replace(upload.temp_name, upload.path.name, src_dir_fd=upload.parent_fd, dst_dir_fd=upload.parent_fd)
                    file_changed = True
                    upload.temp_name = ""
                    published = os.stat(upload.path.name, dir_fd=upload.parent_fd, follow_symlinks=False)
                    if (published.st_dev, published.st_ino) != (upload.temp_device, upload.temp_inode):
                        raise OSError("The destination changed during atomic replacement; inspect it before retrying.")
                file_changed = True
                final_size = published.st_size
                upload.temp_name = ""
                os.fsync(upload.parent_fd)
                final_digest, verify_error = _hash_staged_file(upload)
                if verify_error or final_digest != upload.expected_sha256 or final_size != upload.expected_size:
                    raise OSError(verify_error or "Published file verification did not match the confirmed digest and size.")
            finally:
                if source_fd is not None:
                    os.close(source_fd)
        finally:
            os.close(visible_parent_fd)

        return _response(success=True, state="committed", upload=upload, user_confirmed=True, file_size=final_size, file_changed=True, message="The chunked binary file was published and its size and SHA-256 were verified.")
    except OSError as exc:
        return _response(success=False, state="failed", upload=upload, user_confirmed=True, file_size=final_size, file_changed=file_changed, message=f"Binary-file commit failed: {exc.strerror or str(exc) or type(exc).__name__}. The original target remains intact unless file_changed is true; inspect the destination before retrying.")
    finally:
        with _LOCK:
            _UPLOADS.pop(upload_id, None)
            _close_upload(upload, unlink=bool(upload.temp_name))


def abort_binary_file_upload(upload_id: str) -> BinaryFileUploadResponse:
    if not isinstance(upload_id, str) or not _UPLOAD_ID_RE.fullmatch(upload_id):
        return BinaryFileUploadResponse(success=False, message="upload_id is invalid or expired.")
    with _LOCK:
        _expire_uploads_locked(time.monotonic())
        upload = _UPLOADS.get(upload_id)
        if upload is None:
            return BinaryFileUploadResponse(success=False, message="The upload token is invalid, expired, or already completed.")
        if upload.committing:
            return _response(success=False, state="failed", upload=upload, message="This upload is being committed and cannot be aborted now.")
        _UPLOADS.pop(upload_id, None)
        _close_upload(upload, unlink=True)
        return _response(success=True, state="aborted", upload=upload, user_confirmed=True, message="The private staging file was discarded; the destination was not changed.")


def close_all_binary_file_uploads() -> None:
    with _LOCK:
        for upload_id, upload in tuple(_UPLOADS.items()):
            if upload.committing:
                continue
            _UPLOADS.pop(upload_id, None)
            _close_upload(upload, unlink=True)
