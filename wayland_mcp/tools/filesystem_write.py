"""Explicitly confirmed creation, replacement, and deletion of bounded UTF-8 text files."""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import (
    TextFileCreationResponse,
    TextFileDeletionResponse,
    TextFileReplacementResponse,
)
from wayland_mcp.tools.filesystem import (
    MAX_PATH_LENGTH,
    _is_blocked_path,
    _open_resolved_path,
    _resolve_path,
)

MAX_TEXT_FILE_BYTES = 64 * 1024
PROTECTED_SECURITY_XATTRS = {"security.capability", "security.ima", "security.evm"}
DIRECTORY_FLAGS = (
    getattr(os, "O_PATH", os.O_RDONLY)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_WRITE_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class TextFileCreationTarget:
    path: Path
    content_sha256: str
    byte_count: int
    parent_device: int
    parent_inode: int


@dataclass(frozen=True, slots=True)
class TextFileReplacementTarget:
    path: Path
    current_sha256: str
    replacement_sha256: str
    replacement: bytes
    original: bytes
    mode_octal: str
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    modified_ns: int
    changed_ns: int
    parent_device: int
    parent_inode: int


@dataclass(frozen=True, slots=True)
class TextFileDeletionTarget:
    path: Path
    current_sha256: str
    original: bytes
    mode_octal: str
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    modified_ns: int
    changed_ns: int
    parent_device: int
    parent_inode: int


def _encode_text_content(content: object) -> tuple[bytes | None, str | None]:
    if not isinstance(content, str):
        return None, "content must be UTF-8 text."
    if len(content) > MAX_TEXT_FILE_BYTES:
        return None, f"content cannot exceed {MAX_TEXT_FILE_BYTES} UTF-8 bytes."
    if any(character not in "\n\r\t" and not character.isprintable() for character in content):
        return None, "content must contain printable text, tabs, or line breaks."
    try:
        encoded = content.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None, "content must be valid UTF-8 text."
    if len(encoded) > MAX_TEXT_FILE_BYTES:
        return None, f"content cannot exceed {MAX_TEXT_FILE_BYTES} UTF-8 bytes."
    return encoded, None


def _prepare_creation(
    path: object,
    content: object,
) -> tuple[TextFileCreationTarget | None, bytes | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Text-file creation is available only on Linux."
    if not isinstance(path, str) or not path.strip() or len(path) > MAX_PATH_LENGTH:
        return None, None, f"Path must be non-empty text with at most {MAX_PATH_LENGTH} characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return None, None, "Path cannot contain control characters."
    encoded, error = _encode_text_content(content)
    if error or encoded is None:
        return None, None, error

    try:
        input_path = Path(path).expanduser()
        if not input_path.is_absolute():
            return None, None, "Path must be absolute; '~' is expanded to the current user's home directory."
        lexical_path = Path(os.path.abspath(input_path))
        if _is_blocked_path(lexical_path):
            return None, None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."
        name = lexical_path.name
        if not name or name in {".", ".."}:
            return None, None, "Path must name a new file inside an existing directory."
        parent = lexical_path.parent.resolve(strict=True)
        if _is_blocked_path(parent):
            return None, None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."
        target_path = parent / name
        if _is_blocked_path(target_path):
            return None, None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."
        directory_fd = _open_resolved_path(parent, DIRECTORY_FLAGS)
        try:
            parent_info = os.fstat(directory_fd)
            if not stat.S_ISDIR(parent_info.st_mode):
                return None, None, "The parent path is not a directory."
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as exc:
                return None, None, f"Could not verify that the target is new: {exc.strerror or 'metadata unavailable'}."
            else:
                return None, None, "The target already exists; this action never overwrites files."
        finally:
            os.close(directory_fd)
    except (OSError, RuntimeError, ValueError) as exc:
        return None, None, f"The destination directory could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."

    target = TextFileCreationTarget(
        path=target_path,
        content_sha256=hashlib.sha256(encoded).hexdigest(),
        byte_count=len(encoded),
        parent_device=parent_info.st_dev,
        parent_inode=parent_info.st_ino,
    )
    return target, encoded, None


def text_file_creation_confirmation_details(
    path: str,
    content: str,
) -> tuple[TextFileCreationTarget | None, str | None]:
    """Validate a create-only destination and bind confirmation to exact content."""
    target, _encoded, error = _prepare_creation(path, content)
    return target, error


def create_text_file(
    path: str,
    content: str,
    *,
    confirmed: bool,
    confirmed_path: str | None = None,
    confirmed_content_sha256: str | None = None,
) -> TextFileCreationResponse:
    target, encoded, error = _prepare_creation(path, content)
    if error or target is None or encoded is None:
        return TextFileCreationResponse(
            success=False,
            path=path if isinstance(path, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The file creation request could not be verified.",
        )
    if confirmed is not True:
        return TextFileCreationResponse(
            success=False,
            path=str(target.path),
            sha256=target.content_sha256,
            user_confirmed=False,
            message="Explicit client confirmation is required; no file was created.",
        )
    if confirmed_path != str(target.path) or confirmed_content_sha256 != target.content_sha256:
        return TextFileCreationResponse(
            success=False,
            path=str(target.path),
            sha256=target.content_sha256,
            user_confirmed=True,
            message="The confirmation did not repeat the exact canonical path and content digest; no file was created.",
        )

    with _FILE_WRITE_LOCK:
        current_target, current_encoded, error = _prepare_creation(path, content)
        if error or current_target is None or current_encoded is None:
            return TextFileCreationResponse(
                success=False,
                path=str(target.path),
                sha256=target.content_sha256,
                user_confirmed=True,
                message=error or "The destination could not be revalidated; no file was created.",
            )
        if current_target != target or current_encoded != encoded:
            return TextFileCreationResponse(
                success=False,
                path=str(target.path),
                sha256=target.content_sha256,
                user_confirmed=True,
                message="The destination directory or requested content changed after confirmation; no file was created.",
            )

        directory_fd: int | None = None
        file_fd: int | None = None
        bytes_written = 0
        created = False
        mode_octal: str | None = None
        try:
            directory_fd = _open_resolved_path(target.path.parent, DIRECTORY_FLAGS)
            parent_info = os.fstat(directory_fd)
            if (parent_info.st_dev, parent_info.st_ino) != (target.parent_device, target.parent_inode):
                raise OSError("Destination directory identity changed after confirmation.")
            file_flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            file_fd = os.open(target.path.name, file_flags, 0o600, dir_fd=directory_fd)
            created = True
            os.fchmod(file_fd, 0o600)
            remaining = memoryview(encoded)
            while remaining:
                written = os.write(file_fd, remaining)
                if written <= 0:
                    raise OSError("The filesystem accepted no bytes while writing the new file.")
                bytes_written += written
                remaining = remaining[written:]
            os.fsync(file_fd)
            os.lseek(file_fd, 0, os.SEEK_SET)
            readback = bytearray()
            while len(readback) <= len(encoded):
                chunk = os.read(file_fd, max(1, len(encoded) + 1 - len(readback)))
                if not chunk:
                    break
                readback.extend(chunk)
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("The created target is no longer a regular file.")
            mode_octal = f"{stat.S_IMODE(info.st_mode):04o}"
            if bytes(readback) != encoded or info.st_size != len(encoded):
                return TextFileCreationResponse(
                    success=False,
                    path=str(target.path),
                    bytes_written=bytes_written,
                    sha256=target.content_sha256,
                    mode_octal=mode_octal,
                    created=True,
                    user_confirmed=True,
                    message="The new file was created but its read-back did not match; inspect it before retrying.",
                )
            closing_fd = file_fd
            file_fd = None
            os.close(closing_fd)
            directory_entry = os.stat(target.path.name, dir_fd=directory_fd, follow_symlinks=False)
            if (directory_entry.st_dev, directory_entry.st_ino) != (info.st_dev, info.st_ino):
                raise OSError("The new path was replaced while the file was being verified.")
            visible_parent = target.path.parent.stat()
            if (visible_parent.st_dev, visible_parent.st_ino) != (target.parent_device, target.parent_inode):
                raise OSError("The destination directory path changed while the file was being created.")
        except OSError as exc:
            reason = exc.strerror or str(exc) or "filesystem operation failed"
            suffix = " A partial file may exist; inspect it before retrying." if created else " No file was created."
            return TextFileCreationResponse(
                success=False,
                path=str(target.path),
                bytes_written=bytes_written,
                sha256=target.content_sha256,
                mode_octal=mode_octal,
                created=created,
                user_confirmed=True,
                message=f"Could not complete file creation: {reason}.{suffix}",
            )
        finally:
            if file_fd is not None:
                try:
                    os.close(file_fd)
                except OSError:
                    pass
            if directory_fd is not None:
                try:
                    os.close(directory_fd)
                except OSError:
                    pass

    return TextFileCreationResponse(
        success=True,
        path=str(target.path),
        bytes_written=bytes_written,
        sha256=target.content_sha256,
        mode_octal=mode_octal,
        created=True,
        user_confirmed=True,
        message="Created the exact UTF-8 text file and verified its contents.",
    )


def _read_fd_limited(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    result = bytearray()
    while len(result) <= MAX_TEXT_FILE_BYTES:
        chunk = os.read(descriptor, MAX_TEXT_FILE_BYTES + 1 - len(result))
        if not chunk:
            break
        result.extend(chunk)
    return bytes(result)


def _same_file_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_nlink,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_nlink,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _protected_xattr_error(descriptor: int, *, operation: str = "text replacement") -> str | None:
    try:
        attribute_names = set(os.listxattr(descriptor))
    except (OSError, NotImplementedError, TypeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) else None
        return f"Security-related extended attributes could not be checked: {reason or 'interface unavailable'}."
    if PROTECTED_SECURITY_XATTRS.intersection(attribute_names):
        return f"Files with visible Linux capability, IMA, or EVM security attributes are not supported by {operation}."
    return None


def _prepare_replacement(
    path: object,
    content: object,
) -> tuple[TextFileReplacementTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Text-file replacement is available only on Linux."
    encoded, error = _encode_text_content(content)
    if error or encoded is None:
        return None, error or "Replacement content could not be encoded."
    if not isinstance(path, str) or any(ord(character) < 32 or ord(character) == 127 for character in path):
        return None, "Path must be text without control characters."
    target_path, error = _resolve_path(path)
    if error or target_path is None:
        return None, error or "The exact file path could not be resolved."

    parent_fd: int | None = None
    file_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(target_path.parent, DIRECTORY_FLAGS)
        parent_info = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_info.st_mode):
            return None, "The target parent is not a directory."
        entry_before = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(entry_before.st_mode):
            return None, "Only regular text files can be replaced."
        if entry_before.st_nlink != 1:
            return None, "Files with multiple hard links are not replaced because other paths share their contents."
        if entry_before.st_mode & (stat.S_ISUID | stat.S_ISGID):
            return None, "Setuid or setgid files are not supported by text replacement."
        if entry_before.st_size > MAX_TEXT_FILE_BYTES:
            return None, f"The current file exceeds the {MAX_TEXT_FILE_BYTES}-byte replacement limit."
        file_flags = (
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        file_fd = os.open(target_path.name, file_flags, dir_fd=parent_fd)
        opened_before = os.fstat(file_fd)
        if not stat.S_ISREG(opened_before.st_mode) or not _same_file_snapshot(entry_before, opened_before):
            return None, "The file changed while its identity was being checked."
        if opened_before.st_nlink != 1 or opened_before.st_mode & (stat.S_ISUID | stat.S_ISGID):
            return None, "The file's link count or special permission bits changed while it was inspected."
        attr_error = _protected_xattr_error(file_fd)
        if attr_error:
            return None, attr_error
        original = _read_fd_limited(file_fd)
        opened_after = os.fstat(file_fd)
        if len(original) > MAX_TEXT_FILE_BYTES or len(original) != opened_before.st_size:
            return None, "The file changed or exceeded the content limit while it was read."
        if not _same_file_snapshot(opened_before, opened_after):
            return None, "The file changed while its current content was read."
        if b"\x00" in original:
            return None, "Binary files are not supported by text replacement."
        try:
            old_text = original.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None, "Only valid UTF-8 text files can be replaced."
        if any(character not in "\n\r\t" and not character.isprintable() for character in old_text):
            return None, "The current file contains non-text control characters."
        entry_after = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_file_snapshot(opened_after, entry_after):
            return None, "The file path changed while its current content was read."
        return TextFileReplacementTarget(
            path=target_path,
            current_sha256=hashlib.sha256(original).hexdigest(),
            replacement_sha256=hashlib.sha256(encoded).hexdigest(),
            replacement=encoded,
            original=original,
            mode_octal=f"{stat.S_IMODE(opened_after.st_mode):04o}",
            device=opened_after.st_dev,
            inode=opened_after.st_ino,
            owner_uid=opened_after.st_uid,
            owner_gid=opened_after.st_gid,
            modified_ns=opened_after.st_mtime_ns,
            changed_ns=opened_after.st_ctime_ns,
            parent_device=parent_info.st_dev,
            parent_inode=parent_info.st_ino,
        ), None
    except OSError as exc:
        return None, f"The existing file could not be safely opened: {exc.strerror or 'filesystem error'}."
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def text_file_replacement_confirmation_details(
    path: str,
    content: str,
) -> tuple[TextFileReplacementTarget | None, str | None]:
    """Read and validate the exact current file before eliciting replacement approval."""
    return _prepare_replacement(path, content)


def _write_fd_all(descriptor: int, data: bytes) -> int:
    total_written = 0
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("The filesystem accepted no bytes while writing the file.")
        total_written += written
        remaining = remaining[written:]
    return total_written


def _replace_fd_contents(descriptor: int, data: bytes) -> int:
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    written = _write_fd_all(descriptor, data)
    os.fsync(descriptor)
    if _read_fd_limited(descriptor) != data:
        raise OSError("The file content did not match after writing.")
    return written


def replace_text_file(
    path: str,
    content: str,
    *,
    confirmed: bool,
    confirmed_path: str | None = None,
    confirmed_current_sha256: str | None = None,
    confirmed_replacement_sha256: str | None = None,
) -> TextFileReplacementResponse:
    target, error = _prepare_replacement(path, content)
    if error or target is None:
        return TextFileReplacementResponse(
            success=False,
            path=path if isinstance(path, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The exact text-file replacement could not be verified.",
        )
    if confirmed is not True:
        return TextFileReplacementResponse(
            success=False,
            path=str(target.path),
            previous_sha256=target.current_sha256,
            sha256=target.replacement_sha256,
            mode_octal=target.mode_octal,
            user_confirmed=False,
            message="Explicit client confirmation is required; no file content was changed.",
        )
    if (
        confirmed_path != str(target.path)
        or confirmed_current_sha256 != target.current_sha256
        or confirmed_replacement_sha256 != target.replacement_sha256
    ):
        return TextFileReplacementResponse(
            success=False,
            path=str(target.path),
            previous_sha256=target.current_sha256,
            sha256=target.replacement_sha256,
            mode_octal=target.mode_octal,
            user_confirmed=True,
            message="The confirmation did not repeat the exact canonical path and both content digests; no file content was changed.",
        )

    with _FILE_WRITE_LOCK:
        current, error = _prepare_replacement(path, content)
        if error or current is None:
            return TextFileReplacementResponse(
                success=False,
                path=str(target.path),
                previous_sha256=target.current_sha256,
                sha256=target.replacement_sha256,
                user_confirmed=True,
                message=error or "The current file could not be revalidated; no content was changed.",
            )
        if current != target:
            return TextFileReplacementResponse(
                success=False,
                path=str(target.path),
                previous_sha256=target.current_sha256,
                sha256=target.replacement_sha256,
                user_confirmed=True,
                message="The current file or replacement content changed after confirmation; no content was changed.",
            )

        parent_fd: int | None = None
        file_fd: int | None = None
        bytes_written = 0
        try:
            parent_fd = _open_resolved_path(target.path.parent, DIRECTORY_FLAGS)
            parent_info = os.fstat(parent_fd)
            if (parent_info.st_dev, parent_info.st_ino) != (target.parent_device, target.parent_inode):
                raise OSError("The parent directory identity changed after confirmation.")
            file_flags = (
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            file_fd = os.open(target.path.name, file_flags, dir_fd=parent_fd)
            opened = os.fstat(file_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_mode & (stat.S_ISUID | stat.S_ISGID)
                or (opened.st_dev, opened.st_ino) != (target.device, target.inode)
                or opened.st_uid != target.owner_uid
                or opened.st_gid != target.owner_gid
                or f"{stat.S_IMODE(opened.st_mode):04o}" != target.mode_octal
                or opened.st_mtime_ns != target.modified_ns
                or opened.st_ctime_ns != target.changed_ns
            ):
                raise OSError("The exact regular-file identity changed after confirmation.")
            fcntl.flock(file_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            attr_error = _protected_xattr_error(file_fd)
            if attr_error:
                raise OSError(attr_error)
            current_bytes = _read_fd_limited(file_fd)
            current_info = os.fstat(file_fd)
            if (
                current_bytes != target.original
                or hashlib.sha256(current_bytes).hexdigest() != target.current_sha256
                or len(current_bytes) != current_info.st_size
                or current_info.st_size > MAX_TEXT_FILE_BYTES
                or current_info.st_nlink != 1
                or current_info.st_uid != target.owner_uid
                or current_info.st_gid != target.owner_gid
                or f"{stat.S_IMODE(current_info.st_mode):04o}" != target.mode_octal
                or current_info.st_mtime_ns != target.modified_ns
                or current_info.st_ctime_ns != target.changed_ns
            ):
                raise OSError("The file content changed after confirmation.")
            path_entry = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (path_entry.st_dev, path_entry.st_ino) != (current_info.st_dev, current_info.st_ino):
                raise OSError("The exact path no longer names the confirmed file.")

            try:
                bytes_written = _replace_fd_contents(file_fd, target.replacement)
                info_after = os.fstat(file_fd)
                path_after = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
                if (
                    (path_after.st_dev, path_after.st_ino) != (info_after.st_dev, info_after.st_ino)
                    or (info_after.st_dev, info_after.st_ino) != (target.device, target.inode)
                    or info_after.st_uid != target.owner_uid
                    or info_after.st_gid != target.owner_gid
                    or info_after.st_nlink != 1
                    or f"{stat.S_IMODE(info_after.st_mode):04o}" != target.mode_octal
                ):
                    raise OSError("The path changed while the replacement was being verified.")
            except OSError as exc:
                try:
                    bytes_written = max(bytes_written, min(MAX_TEXT_FILE_BYTES, os.fstat(file_fd).st_size))
                except OSError:
                    pass
                restored = False
                try:
                    _replace_fd_contents(file_fd, target.original)
                    restored_info = os.fstat(file_fd)
                    restored_path = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
                    restored = (
                        restored_info.st_dev == target.device
                        and restored_info.st_ino == target.inode
                        and restored_path.st_dev == target.device
                        and restored_path.st_ino == target.inode
                    )
                except OSError:
                    pass
                reason = exc.strerror or str(exc) or "filesystem write failed"
                return TextFileReplacementResponse(
                    success=False,
                    path=str(target.path),
                    previous_sha256=target.current_sha256,
                    sha256=target.replacement_sha256,
                    bytes_written=bytes_written,
                    mode_octal=target.mode_octal,
                    restored_on_failure=restored,
                    user_confirmed=True,
                    message=(
                        f"Could not verify the replacement: {reason}. "
                        + ("The original content was restored and the path still names the confirmed file." if restored else "The original content could not be verified at the confirmed path after rollback; inspect the file before retrying.")
                    ),
                )
        except (BlockingIOError, OSError) as exc:
            reason = exc.strerror or str(exc) or "filesystem operation failed"
            return TextFileReplacementResponse(
                success=False,
                path=str(target.path),
                previous_sha256=target.current_sha256,
                sha256=target.replacement_sha256,
                mode_octal=target.mode_octal,
                user_confirmed=True,
                message=f"The confirmed file could not be replaced: {reason}. No content change was made.",
            )
        finally:
            if file_fd is not None:
                try:
                    os.close(file_fd)
                except OSError:
                    pass
            if parent_fd is not None:
                try:
                    os.close(parent_fd)
                except OSError:
                    pass

    return TextFileReplacementResponse(
        success=True,
        path=str(target.path),
        previous_sha256=target.current_sha256,
        sha256=target.replacement_sha256,
        bytes_written=bytes_written,
        mode_octal=target.mode_octal,
        restored_on_failure=None,
        user_confirmed=True,
        message="Replaced and verified the exact UTF-8 text-file contents; existing file metadata was preserved.",
    )


def _prepare_deletion(
    path: object,
) -> tuple[TextFileDeletionTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Text-file deletion is available only on Linux."
    if not isinstance(path, str) or not path.strip() or len(path) > MAX_PATH_LENGTH:
        return None, f"Path must be non-empty text with at most {MAX_PATH_LENGTH} characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return None, "Path cannot contain control characters."

    parent_fd: int | None = None
    file_fd: int | None = None
    try:
        input_path = Path(path).expanduser()
        if not input_path.is_absolute():
            return None, "Path must be absolute; '~' is expanded to the current user's home directory."
        lexical_path = Path(os.path.abspath(input_path))
        if _is_blocked_path(lexical_path):
            return None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."
        if not lexical_path.name or lexical_path.name in {".", ".."}:
            return None, "Path must name one regular text file."
        parent_path = lexical_path.parent.resolve(strict=True)
        if _is_blocked_path(parent_path):
            return None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."
        target_path = parent_path / lexical_path.name
        if _is_blocked_path(target_path):
            return None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."

        parent_fd = _open_resolved_path(parent_path, DIRECTORY_FLAGS)
        parent_info = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_info.st_mode):
            return None, "The target parent is not a directory."
        entry_before = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(entry_before.st_mode):
            return None, "The final path component cannot be a symbolic link."
        if not stat.S_ISREG(entry_before.st_mode):
            return None, "Only regular UTF-8 text files can be deleted."
        if entry_before.st_nlink != 1:
            return None, "Files with multiple hard links are not deleted because other paths share their contents."
        if entry_before.st_mode & (stat.S_ISUID | stat.S_ISGID):
            return None, "Setuid or setgid files are not supported by text-file deletion."
        if entry_before.st_size > MAX_TEXT_FILE_BYTES:
            return None, f"The file exceeds the {MAX_TEXT_FILE_BYTES}-byte deletion limit."
        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        file_fd = os.open(target_path.name, file_flags, dir_fd=parent_fd)
        opened_before = os.fstat(file_fd)
        if not stat.S_ISREG(opened_before.st_mode) or not _same_file_snapshot(entry_before, opened_before):
            return None, "The file changed while its identity was being checked."
        if opened_before.st_nlink != 1 or opened_before.st_mode & (stat.S_ISUID | stat.S_ISGID):
            return None, "The file's link count or special permission bits changed while it was inspected."
        attr_error = _protected_xattr_error(file_fd, operation="text-file deletion")
        if attr_error:
            return None, attr_error
        original = _read_fd_limited(file_fd)
        opened_after = os.fstat(file_fd)
        if len(original) > MAX_TEXT_FILE_BYTES or len(original) != opened_before.st_size:
            return None, "The file changed or exceeded the content limit while it was read."
        if not _same_file_snapshot(opened_before, opened_after):
            return None, "The file changed while its current content was read."
        if b"\x00" in original:
            return None, "Binary files are not supported by text-file deletion."
        try:
            current_text = original.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None, "Only valid UTF-8 text files can be deleted through this tool."
        if any(character not in "\n\r\t" and not character.isprintable() for character in current_text):
            return None, "The current file contains non-text control characters."
        entry_after = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_file_snapshot(opened_after, entry_after):
            return None, "The file path changed while its current content was read."
        return TextFileDeletionTarget(
            path=target_path,
            current_sha256=hashlib.sha256(original).hexdigest(),
            original=original,
            mode_octal=f"{stat.S_IMODE(opened_after.st_mode):04o}",
            device=opened_after.st_dev,
            inode=opened_after.st_ino,
            owner_uid=opened_after.st_uid,
            owner_gid=opened_after.st_gid,
            modified_ns=opened_after.st_mtime_ns,
            changed_ns=opened_after.st_ctime_ns,
            parent_device=parent_info.st_dev,
            parent_inode=parent_info.st_ino,
        ), None
    except (OSError, RuntimeError, ValueError) as exc:
        reason = getattr(exc, "strerror", None) or type(exc).__name__
        return None, f"The text file could not be safely verified: {reason}."
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def text_file_deletion_confirmation_details(
    path: str,
) -> tuple[TextFileDeletionTarget | None, str | None]:
    """Read and validate the exact current file before eliciting deletion approval."""
    return _prepare_deletion(path)


def delete_text_file(
    path: str,
    *,
    confirmed: bool,
    confirmed_path: str | None = None,
    confirmed_current_sha256: str | None = None,
) -> TextFileDeletionResponse:
    target, error = _prepare_deletion(path)
    if error or target is None:
        return TextFileDeletionResponse(
            success=False,
            path=path if isinstance(path, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The exact text-file deletion could not be verified; deletion was not attempted.",
        )
    if confirmed is not True:
        return TextFileDeletionResponse(
            success=False,
            path=str(target.path),
            sha256=target.current_sha256,
            user_confirmed=False,
            message="Explicit client confirmation is required; no file was deleted.",
        )
    if confirmed_path != str(target.path) or confirmed_current_sha256 != target.current_sha256:
        return TextFileDeletionResponse(
            success=False,
            path=str(target.path),
            sha256=target.current_sha256,
            user_confirmed=True,
            message="The confirmation did not repeat the exact canonical path and current content digest; no file was deleted.",
        )

    with _FILE_WRITE_LOCK:
        current, error = _prepare_deletion(path)
        if error or current is None:
            return TextFileDeletionResponse(
                success=False,
                path=str(target.path),
                sha256=target.current_sha256,
                user_confirmed=True,
                message=error or "The current file could not be revalidated; deletion was not attempted.",
            )
        if current != target:
            return TextFileDeletionResponse(
                success=False,
                path=str(target.path),
                sha256=target.current_sha256,
                user_confirmed=True,
                message="The file or its content changed after confirmation; no file was deleted.",
            )

        parent_fd: int | None = None
        file_fd: int | None = None
        deleted = False
        try:
            parent_fd = _open_resolved_path(target.path.parent, DIRECTORY_FLAGS)
            parent_info = os.fstat(parent_fd)
            if (parent_info.st_dev, parent_info.st_ino) != (target.parent_device, target.parent_inode):
                raise OSError("The parent directory identity changed after confirmation.")
            file_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            file_fd = os.open(target.path.name, file_flags, dir_fd=parent_fd)
            opened = os.fstat(file_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_mode & (stat.S_ISUID | stat.S_ISGID)
                or (opened.st_dev, opened.st_ino) != (target.device, target.inode)
                or opened.st_uid != target.owner_uid
                or opened.st_gid != target.owner_gid
                or f"{stat.S_IMODE(opened.st_mode):04o}" != target.mode_octal
                or opened.st_mtime_ns != target.modified_ns
                or opened.st_ctime_ns != target.changed_ns
            ):
                raise OSError("The exact regular-file identity changed after confirmation.")
            fcntl.flock(file_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            attr_error = _protected_xattr_error(file_fd, operation="text-file deletion")
            if attr_error:
                raise OSError(attr_error)
            current_bytes = _read_fd_limited(file_fd)
            current_info = os.fstat(file_fd)
            if (
                current_bytes != target.original
                or hashlib.sha256(current_bytes).hexdigest() != target.current_sha256
                or len(current_bytes) != current_info.st_size
                or current_info.st_size > MAX_TEXT_FILE_BYTES
                or current_info.st_uid != target.owner_uid
                or current_info.st_gid != target.owner_gid
                or f"{stat.S_IMODE(current_info.st_mode):04o}" != target.mode_octal
                or current_info.st_mtime_ns != target.modified_ns
                or current_info.st_ctime_ns != target.changed_ns
            ):
                raise OSError("The file content changed after confirmation.")
            path_entry = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(path_entry.st_mode)
                or not _same_file_snapshot(current_info, path_entry)
            ):
                raise OSError("The exact path no longer names the confirmed regular file.")
            attr_error = _protected_xattr_error(file_fd, operation="text-file deletion")
            if attr_error:
                raise OSError(attr_error)

            os.unlink(target.path.name, dir_fd=parent_fd)
            deleted = True
            try:
                os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                visible_parent = target.path.parent.stat()
                if (visible_parent.st_dev, visible_parent.st_ino) == (target.parent_device, target.parent_inode):
                    return TextFileDeletionResponse(
                        success=True,
                        path=str(target.path),
                        sha256=target.current_sha256,
                        file_size_bytes=len(target.original),
                        deleted=True,
                        user_confirmed=True,
                        message="Deleted the exact confirmed UTF-8 text file and verified that its path is absent.",
                    )
                return TextFileDeletionResponse(
                    success=False,
                    path=str(target.path),
                    sha256=target.current_sha256,
                    file_size_bytes=len(target.original),
                    deleted=True,
                    user_confirmed=True,
                    message="Deleted the confirmed file, but the visible parent path changed before verification.",
                )
            return TextFileDeletionResponse(
                success=False,
                path=str(target.path),
                sha256=target.current_sha256,
                file_size_bytes=len(target.original),
                deleted=True,
                user_confirmed=True,
                message="Deleted the confirmed file, but another filesystem entry appeared at its path during verification.",
            )
        except (BlockingIOError, OSError) as exc:
            reason = exc.strerror or str(exc) or "filesystem operation failed"
            return TextFileDeletionResponse(
                success=False,
                path=str(target.path),
                sha256=target.current_sha256,
                file_size_bytes=len(target.original) if deleted else 0,
                deleted=deleted,
                user_confirmed=True,
                message=(
                    f"The confirmed file was deleted, but verification failed: {reason}."
                    if deleted
                    else f"The confirmed file could not be deleted: {reason}. No deletion was completed by this action."
                ),
            )
        finally:
            if file_fd is not None:
                try:
                    os.close(file_fd)
                except OSError:
                    pass
            if parent_fd is not None:
                try:
                    os.close(parent_fd)
                except OSError:
                    pass
