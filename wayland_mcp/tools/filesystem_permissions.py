"""Explicitly confirmed, nonrecursive permission-mode changes."""

from __future__ import annotations

import os
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import FileModeChangeResponse
from wayland_mcp.tools.filesystem import MAX_PATH_LENGTH, _is_blocked_path, _open_resolved_path

PROTECTED_SECURITY_XATTRS = {"security.capability", "security.ima", "security.evm"}
SPECIAL_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
PATH_DIRECTORY_FLAGS = (
    getattr(os, "O_PATH", os.O_RDONLY)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
PATH_TARGET_FLAGS = (
    getattr(os, "O_PATH", os.O_RDONLY)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_MODE_CHANGE_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class FileModeChangeTarget:
    path: Path
    kind: str
    current_mode_octal: str
    new_mode_octal: str
    new_mode: int
    device: int
    inode: int
    link_count: int
    owner_uid: int
    owner_gid: int
    changed_ns: int
    parent_device: int
    parent_inode: int
    access_acl_present: bool


def _parse_mode(mode: object) -> tuple[str | None, int | None, str | None]:
    if not isinstance(mode, str) or len(mode) not in {3, 4} or any(character not in "01234567" for character in mode):
        return None, None, "Mode must be three or four octal digits, such as '644' or '0755'."
    value = int(mode, 8)
    if value > 0o7777:
        return None, None, "Mode cannot exceed 07777."
    if value & SPECIAL_MODE_BITS and len(mode) != 4:
        return None, None, "Use four octal digits when setting setuid, setgid, or sticky bits."
    return f"{value:04o}", value, None


def _validate_mode_for_kind(mode: int, kind: str) -> str | None:
    if kind == "file" and mode & stat.S_ISVTX:
        return "The sticky bit is supported only for directories."
    if kind == "directory" and mode & stat.S_ISUID:
        return "The setuid bit is not supported for directories."
    if kind == "file" and mode & (stat.S_ISUID | stat.S_ISGID) and not mode & 0o111:
        return "Setuid/setgid on regular files requires at least one execute bit in the requested mode."
    return None


def _same_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_nlink,
        left.st_uid,
        left.st_gid,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_nlink,
        right.st_uid,
        right.st_gid,
        right.st_ctime_ns,
    )


def _file_descriptor_path(descriptor: int) -> str:
    return f"/proc/self/fd/{descriptor}"


def _inspect_mode_xattrs(descriptor: int) -> tuple[bool, str | None]:
    try:
        names = set(os.listxattr(_file_descriptor_path(descriptor)))
    except (OSError, NotImplementedError, TypeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) else None
        return False, f"Extended attributes could not be checked through the pinned file descriptor: {reason or 'interface unavailable'}."
    if PROTECTED_SECURITY_XATTRS.intersection(names):
        return False, "Files with visible Linux capability, IMA, or EVM security attributes are not supported by mode changes."
    return "system.posix_acl_access" in names, None


def _prepare_mode_change(
    path: object,
    mode: object,
) -> tuple[FileModeChangeTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "File permission changes are available only on Linux."
    if not hasattr(os, "O_PATH"):
        return None, "The Linux O_PATH descriptor interface is unavailable."
    new_mode_octal, new_mode, error = _parse_mode(mode)
    if error or new_mode_octal is None or new_mode is None:
        return None, error or "The requested file mode could not be validated."
    if not isinstance(path, str) or not path.strip() or len(path) > MAX_PATH_LENGTH:
        return None, f"Path must be non-empty text with at most {MAX_PATH_LENGTH} characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return None, "Path cannot contain control characters."

    parent_fd: int | None = None
    target_fd: int | None = None
    try:
        input_path = Path(path).expanduser()
        if not input_path.is_absolute():
            return None, "Path must be absolute; '~' is expanded to the current user's home directory."
        lexical_path = Path(os.path.abspath(input_path))
        if _is_blocked_path(lexical_path):
            return None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."
        if not lexical_path.name or lexical_path.name in {".", ".."}:
            return None, "Path must name one regular file or directory."
        parent_path = lexical_path.parent.resolve(strict=True)
        if _is_blocked_path(parent_path):
            return None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."
        target_path = parent_path / lexical_path.name
        if _is_blocked_path(target_path):
            return None, "Paths under /proc, /sys, /dev, and /run are not available through general filesystem tools."

        parent_fd = _open_resolved_path(parent_path, PATH_DIRECTORY_FLAGS)
        parent_info = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_info.st_mode):
            return None, "The target parent is not a directory."
        entry_before = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(entry_before.st_mode):
            return None, "The final path component cannot be a symbolic link."
        if stat.S_ISREG(entry_before.st_mode):
            kind = "file"
            if entry_before.st_nlink != 1:
                return None, "Files with multiple hard links are not supported because other paths share their mode."
        elif stat.S_ISDIR(entry_before.st_mode):
            kind = "directory"
        else:
            return None, "Only regular files and directories support this permission-mode action."
        kind_error = _validate_mode_for_kind(new_mode, kind)
        if kind_error:
            return None, kind_error

        target_fd = os.open(target_path.name, PATH_TARGET_FLAGS, dir_fd=parent_fd)
        opened = os.fstat(target_fd)
        if not _same_snapshot(entry_before, opened):
            return None, "The target changed while its identity was being checked."
        if not (stat.S_ISREG(opened.st_mode) or stat.S_ISDIR(opened.st_mode)):
            return None, "Only regular files and directories support this permission-mode action."
        if stat.S_ISREG(opened.st_mode) and opened.st_nlink != 1:
            return None, "The regular file acquired another hard link while it was inspected."
        kind_error = _validate_mode_for_kind(new_mode, kind)
        if kind_error:
            return None, kind_error

        descriptor_path = _file_descriptor_path(target_fd)
        descriptor_info = os.stat(descriptor_path)
        if (descriptor_info.st_dev, descriptor_info.st_ino) != (opened.st_dev, opened.st_ino):
            return None, "The pinned file descriptor path could not be verified."
        access_acl_present, xattr_error = _inspect_mode_xattrs(target_fd)
        if xattr_error:
            return None, xattr_error
        entry_after = os.stat(target_path.name, dir_fd=parent_fd, follow_symlinks=False)
        opened_after = os.fstat(target_fd)
        if not _same_snapshot(opened, opened_after) or not _same_snapshot(opened_after, entry_after):
            return None, "The target changed while its metadata was inspected."
        return FileModeChangeTarget(
            path=target_path,
            kind=kind,
            current_mode_octal=f"{stat.S_IMODE(opened_after.st_mode):04o}",
            new_mode_octal=new_mode_octal,
            new_mode=new_mode,
            device=opened_after.st_dev,
            inode=opened_after.st_ino,
            link_count=opened_after.st_nlink,
            owner_uid=opened_after.st_uid,
            owner_gid=opened_after.st_gid,
            changed_ns=opened_after.st_ctime_ns,
            parent_device=parent_info.st_dev,
            parent_inode=parent_info.st_ino,
            access_acl_present=access_acl_present,
        ), None
    except (OSError, RuntimeError, ValueError) as exc:
        reason = getattr(exc, "strerror", None) or type(exc).__name__
        return None, f"The target mode could not be safely verified: {reason}."
    finally:
        if target_fd is not None:
            try:
                os.close(target_fd)
            except OSError:
                pass
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def file_mode_change_confirmation_details(
    path: str,
    mode: str,
) -> tuple[FileModeChangeTarget | None, str | None]:
    """Validate one exact path and requested standard mode before confirmation."""
    return _prepare_mode_change(path, mode)


def _same_open_target(info: os.stat_result, target: FileModeChangeTarget) -> bool:
    return (
        (info.st_dev, info.st_ino) == (target.device, target.inode)
        and info.st_nlink == target.link_count
        and info.st_uid == target.owner_uid
        and info.st_gid == target.owner_gid
        and f"{stat.S_IMODE(info.st_mode):04o}" == target.current_mode_octal
        and info.st_ctime_ns == target.changed_ns
    )


def set_file_mode(
    path: str,
    mode: str,
    *,
    confirmed: bool,
    confirmed_path: str | None = None,
    confirmed_current_mode_octal: str | None = None,
    confirmed_new_mode_octal: str | None = None,
) -> FileModeChangeResponse:
    target, error = _prepare_mode_change(path, mode)
    if error or target is None:
        return FileModeChangeResponse(
            success=False,
            path=path if isinstance(path, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The exact file-mode change could not be verified.",
        )
    if confirmed is not True:
        return FileModeChangeResponse(
            success=False,
            path=str(target.path),
            previous_mode_octal=target.current_mode_octal,
            mode_octal=target.new_mode_octal,
            kind=target.kind,
            access_acl_present=target.access_acl_present,
            user_confirmed=False,
            message="Explicit client confirmation is required; no permission mode was changed.",
        )
    if (
        confirmed_path != str(target.path)
        or confirmed_current_mode_octal != target.current_mode_octal
        or confirmed_new_mode_octal != target.new_mode_octal
    ):
        return FileModeChangeResponse(
            success=False,
            path=str(target.path),
            previous_mode_octal=target.current_mode_octal,
            mode_octal=target.new_mode_octal,
            kind=target.kind,
            access_acl_present=target.access_acl_present,
            user_confirmed=True,
            message="The confirmation did not repeat the canonical path and exact old/new modes; no permission mode was changed.",
        )

    with _MODE_CHANGE_LOCK:
        current, error = _prepare_mode_change(path, mode)
        if error or current is None:
            return FileModeChangeResponse(
                success=False,
                path=str(target.path),
                previous_mode_octal=target.current_mode_octal,
                mode_octal=target.new_mode_octal,
                kind=target.kind,
                access_acl_present=target.access_acl_present,
                user_confirmed=True,
                message=error or "The current target could not be revalidated; no mode was changed.",
            )
        if current != target:
            return FileModeChangeResponse(
                success=False,
                path=str(target.path),
                previous_mode_octal=target.current_mode_octal,
                mode_octal=target.new_mode_octal,
                kind=target.kind,
                access_acl_present=target.access_acl_present,
                user_confirmed=True,
                message="The path, current mode, or target identity changed after confirmation; no mode was changed.",
            )

        parent_fd: int | None = None
        target_fd: int | None = None
        mode_changed = False
        try:
            parent_fd = _open_resolved_path(target.path.parent, PATH_DIRECTORY_FLAGS)
            parent_info = os.fstat(parent_fd)
            if (parent_info.st_dev, parent_info.st_ino) != (target.parent_device, target.parent_inode):
                raise OSError("The parent directory identity changed after confirmation.")
            target_fd = os.open(target.path.name, PATH_TARGET_FLAGS, dir_fd=parent_fd)
            opened = os.fstat(target_fd)
            if not _same_open_target(opened, target):
                raise OSError("The exact file or directory identity changed after confirmation.")
            descriptor_path = _file_descriptor_path(target_fd)
            descriptor_info = os.stat(descriptor_path)
            if (descriptor_info.st_dev, descriptor_info.st_ino) != (target.device, target.inode):
                raise OSError("The pinned file descriptor path no longer identifies the confirmed target.")
            access_acl_present, xattr_error = _inspect_mode_xattrs(target_fd)
            if xattr_error:
                raise OSError(xattr_error)
            if access_acl_present != target.access_acl_present:
                raise OSError("The visible access ACL state changed after confirmation.")
            path_entry = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
            if not _same_snapshot(opened, path_entry):
                raise OSError("The exact path no longer names the confirmed target.")

            if target.new_mode != stat.S_IMODE(opened.st_mode):
                try:
                    os.chmod(descriptor_path, target.new_mode)
                    mode_changed = True
                except OSError:
                    mode_changed = stat.S_IMODE(os.fstat(target_fd).st_mode) != int(target.current_mode_octal, 8)
                    raise
            info_after = os.fstat(target_fd)
            path_after = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
            visible_parent = target.path.parent.stat()
            _acl_after, xattr_error = _inspect_mode_xattrs(target_fd)
            if xattr_error:
                raise OSError(xattr_error)
            if (
                stat.S_IMODE(info_after.st_mode) != target.new_mode
                or (info_after.st_dev, info_after.st_ino) != (target.device, target.inode)
                or not _same_snapshot(info_after, path_after)
                or (visible_parent.st_dev, visible_parent.st_ino) != (target.parent_device, target.parent_inode)
            ):
                mode_changed = stat.S_IMODE(info_after.st_mode) != int(target.current_mode_octal, 8)
                raise OSError("The requested mode or exact path identity did not verify after chmod.")
        except (BlockingIOError, OSError) as exc:
            reason = exc.strerror or str(exc) or "filesystem operation failed"
            restored = False
            if mode_changed and target_fd is not None and parent_fd is not None:
                try:
                    os.chmod(_file_descriptor_path(target_fd), int(target.current_mode_octal, 8))
                    restored_info = os.fstat(target_fd)
                    restored_path = os.stat(target.path.name, dir_fd=parent_fd, follow_symlinks=False)
                    restored = (
                        (restored_info.st_dev, restored_info.st_ino) == (target.device, target.inode)
                        and stat.S_IMODE(restored_info.st_mode) == int(target.current_mode_octal, 8)
                        and _same_snapshot(restored_info, restored_path)
                    )
                except OSError:
                    pass
            return FileModeChangeResponse(
                success=False,
                path=str(target.path),
                previous_mode_octal=target.current_mode_octal,
                mode_octal=target.new_mode_octal,
                kind=target.kind,
                access_acl_present=target.access_acl_present,
                restored_on_failure=restored if mode_changed else None,
                user_confirmed=True,
                message=(
                    f"The mode change could not be verified: {reason}. "
                    + ("The previous mode was restored and verified at the confirmed path." if restored else "The previous mode could not be verified after rollback; inspect the target before retrying." if mode_changed else "No mode change was completed by this action.")
                ),
            )
        finally:
            if target_fd is not None:
                try:
                    os.close(target_fd)
                except OSError:
                    pass
            if parent_fd is not None:
                try:
                    os.close(parent_fd)
                except OSError:
                    pass

    return FileModeChangeResponse(
        success=True,
        path=str(target.path),
        previous_mode_octal=target.current_mode_octal,
        mode_octal=target.new_mode_octal,
        kind=target.kind,
        access_acl_present=target.access_acl_present,
        restored_on_failure=None,
        user_confirmed=True,
        message=(
            "The exact target already had the requested permission mode."
            if target.current_mode_octal == target.new_mode_octal
            else "Changed and verified the exact target's requested rwx and special permission bits."
        ),
    )
