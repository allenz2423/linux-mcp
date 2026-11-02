"""Confirmed ownership and symbolic-link operations for exact filesystem paths."""

from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import json
import os
import shutil
import stat
import struct
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import ACLWriteEntry, PathAdminResponse
from wayland_mcp.tools.filesystem import MAX_PATH_LENGTH, _is_blocked_path, _open_resolved_path

_PARENT_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_ENTRY_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
_ACL_XATTRS = {"access": "system.posix_acl_access", "default": "system.posix_acl_default"}
_ACL_TAGS = {"user_obj": 0x01, "user": 0x02, "group_obj": 0x04, "group": 0x08, "mask": 0x10, "other": 0x20}
_ACL_ORDER = {"user_obj": 0, "user": 1, "group_obj": 2, "group": 3, "mask": 4, "other": 5}
_ACL_UNDEFINED_ID = 0xFFFFFFFF
_MAX_XATTR_BYTES = 64 * 1024
_AT_SYMLINK_NOFOLLOW = 0x100
_AT_EMPTY_PATH = 0x1000
MAX_RECURSIVE_OWNER_ENTRIES = 20_000
MAX_RECURSIVE_OWNER_DEPTH = 256
_OWNER_CHANGE_LOCK = threading.RLock()


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


def _path_parts(path: object) -> tuple[Path | None, Path | None, str | None]:
    if not isinstance(path, str) or not path.strip() or len(path) > MAX_PATH_LENGTH:
        return None, None, f"Path must be non-empty text with at most {MAX_PATH_LENGTH} characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return None, None, "Path cannot contain control characters."
    try:
        raw = Path(path).expanduser()
        if not raw.is_absolute():
            return None, None, "Path must be absolute; '~' is expanded to the current user's home directory."
        lexical = Path(os.path.abspath(raw))
        if not lexical.name or lexical.name in {".", ".."} or _is_blocked_path(lexical):
            return None, None, "The path must name one entry outside /proc, /sys, /dev, and /run."
        parent = lexical.parent.resolve(strict=True)
        resolved = parent / lexical.name
        if _is_blocked_path(parent) or _is_blocked_path(resolved):
            return None, None, "Paths under /proc, /sys, /dev, and /run are excluded from general filesystem tools."
        return resolved, parent, None
    except (OSError, RuntimeError, ValueError) as exc:
        return None, None, f"Path parent could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."


def _phrase(prefix: str, material: dict[str, object]) -> str:
    digest = hashlib.sha256(
        json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"{prefix} {digest[:16]}"


@dataclass(frozen=True, slots=True)
class SymlinkTarget:
    path: Path
    action: Literal["create", "remove"]
    link_target: str
    parent_device: int
    parent_inode: int
    entry_snapshot: tuple[int, ...] | None


def symlink_action_confirmation_details(
    path: str,
    action: Literal["create", "remove"],
    target: str = "",
) -> tuple[SymlinkTarget | None, str | None, str | None]:
    if action not in {"create", "remove"}:
        return None, None, "action must be 'create' or 'remove'."
    if action == "create":
        if not isinstance(target, str) or not target or len(target) > MAX_PATH_LENGTH or "\x00" in target:
            return None, None, "A symlink target must be non-empty text of at most 4096 characters without NUL bytes."
    elif target:
        return None, None, "target must be empty when removing a symlink."
    resolved, parent, error = _path_parts(path)
    if error or resolved is None or parent is None:
        return None, None, error
    parent_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(parent, _PARENT_FLAGS)
        parent_info = os.fstat(parent_fd)
        try:
            entry = os.stat(resolved.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if action == "remove":
                return None, None, "The symlink to remove does not exist."
            current_target, entry_snapshot = target, None
        else:
            if action == "create":
                return None, None, "The destination path already exists; symlink creation never replaces it."
            if not stat.S_ISLNK(entry.st_mode):
                return None, None, "The path to remove is not a symbolic link."
            current_target = os.readlink(resolved.name, dir_fd=parent_fd)
            entry_snapshot = _snapshot(entry)
    except OSError as exc:
        return None, None, f"The symlink path could not be verified: {exc.strerror or type(exc).__name__}."
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
    prepared = SymlinkTarget(
        path=resolved,
        action=action,
        link_target=current_target,
        parent_device=parent_info.st_dev,
        parent_inode=parent_info.st_ino,
        entry_snapshot=entry_snapshot,
    )
    phrase = _phrase(
        "LINK",
        {
            "path": str(resolved),
            "action": action,
            "target": current_target,
            "parent": [parent_info.st_dev, parent_info.st_ino],
            "entry": entry_snapshot,
        },
    )
    return prepared, phrase, None


def manage_symlink(
    path: str,
    action: Literal["create", "remove"],
    target: str = "",
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> PathAdminResponse:
    prepared, phrase, error = symlink_action_confirmation_details(path, action, target)
    if error or prepared is None or phrase is None:
        return PathAdminResponse(success=False, path=path if isinstance(path, str) else None, action=action, user_confirmed=confirmed is True, message=error or "The symlink operation could not be verified.")
    if confirmed is not True:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, symlink_target=prepared.link_target, message="Explicit client confirmation is required; no symlink was changed.")
    if confirmation_phrase != phrase:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, symlink_target=prepared.link_target, user_confirmed=True, message="Confirmation did not match this exact symlink request and current state.")
    parent_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(prepared.path.parent, _PARENT_FLAGS)
        parent_info = os.fstat(parent_fd)
        if (parent_info.st_dev, parent_info.st_ino) != (prepared.parent_device, prepared.parent_inode):
            raise OSError("The parent directory changed after confirmation.")
        if action == "create":
            os.symlink(prepared.link_target, prepared.path.name, dir_fd=parent_fd)
            entry = os.stat(prepared.path.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISLNK(entry.st_mode) or os.readlink(prepared.path.name, dir_fd=parent_fd) != prepared.link_target:
                raise OSError("The created symlink did not match the confirmed target.")
        else:
            entry = os.stat(prepared.path.name, dir_fd=parent_fd, follow_symlinks=False)
            current_target = os.readlink(prepared.path.name, dir_fd=parent_fd)
            if _snapshot(entry) != prepared.entry_snapshot or current_target != prepared.link_target:
                raise OSError("The symlink changed after confirmation.")
            os.unlink(prepared.path.name, dir_fd=parent_fd)
        return PathAdminResponse(success=True, path=str(prepared.path), action=action, symlink_target=prepared.link_target, user_confirmed=True, message="The symbolic link action completed and was verified.")
    except OSError as exc:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, symlink_target=prepared.link_target, user_confirmed=True, message=f"Symlink operation failed: {exc.strerror or str(exc) or type(exc).__name__}.")
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


@dataclass(frozen=True, slots=True)
class _OwnerTreeEntry:
    relative_path: tuple[str, ...]
    kind: Literal["file", "directory", "symlink"]
    snapshot: tuple[int, ...]
    symlink_target: str | None = None


@dataclass(frozen=True, slots=True)
class OwnerChangeTarget:
    path: Path
    owner_uid: int | None
    owner_gid: int | None
    parent_device: int
    parent_inode: int
    entry_snapshot: tuple[int, ...]
    recursive: bool = False
    tree_sha256: str | None = None
    tree_entries: tuple[_OwnerTreeEntry, ...] = ()
    tree_bytes: int = 0
    external_hardlink_groups: int = 0


def _owner_tree_snapshot_fd(
    root_fd: int,
    root_device: int,
) -> tuple[str | None, tuple[_OwnerTreeEntry, ...], int, str | None]:
    digest = hashlib.sha256()
    entries: list[_OwnerTreeEntry] = []
    total_bytes = 0

    def add_entry(relative_path: tuple[str, ...], kind: Literal["file", "directory", "symlink"], info: os.stat_result, target: str | None = None) -> str | None:
        if len(entries) >= MAX_RECURSIVE_OWNER_ENTRIES:
            return f"The directory tree exceeds the {MAX_RECURSIVE_OWNER_ENTRIES}-entry ownership limit."
        path_bytes = b"/".join(os.fsencode(part) for part in relative_path)
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(kind.encode("ascii"))
        digest.update(repr(_snapshot(info)).encode("ascii"))
        if target is not None:
            target_bytes = os.fsencode(target)
            digest.update(len(target_bytes).to_bytes(4, "big"))
            digest.update(target_bytes)
        entries.append(_OwnerTreeEntry(relative_path, kind, _snapshot(info), target))
        return None

    try:
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_dev != root_device:
            return None, (), 0, "The recursive ownership root changed or is not a directory."
        error = add_entry((), "directory", root_info)
        if error:
            return None, (), 0, error
    except OSError as exc:
        return None, (), 0, f"The ownership tree root could not be inspected: {exc.strerror or type(exc).__name__}."

    def walk(directory_fd: int, relative_directory: tuple[str, ...], depth: int) -> str | None:
        nonlocal total_bytes
        if depth > MAX_RECURSIVE_OWNER_DEPTH:
            return f"Directory depth exceeds the {MAX_RECURSIVE_OWNER_DEPTH}-level recursive ownership limit."
        try:
            names = sorted(os.listdir(directory_fd), key=os.fsencode)
        except OSError as exc:
            return f"A directory could not be scanned: {exc.strerror or type(exc).__name__}."
        for name in names:
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if info.st_dev != root_device:
                    return "The directory tree crosses a filesystem boundary or mounted device."
                relative_path = relative_directory + (name,)
                if stat.S_ISREG(info.st_mode):
                    total_bytes += max(0, info.st_size)
                    error = add_entry(relative_path, "file", info)
                elif stat.S_ISDIR(info.st_mode):
                    error = add_entry(relative_path, "directory", info)
                    if error:
                        return error
                    child_fd = os.open(name, _PARENT_FLAGS, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(child_fd)
                        if _snapshot(opened) != _snapshot(info):
                            return "A directory entry changed while its ownership tree was inspected."
                        error = walk(child_fd, relative_path, depth + 1)
                        if error:
                            return error
                        if _snapshot(os.fstat(child_fd)) != _snapshot(info):
                            return "A directory changed while its ownership tree was inspected."
                    finally:
                        os.close(child_fd)
                    continue
                elif stat.S_ISLNK(info.st_mode):
                    target = os.readlink(name, dir_fd=directory_fd)
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if _snapshot(after) != _snapshot(info):
                        return "A symbolic link changed while its ownership tree was inspected."
                    error = add_entry(relative_path, "symlink", info, target)
                else:
                    return "Recursive ownership changes support regular files, directories, and symlinks; special files are refused."
                if error:
                    return error
            except OSError as exc:
                return f"A directory entry could not be inspected: {exc.strerror or type(exc).__name__}."
        return None

    error = walk(root_fd, (), 0)
    if error:
        return None, (), total_bytes, error
    return digest.hexdigest(), tuple(entries), total_bytes, None


def _owner_tree_external_hardlink_groups(entries: tuple[_OwnerTreeEntry, ...]) -> int:
    in_tree_counts: dict[tuple[int, int], int] = {}
    snapshots: dict[tuple[int, int], tuple[int, ...]] = {}
    for entry in entries:
        if entry.kind not in {"file", "symlink"}:
            continue
        key = (entry.snapshot[0], entry.snapshot[1])
        in_tree_counts[key] = in_tree_counts.get(key, 0) + 1
        snapshots[key] = entry.snapshot
    return sum(1 for key, count in in_tree_counts.items() if snapshots[key][3] > count)


def owner_change_confirmation_details(
    path: str,
    owner_uid: int | None,
    owner_gid: int | None,
    recursive: bool = False,
) -> tuple[OwnerChangeTarget | None, str | None, str | None]:
    if not isinstance(recursive, bool):
        return None, None, "recursive must be a boolean."
    if owner_uid is None and owner_gid is None:
        return None, None, "Provide at least one of owner_uid or owner_gid."
    for name, value in (("owner_uid", owner_uid), ("owner_gid", owner_gid)):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFE):
            return None, None, f"{name} must be a numeric Linux ID from 0 through 4294967294."
    if recursive and os.geteuid() != 0:
        return None, None, "Recursive ownership changes require the MCP server to already run as root so the entire tree can be inspected and revalidated."
    resolved, parent, error = _path_parts(path)
    if error or resolved is None or parent is None:
        return None, None, error
    parent_fd: int | None = None
    target_fd: int | None = None
    tree_sha256: str | None = None
    tree_entries: tuple[_OwnerTreeEntry, ...] = ()
    tree_bytes = 0
    external_hardlink_groups = 0
    try:
        parent_fd = _open_resolved_path(parent, _PARENT_FLAGS)
        parent_info = os.fstat(parent_fd)
        entry = os.stat(resolved.name, dir_fd=parent_fd, follow_symlinks=False)
        if recursive:
            if not stat.S_ISDIR(entry.st_mode):
                return None, None, "Recursive ownership changes require a real directory and never follow a symlink."
        elif stat.S_ISLNK(entry.st_mode) or not (stat.S_ISREG(entry.st_mode) or stat.S_ISDIR(entry.st_mode)):
            return None, None, "Nonrecursive ownership changes support regular files and directories, not symlinks or special files."
        flags = _ENTRY_FLAGS | (getattr(os, "O_DIRECTORY", 0) if stat.S_ISDIR(entry.st_mode) else 0)
        target_fd = os.open(resolved.name, flags, dir_fd=parent_fd)
        opened = os.fstat(target_fd)
        if _snapshot(opened) != _snapshot(entry):
            return None, None, "The target changed while its identity was checked."
        if recursive:
            from wayland_mcp.tools.filesystem_tree import _mountpoints

            mounts = _mountpoints()
            if mounts is None:
                return None, None, "Mounted paths could not be checked safely for recursive ownership changes."
            if resolved in mounts or any(resolved in mount.parents for mount in mounts):
                return None, None, "Recursive ownership changes refuse mounted roots and nested mount points."
            tree_sha256, tree_entries, tree_bytes, error = _owner_tree_snapshot_fd(target_fd, opened.st_dev)
            if error or tree_sha256 is None:
                return None, None, error or "The ownership tree could not be summarized."
            external_hardlink_groups = _owner_tree_external_hardlink_groups(tree_entries)
        prepared = OwnerChangeTarget(
            path=resolved,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            parent_device=parent_info.st_dev,
            parent_inode=parent_info.st_ino,
            entry_snapshot=_snapshot(opened),
            recursive=recursive,
            tree_sha256=tree_sha256,
            tree_entries=tree_entries,
            tree_bytes=tree_bytes,
            external_hardlink_groups=external_hardlink_groups,
        )
    except OSError as exc:
        return None, None, f"The ownership target could not be verified: {exc.strerror or type(exc).__name__}."
    finally:
        for fd in (target_fd, parent_fd):
            if fd is not None:
                os.close(fd)
    phrase = _phrase(
        "CHOWN",
        {
            "path": str(prepared.path),
            "owner_uid": owner_uid,
            "owner_gid": owner_gid,
            "recursive": recursive,
            "parent": [prepared.parent_device, prepared.parent_inode],
            "entry": prepared.entry_snapshot,
            "tree_sha256": prepared.tree_sha256,
            "tree_entries": len(prepared.tree_entries),
        },
    )
    return prepared, phrase, None


def _owner_tree_mount_error(path: Path) -> str | None:
    from wayland_mcp.tools.filesystem_tree import _mountpoints

    mounts = _mountpoints()
    if mounts is None:
        return "Mounted paths could not be checked safely for recursive ownership changes."
    if path in mounts or any(path in mount.parents for mount in mounts):
        return "Recursive ownership changes refuse mounted roots and nested mount points."
    return None


def _open_owner_tree_parent(root_fd: int, components: tuple[str, ...]) -> tuple[int, str]:
    if not components:
        raise OSError(errno.EINVAL, "empty relative ownership path")
    parent_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            child_fd = os.open(component, _PARENT_FLAGS, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        return parent_fd, components[-1]
    except OSError:
        os.close(parent_fd)
        raise


def _fchown_symlink(descriptor: int, owner_uid: int, owner_gid: int) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        fchownat = libc.fchownat
    except (AttributeError, OSError) as exc:
        raise OSError(errno.ENOSYS, "descriptor-bound symlink ownership changes are unavailable") from exc
    fchownat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_int]
    fchownat.restype = ctypes.c_int
    result = fchownat(
        descriptor,
        b"",
        ctypes.c_uint(owner_uid),
        ctypes.c_uint(owner_gid),
        _AT_EMPTY_PATH | _AT_SYMLINK_NOFOLLOW,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _owner_entry_after_matches(
    original: _OwnerTreeEntry,
    info: os.stat_result,
    owner_uid: int | None,
    owner_gid: int | None,
) -> bool:
    return _owner_snapshot_after_matches(original, _snapshot(info), owner_uid, owner_gid)


def _owner_snapshot_after_matches(
    original: _OwnerTreeEntry,
    current: tuple[int, ...],
    owner_uid: int | None,
    owner_gid: int | None,
) -> bool:
    old = original.snapshot
    expected_uid = old[4] if owner_uid is None else owner_uid
    expected_gid = old[5] if owner_gid is None else owner_gid
    cleared_by_chown = stat.S_ISUID | stat.S_ISGID
    return (
        current[0] == old[0]
        and current[1] == old[1]
        and (current[2] & ~cleared_by_chown) == (old[2] & ~cleared_by_chown)
        and current[2] & cleared_by_chown & ~(old[2] & cleared_by_chown) == 0
        and current[3] == old[3]
        and current[4] == expected_uid
        and current[5] == expected_gid
        and current[6] == old[6]
        and current[7] == old[7]
        and ("directory" if stat.S_ISDIR(current[2]) else "file" if stat.S_ISREG(current[2]) else "symlink") == original.kind
    )


def _change_owner_tree_entry(
    root_fd: int,
    entry: _OwnerTreeEntry,
    owner_uid: int | None,
    owner_gid: int | None,
    *,
    already_changed: bool,
) -> bool:
    if not entry.relative_path:
        target_fd = os.dup(root_fd)
        parent_fd = None
        name = None
    else:
        parent_fd, name = _open_owner_tree_parent(root_fd, entry.relative_path)
        target_fd = None
    try:
        if entry.kind == "symlink":
            if parent_fd is None or name is None:
                raise OSError(errno.EINVAL, "the ownership tree root cannot be a symlink")
            if not hasattr(os, "O_PATH"):
                raise OSError(errno.ENOSYS, "descriptor-bound symlink ownership changes are unavailable")
            target_fd = os.open(
                name,
                os.O_PATH | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
            before = os.fstat(target_fd)
            if already_changed:
                if not _owner_entry_after_matches(entry, before, owner_uid, owner_gid):
                    raise OSError(errno.ESTALE, "a hard-linked symlink changed during recursive ownership updates")
                return False
            if _snapshot(before) != entry.snapshot:
                raise OSError(errno.ESTALE, "a symlink changed after ownership confirmation")
            expected_uid = before.st_uid if owner_uid is None else owner_uid
            expected_gid = before.st_gid if owner_gid is None else owner_gid
            if (before.st_uid, before.st_gid) == (expected_uid, expected_gid):
                return False
            _fchown_symlink(
                target_fd,
                0xFFFFFFFF if owner_uid is None else owner_uid,
                0xFFFFFFFF if owner_gid is None else owner_gid,
            )
            after = os.fstat(target_fd)
            named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (named_after.st_dev, named_after.st_ino) != (after.st_dev, after.st_ino):
                raise OSError(errno.ESTALE, "the symlink path changed while its ownership was being updated")
        else:
            if target_fd is None:
                flags = _ENTRY_FLAGS | (getattr(os, "O_DIRECTORY", 0) if entry.kind == "directory" else 0)
                target_fd = os.open(name, flags, dir_fd=parent_fd)
            before = os.fstat(target_fd)
            if already_changed:
                if not _owner_entry_after_matches(entry, before, owner_uid, owner_gid):
                    raise OSError(errno.ESTALE, "a hard-linked file changed during recursive ownership updates")
                return False
            if _snapshot(before) != entry.snapshot:
                raise OSError(errno.ESTALE, "a file or directory changed after ownership confirmation")
            expected_uid = before.st_uid if owner_uid is None else owner_uid
            expected_gid = before.st_gid if owner_gid is None else owner_gid
            if (before.st_uid, before.st_gid) == (expected_uid, expected_gid):
                return False
            os.fchown(
                target_fd,
                -1 if owner_uid is None else owner_uid,
                -1 if owner_gid is None else owner_gid,
            )
            after = os.fstat(target_fd)
        if not _owner_entry_after_matches(entry, after, owner_uid, owner_gid):
            raise OSError(errno.ESTALE, "the resulting recursive ownership or path identity did not match the confirmed request")
        return True
    finally:
        if target_fd is not None:
            os.close(target_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _owner_tree_matches_after(
    before_entries: tuple[_OwnerTreeEntry, ...],
    after_entries: tuple[_OwnerTreeEntry, ...],
    owner_uid: int | None,
    owner_gid: int | None,
) -> bool:
    if len(before_entries) != len(after_entries):
        return False
    for before, after in zip(before_entries, after_entries):
        if (
            before.relative_path != after.relative_path
            or before.kind != after.kind
            or before.symlink_target != after.symlink_target
            or not _owner_snapshot_after_matches(before, after.snapshot, owner_uid, owner_gid)
        ):
            return False
    return True


def _perform_recursive_owner_change(prepared: OwnerChangeTarget) -> PathAdminResponse:
    parent_fd: int | None = None
    root_fd: int | None = None
    changed_objects = 0
    try:
        with _OWNER_CHANGE_LOCK:
            parent_fd = _open_resolved_path(prepared.path.parent, _PARENT_FLAGS)
            parent_info = os.fstat(parent_fd)
            if (parent_info.st_dev, parent_info.st_ino) != (prepared.parent_device, prepared.parent_inode):
                raise OSError(errno.ESTALE, "the ownership tree parent changed after confirmation")
            root_entry = os.stat(prepared.path.name, dir_fd=parent_fd, follow_symlinks=False)
            if _snapshot(root_entry) != prepared.entry_snapshot or not stat.S_ISDIR(root_entry.st_mode):
                raise OSError(errno.ESTALE, "the ownership tree root changed after confirmation")
            root_fd = os.open(prepared.path.name, _PARENT_FLAGS, dir_fd=parent_fd)
            if _snapshot(os.fstat(root_fd)) != prepared.entry_snapshot:
                raise OSError(errno.ESTALE, "the opened ownership tree root changed after confirmation")
            mount_error = _owner_tree_mount_error(prepared.path)
            if mount_error:
                raise OSError(errno.EBUSY, mount_error)
            tree_sha, entries, tree_bytes, error = _owner_tree_snapshot_fd(root_fd, prepared.entry_snapshot[0])
            if error or tree_sha != prepared.tree_sha256 or entries != prepared.tree_entries or tree_bytes != prepared.tree_bytes:
                raise OSError(errno.ESTALE, error or "the ownership tree changed after confirmation")

            seen_inodes: set[tuple[int, int]] = set()
            for entry in reversed(prepared.tree_entries):
                key = (entry.snapshot[0], entry.snapshot[1])
                deduplicate = entry.kind in {"file", "symlink"} and key in seen_inodes
                changed = _change_owner_tree_entry(
                    root_fd,
                    entry,
                    prepared.owner_uid,
                    prepared.owner_gid,
                    already_changed=deduplicate,
                )
                if entry.kind in {"file", "symlink"}:
                    seen_inodes.add(key)
                if changed:
                    changed_objects += 1

            final_sha, final_entries, final_bytes, error = _owner_tree_snapshot_fd(root_fd, prepared.entry_snapshot[0])
            if error or final_sha is None or final_bytes != prepared.tree_bytes or not _owner_tree_matches_after(
                prepared.tree_entries,
                final_entries,
                prepared.owner_uid,
                prepared.owner_gid,
            ):
                raise OSError(errno.ESTALE, error or "the tree changed during recursive ownership verification")
            final_root = os.stat(prepared.path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (final_root.st_dev, final_root.st_ino) != prepared.entry_snapshot[:2]:
                raise OSError(errno.ESTALE, "the ownership tree root path changed during the action")
        outside_note = (
            f" {prepared.external_hardlink_groups} hard-linked file or symlink group(s) also have paths outside this tree."
            if prepared.external_hardlink_groups
            else ""
        )
        return PathAdminResponse(
            success=True,
            path=str(prepared.path),
            action="chown",
            owner_uid=prepared.owner_uid,
            owner_gid=prepared.owner_gid,
            entries_affected=len(prepared.tree_entries),
            bytes_affected=prepared.tree_bytes,
            user_confirmed=True,
            message=(
                f"Recursive ownership was changed and verified for {len(prepared.tree_entries)} entries "
                f"({changed_objects} unique filesystem objects required an ownership update). Setuid/setgid bits may be cleared by chown."
                f"{outside_note}"
            ),
        )
    except OSError as exc:
        return PathAdminResponse(
            success=False,
            path=str(prepared.path),
            action="chown",
            owner_uid=prepared.owner_uid,
            owner_gid=prepared.owner_gid,
            entries_affected=changed_objects,
            bytes_affected=prepared.tree_bytes,
            user_confirmed=True,
            message=(
                f"Recursive ownership change stopped after confirming updates to {changed_objects} unique filesystem object(s); "
                f"the object being processed when verification failed may also have changed. Earlier changes remain in place and were not rolled back. "
                f"{exc.strerror or str(exc) or type(exc).__name__}."
            ),
        )
    finally:
        for fd in (root_fd, parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def change_path_owner(
    path: str,
    owner_uid: int | None,
    owner_gid: int | None,
    *,
    recursive: bool = False,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> PathAdminResponse:
    prepared, phrase, error = owner_change_confirmation_details(path, owner_uid, owner_gid, recursive)
    if error or prepared is None or phrase is None:
        return PathAdminResponse(success=False, path=path if isinstance(path, str) else None, action="chown", user_confirmed=confirmed is True, message=error or "The ownership request could not be verified.")
    if confirmed is not True:
        return PathAdminResponse(
            success=False,
            path=str(prepared.path),
            action="chown",
            previous_uid=None if prepared.recursive else prepared.entry_snapshot[4],
            previous_gid=None if prepared.recursive else prepared.entry_snapshot[5],
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            link_count=None if prepared.recursive else prepared.entry_snapshot[3],
            entries_affected=len(prepared.tree_entries) if prepared.recursive else None,
            bytes_affected=prepared.tree_bytes if prepared.recursive else None,
            message="Explicit client confirmation is required; ownership was not changed.",
        )
    if confirmation_phrase != phrase:
        return PathAdminResponse(success=False, path=str(prepared.path), action="chown", user_confirmed=True, message="Confirmation did not match this exact ownership request and current state.")
    if prepared.recursive:
        return _perform_recursive_owner_change(prepared)
    parent_fd: int | None = None
    target_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(prepared.path.parent, _PARENT_FLAGS)
        parent_info = os.fstat(parent_fd)
        if (parent_info.st_dev, parent_info.st_ino) != (prepared.parent_device, prepared.parent_inode):
            raise OSError("The parent directory changed after confirmation.")
        entry = os.stat(prepared.path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _snapshot(entry) != prepared.entry_snapshot:
            raise OSError("The target changed after confirmation.")
        flags = _ENTRY_FLAGS | (getattr(os, "O_DIRECTORY", 0) if stat.S_ISDIR(entry.st_mode) else 0)
        target_fd = os.open(prepared.path.name, flags, dir_fd=parent_fd)
        before = os.fstat(target_fd)
        if _snapshot(before) != prepared.entry_snapshot:
            raise OSError("The opened target changed after confirmation.")
        os.fchown(target_fd, -1 if owner_uid is None else owner_uid, -1 if owner_gid is None else owner_gid)
        after = os.fstat(target_fd)
        expected_uid = before.st_uid if owner_uid is None else owner_uid
        expected_gid = before.st_gid if owner_gid is None else owner_gid
        if after.st_uid != expected_uid or after.st_gid != expected_gid:
            raise OSError("The resulting ownership did not match the confirmed IDs.")
        return PathAdminResponse(
            success=True,
            path=str(prepared.path),
            action="chown",
            previous_uid=before.st_uid,
            previous_gid=before.st_gid,
            owner_uid=after.st_uid,
            owner_gid=after.st_gid,
            link_count=after.st_nlink,
            user_confirmed=True,
            message="Ownership was changed and verified on the pinned file descriptor.",
        )
    except OSError as exc:
        return PathAdminResponse(success=False, path=str(prepared.path), action="chown", user_confirmed=True, message=f"Ownership change failed: {exc.strerror or str(exc) or type(exc).__name__}.")
    finally:
        for fd in (target_fd, parent_fd):
            if fd is not None:
                os.close(fd)


@dataclass(frozen=True, slots=True)
class AttributeChangeTarget:
    path: Path
    action: Literal["set", "remove"]
    name: str
    value: bytes | None
    parent_device: int
    parent_inode: int
    entry_snapshot: tuple[int, ...]
    current_sha256: str | None


def _open_regular_or_directory(path: str):
    resolved, parent, error = _path_parts(path)
    if error or resolved is None or parent is None:
        return None, None, None, None, error
    parent_fd: int | None = None
    target_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(parent, _PARENT_FLAGS)
        parent_info = os.fstat(parent_fd)
        entry = os.stat(resolved.name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(entry.st_mode) or not (stat.S_ISREG(entry.st_mode) or stat.S_ISDIR(entry.st_mode)):
            return None, None, None, None, "Extended metadata changes support regular files and directories only."
        flags = _ENTRY_FLAGS | (getattr(os, "O_DIRECTORY", 0) if stat.S_ISDIR(entry.st_mode) else 0)
        target_fd = os.open(resolved.name, flags, dir_fd=parent_fd)
        opened = os.fstat(target_fd)
        if _snapshot(opened) != _snapshot(entry):
            os.close(target_fd)
            target_fd = None
            return None, None, None, None, "The target changed while its identity was checked."
        return resolved, parent_info, opened, target_fd, None
    except OSError as exc:
        _close_target(target_fd)
        return None, None, None, None, f"The extended-metadata target could not be verified: {exc.strerror or type(exc).__name__}."
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def _close_target(fd: int | None) -> None:
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass


def _read_xattr(fd: int, name: str) -> tuple[bytes | None, str | None]:
    try:
        return os.getxattr(fd, name), None
    except OSError as exc:
        if exc.errno in {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}:
            return None, None
        return None, f"Could not inspect extended attribute {name!r}: {exc.strerror or type(exc).__name__}."
    except (NotImplementedError, TypeError) as exc:
        return None, f"Extended-attribute access is unavailable: {type(exc).__name__}."


def extended_attribute_confirmation_details(
    path: str,
    name: str,
    action: Literal["set", "remove"],
    value_base64: str = "",
) -> tuple[AttributeChangeTarget | None, str | None, str | None]:
    if action not in {"set", "remove"}:
        return None, None, "action must be 'set' or 'remove'."
    if not isinstance(name, str) or not name or len(name) > 255 or "\x00" in name or not name.isascii() or "." not in name:
        return None, None, "Attribute name must be an ASCII Linux xattr name of at most 255 bytes with a namespace prefix."
    namespace, attribute = name.split(".", 1)
    if namespace not in {"user", "trusted", "security", "system"} or not attribute:
        return None, None, "Attribute name must use a supported Linux namespace and a non-empty attribute name."
    if name.startswith("system.posix_acl_"):
        return None, None, "POSIX ACL xattrs must be changed through manage_posix_acl."
    value: bytes | None = None
    if action == "set":
        if not isinstance(value_base64, str) or len(value_base64) > ((_MAX_XATTR_BYTES + 2) // 3) * 4:
            return None, None, f"Base64 attribute value cannot exceed {_MAX_XATTR_BYTES} decoded bytes."
        try:
            value = base64.b64decode(value_base64.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError):
            return None, None, "value_base64 must be valid strict base64."
        if len(value) > _MAX_XATTR_BYTES:
            return None, None, f"Decoded attribute value cannot exceed {_MAX_XATTR_BYTES} bytes."
    elif value_base64:
        return None, None, "value_base64 must be empty when removing an attribute."
    resolved, parent_info, opened, fd, error = _open_regular_or_directory(path)
    if error or resolved is None or parent_info is None or opened is None or fd is None:
        return None, None, error
    try:
        current_value, error = _read_xattr(fd, name)
        if error:
            return None, None, error
        if action == "remove" and current_value is None:
            return None, None, "The requested extended attribute is not present."
        prepared = AttributeChangeTarget(
            path=resolved,
            action=action,
            name=name,
            value=value,
            parent_device=parent_info.st_dev,
            parent_inode=parent_info.st_ino,
            entry_snapshot=_snapshot(opened),
            current_sha256=hashlib.sha256(current_value).hexdigest() if current_value is not None else None,
        )
    finally:
        _close_target(fd)
    phrase = _phrase(
        "XATTR",
        {
            "path": str(prepared.path),
            "action": prepared.action,
            "name": prepared.name,
            "value_sha256": hashlib.sha256(prepared.value).hexdigest() if prepared.value is not None else None,
            "current_sha256": prepared.current_sha256,
            "entry": prepared.entry_snapshot,
        },
    )
    return prepared, phrase, None


def manage_extended_attribute(
    path: str,
    name: str,
    action: Literal["set", "remove"],
    value_base64: str = "",
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> PathAdminResponse:
    prepared, phrase, error = extended_attribute_confirmation_details(path, name, action, value_base64)
    if error or prepared is None or phrase is None:
        return PathAdminResponse(success=False, path=path, action=action, attribute_name=name, user_confirmed=confirmed is True, message=error or "The xattr request could not be verified.")
    new_sha = hashlib.sha256(prepared.value).hexdigest() if prepared.value is not None else None
    if confirmed is not True:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, attribute_name=name, value_sha256=new_sha, message="Explicit client confirmation is required; the attribute was not changed.")
    if confirmation_phrase != phrase:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, attribute_name=name, user_confirmed=True, message="Confirmation did not match this exact xattr request and current state.")
    resolved, parent, error = _path_parts(path)
    if error or resolved is None or parent is None:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, attribute_name=name, user_confirmed=True, message=error)
    parent_fd: int | None = None
    target_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(parent, _PARENT_FLAGS)
        parent_info = os.fstat(parent_fd)
        if (parent_info.st_dev, parent_info.st_ino) != (prepared.parent_device, prepared.parent_inode):
            raise OSError("The parent directory changed after confirmation.")
        entry = os.stat(resolved.name, dir_fd=parent_fd, follow_symlinks=False)
        if _snapshot(entry) != prepared.entry_snapshot:
            raise OSError("The target changed after confirmation.")
        flags = _ENTRY_FLAGS | (getattr(os, "O_DIRECTORY", 0) if stat.S_ISDIR(entry.st_mode) else 0)
        target_fd = os.open(resolved.name, flags, dir_fd=parent_fd)
        if _snapshot(os.fstat(target_fd)) != prepared.entry_snapshot:
            raise OSError("The opened target changed after confirmation.")
        current_value, error = _read_xattr(target_fd, name)
        if error or (hashlib.sha256(current_value).hexdigest() if current_value is not None else None) != prepared.current_sha256:
            raise OSError(error or "The current extended attribute changed after confirmation.")
        if action == "set":
            assert prepared.value is not None
            os.setxattr(target_fd, name, prepared.value)
        else:
            os.removexattr(target_fd, name)
        resulting, error = _read_xattr(target_fd, name)
        if action == "set" and (error or resulting != prepared.value):
            raise OSError(error or "The stored extended attribute did not match the request.")
        if action == "remove" and (error or resulting is not None):
            raise OSError(error or "The extended attribute remains present after removal.")
        return PathAdminResponse(success=True, path=str(prepared.path), action=action, attribute_name=name, value_sha256=new_sha, bytes_written=len(prepared.value) if prepared.value is not None else 0, user_confirmed=True, message="The extended attribute was changed and verified.")
    except OSError as exc:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, attribute_name=name, value_sha256=new_sha, user_confirmed=True, message=f"Extended-attribute change failed: {exc.strerror or str(exc) or type(exc).__name__}.")
    finally:
        for fd in (target_fd, parent_fd):
            _close_target(fd)


def _encode_acl(entries: list[ACLWriteEntry]) -> tuple[bytes | None, str | None]:
    if not isinstance(entries, list) or not 3 <= len(entries) <= 256:
        return None, "An access/default ACL must contain from 3 through 256 entries."
    seen_base: set[str] = set()
    named_users: set[int] = set()
    named_groups: set[int] = set()
    has_named = False
    normalized: list[tuple[str, int, int]] = []
    for entry in entries:
        tag = entry.tag
        qualifier = entry.qualifier_id
        permissions = entry.permissions
        if (
            not isinstance(permissions, str)
            or len(permissions) != 3
            or permissions[0] not in "r-"
            or permissions[1] not in "w-"
            or permissions[2] not in "x-"
        ):
            return None, "Each ACL entry's permissions must contain exactly three rwx positions, such as 'r-x'."
        bits = sum(bit for char, bit in zip(permissions, (4, 2, 1)) if char != "-")
        if tag in {"user", "group"}:
            has_named = True
            if qualifier is None or isinstance(qualifier, bool) or not 0 <= qualifier <= 0xFFFFFFFE:
                return None, "Named user/group ACL entries require a numeric qualifier ID."
            identity_set = named_users if tag == "user" else named_groups
            if qualifier in identity_set:
                return None, "ACL named user/group qualifier IDs must be unique within their class."
            identity_set.add(qualifier)
        else:
            if qualifier is not None:
                return None, f"ACL entry {tag!r} must not have a qualifier ID."
            if tag in seen_base:
                return None, f"ACL entry {tag!r} may appear only once."
            seen_base.add(tag)
        normalized.append((tag, bits, _ACL_UNDEFINED_ID if qualifier is None else qualifier))
    if not {"user_obj", "group_obj", "other"} <= seen_base:
        return None, "ACLs require exactly one user_obj, group_obj, and other entry."
    if has_named and "mask" not in seen_base:
        return None, "ACLs with named user/group entries require one mask entry."
    normalized.sort(key=lambda item: (_ACL_ORDER[item[0]], item[2]))
    raw = struct.pack("<I", 0x0002) + b"".join(
        struct.pack("<HHI", _ACL_TAGS[tag], permission_bits, qualifier)
        for tag, permission_bits, qualifier in normalized
    )
    return raw, None


@dataclass(frozen=True, slots=True)
class ACLChangeTarget:
    path: Path
    action: Literal["set", "remove"]
    acl_kind: Literal["access", "default"]
    entries: tuple[ACLWriteEntry, ...]
    raw_value: bytes | None
    parent_device: int
    parent_inode: int
    entry_snapshot: tuple[int, ...]
    current_sha256: str | None


def posix_acl_confirmation_details(
    path: str,
    action: Literal["set", "remove"],
    acl_kind: Literal["access", "default"],
    entries: list[ACLWriteEntry],
) -> tuple[ACLChangeTarget | None, str | None, str | None]:
    if action not in {"set", "remove"} or acl_kind not in {"access", "default"}:
        return None, None, "action must be 'set' or 'remove'; acl_kind must be 'access' or 'default'."
    raw: bytes | None = None
    normalized_entries: tuple[ACLWriteEntry, ...] = tuple()
    if action == "set":
        raw, error = _encode_acl(entries)
        if error or raw is None:
            return None, None, error
        normalized_entries = tuple(entries)
    elif entries:
        return None, None, "entries must be empty when removing an ACL."
    resolved, parent_info, opened, fd, error = _open_regular_or_directory(path)
    if error or resolved is None or parent_info is None or opened is None or fd is None:
        return None, None, error
    try:
        if acl_kind == "default" and not stat.S_ISDIR(opened.st_mode):
            return None, None, "Default ACLs can be changed only on directories."
        attr_name = _ACL_XATTRS[acl_kind]
        old_value, error = _read_xattr(fd, attr_name)
        if error:
            return None, None, error
        if action == "remove" and old_value is None:
            return None, None, f"The {acl_kind} ACL is not present."
        prepared = ACLChangeTarget(
            path=resolved,
            action=action,
            acl_kind=acl_kind,
            entries=normalized_entries,
            raw_value=raw,
            parent_device=parent_info.st_dev,
            parent_inode=parent_info.st_ino,
            entry_snapshot=_snapshot(opened),
            current_sha256=hashlib.sha256(old_value).hexdigest() if old_value is not None else None,
        )
    finally:
        _close_target(fd)
    phrase = _phrase(
        "ACL",
        {
            "path": str(prepared.path),
            "action": action,
            "acl_kind": acl_kind,
            "entries": [entry.model_dump() for entry in normalized_entries],
            "raw_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
            "current_sha256": prepared.current_sha256,
            "entry": prepared.entry_snapshot,
        },
    )
    return prepared, phrase, None


def manage_posix_acl(
    path: str,
    action: Literal["set", "remove"],
    acl_kind: Literal["access", "default"],
    entries: list[ACLWriteEntry],
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> PathAdminResponse:
    prepared, phrase, error = posix_acl_confirmation_details(path, action, acl_kind, entries)
    if error or prepared is None or phrase is None:
        return PathAdminResponse(success=False, path=path, action=action, acl_kind=acl_kind, user_confirmed=confirmed is True, message=error or "The ACL request could not be verified.")
    attr_name = _ACL_XATTRS[acl_kind]
    if confirmed is not True:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, acl_kind=acl_kind, acl_entry_count=len(prepared.entries), attribute_name=attr_name, message="Explicit client confirmation is required; the ACL was not changed.")
    if confirmation_phrase != phrase:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, acl_kind=acl_kind, user_confirmed=True, message="Confirmation did not match this exact ACL request and current state.")
    resolved, _parent, error = _path_parts(path)
    if error or resolved is None:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, acl_kind=acl_kind, user_confirmed=True, message=error)
    parent_fd: int | None = None
    target_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(resolved.parent, _PARENT_FLAGS)
        parent_info = os.fstat(parent_fd)
        if (parent_info.st_dev, parent_info.st_ino) != (prepared.parent_device, prepared.parent_inode):
            raise OSError("The parent directory changed after confirmation.")
        entry = os.stat(resolved.name, dir_fd=parent_fd, follow_symlinks=False)
        if _snapshot(entry) != prepared.entry_snapshot:
            raise OSError("The ACL target changed after confirmation.")
        flags = _ENTRY_FLAGS | (getattr(os, "O_DIRECTORY", 0) if stat.S_ISDIR(entry.st_mode) else 0)
        target_fd = os.open(resolved.name, flags, dir_fd=parent_fd)
        if _snapshot(os.fstat(target_fd)) != prepared.entry_snapshot:
            raise OSError("The opened ACL target changed after confirmation.")
        old_value, error = _read_xattr(target_fd, attr_name)
        if error or (hashlib.sha256(old_value).hexdigest() if old_value is not None else None) != prepared.current_sha256:
            raise OSError(error or "The current ACL changed after confirmation.")
        if action == "set":
            assert prepared.raw_value is not None
            os.setxattr(target_fd, attr_name, prepared.raw_value)
        else:
            os.removexattr(target_fd, attr_name)
        after, error = _read_xattr(target_fd, attr_name)
        if action == "set" and (error or after != prepared.raw_value):
            # Linux may represent a three-entry access ACL entirely in the
            # inode mode bits and omit the equivalent ACL xattr.
            simple_access_acl = (
                acl_kind == "access"
                and after is None
                and len(prepared.entries) == 3
                and {entry.tag for entry in prepared.entries} == {"user_obj", "group_obj", "other"}
            )
            if simple_access_acl:
                requested_mode = 0
                for entry in prepared.entries:
                    permissions = sum(
                        bit for char, bit in zip(entry.permissions, (4, 2, 1)) if char != "-"
                    )
                    requested_mode |= permissions << {"user_obj": 6, "group_obj": 3, "other": 0}[entry.tag]
                resulting_mode = stat.S_IMODE(os.fstat(target_fd).st_mode) & 0o777
                if error or resulting_mode != requested_mode:
                    raise OSError(error or "The resulting mode did not match the requested access ACL.")
            else:
                raise OSError(error or "The stored ACL did not match the request.")
        if action == "remove" and (error or after is not None):
            raise OSError(error or "The ACL remains present after removal.")
        return PathAdminResponse(success=True, path=str(prepared.path), action=action, acl_kind=acl_kind, acl_entry_count=len(prepared.entries), attribute_name=attr_name, value_sha256=hashlib.sha256(prepared.raw_value).hexdigest() if prepared.raw_value is not None else None, user_confirmed=True, message="The POSIX ACL was changed and verified.")
    except OSError as exc:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, acl_kind=acl_kind, attribute_name=attr_name, user_confirmed=True, message=f"POSIX ACL change failed: {exc.strerror or str(exc) or type(exc).__name__}.")
    finally:
        for fd in (target_fd, parent_fd):
            _close_target(fd)


MAX_RECURSIVE_DIRECTORY_ENTRIES = 20_000
MAX_CREATED_DIRECTORY_COMPONENTS = 128


@dataclass(frozen=True, slots=True)
class DirectoryActionTarget:
    path: Path
    action: Literal["create_parents", "delete_recursive"]
    mode_octal: str | None
    parent_device: int | None
    parent_inode: int | None
    entry_snapshot: tuple[int, ...] | None
    tree_sha256: str | None
    tree_entries: int
    tree_bytes: int
    anchor_path: Path | None
    anchor_device: int | None
    anchor_inode: int | None
    missing_components: tuple[str, ...]


def _absolute_directory_path(path: object) -> tuple[Path | None, str | None]:
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
            return None, "Directory operations require a named path outside /proc, /sys, /dev, and /run."
        return lexical, None
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"Directory path could not be resolved: {getattr(exc, 'strerror', None) or type(exc).__name__}."


def _inspect_directory_creation(path: Path) -> tuple[Path | None, os.stat_result | None, tuple[str, ...], str | None]:
    components = path.parts[1:]
    current_path = Path("/")
    current_fd: int | None = None
    try:
        current_fd = os.open("/", _PARENT_FLAGS)
        for index, component in enumerate(components):
            try:
                next_fd = os.open(component, _PARENT_FLAGS, dir_fd=current_fd)
            except FileNotFoundError:
                anchor_info = os.fstat(current_fd)
                return current_path, anchor_info, tuple(components[index:]), None
            except OSError as exc:
                return None, None, (), f"An existing path component is not a real directory or cannot be opened without following symlinks: {exc.strerror or type(exc).__name__}."
            os.close(current_fd)
            current_fd = next_fd
            current_path = current_path / component
        return None, None, (), "The directory already exists; create_parents never changes an existing directory."
    except OSError as exc:
        return None, None, (), f"Directory parent could not be safely inspected: {exc.strerror or type(exc).__name__}."
    finally:
        if current_fd is not None:
            os.close(current_fd)


def _snapshot_tree_fd(directory_fd: int) -> tuple[str | None, int, int, str | None]:
    digest = hashlib.sha256()
    count = 0
    total_bytes = 0

    def walk(fd: int, relative: bytes, depth: int) -> str | None:
        nonlocal count, total_bytes
        if depth > 256:
            return "Directory depth exceeds the 256-level limit."
        try:
            names = sorted(os.listdir(fd), key=os.fsencode)
        except OSError as exc:
            return f"A directory could not be scanned: {exc.strerror or type(exc).__name__}."
        for name in names:
            try:
                encoded_name = os.fsencode(name)
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                path_bytes = relative + (b"/" if relative else b"") + encoded_name
                digest.update(len(path_bytes).to_bytes(4, "big"))
                digest.update(path_bytes)
                digest.update(repr(_snapshot(info)).encode("ascii"))
                count += 1
                if count > MAX_RECURSIVE_DIRECTORY_ENTRIES:
                    return f"Directory tree exceeds the {MAX_RECURSIVE_DIRECTORY_ENTRIES}-entry inspection limit."
                if stat.S_ISREG(info.st_mode):
                    total_bytes += max(0, info.st_size)
                if stat.S_ISDIR(info.st_mode):
                    child_fd = os.open(name, _PARENT_FLAGS, dir_fd=fd)
                    try:
                        opened = os.fstat(child_fd)
                        if _snapshot(opened) != _snapshot(info):
                            return "A directory entry changed while the tree was being inspected."
                        error = walk(child_fd, path_bytes, depth + 1)
                        if error:
                            return error
                        if _snapshot(os.fstat(child_fd)) != _snapshot(info):
                            return "A directory changed while the tree was being inspected."
                    finally:
                        os.close(child_fd)
            except OSError as exc:
                return f"A directory entry could not be inspected: {exc.strerror or type(exc).__name__}."
        return None

    error = walk(directory_fd, b"", 0)
    return (None if error else digest.hexdigest()), count, total_bytes, error


def directory_action_confirmation_details(
    path: str,
    action: Literal["create_parents", "delete_recursive"],
    mode: str | None = None,
) -> tuple[DirectoryActionTarget | None, str | None, str | None]:
    if action not in {"create_parents", "delete_recursive"}:
        return None, None, "action must be 'create_parents' or 'delete_recursive'."
    lexical, error = _absolute_directory_path(path)
    if error or lexical is None:
        return None, None, error
    if action == "create_parents":
        if not isinstance(mode, str) or len(mode) not in {3, 4} or any(char not in "01234567" for char in mode):
            return None, None, "mode must be three or four octal digits from 000 through 777."
        numeric_mode = int(mode, 8)
        if numeric_mode > 0o777:
            return None, None, "Special permission bits are not supported for recursive directory creation."
        anchor_path, anchor_info, missing, error = _inspect_directory_creation(lexical)
        if error or anchor_path is None or anchor_info is None or not missing:
            return None, None, error or "No missing directory components were found."
        if len(missing) > MAX_CREATED_DIRECTORY_COMPONENTS:
            return None, None, f"A single operation may create at most {MAX_CREATED_DIRECTORY_COMPONENTS} directory components."
        prepared = DirectoryActionTarget(
            path=lexical,
            action=action,
            mode_octal=f"{numeric_mode:04o}",
            parent_device=None,
            parent_inode=None,
            entry_snapshot=None,
            tree_sha256=None,
            tree_entries=0,
            tree_bytes=0,
            anchor_path=anchor_path,
            anchor_device=anchor_info.st_dev,
            anchor_inode=anchor_info.st_ino,
            missing_components=missing,
        )
    else:
        if mode is not None:
            return None, None, "mode is used only with create_parents."
        parent = lexical.parent.resolve(strict=True)
        resolved = parent / lexical.name
        if _is_blocked_path(parent) or _is_blocked_path(resolved) or resolved == Path("/"):
            return None, None, "Recursive deletion requires one named directory outside /proc, /sys, /dev, and /run."
        parent_fd: int | None = None
        target_fd: int | None = None
        try:
            parent_fd = _open_resolved_path(parent, _PARENT_FLAGS)
            parent_info = os.fstat(parent_fd)
            entry = os.stat(resolved.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(entry.st_mode):
                return None, None, "delete_recursive operates only on a real directory and never follows symlinks."
            target_fd = os.open(resolved.name, _PARENT_FLAGS, dir_fd=parent_fd)
            opened = os.fstat(target_fd)
            if _snapshot(opened) != _snapshot(entry):
                return None, None, "The directory changed while its identity was checked."
            tree_sha, tree_entries, tree_bytes, error = _snapshot_tree_fd(target_fd)
            if error or tree_sha is None:
                return None, None, error or "The directory tree could not be summarized."
            prepared = DirectoryActionTarget(
                path=resolved,
                action=action,
                mode_octal=None,
                parent_device=parent_info.st_dev,
                parent_inode=parent_info.st_ino,
                entry_snapshot=_snapshot(opened),
                tree_sha256=tree_sha,
                tree_entries=tree_entries,
                tree_bytes=tree_bytes,
                anchor_path=None,
                anchor_device=None,
                anchor_inode=None,
                missing_components=(),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return None, None, f"The directory tree could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."
        finally:
            for fd in (target_fd, parent_fd):
                _close_target(fd)
    phrase = _phrase(
        "MKDIR" if action == "create_parents" else "RMDIR",
        {
            "path": str(prepared.path),
            "action": action,
            "mode": prepared.mode_octal,
            "anchor": [str(prepared.anchor_path), prepared.anchor_device, prepared.anchor_inode],
            "missing": prepared.missing_components,
            "parent": [prepared.parent_device, prepared.parent_inode],
            "entry": prepared.entry_snapshot,
            "tree_sha256": prepared.tree_sha256,
        },
    )
    return prepared, phrase, None


def manage_directory(
    path: str,
    action: Literal["create_parents", "delete_recursive"],
    mode: str | None = None,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> PathAdminResponse:
    prepared, phrase, error = directory_action_confirmation_details(path, action, mode)
    if error or prepared is None or phrase is None:
        return PathAdminResponse(success=False, path=path, action=action, user_confirmed=confirmed is True, message=error or "The directory operation could not be verified.")
    if confirmed is not True:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, entries_affected=prepared.tree_entries, bytes_affected=prepared.tree_bytes, mode_octal=prepared.mode_octal, message="Explicit client confirmation is required; no directory operation was performed.")
    if confirmation_phrase != phrase:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, user_confirmed=True, message="Confirmation did not match this exact directory request and current state.")
    if action == "create_parents":
        current_anchor, anchor_info, missing, error = _inspect_directory_creation(prepared.path)
        if error or current_anchor != prepared.anchor_path or not anchor_info or (anchor_info.st_dev, anchor_info.st_ino) != (prepared.anchor_device, prepared.anchor_inode) or missing != prepared.missing_components:
            return PathAdminResponse(success=False, path=str(prepared.path), action=action, user_confirmed=True, message=error or "The existing parent or missing path components changed after confirmation.")
        anchor_fd: int | None = None
        created_fds: list[int] = []
        created_count = 0
        try:
            anchor_fd = _open_resolved_path(prepared.anchor_path, _PARENT_FLAGS)
            anchor_info = os.fstat(anchor_fd)
            if (anchor_info.st_dev, anchor_info.st_ino) != (prepared.anchor_device, prepared.anchor_inode):
                raise OSError("The existing directory anchor changed after confirmation.")
            current_fd = anchor_fd
            mode_value = int(prepared.mode_octal, 8)
            for component in prepared.missing_components:
                os.mkdir(component, 0o700, dir_fd=current_fd)
                next_fd = os.open(component, _PARENT_FLAGS, dir_fd=current_fd)
                created_fds.append(next_fd)
                current_fd = next_fd
                created_count += 1
            for created_fd in reversed(created_fds):
                os.fchmod(created_fd, mode_value)
            for created_fd in created_fds:
                os.close(created_fd)
            created_fds.clear()
            return PathAdminResponse(success=True, path=str(prepared.path), action=action, entries_affected=created_count, mode_octal=prepared.mode_octal, user_confirmed=True, message="Missing directories were created and the requested path was verified.")
        except OSError as exc:
            return PathAdminResponse(success=False, path=str(prepared.path), action=action, entries_affected=created_count, mode_octal=prepared.mode_octal, user_confirmed=True, message=f"Directory creation failed after creating {created_count} component(s): {exc.strerror or type(exc).__name__}.")
        finally:
            for created_fd in created_fds:
                _close_target(created_fd)
            _close_target(anchor_fd)
    parent_fd: int | None = None
    target_fd: int | None = None
    try:
        parent_fd = _open_resolved_path(prepared.path.parent, _PARENT_FLAGS)
        parent_info = os.fstat(parent_fd)
        if (parent_info.st_dev, parent_info.st_ino) != (prepared.parent_device, prepared.parent_inode):
            raise OSError("The parent directory changed after confirmation.")
        entry = os.stat(prepared.path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _snapshot(entry) != prepared.entry_snapshot or not stat.S_ISDIR(entry.st_mode):
            raise OSError("The directory changed after confirmation.")
        if not shutil.rmtree.avoids_symlink_attacks:
            raise OSError("This Python build does not provide symlink-resistant recursive deletion.")
        target_fd = os.open(prepared.path.name, _PARENT_FLAGS, dir_fd=parent_fd)
        if _snapshot(os.fstat(target_fd)) != prepared.entry_snapshot:
            raise OSError("The opened directory changed after confirmation.")
        tree_sha, count, total_bytes, error = _snapshot_tree_fd(target_fd)
        if error or tree_sha != prepared.tree_sha256 or count != prepared.tree_entries or total_bytes != prepared.tree_bytes:
            raise OSError(error or "The directory contents changed after confirmation.")
        if _snapshot(os.fstat(target_fd)) != prepared.entry_snapshot:
            raise OSError("The directory changed during final tree verification.")
        os.close(target_fd)
        target_fd = None
        shutil.rmtree(prepared.path.name, dir_fd=parent_fd)
        try:
            os.stat(prepared.path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise OSError("The directory path remains after recursive removal.")
        os.fsync(parent_fd)
        return PathAdminResponse(success=True, path=str(prepared.path), action=action, entries_affected=prepared.tree_entries, bytes_affected=prepared.tree_bytes, user_confirmed=True, message="The confirmed directory tree was recursively removed.")
    except OSError as exc:
        return PathAdminResponse(success=False, path=str(prepared.path), action=action, entries_affected=prepared.tree_entries, bytes_affected=prepared.tree_bytes, user_confirmed=True, message=f"Recursive directory removal failed: {exc.strerror or str(exc) or type(exc).__name__}. Inspect the tree before retrying.")
    finally:
        _close_target(target_fd)
        _close_target(parent_fd)
