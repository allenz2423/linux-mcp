"""Confirmed recursive directory copy and same-filesystem move operations."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import PathAdminResponse
from wayland_mcp.tools.filesystem import MAX_PATH_LENGTH, _is_blocked_path, _open_resolved_path

DirectoryTreeAction = Literal["copy", "move"]
MAX_TREE_ENTRIES = 20_000
MAX_TREE_COPY_BYTES = 64 * 1024 * 1024 * 1024
MAX_TREE_DEPTH = 256
COPY_CHUNK_BYTES = 1024 * 1024
MAX_MOUNTINFO_BYTES = 4 * 1024 * 1024
_PARENT_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_MOUNTINFO = Path("/proc/self/mountinfo")
_RENAME_NOREPLACE = 1


def _available_capacity(directory_fd: int) -> tuple[int, int | None]:
    space = os.fstatvfs(directory_fd)
    available_bytes = max(0, space.f_bavail) * max(1, space.f_frsize or space.f_bsize)
    available_inodes = space.f_favail if space.f_favail >= 0 else None
    return available_bytes, available_inodes


@dataclass(frozen=True, slots=True)
class DirectoryTreeTarget:
    action: DirectoryTreeAction
    source: Path
    destination: Path
    source_parent_device: int
    source_parent_inode: int
    source_snapshot: tuple[int, ...]
    destination_parent_device: int
    destination_parent_inode: int
    tree_sha256: str
    entries: int
    bytes_total: int


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


def _clean_path(value: object) -> tuple[Path | None, str | None]:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_PATH_LENGTH:
        return None, f"Path must be non-empty text with at most {MAX_PATH_LENGTH} characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None, "Paths cannot contain control characters."
    try:
        raw = Path(value).expanduser()
        if not raw.is_absolute():
            return None, "Paths must be absolute; '~' is expanded to the current user's home directory."
        lexical = Path(os.path.abspath(raw))
        if not lexical.name or lexical.name in {".", ".."} or _is_blocked_path(lexical):
            return None, "Directory-tree operations require named paths outside /proc, /sys, /dev, and /run."
        parent = lexical.parent.resolve(strict=True)
        resolved = parent / lexical.name
        if _is_blocked_path(parent) or _is_blocked_path(resolved):
            return None, "Paths under /proc, /sys, /dev, and /run are excluded from general filesystem tools."
        return resolved, None
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"The path could not be resolved safely: {getattr(exc, 'strerror', None) or type(exc).__name__}."


def _decode_mount_field(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _mountpoints() -> set[Path] | None:
    try:
        with _MOUNTINFO.open("rb") as stream:
            data = stream.read(MAX_MOUNTINFO_BYTES + 1)
        if len(data) > MAX_MOUNTINFO_BYTES:
            return None
        text = data.decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None
    result: set[Path] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            return None
        path_text = _decode_mount_field(fields[4])
        if not path_text.startswith("/") or any(ord(character) < 32 or ord(character) == 127 for character in path_text):
            return None
        result.add(Path(path_text))
    return result


def _inspect_tree(root_fd: int, root_device: int, *, max_bytes: int | None = MAX_TREE_COPY_BYTES) -> tuple[str | None, int, int, str | None]:
    digest = hashlib.sha256()
    entries = 0
    bytes_total = 0

    def walk(directory_fd: int, relative: bytes, depth: int) -> str | None:
        nonlocal entries, bytes_total
        if depth > MAX_TREE_DEPTH:
            return f"The directory tree exceeds the {MAX_TREE_DEPTH}-level depth limit."
        try:
            names = sorted(os.listdir(directory_fd), key=os.fsencode)
        except OSError as exc:
            return f"A source directory could not be scanned: {exc.strerror or type(exc).__name__}."
        for name in names:
            try:
                encoded_name = os.fsencode(name)
                relative_path = relative + (b"/" if relative else b"") + encoded_name
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if info.st_dev != root_device:
                    return "The source tree crosses a filesystem boundary or mounted device."
                entries += 1
                if entries > MAX_TREE_ENTRIES:
                    return f"The directory tree exceeds the {MAX_TREE_ENTRIES}-entry limit."
                digest.update(len(relative_path).to_bytes(4, "big"))
                digest.update(relative_path)
                digest.update(repr(_snapshot(info)).encode("ascii"))
                if stat.S_ISREG(info.st_mode):
                    bytes_total += max(0, info.st_size)
                    if max_bytes is not None and bytes_total > max_bytes:
                        return f"The regular-file data exceeds the {max_bytes}-byte recursive-copy limit."
                    digest.update(b"F")
                elif stat.S_ISLNK(info.st_mode):
                    target = os.readlink(name, dir_fd=directory_fd)
                    target_bytes = os.fsencode(target)
                    digest.update(b"L")
                    digest.update(len(target_bytes).to_bytes(4, "big"))
                    digest.update(target_bytes)
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if _snapshot(after) != _snapshot(info):
                        return "A symbolic link changed while the source tree was inspected."
                elif stat.S_ISDIR(info.st_mode):
                    digest.update(b"D")
                    child_fd = os.open(name, _PARENT_FLAGS, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(child_fd)
                        if _snapshot(opened) != _snapshot(info):
                            return "A source directory changed while its identity was checked."
                        error = walk(child_fd, relative_path, depth + 1)
                        if error:
                            return error
                        if _snapshot(os.fstat(child_fd)) != _snapshot(info):
                            return "A source directory changed while the tree was inspected."
                    finally:
                        os.close(child_fd)
                else:
                    return "Recursive copy/move supports only directories, regular files, and symbolic links; special files are refused."
            except OSError as exc:
                return f"A source entry could not be inspected: {exc.strerror or type(exc).__name__}."
        return None

    error = walk(root_fd, b"", 0)
    return (None if error else digest.hexdigest()), entries, bytes_total, error


def directory_tree_action_confirmation_details(
    action: str,
    source_path: str,
    destination_path: str,
) -> tuple[DirectoryTreeTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Recursive directory copy/move is available only on Linux."
    if not isinstance(action, str) or action not in {"copy", "move"}:
        return None, None, "action must be 'copy' or 'move'."
    source, error = _clean_path(source_path)
    if error or source is None:
        return None, None, error or "The source directory path could not be verified."
    destination, error = _clean_path(destination_path)
    if error or destination is None:
        return None, None, error or "The destination path could not be verified."
    if source == destination:
        return None, None, "The source and destination paths must differ."
    if source == Path("/") or source in destination.parent.parents or source == destination.parent:
        return None, None, "A directory cannot be copied or moved into itself or one of its descendants."

    source_parent_fd: int | None = None
    destination_parent_fd: int | None = None
    source_fd: int | None = None
    try:
        source_parent_fd = _open_resolved_path(source.parent, _PARENT_FLAGS)
        destination_parent_fd = _open_resolved_path(destination.parent, _PARENT_FLAGS)
        source_parent_info = os.fstat(source_parent_fd)
        destination_parent_info = os.fstat(destination_parent_fd)
        try:
            source_entry = os.stat(source.name, dir_fd=source_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None, None, "The exact source directory does not exist."
        if not stat.S_ISDIR(source_entry.st_mode):
            return None, None, "The source must be a real directory; symbolic links are not followed."
        source_fd = os.open(source.name, _PARENT_FLAGS, dir_fd=source_parent_fd)
        opened = os.fstat(source_fd)
        if _snapshot(opened) != _snapshot(source_entry):
            return None, None, "The source directory changed while its identity was checked."
        try:
            os.stat(destination.name, dir_fd=destination_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            return None, None, "The destination already exists; recursive copy/move never overwrites a path."

        mounts = _mountpoints()
        if mounts is None:
            return None, None, "Mounted paths could not be checked safely."
        nested_mounts = {mount for mount in mounts if mount != source and source in mount.parents}
        if nested_mounts:
            return None, None, "The source tree contains a nested mount point; recursive copy/move refuses to cross it."
        if action == "move" and source in mounts:
            return None, None, "Moving a mounted directory is refused."

        tree_sha, entries, bytes_total, error = _inspect_tree(
            source_fd,
            opened.st_dev,
            max_bytes=MAX_TREE_COPY_BYTES if action == "copy" else None,
        )
        if error or tree_sha is None:
            return None, None, error or "The source directory tree could not be summarized."
        if action == "copy":
            available_bytes, available_inodes = _available_capacity(destination_parent_fd)
            if available_bytes < bytes_total:
                return None, None, (
                    f"The destination filesystem currently has {available_bytes} available bytes, but the copy needs "
                    f"approximately {bytes_total}; other processes can change available space after this check."
                )
            required_inodes = entries + 1  # One new inode per entry plus the destination root; internal hard links reduce this.
            if available_inodes is not None and available_inodes < required_inodes:
                return None, None, (
                    f"The destination filesystem currently has {available_inodes} available inodes, but the copy may "
                    f"need up to {required_inodes}; other processes can consume inodes after this check."
                )
        if action == "move" and opened.st_dev != destination_parent_info.st_dev:
            return None, None, "Move is limited to the same filesystem; use copy followed by a separately confirmed deletion across filesystems."
        target = DirectoryTreeTarget(
            action=action,  # type: ignore[arg-type]
            source=source,
            destination=destination,
            source_parent_device=source_parent_info.st_dev,
            source_parent_inode=source_parent_info.st_ino,
            source_snapshot=_snapshot(opened),
            destination_parent_device=destination_parent_info.st_dev,
            destination_parent_inode=destination_parent_info.st_ino,
            tree_sha256=tree_sha,
            entries=entries,
            bytes_total=bytes_total,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return None, None, f"The directory tree operation could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."
    finally:
        for fd in (source_fd, source_parent_fd, destination_parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    material = {
        "action": target.action,
        "source": str(target.source),
        "destination": str(target.destination),
        "source_parent": [target.source_parent_device, target.source_parent_inode],
        "source_snapshot": target.source_snapshot,
        "destination_parent": [target.destination_parent_device, target.destination_parent_inode],
        "tree_sha256": target.tree_sha256,
        "entries": target.entries,
        "bytes_total": target.bytes_total,
    }
    prefix = "COPYTREE" if action == "copy" else "MOVETREE"
    encoded_material = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    phrase = f"{prefix} {hashlib.sha256(encoded_material).hexdigest()[:16]}"
    return target, phrase, None


def _rename_noreplace(source_parent_fd: int, source_name: str, destination_parent_fd: int, destination_name: str) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        raise OSError(errno.ENOSYS, "atomic no-overwrite rename is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(source_parent_fd, os.fsencode(source_name), destination_parent_fd, os.fsencode(destination_name), _RENAME_NOREPLACE)
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write while copying a file")
        view = view[written:]


def _open_destination_parent(root_fd: int, components: tuple[str, ...]) -> tuple[int, str]:
    """Open a copied relative path's parent without following symlinks."""
    if not components:
        raise OSError(errno.EINVAL, "empty relative file path")
    current_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            child_fd = os.open(component, _PARENT_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
        return current_fd, components[-1]
    except OSError:
        os.close(current_fd)
        raise


def _finalize_directory_metadata(
    root_fd: int,
    metadata: dict[tuple[str, ...], tuple[int, int]],
) -> None:
    """Apply directory modes and mtimes bottom-up after all links are created."""
    for components, (mode, modified_ns) in sorted(metadata.items(), key=lambda item: (len(item[0]), item[0]), reverse=True):
        if not components:
            directory_fd = os.dup(root_fd)
        else:
            parent_fd, name = _open_destination_parent(root_fd, components)
            try:
                directory_fd = os.open(name, _PARENT_FLAGS, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        try:
            info = os.fstat(directory_fd)
            os.fchmod(directory_fd, mode)
            os.utime(directory_fd, ns=(info.st_atime_ns, modified_ns))
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def _remove_tree_contents(directory_fd: int) -> None:
    for name in os.listdir(directory_fd):
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            # A copied source mode can remove access before a later failure.
            os.chmod(name, 0o700, dir_fd=directory_fd, follow_symlinks=False)
            child_fd = os.open(name, _PARENT_FLAGS, dir_fd=directory_fd)
            try:
                _remove_tree_contents(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)


def _cleanup_stage(parent_fd: int, stage_name: str) -> None:
    info = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        os.unlink(stage_name, dir_fd=parent_fd)
        return
    os.chmod(stage_name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
    root_fd = os.open(stage_name, _PARENT_FLAGS, dir_fd=parent_fd)
    try:
        _remove_tree_contents(root_fd)
    finally:
        os.close(root_fd)
    os.rmdir(stage_name, dir_fd=parent_fd)


def _copy_contents(
    source_fd: int,
    destination_fd: int,
    destination_root_fd: int,
    source_device: int,
    depth: int,
    counters: list[int],
    relative_directory: tuple[str, ...],
    hardlinks: dict[tuple[int, int], tuple[tuple[str, ...], tuple[int, ...]]],
    directory_metadata: dict[tuple[str, ...], tuple[int, int]],
) -> None:
    if depth > MAX_TREE_DEPTH:
        raise OSError(errno.ELOOP, "directory tree depth changed during copy")
    for name in sorted(os.listdir(source_fd), key=os.fsencode):
        before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        if before.st_dev != source_device:
            raise OSError(errno.EXDEV, "source tree crossed a filesystem boundary during copy")
        counters[0] += 1
        if counters[0] > MAX_TREE_ENTRIES:
            raise OSError(errno.E2BIG, "directory tree exceeded its entry limit during copy")
        relative_path = relative_directory + (name,)
        if stat.S_ISREG(before.st_mode):
            source_key = (before.st_dev, before.st_ino)
            previous_link = hardlinks.get(source_key)
            if previous_link is not None:
                previous_path, previous_snapshot = previous_link
                if previous_snapshot != _snapshot(before):
                    raise OSError(errno.ESTALE, "a hard-linked source file changed between directory entries")
                previous_parent_fd, previous_name = _open_destination_parent(destination_root_fd, previous_path)
                try:
                    os.link(
                        previous_name,
                        name,
                        src_dir_fd=previous_parent_fd,
                        dst_dir_fd=destination_fd,
                        follow_symlinks=False,
                    )
                    previous_info = os.stat(previous_name, dir_fd=previous_parent_fd, follow_symlinks=False)
                    linked_info = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
                    if (previous_info.st_dev, previous_info.st_ino) != (linked_info.st_dev, linked_info.st_ino):
                        raise OSError(errno.ESTALE, "the copied hard-link relationship could not be verified")
                finally:
                    os.close(previous_parent_fd)
                counters[1] += before.st_size
                if counters[1] > MAX_TREE_COPY_BYTES:
                    raise OSError(errno.EFBIG, "source data exceeded the recursive-copy byte limit")
                continue
            source_file_fd = os.open(name, _READ_FLAGS, dir_fd=source_fd)
            destination_file_fd: int | None = None
            try:
                if _snapshot(os.fstat(source_file_fd)) != _snapshot(before):
                    raise OSError(errno.ESTALE, "source file changed before it was copied")
                destination_file_fd = os.open(name, _WRITE_FLAGS, 0o600, dir_fd=destination_fd)
                copied = 0
                while True:
                    chunk = os.read(source_file_fd, COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    copied += len(chunk)
                    counters[1] += len(chunk)
                    if counters[1] > MAX_TREE_COPY_BYTES:
                        raise OSError(errno.EFBIG, "source data exceeded the recursive-copy byte limit")
                    _write_all(destination_file_fd, chunk)
                if copied != before.st_size or _snapshot(os.fstat(source_file_fd)) != _snapshot(before):
                    raise OSError(errno.ESTALE, "source file changed while it was copied")
                os.fchmod(destination_file_fd, stat.S_IMODE(before.st_mode) & 0o777)
                destination_info = os.fstat(destination_file_fd)
                os.utime(destination_file_fd, ns=(destination_info.st_atime_ns, before.st_mtime_ns))
                os.fsync(destination_file_fd)
            finally:
                if destination_file_fd is not None:
                    os.close(destination_file_fd)
                os.close(source_file_fd)
            hardlinks[source_key] = (relative_path, _snapshot(before))
        elif stat.S_ISDIR(before.st_mode):
            os.mkdir(name, 0o700, dir_fd=destination_fd)
            directory_metadata[relative_path] = (stat.S_IMODE(before.st_mode) & 0o777, before.st_mtime_ns)
            source_child_fd = os.open(name, _PARENT_FLAGS, dir_fd=source_fd)
            destination_child_fd = os.open(name, _PARENT_FLAGS, dir_fd=destination_fd)
            try:
                if _snapshot(os.fstat(source_child_fd)) != _snapshot(before):
                    raise OSError(errno.ESTALE, "source directory changed before it was copied")
                _copy_contents(
                    source_child_fd,
                    destination_child_fd,
                    destination_root_fd,
                    source_device,
                    depth + 1,
                    counters,
                    relative_path,
                    hardlinks,
                    directory_metadata,
                )
                if _snapshot(os.fstat(source_child_fd)) != _snapshot(before):
                    raise OSError(errno.ESTALE, "source directory changed while it was copied")
            finally:
                os.close(source_child_fd)
                os.close(destination_child_fd)
        elif stat.S_ISLNK(before.st_mode):
            link_target = os.readlink(name, dir_fd=source_fd)
            if _snapshot(os.stat(name, dir_fd=source_fd, follow_symlinks=False)) != _snapshot(before):
                raise OSError(errno.ESTALE, "source symbolic link changed while it was copied")
            os.symlink(link_target, name, dir_fd=destination_fd)
            destination_info = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
            os.utime(
                name,
                dir_fd=destination_fd,
                ns=(destination_info.st_atime_ns, before.st_mtime_ns),
                follow_symlinks=False,
            )
        else:
            raise OSError(errno.EOPNOTSUPP, "special files are not copied")


def manage_directory_tree(
    action: DirectoryTreeAction,
    source_path: str,
    destination_path: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> PathAdminResponse:
    target, phrase, error = directory_tree_action_confirmation_details(action, source_path, destination_path)
    if error or target is None or phrase is None:
        return PathAdminResponse(success=False, path=destination_path, action=action, user_confirmed=confirmed is True, message=error or "The directory tree operation could not be verified.")
    if confirmed is not True:
        return PathAdminResponse(success=False, path=str(target.destination), action=action, entries_affected=target.entries, bytes_affected=target.bytes_total, message="Explicit client confirmation is required; no directory tree operation was performed.")
    if confirmation_phrase != phrase:
        return PathAdminResponse(success=False, path=str(target.destination), action=action, user_confirmed=True, message="Confirmation did not match the exact source, destination, and tree state.")
    current, current_phrase, error = directory_tree_action_confirmation_details(action, source_path, destination_path)
    if error or current is None or current_phrase != phrase:
        return PathAdminResponse(success=False, path=str(target.destination), action=action, user_confirmed=True, message=error or "The source tree or destination state changed after confirmation; no operation was performed.")

    source_parent_fd: int | None = None
    destination_parent_fd: int | None = None
    source_fd: int | None = None
    stage_fd: int | None = None
    stage_name: str | None = None
    published = False
    try:
        source_parent_fd = _open_resolved_path(target.source.parent, _PARENT_FLAGS)
        destination_parent_fd = _open_resolved_path(target.destination.parent, _PARENT_FLAGS)
        source_parent_info = os.fstat(source_parent_fd)
        destination_parent_info = os.fstat(destination_parent_fd)
        if (source_parent_info.st_dev, source_parent_info.st_ino) != (target.source_parent_device, target.source_parent_inode):
            raise OSError(errno.ESTALE, "source parent changed after confirmation")
        if (destination_parent_info.st_dev, destination_parent_info.st_ino) != (target.destination_parent_device, target.destination_parent_inode):
            raise OSError(errno.ESTALE, "destination parent changed after confirmation")
        source_entry = os.stat(target.source.name, dir_fd=source_parent_fd, follow_symlinks=False)
        source_fd = os.open(target.source.name, _PARENT_FLAGS, dir_fd=source_parent_fd)
        if _snapshot(source_entry) != target.source_snapshot or _snapshot(os.fstat(source_fd)) != target.source_snapshot:
            raise OSError(errno.ESTALE, "source directory changed after confirmation")
        tree_sha, entries, bytes_total, error = _inspect_tree(
            source_fd,
            source_entry.st_dev,
            max_bytes=MAX_TREE_COPY_BYTES if action == "copy" else None,
        )
        if error or tree_sha != target.tree_sha256 or entries != target.entries or bytes_total != target.bytes_total:
            raise OSError(errno.ESTALE, error or "source tree changed after confirmation")
        if action == "copy":
            available_bytes, available_inodes = _available_capacity(destination_parent_fd)
            if available_bytes < target.bytes_total:
                raise OSError(errno.ENOSPC, "the destination filesystem no longer has enough currently available bytes for the confirmed copy")
            if available_inodes is not None and available_inodes < target.entries + 1:
                raise OSError(errno.ENOSPC, "the destination filesystem no longer has enough currently available inodes for the confirmed copy")
        try:
            os.stat(target.destination.name, dir_fd=destination_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise OSError(errno.EEXIST, "destination appeared after confirmation")
    except OSError as exc:
        for fd in (source_fd, source_parent_fd, destination_parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        return PathAdminResponse(success=False, path=str(target.destination), action=action, entries_affected=target.entries, bytes_affected=target.bytes_total, user_confirmed=True, message=f"The source/destination changed after confirmation: {exc.strerror or str(exc) or type(exc).__name__}.")

    try:
        if action == "move":
            # Do not overwrite an entry created after preflight.
            current_source = os.stat(target.source.name, dir_fd=source_parent_fd, follow_symlinks=False)
            if _snapshot(current_source) != target.source_snapshot:
                raise OSError(errno.ESTALE, "source path changed after confirmation")
            _rename_noreplace(source_parent_fd, target.source.name, destination_parent_fd, target.destination.name)
            published = True
            moved = os.stat(target.destination.name, dir_fd=destination_parent_fd, follow_symlinks=False)
            if (moved.st_dev, moved.st_ino) != target.source_snapshot[:2]:
                raise OSError(errno.ESTALE, "the moved directory identity could not be verified")
            try:
                os.stat(target.source.name, dir_fd=source_parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise OSError(errno.ESTALE, "the source path remains after the move")
            os.fsync(source_parent_fd)
            if (source_parent_info.st_dev, source_parent_info.st_ino) != (destination_parent_info.st_dev, destination_parent_info.st_ino):
                os.fsync(destination_parent_fd)
            message = "The exact directory tree was moved on the same filesystem; its existing ownership and metadata were preserved."
        else:
            for _ in range(8):
                candidate = f".linux-mcp-copy-{secrets.token_hex(12)}"
                try:
                    os.mkdir(candidate, 0o700, dir_fd=destination_parent_fd)
                    stage_name = candidate
                    break
                except FileExistsError:
                    continue
            if stage_name is None:
                raise OSError(errno.EEXIST, "could not allocate a private temporary directory")
            stage_fd = os.open(stage_name, _PARENT_FLAGS, dir_fd=destination_parent_fd)
            stage_identity = _snapshot(os.fstat(stage_fd))
            counters = [0, 0]
            hardlinks: dict[tuple[int, int], tuple[tuple[str, ...], tuple[int, ...]]] = {}
            directory_metadata = {
                (): (stat.S_IMODE(source_entry.st_mode) & 0o777, source_entry.st_mtime_ns)
            }
            _copy_contents(
                source_fd,
                stage_fd,
                stage_fd,
                source_entry.st_dev,
                0,
                counters,
                (),
                hardlinks,
                directory_metadata,
            )
            _finalize_directory_metadata(stage_fd, directory_metadata)
            if counters[0] != target.entries or counters[1] != target.bytes_total:
                raise OSError(errno.ESTALE, "the copied entry or byte count changed")
            final_tree, final_entries, final_bytes, error = _inspect_tree(source_fd, source_entry.st_dev)
            if error or final_tree != target.tree_sha256 or final_entries != target.entries or final_bytes != target.bytes_total:
                raise OSError(errno.ESTALE, error or "source tree changed during copy")
            current_source = os.stat(target.source.name, dir_fd=source_parent_fd, follow_symlinks=False)
            if _snapshot(current_source) != target.source_snapshot:
                raise OSError(errno.ESTALE, "source path changed during copy")
            staged_root = os.fstat(stage_fd)
            if (staged_root.st_dev, staged_root.st_ino) != stage_identity[:2]:
                raise OSError(errno.ESTALE, "the staged destination root changed during copy")
            os.close(stage_fd)
            stage_fd = None
            _rename_noreplace(destination_parent_fd, stage_name, destination_parent_fd, target.destination.name)
            published = True
            stage_name = None
            destination_info = os.stat(target.destination.name, dir_fd=destination_parent_fd, follow_symlinks=False)
            if (destination_info.st_dev, destination_info.st_ino) != (stage_identity[0], stage_identity[1]):
                raise OSError(errno.ESTALE, "the published directory identity could not be verified")
            os.fsync(destination_parent_fd)
            message = "The directory tree was copied and atomically published. Regular files, directories, symbolic-link targets, rwx modes, hard-link relationships within the tree, and modification times were copied. Ownership, ACLs, xattrs, access times, and special files were not copied."
        return PathAdminResponse(success=True, path=str(target.destination), action=action, entries_affected=target.entries, bytes_affected=target.bytes_total, user_confirmed=True, message=message)
    except OSError as exc:
        cleanup_error: str | None = None
        if stage_name is not None and destination_parent_fd is not None:
            try:
                if stage_fd is not None:
                    os.close(stage_fd)
                    stage_fd = None
                _cleanup_stage(destination_parent_fd, stage_name)
            except OSError as cleanup_exc:
                cleanup_error = cleanup_exc.strerror or str(cleanup_exc) or type(cleanup_exc).__name__
        detail = "The directory tree was published but post-action verification or syncing failed; inspect the destination." if published else "The recursive directory operation failed; the source was retained."
        if cleanup_error and stage_name is not None:
            detail += f" Temporary staging data may remain at {target.destination.parent / stage_name}; cleanup failed: {cleanup_error}."
        return PathAdminResponse(success=False, path=str(target.destination), action=action, entries_affected=target.entries, bytes_affected=target.bytes_total, user_confirmed=True, message=f"{detail} {exc.strerror or str(exc) or type(exc).__name__}.")
    finally:
        for fd in (stage_fd, source_fd, source_parent_fd, destination_parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
