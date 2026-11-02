"""Bounded Btrfs snapshot inventory and confirmation-gated snapshot actions."""

from __future__ import annotations

import hashlib
import json
import ctypes
import errno
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from wayland_mcp.models import BtrfsSnapshotActionResponse, BtrfsSnapshotListResponse, BtrfsSnapshotInfo
from wayland_mcp.session import find_session_binary, get_sanitized_env

BtrfsSnapshotAction = Literal["create", "delete", "restore"]
MAX_PATH_LENGTH = 4096
MAX_SUBVOLUME_OUTPUT_BYTES = 1024 * 1024
MAX_PROC_MOUNTINFO_BYTES = 4 * 1024 * 1024
MAX_SUBVOLUME_SCAN = 5000
MAX_RETURNED_SNAPSHOTS = 100
READ_TIMEOUT_SECONDS = 20
ACTION_TIMEOUT_SECONDS = 180
MOUNTINFO = Path("/proc/self/mountinfo")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SUBVOLUME_LINE_RE = re.compile(
    r"^ID (?P<id>[0-9]+) gen (?P<generation>[0-9]+) parent (?P<parent_id>[0-9]+) "
    r"top level (?P<top_level_id>[0-9]+) parent_uuid (?P<parent_uuid>\S+) "
    r"received_uuid (?P<received_uuid>\S+) uuid (?P<uuid>\S+) path (?P<path>.*)$"
)


@dataclass(frozen=True, slots=True)
class BtrfsSubvolume:
    path: Path
    relative_path: str
    subvolume_id: int
    generation: int
    parent_id: int
    top_level_id: int
    uuid: str
    parent_uuid: str
    received_uuid: str
    read_only: bool
    stat_identity: tuple[int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class BtrfsSnapshotTarget:
    action: BtrfsSnapshotAction
    filesystem_top_level_path: Path
    filesystem_top_level_identity: tuple[int, int, int, int, int]
    snapshot_path: Path
    snapshot_relative_path: str
    source: BtrfsSubvolume | None
    snapshot: BtrfsSubvolume | None
    restore_target: BtrfsSubvolume | None
    backup_path: Path | None
    stage_path: Path | None
    restore_parent_identity: tuple[int, int, int, int, int] | None
    read_only: bool
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def btrfs_snapshot_tools_available(env: dict[str, str] | None = None) -> bool:
    return sys.platform.startswith("linux") and find_session_binary("btrfs", env or _environment()) is not None


def _run_read(command: list[str], *, timeout: int = READ_TIMEOUT_SECONDS) -> tuple[int, str] | None:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if len(completed.stdout) > MAX_SUBVOLUME_OUTPUT_BYTES:
        return None
    try:
        return completed.returncode, completed.stdout.decode("utf-8", errors="strict")
    except UnicodeError:
        return None


def _run_mutation(command: list[str]) -> bool:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=ACTION_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _clean_absolute_path(value: object, *, must_exist: bool) -> tuple[Path | None, str | None]:
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_LENGTH:
        return None, "Paths must be non-empty absolute paths with at most 4096 characters."
    if not value.startswith("/") or any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None, "Paths must be absolute and cannot contain control characters."
    supplied = Path(value)
    if ".." in supplied.parts:
        return None, "Paths containing '..' are not accepted."
    lexical = Path(os.path.abspath(value))
    try:
        if must_exist:
            resolved = supplied.resolve(strict=True)
        else:
            if not lexical.name or lexical.name in {".", ".."}:
                return None, "A destination path must name a new subvolume below an existing directory."
            resolved_parent = lexical.parent.resolve(strict=True)
            if resolved_parent != lexical.parent:
                return None, "Symbolic links in destination parent paths are not accepted."
            resolved = resolved_parent / lexical.name
    except (OSError, RuntimeError, ValueError):
        return None, "The path could not be resolved safely."
    if resolved != lexical:
        return None, "Symbolic links in Btrfs paths are not accepted."
    return resolved, None


def _stat_identity(path: Path) -> tuple[int, int, int, int, int] | None:
    try:
        info = path.stat()
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        return None
    return info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_ctime_ns, info.st_mtime_ns


def _btrfs_binary() -> str | None:
    return find_session_binary("btrfs", _environment())


def _root_id(path: Path) -> int | None:
    binary = _btrfs_binary()
    if not binary:
        return None
    result = _run_read([binary, "inspect-internal", "rootid", str(path)])
    if result is None or result[0] != 0:
        return None
    value = result[1].strip()
    if not value.isdecimal():
        return None
    return int(value, 10)


def _parse_show(path: Path) -> dict[str, object] | None:
    binary = _btrfs_binary()
    if not binary:
        return None
    result = _run_read([binary, "subvolume", "show", str(path)])
    if result is None or result[0] != 0:
        return None
    fields: dict[str, str] = {}
    for line in result[1].splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip().casefold()] = value.strip()
    uuid = fields.get("uuid", "")
    parent_uuid = fields.get("parent uuid", "")
    received_uuid = fields.get("received uuid", "")
    subvolume_id = fields.get("subvolume id", "")
    generation = fields.get("generation", "")
    parent_id = fields.get("parent id", "")
    top_level_id = fields.get("top level id", "")
    flags = fields.get("flags", "")
    if (
        not UUID_RE.fullmatch(uuid)
        or (parent_uuid != "-" and not UUID_RE.fullmatch(parent_uuid))
        or (received_uuid != "-" and not UUID_RE.fullmatch(received_uuid))
        or not subvolume_id.isdecimal()
        or not generation.isdecimal()
        or not parent_id.isdecimal()
        or not top_level_id.isdecimal()
        or not flags
    ):
        return None
    flag_values = {item.casefold() for item in re.split(r"[\s,]+", flags) if item and item != "-"}
    return {
        "subvolume_id": int(subvolume_id, 10),
        "generation": int(generation, 10),
        "parent_id": int(parent_id, 10),
        "top_level_id": int(top_level_id, 10),
        "uuid": uuid.lower(),
        "parent_uuid": parent_uuid.lower() if parent_uuid != "-" else "-",
        "received_uuid": received_uuid.lower() if received_uuid != "-" else "-",
        "read_only": "readonly" in flag_values or "ro" in flag_values,
    }


def _top_level_root(raw_path: object) -> tuple[Path | None, tuple[int, int, int, int, int] | None, str | None]:
    path, error = _clean_absolute_path(raw_path, must_exist=True)
    if error or path is None:
        return None, None, error or "The Btrfs top-level path could not be resolved."
    identity = _stat_identity(path)
    if identity is None or identity[1] != 256:
        return None, None, "filesystem_top_level_path must be the mounted Btrfs top-level subvolume (inode 256)."
    root_id = _root_id(path)
    if root_id != 5:
        return None, None, "filesystem_top_level_path must resolve to Btrfs subvolume ID 5."
    details = _parse_show(path)
    if details is None or details["subvolume_id"] != 5:
        return None, None, "Btrfs top-level subvolume identity could not be verified."
    return path, identity, None


def _relative_to_root(path: Path, root: Path) -> str | None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    text = relative.as_posix()
    if text in {"", "."}:
        return None
    return text


def _subvolume_from_path(
    path: Path,
    relative_path: str,
    *,
    require_root: bool = True,
) -> tuple[BtrfsSubvolume | None, str | None]:
    identity = _stat_identity(path)
    if identity is None:
        return None, "The Btrfs subvolume directory could not be verified."
    if require_root and identity[1] != 256:
        return None, "The selected path is not the root of a Btrfs subvolume."
    details = _parse_show(path)
    if details is None:
        return None, "Btrfs subvolume metadata could not be read safely."
    root_id = _root_id(path)
    if root_id is None or root_id != details["subvolume_id"]:
        return None, "The Btrfs subvolume ID could not be verified."
    return (
        BtrfsSubvolume(
            path=path,
            relative_path=relative_path,
            subvolume_id=int(details["subvolume_id"]),
            generation=int(details["generation"]),
            parent_id=int(details["parent_id"]),
            top_level_id=int(details["top_level_id"]),
            uuid=str(details["uuid"]),
            parent_uuid=str(details["parent_uuid"]),
            received_uuid=str(details["received_uuid"]),
            read_only=bool(details["read_only"]),
            stat_identity=identity,
        ),
        None,
    )


def _parse_subvolume_list(text: str) -> tuple[list[dict[str, object]], bool]:
    rows: list[dict[str, object]] = []
    partial = False
    for line in text.splitlines():
        if not line:
            continue
        match = SUBVOLUME_LINE_RE.fullmatch(line)
        if not match:
            partial = True
            continue
        relative_text = match.group("path")
        relative = PurePosixPath(relative_text)
        if (
            not relative_text
            or relative.is_absolute()
            or ".." in relative.parts
            or any(ord(character) < 32 or ord(character) == 127 for character in relative_text)
        ):
            partial = True
            continue
        parent_uuid = match.group("parent_uuid")
        received_uuid = match.group("received_uuid")
        uuid = match.group("uuid")
        if (
            (parent_uuid != "-" and not UUID_RE.fullmatch(parent_uuid))
            or (received_uuid != "-" and not UUID_RE.fullmatch(received_uuid))
            or not UUID_RE.fullmatch(uuid)
        ):
            partial = True
            continue
        rows.append(
            {
                "subvolume_id": int(match.group("id"), 10),
                "generation": int(match.group("generation"), 10),
                "parent_id": int(match.group("parent_id"), 10),
                "top_level_id": int(match.group("top_level_id"), 10),
                "parent_uuid": parent_uuid.lower() if parent_uuid != "-" else "-",
                "received_uuid": received_uuid.lower() if received_uuid != "-" else "-",
                "uuid": uuid.lower() if uuid != "-" else "-",
                "relative_path": relative.as_posix(),
            }
        )
    return rows, partial


def _read_subvolume_rows(root: Path, *, readonly_only: bool) -> tuple[list[dict[str, object]] | None, str | None]:
    binary = _btrfs_binary()
    if not binary:
        return None, "The btrfs-progs 'btrfs' command is required."
    command = [binary, "subvolume", "list"]
    if readonly_only:
        command.append("-r")
    command.extend(["-p", "-u", "-q", "-R", str(root)])
    result = _run_read(command)
    if result is None:
        return None, "The Btrfs subvolume inventory command failed or exceeded its bounded output/time limit."
    if result[0] != 0:
        return None, "The Btrfs subvolume inventory could not be read with current OS permissions."
    rows, partial = _parse_subvolume_list(result[1])
    if partial:
        return None, "The Btrfs subvolume inventory used an unrecognized or unsafe output row."
    return rows, None


def list_btrfs_snapshots(
    filesystem_top_level_path: str,
    query: str = "",
    limit: int = 100,
    offset: int = 0,
) -> BtrfsSnapshotListResponse:
    if not sys.platform.startswith("linux"):
        return BtrfsSnapshotListResponse(success=False, message="Btrfs snapshot inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return BtrfsSnapshotListResponse(success=False, message="query must be text with at most 256 characters.")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_RETURNED_SNAPSHOTS:
        return BtrfsSnapshotListResponse(success=False, message=f"limit must be between 1 and {MAX_RETURNED_SNAPSHOTS}.")
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_SUBVOLUME_SCAN:
        return BtrfsSnapshotListResponse(success=False, message=f"offset must be between 0 and {MAX_SUBVOLUME_SCAN}.")
    if not btrfs_snapshot_tools_available():
        return BtrfsSnapshotListResponse(success=False, message="The btrfs-progs 'btrfs' command is required.")
    root, _, error = _top_level_root(filesystem_top_level_path)
    if error or root is None:
        return BtrfsSnapshotListResponse(success=False, message=error or "The Btrfs top-level path could not be verified.")

    rows, error = _read_subvolume_rows(root, readonly_only=False)
    readonly_rows, readonly_error = _read_subvolume_rows(root, readonly_only=True)
    if error or rows is None or readonly_error or readonly_rows is None:
        return BtrfsSnapshotListResponse(
            success=False,
            filesystem_top_level_path=str(root),
            limit=limit,
            offset=offset,
            message=error or readonly_error or "The Btrfs snapshot inventory could not be read.",
        )
    snapshot_rows = [
        row for row in rows
        if row["parent_uuid"] != "-" or row["received_uuid"] != "-"
    ]
    readonly_ids = {int(row["subvolume_id"]) for row in readonly_rows}
    inventory_by_id = {int(row["subvolume_id"]): row for row in rows}
    state_partial = any(
        int(row["subvolume_id"]) not in inventory_by_id
        or row["generation"] != inventory_by_id[int(row["subvolume_id"])]["generation"]
        or row["uuid"] != inventory_by_id[int(row["subvolume_id"])]["uuid"]
        for row in readonly_rows
    )
    scan_truncated = len(snapshot_rows) > MAX_SUBVOLUME_SCAN
    snapshot_rows = snapshot_rows[:MAX_SUBVOLUME_SCAN]
    needle = query.casefold()
    matching_rows = [
        row for row in snapshot_rows
        if not needle or needle in str(row["relative_path"]).casefold() or needle in str(row["uuid"]).casefold()
    ]
    snapshots = [
        BtrfsSnapshotInfo(
            path=str(root / str(row["relative_path"])),
            relative_path=str(row["relative_path"]),
            subvolume_id=int(row["subvolume_id"]),
            generation=int(row["generation"]),
            parent_id=int(row["parent_id"]),
            top_level_id=int(row["top_level_id"]),
            uuid=str(row["uuid"]),
            parent_uuid=str(row["parent_uuid"]),
            received_uuid=str(row["received_uuid"]),
            read_only=int(row["subvolume_id"]) in readonly_ids,
        )
        for row in matching_rows[offset : offset + limit]
    ]
    total = len(matching_rows)
    return BtrfsSnapshotListResponse(
        success=True,
        filesystem_top_level_path=str(root),
        total_snapshots=total,
        returned_snapshots=len(snapshots),
        snapshots=snapshots,
        limit=limit,
        offset=offset,
        partial=state_partial,
        truncated=scan_truncated or offset + len(snapshots) < total,
        message=" ".join(
            message
            for condition, message in (
                (state_partial, "Subvolume state changed while read-only flags were collected."),
                (scan_truncated, "Snapshot inventory is bounded to the first 5000 discovered snapshots."),
            )
            if condition
        ) or None,
    )


def _decode_mount_field(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _snapshot_is_mounted(root: Path, snapshot: BtrfsSubvolume) -> bool | None:
    try:
        with MOUNTINFO.open("rb") as stream:
            data = stream.read(MAX_PROC_MOUNTINFO_BYTES + 1)
        if len(data) > MAX_PROC_MOUNTINFO_BYTES:
            return None
        text = data.decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None
    relative = snapshot.relative_path.strip("/")
    target = str(snapshot.path)
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6:
            return None
        try:
            separator = fields.index("-")
        except ValueError:
            return None
        if len(fields) <= separator + 3:
            return None
        if fields[separator + 1] != "btrfs":
            continue
        mount_root = _decode_mount_field(fields[3]).strip("/")
        mount_point = Path(_decode_mount_field(fields[4]))
        super_options = fields[separator + 3]
        subvolume_id = re.search(r"(?:^|,)subvolid=([0-9]+)(?:,|$)", super_options)
        if subvolume_id and int(subvolume_id.group(1), 10) == snapshot.subvolume_id:
            return True
        if mount_root == relative or mount_root.startswith(relative + "/"):
            return True
        if mount_point == Path(target) or Path(target) in mount_point.parents:
            return True
    return False


def _snapshot_has_children(snapshot_path: Path) -> bool | None:
    binary = _btrfs_binary()
    if not binary:
        return None
    result = _run_read([binary, "subvolume", "list", "-o", str(snapshot_path)])
    if result is None or result[0] != 0:
        return None
    return bool(result[1].strip())


def _default_subvolume_id(root: Path) -> int | None:
    binary = _btrfs_binary()
    if not binary:
        return None
    result = _run_read([binary, "subvolume", "get-default", str(root)])
    if result is None or result[0] != 0:
        return None
    match = re.match(r"^ID\s+([0-9]+)(?:\s|$)", result[1].strip())
    return int(match.group(1), 10) if match else None


def _validate_destination_name(path: Path) -> str | None:
    name = path.name
    try:
        encoded = os.fsencode(name)
    except (OSError, UnicodeError):
        return "The snapshot name could not be encoded safely."
    if not name or name in {".", ".."} or len(encoded) > 255:
        return "The snapshot path must end in a name of at most 255 bytes."
    return None


def _subvolume_material(subvolume: BtrfsSubvolume | None) -> dict[str, object] | None:
    if subvolume is None:
        return None
    return {
        "path": str(subvolume.path),
        "relative_path": subvolume.relative_path,
        "identity": subvolume.stat_identity,
        "subvolume_id": subvolume.subvolume_id,
        "generation": subvolume.generation,
        "parent_id": subvolume.parent_id,
        "top_level_id": subvolume.top_level_id,
        "uuid": subvolume.uuid,
        "parent_uuid": subvolume.parent_uuid,
        "received_uuid": subvolume.received_uuid,
        "read_only": subvolume.read_only,
    }


def _stat_result_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_ctime_ns, info.st_mtime_ns


def _entry_is_directory(parent_fd: int, name: str) -> bool:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(info.st_mode)


def _rename_at2(parent_fd: int, source_name: str, destination_name: str, flags: int) -> None:
    try:
        renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2")
    except (AttributeError, OSError) as exc:
        raise OSError(errno.ENOSYS, "the required atomic rename operation is unavailable") from exc
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd,
        os.fsencode(source_name),
        parent_fd,
        os.fsencode(destination_name),
        flags,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination_name)


def _rename_noreplace(parent_fd: int, source_name: str, destination_name: str) -> None:
    _rename_at2(parent_fd, source_name, destination_name, 1)  # RENAME_NOREPLACE


def _rename_exchange(parent_fd: int, first_name: str, second_name: str) -> None:
    _rename_at2(parent_fd, first_name, second_name, 2)  # RENAME_EXCHANGE


def _same_subvolume_state(current: BtrfsSubvolume | None, expected: BtrfsSubvolume) -> bool:
    return _subvolume_material(current) == _subvolume_material(expected)


def _same_subvolume_identity(current: BtrfsSubvolume | None, expected: BtrfsSubvolume) -> bool:
    # Btrfs subvolume roots all report inode 256; use the subvolume ID and UUID lineage.
    return bool(
        current
        and current.subvolume_id == expected.subvolume_id
        and current.parent_id == expected.parent_id
        and current.top_level_id == expected.top_level_id
        and current.uuid == expected.uuid
        and current.parent_uuid == expected.parent_uuid
        and current.received_uuid == expected.received_uuid
        and current.read_only == expected.read_only
    )


def _subvolume_path_matches(path: Path, relative_path: str, expected: BtrfsSubvolume) -> bool:
    current, error = _subvolume_from_path(path, relative_path)
    return not error and _same_subvolume_identity(current, expected)


def _restore_state_error(
    target: BtrfsSnapshotTarget,
    *,
    staged_expected: BtrfsSubvolume | None = None,
) -> str | None:
    snapshot = target.snapshot
    restore_target = target.restore_target
    backup_path = target.backup_path
    stage_path = target.stage_path
    if not snapshot or not restore_target or not backup_path or not stage_path:
        return "The exact Btrfs restore state is incomplete."
    root, root_identity, error = _top_level_root(str(target.filesystem_top_level_path))
    if (
        error
        or root is None
        or root_identity is None
        or root_identity[:2] != target.filesystem_top_level_identity[:2]
    ):
        return error or "The Btrfs filesystem top-level identity changed."
    snapshot_now, error = _subvolume_from_path(snapshot.path, snapshot.relative_path)
    if error or not _same_subvolume_state(snapshot_now, snapshot):
        return error or "The read-only restore snapshot changed after confirmation."
    target_now, error = _subvolume_from_path(restore_target.path, restore_target.relative_path)
    if error or not _same_subvolume_state(target_now, restore_target):
        return error or "The target subvolume changed after confirmation."
    if _snapshot_is_mounted(root, restore_target) is not False:
        return "The target is no longer verified as unmounted in the current mount namespace."
    if _snapshot_has_children(restore_target.path) is not False:
        return "The target is no longer verified to contain no nested subvolumes."
    if _snapshot_has_children(snapshot.path) is not False:
        return "The restore snapshot is no longer verified to contain no nested subvolumes."
    default_id = _default_subvolume_id(root)
    if default_id is None:
        return "The Btrfs default subvolume could not be verified."
    if default_id == restore_target.subvolume_id:
        return "The target became the Btrfs default subvolume."
    parent_identity = _stat_identity(restore_target.path.parent)
    if (
        parent_identity is None
        or target.restore_parent_identity is None
        or parent_identity[:2] != target.restore_parent_identity[:2]
    ):
        return "The target/backup parent directory identity changed."
    if os.path.lexists(backup_path):
        return "The backup path appeared after confirmation; no path will be overwritten."
    if staged_expected is None:
        if os.path.lexists(stage_path):
            return "The restore staging path appeared before use; inspect it before retrying."
    else:
        stage_relative = _relative_to_root(stage_path, root)
        staged_now, stage_error = (
            _subvolume_from_path(stage_path, stage_relative)
            if stage_relative is not None
            else (None, "The restore staging path escaped the selected filesystem.")
        )
        if (
            stage_error
            or staged_now is None
            or not _same_subvolume_state(staged_now, staged_expected)
            or _snapshot_has_children(stage_path) is not False
        ):
            return stage_error or "The staged restore snapshot changed before installation."
    return None


def btrfs_snapshot_action_confirmation_details(
    action: str,
    filesystem_top_level_path: str,
    snapshot_path: str,
    source_path: str | None = None,
    read_only: bool = False,
    target_path: str | None = None,
    backup_path: str | None = None,
) -> tuple[BtrfsSnapshotTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Btrfs snapshot control is available only on Linux."
    if not isinstance(action, str) or action not in {"create", "delete", "restore"}:
        return None, None, "action must be create, delete, or restore."
    if not isinstance(read_only, bool):
        return None, None, "read_only must be a boolean."
    if not btrfs_snapshot_tools_available():
        return None, None, "The btrfs-progs 'btrfs' command is required."
    root, root_identity, error = _top_level_root(filesystem_top_level_path)
    if error or root is None or root_identity is None:
        return None, None, error or "The Btrfs top-level path could not be verified."

    destination: Path | None
    destination_parent_identity: tuple[int, int, int, int, int] | None
    source: BtrfsSubvolume | None = None
    snapshot: BtrfsSubvolume | None = None
    restore_target: BtrfsSubvolume | None = None
    restore_backup_path: Path | None = None
    restore_stage_path: Path | None = None
    restore_parent_identity: tuple[int, int, int, int, int] | None = None
    effective_read_only = read_only
    snapshot_relative: str

    if action == "create":
        if target_path is not None or backup_path is not None:
            return None, None, "target_path and backup_path are only used when restoring a Btrfs snapshot."
        if not isinstance(source_path, str):
            return None, None, "source_path is required when creating a Btrfs snapshot."
        source_path_value, path_error = _clean_absolute_path(source_path, must_exist=True)
        if path_error or source_path_value is None:
            return None, None, path_error or "The snapshot source path could not be verified."
        source_relative = _relative_to_root(source_path_value, root)
        if source_relative is None:
            return None, None, "The snapshot source must be beneath the selected Btrfs top-level path."
        source_identity = _stat_identity(source_path_value)
        if source_identity is None or source_identity[0] != root_identity[0]:
            return None, None, "The snapshot source must be a directory on the selected Btrfs filesystem."
        source, error = _subvolume_from_path(source_path_value, source_relative)
        if error or source is None:
            return None, None, error or "The snapshot source subvolume could not be verified."
        if source.subvolume_id == 5:
            return None, None, "Creating snapshots of the filesystem top-level subvolume is not supported."

        destination, path_error = _clean_absolute_path(snapshot_path, must_exist=False)
        if path_error or destination is None:
            return None, None, path_error or "The snapshot destination could not be verified."
        snapshot_relative = _relative_to_root(destination, root) or ""
        if not snapshot_relative:
            return None, None, "The snapshot destination must be beneath the selected Btrfs top-level path."
        name_error = _validate_destination_name(destination)
        if name_error:
            return None, None, name_error
        if os.path.lexists(destination):
            return None, None, "The snapshot destination already exists; no path will be overwritten."
        destination_parent_identity = _stat_identity(destination.parent)
        if destination_parent_identity is None or destination_parent_identity[0] != root_identity[0]:
            return None, None, "The snapshot destination parent must be an existing directory on the selected Btrfs filesystem."
        if not os.access(destination.parent, os.W_OK | os.X_OK):
            return None, None, "The current OS identity cannot write to the snapshot destination parent."
    elif action == "delete":
        if source_path is not None or read_only or target_path is not None or backup_path is not None:
            return None, None, "source_path/read_only are used only for creation, and target_path/backup_path only for restoration."
        effective_read_only = False
        destination, path_error = _clean_absolute_path(snapshot_path, must_exist=True)
        if path_error or destination is None:
            return None, None, path_error or "The snapshot path could not be verified."
        snapshot_relative = _relative_to_root(destination, root) or ""
        if not snapshot_relative:
            return None, None, "The filesystem top-level subvolume cannot be deleted."
        snapshot_identity = _stat_identity(destination)
        if snapshot_identity is None or snapshot_identity[0] != root_identity[0]:
            return None, None, "The selected snapshot must be a directory on the selected Btrfs filesystem."
        snapshot, error = _subvolume_from_path(destination, snapshot_relative)
        if error or snapshot is None:
            return None, None, error or "The selected Btrfs subvolume could not be verified."
        if snapshot.parent_uuid == "-" and snapshot.received_uuid == "-":
            return None, None, "Deletion is limited to Btrfs snapshots and received subvolumes; ordinary subvolumes are refused."
        parent_path, parent_error = _clean_absolute_path(str(destination.parent), must_exist=True)
        if parent_error or parent_path is None:
            return None, None, parent_error or "The snapshot parent directory could not be verified."
        destination_parent_identity = _stat_identity(parent_path)
        if destination_parent_identity is None:
            return None, None, "The snapshot parent is not an accessible directory."
        is_mounted = _snapshot_is_mounted(root, snapshot)
        if is_mounted is not False:
            return None, None, "Deletion is refused unless the snapshot is verified as unmounted in the current mount namespace."
        has_children = _snapshot_has_children(destination)
        if has_children is not False:
            return None, None, "Deletion is refused unless the snapshot is verified to contain no nested subvolumes."
        default_id = _default_subvolume_id(root)
        if default_id is None:
            return None, None, "The Btrfs default subvolume could not be verified."
        if default_id == snapshot.subvolume_id:
            return None, None, "The Btrfs default subvolume cannot be deleted."
        if not os.access(destination.parent, os.W_OK | os.X_OK):
            return None, None, "The current OS identity cannot delete from the snapshot parent directory."
    else:
        if source_path is not None or read_only:
            return None, None, "source_path and read_only are only used when creating a Btrfs snapshot."
        if not isinstance(target_path, str) or not isinstance(backup_path, str):
            return None, None, "target_path and backup_path are required when restoring a Btrfs snapshot."
        effective_read_only = False
        destination, path_error = _clean_absolute_path(snapshot_path, must_exist=True)
        if path_error or destination is None:
            return None, None, path_error or "The Btrfs snapshot path could not be verified."
        snapshot_relative = _relative_to_root(destination, root) or ""
        if not snapshot_relative:
            return None, None, "The filesystem top-level subvolume cannot be restored as a snapshot."
        snapshot_identity = _stat_identity(destination)
        if snapshot_identity is None or snapshot_identity[0] != root_identity[0]:
            return None, None, "The selected restore source must be a subvolume on the selected Btrfs filesystem."
        snapshot, error = _subvolume_from_path(destination, snapshot_relative)
        if error or snapshot is None:
            return None, None, error or "The selected restore source could not be verified."
        if snapshot.parent_uuid == "-" and snapshot.received_uuid == "-":
            return None, None, "Restoration requires an exact Btrfs snapshot or received subvolume; ordinary subvolumes are refused."
        if not snapshot.read_only:
            return None, None, "Restoration requires a read-only snapshot so its contents remain stable."
        if _snapshot_has_children(destination) is not False:
            return None, None, "Restoration is refused unless the source snapshot is verified to contain no nested subvolumes."

        restore_target_path, path_error = _clean_absolute_path(target_path, must_exist=True)
        if path_error or restore_target_path is None:
            return None, None, path_error or "The target subvolume path could not be verified."
        target_relative = _relative_to_root(restore_target_path, root) or ""
        if not target_relative:
            return None, None, "The filesystem top-level subvolume cannot be replaced."
        target_identity = _stat_identity(restore_target_path)
        if target_identity is None or target_identity[0] != root_identity[0]:
            return None, None, "The target must be a subvolume on the selected Btrfs filesystem."
        restore_target, error = _subvolume_from_path(restore_target_path, target_relative)
        if error or restore_target is None:
            return None, None, error or "The target Btrfs subvolume could not be verified."
        if restore_target.subvolume_id == 5 or restore_target.path == destination:
            return None, None, "The filesystem top-level subvolume and the restore source cannot be replaced."
        if _snapshot_is_mounted(root, restore_target) is not False:
            return None, None, "Restoration is refused unless the target is verified as unmounted in the current mount namespace."
        if _snapshot_has_children(restore_target_path) is not False:
            return None, None, "Restoration is refused unless the target is verified to contain no nested subvolumes."
        default_id = _default_subvolume_id(root)
        if default_id is None:
            return None, None, "The Btrfs default subvolume could not be verified."
        if default_id == restore_target.subvolume_id:
            return None, None, "The Btrfs default subvolume cannot be replaced."

        restore_backup_path, path_error = _clean_absolute_path(backup_path, must_exist=False)
        if path_error or restore_backup_path is None:
            return None, None, path_error or "The backup subvolume path could not be verified."
        if restore_backup_path.parent != restore_target_path.parent:
            return None, None, "backup_path must be a new sibling of target_path so the subvolume rename stays within one directory."
        if restore_backup_path.name == restore_target_path.name or os.path.lexists(restore_backup_path):
            return None, None, "backup_path must be a new path distinct from target_path; existing paths are never overwritten."
        if (name_error := _validate_destination_name(restore_backup_path)):
            return None, None, name_error
        restore_parent_identity = _stat_identity(restore_target_path.parent)
        if restore_parent_identity is None or restore_parent_identity[0] != root_identity[0]:
            return None, None, "The target and backup parent must be an accessible directory on the selected Btrfs filesystem."
        if not os.access(restore_target_path.parent, os.W_OK | os.X_OK):
            return None, None, "The current OS identity cannot replace the target in its parent directory."
        snapshot_parent_identity = _stat_identity(destination.parent)
        if snapshot_parent_identity is None:
            return None, None, "The restore snapshot parent directory could not be verified."
        destination_parent_identity = snapshot_parent_identity
        stage_suffix = hashlib.sha256(
            f"{root_identity[0]}:{root_identity[1]}:{snapshot.uuid}:{restore_target.uuid}".encode("ascii")
        ).hexdigest()[:20]
        restore_stage_path = restore_target_path.parent / f".linux-mcp-restore-stage-{stage_suffix}"
        if os.path.lexists(restore_stage_path):
            return None, None, "A prior restore staging path already exists; inspect it before retrying."
        if restore_stage_path == restore_backup_path:
            return None, None, "backup_path conflicts with the reserved restore staging path."

    if destination is None or destination_parent_identity is None:
        return None, None, "The snapshot path state could not be verified."
    details = {
        "action": action,
        "filesystem_top_level_path": str(root),
        "filesystem_top_level_identity": root_identity,
        "snapshot_path": str(destination),
        "snapshot_relative_path": snapshot_relative,
        "destination_parent_identity": destination_parent_identity,
        "source": _subvolume_material(source),
        "snapshot": _subvolume_material(snapshot),
        "restore_target": _subvolume_material(restore_target),
        "backup_path": str(restore_backup_path) if restore_backup_path else None,
        "stage_path": str(restore_stage_path) if restore_stage_path else None,
        "restore_parent_identity": restore_parent_identity,
        "read_only": effective_read_only,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    phrase_hash = hashlib.sha256((action + ":" + digest).encode("utf-8")).hexdigest()[:16]
    target = BtrfsSnapshotTarget(
        action=action,  # type: ignore[arg-type]
        filesystem_top_level_path=root,
        filesystem_top_level_identity=root_identity,
        snapshot_path=destination,
        snapshot_relative_path=snapshot_relative,
        source=source,
        snapshot=snapshot,
        restore_target=restore_target,
        backup_path=restore_backup_path,
        stage_path=restore_stage_path,
        restore_parent_identity=restore_parent_identity,
        read_only=effective_read_only,
        state_digest=digest,
    )
    return target, f"BTRFS {action.upper()} {phrase_hash}", None


def _restore_response(
    target: BtrfsSnapshotTarget,
    *,
    success: bool,
    message: str,
    snapshot_uuid: str | None = None,
    restored_subvolume_uuid: str | None = None,
    staging_path: str | None = None,
) -> BtrfsSnapshotActionResponse:
    return BtrfsSnapshotActionResponse(
        success=success,
        action="restore",
        filesystem_top_level_path=str(target.filesystem_top_level_path),
        snapshot_path=str(target.snapshot_path),
        snapshot_uuid=snapshot_uuid or (target.snapshot.uuid if target.snapshot else None),
        target_path=str(target.restore_target.path) if target.restore_target else None,
        backup_path=str(target.backup_path) if target.backup_path else None,
        restored_subvolume_uuid=restored_subvolume_uuid,
        staging_path=staging_path,
        read_only=False,
        user_confirmed=True,
        message=message,
    )


def _perform_btrfs_snapshot_restore(
    target: BtrfsSnapshotTarget,
    binary: str,
) -> BtrfsSnapshotActionResponse:
    snapshot = target.snapshot
    restore_target = target.restore_target
    backup_path = target.backup_path
    stage_path = target.stage_path
    parent_identity = target.restore_parent_identity
    if not snapshot or not restore_target or not backup_path or not stage_path or not parent_identity:
        return _restore_response(target, success=False, message="The exact Btrfs restore state is incomplete.")

    parent_fd: int | None = None
    staged_uuid: str | None = None
    try:
        parent_flags = (
            getattr(os, "O_PATH", os.O_RDONLY)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        parent_fd = os.open(restore_target.path.parent, parent_flags)

        def pinned_parent_matches() -> bool:
            try:
                opened_identity = _stat_result_identity(os.fstat(parent_fd))
                path_identity = _stat_identity(restore_target.path.parent)
            except OSError:
                return False
            return bool(
                opened_identity[:2] == parent_identity[:2]
                and path_identity is not None
                and path_identity[:2] == parent_identity[:2]
            )

        opened_parent = _stat_result_identity(os.fstat(parent_fd))
        if opened_parent != parent_identity:
            return _restore_response(target, success=False, message="The target parent changed after confirmation; no subvolume was moved.")
        state_error = _restore_state_error(target)
        if state_error:
            return _restore_response(target, success=False, message=state_error)

        snapshot_result = _run_mutation([binary, "subvolume", "snapshot", str(snapshot.path), str(stage_path)])
        stage_relative = _relative_to_root(stage_path, target.filesystem_top_level_path)
        staged, stage_error = (
            _subvolume_from_path(stage_path, stage_relative)
            if stage_relative is not None
            else (None, "The staging path escaped the selected Btrfs filesystem.")
        )
        if (
            not snapshot_result
            or stage_error
            or staged is None
            or staged.parent_uuid != snapshot.uuid
            or staged.uuid == snapshot.uuid
            or staged.read_only
        ):
            return _restore_response(
                target,
                success=False,
                message=(
                    "The writable restore clone could not be verified. Inspect the staging path before retrying."
                    if os.path.lexists(stage_path)
                    else "The writable restore clone was not created; the original target remains in place."
                ),
                staging_path=str(stage_path) if os.path.lexists(stage_path) else None,
            )
        staged_uuid = staged.uuid
        state_error = _restore_state_error(target, staged_expected=staged)
        if state_error:
            return _restore_response(
                target,
                success=False,
                message=f"{state_error} The verified clone remains at the staging path for inspection.",
                restored_subvolume_uuid=staged_uuid,
                staging_path=str(stage_path),
            )
        if not pinned_parent_matches():
            return _restore_response(
                target,
                success=False,
                message="The pinned target parent changed while the restore clone was created; inspect the staging path.",
                restored_subvolume_uuid=staged_uuid,
                staging_path=str(stage_path),
            )

        target_before_exchange, target_before_exchange_error = _subvolume_from_path(
            restore_target.path, restore_target.relative_path
        )
        stage_before_exchange, stage_before_exchange_error = _subvolume_from_path(
            stage_path, stage_relative
        )
        if (
            not pinned_parent_matches()
            or target_before_exchange_error
            or stage_before_exchange_error
            or not _entry_is_directory(parent_fd, restore_target.path.name)
            or os.path.lexists(backup_path)
            or not _entry_is_directory(parent_fd, stage_path.name)
            or not _same_subvolume_state(target_before_exchange, restore_target)
            or not _same_subvolume_state(stage_before_exchange, staged)
        ):
            return _restore_response(
                target,
                success=False,
                message="A target, backup, or staging entry changed immediately before the atomic exchange; inspect the paths before retrying.",
                restored_subvolume_uuid=staged_uuid,
                staging_path=str(stage_path),
            )

        def try_exchange_back() -> bool:
            try:
                if stage_relative is None:
                    return False
                if not pinned_parent_matches():
                    return False
                original_at_stage, original_error = _subvolume_from_path(stage_path, stage_relative)
                clone_at_target, clone_error = _subvolume_from_path(
                    restore_target.path, restore_target.relative_path
                )
                if (
                    original_error
                    or clone_error
                    or not _entry_is_directory(parent_fd, stage_path.name)
                    or not _entry_is_directory(parent_fd, restore_target.path.name)
                    or not _same_subvolume_identity(original_at_stage, restore_target)
                    or not _same_subvolume_identity(clone_at_target, staged)
                    or _snapshot_is_mounted(target.filesystem_top_level_path, original_at_stage) is not False
                    or _snapshot_is_mounted(target.filesystem_top_level_path, clone_at_target) is not False
                    or not _subvolume_path_matches(stage_path, stage_relative, restore_target)
                    or not _subvolume_path_matches(restore_target.path, restore_target.relative_path, staged)
                ):
                    return False
                _rename_exchange(parent_fd, restore_target.path.name, stage_path.name)
                original_now, original_now_error = _subvolume_from_path(
                    restore_target.path, restore_target.relative_path
                )
                clone_now, clone_now_error = _subvolume_from_path(stage_path, stage_relative)
                return bool(
                    pinned_parent_matches()
                    and _entry_is_directory(parent_fd, restore_target.path.name)
                    and _entry_is_directory(parent_fd, stage_path.name)
                    and not original_now_error
                    and not clone_now_error
                    and _same_subvolume_identity(original_now, restore_target)
                    and _same_subvolume_identity(clone_now, staged)
                )
            except OSError:
                return False

        try:
            _rename_exchange(parent_fd, restore_target.path.name, stage_path.name)
        except OSError as exc:
            return _restore_response(
                target,
                success=False,
                message=(
                    f"The atomic target/staging exchange failed ({exc.strerror or 'rename exchange unavailable'}). "
                    f"Inspect {restore_target.path} and {stage_path} before retrying; the paths were not changed by a successful exchange."
                ),
                restored_subvolume_uuid=staged_uuid,
                staging_path=str(stage_path),
            )

        original_at_stage, original_error = _subvolume_from_path(stage_path, stage_relative)
        installed, install_error = _subvolume_from_path(
            restore_target.path, restore_target.relative_path
        )
        exchanged_exact = bool(
            pinned_parent_matches()
            and _entry_is_directory(parent_fd, stage_path.name)
            and _entry_is_directory(parent_fd, restore_target.path.name)
            and not original_error
            and not install_error
            and _same_subvolume_identity(original_at_stage, restore_target)
            and installed
            and installed.uuid == staged_uuid
            and installed.parent_uuid == snapshot.uuid
            and not installed.read_only
        )
        if not exchanged_exact:
            rolled_back = try_exchange_back()
            recovery = (
                f"The original target was returned to {restore_target.path}; the clone remains staged at {stage_path}."
                if rolled_back
                else f"Inspect {restore_target.path} and {stage_path} and verify their subvolume UUIDs before retrying."
            )
            return _restore_response(
                target,
                success=False,
                message=(
                    "The atomic exchange completed, but the two subvolume identities could not be fully verified. "
                    + recovery
                ),
                restored_subvolume_uuid=staged_uuid,
                staging_path=str(stage_path),
            )

        if (
            _snapshot_is_mounted(target.filesystem_top_level_path, original_at_stage) is not False
            or _snapshot_is_mounted(target.filesystem_top_level_path, installed) is not False
        ):
            rolled_back = try_exchange_back()
            recovery = (
                f"The original target was returned to {restore_target.path}; the clone remains staged at {stage_path}."
                if rolled_back
                else f"Inspect {restore_target.path} and {stage_path} and verify their subvolume UUIDs before retrying."
            )
            return _restore_response(
                target,
                success=False,
                message=(
                    "A subvolume became mounted during the atomic exchange, so the backup move was not attempted. "
                    + recovery
                ),
                restored_subvolume_uuid=staged_uuid,
                staging_path=str(stage_path),
            )

        default_after_exchange = _default_subvolume_id(target.filesystem_top_level_path)
        if default_after_exchange is None or default_after_exchange == restore_target.subvolume_id:
            rolled_back = try_exchange_back()
            recovery = (
                f"The original target was returned to {restore_target.path}; the clone remains staged at {stage_path}."
                if rolled_back
                else f"Inspect {restore_target.path} and {stage_path} and verify their subvolume UUIDs before retrying."
            )
            return _restore_response(
                target,
                success=False,
                message=(
                    "The Btrfs default-subvolume state changed or could not be verified after the atomic exchange; "
                    "the backup move was not attempted. " + recovery
                ),
                restored_subvolume_uuid=staged_uuid,
                staging_path=str(stage_path),
            )

        if (
            not pinned_parent_matches()
            or not _entry_is_directory(parent_fd, stage_path.name)
            or not _entry_is_directory(parent_fd, restore_target.path.name)
            or not _subvolume_path_matches(stage_path, stage_relative, restore_target)
            or not _subvolume_path_matches(restore_target.path, restore_target.relative_path, staged)
            or os.path.lexists(backup_path)
        ):
            rolled_back = try_exchange_back()
            recovery = (
                f"The original target was returned to {restore_target.path}; the clone remains staged at {stage_path}."
                if rolled_back
                else f"Inspect {restore_target.path}, {stage_path}, and {backup_path}, then verify each subvolume UUID."
            )
            return _restore_response(
                target,
                success=False,
                message="The target, staging, or backup entry changed after exchange. " + recovery,
                restored_subvolume_uuid=staged_uuid,
                staging_path=str(stage_path),
            )

        default_before_backup = _default_subvolume_id(target.filesystem_top_level_path)
        if default_before_backup is None or default_before_backup == restore_target.subvolume_id:
            rolled_back = try_exchange_back()
            recovery = (
                f"The original target was returned to {restore_target.path}; the clone remains staged at {stage_path}."
                if rolled_back
                else f"Inspect {restore_target.path} and {stage_path} and verify their subvolume UUIDs before retrying."
            )
            return _restore_response(
                target,
                success=False,
                message="The Btrfs default-subvolume state changed or could not be verified before backup. " + recovery,
                restored_subvolume_uuid=staged_uuid,
                staging_path=str(stage_path),
            )

        try:
            original_before_backup, original_before_backup_error = _subvolume_from_path(
                stage_path, stage_relative
            )
            clone_before_backup, clone_before_backup_error = _subvolume_from_path(
                restore_target.path, restore_target.relative_path
            )
            if (
                not pinned_parent_matches()
                or original_before_backup_error
                or clone_before_backup_error
                or not _entry_is_directory(parent_fd, stage_path.name)
                or not _entry_is_directory(parent_fd, restore_target.path.name)
                or not _same_subvolume_identity(original_before_backup, restore_target)
                or not _same_subvolume_identity(clone_before_backup, staged)
                or os.path.lexists(backup_path)
            ):
                raise OSError(errno.ESTALE, "the target, staging, or backup identity changed before backup")
            _rename_noreplace(parent_fd, stage_path.name, backup_path.name)
        except OSError as exc:
            rolled_back = try_exchange_back()
            recovery = (
                f"The original target was returned to {restore_target.path}; the clone remains staged at {stage_path}."
                if rolled_back
                else f"Inspect {restore_target.path}, {stage_path}, and {backup_path}, then verify each subvolume UUID."
            )
            return _restore_response(
                target,
                success=False,
                message=(
                    f"The original could not be moved to the requested backup path ({exc.strerror or 'rename failed'}). "
                    + recovery
                ),
                restored_subvolume_uuid=staged_uuid,
                staging_path=str(stage_path),
            )

        backup_relative = _relative_to_root(backup_path, target.filesystem_top_level_path)
        backup_now, backup_error = (
            _subvolume_from_path(backup_path, backup_relative)
            if backup_relative is not None
            else (None, "The backup path escaped the selected Btrfs filesystem.")
        )
        installed, install_error = _subvolume_from_path(
            restore_target.path, restore_target.relative_path
        )
        final_default_id = _default_subvolume_id(target.filesystem_top_level_path)
        backup_is_original = _same_subvolume_identity(backup_now, restore_target)
        target_is_clone = bool(
            installed
            and installed.uuid == staged_uuid
            and installed.parent_uuid == snapshot.uuid
            and not installed.read_only
        )
        backup_unmounted = (
            _snapshot_is_mounted(target.filesystem_top_level_path, backup_now) is False
            if backup_now is not None
            else False
        )
        target_unmounted = (
            _snapshot_is_mounted(target.filesystem_top_level_path, installed) is False
            if installed is not None
            else False
        )
        installed_ok = bool(
            pinned_parent_matches()
            and _entry_is_directory(parent_fd, restore_target.path.name)
            and _entry_is_directory(parent_fd, backup_path.name)
            and backup_is_original
            and target_is_clone
            and backup_unmounted
            and target_unmounted
            and final_default_id is not None
            and final_default_id != restore_target.subvolume_id
            and not os.path.lexists(stage_path)
        )
        if installed_ok:
            message = (
                f"Restored the read-only snapshot as a writable subvolume at {restore_target.path}; "
                f"the previous target is preserved at {backup_path}."
            )
        else:
            state_problem = install_error or backup_error or "identity, mount, default-subvolume, or staging state mismatch"
            message = (
                f"The atomic target exchange completed, but final verification was incomplete ({state_problem}). "
                f"Inspect {restore_target.path} and {backup_path} before retrying."
            )
        return _restore_response(
            target,
            success=installed_ok,
            message=message,
            restored_subvolume_uuid=staged_uuid,
            staging_path=str(stage_path) if os.path.lexists(stage_path) else None,
        )
    except OSError as exc:
        recovery_paths = []

        def recovery_entry(path: Path) -> str | None:
            try:
                if path.is_symlink() or not path.is_dir():
                    return "present but not a verified subvolume"
                relative = _relative_to_root(path, target.filesystem_top_level_path)
                if relative is None:
                    return "outside the selected filesystem"
                current, current_error = _subvolume_from_path(path, relative)
                if current_error or current is None:
                    return "present but its subvolume identity is unreadable"
                if _same_subvolume_identity(current, restore_target):
                    return "original target"
                if (
                    staged_uuid
                    and current.uuid == staged_uuid
                    and current.parent_uuid == snapshot.uuid
                    and not current.read_only
                ):
                    return "writable restore clone"
                return "present with a different subvolume identity"
            except OSError:
                return "present but its identity could not be checked"

        for candidate in (restore_target.path, stage_path, backup_path):
            if os.path.lexists(candidate):
                description = recovery_entry(candidate)
                recovery_paths.append(f"{candidate}: {description or 'present'}")
        recovery_note = (
            " Inspect recovery paths: " + "; ".join(recovery_paths) + "."
            if recovery_paths
            else " No target, staging, or backup path was found; inspect the filesystem before retrying."
        )
        return _restore_response(
            target,
            success=False,
            message=f"Btrfs restore could not proceed: {exc.strerror or str(exc)}.{recovery_note}",
            restored_subvolume_uuid=staged_uuid,
            staging_path=str(stage_path) if os.path.lexists(stage_path) else None,
        )
    finally:
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def perform_btrfs_snapshot_action(
    action: BtrfsSnapshotAction,
    filesystem_top_level_path: str,
    snapshot_path: str,
    source_path: str | None = None,
    read_only: bool = False,
    target_path: str | None = None,
    backup_path: str | None = None,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> BtrfsSnapshotActionResponse:
    target, phrase, error = btrfs_snapshot_action_confirmation_details(
        action, filesystem_top_level_path, snapshot_path, source_path, read_only, target_path, backup_path
    )
    if error or target is None or phrase is None:
        return BtrfsSnapshotActionResponse(
            success=False,
            action=action,
            filesystem_top_level_path=filesystem_top_level_path,
            snapshot_path=snapshot_path,
            source_path=source_path,
            target_path=target_path,
            backup_path=backup_path,
            read_only=read_only,
            user_confirmed=confirmed is True,
            message=error or "The Btrfs snapshot request could not be verified.",
        )
    if confirmed is not True:
        return BtrfsSnapshotActionResponse(
            success=False,
            action=action,
            filesystem_top_level_path=str(target.filesystem_top_level_path),
            snapshot_path=str(target.snapshot_path),
            source_path=str(target.source.path) if target.source else None,
            target_path=str(target.restore_target.path) if target.restore_target else None,
            backup_path=str(target.backup_path) if target.backup_path else None,
            read_only=target.read_only,
            user_confirmed=False,
            message="Explicit client confirmation is required; no Btrfs command was run.",
        )
    if confirmation_phrase != phrase:
        return BtrfsSnapshotActionResponse(
            success=False,
            action=action,
            filesystem_top_level_path=str(target.filesystem_top_level_path),
            snapshot_path=str(target.snapshot_path),
            source_path=str(target.source.path) if target.source else None,
            target_path=str(target.restore_target.path) if target.restore_target else None,
            backup_path=str(target.backup_path) if target.backup_path else None,
            read_only=target.read_only,
            user_confirmed=True,
            message="Confirmation did not match the exact paths and Btrfs snapshot state.",
        )

    current, current_phrase, error = btrfs_snapshot_action_confirmation_details(
        action, filesystem_top_level_path, snapshot_path, source_path, read_only, target_path, backup_path
    )
    if error or current is None or current_phrase != phrase or current.state_digest != target.state_digest:
        return BtrfsSnapshotActionResponse(
            success=False,
            action=action,
            filesystem_top_level_path=str(target.filesystem_top_level_path),
            snapshot_path=str(target.snapshot_path),
            source_path=str(target.source.path) if target.source else None,
            target_path=str(target.restore_target.path) if target.restore_target else None,
            backup_path=str(target.backup_path) if target.backup_path else None,
            read_only=target.read_only,
            user_confirmed=True,
            message=error or "Btrfs filesystem or subvolume state changed after confirmation; no command was run.",
        )

    binary = _btrfs_binary()
    if not binary:
        return BtrfsSnapshotActionResponse(
            success=False,
            action=action,
            filesystem_top_level_path=str(target.filesystem_top_level_path),
            snapshot_path=str(target.snapshot_path),
            source_path=str(target.source.path) if target.source else None,
            target_path=str(target.restore_target.path) if target.restore_target else None,
            backup_path=str(target.backup_path) if target.backup_path else None,
            read_only=target.read_only,
            user_confirmed=True,
            message="The btrfs-progs 'btrfs' command is unavailable.",
        )
    if action == "create":
        assert target.source is not None
        command = [binary, "subvolume", "snapshot"]
        if target.read_only:
            command.append("-r")
        command.extend([str(target.source.path), str(target.snapshot_path)])
        _run_mutation(command)
        details = _parse_show(target.snapshot_path)
        created = (
            details is not None
            and details["parent_uuid"] == target.source.uuid
            and bool(details["read_only"]) is target.read_only
            and str(details["uuid"]) != target.source.uuid
        )
        return BtrfsSnapshotActionResponse(
            success=created,
            action=action,
            filesystem_top_level_path=str(target.filesystem_top_level_path),
            snapshot_path=str(target.snapshot_path),
            source_path=str(target.source.path),
            source_uuid=target.source.uuid,
            snapshot_uuid=str(details["uuid"]) if details else None,
            read_only=target.read_only,
            user_confirmed=True,
            message=(
                "Btrfs snapshot created and its source UUID/read-only state verified."
                if created
                else "The snapshot result could not be verified; inspect the Btrfs snapshot inventory before retrying."
            ),
        )

    if action == "restore":
        return _perform_btrfs_snapshot_restore(target, binary)

    assert target.snapshot is not None
    _run_mutation([binary, "subvolume", "delete", "--commit-after", str(target.snapshot_path)])
    removed = not os.path.lexists(target.snapshot_path)
    return BtrfsSnapshotActionResponse(
        success=removed,
        action=action,
        filesystem_top_level_path=str(target.filesystem_top_level_path),
        snapshot_path=str(target.snapshot_path),
        snapshot_uuid=target.snapshot.uuid,
        read_only=target.snapshot.read_only,
        user_confirmed=True,
        message=(
            "The Btrfs snapshot directory was removed; storage blocks are cleaned asynchronously."
            if removed
            else "The snapshot path remains; no successful deletion was verified."
        ),
    )
