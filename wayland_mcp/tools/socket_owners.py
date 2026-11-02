"""Bounded read-only mapping from socket inodes to visible processes."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from wayland_mcp.models import (
    SocketOwnerListResponse,
    SocketProcessOwner,
)

PROC = Path("/proc")
MAX_REQUESTED_INODES = 128
MAX_PROCESS_SCAN = 10_000
MAX_DESCRIPTOR_SCAN = 100_000
MAX_OWNER_MATCHES = 5_000
MAX_RETURNED_OWNERS = 200
MAX_STAT_BYTES = 8192
MAX_STATUS_BYTES = 32 * 1024
SOCKET_LINK_RE = re.compile(r"^socket:\[([0-9]{1,20})\]$")


def _read_start_ticks(pid: int) -> int | None:
    try:
        with (PROC / str(pid) / "stat").open("rb") as stream:
            value = stream.read(MAX_STAT_BYTES + 1).decode("ascii", errors="replace")
    except OSError:
        return None
    if len(value) > MAX_STAT_BYTES:
        return None
    closing_paren = value.rfind(")")
    if closing_paren < 0:
        return None
    prefix = value[:closing_paren].split()
    fields = value[closing_paren + 1:].split()
    if not prefix or prefix[0] != str(pid) or len(fields) <= 19:
        return None
    try:
        start_ticks = int(fields[19], 10)
    except ValueError:
        return None
    return start_ticks if start_ticks >= 0 else None


def _read_owner_metadata(pid: int, expected_start_ticks: int) -> tuple[str, int | None] | None:
    if _read_start_ticks(pid) != expected_start_ticks:
        return None
    try:
        with (PROC / str(pid) / "status").open("rb") as stream:
            raw = stream.read(MAX_STATUS_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_STATUS_BYTES:
        return None
    name = ""
    uid: int | None = None
    for line in raw.decode("utf-8", errors="replace").splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        if key == "Name":
            name = "".join(character for character in value.strip() if ord(character) >= 32 and ord(character) != 127)[:256]
        elif key == "Uid":
            fields = value.split()
            try:
                parsed_uid = int(fields[1], 10)
            except (ValueError, IndexError):
                continue
            if 0 <= parsed_uid <= 4_294_967_295:
                uid = parsed_uid
    if _read_start_ticks(pid) != expected_start_ticks or not name:
        return None
    return name, uid


def list_socket_owners(inodes: list[int], limit: int = 100) -> SocketOwnerListResponse:
    """Resolve a bounded set of socket inodes to visible process PID/name/UID metadata."""
    if not sys.platform.startswith("linux"):
        return SocketOwnerListResponse(success=False, message="Socket owner lookup is available only on Linux.")
    if not isinstance(inodes, list) or not inodes:
        return SocketOwnerListResponse(success=False, message="Provide at least one socket inode.")
    if len(inodes) > MAX_REQUESTED_INODES:
        return SocketOwnerListResponse(success=False, message=f"At most {MAX_REQUESTED_INODES} socket inodes may be requested.")
    if any(not isinstance(inode, int) or isinstance(inode, bool) or not 1 <= inode <= 2**64 - 1 for inode in inodes):
        return SocketOwnerListResponse(success=False, message="Socket inodes must be positive unsigned 64-bit integers.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return SocketOwnerListResponse(success=False, message="Limit must be an integer.")
    requested = sorted(set(inodes))
    limit = max(1, min(limit, MAX_RETURNED_OWNERS))
    targets = set(requested)
    matches: dict[tuple[int, int], tuple[int, str, int | None]] = {}
    processes_scanned = 0
    descriptors_scanned = 0
    inaccessible_processes = 0
    unreadable_descriptors = 0
    process_cap_reached = False
    descriptor_cap_reached = False
    owner_cap_reached = False
    partial = False

    try:
        process_entries = os.scandir(PROC)
    except OSError as exc:
        return SocketOwnerListResponse(success=False, requested_inodes=requested, limit=limit, message=f"Could not scan procfs: {exc.strerror or 'read error'}")

    try:
        with process_entries:
            for process_entry in process_entries:
                if not process_entry.name.isdecimal():
                    continue
                if processes_scanned >= MAX_PROCESS_SCAN:
                    process_cap_reached = True
                    break
                pid = int(process_entry.name, 10)
                if pid <= 0:
                    continue
                processes_scanned += 1
                start_ticks = _read_start_ticks(pid)
                if start_ticks is None:
                    inaccessible_processes += 1
                    partial = True
                    continue
                process_matches: dict[int, int] = {}
                try:
                    descriptor_entries = os.scandir(PROC / str(pid) / "fd")
                except OSError:
                    inaccessible_processes += 1
                    partial = True
                    continue
                try:
                    with descriptor_entries:
                        for descriptor_entry in descriptor_entries:
                            if descriptors_scanned >= MAX_DESCRIPTOR_SCAN:
                                descriptor_cap_reached = True
                                break
                            descriptors_scanned += 1
                            try:
                                target = os.readlink(descriptor_entry.path)
                            except OSError:
                                unreadable_descriptors += 1
                                partial = True
                                continue
                            match = SOCKET_LINK_RE.fullmatch(target)
                            if match is None:
                                continue
                            inode = int(match.group(1), 10)
                            if inode not in targets:
                                continue
                            process_matches[inode] = process_matches.get(inode, 0) + 1
                except OSError:
                    inaccessible_processes += 1
                    partial = True
                    continue
                if process_matches:
                    metadata = _read_owner_metadata(pid, start_ticks)
                    if metadata is None:
                        inaccessible_processes += 1
                        partial = True
                        continue
                    name, uid = metadata
                    for inode, descriptor_count in process_matches.items():
                        key = (inode, pid)
                        if key not in matches and len(matches) >= MAX_OWNER_MATCHES:
                            owner_cap_reached = True
                            break
                        matches[key] = (descriptor_count, name, uid)
                    if owner_cap_reached:
                        break
                if descriptor_cap_reached:
                    break
    except OSError as exc:
        return SocketOwnerListResponse(
            success=False,
            requested_inodes=requested,
            processes_scanned=processes_scanned,
            descriptors_scanned=descriptors_scanned,
            inaccessible_processes=inaccessible_processes,
            unreadable_descriptors=unreadable_descriptors,
            limit=limit,
            truncated=True,
            message=f"Procfs scan stopped with an error: {exc.strerror or 'read error'}",
        )

    owners: list[SocketProcessOwner] = []
    for (inode, pid), (descriptor_count, name, uid) in matches.items():
        owners.append(SocketProcessOwner(
            inode=inode,
            pid=pid,
            name=name,
            uid=uid,
            open_descriptor_count=descriptor_count,
        ))
    owners.sort(key=lambda item: (item.inode, item.pid))
    matched_inodes = sorted({owner.inode for owner in owners})
    unmatched_inodes = sorted(targets - set(matched_inodes))
    truncated = (
        process_cap_reached
        or descriptor_cap_reached
        or owner_cap_reached
        or partial
        or len(owners) > limit
    )
    messages = ["Socket owners are resolved by matching procfs socket inodes to visible `/proc/PID/fd` links; process arguments, environments, and working directories are not read."]
    if partial:
        messages.append("Some processes or descriptors were inaccessible, changed during the scan, or disappeared.")
    if process_cap_reached or descriptor_cap_reached or owner_cap_reached:
        messages.append("The process, descriptor, or owner scan reached its configured cap.")
    if len(owners) > limit:
        messages.append(f"The result is capped at {limit} owners.")
    if unmatched_inodes:
        messages.append("Unmatched inodes may have no visible process owner or may belong to a process hidden by procfs permissions/namespaces.")
    return SocketOwnerListResponse(
        success=True,
        requested_inodes=requested,
        matched_inodes=matched_inodes,
        unmatched_inodes=unmatched_inodes,
        total_owners=len(owners),
        returned_owners=min(len(owners), limit),
        owners=owners[:limit],
        processes_scanned=processes_scanned,
        descriptors_scanned=descriptors_scanned,
        inaccessible_processes=inaccessible_processes,
        unreadable_descriptors=unreadable_descriptors,
        limit=limit,
        truncated=truncated,
        message=" ".join(messages),
    )
