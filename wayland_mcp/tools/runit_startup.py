"""Confirmed runit initial-state marker changes for exact supervised services."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import RunitServiceStartupResponse
from wayland_mcp.tools.host import _detect_init_system
from wayland_mcp.tools.services import (
    MAX_RUNIT_SERVICES,
    RUNSVDIR_CANDIDATES,
    RUNSVDIR_SCAN_LIMIT,
    SERVICE_NAME_RE,
)

RunitStartupAction = Literal["enable", "disable"]
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RunitServiceEntry:
    name: str
    path: Path
    root: Path
    root_identity: tuple[int, int]
    entry_identity: tuple[int, int, int, int]
    entry_link_target: str | None
    service_identity: tuple[int, int, int, int, int, int]
    run_identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class RunitStartupSnapshot:
    unit: str
    service_directory: Path
    enabled: bool
    state_token: str
    service_identity: tuple[int, int, int, int, int, int]
    marker_identity: tuple[int, int, int, int, int, int, int] | None


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _marker_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (*_stat_identity(value), value.st_nlink)


def _service_entries() -> tuple[list[RunitServiceEntry], str | None]:
    entries: list[RunitServiceEntry] = []
    seen_roots: set[tuple[int, int]] = set()
    scanned_entries = 0
    for candidate_root in RUNSVDIR_CANDIDATES:
        try:
            candidate_stat = candidate_root.stat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as exc:
            return [], f"Could not inspect standard runit service directory {candidate_root}: {exc.strerror or 'read error'}."
        if not stat.S_ISDIR(candidate_stat.st_mode):
            continue
        try:
            root = candidate_root.resolve(strict=True)
            root_stat = root.stat()
            if not stat.S_ISDIR(root_stat.st_mode):
                continue
            root_identity = (root_stat.st_dev, root_stat.st_ino)
            if root_identity in seen_roots:
                continue
            seen_roots.add(root_identity)
            with os.scandir(root) as iterator:
                for entry in iterator:
                    scanned_entries += 1
                    if scanned_entries > RUNSVDIR_SCAN_LIMIT:
                        return [], "The standard runit service-directory scan exceeded its safety limit; no startup change is available."
                    if not SERVICE_NAME_RE.fullmatch(entry.name):
                        continue
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    except OSError as exc:
                        return [], f"Could not inspect a runit service entry in {root}: {exc.strerror or 'read error'}."
                    if not (stat.S_ISDIR(entry_stat.st_mode) or stat.S_ISLNK(entry_stat.st_mode)):
                        continue
                    try:
                        service_directory = Path(entry.path).resolve(strict=True)
                        service_stat = service_directory.stat()
                        if not stat.S_ISDIR(service_stat.st_mode):
                            continue
                        run_path = service_directory / "run"
                        run_stat = run_path.stat()
                        if not stat.S_ISREG(run_stat.st_mode):
                            continue
                        link_target = os.readlink(entry.path) if stat.S_ISLNK(entry_stat.st_mode) else None
                    except (FileNotFoundError, NotADirectoryError, RuntimeError):
                        continue
                    except OSError as exc:
                        return [], f"Could not inspect a runit service definition in {root}: {exc.strerror or 'read error'}."
                    entries.append(RunitServiceEntry(
                        name=entry.name,
                        path=Path(entry.path),
                        root=root,
                        root_identity=root_identity,
                        entry_identity=(entry_stat.st_dev, entry_stat.st_ino, entry_stat.st_mode, entry_stat.st_ctime_ns),
                        entry_link_target=link_target,
                        service_identity=_stat_identity(service_stat),
                        run_identity=_stat_identity(run_stat),
                    ))
                    if len(entries) > MAX_RUNIT_SERVICES:
                        return [], "The standard runit service-directory scan exceeded its service limit; no startup change is available."
        except (FileNotFoundError, NotADirectoryError):
            continue
        except (OSError, RuntimeError) as exc:
            return [], f"Could not safely read standard runit service directories: {exc.strerror or 'read error'}."
    entries.sort(key=lambda item: (str(item.root), item.name.casefold()))
    return entries, None


def runit_startup_control_available() -> bool:
    if not sys.platform.startswith("linux") or _detect_init_system() != "runit":
        return False
    if not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")):
        return False
    entries, error = _service_entries()
    return error is None and bool(entries)


def _open_service_directory(path: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    return os.open(path, flags)


def _read_marker(fd: int) -> tuple[tuple[int, int, int, int, int, int, int] | None, str | None]:
    try:
        marker_stat = os.stat("down", dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, f"Could not safely inspect the runit down marker: {exc.strerror or 'read error'}."
    if not stat.S_ISREG(marker_stat.st_mode) or marker_stat.st_nlink != 1:
        return None, "The runit down marker is not a single-link regular file; no startup change is available."
    return _marker_identity(marker_stat), None


def _read_startup_snapshot(unit: str) -> tuple[RunitStartupSnapshot | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Runit startup control is available only on Linux."
    if _detect_init_system() != "runit":
        return None, "Runit startup control requires runit as the active init system."
    if not isinstance(unit, str) or len(unit) > 255 or not SERVICE_NAME_RE.fullmatch(unit):
        return None, "Service must be one exact runit service name."

    entries, scan_error = _service_entries()
    if scan_error:
        return None, scan_error
    matches = [entry for entry in entries if entry.name == unit]
    if not matches:
        return None, "The exact service was not found in a standard runsvdir service directory."
    if len(matches) != 1:
        return None, "The exact service name appears in multiple standard runsvdir directories; no startup change is available."
    selected = matches[0]
    aliases = [
        entry for entry in entries
        if entry.path != selected.path and entry.service_identity[:2] == selected.service_identity[:2]
    ]
    if aliases:
        return None, "The service directory is supervised under another name; its shared down marker cannot be changed safely."

    try:
        service_directory = selected.path.resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError, OSError, RuntimeError):
        return None, "The exact runit service directory changed or could not be resolved safely."
    try:
        fd = _open_service_directory(service_directory)
    except (FileNotFoundError, NotADirectoryError, OSError, RuntimeError):
        return None, "The exact runit service directory changed or could not be opened safely."
    try:
        service_stat = os.fstat(fd)
        service_identity = _stat_identity(service_stat)
        if service_identity != selected.service_identity:
            return None, "The exact runit service directory changed while its state was being read."
        try:
            run_stat = os.stat("run", dir_fd=fd, follow_symlinks=True)
        except OSError:
            return None, "The exact runit service no longer has a readable run script."
        if not stat.S_ISREG(run_stat.st_mode) or _stat_identity(run_stat) != selected.run_identity:
            return None, "The exact runit service run script changed while its state was being read."
        marker_identity, marker_error = _read_marker(fd)
        if marker_error:
            return None, marker_error
    finally:
        os.close(fd)

    enabled = marker_identity is None
    state = {
        "unit": unit,
        "entry_path": str(selected.path),
        "entry_identity": list(selected.entry_identity),
        "entry_link_target": selected.entry_link_target,
        "runlevel_root": str(selected.root),
        "runlevel_root_identity": list(selected.root_identity),
        "service_directory": str(service_directory),
        "service_identity": list(service_identity),
        "run_identity": list(_stat_identity(run_stat)),
        "marker_identity": list(marker_identity) if marker_identity else None,
    }
    encoded = json.dumps(state, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return RunitStartupSnapshot(
        unit=unit,
        service_directory=service_directory,
        enabled=enabled,
        state_token=hashlib.sha256(encoded).hexdigest(),
        service_identity=service_identity,
        marker_identity=marker_identity,
    ), None


def runit_startup_confirmation_details(
    action: str,
    unit: str,
) -> tuple[RunitStartupSnapshot | None, str | None]:
    if not isinstance(action, str) or action not in {"enable", "disable"}:
        return None, "Action must be enable or disable."
    return _read_startup_snapshot(unit)


def _response(
    action: RunitStartupAction,
    unit: str,
    *,
    confirmed: bool,
    snapshot: RunitStartupSnapshot | None,
    success: bool,
    verified: bool = False,
    message: str,
) -> RunitServiceStartupResponse:
    return RunitServiceStartupResponse(
        success=success,
        action=action,
        unit=unit,
        startup_state=("enabled" if snapshot.enabled else "disabled") if snapshot else None,
        state_verified=verified,
        user_confirmed=confirmed,
        message=message,
    )


def perform_runit_startup_action(
    action: RunitStartupAction,
    unit: str,
    expected_state_token: str,
    *,
    confirmed: bool = False,
) -> RunitServiceStartupResponse:
    valid_action = isinstance(action, str) and action in {"enable", "disable"}
    safe_action: RunitStartupAction = action if valid_action else "enable"
    safe_unit = unit[:255] if isinstance(unit, str) else ""
    if not valid_action:
        return _response(safe_action, safe_unit, confirmed=False, snapshot=None, success=False, message="Unsupported runit startup action supplied; no change was made.")
    if not isinstance(unit, str) or len(unit) > 255 or not SERVICE_NAME_RE.fullmatch(unit):
        return _response(safe_action, safe_unit, confirmed=False, snapshot=None, success=False, message="Service must be one exact runit service name; no change was made.")
    if confirmed is not True:
        return _response(safe_action, safe_unit, confirmed=False, snapshot=None, success=False, message="Explicit client confirmation is required; no runit startup change was made.")

    snapshot, error = _read_startup_snapshot(safe_unit)
    if snapshot is None:
        return _response(safe_action, safe_unit, confirmed=True, snapshot=None, success=False, message=error or "The exact runit startup state could not be revalidated; no change was made.")
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return _response(safe_action, safe_unit, confirmed=True, snapshot=snapshot, success=False, message="A valid state token from the exact runit startup confirmation is required; no change was made.")
    if snapshot.state_token != expected_state_token:
        return _response(safe_action, safe_unit, confirmed=True, snapshot=snapshot, success=False, message="The runit service directory or down-marker state changed after confirmation; review and confirm again.")

    desired_enabled = safe_action == "enable"
    if snapshot.enabled == desired_enabled:
        state = "enabled" if desired_enabled else "disabled"
        return _response(safe_action, safe_unit, confirmed=True, snapshot=snapshot, success=True, verified=True, message=f"The exact runit service is already {state}; no marker change was needed.")

    try:
        fd = _open_service_directory(snapshot.service_directory)
    except (FileNotFoundError, NotADirectoryError, OSError):
        return _response(safe_action, safe_unit, confirmed=True, snapshot=snapshot, success=False, message="The exact runit service directory changed or could not be opened safely; no marker change was made.")

    mutation_error: str | None = None
    try:
        if _stat_identity(os.fstat(fd)) != snapshot.service_identity:
            mutation_error = "The exact runit service directory changed after confirmation; no marker change was made."
        else:
            marker_identity, marker_error = _read_marker(fd)
            if marker_error:
                mutation_error = marker_error
            elif marker_identity != snapshot.marker_identity:
                mutation_error = "The runit down-marker state changed after confirmation; no marker change was made."
            elif desired_enabled:
                try:
                    os.unlink("down", dir_fd=fd)
                except OSError as exc:
                    mutation_error = f"Could not remove the exact runit down marker: {exc.strerror or 'write error'}."
            else:
                marker_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                try:
                    marker_fd = os.open("down", marker_flags, 0o644, dir_fd=fd)
                except OSError as exc:
                    mutation_error = f"Could not create the exact runit down marker: {exc.strerror or 'write error'}."
                else:
                    try:
                        marker_stat = os.fstat(marker_fd)
                        if not stat.S_ISREG(marker_stat.st_mode) or marker_stat.st_nlink != 1:
                            mutation_error = "The new runit down marker did not have the expected file type; inspect the service directory."
                        else:
                            os.fchmod(marker_fd, 0o644)
                            os.fsync(marker_fd)
                    except OSError as exc:
                        mutation_error = f"The runit down marker was created but could not be synced: {exc.strerror or 'write error'}."
                    finally:
                        os.close(marker_fd)
            if mutation_error is None:
                try:
                    os.fsync(fd)
                except OSError as exc:
                    mutation_error = f"The runit down marker changed but the service directory could not be synced: {exc.strerror or 'write error'}."
    finally:
        os.close(fd)

    verified_snapshot, verify_error = _read_startup_snapshot(safe_unit)
    verified = verified_snapshot is not None and verified_snapshot.enabled == desired_enabled
    if mutation_error:
        detail = f" {verify_error}" if verify_error else ""
        return _response(safe_action, safe_unit, confirmed=True, snapshot=verified_snapshot or snapshot, success=False, verified=verified, message=f"{mutation_error}{detail}")
    if not verified:
        return _response(safe_action, safe_unit, confirmed=True, snapshot=verified_snapshot or snapshot, success=False, verified=False, message=verify_error or "The runit down-marker change did not reach the requested startup state; inspect the service directory.")
    state = "enabled" if desired_enabled else "disabled"
    return _response(safe_action, safe_unit, confirmed=True, snapshot=verified_snapshot, success=True, verified=True, message=f"The exact runit service is now {state} for a future runsv start. Its currently running service and supervisor were not changed.")
