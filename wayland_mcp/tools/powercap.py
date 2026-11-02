"""Bounded inventory and confirmation-gated control for Linux powercap limits."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import (
    PowercapLimitActionResponse,
    PowercapLimitInfo,
    PowercapLimitListResponse,
)

POWERCAP_ROOT = Path("/sys/class/powercap")
SYS_DEVICES_ROOT = Path("/sys/devices")
ZONE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
CONSTRAINT_RE = re.compile(r"^constraint_([0-9]{1,3})_power_limit_uw$")
SAFE_LABEL_RE = re.compile(r"^[A-Za-z0-9_.+:/ -]{1,128}$")
MAX_POWER_UW = 1_000_000_000_000
MAX_CONSTRAINT_INDEX = 255
MAX_DIRECTORY_SCAN_ENTRIES = 4096
MAX_ZONES = 1024
MAX_ZONE_DEPTH = 16
MAX_LIMITS = 256


@dataclass(frozen=True, slots=True)
class PowercapTarget:
    zone: str
    zone_name: str
    constraint_index: int
    constraint_name: str | None
    current_power_limit_uw: int
    minimum_power_limit_uw: int
    maximum_power_limit_uw: int
    time_window_us: int | None
    class_root: str
    zone_path: str
    root_identity: tuple[int, int]
    zone_identity: tuple[int, int]
    limit_identity: tuple[int, int]
    digest: str


def _read_text(path: Path, maximum_bytes: int = 256) -> str | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(maximum_bytes + 1)
        if len(raw) > maximum_bytes:
            return None
        value = raw.decode("ascii", errors="strict").strip()
        if any(ord(char) < 32 and char not in "\t" for char in value):
            return None
        return value
    except (OSError, UnicodeError):
        return None


def _read_uint(path: Path, maximum: int = MAX_POWER_UW) -> int | None:
    raw = _read_text(path, 64)
    if raw is None or not re.fullmatch(r"[0-9]{1,20}", raw):
        return None
    value = int(raw, 10)
    return value if 0 <= value <= maximum else None


def _attribute_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return info.st_dev, info.st_ino


def _powercap_root() -> tuple[Path, Path, tuple[int, int]] | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        class_root = POWERCAP_ROOT.resolve(strict=True)
        devices_root = SYS_DEVICES_ROOT.resolve(strict=True)
        class_root.relative_to(devices_root)
        root_info = class_root.stat()
    except (OSError, RuntimeError, ValueError):
        return None
    if not stat.S_ISDIR(root_info.st_mode):
        return None
    return POWERCAP_ROOT, class_root, (root_info.st_dev, root_info.st_ino)


def _safe_zone_parts(zone: str) -> tuple[str, ...] | None:
    if not isinstance(zone, str) or not zone or len(zone) > 512:
        return None
    parts = tuple(zone.split("/"))
    if any(not ZONE_COMPONENT_RE.fullmatch(part) for part in parts):
        return None
    return parts


def _resolve_zone(
    root: Path,
    class_root: Path,
    zone: str,
) -> tuple[Path | None, tuple[int, int] | None, str | None]:
    parts = _safe_zone_parts(zone)
    if parts is None:
        return None, None, "zone must be one exact relative power-zone path from list_powercap_limits."
    candidate = root.joinpath(*parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(class_root)
        info = resolved.stat()
    except (OSError, RuntimeError, ValueError):
        return None, None, "The selected power zone is unavailable or no longer beneath /sys/class/powercap."
    if not stat.S_ISDIR(info.st_mode):
        return None, None, "The selected power zone is not a directory."
    return candidate, (info.st_dev, info.st_ino), None


def _zone_directories() -> tuple[list[tuple[str, Path, tuple[int, int]]], bool]:
    roots = _powercap_root()
    if roots is None:
        return [], False
    root, class_root, _root_identity = roots
    pending: list[tuple[Path, str, int]] = [(root, "", 0)]
    seen: set[str] = {str(class_root)}
    zones: list[tuple[str, Path, tuple[int, int]]] = []
    partial = False
    scanned = 0
    while pending:
        parent, prefix, depth = pending.pop(0)
        if depth >= MAX_ZONE_DEPTH:
            partial = True
            continue
        try:
            with os.scandir(parent) as entries:
                child_names: list[str] = []
                for entry in entries:
                    scanned += 1
                    if scanned > MAX_DIRECTORY_SCAN_ENTRIES:
                        partial = True
                        pending.clear()
                        break
                    child_names.append(entry.name)
        except OSError:
            partial = True
            continue
        for child_name in sorted(child_names):
            if not ZONE_COMPONENT_RE.fullmatch(child_name):
                continue
            try:
                path = parent / child_name
                if not path.is_dir():
                    continue
                resolved = path.resolve(strict=True)
                resolved.relative_to(class_root)
                if str(resolved) in seen:
                    continue
                info = resolved.stat()
            except (OSError, RuntimeError, ValueError):
                partial = True
                continue
            if not stat.S_ISDIR(info.st_mode):
                continue
            seen.add(str(resolved))
            zone = f"{prefix}/{child_name}" if prefix else child_name
            zones.append((zone, path, (info.st_dev, info.st_ino)))
            if len(zones) >= MAX_ZONES:
                partial = True
                pending.clear()
                break
            pending.append((path, zone, depth + 1))
    return zones, partial


def _constraint_name(zone_path: Path, index: int) -> str | None:
    value = _read_text(zone_path / f"constraint_{index}_name", 128)
    if value is None or not SAFE_LABEL_RE.fullmatch(value):
        return None
    return value


def list_powercap_limits(query: str = "", limit: int = 64) -> PowercapLimitListResponse:
    if not sys.platform.startswith("linux"):
        return PowercapLimitListResponse(success=False, message="Linux powercap inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256 or any(ord(char) < 32 for char in query):
        return PowercapLimitListResponse(success=False, message="query must be text with at most 256 characters and no control characters.")
    if type(limit) is not int or not 1 <= limit <= MAX_LIMITS:
        return PowercapLimitListResponse(success=False, message=f"limit must be an integer from 1 through {MAX_LIMITS}.")
    roots = _powercap_root()
    if roots is None:
        return PowercapLimitListResponse(success=False, message="The Linux powercap sysfs hierarchy is unavailable.")
    root, class_root, _root_identity = roots
    zones, partial = _zone_directories()
    items: list[PowercapLimitInfo] = []
    scanned_constraints = 0
    for zone, lexical_path, _zone_identity in zones:
        try:
            zone_path = lexical_path.resolve(strict=True)
            zone_path.relative_to(class_root)
        except (OSError, RuntimeError, ValueError):
            partial = True
            continue
        zone_name = _read_text(zone_path / "name", 128)
        if zone_name is None or not SAFE_LABEL_RE.fullmatch(zone_name):
            continue
        try:
            with os.scandir(zone_path) as entries:
                cap_names: list[str] = []
                for entry in entries:
                    scanned_constraints += 1
                    if scanned_constraints > MAX_DIRECTORY_SCAN_ENTRIES:
                        partial = True
                        break
                    if CONSTRAINT_RE.fullmatch(entry.name):
                        cap_names.append(entry.name)
        except OSError:
            partial = True
            continue
        for cap_name in sorted(cap_names):
            match = CONSTRAINT_RE.fullmatch(cap_name)
            assert match is not None
            index = int(match.group(1), 10)
            if index > MAX_CONSTRAINT_INDEX:
                partial = True
                continue
            current = _read_uint(zone_path / cap_name)
            if current is None:
                partial = True
                continue
            minimum = _read_uint(zone_path / f"constraint_{index}_min_power_uw")
            maximum = _read_uint(zone_path / f"constraint_{index}_max_power_uw")
            time_window = _read_uint(zone_path / f"constraint_{index}_time_window_us", (1 << 64) - 1)
            constraint_name = _constraint_name(zone_path, index)
            controllable = (
                minimum is not None
                and maximum is not None
                and 0 < minimum <= current <= maximum
            )
            if not controllable:
                partial = True
            query_material = " ".join((zone, zone_name, constraint_name or "", str(index)))
            if query and query.casefold() not in query_material.casefold():
                continue
            items.append(PowercapLimitInfo(
                zone=zone,
                zone_name=zone_name,
                constraint_index=index,
                constraint_name=constraint_name,
                current_power_limit_uw=current,
                minimum_power_limit_uw=minimum,
                maximum_power_limit_uw=maximum,
                time_window_us=time_window,
                controllable=controllable,
            ))
        if scanned_constraints > MAX_DIRECTORY_SCAN_ENTRIES:
            break
    items.sort(key=lambda item: (item.zone, item.constraint_index))
    total = len(items)
    return PowercapLimitListResponse(
        success=True,
        total_limits=total,
        returned_limits=min(total, limit),
        limits=items[:limit],
        limit=limit,
        truncated=total > limit,
        partial=partial,
        message="Some powercap zones or constraint ranges could not be fully read." if partial else None,
    )


def _target(
    zone: str,
    constraint_index: int,
    target_power_limit_uw: int,
) -> tuple[PowercapTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Powercap control is available only on Linux."
    if type(constraint_index) is not int or not 0 <= constraint_index <= MAX_CONSTRAINT_INDEX:
        return None, None, f"constraint_index must be an integer from 0 through {MAX_CONSTRAINT_INDEX}."
    if type(target_power_limit_uw) is not int or not 0 < target_power_limit_uw <= MAX_POWER_UW:
        return None, None, "target_power_limit_uw must be a positive integer no greater than 1000000000000."
    roots = _powercap_root()
    if roots is None:
        return None, None, "The Linux powercap sysfs hierarchy is unavailable."
    root, class_root, root_identity = roots
    zone_path, zone_identity, error = _resolve_zone(root, class_root, zone)
    if error or zone_path is None or zone_identity is None:
        return None, None, error or "The exact power zone could not be verified."
    try:
        resolved_zone = zone_path.resolve(strict=True)
        resolved_zone.relative_to(class_root)
    except (OSError, RuntimeError, ValueError):
        return None, None, "The selected power zone changed while it was being inspected."
    zone_name = _read_text(resolved_zone / "name", 128)
    if zone_name is None or not SAFE_LABEL_RE.fullmatch(zone_name):
        return None, None, "The selected power zone name could not be verified."
    cap_path = resolved_zone / f"constraint_{constraint_index}_power_limit_uw"
    cap_identity = _attribute_identity(cap_path)
    if cap_identity is None:
        return None, None, "The selected power limit is unavailable or is not a sysfs file."
    current = _read_uint(cap_path)
    minimum = _read_uint(resolved_zone / f"constraint_{constraint_index}_min_power_uw")
    maximum = _read_uint(resolved_zone / f"constraint_{constraint_index}_max_power_uw")
    if current is None or minimum is None or maximum is None or not 0 < minimum <= current <= maximum:
        return None, None, "The driver must report a valid current power limit and minimum/maximum range before this constraint can be changed."
    if not minimum <= target_power_limit_uw <= maximum:
        return None, None, f"target_power_limit_uw must be within the driver-reported range {minimum}..{maximum}."
    if target_power_limit_uw == current:
        return None, None, "The requested power limit already matches the current value."
    constraint_name = _constraint_name(resolved_zone, constraint_index)
    time_window = _read_uint(resolved_zone / f"constraint_{constraint_index}_time_window_us", (1 << 64) - 1)
    material = {
        "zone": zone,
        "zone_name": zone_name,
        "constraint_index": constraint_index,
        "constraint_name": constraint_name,
        "current": current,
        "minimum": minimum,
        "maximum": maximum,
        "target": target_power_limit_uw,
        "time_window_us": time_window,
        "class_root": str(class_root),
        "zone_path": str(resolved_zone),
        "root_identity": root_identity,
        "zone_identity": zone_identity,
        "limit_identity": cap_identity,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return PowercapTarget(
        zone, zone_name, constraint_index, constraint_name, current, minimum, maximum,
        time_window, str(class_root), str(resolved_zone), root_identity, zone_identity,
        cap_identity, digest,
    ), f"Powercap limit {digest[:16]}", None


def powercap_limit_confirmation_details(
    zone: str,
    constraint_index: int,
    target_power_limit_uw: int,
) -> tuple[PowercapTarget | None, str | None, str | None]:
    return _target(zone, constraint_index, target_power_limit_uw)


def _write_limit(
    zone_path: Path,
    attribute_name: str,
    expected_zone_identity: tuple[int, int],
    expected_attribute_identity: tuple[int, int],
    value: int,
) -> None:
    zone_fd: int | None = None
    fd: int | None = None
    try:
        zone_fd = os.open(
            zone_path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        zone_info = os.fstat(zone_fd)
        if not stat.S_ISDIR(zone_info.st_mode) or (zone_info.st_dev, zone_info.st_ino) != expected_zone_identity:
            raise OSError("The powercap zone identity changed before writing.")
        fd = os.open(
            attribute_name,
            os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=zone_fd,
        )
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != expected_attribute_identity:
            raise OSError("The powercap attribute identity changed before writing.")
        data = f"{value}\n".encode("ascii")
        if os.write(fd, data) != len(data):
            raise OSError("The powercap write was incomplete.")
    finally:
        if fd is not None:
            os.close(fd)
        if zone_fd is not None:
            os.close(zone_fd)


def perform_powercap_limit_action(
    zone: str,
    constraint_index: int,
    target_power_limit_uw: int,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> PowercapLimitActionResponse:
    target, phrase, error = _target(zone, constraint_index, target_power_limit_uw)
    if error or target is None or phrase is None:
        return PowercapLimitActionResponse(success=False, action="set_limit", zone=zone, constraint_index=constraint_index, target_power_limit_uw=target_power_limit_uw, user_confirmed=confirmed is True, message=error or "The powercap limit request could not be verified.")
    if confirmed is not True:
        return PowercapLimitActionResponse(success=False, action="set_limit", zone=zone, constraint_index=constraint_index, target_power_limit_uw=target_power_limit_uw, user_confirmed=False, message="Explicit client confirmation is required; no power limit was changed.")
    if confirmation_phrase != phrase:
        return PowercapLimitActionResponse(success=False, action="set_limit", zone=zone, constraint_index=constraint_index, target_power_limit_uw=target_power_limit_uw, user_confirmed=True, message="Confirmation did not match the exact power zone, constraint, range, and current state.")
    current, current_phrase, error = _target(zone, constraint_index, target_power_limit_uw)
    if error or current is None or current_phrase != phrase:
        return PowercapLimitActionResponse(success=False, action="set_limit", zone=zone, constraint_index=constraint_index, target_power_limit_uw=target_power_limit_uw, user_confirmed=True, message=error or "Powercap identity or state changed after confirmation; no write was performed.")
    roots = _powercap_root()
    if roots is None:
        return PowercapLimitActionResponse(success=False, action="set_limit", zone=zone, constraint_index=constraint_index, target_power_limit_uw=target_power_limit_uw, user_confirmed=True, message="The powercap hierarchy disappeared before the write.")
    root, class_root, root_identity = roots
    zone_path, zone_identity, error = _resolve_zone(root, class_root, zone)
    if error or zone_path is None or zone_identity != target.zone_identity or root_identity != target.root_identity or str(class_root) != target.class_root:
        return PowercapLimitActionResponse(success=False, action="set_limit", zone=zone, constraint_index=constraint_index, target_power_limit_uw=target_power_limit_uw, user_confirmed=True, message=error or "The powercap hierarchy or zone identity changed immediately before the write.")
    resolved_zone = zone_path.resolve(strict=True)
    cap_path = resolved_zone / f"constraint_{constraint_index}_power_limit_uw"
    try:
        _write_limit(
            resolved_zone,
            f"constraint_{constraint_index}_power_limit_uw",
            target.zone_identity,
            target.limit_identity,
            target_power_limit_uw,
        )
    except OSError as exc:
        return PowercapLimitActionResponse(success=False, action="set_limit", zone=zone, constraint_index=constraint_index, target_power_limit_uw=target_power_limit_uw, user_confirmed=True, message=f"The power limit could not be written with current permissions: {exc.strerror or str(exc) or type(exc).__name__}.")
    after_roots = _powercap_root()
    after_zone: Path | None = None
    after_zone_identity: tuple[int, int] | None = None
    if after_roots is not None:
        after_root, after_class_root, after_root_identity = after_roots
        after_zone, after_zone_identity, _after_error = _resolve_zone(after_root, after_class_root, zone)
    else:
        after_class_root = None
        after_root_identity = None
    try:
        after_resolved = after_zone.resolve(strict=True) if after_zone is not None else None
        if after_resolved is not None and after_class_root is not None:
            after_resolved.relative_to(after_class_root)
    except (OSError, RuntimeError, ValueError):
        after_resolved = None
    after_cap_path = after_resolved / f"constraint_{constraint_index}_power_limit_uw" if after_resolved is not None else None
    resulting = _read_uint(after_cap_path) if after_cap_path is not None else None
    after_limit_identity = _attribute_identity(after_cap_path) if after_cap_path is not None else None
    after_minimum = _read_uint(after_resolved / f"constraint_{constraint_index}_min_power_uw") if after_resolved is not None else None
    after_maximum = _read_uint(after_resolved / f"constraint_{constraint_index}_max_power_uw") if after_resolved is not None else None
    if (
        after_roots is None
        or after_class_root is None
        or after_root_identity != target.root_identity
        or str(after_class_root) != target.class_root
        or after_zone_identity != target.zone_identity
        or after_limit_identity != target.limit_identity
        or after_minimum != target.minimum_power_limit_uw
        or after_maximum != target.maximum_power_limit_uw
        or resulting != target_power_limit_uw
    ):
        return PowercapLimitActionResponse(success=False, action="set_limit", zone=zone, constraint_index=constraint_index, target_power_limit_uw=target_power_limit_uw, resulting_power_limit_uw=resulting, user_confirmed=True, message="The value was written, but the requested limit or exact power-zone identity could not be verified; inspect the current driver state.")
    return PowercapLimitActionResponse(success=True, action="set_limit", zone=zone, constraint_index=constraint_index, target_power_limit_uw=target_power_limit_uw, resulting_power_limit_uw=resulting, user_confirmed=True, message="Set and verified the driver-reported powercap limit. A lower limit can reduce performance; a higher limit can increase power use and heat.")
