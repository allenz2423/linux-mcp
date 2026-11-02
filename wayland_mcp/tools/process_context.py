"""Read-only scheduler, cgroup, and namespace context for one Linux PID."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from wayland_mcp.models import (
    ProcessCgroupMembership,
    ProcessCgroupV2Resources,
    ProcessExecutionContextResponse,
)

PROC = Path("/proc")
CGROUP_ROOT = Path("/sys/fs/cgroup")
MAX_PID = 2**31 - 1
MAX_STAT_BYTES = 8192
MAX_STATUS_BYTES = 64 * 1024
MAX_CGROUP_BYTES = 16 * 1024
MAX_CGROUP_LINES = 64
MAX_CGROUP_PATH_CHARS = 512
MAX_CGROUP_MEMBERSHIPS = 64
MAX_CGROUP_DEPTH = 16
MAX_MOUNTINFO_BYTES = 256 * 1024
MAX_CGROUP_ATTRIBUTE_BYTES = 4096
NAMESPACE_NAMES = (
    "cgroup", "ipc", "mnt", "net", "pid", "pid_for_children",
    "time", "time_for_children", "user", "uts",
)
NAMESPACE_RE = re.compile(r"^[a-z_]+:\[([0-9]{1,20})\]$")
NAMESPACE_LINK_TYPES = {
    "cgroup": "cgroup",
    "ipc": "ipc",
    "mnt": "mnt",
    "net": "net",
    "pid": "pid",
    "pid_for_children": "pid",
    "time": "time",
    "time_for_children": "time",
    "user": "user",
    "uts": "uts",
}
CPU_NODE_LIST_RE = re.compile(r"[0-9]{1,10}(?:-[0-9]{1,10})?(?:,[0-9]{1,10}(?:-[0-9]{1,10})?)*")
CAPABILITY_MASK_RE = re.compile(r"[0-9a-fA-F]{1,64}")
CONTROLLER_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
SCHEDULING_POLICIES = {
    0: "normal",
    1: "fifo",
    2: "round_robin",
    3: "batch",
    4: "reserved_iso",
    5: "idle",
    6: "deadline",
    7: "ext",
}


def _read_limited(path: Path, max_bytes: int) -> tuple[str, bool]:
    with path.open("rb") as stream:
        content = stream.read(max_bytes + 1)
    truncated = len(content) > max_bytes
    return content[:max_bytes].decode("utf-8", errors="replace"), truncated


def _parse_stat(pid: int, content: str) -> dict[str, int | str] | None:
    closing_paren = content.rfind(")")
    if closing_paren < 0:
        return None
    prefix = content[:closing_paren].split()
    fields = content[closing_paren + 1 :].split()
    # Fields begin at proc stat field 3 (state). The last index used here is
    # field 41 (scheduling policy), relative to that starting point.
    if not prefix or prefix[0] != str(pid) or len(fields) <= 38:
        return None
    try:
        values: dict[str, int | str] = {
            "state": fields[0],
            "parent_pid": int(fields[1], 10),
            "priority": int(fields[15], 10),
            "nice": int(fields[16], 10),
            "start_ticks": int(fields[19], 10),
            "processor": int(fields[36], 10),
            "rt_priority": int(fields[37], 10),
            "policy": int(fields[38], 10),
        }
    except (ValueError, IndexError):
        return None
    if (
        values["parent_pid"] < 0
        or values["start_ticks"] < 0
        or values["processor"] < 0
        or values["rt_priority"] < 0
        or values["policy"] < 0
        or not -20 <= values["nice"] <= 19
        or not isinstance(values["state"], str)
        or len(values["state"]) != 1
    ):
        return None
    return values


def _status_fields(content: str) -> tuple[dict[str, str], bool]:
    wanted = {
        "Name", "Cpus_allowed_list", "Mems_allowed_list", "NoNewPrivs",
        "Seccomp", "Seccomp_filters", "CapEff",
    }
    fields: dict[str, str] = {}
    malformed = False
    for line in content.splitlines():
        key, separator, value = line.partition(":")
        if not separator or key not in wanted:
            continue
        value = value.strip()
        if len(value) > 4096:
            value = value[:4096]
            malformed = True
        fields[key] = value
    return fields, malformed


def _parse_integer(
    fields: dict[str, str],
    key: str,
    *,
    minimum: int = 0,
    maximum: int = 2**32 - 1,
) -> tuple[int | None, bool]:
    value = fields.get(key)
    if value is None:
        return None, False
    try:
        parsed = int(value, 10)
    except ValueError:
        return None, True
    if not minimum <= parsed <= maximum:
        return None, True
    return parsed, False


def _parse_id_list(fields: dict[str, str], key: str) -> tuple[str | None, bool]:
    value = fields.get(key)
    if value is None:
        return None, False
    if len(value) > 2048 or not CPU_NODE_LIST_RE.fullmatch(value):
        return None, True
    return value, False


def _parse_namespace_link_target(name: str, target: str) -> int | None:
    expected_type = NAMESPACE_LINK_TYPES.get(name)
    if expected_type is None:
        raise ValueError("unknown namespace type")
    if target == "" and name in {"pid_for_children", "time_for_children"}:
        return None
    match = NAMESPACE_RE.fullmatch(target)
    if match is None or target.partition(":")[0] != expected_type:
        raise ValueError("malformed namespace link target")
    inode = int(match.group(1), 10)
    if not 0 < inode <= 2**64 - 1:
        raise ValueError("namespace inode is out of range")
    return inode


def _parse_cgroups(content: str) -> tuple[list[ProcessCgroupMembership], bool]:
    memberships: list[ProcessCgroupMembership] = []
    partial = False
    lines = content.splitlines()
    if len(lines) > MAX_CGROUP_LINES:
        lines = lines[:MAX_CGROUP_LINES]
        partial = True
    for line in lines:
        hierarchy, first_separator, remainder = line.partition(":")
        controllers_raw, second_separator, path = remainder.partition(":")
        if not first_separator or not second_separator or not hierarchy.isascii() or not hierarchy.isdecimal():
            partial = True
            continue
        hierarchy_id = int(hierarchy, 10)
        if hierarchy_id > 2**32 - 1 or not path.startswith("/"):
            partial = True
            continue
        controllers = []
        for controller in controllers_raw.split(",") if controllers_raw else []:
            if not CONTROLLER_RE.fullmatch(controller):
                partial = True
                continue
            controllers.append(controller)
        sanitized_path = re.sub(r"[\x00-\x1f\x7f]", "?", path)[:MAX_CGROUP_PATH_CHARS]
        if len(path) > MAX_CGROUP_PATH_CHARS:
            partial = True
        memberships.append(ProcessCgroupMembership(
            hierarchy_id=hierarchy_id,
            controllers=controllers,
            path=sanitized_path,
        ))
        if len(memberships) >= MAX_CGROUP_MEMBERSHIPS:
            if len(lines) > len(memberships):
                partial = True
            break
    return memberships, partial


def _namespace_ids(pid: int) -> tuple[dict[str, int], bool]:
    namespaces: dict[str, int] = {}
    partial = False
    process_dir = PROC / str(pid)
    for name in NAMESPACE_NAMES:
        path = process_dir / "ns" / name
        try:
            target = str(path.readlink())
        except FileNotFoundError:
            # Optional namespace types are absent on older kernels and for
            # processes without a distinct child namespace.
            continue
        except OSError:
            partial = True
            continue
        try:
            inode = _parse_namespace_link_target(name, target)
        except ValueError:
            partial = True
            continue
        if inode is not None:
            namespaces[name] = inode
    return namespaces, partial


def _read_small_attribute(path: Path) -> tuple[str | None, bool]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_CGROUP_ATTRIBUTE_BYTES + 1)
    except FileNotFoundError:
        return None, False
    except OSError:
        return None, True
    if len(raw) > MAX_CGROUP_ATTRIBUTE_BYTES:
        return None, True
    try:
        return raw.decode("ascii").strip(), False
    except UnicodeDecodeError:
        return None, True


def _read_cgroup_integer(path: Path) -> tuple[int | None, bool]:
    raw, partial = _read_small_attribute(path)
    if raw is None:
        return None, partial
    try:
        value = int(raw, 10)
    except ValueError:
        return None, True
    if not 0 <= value <= 2**64 - 1:
        return None, True
    return value, partial


def _read_cgroup_limit(path: Path) -> tuple[int | None, bool | None, bool]:
    raw, partial = _read_small_attribute(path)
    if raw is None:
        return None, None, partial
    if raw == "max":
        return None, True, partial
    try:
        value = int(raw, 10)
    except ValueError:
        return None, None, True
    if not 0 <= value <= 2**64 - 1:
        return None, None, True
    return value, False, partial


def _read_keyed_cgroup_stats(
    path: Path,
    allowed_keys: set[str],
) -> tuple[dict[str, int], bool]:
    raw, partial = _read_small_attribute(path)
    if raw is None:
        return {}, partial
    values: dict[str, int] = {}
    lines = raw.splitlines()
    if len(lines) > 32:
        lines = lines[:32]
        partial = True
    for line in lines:
        parts = line.split()
        if len(parts) != 2:
            partial = True
            continue
        key, raw_value = parts
        if key not in allowed_keys:
            continue
        if key in values:
            partial = True
            continue
        try:
            value = int(raw_value, 10)
        except ValueError:
            partial = True
            continue
        if not 0 <= value <= 2**64 - 1:
            partial = True
            continue
        values[key] = value
    return values, partial


def _same_cgroup_namespace(pid: int) -> tuple[bool, bool]:
    namespace_re = re.compile(r"^cgroup:\[([0-9]{1,20})\]$")
    try:
        current = str((PROC / "self/ns/cgroup").readlink())
        target = str((PROC / str(pid) / "ns/cgroup").readlink())
    except OSError:
        return False, True
    current_match = namespace_re.fullmatch(current)
    target_match = namespace_re.fullmatch(target)
    if current_match is None or target_match is None:
        return False, True
    return current_match.group(1) == target_match.group(1), False


def _has_cgroup2_mount() -> tuple[bool, bool]:
    try:
        mountinfo, truncated = _read_limited(PROC / "self/mountinfo", MAX_MOUNTINFO_BYTES)
    except OSError:
        return False, True
    if truncated:
        return False, True
    for line in mountinfo.splitlines()[:8192]:
        before, separator, after = line.partition(" - ")
        if not separator:
            continue
        mount_fields = before.split()
        filesystem_fields = after.split()
        if len(mount_fields) >= 5 and len(filesystem_fields) >= 1:
            if (
                filesystem_fields[0] == "cgroup2"
                and mount_fields[3] == "/"
                and mount_fields[4] == str(CGROUP_ROOT)
            ):
                return True, False
    return False, False


def _unified_cgroup_path(content: str) -> tuple[str | None, bool]:
    path: str | None = None
    partial = False
    lines = content.splitlines()
    if len(lines) > MAX_CGROUP_LINES:
        lines = lines[:MAX_CGROUP_LINES]
        partial = True
    for line in lines:
        hierarchy, first_separator, remainder = line.partition(":")
        controllers, second_separator, candidate = remainder.partition(":")
        if not first_separator or not second_separator or not hierarchy.isascii() or not hierarchy.isdecimal():
            continue
        if hierarchy == "0" and controllers == "":
            if path is not None:
                partial = True
                continue
            path = candidate
    return path, partial


def _resolve_cgroup_v2_path(
    pid: int,
    content: str,
) -> tuple[Path | None, str | None, Path | None, str | None]:
    unified_path, malformed = _unified_cgroup_path(content)
    if unified_path is None:
        return None, None, None, "The process has no visible unified cgroup-v2 membership."
    if malformed:
        return None, None, None, "The process cgroup membership list was malformed or truncated."
    if len(unified_path) > MAX_CGROUP_PATH_CHARS or not unified_path.startswith("/"):
        return None, None, None, "The cgroup-v2 path was not safe to resolve."
    same_namespace, namespace_error = _same_cgroup_namespace(pid)
    if namespace_error or not same_namespace:
        return None, None, None, "Cgroup-v2 resources are read only when the target shares this process's cgroup namespace."
    mounted, mount_error = _has_cgroup2_mount()
    if mount_error or not mounted:
        return None, None, None, "A cgroup-v2 hierarchy rooted at /sys/fs/cgroup was not available."

    components = [] if unified_path == "/" else unified_path[1:].split("/")
    if any(not part or part in {".", ".."} or any(ord(char) < 32 or ord(char) == 127 for char in part) for part in components):
        return None, None, None, "The cgroup-v2 path contains an unsafe component."
    try:
        root = CGROUP_ROOT.resolve(strict=True)
        if not root.is_dir():
            return None, None, None, "The cgroup-v2 mount point is not a directory."
        leaf = root.joinpath(*components).resolve(strict=True)
        leaf.relative_to(root)
        if not leaf.is_dir():
            return None, None, None, "The process cgroup-v2 path is not a directory."
    except (OSError, RuntimeError, ValueError):
        return None, None, None, "The cgroup-v2 path could not be safely resolved."
    return root, leaf, unified_path, None


def _read_cgroup_v2_group(
    directory: Path,
    cgroup_path: str,
    level: int,
) -> tuple[ProcessCgroupV2Resources, bool]:
    partial = False

    cpu_max, field_partial = _read_small_attribute(directory / "cpu.max")
    partial |= field_partial
    cpu_quota: int | None = None
    cpu_period: int | None = None
    cpu_unlimited: bool | None = None
    if cpu_max is not None:
        fields = cpu_max.split()
        if len(fields) != 2:
            partial = True
        else:
            if fields[0] == "max":
                cpu_unlimited = True
            else:
                try:
                    cpu_quota = int(fields[0], 10)
                    if cpu_quota < 0:
                        raise ValueError
                    cpu_unlimited = False
                except ValueError:
                    partial = True
                    cpu_quota = None
            try:
                cpu_period = int(fields[1], 10)
                if cpu_period <= 0:
                    raise ValueError
            except ValueError:
                partial = True
                cpu_period = None

    cpu_weight, field_partial = _read_cgroup_integer(directory / "cpu.weight")
    partial |= field_partial
    if cpu_weight is not None and not 1 <= cpu_weight <= 10_000:
        cpu_weight = None
        partial = True
    cpu_stats, field_partial = _read_keyed_cgroup_stats(
        directory / "cpu.stat",
        {"usage_usec", "user_usec", "system_usec", "nr_periods", "nr_throttled", "throttled_usec"},
    )
    partial |= field_partial

    memory_current, field_partial = _read_cgroup_integer(directory / "memory.current")
    partial |= field_partial
    memory_max, memory_unlimited, field_partial = _read_cgroup_limit(directory / "memory.max")
    partial |= field_partial
    memory_high, memory_high_unlimited, field_partial = _read_cgroup_limit(directory / "memory.high")
    partial |= field_partial
    memory_swap_current, field_partial = _read_cgroup_integer(directory / "memory.swap.current")
    partial |= field_partial
    memory_swap_max, memory_swap_unlimited, field_partial = _read_cgroup_limit(directory / "memory.swap.max")
    partial |= field_partial
    memory_events, field_partial = _read_keyed_cgroup_stats(
        directory / "memory.events",
        {"low", "high", "max", "oom", "oom_kill", "oom_group_kill"},
    )
    partial |= field_partial

    pids_current, field_partial = _read_cgroup_integer(directory / "pids.current")
    partial |= field_partial
    pids_max, pids_unlimited, field_partial = _read_cgroup_limit(directory / "pids.max")
    partial |= field_partial

    result = ProcessCgroupV2Resources(
        cgroup_path=cgroup_path,
        level_from_process=level,
        cpu_weight=cpu_weight,
        cpu_quota_usec=cpu_quota,
        cpu_period_usec=cpu_period,
        cpu_quota_unlimited=cpu_unlimited,
        cpu_usage_usec=cpu_stats.get("usage_usec"),
        cpu_user_usec=cpu_stats.get("user_usec"),
        cpu_system_usec=cpu_stats.get("system_usec"),
        cpu_nr_periods=cpu_stats.get("nr_periods"),
        cpu_nr_throttled=cpu_stats.get("nr_throttled"),
        cpu_throttled_usec=cpu_stats.get("throttled_usec"),
        memory_current_bytes=memory_current,
        memory_max_bytes=memory_max,
        memory_max_unlimited=memory_unlimited,
        memory_high_bytes=memory_high,
        memory_high_unlimited=memory_high_unlimited,
        memory_swap_current_bytes=memory_swap_current,
        memory_swap_max_bytes=memory_swap_max,
        memory_swap_max_unlimited=memory_swap_unlimited,
        memory_events=memory_events,
        pids_current=pids_current,
        pids_max=pids_max,
        pids_max_unlimited=pids_unlimited,
    )
    return result, partial


def _cgroup_v2_resources(
    pid: int,
    cgroup_content: str | None,
    cgroup_truncated: bool,
) -> tuple[list[ProcessCgroupV2Resources], bool, bool, str | None]:
    if cgroup_content is None or cgroup_truncated:
        return [], False, True, "Process cgroup data was unavailable or truncated."
    root, _leaf, unified_path, error = _resolve_cgroup_v2_path(pid, cgroup_content)
    if error or root is None or unified_path is None:
        return [], False, True, error or "The cgroup-v2 path could not be safely resolved."
    components = [] if unified_path == "/" else unified_path[1:].split("/")

    snapshots: list[ProcessCgroupV2Resources] = []
    partial = len(components) + 1 > MAX_CGROUP_DEPTH
    levels = min(len(components) + 1, MAX_CGROUP_DEPTH)
    for level in range(levels):
        remaining = max(0, len(components) - level)
        ancestor_components = components[:remaining]
        relative_path = "/" + "/".join(ancestor_components)
        directory = root.joinpath(*ancestor_components)
        try:
            resolved = directory.resolve(strict=True)
            resolved.relative_to(root)
            if not resolved.is_dir():
                partial = True
                continue
        except (OSError, RuntimeError, ValueError):
            partial = True
            continue
        snapshot, group_partial = _read_cgroup_v2_group(resolved, relative_path, level)
        snapshots.append(snapshot)
        partial |= group_partial

    if not snapshots:
        return [], False, True, "No cgroup-v2 resource directories were readable for this process."
    if not any(
        any(value is not None for value in snapshot.model_dump(exclude={"cgroup_path", "level_from_process", "memory_events"}).values())
        or bool(snapshot.memory_events)
        for snapshot in snapshots
    ):
        partial = True
    return snapshots, True, partial, (
        "Some optional controller files were unavailable or malformed."
        if partial else None
    )


def get_process_execution_context(pid: int) -> ProcessExecutionContextResponse:
    """Return a bounded execution-context snapshot for one explicit PID."""
    if not sys.platform.startswith("linux"):
        return ProcessExecutionContextResponse(
            success=False,
            pid=pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
            message="Process execution context is available only on Linux.",
        )
    if not isinstance(pid, int) or isinstance(pid, bool) or not 0 < pid <= MAX_PID:
        return ProcessExecutionContextResponse(
            success=False,
            pid=pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
            message="PID must be a positive Linux process ID.",
        )

    process_dir = PROC / str(pid)
    try:
        stat_before_text, stat_truncated = _read_limited(process_dir / "stat", MAX_STAT_BYTES)
    except OSError:
        return ProcessExecutionContextResponse(
            success=False,
            pid=pid,
            message="The process no longer exists or its stat data is not readable.",
        )
    stat_before = _parse_stat(pid, stat_before_text)
    if stat_before is None or stat_truncated:
        return ProcessExecutionContextResponse(
            success=False,
            pid=pid,
            message="The process stat data was malformed or exceeded its size limit.",
        )

    partial = False
    status: dict[str, str] = {}
    try:
        status_text, status_truncated = _read_limited(process_dir / "status", MAX_STATUS_BYTES)
        status, malformed_status = _status_fields(status_text)
        partial |= status_truncated or malformed_status or not status
    except OSError:
        partial = True

    allowed_cpus, invalid_cpus = _parse_id_list(status, "Cpus_allowed_list")
    allowed_nodes, invalid_nodes = _parse_id_list(status, "Mems_allowed_list")
    no_new_privileges, invalid_nnp = _parse_integer(status, "NoNewPrivs", maximum=1)
    seccomp_mode, invalid_seccomp = _parse_integer(status, "Seccomp", maximum=2)
    seccomp_filters, invalid_seccomp_filters = _parse_integer(status, "Seccomp_filters")
    capabilities_raw = status.get("CapEff")
    if capabilities_raw is not None and not CAPABILITY_MASK_RE.fullmatch(capabilities_raw):
        capabilities_raw = None
        partial = True
    partial |= any((invalid_cpus, invalid_nodes, invalid_nnp, invalid_seccomp, invalid_seccomp_filters))

    cgroups: list[ProcessCgroupMembership] = []
    cgroup_text: str | None = None
    cgroup_truncated = False
    try:
        cgroup_text, cgroup_truncated = _read_limited(process_dir / "cgroup", MAX_CGROUP_BYTES)
        cgroups, malformed_cgroups = _parse_cgroups(cgroup_text)
        partial |= cgroup_truncated or malformed_cgroups or not cgroups
    except OSError:
        partial = True
    cgroup_resources, cgroup_resources_available, cgroup_resources_partial, cgroup_resources_message = (
        _cgroup_v2_resources(pid, cgroup_text, cgroup_truncated)
    )
    partial |= cgroup_resources_partial
    if cgroup_resources_available and cgroup_text is not None:
        try:
            cgroup_after_text, cgroup_after_truncated = _read_limited(
                process_dir / "cgroup",
                MAX_CGROUP_BYTES,
            )
        except OSError:
            cgroup_after_text, cgroup_after_truncated = "", True
        same_cgroup_namespace, namespace_error = _same_cgroup_namespace(pid)
        if (
            cgroup_after_truncated
            or cgroup_after_text != cgroup_text
            or namespace_error
            or not same_cgroup_namespace
        ):
            if not cgroup_after_truncated:
                cgroups, changed_membership = _parse_cgroups(cgroup_after_text)
                partial |= changed_membership
            else:
                cgroups = []
            cgroup_resources = []
            cgroup_resources_available = False
            cgroup_resources_message = "Cgroup membership and namespace stability could not be verified; resource snapshots were discarded."
            partial = True

    namespaces, namespace_partial = _namespace_ids(pid)
    partial |= namespace_partial

    try:
        stat_after_text, stat_after_truncated = _read_limited(process_dir / "stat", MAX_STAT_BYTES)
    except OSError:
        stat_after_text, stat_after_truncated = "", False
    stat_after = _parse_stat(pid, stat_after_text)
    if stat_after_truncated or stat_after is None or stat_after["start_ticks"] != stat_before["start_ticks"]:
        return ProcessExecutionContextResponse(
            success=False,
            pid=pid,
            message="The process exited or its PID was reused during collection; no mixed snapshot was returned.",
        )

    policy_id = int(stat_before["policy"])
    process_name = status.get("Name")
    if process_name is not None:
        process_name = re.sub(r"[\x00-\x1f\x7f]", "?", process_name[:256])
    return ProcessExecutionContextResponse(
        success=True,
        pid=pid,
        process_name=process_name,
        state=str(stat_before["state"]),
        scheduling_policy_id=policy_id,
        scheduling_policy=SCHEDULING_POLICIES.get(policy_id, "unknown"),
        priority=int(stat_before["priority"]),
        nice_value=int(stat_before["nice"]),
        realtime_priority=int(stat_before["rt_priority"]),
        last_cpu=int(stat_before["processor"]),
        allowed_cpus=allowed_cpus,
        allowed_memory_nodes=allowed_nodes,
        cgroups=cgroups,
        cgroup_v2_resources_available=cgroup_resources_available,
        cgroup_v2_resources=cgroup_resources,
        cgroup_v2_message=cgroup_resources_message,
        namespace_ids=namespaces,
        no_new_privileges=bool(no_new_privileges) if no_new_privileges is not None else None,
        seccomp_mode=seccomp_mode,
        seccomp_filter_count=seccomp_filters,
        effective_capabilities_hex=capabilities_raw.lower() if capabilities_raw is not None else None,
        partial=partial,
        message=(
            "Some status, cgroup, or namespace fields were unavailable, malformed, or truncated."
            if partial else None
        ),
    )
