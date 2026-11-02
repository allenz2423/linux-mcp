"""Systemd, OpenRC, runit, and s6 service inventory and confirmed actions."""

from __future__ import annotations

import configparser
import re
import sys
from pathlib import Path
from typing import Literal

from wayland_mcp.models import ServiceActionResponse, ServiceInfo, ServiceListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.host import _detect_init_system

MAX_SERVICES = 10_000
MAX_RETURNED_SERVICES = 200
MAX_INIT_SCRIPT_ENTRIES = 20_000
MAX_SYSTEMCTL_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_OPENRC_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_RUNIT_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_S6_RC_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_SERVICE_ACTION_OUTPUT_BYTES = 64 * 1024
SERVICE_ACTION_TIMEOUT_SECONDS = 30
OPENRC_ACTION_TIMEOUT_SECONDS = 120
S6_RC_ACTION_TIMEOUT_SECONDS = 35
S6_RC_ACTION_TIMEOUT_MS = 30_000
OPENRC_STATUS_TIMEOUT_SECONDS = 10
RUNIT_STATUS_TIMEOUT_SECONDS = 10
S6_RC_STATUS_TIMEOUT_SECONDS = 10
MAX_RUNLEVEL_CONTEXTS = 64
MAX_RUNIT_SERVICES = 512
RUNSVDIR_SCAN_LIMIT = 20_000
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:+-]{0,254}$")
SERVICE_ACTIONS = {"start", "stop", "restart", "reload", "enable", "disable"}
RUNTIME_SERVICE_ACTIONS = {"start", "stop", "restart", "reload"}
RUNSVDIR_CANDIDATES = (
    Path("/var/service"),
    Path("/service"),
    Path("/run/runit/service"),
    Path("/etc/service"),
)
OPENRC_STATES = {
    "started", "stopped", "starting", "stopping", "inactive", "hotplugged",
    "scheduled", "failed", "crashed", "unsupervised",
}


def _run_systemctl(
    systemctl: str,
    scope: Literal["system", "user"],
    arguments: list[str],
    env: dict[str, str],
) -> tuple[str | None, str | None, bool]:
    command = [systemctl]
    if scope == "user":
        command.append("--user")
    command.extend(arguments)
    return run_bounded_command(
        command,
        env,
        command_label="systemctl",
        timeout_seconds=5,
        max_output_bytes=MAX_SYSTEMCTL_OUTPUT_BYTES,
    )


def _parse_unit_files(output: str) -> dict[str, tuple[str | None, str | None]]:
    result: dict[str, tuple[str | None, str | None]] = {}
    for line in output.splitlines()[:MAX_SERVICES]:
        fields = line.split()
        if len(fields) < 2 or not fields[0].endswith(".service"):
            continue
        result[fields[0]] = (fields[1], fields[2] if len(fields) > 2 else None)
    return result


def _parse_loaded_units(output: str) -> dict[str, tuple[str | None, str | None, str | None]]:
    result: dict[str, tuple[str | None, str | None, str | None]] = {}
    for line in output.splitlines()[:MAX_SERVICES]:
        fields = line.split(None, 4)
        if not fields or not fields[0].endswith(".service"):
            continue
        result[fields[0]] = (
            fields[2] if len(fields) > 2 else None,
            fields[3] if len(fields) > 3 else None,
            fields[4][:512] if len(fields) > 4 else None,
        )
    return result


def _list_systemd_services(
    scope: Literal["system", "user"],
    query: str,
    limit: int,
) -> ServiceListResponse:
    env = get_sanitized_env()
    systemctl = find_session_binary("systemctl", env)
    if not systemctl:
        return ServiceListResponse(success=False, manager="systemd", scope=scope, limit=limit, message="systemctl is unavailable.")

    unit_files_output, unit_files_error, unit_files_truncated = _run_systemctl(
        systemctl,
        scope,
        ["list-unit-files", "--type=service", "--no-legend", "--no-pager"],
        env,
    )
    loaded_output, loaded_error, loaded_truncated = _run_systemctl(
        systemctl,
        scope,
        ["list-units", "--all", "--type=service", "--no-legend", "--no-pager", "--plain", "--full"],
        env,
    )
    if unit_files_output is None and loaded_output is None:
        reason = "; ".join(item for item in (unit_files_error, loaded_error) if item)
        return ServiceListResponse(success=False, manager="systemd", scope=scope, limit=limit, message=reason or "systemctl could not list service units.")

    unit_files = _parse_unit_files(unit_files_output or "")
    loaded_units = _parse_loaded_units(loaded_output or "")
    names = set(unit_files) | set(loaded_units)
    needle = query.strip().casefold()
    services: list[ServiceInfo] = []
    for name in names:
        startup_state, preset_state = unit_files.get(name, (None, None))
        active_state, sub_state, description = loaded_units.get(name, (None, None, None))
        if needle and needle not in name.casefold() and needle not in (description or "").casefold():
            continue
        services.append(ServiceInfo(
            name=name,
            manager="systemd",
            scope=scope,
            active_state=active_state,
            sub_state=sub_state,
            startup_state=startup_state,
            preset_state=preset_state,
            description=description,
        ))
    services.sort(key=lambda item: item.name.casefold())

    messages: list[str] = []
    if unit_files_error:
        messages.append(f"Unit-file listing unavailable: {unit_files_error}")
    if loaded_error:
        messages.append(f"Runtime-state listing unavailable: {loaded_error}")
    if unit_files_truncated or loaded_truncated or len(names) >= MAX_SERVICES:
        messages.append(f"Service scan capped at {MAX_SERVICES} entries or {MAX_SYSTEMCTL_OUTPUT_BYTES} bytes per listing.")
    return ServiceListResponse(
        success=True,
        manager="systemd",
        scope=scope,
        total_services=len(services),
        returned_services=min(len(services), limit),
        services=services[:limit],
        limit=limit,
        truncated=len(services) > limit or unit_files_truncated or loaded_truncated or len(names) >= MAX_SERVICES,
        message=" ".join(messages) or None,
    )


def _init_script_names() -> tuple[list[str], bool, str | None]:
    names: list[str] = []
    scan_truncated = False
    try:
        for index, entry in enumerate(Path("/etc/init.d").iterdir(), start=1):
            if index > MAX_INIT_SCRIPT_ENTRIES:
                scan_truncated = True
                break
            if not SERVICE_NAME_RE.fullmatch(entry.name) or not entry.is_file():
                continue
            if len(names) >= MAX_SERVICES:
                scan_truncated = True
                break
            names.append(entry.name)
    except OSError as exc:
        return sorted(names, key=str.casefold), scan_truncated, f"Could not read /etc/init.d: {exc.strerror or 'read error'}."
    return sorted(set(names), key=str.casefold), scan_truncated, None


def _init_script_inventory(
    names: list[str],
    query: str,
    limit: int,
    manager: str,
    *,
    scan_truncated: bool = False,
    extra_message: str | None = None,
) -> ServiceListResponse:
    needle = query.strip().casefold()
    matches = [name for name in names if not needle or needle in name.casefold()]
    services = [ServiceInfo(name=name, manager=manager) for name in matches[:limit]]
    messages = []
    if matches:
        messages.append("Only init-script names are available; active and startup states are not reported.")
    else:
        messages.append("No matching init scripts were found.")
    if scan_truncated:
        messages.append(f"Init-script scan capped at {MAX_INIT_SCRIPT_ENTRIES} directory entries or {MAX_SERVICES} services.")
    if extra_message:
        messages.append(extra_message)
    return ServiceListResponse(
        success=True,
        manager=manager,
        total_services=len(matches),
        returned_services=len(services),
        services=services,
        limit=limit,
        truncated=scan_truncated or len(matches) > limit,
        message=" ".join(messages),
    )


def _list_init_scripts(query: str, limit: int, manager: str) -> ServiceListResponse:
    names, scan_truncated, error = _init_script_names()
    if error:
        return ServiceListResponse(success=False, manager=manager, limit=limit, message=error)
    return _init_script_inventory(names, query, limit, manager, scan_truncated=scan_truncated)


def runit_service_directories_available() -> bool:
    return any(path.is_dir() for path in RUNSVDIR_CANDIDATES)


def _runit_service_paths() -> tuple[list[Path], bool, list[str]]:
    paths: list[Path] = []
    seen_roots: set[Path] = set()
    seen_names: set[str] = set()
    errors: list[str] = []
    truncated = False
    scanned_entries = 0
    for root in RUNSVDIR_CANDIDATES:
        try:
            if not root.is_dir():
                continue
            resolved_root = root.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved_root in seen_roots:
            continue
        seen_roots.add(resolved_root)
        try:
            for entry in root.iterdir():
                scanned_entries += 1
                if scanned_entries > RUNSVDIR_SCAN_LIMIT:
                    truncated = True
                    break
                if not SERVICE_NAME_RE.fullmatch(entry.name) or entry.name in seen_names:
                    continue
                try:
                    if not entry.is_dir() or not (entry / "run").is_file():
                        continue
                except OSError:
                    continue
                if len(paths) >= MAX_RUNIT_SERVICES:
                    truncated = True
                    break
                seen_names.add(entry.name)
                paths.append(entry)
        except OSError as exc:
            errors.append(f"Could not read {root}: {exc.strerror or 'read error'}.")
        if truncated:
            break
    paths.sort(key=lambda path: path.name.casefold())
    return paths, truncated, errors


def _parse_runit_status(
    output: str,
    paths: list[Path],
) -> dict[str, tuple[str, str | None, str | None]]:
    states: dict[str, tuple[str, str | None, str | None]] = {}
    for line in output.splitlines():
        state_prefix, separator, _ = line.partition(": ")
        if not separator or state_prefix not in {"run", "down", "finish", "fail"}:
            continue
        for path in paths:
            prefix = f"{state_prefix}: {path}:"
            if not line.startswith(prefix):
                continue
            state = state_prefix if state_prefix != "fail" else "unknown"
            remainder = line[len(prefix):]
            normal_match = re.search(r"(?:^|, )normally (up|down)(?:,|$)", remainder)
            want_match = re.search(r"(?:^|, )want (up|down)(?:,|$)", remainder)
            startup_state = None
            if normal_match:
                startup_state = "enabled" if normal_match.group(1) == "up" else "disabled"
            sub_state = f"want {want_match.group(1)}" if want_match else None
            states[path.name] = (state, startup_state, sub_state)
            break
    return states


def _runit_name_inventory(
    paths: list[Path],
    query: str,
    limit: int,
    *,
    scan_truncated: bool = False,
    extra_messages: list[str] | None = None,
) -> ServiceListResponse:
    needle = query.strip().casefold()
    matches = [path.name for path in paths if not needle or needle in path.name.casefold()]
    services = [ServiceInfo(name=name, manager="runit") for name in matches[:limit]]
    messages = ["Runit service-directory names are available; active and normal startup states are unknown."] if matches else ["No matching runit service directories were found."]
    if scan_truncated:
        messages.append(f"Runit service-directory scan capped at {MAX_RUNIT_SERVICES} services or {RUNSVDIR_SCAN_LIMIT} directory entries.")
    messages.extend(extra_messages or [])
    return ServiceListResponse(
        success=True,
        manager="runit",
        total_services=len(matches),
        returned_services=len(services),
        services=services,
        limit=limit,
        truncated=scan_truncated or len(matches) > limit,
        message=" ".join(messages),
    )


def _list_runit_services(query: str, limit: int) -> ServiceListResponse:
    paths, scan_truncated, scan_errors = _runit_service_paths()
    if not paths:
        has_runit_directories = runit_service_directories_available()
        if not has_runit_directories and Path("/etc/init.d").is_dir():
            return _list_init_scripts(query=query, limit=limit, manager="runit")
        if has_runit_directories:
            return ServiceListResponse(
                success=True,
                manager="runit",
                limit=limit,
                truncated=scan_truncated,
                message=" ".join((*scan_errors, "No runit service directories with run scripts were found.")),
            )
        message = "No standard runit service directory with service run scripts was found."
        if scan_errors:
            message = " ".join((*scan_errors, message))
        return ServiceListResponse(success=False, manager="runit", limit=limit, message=message)

    env = get_sanitized_env()
    sv = find_session_binary("sv", env)
    if not sv:
        return _runit_name_inventory(
            paths,
            query,
            limit,
            scan_truncated=scan_truncated,
            extra_messages=[*scan_errors, "The sv command is unavailable; runtime status was not read."],
        )

    output, error, output_truncated = run_bounded_command(
        [sv, "status", *(str(path) for path in paths)],
        env,
        command_label="sv status",
        timeout_seconds=RUNIT_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=MAX_RUNIT_OUTPUT_BYTES,
        accept_nonzero_exit=True,
    )
    if output is None:
        return _runit_name_inventory(
            paths,
            query,
            limit,
            scan_truncated=scan_truncated,
            extra_messages=[*scan_errors, f"sv status could not read service state: {(error or 'no output')[:400]}"],
        )

    status_by_name = _parse_runit_status(output, paths)
    needle = query.strip().casefold()
    services: list[ServiceInfo] = []
    for path in paths:
        name = path.name
        if needle and needle not in name.casefold():
            continue
        active_state, startup_state, sub_state = status_by_name.get(name, (None, None, None))
        services.append(ServiceInfo(
            name=name,
            manager="runit",
            active_state=active_state,
            sub_state=sub_state,
            startup_state=startup_state,
        ))

    messages = list(scan_errors)
    missing_status = sum(path.name not in status_by_name for path in paths)
    if missing_status:
        messages.append(f"sv status returned no parseable state for {missing_status} service directories; their state is unknown.")
    if output_truncated or scan_truncated:
        messages.append(f"Runit inventory capped at {MAX_RUNIT_SERVICES} services, {RUNSVDIR_SCAN_LIMIT} directory entries, or {MAX_RUNIT_OUTPUT_BYTES} output bytes.")
    if error and not status_by_name:
        messages.append(f"sv status reported an error: {error[:400]}")
    if not services and not messages:
        messages.append("No matching runit services were found.")
    return ServiceListResponse(
        success=True,
        manager="runit",
        total_services=len(services),
        returned_services=min(len(services), limit),
        services=services[:limit],
        limit=limit,
        truncated=output_truncated or scan_truncated or len(services) > limit,
        message=" ".join(messages) or None,
    )


def _parse_s6_rc_status(output: str) -> tuple[list[ServiceInfo], bool, int]:
    services: list[ServiceInfo] = []
    truncated = False
    malformed = 0
    for line in output.splitlines():
        if not line:
            continue
        fields = line.split("/", 4)
        if (
            len(fields) != 5
            or not SERVICE_NAME_RE.fullmatch(fields[0])
            or fields[1] not in {"longrun", "oneshot"}
            or fields[2] not in {"up", "down"}
            or fields[3] not in {"", "explicit", "pulled"}
            or fields[4] not in {"", "essential", "recommended"}
        ):
            malformed += 1
            continue
        if len(services) >= MAX_SERVICES:
            truncated = True
            break
        manager_details = {}
        if fields[3]:
            manager_details["selection"] = fields[3]
        if fields[4]:
            manager_details["importance"] = fields[4]
        services.append(ServiceInfo(
            name=fields[0],
            manager="s6-rc",
            active_state=fields[2],
            sub_state=fields[1],
            manager_details=manager_details,
        ))
    return services, truncated, malformed


def _parse_s6_startup_status(output: str) -> tuple[dict[str, str], bool, int]:
    prescriptions: dict[str, str] = {}
    seen_names: set[str] = set()
    duplicate_names: set[str] = set()
    truncated = False
    malformed = 0
    valid_prescriptions = {"active", "usable", "always", "masked"}
    for line in output.splitlines():
        row = line.strip()
        if not row:
            continue
        fields = row.rsplit("/", 1)
        if (
            len(fields) != 2
            or not SERVICE_NAME_RE.fullmatch(fields[0])
            or fields[1] not in valid_prescriptions
        ):
            malformed += 1
            continue
        name, prescription = fields
        if name in seen_names:
            malformed += 1
            duplicate_names.add(name)
            prescriptions.pop(name, None)
            continue
        if len(seen_names) >= MAX_SERVICES:
            truncated = True
            break
        seen_names.add(name)
        prescriptions[name] = prescription
    for name in duplicate_names:
        prescriptions.pop(name, None)
    return prescriptions, truncated, malformed


def _s6_startup_set_status(
    env: dict[str, str],
) -> tuple[dict[str, str], bool, int, str | None]:
    binary = find_session_binary("s6", env)
    if not binary:
        return {}, False, 0, "The s6-frontend s6 command is unavailable."
    output, error, output_truncated = run_bounded_command(
        [binary, "set", "status", "-E"],
        env,
        command_label="s6 startup-set status",
        timeout_seconds=S6_RC_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=MAX_S6_RC_OUTPUT_BYTES,
    )
    if output is None:
        return {}, output_truncated, 0, error or "s6 could not read the offline startup set."
    prescriptions, parse_truncated, malformed = _parse_s6_startup_status(output)
    if error:
        return prescriptions, output_truncated or parse_truncated, malformed, error
    return prescriptions, output_truncated or parse_truncated, malformed, None


def _s6_rc_service_status() -> tuple[dict[str, ServiceInfo] | None, str | None]:
    """Read the exact atomic-service set used to validate s6 actions."""
    env = get_sanitized_env()
    binary = find_session_binary("s6-rc", env)
    if not binary:
        return None, "s6-rc is unavailable on this s6 host."
    output, error, output_truncated = run_bounded_command(
        [binary, "-c", "list"],
        env,
        command_label="s6-rc service validation",
        timeout_seconds=S6_RC_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=MAX_S6_RC_OUTPUT_BYTES,
    )
    if output is None:
        return None, error or "s6-rc could not read the live service database."
    services, parse_truncated, _malformed = _parse_s6_rc_status(output)
    if error or output_truncated or parse_truncated:
        return None, error or "s6-rc service listing was truncated; the exact service set cannot be validated."
    return {service.name: service for service in services}, None


def _s6_script_fallback(query: str, limit: int, message: str) -> ServiceListResponse | None:
    if not Path("/etc/init.d").is_dir():
        return None
    names, scan_truncated, error = _init_script_names()
    if error:
        return ServiceListResponse(success=False, manager="s6-svscan", limit=limit, message=f"{message} {error}")
    return _init_script_inventory(
        names,
        query,
        limit,
        "s6-svscan",
        scan_truncated=scan_truncated,
        extra_message=f"{message} Active service states are unavailable.",
    )


def _list_s6_rc_services(query: str, limit: int) -> ServiceListResponse:
    env = get_sanitized_env()
    s6_rc = find_session_binary("s6-rc", env)
    if not s6_rc:
        fallback = _s6_script_fallback(query, limit, "The s6-rc command is unavailable.")
        if fallback:
            return fallback
        return ServiceListResponse(success=False, manager="s6-svscan", limit=limit, message="s6-rc is unavailable and no conventional init-script inventory was found.")

    output, error, output_truncated = run_bounded_command(
        [s6_rc, "-c", "list"],
        env,
        command_label="s6-rc list",
        timeout_seconds=S6_RC_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=MAX_S6_RC_OUTPUT_BYTES,
    )
    if output is None or (error and not output):
        fallback = _s6_script_fallback(
            query,
            limit,
            f"s6-rc could not read service state: {(error or 'no output')[:400]}.",
        )
        if fallback:
            return fallback
        return ServiceListResponse(
            success=False,
            manager="s6-svscan",
            limit=limit,
            message=f"s6-rc could not read service state: {(error or 'no output')[:400]}",
        )

    all_services, parse_truncated, malformed = _parse_s6_rc_status(output)
    services_by_name = {service.name: service for service in all_services}
    for service in all_services:
        service.manager_details["live_database_membership"] = "present"
    live_database_complete = not output_truncated and not parse_truncated and not malformed and not error
    startup_prescriptions, startup_truncated, startup_malformed, startup_error = _s6_startup_set_status(env)
    startup_state_names = {
        "active": "enabled",
        "usable": "disabled",
        "always": "essential",
        "masked": "masked",
    }
    for name, prescription in startup_prescriptions.items():
        service = services_by_name.get(name)
        if service is None:
            service = ServiceInfo(name=name, manager="s6-rc")
            if live_database_complete:
                service.manager_details["live_database_membership"] = "absent"
            services_by_name[name] = service
        service.startup_state = startup_state_names[prescription]
        service.manager_details["startup_prescription"] = prescription

    needle = query.strip().casefold()
    services = [item for item in services_by_name.values() if not needle or needle in item.name.casefold()]
    messages: list[str] = []
    if error:
        messages.append(f"s6-rc reported an error: {error[:400]}")
    if malformed:
        messages.append(f"Ignored {malformed} malformed s6-rc status row(s).")
    if output_truncated or parse_truncated:
        messages.append(f"s6-rc inventory capped at {MAX_SERVICES} services or {MAX_S6_RC_OUTPUT_BYTES} output bytes.")
    if startup_error:
        messages.append(f"Offline s6 startup prescriptions are unavailable: {startup_error[:400]}")
    else:
        messages.append("s6 startup_state values describe the offline current working set, not the live database or current service state.")
    if startup_malformed:
        messages.append(f"Ignored {startup_malformed} malformed s6 startup-set status row(s).")
    if startup_truncated:
        messages.append(f"s6 startup-set inventory capped at {MAX_SERVICES} services or {MAX_S6_RC_OUTPUT_BYTES} output bytes.")
    if not services:
        messages.append("No matching s6-rc services were found.")
    return ServiceListResponse(
        success=True,
        manager="s6-rc",
        total_services=len(services),
        returned_services=min(len(services), limit),
        services=services[:limit],
        limit=limit,
        truncated=output_truncated or parse_truncated or startup_truncated or len(services) > limit,
        message=" ".join(messages) or None,
    )


def _parse_openrc_status(output: str) -> tuple[dict[str, tuple[str, list[str]]], bool, bool]:
    parser = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",))
    parser.optionxform = str
    parser.read_string(output)

    states: dict[str, set[str]] = {}
    contexts: dict[str, set[str]] = {}
    scan_truncated = False
    for section in parser.sections():
        context = "".join(character for character in section if character.isprintable())[:128]
        if not context:
            continue
        for name, raw_state in parser.items(section):
            if not SERVICE_NAME_RE.fullmatch(name):
                continue
            fields = raw_state.strip().split(maxsplit=1)
            if not fields or fields[0].casefold() not in OPENRC_STATES:
                continue
            if name not in states and len(states) >= MAX_SERVICES:
                scan_truncated = True
                continue
            state = fields[0].casefold()
            states.setdefault(name, set()).add(state)
            contexts_for_service = contexts.setdefault(name, set())
            if context not in contexts_for_service:
                if len(contexts_for_service) >= MAX_RUNLEVEL_CONTEXTS:
                    scan_truncated = True
                else:
                    contexts_for_service.add(context)

    parsed: dict[str, tuple[str, list[str]]] = {}
    conflicting_state = False
    for name, values in states.items():
        if len(values) > 1:
            conflicting_state = True
        parsed[name] = (
            next(iter(values)) if len(values) == 1 else "unknown",
            sorted(contexts.get(name, set()), key=str.casefold),
        )
    return parsed, scan_truncated, conflicting_state


def _list_openrc_services(query: str, limit: int) -> ServiceListResponse:
    manager = "openrc"
    env = get_sanitized_env()
    rc_status = find_session_binary("rc-status", env)
    script_names, script_truncated, script_error = _init_script_names()
    if not rc_status:
        if script_error:
            return ServiceListResponse(success=False, manager=manager, limit=limit, message=script_error)
        return _init_script_inventory(
            script_names,
            query,
            limit,
            manager,
            scan_truncated=script_truncated,
            extra_message="rc-status is unavailable; active state and runlevel membership could not be read.",
        )

    output, error, output_truncated = run_bounded_command(
        [rc_status, "--all", "--format=ini", "--nocolor"],
        env,
        command_label="rc-status",
        timeout_seconds=OPENRC_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=MAX_OPENRC_OUTPUT_BYTES,
    )
    if error or output is None:
        reason = f"OpenRC status query failed: {(error or 'no output')[:400]}"
        if script_error and not script_names:
            return ServiceListResponse(success=False, manager=manager, limit=limit, message=f"{script_error} {reason}")
        if script_error:
            reason = f"{script_error} {reason}"
        return _init_script_inventory(
            script_names,
            query,
            limit,
            manager,
            scan_truncated=script_truncated,
            extra_message=f"{reason}; active state and runlevel membership are unknown.",
        )
    try:
        status_by_name, parse_truncated, conflicting_state = _parse_openrc_status(output)
    except configparser.Error:
        reason = "OpenRC status output was not valid INI."
        if script_error and not script_names:
            return ServiceListResponse(success=False, manager=manager, limit=limit, message=f"{script_error} {reason}")
        if script_error:
            reason = f"{script_error} {reason}"
        return _init_script_inventory(
            script_names,
            query,
            limit,
            manager,
            scan_truncated=script_truncated or output_truncated,
            extra_message=f"{reason} Active state and runlevel membership are unknown.",
        )

    all_names = sorted(set(script_names) | set(status_by_name), key=str.casefold)
    combined_truncated = len(all_names) > MAX_SERVICES
    names = set(all_names[:MAX_SERVICES])
    needle = query.strip().casefold()
    services: list[ServiceInfo] = []
    for name in names:
        active_state, contexts = status_by_name.get(name, (None, []))
        searchable = " ".join((name, *contexts)).casefold()
        if needle and needle not in searchable:
            continue
        services.append(ServiceInfo(
            name=name,
            manager=manager,
            active_state=active_state,
            runlevel_contexts=contexts,
        ))
    services.sort(key=lambda item: item.name.casefold())

    messages: list[str] = []
    if script_error:
        messages.append(f"Init-script inventory unavailable: {script_error}")
    if script_names and any(name not in status_by_name for name in script_names):
        messages.append("Some init scripts have no rc-status record; their active state and runlevel membership are unknown.")
    if output_truncated or parse_truncated or script_truncated or combined_truncated:
        messages.append(f"OpenRC inventory capped at {MAX_SERVICES} services, {MAX_RUNLEVEL_CONTEXTS} contexts per service, or {MAX_OPENRC_OUTPUT_BYTES} output bytes.")
    if conflicting_state:
        messages.append("OpenRC reported conflicting states for one or more services; those states are marked unknown.")
    if not services and not messages:
        messages.append("No matching OpenRC services were found.")

    return ServiceListResponse(
        success=True,
        manager=manager,
        total_services=len(services),
        returned_services=min(len(services), limit),
        services=services[:limit],
        limit=limit,
        truncated=output_truncated or parse_truncated or script_truncated or combined_truncated or len(services) > limit,
        message=" ".join(messages) or None,
    )


def list_services(
    query: str = "",
    limit: int = 100,
    scope: Literal["system", "user"] = "system",
) -> ServiceListResponse:
    if not sys.platform.startswith("linux"):
        return ServiceListResponse(success=False, manager="unsupported", scope=scope, message="Service inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return ServiceListResponse(success=False, manager="unknown", scope=scope, message="Query must be text with at most 256 characters.")
    if scope not in {"system", "user"}:
        return ServiceListResponse(success=False, manager="unknown", message="Scope must be 'system' or 'user'.")
    limit = max(1, min(int(limit), MAX_RETURNED_SERVICES))
    manager = _detect_init_system() or "unknown"
    if manager == "systemd":
        return _list_systemd_services(scope=scope, query=query, limit=limit)
    if manager == "openrc" and scope == "system":
        return _list_openrc_services(query=query, limit=limit)
    if manager == "runit" and scope == "system":
        return _list_runit_services(query=query, limit=limit)
    if manager == "s6-svscan" and scope == "system":
        return _list_s6_rc_services(query=query, limit=limit)
    if scope == "user":
        return ServiceListResponse(success=False, manager=manager, scope=scope, limit=limit, message="User service inventory is only implemented for systemd.")
    if Path("/etc/init.d").is_dir():
        return _list_init_scripts(query=query, limit=limit, manager=manager)
    return ServiceListResponse(
        success=False,
        manager=manager,
        scope=scope,
        limit=limit,
        message="This init system does not expose a service inventory adapter yet.",
    )


def validate_service_action(action: str, unit: str, scope: str) -> str | None:
    """Validate an exact manager-specific service action without changing state."""
    if not isinstance(action, str) or action not in SERVICE_ACTIONS:
        return "Action must be one of start, stop, restart, reload, enable, or disable."
    if not isinstance(scope, str) or scope not in {"system", "user"}:
        return "Scope must be 'system' or 'user'."
    if not sys.platform.startswith("linux"):
        return "Service actions are available only on Linux."
    env = get_sanitized_env()
    manager = _detect_init_system()
    if manager == "systemd":
        if not isinstance(unit, str) or len(unit) > 255 or not SERVICE_NAME_RE.fullmatch(unit) or not unit.endswith(".service"):
            return "A systemd unit must be one exact service name ending in '.service'."
        if not find_session_binary("systemctl", env):
            return "systemctl is unavailable on this systemd host."
        return None
    if manager == "s6-svscan":
        if scope != "system":
            return "s6 service actions are available only in system scope."
        if action not in RUNTIME_SERVICE_ACTIONS:
            return "s6 supports only start, stop, restart, and reload; startup enable/disable is not exposed."
        if not isinstance(unit, str) or len(unit) > 255 or not SERVICE_NAME_RE.fullmatch(unit):
            return "An s6 service must be one exact atomic-service name."
        services, error = _s6_rc_service_status()
        if error or services is None:
            return error or "The active s6 service database is unavailable."
        service = services.get(unit)
        if service is None:
            return "The exact atomic service was not found in the active s6-rc database."
        if action == "reload" and service.active_state != "up":
            return "s6-rc reload requires the exact atomic service to be up."
        return None
    if manager not in {"openrc", "runit"}:
        return "Service actions are implemented for systemd, OpenRC, runit, and s6-rc hosts."
    if scope != "system":
        return "Non-systemd service actions are available only in system scope."
    if action not in RUNTIME_SERVICE_ACTIONS:
        return "OpenRC and runit support only start, stop, restart, and reload; startup enable/disable is not exposed."
    if not isinstance(unit, str) or len(unit) > 255 or not SERVICE_NAME_RE.fullmatch(unit):
        return "A non-systemd service must be one exact service name."
    if manager == "openrc":
        if not (Path("/etc/init.d") / unit).is_file():
            return "The exact OpenRC service script was not found in /etc/init.d."
        if not find_session_binary("rc-service", env):
            return "rc-service is unavailable on this OpenRC host."
        return None
    if manager == "runit":
        if not any(path.name == unit for path in _runit_service_paths()[0]):
            return "The exact runit service directory was not found in a standard runsvdir path."
        if not find_session_binary("sv", env):
            return "sv is unavailable on this runit host."
        return None
    return "The selected service manager does not support this action."


def perform_service_action(
    action: str,
    unit: str,
    *,
    confirmed: bool,
    scope: Literal["system", "user"] = "system",
) -> ServiceActionResponse:
    """Run one exact service action after its MCP resolver has confirmed it."""
    safe_action = action if isinstance(action, str) and action in SERVICE_ACTIONS else "start"
    detected_manager = _detect_init_system() or "unknown"
    manager = "s6-rc" if detected_manager == "s6-svscan" else detected_manager
    if not confirmed:
        return ServiceActionResponse(
            success=False,
            action=safe_action,
            unit=unit if isinstance(unit, str) else "",
            scope=scope if scope in {"system", "user"} else "system",
            manager=manager,
            message="Explicit client confirmation is required; no command was run.",
        )
    validation_error = validate_service_action(action, unit, scope)
    detected_manager = _detect_init_system() or "unknown"
    manager = "s6-rc" if detected_manager == "s6-svscan" else detected_manager
    if validation_error:
        return ServiceActionResponse(
            success=False,
            action=safe_action,
            unit=unit if isinstance(unit, str) else "",
            scope=scope if scope in {"system", "user"} else "system",
            manager=manager,
            user_confirmed=True,
            message=validation_error,
        )

    env = get_sanitized_env()
    if manager == "systemd":
        binary = find_session_binary("systemctl", env)
        command = [binary, "--no-pager", "--quiet"] if binary else []
        if scope == "user":
            command.append("--user")
        if binary:
            command.extend((action, unit))
        commands = [(action, command)]
        command_label = "systemctl service action"
        timeout_seconds = SERVICE_ACTION_TIMEOUT_SECONDS
    elif manager == "openrc":
        binary = find_session_binary("rc-service", env)
        command = [binary, unit, action] if binary else []
        commands = [(action, command)]
        command_label = "OpenRC service action"
        timeout_seconds = OPENRC_ACTION_TIMEOUT_SECONDS
    elif manager == "runit":
        binary = find_session_binary("sv", env)
        service_path = next((path for path in _runit_service_paths()[0] if path.name == unit), None)
        command = [binary, action, str(service_path)] if binary and service_path else []
        commands = [(action, command)]
        command_label = "runit service action"
        timeout_seconds = SERVICE_ACTION_TIMEOUT_SECONDS
    elif manager == "s6-rc":
        binary = find_session_binary("s6-rc", env)
        command = [binary] if binary else []
        commands = []
        if binary and action == "start":
            commands = [("start", [binary, "-t", str(S6_RC_ACTION_TIMEOUT_MS), "-u", "change", unit])]
        elif binary and action == "stop":
            commands = [("stop", [binary, "-t", str(S6_RC_ACTION_TIMEOUT_MS), "-d", "change", unit])]
        elif binary and action == "reload":
            commands = [("reload", [binary, "reload", unit])]
        elif binary and action == "restart":
            commands = [
                ("stop", [binary, "-t", str(S6_RC_ACTION_TIMEOUT_MS), "-d", "change", unit]),
                ("start", [binary, "-t", str(S6_RC_ACTION_TIMEOUT_MS), "-u", "change", unit]),
            ]
        command_label = "s6-rc service action"
        timeout_seconds = S6_RC_ACTION_TIMEOUT_SECONDS
    else:
        binary = None
        command = []
        commands = []
        command_label = "service action"
        timeout_seconds = SERVICE_ACTION_TIMEOUT_SECONDS
    if not binary or not commands or any(not command for _, command in commands):
        return ServiceActionResponse(
            success=False,
            action=action,
            unit=unit,
            scope=scope,
            manager=manager,
            user_confirmed=True,
            message=f"The {manager} service adapter became unavailable before the action could run.",
        )
    for phase, phase_command in commands:
        output, error, output_truncated = run_bounded_command(
            phase_command,
            env,
            command_label=command_label,
            timeout_seconds=timeout_seconds,
            max_output_bytes=MAX_SERVICE_ACTION_OUTPUT_BYTES,
        )
        if error or output_truncated:
            message = (error or f"{command_label} output exceeded the {MAX_SERVICE_ACTION_OUTPUT_BYTES}-byte cap.")[:400]
            if "timed out" in message.casefold():
                message += " The service action may still be in progress; check service state before retrying."
            if manager == "s6-rc":
                if action == "restart":
                    message = f"s6-rc restart {phase} phase failed: {message}"
                message += " s6 transition scripts may continue after s6-rc exits; inspect service state before retrying."
            return ServiceActionResponse(
                success=False,
                action=action,
                unit=unit,
                scope=scope,
                manager=manager,
                user_confirmed=True,
                message=message,
            )
    message = f"{manager} {action} completed for {unit}."
    if manager == "s6-rc":
        message += " s6-rc may also have changed prerequisite services to satisfy dependencies."
    return ServiceActionResponse(
        success=True,
        action=action,
        unit=unit,
        scope=scope,
        manager=manager,
        user_confirmed=True,
        message=message,
    )
