"""Confirmed creation and replacement of narrowly generated systemd timer units."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import SystemdTimerDefinitionDeleteResponse, SystemdTimerDefinitionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.filesystem_write import (
    TextFileCreationTarget,
    TextFileDeletionTarget,
    TextFileReplacementTarget,
    create_text_file,
    delete_text_file,
    replace_text_file,
    text_file_creation_confirmation_details,
    text_file_deletion_confirmation_details,
    text_file_replacement_confirmation_details,
)
from wayland_mcp.tools.host import _detect_init_system

TimerDefinitionAction = Literal["create", "update"]
TimerDefinitionScope = Literal["system", "user"]

_UNIT_BASE = r"[A-Za-z0-9][A-Za-z0-9_.@:+-]{0,199}"
_TIMER_UNIT_RE = re.compile(rf"^{_UNIT_BASE}\.timer$")
_SERVICE_UNIT_RE = re.compile(rf"^{_UNIT_BASE}\.service$")
_CALENDAR_CHARS_RE = re.compile(r"^[A-Za-z0-9*.,:/ _+~\-]+$")
_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_MANAGED_HEADER = "# Managed by linux-mcp: systemd timer definition v1"
_STATE_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "UnitFileState",
    "FragmentPath",
    "DropInPaths",
    "Unit",
    "TimersCalendar",
    "TimersMonotonic",
)
_MAX_CALENDAR_CHARS = 256
_MAX_DELAY_SECONDS = 365 * 24 * 60 * 60
_STATE_TIMEOUT_SECONDS = 5
_ACTION_TIMEOUT_SECONDS = 30
_MAX_COMMAND_OUTPUT_BYTES = 32 * 1024
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class TimerManagerState:
    unit: str
    scope: TimerDefinitionScope
    properties: tuple[tuple[str, tuple[str, ...]], ...]

    def value(self, name: str) -> str:
        values = dict(self.properties).get(name, ())
        return values[-1] if values else ""

    def values(self, name: str) -> tuple[str, ...]:
        return dict(self.properties).get(name, ())

    @property
    def token(self) -> str:
        material = {
            "unit": self.unit,
            "scope": self.scope,
            "properties": {key: list(values) for key, values in self.properties},
        }
        return hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class TimerDefinitionTarget:
    action: TimerDefinitionAction
    scope: TimerDefinitionScope
    unit: str
    service_unit: str
    path: Path
    on_calendar: str | None
    on_boot_seconds: int | None
    on_unit_active_seconds: int | None
    persistent: bool
    content: str
    state_token: str
    confirmation_phrase: str
    unit_file_state: str | None
    create_target: TextFileCreationTarget | None = None
    replace_target: TextFileReplacementTarget | None = None


@dataclass(frozen=True, slots=True)
class TimerDefinitionDeletionTarget:
    scope: TimerDefinitionScope
    unit: str
    path: Path
    unit_file_state: str
    file_target: TextFileDeletionTarget
    state_token: str
    confirmation_phrase: str


def _valid_unit_name(value: object, suffix: str) -> bool:
    if not isinstance(value, str) or len(value) > 220:
        return False
    pattern = _TIMER_UNIT_RE if suffix == ".timer" else _SERVICE_UNIT_RE
    return bool(pattern.fullmatch(value))


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["SYSTEMD_COLORS"] = "0"
    env["SYSTEMD_URLIFY"] = "0"
    env["TERM"] = "dumb"
    return env


def _systemd_binaries() -> tuple[str | None, str | None, dict[str, str], str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, {}, "Generated systemd unit-definition control is available only on Linux."
    if _detect_init_system() != "systemd":
        return None, None, {}, "Generated systemd unit-definition control requires systemd as the active init system."
    env = _environment()
    systemctl = find_session_binary("systemctl", env)
    analyzer = find_session_binary("systemd-analyze", env)
    if not systemctl or not analyzer:
        return systemctl, analyzer, env, "systemctl and systemd-analyze are required in the sanitized session PATH."
    return systemctl, analyzer, env, None


def systemd_timer_definition_control_available() -> bool:
    _systemctl, _analyzer, _env, error = _systemd_binaries()
    return error is None


def _manager_state(
    systemctl: str,
    env: dict[str, str],
    unit: str,
    scope: TimerDefinitionScope,
) -> tuple[TimerManagerState | None, str | None]:
    command = [systemctl]
    if scope == "user":
        command.append("--user")
    command.extend(("--no-pager", "--property=" + ",".join(_STATE_PROPERTIES), "show", unit))
    output, error, truncated = run_bounded_command(
        command,
        env,
        command_label="systemd unit-definition state",
        timeout_seconds=_STATE_TIMEOUT_SECONDS,
        max_output_bytes=_MAX_COMMAND_OUTPUT_BYTES,
        accept_nonzero_exit=True,
    )
    if output is None or truncated:
        return None, error or "The selected systemd manager returned an incomplete unit state."
    properties: dict[str, list[str]] = {}
    allowed = set(_STATE_PROPERTIES)
    for line in output.splitlines():
        if not line:
            continue
        if len(line) > 8192 or "=" not in line:
            return None, "The selected systemd manager returned malformed unit state."
        key, value = line.split("=", 1)
        if key in allowed:
            properties.setdefault(key, []).append(value.strip())
    if len(properties.get("LoadState", ())) != 1:
        return None, "The selected systemd manager did not report one exact unit load state."
    if properties.get("Id") and properties["Id"][-1] not in {"", unit}:
        return None, "The selected systemd manager resolved a different unit name."
    return TimerManagerState(
        unit=unit,
        scope=scope,
        properties=tuple((key, tuple(properties.get(key, ()))) for key in _STATE_PROPERTIES),
    ), None


def _unit_directory(scope: TimerDefinitionScope) -> tuple[Path | None, str | None]:
    if scope == "system":
        directory = Path("/etc/systemd/system")
        expected_owner = 0
    elif scope == "user":
        try:
            record = pwd.getpwuid(os.geteuid())
        except (KeyError, OSError):
            return None, "The current server identity has no local home directory for user-scope unit files."
        if not record.pw_dir or not Path(record.pw_dir).is_absolute():
            return None, "The current server identity does not have an absolute home directory."
        try:
            home = Path(record.pw_dir).resolve(strict=True)
            directory = home / ".config" / "systemd" / "user"
        except (OSError, RuntimeError, ValueError):
            return None, "The current server identity's home directory could not be resolved."
        expected_owner = record.pw_uid
    else:
        return None, "Scope must be 'system' or 'user'."

    try:
        resolved = directory.resolve(strict=True)
        info = resolved.stat()
    except (OSError, RuntimeError, ValueError):
        return None, "The selected systemd unit directory does not exist or could not be resolved."
    if resolved != directory or not resolved.is_dir():
        return None, "The selected systemd unit directory must be a real directory, not a symlink."
    if info.st_uid != expected_owner:
        return None, "The selected systemd unit directory is not owned by the expected systemd scope identity."
    if info.st_mode & 0o022:
        return None, "The selected systemd unit directory is writable by group or other users."
    return resolved, None


def _validate_calendar(
    expression: object,
    analyzer: str,
    env: dict[str, str],
) -> tuple[str | None, str | None]:
    if not isinstance(expression, str) or not expression or len(expression) > _MAX_CALENDAR_CHARS:
        return None, f"on_calendar must be non-empty text of at most {_MAX_CALENDAR_CHARS} characters."
    if expression != expression.strip() or expression.startswith("-") or not _CALENDAR_CHARS_RE.fullmatch(expression):
        return None, "on_calendar contains unsupported characters or surrounding whitespace."
    output, error, truncated = run_bounded_command(
        [analyzer, "calendar", expression],
        env,
        command_label="systemd calendar validation",
        timeout_seconds=_STATE_TIMEOUT_SECONDS,
        max_output_bytes=4096,
    )
    if output is None or truncated:
        return None, error or "systemd-analyze could not validate the calendar expression."
    return expression, None


def _validate_schedule(
    on_calendar: object,
    on_boot_seconds: object,
    on_unit_active_seconds: object,
    persistent: object,
    analyzer: str,
    env: dict[str, str],
) -> tuple[str | None, int | None, int | None, bool, str | None]:
    if not isinstance(persistent, bool):
        return None, None, None, False, "persistent must be a boolean."
    calendar_value: str | None = None
    if on_calendar is not None:
        calendar_value, error = _validate_calendar(on_calendar, analyzer, env)
        if error:
            return None, None, None, False, error
    numeric_values: list[int | None] = []
    for label, value in (("on_boot_seconds", on_boot_seconds), ("on_unit_active_seconds", on_unit_active_seconds)):
        if value is None:
            numeric_values.append(None)
            continue
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= _MAX_DELAY_SECONDS:
            return None, None, None, False, f"{label} must be an integer from 1 through {_MAX_DELAY_SECONDS} seconds."
        numeric_values.append(value)
    if calendar_value is None and all(value is None for value in numeric_values):
        return None, None, None, False, "At least one calendar or monotonic schedule value is required."
    if persistent and calendar_value is None:
        return None, None, None, False, "persistent catch-up is supported only with an OnCalendar schedule."
    return calendar_value, numeric_values[0], numeric_values[1], persistent, None


def _render_unit(
    service_unit: str,
    on_calendar: str | None,
    on_boot_seconds: int | None,
    on_unit_active_seconds: int | None,
    persistent: bool,
) -> str:
    lines = [
        _MANAGED_HEADER,
        "[Unit]",
        "Description=Timer managed by linux-mcp",
        "",
        "[Timer]",
        f"Unit={service_unit}",
    ]
    if on_calendar is not None:
        lines.append(f"OnCalendar={on_calendar}")
    if on_boot_seconds is not None:
        lines.append(f"OnBootSec={on_boot_seconds}s")
    if on_unit_active_seconds is not None:
        lines.append(f"OnUnitActiveSec={on_unit_active_seconds}s")
    if persistent:
        lines.append("Persistent=true")
    lines.extend(("", "[Install]", "WantedBy=timers.target", ""))
    return "\n".join(lines)


def _state_token(
    *,
    action: str,
    scope: str,
    unit: str,
    service_unit: str,
    path: Path,
    content: str,
    manager_state: TimerManagerState,
    previous_sha256: str | None,
    schedule: tuple[object, ...],
) -> str:
    material = {
        "action": action,
        "scope": scope,
        "unit": unit,
        "service_unit": service_unit,
        "path": str(path),
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "previous_sha256": previous_sha256,
        "manager_state": manager_state.token,
        "schedule": list(schedule),
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


def _prepare_definition(
    action: object,
    scope: object,
    unit: object,
    service_unit: object,
    on_calendar: object,
    on_boot_seconds: object,
    on_unit_active_seconds: object,
    persistent: object,
) -> tuple[TimerDefinitionTarget | None, str | None]:
    if not isinstance(action, str) or action not in {"create", "update"}:
        return None, "Action must be 'create' or 'update'."
    if not isinstance(scope, str) or scope not in {"system", "user"}:
        return None, "Scope must be 'system' or 'user'."
    if not _valid_unit_name(unit, ".timer"):
        return None, "unit must be one exact, simple systemd .timer unit name without path separators or escaped characters."
    if not _valid_unit_name(service_unit, ".service"):
        return None, "service_unit must be one exact, simple systemd .service unit name without path separators or escaped characters."

    systemctl, analyzer, env, error = _systemd_binaries()
    if error or not systemctl or not analyzer:
        return None, error or "Required systemd commands are unavailable."
    calendar_value, boot_value, active_value, persistent_value, error = _validate_schedule(
        on_calendar,
        on_boot_seconds,
        on_unit_active_seconds,
        persistent,
        analyzer,
        env,
    )
    if error:
        return None, error

    directory, error = _unit_directory(scope)
    if error or directory is None:
        return None, error or "The selected systemd unit directory could not be verified."
    path = directory / unit
    service_state, error = _manager_state(systemctl, env, service_unit, scope)
    if error or service_state is None:
        return None, error or "The exact service unit state could not be verified."
    if service_state.value("Id") != service_unit or service_state.value("LoadState") != "loaded":
        return None, "service_unit must already be loaded by the selected systemd manager."

    manager_state, error = _manager_state(systemctl, env, unit, scope)
    if error or manager_state is None:
        return None, error or "The exact timer unit state could not be verified."
    load_state = manager_state.value("LoadState")
    active_state = manager_state.value("ActiveState")
    unit_file_state = manager_state.value("UnitFileState") or None
    drop_ins = tuple(value for value in manager_state.values("DropInPaths") if value)
    if action == "create":
        if path.exists() or path.is_symlink():
            return None, "A file already exists at the selected timer-unit path; create never overwrites."
        if load_state != "not-found":
            return None, "A timer with this name already exists in the selected manager; create never shadows another unit."
        if drop_ins or unit_file_state not in {None, "", "not-found"}:
            return None, "A timer drop-in or existing enablement state is present; create will not shadow it."
        file_target, error = text_file_creation_confirmation_details(str(path), _render_unit(
            service_unit, calendar_value, boot_value, active_value, persistent_value
        ))
        if error or file_target is None:
            return None, error or "The exact timer-unit destination could not be verified."
        if file_target.path != path:
            return None, "The timer-unit destination resolved to a different path."
        previous_sha256 = None
        replace_target = None
    else:
        if load_state != "loaded" or active_state != "inactive":
            return None, "A timer can be updated only while the exact loaded unit is inactive."
        if unit_file_state not in {"enabled", "disabled"}:
            return None, "A timer can be updated only when its unit-file state is enabled or disabled."
        if manager_state.value("FragmentPath") != str(path) or drop_ins:
            return None, "Only the exact local timer file without drop-ins can be updated."
        content = _render_unit(service_unit, calendar_value, boot_value, active_value, persistent_value)
        replace_target, error = text_file_replacement_confirmation_details(str(path), content)
        if error or replace_target is None:
            return None, error or "The exact current timer file could not be verified."
        if replace_target.path != path:
            return None, "The timer-unit path resolved to a different file."
        try:
            old_content = replace_target.original.decode("utf-8", errors="strict")
        except UnicodeError:
            return None, "The existing timer unit is not valid UTF-8 text."
        if not old_content.startswith(_MANAGED_HEADER + "\n"):
            return None, "Only timer files previously created by this tool can be updated."
        previous_sha256 = replace_target.current_sha256
        file_target = None

    content = _render_unit(service_unit, calendar_value, boot_value, active_value, persistent_value)
    schedule = (calendar_value, boot_value, active_value, persistent_value)
    token = _state_token(
        action=action,
        scope=scope,
        unit=unit,
        service_unit=service_unit,
        path=path,
        content=content,
        manager_state=manager_state,
        previous_sha256=previous_sha256,
        schedule=schedule,
    )
    return TimerDefinitionTarget(
        action=action,
        scope=scope,
        unit=unit,
        service_unit=service_unit,
        path=path,
        on_calendar=calendar_value,
        on_boot_seconds=boot_value,
        on_unit_active_seconds=active_value,
        persistent=persistent_value,
        content=content,
        state_token=token,
        confirmation_phrase=f"CONFIRM TIMER DEFINITION {unit} {token[:16]}",
        unit_file_state=unit_file_state,
        create_target=file_target,
        replace_target=replace_target,
    ), None


def timer_definition_confirmation_details(
    action: TimerDefinitionAction,
    scope: TimerDefinitionScope,
    unit: str,
    service_unit: str,
    on_calendar: str | None,
    on_boot_seconds: int | None,
    on_unit_active_seconds: int | None,
    persistent: bool,
) -> tuple[TimerDefinitionTarget | None, str | None]:
    """Validate a generated schedule and bind it to the current manager/file state."""
    return _prepare_definition(
        action, scope, unit, service_unit, on_calendar,
        on_boot_seconds, on_unit_active_seconds, persistent,
    )


def _prepare_timer_definition_deletion(
    scope: object,
    unit: object,
) -> tuple[TimerDefinitionDeletionTarget | None, str | None]:
    if not isinstance(scope, str) or scope not in {"system", "user"}:
        return None, "Scope must be 'system' or 'user'."
    if not _valid_unit_name(unit, ".timer"):
        return None, "unit must be one exact, simple systemd .timer unit name without path separators or escaped characters."

    systemctl, _analyzer, env, error = _systemd_binaries()
    if error or not systemctl:
        return None, error or "systemctl is unavailable."
    directory, error = _unit_directory(scope)
    if error or directory is None:
        return None, error or "The selected systemd unit directory could not be verified."
    path = directory / unit
    manager_state, error = _manager_state(systemctl, env, unit, scope)
    if error or manager_state is None:
        return None, error or "The exact timer unit state could not be verified."
    if manager_state.value("Id") != unit or manager_state.value("LoadState") != "loaded":
        return None, "Only an already-loaded timer unit can be deleted."
    if manager_state.value("ActiveState") != "inactive":
        return None, "A timer can be deleted only while it is inactive."
    unit_file_state = manager_state.value("UnitFileState")
    if unit_file_state != "disabled":
        return None, "A timer can be deleted only after it is disabled; enabled or otherwise linked units are refused."
    if manager_state.value("FragmentPath") != str(path):
        return None, "Only the exact timer file in the selected managed unit directory can be deleted."
    if tuple(value for value in manager_state.values("DropInPaths") if value):
        return None, "Timer files with drop-ins cannot be deleted by this operation."

    file_target, error = text_file_deletion_confirmation_details(str(path))
    if error or file_target is None:
        return None, error or "The exact timer file could not be verified for deletion."
    if file_target.path != path:
        return None, "The timer-file path resolved to a different file."
    try:
        old_content = file_target.original.decode("utf-8", errors="strict")
    except UnicodeError:
        return None, "The existing timer unit is not valid UTF-8 text."
    if not old_content.startswith(_MANAGED_HEADER + "\n"):
        return None, "Only timer files previously created by this tool can be deleted."

    material = {
        "action": "delete",
        "scope": scope,
        "unit": unit,
        "path": str(path),
        "manager_state": manager_state.token,
        "file_sha256": file_target.current_sha256,
        "device": file_target.device,
        "inode": file_target.inode,
        "owner_uid": file_target.owner_uid,
        "owner_gid": file_target.owner_gid,
        "mode_octal": file_target.mode_octal,
        "modified_ns": file_target.modified_ns,
        "changed_ns": file_target.changed_ns,
        "parent_device": file_target.parent_device,
        "parent_inode": file_target.parent_inode,
    }
    token = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return TimerDefinitionDeletionTarget(
        scope=scope,  # type: ignore[arg-type]
        unit=unit,  # type: ignore[arg-type]
        path=path,
        unit_file_state=unit_file_state,
        file_target=file_target,
        state_token=token,
        confirmation_phrase=f"CONFIRM DELETE TIMER {unit} {token[:16]}",
    ), None


def timer_definition_deletion_confirmation_details(
    scope: TimerDefinitionScope,
    unit: str,
) -> tuple[TimerDefinitionDeletionTarget | None, str | None]:
    """Validate a generated, disabled timer file and bind deletion to its current state."""
    return _prepare_timer_definition_deletion(scope, unit)


def perform_systemd_timer_definition_deletion(
    scope: TimerDefinitionScope,
    unit: str,
    *,
    confirmed: bool,
    confirmed_scope: str | None = None,
    confirmed_unit: str | None = None,
    confirmed_phrase: str | None = None,
    expected_state_token: str | None = None,
) -> SystemdTimerDefinitionDeleteResponse:
    safe_scope: TimerDefinitionScope = scope if isinstance(scope, str) and scope in {"system", "user"} else "system"
    safe_unit = unit[:220] if isinstance(unit, str) else ""
    target, error = _prepare_timer_definition_deletion(scope, unit)
    if error or target is None:
        return SystemdTimerDefinitionDeleteResponse(
            success=False, scope=safe_scope, unit=safe_unit,
            user_confirmed=confirmed is True,
            message=error or "The exact timer file could not be verified for deletion.",
        )
    if confirmed is not True:
        return SystemdTimerDefinitionDeleteResponse(
            success=False, scope=target.scope, unit=target.unit, path=str(target.path),
            unit_file_state=target.unit_file_state, user_confirmed=False,
            message="Explicit client confirmation is required; no timer file was deleted.",
        )
    if (
        confirmed_scope != target.scope
        or confirmed_unit != target.unit
        or confirmed_phrase != target.confirmation_phrase
        or expected_state_token != target.state_token
        or not isinstance(expected_state_token, str)
        or not _TOKEN_RE.fullmatch(expected_state_token)
    ):
        return SystemdTimerDefinitionDeleteResponse(
            success=False, scope=target.scope, unit=target.unit, path=str(target.path),
            unit_file_state=target.unit_file_state, user_confirmed=True,
            message="Confirmation did not repeat the exact timer unit and current state token; no file was deleted.",
        )

    with _ACTION_LOCK:
        current, error = _prepare_timer_definition_deletion(scope, unit)
        if error or current is None or current != target:
            return SystemdTimerDefinitionDeleteResponse(
                success=False, scope=target.scope, unit=target.unit, path=str(target.path),
                unit_file_state=target.unit_file_state, user_confirmed=True,
                message=error or "The timer file or manager state changed after confirmation; no file was deleted.",
            )
        file_result = delete_text_file(
            str(current.path),
            confirmed=True,
            confirmed_path=str(current.file_target.path),
            confirmed_current_sha256=current.file_target.current_sha256,
        )
        if not file_result.success:
            return SystemdTimerDefinitionDeleteResponse(
                success=False, scope=current.scope, unit=current.unit, path=str(current.path),
                unit_file_state=current.unit_file_state, file_deleted=file_result.deleted,
                user_confirmed=True, message=f"The timer file could not be deleted: {file_result.message}",
            )

        reload_success, reload_error = _run_daemon_reload(current.scope)
        if not reload_success:
            return SystemdTimerDefinitionDeleteResponse(
                success=False, scope=current.scope, unit=current.unit, path=str(current.path),
                unit_file_state=current.unit_file_state, file_deleted=True,
                user_confirmed=True,
                message=("The timer file was deleted, but systemd daemon-reload did not report success; "
                         f"the manager may still have the previous definition ({reload_error or 'reload error'}). Inspect before retrying."),
            )

        systemctl, _analyzer, env, error = _systemd_binaries()
        after, state_error = (
            _manager_state(systemctl, env, current.unit, current.scope)
            if systemctl and not error else (None, error)
        )
        path_absent = not current.path.exists() and not current.path.is_symlink()
        verified = bool(after is not None and after.value("LoadState") == "not-found" and path_absent)
        if not verified:
            detail = state_error or "systemd still reports the unit or its file remains present."
            return SystemdTimerDefinitionDeleteResponse(
                success=False, scope=current.scope, unit=current.unit, path=str(current.path),
                unit_file_state=after.value("UnitFileState") if after else current.unit_file_state,
                file_deleted=True, state_verified=False, user_confirmed=True,
                message=f"The timer file was deleted and systemd reloaded, but post-change verification failed ({detail}). Inspect before retrying.",
            )
        return SystemdTimerDefinitionDeleteResponse(
            success=True, scope=current.scope, unit=current.unit, path=str(current.path),
            unit_file_state=after.value("UnitFileState"), file_deleted=True,
            state_verified=True, user_confirmed=True,
            message="Deleted the generated inactive timer file and verified that systemd no longer loads it.",
        )


def _run_daemon_reload(scope: TimerDefinitionScope) -> tuple[bool, str | None]:
    systemctl, _analyzer, env, error = _systemd_binaries()
    if error or not systemctl:
        return False, error or "systemctl is unavailable."
    command = [systemctl]
    if scope == "user":
        command.append("--user")
    command.extend(("--no-pager", "--no-ask-password", "daemon-reload"))
    _output, command_error, truncated = run_bounded_command(
        command,
        env,
        command_label="systemd daemon reload",
        timeout_seconds=_ACTION_TIMEOUT_SECONDS,
        max_output_bytes=_MAX_COMMAND_OUTPUT_BYTES,
        kill_process_group=True,
    )
    return (command_error is None and not truncated, command_error)


def _response(
    action: TimerDefinitionAction,
    scope: TimerDefinitionScope,
    unit: str,
    *,
    target: TimerDefinitionTarget | None,
    confirmed: bool,
    success: bool,
    file_written: bool = False,
    unit_file_state: str | None = None,
    state_verified: bool = False,
    message: str,
) -> SystemdTimerDefinitionResponse:
    return SystemdTimerDefinitionResponse(
        success=success,
        action=action,
        scope=scope,
        unit=unit,
        service_unit=target.service_unit if target else None,
        path=str(target.path) if target else None,
        on_calendar=target.on_calendar if target else None,
        on_boot_seconds=target.on_boot_seconds if target else None,
        on_unit_active_seconds=target.on_unit_active_seconds if target else None,
        persistent=target.persistent if target else False,
        file_written=file_written,
        unit_file_state=unit_file_state,
        state_verified=state_verified,
        user_confirmed=confirmed,
        message=message,
    )


def perform_systemd_timer_definition(
    action: TimerDefinitionAction,
    scope: TimerDefinitionScope,
    unit: str,
    service_unit: str,
    on_calendar: str | None,
    on_boot_seconds: int | None,
    on_unit_active_seconds: int | None,
    persistent: bool,
    *,
    confirmed: bool,
    confirmed_action: str | None = None,
    confirmed_scope: str | None = None,
    confirmed_unit: str | None = None,
    confirmed_service_unit: str | None = None,
    confirmed_on_calendar: str | None = None,
    confirmed_on_boot_seconds: int | None = None,
    confirmed_on_unit_active_seconds: int | None = None,
    confirmed_persistent: bool | None = None,
    confirmed_phrase: str | None = None,
    expected_state_token: str | None = None,
) -> SystemdTimerDefinitionResponse:
    safe_action: TimerDefinitionAction = (
        action if isinstance(action, str) and action in {"create", "update"} else "create"
    )
    safe_scope: TimerDefinitionScope = (
        scope if isinstance(scope, str) and scope in {"system", "user"} else "system"
    )
    safe_unit = unit[:220] if isinstance(unit, str) else ""
    target, error = _prepare_definition(
        action, scope, unit, service_unit, on_calendar,
        on_boot_seconds, on_unit_active_seconds, persistent,
    )
    if error or target is None:
        return _response(
            safe_action, safe_scope, safe_unit, target=None, confirmed=confirmed is True,
            success=False, message=error or "The exact timer definition could not be verified.",
        )
    if confirmed is not True:
        return _response(
            safe_action, safe_scope, safe_unit, target=target, confirmed=False,
            success=False, message="Explicit client confirmation is required; no timer file was written.",
        )
    if (
        confirmed_action != target.action
        or confirmed_scope != target.scope
        or confirmed_unit != target.unit
        or confirmed_service_unit != target.service_unit
        or confirmed_on_calendar != target.on_calendar
        or confirmed_on_boot_seconds != target.on_boot_seconds
        or confirmed_on_unit_active_seconds != target.on_unit_active_seconds
        or confirmed_persistent is not target.persistent
        or confirmed_phrase != target.confirmation_phrase
        or expected_state_token != target.state_token
        or not isinstance(expected_state_token, str)
        or not _TOKEN_RE.fullmatch(expected_state_token)
    ):
        return _response(
            safe_action, safe_scope, safe_unit, target=target, confirmed=True,
            success=False, message="Confirmation did not repeat the exact timer settings and current state token; no file was written.",
        )

    with _ACTION_LOCK:
        current, error = _prepare_definition(
            action, scope, unit, service_unit, on_calendar,
            on_boot_seconds, on_unit_active_seconds, persistent,
        )
        if error or current is None or current != target:
            return _response(
                safe_action, safe_scope, safe_unit, target=target, confirmed=True,
                success=False, message=error or "The timer file or manager state changed after confirmation; no file was written.",
            )

        if current.action == "create":
            if current.create_target is None:
                return _response(
                    safe_action, safe_scope, safe_unit, target=target, confirmed=True,
                    success=False, message="The create-only file target was lost after confirmation; no file was written.",
                )
            file_result = create_text_file(
                str(current.path),
                current.content,
                confirmed=True,
                confirmed_path=str(current.create_target.path),
                confirmed_content_sha256=current.create_target.content_sha256,
            )
        else:
            if current.replace_target is None:
                return _response(
                    safe_action, safe_scope, safe_unit, target=target, confirmed=True,
                    success=False, message="The update file target was lost after confirmation; no file was written.",
                )
            file_result = replace_text_file(
                str(current.path),
                current.content,
                confirmed=True,
                confirmed_path=str(current.replace_target.path),
                confirmed_current_sha256=current.replace_target.current_sha256,
                confirmed_replacement_sha256=current.replace_target.replacement_sha256,
            )
        if not file_result.success:
            return _response(
                safe_action, safe_scope, safe_unit, target=target, confirmed=True,
                success=False, message=f"The timer file was not updated: {file_result.message}",
            )

        reload_success, reload_error = _run_daemon_reload(current.scope)
        if not reload_success:
            return _response(
                safe_action, safe_scope, safe_unit, target=target, confirmed=True,
                success=False, file_written=True, unit_file_state=current.unit_file_state,
                message=("The timer file was written, but systemd daemon-reload did not report success; "
                         f"the manager may still have the previous definition ({reload_error or 'reload error'}). Inspect before retrying."),
            )

        systemctl, _analyzer, env, error = _systemd_binaries()
        after, state_error = (
            _manager_state(systemctl, env, current.unit, current.scope)
            if systemctl and not error else (None, error)
        )
        readback, readback_error = text_file_replacement_confirmation_details(str(current.path), current.content)
        expected_unit_file_state = (
            current.unit_file_state if current.action == "update" else "disabled"
        )
        verified = bool(
            after is not None
            and after.value("Id") == current.unit
            and after.value("LoadState") == "loaded"
            and after.value("ActiveState") == "inactive"
            and after.value("UnitFileState") == expected_unit_file_state
            and after.value("FragmentPath") == str(current.path)
            and not tuple(value for value in after.values("DropInPaths") if value)
            and after.value("Unit") == current.service_unit
            and readback is not None
            and readback.original == current.content.encode("utf-8")
            and readback_error is None
        )
        if not verified:
            detail = state_error or readback_error or "The manager did not report the exact inactive timer definition and service target."
            return _response(
                safe_action, safe_scope, safe_unit, target=target, confirmed=True,
                success=False, file_written=True,
                unit_file_state=after.value("UnitFileState") if after else current.unit_file_state,
                message=f"The timer file was written and the manager reloaded, but post-change verification failed ({detail}). Inspect it before retrying.",
            )
        return _response(
            safe_action, safe_scope, safe_unit, target=target, confirmed=True,
            success=True, file_written=True,
            unit_file_state=after.value("UnitFileState"), state_verified=True,
            message=("Created and loaded the timer definition; it remains inactive and was not enabled."
                     if current.action == "create"
                     else "Updated and loaded the timer definition; its existing enablement was preserved and it remains inactive."),
        )
