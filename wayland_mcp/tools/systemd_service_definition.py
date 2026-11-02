"""Confirmed creation and replacement of generated systemd service units."""

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

from wayland_mcp.models import SystemdServiceDefinitionResponse
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.filesystem_write import (
    TextFileCreationTarget,
    TextFileReplacementTarget,
    create_text_file,
    replace_text_file,
    text_file_creation_confirmation_details,
    text_file_replacement_confirmation_details,
)
from wayland_mcp.tools.systemd_timer_definition import (
    TimerManagerState,
    _ACTION_LOCK,
    _environment,
    _manager_state,
    _run_daemon_reload,
    _systemd_binaries,
    _unit_directory,
)

ServiceDefinitionAction = Literal["create", "update"]
ServiceDefinitionScope = Literal["system", "user"]

_UNIT_BASE = r"[A-Za-z0-9][A-Za-z0-9_.@:+-]{0,199}"
_SERVICE_UNIT_RE = re.compile(rf"^{_UNIT_BASE}\.service$")
_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_MANAGED_HEADER = "# Managed by linux-mcp: systemd service definition v1"
_MAX_ARGV_ITEMS = 128
_MAX_ARG_BYTES = 4096
_MAX_EXEC_BYTES = 16 * 1024


@dataclass(frozen=True, slots=True)
class ServiceDefinitionTarget:
    action: ServiceDefinitionAction
    scope: ServiceDefinitionScope
    unit: str
    executable: str
    arguments: tuple[str, ...]
    path: Path
    content: str
    state_token: str
    confirmation_phrase: str
    unit_file_state: str | None
    create_target: TextFileCreationTarget | None = None
    replace_target: TextFileReplacementTarget | None = None


def _valid_unit_name(value: object) -> bool:
    return isinstance(value, str) and len(value) <= 220 and bool(_SERVICE_UNIT_RE.fullmatch(value))


def systemd_service_definition_control_available() -> bool:
    systemctl, _analyzer, _env, error = _systemd_binaries()
    return bool(systemctl and not error)


def _validate_text(value: object, label: str, *, allow_empty: bool = False) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or (not value and not allow_empty):
        return None, f"{label} must be text of at most {_MAX_ARG_BYTES} UTF-8 bytes."
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return None, f"{label} must contain valid UTF-8 text."
    if len(encoded) > _MAX_ARG_BYTES:
        return None, f"{label} must be at most {_MAX_ARG_BYTES} UTF-8 bytes."
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None, f"{label} may not contain control characters."
    return value, None


def _validate_argv(executable: object, arguments: object) -> tuple[str | None, tuple[str, ...] | None, str | None]:
    valid_executable, error = _validate_text(executable, "executable")
    if error or valid_executable is None:
        return None, None, error or "The executable could not be validated."
    path = Path(valid_executable)
    if not path.is_absolute() or path.as_posix() != valid_executable:
        return None, None, "executable must be one canonical absolute path without dot segments or repeated separators."
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except (OSError, RuntimeError, ValueError):
        return None, None, "The executable path could not be resolved."
    if resolved != path or not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        return None, None, "executable must resolve directly to a regular file executable by the current identity."
    if not isinstance(arguments, list) or len(arguments) > _MAX_ARGV_ITEMS:
        return None, None, f"arguments must be a list containing at most {_MAX_ARGV_ITEMS} text values."
    values: list[str] = []
    total_bytes = len(valid_executable.encode("utf-8"))
    for index, argument in enumerate(arguments):
        valid_argument, error = _validate_text(argument, f"arguments[{index}]", allow_empty=True)
        if error or valid_argument is None:
            return None, None, error or "An argument could not be validated."
        if valid_argument == ";":
            return None, None, "An argument consisting only of ';' is refused because systemd reserves it as a command separator."
        total_bytes += len(valid_argument.encode("utf-8")) + 1
        values.append(valid_argument)
    if total_bytes > _MAX_EXEC_BYTES:
        return None, None, f"The executable and arguments may contain at most {_MAX_EXEC_BYTES} UTF-8 bytes in total."
    return valid_executable, tuple(values), None


def _quote_exec_word(value: str) -> str:
    # ExecStart still expands specifiers and environment variables inside quotes.
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return '"' + escaped + '"'


def _render_unit(executable: str, arguments: tuple[str, ...]) -> str:
    command = " ".join(_quote_exec_word(value) for value in (executable, *arguments))
    return "\n".join((
        _MANAGED_HEADER,
        "[Unit]",
        "Description=One-shot service managed by linux-mcp",
        "",
        "[Service]",
        "Type=oneshot",
        f"ExecStart={command}",
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
    ))


def _manager_value(state: TimerManagerState, name: str) -> str:
    return state.value(name)


def _prepare_definition(
    action: object,
    scope: object,
    unit: object,
    executable: object,
    arguments: object,
) -> tuple[ServiceDefinitionTarget | None, str | None]:
    if not isinstance(action, str) or action not in {"create", "update"}:
        return None, "Action must be 'create' or 'update'."
    if not isinstance(scope, str) or scope not in {"system", "user"}:
        return None, "Scope must be 'system' or 'user'."
    if not _valid_unit_name(unit):
        return None, "unit must be one exact, simple systemd .service unit name without path separators or escaped characters."
    valid_executable, valid_arguments, error = _validate_argv(executable, arguments)
    if error or valid_executable is None or valid_arguments is None:
        return None, error or "The exact executable argument vector could not be validated."

    systemctl, _analyzer, env, error = _systemd_binaries()
    if error or not systemctl:
        return None, error or "systemctl is unavailable."
    directory, error = _unit_directory(scope)  # Shares the timer tool's exact scope/owner/path checks.
    if error or directory is None:
        return None, error or "The selected systemd unit directory could not be verified."
    path = directory / unit
    manager_state, error = _manager_state(systemctl, env, unit, scope)
    if error or manager_state is None:
        return None, error or "The exact service unit state could not be verified."
    load_state = _manager_value(manager_state, "LoadState")
    active_state = _manager_value(manager_state, "ActiveState")
    unit_file_state = _manager_value(manager_state, "UnitFileState") or None
    drop_ins = tuple(value for value in manager_state.values("DropInPaths") if value)
    content = _render_unit(valid_executable, valid_arguments)

    if action == "create":
        if path.exists() or path.is_symlink():
            return None, "A file already exists at the selected service-unit path; create never overwrites."
        if load_state != "not-found":
            return None, "A service with this name already exists in the selected manager; create never shadows another unit."
        if drop_ins or unit_file_state not in {None, "", "not-found"}:
            return None, "A service drop-in or existing enablement state is present; create will not shadow it."
        create_target, error = text_file_creation_confirmation_details(str(path), content)
        if error or create_target is None:
            return None, error or "The exact service-unit destination could not be verified."
        if create_target.path != path:
            return None, "The service-unit destination resolved to a different path."
        previous_sha256 = None
        replace_target = None
    else:
        if load_state != "loaded" or active_state != "inactive":
            return None, "A service can be updated only while the exact loaded unit is inactive."
        if unit_file_state not in {"enabled", "disabled"}:
            return None, "A service can be updated only when its unit-file state is enabled or disabled."
        if _manager_value(manager_state, "FragmentPath") != str(path) or drop_ins:
            return None, "Only the exact local service file without drop-ins can be updated."
        replace_target, error = text_file_replacement_confirmation_details(str(path), content)
        if error or replace_target is None:
            return None, error or "The exact current service file could not be verified."
        if replace_target.path != path:
            return None, "The service-unit path resolved to a different file."
        try:
            old_content = replace_target.original.decode("utf-8", errors="strict")
        except UnicodeError:
            return None, "The existing service unit is not valid UTF-8 text."
        if not old_content.startswith(_MANAGED_HEADER + "\n"):
            return None, "Only service files previously created by this tool can be updated."
        previous_sha256 = replace_target.current_sha256
        create_target = None

    token_material = {
        "action": action,
        "scope": scope,
        "unit": unit,
        "path": str(path),
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "previous_sha256": previous_sha256,
        "manager_state": manager_state.token,
        "executable": valid_executable,
        "arguments": list(valid_arguments),
    }
    state_token = hashlib.sha256(
        json.dumps(token_material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return ServiceDefinitionTarget(
        action=action,
        scope=scope,
        unit=unit,
        executable=valid_executable,
        arguments=valid_arguments,
        path=path,
        content=content,
        state_token=state_token,
        confirmation_phrase=f"CONFIRM SERVICE DEFINITION {unit} {state_token[:16]}",
        unit_file_state=unit_file_state,
        create_target=create_target,
        replace_target=replace_target,
    ), None


def service_definition_confirmation_details(
    action: ServiceDefinitionAction,
    scope: ServiceDefinitionScope,
    unit: str,
    executable: str,
    arguments: list[str],
) -> tuple[ServiceDefinitionTarget | None, str | None]:
    """Validate a generated service definition and bind it to current file/manager state."""
    return _prepare_definition(action, scope, unit, executable, arguments)


def _response(
    action: ServiceDefinitionAction,
    scope: ServiceDefinitionScope,
    unit: str,
    *,
    target: ServiceDefinitionTarget | None,
    confirmed: bool,
    success: bool,
    file_written: bool = False,
    unit_file_state: str | None = None,
    state_verified: bool = False,
    message: str,
) -> SystemdServiceDefinitionResponse:
    return SystemdServiceDefinitionResponse(
        success=success,
        action=action,
        scope=scope,
        unit=unit,
        executable=target.executable if target else None,
        arguments=list(target.arguments) if target else [],
        path=str(target.path) if target else None,
        file_written=file_written,
        unit_file_state=unit_file_state,
        state_verified=state_verified,
        user_confirmed=confirmed,
        message=message,
    )


def perform_systemd_service_definition(
    action: ServiceDefinitionAction,
    scope: ServiceDefinitionScope,
    unit: str,
    executable: str,
    arguments: list[str],
    *,
    confirmed: bool,
    confirmed_action: str | None = None,
    confirmed_scope: str | None = None,
    confirmed_unit: str | None = None,
    confirmed_executable: str | None = None,
    confirmed_arguments: list[str] | None = None,
    confirmed_phrase: str | None = None,
    expected_state_token: str | None = None,
) -> SystemdServiceDefinitionResponse:
    safe_action: ServiceDefinitionAction = action if isinstance(action, str) and action in {"create", "update"} else "create"
    safe_scope: ServiceDefinitionScope = scope if isinstance(scope, str) and scope in {"system", "user"} else "user"
    safe_unit = unit[:220] if isinstance(unit, str) else ""
    target, error = _prepare_definition(action, scope, unit, executable, arguments)
    if error or target is None:
        return _response(safe_action, safe_scope, safe_unit, target=None, confirmed=confirmed is True, success=False,
                         message=error or "The exact service definition could not be verified.")
    if confirmed is not True:
        return _response(safe_action, safe_scope, safe_unit, target=target, confirmed=False, success=False,
                         message="Explicit client confirmation is required; no service file was written.")
    if (
        confirmed_action != target.action or confirmed_scope != target.scope or confirmed_unit != target.unit
        or confirmed_executable != target.executable or confirmed_arguments != list(target.arguments)
        or confirmed_phrase != target.confirmation_phrase or expected_state_token != target.state_token
        or not isinstance(expected_state_token, str) or not _TOKEN_RE.fullmatch(expected_state_token)
    ):
        return _response(safe_action, safe_scope, safe_unit, target=target, confirmed=True, success=False,
                         message="Confirmation did not repeat the exact command and current state token; no file was written.")

    with _ACTION_LOCK:
        current, error = _prepare_definition(action, scope, unit, executable, arguments)
        if error or current is None or current != target:
            return _response(safe_action, safe_scope, safe_unit, target=target, confirmed=True, success=False,
                             message=error or "The service file or manager state changed after confirmation; no file was written.")
        if current.action == "create":
            if current.create_target is None:
                return _response(safe_action, safe_scope, safe_unit, target=target, confirmed=True, success=False,
                                 message="The create-only file target was lost after confirmation; no file was written.")
            file_result = create_text_file(
                str(current.path), current.content, confirmed=True,
                confirmed_path=str(current.create_target.path),
                confirmed_content_sha256=current.create_target.content_sha256,
            )
        else:
            if current.replace_target is None:
                return _response(safe_action, safe_scope, safe_unit, target=target, confirmed=True, success=False,
                                 message="The update file target was lost after confirmation; no file was written.")
            file_result = replace_text_file(
                str(current.path), current.content, confirmed=True,
                confirmed_path=str(current.replace_target.path),
                confirmed_current_sha256=current.replace_target.current_sha256,
                confirmed_replacement_sha256=current.replace_target.replacement_sha256,
            )
        if not file_result.success:
            return _response(safe_action, safe_scope, safe_unit, target=target, confirmed=True, success=False,
                             message=f"The service file was not updated: {file_result.message}")

        reload_success, reload_error = _run_daemon_reload(current.scope)
        if not reload_success:
            return _response(safe_action, safe_scope, safe_unit, target=target, confirmed=True, success=False,
                             file_written=True, unit_file_state=current.unit_file_state,
                             message=("The service file was written, but systemd daemon-reload did not report success; "
                                      f"the manager may still have the previous definition ({reload_error or 'reload error'}). Inspect before retrying."))

        systemctl, _analyzer, env, binary_error = _systemd_binaries()
        after, state_error = (_manager_state(systemctl, env, current.unit, current.scope)
                              if systemctl and not binary_error else (None, binary_error))
        readback, readback_error = text_file_replacement_confirmation_details(str(current.path), current.content)
        expected_unit_file_state = current.unit_file_state if current.action == "update" else "disabled"
        verified = bool(
            after is not None and _manager_value(after, "Id") == current.unit
            and _manager_value(after, "LoadState") == "loaded"
            and _manager_value(after, "ActiveState") == "inactive"
            and _manager_value(after, "UnitFileState") == expected_unit_file_state
            and _manager_value(after, "FragmentPath") == str(current.path)
            and not tuple(value for value in after.values("DropInPaths") if value)
            and readback is not None and readback.original == current.content.encode("utf-8")
            and readback_error is None
        )
        if not verified:
            detail = state_error or readback_error or "the manager did not report the exact inactive service definition."
            return _response(safe_action, safe_scope, safe_unit, target=target, confirmed=True, success=False,
                             file_written=True, unit_file_state=after.value("UnitFileState") if after else current.unit_file_state,
                             message=f"The service file was written and the manager reloaded, but post-change verification failed ({detail}). Inspect it before retrying.")
        effect = ("Created and loaded the service definition; it remains inactive and disabled."
                  if current.action == "create"
                  else "Updated and loaded the service definition; its existing enablement was preserved and it remains inactive.")
        return _response(safe_action, safe_scope, safe_unit, target=target, confirmed=True, success=True,
                         file_written=True, unit_file_state=after.value("UnitFileState"), state_verified=True,
                         message=effect)
