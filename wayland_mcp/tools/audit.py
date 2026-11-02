"""Bounded Linux audit inspection and exact confirmed runtime watch control."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    LinuxAuditEventInfo,
    LinuxAuditEventListResponse,
    LinuxAuditKernelStatus,
    LinuxAuditRuleActionResponse,
    LinuxAuditSummaryResponse,
    LinuxAuditStatusResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

STATUS_FIELDS = {
    "enabled": "enabled",
    "failure": "failure_mode",
    "pid": "daemon_pid",
    "rate_limit": "rate_limit",
    "backlog_limit": "backlog_limit",
    "lost": "lost_events",
    "backlog": "backlog_events",
    "backlog_wait_time": "backlog_wait_time",
    "backlog_wait_time_actual": "backlog_wait_time_actual",
}
STATUS_VALUE_RE = re.compile(r"^\d{1,16}$")
MESSAGE_TYPES_RE = re.compile(r"^[A-Za-z0-9_]+(?:,[A-Za-z0-9_]+)*$")
AUDIT_EVENT_ID_RE = re.compile(r"msg=audit\((\d{1,20}(?:\.\d{1,9})?):(\d{1,20})\)")
RULE_PREFIXES = {"-a", "-A", "-d", "-D", "-w", "-W"}
AUDIT_COMMAND_TIMEOUT_SECONDS = 5.0
AUDIT_HISTORIC_QUERY_TIMEOUT_SECONDS = 10.0
MAX_STATUS_OUTPUT_BYTES = 16 * 1024
MAX_RULE_OUTPUT_BYTES = 512 * 1024
MAX_EVENT_OUTPUT_BYTES = 1024 * 1024
MAX_AUDIT_REPORT_OUTPUT_BYTES = 256 * 1024
MAX_RULES = 100
MAX_RULE_LINE_BYTES = 2 * 1024
MAX_AUDIT_EVENTS = 100
MAX_AUDIT_RECORDS = 200
MAX_AUDIT_RECORD_BYTES = 4 * 1024
MAX_AUDIT_REPORT_LINES = 120
MAX_AUDIT_REPORT_LINE_BYTES = 2 * 1024
MAX_AUDIT_REPORT_RESPONSE_BYTES = 96 * 1024
MAX_AUDIT_WATCH_PATH_CHARS = 4095
AUDIT_WATCH_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,31}$")
AUDIT_WATCH_PERMISSIONS = "rwxa"
PSEUDO_AUDIT_PATHS = (Path("/proc"), Path("/sys"), Path("/dev"), Path("/run"))
AUDIT_EVENT_WINDOWS = {
    "recent": "recent",
    "this-hour": "this-hour",
    "today": "today",
    "yesterday": "yesterday",
    "this-week": "this-week",
    "this-month": "this-month",
    "this-year": "this-year",
    "boot": "boot",
    "all": None,
}
AUDIT_EVENT_END_WINDOWS = {"yesterday": "yesterday"}
AUDIT_REPORT_OPTIONS = {
    "overview": (),
    "authentication": ("--auth",),
    "logins": ("--login",),
    "files": ("--file",),
    "hosts": ("--host",),
    "users": ("--user",),
    "processes": ("--pid",),
    "executables": ("--executable",),
    "syscalls": ("--syscall",),
    "keys": ("--key",),
}


def linux_audit_tools_available(env: dict[str, str] | None = None) -> bool:
    """Report whether an optional Linux audit inspection client is present."""
    return sys.platform.startswith("linux") and any(
        find_session_binary(binary, env)
        for binary in ("auditctl", "ausearch", "aureport")
    )


def _parse_status(output: str) -> tuple[LinuxAuditKernelStatus, int]:
    values: dict[str, int] = {}
    seen: set[str] = set()
    invalid: set[str] = set()
    malformed = 0
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        key = parts[0]
        field_name = STATUS_FIELDS.get(key)
        if field_name is None:
            continue
        if key in seen:
            malformed += 1
            invalid.add(key)
            values.pop(field_name, None)
            continue
        seen.add(key)
        if len(parts) != 2 or not STATUS_VALUE_RE.fullmatch(parts[1]):
            malformed += 1
            invalid.add(key)
            continue
        try:
            value = int(parts[1], 10)
        except ValueError:
            malformed += 1
            invalid.add(key)
            continue
        values[field_name] = value
    for key in invalid:
        values.pop(STATUS_FIELDS[key], None)
    return LinuxAuditKernelStatus(**values), malformed


def _clean_text(value: str) -> str:
    """Remove terminal/control characters before returning command text."""
    return "".join(
        character for character in value
        if ord(character) >= 32 and not 127 <= ord(character) <= 159
    )


def _parse_rules(output: str) -> tuple[list[str], int, bool]:
    rules: list[str] = []
    malformed = 0
    truncated = False
    for raw_line in output.splitlines():
        line = _clean_text(raw_line).strip()
        if not line or line.lower() == "no rules":
            continue
        if line.split(maxsplit=1)[0] not in RULE_PREFIXES:
            malformed += 1
            continue
        encoded = line.encode("utf-8")
        if len(encoded) > MAX_RULE_LINE_BYTES:
            line = encoded[:MAX_RULE_LINE_BYTES].decode("utf-8", errors="ignore")
            truncated = True
        if len(rules) >= MAX_RULES:
            truncated = True
            break
        rules.append(line)
    return rules, malformed, truncated


def _safe_error(error: str | None) -> str | None:
    if error is None:
        return None
    return _clean_text(error).strip()[:300] or "The audit query failed."


@dataclass(slots=True)
class _AuditEventBuilder:
    timestamp: str
    serial: int
    records: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AuditWatchTarget:
    action: Literal["add", "remove"]
    path: Path
    path_identity: tuple[int, ...]
    permissions: str
    key: str
    binary: str
    binary_identity: tuple[int, ...]
    actor_uid: int
    actor_euid: int
    rules_digest: str
    state_digest: str


def audit_rule_control_available(env: dict[str, str] | None = None) -> bool:
    return sys.platform.startswith("linux") and find_session_binary("auditctl", env) is not None


def _audit_binary_identity(binary: str) -> tuple[str | None, tuple[int, ...] | None, str | None]:
    try:
        path = Path(binary).resolve(strict=True)
        info = path.stat()
    except (OSError, RuntimeError, ValueError):
        return None, None, "The auditctl executable identity could not be verified."
    if (
        not stat.S_ISREG(info.st_mode)
        or not info.st_mode & 0o111
        or info.st_mode & 0o022
    ):
        return None, None, "The auditctl executable failed its type, execute, or write-permission check."
    return str(path), (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns), None


def _read_active_audit_rules(binary: str, env: dict[str, str]) -> tuple[tuple[str, ...] | None, str | None, str | None]:
    output, error, output_truncated = run_bounded_command(
        [binary, "-l"],
        env,
        command_label="Linux audit rule-list query",
        timeout_seconds=AUDIT_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_RULE_OUTPUT_BYTES,
    )
    if output is None or error or output_truncated:
        return None, None, _safe_error(error) or "The active audit rule set could not be read completely."
    rules, malformed, parsed_truncated = _parse_rules(output)
    if malformed or parsed_truncated:
        return None, None, "The active audit rule output contained malformed or oversized rules; no rule change was prepared."
    return tuple(rules), hashlib.sha256(output.encode("utf-8")).hexdigest(), None


def _audit_rules_are_locked(binary: str, env: dict[str, str]) -> tuple[bool | None, str | None]:
    output, error, output_truncated = run_bounded_command(
        [binary, "-s"],
        env,
        command_label="Linux audit status query",
        timeout_seconds=AUDIT_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_STATUS_OUTPUT_BYTES,
    )
    if output is None or error or output_truncated:
        return None, _safe_error(error) or "The audit subsystem lock state could not be read."
    status, malformed = _parse_status(output)
    if malformed or status.enabled is None:
        return None, "The audit subsystem lock state could not be parsed safely."
    return status.enabled == 2, None


def _path_identity(path: object) -> tuple[Path | None, tuple[int, ...] | None, str | None]:
    if (
        not isinstance(path, str)
        or not path
        or len(path) > MAX_AUDIT_WATCH_PATH_CHARS
        or not os.path.isabs(path)
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
        or any(character in path for character in "*?[]")
    ):
        return None, None, "path must be one absolute path without control characters or wildcard syntax."
    try:
        canonical = Path(path).resolve(strict=True)
        info = canonical.stat(follow_symlinks=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return None, None, f"The audit watch path could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."
    if canonical == Path("/"):
        return None, None, "The filesystem root cannot be selected as an audit watch."
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        return None, None, "Audit watches are limited to existing regular files or directories."
    if any(canonical == blocked or blocked in canonical.parents for blocked in PSEUDO_AUDIT_PATHS):
        return None, None, "Audit watches under /proc, /sys, /dev, and /run are not supported."
    identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    return canonical, identity, None


def _watch_rule_fields(line: str) -> tuple[str, str, str] | None:
    try:
        tokens = shlex.split(line, comments=False, posix=True)
    except ValueError:
        return None
    if len(tokens) not in {4, 6} or tokens[0] != "-w":
        return None
    if tokens[2] != "-p":
        return None
    if len(tokens) == 6 and tokens[4] != "-k":
        return None
    path = tokens[1]
    permissions = tokens[3]
    key = tokens[5] if len(tokens) == 6 else ""
    if not permissions or any(char not in AUDIT_WATCH_PERMISSIONS for char in permissions) or len(set(permissions)) != len(permissions):
        return None
    if key and not AUDIT_WATCH_KEY_RE.fullmatch(key):
        return None
    canonical_permissions = "".join(char for char in AUDIT_WATCH_PERMISSIONS if char in permissions)
    return path, canonical_permissions, key


def audit_watch_rule_confirmation_details(
    action: str,
    path: str,
    permissions: str,
    key: str,
) -> tuple[AuditWatchTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Linux audit rule management is available only on Linux."
    if not isinstance(action, str) or action not in {"add", "remove"}:
        return None, None, "action must be add or remove."
    canonical_path, target_identity, error = _path_identity(path)
    if error or canonical_path is None or target_identity is None:
        return None, None, error or "The exact audit watch path could not be verified."
    if (
        not isinstance(permissions, str)
        or not permissions
        or len(permissions) > len(AUDIT_WATCH_PERMISSIONS)
        or any(char not in AUDIT_WATCH_PERMISSIONS for char in permissions)
        or len(set(permissions)) != len(permissions)
    ):
        return None, None, "permissions must contain one or more unique r, w, x, and a audit access types."
    canonical_permissions = "".join(char for char in AUDIT_WATCH_PERMISSIONS if char in permissions)
    if not isinstance(key, str) or not AUDIT_WATCH_KEY_RE.fullmatch(key):
        return None, None, "key must contain 1 through 31 ASCII letters, numbers, periods, underscores, or hyphens."
    env = get_sanitized_env()
    binary = find_session_binary("auditctl", env)
    if binary is None:
        return None, None, "The optional auditctl executable is unavailable."
    canonical_binary, binary_identity, error = _audit_binary_identity(binary)
    if error or canonical_binary is None or binary_identity is None:
        return None, None, error or "The auditctl executable could not be verified."
    locked, error = _audit_rules_are_locked(canonical_binary, env)
    if error or locked is None:
        return None, None, error or "The audit subsystem lock state is unavailable."
    if locked:
        return None, None, "The audit subsystem is immutable (enabled=2); its runtime rules cannot be changed."
    rules, rules_digest, error = _read_active_audit_rules(canonical_binary, env)
    if error or rules is None or rules_digest is None:
        return None, None, error or "The active audit rule set could not be verified."
    path_watches = [fields for line in rules if (fields := _watch_rule_fields(line)) is not None and fields[0] == str(canonical_path)]
    expected = (str(canonical_path), canonical_permissions, key)
    exact_count = path_watches.count(expected)
    if action == "add" and path_watches:
        return None, None, "A watch rule already exists for this path; this tool will not merge or reorder audit watches."
    if action == "remove" and (len(path_watches) != 1 or exact_count != 1):
        return None, None, "Removal requires exactly one matching watch on this path with the selected permissions and key."
    actor_uid = os.getuid()
    actor_euid = os.geteuid()
    detail = {
        "action": action,
        "path": str(canonical_path),
        "path_identity": target_identity,
        "permissions": canonical_permissions,
        "key": key,
        "binary": canonical_binary,
        "binary_identity": binary_identity,
        "actor_uid": actor_uid,
        "actor_euid": actor_euid,
        "rules_digest": rules_digest,
        "exact_count": exact_count,
    }
    state_digest = hashlib.sha256(json.dumps(detail, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = AuditWatchTarget(
        action=action,  # type: ignore[arg-type]
        path=canonical_path,
        path_identity=target_identity,
        permissions=canonical_permissions,
        key=key,
        binary=canonical_binary,
        binary_identity=binary_identity,
        actor_uid=actor_uid,
        actor_euid=actor_euid,
        rules_digest=rules_digest,
        state_digest=state_digest,
    )
    phrase = f"AUDIT {hashlib.sha256((action + ':' + state_digest).encode('ascii')).hexdigest()[:16]}"
    return target, phrase, None


def perform_audit_watch_rule_action(
    action: Literal["add", "remove"],
    path: str,
    permissions: str,
    key: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> LinuxAuditRuleActionResponse:
    target, phrase, error = audit_watch_rule_confirmation_details(action, path, permissions, key)
    response = {
        "action": action,
        "path": str(target.path) if target else (path if isinstance(path, str) else None),
        "permissions": target.permissions if target else None,
        "key": target.key if target else None,
    }
    if error or target is None or phrase is None:
        return LinuxAuditRuleActionResponse(success=False, **response, user_confirmed=confirmed is True, message=error or "The exact audit watch change could not be verified.")
    if confirmed is not True:
        return LinuxAuditRuleActionResponse(success=False, **response, user_confirmed=False, message="Explicit client confirmation is required; no audit rule was changed.")
    if confirmation_phrase != phrase:
        return LinuxAuditRuleActionResponse(success=False, **response, user_confirmed=True, message="Confirmation did not match this exact audit rule and current ruleset; no change was made.")
    current, current_phrase, error = audit_watch_rule_confirmation_details(action, path, permissions, key)
    if error or current is None or current_phrase != phrase or current.state_digest != target.state_digest:
        return LinuxAuditRuleActionResponse(success=False, **response, user_confirmed=True, message=error or "The audit rule set or watched path changed after confirmation; no change was made.")
    command = [target.binary, "-w", str(target.path), "-p", target.permissions, "-k", target.key] if action == "add" else [target.binary, "-W", str(target.path), "-p", target.permissions, "-k", target.key]
    env = get_sanitized_env()
    output, command_error, truncated = run_bounded_command(
        command,
        env,
        command_label="Linux audit watch-rule update",
        timeout_seconds=AUDIT_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_STATUS_OUTPUT_BYTES,
    )
    if output is None or command_error or truncated:
        return LinuxAuditRuleActionResponse(success=False, **response, user_confirmed=True, message=_safe_error(command_error) or "auditctl did not complete the exact watch-rule update safely.")
    resulting_rules, _digest, error = _read_active_audit_rules(target.binary, env)
    if error or resulting_rules is None:
        return LinuxAuditRuleActionResponse(success=False, **response, user_confirmed=True, message="auditctl returned, but the resulting active rule set could not be verified.")
    watches = [fields for line in resulting_rules if (fields := _watch_rule_fields(line)) is not None and fields[0] == str(target.path)]
    expected = (str(target.path), target.permissions, target.key)
    verified = watches.count(expected) == 1 if action == "add" else not watches
    if not verified:
        return LinuxAuditRuleActionResponse(success=False, **response, user_confirmed=True, message="auditctl returned, but the exact requested watch-rule state was not verified. Inspect current rules before retrying.")
    resulting_path, resulting_identity, path_error = _path_identity(str(target.path))
    if (
        path_error
        or resulting_path != target.path
        or resulting_identity is None
        or resulting_identity[:2] != target.path_identity[:2]
    ):
        return LinuxAuditRuleActionResponse(success=False, **response, user_confirmed=True, message="The audit watch command returned, but the selected path was replaced during the operation. Inspect the active rule set before retrying.")
    verb = "Added" if action == "add" else "Removed"
    return LinuxAuditRuleActionResponse(success=True, **response, user_confirmed=True, message=f"{verb} the exact runtime audit watch. The change is not persistent across reboot unless the host's audit rules are updated separately.")


def _parse_audit_events(
    output: str,
    *,
    limit: int,
    output_truncated: bool,
) -> tuple[list[LinuxAuditEventInfo], int, bool]:
    """Group bounded raw audit records, retaining the newest events in log order."""
    lines = output.splitlines()
    truncated = output_truncated
    if output_truncated and output and not output.endswith(("\n", "\r")) and lines:
        # The final record may have been cut by the command-output cap.
        lines.pop()
    builders: list[_AuditEventBuilder] = []
    by_event_id: dict[str, _AuditEventBuilder] = {}
    malformed = 0
    record_count = 0
    for raw_line in reversed(lines):
        line = _clean_text(raw_line).strip()
        if not line:
            continue
        match = AUDIT_EVENT_ID_RE.search(line)
        if match is None:
            malformed += 1
            continue
        timestamp, raw_serial = match.groups()
        event_id = f"{timestamp}:{raw_serial}"
        event = by_event_id.get(event_id)
        if event is None:
            if len(builders) >= limit:
                truncated = True
                break
            event = _AuditEventBuilder(timestamp=timestamp, serial=int(raw_serial))
            by_event_id[event_id] = event
            builders.append(event)
        if record_count >= MAX_AUDIT_RECORDS:
            truncated = True
            break
        encoded = line.encode("utf-8")
        if len(encoded) > MAX_AUDIT_RECORD_BYTES:
            line = encoded[:MAX_AUDIT_RECORD_BYTES].decode("utf-8", errors="ignore")
            truncated = True
        event.records.append(line)
        record_count += 1

    result: list[LinuxAuditEventInfo] = []
    for event in reversed(builders):
        event.records.reverse()
        result.append(
            LinuxAuditEventInfo(
                event_id=f"{event.timestamp}:{event.serial}",
                timestamp=event.timestamp,
                serial=event.serial,
                records=event.records,
            )
        )
    return result, malformed, truncated


def _parse_audit_report(
    output: str,
    *,
    limit: int,
    output_truncated: bool,
) -> tuple[list[str], bool]:
    """Return bounded printable report lines without terminal controls."""
    lines: list[str] = []
    response_bytes = 0
    truncated = output_truncated
    raw_lines = output.splitlines()
    if output_truncated and output and not output.endswith(("\n", "\r")) and raw_lines:
        raw_lines.pop()
    for raw_line in raw_lines:
        line = _clean_text(raw_line).rstrip()
        if not line:
            continue
        encoded = line.encode("utf-8")
        if len(encoded) > MAX_AUDIT_REPORT_LINE_BYTES:
            line = encoded[:MAX_AUDIT_REPORT_LINE_BYTES].decode("utf-8", errors="ignore")
            encoded = line.encode("utf-8")
            truncated = True
        if len(lines) >= limit or response_bytes + len(encoded) > MAX_AUDIT_REPORT_RESPONSE_BYTES:
            truncated = True
            break
        lines.append(line)
        response_bytes += len(encoded)
    return lines, truncated


def get_linux_audit_status() -> LinuxAuditStatusResponse:
    """Read kernel audit status and active rules using fixed auditctl queries."""
    if not sys.platform.startswith("linux"):
        return LinuxAuditStatusResponse(
            success=False,
            status_error="Linux audit inventory is available only on Linux.",
            rules_error="Linux audit inventory is available only on Linux.",
            unavailable_sources=["status", "rules"],
            message="Linux audit inventory is available only on Linux.",
        )

    env = get_sanitized_env()
    auditctl = find_session_binary("auditctl", env)
    if auditctl is None:
        unavailable_message = "The optional auditctl executable is unavailable."
        return LinuxAuditStatusResponse(
            success=False,
            status_error=unavailable_message,
            rules_error=unavailable_message,
            unavailable_sources=["status", "rules"],
            message=unavailable_message,
        )

    status_output, status_error, status_truncated = run_bounded_command(
        [auditctl, "-s"],
        env,
        command_label="Linux audit status query",
        timeout_seconds=AUDIT_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_STATUS_OUTPUT_BYTES,
    )
    rules_output, rules_error, rules_output_truncated = run_bounded_command(
        [auditctl, "-l"],
        env,
        command_label="Linux audit rule-list query",
        timeout_seconds=AUDIT_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_RULE_OUTPUT_BYTES,
    )

    status_readable = status_error is None and status_output is not None
    rules_readable = rules_error is None and rules_output is not None
    kernel_status = LinuxAuditKernelStatus()
    malformed_status_lines = 0
    if status_readable and status_output is not None:
        kernel_status, malformed_status_lines = _parse_status(status_output)

    rules: list[str] = []
    malformed_rule_lines = 0
    parsed_rules_truncated = False
    if rules_readable and rules_output is not None:
        rules, malformed_rule_lines, parsed_rules_truncated = _parse_rules(rules_output)

    unavailable_sources = []
    if not status_readable:
        unavailable_sources.append("status")
    if not rules_readable:
        unavailable_sources.append("rules")
    success = status_readable or rules_readable
    truncated = status_truncated or rules_output_truncated or parsed_rules_truncated
    message = (
        "Read-only kernel audit status and active-rule snapshot. Rule text may expose watched paths, syscall filters, and audit keys; permissions and kernel audit support are checked per query."
        if success else "Neither Linux audit status nor active rules could be read."
    )
    if malformed_status_lines or malformed_rule_lines:
        message += " Some command output lines were malformed and omitted."
    return LinuxAuditStatusResponse(
        success=success,
        status_readable=status_readable,
        rules_readable=rules_readable,
        kernel_status=kernel_status,
        rules=rules,
        returned_rule_count=len(rules),
        malformed_status_lines=malformed_status_lines,
        malformed_rule_lines=malformed_rule_lines,
        unavailable_sources=unavailable_sources,
        status_error=_safe_error(status_error),
        rules_error=_safe_error(rules_error),
        truncated=truncated,
        message=message,
    )


def list_linux_audit_events(
    message_type: str = "",
    limit: int = 50,
    window: Literal[
        "recent", "this-hour", "today", "yesterday", "this-week",
        "this-month", "this-year", "boot", "all",
    ] = "recent",
    event_serial: int | None = None,
    process_id: int | None = None,
) -> LinuxAuditEventListResponse:
    """Read recent audit events through a fixed, bounded ausearch query."""
    if not sys.platform.startswith("linux"):
        return LinuxAuditEventListResponse(
            success=False,
            message="Linux audit event inventory is available only on Linux.",
        )
    if not isinstance(message_type, str) or len(message_type) > 128 or (
        message_type and not MESSAGE_TYPES_RE.fullmatch(message_type)
    ):
        return LinuxAuditEventListResponse(
            success=False,
            message="Message type must be one or more comma-separated audit type names or numeric IDs, up to 128 characters.",
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        return LinuxAuditEventListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_AUDIT_EVENTS))
    if not isinstance(window, str) or window not in AUDIT_EVENT_WINDOWS:
        return LinuxAuditEventListResponse(
            success=False,
            limit=limit,
            message="Window must be recent, this-hour, today, yesterday, this-week, this-month, this-year, boot, or all.",
        )
    if event_serial is not None and (
        not isinstance(event_serial, int) or isinstance(event_serial, bool)
        or not 0 <= event_serial <= 4_294_967_295
    ):
        return LinuxAuditEventListResponse(
            success=False,
            limit=limit,
            window=window,
            message="Event serial must be an integer from 0 through 4294967295.",
        )
    if process_id is not None and (
        not isinstance(process_id, int) or isinstance(process_id, bool)
        or not 1 <= process_id <= 2_147_483_647
    ):
        return LinuxAuditEventListResponse(
            success=False,
            limit=limit,
            window=window,
            message="Process ID must be an integer from 1 through 2147483647.",
        )

    env = get_sanitized_env()
    ausearch = find_session_binary("ausearch", env)
    if ausearch is None:
        return LinuxAuditEventListResponse(
            success=False,
            limit=limit,
            window=window,
            message="The optional ausearch executable is unavailable.",
        )

    command = [
        ausearch,
        "--input-logs",
    ]
    start_window = AUDIT_EVENT_WINDOWS[window]
    if start_window is not None:
        command.extend(("--start", start_window))
    end_window = AUDIT_EVENT_END_WINDOWS.get(window)
    if end_window is not None:
        command.extend(("--end", end_window))
    command.extend(("--format", "raw", "--escape", "tty"))
    if message_type:
        command.extend(("--message", message_type))
    if event_serial is not None:
        command.extend(("--event", str(event_serial)))
    if process_id is not None:
        command.extend(("--pid", str(process_id)))
    command_label = "Linux audit event query"
    output, error, output_truncated = run_bounded_command(
        command,
        env,
        command_label=command_label,
        timeout_seconds=(
            AUDIT_HISTORIC_QUERY_TIMEOUT_SECONDS
            if window in {"this-year", "all"}
            else AUDIT_COMMAND_TIMEOUT_SECONDS
        ),
        max_output_bytes=MAX_EVENT_OUTPUT_BYTES,
    )
    if output is None:
        # ausearch uses status 1 both for no matches and minor log read errors.
        no_output_status = f"{command_label} exited with status 1."
        if error == no_output_status:
            return LinuxAuditEventListResponse(
                success=True,
                partial=True,
                limit=limit,
                window=window,
                message_type=message_type,
                event_serial=event_serial,
                process_id=process_id,
                message=(
                    "ausearch returned no output with status 1. This can mean there were no matching events, "
                    "or that a minor audit-log access/read error occurred."
                ),
            )
        return LinuxAuditEventListResponse(
            success=False,
            limit=limit,
            window=window,
            message_type=message_type,
            event_serial=event_serial,
            process_id=process_id,
            query_error=_safe_error(error),
            message="Linux audit events could not be read for the requested window and filters.",
        )

    events, malformed_records, truncated = _parse_audit_events(
        output,
        limit=limit,
        output_truncated=output_truncated,
    )
    partial = truncated or malformed_records > 0
    message = (
        "Read-only audit event records. Records may expose user IDs, paths, command arguments, network addresses, terminal data, and audit keys."
    )
    if malformed_records:
        message += " Unrecognized output lines were omitted."
    if truncated:
        message += " Results were truncated by the configured response or command-output bounds; an output-cap truncation can omit later records from the requested window."
    return LinuxAuditEventListResponse(
        success=True,
        partial=partial,
        window=window,
        limit=limit,
        message_type=message_type,
        event_serial=event_serial,
        process_id=process_id,
        events=events,
        returned_event_count=len(events),
        malformed_records=malformed_records,
        truncated=truncated,
        message=message,
    )


def summarize_linux_audit(
    report_type: Literal[
        "overview", "authentication", "logins", "files", "hosts", "users",
        "processes", "executables", "syscalls", "keys",
    ] = "overview",
    window: Literal[
        "recent", "this-hour", "today", "yesterday", "this-week",
        "this-month", "this-year", "boot", "all",
    ] = "recent",
    limit: int = 80,
) -> LinuxAuditSummaryResponse:
    """Read one allowlisted aggregate audit report through aureport."""
    if not sys.platform.startswith("linux"):
        return LinuxAuditSummaryResponse(
            success=False,
            message="Linux audit summaries are available only on Linux.",
        )
    if not isinstance(report_type, str) or report_type not in AUDIT_REPORT_OPTIONS:
        return LinuxAuditSummaryResponse(
            success=False,
            message="Report type must be overview, authentication, logins, files, hosts, users, processes, executables, syscalls, or keys.",
        )
    if not isinstance(window, str) or window not in AUDIT_EVENT_WINDOWS:
        return LinuxAuditSummaryResponse(
            success=False,
            report_type=report_type,
            message="Window must be recent, this-hour, today, yesterday, this-week, this-month, this-year, boot, or all.",
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        return LinuxAuditSummaryResponse(
            success=False,
            report_type=report_type,
            window=window,
            message="Limit must be an integer number of report lines.",
        )
    limit = max(1, min(limit, MAX_AUDIT_REPORT_LINES))

    env = get_sanitized_env()
    aureport = find_session_binary("aureport", env)
    if aureport is None:
        return LinuxAuditSummaryResponse(
            success=False,
            report_type=report_type,
            window=window,
            limit=limit,
            message="The optional aureport executable is unavailable.",
        )

    command = [aureport, "--input-logs", "--escape", "tty"]
    command.extend(AUDIT_REPORT_OPTIONS[report_type])
    start_window = AUDIT_EVENT_WINDOWS[window]
    if start_window is not None:
        command.extend(("--start", start_window))
    end_window = AUDIT_EVENT_END_WINDOWS.get(window)
    if end_window is not None:
        command.extend(("--end", end_window))
    command.append("--summary")

    command_label = "Linux audit summary query"
    output, error, output_truncated = run_bounded_command(
        command,
        env,
        command_label=command_label,
        timeout_seconds=(
            AUDIT_HISTORIC_QUERY_TIMEOUT_SECONDS
            if window in {"this-week", "this-month", "this-year", "all"}
            else AUDIT_COMMAND_TIMEOUT_SECONDS
        ),
        max_output_bytes=MAX_AUDIT_REPORT_OUTPUT_BYTES,
    )
    if output is None:
        return LinuxAuditSummaryResponse(
            success=False,
            report_type=report_type,
            window=window,
            limit=limit,
            query_error=_safe_error(error),
            message="Linux audit summary could not be read for the requested report and window.",
        )

    report_lines, truncated = _parse_audit_report(
        output,
        limit=limit,
        output_truncated=output_truncated,
    )
    message = (
        "Read-only aggregate Linux audit report. Reports may expose user IDs, file paths, hosts, process names, and audit keys."
    )
    if truncated:
        message += " Report output was truncated by the configured byte or line bounds."
    return LinuxAuditSummaryResponse(
        success=True,
        partial=truncated,
        report_type=report_type,
        window=window,
        limit=limit,
        report_lines=report_lines,
        returned_line_count=len(report_lines),
        truncated=truncated,
        message=message,
    )
