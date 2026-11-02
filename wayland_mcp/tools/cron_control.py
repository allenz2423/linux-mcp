"""Confirmed add/update/remove of marked current-user or generated system cron jobs."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import CronJobActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env

CronJobAction = Literal["add", "update", "remove"]
MAX_CRONTAB_BYTES = 1024 * 1024
MAX_COMMAND_BYTES = 4096
COMMAND_TIMEOUT_SECONDS = 30
MARKER_PREFIX = "# linux-mcp-job:"
_FIELD_CHARS = re.compile(r"^[0-9*,/-]+$")
SYSTEM_CRON_DIRECTORY = Path("/etc/cron.d")
SYSTEM_CRON_FILE_PREFIX = "linux-mcp-"
SYSTEM_CRON_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$")
SYSTEM_CRON_USERNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,62}\$?$")
EMPTY_FILE_DIGEST = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True, slots=True)
class CronJobTarget:
    action: CronJobAction
    scope: Literal["user", "system"]
    username: str
    uid: int
    actor_uid: int
    actor_euid: int
    job_id: str | None
    schedule: str
    command: str
    marker: str
    new_schedule: str | None
    new_command: str | None
    new_marker: str | None
    current_digest: str
    system_file_exists: bool
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def cron_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    if find_session_binary("crontab", env or _environment()):
        return True
    if os.geteuid() != 0:
        return False
    directory_fd, error = _open_system_cron_directory()
    if error or directory_fd is None:
        return False
    os.close(directory_fd)
    return True


def _field_valid(value: str, minimum: int, maximum: int) -> bool:
    if not value or not _FIELD_CHARS.fullmatch(value):
        return False
    for element in value.split(","):
        if not element:
            return False
        base, slash, step_text = element.partition("/")
        if slash:
            if not step_text.isdigit() or int(step_text, 10) < 1 or int(step_text, 10) > maximum - minimum + 1:
                return False
        if base == "*":
            continue
        if "-" in base:
            pieces = base.split("-")
            if len(pieces) != 2 or not all(piece.isdigit() for piece in pieces):
                return False
            start, end = (int(piece, 10) for piece in pieces)
            if not minimum <= start <= end <= maximum:
                return False
        elif base.isdigit():
            number = int(base, 10)
            if not minimum <= number <= maximum:
                return False
        else:
            return False
    return True


def _validate_schedule(schedule: object) -> tuple[str | None, str | None]:
    if not isinstance(schedule, str) or len(schedule) > 128 or schedule != schedule.strip():
        return None, "schedule must be five numeric cron fields without surrounding whitespace."
    fields = schedule.split()
    ranges = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
    if len(fields) != 5 or not all(_field_valid(field, *bounds) for field, bounds in zip(fields, ranges)):
        return None, "schedule must contain five valid numeric cron fields (minute, hour, day, month, weekday); names and macros are not accepted."
    return " ".join(fields), None


def _validate_command(command: object) -> tuple[str | None, str | None]:
    if not isinstance(command, str) or not command:
        return None, f"command must be non-empty text of at most {MAX_COMMAND_BYTES} UTF-8 bytes."
    try:
        encoded = command.encode("utf-8", errors="strict")
    except UnicodeError:
        return None, "command must contain valid UTF-8 text."
    if len(encoded) > MAX_COMMAND_BYTES:
        return None, f"command must be non-empty text of at most {MAX_COMMAND_BYTES} UTF-8 bytes."
    if any(ord(character) < 32 or ord(character) == 127 for character in command):
        return None, "command may not contain newline, tab, NUL, or other control characters."
    if command != command.strip() or command.endswith("\\"):
        return None, "command may not have surrounding whitespace or end with a continuation backslash."
    return command, None


def _current_identity() -> tuple[str | None, int | None, str | None]:
    try:
        record = pwd.getpwuid(os.geteuid())
    except (KeyError, OSError):
        return None, None, "The server identity has no local passwd record for current-user crontab control."
    if not record.pw_name or any(character in record.pw_name for character in "\r\n\x00"):
        return None, None, "The current server identity name is invalid for crontab."
    return record.pw_name, record.pw_uid, None


def _read_crontab() -> tuple[str | None, str | None, str | None]:
    binary = find_session_binary("crontab", _environment())
    if not binary:
        return None, None, "The crontab command is unavailable."
    try:
        result = subprocess.run(
            [binary, "-l"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, None, "The current user's crontab could not be read."
    if len(result.stdout) > MAX_CRONTAB_BYTES or len(result.stderr) > 16 * 1024:
        return None, None, "The current user's crontab exceeded the bounded read limit."
    if result.returncode == 0:
        try:
            text = result.stdout.decode("utf-8", errors="strict")
        except UnicodeError:
            return None, None, "The current user's crontab is not valid UTF-8."
        return text, hashlib.sha256(result.stdout).hexdigest(), None
    try:
        stderr = result.stderr.decode("utf-8", errors="replace").casefold()
    except UnicodeError:
        stderr = ""
    if result.returncode == 1 and not result.stdout and "no crontab for" in stderr:
        return "", hashlib.sha256(b"").hexdigest(), None
    return None, None, "The current user's crontab could not be read safely; no account or schedule details were returned."


def _open_system_cron_directory() -> tuple[int | None, str | None]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_fd = os.open(SYSTEM_CRON_DIRECTORY, flags)
    except OSError:
        return None, "The fixed /etc/cron.d directory could not be opened safely."
    try:
        info = os.fstat(directory_fd)
    except OSError:
        os.close(directory_fd)
        return None, "The fixed /etc/cron.d directory could not be inspected safely."
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        os.close(directory_fd)
        return None, "The fixed /etc/cron.d directory failed its ownership or permission check."
    return directory_fd, None


def _read_system_file_at(
    directory_fd: int,
    job_id: str,
) -> tuple[str | None, str, bool, str | None]:
    file_name = SYSTEM_CRON_FILE_PREFIX + job_id
    try:
        descriptor = os.open(
            file_name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        return None, EMPTY_FILE_DIGEST, False, None
    except OSError:
        return None, EMPTY_FILE_DIGEST, False, "The exact managed system cron file could not be opened safely."
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_nlink != 1
            or info.st_size > MAX_CRONTAB_BYTES
        ):
            return None, EMPTY_FILE_DIGEST, True, "The exact system cron file failed its ownership, link-count, type, or size check."
        data = bytearray()
        while len(data) <= MAX_CRONTAB_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_CRONTAB_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_CRONTAB_BYTES:
            return None, EMPTY_FILE_DIGEST, True, "The exact system cron file exceeded the bounded read size."
        try:
            text = bytes(data).decode("utf-8", errors="strict")
        except UnicodeError:
            return None, EMPTY_FILE_DIGEST, True, "The exact system cron file is not valid UTF-8."
        return text, hashlib.sha256(data).hexdigest(), True, None
    except OSError:
        return None, EMPTY_FILE_DIGEST, True, "The exact system cron file could not be read safely."
    finally:
        os.close(descriptor)


def _read_system_cron_file(job_id: str) -> tuple[str | None, str | None, bool, str | None]:
    directory_fd, error = _open_system_cron_directory()
    if error or directory_fd is None:
        return None, None, False, error or "The fixed /etc/cron.d directory is unavailable."
    try:
        return _read_system_file_at(directory_fd, job_id)
    finally:
        os.close(directory_fd)


def _install_system_cron_file(
    job_id: str,
    *,
    expected_exists: bool,
    expected_digest: str,
    contents: str | None,
) -> bool:
    if os.geteuid() != 0:
        return False
    directory_fd, error = _open_system_cron_directory()
    if error or directory_fd is None:
        return False
    file_name = SYSTEM_CRON_FILE_PREFIX + job_id
    temporary_name = ".linux-mcp-tmp-" + secrets.token_hex(12)
    temporary_fd: int | None = None
    try:
        current_text, current_digest, current_exists, read_error = _read_system_file_at(directory_fd, job_id)
        if read_error or current_exists != expected_exists or current_digest != expected_digest:
            return False
        if contents is None:
            if not current_exists:
                return False
            os.unlink(file_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
            return True
        data = contents.encode("utf-8", errors="strict")
        if not data or len(data) > MAX_CRONTAB_BYTES:
            return False
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        offset = 0
        while offset < len(data):
            written = os.write(temporary_fd, data[offset:])
            if written <= 0:
                return False
            offset += written
        os.fchmod(temporary_fd, 0o644)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        if current_exists:
            os.replace(
                temporary_name,
                file_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
        else:
            os.link(
                temporary_name,
                file_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.unlink(temporary_name, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return True
    except (OSError, UnicodeError):
        return False
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except OSError:
            pass
        os.close(directory_fd)


def cron_job_action_confirmation_details(
    action: str,
    schedule: str,
    command: str,
    new_schedule: str | None = None,
    new_command: str | None = None,
    scope: str = "user",
    run_as_user: str = "",
    job_id: str = "",
) -> tuple[CronJobTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Crontab control is available only on Linux."
    if not isinstance(action, str) or action not in {"add", "update", "remove"}:
        return None, None, "action must be add, update, or remove."
    if not isinstance(scope, str) or scope not in {"user", "system"}:
        return None, None, "scope must be user or system."
    valid_schedule, error = _validate_schedule(schedule)
    if error or valid_schedule is None:
        return None, None, error or "The schedule could not be validated."
    valid_command, error = _validate_command(command)
    if error or valid_command is None:
        return None, None, error or "The command could not be validated."
    valid_new_schedule: str | None = None
    valid_new_command: str | None = None
    new_marker: str | None = None
    if action == "update":
        valid_new_schedule, error = _validate_schedule(new_schedule)
        if error or valid_new_schedule is None:
            return None, None, "update requires a valid new_schedule: " + (error or "the replacement schedule could not be validated.")
        valid_new_command, error = _validate_command(new_command)
        if error or valid_new_command is None:
            return None, None, "update requires a valid new_command: " + (error or "the replacement command could not be validated.")
    elif new_schedule is not None or new_command is not None:
        return None, None, "new_schedule and new_command are only valid for update."
    current_name, current_uid, error = _current_identity()
    if error or current_name is None or current_uid is None:
        return None, None, error or "The current server identity could not be verified."
    actor_uid = os.getuid()
    actor_euid = os.geteuid()
    run_as_uid: int | None = None
    system_file_exists = False
    if scope == "user":
        if run_as_user or job_id:
            return None, None, "run_as_user and job_id must be empty for user scope."
        if not find_session_binary("crontab", _environment()):
            return None, None, "The crontab command is required for user scope."
        username = current_name
        uid = current_uid
        crontab, current_digest, error = _read_crontab()
        if error or crontab is None or current_digest is None:
            return None, None, error or "The current user's crontab could not be read."
        current_text = crontab
        marker_basis = valid_schedule + "\x00" + valid_command
        expected_line = f"{valid_schedule} {valid_command}"
        system_path = ""
    else:
        if actor_euid != 0:
            return None, None, "System cron changes require the server process to already run as root; this tool does not elevate."
        if not isinstance(job_id, str) or not SYSTEM_CRON_JOB_ID_RE.fullmatch(job_id):
            return None, None, "System scope requires one safe job_id using letters, numbers, underscores, or hyphens."
        if not isinstance(run_as_user, str) or not SYSTEM_CRON_USERNAME_RE.fullmatch(run_as_user):
            return None, None, "System scope requires one exact local run_as_user name."
        try:
            account = pwd.getpwnam(run_as_user)
        except KeyError:
            return None, None, "run_as_user must name an existing local account."
        if account.pw_name != run_as_user:
            return None, None, "run_as_user must exactly match an existing local account name."
        username = account.pw_name
        uid = account.pw_uid
        run_as_uid = account.pw_uid
        system_path = str(SYSTEM_CRON_DIRECTORY / (SYSTEM_CRON_FILE_PREFIX + job_id))
        current_text, current_digest, system_file_exists, error = _read_system_cron_file(job_id)
        if error or current_digest is None:
            return None, None, error or "The exact system cron file could not be read."
        if action == "add" and system_file_exists:
            return None, None, "This system job_id already names a file; existing system cron files are never overwritten unless their exact marked entry is selected for update."
        if action in {"update", "remove"} and not system_file_exists:
            return None, None, "The exact managed system cron file was not found."
        if current_text is None:
            current_text = ""
        marker_basis = username + "\x00" + job_id + "\x00" + valid_schedule + "\x00" + valid_command
        expected_line = f"{valid_schedule} {username} {valid_command}"
        if system_file_exists and len(current_text.splitlines()) != 2:
            # The managed file contains exactly its marker and one system-cron line.
            return None, None, "The system cron file contains content outside the one marked job; it will not be edited."
    marker_hash = hashlib.sha256(marker_basis.encode("utf-8")).hexdigest()[:24]
    marker = f"{MARKER_PREFIX}{marker_hash}"
    if action == "update":
        assert valid_new_schedule is not None and valid_new_command is not None
        new_marker_basis = (
            valid_new_schedule + "\x00" + valid_new_command
            if scope == "user"
            else username + "\x00" + job_id + "\x00" + valid_new_schedule + "\x00" + valid_new_command
        )
        new_marker_hash = hashlib.sha256(new_marker_basis.encode("utf-8")).hexdigest()[:24]
        new_marker = f"{MARKER_PREFIX}{new_marker_hash}"
        if new_marker == marker:
            new_expected_line = (
                f"{valid_new_schedule} {valid_new_command}"
                if scope == "user"
                else f"{valid_new_schedule} {username} {valid_new_command}"
            )
            if new_expected_line == expected_line:
                return None, None, "The requested update is identical to the existing job."
            return None, None, "The replacement job collides with the existing managed marker."
    lines = current_text.splitlines()
    marker_indexes = [index for index, line in enumerate(lines) if line == marker]
    if action == "add":
        if scope == "user" and marker_indexes:
            return None, None, "This exact managed job already exists; duplicate entries are refused."
    else:
        if len(marker_indexes) != 1 or marker_indexes[0] + 1 >= len(lines) or lines[marker_indexes[0] + 1] != expected_line:
            return None, None, "The exact marked job was not found uniquely or its schedule/command changed."
        if scope == "system" and (marker_indexes[0] != 0 or len(lines) != 2):
            return None, None, "The system cron file contains content outside the exact marked job; it will not be edited."
        if action == "update" and new_marker in lines:
            return None, None, "A marked job with the replacement schedule and command already exists; duplicate entries are refused."
    details = {
        "action": action,
        "scope": scope,
        "username": username,
        "uid": uid,
        "run_as_uid": run_as_uid,
        "actor_uid": actor_uid,
        "actor_euid": actor_euid,
        "job_id": job_id if scope == "system" else None,
        "system_path": system_path,
        "schedule": valid_schedule,
        "command": valid_command,
        "marker": marker,
        "new_schedule": valid_new_schedule,
        "new_command": valid_new_command,
        "new_marker": new_marker,
        "current_source_digest": current_digest,
        "system_file_exists": system_file_exists,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = CronJobTarget(
        action=action,  # type: ignore[arg-type]
        scope=scope,  # type: ignore[arg-type]
        username=username,
        uid=uid,
        actor_uid=actor_uid,
        actor_euid=actor_euid,
        job_id=job_id if scope == "system" else None,
        schedule=valid_schedule,
        command=valid_command,
        marker=marker,
        new_schedule=valid_new_schedule,
        new_command=valid_new_command,
        new_marker=new_marker,
        current_digest=current_digest,
        system_file_exists=system_file_exists,
        state_digest=digest,
    )
    phrase = hashlib.sha256((action + ":" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"cron {phrase}", None


def _install_crontab(text: str) -> bool:
    binary = find_session_binary("crontab", _environment())
    if not binary:
        return False
    data = text.encode("utf-8")
    if len(data) > MAX_CRONTAB_BYTES:
        return False
    try:
        result = subprocess.run(
            [binary, "-"],
            input=data,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def perform_cron_job_action(
    action: CronJobAction,
    schedule: str,
    command: str,
    *,
    new_schedule: str | None = None,
    new_command: str | None = None,
    scope: Literal["user", "system"] = "user",
    run_as_user: str = "",
    job_id: str = "",
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> CronJobActionResponse:
    safe_scope: Literal["user", "system"] = scope if isinstance(scope, str) and scope in {"user", "system"} else "user"
    safe_job_id = job_id if safe_scope == "system" and isinstance(job_id, str) else None
    target, phrase, error = cron_job_action_confirmation_details(
        action,
        schedule,
        command,
        new_schedule,
        new_command,
        scope,
        run_as_user,
        job_id,
    )
    response_schedule = target.new_schedule if target is not None and action == "update" and target.new_schedule is not None else (target.schedule if target is not None else schedule)
    if error or target is None or phrase is None:
        return CronJobActionResponse(success=False, action=action, username=run_as_user or "", schedule=response_schedule, scope=safe_scope, job_id=safe_job_id, user_confirmed=confirmed is True, message=error or "The cron job request could not be verified.")
    if confirmed is not True:
        return CronJobActionResponse(success=False, action=action, username=target.username, schedule=response_schedule, scope=target.scope, job_id=target.job_id, user_confirmed=False, message="Explicit client confirmation is required; no cron source was changed.")
    if confirmation_phrase != phrase:
        return CronJobActionResponse(success=False, action=action, username=target.username, schedule=response_schedule, scope=target.scope, job_id=target.job_id, user_confirmed=True, message="Confirmation did not match the exact marked cron job and current source state.")
    current, current_phrase, error = cron_job_action_confirmation_details(
        action,
        schedule,
        command,
        new_schedule,
        new_command,
        scope,
        run_as_user,
        job_id,
    )
    if error or current is None or current_phrase != phrase:
        return CronJobActionResponse(success=False, action=action, username=target.username, schedule=response_schedule, scope=target.scope, job_id=target.job_id, user_confirmed=True, message=error or "The cron source changed after confirmation; no change was made.")

    if target.scope == "user":
        crontab, current_digest, error = _read_crontab()
        if error or crontab is None or current_digest != target.current_digest:
            return CronJobActionResponse(success=False, action=action, username=target.username, schedule=response_schedule, scope=target.scope, user_confirmed=True, message=error or "The crontab changed immediately before installation; no crontab was changed.")
        lines = crontab.splitlines()
        expected_line = f"{target.schedule} {target.command}"
        if action == "add":
            lines.extend((target.marker, expected_line))
        elif action == "remove":
            index = lines.index(target.marker)
            del lines[index:index + 2]
        else:
            assert target.new_marker is not None and target.new_schedule is not None and target.new_command is not None
            index = lines.index(target.marker)
            lines[index:index + 2] = (target.new_marker, f"{target.new_schedule} {target.new_command}")
        updated = "\n".join(lines)
        if updated and not updated.endswith("\n"):
            updated += "\n"
        if not _install_crontab(updated):
            return CronJobActionResponse(success=False, action=action, username=target.username, schedule=response_schedule, scope=target.scope, user_confirmed=True, message="crontab did not accept the update; inspect current schedules before retrying.")
        resulting, _digest, error = _read_crontab()
        if error or resulting is None:
            return CronJobActionResponse(success=False, action=action, username=target.username, schedule=response_schedule, scope=target.scope, user_confirmed=True, message="crontab accepted the update, but the resulting schedule could not be read back.")
        result_lines = resulting.splitlines()
        if action == "add":
            index = result_lines.index(target.marker) if target.marker in result_lines else -1
            verified = index >= 0 and index + 1 < len(result_lines) and result_lines[index + 1] == expected_line
        elif action == "remove":
            verified = target.marker not in result_lines
        else:
            assert target.new_marker is not None and target.new_schedule is not None and target.new_command is not None
            index = result_lines.index(target.new_marker) if result_lines.count(target.new_marker) == 1 else -1
            verified = target.marker not in result_lines and index >= 0 and index + 1 < len(result_lines) and result_lines[index + 1] == f"{target.new_schedule} {target.new_command}"
    else:
        assert target.job_id is not None
        current_text, current_digest, current_exists, error = _read_system_cron_file(target.job_id)
        if error or current_digest != target.current_digest or current_exists != target.system_file_exists:
            return CronJobActionResponse(success=False, action=action, username=target.username, schedule=response_schedule, scope=target.scope, job_id=target.job_id, user_confirmed=True, message=error or "The system cron file changed immediately before installation; no change was made.")
        expected_line = f"{target.schedule} {target.username} {target.command}"
        if action == "add":
            updated_content = f"{target.marker}\n{expected_line}\n"
        elif action == "remove":
            updated_content = None
        else:
            assert target.new_marker is not None and target.new_schedule is not None and target.new_command is not None
            updated_content = f"{target.new_marker}\n{target.new_schedule} {target.username} {target.new_command}\n"
        if not _install_system_cron_file(
            target.job_id,
            expected_exists=target.system_file_exists,
            expected_digest=target.current_digest,
            contents=updated_content,
        ):
            return CronJobActionResponse(success=False, action=action, username=target.username, schedule=response_schedule, scope=target.scope, job_id=target.job_id, user_confirmed=True, message="The exact system cron file could not be updated atomically; inspect current schedules before retrying.")
        resulting, _digest, result_exists, error = _read_system_cron_file(target.job_id)
        if error:
            return CronJobActionResponse(success=False, action=action, username=target.username, schedule=response_schedule, scope=target.scope, job_id=target.job_id, user_confirmed=True, message="The system cron file changed, but its resulting state could not be read back.")
        result_lines = resulting.splitlines() if resulting is not None else []
        if action == "add":
            verified = result_exists and result_lines == [target.marker, expected_line]
        elif action == "remove":
            verified = not result_exists
        else:
            assert target.new_marker is not None and target.new_schedule is not None and target.new_command is not None
            verified = result_exists and result_lines == [target.new_marker, f"{target.new_schedule} {target.username} {target.new_command}"]
    if not verified:
        return CronJobActionResponse(success=False, action=action, username=target.username, schedule=response_schedule, scope=target.scope, job_id=target.job_id, user_confirmed=True, message="The cron update returned, but the requested marked job state could not be verified.")
    if target.scope == "system":
        verb = {"add": "Added", "update": "Updated", "remove": "Removed"}[action]
        message = f"{verb} the exact marked /etc/cron.d job for {target.username}. The cron daemon will run it with that account's permissions."
    else:
        message = {
            "add": "Added the confirmed marked job to the current user's crontab.",
            "update": "Updated the exact marked job in the current user's crontab.",
            "remove": "Removed the exact marked job from the current user's crontab.",
        }[action]
    return CronJobActionResponse(success=True, action=action, username=target.username, schedule=response_schedule, scope=target.scope, job_id=target.job_id, user_confirmed=True, message=message)
