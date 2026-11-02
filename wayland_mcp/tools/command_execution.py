"""Explicitly confirmed shell execution with bounded time and output."""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import CommandExecutionResponse

MAX_COMMAND_CHARS = 64 * 1024
MAX_STDIN_BYTES = 64 * 1024
MAX_ENV_ENTRIES = 64
MAX_ENV_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_TIMEOUT_SECONDS = 30 * 60
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class PreparedCommand:
    command: str
    working_directory: str
    timeout_seconds: int
    max_output_bytes: int
    stdin_text: str
    environment: dict[str, str]
    run_as: Literal["server", "root"]
    command_sha256: str
    phrase: str
    sudo_path: str | None


def command_invocation(prepared: PreparedCommand) -> tuple[list[str], dict[str, str]]:
    """Build argv/environment once for both pipe-based and PTY execution."""
    argv = ["/bin/sh", "-c", prepared.command]
    if prepared.run_as == "root" and prepared.sudo_path:
        env_program = "/usr/bin/env" if Path("/usr/bin/env").is_file() else "/bin/env"
        assignments = [f"{key}={value}" for key, value in sorted(prepared.environment.items())]
        argv = [prepared.sudo_path, "-n", "--", env_program, *assignments, *argv]
        environment = {"PATH": os.defpath, "LANG": os.environ.get("LANG", "C")}
    else:
        environment = os.environ.copy()
        environment.update(prepared.environment)
    return argv, environment


def prepare_command(
    command: str,
    working_directory: str,
    timeout_seconds: int,
    max_output_bytes: int,
    stdin_text: str,
    environment: dict[str, str] | None,
    run_as: Literal["server", "root"],
) -> tuple[PreparedCommand | None, str | None]:
    """Validate and canonicalize the exact request used by confirmation and execution."""
    if not sys.platform.startswith("linux"):
        return None, "Shell execution is available only on Linux."
    if not isinstance(command, str) or not command.strip() or len(command) > MAX_COMMAND_CHARS or "\x00" in command:
        return None, f"Command must be non-empty and at most {MAX_COMMAND_CHARS} characters, without NUL bytes."
    try:
        command.encode("utf-8")
    except UnicodeEncodeError:
        return None, "Command must contain valid UTF-8 text."
    if not isinstance(working_directory, str) or len(working_directory) > 4096 or "\x00" in working_directory:
        return None, "Working directory must be a path of at most 4096 characters without NUL bytes."
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        return None, f"Timeout must be an integer from 1 through {MAX_TIMEOUT_SECONDS} seconds."
    if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int) or not 1024 <= max_output_bytes <= MAX_OUTPUT_BYTES:
        return None, f"Output limit must be an integer from 1024 through {MAX_OUTPUT_BYTES} bytes."
    if not isinstance(stdin_text, str) or "\x00" in stdin_text:
        return None, f"Standard input must be at most {MAX_STDIN_BYTES} encoded bytes and contain no NUL bytes."
    try:
        stdin_bytes = stdin_text.encode("utf-8")
    except UnicodeEncodeError:
        return None, "Standard input must contain valid UTF-8 text."
    if len(stdin_bytes) > MAX_STDIN_BYTES:
        return None, f"Standard input must be at most {MAX_STDIN_BYTES} encoded bytes and contain no NUL bytes."
    if not isinstance(run_as, str) or run_as not in {"server", "root"}:
        return None, "run_as must be 'server' or 'root'."

    try:
        cwd = Path(working_directory or os.getcwd()).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None, "Working directory does not exist or cannot be resolved."
    if not cwd.is_dir():
        return None, "Working directory must resolve to an existing directory."

    overrides = {} if environment is None else environment
    if not isinstance(overrides, dict) or len(overrides) > MAX_ENV_ENTRIES:
        return None, f"Environment overrides must be an object with at most {MAX_ENV_ENTRIES} entries."
    env_bytes = 0
    normalized_env: dict[str, str] = {}
    for key, value in overrides.items():
        if not isinstance(key, str) or not _ENV_NAME_RE.fullmatch(key):
            return None, "Environment variable names must use standard shell identifier syntax."
        if not isinstance(value, str) or "\x00" in value:
            return None, f"Environment value for {key} must be text without NUL bytes."
        try:
            value_bytes = value.encode("utf-8")
        except UnicodeEncodeError:
            return None, f"Environment value for {key} must contain valid UTF-8 text."
        env_bytes += len(key.encode("utf-8")) + len(value_bytes)
        if env_bytes > MAX_ENV_BYTES:
            return None, f"Environment overrides exceed {MAX_ENV_BYTES} encoded bytes."
        normalized_env[key] = value

    sudo_path: str | None = None
    if run_as == "root" and os.geteuid() != 0:
        sudo_path = shutil.which("sudo", path=os.defpath)
        if sudo_path is None:
            return None, "Root execution requires sudo or a server process already running as root."

    confirmation_material = json.dumps(
        {
            "command": command,
            "working_directory": str(cwd),
            "timeout_seconds": timeout_seconds,
            "max_output_bytes": max_output_bytes,
            "stdin_text": stdin_text,
            "environment": sorted(normalized_env.items()),
            "run_as": run_as,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(confirmation_material).hexdigest()
    return PreparedCommand(
        command=command,
        working_directory=str(cwd),
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        stdin_text=stdin_text,
        environment=normalized_env,
        run_as=run_as,
        command_sha256=digest,
        phrase=f"RUN {digest[:16]}",
        sudo_path=sudo_path,
    ), None


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        pass
    deadline = time.monotonic() + 0.5
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    remaining = deadline - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)
    # The shell can exit before same-group descendants do, so kill the group
    # after the grace period even when wait() observed the shell exit early.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass


def _response(
    prepared: PreparedCommand,
    *,
    started: float,
    exit_code: int | None,
    stdout: bytearray,
    stderr: bytearray,
    user_confirmed: bool,
    timed_out: bool = False,
    output_truncated: bool = False,
    message: str | None = None,
) -> CommandExecutionResponse:
    return CommandExecutionResponse(
        success=exit_code == 0 and not timed_out and not output_truncated,
        command_sha256=prepared.command_sha256,
        working_directory=prepared.working_directory,
        run_as=prepared.run_as,
        exit_code=exit_code,
        duration_seconds=max(0.0, time.monotonic() - started),
        stdout=bytes(stdout).decode("utf-8", errors="replace"),
        stderr=bytes(stderr).decode("utf-8", errors="replace"),
        output_truncated=output_truncated,
        timed_out=timed_out,
        user_confirmed=user_confirmed,
        message=message,
    )


def run_prepared_command(prepared: PreparedCommand, *, confirmed: bool) -> CommandExecutionResponse:
    """Run one confirmed shell string under the server identity or noninteractive sudo."""
    started = time.monotonic()
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    if not confirmed:
        return _response(
            prepared,
            started=started,
            exit_code=None,
            stdout=stdout_buffer,
            stderr=stderr_buffer,
            user_confirmed=False,
            message="Explicit client confirmation is required; no command was run.",
        )

    command_argv, child_env = command_invocation(prepared)

    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    input_bytes = prepared.stdin_text.encode("utf-8")
    input_offset = 0
    total_output = 0
    output_truncated = False
    timed_out = False
    deadline = started + prepared.timeout_seconds
    try:
        process = subprocess.Popen(
            command_argv,
            cwd=prepared.working_directory,
            env=child_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        if input_bytes:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")

        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                timed_out = True
                _terminate(process)
                break
            events = selector.select(remaining_time)
            if not events:
                timed_out = True
                _terminate(process)
                break
            for key, _ in events:
                if key.data == "stdin":
                    try:
                        written = os.write(key.fileobj.fileno(), input_bytes[input_offset:input_offset + 16 * 1024])
                    except (BrokenPipeError, OSError):
                        written = 0
                        input_offset = len(input_bytes)
                    else:
                        input_offset += written
                    if input_offset >= len(input_bytes):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue

                remaining_bytes = prepared.max_output_bytes - total_output
                try:
                    chunk = os.read(key.fileobj.fileno(), min(64 * 1024, max(1, remaining_bytes + 1)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(chunk) > remaining_bytes:
                    chunk = chunk[:remaining_bytes]
                    output_truncated = True
                if key.data == "stdout":
                    stdout_buffer.extend(chunk)
                else:
                    stderr_buffer.extend(chunk)
                total_output += len(chunk)
                if output_truncated:
                    _terminate(process)
                    break
            if output_truncated:
                break

        if process.poll() is None:
            _terminate(process)
        else:
            process.wait()
    except (OSError, ValueError) as exc:
        if process is not None and process.poll() is None:
            _terminate(process)
        return _response(
            prepared,
            started=started,
            exit_code=process.returncode if process is not None else None,
            stdout=stdout_buffer,
            stderr=stderr_buffer,
            user_confirmed=True,
            timed_out=timed_out,
            output_truncated=output_truncated,
            message=f"Could not complete the command: {getattr(exc, 'strerror', None) or type(exc).__name__}.",
        )
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

    exit_code = process.returncode if process is not None else None
    message = None
    if timed_out:
        message = f"Command timed out after {prepared.timeout_seconds} seconds; its process group was terminated."
    elif output_truncated:
        message = f"Command output exceeded {prepared.max_output_bytes} bytes; its process group was terminated."
    elif exit_code != 0:
        message = f"Command exited with status {exit_code}."
    return _response(
        prepared,
        started=started,
        exit_code=exit_code,
        stdout=stdout_buffer,
        stderr=stderr_buffer,
        user_confirmed=True,
        timed_out=timed_out,
        output_truncated=output_truncated,
        message=message,
    )


def failed_command_response(
    *,
    command: str,
    working_directory: str,
    run_as: Literal["server", "root"],
    message: str,
    timeout_seconds: int = 60,
    max_output_bytes: int = 65536,
    stdin_text: str = "",
    environment: dict[str, str] | None = None,
    user_confirmed: bool = False,
) -> CommandExecutionResponse:
    request_material = json.dumps(
        {
            "command": command,
            "working_directory": working_directory,
            "timeout_seconds": timeout_seconds,
            "max_output_bytes": max_output_bytes,
            "stdin_text": stdin_text,
            "environment": environment,
            "run_as": run_as,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=repr,
    ).encode("utf-8")
    digest = hashlib.sha256(request_material).hexdigest()
    return CommandExecutionResponse(
        success=False,
        command_sha256=digest,
        working_directory=working_directory or None,
        run_as=run_as if isinstance(run_as, str) and run_as in {"server", "root"} else "server",
        user_confirmed=user_confirmed,
        message=message,
    )
