"""Bounded execution for fixed helper commands."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time


def _stop_process(process: subprocess.Popen[bytes], *, kill_process_group: bool = False) -> None:
    if kill_process_group:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
    elif process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            pass


def run_bounded_command(
    command: list[str],
    env: dict[str, str],
    *,
    command_label: str,
    timeout_seconds: float,
    max_output_bytes: int,
    cwd: str | os.PathLike[str] | None = None,
    accept_nonzero_exit: bool = False,
    kill_process_group: bool = False,
    pass_fds: tuple[int, ...] = (),
) -> tuple[str | None, str | None, bool]:
    """Run a fixed argument vector with bounded time/output and combined capture.

    Structured command callers may accept nonzero exit codes when the command
    reports useful data and its own status field in the bounded output.
    """
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    total_bytes = 0
    truncated = False
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            start_new_session=kill_process_group,
            pass_fds=pass_fds,
        )
        if process.stdout is None or process.stderr is None:
            return None, f"{command_label} output streams could not be opened.", False
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        stop_reading = False
        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                _stop_process(process, kill_process_group=kill_process_group)
                return None, f"{command_label} timed out after {timeout_seconds:g} seconds.", truncated
            events = selector.select(remaining_time)
            if not events:
                _stop_process(process, kill_process_group=kill_process_group)
                return None, f"{command_label} timed out after {timeout_seconds:g} seconds.", truncated
            for key, _ in events:
                remaining_bytes = max_output_bytes - total_bytes
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
                    truncated = True
                if key.data == "stdout":
                    stdout_buffer.extend(chunk)
                else:
                    stderr_buffer.extend(chunk)
                total_bytes += len(chunk)
                if truncated:
                    _stop_process(process, kill_process_group=kill_process_group)
                    stop_reading = True
                    break
            if stop_reading:
                break
        if not truncated:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except OSError as exc:
        return None, f"Could not run {command_label}: {exc.strerror or type(exc).__name__}.", truncated
    except subprocess.TimeoutExpired:
        if process is not None:
            _stop_process(process, kill_process_group=kill_process_group)
        return None, f"{command_label} timed out after {timeout_seconds:g} seconds.", truncated
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                _stop_process(process, kill_process_group=kill_process_group)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    if process is None:
        return None, f"Could not start {command_label}.", truncated
    stdout = bytes(stdout_buffer).decode("utf-8", errors="replace")
    stderr = bytes(stderr_buffer).decode("utf-8", errors="replace")[:500].strip()
    if process.returncode != 0 and not truncated and not accept_nonzero_exit:
        return None, stderr or f"{command_label} exited with status {process.returncode}.", False
    return stdout, None, truncated


def run_bounded_binary_command(
    command: list[str],
    env: dict[str, str],
    *,
    command_label: str,
    timeout_seconds: float,
    max_output_bytes: int,
    cwd: str | os.PathLike[str] | None = None,
) -> tuple[bytes | None, str | None, bool]:
    """Run a fixed binary-output command with bounded time and combined capture."""
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    total_bytes = 0
    truncated = False
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
        )
        if process.stdout is None or process.stderr is None:
            return None, f"{command_label} output streams could not be opened.", False
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                _stop_process(process)
                return None, f"{command_label} timed out after {timeout_seconds:g} seconds.", truncated
            events = selector.select(remaining_time)
            if not events:
                _stop_process(process)
                return None, f"{command_label} timed out after {timeout_seconds:g} seconds.", truncated
            for key, _ in events:
                remaining_bytes = max_output_bytes - total_bytes
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
                    truncated = True
                if key.data == "stdout":
                    stdout_buffer.extend(chunk)
                else:
                    stderr_buffer.extend(chunk)
                total_bytes += len(chunk)
                if truncated:
                    _stop_process(process)
                    break
            if truncated:
                break
        if not truncated:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except OSError as exc:
        return None, f"Could not run {command_label}: {exc.strerror or type(exc).__name__}.", truncated
    except subprocess.TimeoutExpired:
        if process is not None:
            _stop_process(process)
        return None, f"{command_label} timed out after {timeout_seconds:g} seconds.", truncated
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                _stop_process(process)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    if process is None:
        return None, f"Could not start {command_label}.", truncated
    if process.returncode != 0 and not truncated:
        stderr = bytes(stderr_buffer).decode("utf-8", errors="replace")[:500].strip()
        return None, stderr or f"{command_label} exited with status {process.returncode}.", False
    return bytes(stdout_buffer), None, truncated
