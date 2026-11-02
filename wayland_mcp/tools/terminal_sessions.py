"""Process-local, bounded PTY sessions for explicitly confirmed commands."""

from __future__ import annotations

import errno
import fcntl
import os
import pty
import secrets
import select
import selectors
import signal
import struct
import subprocess
import sys
import threading
import termios
import time
from dataclasses import dataclass, field
from pathlib import Path

from wayland_mcp.models import (
    TerminalSessionCloseResponse,
    TerminalSessionOutputResponse,
    TerminalSessionStartResponse,
    TerminalSessionWriteResponse,
)
from wayland_mcp.tools.command_execution import (
    PreparedCommand,
    _terminate,
    command_invocation,
)

MAX_TERMINAL_SESSIONS = 8
MAX_TERMINAL_BUFFER_BYTES = 1024 * 1024
MAX_TERMINAL_READ_BYTES = 64 * 1024
MAX_TERMINAL_INPUT_BYTES = 4096
MAX_TERMINAL_WAIT_SECONDS = 10.0
MAX_TERMINAL_ROWS = 500
MAX_TERMINAL_COLUMNS = 500
COMPLETED_SESSION_RETENTION_SECONDS = 120.0


@dataclass
class _Session:
    session_id: str
    process: subprocess.Popen[bytes]
    master_fd: int
    created_at: float
    expires_at: float
    command_sha256: str
    working_directory: str
    run_as: str
    rows: int
    columns: int
    output: bytearray = field(default_factory=bytearray)
    dropped_bytes: int = 0
    timed_out: bool = False
    closed_by_client: bool = False
    eof: bool = False
    exit_code: int | None = None
    finished_at: float | None = None
    condition: threading.Condition = field(default_factory=threading.Condition)
    io_lock: threading.Lock = field(default_factory=threading.Lock)
    reader_thread: threading.Thread | None = None


class TerminalSessionManager:
    """Own bounded PTY processes until they exit, expire, or the server stops."""

    def __init__(self) -> None:
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._reaper: threading.Thread | None = None
        self._closing = False

    @staticmethod
    def _group_alive(process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False

    def _get(self, session_id: str) -> _Session | None:
        if not isinstance(session_id, str) or not 16 <= len(session_id) <= 128:
            return None
        with self._lock:
            return self._sessions.get(session_id)

    def _start_reaper_locked(self) -> None:
        if self._reaper is not None and self._reaper.is_alive():
            return
        self._stop.clear()
        self._reaper = threading.Thread(
            target=self._reap_loop,
            name="linux-mcp-pty-reaper",
            daemon=True,
        )
        self._reaper.start()

    def start(
        self,
        prepared: PreparedCommand,
        *,
        request_digest: str,
        rows: int,
        columns: int,
    ) -> TerminalSessionStartResponse:
        if not 1 <= rows <= MAX_TERMINAL_ROWS or not 1 <= columns <= MAX_TERMINAL_COLUMNS:
            return TerminalSessionStartResponse(
                success=False,
                request_sha256=request_digest,
                working_directory=prepared.working_directory,
                run_as=prepared.run_as,
                terminal_rows=rows,
                terminal_columns=columns,
                message=f"Terminal size must be between 1 and {MAX_TERMINAL_ROWS} rows and columns.",
            )

        with self._lock:
            if self._closing:
                return TerminalSessionStartResponse(
                    success=False,
                    request_sha256=request_digest,
                    working_directory=prepared.working_directory,
                    run_as=prepared.run_as,
                    terminal_rows=rows,
                    terminal_columns=columns,
                    message="The terminal session manager is shutting down.",
                )
            running = sum(
                1 for item in self._sessions.values()
                if self._group_alive(item.process.pid)
            )
            if running >= MAX_TERMINAL_SESSIONS:
                return TerminalSessionStartResponse(
                    success=False,
                    request_sha256=request_digest,
                    working_directory=prepared.working_directory,
                    run_as=prepared.run_as,
                    terminal_rows=rows,
                    terminal_columns=columns,
                    message=f"At most {MAX_TERMINAL_SESSIONS} terminal sessions may run at once.",
                )

        master_fd = -1
        slave_fd = -1
        process: subprocess.Popen[bytes] | None = None
        try:
            master_fd, slave_fd = pty.openpty()
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
            command_argv, child_env = command_invocation(prepared)
            helper = str(Path(__file__).with_name("pty_child.py"))
            helper_argv = [sys.executable, helper, str(slave_fd), "--", *command_argv]
            process = subprocess.Popen(
                helper_argv,
                cwd=prepared.working_directory,
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(slave_fd,),
                start_new_session=True,
            )
            os.close(slave_fd)
            slave_fd = -1
            os.set_blocking(master_fd, False)
            session_id = secrets.token_urlsafe(24)
            now = time.monotonic()
            session = _Session(
                session_id=session_id,
                process=process,
                master_fd=master_fd,
                created_at=now,
                expires_at=now + prepared.timeout_seconds,
                command_sha256=request_digest,
                working_directory=prepared.working_directory,
                run_as=prepared.run_as,
                rows=rows,
                columns=columns,
            )
            session.reader_thread = threading.Thread(
                target=self._read_pty,
                args=(session,),
                name=f"linux-mcp-pty-{process.pid}",
                daemon=True,
            )
            with self._lock:
                # Recheck after creating the PTY to cover concurrent starts.
                running = sum(
                    1 for item in self._sessions.values()
                    if self._group_alive(item.process.pid)
                )
                if running >= MAX_TERMINAL_SESSIONS:
                    _terminate(process)
                    os.close(master_fd)
                    master_fd = -1
                    return TerminalSessionStartResponse(
                        success=False,
                        request_sha256=request_digest,
                        working_directory=prepared.working_directory,
                        run_as=prepared.run_as,
                        terminal_rows=rows,
                        terminal_columns=columns,
                        message=f"At most {MAX_TERMINAL_SESSIONS} terminal sessions may run at once.",
                    )
                if self._closing:
                    _terminate(process)
                    os.close(master_fd)
                    master_fd = -1
                    return TerminalSessionStartResponse(
                        success=False,
                        request_sha256=request_digest,
                        working_directory=prepared.working_directory,
                        run_as=prepared.run_as,
                        terminal_rows=rows,
                        terminal_columns=columns,
                        message="The terminal session manager is shutting down.",
                    )
                self._sessions[session_id] = session
                self._start_reaper_locked()
            assert session.reader_thread is not None
            session.reader_thread.start()
            master_fd = -1
            return TerminalSessionStartResponse(
                success=True,
                session_id=session_id,
                pid=process.pid,
                request_sha256=request_digest,
                working_directory=prepared.working_directory,
                run_as=prepared.run_as,
                terminal_rows=rows,
                terminal_columns=columns,
                expires_in_seconds=float(prepared.timeout_seconds),
                message="Terminal session started. Use its opaque session ID to read output, send confirmed input, resize, or close it.",
            )
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            if process is not None and process.poll() is None:
                _terminate(process)
            return TerminalSessionStartResponse(
                success=False,
                request_sha256=request_digest,
                working_directory=prepared.working_directory,
                run_as=prepared.run_as,
                terminal_rows=rows,
                terminal_columns=columns,
                message=f"Could not start terminal session: {getattr(exc, 'strerror', None) or type(exc).__name__}.",
            )
        finally:
            for fd in (slave_fd, master_fd):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    def _read_pty(self, session: _Session) -> None:
        selector = selectors.DefaultSelector()
        try:
            selector.register(session.master_fd, selectors.EVENT_READ)
            while True:
                events = selector.select(0.5)
                if not events and not self._group_alive(session.process.pid):
                    break
                for _, _ in events:
                    try:
                        chunk = os.read(session.master_fd, 64 * 1024)
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        # Linux PTY masters return EIO after the last slave closes.
                        if exc.errno in {errno.EIO, errno.EBADF}:
                            chunk = b""
                        else:
                            raise
                    if not chunk:
                        return
                    with session.condition:
                        session.output.extend(chunk)
                        overflow = len(session.output) - MAX_TERMINAL_BUFFER_BYTES
                        if overflow > 0:
                            del session.output[:overflow]
                            session.dropped_bytes += overflow
                        session.condition.notify_all()
        except (OSError, ValueError):
            pass
        finally:
            selector.close()
            try:
                exit_code = session.process.poll()
            except Exception:
                exit_code = None
            with session.condition:
                session.eof = True
                session.exit_code = exit_code
                if not self._group_alive(session.process.pid):
                    session.finished_at = time.monotonic()
                session.condition.notify_all()

    def read(
        self,
        session_id: str,
        *,
        wait_seconds: float,
        max_bytes: int,
    ) -> TerminalSessionOutputResponse:
        session = self._get(session_id)
        if session is None:
            return TerminalSessionOutputResponse(
                success=False,
                session_id=session_id if isinstance(session_id, str) else "",
                message="Terminal session is unknown or expired.",
            )
        if isinstance(wait_seconds, bool) or not isinstance(wait_seconds, (int, float)) or not 0 <= wait_seconds <= MAX_TERMINAL_WAIT_SECONDS:
            return TerminalSessionOutputResponse(success=False, session_id=session_id, message=f"wait_seconds must be between 0 and {MAX_TERMINAL_WAIT_SECONDS:g}.")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= MAX_TERMINAL_READ_BYTES:
            return TerminalSessionOutputResponse(success=False, session_id=session_id, message=f"max_bytes must be between 1 and {MAX_TERMINAL_READ_BYTES}.")

        with session.condition:
            if not session.output and not session.eof and wait_seconds:
                session.condition.wait_for(
                    lambda: bool(session.output) or session.eof,
                    timeout=float(wait_seconds),
                )
            size = min(max_bytes, len(session.output))
            output = bytes(session.output[:size])
            if size:
                del session.output[:size]
            running = self._group_alive(session.process.pid)
            exit_code = session.process.poll()
            remaining = max(0.0, session.expires_at - time.monotonic())
            timed_out = session.timed_out
            dropped = session.dropped_bytes
        message = None
        if timed_out:
            message = "Terminal session reached its maximum lifetime and was terminated."
        elif not running and not output:
            message = "Terminal session has exited."
        return TerminalSessionOutputResponse(
            success=True,
            session_id=session_id,
            output_text=output.decode("utf-8", errors="replace"),
            returned_bytes=len(output),
            dropped_bytes=dropped,
            process_running=running,
            exit_code=exit_code,
            timed_out=timed_out,
            expires_in_seconds=remaining if running else None,
            message=message,
        )

    def write(
        self,
        session_id: str,
        *,
        text: str,
        rows: int | None,
        columns: int | None,
    ) -> TerminalSessionWriteResponse:
        session = self._get(session_id)
        if session is None:
            return TerminalSessionWriteResponse(success=False, session_id=session_id if isinstance(session_id, str) else "", message="Terminal session is unknown or expired.")
        if not isinstance(text, str) or "\x00" in text:
            return TerminalSessionWriteResponse(success=False, session_id=session_id, message="Terminal input must be text without NUL bytes.")
        try:
            payload = text.encode("utf-8")
        except UnicodeEncodeError:
            return TerminalSessionWriteResponse(success=False, session_id=session_id, message="Terminal input must contain valid UTF-8 text.")
        if len(payload) > MAX_TERMINAL_INPUT_BYTES:
            return TerminalSessionWriteResponse(success=False, session_id=session_id, message=f"Terminal input is capped at {MAX_TERMINAL_INPUT_BYTES} bytes per call.")
        if (rows is None) != (columns is None):
            return TerminalSessionWriteResponse(success=False, session_id=session_id, message="Both rows and columns are required to resize the terminal.")
        if rows is not None and columns is not None:
            if any(isinstance(value, bool) or not isinstance(value, int) for value in (rows, columns)) or not (1 <= rows <= MAX_TERMINAL_ROWS and 1 <= columns <= MAX_TERMINAL_COLUMNS):
                return TerminalSessionWriteResponse(success=False, session_id=session_id, message=f"Terminal size must be between 1 and {MAX_TERMINAL_ROWS} rows and columns.")
        if not self._group_alive(session.process.pid):
            return TerminalSessionWriteResponse(success=False, session_id=session_id, process_running=False, message="Terminal session has exited; no input was sent.")
        if time.monotonic() >= session.expires_at:
            return TerminalSessionWriteResponse(success=False, session_id=session_id, process_running=True, message="Terminal session has reached its maximum lifetime and is being terminated.")
        if not payload and rows is None:
            return TerminalSessionWriteResponse(success=False, session_id=session_id, message="Provide terminal input or a new terminal size.")

        with session.io_lock:
            if rows is not None and columns is not None:
                try:
                    fcntl.ioctl(session.master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
                    os.killpg(session.process.pid, signal.SIGWINCH)
                    session.rows = rows
                    session.columns = columns
                except OSError as exc:
                    return TerminalSessionWriteResponse(success=False, session_id=session_id, message=f"Could not resize terminal: {exc.strerror or type(exc).__name__}.")
            written = 0
            deadline = time.monotonic() + 1.0
            while written < len(payload):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    _, writable, _ = select.select([], [session.master_fd], [], remaining)
                    if not writable:
                        break
                    count = os.write(session.master_fd, payload[written:])
                    if count <= 0:
                        break
                    written += count
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError as exc:
                    return TerminalSessionWriteResponse(success=False, session_id=session_id, bytes_written=written, message=f"Could not write to terminal: {exc.strerror or type(exc).__name__}.")
        running = self._group_alive(session.process.pid)
        return TerminalSessionWriteResponse(
            success=written == len(payload),
            session_id=session_id,
            bytes_written=written,
            terminal_rows=session.rows,
            terminal_columns=session.columns,
            process_running=running,
            message=None if written == len(payload) else "Only part of the terminal input was accepted; send the remaining bytes in a new confirmed call.",
        )

    def close(self, session_id: str) -> TerminalSessionCloseResponse:
        session = self._get(session_id)
        if session is None:
            return TerminalSessionCloseResponse(success=False, session_id=session_id if isinstance(session_id, str) else "", message="Terminal session is unknown or expired.")
        was_running = self._group_alive(session.process.pid)
        if was_running:
            session.closed_by_client = True
            try:
                os.killpg(session.process.pid, signal.SIGHUP)
            except OSError:
                pass
            _terminate(session.process)
        with session.condition:
            session.condition.notify_all()
        return TerminalSessionCloseResponse(
            success=True,
            session_id=session_id,
            was_running=was_running,
            exit_code=session.process.poll(),
            message="Terminal process group terminated." if was_running else "Terminal session had already exited.",
        )

    def _reap_loop(self) -> None:
        while not self._stop.wait(0.5):
            now = time.monotonic()
            with self._lock:
                sessions = list(self._sessions.items())
            remove: list[str] = []
            for session_id, session in sessions:
                alive = self._group_alive(session.process.pid)
                if alive and now >= session.expires_at and not session.timed_out:
                    session.timed_out = True
                    _terminate(session.process)
                    with session.condition:
                        session.condition.notify_all()
                    alive = self._group_alive(session.process.pid)
                if not alive:
                    with session.condition:
                        if session.finished_at is None:
                            session.finished_at = now
                        if session.eof and now - session.finished_at >= COMPLETED_SESSION_RETENTION_SECONDS:
                            remove.append(session_id)
            if remove:
                with self._lock:
                    for session_id in remove:
                        session = self._sessions.pop(session_id, None)
                        if session is not None:
                            try:
                                os.close(session.master_fd)
                            except OSError:
                                pass

    def close_all(self) -> None:
        with self._lock:
            self._closing = True
            self._stop.set()
            reaper = self._reaper
            sessions = list(self._sessions.values())
        if reaper is not None and reaper is not threading.current_thread():
            reaper.join(timeout=5.0)
        for session in sessions:
            if self._group_alive(session.process.pid):
                try:
                    os.killpg(session.process.pid, signal.SIGHUP)
                except OSError:
                    pass
                _terminate(session.process)
        for session in sessions:
            if session.reader_thread is not None:
                session.reader_thread.join(timeout=1.0)
            try:
                os.close(session.master_fd)
            except OSError:
                pass
        with self._lock:
            self._sessions.clear()
            if self._reaper is reaper:
                self._reaper = None
            self._closing = False


terminal_sessions = TerminalSessionManager()
