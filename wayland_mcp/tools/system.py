"""Explicit, bounded clipboard and notification operations."""

from __future__ import annotations

import subprocess
import os
import selectors
import time

from wayland_mcp.models import ClipboardContent, ClipboardWriteResult, NotificationResult
from wayland_mcp.safety.tokens import snapshot_token_manager
from wayland_mcp.session import find_session_binary, get_sanitized_env

MAX_CLIPBOARD_READ_BYTES = 256 * 1024
MAX_CLIPBOARD_WRITE_BYTES = 64 * 1024


def _authorize(token_id: str, operation: str, target_type: str) -> tuple[bool, str | None]:
    ok, error, _ = snapshot_token_manager.validate_and_consume(
        token_id, operation=operation, target=target_type, target_type=target_type,
    )
    return ok, error


def read_clipboard(token_id: str, max_bytes: int = 32_768) -> ClipboardContent:
    ok, error = _authorize(token_id, "clipboard_read", "clipboard")
    if not ok:
        return ClipboardContent(success=False, text="", message=f"Clipboard read rejected: {error}")
    env = get_sanitized_env()
    wl_paste = find_session_binary("wl-paste", env)
    if not wl_paste:
        return ClipboardContent(success=False, message="wl-paste is unavailable; install wl-clipboard.")
    max_bytes = max(1, min(int(max_bytes), MAX_CLIPBOARD_READ_BYTES))
    process = None
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + 2.0
    chunks: list[bytes] = []
    total = 0
    truncated = False
    try:
        process = subprocess.Popen(
            [wl_paste, "--no-newline", "--type", "text/plain"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        if process.stdout is None:
            return ClipboardContent(success=False, message="Clipboard output stream could not be opened.")
        fd = process.stdout.fileno()
        os.set_blocking(fd, False)
        selector.register(fd, selectors.EVENT_READ)
        reached_eof = False
        while total <= max_bytes and not reached_eof:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0 or not selector.select(remaining_time):
                return ClipboardContent(success=False, message="Clipboard read timed out after 2 seconds.")
            try:
                chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            except BlockingIOError:
                continue
            if not chunk:
                reached_eof = True
                continue
            chunks.append(chunk)
            total += len(chunk)
            truncated = total > max_bytes
        if truncated:
            process.terminate()
        else:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        return ClipboardContent(success=False, message="Clipboard read timed out after 2 seconds.")
    except OSError as exc:
        return ClipboardContent(success=False, message=f"Clipboard read failed: {exc.strerror or type(exc).__name__}.")
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
            if process.stdout is not None:
                process.stdout.close()
    if process is None or (process.returncode != 0 and not truncated):
        return ClipboardContent(success=False, message="Clipboard has no readable plain text.")
    text = b"".join(chunks)[:max_bytes].decode("utf-8", errors="replace")
    return ClipboardContent(
        success=True,
        text=text,
        message="Clipboard text truncated at the requested byte limit." if truncated else None,
    )


def write_clipboard(text: str, token_id: str) -> ClipboardWriteResult:
    ok, error = _authorize(token_id, "clipboard_write", "clipboard")
    if not ok:
        return ClipboardWriteResult(success=False, message=f"Clipboard write rejected: {error}")
    if not isinstance(text, str):
        return ClipboardWriteResult(success=False, message="Clipboard content must be text.")
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_CLIPBOARD_WRITE_BYTES:
        return ClipboardWriteResult(success=False, message=f"Clipboard text exceeds {MAX_CLIPBOARD_WRITE_BYTES} UTF-8 bytes.")
    env = get_sanitized_env()
    wl_copy = find_session_binary("wl-copy", env)
    if not wl_copy:
        return ClipboardWriteResult(success=False, message="wl-copy is unavailable; install wl-clipboard.")
    try:
        result = subprocess.run(
            [wl_copy, "--type", "text/plain;charset=utf-8"],
            input=encoded,
            capture_output=True,
            timeout=2.0,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return ClipboardWriteResult(success=False, message="Clipboard write timed out after 2 seconds.")
    except OSError as exc:
        return ClipboardWriteResult(success=False, message=f"Clipboard write failed: {exc.strerror or type(exc).__name__}.")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")[:300].strip()
        return ClipboardWriteResult(success=False, message=f"wl-copy failed. {detail}".strip())
    return ClipboardWriteResult(success=True, bytes_written=len(encoded), message="Clipboard text replaced.")


def send_notification(title: str, body: str, token_id: str) -> NotificationResult:
    ok, error = _authorize(token_id, "send_notification", "notification")
    if not ok:
        return NotificationResult(success=False, message=f"Notification rejected: {error}")
    if not isinstance(title, str) or not isinstance(body, str) or not title.strip() or len(title) > 200 or len(body) > 2000:
        return NotificationResult(success=False, message="Title must be 1–200 characters and body at most 2000 characters.")
    env = get_sanitized_env()
    notify_send = find_session_binary("notify-send", env)
    if not notify_send:
        return NotificationResult(success=False, message="notify-send is unavailable; no notification was sent.")
    try:
        result = subprocess.run(
            [notify_send, "--app-name=linux-mcp", "--", title, body],
            capture_output=True,
            text=True,
            timeout=3.0,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return NotificationResult(success=False, message="Notification request timed out after 3 seconds.")
    except OSError as exc:
        return NotificationResult(success=False, message=f"Notification request failed: {exc.strerror or type(exc).__name__}.")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout)[:300].strip()
        return NotificationResult(success=False, message=f"notify-send failed. {detail}".strip())
    return NotificationResult(success=True, message="Notification sent.")
