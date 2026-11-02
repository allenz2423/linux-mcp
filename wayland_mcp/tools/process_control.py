"""Explicitly confirmed signals for one observed Linux process instance."""

from __future__ import annotations

import errno
import hmac
import os
import re
import signal
import sys

from wayland_mcp.models import ProcessDetailResponse, ProcessInfo, ProcessSignalResponse
from wayland_mcp.tools.host import get_process_detail

_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNAL_NAME_RE = re.compile(r"^SIG[A-Z0-9]+$")
_PIDFD_UNSUPPORTED_ERRNOS = {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}


def resolve_signal_name(signal_name: str) -> tuple[str, int] | None:
    """Resolve a symbolic Linux signal name, including real-time offsets."""
    if not isinstance(signal_name, str) or not signal_name or len(signal_name) > 32:
        return None
    normalized = signal_name.upper()
    if not normalized.startswith("SIG"):
        normalized = f"SIG{normalized}"

    number: int | None = None
    canonical = normalized
    if normalized.startswith("SIGRTMIN+"):
        offset_text = normalized.removeprefix("SIGRTMIN+")
        if not offset_text.isdecimal():
            return None
        offset = int(offset_text)
        number = int(signal.SIGRTMIN) + offset
        if number > int(signal.SIGRTMAX):
            return None
        canonical = "SIGRTMIN" if offset == 0 else f"SIGRTMIN+{offset}"
    elif normalized.startswith("SIGRTMAX-"):
        offset_text = normalized.removeprefix("SIGRTMAX-")
        if not offset_text.isdecimal():
            return None
        offset = int(offset_text)
        number = int(signal.SIGRTMAX) - offset
        if number < int(signal.SIGRTMIN):
            return None
        canonical = "SIGRTMAX" if offset == 0 else f"SIGRTMAX-{offset}"
    else:
        if not _SIGNAL_NAME_RE.fullmatch(normalized):
            return None
        member = signal.Signals.__members__.get(normalized)
        if member is None:
            return None
        number = int(member)
        canonical = member.name

    if number == 0 or number not in signal.valid_signals():
        return None
    return canonical, number


def _validated_target(
    pid: int,
    identity_token: str,
    signal_name: str,
) -> tuple[ProcessInfo, str, int] | str:
    if not sys.platform.startswith("linux"):
        return "Process signals are available only on Linux."
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or pid > 2**31 - 1:
        return "PID must be a positive Linux process ID."
    if not isinstance(identity_token, str) or not _TOKEN_RE.fullmatch(identity_token):
        return "Identity token must come from a successful get_process_detail response."
    resolved = resolve_signal_name(signal_name)
    if resolved is None:
        return "Signal must be one valid symbolic Linux signal name, such as SIGTERM or SIGINT."

    detail: ProcessDetailResponse = get_process_detail(pid)
    if not detail.success or detail.process is None or detail.identity_token is None:
        return detail.message or "The process could not be inspected."
    if not hmac.compare_digest(identity_token, detail.identity_token):
        return "The PID no longer identifies the observed process instance; inspect it again before signaling."
    return detail.process, resolved[0], resolved[1]


def validate_process_signal(pid: int, identity_token: str, signal_name: str) -> str | None:
    """Validate the exact observed process and signal before eliciting confirmation."""
    target = _validated_target(pid, identity_token, signal_name)
    return target if isinstance(target, str) else None


def process_signal_confirmation_details(
    pid: int,
    identity_token: str,
    signal_name: str,
) -> tuple[ProcessInfo, str, int] | str:
    """Return the current matching target details used in the confirmation prompt."""
    return _validated_target(pid, identity_token, signal_name)


def signal_effect(name: str) -> str:
    if name == "SIGKILL":
        return " SIGKILL ends the process immediately; it cannot handle or clean up after it."
    if name == "SIGSTOP":
        return " SIGSTOP pauses the process and cannot be caught or ignored."
    if name == "SIGCONT":
        return " SIGCONT resumes a stopped process."
    if name in {"SIGTERM", "SIGINT", "SIGHUP"}:
        return " The process may handle this signal or exit; its exact response depends on the application."
    return " The process may handle, ignore, or act on this signal according to its implementation."


def _response_signal_name(signal_name: object) -> str:
    resolved = resolve_signal_name(signal_name) if isinstance(signal_name, str) else None
    if resolved:
        return resolved[0]
    return signal_name[:32] if isinstance(signal_name, str) else ""


def _failed_response(
    pid: int,
    signal_name: str,
    message: str,
    *,
    confirmed: bool = False,
    process: ProcessInfo | None = None,
    signal_number: int | None = None,
) -> ProcessSignalResponse:
    safe_pid = pid if isinstance(pid, int) and not isinstance(pid, bool) and pid >= 0 else 0
    return ProcessSignalResponse(
        success=False,
        pid=safe_pid,
        process_name=process.name if process else None,
        uid=process.uid if process else None,
        signal_name=_response_signal_name(signal_name),
        signal_number=signal_number,
        user_confirmed=confirmed,
        message=message,
    )


def _is_pidfd_unsupported(exc: OSError) -> bool:
    return exc.errno in _PIDFD_UNSUPPORTED_ERRNOS


def perform_process_signal(
    pid: int,
    identity_token: str,
    signal_name: str,
    *,
    confirmed: bool,
) -> ProcessSignalResponse:
    """Send one named signal after confirmation and a fresh process identity check."""
    if not confirmed:
        return _failed_response(
            pid,
            signal_name,
            "Explicit client confirmation is required; no signal was sent.",
        )

    target = _validated_target(pid, identity_token, signal_name)
    if isinstance(target, str):
        return _failed_response(pid, signal_name, target, confirmed=True)
    process, canonical_name, number = target

    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    pidfd: int | None = None
    if callable(pidfd_open) and callable(pidfd_send_signal):
        try:
            pidfd = pidfd_open(pid, 0)
        except OSError as exc:
            if not _is_pidfd_unsupported(exc):
                return _failed_response(
                    pid,
                    canonical_name,
                    f"Could not open a stable process handle: {exc.strerror or 'OS error'}.",
                    confirmed=True,
                    process=process,
                    signal_number=number,
                )

    if pidfd is not None:
        try:
            latest = _validated_target(pid, identity_token, canonical_name)
            if isinstance(latest, str):
                return _failed_response(
                    pid, canonical_name, latest, confirmed=True,
                    process=process, signal_number=number,
                )
            try:
                pidfd_send_signal(pidfd, number, None, 0)
            except OSError as exc:
                if not _is_pidfd_unsupported(exc):
                    return _failed_response(
                        pid,
                        canonical_name,
                        f"Signal was not sent: {exc.strerror or 'OS error'}.",
                        confirmed=True,
                        process=process,
                        signal_number=number,
                    )
                # Older kernels can expose pidfd_open without pidfd_send_signal.
                # Fall through to the checked os.kill compatibility path.
            else:
                return ProcessSignalResponse(
                    success=True,
                    pid=pid,
                    process_name=process.name,
                    uid=process.uid,
                    signal_name=canonical_name,
                    signal_number=number,
                    user_confirmed=True,
                    message=f"Sent {canonical_name} to PID {pid} ({process.name}).",
                )
        finally:
            os.close(pidfd)

    latest = _validated_target(pid, identity_token, canonical_name)
    if isinstance(latest, str):
        return _failed_response(
            pid, canonical_name, latest, confirmed=True,
            process=process, signal_number=number,
        )
    try:
        os.kill(pid, number)
    except OSError as exc:
        return _failed_response(
            pid,
            canonical_name,
            f"Signal was not sent: {exc.strerror or 'OS error'}.",
            confirmed=True,
            process=process,
            signal_number=number,
        )
    return ProcessSignalResponse(
        success=True,
        pid=pid,
        process_name=process.name,
        uid=process.uid,
        signal_name=canonical_name,
        signal_number=number,
        user_confirmed=True,
        message=(
            f"Sent {canonical_name} to PID {pid} ({process.name}); this host used the "
            "checked PID fallback because pidfd signaling is unavailable."
        ),
    )
