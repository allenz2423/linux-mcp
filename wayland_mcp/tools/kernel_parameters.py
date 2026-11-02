"""Bounded runtime sysctl inventory and state-bound parameter changes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import (
    KernelParameterChangeResponse,
    KernelParameterInfo,
    KernelParameterListResponse,
)

MAX_PARAMETER_BYTES = 64
MAX_TOKENS = 1024
TOKEN_TTL_SECONDS = 180
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,100}$")
MAX_RETURNED_PARAMETERS = 32
OPEN_FLAGS = os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True, slots=True)
class _ParameterSpec:
    name: str
    path: Path
    minimum: int
    maximum: int
    description: str


@dataclass(frozen=True, slots=True)
class _ParameterSnapshot:
    name: str
    value: int
    identity: tuple[int, int, int, int, int]


@dataclass(slots=True)
class _ParameterToken:
    snapshot: _ParameterSnapshot
    expires_at: float
    claimed: bool = False
    executing: bool = False
    new_value: int | None = None
    state_token: str | None = None


@dataclass(frozen=True, slots=True)
class KernelParameterTarget:
    name: str
    current_value: int
    new_value: int
    minimum_value: int
    maximum_value: int
    description: str
    state_token: str


PARAMETERS = (
    _ParameterSpec(
        "vm.swappiness",
        Path("/proc/sys/vm/swappiness"),
        0,
        200,
        "Controls the relative preference for swapping versus filesystem paging.",
    ),
    _ParameterSpec(
        "vm.vfs_cache_pressure",
        Path("/proc/sys/vm/vfs_cache_pressure"),
        0,
        1000,
        "Controls reclaim pressure applied to inode and dentry caches.",
    ),
    _ParameterSpec(
        "fs.inotify.max_user_instances",
        Path("/proc/sys/fs/inotify/max_user_instances"),
        1,
        4096,
        "Sets the per-user ceiling for inotify instances.",
    ),
    _ParameterSpec(
        "fs.inotify.max_user_watches",
        Path("/proc/sys/fs/inotify/max_user_watches"),
        1,
        262144,
        "Sets the per-user ceiling for inotify watches; raising it can increase kernel memory use.",
    ),
)
_PARAMETERS_BY_NAME = {item.name: item for item in PARAMETERS}
_TOKENS: dict[str, _ParameterToken] = {}
_TOKEN_LOCK = threading.Lock()
_CHANGE_LOCK = threading.Lock()


def kernel_parameter_control_available() -> bool:
    return sys.platform.startswith("linux") and any(
        _read_parameter(item.name)[0] is not None for item in PARAMETERS
    )


def _read_parameter(name: str) -> tuple[_ParameterSnapshot | None, str | None]:
    spec = _PARAMETERS_BY_NAME.get(name)
    if spec is None:
        return None, "Choose one supported kernel parameter from list_kernel_parameters."
    if not sys.platform.startswith("linux"):
        return None, "Runtime kernel parameter controls are available only on Linux."
    if not hasattr(os, "O_NOFOLLOW"):
        return None, "The no-follow file-descriptor interface is unavailable."
    descriptor: int | None = None
    try:
        descriptor = os.open(spec.path, os.O_RDONLY | OPEN_FLAGS)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None, "The kernel parameter does not expose a regular procfs control file."
        raw = os.read(descriptor, MAX_PARAMETER_BYTES + 1)
        if len(raw) > MAX_PARAMETER_BYTES:
            return None, "The kernel parameter value exceeded its read limit."
        value_text = raw.decode("ascii", errors="strict").strip()
        if not re.fullmatch(r"[0-9]{1,10}", value_text):
            return None, "The kernel parameter did not return one non-negative decimal integer."
        value = int(value_text, 10)
        if value > 2_147_483_647:
            return None, "The current kernel parameter value exceeds the supported integer range."
        identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        return _ParameterSnapshot(name=name, value=value, identity=identity), None
    except (OSError, UnicodeError, ValueError) as exc:
        reason = getattr(exc, "strerror", None) or type(exc).__name__
        return None, f"The exact kernel parameter could not be read: {reason}."
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _prune_tokens_locked(now: float) -> None:
    expired = [key for key, value in _TOKENS.items() if value.expires_at <= now]
    for key in expired:
        _TOKENS.pop(key, None)
    if len(_TOKENS) >= MAX_TOKENS:
        oldest = sorted(_TOKENS, key=lambda key: _TOKENS[key].expires_at)
        for key in oldest[: len(_TOKENS) - MAX_TOKENS + 1]:
            _TOKENS.pop(key, None)


def _issue_token(snapshot: _ParameterSnapshot) -> str:
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _TOKEN_LOCK:
        _prune_tokens_locked(now)
        _TOKENS[token] = _ParameterToken(snapshot=snapshot, expires_at=now + TOKEN_TTL_SECONDS)
    return token


def list_kernel_parameters(limit: int = 32) -> KernelParameterListResponse:
    """List a fixed allowlist of runtime-tunable integer sysctls."""
    if not sys.platform.startswith("linux"):
        return KernelParameterListResponse(success=False, message="Kernel parameter inventory is available only on Linux.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return KernelParameterListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_PARAMETERS))
    available: list[tuple[_ParameterSpec, _ParameterSnapshot]] = []
    unavailable: list[str] = []
    for spec in PARAMETERS:
        snapshot, error = _read_parameter(spec.name)
        if snapshot is None:
            unavailable.append(spec.name)
            continue
        available.append((spec, snapshot))
    shown = available[:limit]
    parameters = [
        KernelParameterInfo(
            name=spec.name,
            current_value=snapshot.value,
            minimum_value=spec.minimum,
            maximum_value=spec.maximum,
            description=spec.description,
            identity_token=_issue_token(snapshot),
        )
        for spec, snapshot in shown
    ]
    messages: list[str] = []
    if unavailable:
        messages.append("Some allowlisted sysctl files were unavailable or unreadable.")
    if len(available) > limit:
        messages.append("The kernel parameter result was capped by the requested limit.")
    return KernelParameterListResponse(
        success=True,
        total_parameters=len(available),
        returned_parameters=len(parameters),
        parameters=parameters,
        partial=bool(messages),
        message=" ".join(messages) or None,
    )


def _token_record(identity_token: str) -> tuple[_ParameterToken | None, str | None]:
    if not isinstance(identity_token, str) or not TOKEN_RE.fullmatch(identity_token):
        return None, "A fresh parameter identity token from list_kernel_parameters is required."
    with _TOKEN_LOCK:
        _prune_tokens_locked(time.monotonic())
        record = _TOKENS.get(identity_token)
    if record is None:
        return None, "The kernel parameter token is unknown or expired; list parameters again."
    return record, None


def kernel_parameter_confirmation_details(
    identity_token: str,
    new_value: int,
) -> tuple[KernelParameterTarget | None, str | None]:
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, error
    spec = _PARAMETERS_BY_NAME[record.snapshot.name]
    if not isinstance(new_value, int) or isinstance(new_value, bool):
        return None, "The requested sysctl value must be an integer."
    if not spec.minimum <= new_value <= spec.maximum:
        return None, f"{spec.name} accepts values from {spec.minimum} through {spec.maximum}."
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.claimed or record.expires_at <= time.monotonic():
            return None, "The kernel parameter token is expired or already in use; list parameters again."
        record.claimed = True
    current, error = _read_parameter(record.snapshot.name)
    if error or current is None or current != record.snapshot:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, error or "The parameter value or procfs identity changed after inventory; list parameters again."
    digest_payload = {
        "name": current.name,
        "old": current.value,
        "new": new_value,
        "identity": current.identity,
    }
    state_token = hashlib.sha256(
        json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    record.new_value = new_value
    record.state_token = state_token
    description = spec.description
    if spec.name == "vm.vfs_cache_pressure" and new_value == 0:
        description += (
            " The kernel will not reclaim dentry and inode caches under memory pressure; "
            "this can cause out-of-memory conditions."
        )
    elif spec.name == "vm.vfs_cache_pressure" and new_value > 100:
        description += " Values above 100 increase reclaim pressure and can reduce performance."
    elif spec.name == "vm.swappiness" and new_value == 0:
        description += " At 0, the kernel delays initiating swap until free and file-backed memory is low."
    elif spec.name == "vm.swappiness" and new_value > 100:
        description += " Values above 100 treat swap I/O as relatively cheap; the result depends on the workload and swap device."
    return KernelParameterTarget(
        name=current.name,
        current_value=current.value,
        new_value=new_value,
        minimum_value=spec.minimum,
        maximum_value=spec.maximum,
        description=description,
        state_token=state_token,
    ), None


def _write_parameter(snapshot: _ParameterSnapshot, new_value: int) -> tuple[bool, str | None]:
    spec = _PARAMETERS_BY_NAME[snapshot.name]
    descriptor: int | None = None
    try:
        descriptor = os.open(spec.path, os.O_WRONLY | OPEN_FLAGS)
        info = os.fstat(descriptor)
        identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        if identity != snapshot.identity:
            return False, "The procfs parameter file identity changed before the write."
        payload = f"{new_value}\n".encode("ascii")
        written = os.write(descriptor, payload)
        if written != len(payload):
            return False, "The kernel parameter write was incomplete."
        return True, None
    except OSError as exc:
        return False, f"The runtime parameter write failed: {exc.strerror or type(exc).__name__}."
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def perform_kernel_parameter_change(
    identity_token: str,
    state_token: str,
    confirmed_name: str,
    confirmed_current_value: int,
    confirmed_new_value: int,
    *,
    confirmed: bool,
) -> KernelParameterChangeResponse:
    record, error = _token_record(identity_token)
    if error or record is None:
        return KernelParameterChangeResponse(success=False, message=error or "A fresh kernel parameter token is required.")
    response_name = record.snapshot.name
    response_old = record.snapshot.value
    if confirmed is not True:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return KernelParameterChangeResponse(
            success=False,
            name=response_name,
            previous_value=response_old,
            current_value=response_old,
            user_confirmed=False,
            message="Explicit client confirmation is required; no sysctl value was changed.",
        )
    with _TOKEN_LOCK:
        expired = record.expires_at <= time.monotonic()
        if _TOKENS.get(identity_token) is not record or expired or record.executing:
            if expired:
                _TOKENS.pop(identity_token, None)
            return KernelParameterChangeResponse(
                success=False,
                name=response_name,
                previous_value=response_old,
                user_confirmed=True,
                message=(
                    "The kernel parameter token has expired; list parameters again."
                    if expired
                    else "The kernel parameter token is unknown or already being used."
                ),
            )
        record.executing = True
    try:
        if (
            not record.claimed
            or record.new_value is None
            or record.state_token is None
            or state_token != record.state_token
            or confirmed_name != record.snapshot.name
            or confirmed_current_value != record.snapshot.value
            or confirmed_new_value != record.new_value
        ):
            return KernelParameterChangeResponse(
                success=False,
                name=response_name,
                previous_value=response_old,
                user_confirmed=True,
                message="Confirmation did not match the exact parameter, observed value, and requested value.",
            )
        with _CHANGE_LOCK:
            current, error = _read_parameter(record.snapshot.name)
            if error or current is None or current != record.snapshot:
                return KernelParameterChangeResponse(
                    success=False,
                    name=response_name,
                    previous_value=response_old,
                    current_value=current.value if current else None,
                    user_confirmed=True,
                    message=error or "The parameter state changed after confirmation; no write was attempted.",
                )
            if record.new_value == current.value:
                return KernelParameterChangeResponse(
                    success=True,
                    name=current.name,
                    previous_value=current.value,
                    current_value=current.value,
                    user_confirmed=True,
                    message="The kernel parameter already has the requested runtime value.",
                )
            written, write_error = _write_parameter(current, record.new_value)
            after, after_error = _read_parameter(current.name)
            if after is not None and after.identity == current.identity and after.value == record.new_value:
                return KernelParameterChangeResponse(
                    success=True,
                    name=after.name,
                    previous_value=current.value,
                    current_value=after.value,
                    user_confirmed=True,
                    message="Changed and verified the runtime kernel parameter. The value is not made persistent across reboot.",
                )
            reason = after_error or write_error or (
                "The parameter changed to a value other than the confirmed target; concurrent state was left untouched."
                if after is not None and after.value != current.value
                else "The resulting value did not match the requested value."
            )
            return KernelParameterChangeResponse(
                success=False,
                name=response_name,
                previous_value=response_old,
                current_value=after.value if after else None,
                user_confirmed=True,
                message=f"The runtime parameter change could not be verified: {reason}. Inspect the parameter before retrying.",
            )
    finally:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
