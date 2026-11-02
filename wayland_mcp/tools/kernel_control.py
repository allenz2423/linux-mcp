"""Confirmed transient load/unload operations for one Linux kernel module."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import KernelModuleActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env

KernelModuleAction = Literal["load", "unload"]
MODULE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
MODULE_ROOTS = (Path("/lib/modules"), Path("/usr/lib/modules"))
COMMAND_TIMEOUT_SECONDS = 30
MAX_OUTPUT_BYTES = 16 * 1024


@dataclass(frozen=True, slots=True)
class KernelModuleTarget:
    action: KernelModuleAction
    module: str
    normalized_name: str
    kernel_release: str
    loaded: bool
    refcount: int | None
    holders: tuple[str, ...]
    module_file: str
    module_file_identity: tuple[int, int, int, int, int]
    state_digest: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return env


def kernel_module_control_available(env: dict[str, str] | None = None) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    selected = env or _environment()
    return all(find_session_binary(binary, selected) for binary in ("modinfo", "modprobe", "rmmod")) and Path("/sys/module").is_dir()


def _command(command: list[str]) -> tuple[int, str] | None:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=_environment(),
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if len(completed.stdout) > MAX_OUTPUT_BYTES:
        return None
    try:
        return completed.returncode, completed.stdout.decode("utf-8", errors="strict")
    except UnicodeError:
        return None


def _module_details(module: str) -> tuple[str | None, tuple[int, int, int, int, int] | None, str | None]:
    modinfo = find_session_binary("modinfo", _environment())
    if not modinfo:
        return None, None, "The modinfo command is unavailable."
    output = _command([modinfo, "-F", "filename", module])
    if output is None or output[0] != 0:
        return None, None, "The exact module file could not be resolved."
    filename = output[1].strip()
    if not filename or filename == "(builtin)":
        return None, None, "Built-in kernel components cannot be loaded or unloaded by this operation."
    try:
        path = Path(filename).resolve(strict=True)
        path.relative_to(Path("/lib/modules") / os.uname().release)
        info = path.stat()
    except (OSError, ValueError, RuntimeError):
        try:
            path = Path(filename).resolve(strict=True)
            path.relative_to(Path("/usr/lib/modules") / os.uname().release)
            info = path.stat()
        except (OSError, ValueError, RuntimeError):
            return None, None, "The module file is not under the running kernel's installed module directories."
    if not path.is_file() or info.st_size <= 0 or info.st_size > (1 << 30):
        return None, None, "The exact installed module file could not be verified."
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    return str(path), identity, None


def _loaded_state(normalized_name: str) -> tuple[bool, int | None, tuple[str, ...] | None, str | None]:
    root = Path("/sys/module") / normalized_name
    if not root.exists():
        return False, 0, (), None
    try:
        initstate = (root / "initstate").read_text(encoding="ascii").strip()
        ref_text = (root / "refcnt").read_text(encoding="ascii").strip()
        refcount = int(ref_text, 10)
        holders = tuple(sorted(path.name for path in (root / "holders").iterdir()))
    except (OSError, UnicodeError, ValueError):
        return True, None, None, "The loaded module state could not be read safely."
    if initstate != "live" or refcount < 0:
        return True, None, None, "The module is not in a stable live state."
    return True, refcount, holders, None


def kernel_module_action_confirmation_details(
    action: str,
    module: str,
) -> tuple[KernelModuleTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Kernel module actions are available only on Linux."
    if not isinstance(action, str) or action not in {"load", "unload"}:
        return None, None, "action must be load or unload."
    if not isinstance(module, str) or not MODULE_NAME_RE.fullmatch(module):
        return None, None, "module must be one exact installed module name containing only letters, digits, underscores, or hyphens."
    if not kernel_module_control_available():
        return None, None, "The modinfo, modprobe, rmmod commands and Linux sysfs module state are required."
    normalized = module.replace("-", "_")
    kernel_release = os.uname().release
    module_file, file_identity, error = _module_details(module)
    if error or module_file is None or file_identity is None:
        return None, None, error or "The installed module identity could not be verified."
    loaded, refcount, holders, error = _loaded_state(normalized)
    if error or refcount is None or holders is None:
        return None, None, error or "The module state could not be verified."
    if action == "load" and loaded:
        return None, None, "The requested module is already loaded."
    if action == "unload" and not loaded:
        return None, None, "The requested module is not loaded."
    if action == "unload" and (refcount != 0 or holders):
        return None, None, "A module with active references or dependent holder modules cannot be unloaded by this tool."

    details = {
        "action": action,
        "module": module,
        "normalized_name": normalized,
        "kernel_release": kernel_release,
        "loaded": loaded,
        "refcount": refcount,
        "holders": holders,
        "module_file": module_file,
        "module_file_identity": file_identity,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = KernelModuleTarget(
        action=action,  # type: ignore[arg-type]
        module=module,
        normalized_name=normalized,
        kernel_release=kernel_release,
        loaded=loaded,
        refcount=refcount,
        holders=holders,
        module_file=module_file,
        module_file_identity=file_identity,
        state_digest=digest,
    )
    phrase = hashlib.sha256((action + ":" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"module {phrase}", None


def perform_kernel_module_action(
    action: KernelModuleAction,
    module: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> KernelModuleActionResponse:
    target, phrase, error = kernel_module_action_confirmation_details(action, module)
    if error or target is None or phrase is None:
        return KernelModuleActionResponse(success=False, action=action, module=module, user_confirmed=confirmed is True, message=error or "The module action could not be verified.")
    if confirmed is not True:
        return KernelModuleActionResponse(success=False, action=action, module=module, user_confirmed=False, message="Explicit client confirmation is required; no module command was run.")
    if confirmation_phrase != phrase:
        return KernelModuleActionResponse(success=False, action=action, module=module, user_confirmed=True, message="Confirmation did not match the exact installed module and current kernel state.")
    current, current_phrase, error = kernel_module_action_confirmation_details(action, module)
    if error or current is None or current_phrase != phrase:
        return KernelModuleActionResponse(success=False, action=action, module=module, user_confirmed=True, message=error or "Kernel module state changed after confirmation; no command was run.")

    if action == "load":
        binary = find_session_binary("modprobe", _environment())
        command = [binary, "--ignore-install", module] if binary else []
    else:
        binary = find_session_binary("rmmod", _environment())
        command = [binary, module] if binary else []
    if not command:
        return KernelModuleActionResponse(success=False, action=action, module=module, user_confirmed=True, message=f"The {action} command is unavailable.")
    result = _command(command)
    if result is None or result[0] != 0:
        return KernelModuleActionResponse(success=False, action=action, module=module, user_confirmed=True, message="The kernel module command did not complete successfully; inspect kernel and device state before retrying.")
    loaded, refcount, holders, state_error = _loaded_state(target.normalized_name)
    verified = state_error is None and refcount is not None and holders is not None and (loaded if action == "load" else not loaded)
    if not verified:
        return KernelModuleActionResponse(success=False, action=action, module=module, user_confirmed=True, message="The command returned successfully, but the resulting loaded state could not be verified.")
    message = "Loaded the kernel module; modprobe may also have loaded required dependencies." if action == "load" else "Unloaded the exact kernel module."
    return KernelModuleActionResponse(success=True, action=action, module=module, user_confirmed=True, message=message)
