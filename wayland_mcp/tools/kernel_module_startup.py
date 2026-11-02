"""Confirmed persistent module-load configuration through modules-load.d."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import KernelModuleStartupResponse
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.filesystem_write import (
    TextFileCreationTarget,
    TextFileDeletionTarget,
    create_text_file,
    delete_text_file,
    text_file_creation_confirmation_details,
    text_file_deletion_confirmation_details,
    text_file_replacement_confirmation_details,
)
from wayland_mcp.tools.host import _detect_init_system
from wayland_mcp.tools.kernel_control import MODULE_NAME_RE, _module_details, _environment

KernelModuleStartupAction = Literal["enable", "disable"]
MODULES_LOAD_DIRECTORY = Path("/etc/modules-load.d")
MODULES_LOAD_DIRECTORIES = (
    Path("/etc/modules-load.d"),
    Path("/run/modules-load.d"),
    Path("/usr/local/lib/modules-load.d"),
    Path("/usr/lib/modules-load.d"),
)
MODULES_LOAD_HEADER = "# Managed by linux-mcp: persistent kernel module v1"
MAX_CONFIG_FILES = 4096
MAX_CONFIG_FILE_BYTES = 64 * 1024
MAX_CONFIG_SCAN_BYTES = 4 * 1024 * 1024
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class KernelModuleStartupTarget:
    action: KernelModuleStartupAction
    module: str
    kernel_release: str
    module_file: str
    module_file_identity: tuple[int, int, int, int, int]
    path: Path
    content: str
    current_sha256: str | None
    state_token: str
    confirmation_phrase: str
    create_target: TextFileCreationTarget | None = None
    delete_target: TextFileDeletionTarget | None = None


def _module_config_directory(env: dict[str, str] | None = None) -> tuple[Path | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Persistent kernel-module configuration is available only on Linux."
    if _detect_init_system() != "systemd":
        return None, "Persistent kernel-module configuration requires systemd modules-load.d support."
    try:
        resolved = MODULES_LOAD_DIRECTORY.resolve(strict=True)
        info = resolved.stat()
    except (OSError, RuntimeError, ValueError):
        return None, "The system modules-load.d configuration directory is unavailable."
    if resolved != MODULES_LOAD_DIRECTORY or not stat.S_ISDIR(info.st_mode):
        return None, "The system modules-load.d path must be a real directory, not a symlink."
    if info.st_uid != 0 or info.st_mode & 0o022:
        return None, "The system modules-load.d directory must be root-owned and not group/other writable."
    if not find_session_binary("modinfo", env or _environment()):
        return None, "The modinfo command is required to verify an installed module for the running kernel."
    return resolved, None


def kernel_module_startup_control_available(env: dict[str, str] | None = None) -> bool:
    _directory, error = _module_config_directory(env)
    return error is None


def _render_config(module: str) -> str:
    return f"{MODULES_LOAD_HEADER}\n{module}\n"


def _other_configuration(
    module: str,
    managed_path: Path,
) -> tuple[tuple[str, ...] | None, tuple[str, ...] | None, str | None]:
    """Find exact duplicate module entries and same-name overrides in bounded config files."""
    module_key = module.replace("-", "_")
    module_paths: list[str] = []
    collision_paths: list[str] = []
    file_count = 0
    byte_count = 0
    for directory in MODULES_LOAD_DIRECTORIES:
        if not directory.exists() and not directory.is_symlink():
            continue
        try:
            resolved_directory = directory.resolve(strict=True)
            info = resolved_directory.stat()
        except (OSError, RuntimeError, ValueError):
            return None, None, "A system modules-load.d directory could not be read safely."
        if resolved_directory != directory or not stat.S_ISDIR(info.st_mode):
            return None, None, "A system modules-load.d directory is a symlink or non-directory; duplicate startup entries cannot be checked safely."
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError:
            return None, None, "A system modules-load.d directory could not be enumerated."
        for path in entries:
            if path.suffix != ".conf" or path == managed_path:
                continue
            file_count += 1
            if file_count > MAX_CONFIG_FILES:
                return None, None, "The modules-load.d configuration tree exceeded its file-count scan limit."
            if path.name == managed_path.name:
                collision_paths.append(str(path))
            if path.is_symlink():
                try:
                    if path.resolve(strict=True) == Path("/dev/null"):
                        continue
                except (OSError, RuntimeError, ValueError):
                    return None, None, "A modules-load.d configuration symlink could not be resolved safely."
                return None, None, "A modules-load.d configuration symlink prevents a safe duplicate-entry check."
            try:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(fd, "rb") as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > MAX_CONFIG_FILE_BYTES:
                        return None, None, "A modules-load.d configuration file is not a bounded regular file."
                    raw = stream.read(MAX_CONFIG_FILE_BYTES + 1)
                    after = os.fstat(stream.fileno())
            except OSError:
                return None, None, "A modules-load.d configuration file could not be read safely."
            if (
                len(raw) > MAX_CONFIG_FILE_BYTES
                or len(raw) != before.st_size
                or before.st_ino != after.st_ino
                or before.st_dev != after.st_dev
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns
            ):
                return None, None, "A modules-load.d configuration file changed during its bounded read."
            byte_count += len(raw)
            if byte_count > MAX_CONFIG_SCAN_BYTES:
                return None, None, "The modules-load.d configuration tree exceeded its total byte scan limit."
            try:
                text = raw.decode("utf-8", errors="strict")
            except UnicodeError:
                return None, None, "A modules-load.d configuration file is not valid UTF-8."
            for line in text.splitlines():
                value = line.strip()
                if not value or value.startswith(("#", ";")):
                    continue
                if value.replace("-", "_") == module_key:
                    module_paths.append(str(path))
                    break
    return tuple(sorted(set(module_paths))), tuple(sorted(set(collision_paths))), None


def kernel_module_startup_confirmation_details(
    action: str,
    module: str,
) -> tuple[KernelModuleStartupTarget | None, str | None]:
    if not isinstance(action, str) or action not in {"enable", "disable"}:
        return None, "action must be enable or disable."
    if not isinstance(module, str) or not MODULE_NAME_RE.fullmatch(module):
        return None, "module must be one exact installed module name containing only letters, digits, underscores, or hyphens."
    directory, error = _module_config_directory()
    if error or directory is None:
        return None, error or "The modules-load.d configuration directory could not be verified."
    module_file, file_identity, error = _module_details(module)
    if error or module_file is None or file_identity is None:
        return None, error or "The exact installed module file could not be verified."
    kernel_release = os.uname().release
    path = directory / f"80-linux-mcp-{module}.conf"
    module_paths, collision_paths, error = _other_configuration(module, path)
    if error or module_paths is None or collision_paths is None:
        return None, error or "The other modules-load.d configuration could not be verified."
    if collision_paths:
        return None, "Another modules-load.d file uses the selected managed filename; refusing to shadow or expose it."
    if module_paths:
        return None, "The module is listed in another modules-load.d file; refusing a duplicate entry or an incomplete disable action."
    content = _render_config(module)
    current_sha256: str | None = None
    create_target: TextFileCreationTarget | None = None
    delete_target: TextFileDeletionTarget | None = None
    if action == "enable":
        if path.exists() or path.is_symlink():
            return None, "A file already exists at this managed modules-load.d path; enable never overwrites."
        create_target, error = text_file_creation_confirmation_details(str(path), content)
        if error or create_target is None:
            return None, error or "The exact modules-load.d destination could not be verified."
        if create_target.path != path:
            return None, "The modules-load.d destination resolved to a different path."
    else:
        delete_target, error = text_file_deletion_confirmation_details(str(path))
        if error or delete_target is None:
            return None, error or "The exact managed modules-load.d file could not be verified."
        if delete_target.path != path or delete_target.owner_uid != 0:
            return None, "Only the exact root-owned managed modules-load.d file can be removed."
        try:
            current_text = delete_target.original.decode("utf-8", errors="strict")
        except UnicodeError:
            return None, "The existing modules-load.d file is not valid UTF-8 text."
        if current_text != content:
            return None, "Only an unchanged modules-load.d file previously created for this module can be removed."
        current_sha256 = delete_target.current_sha256

    material = {
        "action": action,
        "module": module,
        "kernel_release": kernel_release,
        "module_file": module_file,
        "module_file_identity": file_identity,
        "other_module_entries": list(module_paths),
        "filename_collisions": list(collision_paths),
        "path": str(path),
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "current_sha256": current_sha256,
    }
    state_token = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return KernelModuleStartupTarget(
        action=action,  # type: ignore[arg-type]
        module=module,
        kernel_release=kernel_release,
        module_file=module_file,
        module_file_identity=file_identity,
        path=path,
        content=content,
        current_sha256=current_sha256,
        state_token=state_token,
        confirmation_phrase=f"CONFIRM MODULE STARTUP {module} {state_token[:16]}",
        create_target=create_target,
        delete_target=delete_target,
    ), None


def perform_kernel_module_startup_action(
    action: KernelModuleStartupAction,
    module: str,
    *,
    confirmed: bool,
    confirmed_action: str | None = None,
    confirmed_module: str | None = None,
    confirmation_phrase: str | None = None,
    expected_state_token: str | None = None,
) -> KernelModuleStartupResponse:
    safe_action: KernelModuleStartupAction = action if isinstance(action, str) and action in {"enable", "disable"} else "enable"
    safe_module = module[:63] if isinstance(module, str) else ""
    target, error = kernel_module_startup_confirmation_details(action, module)
    if error or target is None:
        return KernelModuleStartupResponse(success=False, action=safe_action, module=safe_module,
                                           user_confirmed=confirmed is True,
                                           message=error or "The persistent module-load change could not be verified.")
    if confirmed is not True:
        return KernelModuleStartupResponse(success=False, action=target.action, module=target.module,
                                           path=str(target.path), user_confirmed=False,
                                           message="Explicit client confirmation is required; no startup file was changed.")
    if (confirmed_action != target.action or confirmed_module != target.module
            or confirmation_phrase != target.confirmation_phrase or expected_state_token != target.state_token):
        return KernelModuleStartupResponse(success=False, action=target.action, module=target.module,
                                           path=str(target.path), user_confirmed=True,
                                           message="Confirmation did not match the exact module, action, and current state token.")

    with _ACTION_LOCK:
        current, error = kernel_module_startup_confirmation_details(action, module)
        if error or current is None or current != target:
            return KernelModuleStartupResponse(success=False, action=target.action, module=target.module,
                                               path=str(target.path), user_confirmed=True,
                                               message=error or "The module or startup file changed after confirmation; no file was changed.")
        if target.action == "enable":
            if target.create_target is None:
                return KernelModuleStartupResponse(success=False, action=target.action, module=target.module,
                                                   path=str(target.path), user_confirmed=True,
                                                   message="The create-only startup file target was lost; no file was changed.")
            result = create_text_file(
                str(target.path), target.content, confirmed=True,
                confirmed_path=str(target.create_target.path),
                confirmed_content_sha256=target.create_target.content_sha256,
            )
            changed = result.success
            message = "Added the exact module to system modules-load.d; it is configured for a future boot and was not loaded now."
        else:
            if target.delete_target is None or target.current_sha256 is None:
                return KernelModuleStartupResponse(success=False, action=target.action, module=target.module,
                                                   path=str(target.path), user_confirmed=True,
                                                   message="The exact deletion target was lost; no file was changed.")
            result = delete_text_file(
                str(target.path), confirmed=True,
                confirmed_path=str(target.delete_target.path),
                confirmed_current_sha256=target.current_sha256,
            )
            changed = result.success and result.deleted
            message = "Removed the exact module from system modules-load.d; an already-loaded module remains loaded until separately unloaded."
        if not changed:
            return KernelModuleStartupResponse(success=False, action=target.action, module=target.module,
                                               path=str(target.path), user_confirmed=True,
                                               message=f"The startup file was not changed: {result.message}")

        if target.action == "enable":
            readback, readback_error = text_file_replacement_confirmation_details(str(target.path), target.content)
            verified = bool(
                readback is not None and readback.path == target.path
                and readback.original == target.content.encode("utf-8")
                and readback.owner_uid == 0 and readback_error is None
            )
        else:
            verified = not target.path.exists() and not target.path.is_symlink()
        if not verified:
            return KernelModuleStartupResponse(success=False, action=target.action, module=target.module,
                                               path=str(target.path), file_changed=True,
                                               user_confirmed=True,
                                               message="The startup file was changed, but the final file state could not be verified; inspect it before retrying.")
        return KernelModuleStartupResponse(success=True, action=target.action, module=target.module,
                                           path=str(target.path), file_changed=True,
                                           user_confirmed=True, message=message)
