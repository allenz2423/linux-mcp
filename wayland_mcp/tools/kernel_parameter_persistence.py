"""Confirmed persistent sysctl.d entries for a fixed kernel-parameter allowlist."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import KernelParameterPersistenceResponse
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.filesystem_write import (
    TextFileCreationTarget,
    TextFileDeletionTarget,
    TextFileReplacementTarget,
    create_text_file,
    delete_text_file,
    replace_text_file,
    text_file_creation_confirmation_details,
    text_file_deletion_confirmation_details,
    text_file_replacement_confirmation_details,
)
from wayland_mcp.tools.host import _detect_init_system
from wayland_mcp.tools.kernel_parameters import _PARAMETERS_BY_NAME

KernelParameterPersistenceAction = Literal["set", "remove"]
SYSCTL_DIRECTORY = Path("/etc/sysctl.d")
SYSCTL_DIRECTORIES = (
    Path("/etc/sysctl.d"),
    Path("/run/sysctl.d"),
    Path("/usr/local/lib/sysctl.d"),
    Path("/usr/lib/sysctl.d"),
)
SYSCTL_HEADER = "# Managed by linux-mcp: persistent kernel parameter v1"
MAX_CONFIG_FILES = 4096
MAX_CONFIG_FILE_BYTES = 64 * 1024
MAX_CONFIG_SCAN_BYTES = 4 * 1024 * 1024
ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _ConfigFile:
    path: Path
    identity: tuple[int, int, int, int, int, int, int, int]
    sha256: str
    data: bytes


@dataclass(frozen=True, slots=True)
class PersistentKernelParameterTarget:
    action: KernelParameterPersistenceAction
    name: str
    value: int | None
    previous_value: int | None
    path: Path
    state_token: str
    config_signature: str
    other_matching_paths: tuple[str, ...]
    filename_collision_paths: tuple[str, ...]
    create_target: TextFileCreationTarget | None = None
    replacement_target: TextFileReplacementTarget | None = None
    deletion_target: TextFileDeletionTarget | None = None


def _target_path(name: str) -> Path:
    slug = name.replace(".", "_")
    return SYSCTL_DIRECTORY / f"99-linux-mcp-{slug}.conf"


def _configuration_directory(env: dict[str, str] | None = None) -> tuple[Path | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Persistent kernel-parameter configuration is available only on Linux."
    if _detect_init_system() != "systemd":
        return None, "Persistent sysctl.d management requires a systemd host."
    systemd_sysctl = find_session_binary("systemd-sysctl", env) or next(
        (
            str(candidate)
            for candidate in (
                Path("/usr/lib/systemd/systemd-sysctl"),
                Path("/lib/systemd/systemd-sysctl"),
            )
            if candidate.is_file() and os.access(candidate, os.X_OK)
        ),
        None,
    )
    if not systemd_sysctl:
        return None, "The systemd-sysctl executable is required for persistent sysctl.d configuration."
    try:
        resolved = SYSCTL_DIRECTORY.resolve(strict=True)
        info = SYSCTL_DIRECTORY.stat(follow_symlinks=False)
    except (OSError, RuntimeError, ValueError):
        return None, "The system sysctl.d configuration directory is unavailable."
    if resolved != SYSCTL_DIRECTORY or not stat.S_ISDIR(info.st_mode):
        return None, "The /etc/sysctl.d path must be a real directory, not a symlink."
    if info.st_uid != 0 or info.st_mode & 0o022:
        return None, "The /etc/sysctl.d directory must be root-owned and not group/other writable."
    return resolved, None


def persistent_kernel_parameter_control_available(env: dict[str, str] | None = None) -> bool:
    _directory, error = _configuration_directory(env)
    return error is None


def _render_config(name: str, value: int) -> str:
    return f"{SYSCTL_HEADER}\n{name} = {value}\n"


def _read_config_file(path: Path) -> tuple[_ConfigFile | None, str | None]:
    if not hasattr(os, "O_NOFOLLOW"):
        return None, "The no-follow file-descriptor interface is unavailable."
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > MAX_CONFIG_FILE_BYTES:
            return None, "A sysctl.d configuration file is not a bounded regular file."
        data = bytearray()
        while len(data) <= MAX_CONFIG_FILE_BYTES:
            chunk = os.read(descriptor, min(8192, MAX_CONFIG_FILE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if len(data) > MAX_CONFIG_FILE_BYTES or len(data) != before.st_size or identity_before != identity_after:
            return None, "A sysctl.d configuration file changed during its bounded read."
        raw = bytes(data)
        raw.decode("utf-8", errors="strict")
        return _ConfigFile(
            path=path,
            identity=identity_after,
            sha256=hashlib.sha256(raw).hexdigest(),
            data=raw,
        ), None
    except (OSError, UnicodeError) as exc:
        return None, f"A sysctl.d configuration file could not be read safely: {getattr(exc, 'strerror', None) or type(exc).__name__}."
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _matches_parameter(line: str, parameter_name: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";")):
        return False
    key = stripped.split("=", 1)[0].strip() if "=" in stripped else stripped.split(None, 1)[0]
    if key.startswith("-"):
        key = key[1:]
    if not key:
        return False
    normalized = key.replace("/", ".")
    candidates = {parameter_name, parameter_name.replace(".", "/")}
    return any(fnmatch.fnmatchcase(candidate, normalized) for candidate in candidates)


def _scan_configuration(
    name: str,
    managed_path: Path,
) -> tuple[str | None, tuple[str, ...] | None, tuple[str, ...] | None, str | None]:
    files: list[_ConfigFile] = []
    directory_states: list[tuple[str, tuple[int, int, int, int, int, int, int]]] = []
    masked_symlinks: list[tuple[str, tuple[int, int, int, int, int, int, int, int]]] = []
    file_count = 0
    byte_count = 0
    managed_filename_collisions: set[str] = set()
    matching_paths: set[str] = set()

    for directory in SYSCTL_DIRECTORIES:
        if not directory.exists() and not directory.is_symlink():
            continue
        try:
            resolved = directory.resolve(strict=True)
            before = directory.stat(follow_symlinks=False)
        except (OSError, RuntimeError, ValueError):
            return None, None, None, "A standard sysctl.d directory could not be inspected safely."
        if resolved != directory or not stat.S_ISDIR(before.st_mode):
            return None, None, None, "A standard sysctl.d directory is a symlink or non-directory; conflicting settings cannot be checked safely."
        try:
            paths = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError:
            return None, None, None, "A standard sysctl.d directory could not be enumerated."
        directory_states.append(
            (
                str(directory),
                (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_uid,
                    before.st_gid,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ),
            )
        )
        for path in paths:
            if path.suffix != ".conf":
                continue
            file_count += 1
            if file_count > MAX_CONFIG_FILES:
                return None, None, None, "The sysctl.d configuration tree exceeded its file-count scan limit."
            if path.name == managed_path.name and path != managed_path:
                managed_filename_collisions.add(str(path))
            if path.is_symlink():
                try:
                    if path.resolve(strict=True) == Path("/dev/null"):
                        link_info = path.stat(follow_symlinks=False)
                        masked_symlinks.append((
                            str(path),
                            (
                                link_info.st_dev,
                                link_info.st_ino,
                                link_info.st_mode,
                                link_info.st_uid,
                                link_info.st_gid,
                                link_info.st_size,
                                link_info.st_mtime_ns,
                                link_info.st_ctime_ns,
                            ),
                        ))
                        continue
                except (OSError, RuntimeError, ValueError):
                    return None, None, None, "A sysctl.d configuration symlink could not be resolved safely."
                return None, None, None, "A sysctl.d configuration symlink prevents a safe conflict check."
            config_file, error = _read_config_file(path)
            if error or config_file is None:
                return None, None, None, error or "A sysctl.d configuration file could not be verified."
            byte_count += len(config_file.data)
            if byte_count > MAX_CONFIG_SCAN_BYTES:
                return None, None, None, "The sysctl.d configuration tree exceeded its total byte scan limit."
            files.append(config_file)
            if path != managed_path:
                try:
                    text = config_file.data.decode("utf-8", errors="strict")
                except UnicodeError:
                    return None, None, None, "A sysctl.d configuration file is not valid UTF-8."
                if any(_matches_parameter(line, name) for line in text.splitlines()):
                    matching_paths.add(str(path))
        try:
            after = directory.stat(follow_symlinks=False)
        except OSError:
            return None, None, None, "A standard sysctl.d directory changed during its scan."
        after_state = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if after_state != directory_states[-1][1]:
            return None, None, None, "A standard sysctl.d directory changed during its scan."

    signature_payload = {
        "directories": directory_states,
        "files": [
            (str(item.path), item.identity, item.sha256)
            for item in sorted(files, key=lambda current: str(current.path))
        ],
        "masked_symlinks": sorted(masked_symlinks),
    }
    signature = hashlib.sha256(
        json.dumps(signature_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return signature, tuple(sorted(matching_paths)), tuple(sorted(managed_filename_collisions)), None


def _parse_managed_content(content: bytes, name: str) -> tuple[int | None, str | None]:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeError:
        return None, "The generated sysctl.d file is not valid UTF-8 text."
    match = re.fullmatch(
        re.escape(SYSCTL_HEADER) + r"\n" + re.escape(name) + r" = ([0-9]{1,10})\n",
        text,
    )
    if not match:
        return None, "The sysctl.d destination is not an unchanged linux-mcp generated file."
    value = int(match.group(1), 10)
    spec = _PARAMETERS_BY_NAME[name]
    if not spec.minimum <= value <= spec.maximum:
        return None, "The generated sysctl.d value is outside the allowlisted range."
    return value, None


def persistent_kernel_parameter_confirmation_details(
    action: str,
    name: str,
    value: int | None,
) -> tuple[PersistentKernelParameterTarget | None, str | None]:
    if not isinstance(action, str) or action not in {"set", "remove"}:
        return None, "action must be set or remove."
    spec = _PARAMETERS_BY_NAME.get(name) if isinstance(name, str) else None
    if spec is None:
        return None, "Choose one supported parameter from list_kernel_parameters."
    if action == "set":
        if not isinstance(value, int) or isinstance(value, bool):
            return None, "A persistent sysctl value must be an integer."
        if not spec.minimum <= value <= spec.maximum:
            return None, f"{name} accepts values from {spec.minimum} through {spec.maximum}."
    elif value is not None:
        return None, "value must be null when removing a generated setting."

    directory, error = _configuration_directory()
    if error or directory is None:
        return None, error or "The system sysctl.d directory could not be verified."
    path = _target_path(name)
    signature, matching_paths, filename_collisions, error = _scan_configuration(name, path)
    if error or signature is None or matching_paths is None or filename_collisions is None:
        return None, error or "The other sysctl.d configuration could not be verified."

    current_value: int | None = None
    create_target: TextFileCreationTarget | None = None
    replacement_target: TextFileReplacementTarget | None = None
    deletion_target: TextFileDeletionTarget | None = None
    current_exists = path.exists() or path.is_symlink()
    if action == "set" and (matching_paths or filename_collisions):
        return None, "Another sysctl.d file has a matching assignment or generated-name collision; refusing ambiguous precedence."
    if current_exists:
        if path.is_symlink():
            return None, "A symlink occupies the generated sysctl.d destination; it will not be followed or replaced."
        if action == "remove":
            deletion_target, error = text_file_deletion_confirmation_details(str(path))
            if error or deletion_target is None:
                return None, error or "The generated sysctl.d file could not be read safely."
            if deletion_target.path != path or deletion_target.owner_uid != 0:
                return None, "Only the exact root-owned generated sysctl.d file can be removed."
            if int(deletion_target.mode_octal, 8) & 0o022:
                return None, "The generated sysctl.d file is group/other writable and requires manual inspection."
            current_value, error = _parse_managed_content(deletion_target.original, name)
            if error or current_value is None:
                return None, error or "The generated sysctl.d file could not be verified."
        else:
            assert value is not None
            replacement_target, error = text_file_replacement_confirmation_details(str(path), _render_config(name, value))
            if error or replacement_target is None:
                return None, error or "The generated sysctl.d file could not be read safely."
            if replacement_target.path != path or replacement_target.owner_uid != 0:
                return None, "Only the exact root-owned generated sysctl.d file can be updated."
            if int(replacement_target.mode_octal, 8) & 0o022:
                return None, "The generated sysctl.d file is group/other writable and requires manual inspection."
            current_value, error = _parse_managed_content(replacement_target.original, name)
            if error or current_value is None:
                return None, error or "The generated sysctl.d file could not be verified."
    elif action == "set":
        assert value is not None
        create_target, error = text_file_creation_confirmation_details(str(path), _render_config(name, value))
        if error or create_target is None:
            return None, error or "The generated sysctl.d destination could not be verified."
        if create_target.path != path:
            return None, "The generated sysctl.d destination resolved to a different path."
    else:
        return None, "There is no linux-mcp generated sysctl.d file to remove."

    # Updates are refused if an external assignment could override or compete
    # with this managed setting. Removal remains available, but its prompt shows
    # any setting that will become active after the managed file is deleted.
    material = {
        "action": action,
        "name": name,
        "value": value,
        "current_value": current_value,
        "path": str(path),
        "config_signature": signature,
        "matching_paths": matching_paths,
        "filename_collisions": filename_collisions,
        "managed_sha256": (
            replacement_target.current_sha256 if replacement_target is not None
            else deletion_target.current_sha256 if deletion_target is not None
            else None
        ),
    }
    state_token = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return PersistentKernelParameterTarget(
        action=action,  # type: ignore[arg-type]
        name=name,
        value=value,
        previous_value=current_value,
        path=path,
        state_token=state_token,
        config_signature=signature,
        other_matching_paths=matching_paths,
        filename_collision_paths=filename_collisions,
        create_target=create_target,
        replacement_target=replacement_target,
        deletion_target=deletion_target,
    ), None


def perform_persistent_kernel_parameter_change(
    action: KernelParameterPersistenceAction,
    name: str,
    value: int | None,
    *,
    confirmed: bool,
    confirmed_action: str | None = None,
    confirmed_name: str | None = None,
    confirmed_value: int | None = None,
    state_token: str | None = None,
) -> KernelParameterPersistenceResponse:
    safe_action: KernelParameterPersistenceAction = action if action in {"set", "remove"} else "set"
    safe_name = name if isinstance(name, str) and name in _PARAMETERS_BY_NAME else "unknown"
    target, error = persistent_kernel_parameter_confirmation_details(action, name, value)
    if error or target is None:
        return KernelParameterPersistenceResponse(
            success=False,
            action=safe_action,
            name=safe_name,
            path=str(_target_path(safe_name)) if safe_name != "unknown" else None,
            user_confirmed=confirmed is True,
            message=error or "The persistent sysctl change could not be verified.",
        )
    if confirmed is not True:
        return KernelParameterPersistenceResponse(
            success=False,
            action=target.action,
            name=target.name,
            path=str(target.path),
            previous_value=target.previous_value,
            configured_value=target.previous_value,
            user_confirmed=False,
            message="Explicit client confirmation is required; no sysctl.d file was changed.",
        )
    if (
        confirmed_action != target.action
        or confirmed_name != target.name
        or confirmed_value != target.value
        or state_token != target.state_token
    ):
        return KernelParameterPersistenceResponse(
            success=False,
            action=target.action,
            name=target.name,
            path=str(target.path),
            previous_value=target.previous_value,
            configured_value=target.previous_value,
            user_confirmed=True,
            message="Confirmation did not match the exact parameter, action, value, and sysctl.d state.",
        )

    with ACTION_LOCK:
        current, error = persistent_kernel_parameter_confirmation_details(action, name, value)
        if error or current is None or current != target:
            return KernelParameterPersistenceResponse(
                success=False,
                action=target.action,
                name=target.name,
                path=str(target.path),
                previous_value=target.previous_value,
                configured_value=target.previous_value,
                user_confirmed=True,
                message=error or "The sysctl.d configuration changed after confirmation; no file was changed.",
            )
        if target.action == "set" and target.previous_value == target.value:
            return KernelParameterPersistenceResponse(
                success=True,
                action=target.action,
                name=target.name,
                path=str(target.path),
                previous_value=target.previous_value,
                configured_value=target.value,
                user_confirmed=True,
                message="The generated sysctl.d file already contains the requested value.",
            )

        if target.action == "set":
            assert target.value is not None
            content = _render_config(target.name, target.value)
            if target.create_target is not None:
                result = create_text_file(
                    str(target.path),
                    content,
                    confirmed=True,
                    confirmed_path=str(target.create_target.path),
                    confirmed_content_sha256=target.create_target.content_sha256,
                )
                changed = result.success and result.created
            elif target.replacement_target is not None:
                replacement = target.replacement_target
                result = replace_text_file(
                    str(target.path),
                    content,
                    confirmed=True,
                    confirmed_path=str(replacement.path),
                    confirmed_current_sha256=replacement.current_sha256,
                    confirmed_replacement_sha256=replacement.replacement_sha256,
                )
                changed = result.success
            else:
                return KernelParameterPersistenceResponse(
                    success=False, action=target.action, name=target.name, path=str(target.path),
                    previous_value=target.previous_value, user_confirmed=True,
                    message="The exact create/update target was lost; no sysctl.d file was changed.",
                )
            message = "Saved the allowlisted sysctl value in /etc/sysctl.d for systemd-sysctl at boot; the running value was not changed."
        else:
            deletion = target.deletion_target
            if deletion is None:
                return KernelParameterPersistenceResponse(
                    success=False, action=target.action, name=target.name, path=str(target.path),
                    previous_value=target.previous_value, user_confirmed=True,
                    message="The exact generated-file deletion target was lost; no sysctl.d file was changed.",
                )
            result = delete_text_file(
                str(target.path),
                confirmed=True,
                confirmed_path=str(deletion.path),
                confirmed_current_sha256=deletion.current_sha256,
            )
            changed = result.success and result.deleted
            message = "Removed the exact generated sysctl.d setting; any other matching host configuration remains in place."

        if not changed:
            return KernelParameterPersistenceResponse(
                success=False,
                action=target.action,
                name=target.name,
                path=str(target.path),
                previous_value=target.previous_value,
                configured_value=target.previous_value,
                file_changed=False,
                user_confirmed=True,
                message=f"The sysctl.d file was not changed: {result.message}",
            )

        if target.action == "set":
            expected_content = _render_config(target.name, target.value or 0).encode("utf-8")
            readback, readback_error = text_file_replacement_confirmation_details(str(target.path), expected_content.decode("utf-8"))
            verified = bool(
                readback is not None
                and readback.path == target.path
                and readback.original == expected_content
                and readback.owner_uid == 0
                and not (int(readback.mode_octal, 8) & 0o022)
                and readback_error is None
            )
        else:
            verified = not target.path.exists() and not target.path.is_symlink()
        if not verified:
            return KernelParameterPersistenceResponse(
                success=False,
                action=target.action,
                name=target.name,
                path=str(target.path),
                previous_value=target.previous_value,
                configured_value=target.value if target.action == "set" else None,
                file_changed=True,
                user_confirmed=True,
                message="The sysctl.d file changed, but its final state could not be verified; inspect it before retrying.",
            )
        if target.action == "remove" and (target.other_matching_paths or target.filename_collision_paths):
            message += " Other matching configuration paths were present and were not modified."
        return KernelParameterPersistenceResponse(
            success=True,
            action=target.action,
            name=target.name,
            path=str(target.path),
            previous_value=target.previous_value,
            configured_value=target.value if target.action == "set" else None,
            file_changed=True,
            user_confirmed=True,
            message=message,
        )
