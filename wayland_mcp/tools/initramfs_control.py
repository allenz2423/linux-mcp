"""Confirmed rebuild of the current kernel's standard initramfs image."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from wayland_mcp.models import InitramfsRebuildResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

InitramfsBackend = Literal["dracut", "update-initramfs", "mkinitcpio"]
BOOT_DIRECTORY = Path("/boot")
MKINITCPIO_PRESET_DIRECTORY = Path("/etc/mkinitcpio.d")
MKINITCPIO_CONFIG_DROPIN_DIRECTORY = Path("/etc/mkinitcpio.conf.d")
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_PRESET_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 256 * 1024
ACTION_TIMEOUT_SECONDS = 1200
KERNEL_RELEASE_RE = re.compile(r"^[A-Za-z0-9._+-]{1,128}$")
PRESET_NAME_RE = re.compile(r"^[A-Za-z0-9_+-]{1,64}$")
LITERAL_RE = re.compile(r"^[A-Za-z0-9_./:+-]*$")
OPTION_LITERAL_RE = re.compile(r"^[A-Za-z0-9_./:+ -]*$")
ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
PRESET_VARIABLE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)_(kver|config|image|uki|options)$")
STANDARD_IMAGE_RE = re.compile(r"^(?:initramfs-[A-Za-z0-9._+-]+\.img|initrd-[A-Za-z0-9._+-]+\.img|initrd\.img-[A-Za-z0-9._+-]+)$")
_ACTION_LOCK = threading.Lock()
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


@dataclass(frozen=True, slots=True)
class InitramfsRebuildTarget:
    backend: InitramfsBackend
    kernel_release: str
    image_path: Path
    image_snapshot: tuple[int, ...]
    boot_directory_snapshot: tuple[int, ...]
    binary: str
    binary_snapshot: tuple[int, ...]
    command_arguments: tuple[str, ...]
    config_path: Path | None
    uses_default_config_dropins: bool
    state_token: str


@dataclass(frozen=True, slots=True)
class _Candidate:
    backend: InitramfsBackend
    binary: str
    binary_snapshot: tuple[int, ...]
    image_path: Path
    command_arguments: tuple[str, ...]
    generator_state: dict[str, object]
    config_path: Path | None = None
    uses_default_config_dropins: bool = False


def _environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _safe_directory(path: Path) -> tuple[tuple[int, ...] | None, str | None]:
    try:
        resolved = path.resolve(strict=True)
        info = path.stat(follow_symlinks=False)
    except (OSError, RuntimeError, ValueError):
        return None, "The standard /boot directory could not be verified."
    if (
        resolved != path
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
    ):
        return None, "The standard /boot path must be a real root-owned directory that is not group/other writable."
    return _identity(info), None


def _safe_rooted_file(path: Path, label: str, max_bytes: int) -> tuple[bytes | None, tuple[int, ...] | None, str | None]:
    """Read a small root-owned regular file without following its final symlink."""
    descriptor: int | None = None
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            return None, None, f"The {label} path must be absolute and contain no symlinked components."
        for parent in reversed(path.parents):
            parent_info = parent.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != 0
                or parent_info.st_mode & 0o022
            ):
                return None, None, f"The {label} path has a directory that is not root-owned and non-writable by group/other."
        descriptor = os.open(path, _READ_FLAGS)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or before.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
            or before.st_size < 1
            or before.st_size > max_bytes
        ):
            return None, None, f"The {label} must be a bounded root-owned single-link regular file without group/other write or set-id bits."
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(16384, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            return None, None, f"The {label} exceeds the supported size limit."
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            return None, None, f"The {label} changed while it was being inspected."
        return b"".join(chunks), _identity(after), None
    except (OSError, RuntimeError, ValueError):
        return None, None, f"The {label} could not be opened safely."
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _mkinitcpio_dropin_state() -> tuple[dict[str, object] | None, str | None]:
    path = MKINITCPIO_CONFIG_DROPIN_DIRECTORY
    try:
        if path.resolve(strict=True) != path:
            return None, "The mkinitcpio config drop-in directory must not contain symlinked path components."
        for parent in reversed(path.parents):
            parent_info = parent.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != 0
                or parent_info.st_mode & 0o022
            ):
                return None, "The mkinitcpio config drop-in directory has an unsafe parent directory."
        directory_info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return {"directory": None, "files": []}, None
    except (OSError, RuntimeError, ValueError):
        return None, "The mkinitcpio config drop-in directory could not be inspected safely."
    if (
        not stat.S_ISDIR(directory_info.st_mode)
        or directory_info.st_uid != 0
        or directory_info.st_mode & 0o022
    ):
        return None, "The mkinitcpio config drop-in directory must be a real root-owned directory that is not group/other writable."
    try:
        with os.scandir(path) as scan:
            entries = sorted((entry for entry in scan if entry.name.endswith(".conf")), key=lambda entry: entry.name)
    except OSError:
        return None, "The mkinitcpio config drop-ins could not be listed safely."
    if len(entries) > 128:
        return None, "The mkinitcpio config drop-in directory exceeds the supported entry limit."
    files: list[dict[str, object]] = []
    for entry in entries:
        file_path = path / entry.name
        try:
            entry_info = entry.stat(follow_symlinks=False)
        except OSError:
            return None, "A mkinitcpio config drop-in changed while the directory was being inspected."
        if stat.S_ISLNK(entry_info.st_mode):
            return None, "A mkinitcpio config drop-in is a symlink; refusing to follow it."
        contents, identity, error = _safe_rooted_file(file_path, "mkinitcpio config drop-in", MAX_CONFIG_BYTES)
        if error or contents is None or identity is None:
            return None, error or "A mkinitcpio config drop-in could not be verified."
        if _identity(entry_info) != identity:
            return None, "A mkinitcpio config drop-in changed while it was being inspected."
        files.append({
            "path": str(file_path),
            "identity": list(identity),
            "sha256": hashlib.sha256(contents).hexdigest(),
        })
    try:
        if _identity(path.stat(follow_symlinks=False)) != _identity(directory_info):
            return None, "The mkinitcpio config drop-in directory changed while it was being inspected."
    except OSError:
        return None, "The mkinitcpio config drop-in directory could not be revalidated."
    return {"directory": list(_identity(directory_info)), "files": files}, None


def _safe_resolved_kernel_file(path: Path) -> tuple[Path | None, tuple[int, ...] | None]:
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat(follow_symlinks=False)
    except (OSError, RuntimeError, ValueError):
        return None, None
    for parent in reversed(resolved.parents):
        try:
            parent_info = parent.stat(follow_symlinks=False)
        except OSError:
            return None, None
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or parent_info.st_mode & 0o022
        ):
            return None, None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
    ):
        return None, None
    return resolved, _identity(info)


def _parse_literal_assignment(raw_value: str, *, allow_options: bool = False) -> str | list[str] | None:
    value = raw_value.strip()
    if value.startswith("(") and value.endswith(")"):
        inner = value[1:-1]
        try:
            items = shlex.split(inner, comments=False, posix=True)
        except ValueError:
            return None
        if any(not PRESET_NAME_RE.fullmatch(item) for item in items):
            return None
        return items
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        literal = value[1:-1]
    elif value and not any(character.isspace() for character in value):
        literal = value
    elif value == "":
        literal = ""
    else:
        return None
    if "$" in literal or "`" in literal or "\\" in literal:
        return None
    accepted = OPTION_LITERAL_RE if allow_options else LITERAL_RE
    return literal if accepted.fullmatch(literal) else None


def _parse_mkinitcpio_preset(contents: bytes) -> tuple[dict[str, object] | None, str | None]:
    try:
        source = contents.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, "A mkinitcpio preset is not valid UTF-8."
    values: dict[str, object] = {}
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ASSIGNMENT_RE.fullmatch(stripped)
        if not match:
            return None, "A mkinitcpio preset contains shell syntax outside simple literal assignments; refusing to evaluate it."
        name, raw_value = match.groups()
        if name in values:
            return None, "A mkinitcpio preset repeats an assignment; refusing ambiguous shell semantics."
        if name == "PRESETS":
            parsed = _parse_literal_assignment(raw_value)
            if not isinstance(parsed, list) or not parsed:
                return None, "A mkinitcpio preset must define PRESETS as a nonempty literal array."
            values[name] = parsed
            continue
        variable_match = PRESET_VARIABLE_RE.fullmatch(name)
        if not variable_match:
            return None, f"A mkinitcpio preset uses unsupported variable {name}; only literal image, kernel, config, UKI, and options assignments are handled."
        preset_name, variable = variable_match.groups()
        if preset_name != "ALL" and not PRESET_NAME_RE.fullmatch(preset_name):
            return None, "A mkinitcpio preset contains an unsupported preset name."
        parsed = _parse_literal_assignment(raw_value, allow_options=variable == "options")
        if not isinstance(parsed, str) and not (variable == "options" and isinstance(parsed, list)):
            return None, f"The mkinitcpio preset assignment {name} is not a supported literal string."
        values[name] = parsed
    presets = values.get("PRESETS")
    if not isinstance(presets, list) or len(set(presets)) != len(presets):
        return None, "A mkinitcpio preset has missing or duplicate preset names."
    for preset in presets:
        if not isinstance(preset, str):
            return None, "A mkinitcpio preset name is invalid."
        for suffix in ("kver", "config", "image", "uki", "options"):
            key = f"{preset}_{suffix}"
            if key in values and not isinstance(values[key], str) and not (suffix == "options" and isinstance(values[key], list)):
                return None, f"The mkinitcpio preset assignment {key} is invalid."
    return values, None


def _mkinitcpio_candidates(kernel_release: str, env: dict[str, str]) -> tuple[list[_Candidate], str | None]:
    binary, binary_snapshot = _safe_binary("mkinitcpio", env)
    if binary is None or binary_snapshot is None:
        return [], None
    try:
        if MKINITCPIO_PRESET_DIRECTORY.resolve(strict=True) != MKINITCPIO_PRESET_DIRECTORY:
            return [], "The mkinitcpio preset directory must not contain symlinked path components."
        for parent in reversed(MKINITCPIO_PRESET_DIRECTORY.parents):
            parent_info = parent.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != 0
                or parent_info.st_mode & 0o022
            ):
                return [], "The mkinitcpio preset directory has an unsafe parent directory."
        directory_info = MKINITCPIO_PRESET_DIRECTORY.stat(follow_symlinks=False)
        if not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != 0 or directory_info.st_mode & 0o022:
            return [], "The mkinitcpio preset directory must be a real root-owned directory that is not group/other writable."
        with os.scandir(MKINITCPIO_PRESET_DIRECTORY) as scan:
            entries = sorted(
                (entry for entry in scan if entry.name.endswith(".preset")),
                key=lambda entry: entry.name,
            )
    except FileNotFoundError:
        return [], None
    except OSError:
        return [], "The mkinitcpio preset directory could not be inspected safely."
    if len(entries) > 128:
        return [], "The mkinitcpio preset directory exceeds the supported entry limit."

    module_kernel_paths = (
        Path("/usr/lib/modules") / kernel_release / "vmlinuz",
        Path("/lib/modules") / kernel_release / "vmlinuz",
    )
    module_kernel_files = {
        resolved: identity
        for path in module_kernel_paths
        for resolved, identity in [_safe_resolved_kernel_file(path)]
        if resolved is not None and identity is not None
    }
    if not module_kernel_files:
        return [], None

    candidates: list[_Candidate] = []
    directory_snapshot = _identity(directory_info)
    all_preset_state: list[dict[str, object]] = []
    parsed_presets: list[tuple[Path, dict[str, object], tuple[int, ...], str]] = []
    for entry in entries:
        preset_path = MKINITCPIO_PRESET_DIRECTORY / entry.name
        try:
            entry_info = entry.stat(follow_symlinks=False)
        except OSError:
            return [], "A mkinitcpio preset changed while the directory was being inspected."
        if stat.S_ISLNK(entry_info.st_mode):
            return [], "A mkinitcpio preset is a symlink; refusing to follow it."
        contents, preset_identity, error = _safe_rooted_file(preset_path, "mkinitcpio preset", MAX_PRESET_BYTES)
        if error or contents is None or preset_identity is None:
            return [], error or "A mkinitcpio preset could not be verified."
        if _identity(entry_info) != preset_identity:
            return [], "A mkinitcpio preset changed while it was being inspected."
        parsed, error = _parse_mkinitcpio_preset(contents)
        if error or parsed is None:
            return [], error or "A mkinitcpio preset could not be parsed safely."
        digest = hashlib.sha256(contents).hexdigest()
        parsed_presets.append((preset_path, parsed, preset_identity, digest))
        all_preset_state.append({
            "path": str(preset_path),
            "identity": list(preset_identity),
            "sha256": digest,
        })

    for preset_path, values, preset_identity, preset_digest in parsed_presets:
        preset_names = cast(list[str], values["PRESETS"])
        if "default" not in preset_names:
            continue
        kernel_value = values.get("default_kver") or values.get("ALL_kver")
        explicit_config_value = values.get("default_config") or values.get("ALL_config")
        config_value = explicit_config_value or "/etc/mkinitcpio.conf"
        image_value = values.get("default_image")
        if not all(isinstance(value, str) and value for value in (kernel_value, config_value, image_value)):
            return [], "The default mkinitcpio preset must define literal kernel, config, and image paths."
        kernel_text = cast(str, kernel_value)
        kernel_path = Path(kernel_text) if kernel_text.startswith("/") else Path("/usr/lib/modules") / kernel_text / "vmlinuz"
        config_path = Path(cast(str, config_value))
        image_path = Path(cast(str, image_value))
        if (
            (not kernel_text.startswith("/") and not KERNEL_RELEASE_RE.fullmatch(kernel_text))
            or not config_path.is_absolute()
            or not image_path.is_absolute()
            or image_path.parent != BOOT_DIRECTORY
            or not STANDARD_IMAGE_RE.fullmatch(image_path.name)
            or str(image_path) != cast(str, image_value)
        ):
            return [], "The default mkinitcpio preset target must be a direct standard initramfs image in /boot."
        if kernel_text == kernel_release:
            resolved_kernel = next(iter(module_kernel_files), None)
            kernel_identity = module_kernel_files.get(resolved_kernel) if resolved_kernel is not None else None
        elif kernel_text.startswith("/"):
            resolved_kernel, kernel_identity = _safe_resolved_kernel_file(kernel_path)
        else:
            continue
        if resolved_kernel is None or kernel_identity is None or resolved_kernel not in module_kernel_files:
            continue
        if values.get("default_uki"):
            return [], "The default mkinitcpio preset builds a unified kernel image; only standard initramfs images are supported."
        if values.get("default_options"):
            return [], "The default mkinitcpio preset has extra command-line options; those are not executed by this tool."
        config_contents, config_identity, error = _safe_rooted_file(
            config_path, "mkinitcpio config", MAX_CONFIG_BYTES
        )
        if error or config_contents is None or config_identity is None:
            return [], error or "The mkinitcpio config could not be verified."
        config_digest = hashlib.sha256(config_contents).hexdigest()
        uses_default_config_dropins = not bool(explicit_config_value)
        if uses_default_config_dropins:
            dropin_state, error = _mkinitcpio_dropin_state()
            if error or dropin_state is None:
                return [], error or "The mkinitcpio config drop-ins could not be verified."
        else:
            dropin_state = {"ignored_by_explicit_config": True, "files": []}
        try:
            image_info = image_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            return [], "A standard mkinitcpio image target could not be inspected."
        if stat.S_ISLNK(image_info.st_mode):
            return [], "A standard mkinitcpio image target is a symlink; refusing to follow it."
        command_arguments = ("-g", str(image_path), "-k", kernel_text)
        if explicit_config_value:
            command_arguments += ("-c", str(config_path))
        generator_state: dict[str, object] = {
            "preset_directory_identity": list(directory_snapshot),
            "presets": all_preset_state,
            "selected_preset": str(preset_path),
            "selected_preset_identity": list(preset_identity),
            "selected_preset_sha256": preset_digest,
            "config_path": str(config_path),
            "config_identity": list(config_identity),
            "config_sha256": config_digest,
            "config_dropins": dropin_state,
            "preset_kernel_value": kernel_text,
            "kernel_path": str(kernel_path),
            "resolved_kernel_path": str(resolved_kernel),
            "kernel_identity": list(kernel_identity),
        }
        candidates.append(
            _Candidate(
                backend="mkinitcpio",
                binary=binary,
                binary_snapshot=binary_snapshot,
                image_path=image_path,
                command_arguments=command_arguments,
                generator_state=generator_state,
                config_path=config_path,
                uses_default_config_dropins=uses_default_config_dropins,
            )
        )
    try:
        if _identity(MKINITCPIO_PRESET_DIRECTORY.stat(follow_symlinks=False)) != directory_snapshot:
            return [], "The mkinitcpio preset directory changed while it was being inspected."
    except OSError:
        return [], "The mkinitcpio preset directory could not be revalidated."
    return candidates, None


def _safe_binary(binary_name: str, env: dict[str, str]) -> tuple[str | None, tuple[int, ...] | None]:
    raw_path = find_session_binary(binary_name, env)
    if not raw_path:
        return None, None
    try:
        resolved = os.path.realpath(raw_path, strict=True)
        info = os.stat(resolved, follow_symlinks=False)
    except (OSError, RuntimeError, ValueError):
        return None, None
    candidate = Path(resolved)
    for parent in reversed(candidate.parents):
        try:
            parent_info = parent.stat(follow_symlinks=False)
        except OSError:
            return None, None
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or parent_info.st_mode & 0o022
        ):
            return None, None
    if (
        not stat.S_ISREG(info.st_mode)
        or not os.access(resolved, os.X_OK)
        or info.st_uid != 0
        or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
    ):
        return None, None
    return resolved, _identity(info)


def _image_snapshot(path: Path) -> tuple[tuple[int, ...] | None, str | None]:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, _READ_FLAGS)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_nlink != 1
            or before.st_uid != 0
            or before.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
        ):
            return None, "The current initramfs target must be a nonempty, root-owned, single-link regular file without group/other write or set-id bits."
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            return None, "The current initramfs target changed while it was being inspected."
        return _identity(after), None
    except OSError:
        return None, "The current initramfs target could not be opened safely."
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _prepare_target() -> tuple[InitramfsRebuildTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Initramfs rebuilding is available only on Linux."
    kernel_release = os.uname().release
    if not KERNEL_RELEASE_RE.fullmatch(kernel_release):
        return None, "The running kernel release is not a supported filename component."
    env = _environment()
    boot_snapshot, error = _safe_directory(BOOT_DIRECTORY)
    if error or boot_snapshot is None:
        return None, error or "The standard /boot directory could not be verified."

    candidates: list[_Candidate] = []
    for backend, binary_name, filename in (
        ("dracut", "dracut", f"initramfs-{kernel_release}.img"),
        ("update-initramfs", "update-initramfs", f"initrd.img-{kernel_release}"),
    ):
        binary, binary_snapshot = _safe_binary(binary_name, env)
        image_path = BOOT_DIRECTORY / filename
        if binary is None or binary_snapshot is None:
            continue
        try:
            image_info = image_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            return None, "A standard current-kernel initramfs target could not be inspected."
        if stat.S_ISLNK(image_info.st_mode):
            return None, "A standard current-kernel initramfs target is a symlink; refusing to follow it."
        image_snapshot, error = _image_snapshot(image_path)
        if error or image_snapshot is None:
            return None, error or "A standard current-kernel initramfs target could not be verified."
        arguments = (
            ("--force", str(image_path), kernel_release)
            if backend == "dracut"
            else ("-u", "-k", kernel_release)
        )
        candidates.append(
            _Candidate(
                backend=cast(InitramfsBackend, backend),
                binary=binary,
                binary_snapshot=binary_snapshot,
                image_path=image_path,
                command_arguments=arguments,
                generator_state={"manager": backend},
            )
        )

    mkinitcpio_candidates, mkinitcpio_error = _mkinitcpio_candidates(kernel_release, env)
    if mkinitcpio_error:
        return None, mkinitcpio_error
    for candidate in mkinitcpio_candidates:
        image_snapshot, error = _image_snapshot(candidate.image_path)
        if error or image_snapshot is None:
            return None, error or "A standard current-kernel mkinitcpio target could not be verified."
        candidates.append(candidate)

    if len(candidates) != 1:
        return None, (
            "Exactly one existing standard current-kernel initramfs target managed by dracut, update-initramfs, or a supported mkinitcpio preset is required; "
            "missing and ambiguous targets are refused."
        )
    candidate = candidates[0]
    backend = candidate.backend
    binary = candidate.binary
    binary_snapshot = candidate.binary_snapshot
    image_path = candidate.image_path
    image_snapshot, error = _image_snapshot(image_path)
    if error or image_snapshot is None:
        return None, error or "The selected current initramfs target could not be verified."
    material = {
        "backend": backend,
        "kernel_release": kernel_release,
        "image_path": str(image_path),
        "image_snapshot": list(image_snapshot),
        "boot_directory_snapshot": list(boot_snapshot),
        "binary": binary,
        "binary_snapshot": list(binary_snapshot),
        "command_arguments": list(candidate.command_arguments),
        "generator_state": candidate.generator_state,
    }
    state_token = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return InitramfsRebuildTarget(
        backend=backend,
        kernel_release=kernel_release,
        image_path=image_path,
        image_snapshot=image_snapshot,
        boot_directory_snapshot=boot_snapshot,
        binary=binary,
        binary_snapshot=binary_snapshot,
        command_arguments=candidate.command_arguments,
        config_path=candidate.config_path,
        uses_default_config_dropins=candidate.uses_default_config_dropins,
        state_token=state_token,
    ), None


def initramfs_rebuild_available() -> bool:
    target, error = _prepare_target()
    return target is not None and error is None


def initramfs_rebuild_confirmation_details() -> tuple[InitramfsRebuildTarget | None, str | None]:
    return _prepare_target()


def _response(
    *,
    success: bool,
    backend: str | None = None,
    kernel_release: str | None = None,
    image_path: str | None = None,
    previous_size_bytes: int | None = None,
    image_size_bytes: int | None = None,
    user_confirmed: bool,
    message: str,
) -> InitramfsRebuildResponse:
    return InitramfsRebuildResponse(
        success=success,
        backend=backend,
        kernel_release=kernel_release,
        image_path=image_path,
        previous_size_bytes=previous_size_bytes,
        image_size_bytes=image_size_bytes,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_initramfs_rebuild(
    *,
    confirmed: bool,
    confirmed_backend: str | None = None,
    confirmed_kernel_release: str | None = None,
    confirmed_image_path: str | None = None,
    state_token: str | None = None,
) -> InitramfsRebuildResponse:
    target, error = initramfs_rebuild_confirmation_details()
    if error or target is None:
        return _response(
            success=False,
            kernel_release=os.uname().release if sys.platform.startswith("linux") else None,
            user_confirmed=confirmed is True,
            message=error or "The current initramfs target could not be verified.",
        )
    previous_size = target.image_snapshot[6]
    if not confirmed:
        return _response(
            success=False,
            backend=target.backend,
            kernel_release=target.kernel_release,
            image_path=str(target.image_path),
            previous_size_bytes=previous_size,
            user_confirmed=False,
            message="Explicit client confirmation is required; no initramfs was rebuilt.",
        )
    if (
        confirmed_backend != target.backend
        or confirmed_kernel_release != target.kernel_release
        or confirmed_image_path != str(target.image_path)
        or state_token != target.state_token
    ):
        return _response(
            success=False,
            backend=target.backend,
            kernel_release=target.kernel_release,
            image_path=str(target.image_path),
            previous_size_bytes=previous_size,
            user_confirmed=True,
            message="Confirmation did not repeat the exact backend, running kernel, target image, and state-bound token.",
        )

    with _ACTION_LOCK:
        current, error = initramfs_rebuild_confirmation_details()
        if error or current is None or current.state_token != target.state_token:
            return _response(
                success=False,
                backend=target.backend,
                kernel_release=target.kernel_release,
                image_path=str(target.image_path),
                previous_size_bytes=previous_size,
                user_confirmed=True,
                message=error or "The kernel, initramfs target, or generator changed after confirmation; no rebuild was run.",
            )
        if os.uname().release != target.kernel_release:
            return _response(
                success=False,
                backend=target.backend,
                kernel_release=target.kernel_release,
                image_path=str(target.image_path),
                previous_size_bytes=previous_size,
                user_confirmed=True,
                message="The running kernel changed after confirmation; no rebuild was run.",
            )
        arguments = list(target.command_arguments)
        _output, command_error, truncated = run_bounded_command(
            [target.binary, *arguments],
            _environment(),
            command_label=f"Rebuild current initramfs with {target.backend}",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_OUTPUT_BYTES,
            cwd="/",
            kill_process_group=True,
        )
        if command_error or _output is None or truncated:
            return _response(
                success=False,
                backend=target.backend,
                kernel_release=target.kernel_release,
                image_path=str(target.image_path),
                previous_size_bytes=previous_size,
                user_confirmed=True,
                message="The initramfs command did not complete cleanly. Inspect the target image and boot-manager state before retrying; command output is withheld.",
            )
        if os.uname().release != target.kernel_release:
            return _response(
                success=False,
                backend=target.backend,
                kernel_release=target.kernel_release,
                image_path=str(target.image_path),
                previous_size_bytes=previous_size,
                user_confirmed=True,
                message="The command returned, but the running kernel changed during the operation. Inspect the image before retrying.",
            )
        image_snapshot, image_error = _image_snapshot(target.image_path)
        if image_error or image_snapshot is None:
            return _response(
                success=False,
                backend=target.backend,
                kernel_release=target.kernel_release,
                image_path=str(target.image_path),
                previous_size_bytes=previous_size,
                user_confirmed=True,
                message="The rebuild command returned, but the resulting initramfs image could not be verified. Inspect it before retrying.",
            )
        if image_snapshot == target.image_snapshot:
            return _response(
                success=False,
                backend=target.backend,
                kernel_release=target.kernel_release,
                image_path=str(target.image_path),
                previous_size_bytes=previous_size,
                image_size_bytes=image_snapshot[6],
                user_confirmed=True,
                message="The command returned without a detectable change to the current initramfs image. Inspect manager state before retrying.",
            )
        return _response(
            success=True,
            backend=target.backend,
            kernel_release=target.kernel_release,
            image_path=str(target.image_path),
            previous_size_bytes=previous_size,
            image_size_bytes=image_snapshot[6],
            user_confirmed=True,
            message=(
                f"Rebuilt and verified the current kernel's initramfs with {target.backend}. "
                "Configured generator modules or post-update hooks may have run with the server's current OS permissions."
            ),
        )
