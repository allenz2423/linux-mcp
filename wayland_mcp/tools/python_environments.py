"""Confirmed, current-user Python virtual-environment and pip operations."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    PythonEnvironmentActionResponse,
    PythonEnvironmentInfo,
    PythonEnvironmentListResponse,
    PythonEnvironmentPackageInfo,
    PythonEnvironmentPackageListResponse,
)
from wayland_mcp.session import get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

PythonEnvironmentAction = Literal["create", "install", "upgrade", "uninstall"]
MANAGED_ROOT_NAME = ".linux-mcp-python-venvs"
ENVIRONMENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
PACKAGE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ENVIRONMENTS = 100
MAX_ENVIRONMENT_DIRECTORY_ENTRIES = 5000
MAX_PACKAGES = 10_000
MAX_PACKAGE_METADATA_ENTRIES = 20_000
MAX_TRANSACTION_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_VENV_CONFIG_BYTES = 64 * 1024
MAX_PACKAGE_METADATA_BYTES = 1024 * 1024
STATUS_TIMEOUT_SECONDS = 20
CREATE_TIMEOUT_SECONDS = 180
TRANSACTION_TIMEOUT_SECONDS = 30 * 60


@dataclass(frozen=True, slots=True)
class PythonEnvironmentSnapshot:
    action: str
    environment_name: str
    package_name: str
    version: str
    home: Path
    home_identity: tuple[int, ...]
    root: Path
    root_identity: tuple[int, ...] | None
    environment_path: Path
    environment_identity: tuple[int, ...] | None
    config_sha256: str | None
    python_binary: str
    python_identity: tuple[int, ...]
    packages: tuple[PythonEnvironmentPackageInfo, ...]
    package_inventory_sha256: str
    uid: int
    euid: int
    state_token: str


@dataclass(frozen=True, slots=True)
class PythonEnvironmentReadiness:
    available: bool
    python_binary: str | None
    reason: str | None
    required_dependency: str | None
    required_permission: str | None


def _environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["TERM"] = "dumb"
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Disable pip configuration and environment overrides. Package operations
    # use pip's normal public-index defaults and accept no arbitrary options.
    env["PIP_CONFIG_FILE"] = os.devnull
    return env


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _current_home() -> tuple[Path | None, os.stat_result | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Python environments are available only on Linux."
    try:
        account = pwd.getpwuid(os.getuid())
        home = Path(account.pw_dir).resolve(strict=True)
        info = os.stat(home, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            return None, None, "The current user's home directory is not an owned directory."
        if info.st_mode & 0o022:
            return None, None, "The current user's home directory is writable by another account; Python environments are unavailable there."
        return home, info, None
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        return None, None, f"The current user's home directory could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."


def _safe_directory(
    path: Path,
    *,
    owner_uid: int,
    private: bool = False,
) -> tuple[os.stat_result | None, str | None]:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, f"A managed environment directory could not be inspected: {exc.strerror or type(exc).__name__}."
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return None, "Managed environment paths must be real directories without symlinks."
    unsafe_mode = info.st_mode & (0o077 if private else 0o022)
    if info.st_uid != owner_uid or unsafe_mode:
        return None, (
            "The managed environment root must belong to the current user and be inaccessible to group/other users."
            if private
            else "Managed environment directories must belong to the current user and must not be group/world writable."
        )
    return info, None


def _read_venv_config(path: Path) -> tuple[str | None, Path | None, str | None]:
    config_path = path / "pyvenv.cfg"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(config_path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > MAX_VENV_CONFIG_BYTES:
                return None, None, "The virtual environment configuration is not a bounded regular file owned by the current user."
            chunks: list[bytes] = []
            remaining = MAX_VENV_CONFIG_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(16 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > MAX_VENV_CONFIG_BYTES:
                return None, None, "The virtual environment configuration exceeds the inspection limit."
        finally:
            os.close(descriptor)
    except OSError as exc:
        return None, None, f"The virtual environment configuration could not be read: {exc.strerror or type(exc).__name__}."
    try:
        lines = data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError:
        return None, None, "The virtual environment configuration is not valid UTF-8."
    values: dict[str, list[str]] = {}
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values.setdefault(key.strip().casefold(), []).append(value.strip())
    homes = values.get("home", [])
    system_packages = values.get("include-system-site-packages", [])
    if len(homes) != 1 or not Path(homes[0]).is_absolute():
        return None, None, "The virtual environment configuration does not contain one valid base Python directory."
    if len(system_packages) != 1 or system_packages[0].casefold() not in {"false", "0"}:
        return None, None, "The managed environment must exclude system site-packages."
    try:
        base_home = Path(homes[0]).resolve(strict=True)
        if not base_home.is_dir():
            return None, None, "The virtual environment's base Python directory is unavailable."
    except (OSError, RuntimeError, ValueError):
        return None, None, "The virtual environment's base Python directory could not be verified."
    return hashlib.sha256(data).hexdigest(), base_home, None


def _python_identity(binary: str) -> tuple[str | None, tuple[int, ...] | None, str | None]:
    try:
        resolved = str(Path(binary).resolve(strict=True))
        info = os.stat(resolved, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
            return None, None, "The Python interpreter is not an executable regular file."
        return resolved, _identity(info), None
    except (OSError, RuntimeError, ValueError) as exc:
        return None, None, f"The Python interpreter could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."


def _discover_python3(env: dict[str, str]) -> tuple[str | None, tuple[int, ...] | None, str | None]:
    candidate = shutil.which("python3", path=env.get("PATH"))
    if not candidate:
        return None, None, "The python3 executable is unavailable."
    return _python_identity(candidate)


def _package_inventory(
    environment_path: Path,
    *,
    owner_uid: int,
) -> tuple[tuple[PythonEnvironmentPackageInfo, ...] | None, str | None]:
    site_directories: list[Path] = []
    scanned = 0
    for library_name in ("lib", "lib64"):
        library = environment_path / library_name
        try:
            library_info = os.lstat(library)
        except FileNotFoundError:
            continue
        except OSError as exc:
            return None, f"A virtual environment library directory could not be inspected: {exc.strerror or type(exc).__name__}."
        if stat.S_ISLNK(library_info.st_mode) and library_name == "lib64":
            continue
        if not stat.S_ISDIR(library_info.st_mode) or stat.S_ISLNK(library_info.st_mode) or library_info.st_uid != owner_uid or library_info.st_mode & 0o022:
            return None, "A virtual environment library directory is unsafe or not owned by the current user."
        try:
            with os.scandir(library) as entries:
                version_names: list[str] = []
                for entry in entries:
                    scanned += 1
                    if scanned > MAX_PACKAGE_METADATA_ENTRIES:
                        return None, "The virtual environment contains too many package metadata directories."
                    if re.fullmatch(r"python\d+(?:\.\d+)+", entry.name):
                        version_names.append(entry.name)
        except OSError as exc:
            return None, f"A virtual environment library directory could not be listed: {exc.strerror or type(exc).__name__}."
        for version_name in version_names:
            version_dir = library / version_name
            try:
                version_info = os.lstat(version_dir)
                site = version_dir / "site-packages"
                site_info = os.lstat(site)
            except FileNotFoundError:
                continue
            except OSError as exc:
                return None, f"A virtual environment package directory could not be inspected: {exc.strerror or type(exc).__name__}."
            if (
                not stat.S_ISDIR(version_info.st_mode)
                or stat.S_ISLNK(version_info.st_mode)
                or version_info.st_uid != owner_uid
                or version_info.st_mode & 0o022
                or not stat.S_ISDIR(site_info.st_mode)
                or stat.S_ISLNK(site_info.st_mode)
                or site_info.st_uid != owner_uid
                or site_info.st_mode & 0o022
            ):
                return None, "A virtual environment package directory is unsafe or not owned by the current user."
            site_directories.append(site)
    if not site_directories:
        return None, "No bounded virtual environment site-packages directory was found."

    packages: list[PythonEnvironmentPackageInfo] = []
    seen: set[str] = set()
    for site in site_directories:
        try:
            with os.scandir(site) as entries:
                metadata_names: list[str] = []
                for entry in entries:
                    scanned += 1
                    if scanned > MAX_PACKAGE_METADATA_ENTRIES:
                        return None, "The virtual environment contains too many package metadata entries."
                    if entry.name.endswith((".dist-info", ".egg-info")):
                        metadata_names.append(entry.name)
        except OSError as exc:
            return None, f"A virtual environment package directory could not be listed: {exc.strerror or type(exc).__name__}."
        for metadata_name in metadata_names:
            metadata_path = site / metadata_name
            try:
                metadata_info = os.lstat(metadata_path)
                is_dist_info = metadata_name.endswith(".dist-info")
                is_metadata_directory = stat.S_ISDIR(metadata_info.st_mode)
                if (
                    stat.S_ISLNK(metadata_info.st_mode)
                    or metadata_info.st_uid != owner_uid
                    or metadata_info.st_mode & 0o022
                    or (is_dist_info and not is_metadata_directory)
                    or (not is_dist_info and not is_metadata_directory and not stat.S_ISREG(metadata_info.st_mode))
                ):
                    return None, "A Python distribution metadata entry is unsafe or not owned by the current user."
                if is_metadata_directory:
                    metadata_file = metadata_path / ("METADATA" if is_dist_info else "PKG-INFO")
                else:
                    metadata_file = metadata_path
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(metadata_file, flags)
                try:
                    info = os.fstat(descriptor)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_size > MAX_PACKAGE_METADATA_BYTES:
                        return None, "A Python distribution metadata file is not a bounded regular file owned by the current user."
                    data = bytearray()
                    while len(data) <= MAX_PACKAGE_METADATA_BYTES:
                        chunk = os.read(descriptor, min(16 * 1024, MAX_PACKAGE_METADATA_BYTES + 1 - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                    if len(data) > MAX_PACKAGE_METADATA_BYTES:
                        return None, "A Python distribution metadata file exceeds the inspection limit."
                finally:
                    os.close(descriptor)
            except FileNotFoundError:
                return None, "A Python distribution metadata file is missing."
            except OSError as exc:
                return None, f"A Python distribution metadata file could not be read: {exc.strerror or type(exc).__name__}."
            try:
                lines = bytes(data).decode("utf-8", errors="strict").splitlines()
            except UnicodeDecodeError:
                return None, "A Python distribution metadata file is not valid UTF-8."
            name = next((line[6:].strip() for line in lines if line.casefold().startswith("name: ")), "")
            version = next((line[9:].strip() for line in lines if line.casefold().startswith("version: ")), "")
            if (
                not PACKAGE_NAME_RE.fullmatch(name)
                or not version
                or len(version) > 256
                or any(ord(char) < 32 or ord(char) == 127 for char in version)
            ):
                return None, "A Python distribution metadata entry has an invalid name or version."
            normalized = _canonical_package_name(name)
            if normalized in seen:
                return None, "The virtual environment contains duplicate normalized package names."
            seen.add(normalized)
            packages.append(PythonEnvironmentPackageInfo(name=name, version=version))
            if len(packages) > MAX_PACKAGES:
                return None, "The virtual environment package inventory exceeds the entry limit."
    packages.sort(key=lambda package: (package.name.casefold(), package.version))
    return tuple(packages), None


def _canonical_package_name(package_name: str) -> str:
    return re.sub(r"[-_.]+", "-", package_name).casefold()


def _capture_snapshot(
    action: str,
    environment_name: str,
    package_name: str = "",
    version: str = "",
) -> tuple[PythonEnvironmentSnapshot | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Python environment operations are available only on Linux."
    if not isinstance(environment_name, str) or not ENVIRONMENT_NAME_RE.fullmatch(environment_name):
        return None, "environment_name must be one managed name using letters, digits, dots, underscores, or hyphens."
    if not isinstance(package_name, str) or not isinstance(version, str):
        return None, "package_name and version must be text."
    if action not in {"create", "install", "upgrade", "uninstall", "list"}:
        return None, "Unsupported Python environment action."
    if action in {"install", "upgrade", "uninstall"} and not PACKAGE_NAME_RE.fullmatch(package_name):
        return None, "package_name must be one exact Python project name; URLs, paths, options, and requirement files are not accepted."
    if action in {"upgrade", "uninstall", "list"} and version:
        return None, "version is used only when installing a package."
    if version and not PACKAGE_VERSION_RE.fullmatch(version):
        return None, "version must be one exact version token; ranges, markers, URLs, and options are not accepted."

    env = _environment()
    home, home_info, error = _current_home()
    if error or home is None or home_info is None:
        return None, error or "The current user's home directory could not be verified."
    env["HOME"] = str(home)
    root = home / MANAGED_ROOT_NAME
    root_info, error = _safe_directory(root, owner_uid=os.getuid(), private=True)
    if error:
        return None, error
    environment_path = root / environment_name
    environment_info: os.stat_result | None = None
    config_sha256: str | None = None
    python_binary: str | None = None
    python_identity: tuple[int, ...] | None = None
    packages: tuple[PythonEnvironmentPackageInfo, ...] = ()

    if action == "create":
        if os.getuid() == 0 or os.geteuid() == 0 or os.getuid() != os.geteuid():
            return None, "Creating Python environments is limited to an unprivileged, non-root server identity."
        if root_info is not None:
            try:
                os.lstat(environment_path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                return None, f"The environment name could not be checked: {exc.strerror or type(exc).__name__}."
            else:
                return None, "That managed environment name already exists; create never overwrites an environment."
        binary, binary_identity, error = _discover_python3(env)
        if error or binary is None or binary_identity is None:
            return None, error or "The python3 executable could not be verified."
        output, error, truncated = run_bounded_command(
            [binary, "-I", "-c", "import venv, ensurepip"],
            env,
            command_label="Python venv module check",
            timeout_seconds=STATUS_TIMEOUT_SECONDS,
            max_output_bytes=64 * 1024,
        )
        if output is None or error or truncated:
            return None, "The installed Python does not provide both venv and ensurepip support."
        python_binary, python_identity = binary, binary_identity
    else:
        if root_info is None:
            return None, "No managed Python environments exist yet; create one first."
        environment_info, error = _safe_directory(environment_path, owner_uid=os.getuid())
        if error:
            return None, error
        if environment_info is None:
            return None, "The exact managed Python environment does not exist."
        if os.getuid() == 0 or os.geteuid() == 0 or os.getuid() != os.geteuid():
            return None, "Running pip or a virtual-environment interpreter is limited to an unprivileged, non-root server identity."
        config_sha256, base_home, error = _read_venv_config(environment_path)
        if error or config_sha256 is None or base_home is None:
            return None, error or "The virtual environment configuration could not be verified."
        binary_path = environment_path / "bin" / "python"
        resolved_binary, binary_identity, error = _python_identity(str(binary_path))
        if error or resolved_binary is None or binary_identity is None:
            return None, error or "The virtual environment's Python interpreter could not be verified."
        resolved_binary_path = Path(resolved_binary)
        try:
            resolved_binary_path.relative_to(environment_path.resolve(strict=True))
            interpreter_in_environment = True
        except (OSError, ValueError):
            try:
                resolved_binary_path.relative_to(base_home)
                interpreter_in_environment = True
            except ValueError:
                interpreter_in_environment = False
        if not interpreter_in_environment:
            return None, "The virtual environment's Python executable resolves outside its environment and configured base interpreter."
        binary = str(binary_path)
        package_inventory, error = _package_inventory(environment_path, owner_uid=os.getuid())
        if error or package_inventory is None:
            return None, error or "The Python package inventory could not be verified."
        packages = package_inventory
        installed_names = {_canonical_package_name(package.name) for package in packages}
        if action in {"install", "upgrade", "uninstall"} and "pip" not in installed_names:
            return None, "pip is not installed in the selected environment. Recreate the environment with a Python installation that provides ensurepip."
        python_binary, python_identity = binary, binary_identity

        normalized_name = _canonical_package_name(package_name) if package_name else ""
        installed = { _canonical_package_name(package.name): package.version for package in packages }
        if action == "install" and normalized_name in installed:
            return None, "That package is already installed; use upgrade or choose a new package name."
        if action in {"upgrade", "uninstall"} and normalized_name not in installed:
            return None, "That exact package is not installed in the selected environment."

    assert python_binary is not None and python_identity is not None
    package_material = [package.model_dump() for package in packages]
    package_inventory_sha256 = hashlib.sha256(
        json.dumps(package_material, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    root_identity = _identity(root_info) if root_info is not None else None
    environment_identity = _identity(environment_info) if environment_info is not None else None
    token_payload = {
        "action": action,
        "environment_name": environment_name,
        "package_name": package_name,
        "version": version,
        "home": str(home),
        "home_identity": _identity(home_info),
        "root_identity": root_identity,
        "environment_identity": environment_identity,
        "config_sha256": config_sha256,
        "python_binary": python_binary,
        "python_identity": python_identity,
        "package_inventory_sha256": package_inventory_sha256,
        "uid": os.getuid(),
        "euid": os.geteuid(),
    }
    state_token = hashlib.sha256(
        json.dumps(token_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return PythonEnvironmentSnapshot(
        action=action,
        environment_name=environment_name,
        package_name=package_name,
        version=version,
        home=home,
        home_identity=_identity(home_info),
        root=root,
        root_identity=root_identity,
        environment_path=environment_path,
        environment_identity=environment_identity,
        config_sha256=config_sha256,
        python_binary=python_binary,
        python_identity=python_identity,
        packages=packages,
        package_inventory_sha256=package_inventory_sha256,
        uid=os.getuid(),
        euid=os.geteuid(),
        state_token=state_token,
    ), None


def python_environment_action_confirmation_details(
    action: str,
    environment_name: str,
    package_name: str = "",
    version: str = "",
) -> PythonEnvironmentSnapshot | str:
    if action not in {"create", "install", "upgrade", "uninstall"}:
        return "Action must be create, install, upgrade, or uninstall."
    if action == "create" and (package_name or version):
        return "package_name and version must be empty when creating an environment."
    if action in {"upgrade", "uninstall"} and version:
        return "version is supported only for install."
    snapshot, error = _capture_snapshot(action, environment_name, package_name, version)
    if error or snapshot is None:
        return error or "The Python environment action could not be inspected."
    return snapshot


def _expected_package_state(
    action: PythonEnvironmentAction,
    package_name: str,
    version: str,
    packages: tuple[PythonEnvironmentPackageInfo, ...],
) -> bool:
    normalized = _canonical_package_name(package_name)
    installed = {
        _canonical_package_name(package.name): package.version
        for package in packages
    }
    actual_version = installed.get(normalized)
    if action == "uninstall":
        return actual_version is None
    if action == "install" and version:
        return actual_version == version
    return actual_version is not None


def _pip_command(snapshot: PythonEnvironmentSnapshot, action: PythonEnvironmentAction) -> list[str]:
    common = [
        snapshot.python_binary,
        "-I",
        "-m",
        "pip",
        "--disable-pip-version-check",
        "--no-input",
        "--no-color",
    ]
    if action == "install":
        specifier = f"{snapshot.package_name}=={snapshot.version}" if snapshot.version else snapshot.package_name
        return common + [
            "install",
            "--no-warn-script-location",
            "--progress-bar",
            "off",
            specifier,
        ]
    if action == "upgrade":
        return common + [
            "install",
            "--upgrade",
            "--no-warn-script-location",
            "--progress-bar",
            "off",
            snapshot.package_name,
        ]
    return common + ["uninstall", "--yes", snapshot.package_name]


def _ensure_managed_root(snapshot: PythonEnvironmentSnapshot) -> str | None:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    home_fd: int | None = None
    root_fd: int | None = None
    try:
        home_fd = os.open(snapshot.home, directory_flags)
        home_info = os.fstat(home_fd)
        if _identity(home_info) != snapshot.home_identity:
            return "The current user's home directory changed after confirmation."
        if snapshot.root_identity is None:
            try:
                os.mkdir(MANAGED_ROOT_NAME, 0o700, dir_fd=home_fd)
            except FileExistsError:
                return "The managed environment directory appeared after confirmation; review and confirm again."
        root_fd = os.open(MANAGED_ROOT_NAME, directory_flags, dir_fd=home_fd)
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != snapshot.uid or root_info.st_mode & 0o077:
            return "The managed environment directory is not private to the current user."
        if snapshot.root_identity is not None and _identity(root_info) != snapshot.root_identity:
            return "The managed environment directory changed after confirmation."
        if snapshot.root_identity is None:
            os.fchmod(root_fd, 0o700)
        try:
            os.stat(snapshot.environment_name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        return "The environment name appeared after confirmation; review and confirm again."
    except OSError as exc:
        return f"The managed environment directory could not be revalidated: {exc.strerror or type(exc).__name__}."
    finally:
        for descriptor in (root_fd, home_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _response(
    action: PythonEnvironmentAction,
    environment_name: str,
    package_name: str,
    version: str,
    *,
    success: bool,
    confirmed: bool,
    state_verified: bool = False,
    return_code: int | None = None,
    timed_out: bool = False,
    message: str,
) -> PythonEnvironmentActionResponse:
    return PythonEnvironmentActionResponse(
        success=success,
        action=action,
        environment_name=environment_name,
        package_name=package_name or None,
        version=version or None,
        state_verified=state_verified,
        return_code=return_code,
        timed_out=timed_out,
        user_confirmed=confirmed,
        message=message,
    )


def perform_python_environment_action(
    action: str,
    environment_name: str,
    package_name: str = "",
    version: str = "",
    expected_state_token: str = "",
    *,
    confirmed: bool = False,
) -> PythonEnvironmentActionResponse:
    actions = {"create", "install", "upgrade", "uninstall"}
    valid_action = isinstance(action, str) and action in actions
    safe_action: PythonEnvironmentAction = action if valid_action else "create"
    safe_environment_name = environment_name[:64] if isinstance(environment_name, str) else ""
    safe_package_name = package_name[:128] if isinstance(package_name, str) else ""
    safe_version = version[:128] if isinstance(version, str) else ""
    if not valid_action:
        return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=False, confirmed=False, message="Unsupported Python environment action; no command was run.")
    if confirmed is not True:
        return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=False, confirmed=False, message="Explicit MCP client confirmation is required; no Python environment command was run.")
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=False, confirmed=True, message="A valid state token from the exact Python environment confirmation is required; no change was made.")
    expected = python_environment_action_confirmation_details(action, environment_name, package_name, version)
    if isinstance(expected, str):
        return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=False, confirmed=True, message=expected)
    if expected.state_token != expected_state_token:
        return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=False, confirmed=True, message="The selected Python environment or package inventory changed after confirmation; review and confirm again.")
    if (os.getuid(), os.geteuid()) != (expected.uid, expected.euid) or os.getuid() == 0 or os.geteuid() == 0:
        return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=False, confirmed=True, message="Python environment mutations require the same unprivileged, non-root server identity used at confirmation.")

    env = _environment()
    env["HOME"] = str(expected.home)
    if action == "create":
        root_error = _ensure_managed_root(expected)
        if root_error:
            return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=False, confirmed=True, message=f"{root_error} No virtual environment was created.")
        command = [expected.python_binary, "-I", "-m", "venv", str(expected.environment_path)]
        timeout = CREATE_TIMEOUT_SECONDS
        command_label = "Python virtual-environment creation"
    else:
        command = _pip_command(expected, action)
        timeout = TRANSACTION_TIMEOUT_SECONDS
        command_label = "pip package transaction"
    output, error, truncated = run_bounded_command(
        command,
        env,
        command_label=command_label,
        timeout_seconds=timeout,
        max_output_bytes=MAX_TRANSACTION_OUTPUT_BYTES,
        kill_process_group=True,
    )
    if error or output is None or truncated:
        timed_out = bool(error and "timed out after" in error)
        note = "Command output is withheld because it can contain package or environment details."
        if timed_out:
            message = f"The {command_label} exceeded its {timeout}-second limit and was asked to stop. Environment state may be incomplete; inspect it before retrying. {note}"
        else:
            message = f"The {command_label} did not complete successfully. Inspect the environment before retrying. {note}"
        return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=False, confirmed=True, timed_out=timed_out, message=message)

    verified, verification_error = _capture_snapshot("list", environment_name)
    if verification_error or verified is None:
        return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=False, confirmed=True, return_code=0, message="The command completed, but the managed environment could not be verified afterward. Inspect it before retrying.")
    state_verified = action == "create" or _expected_package_state(action, package_name, version, verified.packages)
    if not state_verified:
        return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=False, confirmed=True, return_code=0, state_verified=False, message="The command completed, but the requested package state was not present afterward. Inspect the environment before retrying.")
    return _response(safe_action, safe_environment_name, safe_package_name, safe_version, success=True, confirmed=True, return_code=0, state_verified=True, message="The confirmed Python environment action completed and its resulting state was verified. Command output was withheld.")


def list_python_environments(limit: int = 100) -> PythonEnvironmentListResponse:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_ENVIRONMENTS:
        return PythonEnvironmentListResponse(success=False, message=f"limit must be from 1 through {MAX_ENVIRONMENTS}.")
    home, _home_info, error = _current_home()
    if error or home is None:
        return PythonEnvironmentListResponse(success=False, message=error or "The current user's home directory could not be verified.")
    root = home / MANAGED_ROOT_NAME
    root_info, error = _safe_directory(root, owner_uid=os.getuid(), private=True)
    if error:
        return PythonEnvironmentListResponse(success=False, message=error)
    if root_info is None:
        return PythonEnvironmentListResponse(success=True, message="No Linux MCP-managed Python virtual environments exist yet.")
    environments: list[PythonEnvironmentInfo] = []
    total_valid = 0
    skipped = 0
    try:
        with os.scandir(root) as scan:
            entry_names: list[str] = []
            directory_truncated = False
            for entry in scan:
                if len(entry_names) >= MAX_ENVIRONMENT_DIRECTORY_ENTRIES:
                    directory_truncated = True
                    break
                entry_names.append(entry.name)
        entry_names.sort(key=str.casefold)
    except OSError as exc:
        return PythonEnvironmentListResponse(success=False, message=f"The managed environment directory could not be listed: {exc.strerror or type(exc).__name__}.")
    for entry_name in entry_names:
        if not ENVIRONMENT_NAME_RE.fullmatch(entry_name):
            skipped += 1
            continue
        try:
            info = os.lstat(root / entry_name)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
                skipped += 1
                continue
            env_path = root / entry_name
            cfg = env_path / "pyvenv.cfg"
            python = env_path / "bin" / "python"
            cfg_info = os.lstat(cfg)
            python_info = os.stat(python)
            if not stat.S_ISREG(cfg_info.st_mode) or cfg_info.st_uid != os.getuid() or not stat.S_ISREG(python_info.st_mode) or not os.access(python, os.X_OK):
                skipped += 1
                continue
            total_valid += 1
            if len(environments) < limit:
                environments.append(PythonEnvironmentInfo(environment_name=entry_name, python_available=True))
        except OSError:
            skipped += 1
    return PythonEnvironmentListResponse(
        success=True,
        total_environments=total_valid,
        returned_environments=len(environments),
        environments=environments,
        limit=limit,
        truncated=directory_truncated or total_valid > limit,
        skipped_entries=skipped,
        message=(
            f"Skipped {skipped} unsafe or incomplete directory entries."
            if skipped
            else f"Only the first {MAX_ENVIRONMENT_DIRECTORY_ENTRIES} directory entries were inspected."
            if directory_truncated
            else None
        ),
    )


def list_python_environment_packages(environment_name: str, limit: int = 100) -> PythonEnvironmentPackageListResponse:
    if not isinstance(environment_name, str):
        environment_name = ""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PACKAGES:
        return PythonEnvironmentPackageListResponse(
            success=False,
            environment_name=environment_name[:64],
            limit=MAX_PACKAGES,
            message=f"limit must be from 1 through {MAX_PACKAGES}.",
        )
    snapshot, error = _capture_snapshot("list", environment_name)
    if error or snapshot is None:
        return PythonEnvironmentPackageListResponse(
            success=False,
            environment_name=environment_name[:64],
            message=error or "The exact managed Python environment could not be inspected.",
        )
    return PythonEnvironmentPackageListResponse(
        success=True,
        environment_name=environment_name,
        total_packages=len(snapshot.packages),
        returned_packages=min(limit, len(snapshot.packages)),
        packages=list(snapshot.packages[:limit]),
        limit=limit,
        truncated=len(snapshot.packages) > limit,
        message="Package names and versions were read from bounded distribution metadata without executing environment package code.",
    )


def python_environment_readiness(env: dict[str, str] | None = None) -> PythonEnvironmentReadiness:
    if not sys.platform.startswith("linux"):
        return PythonEnvironmentReadiness(False, None, "Python virtual-environment tools are available only on Linux.", None, None)
    child_env = _environment() if env is None else dict(env)
    binary, _identity_value, error = _discover_python3(child_env)
    if error or binary is None:
        return PythonEnvironmentReadiness(False, None, error or "The python3 executable is unavailable.", "python3", None)
    output, error, truncated = run_bounded_command(
        [binary, "-I", "-c", "import venv, ensurepip"],
        child_env,
        command_label="Python venv readiness check",
        timeout_seconds=STATUS_TIMEOUT_SECONDS,
        max_output_bytes=64 * 1024,
    )
    if output is None or error or truncated:
        return PythonEnvironmentReadiness(False, binary, "The python3 executable is present, but its venv/ensurepip support is unavailable.", "python3 venv and ensurepip modules (often packaged separately)", None)
    if os.geteuid() == 0 or os.getuid() == 0 or os.getuid() != os.geteuid():
        return PythonEnvironmentReadiness(False, binary, "Package environment mutations are restricted to an unprivileged, non-root server identity because pip may execute package build code.", None, "A non-root server identity with matching real and effective UIDs")
    return PythonEnvironmentReadiness(True, binary, None, None, None)
