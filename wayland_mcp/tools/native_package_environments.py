"""Confirmed, current-user npm and Cargo package environments."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    NativeEnvironmentPackageInfo,
    NativeEnvironmentPackageListResponse,
    NativePackageEnvironmentActionResponse,
    NativePackageEnvironmentInfo,
    NativePackageEnvironmentListResponse,
)
from wayland_mcp.session import get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

NativeEcosystem = Literal["npm", "cargo"]
NativeAction = Literal["create", "install", "upgrade", "uninstall"]
ECOSYSTEMS = {"npm", "cargo"}
ACTIONS = {"create", "install", "upgrade", "uninstall"}
ENVIRONMENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
NPM_NAME_RE = re.compile(r"^(?:[a-z0-9][a-z0-9._-]{0,213}|@[a-z0-9][a-z0-9._-]{0,99}/[a-z0-9][a-z0-9._-]{0,99})$")
CARGO_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
PACKAGE_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
ROOT_NAMES = {"npm": ".linux-mcp-npm-prefixes", "cargo": ".linux-mcp-cargo-roots"}
MAX_ENVIRONMENTS = 100
MAX_DIRECTORY_ENTRIES = 20_000
MAX_PACKAGES = 10_000
MAX_PACKAGE_JSON_BYTES = 256 * 1024
MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024
STATUS_TIMEOUT_SECONDS = 20
ACTION_TIMEOUT_SECONDS = 30 * 60


@dataclass(frozen=True, slots=True)
class NativePackageSnapshot:
    ecosystem: NativeEcosystem
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
    npm_cache_identity: tuple[int, ...] | None
    manager_binary: str
    manager_identity: tuple[int, ...]
    runtime_binary: str | None
    runtime_identity: tuple[int, ...] | None
    packages: tuple[NativeEnvironmentPackageInfo, ...]
    package_inventory_sha256: str
    uid: int
    euid: int
    state_token: str


@dataclass(frozen=True, slots=True)
class NativeEnvironmentReadiness:
    npm_available: bool
    cargo_available: bool
    mutation_available: bool
    reason: str | None


def _safe_path(env: dict[str, str] | None = None) -> str:
    source = get_sanitized_env(dict(os.environ)) if env is None else env
    return os.pathsep.join(
        component
        for component in source.get("PATH", "").split(os.pathsep)
        if component and Path(component).is_absolute()
    )


def native_package_environment_readiness(env: dict[str, str] | None = None) -> NativeEnvironmentReadiness:
    if not sys.platform.startswith("linux"):
        return NativeEnvironmentReadiness(False, False, False, "Managed npm and Cargo environments are available only on Linux.")
    child_env = get_sanitized_env(dict(os.environ)) if env is None else env
    path = _safe_path(child_env)
    npm_available = bool(shutil.which("npm", path=path) and shutil.which("node", path=path))
    cargo_available = bool(shutil.which("cargo", path=path))
    mutation_available = (npm_available or cargo_available) and os.getuid() != 0 and os.geteuid() != 0 and os.getuid() == os.geteuid()
    if not npm_available and not cargo_available:
        reason = "Neither the npm/node pair nor Cargo is available on the sanitized PATH."
    elif not mutation_available:
        reason = "Package environment mutations require the current server to run with matching non-root real and effective UIDs."
    else:
        ready = []
        if npm_available:
            ready.append("npm with node")
        if cargo_available:
            ready.append("Cargo")
        reason = f"Managed current-user environments are available for {', '.join(ready)}; package installation may download sources and run build or lifecycle code."
    return NativeEnvironmentReadiness(npm_available, cargo_available, mutation_available, reason)


def _environment(home: Path) -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["PATH"] = _safe_path(env)
    env["HOME"] = str(home)
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["TERM"] = "dumb"
    env["NPM_CONFIG_USERCONFIG"] = os.devnull
    env["NPM_CONFIG_GLOBALCONFIG"] = os.devnull
    env["NPM_CONFIG_UPDATE_NOTIFIER"] = "false"
    env["NPM_CONFIG_AUDIT"] = "false"
    env["NPM_CONFIG_FUND"] = "false"
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
        return None, None, "Managed npm and Cargo environments are available only on Linux."
    try:
        account = pwd.getpwuid(os.getuid())
        home = Path(account.pw_dir).resolve(strict=True)
        info = os.stat(home, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            return None, None, "The current user's home directory is not an owned directory."
        if info.st_mode & 0o022:
            return None, None, "The current user's home directory is writable by another account."
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
    if info.st_uid != owner_uid or info.st_mode & (0o077 if private else 0o022):
        return None, (
            "The managed environment root must belong to the current user and be private to that account."
            if private
            else "Managed environments must belong to the current user and must not be group/world writable."
        )
    return info, None


def _bounded_directory_entries(path: Path) -> tuple[list[os.DirEntry[str]] | None, str | None]:
    try:
        with os.scandir(path) as scan:
            entries: list[os.DirEntry[str]] = []
            for entry in scan:
                entries.append(entry)
                if len(entries) > MAX_DIRECTORY_ENTRIES:
                    return None, "The managed package directory contains too many entries."
    except OSError as exc:
        return None, f"The managed package directory could not be listed: {exc.strerror or type(exc).__name__}."
    entries.sort(key=lambda entry: entry.name.casefold())
    return entries, None


def _manager(ecosystem: NativeEcosystem) -> tuple[str | None, tuple[int, ...] | None, str | None]:
    safe_path = _safe_path()
    candidate = shutil.which(ecosystem, path=safe_path) if safe_path else None
    if not candidate:
        return None, None, f"The {ecosystem} executable is unavailable."
    try:
        resolved = Path(candidate).resolve(strict=True)
        info = os.stat(resolved, follow_symlinks=False)
        allowed_owners = {0} if os.geteuid() == 0 else {0, os.getuid()}
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in allowed_owners
            or info.st_mode & 0o6022
            or not os.access(resolved, os.X_OK)
        ):
            return None, None, f"The {ecosystem} executable is not an executable regular file."
        return candidate, _identity(info), None
    except (OSError, RuntimeError, ValueError) as exc:
        return None, None, f"The {ecosystem} executable could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."


def _node_runtime() -> tuple[str | None, tuple[int, ...] | None, str | None]:
    safe_path = _safe_path()
    candidate = shutil.which("node", path=safe_path) if safe_path else None
    if not candidate:
        return None, None, "The node executable is unavailable."
    try:
        resolved = Path(candidate).resolve(strict=True)
        info = os.stat(resolved, follow_symlinks=False)
        allowed_owners = {0} if os.geteuid() == 0 else {0, os.getuid()}
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in allowed_owners
            or info.st_mode & 0o6022
            or not os.access(resolved, os.X_OK)
        ):
            return None, None, "The node executable is not an executable regular file."
        return candidate, _identity(info), None
    except (OSError, RuntimeError, ValueError) as exc:
        return None, None, f"The node executable could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."


def _canonical_name(ecosystem: NativeEcosystem, name: str) -> str:
    return name.casefold() if ecosystem == "npm" else name.casefold().replace("_", "-")


def _read_package_json(path: Path, owner_uid: int) -> tuple[NativeEnvironmentPackageInfo | None, str | None]:
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022 or info.st_size > MAX_PACKAGE_JSON_BYTES:
            return None, "An npm package manifest is unsafe or exceeds the inspection limit."
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if _identity(opened) != _identity(info):
                return None, "An npm package manifest changed while it was being inspected."
            data = bytearray()
            while len(data) <= MAX_PACKAGE_JSON_BYTES:
                chunk = os.read(descriptor, min(16 * 1024, MAX_PACKAGE_JSON_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > MAX_PACKAGE_JSON_BYTES:
                return None, "An npm package manifest exceeds the inspection limit."
        finally:
            os.close(descriptor)
    except OSError as exc:
        return None, f"An npm package manifest could not be read: {exc.strerror or type(exc).__name__}."
    try:
        value = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "An npm package manifest is not valid bounded UTF-8 JSON."
    if not isinstance(value, dict):
        return None, "An npm package manifest has an unsupported structure."
    name, version = value.get("name"), value.get("version")
    if not isinstance(name, str) or not NPM_NAME_RE.fullmatch(name) or not isinstance(version, str) or not version or len(version) > 256 or any(ord(ch) < 32 or ord(ch) == 127 for ch in version):
        return None, "An npm package manifest has an invalid name or version."
    return NativeEnvironmentPackageInfo(name=name, version=version), None


def _npm_packages(environment_path: Path, owner_uid: int) -> tuple[tuple[NativeEnvironmentPackageInfo, ...] | None, str | None]:
    library = environment_path / "lib"
    library_info, error = _safe_directory(library, owner_uid=owner_uid)
    if error:
        return None, error
    if library_info is None:
        return (), None
    node_modules = environment_path / "lib" / "node_modules"
    info, error = _safe_directory(node_modules, owner_uid=owner_uid)
    if error:
        return None, error
    if info is None:
        return (), None
    packages: list[NativeEnvironmentPackageInfo] = []
    inspected = 0
    entries, error = _bounded_directory_entries(node_modules)
    if error or entries is None:
        return None, error or "The npm package directory could not be listed."
    for entry in entries:
        if entry.name.startswith("."):
            continue
        try:
            entry_info = os.lstat(entry.path)
        except OSError as exc:
            return None, f"An npm package entry could not be inspected: {exc.strerror or type(exc).__name__}."
        if entry.name.startswith("@"):
            if not NPM_NAME_RE.fullmatch(entry.name + "/package") or not stat.S_ISDIR(entry_info.st_mode) or stat.S_ISLNK(entry_info.st_mode) or entry_info.st_uid != owner_uid or entry_info.st_mode & 0o022:
                return None, "An npm scope directory is unsafe or malformed."
            scoped_entries, error = _bounded_directory_entries(Path(entry.path))
            if error or scoped_entries is None:
                return None, error or "An npm scope directory could not be listed."
            package_entries = [(child, f"{entry.name}/{child.name}") for child in scoped_entries]
        else:
            package_entries = [(entry, entry.name)]
        for package_entry, expected_name in package_entries:
            inspected += 1
            if inspected > MAX_DIRECTORY_ENTRIES:
                return None, "The npm environment contains too many package entries."
            try:
                package_info = os.lstat(package_entry.path)
            except OSError as exc:
                return None, f"An npm package directory could not be inspected: {exc.strerror or type(exc).__name__}."
            if not stat.S_ISDIR(package_info.st_mode) or stat.S_ISLNK(package_info.st_mode) or package_info.st_uid != owner_uid or package_info.st_mode & 0o022:
                return None, "An npm package directory is unsafe or not owned by the current user."
            package, error = _read_package_json(Path(package_entry.path) / "package.json", owner_uid)
            if error or package is None:
                return None, error or "An npm package manifest could not be inspected."
            if package.name != expected_name:
                return None, "An npm package manifest name does not match its exact installation path."
            packages.append(package)
            if len(packages) > MAX_PACKAGES:
                return None, "The npm package inventory exceeds the entry limit."
    packages.sort(key=lambda package: (package.name.casefold(), package.version))
    return tuple(packages), None


def _validate_cargo_root(environment_path: Path, owner_uid: int) -> str | None:
    binary_directory, error = _safe_directory(environment_path / "bin", owner_uid=owner_uid)
    if error:
        return error
    for metadata_name in (".crates.toml", ".crates2.json"):
        path = environment_path / metadata_name
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            return f"Cargo install metadata could not be inspected: {exc.strerror or type(exc).__name__}."
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022 or info.st_size > MAX_COMMAND_OUTPUT_BYTES:
            return "Cargo install metadata must be a bounded regular file owned by the current user."
    return None


def _cargo_packages(
    manager_binary: str,
    environment_path: Path,
    home: Path,
) -> tuple[tuple[NativeEnvironmentPackageInfo, ...] | None, str | None]:
    with tempfile.TemporaryDirectory(prefix="linux-mcp-cargo-") as cargo_home:
        env = _environment(home)
        env["CARGO_HOME"] = cargo_home
        env["CARGO_TARGET_DIR"] = str(Path(cargo_home) / "target")
        output, error, truncated = run_bounded_command(
            [manager_binary, "install", "--list", "--root", str(environment_path)],
            env,
            command_label="Cargo installed-package inventory",
            timeout_seconds=STATUS_TIMEOUT_SECONDS,
            max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
            cwd="/",
        )
    if output is None or error or truncated:
        return None, "The installed Cargo package inventory could not be inspected exactly."
    packages: list[NativeEnvironmentPackageInfo] = []
    current_package: NativeEnvironmentPackageInfo | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.casefold() in {"nothing installed", "no packages installed"} or line.startswith("warning:"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_-]{0,63}) v([^\s:]{1,256}):", line)
        if match:
            current_package = NativeEnvironmentPackageInfo(name=match.group(1), version=match.group(2))
            packages.append(current_package)
            if len(packages) > MAX_PACKAGES:
                return None, "The Cargo package inventory exceeds the entry limit."
            continue
        if raw_line[:1].isspace() and current_package is not None:
            continue
        return None, "Cargo returned an unsupported package-list format."
    names = [_canonical_name("cargo", package.name) for package in packages]
    if len(names) != len(set(names)):
        return None, "The Cargo package inventory contains duplicate crate names."
    packages.sort(key=lambda package: (package.name.casefold(), package.version))
    return tuple(packages), None


def _capture_snapshot(
    ecosystem: NativeEcosystem,
    action: str,
    environment_name: str,
    package_name: str = "",
    version: str = "",
) -> tuple[NativePackageSnapshot | None, str | None]:
    if not isinstance(ecosystem, str) or ecosystem not in ECOSYSTEMS:
        return None, "ecosystem must be npm or cargo."
    if not isinstance(action, str):
        return None, "Unsupported native package environment action."
    if not isinstance(environment_name, str) or not ENVIRONMENT_NAME_RE.fullmatch(environment_name):
        return None, "environment_name must use letters, digits, dots, underscores, or hyphens."
    if action not in ACTIONS | {"inventory"}:
        return None, "Unsupported native package environment action."
    if not isinstance(package_name, str) or not isinstance(version, str):
        return None, "package_name and version must be text."
    if action == "create" and (package_name or version):
        return None, "package_name and version must be empty when creating an environment."
    if action in {"inventory", "create", "upgrade", "uninstall"} and version:
        return None, "version is supported only for install."
    name_pattern = NPM_NAME_RE if ecosystem == "npm" else CARGO_NAME_RE
    if action in {"install", "upgrade", "uninstall"} and not name_pattern.fullmatch(package_name):
        return None, "package_name must be one exact npm package or crates.io crate name; URLs, paths, git sources, and options are not accepted."
    if action == "install" and version and not PACKAGE_VERSION_RE.fullmatch(version):
        return None, "version must be one exact semantic version; ranges, tags, URLs, and options are not accepted."

    home, home_info, error = _current_home()
    if error or home is None or home_info is None:
        return None, error or "The current user's home directory could not be verified."
    root = home / ROOT_NAMES[ecosystem]
    root_info, error = _safe_directory(root, owner_uid=os.getuid(), private=True)
    if error:
        return None, error
    environment_path = root / environment_name
    environment_info = None
    npm_cache_identity = None
    if action == "create":
        if os.getuid() == 0 or os.geteuid() == 0 or os.getuid() != os.geteuid():
            return None, "Native package environments are limited to an unprivileged, non-root server identity."
        if root_info is not None:
            try:
                os.lstat(environment_path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                return None, f"The environment name could not be checked: {exc.strerror or type(exc).__name__}."
            else:
                return None, "That managed environment name already exists; create never overwrites an environment."
    else:
        if root_info is None:
            return None, "No managed environments exist for this package ecosystem yet; create one first."
        environment_info, error = _safe_directory(environment_path, owner_uid=os.getuid(), private=True)
        if error:
            return None, error
        if environment_info is None:
            return None, "The exact managed package environment does not exist."
        if ecosystem == "npm":
            cache_info, error = _safe_directory(environment_path / ".npm-cache", owner_uid=os.getuid(), private=True)
            if error:
                return None, error
            npm_cache_identity = _identity(cache_info) if cache_info is not None else None
        else:
            error = _validate_cargo_root(environment_path, os.getuid())
            if error:
                return None, error
        if action not in {"inventory"} and (os.getuid() == 0 or os.geteuid() == 0 or os.getuid() != os.geteuid()):
            return None, "Native package mutations require the same unprivileged, non-root server identity used at confirmation."

    manager_binary, manager_identity, manager_error = _manager(ecosystem)
    runtime_binary = None
    runtime_identity = None
    if ecosystem == "npm":
        runtime_binary, runtime_identity, runtime_error = _node_runtime()
        if manager_error or manager_binary is None or runtime_error or runtime_binary is None:
            return None, manager_error or runtime_error or "The npm and node executables could not be verified."
    elif manager_error or manager_binary is None:
        return None, manager_error or "The cargo executable could not be verified."
    assert manager_identity is not None
    if ecosystem == "npm":
        assert runtime_identity is not None

    packages: tuple[NativeEnvironmentPackageInfo, ...] = ()
    if action != "create":
        if ecosystem == "npm":
            packages, error = _npm_packages(environment_path, os.getuid())
        else:
            packages, error = _cargo_packages(manager_binary, environment_path, home)
        if error or packages is None:
            return None, error or "The native package inventory could not be inspected."
        installed = {_canonical_name(ecosystem, package.name): package.version for package in packages}
        normalized_name = _canonical_name(ecosystem, package_name) if package_name else ""
        if action == "install" and normalized_name in installed:
            return None, "That exact package is already installed in this managed environment; use upgrade or choose another name."
        if action in {"upgrade", "uninstall"} and normalized_name not in installed:
            return None, "That exact package is not installed in the selected managed environment."

    inventory = [package.model_dump() for package in packages]
    inventory_sha256 = hashlib.sha256(json.dumps(inventory, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    root_identity = _identity(root_info) if root_info is not None else None
    environment_identity = _identity(environment_info) if environment_info is not None else None
    token_payload = {
        "ecosystem": ecosystem,
        "action": action,
        "environment_name": environment_name,
        "package_name": package_name,
        "version": version,
        "home": str(home),
        "home_identity": _identity(home_info),
        "root_identity": root_identity,
        "environment_identity": environment_identity,
        "npm_cache_identity": npm_cache_identity,
        "manager_binary": manager_binary,
        "manager_identity": manager_identity,
        "runtime_binary": runtime_binary,
        "runtime_identity": runtime_identity,
        "package_inventory_sha256": inventory_sha256,
        "uid": os.getuid(),
        "euid": os.geteuid(),
    }
    state_token = hashlib.sha256(json.dumps(token_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return NativePackageSnapshot(
        ecosystem=ecosystem,
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
        npm_cache_identity=npm_cache_identity,
        manager_binary=manager_binary,
        manager_identity=manager_identity,
        runtime_binary=runtime_binary,
        runtime_identity=runtime_identity,
        packages=packages,
        package_inventory_sha256=inventory_sha256,
        uid=os.getuid(),
        euid=os.geteuid(),
        state_token=state_token,
    ), None


def native_package_action_confirmation_details(
    ecosystem: str,
    action: str,
    environment_name: str,
    package_name: str = "",
    version: str = "",
) -> NativePackageSnapshot | str:
    if not isinstance(ecosystem, str) or ecosystem not in ECOSYSTEMS:
        return "ecosystem must be npm or cargo."
    if not isinstance(action, str) or action not in ACTIONS:
        return "Action must be create, install, upgrade, or uninstall."
    snapshot, error = _capture_snapshot(ecosystem, action, environment_name, package_name, version)
    if error or snapshot is None:
        return error or "The exact native package environment action could not be inspected."
    return snapshot


def _secure_create_environment(snapshot: NativePackageSnapshot) -> str | None:
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    home_fd: int | None = None
    root_fd: int | None = None
    environment_fd: int | None = None
    root_name = ROOT_NAMES[snapshot.ecosystem]
    try:
        home_fd = os.open(snapshot.home, directory_flags)
        if _identity(os.fstat(home_fd)) != snapshot.home_identity:
            return "The current user's home directory changed after confirmation."
        if snapshot.root_identity is None:
            try:
                os.mkdir(root_name, 0o700, dir_fd=home_fd)
            except FileExistsError:
                return "The managed environment root appeared after confirmation; review and confirm again."
        root_fd = os.open(root_name, directory_flags, dir_fd=home_fd)
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != snapshot.uid or root_info.st_mode & 0o077:
            return "The managed environment root is not private to the current user."
        if snapshot.root_identity is not None and _identity(root_info) != snapshot.root_identity:
            return "The managed environment root changed after confirmation."
        if snapshot.root_identity is None:
            os.fchmod(root_fd, 0o700)
        try:
            os.mkdir(snapshot.environment_name, 0o700, dir_fd=root_fd)
        except FileExistsError:
            return "The environment name appeared after confirmation; review and confirm again."
        environment_fd = os.open(snapshot.environment_name, directory_flags, dir_fd=root_fd)
        environment_info = os.fstat(environment_fd)
        if not stat.S_ISDIR(environment_info.st_mode) or environment_info.st_uid != snapshot.uid or environment_info.st_mode & 0o077:
            return "The new environment directory is not private to the current user."
        return None
    except OSError as exc:
        return f"The managed environment could not be created safely: {exc.strerror or type(exc).__name__}."
    finally:
        for descriptor in (environment_fd, root_fd, home_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _ensure_npm_cache(snapshot: NativePackageSnapshot) -> str | None:
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    home_fd: int | None = None
    root_fd: int | None = None
    environment_fd: int | None = None
    cache_fd: int | None = None
    try:
        home_fd = os.open(snapshot.home, directory_flags)
        if _identity(os.fstat(home_fd)) != snapshot.home_identity:
            return "The current user's home directory changed after confirmation."
        root_fd = os.open(ROOT_NAMES[snapshot.ecosystem], directory_flags, dir_fd=home_fd)
        root_info = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != snapshot.uid
            or root_info.st_mode & 0o077
            or _identity(root_info) != snapshot.root_identity
        ):
            return "The managed npm environment root changed after confirmation."
        environment_fd = os.open(snapshot.environment_name, directory_flags, dir_fd=root_fd)
        environment_info = os.fstat(environment_fd)
        if _identity(environment_info) != snapshot.environment_identity:
            return "The npm prefix changed after confirmation."
        if snapshot.npm_cache_identity is None:
            try:
                os.mkdir(".npm-cache", 0o700, dir_fd=environment_fd)
            except FileExistsError:
                return "The npm cache directory appeared after confirmation; review and confirm again."
        cache_fd = os.open(".npm-cache", directory_flags, dir_fd=environment_fd)
        cache_info = os.fstat(cache_fd)
        if not stat.S_ISDIR(cache_info.st_mode) or cache_info.st_uid != snapshot.uid or cache_info.st_mode & 0o077:
            return "The npm cache directory is not private to the current user."
        if snapshot.npm_cache_identity is not None and _identity(cache_info) != snapshot.npm_cache_identity:
            return "The npm cache directory changed after confirmation."
        return None
    except OSError as exc:
        return f"The npm cache directory could not be validated: {exc.strerror or type(exc).__name__}."
    finally:
        for descriptor in (cache_fd, environment_fd, root_fd, home_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _command(snapshot: NativePackageSnapshot) -> list[str]:
    if snapshot.ecosystem == "npm":
        common = [snapshot.manager_binary, "--global", "--prefix", str(snapshot.environment_path), "--no-audit", "--no-fund", "--no-progress", "--registry=https://registry.npmjs.org/"]
        if snapshot.action == "uninstall":
            return [snapshot.manager_binary, "uninstall", *common[1:], snapshot.package_name]
        specifier = snapshot.package_name
        if snapshot.action == "upgrade":
            specifier += "@latest"
        elif snapshot.version:
            specifier += "@" + snapshot.version
        return [snapshot.manager_binary, "install", *common[1:], specifier]
    if snapshot.action == "uninstall":
        return [snapshot.manager_binary, "uninstall", "--root", str(snapshot.environment_path), snapshot.package_name]
    command = [snapshot.manager_binary, "install", "--root", str(snapshot.environment_path)]
    if snapshot.version:
        command.extend(["--version", snapshot.version])
    command.append(snapshot.package_name)
    return command


def _run_snapshot_command(
    snapshot: NativePackageSnapshot,
    command: list[str],
    *,
    timeout: int,
    label: str,
) -> tuple[str | None, str | None, bool]:
    env = _environment(snapshot.home)
    if snapshot.ecosystem == "npm":
        env["NPM_CONFIG_CACHE"] = str(snapshot.environment_path / ".npm-cache")
        return run_bounded_command(command, env, command_label=label, timeout_seconds=timeout, max_output_bytes=MAX_COMMAND_OUTPUT_BYTES, cwd="/", kill_process_group=True)
    with tempfile.TemporaryDirectory(prefix="linux-mcp-cargo-") as cargo_home:
        env["CARGO_HOME"] = cargo_home
        env["CARGO_TARGET_DIR"] = str(Path(cargo_home) / "target")
        return run_bounded_command(command, env, command_label=label, timeout_seconds=timeout, max_output_bytes=MAX_COMMAND_OUTPUT_BYTES, cwd="/", kill_process_group=True)


def _response(
    ecosystem: NativeEcosystem,
    action: NativeAction,
    environment_name: str,
    package_name: str,
    version: str,
    *,
    success: bool,
    confirmed: bool,
    state_verified: bool = False,
    timed_out: bool = False,
    message: str,
) -> NativePackageEnvironmentActionResponse:
    return NativePackageEnvironmentActionResponse(
        success=success,
        ecosystem=ecosystem,
        action=action,
        environment_name=environment_name,
        package_name=package_name or None,
        version=version or None,
        state_verified=state_verified,
        timed_out=timed_out,
        user_confirmed=confirmed,
        message=message,
    )


def perform_native_package_environment_action(
    ecosystem: str,
    action: str,
    environment_name: str,
    package_name: str = "",
    version: str = "",
    expected_state_token: str = "",
    *,
    confirmed: bool = False,
) -> NativePackageEnvironmentActionResponse:
    valid_ecosystem = isinstance(ecosystem, str) and ecosystem in ECOSYSTEMS
    safe_ecosystem: NativeEcosystem = ecosystem if valid_ecosystem else "npm"
    valid_action = isinstance(action, str) and action in ACTIONS
    safe_action: NativeAction = action if valid_action else "create"
    safe_environment = environment_name[:64] if isinstance(environment_name, str) else ""
    safe_package = package_name[:220] if isinstance(package_name, str) else ""
    safe_version = version[:128] if isinstance(version, str) else ""
    if not valid_ecosystem or not valid_action:
        return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=False, message="Unsupported native package environment action; no command was run.")
    if confirmed is not True:
        return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=False, message="Explicit MCP client confirmation is required; no npm or Cargo command was run.")
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message="A valid state token from the exact package environment confirmation is required; no change was made.")
    expected = native_package_action_confirmation_details(ecosystem, action, environment_name, package_name, version)
    if isinstance(expected, str):
        return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message=expected)
    if expected.state_token != expected_state_token:
        return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message="The selected package environment or installed package state changed after confirmation; review and confirm again.")
    if (os.getuid(), os.geteuid()) != (expected.uid, expected.euid) or os.getuid() == 0 or os.geteuid() == 0:
        return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message="npm and Cargo package operations require the same unprivileged, non-root server identity used at confirmation.")

    if action == "create":
        error = _secure_create_environment(expected)
        if error:
            return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message=f"{error} No environment was created or replaced.")
    else:
        current_home, current_home_info, error = _current_home()
        manager_binary, manager_identity, manager_error = _manager(safe_ecosystem)
        runtime_identity = None
        runtime_binary = None
        if safe_ecosystem == "npm":
            runtime_binary, runtime_identity, runtime_error = _node_runtime()
            manager_error = manager_error or runtime_error
        if error or current_home is None or current_home_info is None or manager_error or manager_binary is None or manager_identity is None:
            return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message="The current home or package-manager identity could not be revalidated; no package command was run.")
        if current_home != expected.home or _identity(current_home_info) != expected.home_identity:
            return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message="The current user's home directory changed after confirmation; no package command was run.")
        if manager_binary != expected.manager_binary or manager_identity != expected.manager_identity or (safe_ecosystem == "npm" and (runtime_binary != expected.runtime_binary or runtime_identity != expected.runtime_identity)):
            return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message="The package-manager executable changed after confirmation; review and confirm again.")
        root_info, root_error = _safe_directory(expected.root, owner_uid=expected.uid, private=True)
        environment_info, environment_error = _safe_directory(expected.environment_path, owner_uid=expected.uid, private=True)
        if (
            root_error
            or environment_error
            or root_info is None
            or environment_info is None
            or _identity(root_info) != expected.root_identity
            or _identity(environment_info) != expected.environment_identity
        ):
            return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message="The managed package environment changed after confirmation; no package command was run.")
        if safe_ecosystem == "npm":
            cache_error = _ensure_npm_cache(expected)
            if cache_error:
                return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message=f"{cache_error} No npm command was run.")
        label = f"{safe_ecosystem} package transaction"
        output, error, truncated = _run_snapshot_command(expected, _command(expected), timeout=ACTION_TIMEOUT_SECONDS, label=label)
        if output is None or error or truncated:
            timed_out = bool(error and "timed out after" in error)
            message = (
                f"The {label} exceeded {ACTION_TIMEOUT_SECONDS} seconds and was asked to stop. Environment state may be incomplete; inspect it before retrying."
                if timed_out
                else f"The {label} did not complete successfully. Command output is withheld; inspect the environment before retrying."
            )
            return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, timed_out=timed_out, message=message)

    verified, error = _capture_snapshot(safe_ecosystem, "inventory", environment_name)
    if error or verified is None:
        return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message="The command completed, but the managed package environment could not be verified afterward. Inspect it before retrying.")
    if action == "create":
        state_verified = not verified.packages
    else:
        installed = {_canonical_name(safe_ecosystem, package.name): package.version for package in verified.packages}
        actual = installed.get(_canonical_name(safe_ecosystem, package_name))
        if action == "uninstall":
            state_verified = actual is None
        elif action == "install" and version:
            state_verified = actual == version
        else:
            state_verified = actual is not None
    if not state_verified:
        return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=False, confirmed=True, message="The command completed, but the requested package state was not present afterward. Inspect the environment before retrying.")
    return _response(safe_ecosystem, safe_action, safe_environment, safe_package, safe_version, success=True, confirmed=True, state_verified=True, message=f"The confirmed {safe_ecosystem} environment action completed and the resulting package state was verified. Package-manager output was withheld.")


def list_native_package_environments(ecosystem: str, limit: int = 100) -> NativePackageEnvironmentListResponse:
    safe_ecosystem = ecosystem if isinstance(ecosystem, str) and ecosystem in ECOSYSTEMS else "npm"
    if not isinstance(ecosystem, str) or ecosystem not in ECOSYSTEMS:
        return NativePackageEnvironmentListResponse(success=False, ecosystem=safe_ecosystem, message="ecosystem must be npm or cargo.")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_ENVIRONMENTS:
        return NativePackageEnvironmentListResponse(success=False, ecosystem=safe_ecosystem, message=f"limit must be from 1 through {MAX_ENVIRONMENTS}.")
    home, _home_info, error = _current_home()
    if error or home is None:
        return NativePackageEnvironmentListResponse(success=False, ecosystem=safe_ecosystem, message=error or "The current user's home directory could not be verified.")
    root = home / ROOT_NAMES[safe_ecosystem]
    root_info, error = _safe_directory(root, owner_uid=os.getuid(), private=True)
    if error:
        return NativePackageEnvironmentListResponse(success=False, ecosystem=safe_ecosystem, message=error)
    if root_info is None:
        return NativePackageEnvironmentListResponse(success=True, ecosystem=safe_ecosystem, message=f"No managed {safe_ecosystem} environments exist yet.")
    entries, error = _bounded_directory_entries(root)
    if error or entries is None:
        return NativePackageEnvironmentListResponse(success=False, ecosystem=safe_ecosystem, message=error or "The managed environment directory could not be listed.")
    names = [entry.name for entry in entries]
    environments: list[NativePackageEnvironmentInfo] = []
    total_valid = 0
    skipped = 0
    for name in names:
        if not ENVIRONMENT_NAME_RE.fullmatch(name):
            skipped += 1
            continue
        info, error = _safe_directory(root / name, owner_uid=os.getuid(), private=True)
        if error or info is None:
            skipped += 1
            continue
        total_valid += 1
        if len(environments) < limit:
            environments.append(NativePackageEnvironmentInfo(ecosystem=safe_ecosystem, environment_name=name))
    return NativePackageEnvironmentListResponse(
        success=True,
        ecosystem=safe_ecosystem,
        total_environments=total_valid,
        returned_environments=len(environments),
        environments=environments,
        limit=limit,
        truncated=total_valid > limit,
        skipped_entries=skipped,
        message=f"Skipped {skipped} unsafe or incomplete entries." if skipped else None,
    )


def list_native_environment_packages(ecosystem: str, environment_name: str, limit: int = 100) -> NativeEnvironmentPackageListResponse:
    safe_ecosystem = ecosystem if isinstance(ecosystem, str) and ecosystem in ECOSYSTEMS else "npm"
    safe_name = environment_name[:64] if isinstance(environment_name, str) else ""
    if not isinstance(ecosystem, str) or ecosystem not in ECOSYSTEMS:
        return NativeEnvironmentPackageListResponse(success=False, ecosystem=safe_ecosystem, environment_name=safe_name, message="ecosystem must be npm or cargo.")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PACKAGES:
        return NativeEnvironmentPackageListResponse(success=False, ecosystem=safe_ecosystem, environment_name=safe_name, message=f"limit must be from 1 through {MAX_PACKAGES}.")
    snapshot, error = _capture_snapshot(safe_ecosystem, "inventory", environment_name)
    if error or snapshot is None:
        return NativeEnvironmentPackageListResponse(success=False, ecosystem=safe_ecosystem, environment_name=safe_name, message=error or "The exact managed package environment could not be inspected.")
    return NativeEnvironmentPackageListResponse(
        success=True,
        ecosystem=safe_ecosystem,
        environment_name=environment_name,
        total_packages=len(snapshot.packages),
        returned_packages=min(limit, len(snapshot.packages)),
        packages=list(snapshot.packages[:limit]),
        limit=limit,
        truncated=len(snapshot.packages) > limit,
        message="npm package manifests were read without executing package code; Cargo's supported install-list command was used without installing or updating packages.",
    )
