"""Read-only installed-package inventory for common Linux package managers."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from wayland_mcp.models import InstalledPackageInfo, InstalledPackageListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.host import _read_os_release

MAX_PACKAGE_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_PACKAGE_DATABASE_BYTES = 32 * 1024 * 1024
MAX_PACKAGE_RECORDS = 50_000
MAX_PACKAGE_LINE_BYTES = 64 * 1024
MAX_RETURNED_PACKAGES = 200
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:@-]{0,255}$")

MANAGER_COMMANDS = {
    "dpkg": "dpkg-query",
    "rpm": "rpm",
    "pacman": "pacman",
}
MANAGER_ALIASES = {
    "dpkg": {"debian", "ubuntu", "linuxmint", "pop", "pop_os", "raspbian", "kali", "elementary", "zorin", "deepin"},
    "rpm": {"fedora", "rhel", "centos", "rocky", "almalinux", "ol", "opensuse", "sles", "sled", "amzn", "nobara"},
    "pacman": {"arch", "manjaro", "endeavouros", "artix", "garuda"},
    "apk": {"alpine"},
}
APK_DATABASE_PATHS = (Path("/lib/apk/db/installed"), Path("/var/lib/apk/db/installed"))
PACKAGE_DATABASE_MARKERS = {
    "dpkg": (Path("/var/lib/dpkg/status"),),
    "rpm": (Path("/var/lib/rpm"), Path("/usr/lib/sysimage/rpm")),
    "pacman": (Path("/var/lib/pacman/local"),),
    "apk": APK_DATABASE_PATHS,
}


def _apk_database_path() -> Path | None:
    return next((path for path in APK_DATABASE_PATHS if path.is_file() and os.access(path, os.R_OK)), None)


def _has_manager_database(manager: str) -> bool:
    if manager == "apk":
        return _apk_database_path() is not None
    return any(path.exists() for path in PACKAGE_DATABASE_MARKERS[manager])


def _manager_for_id(value: str) -> str | None:
    normalized = value.casefold()
    for manager, aliases in MANAGER_ALIASES.items():
        if normalized in aliases:
            return manager
        if manager == "rpm" and normalized.startswith("opensuse-"):
            return manager
    return None


def detect_package_manager(env: dict[str, str] | None = None) -> tuple[str, str | None]:
    """Return the host's likely package database and its query executable, if needed."""
    sanitized_env = env if env is not None else get_sanitized_env()
    release = _read_os_release()
    identifiers = [release.get("ID", ""), *release.get("ID_LIKE", "").split()]
    manager = next((found for item in identifiers if (found := _manager_for_id(item))), None)
    if manager is None:
        manager = next((name for name in ("dpkg", "rpm", "pacman", "apk") if _has_manager_database(name)), None)
    if manager is None:
        return "unsupported", None
    if manager == "apk":
        return manager, None
    return manager, find_session_binary(MANAGER_COMMANDS[manager], sanitized_env)


def package_inventory_available(manager: str, executable: str | None) -> bool:
    if manager == "apk":
        return _apk_database_path() is not None
    return manager in MANAGER_COMMANDS and executable is not None


def _safe_field(value: str, limit: int) -> str | None:
    if not value or len(value) > limit or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value


def _package_matches(package: InstalledPackageInfo, needle: str) -> bool:
    return not needle or any(
        needle in value.casefold()
        for value in (package.name, package.version or "", package.architecture or "")
    )


def _parse_command_output(manager: str, output: str, query: str, already_truncated: bool) -> tuple[list[InstalledPackageInfo], bool]:
    lines = output.splitlines()
    truncated = already_truncated or len(lines) > MAX_PACKAGE_RECORDS
    if len(lines) > MAX_PACKAGE_RECORDS:
        lines = lines[:MAX_PACKAGE_RECORDS]
    if already_truncated and output and not output.endswith("\n") and lines:
        lines = lines[:-1]

    packages: list[InstalledPackageInfo] = []
    for line in lines:
        if manager == "dpkg":
            fields = line.split("\t")
            if len(fields) < 4 or not fields[3].strip().startswith("ii"):
                continue
            raw_name, raw_version, raw_arch = fields[:3]
        elif manager == "rpm":
            fields = line.split("\t")
            if len(fields) < 3:
                continue
            raw_name, raw_version, raw_arch = fields[:3]
        else:  # pacman -Q
            fields = line.split(None, 1)
            if len(fields) < 2:
                continue
            raw_name, raw_version = fields
            raw_arch = ""
        name = _safe_field(raw_name, 256)
        version = _safe_field(raw_version, 256)
        architecture = _safe_field(raw_arch, 64)
        if name is None or not PACKAGE_NAME_RE.fullmatch(name):
            continue
        package = InstalledPackageInfo(name=name, version=version, architecture=architecture)
        if _package_matches(package, query):
            packages.append(package)
    return packages, truncated


def _parse_apk_database(path: Path, query: str) -> tuple[list[InstalledPackageInfo] | None, bool, str | None]:
    packages: list[InstalledPackageInfo] = []
    record: dict[str, str] = {}
    bytes_read = 0
    records_read = 0
    truncated = False

    def add_record() -> None:
        nonlocal record, records_read
        if record:
            records_read += 1
            raw_name = record.get("P", "")
            raw_version = record.get("V", "")
            raw_arch = record.get("A", "")
            name = _safe_field(raw_name, 256)
            version = _safe_field(raw_version, 256)
            architecture = _safe_field(raw_arch, 64)
            if name is not None and PACKAGE_NAME_RE.fullmatch(name):
                package = InstalledPackageInfo(name=name, version=version, architecture=architecture)
                if _package_matches(package, query):
                    packages.append(package)
        record = {}

    try:
        with path.open("rb") as stream:
            while records_read < MAX_PACKAGE_RECORDS:
                remaining = MAX_PACKAGE_DATABASE_BYTES - bytes_read
                if remaining <= 0:
                    truncated = bool(stream.read(1))
                    break
                raw_line = stream.readline(min(MAX_PACKAGE_LINE_BYTES + 1, remaining + 1))
                if not raw_line:
                    add_record()
                    break
                if len(raw_line) > remaining or len(raw_line) > MAX_PACKAGE_LINE_BYTES:
                    truncated = True
                    break
                bytes_read += len(raw_line)
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line:
                    add_record()
                    continue
                if len(line) >= 2 and line[1] == ":" and line[0] in {"P", "V", "A"}:
                    record[line[0]] = line[2:]
            if bytes_read == MAX_PACKAGE_DATABASE_BYTES:
                truncated = truncated or bool(stream.read(1))
            if records_read >= MAX_PACKAGE_RECORDS and stream.read(1):
                truncated = True
    except OSError as exc:
        return None, False, f"Could not read the Alpine installed-package database: {exc.strerror or 'read error'}."
    return packages, truncated, None


def list_installed_packages(query: str = "", limit: int = 100) -> InstalledPackageListResponse:
    if not sys.platform.startswith("linux"):
        return InstalledPackageListResponse(success=False, manager="unsupported", message="Package inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return InstalledPackageListResponse(success=False, manager="unknown", message="Query must be text with at most 256 characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return InstalledPackageListResponse(success=False, manager="unknown", message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_PACKAGES))
    needle = query.strip().casefold()
    env = get_sanitized_env()
    manager, executable = detect_package_manager(env)
    if manager == "unsupported":
        return InstalledPackageListResponse(success=False, manager=manager, limit=limit, message="No supported dpkg, RPM, pacman, or APK package database was detected.")

    if manager == "apk":
        database = _apk_database_path()
        if database is None:
            return InstalledPackageListResponse(success=False, manager=manager, limit=limit, message="The Alpine installed-package database is unavailable or unreadable.")
        packages, truncated, error = _parse_apk_database(database, needle)
    else:
        if executable is None:
            return InstalledPackageListResponse(success=False, manager=manager, limit=limit, message=f"The {MANAGER_COMMANDS[manager]} query executable is unavailable.")
        if manager == "dpkg":
            command = [executable, "--show", r"--showformat=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"]
        elif manager == "rpm":
            command = [executable, "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"]
        else:
            command = [executable, "-Q"]
        child_env = dict(env)
        child_env["LANG"] = "C"
        child_env["LC_ALL"] = "C"
        output, error, truncated = run_bounded_command(
            command,
            child_env,
            command_label="Package query",
            timeout_seconds=15,
            max_output_bytes=MAX_PACKAGE_OUTPUT_BYTES,
        )
        if output is None:
            return InstalledPackageListResponse(success=False, manager=manager, limit=limit, message=error)
        packages, parse_truncated = _parse_command_output(manager, output, needle, truncated)
        truncated = truncated or parse_truncated

    if packages is None:
        return InstalledPackageListResponse(success=False, manager=manager, limit=limit, message=error)
    packages.sort(key=lambda item: (item.name.casefold(), (item.architecture or "").casefold()))
    message = f"Inventory is limited to the {manager} system package database; Flatpak, Snap, Nix, and language-specific environments are not included."
    if truncated:
        message += " The package scan reached its output, database, line, or record limit."
    return InstalledPackageListResponse(
        success=True,
        manager=manager,
        total_packages=len(packages),
        returned_packages=min(len(packages), limit),
        packages=packages[:limit],
        limit=limit,
        truncated=truncated or len(packages) > limit,
        message=message,
    )
