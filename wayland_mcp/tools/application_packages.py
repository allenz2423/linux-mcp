"""Bounded read-only inventory for Flatpak, Snap, and the current Nix profile."""

from __future__ import annotations

import json
import configparser
import hashlib
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Literal

from wayland_mcp.models import (
    ApplicationPackageInfo,
    ApplicationPackageInventoryResponse,
    ApplicationPackageSourceStatus,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

ApplicationPackageManager = Literal["flatpak", "snap", "nix"]
PACKAGE_COMMANDS: dict[str, str] = {"flatpak": "flatpak", "snap": "snap", "nix": "nix"}
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:@/-]{0,255}$")
FLATPAK_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$")
MAX_PACKAGE_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_PACKAGE_LINE_BYTES = 64 * 1024
MAX_SOURCE_PACKAGES = 50_000
MAX_TOTAL_PACKAGES = 100_000
MAX_RETURNED_PACKAGES = 200
COMMAND_TIMEOUT_SECONDS = 12
FLATPAK_INSTALLATIONS_DIRECTORY = Path("/etc/flatpak/installations.d")
FLATPAK_INSTALLATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
MAX_FLATPAK_INSTALLATION_FILES = 64
MAX_FLATPAK_INSTALLATION_FILE_BYTES = 64 * 1024


def detect_application_package_tools(env: dict[str, str] | None = None) -> dict[str, str | None]:
    """Find optional package tools through the sanitized session PATH."""
    child_env = env if env is not None else get_sanitized_env(dict(os.environ))
    return {
        manager: find_session_binary(binary, child_env)
        for manager, binary in PACKAGE_COMMANDS.items()
    }


def _clean_field(value: Any, limit: int = 256) -> str | None:
    if not isinstance(value, str) or not value or len(value) > limit:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value


def _matches(package: ApplicationPackageInfo, needle: str) -> bool:
    return not needle or any(
        needle in value.casefold()
        for value in (
            package.manager,
            package.name,
            package.package_kind,
            package.version or "",
            package.architecture or "",
            package.branch or "",
            package.revision or "",
            package.scope,
        )
    )


def _run_query(
    executable: str,
    arguments: list[str],
    *,
    label: str,
) -> tuple[str | None, str | None, bool]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    return run_bounded_command(
        [executable, *arguments],
        env,
        command_label=label,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_PACKAGE_OUTPUT_BYTES,
    )


def flatpak_named_installations() -> tuple[dict[str, tuple[str, str]], str | None]:
    """Return configured named system-installation IDs and state fingerprints.

    Installation paths are used only to validate the fixed configuration and
    are never returned to the caller.
    """
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_fd = os.open(FLATPAK_INSTALLATIONS_DIRECTORY, directory_flags)
    except FileNotFoundError:
        return {}, None
    except OSError:
        return {}, "The configured Flatpak system installations could not be inspected."
    try:
        directory_info = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != 0
            or directory_info.st_mode & 0o022
        ):
            return {}, "The configured Flatpak installation directory failed its ownership or permission check."
        try:
            with os.scandir(directory_fd) as iterator:
                entries = sorted((entry.name for entry in iterator), key=str.casefold)
        except OSError:
            return {}, "The configured Flatpak system installations could not be inspected."
        if len(entries) > MAX_FLATPAK_INSTALLATION_FILES:
            return {}, "The configured Flatpak installation list exceeded its bounded file count."

        installations: dict[str, tuple[str, str]] = {}
        total_bytes = 0
        for name in entries:
            if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}\.conf", name):
                continue
            try:
                file_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISREG(file_info.st_mode):
                    continue
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                continue
            except OSError:
                return {}, "A configured Flatpak installation file could not be opened safely."
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    return {}, "A Flatpak installation file failed its ownership or file-type check."
                if info.st_size > MAX_FLATPAK_INSTALLATION_FILE_BYTES:
                    return {}, "A Flatpak installation file exceeded its bounded size."
                remaining = MAX_FLATPAK_INSTALLATION_FILE_BYTES + 1
                raw = bytearray()
                while remaining > 0:
                    chunk = os.read(descriptor, min(16 * 1024, remaining))
                    if not chunk:
                        break
                    raw.extend(chunk)
                    remaining -= len(chunk)
                if len(raw) > MAX_FLATPAK_INSTALLATION_FILE_BYTES:
                    return {}, "A Flatpak installation file grew beyond its bounded size."
            except OSError:
                return {}, "A Flatpak installation file could not be read safely."
            finally:
                os.close(descriptor)
            total_bytes += len(raw)
            if total_bytes > MAX_FLATPAK_INSTALLATION_FILES * MAX_FLATPAK_INSTALLATION_FILE_BYTES:
                return {}, "The configured Flatpak installation data exceeded its total size limit."
            try:
                parser = configparser.RawConfigParser(interpolation=None, strict=True)
                parser.read_string(raw.decode("utf-8", errors="strict"))
            except (configparser.Error, UnicodeError):
                return {}, "A Flatpak installation file could not be parsed safely."
            for section in parser.sections():
                match = re.fullmatch(r'Installation\s+"([A-Za-z0-9][A-Za-z0-9._+-]{0,127})"', section)
                if not match:
                    continue
                installation_id = match.group(1)
                path = parser.get(section, "Path", fallback="")
                if (
                    installation_id == "default"
                    or not FLATPAK_INSTALLATION_ID_RE.fullmatch(installation_id)
                    or not path.startswith("/")
                    or len(path) > 4096
                    or any(ord(char) < 32 or ord(char) == 127 for char in path)
                ):
                    return {}, "A named Flatpak installation has invalid identity or path metadata."
                if installation_id in installations:
                    return {}, "Duplicate named Flatpak installation IDs were found."
                fingerprint = hashlib.sha256(raw).hexdigest()
                installations[installation_id] = (path, fingerprint)
        return installations, None
    finally:
        os.close(directory_fd)


def _parse_flatpak(output: str, scope: str, query: str, already_truncated: bool) -> tuple[list[ApplicationPackageInfo], bool]:
    lines = output.splitlines()
    truncated = already_truncated or len(lines) > MAX_SOURCE_PACKAGES
    packages: list[ApplicationPackageInfo] = []
    for line in lines[:MAX_SOURCE_PACKAGES]:
        if len(line.encode("utf-8", errors="replace")) > MAX_PACKAGE_LINE_BYTES:
            truncated = True
            continue
        ref = line.strip()
        if not ref or ref.casefold() == "ref":
            continue
        parts = ref.split("/")
        if len(parts) != 4 or parts[0] not in {"app", "runtime"}:
            continue
        _kind, raw_name, raw_arch, raw_branch = parts
        name = _clean_field(raw_name)
        architecture = _clean_field(raw_arch, 64)
        branch = _clean_field(raw_branch, 128)
        if (
            name is None
            or not FLATPAK_COMPONENT_RE.fullmatch(name)
            or architecture is None
            or not FLATPAK_COMPONENT_RE.fullmatch(architecture)
            or branch is None
            or not FLATPAK_COMPONENT_RE.fullmatch(branch)
        ):
            continue
        package = ApplicationPackageInfo(
            manager="flatpak",
            name=name,
            package_kind=_kind,
            architecture=architecture,
            branch=branch,
            scope=scope,
        )
        if _matches(package, query):
            packages.append(package)
    return packages, truncated


def _parse_snap(output: str, query: str, already_truncated: bool) -> tuple[list[ApplicationPackageInfo], bool]:
    lines = output.splitlines()
    truncated = already_truncated or len(lines) > MAX_SOURCE_PACKAGES
    if already_truncated and output and not output.endswith("\n") and lines:
        lines = lines[:-1]
    packages: list[ApplicationPackageInfo] = []
    for line in lines[:MAX_SOURCE_PACKAGES]:
        if len(line.encode("utf-8", errors="replace")) > MAX_PACKAGE_LINE_BYTES:
            truncated = True
            continue
        fields = line.split()
        if not fields or fields[0].casefold() == "name" or fields[0].casefold() == "no":
            continue
        if len(fields) < 3:
            continue
        name = _clean_field(fields[0])
        version = _clean_field(fields[1])
        revision = _clean_field(fields[2], 128)
        if name is None or not PACKAGE_NAME_RE.fullmatch(name) or version is None or revision is None:
            continue
        package = ApplicationPackageInfo(
            manager="snap",
            name=name,
            package_kind="snap",
            version=version,
            revision=revision,
            scope="system",
        )
        if _matches(package, query):
            packages.append(package)
    return packages, truncated


def _parse_nix(output: str, query: str) -> list[ApplicationPackageInfo] | None:
    try:
        payload = json.loads(
            output,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (json.JSONDecodeError, RecursionError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    elements = payload.get("elements")
    if not isinstance(elements, dict) or len(elements) > MAX_SOURCE_PACKAGES:
        return None
    packages: list[ApplicationPackageInfo] = []
    for raw_name, value in elements.items():
        name = _clean_field(raw_name)
        if name is None or not PACKAGE_NAME_RE.fullmatch(name) or not isinstance(value, dict):
            continue
        active_value = value.get("active")
        active = active_value if isinstance(active_value, bool) else None
        package = ApplicationPackageInfo(
            manager="nix",
            name=name,
            package_kind="profile_entry",
            scope="current_user_default_profile",
            active=active,
        )
        if _matches(package, query):
            packages.append(package)
    return packages


def _source_status(
    manager: ApplicationPackageManager,
    scope: str,
    *,
    available: bool,
    success: bool,
    package_count: int = 0,
    truncated: bool = False,
    message: str | None = None,
) -> ApplicationPackageSourceStatus:
    return ApplicationPackageSourceStatus(
        manager=manager,
        scope=scope,
        available=available,
        success=success,
        package_count=package_count,
        truncated=truncated,
        message=message,
    )


def list_application_packages(query: str = "", limit: int = 100) -> ApplicationPackageInventoryResponse:
    """List installed Flatpaks, Snaps, and current-user Nix profile entries."""
    if not sys.platform.startswith("linux"):
        return ApplicationPackageInventoryResponse(
            success=False,
            message="Application package inventory is available only on Linux.",
        )
    if not isinstance(query, str) or len(query) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in query):
        return ApplicationPackageInventoryResponse(
            success=False,
            message="Query must be text with at most 256 characters and no control characters.",
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        return ApplicationPackageInventoryResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_PACKAGES))
    needle = query.strip().casefold()
    tools = detect_application_package_tools()
    sources: list[ApplicationPackageSourceStatus] = []
    packages: list[ApplicationPackageInfo] = []

    flatpak = tools["flatpak"]
    for scope, switch in (("system_default", "--system"), ("current_user", "--user")):
        if not flatpak:
            sources.append(_source_status(
                "flatpak", scope, available=False, success=False,
                message="The optional flatpak command is unavailable.",
            ))
            continue
        output, _error, command_truncated = _run_query(
            flatpak,
            [switch, "--columns=ref:full", "list"],
            label="Flatpak package inventory",
        )
        if output is None:
            sources.append(_source_status(
                "flatpak", scope, available=True, success=False,
                message="The Flatpak installation could not be queried with current permissions or installation state.",
            ))
            continue
        found, source_truncated = _parse_flatpak(output, scope, needle, command_truncated)
        if len(packages) + len(found) > MAX_TOTAL_PACKAGES:
            found = found[: max(0, MAX_TOTAL_PACKAGES - len(packages))]
            source_truncated = True
        packages.extend(found)
        sources.append(_source_status(
            "flatpak", scope, available=True, success=True,
            package_count=len(found), truncated=source_truncated,
            message="The Flatpak ref scan reached its output or record limit." if source_truncated else None,
        ))

    named_installations, installation_error = flatpak_named_installations()
    if installation_error:
        sources.append(_source_status(
            "flatpak", "system_named_installations", available=bool(flatpak), success=False,
            message=installation_error,
        ))
    elif flatpak:
        for installation_id in sorted(named_installations):
            scope = f"system_installation:{installation_id}"
            output, _error, command_truncated = _run_query(
                flatpak,
                [f"--installation={installation_id}", "--columns=ref:full", "list"],
                label="Named Flatpak installation inventory",
            )
            if output is None:
                sources.append(_source_status(
                    "flatpak", scope, available=True, success=False,
                    message="The named Flatpak installation could not be queried with current permissions or installation state.",
                ))
                continue
            found, source_truncated = _parse_flatpak(output, scope, needle, command_truncated)
            if len(packages) + len(found) > MAX_TOTAL_PACKAGES:
                found = found[: max(0, MAX_TOTAL_PACKAGES - len(packages))]
                source_truncated = True
            packages.extend(found)
            sources.append(_source_status(
                "flatpak", scope, available=True, success=True,
                package_count=len(found), truncated=source_truncated,
                message="The named Flatpak ref scan reached its output or record limit." if source_truncated else None,
            ))

    snap = tools["snap"]
    if not snap:
        sources.append(_source_status(
            "snap", "system", available=False, success=False,
            message="The optional snap command is unavailable.",
        ))
    else:
        output, _error, command_truncated = _run_query(
            snap,
            ["list"],
            label="Snap package inventory",
        )
        if output is None:
            sources.append(_source_status(
                "snap", "system", available=True, success=False,
                message="The Snap service could not be queried with current permissions or service state.",
            ))
        else:
            found, source_truncated = _parse_snap(output, needle, command_truncated)
            if len(packages) + len(found) > MAX_TOTAL_PACKAGES:
                found = found[: max(0, MAX_TOTAL_PACKAGES - len(packages))]
                source_truncated = True
            packages.extend(found)
            sources.append(_source_status(
                "snap", "system", available=True, success=True,
                package_count=len(found), truncated=source_truncated,
                message="The Snap inventory reached its output or record limit." if source_truncated else None,
            ))

    nix = tools["nix"]
    if not nix:
        sources.append(_source_status(
            "nix", "current_user_default_profile", available=False, success=False,
            message="The optional nix command is unavailable.",
        ))
    else:
        output, _error, command_truncated = _run_query(
            nix,
            ["profile", "list", "--json"],
            label="Nix profile inventory",
        )
        if output is None:
            sources.append(_source_status(
                "nix", "current_user_default_profile", available=True, success=False,
                message="The current user's Nix profile could not be queried; the CLI may lack profile support or required features.",
            ))
        elif command_truncated:
            sources.append(_source_status(
                "nix", "current_user_default_profile", available=True, success=False,
                truncated=True,
                message="The Nix profile JSON exceeded the output limit; no partial records were returned.",
            ))
        else:
            found = _parse_nix(output, needle)
            if found is None:
                sources.append(_source_status(
                    "nix", "current_user_default_profile", available=True, success=False,
                    message="The Nix profile returned malformed or unsupported JSON.",
                ))
            else:
                source_truncated = False
                if len(packages) + len(found) > MAX_TOTAL_PACKAGES:
                    found = found[: max(0, MAX_TOTAL_PACKAGES - len(packages))]
                    source_truncated = True
                packages.extend(found)
                sources.append(_source_status(
                    "nix", "current_user_default_profile", available=True, success=True,
                    package_count=len(found), truncated=source_truncated,
                    message="The combined package inventory reached its record limit." if source_truncated else None,
                ))

    success = any(source.success for source in sources)
    partial = any(source.available and not source.success for source in sources)
    truncated = any(source.truncated for source in sources) or len(packages) > limit
    packages.sort(key=lambda item: (
        item.manager,
        item.name.casefold(),
        item.scope,
        (item.architecture or "").casefold(),
        (item.branch or "").casefold(),
    ))
    if not success:
        message = "No Flatpak, Snap, or Nix package source could be queried; see per-source status for missing tools or unavailable services."
    elif partial:
        message = "Some installed package sources could not be queried; results include successful sources only."
    else:
        message = "Read-only results include successfully queried sources; per-source status lists unavailable tools and installations."
    if truncated:
        message += " One or more package sources or the returned list reached a configured limit."
    return ApplicationPackageInventoryResponse(
        success=success,
        partial=partial,
        sources=sources,
        total_packages=len(packages),
        returned_packages=min(len(packages), limit),
        packages=packages[:limit],
        limit=limit,
        truncated=truncated,
        message=message,
    )
