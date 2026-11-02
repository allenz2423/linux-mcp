"""Explicitly confirmed system package operations for supported Linux managers."""

from __future__ import annotations

import re
import subprocess
import sys
import time
from dataclasses import dataclass

from wayland_mcp.models import PackageAction, PackageActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.host import _read_os_release
from wayland_mcp.tools.packages import detect_package_manager, package_inventory_available

PACKAGE_ACTIONS = {"install", "upgrade", "remove", "upgrade_all"}
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,255}$")
DEBIAN_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,255}(?::[A-Za-z0-9][A-Za-z0-9_-]{0,63})?$")
PACKAGE_ACTION_TIMEOUT_SECONDS = 30 * 60
PACKAGE_ACTION_TERMINATE_GRACE_SECONDS = 10
PACKAGE_ACTION_POLL_SECONDS = 0.2


@dataclass(frozen=True)
class PackageActionTarget:
    manager: str
    frontend: str
    package: str


def _package_frontend(manager: str, env: dict[str, str]) -> tuple[str | None, str | None]:
    if manager == "dpkg":
        candidates = ("apt-get",)
    elif manager == "rpm":
        release = _read_os_release()
        identifiers = {release.get("ID", "").casefold(), *release.get("ID_LIKE", "").casefold().split()}
        suse_host = any("suse" in item or item in {"sled", "sles"} for item in identifiers)
        candidates = ("zypper", "dnf5", "dnf", "yum") if suse_host else ("dnf5", "dnf", "yum", "zypper")
    elif manager == "pacman":
        candidates = ("pacman",)
    elif manager == "apk":
        candidates = ("apk",)
    else:
        return None, None

    for candidate in candidates:
        executable = find_session_binary(candidate, env)
        if executable:
            return candidate, executable
    return None, None


def package_control_readiness() -> tuple[bool, str, str | None, str | None]:
    """Return whether a supported package database and transaction frontend exist."""
    if not sys.platform.startswith("linux"):
        return False, "unsupported", None, "System package operations are available only on Linux."
    env = get_sanitized_env()
    manager, query_executable = detect_package_manager(env)
    if manager == "unsupported":
        return False, manager, None, "No supported dpkg, RPM, pacman, or APK package database was detected."
    if not package_inventory_available(manager, query_executable):
        return False, manager, None, f"The {manager} installed-package inventory source is unavailable."
    frontend, executable = _package_frontend(manager, env)
    if not frontend or not executable:
        return False, manager, None, f"No supported transaction frontend for the {manager} package database is available."
    return True, manager, frontend, None


def package_action_confirmation_details(
    action: str,
    package: str,
) -> PackageActionTarget | str:
    """Validate an exact package operation and resolve its manager without changing state."""
    if not isinstance(action, str) or action not in PACKAGE_ACTIONS:
        return "Action must be install, upgrade, remove, or upgrade_all."
    if not isinstance(package, str):
        return "Package must be text."
    if action == "upgrade_all":
        if package:
            return "The package argument must be empty for upgrade_all."
    elif not package or package != package.strip() or len(package) > 320:
        return "Supply one exact package name with no surrounding whitespace and at most 320 characters."

    ready, manager, frontend, error = package_control_readiness()
    if not ready or not frontend:
        return error or "A supported package transaction frontend is unavailable."
    if action != "upgrade_all":
        name_pattern = DEBIAN_PACKAGE_NAME_RE if manager == "dpkg" else PACKAGE_NAME_RE
        if not name_pattern.fullmatch(package):
            return "Package must be one exact package name; versions, paths, repository selectors, patterns, and groups are not accepted."
    return PackageActionTarget(manager=manager, frontend=frontend, package=package)


def _commands_for_action(target: PackageActionTarget, action: PackageAction) -> list[list[str]]:
    package = target.package
    manager = target.manager
    frontend = target.frontend

    if manager == "dpkg":
        if action == "install":
            return [[frontend, "-y", "--no-install-recommends", "install", package]]
        if action == "upgrade":
            return [[frontend, "-y", "--only-upgrade", "install", package]]
        if action == "remove":
            return [[frontend, "-y", "remove", package]]
        return [[frontend, "update"], [frontend, "-y", "upgrade"]]

    if manager == "rpm":
        if frontend == "zypper":
            if action == "install":
                return [[frontend, "--non-interactive", "install", package]]
            if action == "upgrade":
                return [[frontend, "--non-interactive", "update", package]]
            if action == "remove":
                return [[frontend, "--non-interactive", "remove", package]]
            return [[frontend, "--non-interactive", "update"]]
        if action == "install":
            return [[frontend, "-y", "install", package]]
        if action == "upgrade":
            return [[frontend, "-y", "upgrade", package]]
        if action == "remove":
            return [[frontend, "-y", "remove", package]]
        return [[frontend, "-y", "upgrade"]]

    if manager == "pacman":
        if action in {"install", "upgrade"}:
            # Arch supports synchronized package changes as part of a full system upgrade.
            return [[frontend, "--noconfirm", "--needed", "-Syu", package]]
        if action == "remove":
            return [[frontend, "--noconfirm", "-R", package]]
        return [[frontend, "--noconfirm", "-Syu"]]

    if manager == "apk":
        common = [frontend, "--interactive=no"]
        if action == "install":
            return [common + ["--update-cache", "add", package]]
        if action == "upgrade":
            return [common + ["--update-cache", "upgrade", package]]
        if action == "remove":
            return [common + ["del", package]]
        return [common + ["update"], common + ["upgrade"]]

    return []


def _run_transaction_command(
    command: list[str],
    env: dict[str, str],
    deadline: float,
) -> tuple[int | None, bool, str | None]:
    """Run one package-manager command without buffering output."""
    if time.monotonic() >= deadline:
        return None, True, None
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
    except OSError as exc:
        return None, False, f"Could not start the {command[0]} package manager: {exc.strerror or type(exc).__name__}."

    while True:
        return_code = process.poll()
        if return_code is not None:
            return return_code, False, None
        if time.monotonic() >= deadline:
            try:
                process.terminate()
            except OSError:
                pass
            try:
                process.wait(timeout=PACKAGE_ACTION_TERMINATE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except OSError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            return None, True, None
        time.sleep(PACKAGE_ACTION_POLL_SECONDS)


def perform_package_action(
    action: str,
    package: str,
    *,
    confirmed: bool,
) -> PackageActionResponse:
    """Execute a single explicitly confirmed package-manager operation."""
    safe_action: PackageAction = action if isinstance(action, str) and action in PACKAGE_ACTIONS else "install"
    safe_package = package if isinstance(package, str) else ""
    target_or_error = package_action_confirmation_details(action, package)
    target = target_or_error if isinstance(target_or_error, PackageActionTarget) else None
    if not confirmed:
        return PackageActionResponse(
            success=False,
            action=safe_action,
            package=safe_package,
            manager=target.manager if target else None,
            frontend=target.frontend if target else None,
            message="Explicit client confirmation is required; no package-manager command was run.",
        )
    if target is None:
        return PackageActionResponse(
            success=False,
            action=safe_action,
            package=safe_package,
            user_confirmed=True,
            message=str(target_or_error),
        )

    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["TERM"] = "dumb"
    if target.manager == "dpkg":
        env["DEBIAN_FRONTEND"] = "noninteractive"

    commands = _commands_for_action(target, safe_action)
    if not commands:
        return PackageActionResponse(
            success=False,
            action=safe_action,
            package=safe_package,
            manager=target.manager,
            frontend=target.frontend,
            user_confirmed=True,
            message="No transaction command is defined for this package manager and action.",
        )

    action_deadline = time.monotonic() + PACKAGE_ACTION_TIMEOUT_SECONDS
    for command in commands:
        return_code, timed_out, error = _run_transaction_command(command, env, action_deadline)
        if error:
            return PackageActionResponse(
                success=False,
                action=safe_action,
                package=safe_package,
                manager=target.manager,
                frontend=target.frontend,
                return_code=return_code,
                user_confirmed=True,
                message=f"{error} No package-manager output was returned.",
            )
        if timed_out:
            return PackageActionResponse(
                success=False,
                action=safe_action,
                package=safe_package,
                manager=target.manager,
                frontend=target.frontend,
                timed_out=True,
                user_confirmed=True,
                message=(
                    f"The {target.frontend} operation exceeded {PACKAGE_ACTION_TIMEOUT_SECONDS} seconds and was asked to stop. "
                    "The package transaction may be incomplete; inspect package state and logs before retrying."
                ),
            )
        if return_code != 0:
            return PackageActionResponse(
                success=False,
                action=safe_action,
                package=safe_package,
                manager=target.manager,
                frontend=target.frontend,
                return_code=return_code,
                user_confirmed=True,
                message=(
                    f"{target.frontend} exited with status {return_code}. Command output is withheld; "
                    "inspect package-manager logs and current package state for details."
                ),
            )

    target_description = "all eligible installed packages" if safe_action == "upgrade_all" else safe_package
    return PackageActionResponse(
        success=True,
        action=safe_action,
        package=safe_package,
        manager=target.manager,
        frontend=target.frontend,
        return_code=0,
        user_confirmed=True,
        message=(
            f"{target.frontend} completed {safe_action.replace('_', ' ')} for {target_description}. "
            "Success reflects the package-manager exit status, not a separate inventory check. Package scripts and dependency changes may have affected other software or services."
        ),
    )
