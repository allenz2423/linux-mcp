"""Confirmed mode changes for exact loaded AppArmor profiles."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import AppArmorProfileActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.apparmor import (
    APPARMOR_PROFILES,
    MAX_ENTRY_LINE_BYTES,
    _parse_entry,
    apparmor_profiles_available,
)
from wayland_mcp.tools.commands import run_bounded_command

AppArmorProfileAction = Literal["enforce", "complain"]
APPARMOR_PROFILE_ROOT = Path("/etc/apparmor.d")
MAX_PROFILE_NAME_LENGTH = 4096
MAX_PROFILE_SCAN_BYTES = 16 * 1024 * 1024
APPARMOR_COMMAND_TIMEOUT_SECONDS = 300
APPARMOR_COMMAND_OUTPUT_BYTES = 16 * 1024
APPARMOR_HELP_TIMEOUT_SECONDS = 10
APPARMOR_HELP_OUTPUT_BYTES = 32 * 1024


@dataclass(frozen=True, slots=True)
class _LoadedProfile:
    name: str
    mode: str
    interface_identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _AppArmorActionTarget:
    name: str
    action: AppArmorProfileAction
    mode_before: str
    mode_after: str
    binary: str
    binary_identity: tuple[int, int, int, int, int]
    interface_identity: tuple[int, int, int, int, int, int]
    state_digest: str


def _interface_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _binary_identity(binary: str) -> tuple[int, int, int, int, int] | None:
    try:
        info = os.stat(binary, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or not os.access(binary, os.X_OK):
        return None
    return (info.st_dev, info.st_ino, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)


def _profile_name_error(name: object) -> str | None:
    if not isinstance(name, str) or not name or len(name) > MAX_PROFILE_NAME_LENGTH:
        return f"name must be one exact loaded AppArmor profile name no longer than {MAX_PROFILE_NAME_LENGTH} characters."
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in name):
        return "name cannot contain control characters; use the exact printable name from list_apparmor_profiles."
    return None


def _read_loaded_profile(name: str) -> tuple[_LoadedProfile | None, str | None]:
    """Read and validate the exact loaded profile from the fixed securityfs list."""
    if not apparmor_profiles_available():
        return None, "The AppArmor profile list is not visible in securityfs."
    found: list[tuple[str, str]] = []
    scanned = 0
    try:
        with APPARMOR_PROFILES.open("rb") as stream:
            before = _interface_identity(os.fstat(stream.fileno()))
            while True:
                raw_line = stream.readline(MAX_ENTRY_LINE_BYTES + 1)
                if not raw_line:
                    break
                scanned += len(raw_line)
                if scanned > MAX_PROFILE_SCAN_BYTES:
                    return None, f"The loaded-profile scan exceeded its {MAX_PROFILE_SCAN_BYTES}-byte limit."
                if len(raw_line) > MAX_ENTRY_LINE_BYTES:
                    return None, f"An AppArmor profile entry exceeded the {MAX_ENTRY_LINE_BYTES}-byte limit."
                if not raw_line.strip():
                    continue
                profile = _parse_entry(raw_line, 0)
                if profile is None:
                    return None, "The AppArmor profile list contained an unrecognized entry; no change was run."
                if profile.name == name:
                    found.append((profile.name, profile.mode))
            after = _interface_identity(os.fstat(stream.fileno()))
    except OSError as exc:
        return None, f"The AppArmor profile list could not be read: {exc.strerror or type(exc).__name__}."

    if before != after:
        return None, "The AppArmor profile list changed while it was being read; list profiles again."
    if not found:
        return None, "The exact profile is not currently loaded; list profiles again."
    if len(found) != 1:
        return None, "The exact profile name appears more than once in the loaded-profile list."
    profile_name, mode = found[0]
    return _LoadedProfile(profile_name, mode, after), None


def _resolve_command(action: AppArmorProfileAction) -> tuple[str | None, tuple[int, int, int, int, int] | None, str | None]:
    env = get_sanitized_env(dict(os.environ))
    command_name = "aa-enforce" if action == "enforce" else "aa-complain"
    binary = find_session_binary(command_name, env)
    if not binary:
        return None, None, f"The optional {command_name} command is unavailable."
    try:
        binary = str(Path(binary).resolve(strict=True))
    except (OSError, RuntimeError):
        return None, None, f"The selected {command_name} executable could not be resolved safely."
    identity = _binary_identity(binary)
    if identity is None:
        return None, None, f"The selected {command_name} executable identity could not be verified."
    help_output, command_error, truncated = run_bounded_command(
        [binary, "--help"],
        env,
        command_label=f"{command_name} feature check",
        timeout_seconds=APPARMOR_HELP_TIMEOUT_SECONDS,
        max_output_bytes=APPARMOR_HELP_OUTPUT_BYTES,
        kill_process_group=True,
    )
    if command_error or truncated or help_output is None or "--profile" not in help_output:
        return None, None, f"The installed {command_name} does not expose the exact --profile option required by this tool."
    return binary, identity, None


def apparmor_profile_control_available() -> bool:
    """Return whether both profile-specific mode tools are available."""
    if (
        not sys.platform.startswith("linux")
        or not apparmor_profiles_available()
        or not APPARMOR_PROFILE_ROOT.is_dir()
        or not os.access(APPARMOR_PROFILE_ROOT, os.W_OK | os.X_OK)
    ):
        return False
    for action in ("enforce", "complain"):
        binary, identity, error = _resolve_command(action)
        if error or binary is None or identity is None:
            return False
    return True


def apparmor_profile_confirmation_details(
    name: str,
    action: AppArmorProfileAction,
) -> tuple[_AppArmorActionTarget | None, str | None, str | None]:
    """Bind one mode change to the exact loaded profile, mode, and helper."""
    if not sys.platform.startswith("linux"):
        return None, None, "AppArmor profile control is available only on Linux."
    if not APPARMOR_PROFILE_ROOT.is_dir() or not os.access(APPARMOR_PROFILE_ROOT, os.W_OK | os.X_OK):
        return None, None, "The current server identity cannot write to the standard AppArmor profile directory."
    validation_error = _profile_name_error(name)
    if validation_error:
        return None, None, validation_error
    if action not in {"enforce", "complain"}:
        return None, None, "Choose one supported AppArmor action: enforce or complain."
    profile, error = _read_loaded_profile(name)
    if error or profile is None:
        return None, None, error or "The exact loaded AppArmor profile could not be verified."
    if profile.mode not in {"enforce", "complain"}:
        return None, None, f"The profile is in {profile.mode!r} mode; this tool changes only enforce and complain profiles."
    binary, binary_identity, error = _resolve_command(action)
    if error or binary is None or binary_identity is None:
        return None, None, error or "The AppArmor mode-change command could not be verified."

    requested_mode = "enforce" if action == "enforce" else "complain"
    material = {
        "name": profile.name,
        "action": action,
        "mode_before": profile.mode,
        "mode_after": requested_mode,
        "binary": binary,
        "binary_identity": binary_identity,
        "interface_identity": profile.interface_identity,
    }
    state_digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    target = _AppArmorActionTarget(
        name=profile.name,
        action=action,
        mode_before=profile.mode,
        mode_after=requested_mode,
        binary=binary,
        binary_identity=binary_identity,
        interface_identity=profile.interface_identity,
        state_digest=state_digest,
    )
    phrase = hashlib.sha256(("apparmor-profile:" + state_digest).encode("ascii")).hexdigest()[:16]
    return target, f"set profile {phrase}", None


def perform_apparmor_profile_action(
    name: str,
    action: AppArmorProfileAction,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> AppArmorProfileActionResponse:
    target, phrase, error = apparmor_profile_confirmation_details(name, action)
    if error or target is None or phrase is None:
        return AppArmorProfileActionResponse(
            success=False,
            name=name if isinstance(name, str) and _profile_name_error(name) is None else None,
            action=action if action in {"enforce", "complain"} else None,
            user_confirmed=confirmed is True,
            message=error or "The exact loaded AppArmor profile could not be verified.",
        )
    if confirmed is not True:
        return AppArmorProfileActionResponse(
            success=False,
            name=target.name,
            action=target.action,
            mode_before=target.mode_before,
            user_confirmed=False,
            message="Explicit client confirmation is required; no AppArmor profile was changed.",
        )
    if confirmation_phrase != phrase:
        return AppArmorProfileActionResponse(
            success=False,
            name=target.name,
            action=target.action,
            mode_before=target.mode_before,
            user_confirmed=True,
            message="Confirmation did not match the exact profile, requested mode, current mode, or helper identity.",
        )

    current, current_phrase, error = apparmor_profile_confirmation_details(target.name, target.action)
    if error or current is None or current_phrase != phrase or current.state_digest != target.state_digest:
        return AppArmorProfileActionResponse(
            success=False,
            name=target.name,
            action=target.action,
            mode_before=target.mode_before,
            user_confirmed=True,
            message=error or "The profile or AppArmor helper changed after confirmation; list profiles again.",
        )
    if target.mode_before == target.mode_after:
        return AppArmorProfileActionResponse(
            success=True,
            name=target.name,
            action=target.action,
            mode_before=target.mode_before,
            mode_after=target.mode_after,
            user_confirmed=True,
            message=f"The profile is already in {target.mode_after} mode; no command was run.",
        )

    env = get_sanitized_env(dict(os.environ))
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    _output, command_error, truncated = run_bounded_command(
        [target.binary, f"--profile={target.name}"],
        env,
        command_label=f"AppArmor {target.action} update",
        timeout_seconds=APPARMOR_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=APPARMOR_COMMAND_OUTPUT_BYTES,
        kill_process_group=True,
    )
    after, verify_error = _read_loaded_profile(target.name)
    if command_error or truncated:
        return AppArmorProfileActionResponse(
            success=False,
            name=target.name,
            action=target.action,
            mode_before=target.mode_before,
            mode_after=after.mode if after else None,
            user_confirmed=True,
            message="The AppArmor mode command failed, timed out, or exceeded its output limit; the policy may have changed, so inspect the profile before retrying.",
        )
    if verify_error or after is None:
        return AppArmorProfileActionResponse(
            success=False,
            name=target.name,
            action=target.action,
            mode_before=target.mode_before,
            user_confirmed=True,
            message=verify_error or "The profile mode could not be verified after the command.",
        )
    if after.mode != target.mode_after:
        return AppArmorProfileActionResponse(
            success=False,
            name=target.name,
            action=target.action,
            mode_before=target.mode_before,
            mode_after=after.mode,
            user_confirmed=True,
            message="The helper completed but the requested kernel-reported mode is not active; inspect the local profile and policy before retrying.",
        )
    return AppArmorProfileActionResponse(
        success=True,
        name=target.name,
        action=target.action,
        mode_before=target.mode_before,
        mode_after=after.mode,
        user_confirmed=True,
        message=f"The profile is now in {after.mode} mode; its local policy file was updated and reloaded.",
    )
