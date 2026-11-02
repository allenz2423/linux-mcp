"""Bounded inventory and confirmed power-profiles-daemon profile changes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import (
    PowerProfileActionResponse,
    PowerProfileResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

PowerProfile = Literal["power-saver", "balanced", "performance"]
ALLOWED_PROFILES: frozenset[str] = frozenset({"power-saver", "balanced", "performance"})
PROFILE_HEADER_RE = re.compile(r"^ {0,2}(\*)?\s*([a-z][a-z0-9-]*):\s*$")
PROFILE_VALUE_RE = re.compile(r"^(?:power-saver|balanced|performance)\s*$")
MAX_OUTPUT_BYTES = 32 * 1024
QUERY_TIMEOUT_SECONDS = 6
ACTION_TIMEOUT_SECONDS = 15
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class PowerProfileSnapshot:
    binary: str
    active_profile: PowerProfile
    available_profiles: tuple[PowerProfile, ...]

    def payload(self) -> dict[str, object]:
        return {
            "binary": self.binary,
            "active_profile": self.active_profile,
            "available_profiles": list(self.available_profiles),
        }


@dataclass(frozen=True, slots=True)
class PowerProfileTarget:
    before: PowerProfileSnapshot
    requested_profile: PowerProfile
    state_token: str
    confirmation_phrase: str


def _environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env


def _read_snapshot() -> tuple[PowerProfileSnapshot | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "Power-profile inventory is available only on Linux."
    env = _environment()
    binary = find_session_binary("powerprofilesctl", env)
    if not binary:
        return None, "Power-profile inventory requires powerprofilesctl from power-profiles-daemon."
    output, error, truncated = run_bounded_command(
        [binary, "list"],
        env,
        command_label="Read available system power profiles",
        timeout_seconds=QUERY_TIMEOUT_SECONDS,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if error or output is None:
        return None, "The available power profiles could not be read from power-profiles-daemon."
    if truncated:
        return None, "The power-profile list exceeded its output limit."
    available: list[PowerProfile] = []
    starred: list[PowerProfile] = []
    unsupported: list[str] = []
    for line in output.splitlines():
        match = PROFILE_HEADER_RE.fullmatch(line)
        if match is None:
            continue
        name = match.group(2)
        if name not in ALLOWED_PROFILES:
            unsupported.append(name)
            continue
        if name in available:
            return None, "powerprofilesctl returned a duplicate profile name."
        available.append(name)  # type: ignore[arg-type]
        if match.group(1):
            starred.append(name)  # type: ignore[arg-type]
    if not available or unsupported or len(starred) > 1:
        return None, "powerprofilesctl returned an unsupported or incomplete profile list."

    current_output, current_error, current_truncated = run_bounded_command(
        [binary, "get"],
        env,
        command_label="Read active system power profile",
        timeout_seconds=QUERY_TIMEOUT_SECONDS,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if current_error or current_output is None or current_truncated:
        return None, "The active power profile could not be read."
    current_text = current_output.strip()
    if not PROFILE_VALUE_RE.fullmatch(current_text) or current_text not in available:
        return None, "powerprofilesctl returned an invalid or unavailable active profile."
    current: PowerProfile = current_text  # type: ignore[assignment]
    if starred and starred[0] != current:
        return None, "The active profile reported by list and get did not match."
    return PowerProfileSnapshot(
        binary=binary,
        active_profile=current,
        available_profiles=tuple(sorted(available)),
    ), None


def get_power_profile() -> PowerProfileResponse:
    snapshot, error = _read_snapshot()
    if snapshot is None:
        return PowerProfileResponse(success=False, message=error or "Power-profile state could not be read.")
    return PowerProfileResponse(
        success=True,
        active_profile=snapshot.active_profile,
        available_profiles=list(snapshot.available_profiles),
        message=(
            "Power-profiles-daemon reports the active profile and available profile names. "
            "Hardware effects depend on the installed drivers and firmware."
        ),
    )


def _target(requested_profile: object) -> tuple[PowerProfileTarget | None, str | None]:
    if not isinstance(requested_profile, str) or requested_profile not in ALLOWED_PROFILES:
        return None, "profile must be power-saver, balanced, or performance."
    snapshot, error = _read_snapshot()
    if error or snapshot is None:
        return None, error or "Power-profile state could not be verified."
    if requested_profile not in snapshot.available_profiles:
        return None, "The requested profile is not available on this system."
    if requested_profile == snapshot.active_profile:
        return None, "The requested profile is already active."
    requested: PowerProfile = requested_profile  # type: ignore[assignment]
    material = {
        "before": snapshot.payload(),
        "requested_profile": requested,
    }
    state_token = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return PowerProfileTarget(
        before=snapshot,
        requested_profile=requested,
        state_token=state_token,
        confirmation_phrase=f"SET POWER PROFILE {requested.upper()} {state_token[:16]}",
    ), None


def power_profile_confirmation_details(
    requested_profile: str,
) -> tuple[PowerProfileTarget | None, str | None]:
    return _target(requested_profile)


def perform_power_profile_change(
    requested_profile: str,
    *,
    confirmed: bool,
    confirmed_phrase: str | None = None,
) -> PowerProfileActionResponse:
    if not isinstance(requested_profile, str) or requested_profile not in ALLOWED_PROFILES:
        return PowerProfileActionResponse(
            success=False,
            requested_profile=None,
            user_confirmed=confirmed is True,
            message="profile must be power-saver, balanced, or performance.",
        )
    target, error = _target(requested_profile)
    if error or target is None:
        return PowerProfileActionResponse(
            success=False,
            active_profile=None,
            requested_profile=requested_profile,  # type: ignore[arg-type]
            user_confirmed=confirmed is True,
            message=error or "Power-profile state could not be verified.",
        )
    before = target.before
    response_values = {
        "active_profile": before.active_profile,
        "available_profiles": list(before.available_profiles),
        "requested_profile": target.requested_profile,
        "user_confirmed": confirmed is True,
    }
    if not confirmed:
        return PowerProfileActionResponse(
            success=False,
            **response_values,
            message="Explicit MCP client confirmation is required; no power-profile change was made.",
        )
    if confirmed_phrase != target.confirmation_phrase:
        return PowerProfileActionResponse(
            success=False,
            **response_values,
            message="Confirmation did not match the active profile, available profiles, and requested profile.",
        )
    with _ACTION_LOCK:
        current, current_error = _target(requested_profile)
        if current_error or current is None or current.state_token != target.state_token or current.confirmation_phrase != confirmed_phrase:
            return PowerProfileActionResponse(
                success=False,
                **response_values,
                message=current_error or "Power-profile state changed after confirmation; no change was made.",
            )
        env = _environment()
        output, command_error, truncated = run_bounded_command(
            [before.binary, "set", target.requested_profile],
            env,
            command_label="Set confirmed system power profile",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_OUTPUT_BYTES,
        )
        if command_error or output is None or truncated:
            return PowerProfileActionResponse(
                success=False,
                **response_values,
                message="powerprofilesctl could not confirm completion; inspect the active profile before retrying.",
            )
        after, read_error = _read_snapshot()
        if read_error or after is None:
            return PowerProfileActionResponse(
                success=False,
                **response_values,
                message="The profile command completed, but the resulting power-profile state could not be verified.",
            )
        if target.requested_profile not in after.available_profiles or after.active_profile != target.requested_profile:
            return PowerProfileActionResponse(
                success=False,
                **response_values,
                message="The system did not remain on the requested power profile; inspect current power-profile state.",
            )
        return PowerProfileActionResponse(
            success=True,
            active_profile=after.active_profile,
            available_profiles=list(after.available_profiles),
            requested_profile=target.requested_profile,
            user_confirmed=True,
            message=(
                "The requested power profile is active and verified. Power-profiles-daemon stores the selected "
                "profile for restoration at startup; hardware effects depend on available drivers and firmware."
            ),
        )
