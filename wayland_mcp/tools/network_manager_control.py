"""Exact, confirmed NetworkManager connection-profile actions."""

from __future__ import annotations

import os
import sys
import threading
import uuid as uuid_module
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import NetworkManagerProfileActionResponse, NetworkManagerProfileInfo
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.network_manager import UUID_PATTERN, _parse_profile_row

NetworkManagerProfileAction = Literal[
    "activate",
    "deactivate",
    "enable_autoconnect",
    "disable_autoconnect",
]
PROFILE_ACTIONS = {
    "activate",
    "deactivate",
    "enable_autoconnect",
    "disable_autoconnect",
}
PROFILE_FIELDS = "UUID,NAME,TYPE,DEVICE,AUTOCONNECT"
MAX_OUTPUT_BYTES = 256 * 1024
MAX_PROFILE_ROWS = 4_096
MAX_ACTIVE_ROWS = 4_096
QUERY_TIMEOUT_SECONDS = 5
ACTION_WAIT_SECONDS = 12
ACTION_TIMEOUT_SECONDS = 15
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class NetworkManagerProfileTarget:
    action: NetworkManagerProfileAction
    profile: NetworkManagerProfileInfo
    active_count: int


def network_manager_profile_control_available() -> bool:
    return sys.platform.startswith("linux") and bool(
        find_session_binary("nmcli", get_sanitized_env(dict(os.environ)))
    )


def _normalize_uuid(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not UUID_PATTERN.fullmatch(value):
        return None, "profile_uuid must be one exact NetworkManager UUID from list_network_manager_profiles."
    try:
        return str(uuid_module.UUID(value)), None
    except ValueError:
        return None, "profile_uuid is not a valid NetworkManager UUID."


def _command(
    binary: str,
    arguments: list[str],
    env: dict[str, str],
    *,
    label: str,
    timeout_seconds: int,
) -> tuple[str | None, str | None, bool]:
    return run_bounded_command(
        [binary, *arguments],
        env,
        command_label=label,
        timeout_seconds=timeout_seconds,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


def _read_exact_profile(
    binary: str,
    env: dict[str, str],
    profile_uuid: str,
) -> tuple[NetworkManagerProfileInfo | None, str | None]:
    output, error, truncated = _command(
        binary,
        [
            "--wait", str(QUERY_TIMEOUT_SECONDS),
            "--terse", "--escape", "yes", "--fields", PROFILE_FIELDS,
            "connection", "show",
        ],
        env,
        label="Exact NetworkManager profile inspection",
        timeout_seconds=QUERY_TIMEOUT_SECONDS + 1,
    )
    if error or output is None:
        return None, "The exact NetworkManager profile could not be read; permissions or daemon availability may limit access."
    if truncated:
        return None, "The exact NetworkManager profile response exceeded its output limit."
    rows = [row for row in output.splitlines() if row]
    if len(rows) > MAX_PROFILE_ROWS:
        return None, "The NetworkManager profile inventory exceeded its row limit."
    seen: set[str] = set()
    selected: NetworkManagerProfileInfo | None = None
    for row in rows:
        profile = _parse_profile_row(row)
        if profile is None:
            return None, "NetworkManager returned a malformed profile row."
        if profile.uuid in seen:
            return None, "NetworkManager returned a duplicate profile UUID."
        seen.add(profile.uuid)
        if profile.uuid == profile_uuid:
            selected = profile
    if selected is None:
        return None, "The exact NetworkManager profile UUID is no longer present in the current inventory."
    return selected, None


def _read_active_profile_counts(
    binary: str,
    env: dict[str, str],
) -> tuple[Counter[str] | None, str | None]:
    output, error, truncated = _command(
        binary,
        [
            "--wait", str(QUERY_TIMEOUT_SECONDS),
            "--terse", "--fields", "UUID", "connection", "show", "--active",
        ],
        env,
        label="Active NetworkManager profile inventory",
        timeout_seconds=QUERY_TIMEOUT_SECONDS + 1,
    )
    if error or output is None:
        return None, "Active NetworkManager profiles could not be read."
    if truncated:
        return None, "The active NetworkManager profile response exceeded its output limit."
    rows = [row for row in output.splitlines() if row]
    if len(rows) > MAX_ACTIVE_ROWS:
        return None, "The active NetworkManager profile list exceeded its row limit."
    counts: Counter[str] = Counter()
    for row in rows:
        if not UUID_PATTERN.fullmatch(row):
            return None, "NetworkManager returned a malformed UUID in its active profile list."
        try:
            counts[str(uuid_module.UUID(row))] += 1
        except ValueError:
            return None, "NetworkManager returned an invalid UUID in its active profile list."
    return counts, None


def _validate_target_state(
    action: NetworkManagerProfileAction,
    profile: NetworkManagerProfileInfo,
    active_count: int,
) -> str | None:
    if action == "activate" and active_count:
        return "The exact profile is already active; no activation was run."
    if action == "deactivate" and active_count == 0:
        return "The exact profile is not active; no deactivation was run."
    if action == "deactivate" and active_count != 1:
        return "The profile has multiple active instances; deactivation is ambiguous and was refused."
    if action == "enable_autoconnect" and profile.autoconnect is not False:
        return "Autoconnect is already enabled or its state is unavailable; no profile change was run."
    if action == "disable_autoconnect" and profile.autoconnect is not True:
        return "Autoconnect is already disabled or its state is unavailable; no profile change was run."
    return None


def network_manager_profile_confirmation_details(
    action: str,
    profile_uuid: str,
) -> tuple[NetworkManagerProfileTarget | None, str | None]:
    """Read an exact profile and validate one requested action before elicitation."""
    if not isinstance(action, str) or action not in PROFILE_ACTIONS:
        return None, "Choose activate, deactivate, enable_autoconnect, or disable_autoconnect."
    normalized_uuid, error = _normalize_uuid(profile_uuid)
    if error or normalized_uuid is None:
        return None, error
    if not network_manager_profile_control_available():
        return None, "NetworkManager profile control requires Linux and the nmcli command."
    env = get_sanitized_env(dict(os.environ))
    env["LC_ALL"] = "C"
    binary = find_session_binary("nmcli", env)
    if not binary:
        return None, "NetworkManager's nmcli command became unavailable."
    profile, error = _read_exact_profile(binary, env, normalized_uuid)
    if error or profile is None:
        return None, error or "The exact NetworkManager profile could not be verified."
    active_counts, error = _read_active_profile_counts(binary, env)
    if error or active_counts is None:
        return None, error or "Active NetworkManager profile state could not be verified."
    active_count = active_counts[normalized_uuid]
    error = _validate_target_state(action, profile, active_count)
    if error:
        return None, error
    return NetworkManagerProfileTarget(
        action=action,
        profile=profile,
        active_count=active_count,
    ), None


def _response_values(
    action: object,
    profile_uuid: object,
    target: NetworkManagerProfileTarget | None,
) -> dict[str, object]:
    safe_action = action if isinstance(action, str) and action in PROFILE_ACTIONS else "activate"
    safe_uuid, _ = _normalize_uuid(profile_uuid)
    profile = target.profile if target is not None else None
    return {
        "action": safe_action,
        "profile_uuid": profile.uuid if profile is not None else safe_uuid,
        "name": profile.name if profile is not None else None,
        "connection_type": profile.connection_type if profile is not None else None,
        "device": profile.device if profile is not None else None,
        "active_before": target.active_count > 0 if target is not None else None,
        "active_after": None,
        "autoconnect_before": profile.autoconnect if profile is not None else None,
        "autoconnect_after": None,
    }


def _failure(
    values: dict[str, object],
    message: str,
    *,
    user_confirmed: bool,
    active_after: bool | None = None,
    autoconnect_after: bool | None = None,
) -> NetworkManagerProfileActionResponse:
    return NetworkManagerProfileActionResponse(
        success=False,
        **(values | {
            "active_after": active_after,
            "autoconnect_after": autoconnect_after,
        }),
        user_confirmed=user_confirmed,
        message=message,
    )


def _run_profile_action(
    action: NetworkManagerProfileAction,
    profile_uuid: str,
    binary: str,
    env: dict[str, str],
) -> tuple[bool, str | None]:
    arguments = ["--wait", str(ACTION_WAIT_SECONDS), "connection"]
    if action == "activate":
        arguments.extend(("up", "uuid", profile_uuid))
        label = "Activate NetworkManager profile"
    elif action == "deactivate":
        arguments.extend(("down", "uuid", profile_uuid))
        label = "Deactivate NetworkManager profile"
    else:
        value = "yes" if action == "enable_autoconnect" else "no"
        arguments.extend(("modify", "uuid", profile_uuid, "connection.autoconnect", value))
        label = "Change NetworkManager profile autoconnect"
    _output, error, truncated = _command(
        binary,
        arguments,
        env,
        label=label,
        timeout_seconds=ACTION_TIMEOUT_SECONDS,
    )
    if error and "timed out" in error.casefold():
        return False, "The NetworkManager action timed out; its state may be partial. Inspect the profile before retrying."
    if error or truncated:
        return False, "NetworkManager rejected or could not complete the profile action. Inspect the profile before retrying."
    return True, None


def perform_network_manager_profile_action(
    action: str,
    profile_uuid: str,
    *,
    confirmed: bool,
    confirmed_profile_uuid: str | None = None,
) -> NetworkManagerProfileActionResponse:
    if not isinstance(action, str) or action not in PROFILE_ACTIONS:
        values = _response_values(action, profile_uuid, None)
        return _failure(values, "Choose one supported NetworkManager profile action.", user_confirmed=confirmed)
    values = _response_values(action, profile_uuid, None)
    if not confirmed:
        return _failure(
            values,
            "Explicit client confirmation is required; no NetworkManager profile change was run.",
            user_confirmed=False,
        )
    normalized_uuid, error = _normalize_uuid(profile_uuid)
    if error or normalized_uuid is None:
        return _failure(values, error or "The exact NetworkManager profile UUID could not be validated.", user_confirmed=True)
    confirmed_uuid, error = _normalize_uuid(confirmed_profile_uuid)
    if error or confirmed_uuid != normalized_uuid:
        return _failure(
            values,
            "The confirmation did not repeat the exact profile UUID; no change was run.",
            user_confirmed=True,
        )
    if not network_manager_profile_control_available():
        return _failure(values, "NetworkManager profile control requires Linux and nmcli; no change was run.", user_confirmed=True)

    with _ACTION_LOCK:
        env = get_sanitized_env(dict(os.environ))
        env["LC_ALL"] = "C"
        binary = find_session_binary("nmcli", env)
        if not binary:
            return _failure(values, "NetworkManager's nmcli command became unavailable; no change was run.", user_confirmed=True)
        profile, error = _read_exact_profile(binary, env, normalized_uuid)
        if error or profile is None:
            return _failure(values, error or "The exact profile could not be revalidated; no change was run.", user_confirmed=True)
        active_counts, error = _read_active_profile_counts(binary, env)
        if error or active_counts is None:
            return _failure(values, error or "Active profile state could not be revalidated; no change was run.", user_confirmed=True)
        target = NetworkManagerProfileTarget(action, profile, active_counts[normalized_uuid])
        error = _validate_target_state(action, profile, target.active_count)
        values = _response_values(action, normalized_uuid, target)
        if error:
            return _failure(values, error, user_confirmed=True, active_after=target.active_count > 0, autoconnect_after=profile.autoconnect)

        completed, error = _run_profile_action(action, normalized_uuid, binary, env)
        if not completed:
            return _failure(values, error or "The NetworkManager action failed; inspect the profile before retrying.", user_confirmed=True)

        updated_profile, read_error = _read_exact_profile(binary, env, normalized_uuid)
        active_after_counts, active_error = _read_active_profile_counts(binary, env)
        if read_error or updated_profile is None or active_error or active_after_counts is None:
            return _failure(
                values,
                "The NetworkManager command completed but its result could not be verified; inspect the profile before retrying.",
                user_confirmed=True,
            )
        active_after_count = active_after_counts[normalized_uuid]
        active_after = active_after_count > 0
        autoconnect_after = updated_profile.autoconnect
        if action == "activate":
            expected = active_after
        elif action == "deactivate":
            expected = not active_after
        elif action == "enable_autoconnect":
            expected = autoconnect_after is True
        else:
            expected = autoconnect_after is False
        if not expected:
            return _failure(
                values,
                "The command completed, but the profile did not reach the requested state; inspect it before retrying.",
                user_confirmed=True,
                active_after=active_after,
                autoconnect_after=autoconnect_after,
            )
        values.update({
            "name": updated_profile.name,
            "connection_type": updated_profile.connection_type,
            "device": updated_profile.device,
            "active_after": active_after,
            "autoconnect_after": autoconnect_after,
        })
        messages = {
            "activate": "Activated and verified the exact NetworkManager connection profile.",
            "deactivate": (
                "Deactivated and verified the exact NetworkManager connection profile. "
                "NetworkManager blocks it from autoconnecting again until reboot or a later user action."
            ),
            "enable_autoconnect": "Enabled and verified persistent autoconnect for the exact NetworkManager profile.",
            "disable_autoconnect": "Disabled and verified persistent autoconnect for the exact NetworkManager profile.",
        }
        return NetworkManagerProfileActionResponse(
            success=True,
            **values,
            user_confirmed=True,
            message=messages[action],
        )
