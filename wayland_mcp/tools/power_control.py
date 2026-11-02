"""Confirmed system power transitions and logind readiness queries."""

from __future__ import annotations

import shlex
import sys

from wayland_mcp.models import (
    PowerAction,
    PowerActionReadinessResponse,
    PowerActionResponse,
    PowerReadinessAction,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_POWER_ACTION_OUTPUT_BYTES = 16 * 1024
POWER_ACTION_TIMEOUT_SECONDS = 7.0
LOGIND_SERVICE = "org.freedesktop.login1"
LOGIND_OBJECT = "/org/freedesktop/login1"
LOGIND_INTERFACE = "org.freedesktop.login1.Manager"

POWER_ACTION_METHODS: dict[str, str] = {
    "poweroff": "PowerOff",
    "reboot": "Reboot",
    "halt": "Halt",
    "suspend": "Suspend",
    "hibernate": "Hibernate",
    "hybrid_sleep": "HybridSleep",
    "suspend_then_hibernate": "SuspendThenHibernate",
}
POWER_READINESS_METHODS: dict[str, str] = {
    "poweroff": "CanPowerOff",
    "reboot": "CanReboot",
    "halt": "CanHalt",
    "suspend": "CanSuspend",
    "hibernate": "CanHibernate",
    "hybrid_sleep": "CanHybridSleep",
    "suspend_then_hibernate": "CanSuspendThenHibernate",
    "reboot_to_firmware_setup": "CanRebootToFirmwareSetup",
}
POWER_ACTION_NAMES = frozenset((*POWER_ACTION_METHODS, "reboot_to_firmware_setup"))
POWER_READINESS_VALUES = {"yes", "no", "challenge", "na"}


def _power_action_validation_error(action: str) -> str | None:
    if not isinstance(action, str) or action not in POWER_ACTION_NAMES:
        return "Action must be one of poweroff, reboot, halt, suspend, hibernate, hybrid_sleep, suspend_then_hibernate, or reboot_to_firmware_setup."
    if not sys.platform.startswith("linux"):
        return "System power actions are available only on Linux."
    env = get_sanitized_env()
    if action == "reboot_to_firmware_setup":
        if not find_session_binary("systemctl", env):
            return "systemctl is unavailable for a firmware-setup reboot request."
    elif not find_session_binary("busctl", env):
        return "busctl is unavailable for the system logind interface."
    return None


def validate_power_action(action: str) -> str | None:
    """Validate one fixed system power action without invoking it."""
    return _power_action_validation_error(action)


def _bounded_error(error: str | None) -> str:
    if not error:
        return "The system power interface did not return a result."
    safe = " ".join("".join(char if char.isprintable() else " " for char in error).split())
    return safe[:400] or "The system power interface did not return a result."


def perform_power_action(action: PowerAction, *, confirmed: bool) -> PowerActionResponse:
    """Request one fixed power action after its MCP resolver has confirmed it."""
    safe_action = action if isinstance(action, str) and action in POWER_ACTION_NAMES else "unknown"
    if not confirmed:
        return PowerActionResponse(
            success=False,
            action=safe_action,
            message="Explicit client confirmation is required; no power action was requested.",
        )

    validation_error = _power_action_validation_error(action)
    if validation_error:
        return PowerActionResponse(
            success=False,
            action=safe_action,
            user_confirmed=True,
            message=validation_error,
        )

    env = get_sanitized_env()
    if action == "reboot_to_firmware_setup":
        systemctl = find_session_binary("systemctl", env)
        if not systemctl:
            return PowerActionResponse(
                success=False,
                action=action,
                user_confirmed=True,
                message="systemctl became unavailable before the request could run.",
            )
        command = [
            systemctl,
            "--no-ask-password",
            "--no-block",
            "--firmware-setup",
            "reboot",
        ]
        command_label = "firmware-setup reboot request"
    else:
        busctl = find_session_binary("busctl", env)
        if not busctl:
            return PowerActionResponse(
                success=False,
                action=action,
                user_confirmed=True,
                message="busctl became unavailable before the logind request could run.",
            )
        command = [
            busctl,
            "--system",
            f"--timeout={int(POWER_ACTION_TIMEOUT_SECONDS)}s",
            "call",
            LOGIND_SERVICE,
            LOGIND_OBJECT,
            LOGIND_INTERFACE,
            POWER_ACTION_METHODS[action],
            "b",
            "false",
        ]
        command_label = "logind power-action request"

    output, error, output_truncated = run_bounded_command(
        command,
        env,
        command_label=command_label,
        timeout_seconds=POWER_ACTION_TIMEOUT_SECONDS,
        max_output_bytes=MAX_POWER_ACTION_OUTPUT_BYTES,
    )
    if output is None:
        if error and "timed out" in error.casefold():
            message = (
                "The power-action request timed out without a reply; the transition may already be in progress. "
                "Check the system state before retrying."
            )
        else:
            message = f"The power-action request failed: {_bounded_error(error)}"
        return PowerActionResponse(
            success=False,
            action=action,
            user_confirmed=True,
            message=message,
        )
    if output_truncated:
        return PowerActionResponse(
            success=False,
            action=action,
            user_confirmed=True,
            message="The response exceeded the output bound; the transition may have been accepted. Check system state before retrying.",
        )

    message = (
        "systemd accepted the firmware-setup reboot request. Firmware and bootloader support, and completion of the reboot, are not verified."
        if action == "reboot_to_firmware_setup"
        else f"logind accepted the {action.replace('_', ' ')} request. Hardware or firmware may still fail to complete the transition."
    )
    return PowerActionResponse(
        success=True,
        action=action,
        user_confirmed=True,
        message=message,
    )


def _parse_availability(output: str) -> str | None:
    try:
        fields = shlex.split(output, posix=True)
    except ValueError:
        return None
    if len(fields) != 2 or fields[0] != "s" or fields[1] not in POWER_READINESS_VALUES:
        return None
    return fields[1]


def get_power_action_readiness(action: PowerReadinessAction) -> PowerActionReadinessResponse:
    """Read logind's current support/authorization result for one power operation."""
    if not isinstance(action, str) or action not in POWER_READINESS_METHODS:
        return PowerActionReadinessResponse(
            success=False,
            action="unknown",
            message="Action is not supported by the logind readiness interface.",
        )
    safe_action = action
    if not sys.platform.startswith("linux"):
        return PowerActionReadinessResponse(
            success=False,
            action=safe_action,
            message="Power-action readiness is available only on Linux.",
        )
    env = get_sanitized_env()
    busctl = find_session_binary("busctl", env)
    if not busctl:
        return PowerActionReadinessResponse(
            success=False,
            action=safe_action,
            message="busctl is unavailable for the system logind interface.",
        )

    output, error, output_truncated = run_bounded_command(
        [
            busctl,
            "--system",
            "--timeout=4s",
            "call",
            LOGIND_SERVICE,
            LOGIND_OBJECT,
            LOGIND_INTERFACE,
            POWER_READINESS_METHODS[safe_action],
        ],
        env,
        command_label="logind power-action readiness query",
        timeout_seconds=5.0,
        max_output_bytes=1024,
    )
    if output is None or output_truncated:
        message = (
            "The logind readiness response exceeded the output bound."
            if output_truncated
            else f"The logind readiness query failed: {_bounded_error(error)}"
        )
        return PowerActionReadinessResponse(success=False, action=safe_action, message=message)
    availability = _parse_availability(output)
    if availability is None:
        return PowerActionReadinessResponse(
            success=False,
            action=safe_action,
            message="logind returned an unrecognized readiness result.",
        )

    explanations = {
        "yes": "logind currently reports the operation as supported and allowed for this caller; this does not guarantee transition success.",
        "no": "logind currently reports the operation as unavailable to this caller.",
        "challenge": "logind reports that additional authorization is required; manage_power_action does not request interactive authorization.",
        "na": "logind reports that the operation is unsupported by the current system configuration or hardware.",
    }
    return PowerActionReadinessResponse(
        success=True,
        action=safe_action,
        availability=availability,
        message=explanations[availability],
    )
