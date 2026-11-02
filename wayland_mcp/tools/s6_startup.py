"""Confirmed enable/disable changes to the offline s6-frontend startup set."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import S6StartupSetResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.host import _detect_init_system
from wayland_mcp.tools.services import SERVICE_NAME_RE

S6StartupAction = Literal["enable", "disable"]
PRESCRIPTIONS = {"active", "usable", "always", "masked"}
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
COMMAND_TIMEOUT_SECONDS = 15
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024


@dataclass(frozen=True)
class S6StartupSetSnapshot:
    unit: str
    prescription: str
    s6_binary: str
    configuration_fingerprint: str
    state_token: str


def s6_startup_set_available() -> bool:
    if not sys.platform.startswith("linux") or _detect_init_system() != "s6-svscan":
        return False
    return bool(find_session_binary("s6", get_sanitized_env()))


def _configuration_fingerprint(binary: str, env: dict[str, str]) -> tuple[str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "version", "export"],
        env,
        command_label="s6 configuration export",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
    )
    if output is None:
        return None, error or "The effective s6 configuration could not be inspected."
    if truncated:
        return None, "The effective s6 configuration output was truncated."
    return hashlib.sha256(output.encode("utf-8")).hexdigest(), None


def _read_snapshot(unit: str) -> tuple[S6StartupSetSnapshot | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "s6 startup-set control is available only on Linux."
    if _detect_init_system() != "s6-svscan":
        return None, "s6 startup-set control requires s6-svscan as the active init system."
    if not isinstance(unit, str) or len(unit) > 255 or not SERVICE_NAME_RE.fullmatch(unit):
        return None, "Service must be one exact s6 atomic-service name."

    env = get_sanitized_env()
    binary = find_session_binary("s6", env)
    if not binary:
        return None, "The s6-frontend s6 command is unavailable."
    configuration_fingerprint, configuration_error = _configuration_fingerprint(binary, env)
    if configuration_fingerprint is None:
        return None, configuration_error or "The effective s6 configuration could not be inspected."
    output, error, truncated = run_bounded_command(
        [binary, "set", "status", "-E", unit],
        env,
        command_label="s6 startup-set status",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
    )
    if output is None:
        return None, error or "The s6 offline startup set could not be read."
    if truncated:
        return None, "The s6 startup-set status output was truncated; exact service state cannot be confirmed."

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        return None, "s6 did not report exactly one startup-set state for this service."
    fields = lines[0].rsplit("/", 1)
    if len(fields) != 2 or fields[0] != unit or fields[1] not in PRESCRIPTIONS:
        return None, "s6 returned an unrecognized startup-set row for this exact service."
    prescription = fields[1]
    token_payload = {
        "unit": unit,
        "prescription": prescription,
        "s6_binary": binary,
        "configuration_fingerprint": configuration_fingerprint,
    }
    encoded = json.dumps(token_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return S6StartupSetSnapshot(
        unit=unit,
        prescription=prescription,
        s6_binary=binary,
        configuration_fingerprint=configuration_fingerprint,
        state_token=hashlib.sha256(encoded).hexdigest(),
    ), None


def s6_startup_confirmation_details(
    action: str,
    unit: str,
) -> tuple[S6StartupSetSnapshot | None, str | None]:
    if not isinstance(action, str) or action not in {"enable", "disable"}:
        return None, "Action must be enable or disable."
    snapshot, error = _read_snapshot(unit)
    if snapshot is None:
        return None, error
    if snapshot.prescription not in {"active", "usable"}:
        state = "essential" if snapshot.prescription == "always" else "masked"
        return None, f"The exact service is {state} in the s6 working set; only enabled/disabled services can be changed."
    return snapshot, None


def _startup_state(snapshot: S6StartupSetSnapshot | None) -> str | None:
    if snapshot is None:
        return None
    return {
        "active": "enabled",
        "usable": "disabled",
        "always": "essential",
        "masked": "masked",
    }.get(snapshot.prescription)


def _response(
    action: S6StartupAction,
    unit: str,
    *,
    confirmed: bool,
    snapshot: S6StartupSetSnapshot | None,
    success: bool,
    verified: bool = False,
    message: str,
) -> S6StartupSetResponse:
    return S6StartupSetResponse(
        success=success,
        action=action,
        unit=unit,
        startup_state=_startup_state(snapshot),
        state_verified=verified,
        user_confirmed=confirmed,
        message=message,
    )


def perform_s6_startup_set(
    action: S6StartupAction,
    unit: str,
    expected_state_token: str,
    *,
    confirmed: bool = False,
) -> S6StartupSetResponse:
    valid_action = isinstance(action, str) and action in {"enable", "disable"}
    safe_action: S6StartupAction = action if valid_action else "enable"
    safe_unit = unit[:255] if isinstance(unit, str) else ""
    if not valid_action:
        return _response(safe_action, safe_unit, confirmed=False, snapshot=None, success=False, message="Unsupported s6 startup action supplied; no command was run.")
    if not isinstance(unit, str) or len(unit) > 255 or not SERVICE_NAME_RE.fullmatch(unit):
        return _response(safe_action, safe_unit, confirmed=False, snapshot=None, success=False, message="Service must be one exact s6 atomic-service name; no command was run.")
    if confirmed is not True:
        return _response(safe_action, safe_unit, confirmed=False, snapshot=None, success=False, message="Explicit client confirmation is required; no s6 command was run.")

    snapshot, error = _read_snapshot(safe_unit)
    if snapshot is None:
        return _response(safe_action, safe_unit, confirmed=True, snapshot=None, success=False, message=error or "The exact s6 startup-set state could not be revalidated; no change was made.")
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return _response(safe_action, safe_unit, confirmed=True, snapshot=snapshot, success=False, message="A valid state token from the exact s6 startup-set confirmation is required; no change was made.")
    if snapshot.state_token != expected_state_token:
        return _response(safe_action, safe_unit, confirmed=True, snapshot=snapshot, success=False, message="The s6 startup-set state changed after confirmation; review and confirm again.")
    if snapshot.prescription not in {"active", "usable"}:
        state = "essential" if snapshot.prescription == "always" else "masked"
        return _response(safe_action, safe_unit, confirmed=True, snapshot=snapshot, success=False, message=f"The exact service is {state} in the s6 working set; no change was made.")

    target_prescription = "active" if safe_action == "enable" else "usable"
    if snapshot.prescription == target_prescription:
        state = "enabled" if safe_action == "enable" else "disabled"
        return _response(safe_action, safe_unit, confirmed=True, snapshot=snapshot, success=True, verified=True, message=f"The exact service is already {state} in the offline s6 working set; no command was needed. The live service database was not changed, and commit/install is still required before boot behavior changes.")

    env = get_sanitized_env()
    binary = find_session_binary("s6", env)
    if not binary or binary != snapshot.s6_binary:
        return _response(safe_action, safe_unit, confirmed=True, snapshot=snapshot, success=False, message="The s6 command changed or became unavailable after confirmation; no command was run.")
    _output, command_error, command_truncated = run_bounded_command(
        [binary, "set", safe_action, "-i", safe_unit],
        env,
        command_label=f"s6 set {safe_action}",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
    )
    if command_truncated:
        command_error = command_error or "s6 command output exceeded the configured limit."

    verified_snapshot, verify_error = _read_snapshot(safe_unit)
    same_configuration = (
        verified_snapshot is not None
        and verified_snapshot.configuration_fingerprint == snapshot.configuration_fingerprint
    )
    verified = (
        verified_snapshot is not None
        and verified_snapshot.prescription == target_prescription
        and same_configuration
    )
    if command_error:
        message = "The s6 command did not report success; inspect the startup set before retrying."
        if verify_error:
            message += f" {verify_error}"
        return _response(safe_action, safe_unit, confirmed=True, snapshot=verified_snapshot or snapshot, success=False, verified=verified, message=message)
    if not verified:
        message = verify_error or (
            "The effective s6 configuration changed during the operation; inspect the working set before retrying."
            if verified_snapshot is not None and not same_configuration
            else "The s6 working set did not reach the requested state; inspect it before retrying."
        )
        return _response(safe_action, safe_unit, confirmed=True, snapshot=verified_snapshot or snapshot, success=False, message=message)

    state = "enabled" if safe_action == "enable" else "disabled"
    return _response(
        safe_action,
        safe_unit,
        confirmed=True,
        snapshot=verified_snapshot,
        success=True,
        verified=True,
        message=(
            f"The exact service is now {state} in the offline s6 working set. This does not change the live service database or current service state; "
            "the working set must be committed and installed before it affects boot. The service-set dependency check passed without changing other prescriptions."
        ),
    )
