"""Confirmation-gated control for exact configured CUPS printer queues."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import PrinterActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.printers import _safe_queue_name, list_printers

PrinterAction = Literal["enable", "disable", "accept", "reject"]
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
COMMANDS = {
    "enable": "cupsenable",
    "disable": "cupsdisable",
    "accept": "cupsaccept",
    "reject": "cupsreject",
}
COMMAND_TIMEOUT_SECONDS = 15
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024


@dataclass(frozen=True)
class PrinterSnapshot:
    printer: str
    state: str
    enabled: bool
    accepting_jobs: bool
    state_token: str


def _state_token(printer: str, state: str, enabled: bool, accepting_jobs: bool) -> str:
    payload = {
        "printer": printer,
        "state": state,
        "enabled": enabled,
        "accepting_jobs": accepting_jobs,
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def printer_control_available() -> bool:
    if not sys.platform.startswith("linux"):
        return False
    env = get_sanitized_env()
    return all(find_session_binary(name, env) for name in ("lpstat", *COMMANDS.values()))


def _read_snapshot(printer: str) -> tuple[PrinterSnapshot | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "CUPS printer control is available only on Linux."
    if not isinstance(printer, str) or not printer or len(printer) > 255 or _safe_queue_name(printer) != printer:
        return None, "Printer must be one exact configured CUPS queue name from list_printers."

    inventory = list_printers(query=printer, limit=200)
    if not inventory.success:
        return None, inventory.message or "CUPS queue state could not be read."
    if inventory.truncated:
        return None, "The CUPS queue query was truncated; the exact queue state cannot be confirmed safely."
    matches = [item for item in inventory.printers if item.name == printer]
    if not matches:
        return None, "The exact configured CUPS printer queue was not found."
    if len(matches) != 1:
        return None, "The exact CUPS printer queue name is ambiguous."
    item = matches[0]
    if item.enabled is None or item.accepting_jobs is None:
        return None, "CUPS did not report complete enabled and job-acceptance state for this queue."
    return PrinterSnapshot(
        printer=item.name,
        state=item.state,
        enabled=item.enabled,
        accepting_jobs=item.accepting_jobs,
        state_token=_state_token(item.name, item.state, item.enabled, item.accepting_jobs),
    ), None


def printer_action_confirmation_details(
    action: str,
    printer: str,
) -> tuple[PrinterSnapshot | None, str | None]:
    if not isinstance(action, str) or action not in COMMANDS:
        return None, "Action must be enable, disable, accept, or reject."
    env = get_sanitized_env()
    command = find_session_binary(COMMANDS[action], env)
    if not command:
        return None, f"The CUPS {COMMANDS[action]} command is unavailable."
    return _read_snapshot(printer)


def _response(
    action: PrinterAction,
    printer: str,
    *,
    confirmed: bool,
    snapshot: PrinterSnapshot | None,
    success: bool,
    verified: bool = False,
    message: str,
) -> PrinterActionResponse:
    return PrinterActionResponse(
        success=success,
        action=action,
        printer=printer,
        enabled=snapshot.enabled if snapshot else None,
        accepting_jobs=snapshot.accepting_jobs if snapshot else None,
        state_verified=verified,
        user_confirmed=confirmed,
        message=message,
    )


def perform_printer_action(
    action: PrinterAction,
    printer: str,
    expected_state_token: str,
    *,
    confirmed: bool = False,
) -> PrinterActionResponse:
    valid_action = isinstance(action, str) and action in COMMANDS
    safe_action: PrinterAction = action if valid_action else "enable"
    safe_printer = printer[:255] if isinstance(printer, str) else ""
    if not valid_action:
        return _response(safe_action, safe_printer, confirmed=False, snapshot=None, success=False, message="Unsupported CUPS printer action supplied; no command was run.")
    if not isinstance(printer, str) or not printer or len(printer) > 255 or _safe_queue_name(printer) != printer:
        return _response(safe_action, safe_printer, confirmed=False, snapshot=None, success=False, message="Printer must be one exact configured CUPS queue name; no command was run.")
    if confirmed is not True:
        return _response(safe_action, safe_printer, confirmed=False, snapshot=None, success=False, message="Explicit client confirmation is required; no CUPS command was run.")

    snapshot, error = _read_snapshot(safe_printer)
    if snapshot is None:
        return _response(safe_action, safe_printer, confirmed=True, snapshot=None, success=False, message=error or "The exact CUPS queue state could not be revalidated; no command was run.")
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return _response(safe_action, safe_printer, confirmed=True, snapshot=snapshot, success=False, message="A valid state token from the exact CUPS queue confirmation is required; no command was run.")
    if snapshot.state_token != expected_state_token:
        return _response(safe_action, safe_printer, confirmed=True, snapshot=snapshot, success=False, message="The CUPS queue state changed after confirmation; review and confirm again.")

    target_state = safe_action in {"enable", "accept"}
    current_state = snapshot.enabled if safe_action in {"enable", "disable"} else snapshot.accepting_jobs
    if current_state == target_state:
        if safe_action in {"enable", "disable"}:
            state_name = "enabled" if current_state else "disabled"
        else:
            state_name = "accepting jobs" if current_state else "rejecting jobs"
        return _response(safe_action, safe_printer, confirmed=True, snapshot=snapshot, success=True, verified=True, message=f"The exact CUPS queue is already {state_name}; no command was needed.")

    env = get_sanitized_env()
    binary = find_session_binary(COMMANDS[safe_action], env)
    if not binary:
        return _response(safe_action, safe_printer, confirmed=True, snapshot=snapshot, success=False, message=f"The CUPS {COMMANDS[safe_action]} command is unavailable; no command was run.")
    _output, command_error, command_truncated = run_bounded_command(
        [binary, snapshot.printer],
        env,
        command_label=f"CUPS {COMMANDS[safe_action]}",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
    )
    if command_truncated:
        command_error = command_error or "CUPS command output exceeded the configured limit."

    verified_snapshot, verify_error = _read_snapshot(safe_printer)
    verified = False
    if verified_snapshot is not None:
        verified_state = verified_snapshot.enabled if safe_action in {"enable", "disable"} else verified_snapshot.accepting_jobs
        verified = verified_state == target_state
    if command_error:
        message = f"CUPS reported an error: {command_error[:500]}"
        if verify_error:
            message += f" {verify_error}"
        return _response(safe_action, safe_printer, confirmed=True, snapshot=verified_snapshot or snapshot, success=False, verified=verified, message=message)
    if not verified:
        return _response(safe_action, safe_printer, confirmed=True, snapshot=verified_snapshot or snapshot, success=False, message=verify_error or "The CUPS queue did not reach the requested state; inspect it before retrying.")
    if safe_action in {"enable", "disable"}:
        state_name = "enabled" if target_state else "disabled"
    else:
        state_name = "accepting jobs" if target_state else "rejecting jobs"
    effect = " Queued jobs may resume printing." if safe_action == "enable" else " The command did not request job cancellation." if safe_action == "disable" else ""
    return _response(safe_action, safe_printer, confirmed=True, snapshot=verified_snapshot, success=True, verified=True, message=f"The exact CUPS queue is now {state_name}.{effect}")
