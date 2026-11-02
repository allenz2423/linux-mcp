"""Bounded local QEMU/libvirt VM inventory and confirmed lifecycle actions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import (
    VirtualMachineActionResponse,
    VirtualMachineInfo,
    VirtualMachineListResponse,
)
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.libvirt_common import (
    SCOPED_URIS,
    virsh_available,
    virsh_environment,
)

VirtualMachineScope = Literal["system", "session"]
VirtualMachineAction = Literal["start", "shutdown", "reboot", "suspend", "resume"]
SCOPES = {"system", "session"}
ACTIONS = {"start", "shutdown", "reboot", "suspend", "resume"}
ACTIVE_STATES = {"running", "idle"}
DOMAIN_STATES = (
    "in shutdown", "shut off", "pmsuspended", "running", "paused", "crashed", "idle", "blocked",
)
UUID_RE = re.compile(r"(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
DOMAIN_ID_RE = re.compile(r"^(-|[0-9]{1,10})\s+(.*)$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,100}$")
MAX_SCANNED_DOMAINS = 2_000
MAX_RETURNED_DOMAINS = 200
MAX_VIRSH_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_ACTION_OUTPUT_BYTES = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 15
ACTION_TIMEOUT_SECONDS = 30
TOKEN_TTL_SECONDS = 180


@dataclass(frozen=True, slots=True)
class _Domain:
    scope: VirtualMachineScope
    uuid: str
    name: str
    state: str
    domain_id: int | None


@dataclass(slots=True)
class _ActionToken:
    scope: VirtualMachineScope
    uuid: str
    name: str
    state: str
    domain_id: int | None
    virsh: str
    expires_at: float
    claimed: bool = False
    action: str | None = None
    confirmation_token: str | None = None


@dataclass(frozen=True, slots=True)
class _ActionTarget:
    scope: VirtualMachineScope
    uuid: str
    name: str
    state: str
    domain_id: int | None
    confirmation_token: str


_TOKENS: dict[str, _ActionToken] = {}
_TOKEN_LOCK = threading.Lock()


def _clean_text(value: str, limit: int = 255) -> str:
    return "".join(
        character for character in value
        if ord(character) >= 32 and ord(character) != 127
    )[:limit].strip()


def _parse_domain_row(line: str, scope: VirtualMachineScope) -> _Domain | None:
    raw = line.rstrip()
    uuid_match = UUID_RE.search(raw)
    if uuid_match is None:
        return None
    domain_uuid = uuid_match.group(1).lower()
    prefix = raw[:uuid_match.start()].rstrip()
    id_match = DOMAIN_ID_RE.match(prefix.strip())
    if id_match is None:
        return None
    id_text, remainder = id_match.groups()
    state = next(
        (
            candidate for candidate in DOMAIN_STATES
            if remainder.casefold().endswith(candidate)
            and len(remainder) > len(candidate)
            and remainder[-len(candidate) - 1].isspace()
        ),
        None,
    )
    if state is None:
        return None
    name = _clean_text(remainder[:-(len(state))])
    if not name:
        return None
    domain_id = int(id_text) if id_text.isdigit() else None
    return _Domain(scope, domain_uuid, name, state, domain_id)


def _read_scope(
    scope: str,
    virsh: str | None = None,
) -> tuple[list[_Domain] | None, str | None, bool]:
    if not sys.platform.startswith("linux"):
        return None, "Libvirt VM inventory is available only on Linux.", False
    if not isinstance(scope, str) or scope not in SCOPES:
        return None, "Choose the local system or user-session QEMU connection.", False
    env = virsh_environment()
    binary = virsh or find_session_binary("virsh", env)
    if not binary:
        return None, "The optional virsh command is unavailable.", False
    output, error, output_truncated = run_bounded_command(
        [
            binary,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[scope],
            "--readonly",
            "list",
            "--all",
            "--table",
            "--uuid",
        ],
        env,
        command_label=f"local libvirt {scope} domain inventory",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_VIRSH_OUTPUT_BYTES,
    )
    if error or output is None:
        return None, error or "virsh returned no inventory output.", output_truncated

    lines = output.splitlines()
    source_truncated = output_truncated or len(lines) > MAX_SCANNED_DOMAINS
    domains: list[_Domain] = []
    invalid_rows = 0
    for line in lines[:MAX_SCANNED_DOMAINS]:
        if not UUID_RE.search(line.rstrip()):
            continue
        domain = _parse_domain_row(line, scope)  # type: ignore[arg-type]
        if domain is None:
            invalid_rows += 1
        else:
            domains.append(domain)
    if invalid_rows:
        source_truncated = True
    return domains, None, source_truncated


def _prune_tokens_locked(now: float) -> None:
    expired = [key for key, record in _TOKENS.items() if record.expires_at <= now]
    for key in expired:
        _TOKENS.pop(key, None)


def _issue_token(domain: _Domain, virsh: str) -> str:
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _ActionToken(
        scope=domain.scope,
        uuid=domain.uuid,
        name=domain.name,
        state=domain.state,
        domain_id=domain.domain_id,
        virsh=virsh,
        expires_at=now + TOKEN_TTL_SECONDS,
    )
    with _TOKEN_LOCK:
        _prune_tokens_locked(now)
        _TOKENS[token] = record
    return token


def _token_record(token: str) -> tuple[_ActionToken | None, str | None]:
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        return None, "A fresh identity token from list_virtual_machines is required."
    with _TOKEN_LOCK:
        _prune_tokens_locked(time.monotonic())
        record = _TOKENS.get(token)
    if record is None:
        return None, "The virtual-machine identity token is unknown or expired; list virtual machines again."
    return record, None


def _lookup_current(record: _ActionToken) -> tuple[_Domain | None, str | None]:
    domains, error, _truncated = _read_scope(record.scope, record.virsh)
    if domains is None:
        return None, error
    matches = [domain for domain in domains if domain.uuid == record.uuid]
    if len(matches) != 1:
        return None, "The exact libvirt domain is missing or ambiguous; list virtual machines again."
    current = matches[0]
    if current.name != record.name:
        return None, "The exact domain name changed after it was listed; list virtual machines again."
    return current, None


def _state_error(action: str, state: str) -> tuple[str | None, bool]:
    """Return an invalid-state explanation and whether the requested state is already reached."""
    if action == "start":
        if state in ACTIVE_STATES | {"paused"}:
            return None, True
        if state == "shut off":
            return None, False
        return f"A domain in state {state!r} cannot be started by this action.", False
    if action == "shutdown":
        if state in {"shut off", "in shutdown"}:
            return None, True
        if state in ACTIVE_STATES:
            return None, False
        return f"A domain in state {state!r} cannot be shut down gracefully by this action.", False
    if action == "reboot":
        if state in ACTIVE_STATES:
            return None, False
        return f"A domain in state {state!r} cannot be rebooted by this action.", False
    if action == "suspend":
        if state == "paused":
            return None, True
        if state in ACTIVE_STATES:
            return None, False
        return f"A domain in state {state!r} cannot be suspended by this action.", False
    if action == "resume":
        if state in ACTIVE_STATES:
            return None, True
        if state == "paused":
            return None, False
        return f"A domain in state {state!r} cannot be resumed by this action.", False
    return "Unsupported libvirt domain action.", False


def list_virtual_machines(
    scope: str = "both",
    query: str = "",
    limit: int = 100,
) -> VirtualMachineListResponse:
    """List local QEMU domains through fixed read-only libvirt connections."""
    if not isinstance(scope, str) or scope not in {"system", "session", "both"}:
        return VirtualMachineListResponse(success=False, scope="both", message="Scope must be system, session, or both.")
    if not isinstance(query, str) or len(query) > 256:
        return VirtualMachineListResponse(success=False, scope=scope, message="Query must be text with at most 256 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in query):
        return VirtualMachineListResponse(success=False, scope=scope, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return VirtualMachineListResponse(success=False, scope=scope, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_DOMAINS))
    env = virsh_environment()
    virsh = find_session_binary("virsh", env)
    if not sys.platform.startswith("linux"):
        return VirtualMachineListResponse(success=False, scope=scope, limit=limit, message="Libvirt VM inventory is available only on Linux.")
    if not virsh:
        return VirtualMachineListResponse(success=False, scope=scope, limit=limit, message="The optional virsh command is unavailable.")

    scopes = ("system", "session") if scope == "both" else (scope,)
    domains: list[_Domain] = []
    errors: list[str] = []
    successful_scopes = 0
    truncated = False
    for selected_scope in scopes:
        items, error, scope_truncated = _read_scope(selected_scope, virsh)
        if error:
            errors.append(f"{selected_scope} scope: {error[:400]}")
            continue
        successful_scopes += 1
        truncated |= scope_truncated
        domains.extend(items or [])

    needle = query.strip().casefold()
    filtered = [
        domain for domain in domains
        if not needle
        or needle in domain.uuid
        or needle in domain.name.casefold()
        or needle in domain.state.casefold()
    ]
    filtered.sort(key=lambda domain: (domain.scope, domain.name.casefold(), domain.uuid))
    selected = filtered[:limit]
    virtual_machines = [
        VirtualMachineInfo(
            scope=domain.scope,
            uuid=domain.uuid,
            name=domain.name,
            state=domain.state,
            domain_id=domain.domain_id,
            identity_token=_issue_token(domain, virsh),
        )
        for domain in selected
    ]
    truncated |= len(filtered) > limit
    if truncated:
        errors.append("The libvirt domain inventory was capped by scan, output, or result limits.")
    return VirtualMachineListResponse(
        success=successful_scopes > 0,
        scope=scope,  # type: ignore[arg-type]
        total_virtual_machines=len(filtered),
        returned_virtual_machines=len(virtual_machines),
        virtual_machines=virtual_machines,
        limit=limit,
        truncated=truncated,
        partial=bool(errors),
        message=" ".join(errors[:4]) or None,
    )


def virtual_machine_action_confirmation_details(
    action: str,
    identity_token: str,
) -> tuple[_ActionTarget | None, str | None]:
    if not isinstance(action, str) or action not in ACTIONS:
        return None, "Choose start, shutdown, reboot, suspend, or resume."
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, error
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.expires_at <= time.monotonic():
            _TOKENS.pop(identity_token, None)
            return None, "The virtual-machine identity token expired; list virtual machines again."
        if record.claimed:
            return None, "This virtual-machine token is already being used for an action. List virtual machines again."
        record.claimed = True

    current, error = _lookup_current(record)
    if error or current is None:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, error
    if current.state != record.state or current.domain_id != record.domain_id:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, "The domain state changed after it was listed; inspect the current VM and try again."
    state_error, _already_reached = _state_error(action, current.state)
    if state_error:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, state_error

    token_payload = {
        "action": action,
        "scope": record.scope,
        "uuid": record.uuid,
        "name": record.name,
        "state": current.state,
        "domain_id": current.domain_id,
        "uid": os.getuid(),
        "euid": os.geteuid(),
    }
    confirmation_token = hashlib.sha256(
        json.dumps(token_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    record.action = action
    record.confirmation_token = confirmation_token
    return _ActionTarget(
        scope=record.scope,
        uuid=record.uuid,
        name=record.name,
        state=current.state,
        domain_id=current.domain_id,
        confirmation_token=confirmation_token,
    ), None


def _post_state_verified(action: str, state: str) -> bool:
    if action == "start":
        return state in ACTIVE_STATES | {"paused"}
    if action == "shutdown":
        return state in {"in shutdown", "shut off"}
    if action == "suspend":
        return state == "paused"
    if action == "resume":
        return state in ACTIVE_STATES
    # virsh reboot returns before the guest necessarily completes its reboot.
    return False


def perform_virtual_machine_action(
    action: str,
    identity_token: str,
    expected_state_token: str,
    confirmed_scope: str,
    confirmed_uuid: str,
    confirmed_name: str,
    *,
    confirmed: bool,
) -> VirtualMachineActionResponse:
    safe_action: VirtualMachineAction = action if isinstance(action, str) and action in ACTIONS else "start"  # type: ignore[assignment]
    record, error = _token_record(identity_token)
    if error or record is None:
        return VirtualMachineActionResponse(success=False, action=safe_action, message=error or "A fresh VM identity token is required.")
    response_target = {
        "scope": record.scope,
        "uuid": record.uuid,
        "name": record.name,
    }
    try:
        if confirmed is not True:
            return VirtualMachineActionResponse(success=False, action=safe_action, **response_target, message="Explicit client confirmation is required; no libvirt command was run.")
        if not isinstance(action, str) or action not in ACTIONS:
            return VirtualMachineActionResponse(success=False, action=safe_action, **response_target, user_confirmed=True, message="Unsupported libvirt VM action; no command was run.")
        if not record.claimed or record.action != action:
            return VirtualMachineActionResponse(success=False, action=safe_action, **response_target, user_confirmed=True, message="The action was not confirmed from a fresh virtual-machine token.")
        if (
            record.scope != confirmed_scope
            or record.uuid != confirmed_uuid
            or record.name != confirmed_name
            or record.confirmation_token != expected_state_token
        ):
            return VirtualMachineActionResponse(success=False, action=safe_action, **response_target, user_confirmed=True, message="Confirmation did not match the exact VM, scope, action, or current-state token; no command was run.")

        current, error = _lookup_current(record)
        if error or current is None:
            return VirtualMachineActionResponse(success=False, action=safe_action, **response_target, user_confirmed=True, message=error or "The exact libvirt domain could not be revalidated.")
        if current.state != record.state or current.domain_id != record.domain_id:
            return VirtualMachineActionResponse(success=False, action=safe_action, **response_target, state=current.state, user_confirmed=True, message="The domain state changed after confirmation; inspect it and confirm again before another action.")
        state_error, already_reached = _state_error(action, current.state)
        if state_error:
            return VirtualMachineActionResponse(success=False, action=safe_action, **response_target, state=current.state, user_confirmed=True, message=state_error)
        if already_reached:
            return VirtualMachineActionResponse(success=True, action=safe_action, **response_target, state=current.state, state_verified=True, user_confirmed=True, message=f"The domain is already in the requested state for {action}; no command was needed.")

        env = virsh_environment()
        command = [
            record.virsh,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[record.scope],
            action,
            record.uuid,
        ]
        _output, command_error, command_truncated = run_bounded_command(
            command,
            env,
            command_label=f"local libvirt VM {action}",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
        )
        if command_truncated:
            command_error = command_error or "virsh output exceeded the configured limit."

        after, verify_error = _lookup_current(record)
        state = after.state if after is not None else None
        verified = _post_state_verified(action, state) if state is not None else False
        if command_error:
            message = f"virsh reported an error: {command_error[:400]}"
            if verify_error:
                message += f" {verify_error}"
            if verified:
                message += " The requested state is visible now; inspect the domain before retrying."
            return VirtualMachineActionResponse(success=False, action=safe_action, **response_target, state=state, state_verified=verified, user_confirmed=True, message=message)
        if action == "reboot":
            message = "The reboot request was accepted; guest reboot completion is asynchronous and was not verified. Call list_virtual_machines to inspect the domain."
        elif verified:
            message = f"The domain action {action} reached state {state!r}."
        else:
            message = f"The domain action {action} was accepted, but the requested state is not yet visible. Current state: {state or 'unavailable'}. Inspect the domain before retrying."
            if verify_error:
                message += f" {verify_error}"
        return VirtualMachineActionResponse(
            success=True,
            action=safe_action,
            **response_target,
            state=state,
            state_verified=verified,
            user_confirmed=True,
            message=message,
        )
    finally:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
