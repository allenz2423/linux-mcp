"""Constrained remote QEMU/libvirt VM inventory and confirmed lifecycle actions."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import stat
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlsplit

from wayland_mcp.models import (
    RemoteVirtualMachineActionResponse,
    RemoteVirtualMachineInfo,
    RemoteVirtualMachineListResponse,
)
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.libvirt_common import virsh_environment
from wayland_mcp.tools.virtual_machines import (
    ACTIONS as LOCAL_ACTIONS,
    DOMAIN_STATES,
    DOMAIN_ID_RE,
    MAX_ACTION_OUTPUT_BYTES,
    MAX_RETURNED_DOMAINS,
    MAX_SCANNED_DOMAINS,
    MAX_VIRSH_OUTPUT_BYTES,
    TOKEN_RE,
    TOKEN_TTL_SECONDS,
    UUID_RE,
    _Domain,
    _clean_text,
    _post_state_verified,
    _state_error,
)

RemoteAction = Literal["start", "shutdown", "reboot", "suspend", "resume"]
REMOTE_ACTIONS = LOCAL_ACTIONS
COMMAND_TIMEOUT_SECONDS = 20
ACTION_TIMEOUT_SECONDS = 45
MAX_ENDPOINT_LENGTH = 512
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9])?$")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


@dataclass(frozen=True, slots=True)
class _Endpoint:
    canonical: str
    scope: Literal["system", "session"]


@dataclass(slots=True)
class _RemoteActionToken:
    endpoint: str
    scope: Literal["system", "session"]
    uuid: str
    name: str
    state: str
    domain_id: int | None
    expires_at: float
    claimed: bool = False
    action: str | None = None
    confirmation_token: str | None = None


@dataclass(frozen=True, slots=True)
class _RemoteActionTarget:
    endpoint: str
    scope: Literal["system", "session"]
    uuid: str
    name: str
    state: str
    domain_id: int | None
    confirmation_token: str


_TOKENS: dict[str, _RemoteActionToken] = {}
_TOKEN_LOCK = threading.Lock()


def _parse_endpoint(value: str) -> tuple[_Endpoint | None, str | None]:
    if not isinstance(value, str) or not value or len(value) > MAX_ENDPOINT_LENGTH:
        return None, "Endpoint must be a qemu+ssh URI no longer than 512 characters."
    if any(ord(character) < 33 or ord(character) == 127 for character in value):
        return None, "Endpoint cannot contain whitespace or control characters."
    if "%" in value:
        return None, "Percent-encoded endpoint components are not supported."
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None, "Endpoint has invalid URI syntax or port."
    if parsed.scheme.casefold() != "qemu+ssh":
        return None, "Only qemu+ssh remote URIs are supported."
    if not parsed.netloc or not parsed.hostname:
        return None, "Endpoint must include a remote host."
    if parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in {"/system", "/session"}:
        return None, "Endpoint must have no password, query, or fragment and must end in /system or /session."

    raw_userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
    if "@" in raw_userinfo or ":" in raw_userinfo or "%" in raw_userinfo:
        return None, "Endpoint may include one plain SSH username, but no password or encoded user information."
    if raw_userinfo and (not USER_RE.fullmatch(raw_userinfo) or raw_userinfo.startswith("-")):
        return None, "Endpoint SSH username contains unsupported characters."

    host = parsed.hostname
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ipaddress.AddressValueError:
            return None, "Endpoint IPv6 host is invalid."
        if not parsed.netloc.rsplit("@", 1)[-1].startswith("["):
            return None, "IPv6 hosts must be enclosed in brackets."
        host_text = f"[{host}]"
    else:
        if not HOST_RE.fullmatch(host) or host.startswith("-"):
            return None, "Endpoint host contains unsupported characters."
        host_text = host
    if port is not None and not (1 <= port <= 65535):
        return None, "Endpoint port must be between 1 and 65535."

    host_port = f"{host_text}:{port}" if port is not None else host_text
    username_prefix = f"{raw_userinfo}@" if raw_userinfo else ""
    canonical = f"qemu+ssh://{username_prefix}{host_port}{parsed.path}"
    scope: Literal["system", "session"] = "system" if parsed.path == "/system" else "session"
    return _Endpoint(canonical=canonical, scope=scope), None


def _agent_socket_for_current_user() -> str | None:
    """Expose only this process user's existing SSH agent socket to remote virsh."""
    raw = os.environ.get("SSH_AUTH_SOCK", "")
    if not raw or not os.path.isabs(raw):
        return None
    try:
        info = os.lstat(raw)
    except OSError:
        return None
    if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid():
        return raw
    return None


def _remote_env() -> dict[str, str]:
    env = virsh_environment()
    agent_socket = _agent_socket_for_current_user()
    if agent_socket:
        env["SSH_AUTH_SOCK"] = agent_socket
    return env


def _run_remote_virsh(
    endpoint: str,
    arguments: list[str],
    *,
    readonly: bool,
    quiet: bool = True,
    timeout_seconds: int,
    max_output_bytes: int,
    command_label: str,
) -> tuple[str | None, str | None, bool]:
    parsed, error = _parse_endpoint(endpoint)
    if error or parsed is None:
        return None, error or "Remote endpoint is invalid.", False
    if not sys.platform.startswith("linux"):
        return None, "Remote libvirt VM tools are available only on Linux.", False
    env = _remote_env()
    virsh = find_session_binary("virsh", env)
    ssh = find_session_binary("ssh", env)
    if not virsh:
        return None, "The optional virsh command is unavailable.", False
    if not ssh:
        return None, "The OpenSSH client is required for qemu+ssh connections.", False

    try:
        with tempfile.TemporaryDirectory(prefix="linux-mcp-libvirt-ssh-", dir="/tmp") as temporary_directory:
            wrapper = Path(temporary_directory) / "ssh"
            wrapper.write_text(
                "#!/bin/sh\n"
                f"exec {shlex.quote(ssh)} -F /dev/null -oBatchMode=yes "
                "-oForwardAgent=no -oStrictHostKeyChecking=yes \"$@\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            connection_uri = (
                parsed.canonical
                + "?no_tty=1&command="
                + quote(str(wrapper), safe="/")
            )
            command = [virsh]
            if quiet:
                command.append("--quiet")
            command.extend(("--no-pkttyagent", "--connect", connection_uri))
            if readonly:
                command.append("--readonly")
            command.extend(arguments)
            return run_bounded_command(
                command,
                env,
                command_label=command_label,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                kill_process_group=True,
            )
    except OSError:
        return None, "A private temporary OpenSSH wrapper could not be prepared.", False


def remote_virsh_available(env: dict[str, str] | None = None) -> bool:
    selected_env = env or _remote_env()
    return (
        sys.platform.startswith("linux")
        and find_session_binary("virsh", selected_env) is not None
        and find_session_binary("ssh", selected_env) is not None
    )


def _parse_remote_domain_row(line: str, scope: Literal["system", "session"]) -> _Domain | None:
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


def _read_remote_domains(endpoint: str) -> tuple[list[_Domain] | None, str | None, bool]:
    parsed, error = _parse_endpoint(endpoint)
    if error or parsed is None:
        return None, error or "Remote endpoint is invalid.", False
    output, command_error, truncated = _run_remote_virsh(
        parsed.canonical,
        ["list", "--all", "--table", "--uuid"],
        readonly=True,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_VIRSH_OUTPUT_BYTES,
        command_label="remote libvirt domain inventory",
    )
    if command_error or output is None:
        return None, command_error or "Remote virsh returned no inventory output.", truncated
    lines = output.splitlines()
    source_truncated = truncated or len(lines) > MAX_SCANNED_DOMAINS
    domains: list[_Domain] = []
    invalid_rows = 0
    for line in lines[:MAX_SCANNED_DOMAINS]:
        if not UUID_RE.search(line.rstrip()):
            continue
        domain = _parse_remote_domain_row(line, parsed.scope)
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


def _issue_token(endpoint: str, domain: _Domain) -> str:
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _RemoteActionToken(
        endpoint=endpoint,
        scope=domain.scope,
        uuid=domain.uuid,
        name=domain.name,
        state=domain.state,
        domain_id=domain.domain_id,
        expires_at=now + TOKEN_TTL_SECONDS,
    )
    with _TOKEN_LOCK:
        _prune_tokens_locked(now)
        _TOKENS[token] = record
    return token


def _token_record(token: str) -> tuple[_RemoteActionToken | None, str | None]:
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        return None, "A fresh identity token from list_remote_virtual_machines is required."
    with _TOKEN_LOCK:
        _prune_tokens_locked(time.monotonic())
        record = _TOKENS.get(token)
    if record is None:
        return None, "The remote virtual-machine identity token is unknown or expired; list remote virtual machines again."
    return record, None


def _lookup_current(record: _RemoteActionToken) -> tuple[_Domain | None, str | None]:
    domains, error, _truncated = _read_remote_domains(record.endpoint)
    if domains is None:
        return None, error
    matches = [domain for domain in domains if domain.uuid == record.uuid]
    if len(matches) != 1:
        return None, "The exact remote libvirt domain is missing or ambiguous; list remote virtual machines again."
    current = matches[0]
    if current.name != record.name or current.scope != record.scope:
        return None, "The exact remote domain identity changed after it was listed; list remote virtual machines again."
    return current, None


def list_remote_virtual_machines(
    endpoint: str,
    query: str = "",
    limit: int = 100,
) -> RemoteVirtualMachineListResponse:
    parsed, error = _parse_endpoint(endpoint)
    if error or parsed is None:
        return RemoteVirtualMachineListResponse(success=False, message=error or "Remote endpoint is invalid.")
    if not isinstance(query, str) or len(query) > 256 or any(ord(character) < 32 or ord(character) == 127 for character in query):
        return RemoteVirtualMachineListResponse(endpoint=parsed.canonical, scope=parsed.scope, message="Query must be text with at most 256 characters and no control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return RemoteVirtualMachineListResponse(endpoint=parsed.canonical, scope=parsed.scope, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_DOMAINS))
    domains, read_error, truncated = _read_remote_domains(parsed.canonical)
    if read_error or domains is None:
        return RemoteVirtualMachineListResponse(
            success=False,
            endpoint=parsed.canonical,
            scope=parsed.scope,
            limit=limit,
            message=read_error or "Remote libvirt inventory is unavailable.",
        )
    needle = query.strip().casefold()
    filtered = [
        domain for domain in domains
        if not needle or needle in domain.uuid or needle in domain.name.casefold() or needle in domain.state.casefold()
    ]
    filtered.sort(key=lambda domain: (domain.name.casefold(), domain.uuid))
    selected = filtered[:limit]
    machines = [
        RemoteVirtualMachineInfo(
            endpoint=parsed.canonical,
            scope=domain.scope,
            uuid=domain.uuid,
            name=domain.name,
            state=domain.state,
            domain_id=domain.domain_id,
            identity_token=_issue_token(parsed.canonical, domain),
        )
        for domain in selected
    ]
    truncated |= len(filtered) > limit
    return RemoteVirtualMachineListResponse(
        success=True,
        endpoint=parsed.canonical,
        scope=parsed.scope,
        total_virtual_machines=len(filtered),
        returned_virtual_machines=len(machines),
        virtual_machines=machines,
        limit=limit,
        truncated=truncated,
        message="The remote domain inventory was capped by scan, output, or result limits." if truncated else None,
    )


def remote_virtual_machine_action_confirmation_details(
    action: str,
    identity_token: str,
) -> tuple[_RemoteActionTarget | None, str | None]:
    if not isinstance(action, str) or action not in REMOTE_ACTIONS:
        return None, "Choose start, shutdown, reboot, suspend, or resume."
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, error
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.expires_at <= time.monotonic():
            _TOKENS.pop(identity_token, None)
            return None, "The remote virtual-machine identity token expired; list remote virtual machines again."
        if record.claimed:
            return None, "This remote virtual-machine token is already being used for an action. List remote virtual machines again."
        record.claimed = True
    current, error = _lookup_current(record)
    if error or current is None:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, error
    if current.state != record.state or current.domain_id != record.domain_id:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, "The remote domain state changed after it was listed; inspect it and try again."
    state_error, _already_reached = _state_error(action, current.state)
    if state_error:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, state_error
    token_payload = {
        "action": action,
        "endpoint": record.endpoint,
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
    return _RemoteActionTarget(
        endpoint=record.endpoint,
        scope=record.scope,
        uuid=record.uuid,
        name=record.name,
        state=current.state,
        domain_id=current.domain_id,
        confirmation_token=confirmation_token,
    ), None


def perform_remote_virtual_machine_action(
    action: str,
    identity_token: str,
    expected_state_token: str,
    confirmed_endpoint: str,
    confirmed_scope: str,
    confirmed_uuid: str,
    confirmed_name: str,
    *,
    confirmed: bool,
) -> RemoteVirtualMachineActionResponse:
    safe_action: RemoteAction = action if isinstance(action, str) and action in REMOTE_ACTIONS else "start"  # type: ignore[assignment]
    record, error = _token_record(identity_token)
    if error or record is None:
        return RemoteVirtualMachineActionResponse(success=False, action=safe_action, message=error or "A fresh remote VM identity token is required.")
    response_target = {
        "endpoint": record.endpoint,
        "scope": record.scope,
        "uuid": record.uuid,
        "name": record.name,
    }
    try:
        if confirmed is not True:
            return RemoteVirtualMachineActionResponse(success=False, action=safe_action, **response_target, message="Explicit client confirmation is required; no remote libvirt command was run.")
        if not isinstance(action, str) or action not in REMOTE_ACTIONS:
            return RemoteVirtualMachineActionResponse(success=False, action=safe_action, **response_target, user_confirmed=True, message="Unsupported remote libvirt VM action; no command was run.")
        if not record.claimed or record.action != action:
            return RemoteVirtualMachineActionResponse(success=False, action=safe_action, **response_target, user_confirmed=True, message="The action was not confirmed from a fresh remote virtual-machine token.")
        if (
            record.endpoint != confirmed_endpoint
            or record.scope != confirmed_scope
            or record.uuid != confirmed_uuid
            or record.name != confirmed_name
            or record.confirmation_token != expected_state_token
        ):
            return RemoteVirtualMachineActionResponse(success=False, action=safe_action, **response_target, user_confirmed=True, message="Confirmation did not match the exact remote endpoint, domain, action, or current-state token; no command was run.")
        current, error = _lookup_current(record)
        if error or current is None:
            return RemoteVirtualMachineActionResponse(success=False, action=safe_action, **response_target, user_confirmed=True, message=error or "The exact remote libvirt domain could not be revalidated.")
        if current.state != record.state or current.domain_id != record.domain_id:
            return RemoteVirtualMachineActionResponse(success=False, action=safe_action, **response_target, state=current.state, user_confirmed=True, message="The remote domain state changed after confirmation; inspect it and confirm again before another action.")
        state_error, already_reached = _state_error(action, current.state)
        if state_error:
            return RemoteVirtualMachineActionResponse(success=False, action=safe_action, **response_target, state=current.state, user_confirmed=True, message=state_error)
        if already_reached:
            return RemoteVirtualMachineActionResponse(success=True, action=safe_action, **response_target, state=current.state, state_verified=True, user_confirmed=True, message=f"The remote domain is already in the requested state for {action}; no command was needed.")

        _output, command_error, command_truncated = _run_remote_virsh(
            record.endpoint,
            [action, record.uuid],
            readonly=False,
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
            command_label=f"remote libvirt VM {action}",
        )
        if command_truncated:
            command_error = command_error or "Remote virsh output exceeded the configured limit."
        after, verify_error = _lookup_current(record)
        state = after.state if after is not None else None
        verified = _post_state_verified(action, state) if state is not None else False
        if command_error:
            message = f"Remote virsh reported an error: {command_error[:400]}"
            if verify_error:
                message += f" {verify_error}"
            if verified:
                message += " The requested state is visible now; inspect the domain before retrying."
            return RemoteVirtualMachineActionResponse(success=False, action=safe_action, **response_target, state=state, state_verified=verified, user_confirmed=True, message=message)
        if action == "reboot":
            message = "The remote reboot request was accepted; guest reboot completion is asynchronous and was not verified. Inspect the remote VM before retrying."
        elif verified:
            message = f"The remote domain action {action} reached state {state!r}."
        else:
            message = f"The remote domain action {action} was accepted, but the requested state is not yet visible. Current state: {state or 'unavailable'}. Inspect the domain before retrying."
            if verify_error:
                message += f" {verify_error}"
        return RemoteVirtualMachineActionResponse(
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
