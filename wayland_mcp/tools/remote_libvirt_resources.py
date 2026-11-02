"""Bounded remote libvirt network/storage inventory and confirmed lifecycle controls."""

from __future__ import annotations

import secrets
import sys
import threading
import time
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import (
    RemoteLibvirtNetworkInfo,
    RemoteLibvirtNetworkListResponse,
    RemoteLibvirtResourceActionResponse,
    RemoteLibvirtStorageInventoryResponse,
    RemoteLibvirtStoragePoolInfo,
    RemoteLibvirtStorageVolumeInfo,
)
from wayland_mcp.tools.libvirt_resources import (
    MAX_ACTION_OUTPUT_BYTES,
    MAX_NAME_LENGTH,
    MAX_RETURNED_ROWS,
    MAX_SCANNED_ROWS,
    MAX_VIRSH_OUTPUT_BYTES,
    RESOURCE_ACTIONS,
    RESOURCE_TYPES,
    TOKEN_RE,
    TOKEN_TTL_SECONDS,
    _optional_value,
    _parse_yes_no,
    _safe_cell,
    _table_rows,
)
from wayland_mcp.tools.remote_virtual_machines import (
    ACTION_TIMEOUT_SECONDS as REMOTE_ACTION_TIMEOUT_SECONDS,
    COMMAND_TIMEOUT_SECONDS as REMOTE_COMMAND_TIMEOUT_SECONDS,
    _Endpoint,
    _parse_endpoint,
    _run_remote_virsh,
    remote_virsh_available,
)

RemoteLibvirtResourceType = Literal["network", "storage_pool"]
RemoteLibvirtResourceAction = Literal["start", "stop", "enable_autostart", "disable_autostart"]

REMOTE_ACTION_OUTPUT_BYTES = MAX_ACTION_OUTPUT_BYTES
REMOTE_RESOURCE_TOKEN_LIMIT = 1024


@dataclass(frozen=True, slots=True)
class _RemoteResourceSnapshot:
    endpoint: str
    scope: Literal["system", "session"]
    resource_type: str
    name: str
    uuid: str
    state: str
    active: bool
    persistent: bool | None
    autostart: bool | None


@dataclass(slots=True)
class _RemoteResourceActionToken:
    endpoint: str
    scope: Literal["system", "session"]
    resource_type: str
    action: str
    name: str
    uuid: str
    state: str
    active: bool
    persistent: bool | None
    autostart: bool | None
    expires_at: float
    claimed: bool = False


@dataclass(frozen=True, slots=True)
class RemoteLibvirtResourceActionTarget:
    endpoint: str
    scope: Literal["system", "session"]
    resource_type: str
    action: str
    name: str
    uuid: str
    state: str
    active: bool
    persistent: bool | None
    autostart: bool | None
    confirmation_token: str


_ACTION_TOKENS: dict[str, _RemoteResourceActionToken] = {}
_ACTION_LOCK = threading.Lock()


def _limit_value(limit: int) -> int | None:
    if not isinstance(limit, int) or isinstance(limit, bool):
        return None
    return max(1, min(limit, MAX_RETURNED_ROWS))


def _resource_name_error(resource_type: str, name: str) -> str | None:
    if not isinstance(name, str) or not name or len(name) > MAX_NAME_LENGTH:
        return f"Resource name must be non-empty text of at most {MAX_NAME_LENGTH} characters."
    if name != name.strip() or name.startswith("-"):
        return "Resource name has surrounding whitespace or an unsupported leading option marker."
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        return "Resource name cannot contain control characters."
    if resource_type == "storage_pool" and ("/" in name or "\\" in name):
        return "Path-like storage-pool names are not accepted by this control."
    return None


def _read_remote_table(
    endpoint: str,
    arguments: list[str],
    required_headers: set[str],
    command_label: str,
) -> tuple[list[dict[str, str]] | None, str | None, bool]:
    output, error, command_truncated = _run_remote_virsh(
        endpoint,
        arguments,
        readonly=True,
        quiet=False,
        timeout_seconds=REMOTE_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_VIRSH_OUTPUT_BYTES,
        command_label=command_label,
    )
    if error or output is None:
        return None, error or "Remote virsh returned no inventory output.", command_truncated
    rows, table_truncated, parse_error = _table_rows(output, required_headers)
    if parse_error:
        return None, parse_error, command_truncated
    return rows, None, command_truncated or table_truncated


def list_remote_libvirt_networks(
    endpoint: str,
    limit: int = 100,
) -> RemoteLibvirtNetworkListResponse:
    bounded_limit = _limit_value(limit)
    if bounded_limit is None:
        return RemoteLibvirtNetworkListResponse(success=False, message="Limit must be an integer.")
    parsed, error = _parse_endpoint(endpoint)
    if error or parsed is None:
        return RemoteLibvirtNetworkListResponse(success=False, limit=bounded_limit, message=error or "Remote endpoint is invalid.")
    if not sys.platform.startswith("linux") or not remote_virsh_available():
        return RemoteLibvirtNetworkListResponse(
            success=False,
            endpoint=parsed.canonical,
            scope=parsed.scope,
            limit=bounded_limit,
            message="Remote network inventory requires Linux, virsh, and the OpenSSH client.",
        )

    rows, error, truncated = _read_remote_table(
        parsed.canonical,
        ["net-list", "--all", "--table"],
        {"name", "state", "autostart", "persistent"},
        "remote libvirt network inventory",
    )
    if error or rows is None:
        return RemoteLibvirtNetworkListResponse(
            success=False,
            endpoint=parsed.canonical,
            scope=parsed.scope,
            limit=bounded_limit,
            truncated=truncated,
            message=error or "The remote network inventory could not be read.",
        )

    networks: list[RemoteLibvirtNetworkInfo] = []
    for row in rows:
        name = _safe_cell(row.get("name", ""))
        state = _safe_cell(row.get("state", ""), 64)
        autostart, bad_autostart = _parse_yes_no(row.get("autostart", ""))
        persistent, bad_persistent = _parse_yes_no(row.get("persistent", ""))
        if name is None or state is None or bad_autostart or bad_persistent:
            truncated = True
            continue
        networks.append(RemoteLibvirtNetworkInfo(
            endpoint=parsed.canonical,
            scope=parsed.scope,
            name=name,
            state=state,
            autostart=autostart,
            persistent=persistent,
        ))
    networks.sort(key=lambda item: item.name.casefold())
    total = len(networks)
    truncated |= total > bounded_limit
    selected = networks[:bounded_limit]
    return RemoteLibvirtNetworkListResponse(
        success=True,
        endpoint=parsed.canonical,
        scope=parsed.scope,
        total_networks=total,
        returned_networks=len(selected),
        networks=selected,
        limit=bounded_limit,
        truncated=truncated,
        partial=truncated,
        message="The remote network inventory was capped or contained unrecognized rows." if truncated else None,
    )


def list_remote_libvirt_storage(
    endpoint: str,
    pool_name: str = "",
    limit: int = 100,
) -> RemoteLibvirtStorageInventoryResponse:
    bounded_limit = _limit_value(limit)
    if bounded_limit is None:
        return RemoteLibvirtStorageInventoryResponse(success=False, message="Limit must be an integer.")
    parsed, error = _parse_endpoint(endpoint)
    if error or parsed is None:
        return RemoteLibvirtStorageInventoryResponse(success=False, limit=bounded_limit, message=error or "Remote endpoint is invalid.")
    if (
        not isinstance(pool_name, str)
        or len(pool_name) > MAX_NAME_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in pool_name)
    ):
        return RemoteLibvirtStorageInventoryResponse(
            success=False,
            endpoint=parsed.canonical,
            scope=parsed.scope,
            limit=bounded_limit,
            message=f"Pool name must be text with at most {MAX_NAME_LENGTH} characters and no control characters.",
        )
    pool_name = pool_name.strip()
    if pool_name and _resource_name_error("storage_pool", pool_name):
        return RemoteLibvirtStorageInventoryResponse(
            success=False,
            endpoint=parsed.canonical,
            scope=parsed.scope,
            limit=bounded_limit,
            message=_resource_name_error("storage_pool", pool_name),
        )
    if not sys.platform.startswith("linux") or not remote_virsh_available():
        return RemoteLibvirtStorageInventoryResponse(
            success=False,
            endpoint=parsed.canonical,
            scope=parsed.scope,
            limit=bounded_limit,
            message="Remote storage inventory requires Linux, virsh, and the OpenSSH client.",
        )

    rows, error, truncated = _read_remote_table(
        parsed.canonical,
        ["pool-list", "--all", "--details"],
        {"name", "state", "autostart", "persistent"},
        "remote libvirt storage-pool inventory",
    )
    if error or rows is None:
        return RemoteLibvirtStorageInventoryResponse(
            success=False,
            endpoint=parsed.canonical,
            scope=parsed.scope,
            limit=bounded_limit,
            truncated=truncated,
            message=error or "The remote storage inventory could not be read.",
        )

    pools: list[RemoteLibvirtStoragePoolInfo] = []
    for row in rows:
        name = _safe_cell(row.get("name", ""))
        state = _safe_cell(row.get("state", ""), 64)
        autostart, bad_autostart = _parse_yes_no(row.get("autostart", ""))
        persistent, bad_persistent = _parse_yes_no(row.get("persistent", ""))
        if name is None or "/" in name or "\\" in name or state is None or bad_autostart or bad_persistent:
            truncated = True
            continue
        capacity, bad_capacity = _optional_value(row.get("capacity"))
        allocation, bad_allocation = _optional_value(row.get("allocation"))
        available, bad_available = _optional_value(row.get("available"))
        truncated |= bad_capacity or bad_allocation or bad_available
        pools.append(RemoteLibvirtStoragePoolInfo(
            endpoint=parsed.canonical,
            scope=parsed.scope,
            name=name,
            state=state,
            autostart=autostart,
            persistent=persistent,
            capacity=capacity,
            allocation=allocation,
            available=available,
        ))
    pools.sort(key=lambda item: item.name.casefold())
    total_pools = len(pools)
    selected_pools = pools[:bounded_limit]
    truncated |= total_pools > bounded_limit
    volumes: list[RemoteLibvirtStorageVolumeInfo] = []
    total_volumes = 0
    messages: list[str] = []
    if pool_name:
        matches = [pool for pool in pools if pool.name == pool_name]
        if truncated and total_pools <= bounded_limit:
            messages.append("The remote pool inventory was incomplete; request volumes again after a complete pool inventory.")
        elif len(matches) != 1:
            messages.append("The exact remote pool name was not found uniquely; list pools and use an exact returned name.")
        else:
            volume_rows, volume_error, volume_truncated = _read_remote_table(
                parsed.canonical,
                ["vol-list", "--pool", pool_name, "--details"],
                {"name"},
                "remote libvirt storage-volume inventory",
            )
            if volume_error or volume_rows is None:
                messages.append(volume_error or "The remote volume inventory could not be read.")
            else:
                truncated |= volume_truncated
                for row in volume_rows:
                    name = _safe_cell(row.get("name", ""))
                    if name is None or "/" in name or "\\" in name:
                        truncated = True
                        continue
                    volume_type, bad_type = _optional_value(row.get("type"))
                    capacity, bad_capacity = _optional_value(row.get("capacity"))
                    allocation, bad_allocation = _optional_value(row.get("allocation"))
                    if bad_type or bad_capacity or bad_allocation:
                        truncated = True
                        continue
                    volumes.append(RemoteLibvirtStorageVolumeInfo(
                        name=name,
                        volume_type=volume_type,
                        capacity=capacity,
                        allocation=allocation,
                    ))
                volumes.sort(key=lambda item: item.name.casefold())
                total_volumes = len(volumes)
                truncated |= total_volumes > bounded_limit
                volumes = volumes[:bounded_limit]
    if truncated:
        messages.append("The remote storage inventory was capped by scan, output, parse, or result limits.")
    return RemoteLibvirtStorageInventoryResponse(
        success=True,
        endpoint=parsed.canonical,
        scope=parsed.scope,
        total_pools=total_pools,
        returned_pools=len(selected_pools),
        pools=selected_pools,
        selected_pool_name=pool_name or None,
        total_volumes=total_volumes,
        returned_volumes=len(volumes),
        volumes=volumes,
        limit=bounded_limit,
        truncated=truncated,
        partial=bool(messages),
        message=" ".join(messages[:3]) or None,
    )


def _read_remote_resource_info(
    endpoint: str,
    resource_type: str,
    name: str,
) -> tuple[_RemoteResourceSnapshot | None, str | None]:
    parsed, error = _parse_endpoint(endpoint)
    if error or parsed is None:
        return None, error or "Remote endpoint is invalid."
    name_error = _resource_name_error(resource_type, name)
    if name_error:
        return None, name_error
    command_name = "net-info" if resource_type == "network" else "pool-info"
    output, command_error, truncated = _run_remote_virsh(
        parsed.canonical,
        [command_name, name],
        readonly=True,
        timeout_seconds=REMOTE_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=64 * 1024,
        command_label=f"remote libvirt {resource_type} inspection",
    )
    if command_error or output is None or truncated:
        return None, "The exact remote libvirt resource could not be inspected; check endpoint, permissions, and current definition."
    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip().casefold()] = value.strip()
    reported_name = fields.get("name")
    uuid = fields.get("uuid", "").casefold()
    if reported_name != name or not re_full_uuid(uuid):
        return None, "Remote libvirt returned a missing, malformed, or mismatched resource identity."
    persistent, bad_persistent = _parse_yes_no(fields.get("persistent", ""))
    autostart, bad_autostart = _parse_yes_no(fields.get("autostart", ""))
    if bad_persistent or bad_autostart:
        return None, "Remote libvirt returned an unrecognized persistence or autostart state."
    if resource_type == "network":
        active, bad_active = _parse_yes_no(fields.get("active", ""))
        if bad_active or active is None:
            return None, "Remote libvirt returned an unrecognized virtual-network state."
        state = "active" if active else "inactive"
    else:
        state = fields.get("state", "").casefold()
        if state not in {"running", "inactive"}:
            return None, "Remote libvirt returned an unsupported storage-pool state."
        active = state == "running"
    return _RemoteResourceSnapshot(
        endpoint=parsed.canonical,
        scope=parsed.scope,
        resource_type=resource_type,
        name=reported_name,
        uuid=uuid,
        state=state,
        active=active,
        persistent=persistent,
        autostart=autostart,
    ), None


def re_full_uuid(value: str) -> bool:
    return len(value) == 36 and all(
        (character in "0123456789abcdef" if index not in {8, 13, 18, 23} else character == "-")
        for index, character in enumerate(value)
    )


def _validate_action(action: str, snapshot: _RemoteResourceSnapshot) -> tuple[str | None, bool]:
    if action == "start":
        return None, snapshot.active
    if action == "stop":
        return None, not snapshot.active
    if action not in RESOURCE_ACTIONS:
        return "Choose start, stop, enable_autostart, or disable_autostart.", False
    if snapshot.persistent is not True:
        return "Autostart can be changed only for a persistent remote libvirt resource.", False
    if snapshot.autostart is None:
        return "Remote libvirt did not report the resource's autostart state.", False
    desired = action == "enable_autostart"
    return None, snapshot.autostart is desired


def _prune_action_tokens(now: float) -> None:
    for token in [token for token, record in _ACTION_TOKENS.items() if record.expires_at <= now]:
        _ACTION_TOKENS.pop(token, None)


def remote_libvirt_resource_action_confirmation_details(
    action: str,
    resource_type: str,
    endpoint: str,
    name: str,
) -> tuple[RemoteLibvirtResourceActionTarget | None, str | None]:
    if not isinstance(action, str) or action not in RESOURCE_ACTIONS:
        return None, "Choose start, stop, enable_autostart, or disable_autostart."
    if not isinstance(resource_type, str) or resource_type not in RESOURCE_TYPES:
        return None, "Choose network or storage_pool as the remote libvirt resource type."
    parsed, error = _parse_endpoint(endpoint)
    if error or parsed is None:
        return None, error or "Remote endpoint is invalid."
    if not sys.platform.startswith("linux") or not remote_virsh_available():
        return None, "Remote libvirt resource control requires Linux, virsh, and the OpenSSH client."
    snapshot, error = _read_remote_resource_info(parsed.canonical, resource_type, name)
    if error or snapshot is None:
        return None, error or "The exact remote libvirt resource could not be verified."
    error, _already_reached = _validate_action(action, snapshot)
    if error:
        return None, error
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _RemoteResourceActionToken(
        endpoint=parsed.canonical,
        scope=parsed.scope,
        resource_type=resource_type,
        action=action,
        name=snapshot.name,
        uuid=snapshot.uuid,
        state=snapshot.state,
        active=snapshot.active,
        persistent=snapshot.persistent,
        autostart=snapshot.autostart,
        expires_at=now + TOKEN_TTL_SECONDS,
    )
    with _ACTION_LOCK:
        _prune_action_tokens(now)
        if len(_ACTION_TOKENS) >= REMOTE_RESOURCE_TOKEN_LIMIT:
            return None, "Too many pending remote libvirt confirmations; retry after existing prompts expire."
        _ACTION_TOKENS[token] = record
    return RemoteLibvirtResourceActionTarget(
        endpoint=record.endpoint,
        scope=record.scope,
        resource_type=record.resource_type,
        action=record.action,
        name=record.name,
        uuid=record.uuid,
        state=record.state,
        active=record.active,
        persistent=record.persistent,
        autostart=record.autostart,
        confirmation_token=token,
    ), None


def _remote_action_command(record: _RemoteResourceActionToken) -> list[str]:
    if record.resource_type == "network":
        command = {
            "start": "net-start",
            "stop": "net-destroy",
            "enable_autostart": "net-autostart",
            "disable_autostart": "net-autostart",
        }[record.action]
    else:
        command = {
            "start": "pool-start",
            "stop": "pool-destroy",
            "enable_autostart": "pool-autostart",
            "disable_autostart": "pool-autostart",
        }[record.action]
    arguments = [command, record.uuid]
    if record.action == "disable_autostart":
        arguments.append("--disable")
    return arguments


def _action_reached(record: _RemoteResourceActionToken, snapshot: _RemoteResourceSnapshot) -> bool:
    if record.action == "start":
        return snapshot.active
    if record.action == "stop":
        return not snapshot.active
    if record.action == "enable_autostart":
        return snapshot.autostart is True
    return snapshot.autostart is False


def _action_response(
    *,
    success: bool,
    action: str,
    resource_type: str,
    endpoint: str | None,
    scope: str | None,
    name: str | None,
    uuid: str | None,
    state: str | None,
    autostart: bool | None,
    state_verified: bool,
    user_confirmed: bool,
    message: str,
) -> RemoteLibvirtResourceActionResponse:
    return RemoteLibvirtResourceActionResponse(
        success=success,
        action=action if action in RESOURCE_ACTIONS else "start",
        resource_type=resource_type if resource_type in RESOURCE_TYPES else "network",
        endpoint=endpoint,
        scope=scope if scope in {"system", "session"} else None,
        name=name,
        uuid=uuid,
        state=state,
        autostart=autostart,
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_remote_libvirt_resource_action(
    action: str,
    resource_type: str,
    endpoint: str,
    name: str,
    uuid: str,
    expected_state_token: str,
    *,
    confirmed: bool,
) -> RemoteLibvirtResourceActionResponse:
    safe_action = action if isinstance(action, str) and action in RESOURCE_ACTIONS else "start"
    safe_type = resource_type if isinstance(resource_type, str) and resource_type in RESOURCE_TYPES else "network"
    record = None
    with _ACTION_LOCK:
        if isinstance(expected_state_token, str) and TOKEN_RE.fullmatch(expected_state_token):
            record = _ACTION_TOKENS.get(expected_state_token)
        if record is None or record.expires_at <= time.monotonic():
            if isinstance(expected_state_token, str):
                _ACTION_TOKENS.pop(expected_state_token, None)
            return _action_response(
                success=False, action=safe_action, resource_type=safe_type,
                endpoint=None, scope=None, name=None, uuid=None, state=None, autostart=None,
                state_verified=False, user_confirmed=confirmed is True,
                message="A fresh remote libvirt confirmation token is required; inspect the resource and try again.",
            )
        if record.claimed:
            return _action_response(
                success=False, action=safe_action, resource_type=safe_type,
                endpoint=record.endpoint, scope=record.scope, name=record.name, uuid=record.uuid,
                state=record.state, autostart=record.autostart, state_verified=False,
                user_confirmed=confirmed is True,
                message="This remote libvirt confirmation token is already being used; request a new action.",
            )
        record.claimed = True
    try:
        if confirmed is not True:
            return _action_response(
                success=False, action=safe_action, resource_type=safe_type,
                endpoint=record.endpoint, scope=record.scope, name=record.name, uuid=record.uuid,
                state=record.state, autostart=record.autostart, state_verified=False,
                user_confirmed=False, message="Explicit client confirmation is required; no remote command was run.",
            )
        parsed, endpoint_error = _parse_endpoint(endpoint)
        if (
            action != record.action
            or resource_type != record.resource_type
            or parsed is None
            or parsed.canonical != record.endpoint
            or name != record.name
            or uuid.casefold() != record.uuid
        ):
            return _action_response(
                success=False, action=safe_action, resource_type=safe_type,
                endpoint=record.endpoint, scope=record.scope, name=record.name, uuid=record.uuid,
                state=record.state, autostart=record.autostart, state_verified=False,
                user_confirmed=True,
                message=endpoint_error or "Confirmation did not match the exact remote endpoint, resource, action, or UUID; no command was run.",
            )
        current, error = _read_remote_resource_info(record.endpoint, record.resource_type, record.name)
        if error or current is None:
            return _action_response(
                success=False, action=safe_action, resource_type=safe_type,
                endpoint=record.endpoint, scope=record.scope, name=record.name, uuid=record.uuid,
                state=None, autostart=None, state_verified=False, user_confirmed=True,
                message=error or "The exact remote resource could not be revalidated; no action was run.",
            )
        if (
            current.uuid != record.uuid
            or current.state != record.state
            or current.active != record.active
            or current.persistent != record.persistent
            or current.autostart != record.autostart
        ):
            return _action_response(
                success=False, action=safe_action, resource_type=safe_type,
                endpoint=record.endpoint, scope=record.scope, name=record.name, uuid=current.uuid,
                state=current.state, autostart=current.autostart, state_verified=False, user_confirmed=True,
                message="The remote resource identity or state changed after confirmation; inspect it and confirm again.",
            )
        action_error, already_reached = _validate_action(record.action, current)
        if action_error:
            return _action_response(
                success=False, action=safe_action, resource_type=safe_type,
                endpoint=record.endpoint, scope=record.scope, name=record.name, uuid=record.uuid,
                state=current.state, autostart=current.autostart, state_verified=False, user_confirmed=True,
                message=action_error,
            )
        if already_reached:
            return _action_response(
                success=True, action=safe_action, resource_type=safe_type,
                endpoint=record.endpoint, scope=record.scope, name=record.name, uuid=record.uuid,
                state=current.state, autostart=current.autostart, state_verified=True, user_confirmed=True,
                message=f"The exact remote libvirt resource already has the requested state for {record.action}; no command was needed.",
            )
        _output, command_error, command_truncated = _run_remote_virsh(
            record.endpoint,
            _remote_action_command(record),
            readonly=False,
            timeout_seconds=REMOTE_ACTION_TIMEOUT_SECONDS,
            max_output_bytes=REMOTE_ACTION_OUTPUT_BYTES,
            command_label=f"remote libvirt {record.resource_type} {record.action}",
        )
        after, verify_error = _read_remote_resource_info(record.endpoint, record.resource_type, record.name)
        state = after.state if after is not None else None
        autostart = after.autostart if after is not None else None
        verified = after is not None and after.uuid == record.uuid and _action_reached(record, after)
        if command_error or command_truncated:
            message = "Remote libvirt timed out; inspect the resource before retrying." if command_error and "timed out" in command_error.casefold() else "Remote libvirt reported an action error; inspect the resource before retrying."
            if verified:
                message += " The requested state is visible now."
            elif verify_error:
                message += " The resulting state could not be read."
            return _action_response(
                success=False, action=safe_action, resource_type=safe_type,
                endpoint=record.endpoint, scope=record.scope, name=record.name, uuid=record.uuid,
                state=state, autostart=autostart, state_verified=verified, user_confirmed=True,
                message=message,
            )
        if not verified:
            message = "Remote libvirt accepted the action, but the requested state is not visible; inspect the resource before retrying."
            if verify_error:
                message += " The resulting state could not be read."
            return _action_response(
                success=False, action=safe_action, resource_type=safe_type,
                endpoint=record.endpoint, scope=record.scope, name=record.name, uuid=record.uuid,
                state=state, autostart=autostart, state_verified=False, user_confirmed=True,
                message=message,
            )
        return _action_response(
            success=True, action=safe_action, resource_type=safe_type,
            endpoint=record.endpoint, scope=record.scope, name=record.name, uuid=record.uuid,
            state=state, autostart=autostart, state_verified=True, user_confirmed=True,
            message=f"Remote libvirt {record.resource_type} action {record.action} reached and verified the requested state.",
        )
    finally:
        with _ACTION_LOCK:
            _ACTION_TOKENS.pop(expected_state_token, None)
