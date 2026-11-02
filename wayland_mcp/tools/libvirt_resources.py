"""Bounded inventory and confirmed controls for local libvirt resources."""

from __future__ import annotations

import re
import secrets
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import (
    LibvirtNetworkInfo,
    LibvirtNetworkListResponse,
    LibvirtResourceActionResponse,
    LibvirtStorageInventoryResponse,
    LibvirtStoragePoolInfo,
    LibvirtStorageVolumeInfo,
    LibvirtVolumeCreateResponse,
)
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.libvirt_common import SCOPED_URIS, virsh_environment

MAX_SCANNED_ROWS = 1_000
MAX_RETURNED_ROWS = 200
MAX_VIRSH_OUTPUT_BYTES = 2 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 15
ACTION_TIMEOUT_SECONDS = 30
MAX_ACTION_OUTPUT_BYTES = 16 * 1024
MAX_NAME_LENGTH = 256
TOKEN_TTL_SECONDS = 180
VOLUME_CREATE_TIMEOUT_SECONDS = 120
MIN_VOLUME_CAPACITY_BYTES = 1 << 20
MAX_VOLUME_CAPACITY_BYTES = 1 << 40
UUID_RE = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,100}$")
VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
RESOURCE_TYPES = {"network", "storage_pool"}
RESOURCE_ACTIONS = {"start", "stop", "enable_autostart", "disable_autostart"}
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _ResourceSnapshot:
    resource_type: str
    scope: str
    name: str
    uuid: str
    state: str
    active: bool
    persistent: bool | None
    autostart: bool | None


@dataclass(slots=True)
class _ResourceActionToken:
    action: str
    resource_type: str
    scope: str
    name: str
    uuid: str
    state: str
    active: bool
    persistent: bool | None
    autostart: bool | None
    expires_at: float
    claimed: bool = False


@dataclass(frozen=True, slots=True)
class LibvirtResourceActionTarget:
    action: str
    resource_type: str
    scope: str
    name: str
    uuid: str
    state: str
    active: bool
    persistent: bool | None
    autostart: bool | None
    confirmation_token: str


@dataclass(slots=True)
class _VolumeCreateActionToken:
    scope: str
    pool_name: str
    pool_uuid: str
    pool_state: str
    pool_autostart: bool | None
    volume_name: str
    capacity_bytes: int
    volume_format: str
    expires_at: float
    claimed: bool = False


@dataclass(frozen=True, slots=True)
class LibvirtVolumeCreateTarget:
    scope: str
    pool_name: str
    pool_uuid: str
    pool_state: str
    volume_name: str
    capacity_bytes: int
    volume_format: str
    confirmation_token: str


_ACTION_TOKENS: dict[str, _ResourceActionToken] = {}
_VOLUME_CREATE_TOKENS: dict[str, _VolumeCreateActionToken] = {}

LibvirtResourceType = Literal["network", "storage_pool"]
LibvirtResourceAction = Literal["start", "stop", "enable_autostart", "disable_autostart"]
LibvirtVolumeFormat = Literal["raw", "qcow2"]


def _safe_cell(value: str, limit: int = MAX_NAME_LENGTH) -> str | None:
    value = value.strip()
    if not value or len(value) > limit:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    return value


def _table_rows(
    output: str,
    required_headers: set[str],
) -> tuple[list[dict[str, str]], bool, str | None]:
    lines = output.splitlines()
    header_index: int | None = None
    headers: list[str] = []
    starts: list[int] = []
    for index, line in enumerate(lines):
        matches = list(re.finditer(r"\S+", line))
        candidate = [match.group().casefold() for match in matches]
        if required_headers.issubset(candidate):
            header_index = index
            headers = candidate
            starts = [match.start() for match in matches]
            break
    if header_index is None:
        return [], False, "virsh returned an unrecognized table header."

    separator_index = next(
        (
            index
            for index in range(header_index + 1, len(lines))
            if re.fullmatch(r"\s*-{3,}[\s-]*", lines[index])
        ),
        None,
    )
    if separator_index is None:
        return [], False, "virsh returned a table without its expected column separator."

    row_lines = [line for line in lines[separator_index + 1 :] if line.strip()]
    truncated = len(row_lines) > MAX_SCANNED_ROWS
    rows: list[dict[str, str]] = []
    invalid_rows = False
    for line in row_lines[:MAX_SCANNED_ROWS]:
        values = [
            line[start : starts[column_index + 1]].strip()
            if column_index + 1 < len(starts)
            else line[start:].strip()
            for column_index, start in enumerate(starts)
        ]
        row = dict(zip(headers, values, strict=True))
        if not _safe_cell(row.get("name", "")):
            invalid_rows = True
            continue
        if any(
            any(ord(character) < 32 or ord(character) == 127 for character in value)
            for value in values
        ):
            invalid_rows = True
            continue
        if any(len(value) > 512 for value in values):
            invalid_rows = True
            continue
        rows.append(row)
    return rows, truncated or invalid_rows, None


def _read_table(
    scope: str,
    args: list[str],
    required_headers: set[str],
    label: str,
    binary: str,
    env: dict[str, str],
) -> tuple[list[dict[str, str]] | None, str | None, bool]:
    command = [
        binary,
        "--quiet",
        "--no-pkttyagent",
        "--connect",
        SCOPED_URIS[scope],
        "--readonly",
        *args,
    ]
    output, error, command_truncated = run_bounded_command(
        command,
        env,
        command_label=label,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_VIRSH_OUTPUT_BYTES,
    )
    if error or output is None:
        return (
            None,
            "virsh could not return this inventory; check libvirt connectivity, authorization, and the selected resource.",
            command_truncated,
        )
    rows, table_truncated, parse_error = _table_rows(output, required_headers)
    if parse_error:
        return None, parse_error, command_truncated
    return rows, None, command_truncated or table_truncated


def _parse_yes_no(value: str) -> tuple[bool | None, bool]:
    normalized = value.casefold()
    if normalized == "yes":
        return True, False
    if normalized == "no":
        return False, False
    if normalized in {"", "-"}:
        return None, False
    return None, True


def _optional_value(value: str | None) -> tuple[str | None, bool]:
    if value is None or value.strip() in {"", "-"}:
        return None, False
    cleaned = _safe_cell(value, 128)
    return cleaned, cleaned is None


def _limit_value(limit: int) -> int | None:
    if not isinstance(limit, int) or isinstance(limit, bool):
        return None
    return max(1, min(limit, MAX_RETURNED_ROWS))


def _initial_error(
    scope: str,
    limit: int,
    message: str,
) -> LibvirtNetworkListResponse:
    return LibvirtNetworkListResponse(
        success=False,
        scope=(
            scope
            if isinstance(scope, str) and scope in {"system", "session", "both"}
            else "both"
        ),
        limit=limit,
        message=message,
    )


def list_libvirt_networks(
    scope: str = "both",
    limit: int = 100,
) -> LibvirtNetworkListResponse:
    """List local libvirt network names and state through fixed read-only URIs."""
    bounded_limit = _limit_value(limit)
    if bounded_limit is None:
        return _initial_error(scope, 100, "Limit must be an integer.")
    if not isinstance(scope, str) or scope not in {"system", "session", "both"}:
        return _initial_error(scope, bounded_limit, "Scope must be system, session, or both.")
    if not sys.platform.startswith("linux"):
        return _initial_error(scope, bounded_limit, "Libvirt network inventory is available only on Linux.")

    env = virsh_environment()
    binary = find_session_binary("virsh", env)
    if not binary:
        return _initial_error(scope, bounded_limit, "The optional virsh command is unavailable.")

    scopes = ("system", "session") if scope == "both" else (scope,)
    networks: list[LibvirtNetworkInfo] = []
    messages: list[str] = []
    successful_scopes = 0
    truncated = False
    for selected_scope in scopes:
        rows, error, source_truncated = _read_table(
            selected_scope,
            ["net-list", "--all", "--table"],
            {"name", "state", "autostart", "persistent"},
            f"local libvirt {selected_scope} network inventory",
            binary,
            env,
        )
        if error:
            messages.append(f"{selected_scope} scope: {error}")
            continue
        successful_scopes += 1
        truncated |= source_truncated
        for row in rows or []:
            autostart, bad_autostart = _parse_yes_no(row.get("autostart", ""))
            persistent, bad_persistent = _parse_yes_no(row.get("persistent", ""))
            name = _safe_cell(row.get("name", ""))
            state = _safe_cell(row.get("state", ""), 64)
            if (
                bad_autostart
                or bad_persistent
                or name is None
                or state is None
            ):
                truncated = True
                continue
            networks.append(
                LibvirtNetworkInfo(
                    scope=selected_scope,
                    name=name,
                    state=state,
                    autostart=autostart,
                    persistent=persistent,
                )
            )

    networks.sort(key=lambda item: (item.scope, item.name.casefold()))
    selected = networks[:bounded_limit]
    truncated |= len(networks) > bounded_limit
    if truncated:
        messages.append("The libvirt network inventory was capped by scan, output, parse, or result limits.")
    return LibvirtNetworkListResponse(
        success=successful_scopes > 0,
        scope=scope,
        total_networks=len(networks),
        returned_networks=len(selected),
        networks=selected,
        limit=bounded_limit,
        truncated=truncated,
        partial=bool(messages),
        message=" ".join(messages[:4]) or None,
    )


def list_libvirt_storage(
    scope: str = "both",
    pool_name: str = "",
    limit: int = 100,
) -> LibvirtStorageInventoryResponse:
    """List local libvirt pools and, optionally, volumes in one exact scoped pool."""
    bounded_limit = _limit_value(limit)
    if bounded_limit is None:
        return LibvirtStorageInventoryResponse(success=False, message="Limit must be an integer.")
    if not isinstance(scope, str) or scope not in {"system", "session", "both"}:
        return LibvirtStorageInventoryResponse(
            success=False,
            scope="both",
            limit=bounded_limit,
            message="Scope must be system, session, or both.",
        )
    if not isinstance(pool_name, str) or len(pool_name) > MAX_NAME_LENGTH:
        return LibvirtStorageInventoryResponse(
            success=False,
            scope=scope,
            limit=bounded_limit,
            message=f"Pool name must be text with at most {MAX_NAME_LENGTH} characters.",
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in pool_name):
        return LibvirtStorageInventoryResponse(
            success=False,
            scope=scope,
            limit=bounded_limit,
            message="Pool name cannot contain control characters.",
        )
    pool_name = pool_name.strip()
    if pool_name and scope == "both":
        return LibvirtStorageInventoryResponse(
            success=False,
            scope=scope,
            limit=bounded_limit,
            message="Choose system or session scope when requesting volumes from one pool.",
        )
    if not sys.platform.startswith("linux"):
        return LibvirtStorageInventoryResponse(
            success=False,
            scope=scope,
            limit=bounded_limit,
            message="Libvirt storage inventory is available only on Linux.",
        )

    env = virsh_environment()
    binary = find_session_binary("virsh", env)
    if not binary:
        return LibvirtStorageInventoryResponse(
            success=False,
            scope=scope,
            limit=bounded_limit,
            message="The optional virsh command is unavailable.",
        )

    scopes = ("system", "session") if scope == "both" else (scope,)
    pools: list[LibvirtStoragePoolInfo] = []
    messages: list[str] = []
    successful_scopes = 0
    truncated = False
    selected_scope_truncated = False
    for selected_scope in scopes:
        rows, error, source_truncated = _read_table(
            selected_scope,
            ["pool-list", "--all", "--details"],
            {"name", "state", "autostart", "persistent"},
            f"local libvirt {selected_scope} storage-pool inventory",
            binary,
            env,
        )
        if error:
            messages.append(f"{selected_scope} scope: {error}")
            continue
        successful_scopes += 1
        truncated |= source_truncated
        if selected_scope == scope:
            selected_scope_truncated = source_truncated
        for row in rows or []:
            autostart, bad_autostart = _parse_yes_no(row.get("autostart", ""))
            persistent, bad_persistent = _parse_yes_no(row.get("persistent", ""))
            name = _safe_cell(row.get("name", ""))
            state = _safe_cell(row.get("state", ""), 64)
            if (
                bad_autostart
                or bad_persistent
                or name is None
                or "/" in name
                or "\\" in name
                or state is None
            ):
                truncated = True
                continue
            capacity, bad_capacity = _optional_value(row.get("capacity"))
            allocation, bad_allocation = _optional_value(row.get("allocation"))
            available, bad_available = _optional_value(row.get("available"))
            if bad_capacity or bad_allocation or bad_available:
                truncated = True
            pools.append(
                LibvirtStoragePoolInfo(
                    scope=selected_scope,
                    name=name,
                    state=state,
                    autostart=autostart,
                    persistent=persistent,
                    capacity=capacity,
                    allocation=allocation,
                    available=available,
                )
            )

    pools.sort(key=lambda item: (item.scope, item.name.casefold()))
    all_pools = pools
    selected_pools = pools[:bounded_limit]
    truncated |= len(pools) > bounded_limit
    volumes: list[LibvirtStorageVolumeInfo] = []
    total_volumes = 0
    if pool_name:
        selected_scope = scope
        if selected_scope_truncated:
            messages.append("The scoped pool inventory was truncated; request volumes again after a complete inventory.")
        else:
            matches = [
                pool for pool in all_pools
                if pool.scope == selected_scope and pool.name == pool_name
            ]
            if len(matches) != 1:
                messages.append("The exact pool name was not found uniquely in this scope; list pools again and use its exact name.")
            else:
                volume_rows, error, volume_truncated = _read_table(
                    selected_scope,
                    ["vol-list", "--pool", pool_name, "--details"],
                    {"name"},
                    f"local libvirt {selected_scope} storage-volume inventory",
                    binary,
                    env,
                )
                if error:
                    messages.append(error)
                else:
                    truncated |= volume_truncated
                    for row in volume_rows or []:
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
                        volumes.append(
                            LibvirtStorageVolumeInfo(
                                name=name,
                                volume_type=volume_type,
                                capacity=capacity,
                                allocation=allocation,
                            )
                        )
                    volumes.sort(key=lambda item: item.name.casefold())
                    total_volumes = len(volumes)
                    truncated |= len(volumes) > bounded_limit
                    volumes = volumes[:bounded_limit]

    if truncated:
        messages.append("The libvirt storage inventory was capped by scan, output, parse, or result limits.")
    return LibvirtStorageInventoryResponse(
        success=successful_scopes > 0,
        scope=scope,
        total_pools=len(all_pools),
        returned_pools=len(selected_pools),
        pools=selected_pools,
        selected_pool_name=pool_name or None,
        total_volumes=total_volumes,
        returned_volumes=len(volumes),
        volumes=volumes,
        limit=bounded_limit,
        truncated=truncated,
        partial=bool(messages),
        message=" ".join(messages[:4]) or None,
    )


def _validate_resource_name(resource_type: str, name: str) -> str | None:
    if not isinstance(name, str) or not name or len(name) > MAX_NAME_LENGTH:
        return f"Resource name must be non-empty text of at most {MAX_NAME_LENGTH} characters."
    if name != name.strip() or name.startswith("-"):
        return "Resource name has surrounding whitespace or an unsupported leading option marker."
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        return "Resource name cannot contain control characters."
    if resource_type == "storage_pool" and ("/" in name or "\\" in name):
        return "Path-like storage-pool names are not accepted by this control."
    return None


def _read_resource_info(
    resource_type: str,
    scope: str,
    name: str,
    binary: str,
    env: dict[str, str],
) -> tuple[_ResourceSnapshot | None, str | None]:
    command_name = "net-info" if resource_type == "network" else "pool-info"
    output, error, truncated = run_bounded_command(
        [
            binary,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[scope],
            "--readonly",
            command_name,
            name,
        ],
        env,
        command_label=f"local libvirt {scope} resource inspection",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=64 * 1024,
    )
    if error or output is None:
        return None, "The exact libvirt resource could not be inspected; check connection, permissions, and its current definition."
    if truncated:
        return None, "The libvirt resource inspection exceeded its output limit."

    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip().casefold()] = value.strip()
    reported_name = fields.get("name")
    reported_uuid = fields.get("uuid", "").casefold()
    if reported_name != name or not UUID_RE.fullmatch(reported_uuid):
        return None, "Libvirt returned a missing, malformed, or mismatched resource identity."

    persistent, bad_persistent = _parse_yes_no(fields.get("persistent", ""))
    autostart, bad_autostart = _parse_yes_no(fields.get("autostart", ""))
    if bad_persistent or bad_autostart:
        return None, "Libvirt returned an unrecognized persistence or autostart state."

    if resource_type == "network":
        active, bad_active = _parse_yes_no(fields.get("active", ""))
        if bad_active or active is None:
            return None, "Libvirt returned an unrecognized virtual-network state."
        state = "active" if active else "inactive"
    else:
        raw_state = fields.get("state", "").casefold()
        if raw_state == "running":
            active = True
        elif raw_state == "inactive":
            active = False
        else:
            return None, "Libvirt returned an unsupported storage-pool state."
        state = raw_state
    return _ResourceSnapshot(
        resource_type=resource_type,
        scope=scope,
        name=reported_name,
        uuid=reported_uuid,
        state=state,
        active=active,
        persistent=persistent,
        autostart=autostart,
    ), None


def _validate_resource_action(
    action: str,
    snapshot: _ResourceSnapshot,
) -> tuple[str | None, bool]:
    if action == "start":
        return None, snapshot.active
    if action == "stop":
        return None, not snapshot.active
    if action not in {"enable_autostart", "disable_autostart"}:
        return "Choose start, stop, enable_autostart, or disable_autostart.", False
    if snapshot.persistent is not True:
        return "Autostart can be changed only for a persistent libvirt resource.", False
    if snapshot.autostart is None:
        return "Libvirt did not report the resource's autostart state.", False
    desired = action == "enable_autostart"
    return None, snapshot.autostart is desired


def _prune_action_tokens_locked(now: float) -> None:
    expired = [token for token, record in _ACTION_TOKENS.items() if record.expires_at <= now]
    for token in expired:
        _ACTION_TOKENS.pop(token, None)


def libvirt_resource_action_confirmation_details(
    action: str,
    resource_type: str,
    scope: str,
    name: str,
) -> tuple[LibvirtResourceActionTarget | None, str | None]:
    """Read and bind an exact resource state before requesting client confirmation."""
    if not isinstance(action, str) or action not in RESOURCE_ACTIONS:
        return None, "Choose start, stop, enable_autostart, or disable_autostart."
    if not isinstance(resource_type, str) or resource_type not in RESOURCE_TYPES:
        return None, "Choose network or storage_pool as the libvirt resource type."
    if not isinstance(scope, str) or scope not in SCOPED_URIS:
        return None, "Choose the local system or user-session libvirt scope."
    name_error = _validate_resource_name(resource_type, name)
    if name_error:
        return None, name_error
    if not sys.platform.startswith("linux"):
        return None, "Libvirt resource control is available only on Linux."

    env = virsh_environment()
    binary = find_session_binary("virsh", env)
    if not binary:
        return None, "The optional virsh command is unavailable."
    snapshot, error = _read_resource_info(resource_type, scope, name, binary, env)
    if error or snapshot is None:
        return None, error or "The exact libvirt resource could not be verified."
    error, _already_reached = _validate_resource_action(action, snapshot)
    if error:
        return None, error

    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _ResourceActionToken(
        action=action,
        resource_type=resource_type,
        scope=scope,
        name=snapshot.name,
        uuid=snapshot.uuid,
        state=snapshot.state,
        active=snapshot.active,
        persistent=snapshot.persistent,
        autostart=snapshot.autostart,
        expires_at=now + TOKEN_TTL_SECONDS,
    )
    with _ACTION_LOCK:
        _prune_action_tokens_locked(now)
        if len(_ACTION_TOKENS) >= 1_024:
            return None, "Too many pending libvirt confirmations; retry after existing prompts expire."
        _ACTION_TOKENS[token] = record
    return LibvirtResourceActionTarget(
        action=action,
        resource_type=resource_type,
        scope=scope,
        name=snapshot.name,
        uuid=snapshot.uuid,
        state=snapshot.state,
        active=snapshot.active,
        persistent=snapshot.persistent,
        autostart=snapshot.autostart,
        confirmation_token=token,
    ), None


def _action_command(action: str, resource_type: str, uuid: str) -> list[str]:
    if resource_type == "network":
        command = {
            "start": "net-start",
            "stop": "net-destroy",
            "enable_autostart": "net-autostart",
            "disable_autostart": "net-autostart",
        }[action]
    else:
        command = {
            "start": "pool-start",
            "stop": "pool-destroy",
            "enable_autostart": "pool-autostart",
            "disable_autostart": "pool-autostart",
        }[action]
    args = [command, uuid]
    if action == "disable_autostart":
        args.append("--disable")
    return args


def _action_reached(action: str, snapshot: _ResourceSnapshot) -> bool:
    if action == "start":
        return snapshot.active
    if action == "stop":
        return not snapshot.active
    if action == "enable_autostart":
        return snapshot.autostart is True
    return snapshot.autostart is False


def _resource_action_response(
    *,
    success: bool,
    action: str,
    resource_type: str,
    scope: str | None,
    name: str | None,
    uuid: str | None,
    state: str | None,
    autostart: bool | None,
    state_verified: bool,
    user_confirmed: bool,
    message: str,
) -> LibvirtResourceActionResponse:
    safe_action = action if action in RESOURCE_ACTIONS else "start"
    safe_type = resource_type if resource_type in RESOURCE_TYPES else "network"
    safe_scope = scope if scope in SCOPED_URIS else None
    return LibvirtResourceActionResponse(
        success=success,
        action=safe_action,
        resource_type=safe_type,
        scope=safe_scope,
        name=name,
        uuid=uuid,
        state=state,
        autostart=autostart,
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_libvirt_resource_action(
    action: str,
    resource_type: str,
    scope: str,
    name: str,
    uuid: str,
    expected_state_token: str,
    *,
    confirmed: bool,
) -> LibvirtResourceActionResponse:
    safe_action = action if isinstance(action, str) and action in RESOURCE_ACTIONS else "start"
    safe_type = resource_type if isinstance(resource_type, str) and resource_type in RESOURCE_TYPES else "network"
    safe_scope = scope if isinstance(scope, str) and scope in SCOPED_URIS else None
    safe_name = name[:MAX_NAME_LENGTH] if isinstance(name, str) else None
    safe_uuid = (
        uuid.casefold()
        if isinstance(uuid, str) and len(uuid) == 36 and UUID_RE.fullmatch(uuid)
        else None
    )

    with _ACTION_LOCK:
        record = (
            _ACTION_TOKENS.get(expected_state_token)
            if isinstance(expected_state_token, str)
            and len(expected_state_token) <= 100
            and TOKEN_RE.fullmatch(expected_state_token)
            else None
        )
        if record is None or record.expires_at <= time.monotonic():
            if isinstance(expected_state_token, str) and len(expected_state_token) <= 100:
                _ACTION_TOKENS.pop(expected_state_token, None)
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=safe_uuid,
                state=None,
                autostart=None,
                state_verified=False,
                user_confirmed=confirmed is True,
                message="A fresh libvirt confirmation token is required; inspect the resource and try again.",
            )
        if record.claimed:
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=safe_uuid,
                state=record.state,
                autostart=record.autostart,
                state_verified=False,
                user_confirmed=confirmed is True,
                message="This libvirt confirmation token is already being used; inspect the resource and request a new action.",
            )
        record.claimed = True

    try:
        if confirmed is not True:
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=safe_uuid,
                state=record.state,
                autostart=record.autostart,
                state_verified=False,
                user_confirmed=False,
                message="Explicit client confirmation is required; no libvirt command was run.",
            )
        if (
            action != record.action
            or resource_type != record.resource_type
            or scope != record.scope
            or name != record.name
            or safe_uuid != record.uuid
        ):
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=safe_uuid,
                state=record.state,
                autostart=record.autostart,
                state_verified=False,
                user_confirmed=True,
                message="Confirmation did not match the exact resource, scope, action, or UUID; no command was run.",
            )

        name_error = _validate_resource_name(record.resource_type, record.name)
        if name_error:
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=safe_uuid,
                state=record.state,
                autostart=record.autostart,
                state_verified=False,
                user_confirmed=True,
                message=name_error,
            )
        if not sys.platform.startswith("linux"):
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=safe_uuid,
                state=record.state,
                autostart=record.autostart,
                state_verified=False,
                user_confirmed=True,
                message="Libvirt resource control is available only on Linux.",
            )
        env = virsh_environment()
        binary = find_session_binary("virsh", env)
        if not binary:
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=safe_uuid,
                state=record.state,
                autostart=record.autostart,
                state_verified=False,
                user_confirmed=True,
                message="The optional virsh command became unavailable; no action was run.",
            )
        current, error = _read_resource_info(record.resource_type, record.scope, record.name, binary, env)
        if error or current is None:
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=safe_uuid,
                state=None,
                autostart=None,
                state_verified=False,
                user_confirmed=True,
                message=error or "The exact libvirt resource could not be revalidated; no action was run.",
            )
        if (
            current.uuid != record.uuid
            or current.state != record.state
            or current.active != record.active
            or current.persistent != record.persistent
            or current.autostart != record.autostart
        ):
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=current.uuid,
                state=current.state,
                autostart=current.autostart,
                state_verified=False,
                user_confirmed=True,
                message="The libvirt resource identity or state changed after confirmation; inspect it and confirm again.",
            )
        action_error, already_reached = _validate_resource_action(record.action, current)
        if action_error:
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=safe_uuid,
                state=current.state,
                autostart=current.autostart,
                state_verified=False,
                user_confirmed=True,
                message=action_error,
            )
        if already_reached:
            return _resource_action_response(
                success=True,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=safe_uuid,
                state=current.state,
                autostart=current.autostart,
                state_verified=True,
                user_confirmed=True,
                message=f"The exact libvirt resource already has the requested state for {safe_action}; no command was needed.",
            )

        command = [
            binary,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[record.scope],
            *_action_command(record.action, record.resource_type, record.uuid),
        ]
        _output, command_error, command_truncated = run_bounded_command(
            command,
            env,
            command_label=f"local libvirt {record.resource_type} {record.action}",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
        )
        after, verify_error = _read_resource_info(record.resource_type, record.scope, record.name, binary, env)
        state = after.state if after is not None else None
        autostart = after.autostart if after is not None else None
        verified = after is not None and after.uuid == record.uuid and _action_reached(record.action, after)
        if command_error or command_truncated:
            message = (
                "The libvirt command timed out; the resource may have changed partially. Inspect it before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "Libvirt reported an action error; inspect the resource before retrying."
            )
            if verified:
                message += " The requested state is visible now."
            elif verify_error:
                message += " The resulting state could not be verified."
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=record.uuid,
                state=state,
                autostart=autostart,
                state_verified=verified,
                user_confirmed=True,
                message=message,
            )
        if not verified:
            message = "Libvirt accepted the action, but the requested state is not visible; inspect the resource before retrying."
            if verify_error:
                message += " The resulting state could not be read."
            return _resource_action_response(
                success=False,
                action=safe_action,
                resource_type=safe_type,
                scope=safe_scope,
                name=safe_name,
                uuid=record.uuid,
                state=state,
                autostart=autostart,
                state_verified=False,
                user_confirmed=True,
                message=message,
            )
        return _resource_action_response(
            success=True,
            action=safe_action,
            resource_type=safe_type,
            scope=safe_scope,
            name=safe_name,
            uuid=record.uuid,
            state=state,
            autostart=autostart,
            state_verified=True,
            user_confirmed=True,
            message=f"Libvirt {record.resource_type} action {record.action} reached and verified the requested state.",
        )
    finally:
        with _ACTION_LOCK:
            _ACTION_TOKENS.pop(expected_state_token, None)


def _validate_volume_create_request(
    scope: str,
    pool_name: str,
    volume_name: str,
    capacity_bytes: int,
    volume_format: str,
) -> str | None:
    if not isinstance(scope, str) or scope not in SCOPED_URIS:
        return "Choose the local system or user-session libvirt scope."
    pool_error = _validate_resource_name("storage_pool", pool_name)
    if pool_error:
        return pool_error
    if not isinstance(volume_name, str) or not VOLUME_NAME_RE.fullmatch(volume_name):
        return "Volume names must start with a letter or digit and contain at most 128 letters, digits, dots, underscores, or hyphens."
    if (
        not isinstance(capacity_bytes, int)
        or isinstance(capacity_bytes, bool)
        or not MIN_VOLUME_CAPACITY_BYTES <= capacity_bytes <= MAX_VOLUME_CAPACITY_BYTES
    ):
        return (
            f"Capacity must be an integer from {MIN_VOLUME_CAPACITY_BYTES} bytes "
            f"(1 MiB) through {MAX_VOLUME_CAPACITY_BYTES} bytes (1 TiB)."
        )
    if not isinstance(volume_format, str) or volume_format not in {"raw", "qcow2"}:
        return "Choose raw or qcow2 as the volume format."
    return None


def _read_pool_type(
    scope: str,
    pool_uuid: str,
    binary: str,
    env: dict[str, str],
) -> tuple[str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [
            binary,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[scope],
            "--readonly",
            "pool-dumpxml",
            pool_uuid,
        ],
        env,
        command_label=f"local libvirt {scope} storage-pool type inspection",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=64 * 1024,
    )
    if error or output is None or truncated:
        return None, "The storage-pool definition could not be safely inspected."
    if "<!doctype" in output.casefold() or "<!entity" in output.casefold():
        return None, "The storage-pool definition contains unsupported XML declarations."
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return None, "Libvirt returned an unrecognized storage-pool definition."
    if root.tag != "pool":
        return None, "Libvirt returned an unrecognized storage-pool definition."
    pool_type = root.get("type")
    if not pool_type or len(pool_type) > 32 or not re.fullmatch(r"[a-z0-9_]+", pool_type):
        return None, "Libvirt returned an invalid storage-pool type."
    return pool_type, None


def _read_pool_volume_names(
    scope: str,
    pool_uuid: str,
    binary: str,
    env: dict[str, str],
) -> tuple[set[str] | None, str | None]:
    rows, error, truncated = _read_table(
        scope,
        ["vol-list", "--pool", pool_uuid, "--details"],
        {"name", "type", "capacity", "allocation"},
        f"local libvirt {scope} storage-volume inventory",
        binary,
        env,
    )
    if error or rows is None or truncated:
        return None, "The storage-pool volume list could not be fully inspected."
    return {row["name"] for row in rows}, None


def _read_volume_create_snapshot(
    scope: str,
    pool_name: str,
    volume_name: str,
    binary: str,
    env: dict[str, str],
) -> tuple[_ResourceSnapshot | None, str | None]:
    pool, error = _read_resource_info("storage_pool", scope, pool_name, binary, env)
    if error or pool is None:
        return None, error or "The exact storage pool could not be verified."
    if pool.persistent is not True:
        return None, "Volume creation requires a persistent storage pool."
    if not pool.active or pool.state != "running":
        return None, "Volume creation requires the exact storage pool to be running."

    pool_type, error = _read_pool_type(scope, pool.uuid, binary, env)
    if error or pool_type != "dir":
        return None, error or "Volume creation supports only directory-backed libvirt storage pools."
    names, error = _read_pool_volume_names(scope, pool.uuid, binary, env)
    if error or names is None:
        return None, error or "The storage-pool volume list could not be inspected."
    if volume_name in names:
        return None, "A volume with that exact name already exists in the selected pool."
    return pool, None


def libvirt_volume_create_confirmation_details(
    scope: str,
    pool_name: str,
    volume_name: str,
    capacity_bytes: int,
    volume_format: str,
) -> tuple[LibvirtVolumeCreateTarget | None, str | None]:
    """Bind a new sparse file-backed volume request to one pool and its current state."""
    validation_error = _validate_volume_create_request(
        scope, pool_name, volume_name, capacity_bytes, volume_format
    )
    if validation_error:
        return None, validation_error
    if not sys.platform.startswith("linux"):
        return None, "Libvirt volume creation is available only on Linux."
    env = virsh_environment()
    binary = find_session_binary("virsh", env)
    if not binary:
        return None, "The optional virsh command is unavailable."
    snapshot, error = _read_volume_create_snapshot(
        scope, pool_name, volume_name, binary, env
    )
    if error or snapshot is None:
        return None, error or "The exact storage-pool state could not be verified."

    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _VolumeCreateActionToken(
        scope=scope,
        pool_name=snapshot.name,
        pool_uuid=snapshot.uuid,
        pool_state=snapshot.state,
        pool_autostart=snapshot.autostart,
        volume_name=volume_name,
        capacity_bytes=capacity_bytes,
        volume_format=volume_format,
        expires_at=now + TOKEN_TTL_SECONDS,
    )
    with _ACTION_LOCK:
        expired = [key for key, item in _VOLUME_CREATE_TOKENS.items() if item.expires_at <= now]
        for key in expired:
            _VOLUME_CREATE_TOKENS.pop(key, None)
        if len(_VOLUME_CREATE_TOKENS) >= 1_024:
            return None, "Too many pending libvirt volume confirmations; retry after existing prompts expire."
        _VOLUME_CREATE_TOKENS[token] = record
    return LibvirtVolumeCreateTarget(
        scope=scope,
        pool_name=snapshot.name,
        pool_uuid=snapshot.uuid,
        pool_state=snapshot.state,
        volume_name=volume_name,
        capacity_bytes=capacity_bytes,
        volume_format=volume_format,
        confirmation_token=token,
    ), None


def _read_created_volume_definition(
    scope: str,
    pool_uuid: str,
    volume_name: str,
    binary: str,
    env: dict[str, str],
) -> tuple[tuple[int, str] | None, str | None]:
    output, error, truncated = run_bounded_command(
        [
            binary,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[scope],
            "--readonly",
            "vol-dumpxml",
            "--pool",
            pool_uuid,
            volume_name,
        ],
        env,
        command_label=f"local libvirt {scope} created-volume definition verification",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=64 * 1024,
    )
    if error or output is None or truncated:
        return None, "The new volume could not be verified."
    if "<!doctype" in output.casefold() or "<!entity" in output.casefold():
        return None, "The new volume definition contains unsupported XML declarations."
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return None, "Libvirt returned an unrecognized created-volume definition."
    capacity_element = root.find("capacity")
    target_element = root.find("target")
    format_element = target_element.find("format") if target_element is not None else None
    capacity = capacity_element.text.strip() if capacity_element is not None and capacity_element.text else ""
    unit = capacity_element.get("unit", "bytes") if capacity_element is not None else ""
    volume_format = format_element.get("type", "") if format_element is not None else ""
    if (
        root.tag != "volume"
        or root.findtext("name") != volume_name
        or unit != "bytes"
        or not re.fullmatch(r"[0-9]+", capacity)
        or volume_format not in {"raw", "qcow2"}
    ):
        return None, "Libvirt returned an unrecognized created-volume summary."
    return (int(capacity), volume_format), None


def _volume_create_response(
    *,
    success: bool,
    scope: str | None,
    pool_name: str | None,
    pool_uuid: str | None,
    volume_name: str | None,
    capacity_bytes: int | None,
    volume_format: str,
    state_verified: bool,
    user_confirmed: bool,
    message: str,
) -> LibvirtVolumeCreateResponse:
    return LibvirtVolumeCreateResponse(
        success=success,
        scope=scope if scope in SCOPED_URIS else None,
        pool_name=pool_name[:MAX_NAME_LENGTH] if isinstance(pool_name, str) else None,
        pool_uuid=pool_uuid.casefold() if isinstance(pool_uuid, str) and UUID_RE.fullmatch(pool_uuid) else None,
        volume_name=volume_name[:128] if isinstance(volume_name, str) else None,
        capacity_bytes=capacity_bytes if isinstance(capacity_bytes, int) and not isinstance(capacity_bytes, bool) else None,
        volume_format=volume_format if volume_format in {"raw", "qcow2"} else "qcow2",
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_libvirt_volume_create(
    scope: str,
    pool_name: str,
    volume_name: str,
    capacity_bytes: int,
    volume_format: str,
    pool_uuid: str,
    expected_state_token: str,
    *,
    confirmed: bool,
) -> LibvirtVolumeCreateResponse:
    safe_scope = scope if isinstance(scope, str) and scope in SCOPED_URIS else None
    safe_pool_name = pool_name if isinstance(pool_name, str) else None
    safe_pool_uuid = (
        pool_uuid.casefold()
        if isinstance(pool_uuid, str) and UUID_RE.fullmatch(pool_uuid)
        else None
    )
    safe_volume_name = volume_name if isinstance(volume_name, str) else None
    safe_format = volume_format if isinstance(volume_format, str) else "qcow2"
    with _ACTION_LOCK:
        record = (
            _VOLUME_CREATE_TOKENS.get(expected_state_token)
            if isinstance(expected_state_token, str)
            and len(expected_state_token) <= 100
            and TOKEN_RE.fullmatch(expected_state_token)
            else None
        )
        if record is None or record.expires_at <= time.monotonic():
            if isinstance(expected_state_token, str) and len(expected_state_token) <= 100:
                _VOLUME_CREATE_TOKENS.pop(expected_state_token, None)
            return _volume_create_response(
                success=False,
                scope=safe_scope,
                pool_name=safe_pool_name,
                pool_uuid=safe_pool_uuid,
                volume_name=safe_volume_name,
                capacity_bytes=capacity_bytes,
                volume_format=safe_format,
                state_verified=False,
                user_confirmed=confirmed is True,
                message="A fresh libvirt volume-creation confirmation token is required; inspect the pool and try again.",
            )
        if record.claimed:
            return _volume_create_response(
                success=False,
                scope=safe_scope,
                pool_name=safe_pool_name,
                pool_uuid=safe_pool_uuid,
                volume_name=safe_volume_name,
                capacity_bytes=capacity_bytes,
                volume_format=safe_format,
                state_verified=False,
                user_confirmed=confirmed is True,
                message="This libvirt volume-creation token is already in use; inspect the pool and request a new confirmation.",
            )
        record.claimed = True

    try:
        if confirmed is not True:
            return _volume_create_response(
                success=False,
                scope=record.scope,
                pool_name=record.pool_name,
                pool_uuid=record.pool_uuid,
                volume_name=record.volume_name,
                capacity_bytes=record.capacity_bytes,
                volume_format=record.volume_format,
                state_verified=False,
                user_confirmed=False,
                message="Explicit client confirmation is required; no libvirt command was run.",
            )
        if (
            _validate_volume_create_request(
                scope, pool_name, volume_name, capacity_bytes, volume_format
            )
            or scope != record.scope
            or pool_name != record.pool_name
            or volume_name != record.volume_name
            or capacity_bytes != record.capacity_bytes
            or volume_format != record.volume_format
            or safe_pool_uuid != record.pool_uuid
        ):
            return _volume_create_response(
                success=False,
                scope=safe_scope,
                pool_name=safe_pool_name,
                pool_uuid=safe_pool_uuid,
                volume_name=safe_volume_name,
                capacity_bytes=capacity_bytes,
                volume_format=safe_format,
                state_verified=False,
                user_confirmed=True,
                message="Confirmation did not match the exact pool, volume name, capacity, format, scope, and pool UUID; no command was run.",
            )
        if not sys.platform.startswith("linux"):
            return _volume_create_response(
                success=False,
                scope=record.scope,
                pool_name=record.pool_name,
                pool_uuid=record.pool_uuid,
                volume_name=record.volume_name,
                capacity_bytes=record.capacity_bytes,
                volume_format=record.volume_format,
                state_verified=False,
                user_confirmed=True,
                message="Libvirt volume creation is available only on Linux.",
            )
        env = virsh_environment()
        binary = find_session_binary("virsh", env)
        if not binary:
            return _volume_create_response(
                success=False,
                scope=record.scope,
                pool_name=record.pool_name,
                pool_uuid=record.pool_uuid,
                volume_name=record.volume_name,
                capacity_bytes=record.capacity_bytes,
                volume_format=record.volume_format,
                state_verified=False,
                user_confirmed=True,
                message="The optional virsh command became unavailable; no volume was created.",
            )
        current, error = _read_volume_create_snapshot(
            record.scope, record.pool_name, record.volume_name, binary, env
        )
        if error or current is None:
            return _volume_create_response(
                success=False,
                scope=record.scope,
                pool_name=record.pool_name,
                pool_uuid=record.pool_uuid,
                volume_name=record.volume_name,
                capacity_bytes=record.capacity_bytes,
                volume_format=record.volume_format,
                state_verified=False,
                user_confirmed=True,
                message=error or "The storage pool could not be revalidated; no command was run.",
            )
        if (
            current.uuid != record.pool_uuid
            or current.state != record.pool_state
            or current.autostart != record.pool_autostart
        ):
            return _volume_create_response(
                success=False,
                scope=record.scope,
                pool_name=record.pool_name,
                pool_uuid=current.uuid,
                volume_name=record.volume_name,
                capacity_bytes=record.capacity_bytes,
                volume_format=record.volume_format,
                state_verified=False,
                user_confirmed=True,
                message="The storage-pool identity or state changed after confirmation; inspect it and confirm again.",
            )

        command = [
            binary,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[record.scope],
            "vol-create-as",
            record.pool_uuid,
            record.volume_name,
            str(record.capacity_bytes),
            "--allocation",
            "0",
            "--format",
            record.volume_format,
        ]
        _output, command_error, command_truncated = run_bounded_command(
            command,
            env,
            command_label=f"local libvirt {record.scope} storage-volume creation",
            timeout_seconds=VOLUME_CREATE_TIMEOUT_SECONDS,
            max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
        )
        created_volume, verify_error = _read_created_volume_definition(
            record.scope, record.pool_uuid, record.volume_name, binary, env
        )
        verified = created_volume == (record.capacity_bytes, record.volume_format)
        if command_error or command_truncated:
            message = (
                "The libvirt volume-creation command timed out; inspect the pool before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "Libvirt reported a volume-creation error; inspect the pool before retrying."
            )
            if verified:
                message += " A volume with the requested name, capacity, and format is visible."
            elif verify_error:
                message += " The resulting volume could not be verified."
            return _volume_create_response(
                success=False,
                scope=record.scope,
                pool_name=record.pool_name,
                pool_uuid=record.pool_uuid,
                volume_name=record.volume_name,
                capacity_bytes=record.capacity_bytes,
                volume_format=record.volume_format,
                state_verified=verified,
                user_confirmed=True,
                message=message,
            )
        if not verified:
            message = "Libvirt returned from volume creation, but the requested name, capacity, and format are not all visible."
            if verify_error:
                message += " The resulting volume could not be read; inspect the pool before retrying."
            return _volume_create_response(
                success=False,
                scope=record.scope,
                pool_name=record.pool_name,
                pool_uuid=record.pool_uuid,
                volume_name=record.volume_name,
                capacity_bytes=record.capacity_bytes,
                volume_format=record.volume_format,
                state_verified=False,
                user_confirmed=True,
                message=message,
            )
        return _volume_create_response(
            success=True,
            scope=record.scope,
            pool_name=record.pool_name,
            pool_uuid=record.pool_uuid,
            volume_name=record.volume_name,
            capacity_bytes=record.capacity_bytes,
            volume_format=record.volume_format,
            state_verified=True,
            user_confirmed=True,
            message="The new libvirt volume's exact name, capacity, and format were verified. The sparse volume can consume pool space as data is written.",
        )
    finally:
        with _ACTION_LOCK:
            _VOLUME_CREATE_TOKENS.pop(expected_state_token, None)
