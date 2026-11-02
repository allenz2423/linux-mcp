"""Constrained remote libvirt snapshot inventory and confirmed actions."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass

from wayland_mcp.models import (
    VirtualMachineSnapshotActionResponse,
    VirtualMachineSnapshotInfo,
    VirtualMachineSnapshotListResponse,
)
from wayland_mcp.tools.remote_virtual_machines import (
    _RemoteActionToken,
    _TOKEN_LOCK,
    _TOKENS,
    _lookup_current,
    _run_remote_virsh,
    _token_record,
)
from wayland_mcp.tools.virtual_machines import TOKEN_RE, _Domain

MAX_SNAPSHOTS = 512
MAX_RETURNED_SNAPSHOTS = 200
MAX_OUTPUT_BYTES = 256 * 1024
MAX_ACTION_OUTPUT_BYTES = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 20
ACTION_TIMEOUT_SECONDS = 300
SNAPSHOT_NAME_MAX = 255
DESCRIPTION_MAX = 512
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class _SnapshotEntry:
    name: str
    parent_name: str | None


@dataclass(frozen=True, slots=True)
class _SnapshotState:
    name: str
    parent_name: str | None
    state: str
    children: int


@dataclass(frozen=True, slots=True)
class _SnapshotTarget:
    action: str
    endpoint: str
    scope: str
    uuid: str
    domain_name: str
    domain_state: str
    domain_id: int | None
    snapshot_name: str
    description: str | None
    snapshot_state: str | None
    parent_name: str | None
    children: int | None
    expected_token: str
    confirmation_phrase: str


_TARGETS: dict[str, _SnapshotTarget] = {}


def _prune_targets_locked() -> None:
    now = time.monotonic()
    expired = [
        token
        for token in _TARGETS
        if token not in _TOKENS or _TOKENS[token].expires_at <= now
    ]
    for token in expired:
        _TARGETS.pop(token, None)


def _valid_snapshot_name(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > SNAPSHOT_NAME_MAX:
        return f"snapshot_name must be non-empty text up to {SNAPSHOT_NAME_MAX} characters."
    if (
        value != value.strip()
        or value in {".", ".."}
        or value.startswith("-")
        or _CONTROL_RE.search(value)
    ):
        return "snapshot_name must be a single-line libvirt name that does not begin with '-'."
    return None


def _read_snapshot_names(
    record: _RemoteActionToken,
) -> tuple[list[_SnapshotEntry] | None, bool, str | None]:
    output, error, truncated = _run_remote_virsh(
        record.endpoint,
        ["snapshot-list", record.uuid, "--name", "--parent"],
        readonly=True,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_OUTPUT_BYTES,
        command_label="remote libvirt snapshot inventory",
    )
    if error or output is None:
        return None, truncated, "The remote snapshot inventory could not be read safely."
    lines = output.splitlines()
    source_truncated = truncated or len(lines) > MAX_SNAPSHOTS
    snapshots: list[_SnapshotEntry] = []
    for line in lines[:MAX_SNAPSHOTS]:
        name, separator, parent = line.partition("\t")
        if not name:
            continue
        if len(name) > SNAPSHOT_NAME_MAX or _CONTROL_RE.search(name):
            return None, source_truncated, "The remote snapshot inventory contained an invalid name."
        parent_name = parent.strip() if separator else ""
        if parent_name.casefold() in {"", "(none)", "none", "-"}:
            parent_name = None
        if parent_name is not None and (len(parent_name) > SNAPSHOT_NAME_MAX or _CONTROL_RE.search(parent_name)):
            return None, source_truncated, "The remote snapshot inventory contained an invalid parent name."
        snapshots.append(_SnapshotEntry(name, parent_name))
    names = [snapshot.name for snapshot in snapshots]
    if len(set(names)) != len(names):
        return None, source_truncated, "The remote snapshot inventory contained duplicate names."
    return snapshots, source_truncated, None


def _read_snapshot_info(
    record: _RemoteActionToken,
    name: str,
) -> tuple[_SnapshotState | None, str | None]:
    output, error, truncated = _run_remote_virsh(
        record.endpoint,
        ["snapshot-info", record.uuid, name],
        readonly=True,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
        command_label="remote libvirt snapshot details",
    )
    if error or output is None or truncated:
        return None, "The remote snapshot details could not be read safely."
    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip().casefold()] = value.strip()
    state = fields.get("state")
    children_text = fields.get("children")
    if not state or not children_text or not children_text.isdecimal():
        return None, "The remote snapshot state and child count could not be verified."
    parent = fields.get("parent", "")
    if parent.casefold() in {"", "(none)", "none", "-"}:
        parent = None
    elif _CONTROL_RE.search(parent) or len(parent) > SNAPSHOT_NAME_MAX:
        return None, "The remote snapshot parent name could not be verified."
    return _SnapshotState(name, parent, state[:64], int(children_text)), None


def _domain_matches_token(
    record: _RemoteActionToken,
) -> tuple[_Domain | None, str | None]:
    current, error = _lookup_current(record)
    if error or current is None:
        return None, error or "The exact remote VM could not be found."
    if current.state != record.state or current.domain_id != record.domain_id:
        return None, "The remote VM state changed after it was listed; list remote virtual machines again."
    return current, None


def list_remote_virtual_machine_snapshots(
    identity_token: str,
    limit: int = 100,
) -> VirtualMachineSnapshotListResponse:
    if not isinstance(identity_token, str) or not TOKEN_RE.fullmatch(identity_token):
        return VirtualMachineSnapshotListResponse(success=False, message="A fresh identity_token from list_remote_virtual_machines is required.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return VirtualMachineSnapshotListResponse(success=False, message="limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_SNAPSHOTS))
    with _TOKEN_LOCK:
        _prune_targets_locked()
    record, error = _token_record(identity_token)
    if error or record is None:
        return VirtualMachineSnapshotListResponse(success=False, limit=limit, message=error or "The remote VM identity token is unavailable.")
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.claimed:
            return VirtualMachineSnapshotListResponse(success=False, limit=limit, message="The remote VM token is expired or reserved for an action; list remote virtual machines again.")
    _domain, error = _domain_matches_token(record)
    values = {
        "endpoint": record.endpoint,
        "scope": record.scope,
        "uuid": record.uuid,
        "domain_name": record.name,
        "domain_state": record.state,
        "limit": limit,
    }
    if error:
        return VirtualMachineSnapshotListResponse(success=False, **values, message=error)
    names, source_truncated, error = _read_snapshot_names(record)
    if error or names is None:
        return VirtualMachineSnapshotListResponse(success=False, **values, truncated=source_truncated, message=error or "The remote snapshot inventory was unavailable.")
    selected = names[:limit]
    return VirtualMachineSnapshotListResponse(
        success=True,
        **values,
        total_snapshots=len(names),
        returned_snapshots=len(selected),
        snapshots=[VirtualMachineSnapshotInfo(name=item.name, parent_name=item.parent_name) for item in selected],
        truncated=source_truncated or len(names) > limit,
        partial=source_truncated,
        message="Snapshot actions require a fresh complete inventory." if source_truncated else None,
    )


def _observe_target(
    record: _RemoteActionToken,
    action: str,
    snapshot_name: str,
    description: str | None,
) -> tuple[_SnapshotTarget | None, str | None]:
    domain, error = _domain_matches_token(record)
    if error or domain is None:
        return None, error or "The exact remote VM could not be verified."
    names, truncated, error = _read_snapshot_names(record)
    if error or names is None or truncated:
        return None, error or "The full remote snapshot inventory could not be verified."
    name_set = {item.name for item in names}
    if action == "create":
        if domain.state != "shut off":
            return None, "Remote snapshot creation is limited to shut-off VMs; stop the VM and list it again first."
        if snapshot_name in name_set:
            return None, "That snapshot name already exists for this remote VM."
        detail = None
    else:
        if snapshot_name not in name_set:
            return None, "The exact remote snapshot name was not found; list remote VM snapshots again."
        detail, error = _read_snapshot_info(record, snapshot_name)
        if error or detail is None:
            return None, error or "The selected remote snapshot could not be verified."
        if action == "delete" and detail.children != 0:
            return None, "Only leaf snapshots with no children can be deleted; this avoids merging or deleting child snapshots."
    material = {
        "action": action,
        "endpoint": record.endpoint,
        "scope": record.scope,
        "uuid": record.uuid,
        "domain_name": record.name,
        "domain_state": domain.state,
        "domain_id": domain.domain_id,
        "inventory": [{"name": item.name, "parent": item.parent_name} for item in names],
        "snapshot_name": snapshot_name,
        "description": description,
        "snapshot_info": None if detail is None else {
            "state": detail.state,
            "parent": detail.parent_name,
            "children": detail.children,
        },
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    return _SnapshotTarget(
        action=action,
        endpoint=record.endpoint,
        scope=record.scope,
        uuid=record.uuid,
        domain_name=record.name,
        domain_state=domain.state,
        domain_id=domain.domain_id,
        snapshot_name=snapshot_name,
        description=description,
        snapshot_state=detail.state if detail else None,
        parent_name=detail.parent_name if detail else None,
        children=detail.children if detail else None,
        expected_token=digest,
        confirmation_phrase=f"REMOTE-SNAPSHOT-{action.upper()}-{digest[:12]}",
    ), None


def remote_snapshot_action_confirmation_details(
    action: str,
    identity_token: str,
    snapshot_name: str,
    description: str = "",
) -> tuple[_SnapshotTarget | None, str | None, str | None]:
    if action not in {"create", "revert", "delete"}:
        return None, None, "action must be create, revert, or delete."
    error = _valid_snapshot_name(snapshot_name)
    if error:
        return None, None, error
    if not isinstance(description, str) or len(description) > DESCRIPTION_MAX or _CONTROL_RE.search(description):
        return None, None, f"description must be single-line text up to {DESCRIPTION_MAX} characters."
    if description.lstrip().startswith("-"):
        return None, None, "description cannot begin with '-'; virsh would treat it as an option."
    if action != "create" and description:
        return None, None, "description is used only when creating a snapshot."
    if action == "create":
        description = description.strip()
    with _TOKEN_LOCK:
        _prune_targets_locked()
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, None, error or "A fresh remote VM identity token is required."
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.claimed or record.expires_at <= time.monotonic():
            return None, None, "The remote VM identity token is expired or already reserved; list remote virtual machines again."
        record.claimed = True
    target, error = _observe_target(record, action, snapshot_name, description or None)
    if error or target is None:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
            _TARGETS.pop(identity_token, None)
        return None, None, error or "The remote VM snapshot action could not be prepared."
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record:
            return None, None, "The remote VM identity token expired while preparing confirmation."
        record.action = f"snapshot:{action}"
        record.confirmation_token = target.expected_token
        _TARGETS[identity_token] = target
    return target, target.confirmation_phrase, None


def _read_current_snapshot(record: _RemoteActionToken) -> tuple[str | None, str | None]:
    output, error, truncated = _run_remote_virsh(
        record.endpoint,
        ["snapshot-current", record.uuid, "--name"],
        readonly=True,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
        command_label="remote libvirt current snapshot query",
    )
    if error or output is None or truncated:
        return None, "The current remote snapshot could not be verified."
    return output.strip() or None, None


def perform_remote_virtual_machine_snapshot_action(
    action: str,
    identity_token: str,
    snapshot_name: str,
    description: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> VirtualMachineSnapshotActionResponse:
    safe_action = action if action in {"create", "revert", "delete"} else "create"
    with _TOKEN_LOCK:
        _prune_targets_locked()
    record, error = _token_record(identity_token)
    if error or record is None:
        return VirtualMachineSnapshotActionResponse(success=False, action=safe_action, snapshot_name=snapshot_name or None, message=error or "A fresh remote VM identity token is required.")
    with _TOKEN_LOCK:
        target = _TARGETS.get(identity_token)
    response = {
        "endpoint": record.endpoint,
        "scope": record.scope,
        "uuid": record.uuid,
        "domain_name": record.name,
        "snapshot_name": snapshot_name or None,
        "snapshot_description": description or None,
        "domain_state_before": record.state,
        "user_confirmed": confirmed is True,
    }
    try:
        if confirmed is not True:
            return VirtualMachineSnapshotActionResponse(success=False, action=safe_action, **response, message="Explicit client confirmation is required; no remote libvirt snapshot command was run.")
        if action not in {"create", "revert", "delete"}:
            return VirtualMachineSnapshotActionResponse(success=False, action=safe_action, **response, message="Unsupported remote snapshot action; no command was run.")
        if (
            target is None
            or not record.claimed
            or record.action != f"snapshot:{action}"
            or record.confirmation_token != target.expected_token
            or target.action != action
            or target.endpoint != record.endpoint
            or target.snapshot_name != snapshot_name
            or target.description != (description.strip() or None)
            or confirmation_phrase != target.confirmation_phrase
        ):
            return VirtualMachineSnapshotActionResponse(success=False, action=safe_action, **response, message="Confirmation did not match the exact remote VM, snapshot, action, or state; no command was run.")
        current_target, error = _observe_target(record, action, snapshot_name, target.description)
        if error or current_target is None or current_target.expected_token != target.expected_token:
            return VirtualMachineSnapshotActionResponse(success=False, action=safe_action, **response, message=error or "Remote VM or snapshot state changed after confirmation; inspect it and confirm again.")
        arguments = ["snapshot-create-as", record.uuid, snapshot_name]
        if action == "create":
            if target.description:
                arguments.append(target.description)
            arguments.extend(["--disk-only", "--atomic"])
        elif action == "revert":
            arguments = ["snapshot-revert", record.uuid, snapshot_name]
        else:
            arguments = ["snapshot-delete", record.uuid, snapshot_name]
        _output, command_error, command_truncated = _run_remote_virsh(
            record.endpoint,
            arguments,
            readonly=False,
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
            command_label=f"remote libvirt snapshot {action}",
        )
        if command_truncated:
            command_error = command_error or "Remote virsh output exceeded the configured limit."
        after_domain, domain_error = _lookup_current(record)
        names, inventory_truncated, inventory_error = _read_snapshot_names(record)
        state_after = after_domain.state if after_domain is not None else None
        if action == "create":
            verified = names is not None and not inventory_truncated and snapshot_name in {item.name for item in names}
        elif action == "delete":
            verified = names is not None and not inventory_truncated and snapshot_name not in {item.name for item in names}
        else:
            current_name, current_error = _read_current_snapshot(record)
            verified = current_error is None and current_name == snapshot_name
            if current_error:
                inventory_error = current_error
        if command_error:
            message = "The remote libvirt snapshot operation could not be completed."
            if verified:
                message += " The requested result is visible; inspect the VM before retrying."
        elif verified:
            if action == "create":
                message = "The shut-off remote VM disk snapshot was created and verified."
            elif action == "delete":
                message = "The remote leaf snapshot was deleted and its absence was verified."
            else:
                message = "The remote VM was reverted to the selected snapshot and that snapshot is current. Its saved execution state may resume the guest."
        else:
            message = "The remote snapshot command returned, but its result could not be verified; inspect the VM before retrying."
            if domain_error or inventory_error:
                message += " The post-action inventory was unavailable."
        return VirtualMachineSnapshotActionResponse(
            success=command_error is None and verified,
            action=safe_action,
            **{**response, "domain_state_after": state_after},
            message=message,
        )
    finally:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
            _TARGETS.pop(identity_token, None)
