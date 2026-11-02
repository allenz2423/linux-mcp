"""Bounded local libvirt snapshot inventory and confirmed snapshot actions."""

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
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.libvirt_common import SCOPED_URIS, virsh_environment
from wayland_mcp.tools.virtual_machines import (
    TOKEN_RE,
    _ActionToken,
    _Domain,
    _TOKEN_LOCK,
    _TOKENS,
    _lookup_current,
    _token_record,
)

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
    scope: str
    uuid: str
    domain_name: str
    domain_state: str
    domain_id: int | None
    snapshot_name: str
    description: str | None
    inventory_digest: str
    snapshot_state: str | None
    parent_name: str | None
    children: int | None
    expected_token: str
    confirmation_phrase: str


_TARGETS: dict[str, _SnapshotTarget] = {}


def _clean_error(error: str | None) -> str:
    # Do not return virsh output, which can contain host-specific details.
    return "The local libvirt snapshot operation could not be completed." if error else ""


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


def _read_snapshot_names(record: _ActionToken) -> tuple[list[_SnapshotEntry] | None, bool, str | None]:
    env = virsh_environment()
    output, error, truncated = run_bounded_command(
        [
            record.virsh,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[record.scope],
            "--readonly",
            "snapshot-list",
            record.uuid,
            "--name",
            "--parent",
        ],
        env,
        command_label="local libvirt snapshot inventory",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if error or output is None:
        return None, truncated, error or "Snapshot inventory was unavailable."
    lines = output.splitlines()
    source_truncated = truncated or len(lines) > MAX_SNAPSHOTS
    snapshots: list[_SnapshotEntry] = []
    for line in lines[:MAX_SNAPSHOTS]:
        name, separator, parent = line.partition("\t")
        if not name:
            continue
        if len(name) > SNAPSHOT_NAME_MAX or _CONTROL_RE.search(name):
            return None, source_truncated, "The snapshot inventory contained an invalid name."
        parent_name = parent.strip() if separator else ""
        if parent_name.casefold() in {"", "(none)", "none", "-"}:
            parent_name = None
        if parent_name is not None and (len(parent_name) > SNAPSHOT_NAME_MAX or _CONTROL_RE.search(parent_name)):
            return None, source_truncated, "The snapshot inventory contained an invalid parent name."
        snapshots.append(_SnapshotEntry(name, parent_name))
    names = [snapshot.name for snapshot in snapshots]
    if len(set(names)) != len(names):
        return None, source_truncated, "The snapshot inventory contained duplicate names."
    return snapshots, source_truncated, None


def _read_snapshot_info(record: _ActionToken, name: str) -> tuple[_SnapshotState | None, str | None]:
    output, error, truncated = run_bounded_command(
        [
            record.virsh,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[record.scope],
            "--readonly",
            "snapshot-info",
            record.uuid,
            name,
        ],
        virsh_environment(),
        command_label="local libvirt snapshot details",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
    )
    if error or output is None or truncated:
        return None, error or "Snapshot details were unavailable or exceeded the output limit."
    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip().casefold()] = value.strip()
    state = fields.get("state")
    children_text = fields.get("children")
    if not state or not children_text or not children_text.isdecimal():
        return None, "The snapshot state and child count could not be verified."
    parent = fields.get("parent", "")
    if parent.casefold() in {"", "(none)", "none", "-"}:
        parent = None
    elif _CONTROL_RE.search(parent) or len(parent) > SNAPSHOT_NAME_MAX:
        return None, "The snapshot parent name could not be verified."
    return _SnapshotState(name, parent, state[:64], int(children_text)), None


def _domain_matches_token(record: _ActionToken) -> tuple[_Domain | None, str | None]:
    current, error = _lookup_current(record)
    if error or current is None:
        return None, error or "The exact local VM could not be found."
    if current.state != record.state or current.domain_id != record.domain_id:
        return None, "The VM state changed after it was listed; list virtual machines again."
    return current, None


def list_virtual_machine_snapshots(
    identity_token: str,
    limit: int = 100,
) -> VirtualMachineSnapshotListResponse:
    """List snapshot names for one exact VM token from list_virtual_machines."""
    if not isinstance(identity_token, str) or not TOKEN_RE.fullmatch(identity_token):
        return VirtualMachineSnapshotListResponse(success=False, message="A fresh identity_token from list_virtual_machines is required.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return VirtualMachineSnapshotListResponse(success=False, message="limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_SNAPSHOTS))
    record, error = _token_record(identity_token)
    if error or record is None:
        return VirtualMachineSnapshotListResponse(success=False, limit=limit, message=error or "The VM identity token is unavailable.")
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.claimed:
            return VirtualMachineSnapshotListResponse(success=False, limit=limit, message="The VM token is expired or reserved for an action; list virtual machines again.")
    _domain, error = _domain_matches_token(record)
    if error:
        return VirtualMachineSnapshotListResponse(success=False, scope=record.scope, uuid=record.uuid, domain_name=record.name, domain_state=record.state, limit=limit, message=error)
    names, source_truncated, error = _read_snapshot_names(record)
    if error or names is None:
        return VirtualMachineSnapshotListResponse(success=False, scope=record.scope, uuid=record.uuid, domain_name=record.name, domain_state=record.state, limit=limit, truncated=source_truncated, message=error or "Snapshot inventory was unavailable.")
    selected = names[:limit]
    snapshots = [VirtualMachineSnapshotInfo(name=item.name, parent_name=item.parent_name) for item in selected]
    truncated = source_truncated or len(names) > limit
    message = "Snapshot inventory was capped; snapshot actions require a fresh complete inventory." if source_truncated else None
    return VirtualMachineSnapshotListResponse(
        success=True,
        scope=record.scope,
        uuid=record.uuid,
        domain_name=record.name,
        domain_state=record.state,
        total_snapshots=len(names),
        returned_snapshots=len(snapshots),
        snapshots=snapshots,
        limit=limit,
        truncated=truncated,
        partial=source_truncated,
        message=message,
    )


def _observe_target(
    record: _ActionToken,
    action: str,
    snapshot_name: str,
    description: str | None,
) -> tuple[_SnapshotTarget | None, str | None]:
    domain, error = _domain_matches_token(record)
    if error or domain is None:
        return None, error or "The exact local VM could not be verified."
    names, truncated, error = _read_snapshot_names(record)
    if error or names is None or truncated:
        return None, error or "The full snapshot inventory could not be verified."
    name_set = {item.name for item in names}
    if action == "create":
        if domain.state != "shut off":
            return None, "Snapshot creation is limited to shut-off VMs; stop the VM and list it again first."
        if snapshot_name in name_set:
            return None, "That snapshot name already exists for this VM."
        detail = None
    else:
        if snapshot_name not in name_set:
            return None, "The exact snapshot name was not found; list VM snapshots again."
        detail, error = _read_snapshot_info(record, snapshot_name)
        if error or detail is None:
            return None, error or "The selected snapshot could not be verified."
        if action == "delete" and detail.children != 0:
            return None, "Only leaf snapshots with no children can be deleted; this avoids merging or deleting child snapshots."
    material = {
        "action": action,
        "scope": record.scope,
        "uuid": record.uuid,
        "domain_name": record.name,
        "domain_state": domain.state,
        "domain_id": domain.domain_id,
        "virsh": record.virsh,
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
    phrase = f"SNAPSHOT-{action.upper()}-{digest[:12]}"
    return _SnapshotTarget(
        action=action,
        scope=record.scope,
        uuid=record.uuid,
        domain_name=record.name,
        domain_state=domain.state,
        domain_id=domain.domain_id,
        snapshot_name=snapshot_name,
        description=description,
        inventory_digest=digest,
        snapshot_state=detail.state if detail else None,
        parent_name=detail.parent_name if detail else None,
        children=detail.children if detail else None,
        expected_token=digest,
        confirmation_phrase=phrase,
    ), None


def snapshot_action_confirmation_details(
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
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, None, error or "A fresh VM identity token is required."
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.claimed or record.expires_at <= time.monotonic():
            return None, None, "The VM identity token is expired or already reserved; list virtual machines again."
        record.claimed = True
    target, error = _observe_target(record, action, snapshot_name, description or None)
    if error or target is None:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
            _TARGETS.pop(identity_token, None)
        return None, None, error or "The VM snapshot action could not be prepared."
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record:
            return None, None, "The VM identity token expired while preparing confirmation."
        record.action = f"snapshot:{action}"
        record.confirmation_token = target.expected_token
        _TARGETS[identity_token] = target
    return target, target.confirmation_phrase, None


def _read_current_snapshot(record: _ActionToken) -> tuple[str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [
            record.virsh,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[record.scope],
            "--readonly",
            "snapshot-current",
            record.uuid,
            "--name",
        ],
        virsh_environment(),
        command_label="local libvirt current snapshot query",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
    )
    if error or output is None or truncated:
        return None, error or "The current snapshot could not be verified."
    return output.strip() or None, None


def perform_virtual_machine_snapshot_action(
    action: str,
    identity_token: str,
    snapshot_name: str,
    description: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> VirtualMachineSnapshotActionResponse:
    safe_action = action if action in {"create", "revert", "delete"} else "create"
    record, error = _token_record(identity_token)
    if error or record is None:
        return VirtualMachineSnapshotActionResponse(success=False, action=safe_action, snapshot_name=snapshot_name or None, message=error or "A fresh VM identity token is required.")
    with _TOKEN_LOCK:
        target = _TARGETS.get(identity_token)
    response = {
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
            return VirtualMachineSnapshotActionResponse(success=False, action=safe_action, **response, message="Explicit client confirmation is required; no libvirt snapshot command was run.")
        if action not in {"create", "revert", "delete"}:
            return VirtualMachineSnapshotActionResponse(success=False, action=safe_action, **response, message="Unsupported snapshot action; no command was run.")
        if (
            target is None
            or not record.claimed
            or record.action != f"snapshot:{action}"
            or record.confirmation_token != target.expected_token
            or target.action != action
            or target.snapshot_name != snapshot_name
            or target.description != (description.strip() or None)
            or confirmation_phrase != target.confirmation_phrase
        ):
            return VirtualMachineSnapshotActionResponse(success=False, action=safe_action, **response, message="Confirmation did not match the exact VM, snapshot, action, or state; no command was run.")
        current_target, error = _observe_target(record, action, snapshot_name, target.description)
        if error or current_target is None or current_target.expected_token != target.expected_token:
            return VirtualMachineSnapshotActionResponse(success=False, action=safe_action, **response, message=error or "VM or snapshot state changed after confirmation; inspect it and confirm again.")
        command = [
            record.virsh,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[record.scope],
        ]
        if action == "create":
            command.extend(["snapshot-create-as", record.uuid, snapshot_name])
            if target.description:
                command.append(target.description)
            command.extend(["--disk-only", "--atomic"])
        elif action == "revert":
            command.extend(["snapshot-revert", record.uuid, snapshot_name])
        else:
            command.extend(["snapshot-delete", record.uuid, snapshot_name])
        _output, command_error, command_truncated = run_bounded_command(
            command,
            virsh_environment(),
            command_label=f"local libvirt snapshot {action}",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_ACTION_OUTPUT_BYTES,
        )
        if command_truncated:
            command_error = command_error or "virsh output exceeded the configured limit."
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
            message = _clean_error(command_error)
            if verified:
                message += " The requested result is visible; inspect the VM before retrying."
        elif verified:
            if action == "create":
                message = "The shut-off VM snapshot was created and verified."
            elif action == "delete":
                message = "The leaf snapshot was deleted and its absence was verified."
            else:
                message = "The VM was reverted to the selected snapshot and that snapshot is current. Its saved execution state may resume the guest."
        else:
            message = "The command returned, but the requested snapshot result could not be verified; inspect the VM before retrying."
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
