"""Bounded local container-network attachment inventory and control."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from typing import Literal
from urllib.parse import quote

from wayland_mcp.models import (
    ContainerNetworkAttachmentActionResponse,
    ContainerNetworkAttachmentResponse,
)
from wayland_mcp.tools.container_resources import (
    DEFAULT_NETWORK_NAMES,
    _read_resources,
    _resource_name,
    _select_endpoint,
)
from wayland_mcp.tools.containers import (
    ACTION_RUNTIMES,
    CONTAINER_NAME_RE,
    _Endpoint,
    ContainerRuntime,
    _APIResult,
    _clean_text,
    _container_id,
    _decode_json,
    _endpoint_identity,
    _read_container_list,
    _request,
    _run_podman,
    MAX_RESPONSE_BYTES,
)

ContainerNetworkAction = Literal["connect", "disconnect"]
ATTACHABLE_STATES = {"created", "running", "stopped", "exited"}


@dataclass(frozen=True, slots=True)
class _ContainerNetworkState:
    endpoint: _Endpoint
    api_prefix: str | None
    endpoint_identity: str
    container_id: str
    container_name: str
    image: str
    state: str
    networks: dict[str, str]


@dataclass(frozen=True, slots=True)
class _ContainerNetworkTarget:
    action: ContainerNetworkAction
    runtime: ContainerRuntime
    scope: Literal["system", "user"]
    endpoint: _Endpoint
    api_prefix: str | None
    container_id: str
    container_name: str
    network: str
    network_id: str
    state_digest: str


def _read_inspect(endpoint, api_prefix: str | None, container_id: str) -> tuple[dict[str, object] | None, str | None]:
    if endpoint.podman_binary:
        output, error, truncated = _run_podman(
            endpoint,
            ["container", "inspect", container_id],
        )
        if error or truncated:
            return None, "The local Podman container details could not be read completely."
        try:
            payload = json.loads(output or "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, "Local Podman returned malformed container details."
        if isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], dict):
            return payload[0], None
        if isinstance(payload, dict):
            return payload, None
        return None, "Local Podman returned an unexpected container-details shape."

    if api_prefix is None:
        return None, "The local container API version is unavailable."
    result: _APIResult = _request(
        endpoint,
        "GET",
        f"{api_prefix}/containers/{quote(container_id, safe='')}/json",
    )
    payload, error = _decode_json(result)
    if error or not isinstance(payload, dict):
        return None, error or "The local engine returned an unexpected container-details shape."
    return payload, None


def _network_map(raw: object) -> dict[str, str] | None:
    if not isinstance(raw, dict):
        return None
    networks: dict[str, str] = {}
    for name, details in raw.items():
        safe_name = _resource_name(name)
        if safe_name is None or not isinstance(details, dict):
            return None
        network_id = _clean_text(details.get("NetworkID", details.get("NetworkId", details.get("ID"))), 128)
        networks[safe_name] = network_id
    return networks


def _read_podman_network_attachments(
    endpoint: _Endpoint,
    container_id: str,
    container_state: str,
) -> tuple[dict[str, str] | None, str | None]:
    # Podman's network inventory reports running members. It does not provide
    # enough information to safely infer saved attachments for stopped ones.
    if container_state != "running":
        return None, "Podman network attachment inventory and control are limited to running standalone containers."
    resources, error, truncated = _read_resources(endpoint, None, "network")
    if error or truncated:
        return None, error or "The local Podman network inventory is incomplete."
    if len(resources) > 200:
        return None, "The local Podman network inventory exceeds the bounded attachment-inspection limit."
    if not resources:
        return {}, None
    names = [str(item["name"]) for item in resources]
    output, error, output_truncated = _run_podman(
        endpoint,
        ["network", "inspect", *names],
        max_output_bytes=MAX_RESPONSE_BYTES,
    )
    if error or output_truncated:
        return None, "The local Podman network attachment details could not be read completely."
    try:
        payload = json.loads(output or "")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "Local Podman returned malformed network details."
    if not isinstance(payload, list) or len(payload) != len(resources):
        return None, "Local Podman returned an incomplete network-details inventory."
    resource_ids = {str(item["name"]): str(item.get("resource_id") or "") for item in resources}
    attachments: dict[str, str] = {}
    seen: set[str] = set()
    for raw in payload:
        if not isinstance(raw, dict):
            return None, "Local Podman returned a malformed network detail."
        name = _resource_name(raw.get("name", raw.get("Name")))
        network_id = _clean_text(raw.get("id", raw.get("ID")), 128)
        if name is None or name in seen or not network_id or resource_ids.get(name) != network_id:
            return None, "A Podman network identity changed during attachment inspection."
        seen.add(name)
        if "containers" in raw:
            members = raw["containers"]
        elif "Containers" in raw:
            members = raw["Containers"]
        else:
            return None, "Podman did not report network-member state."
        if members is None:
            members = {}
        if not isinstance(members, dict):
            return None, "Podman returned an unexpected network-member inventory."
        for raw_id in members:
            member_id = _container_id(raw_id)
            if member_id is None:
                return None, "Podman returned a network member without a valid container ID."
            if member_id == container_id:
                attachments[name] = network_id
    if seen != set(names):
        return None, "The Podman network-details inventory did not match the selected resource inventory."
    return attachments, None


def _container_network_state(runtime: str, scope: str, container: str) -> tuple[_ContainerNetworkState | None, str | None]:
    if runtime not in ACTION_RUNTIMES:
        return None, "runtime must be docker or podman."
    if scope not in {"system", "user"}:
        return None, "scope must be system or user."
    if not isinstance(container, str) or not container or len(container) > 128 or any(ord(ch) < 32 or ord(ch) == 127 for ch in container):
        return None, "container must be one exact local container name or full ID."
    if not CONTAINER_NAME_RE.fullmatch(container) and _container_id(container) is None:
        return None, "container must be one exact local container name or full ID."

    endpoint, api_prefix, error = _select_endpoint(runtime, scope)
    if error or endpoint is None:
        return None, error or "The selected local runtime endpoint could not be verified."
    items, error, truncated = _read_container_list(endpoint, api_prefix)
    if error or truncated:
        return None, error or "The bounded local container inventory is incomplete."
    supplied_id = _container_id(container)
    matches = [
        item for item in items
        if item.get("container_id") == supplied_id or item.get("name") == container
    ]
    if len(matches) != 1:
        return None, "The exact local container name or ID was not found uniquely."
    selected = matches[0]
    container_id = str(selected["container_id"])
    details, error = _read_inspect(endpoint, api_prefix, container_id)
    if error or details is None:
        return None, error or "The local container details could not be verified."

    inspect_id = _container_id(details.get("Id", details.get("ID", details.get("IdShort"))))
    raw_name = _clean_text(details.get("Name", details.get("name")), 130).lstrip("/")
    if inspect_id != container_id or raw_name != selected.get("name"):
        return None, "The container identity changed between inventory and inspection."
    if endpoint.podman_binary and _clean_text(details.get("Pod"), 128):
        return None, "Podman network attachment control for containers sharing a pod network namespace is not supported."
    raw_state = details.get("State")
    if isinstance(raw_state, dict):
        state_value = raw_state.get("Status", raw_state.get("status"))
    else:
        state_value = raw_state
    state = _clean_text(state_value, 32).casefold()
    if state not in ATTACHABLE_STATES:
        return None, "The container is not in a supported created, running, stopped, or exited state."
    config = details.get("Config")
    image_value = config.get("Image") if isinstance(config, dict) else details.get("ImageName", details.get("Image"))
    image = _clean_text(image_value, 256)
    if endpoint.podman_binary:
        networks, error = _read_podman_network_attachments(endpoint, container_id, state)
        if error or networks is None:
            return None, error or "The complete local Podman network-attachment state could not be read."
    else:
        network_settings = details.get("NetworkSettings")
        if not isinstance(network_settings, dict) or "Networks" not in network_settings:
            return None, "The complete local network-attachment state could not be read."
        networks_raw = network_settings["Networks"]
        networks = {} if networks_raw is None else _network_map(networks_raw)
        if networks is None:
            return None, "The complete local network-attachment state could not be read."
    endpoint_identity = _endpoint_identity(endpoint)
    if endpoint_identity is None:
        return None, "The selected local runtime endpoint identity could not be verified."
    return _ContainerNetworkState(
        endpoint=endpoint,
        api_prefix=api_prefix,
        endpoint_identity=endpoint_identity,
        container_id=container_id,
        container_name=raw_name,
        image=image,
        state=state,
        networks=networks,
    ), None


def _network_inventory(state: _ContainerNetworkState) -> tuple[dict[str, dict[str, str | None]], str | None]:
    records, error, truncated = _read_resources(state.endpoint, state.api_prefix, "network")
    if error or truncated:
        return {}, error or "The local network inventory is incomplete."
    networks = {
        str(item["name"]): {
            "id": str(item.get("resource_id") or ""),
            "driver": str(item.get("driver") or ""),
            "is_default": str(item.get("is_default") or "false"),
        }
        for item in records
    }
    if any(name not in networks for name in state.networks):
        return {}, "An attached network is missing from the complete local network inventory."
    for name, network_id in state.networks.items():
        listed_id = networks[name]["id"]
        if network_id and listed_id and network_id != listed_id:
            return {}, "An attached network identity differs between container and network inventories."
    return networks, None


def list_container_network_attachments(
    runtime: str,
    scope: Literal["system", "user"],
    container: str,
) -> ContainerNetworkAttachmentResponse:
    """List selected network names for one exact local Docker/Podman container."""
    if not sys.platform.startswith("linux"):
        return ContainerNetworkAttachmentResponse(success=False, message="Container network inspection is available only on Linux.")
    state, error = _container_network_state(runtime, scope, container)
    if error or state is None:
        return ContainerNetworkAttachmentResponse(success=False, message=error or "The container attachment state is unavailable.")
    _networks, error = _network_inventory(state)
    if error:
        return ContainerNetworkAttachmentResponse(success=False, runtime=runtime, scope=scope, container_id=state.container_id, container_name=state.container_name, container_state=state.state, message=error)
    return ContainerNetworkAttachmentResponse(
        success=True,
        runtime=runtime,  # type: ignore[arg-type]
        scope=scope,
        container_id=state.container_id,
        container_name=state.container_name,
        container_state=state.state,
        networks=sorted(state.networks, key=str.casefold),
        message="Only exact attached network names are returned; network addresses and endpoint settings are omitted.",
    )


def container_network_attachment_action_confirmation_details(
    action: str,
    runtime: str,
    scope: str,
    container: str,
    network: str,
) -> tuple[_ContainerNetworkTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Container network attachment control is available only on Linux."
    if action not in {"connect", "disconnect"}:
        return None, None, "action must be connect or disconnect."
    if runtime not in ACTION_RUNTIMES:
        return None, None, "runtime must be docker or podman."
    if scope not in {"system", "user"}:
        return None, None, "scope must be system or user."
    network_name = _resource_name(network)
    if network_name is None:
        return None, None, "network must be one exact local network name."

    state, error = _container_network_state(runtime, scope, container)
    if error or state is None:
        return None, None, error or "The exact local container state could not be verified."
    networks, error = _network_inventory(state)
    if error:
        return None, None, error
    selected_network = networks.get(network_name)
    if selected_network is None:
        return None, None, "The exact network was not found uniquely in the selected local runtime and scope."
    if selected_network["is_default"] == "true" or network_name.casefold() in DEFAULT_NETWORK_NAMES:
        return None, None, "Built-in or default networks cannot be connected or disconnected through this tool."
    network_id = selected_network["id"]
    if not network_id:
        return None, None, "The exact network has no verifiable runtime identity."
    attached_id = state.networks.get(network_name)
    if action == "connect" and attached_id is not None:
        return None, None, "The container is already attached to that exact network."
    if action == "disconnect":
        if attached_id is None:
            return None, None, "The container is not attached to that exact network."
        if attached_id != network_id:
            return None, None, "The attached network identity could not be verified against the selected network."
        if len(state.networks) <= 1:
            return None, None, "Disconnecting the container's last network is refused."

    network_snapshot = sorted(
        (name, str(info["id"]), str(info["driver"]), str(info["is_default"]))
        for name, info in networks.items()
    )
    details = {
        "action": action,
        "runtime": runtime,
        "scope": scope,
        "endpoint_identity": state.endpoint_identity,
        "api_prefix": state.api_prefix,
        "container_id": state.container_id,
        "container_name": state.container_name,
        "image": state.image,
        "state": state.state,
        "attached_networks": sorted(state.networks.items()),
        "network": network_name,
        "network_id": network_id,
        "network_snapshot": network_snapshot,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = _ContainerNetworkTarget(
        action=action,  # type: ignore[arg-type]
        runtime=runtime,  # type: ignore[arg-type]
        scope=scope,  # type: ignore[arg-type]
        endpoint=state.endpoint,
        api_prefix=state.api_prefix,
        container_id=state.container_id,
        container_name=state.container_name,
        network=network_name,
        network_id=network_id,
        state_digest=digest,
    )
    phrase = hashlib.sha256(("container-network:" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"network {phrase}", None


def perform_container_network_attachment_action(
    action: ContainerNetworkAction,
    runtime: ContainerRuntime,
    scope: Literal["system", "user"],
    container: str,
    network: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> ContainerNetworkAttachmentActionResponse:
    target, phrase, error = container_network_attachment_action_confirmation_details(action, runtime, scope, container, network)
    if error or target is None or phrase is None:
        return ContainerNetworkAttachmentActionResponse(success=False, action=action, runtime=runtime, scope=scope, network=network, user_confirmed=confirmed is True, message=error or "The container network action could not be verified.")
    if confirmed is not True:
        return ContainerNetworkAttachmentActionResponse(success=False, action=action, runtime=runtime, scope=scope, container_id=target.container_id, container_name=target.container_name, network=target.network, user_confirmed=False, message="Explicit client confirmation is required; no network action was run.")
    if confirmation_phrase != phrase:
        return ContainerNetworkAttachmentActionResponse(success=False, action=action, runtime=runtime, scope=scope, container_id=target.container_id, container_name=target.container_name, network=target.network, user_confirmed=True, message="Confirmation did not match the exact container, network, and current attachment state.")
    current, current_phrase, error = container_network_attachment_action_confirmation_details(action, runtime, scope, container, network)
    if error or current is None or current_phrase != phrase:
        return ContainerNetworkAttachmentActionResponse(success=False, action=action, runtime=runtime, scope=scope, container_id=target.container_id, container_name=target.container_name, network=target.network, user_confirmed=True, message=error or "The container or network state changed after confirmation; no action was run.")

    if target.endpoint.podman_binary:
        command = ["network", action, target.network, target.container_id]
        _output, error, truncated = _run_podman(target.endpoint, command)
        if error or truncated:
            return ContainerNetworkAttachmentActionResponse(success=False, action=action, runtime=runtime, scope=scope, container_id=target.container_id, container_name=target.container_name, network=target.network, user_confirmed=True, message="The Podman network action failed or may have completed before timing out; inspect the attachment inventory before retrying.")
    else:
        if target.api_prefix is None:
            return ContainerNetworkAttachmentActionResponse(success=False, action=action, runtime=runtime, scope=scope, container_id=target.container_id, container_name=target.container_name, network=target.network, user_confirmed=True, message="The local Docker-compatible API version is unavailable.")
        body: dict[str, object] = {"Container": target.container_id}
        if action == "disconnect":
            body["Force"] = False
        result = _request(
            target.endpoint,
            "POST",
            f"{target.api_prefix}/networks/{quote(target.network_id, safe='')}/{action}",
            json.dumps(body).encode("utf-8"),
        )
        if result.error or result.status != 200:
            return ContainerNetworkAttachmentActionResponse(success=False, action=action, runtime=runtime, scope=scope, container_id=target.container_id, container_name=target.container_name, network=target.network, user_confirmed=True, message="The local engine rejected or could not confirm the network action; inspect the attachment inventory before retrying.")

    state, error = _container_network_state(runtime, scope, target.container_id)
    if error or state is None:
        return ContainerNetworkAttachmentActionResponse(success=False, action=action, runtime=runtime, scope=scope, container_id=target.container_id, container_name=target.container_name, network=target.network, user_confirmed=True, message="The network command returned, but the resulting container identity or attachment state could not be checked.")
    resulting_networks, inventory_error = _network_inventory(state)
    if inventory_error:
        return ContainerNetworkAttachmentActionResponse(success=False, action=action, runtime=runtime, scope=scope, container_id=target.container_id, container_name=target.container_name, network=target.network, user_confirmed=True, message="The command returned, but the resulting network identity could not be checked.")
    attached_id = state.networks.get(target.network)
    attached = attached_id is not None
    expected = action == "connect"
    resulting_network_id = resulting_networks.get(target.network, {}).get("id")
    if (
        state.container_id != target.container_id
        or state.container_name != target.container_name
        or resulting_network_id != target.network_id
        or attached is not expected
        or (expected and attached_id != target.network_id)
    ):
        return ContainerNetworkAttachmentActionResponse(success=False, action=action, runtime=runtime, scope=scope, container_id=target.container_id, container_name=target.container_name, network=target.network, user_confirmed=True, message="The command returned, but the requested exact network attachment was not verified.")
    return ContainerNetworkAttachmentActionResponse(
        success=True,
        action=action,
        runtime=runtime,
        scope=scope,
        container_id=target.container_id,
        container_name=target.container_name,
        network=target.network,
        user_confirmed=True,
        message=f"The container was { 'connected to' if action == 'connect' else 'disconnected from' } the exact network and the resulting attachment state was verified.",
    )
