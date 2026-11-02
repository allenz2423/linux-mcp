"""Bounded local Docker/Podman network and volume inventory and control."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Literal
from urllib.parse import quote

from wayland_mcp.models import (
    ContainerResourceActionResponse,
    ContainerResourceInfo,
    ContainerResourceListResponse,
)
from wayland_mcp.tools.containers import (
    ACTION_RUNTIMES,
    MAX_CONTAINERS_RETURNED,
    MAX_CONTAINERS_SCANNED,
    ContainerRuntime,
    _Endpoint,
    _api_prefix,
    _available_endpoints,
    _clean_text,
    _decode_json,
    _endpoint_identity,
    _request,
    _run_podman,
)

ContainerResourceKind = Literal["volume", "network"]
ContainerResourceAction = Literal["create", "remove"]
RESOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
BRIDGE_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
DEFAULT_NETWORK_NAMES = {"bridge", "host", "none", "podman"}
MAX_NETWORK_SUBNETS = 8
MAX_NETWORK_SUBNETS_PER_FAMILY = 4


@dataclass(frozen=True, slots=True)
class _ResourceTarget:
    action: ContainerResourceAction
    kind: ContainerResourceKind
    endpoint: _Endpoint
    api_prefix: str | None
    name: str
    resource_id: str | None
    driver: str | None
    network_subnets: tuple[str, ...]
    network_gateways: tuple[str | None, ...]
    network_internal: bool | None
    network_bridge_name: str | None
    network_mtu: int | None
    state_digest: str


def _resource_name(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    name = raw.strip()
    return name if RESOURCE_NAME_RE.fullmatch(name) else None


def _parse_resources(payload: object, kind: ContainerResourceKind) -> tuple[list[dict[str, str | None]], str | None, bool]:
    if kind == "volume" and isinstance(payload, dict):
        payload = payload.get("Volumes")
    elif isinstance(payload, dict) and isinstance(payload.get("networks"), list):
        payload = payload["networks"]
    if payload is None and kind == "volume":
        return [], None, False
    if not isinstance(payload, list):
        return [], "The local engine returned an unexpected resource-list shape.", False
    truncated = len(payload) > MAX_CONTAINERS_SCANNED
    resources: list[dict[str, str | None]] = []
    for raw in payload[:MAX_CONTAINERS_SCANNED]:
        if not isinstance(raw, dict):
            return [], "The local engine returned a malformed resource entry.", truncated
        name = _resource_name(raw.get("Name", raw.get("name")))
        if name is None:
            return [], "The local engine returned a resource without a valid exact name.", truncated
        resource_id_value = raw.get("Id", raw.get("ID", raw.get("id")))
        resource_id = _clean_text(resource_id_value, 128) or None
        driver = _clean_text(raw.get("Driver", raw.get("driver")), 64) or None
        created = _clean_text(raw.get("CreatedAt", raw.get("Created", raw.get("created"))), 64) or None
        is_default = raw.get("IsDefault", raw.get("Default", False)) is True
        if kind == "network" and name.casefold() in DEFAULT_NETWORK_NAMES:
            is_default = True
        resources.append({
            "name": name,
            "resource_id": resource_id,
            "driver": driver,
            "created_at": created,
            "is_default": "true" if is_default else "false",
        })
    return resources, None, truncated


def _read_resources(
    endpoint: _Endpoint,
    api_prefix: str | None,
    kind: ContainerResourceKind,
) -> tuple[list[dict[str, str | None]], str | None, bool]:
    if endpoint.podman_binary:
        command = ["volume", "ls", "--format=json"] if kind == "volume" else ["network", "ls", "--format=json"]
        output, error, command_truncated = _run_podman(endpoint, command)
        if error:
            return [], f"The local Podman {kind} inventory could not be read.", False
        if command_truncated:
            return [], f"The local Podman {kind} inventory exceeded the output limit.", True
        try:
            payload = json.loads(output or "[]")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return [], f"Local Podman returned malformed JSON for its {kind} inventory.", False
    else:
        if api_prefix is None:
            return [], "The local container API version was unavailable.", False
        path = f"{api_prefix}/volumes" if kind == "volume" else f"{api_prefix}/networks"
        payload, error = _decode_json(_request(endpoint, "GET", path))
        if error:
            return [], error, False
    return _parse_resources(payload, kind)


def list_container_resources(
    runtime: str = "auto",
    kind: ContainerResourceKind = "volume",
    query: str = "",
    limit: int = 100,
) -> ContainerResourceListResponse:
    """List bounded names and selected metadata for local runtime volumes or networks."""
    if not isinstance(kind, str) or kind not in {"volume", "network"}:
        return ContainerResourceListResponse(success=False, kind="volume", message="kind must be volume or network.")
    if not sys.platform.startswith("linux"):
        return ContainerResourceListResponse(success=False, kind=kind, message="Container resource inventory is available only on Linux.")
    if not isinstance(runtime, str) or runtime not in {"auto", "docker", "podman"}:
        return ContainerResourceListResponse(success=False, kind=kind, message="runtime must be auto, docker, or podman.")
    if not isinstance(query, str) or len(query) > 256 or any(ord(character) < 32 or ord(character) == 127 for character in query):
        return ContainerResourceListResponse(success=False, kind=kind, message="query must be text with at most 256 characters and no control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return ContainerResourceListResponse(success=False, kind=kind, message="limit must be an integer.")
    limit = max(1, min(limit, MAX_CONTAINERS_RETURNED))
    endpoints = [endpoint for endpoint in _available_endpoints(runtime) if endpoint.runtime in ACTION_RUNTIMES]
    if not endpoints:
        return ContainerResourceListResponse(success=False, kind=kind, limit=limit, message="No standard local Docker/Podman endpoint or local Podman CLI was found.")

    collected: list[ContainerResourceInfo] = []
    errors: list[str] = []
    successful_endpoints = 0
    truncated = False
    needle = query.strip().casefold()
    for endpoint in endpoints:
        prefix: str | None = None
        if not endpoint.podman_binary:
            prefix, error = _api_prefix(endpoint)
            if error or prefix is None:
                errors.append(error or "A local container API version could not be read.")
                continue
        records, error, endpoint_truncated = _read_resources(endpoint, prefix, kind)
        truncated |= endpoint_truncated
        if error:
            errors.append(error)
            continue
        successful_endpoints += 1
        for item in records:
            name = str(item["name"])
            if needle and needle not in name.casefold():
                continue
            collected.append(ContainerResourceInfo(
                runtime=endpoint.runtime,  # type: ignore[arg-type]
                scope=endpoint.scope,  # type: ignore[arg-type]
                kind=kind,
                name=name,
                resource_id=item.get("resource_id"),
                driver=item.get("driver"),
                created_at=item.get("created_at"),
                is_default=item.get("is_default") == "true",
            ))
    collected.sort(key=lambda item: (item.runtime, item.scope, item.name.casefold()))
    truncated |= len(collected) > limit
    messages = errors[:3]
    if errors and successful_endpoints:
        messages.append("Some local container resource endpoints could not be queried.")
    if truncated:
        messages.append("The resource inventory was capped by scan, response-size, or result limits.")
    return ContainerResourceListResponse(
        success=successful_endpoints > 0,
        kind=kind,
        total_resources=len(collected),
        returned_resources=min(len(collected), limit),
        resources=collected[:limit],
        limit=limit,
        truncated=truncated,
        partial=bool(errors),
        message=" ".join(messages) or None,
    )


def _select_endpoint(runtime: str, scope: str) -> tuple[_Endpoint | None, str | None, str | None]:
    endpoints = [
        endpoint for endpoint in _available_endpoints(runtime)
        if endpoint.runtime == runtime
        and endpoint.scope == scope
        and (endpoint.podman_binary is not None or endpoint.socket_path is not None and os.access(endpoint.socket_path, os.W_OK))
    ]
    if len(endpoints) != 1:
        return None, None, "Exactly one accessible local endpoint for the selected runtime and scope is required."
    endpoint = endpoints[0]
    if _endpoint_identity(endpoint) is None:
        return None, None, "The selected local runtime endpoint identity could not be verified."
    prefix: str | None = None
    if not endpoint.podman_binary:
        prefix, error = _api_prefix(endpoint)
        if error or prefix is None:
            return None, None, error or "The local runtime API version could not be verified."
    return endpoint, prefix, None


def _normalize_bridge_network_settings(
    kind: str,
    action: str,
    network_subnet: object,
    network_gateway: object,
    network_internal: object,
    network_bridge_name: object,
    network_mtu: object,
    network_subnets: object = None,
    network_gateways: object = None,
) -> tuple[tuple[tuple[str, ...], tuple[str | None, ...], bool | None, str | None, int | None] | None, str | None]:
    supplied = (
        network_subnet,
        network_gateway,
        network_subnets,
        network_gateways,
        network_internal,
        network_bridge_name,
        network_mtu,
    )
    if kind != "network" or action != "create":
        if any(value is not None for value in supplied):
            return None, "Bridge network settings are accepted only when creating a network."
        return ((), (), None, None, None), None

    if network_subnet is not None and network_subnets is not None:
        return None, "Use the legacy IPv4 network_subnet field or network_subnets, not both."
    if network_gateway is not None and network_gateways is not None:
        return None, "Use the legacy IPv4 network_gateway field or network_gateways, not both."

    parsed_subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    if network_subnet is not None:
        if not isinstance(network_subnet, str):
            return None, "network_subnet must be one IPv4 CIDR network string."
        try:
            parsed_legacy = ipaddress.ip_network(network_subnet, strict=True)
        except ValueError:
            return None, "network_subnet must be a canonical IPv4 CIDR network with no host bits set."
        if not isinstance(parsed_legacy, ipaddress.IPv4Network) or not 8 <= parsed_legacy.prefixlen <= 30:
            return None, "network_subnet must be IPv4 with a prefix length from /8 through /30."
        parsed_subnets.append(parsed_legacy)
        if network_gateway is not None and not isinstance(network_gateway, str):
            return None, "network_gateway must be a literal IPv4 address within network_subnet."
        gateway_values: list[object] = [network_gateway]
    else:
        if network_gateway is not None:
            return None, "network_gateway requires network_subnet."
        if network_subnets is None:
            if network_gateways is not None:
                return None, "network_gateways requires network_subnets."
            subnet_values: list[object] = []
        elif isinstance(network_subnets, (list, tuple)):
            if not 1 <= len(network_subnets) <= MAX_NETWORK_SUBNETS:
                return None, f"network_subnets must contain 1-{MAX_NETWORK_SUBNETS} CIDR networks."
            subnet_values = list(network_subnets)
        else:
            return None, "network_subnets must be a list of canonical IPv4/IPv6 CIDR networks."

        if network_gateways is None:
            gateway_values = [None] * len(subnet_values)
        elif isinstance(network_gateways, (list, tuple)):
            if len(network_gateways) != len(subnet_values):
                return None, "network_gateways must have one entry per network_subnets item; use null for an automatic gateway."
            gateway_values = list(network_gateways)
        else:
            return None, "network_gateways must be a list matching network_subnets, with null for automatic gateways."

        for index, raw_subnet in enumerate(subnet_values):
            if not isinstance(raw_subnet, str):
                return None, f"network_subnets[{index}] must be a canonical IPv4/IPv6 CIDR network."
            try:
                parsed = ipaddress.ip_network(raw_subnet, strict=True)
            except ValueError:
                return None, f"network_subnets[{index}] must be canonical and contain no host bits."
            if str(parsed) != raw_subnet:
                return None, f"network_subnets[{index}] must use canonical CIDR notation."
            if isinstance(parsed, ipaddress.IPv4Network) and not 8 <= parsed.prefixlen <= 30:
                return None, f"IPv4 network_subnets[{index}] must have a prefix length from /8 through /30."
            if isinstance(parsed, ipaddress.IPv6Network) and not 48 <= parsed.prefixlen <= 120:
                return None, f"IPv6 network_subnets[{index}] must have a prefix length from /48 through /120."
            same_family = [previous for previous in parsed_subnets if previous.version == parsed.version]
            if len(same_family) >= MAX_NETWORK_SUBNETS_PER_FAMILY:
                return None, f"A bridge network accepts at most {MAX_NETWORK_SUBNETS_PER_FAMILY} subnets per IP family."
            if any(previous.overlaps(parsed) for previous in same_family):
                return None, "Subnets in the same IP family must not overlap."
            parsed_subnets.append(parsed)

    if network_subnet is not None and network_gateways is not None:
        return None, "Use the legacy network_gateway field with network_subnet, or network_gateways with network_subnets."

    subnet_values: list[str] = [str(subnet) for subnet in parsed_subnets]
    gateway_values_normalized: list[str | None] = []
    for index, (subnet, raw_gateway) in enumerate(zip(parsed_subnets, gateway_values)):
        if raw_gateway is None:
            gateway_values_normalized.append(None)
            continue
        if not isinstance(raw_gateway, str):
            return None, f"network gateway {index} must be a literal IP address or null."
        try:
            gateway = ipaddress.ip_address(raw_gateway)
        except ValueError:
            return None, f"network gateway {index} must be a literal IP address in its subnet."
        if gateway.version != subnet.version or gateway not in subnet:
            return None, f"network gateway {index} must use the subnet's IP family and belong to that subnet."
        if gateway == subnet.network_address or (
            isinstance(subnet, ipaddress.IPv4Network) and gateway == subnet.broadcast_address
        ):
            return None, f"network gateway {index} must be a usable host address inside its subnet."
        if str(gateway) != raw_gateway:
            return None, f"network gateway {index} must use canonical IP address notation."
        gateway_values_normalized.append(str(gateway))

    subnets_tuple = tuple(subnet_values)
    gateways_tuple = tuple(gateway_values_normalized)

    if network_internal is not None and not isinstance(network_internal, bool):
        return None, "network_internal must be a boolean when supplied."
    internal_value = network_internal if isinstance(network_internal, bool) else None

    bridge_name: str | None = None
    if network_bridge_name is not None:
        if not isinstance(network_bridge_name, str) or not BRIDGE_INTERFACE_RE.fullmatch(network_bridge_name):
            return None, "network_bridge_name must be 1-15 letters, digits, dot, underscore, or hyphen."
        bridge_name = network_bridge_name

    mtu_value: int | None = None
    if network_mtu is not None:
        if isinstance(network_mtu, bool) or not isinstance(network_mtu, int) or not 576 <= network_mtu <= 9000:
            return None, "network_mtu must be an integer from 576 through 9000."
        mtu_value = network_mtu

    return (subnets_tuple, gateways_tuple, internal_value, bridge_name, mtu_value), None


def container_resource_action_confirmation_details(
    action: str,
    runtime: str,
    scope: str,
    kind: str,
    name: str,
    network_subnet: object = None,
    network_gateway: object = None,
    network_internal: object = None,
    network_bridge_name: object = None,
    network_mtu: object = None,
    network_subnets: object = None,
    network_gateways: object = None,
) -> tuple[_ResourceTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Container resource actions are available only on Linux."
    if not isinstance(action, str) or action not in {"create", "remove"}:
        return None, None, "action must be create or remove."
    if not isinstance(runtime, str) or runtime not in ACTION_RUNTIMES:
        return None, None, "runtime must be docker or podman."
    if not isinstance(scope, str) or scope not in {"system", "user"}:
        return None, None, "scope must be system or user."
    if not isinstance(kind, str) or kind not in {"volume", "network"}:
        return None, None, "kind must be volume or network."
    if not isinstance(name, str) or not RESOURCE_NAME_RE.fullmatch(name):
        return None, None, "name must be one exact runtime resource name using letters, digits, dot, underscore, or hyphen."

    network_settings, config_error = _normalize_bridge_network_settings(
        kind,
        action,
        network_subnet,
        network_gateway,
        network_internal,
        network_bridge_name,
        network_mtu,
        network_subnets,
        network_gateways,
    )
    if config_error or network_settings is None:
        return None, None, config_error or "Bridge network settings could not be verified."
    subnet_values, gateway_values, internal_value, bridge_name, mtu_value = network_settings

    endpoint, prefix, error = _select_endpoint(runtime, scope)
    if error or endpoint is None:
        return None, None, error or "The local runtime endpoint could not be verified."
    if kind == "network" and action == "create" and endpoint.podman_binary:
        saw_automatic_gateway = False
        for gateway in gateway_values:
            if gateway is None:
                saw_automatic_gateway = True
            elif saw_automatic_gateway:
                return None, None, "Podman requires explicit gateways to follow subnet order without gaps; use automatic gateways after the last explicit gateway."
    if kind == "network" and action == "create" and runtime == "docker":
        family_counts = {
            version: sum(ipaddress.ip_network(subnet).version == version for subnet in subnet_values)
            for version in (4, 6)
        }
        if any(count > 1 for count in family_counts.values()):
            return None, None, "Docker bridge networks support at most one requested subnet per IP family; use Podman for multiple same-family subnets."
    resources, error, truncated = _read_resources(endpoint, prefix, kind)  # type: ignore[arg-type]
    if error or truncated:
        return None, None, error or "The local resource inventory is incomplete; the action is refused."
    matches = [item for item in resources if item.get("name") == name]
    if action == "create":
        if kind == "network" and name.casefold() in DEFAULT_NETWORK_NAMES:
            return None, None, "Default or built-in network names cannot be created through this tool."
        if matches:
            return None, None, "A resource with that exact name already exists in the selected runtime and scope."
        resource_id = None
        driver = "local" if kind == "volume" else "bridge"
    else:
        if len(matches) != 1:
            return None, None, "The exact resource name was not found uniquely in the selected runtime and scope."
        selected = matches[0]
        if kind == "network" and selected.get("is_default") == "true":
            return None, None, "Default or built-in networks cannot be removed through this tool."
        resource_id = selected.get("resource_id")
        driver = selected.get("driver")

    endpoint_identity = _endpoint_identity(endpoint)
    if endpoint_identity is None:
        return None, None, "The selected local runtime endpoint identity could not be verified."
    snapshot = sorted(
        (str(item.get("name", "")), str(item.get("resource_id") or ""), str(item.get("driver") or ""), str(item.get("is_default") or ""))
        for item in resources
    )
    details = {
        "action": action,
        "runtime": runtime,
        "scope": scope,
        "kind": kind,
        "name": name,
        "resource_id": resource_id,
        "driver": driver,
        "network_subnets": subnet_values,
        "network_gateways": gateway_values,
        "network_internal": internal_value,
        "network_bridge_name": bridge_name,
        "network_mtu": mtu_value,
        "endpoint_identity": endpoint_identity,
        "api_prefix": prefix,
        "resource_snapshot": snapshot,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = _ResourceTarget(
        action=action,  # type: ignore[arg-type]
        kind=kind,  # type: ignore[arg-type]
        endpoint=endpoint,
        api_prefix=prefix,
        name=name,
        resource_id=resource_id,
        driver=driver,
        network_subnets=subnet_values,
        network_gateways=gateway_values,
        network_internal=internal_value,
        network_bridge_name=bridge_name,
        network_mtu=mtu_value,
        state_digest=digest,
    )
    phrase = hashlib.sha256(("container-resource:" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"resource {phrase}", None


def _inspect_network(
    target: _ResourceTarget,
) -> tuple[dict[str, object] | None, str | None]:
    if target.endpoint.podman_binary:
        output, error, truncated = _run_podman(
            target.endpoint,
            ["network", "inspect", target.name],
        )
        if error or truncated:
            return None, "The newly created Podman network configuration could not be read completely."
        try:
            payload = json.loads(output or "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, "Podman returned malformed network configuration."
        if isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], dict):
            return payload[0], None
        if isinstance(payload, dict):
            return payload, None
        return None, "Podman returned an unexpected network-inspect shape."

    if target.api_prefix is None:
        return None, "The local container API version is unavailable."
    identifier = target.resource_id or target.name
    result = _request(
        target.endpoint,
        "GET",
        f"{target.api_prefix}/networks/{quote(identifier, safe='')}",
    )
    payload, error = _decode_json(result)
    if error or not isinstance(payload, dict):
        return None, error or "The local engine returned an unexpected network-inspect shape."
    return payload, None


def _created_network_matches(target: _ResourceTarget) -> bool:
    payload, error = _inspect_network(target)
    if error or payload is None:
        return False
    if _clean_text(payload.get("Name", payload.get("name")), 128) != target.name:
        return False
    driver = _clean_text(payload.get("Driver", payload.get("driver")), 64)
    if driver.casefold() != "bridge":
        return False

    if target.endpoint.podman_binary:
        raw_internal = payload.get("internal", payload.get("Internal"))
        raw_interface = payload.get("network_interface", payload.get("NetworkInterface"))
        raw_subnets = payload.get("subnets", payload.get("Subnets"))
        raw_options = payload.get("options", payload.get("Options"))
    else:
        raw_internal = payload.get("Internal")
        raw_interface = None
        raw_subnets = None
        raw_options = payload.get("Options")
        ipam = payload.get("IPAM")
        if isinstance(ipam, dict):
            raw_subnets = ipam.get("Config")

    if target.network_internal is not None and raw_internal is not target.network_internal:
        return False
    if target.network_subnets:
        if not isinstance(raw_subnets, list):
            return False
        inspected_subnets: dict[str, list[dict[str, object]]] = {}
        for item in raw_subnets:
            if not isinstance(item, dict):
                continue
            subnet = _clean_text(item.get("Subnet", item.get("subnet")), 64)
            if subnet is not None:
                inspected_subnets.setdefault(subnet, []).append(item)
        for subnet, requested_gateway in zip(target.network_subnets, target.network_gateways):
            matches = inspected_subnets.get(subnet, [])
            if len(matches) != 1:
                return False
            if requested_gateway is not None:
                gateway = _clean_text(
                    matches[0].get("Gateway", matches[0].get("gateway")),
                    64,
                )
                if gateway != requested_gateway:
                    return False
        needs_ipv6 = any(ipaddress.ip_network(subnet).version == 6 for subnet in target.network_subnets)
        if needs_ipv6:
            ipv6_enabled = (
                payload.get("ipv6_enabled", payload.get("IPv6Enabled"))
                if target.endpoint.podman_binary
                else payload.get("EnableIPv6")
            )
            if ipv6_enabled is not True:
                return False

    options = raw_options if isinstance(raw_options, dict) else {}
    if target.network_bridge_name is not None:
        configured_name = options.get("com.docker.network.bridge.name")
        if not isinstance(configured_name, str) or configured_name != target.network_bridge_name:
            if not isinstance(raw_interface, str) or raw_interface != target.network_bridge_name:
                return False
    if target.network_mtu is not None:
        configured_mtu = options.get("mtu", options.get("com.docker.network.driver.mtu"))
        if configured_mtu is None:
            return False
        try:
            parsed_mtu = int(configured_mtu)
        except (TypeError, ValueError):
            return False
        if parsed_mtu != target.network_mtu:
            return False
    return True


def perform_container_resource_action(
    action: ContainerResourceAction,
    runtime: ContainerRuntime,
    scope: str,
    kind: ContainerResourceKind,
    name: str,
    network_subnet: str | None = None,
    network_gateway: str | None = None,
    network_internal: bool | None = None,
    network_bridge_name: str | None = None,
    network_mtu: int | None = None,
    network_subnets: list[str] | None = None,
    network_gateways: list[str | None] | None = None,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> ContainerResourceActionResponse:
    target, phrase, error = container_resource_action_confirmation_details(
        action,
        runtime,
        scope,
        kind,
        name,
        network_subnet,
        network_gateway,
        network_internal,
        network_bridge_name,
        network_mtu,
        network_subnets,
        network_gateways,
    )
    if error or target is None or phrase is None:
        return ContainerResourceActionResponse(success=False, action=action, runtime=runtime, scope=scope, kind=kind, name=name, user_confirmed=confirmed is True, message=error or "The resource action could not be verified.")
    if confirmed is not True:
        return ContainerResourceActionResponse(success=False, action=action, runtime=runtime, scope=scope, kind=kind, name=name, resource_id=target.resource_id, user_confirmed=False, message="Explicit client confirmation is required; no resource action was run.")
    if confirmation_phrase != phrase:
        return ContainerResourceActionResponse(success=False, action=action, runtime=runtime, scope=scope, kind=kind, name=name, resource_id=target.resource_id, user_confirmed=True, message="Confirmation did not match the selected runtime, resource identity, and current resource inventory.")
    current, current_phrase, error = container_resource_action_confirmation_details(
        action,
        runtime,
        scope,
        kind,
        name,
        network_subnet,
        network_gateway,
        network_internal,
        network_bridge_name,
        network_mtu,
        network_subnets,
        network_gateways,
    )
    if error or current is None or current_phrase != phrase:
        return ContainerResourceActionResponse(success=False, action=action, runtime=runtime, scope=scope, kind=kind, name=name, resource_id=target.resource_id, user_confirmed=True, message=error or "The runtime resource inventory changed after confirmation; no action was run.")

    if target.endpoint.podman_binary:
        if action == "create" and kind == "network":
            command = ["network", "create", "--driver", "bridge"]
            for subnet, gateway in zip(target.network_subnets, target.network_gateways):
                command.extend(["--subnet", subnet])
                if gateway is not None:
                    command.extend(["--gateway", gateway])
            if any(ipaddress.ip_network(subnet).version == 6 for subnet in target.network_subnets):
                command.append("--ipv6")
            if target.network_internal is True:
                command.append("--internal")
            if target.network_bridge_name is not None:
                command.extend(["--interface-name", target.network_bridge_name])
            if target.network_mtu is not None:
                command.extend(["--opt", f"mtu={target.network_mtu}"])
            command.append(target.name)
        else:
            command = [kind, "create", name] if action == "create" else [kind, "rm", name]
        _output, error, truncated = _run_podman(target.endpoint, command)
        if error or truncated:
            return ContainerResourceActionResponse(success=False, action=action, runtime=runtime, scope=scope, kind=kind, name=name, resource_id=target.resource_id, user_confirmed=True, message="The Podman resource action failed or may have completed before timing out; inspect the resource inventory before retrying.")
    else:
        if target.api_prefix is None:
            return ContainerResourceActionResponse(success=False, action=action, runtime=runtime, scope=scope, kind=kind, name=name, resource_id=target.resource_id, user_confirmed=True, message="The local Docker API version is unavailable.")
        if action == "create" and kind == "volume":
            result = _request(target.endpoint, "POST", f"{target.api_prefix}/volumes/create", json.dumps({"Name": name, "Driver": "local"}).encode("utf-8"))
            accepted = result.status == 201
        elif action == "create":
            body = {"Name": name, "Driver": "bridge"}
            if target.network_subnets:
                ipam_configs: list[dict[str, str]] = []
                for subnet, gateway in zip(target.network_subnets, target.network_gateways):
                    config = {"Subnet": subnet}
                    if gateway is not None:
                        config["Gateway"] = gateway
                    ipam_configs.append(config)
                body["IPAM"] = {"Driver": "default", "Config": ipam_configs}
                if any(ipaddress.ip_network(subnet).version == 6 for subnet in target.network_subnets):
                    body["EnableIPv6"] = True
            if target.network_internal is not None:
                body["Internal"] = target.network_internal
            options: dict[str, str] = {}
            if target.network_bridge_name is not None:
                options["com.docker.network.bridge.name"] = target.network_bridge_name
            if target.network_mtu is not None:
                options["com.docker.network.driver.mtu"] = str(target.network_mtu)
            if options:
                body["Options"] = options
            result = _request(target.endpoint, "POST", f"{target.api_prefix}/networks/create", json.dumps(body).encode("utf-8"))
            response, response_error = _decode_json(result, expected_status=201)
            if result.error:
                response_error = result.error
            if not isinstance(response, dict):
                response = {}
            accepted = result.status == 201 and response_error is None
        elif kind == "volume":
            result = _request(target.endpoint, "DELETE", f"{target.api_prefix}/volumes/{quote(name, safe='')}?force=false")
            accepted = result.status == 204
        else:
            network_key = target.resource_id or name
            result = _request(target.endpoint, "DELETE", f"{target.api_prefix}/networks/{quote(network_key, safe='')}")
            accepted = result.status == 204
        if result.error or not accepted:
            return ContainerResourceActionResponse(success=False, action=action, runtime=runtime, scope=scope, kind=kind, name=name, resource_id=target.resource_id, user_confirmed=True, message="The local engine rejected or could not confirm the resource action; inspect the current inventory before retrying. In-use resources are never force-removed.")

    resulting, result_error, result_truncated = _read_resources(target.endpoint, target.api_prefix, kind)
    if result_error or result_truncated:
        return ContainerResourceActionResponse(success=False, action=action, runtime=runtime, scope=scope, kind=kind, name=name, resource_id=target.resource_id, user_confirmed=True, message="The resource action returned, but its result could not be verified; inspect the local resource inventory before retrying.")
    matches = [item for item in resulting if item.get("name") == name]
    if action == "create":
        if len(matches) != 1:
            return ContainerResourceActionResponse(success=False, action=action, runtime=runtime, scope=scope, kind=kind, name=name, user_confirmed=True, message="The create command returned, but the exact resource could not be verified in the selected runtime.")
        resource_id = matches[0].get("resource_id")
        if kind == "network" and any((
            bool(target.network_subnets),
            target.network_internal is not None,
            target.network_bridge_name is not None,
            target.network_mtu is not None,
        )) and not _created_network_matches(target):
            return ContainerResourceActionResponse(
                success=False,
                action=action,
                runtime=runtime,
                scope=scope,
                kind=kind,
                name=name,
                resource_id=resource_id,
                user_confirmed=True,
                message="The bridge network was created or may have been created, but its requested configuration could not be verified; inspect the local network before retrying.",
            )
        if kind == "network" and any((
            bool(target.network_subnets),
            target.network_internal is not None,
            target.network_bridge_name is not None,
            target.network_mtu is not None,
        )):
            message = "Created and verified the bridge network with the requested settings."
        else:
            message = f"Created and verified the local {kind} with the runtime's default {target.driver} configuration."
    else:
        if matches:
            return ContainerResourceActionResponse(success=False, action=action, runtime=runtime, scope=scope, kind=kind, name=name, resource_id=target.resource_id, user_confirmed=True, message="The removal command returned, but the exact resource is still present.")
        resource_id = target.resource_id
        message = "Removed the exact unused resource without force. Volume data may have been deleted."
    ipv4_settings = [
        (subnet, gateway)
        for subnet, gateway in zip(target.network_subnets, target.network_gateways)
        if ipaddress.ip_network(subnet).version == 4
    ]
    legacy_subnet, legacy_gateway = ipv4_settings[0] if len(ipv4_settings) == 1 else (None, None)
    return ContainerResourceActionResponse(
        success=True,
        action=action,
        runtime=runtime,
        scope=scope,
        kind=kind,
        name=name,
        resource_id=resource_id,
        network_subnet=legacy_subnet,
        network_gateway=legacy_gateway,
        network_subnets=list(target.network_subnets),
        network_gateways=list(target.network_gateways),
        network_internal=target.network_internal,
        network_bridge_name=target.network_bridge_name,
        network_mtu=target.network_mtu,
        user_confirmed=True,
        message=message,
    )
