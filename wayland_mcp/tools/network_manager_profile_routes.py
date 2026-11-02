"""Read and change simple saved NetworkManager IPv4/IPv6 routes."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sys
import threading
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import (
    NetworkManagerProfileRoute,
    NetworkManagerProfileRouteActionResponse,
    NetworkManagerProfileRoutesResponse,
)
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.network_manager_dns import _split_terse_field
from wayland_mcp.tools.network_manager_ip_control import (
    _environment,
    _normalized_uuid,
)

IPFamily = Literal["ipv4", "ipv6"]
RouteAction = Literal["add", "remove"]
MAX_OUTPUT_BYTES = 128 * 1024
MAX_ROUTES = 64
QUERY_TIMEOUT_SECONDS = 6
ACTION_TIMEOUT_SECONDS = 15
_ACTION_LOCK = threading.Lock()
_ATTRIBUTE_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}(?:=[^\s,]{1,512})?$")


@dataclass(frozen=True, slots=True)
class _Route:
    destination: str
    gateway: str | None = None
    metric: int | None = None
    attributes: tuple[str, ...] = ()

    def payload(self) -> dict[str, object]:
        return {
            "destination": self.destination,
            "gateway": self.gateway,
            "metric": self.metric,
            "attributes": list(self.attributes),
        }

    def model(self) -> NetworkManagerProfileRoute:
        return NetworkManagerProfileRoute(**self.payload())


@dataclass(frozen=True, slots=True)
class _Snapshot:
    profile_uuid: str
    profile_name: str
    connection_type: str
    family: IPFamily
    routes: tuple[_Route, ...]

    def payload(self) -> dict[str, object]:
        return {
            "profile_uuid": self.profile_uuid,
            "profile_name": self.profile_name,
            "connection_type": self.connection_type,
            "family": self.family,
            "routes": [route.payload() for route in self.routes],
        }


@dataclass(frozen=True, slots=True)
class _Target:
    before: _Snapshot
    action: RouteAction
    route: _Route
    confirmation_phrase: str


def _family_version(family: object) -> int | None:
    return 4 if family == "ipv4" else 6 if family == "ipv6" else None


def _parse_route(raw: str, family: IPFamily) -> _Route | None:
    parts = raw.split()
    if not parts or len(parts) > 16:
        return None
    try:
        destination = ipaddress.ip_network(parts[0], strict=False)
    except ValueError:
        return None
    if destination.version != _family_version(family):
        return None
    gateway: str | None = None
    metric: int | None = None
    attributes: list[str] = []
    index = 1
    if index < len(parts) and "=" not in parts[index] and not re.fullmatch(r"-?[0-9]+", parts[index]):
        try:
            parsed_gateway = ipaddress.ip_address(parts[index])
        except ValueError:
            return None
        if parsed_gateway.version != destination.version:
            return None
        gateway = str(parsed_gateway)
        index += 1
    if index < len(parts) and re.fullmatch(r"-?[0-9]+", parts[index]):
        try:
            metric = int(parts[index])
        except ValueError:
            return None
        if metric < -1 or metric > 4_294_967_295:
            return None
        index += 1
    for attribute in parts[index:]:
        if not _ATTRIBUTE_TOKEN_RE.fullmatch(attribute):
            return None
        attributes.append(attribute)
    return _Route(str(destination), gateway, metric, tuple(attributes))


def _parse_routes(raw: str, family: IPFamily) -> tuple[_Route, ...] | None:
    if raw.strip() in {"", "--", "-"}:
        return ()
    entries = raw.split(",")
    if len(entries) > MAX_ROUTES:
        return None
    routes: list[_Route] = []
    for entry in entries:
        route = _parse_route(entry.strip(), family)
        if route is None:
            return None
        routes.append(route)
    return tuple(routes)


def _read_snapshot(profile_uuid: object, family: object) -> tuple[_Snapshot | None, str | None]:
    normalized_uuid, error = _normalized_uuid(profile_uuid)
    if error or normalized_uuid is None:
        return None, error
    if _family_version(family) is None:
        return None, "family must be ipv4 or ipv6."
    if not sys.platform.startswith("linux"):
        return None, "Saved NetworkManager route inspection is available only on Linux."
    selected_family: IPFamily = family  # type: ignore[assignment]
    env = _environment()
    binary = find_session_binary("nmcli", env)
    if not binary:
        return None, "Saved NetworkManager route inspection requires nmcli."
    fields = ["connection.uuid", "connection.id", "connection.type", f"{selected_family}.routes"]
    output, command_error, truncated = run_bounded_command(
        [
            binary,
            "--wait", str(QUERY_TIMEOUT_SECONDS),
            "--terse", "--escape", "yes", "--mode", "multiline", "--fields", ",".join(fields),
            "connection", "show", "uuid", normalized_uuid,
        ],
        env,
        command_label="Read saved NetworkManager profile routes",
        timeout_seconds=QUERY_TIMEOUT_SECONDS + 1,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if command_error or output is None:
        return None, "The exact NetworkManager profile routes could not be read."
    if truncated:
        return None, "The NetworkManager route profile response exceeded its output limit."
    values: dict[str, str] = {}
    malformed = False
    lines = output.splitlines()
    if len(lines) > len(fields):
        return None, "NetworkManager returned more profile fields than were requested."
    for line in lines:
        parsed = _split_terse_field(line)
        if parsed is None:
            malformed = True
            continue
        key, value = parsed
        if key not in fields or key in values:
            malformed = True
            continue
        values[key] = value
    if malformed or set(values) != set(fields):
        return None, "NetworkManager did not return exactly one complete saved profile field set."
    returned_uuid = values["connection.uuid"]
    name = values["connection.id"]
    connection_type = values["connection.type"]
    raw_routes = values[f"{selected_family}.routes"]
    returned_uuid, uuid_error = _normalized_uuid(returned_uuid)
    if uuid_error or returned_uuid is None:
        return None, "NetworkManager returned a malformed profile UUID."
    if returned_uuid != normalized_uuid or not name or len(name) > 256 or not connection_type or len(connection_type) > 64:
        return None, "NetworkManager returned a mismatched or malformed connection-profile identity."
    if any(not character.isprintable() for character in name + connection_type):
        return None, "NetworkManager returned a malformed connection-profile identity."
    routes = _parse_routes(raw_routes, selected_family)
    if routes is None:
        return None, "Saved routes contain a value outside the supported NetworkManager route syntax."
    return _Snapshot(returned_uuid, name, connection_type, selected_family, routes), None


def get_network_manager_profile_routes(profile_uuid: str, family: IPFamily) -> NetworkManagerProfileRoutesResponse:
    safe_family = family if isinstance(family, str) and family in {"ipv4", "ipv6"} else None
    snapshot, error = _read_snapshot(profile_uuid, family)
    if snapshot is None:
        return NetworkManagerProfileRoutesResponse(
            success=False,
            family=safe_family,
            message=error or "Saved NetworkManager profile routes could not be read.",
        )
    return NetworkManagerProfileRoutesResponse(
        success=True,
        profile_uuid=snapshot.profile_uuid,
        profile_name=snapshot.profile_name,
        connection_type=snapshot.connection_type,
        family=snapshot.family,
        routes=[route.model() for route in snapshot.routes],
        message="These are saved profile routes. The tool does not activate or reapply the profile.",
    )


def _normalize_request(
    profile_uuid: object,
    family: object,
    action: object,
    destination: object,
    gateway: object,
    metric: object,
) -> tuple[str | None, IPFamily | None, RouteAction | None, _Route | None, str | None]:
    normalized_uuid, error = _normalized_uuid(profile_uuid)
    if error or normalized_uuid is None:
        return None, None, None, None, error
    if _family_version(family) is None:
        return None, None, None, None, "family must be ipv4 or ipv6."
    if not isinstance(action, str) or action not in {"add", "remove"}:
        return None, None, None, None, "action must be add or remove."
    selected_family: IPFamily = family  # type: ignore[assignment]
    version = _family_version(selected_family)
    if not isinstance(destination, str) or len(destination) > 80 or "/" not in destination or "%" in destination:
        return None, None, None, None, "destination must be one IPv4/IPv6 network with an explicit prefix length."
    try:
        network = ipaddress.ip_network(destination, strict=False)
    except ValueError:
        return None, None, None, None, "destination must be one IPv4/IPv6 network with an explicit prefix length."
    if network.version != version:
        return None, None, None, None, f"destination must be an IPv{version} network."
    normalized_gateway: str | None = None
    if gateway is not None:
        if not isinstance(gateway, str) or len(gateway) > 64 or "%" in gateway:
            return None, None, None, None, "gateway must be one literal same-family IP address or omitted."
        try:
            parsed_gateway = ipaddress.ip_address(gateway)
        except ValueError:
            return None, None, None, None, "gateway must be one literal same-family IP address or omitted."
        if parsed_gateway.version != version:
            return None, None, None, None, f"gateway must be an IPv{version} address."
        normalized_gateway = str(parsed_gateway)
    if metric is not None and (not isinstance(metric, int) or isinstance(metric, bool) or not 0 <= metric <= 4_294_967_295):
        return None, None, None, None, "metric must be an integer from 0 through 4294967295 or omitted."
    if metric is not None and normalized_gateway is None:
        return None, None, None, None, "A metric may be supplied only when a gateway is supplied."
    selected_action: RouteAction = action  # type: ignore[assignment]
    requested = _Route(str(network), normalized_gateway, metric)
    return normalized_uuid, selected_family, selected_action, requested, None


def _route_key(route: _Route) -> tuple[object, ...]:
    return route.destination, route.gateway, route.metric, route.attributes


def _route_value(route: _Route) -> str | None:
    values = [route.destination]
    if route.gateway is not None:
        values.append(route.gateway)
    elif route.metric is not None:
        unspecified_gateway = "::" if ":" in route.destination else "0.0.0.0"
        values.append(unspecified_gateway)
    if route.metric is not None:
        values.append(str(route.metric))
    values.extend(route.attributes)
    return " ".join(values)


def _target_for(
    profile_uuid: object,
    family: object,
    action: object,
    destination: object,
    gateway: object,
    metric: object,
) -> tuple[_Target | None, str | None]:
    normalized = _normalize_request(profile_uuid, family, action, destination, gateway, metric)
    normalized_uuid, selected_family, selected_action, requested, error = normalized
    if error or normalized_uuid is None or selected_family is None or selected_action is None or requested is None:
        return None, error or "The requested saved route could not be validated."
    snapshot, error = _read_snapshot(normalized_uuid, selected_family)
    if error or snapshot is None:
        return None, error or "The exact saved profile route state could not be read."
    matches = [route for route in snapshot.routes if route.destination == requested.destination]
    if selected_action == "add":
        if matches:
            return None, "A route for this destination already exists; replacement and multipath changes are not supported."
        selected_route = requested
    else:
        if len(matches) != 1:
            return None, "Removal requires exactly one saved route for the destination; ambiguous destinations are refused."
        selected_route = matches[0]
        if selected_route.attributes:
            return None, "Routes with advanced attributes cannot be removed by this tool."
        if requested.gateway is not None and requested.gateway != selected_route.gateway:
            return None, "The saved route gateway does not match the requested gateway."
        if requested.metric is not None and requested.metric != selected_route.metric:
            return None, "The saved route metric does not match the requested metric."
    material = {
        "before": snapshot.payload(),
        "action": selected_action,
        "requested": requested.payload(),
        "selected": selected_route.payload(),
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()[:16]
    return _Target(snapshot, selected_action, selected_route, f"{selected_action.upper()} ROUTE {selected_family.upper()} {normalized_uuid} {digest}"), None


def network_manager_profile_route_confirmation_details(
    profile_uuid: str,
    family: IPFamily,
    action: RouteAction,
    destination: str,
    gateway: str | None = None,
    metric: int | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    target, error = _target_for(profile_uuid, family, action, destination, gateway, metric)
    if error or target is None:
        return None, error
    return {
        "profile_uuid": target.before.profile_uuid,
        "profile_name": target.before.profile_name,
        "connection_type": target.before.connection_type,
        "family": target.before.family,
        "action": target.action,
        "route": target.route.payload(),
        "all_routes": [route.payload() for route in target.before.routes],
        "confirmation_phrase": target.confirmation_phrase,
    }, None


def _same_routes(left: tuple[_Route, ...], right: tuple[_Route, ...]) -> bool:
    return Counter(_route_key(route) for route in left) == Counter(_route_key(route) for route in right)


def _gateway_matches(route: _Route, requested_gateway: str | None) -> bool:
    if requested_gateway is not None:
        return route.gateway == requested_gateway
    unspecified_gateway = "::" if ":" in route.destination else "0.0.0.0"
    return route.gateway in {None, unspecified_gateway}


def perform_network_manager_profile_route_action(
    profile_uuid: str,
    family: IPFamily,
    action: RouteAction,
    destination: str,
    gateway: str | None = None,
    metric: int | None = None,
    *,
    confirmed: bool,
    confirmed_profile_uuid: str | None = None,
    confirmed_phrase: str | None = None,
) -> NetworkManagerProfileRouteActionResponse:
    normalized = _normalize_request(profile_uuid, family, action, destination, gateway, metric)
    normalized_uuid, selected_family, selected_action, requested, error = normalized
    if error or normalized_uuid is None or selected_family is None or selected_action is None or requested is None:
        return NetworkManagerProfileRouteActionResponse(
            success=False,
            family=family if isinstance(family, str) and family in {"ipv4", "ipv6"} else None,
            action=action if isinstance(action, str) and action in {"add", "remove"} else None,
            user_confirmed=confirmed is True,
            message=error or "The requested saved route could not be validated.",
        )
    target, error = _target_for(normalized_uuid, selected_family, selected_action, destination, gateway, metric)
    if error or target is None:
        return NetworkManagerProfileRouteActionResponse(
            success=False,
            profile_uuid=normalized_uuid,
            family=selected_family,
            action=selected_action,
            route=requested.model(),
            user_confirmed=confirmed is True,
            message=error or "The saved route state could not be verified.",
        )
    before = target.before
    response_values = {
        "profile_uuid": before.profile_uuid,
        "profile_name": before.profile_name,
        "connection_type": before.connection_type,
        "family": selected_family,
        "action": selected_action,
        "route": target.route.model(),
        "previous_routes": [route.model() for route in before.routes],
        "user_confirmed": confirmed is True,
    }
    if not confirmed:
        return NetworkManagerProfileRouteActionResponse(
            success=False,
            **response_values,
            message="Explicit client confirmation is required; no saved profile change was made.",
        )
    repeated_uuid, uuid_error = _normalized_uuid(confirmed_profile_uuid)
    if uuid_error or repeated_uuid != normalized_uuid or confirmed_phrase != target.confirmation_phrase:
        return NetworkManagerProfileRouteActionResponse(
            success=False,
            **response_values,
            message="Confirmation did not match the exact profile UUID and saved route state.",
        )
    with _ACTION_LOCK:
        current, current_error = _target_for(normalized_uuid, selected_family, selected_action, destination, gateway, metric)
        if current_error or current is None or current.confirmation_phrase != target.confirmation_phrase:
            return NetworkManagerProfileRouteActionResponse(
                success=False,
                **response_values,
                message=current_error or "The saved profile routes changed after confirmation; no update was run.",
            )
        env = _environment()
        binary = find_session_binary("nmcli", env)
        if not binary:
            return NetworkManagerProfileRouteActionResponse(
                success=False,
                **response_values,
                message="NetworkManager's nmcli command became unavailable; no update was run.",
            )
        route_value = _route_value(target.route)
        if route_value is None:
            return NetworkManagerProfileRouteActionResponse(
                success=False,
                **response_values,
                message="The selected route cannot be represented safely by nmcli modification syntax.",
            )
        operator = "+" if selected_action == "add" else "-"
        _output, command_error, truncated = run_bounded_command(
            [
                binary, "--wait", "12", "connection", "modify", "uuid", normalized_uuid,
                f"{operator}{selected_family}.routes", route_value,
            ],
            env,
            command_label="Update confirmed saved NetworkManager route",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_OUTPUT_BYTES,
        )
        if command_error or _output is None or truncated:
            message = (
                "The NetworkManager update timed out; saved profile state may be partial. Inspect the profile before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "NetworkManager rejected or could not complete the route update. Inspect the profile before retrying."
            )
            return NetworkManagerProfileRouteActionResponse(success=False, **response_values, message=message)
        updated, read_error = _read_snapshot(normalized_uuid, selected_family)
        if read_error or updated is None:
            return NetworkManagerProfileRouteActionResponse(
                success=False,
                **response_values,
                message="NetworkManager changed the profile, but the saved route result could not be verified; inspect it before retrying.",
            )
        old_routes = list(before.routes)
        expected = list(before.routes)
        if selected_action == "add":
            expected.append(target.route)
            # NetworkManager may materialize an omitted metric as its default; the route identity remains exact otherwise.
            actual_new = [
                route for route in updated.routes
                if route.destination == target.route.destination
                and _gateway_matches(route, target.route.gateway)
                and not route.attributes
                and (target.route.metric is None or route.metric == target.route.metric)
            ]
            old_without_new = list(updated.routes)
            if len(actual_new) == 1:
                old_without_new.remove(actual_new[0])
            verified = len(actual_new) == 1 and _same_routes(tuple(old_routes), tuple(old_without_new))
        else:
            expected.remove(target.route)
            verified = _same_routes(tuple(expected), updated.routes)
        identity_verified = (
            updated.profile_uuid == normalized_uuid
            and updated.profile_name == before.profile_name
            and updated.connection_type == before.connection_type
        )
        if not identity_verified or not verified:
            return NetworkManagerProfileRouteActionResponse(
                success=False,
                **response_values,
                message="The saved profile did not reach the requested route state; inspect it before retrying.",
            )
        return NetworkManagerProfileRouteActionResponse(
            success=True,
            **response_values,
            routes=[route.model() for route in updated.routes],
            message="Updated and verified the saved NetworkManager route. No activation or reapply command was run.",
        )
