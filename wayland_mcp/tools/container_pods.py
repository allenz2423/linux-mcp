"""Bounded forced-local Podman pod inventory and confirmation-gated actions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import ContainerPodActionResponse, ContainerPodInfo, ContainerPodListResponse
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.containers import (
    MAX_CONTAINERS_RETURNED,
    MAX_CONTAINERS_SCANNED,
    _Endpoint,
    _clean_text,
    _endpoint_identity,
    _podman_env,
    _run_podman,
)

ContainerPodAction = Literal["create", "start", "stop", "remove"]
POD_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
POD_ID_RE = re.compile(r"^[0-9a-fA-F]{12,128}$")
POD_STATES = {"created", "running", "stopped", "exited", "paused", "degraded", "dead", "unknown"}


@dataclass(frozen=True, slots=True)
class _PodTarget:
    action: ContainerPodAction
    endpoint: _Endpoint
    scope: str
    name: str
    pod_id: str | None
    state: str | None
    container_ids: tuple[str, ...]
    container_names: tuple[str, ...]
    state_digest: str


def _podman_endpoint() -> tuple[_Endpoint | None, str | None]:
    env = _podman_env()
    binary = find_session_binary("podman", env)
    if not binary:
        return None, "The local Podman executable is unavailable."
    scope = "system" if os.getuid() == 0 else "user"
    endpoint = _Endpoint("podman", scope, podman_binary=binary)
    if _endpoint_identity(endpoint) is None:
        return None, "The local Podman executable identity could not be verified."
    return endpoint, None


def container_pod_readiness() -> tuple[bool, bool]:
    """Return whether the forced-local Podman CLI is present and usable."""
    found = find_session_binary("podman", _podman_env()) is not None
    endpoint, _error = _podman_endpoint()
    return found, endpoint is not None


def _split_members(value: object, *, ids: bool) -> tuple[str, ...] | None:
    if value is None or value == "":
        return ()
    if isinstance(value, list):
        values = value
    elif isinstance(value, str):
        values = value.split(",")
    else:
        return None
    output: list[str] = []
    for item in values:
        if not isinstance(item, str):
            return None
        cleaned = _clean_text(item, 128)
        if not cleaned:
            continue
        if ids and not POD_ID_RE.fullmatch(cleaned):
            return None
        output.append(cleaned.lower() if ids else cleaned)
    return tuple(output)


def _parse_pods(payload: object) -> tuple[list[dict[str, object]], str | None, bool]:
    if not isinstance(payload, list):
        return [], "The local Podman pod list had an unexpected shape.", False
    truncated = len(payload) > MAX_CONTAINERS_SCANNED
    pods: list[dict[str, object]] = []
    for raw in payload[:MAX_CONTAINERS_SCANNED]:
        if not isinstance(raw, dict):
            return [], "The local Podman pod list contained a malformed entry.", truncated
        pod_id = raw.get("Id", raw.get("ID", raw.get("id")))
        name = raw.get("Name", raw.get("Names", raw.get("name")))
        if isinstance(name, list):
            name = name[0] if name else None
        if not isinstance(pod_id, str) or not POD_ID_RE.fullmatch(pod_id):
            return [], "The local Podman pod list contained an invalid pod ID.", truncated
        if not isinstance(name, str) or not POD_NAME_RE.fullmatch(name):
            return [], "The local Podman pod list contained an invalid pod name.", truncated
        status = _clean_text(raw.get("Status", raw.get("status")), 32).casefold()
        state = status if status in POD_STATES else "unknown"
        ids = _split_members(raw.get("ContainerIds", raw.get("ContainerIDs", raw.get("container_ids"))), ids=True)
        names = _split_members(raw.get("ContainerNames", raw.get("container_names")), ids=False)
        statuses = _split_members(raw.get("ContainerStatuses", raw.get("container_statuses")), ids=False)
        if ids is None or names is None or statuses is None:
            return [], "The local Podman pod list contained malformed member metadata.", truncated
        created = _clean_text(raw.get("Created", raw.get("CreatedAt", raw.get("created"))), 64) or None
        raw_count = raw.get("NumberOfContainers", raw.get("number_of_containers"))
        count = raw_count if isinstance(raw_count, int) and not isinstance(raw_count, bool) and 0 <= raw_count <= 1_000_000 else len(ids)
        infra_id = raw.get("InfraID", raw.get("InfraId", raw.get("infra_id")))
        if infra_id is not None and (not isinstance(infra_id, str) or infra_id and not POD_ID_RE.fullmatch(infra_id)):
            infra_id = None
        pods.append({
            "pod_id": pod_id.lower(),
            "name": name,
            "state": state,
            "created_at": created,
            "container_count": count,
            "container_ids": ids,
            "container_names": names,
            "container_statuses": statuses,
            "infra_id": infra_id.lower() if isinstance(infra_id, str) and infra_id else None,
        })
    return pods, None, truncated


def _read_pods(endpoint: _Endpoint) -> tuple[list[dict[str, object]], str | None, bool]:
    output, error, command_truncated = _run_podman(
        endpoint,
        ["pod", "ps", "--no-trunc", "--ctr-ids", "--ctr-names", "--ctr-status", "--format=json"],
    )
    if error:
        return [], "The local Podman pod inventory could not be read.", False
    if command_truncated:
        return [], "The local Podman pod inventory exceeded the output limit.", True
    try:
        payload = json.loads(output or "[]")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return [], "Local Podman returned malformed JSON for its pod inventory.", False
    return _parse_pods(payload)


def _pod_info(endpoint: _Endpoint, item: dict[str, object]) -> ContainerPodInfo:
    return ContainerPodInfo(
        runtime="podman",
        scope=endpoint.scope,  # type: ignore[arg-type]
        pod_id=str(item["pod_id"]),
        name=str(item["name"]),
        state=str(item["state"]),  # type: ignore[arg-type]
        created_at=item.get("created_at") if isinstance(item.get("created_at"), str) else None,
        container_count=int(item.get("container_count", 0)),
        container_ids=list(item.get("container_ids", ())),
        container_names=list(item.get("container_names", ())),
        container_statuses=list(item.get("container_statuses", ())),
    )


def list_container_pods(query: str = "", limit: int = 100) -> ContainerPodListResponse:
    """List bounded local Podman pods and their member identities/states."""
    if not sys.platform.startswith("linux"):
        return ContainerPodListResponse(success=False, message="Podman pod inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256 or any(ord(character) < 32 or ord(character) == 127 for character in query):
        return ContainerPodListResponse(success=False, message="query must be text with at most 256 characters and no control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return ContainerPodListResponse(success=False, message="limit must be an integer.")
    limit = max(1, min(limit, MAX_CONTAINERS_RETURNED))
    endpoint, error = _podman_endpoint()
    if error or endpoint is None:
        return ContainerPodListResponse(success=False, limit=limit, message=error)
    pods, error, truncated = _read_pods(endpoint)
    if error:
        return ContainerPodListResponse(success=False, limit=limit, message=error)
    needle = query.strip().casefold()
    selected = [item for item in pods if not needle or needle in str(item.get("name", "")).casefold() or needle in str(item.get("pod_id", "")).casefold()]
    selected.sort(key=lambda item: (str(item.get("name", "")).casefold(), str(item.get("pod_id", ""))))
    truncated |= len(selected) > limit
    return ContainerPodListResponse(
        success=True,
        total_pods=len(selected),
        returned_pods=min(len(selected), limit),
        pods=[_pod_info(endpoint, item) for item in selected[:limit]],
        limit=limit,
        truncated=truncated,
        message="The local pod inventory was capped by scan or result limits." if truncated else None,
    )


def container_pod_action_confirmation_details(
    action: str,
    name: str,
) -> tuple[_PodTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Podman pod actions are available only on Linux."
    if not isinstance(action, str) or action not in {"create", "start", "stop", "remove"}:
        return None, None, "action must be create, start, stop, or remove."
    if not isinstance(name, str) or not POD_NAME_RE.fullmatch(name):
        return None, None, "name must be one exact pod name using letters, digits, dot, underscore, or hyphen."
    endpoint, error = _podman_endpoint()
    if error or endpoint is None:
        return None, None, error or "The local Podman endpoint could not be verified."
    pods, error, truncated = _read_pods(endpoint)
    if error or truncated:
        return None, None, error or "The local pod inventory is incomplete; the action is refused."
    matches = [item for item in pods if item.get("name") == name]
    if action == "create":
        if matches:
            return None, None, "A pod with that exact name already exists in the current local Podman scope."
        selected = None
    else:
        if len(matches) != 1:
            return None, None, "The exact pod name was not found uniquely in the current local Podman scope."
        selected = matches[0]
        state = str(selected.get("state", "unknown"))
        members = tuple(str(value) for value in selected.get("container_ids", ()) if isinstance(value, str))
        if action == "start" and (state == "running" or not members or state not in {"created", "stopped", "exited"}):
            return None, None, "Starting requires a stopped/created pod with at least one known attached container."
        if action == "stop" and (state != "running" or not members):
            return None, None, "Stopping requires the exact pod to be running with known attached containers."
        if action == "remove" and (members or int(selected.get("container_count", len(members))) != 0 or state not in {"created", "stopped", "exited"}):
            return None, None, "Removal is limited to an empty stopped/created pod; member containers are never removed by this tool."

    identity = _endpoint_identity(endpoint)
    if identity is None:
        return None, None, "The local Podman executable identity could not be verified."
    snapshot = sorted(
        (
            str(item.get("pod_id", "")),
            str(item.get("name", "")),
            str(item.get("state", "")),
            tuple(str(value) for value in item.get("container_ids", ()) if isinstance(value, str)),
            tuple(str(value) for value in item.get("container_names", ()) if isinstance(value, str)),
            tuple(str(value) for value in item.get("container_statuses", ()) if isinstance(value, str)),
        )
        for item in pods
    )
    details = {
        "action": action,
        "scope": endpoint.scope,
        "name": name,
        "endpoint": identity,
        "pod_snapshot": snapshot,
        "target": None if selected is None else {
            "pod_id": selected.get("pod_id"),
            "state": selected.get("state"),
            "container_ids": selected.get("container_ids"),
            "container_names": selected.get("container_names"),
            "container_statuses": selected.get("container_statuses"),
        },
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = _PodTarget(
        action=action,  # type: ignore[arg-type]
        endpoint=endpoint,
        scope=endpoint.scope,
        name=name,
        pod_id=str(selected.get("pod_id")) if selected else None,
        state=str(selected.get("state")) if selected else None,
        container_ids=tuple(str(value) for value in selected.get("container_ids", ()) if isinstance(value, str)) if selected else (),
        container_names=tuple(str(value) for value in selected.get("container_names", ()) if isinstance(value, str)) if selected else (),
        state_digest=digest,
    )
    phrase = hashlib.sha256(("podman-pod:" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"pod {phrase}", None


def perform_container_pod_action(
    action: ContainerPodAction,
    name: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> ContainerPodActionResponse:
    target, phrase, error = container_pod_action_confirmation_details(action, name)
    if error or target is None or phrase is None:
        return ContainerPodActionResponse(success=False, action=action, name=name, user_confirmed=confirmed is True, message=error or "The pod action could not be verified.")
    if confirmed is not True:
        return ContainerPodActionResponse(success=False, action=action, scope=target.scope, name=name, pod_id=target.pod_id, user_confirmed=False, message="Explicit client confirmation is required; no pod action was run.")
    if confirmation_phrase != phrase:
        return ContainerPodActionResponse(success=False, action=action, scope=target.scope, name=name, pod_id=target.pod_id, user_confirmed=True, message="Confirmation did not match the current local Podman pod inventory.")
    current, current_phrase, error = container_pod_action_confirmation_details(action, name)
    if error or current is None or current_phrase != phrase:
        return ContainerPodActionResponse(success=False, action=action, scope=target.scope, name=name, pod_id=target.pod_id, user_confirmed=True, message=error or "The Podman pod inventory changed after confirmation; no action was run.")

    if action == "create":
        command = ["pod", "create", "--infra=false", "--name", name]
    elif action == "remove":
        command = ["pod", "rm", name]
    else:
        command = ["pod", action, name]
    _output, error, truncated = _run_podman(target.endpoint, command, timeout_seconds=30.0)
    if error or truncated:
        return ContainerPodActionResponse(success=False, action=action, scope=target.scope, name=name, pod_id=target.pod_id, user_confirmed=True, message="The Podman pod action failed or may have completed before timing out; inspect the pod and container inventories before retrying.")

    pods, result_error, result_truncated = _read_pods(target.endpoint)
    if result_error or result_truncated:
        return ContainerPodActionResponse(success=False, action=action, scope=target.scope, name=name, pod_id=target.pod_id, user_confirmed=True, message="The pod action returned, but its result could not be verified; inspect the local pod inventory before retrying.")
    matches = [item for item in pods if item.get("name") == name]
    if action == "create":
        if len(matches) != 1 or int(matches[0].get("container_count", 0)) != 0:
            return ContainerPodActionResponse(success=False, action=action, scope=target.scope, name=name, user_confirmed=True, message="The create command returned, but an exact empty pod could not be verified.")
        pod_id = str(matches[0].get("pod_id"))
        message = "Created and verified an empty pod without an infra container; the pod is not started."
    elif action == "remove":
        if matches:
            return ContainerPodActionResponse(success=False, action=action, scope=target.scope, name=name, pod_id=target.pod_id, user_confirmed=True, message="The remove command returned, but the exact pod is still present.")
        pod_id = target.pod_id
        message = "Removed the exact empty pod without force."
    elif len(matches) != 1:
        return ContainerPodActionResponse(success=False, action=action, scope=target.scope, name=name, pod_id=target.pod_id, user_confirmed=True, message="The pod action returned, but the exact pod could not be found afterward.")
    elif action == "start" and matches[0].get("state") == "running":
        pod_id = str(matches[0].get("pod_id"))
        message = "Started and verified the exact pod and its attached containers."
    elif action == "stop" and matches[0].get("state") in {"stopped", "exited", "created"}:
        pod_id = str(matches[0].get("pod_id"))
        message = "Stopped and verified the exact pod and its attached containers."
    else:
        return ContainerPodActionResponse(success=False, action=action, scope=target.scope, name=name, pod_id=target.pod_id, user_confirmed=True, message="The pod action returned, but its expected state was not observed.")
    return ContainerPodActionResponse(success=True, action=action, scope=target.scope, name=name, pod_id=pod_id, user_confirmed=True, message=message)
