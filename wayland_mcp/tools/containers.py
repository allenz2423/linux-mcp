"""Bounded local Docker, Podman, and CRI container inventory and confirmed actions."""

from __future__ import annotations

import http.client
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import stat
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlencode

from wayland_mcp.models import (
    ContainerActionResponse,
    ContainerCreateResponse,
    ContainerImageActionResponse,
    ContainerImageInfo,
    ContainerImageListResponse,
    ContainerInfo,
    ContainerListResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

ContainerAction = Literal["start", "stop", "restart", "pause", "unpause", "remove"]
ContainerRuntime = Literal["docker", "podman"]
ContainerImageAction = Literal["pull", "tag", "remove"]
RUNTIMES = {"docker", "podman", "containerd", "cri-o"}
ACTION_RUNTIMES = {"docker", "podman"}
CRI_SOCKET_PATHS = {
    "containerd": Path("/run/containerd/containerd.sock"),
    "cri-o": Path("/run/crio/crio.sock"),
}
CONTAINER_STATES = {
    "created", "initialized", "restarting", "running", "paused", "stopped", "stopping",
    "exited", "dead", "removing", "unknown",
}
CONTAINER_ACTIONS = {"start", "stop", "restart", "pause", "unpause", "remove"}
CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,254}$")
IMAGE_ID_RE = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{12,128}$")
PORT_NUMBER_RE = re.compile(r"^(?P<port>[0-9]{1,5})(?:/(?P<protocol>tcp|udp))?$", re.IGNORECASE)
ENVIRONMENT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
CONTAINER_USER_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?::(?:0|[1-9][0-9]*))?$")
CONTAINER_CAPABILITIES = frozenset({
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL",
    "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE",
    "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
    "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT",
    "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME",
    "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL",
    "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM",
    "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE",
})
MAX_CONTAINER_ENVIRONMENT_VARIABLES = 128
MAX_CONTAINER_ENVIRONMENT_BYTES = 64 * 1024
MAX_CONTAINERS_SCANNED = 2_000
MAX_CONTAINERS_RETURNED = 200
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_IMAGE_PULL_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_TOKENS = 8_192
TOKEN_TTL_SECONDS = 300
API_TIMEOUT_SECONDS = 5.0
IMAGE_PULL_TIMEOUT_SECONDS = 30 * 60.0
CONTAINER_STOP_GRACE_SECONDS = 10
CONTAINER_ACTION_TIMEOUT_SECONDS = API_TIMEOUT_SECONDS + CONTAINER_STOP_GRACE_SECONDS + 2.0


@dataclass(frozen=True, slots=True)
class _Endpoint:
    runtime: str
    scope: str
    socket_path: Path | None = None
    podman_binary: str | None = None
    crictl_binary: str | None = None


@dataclass(slots=True)
class _TokenRecord:
    endpoint: _Endpoint
    api_prefix: str | None
    container_id: str
    name: str
    image: str
    expires_at: float
    claimed: bool = False


@dataclass(frozen=True, slots=True)
class _ContainerTarget:
    endpoint: _Endpoint
    api_prefix: str | None
    container_id: str
    name: str
    image: str
    state: str
    environment_variables: tuple[tuple[str, str], ...] = ()
    container_user: str | None = None
    read_only_rootfs: bool | None = None
    no_new_privileges: bool | None = None
    dropped_capabilities: tuple[str, ...] = ()
    network_names: tuple[str, ...] = ()
    network_mode: str | None = None


@dataclass(frozen=True, slots=True)
class _ContainerCreateTarget:
    endpoint: _Endpoint
    api_prefix: str | None
    image: str
    image_id: str
    name: str
    command: tuple[str, ...]
    port_mappings: tuple[tuple[str, int, int, str], ...]
    memory_limit_bytes: int | None
    cpu_limit_millicores: int | None
    volume_mounts: tuple[tuple[str, str, bool, str | None, str | None, str | None], ...]
    host_path_mounts: tuple[tuple[str, str, bool, tuple[int, ...]], ...]
    environment_variables: tuple[tuple[str, str], ...]
    container_user: str | None
    read_only_rootfs: bool
    no_new_privileges: bool
    dropped_capabilities: tuple[str, ...]
    network_name: str | None
    network_id: str | None
    network_driver: str | None
    network_created_at: str | None
    state_digest: str


@dataclass(frozen=True, slots=True)
class _ContainerImageActionTarget:
    action: ContainerImageAction
    endpoint: _Endpoint
    api_prefix: str | None
    image: str
    image_id: str | None
    target_tag: str | None
    state_digest: str


@dataclass(frozen=True, slots=True)
class _APIResult:
    status: int | None
    body: bytes
    error: str | None = None


_TOKENS: dict[str, _TokenRecord] = {}
_TOKEN_LOCK = threading.Lock()
# Confirmation phrases are shown to the client. Key the digest so the phrase
# cannot be used as an offline dictionary oracle for configured environment
# values, which are intentionally kept out of the prompt and response.
_CONFIRMATION_KEY = secrets.token_bytes(32)


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(str(self._socket_path))
        self.sock = connection


def _endpoint_candidates() -> list[_Endpoint]:
    if not sys.platform.startswith("linux"):
        return []
    uid = os.getuid()
    runtime_dir = Path(f"/run/user/{uid}")
    configured_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if configured_runtime:
        try:
            candidate = Path(configured_runtime)
            metadata = candidate.stat()
            if (
                candidate.is_absolute()
                and stat.S_ISDIR(metadata.st_mode)
                and metadata.st_uid == uid
                and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
            ):
                runtime_dir = candidate.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            pass
    return [
        _Endpoint("docker", "system", Path("/run/docker.sock")),
        _Endpoint("docker", "user", runtime_dir / "docker.sock"),
        _Endpoint("podman", "system", Path("/run/podman/podman.sock")),
        _Endpoint("podman", "user", runtime_dir / "podman/podman.sock"),
    ]


def _socket_is_available(path: Path) -> bool:
    try:
        return stat.S_ISSOCK(path.lstat().st_mode)
    except OSError:
        return False


def _podman_env() -> dict[str, str]:
    return get_sanitized_env(dict(os.environ))


def container_runtime_readiness() -> tuple[bool, bool, bool, bool]:
    """Return inventory found/access and action found/access for local runtimes."""
    sockets = [
        endpoint.socket_path
        for endpoint in _endpoint_candidates()
        if endpoint.socket_path is not None and _socket_is_available(endpoint.socket_path)
    ]
    env = _podman_env()
    podman_cli = find_session_binary("podman", env)
    control_found = bool(sockets or podman_cli)
    control_access = bool(any(os.access(path, os.W_OK) for path in sockets) or podman_cli)
    crictl = find_session_binary("crictl", env)
    cri_sockets = [path for path in CRI_SOCKET_PATHS.values() if _socket_is_available(path)]
    cri_found = bool(crictl and cri_sockets)
    cri_access = bool(crictl and any(os.access(path, os.W_OK) for path in cri_sockets))
    return (
        control_found or cri_found,
        control_access or cri_access,
        control_found,
        control_access,
    )


def _available_endpoints(runtime: str = "auto") -> list[_Endpoint]:
    endpoints = [
        endpoint
        for endpoint in _endpoint_candidates()
        if (runtime == "auto" or endpoint.runtime == runtime)
        and endpoint.socket_path is not None
        and _socket_is_available(endpoint.socket_path)
    ]
    if runtime in {"auto", "podman"}:
        env = _podman_env()
        podman_cli = find_session_binary("podman", env)
        scope = "system" if os.getuid() == 0 else "user"
        same_scope_socket_accessible = any(
            endpoint.runtime == "podman"
            and endpoint.scope == scope
            and endpoint.socket_path is not None
            and os.access(endpoint.socket_path, os.W_OK)
            for endpoint in endpoints
        )
        if podman_cli and not same_scope_socket_accessible:
            endpoints.append(_Endpoint("podman", scope, podman_binary=podman_cli))
    if runtime in {"auto", "containerd", "cri-o"}:
        env = _podman_env()
        crictl = find_session_binary("crictl", env)
        if crictl:
            for cri_runtime, socket_path in CRI_SOCKET_PATHS.items():
                if (runtime == "auto" or runtime == cri_runtime) and _socket_is_available(socket_path):
                    endpoints.append(_Endpoint(cri_runtime, "system", socket_path, crictl_binary=crictl))
    return endpoints


def _request(
    endpoint: _Endpoint,
    method: str,
    path: str,
    body: bytes | None = None,
    *,
    content_type: str = "application/json",
    timeout_seconds: float = API_TIMEOUT_SECONDS,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> _APIResult:
    if endpoint.socket_path is None:
        return _APIResult(None, b"", "No local API socket is configured for this runtime.")
    connection = _UnixHTTPConnection(endpoint.socket_path, timeout_seconds)
    try:
        headers = {"Host": "localhost", "Connection": "close"}
        if body is not None:
            headers["Content-Type"] = content_type
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if response.length is not None and response.length > max_response_bytes:
            return _APIResult(response.status, b"", "Container engine response exceeded the size limit.")
        body = response.read(max_response_bytes + 1)
        if len(body) > max_response_bytes:
            return _APIResult(response.status, b"", "Container engine response exceeded the size limit.")
        return _APIResult(response.status, body)
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        reason = "timed out" if isinstance(exc, TimeoutError) else "could not be reached"
        return _APIResult(None, b"", f"The local {endpoint.runtime} {endpoint.scope} engine {reason}.")
    finally:
        connection.close()


def _decode_json(result: _APIResult, expected_status: int = 200):
    if result.error:
        return None, result.error
    if result.status != expected_status:
        return None, f"Container engine returned HTTP {result.status} instead of {expected_status}."
    try:
        return json.loads(result.body), None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "Container engine returned malformed JSON."


def _api_prefix(endpoint: _Endpoint) -> tuple[str | None, str | None]:
    payload, error = _decode_json(_request(endpoint, "GET", "/version"))
    if error:
        return None, error
    if not isinstance(payload, dict):
        return None, "Container engine returned an unexpected version response."
    version = payload.get("ApiVersion", payload.get("APIVersion"))
    if not isinstance(version, str) or not re.fullmatch(r"1\.[0-9]{1,3}", version):
        return None, "Container engine did not report a supported Docker-compatible API version."
    return f"/v{version}", None


def _clean_text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(character for character in value if ord(character) >= 32 and ord(character) != 127)[:limit].strip()


def _container_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not 12 <= len(candidate) <= 128 or any(character not in "0123456789abcdefABCDEF" for character in candidate):
        return None
    return candidate.lower()


def _created_at(value: object, fallback: object) -> str | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**63 - 1:
        try:
            return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return None
    for candidate in (value, fallback):
        if not isinstance(candidate, str):
            continue
        cleaned = _clean_text(candidate, 64)
        try:
            parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError):
            pass
    if isinstance(fallback, str):
        result = _clean_text(fallback, 64)
        return result or None
    return None


def _created_at_nanoseconds(value: object) -> str | None:
    if isinstance(value, str) and value.isdigit():
        try:
            value = int(value)
        except ValueError:
            return None
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
        return None
    seconds, nanoseconds = divmod(value, 1_000_000_000)
    try:
        created = datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=nanoseconds // 1_000)
    except (OverflowError, OSError, ValueError):
        return None
    return created.isoformat().replace("+00:00", "Z")


def _parse_list_item(raw: object, endpoint: _Endpoint) -> tuple[dict[str, str | None] | None, str | None]:
    if not isinstance(raw, dict):
        return None, None
    identifier = _container_id(raw.get("Id", raw.get("ID")))
    if identifier is None:
        return None, None
    raw_names = raw.get("Names")
    name = ""
    if isinstance(raw_names, list) and raw_names and isinstance(raw_names[0], str):
        name = _clean_text(raw_names[0].lstrip("/"), 128)
    elif isinstance(raw_names, str):
        name = _clean_text(raw_names.lstrip("/"), 128)
    if not name:
        name = _clean_text(raw.get("Name"), 128)
    image = _clean_text(raw.get("Image", raw.get("ImageName")), 256) or "(unknown image)"
    image_identity = _image_id(raw.get("ImageID", raw.get("ImageId")))
    raw_state = _clean_text(raw.get("State", raw.get("Status")), 32).casefold()
    state = raw_state if raw_state in CONTAINER_STATES else "unknown"
    status = _clean_text(raw.get("Status", raw.get("State")), 160) or state
    created = _created_at(raw.get("Created"), raw.get("CreatedAt"))
    return {
        "runtime": endpoint.runtime,
        "scope": endpoint.scope,
        "container_id": identifier,
        "name": name or identifier[:12],
        "image": image,
        "image_identity": image_identity,
        "state": state,
        "status": status,
        "created_at": created,
    }, None


def _parse_cri_list(output: str, endpoint: _Endpoint) -> tuple[list[dict[str, str | None]], str | None, bool]:
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return [], "crictl returned malformed JSON for its container list.", False
    if not isinstance(payload, dict) or not isinstance(payload.get("containers"), list):
        return [], "crictl returned an unexpected container-list shape.", False
    raw_containers = payload["containers"]
    truncated = len(raw_containers) > MAX_CONTAINERS_SCANNED
    items: list[dict[str, str | None]] = []
    state_names = {
        "container_created": "created",
        "container_running": "running",
        "container_exited": "exited",
        "container_unknown": "unknown",
        "container_unset": "unknown",
    }
    for raw in raw_containers[:MAX_CONTAINERS_SCANNED]:
        if not isinstance(raw, dict):
            continue
        identifier = _container_id(raw.get("id", raw.get("ID")))
        if identifier is None:
            continue
        metadata = raw.get("metadata")
        name_value = metadata.get("name") if isinstance(metadata, dict) else raw.get("name")
        name = _clean_text(name_value, 128) or identifier[:12]
        image_value = raw.get("image")
        if isinstance(image_value, dict):
            image_value = image_value.get("image")
        image = _clean_text(image_value, 256) or "(unknown image)"
        raw_state = _clean_text(raw.get("state", raw.get("State")), 32).casefold()
        state = state_names.get(raw_state, raw_state if raw_state in CONTAINER_STATES else "unknown")
        status = _clean_text(raw.get("status", raw.get("Status")), 160) or raw_state or state
        items.append({
            "runtime": endpoint.runtime,
            "scope": endpoint.scope,
            "container_id": identifier,
            "name": name,
            "image": image,
            "state": state,
            "status": status,
            "created_at": _created_at_nanoseconds(raw.get("createdAt", raw.get("created_at"))),
        })
    return items, None, truncated


def _prune_tokens_locked() -> None:
    now = time.monotonic()
    expired = [key for key, record in _TOKENS.items() if record.expires_at <= now]
    for key in expired:
        _TOKENS.pop(key, None)
    if len(_TOKENS) >= MAX_TOKENS:
        oldest = sorted(_TOKENS, key=lambda key: _TOKENS[key].expires_at)
        for key in oldest[: len(_TOKENS) - MAX_TOKENS + 1]:
            _TOKENS.pop(key, None)


def _issue_token(endpoint: _Endpoint, api_prefix: str | None, item: dict[str, str | None]) -> str:
    identity_token = secrets.token_urlsafe(32)
    with _TOKEN_LOCK:
        _prune_tokens_locked()
        _TOKENS[identity_token] = _TokenRecord(
            endpoint=endpoint,
            api_prefix=api_prefix,
            container_id=str(item["container_id"]),
            name=str(item["name"]),
            image=str(item.get("image_identity") or item["image"]),
            expires_at=time.monotonic() + TOKEN_TTL_SECONDS,
        )
    return identity_token


def _run_podman(
    endpoint: _Endpoint,
    arguments: list[str],
    *,
    timeout_seconds: float = API_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_RESPONSE_BYTES,
    pass_fds: tuple[int, ...] = (),
) -> tuple[str | None, str | None, bool]:
    if not endpoint.podman_binary:
        return None, "The local Podman executable is unavailable.", False
    return run_bounded_command(
        [endpoint.podman_binary, "--remote=false", *arguments],
        _podman_env(),
        command_label="local Podman",
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        pass_fds=pass_fds,
    )


def _anonymous_environment_file(values: tuple[tuple[str, str], ...]) -> int | None:
    create = getattr(os, "memfd_create", None)
    if create is None:
        return None
    descriptor = -1
    try:
        descriptor = create("linux-mcp-container-env", getattr(os, "MFD_CLOEXEC", 0))
        content = "".join(f"{name}={value}\n" for name, value in values).encode("utf-8", errors="strict")
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("short write to anonymous environment file")
            offset += written
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except (OSError, UnicodeError):
        if descriptor >= 0:
            os.close(descriptor)
        return None


def _run_crictl(endpoint: _Endpoint, arguments: list[str]) -> tuple[str | None, str | None, bool]:
    if not endpoint.crictl_binary or endpoint.socket_path is None:
        return None, "The local CRI executable or fixed runtime socket is unavailable.", False
    env = _podman_env()
    env.pop("CONTAINER_RUNTIME_ENDPOINT", None)
    env.pop("IMAGE_SERVICE_ENDPOINT", None)
    socket_endpoint = f"unix://{endpoint.socket_path}"
    return run_bounded_command(
        [
            endpoint.crictl_binary,
            "--config", "/dev/null",
            "--runtime-endpoint", socket_endpoint,
            "--image-endpoint", socket_endpoint,
            "--timeout", f"{int(API_TIMEOUT_SECONDS)}s",
            *arguments,
        ],
        env,
        command_label="local CRI container inventory",
        timeout_seconds=API_TIMEOUT_SECONDS,
        max_output_bytes=MAX_RESPONSE_BYTES,
    )


def _read_container_list(
    endpoint: _Endpoint,
    api_prefix: str | None,
) -> tuple[list[dict[str, str | None]], str | None, bool]:
    if endpoint.crictl_binary:
        output, error, command_truncated = _run_crictl(
            endpoint,
            ["ps", "--all", "--no-trunc", "--output", "json"],
        )
        if error:
            return [], "The local CRI container list could not be read.", False
        if command_truncated:
            return [], "The local CRI container list exceeded the output limit.", True
        return _parse_cri_list(output or "", endpoint)
    if endpoint.podman_binary:
        output, error, truncated = _run_podman(endpoint, ["ps", "--all", "--no-trunc", "--format=json"])
        if error:
            return [], "The local Podman container list could not be read.", False
        if truncated:
            return [], "The local Podman container list exceeded the output limit.", True
        try:
            payload = json.loads(output or "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return [], "Local Podman returned malformed JSON for its container list.", False
    else:
        if api_prefix is None:
            return [], "The local container API version was unavailable.", False
        result = _request(endpoint, "GET", f"{api_prefix}/containers/json?all=1")
        payload, error = _decode_json(result)
    if error:
        return [], error, False
    if not isinstance(payload, list):
        return [], "Container engine returned an unexpected container-list shape.", False
    truncated = len(payload) > MAX_CONTAINERS_SCANNED
    items: list[dict[str, str | None]] = []
    for raw in payload[:MAX_CONTAINERS_SCANNED]:
        item, _reason = _parse_list_item(raw, endpoint)
        if item:
            items.append(item)
    return items, None, truncated


def _image_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if candidate.startswith("sha256:"):
        digest = candidate[7:]
        if re.fullmatch(r"[0-9a-fA-F]{12,128}", digest):
            return "sha256:" + digest.lower()
        return None
    if re.fullmatch(r"[0-9a-fA-F]{12,128}", candidate):
        return candidate.lower()
    return None


def _image_tags(raw: dict[str, object]) -> tuple[str, ...]:
    raw_tags: list[object] = []
    for key, alternate in (("RepoTags", "repoTags"), ("RepoDigests", "repoDigests"), ("Names", "names")):
        value = raw.get(key, raw.get(alternate))
        if isinstance(value, list):
            raw_tags.extend(value)
        elif isinstance(value, str):
            raw_tags.append(value)
    repository = raw.get("Repository")
    tag = raw.get("Tag")
    if isinstance(repository, str) and isinstance(tag, str) and repository not in {"", "<none>"} and tag not in {"", "<none>"}:
        raw_tags.append(f"{repository}:{tag}")
    tags = {
        clean
        for value in raw_tags
        if (clean := _clean_text(value, 512))
        and clean not in {"<none>:<none>", "<none>"}
        and IMAGE_REF_RE.fullmatch(clean)
    }
    return tuple(sorted(tags, key=str.casefold))


def _parse_image_list(payload: object) -> tuple[list[dict[str, object]], bool]:
    if isinstance(payload, dict) and isinstance(payload.get("images"), list):
        payload = payload["images"]
    if not isinstance(payload, list):
        return [], False
    truncated = len(payload) > MAX_CONTAINERS_SCANNED
    images: dict[str, dict[str, object]] = {}
    for raw in payload[:MAX_CONTAINERS_SCANNED]:
        if not isinstance(raw, dict):
            continue
        identifier = _image_id(raw.get("Id", raw.get("ID", raw.get("id"))))
        if identifier is None:
            continue
        tags = _image_tags(raw)
        try:
            size_value = raw.get("Size", raw.get("size"))
            size_bytes = int(size_value) if isinstance(size_value, (int, str)) and str(size_value).isdigit() else None
        except (ValueError, OverflowError):
            size_bytes = None
        if size_bytes is not None and not 0 <= size_bytes <= (1 << 63) - 1:
            size_bytes = None
        created = _created_at(raw.get("Created", raw.get("created")), raw.get("CreatedAt", raw.get("CreatedTime")))
        existing = images.get(identifier)
        if existing is None:
            images[identifier] = {
                "image_id": identifier,
                "tags": set(tags),
                "size_bytes": size_bytes,
                "created_at": created,
            }
        else:
            existing_tags = existing["tags"]
            if isinstance(existing_tags, set):
                existing_tags.update(tags)
            if existing.get("size_bytes") is None:
                existing["size_bytes"] = size_bytes
            if existing.get("created_at") is None:
                existing["created_at"] = created
    result: list[dict[str, object]] = []
    for record in images.values():
        tags = record.pop("tags", set())
        record["tags"] = sorted(tags, key=str.casefold) if isinstance(tags, set) else []
        result.append(record)
    result.sort(key=lambda item: (str(item.get("tags", [""])[0] if item.get("tags") else "").casefold(), str(item["image_id"])))
    return result, truncated


def _read_image_list(endpoint: _Endpoint, api_prefix: str | None) -> tuple[list[dict[str, object]], str | None, bool]:
    if endpoint.podman_binary:
        output, error, command_truncated = _run_podman(endpoint, ["image", "ls", "--all", "--no-trunc", "--format=json"])
        if error:
            return [], "The local Podman image list could not be read.", False
        if command_truncated:
            return [], "The local Podman image list exceeded the output limit.", True
        try:
            payload = json.loads(output or "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return [], "Local Podman returned malformed JSON for its image list.", False
    else:
        if api_prefix is None:
            return [], "The local container API version was unavailable.", False
        result = _request(endpoint, "GET", f"{api_prefix}/images/json?all=1")
        payload, error = _decode_json(result)
        if error:
            return [], error, False
    if not isinstance(payload, list) and not (isinstance(payload, dict) and isinstance(payload.get("images"), list)):
        return [], "The local engine returned an unexpected image-list shape.", False
    images, truncated = _parse_image_list(payload)
    return images, None, truncated


def list_container_images(
    runtime: str = "auto",
    query: str = "",
    limit: int = 100,
) -> ContainerImageListResponse:
    """List bounded image IDs and exact local tags from Docker/Podman endpoints."""
    if not sys.platform.startswith("linux"):
        return ContainerImageListResponse(success=False, message="Container image inventory is available only on Linux.")
    if not isinstance(runtime, str) or runtime not in {"auto", "docker", "podman"}:
        return ContainerImageListResponse(success=False, message="runtime must be auto, docker, or podman.")
    if not isinstance(query, str) or len(query) > 256 or any(ord(character) < 32 or ord(character) == 127 for character in query):
        return ContainerImageListResponse(success=False, message="query must be text with at most 256 characters and no control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return ContainerImageListResponse(success=False, message="limit must be an integer.")
    limit = max(1, min(limit, MAX_CONTAINERS_RETURNED))
    endpoints = [endpoint for endpoint in _available_endpoints(runtime) if endpoint.runtime in ACTION_RUNTIMES]
    if not endpoints:
        return ContainerImageListResponse(success=False, limit=limit, message="No standard local Docker/Podman endpoint or local Podman CLI was found.")
    collected: list[ContainerImageInfo] = []
    errors: list[str] = []
    truncated = False
    successful_endpoints = 0
    needle = query.strip().casefold()
    for endpoint in endpoints:
        api_prefix: str | None = None
        if not endpoint.podman_binary:
            api_prefix, error = _api_prefix(endpoint)
            if error or api_prefix is None:
                errors.append(error or "A local container API version could not be read.")
                continue
        records, error, endpoint_truncated = _read_image_list(endpoint, api_prefix)
        truncated |= endpoint_truncated
        if error:
            errors.append(error)
            continue
        successful_endpoints += 1
        for item in records:
            tags = [str(tag) for tag in item.get("tags", []) if isinstance(tag, str)]
            image_id = str(item.get("image_id", ""))
            if needle and needle not in image_id.casefold() and not any(needle in tag.casefold() for tag in tags):
                continue
            collected.append(ContainerImageInfo(
                runtime=endpoint.runtime,  # type: ignore[arg-type]
                scope=endpoint.scope,  # type: ignore[arg-type]
                image_id=image_id,
                tags=tags,
                size_bytes=item.get("size_bytes") if isinstance(item.get("size_bytes"), int) else None,
                created_at=item.get("created_at") if isinstance(item.get("created_at"), str) else None,
            ))
    collected.sort(key=lambda item: (item.runtime, item.scope, (item.tags[0] if item.tags else "").casefold(), item.image_id))
    truncated |= len(collected) > limit
    messages = errors[:3]
    if errors and successful_endpoints:
        messages.append("Some local image endpoints could not be queried.")
    if truncated:
        messages.append("The image inventory was capped by scan, response-size, or result limits.")
    return ContainerImageListResponse(
        success=successful_endpoints > 0,
        total_images=len(collected),
        returned_images=min(len(collected), limit),
        images=collected[:limit],
        limit=limit,
        truncated=truncated,
        partial=bool(errors) or truncated,
        message=" ".join(messages) or None,
    )


def _split_tag_reference(reference: str) -> tuple[str, str] | None:
    if "@" in reference:
        return None
    separator = reference.rfind(":")
    slash = reference.rfind("/")
    if separator <= slash or separator == len(reference) - 1:
        return None
    return reference[:separator], reference[separator + 1:]


def _exact_image_match(images: list[dict[str, object]], reference: str) -> dict[str, object] | None:
    matches = [
        item for item in images
        if reference == str(item.get("image_id", ""))
        or any(reference == str(tag) for tag in item.get("tags", []) if isinstance(tag, str))
    ]
    return matches[0] if len(matches) == 1 else None


def container_image_action_confirmation_details(
    action: str,
    runtime: str,
    scope: str,
    image: str,
    target_tag: str | None = None,
) -> tuple[_ContainerImageActionTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Container image actions are available only on Linux."
    if not isinstance(action, str) or action not in {"pull", "tag", "remove"}:
        return None, None, "action must be pull, tag, or remove."
    if not isinstance(runtime, str) or runtime not in ACTION_RUNTIMES:
        return None, None, "runtime must be docker or podman."
    if not isinstance(scope, str) or scope not in {"system", "user"}:
        return None, None, "scope must be system or user."
    if not isinstance(image, str) or not IMAGE_REF_RE.fullmatch(image) or image.startswith(("/", ".")):
        return None, None, "image must be one exact repository tag or digest reference without whitespace or control characters."
    if action == "pull" and (IMAGE_ID_RE.fullmatch(image) or not ("/" in image and ("@" in image or _split_tag_reference(image)))):
        return None, None, "pull requires a fully qualified repository reference with an explicit tag or digest."
    if action == "tag":
        if not isinstance(target_tag, str) or not IMAGE_REF_RE.fullmatch(target_tag) or target_tag.startswith(("/", ".")) or _split_tag_reference(target_tag) is None:
            return None, None, "tag requires a destination repository reference with an explicit tag."
    elif target_tag is not None:
        return None, None, "target_tag is accepted only for tag actions."
    if action == "remove" and (IMAGE_ID_RE.fullmatch(image) or "@" in image):
        return None, None, "remove requires one exact local repository tag; image IDs and digests can refer to multiple names."

    endpoints = [endpoint for endpoint in _available_endpoints(runtime) if endpoint.runtime == runtime and endpoint.scope == scope]
    if len(endpoints) != 1:
        return None, None, "Exactly one accessible local endpoint for the selected runtime and scope is required."
    endpoint = endpoints[0]
    endpoint_identity = _endpoint_identity(endpoint)
    if endpoint_identity is None:
        return None, None, "The selected local runtime endpoint identity could not be verified."
    api_prefix: str | None = None
    if not endpoint.podman_binary:
        api_prefix, error = _api_prefix(endpoint)
        if error or api_prefix is None:
            return None, None, error or "The local runtime API version could not be verified."
    images, error, truncated = _read_image_list(endpoint, api_prefix)
    if error or truncated:
        return None, None, error or "The local image inventory is incomplete; image action is refused."

    image_id: str | None = None
    if action == "pull":
        # A pull may replace a mutable local tag; its current identity is included in confirmation.
        existing = _exact_image_match(images, image)
        image_id = str(existing["image_id"]) if existing is not None else None
    elif action == "tag":
        source = _exact_image_match(images, image)
        if source is None:
            return None, None, "The exact source image tag or ID was not found uniquely in the selected local runtime."
        if _exact_image_match(images, target_tag or "") is not None:
            return None, None, "The destination image tag already exists; overwriting a tag is refused."
        image_id = str(source["image_id"])
    else:
        source = _exact_image_match(images, image)
        if source is None or not any(image == str(tag) for tag in source.get("tags", []) if isinstance(tag, str)):
            return None, None, "The exact removable local repository tag was not found uniquely."
        image_id = str(source["image_id"])

    image_snapshot = sorted(
        (
            str(item.get("image_id", "")),
            tuple(str(tag) for tag in item.get("tags", []) if isinstance(tag, str)),
        )
        for item in images
    )
    details = {
        "action": action,
        "runtime": runtime,
        "scope": scope,
        "endpoint_identity": endpoint_identity,
        "api_prefix": api_prefix,
        "image": image,
        "image_id": image_id,
        "target_tag": target_tag,
        "image_snapshot": image_snapshot,
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = _ContainerImageActionTarget(
        action=action,  # type: ignore[arg-type]
        endpoint=endpoint,
        api_prefix=api_prefix,
        image=image,
        image_id=image_id,
        target_tag=target_tag,
        state_digest=digest,
    )
    phrase = hashlib.sha256(("image:" + digest).encode("utf-8")).hexdigest()[:16]
    return target, f"image {phrase}", None


def _docker_pull_error(body: bytes) -> bool:
    for line in body.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return True
        if isinstance(entry, dict) and (entry.get("error") or entry.get("errorDetail")):
            return True
    return False


def perform_container_image_action(
    action: ContainerImageAction,
    runtime: ContainerRuntime,
    scope: str,
    image: str,
    target_tag: str | None,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> ContainerImageActionResponse:
    target, phrase, error = container_image_action_confirmation_details(action, runtime, scope, image, target_tag)
    if error or target is None or phrase is None:
        return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=None, user_confirmed=confirmed is True, message=error or "The image action could not be verified.")
    if confirmed is not True:
        return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=False, message="Explicit client confirmation is required; no image action was run.")
    if confirmation_phrase != phrase:
        return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message="Confirmation did not match the selected runtime, image identity, and current image inventory.")
    current, current_phrase, error = container_image_action_confirmation_details(action, runtime, scope, image, target_tag)
    if error or current is None or current_phrase != phrase:
        return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message=error or "The runtime image inventory changed after confirmation; no image action was run.")

    if target.endpoint.podman_binary:
        if action == "pull":
            arguments = ["image", "pull", "--quiet", image]
        elif action == "tag":
            arguments = ["image", "tag", image, target.target_tag or ""]
        else:
            arguments = ["image", "rm", "--no-prune", image]
        _output, error, truncated = _run_podman(
            target.endpoint,
            arguments,
            timeout_seconds=IMAGE_PULL_TIMEOUT_SECONDS if action == "pull" else API_TIMEOUT_SECONDS,
            max_output_bytes=MAX_IMAGE_PULL_RESPONSE_BYTES if action == "pull" else MAX_RESPONSE_BYTES,
        )
        if error or truncated:
            message = "The local Podman image action may have completed before timing out; inspect the image inventory before retrying." if error and "timed out" in error.casefold() else "The local Podman image action failed or exceeded its output limit; inspect the image inventory before retrying."
            return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message=message)
    else:
        if target.api_prefix is None:
            return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message="The local Docker API version is unavailable.")
        if action == "pull":
            query = urlencode({"fromImage": image})
            result = _request(
                target.endpoint,
                "POST",
                f"{target.api_prefix}/images/create?{query}",
                timeout_seconds=IMAGE_PULL_TIMEOUT_SECONDS,
                max_response_bytes=MAX_IMAGE_PULL_RESPONSE_BYTES,
            )
            if result.error or result.status != 200 or _docker_pull_error(result.body):
                return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message="Docker image pull failed or its bounded progress response was incomplete; inspect the image inventory before retrying.")
        elif action == "tag":
            destination = _split_tag_reference(target.target_tag or "")
            if destination is None:
                return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message="The destination image tag could not be parsed safely.")
            query = urlencode({"repo": destination[0], "tag": destination[1]})
            result = _request(
                target.endpoint,
                "POST",
                f"{target.api_prefix}/images/{quote(image, safe='')}/tag?{query}",
            )
            if result.error or result.status not in {200, 201}:
                return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message="Docker rejected the image tag action; inspect the image inventory before retrying.")
        else:
            result = _request(
                target.endpoint,
                "DELETE",
                f"{target.api_prefix}/images/{quote(image, safe='')}?force=false&noprune=true",
            )
            if result.error or result.status not in {200, 204}:
                return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message="Docker refused or could not confirm image removal; in-use images are not forced. Inspect the image inventory before retrying.")

    resulting, result_error, result_truncated = _read_image_list(target.endpoint, target.api_prefix)
    if result_error or result_truncated:
        return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message="The image command returned, but its result could not be verified; inspect the local image inventory before retrying.")
    if action == "pull":
        pulled = _exact_image_match(resulting, image)
        if pulled is None:
            return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message="The pull completed without a verifiable exact local image reference.")
        resulting_id = str(pulled["image_id"])
    elif action == "tag":
        tagged = _exact_image_match(resulting, target.target_tag or "")
        if tagged is None or str(tagged.get("image_id")) != target.image_id:
            return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message="The tag command returned, but the requested alias did not resolve to the confirmed image.")
        resulting_id = target.image_id
    else:
        if _exact_image_match(resulting, image) is not None:
            return ContainerImageActionResponse(success=False, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=target.image_id, user_confirmed=True, message="The remove command returned, but the requested tag is still present.")
        resulting_id = target.image_id
    messages = {
        "pull": "Pulled and verified the exact image reference.",
        "tag": "Created and verified the new local image tag.",
        "remove": "Removed the exact image tag without force; untagged parent layers were not pruned.",
    }
    return ContainerImageActionResponse(success=True, action=action, runtime=runtime, scope=scope, image=image, target_tag=target_tag, image_id=resulting_id, user_confirmed=True, message=messages[action])


def _endpoint_identity(endpoint: _Endpoint) -> tuple[object, ...] | None:
    try:
        if endpoint.socket_path is not None:
            info = endpoint.socket_path.lstat()
            if not stat.S_ISSOCK(info.st_mode):
                return None
            return ("socket", str(endpoint.socket_path), info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))
        if endpoint.podman_binary:
            binary = Path(endpoint.podman_binary).resolve(strict=True)
            info = binary.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
                return None
            return ("podman", str(binary), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    except (OSError, RuntimeError, ValueError):
        return None
    return None


def _normalize_container_environment(
    value: object,
) -> tuple[tuple[tuple[str, str], ...] | None, str | None]:
    if value is None:
        return (), None
    if not isinstance(value, dict) or len(value) > MAX_CONTAINER_ENVIRONMENT_VARIABLES:
        return None, f"environment_variables must be an object with at most {MAX_CONTAINER_ENVIRONMENT_VARIABLES} entries."
    normalized: list[tuple[str, str]] = []
    total_bytes = 0
    for name, content in value.items():
        if not isinstance(name, str) or not ENVIRONMENT_NAME_RE.fullmatch(name):
            return None, "Environment variable names must match [A-Za-z_][A-Za-z0-9_]* and be at most 128 characters."
        if not isinstance(content, str) or any(ord(character) < 32 or ord(character) == 127 for character in content):
            return None, "Environment values must be single-line text without control characters."
        try:
            encoded = content.encode("utf-8", errors="strict")
        except UnicodeError:
            return None, "Environment values must contain valid UTF-8 text."
        total_bytes += len(name.encode("ascii")) + 1 + len(encoded) + 1
        if total_bytes > MAX_CONTAINER_ENVIRONMENT_BYTES:
            return None, f"The combined environment-variable data cannot exceed {MAX_CONTAINER_ENVIRONMENT_BYTES} bytes."
        normalized.append((name, content))
    return tuple(sorted(normalized)), None


def _normalize_container_user(value: object) -> tuple[str | None, str | None]:
    if value is None:
        return None, None
    if not isinstance(value, str) or not CONTAINER_USER_RE.fullmatch(value):
        return None, "container_user must be a numeric UID or UID:GID; usernames and supplementary groups are not accepted."
    for identifier in value.split(":"):
        if int(identifier, 10) > 2_147_483_647:
            return None, "container_user UID/GID values must be no greater than 2147483647."
    return value, None


def _normalize_dropped_capabilities(value: object) -> tuple[tuple[str, ...] | None, str | None]:
    if value is None:
        return (), None
    if not isinstance(value, list) or len(value) > len(CONTAINER_CAPABILITIES) + 1:
        return None, "drop_capabilities must be an array of known Linux capability names."
    normalized: list[str] = []
    for capability in value:
        if not isinstance(capability, str) or capability != capability.strip():
            return None, "Capability names must be exact text values."
        selected = capability.upper()
        if selected.startswith("CAP_"):
            selected = selected[4:]
        if selected != "ALL" and selected not in CONTAINER_CAPABILITIES:
            return None, f"Unsupported capability name {capability!r}."
        normalized.append(selected)
    if len(set(normalized)) != len(normalized):
        return None, "Each capability may be listed only once."
    if "ALL" in normalized and len(normalized) != 1:
        return None, "ALL cannot be combined with individual capability names."
    return tuple(sorted(normalized)), None


def _normalize_port_mappings(value: object) -> tuple[tuple[tuple[str, int, int, str], ...] | None, str | None]:
    if value is None:
        return (), None
    if not isinstance(value, list) or len(value) > 32:
        return None, "port_mappings must be an array of at most 32 host_port:container_port[/tcp|udp] strings."
    normalized: list[tuple[str, int, int, str]] = []
    host_bindings: set[tuple[str, int, str]] = set()
    for specification in value:
        if not isinstance(specification, str) or "\x00" in specification:
            return None, "Each port mapping must be a NUL-free host_port:container_port[/tcp|udp] string."
        parts = specification.split(":")
        if len(parts) == 2:
            host_ip = "127.0.0.1"
            host_port_text, container_port_text = parts
        elif len(parts) == 3:
            host_ip_text, host_port_text, container_port_text = parts
            try:
                host_ip = str(ipaddress.IPv4Address(host_ip_text))
            except ipaddress.AddressValueError:
                return None, "Port mapping host addresses must be literal IPv4 addresses; use 127.0.0.1 for loopback or 0.0.0.0 for all IPv4 interfaces."
        else:
            return None, "Each port mapping must be host_port:container_port[/tcp|udp] or host_ipv4:host_port:container_port[/tcp|udp]."

        host_match = PORT_NUMBER_RE.fullmatch(host_port_text)
        container_match = PORT_NUMBER_RE.fullmatch(container_port_text)
        if host_match is None or container_match is None or host_match.group("protocol") is not None:
            return None, "Port mappings must use numeric ports 1-65535 and an optional tcp or udp protocol suffix on the container port."
        host_port = int(host_match.group("port"))
        container_port = int(container_match.group("port"))
        protocol = (container_match.group("protocol") or "tcp").lower()
        if not (1 <= host_port <= 65535 and 1 <= container_port <= 65535):
            return None, "Host and container ports must be in the range 1-65535."
        binding = (host_ip, host_port, protocol)
        if binding in host_bindings:
            return None, "A host IPv4 address, host port, and protocol may appear only once."
        host_bindings.add(binding)
        normalized.append((host_ip, host_port, container_port, protocol))
    return tuple(normalized), None


def _normalize_volume_mounts(value: object) -> tuple[tuple[tuple[str, str, bool], ...] | None, str | None]:
    if value is None:
        return (), None
    if not isinstance(value, list) or len(value) > 32:
        return None, "volume_mounts must be an array of at most 32 existing-volume mount strings."
    normalized: list[tuple[str, str, bool]] = []
    destinations: set[str] = set()
    for specification in value:
        if not isinstance(specification, str) or "\x00" in specification:
            return None, "Each volume mount must be a NUL-free name:/container/path[:ro|rw] string."
        parts = specification.split(":")
        if len(parts) not in {2, 3}:
            return None, "Volume mounts must use name:/container/path[:ro|rw]."
        name, destination = parts[:2]
        mode = parts[2] if len(parts) == 3 else "rw"
        if not CONTAINER_NAME_RE.fullmatch(name):
            return None, "Volume mount names must use letters, digits, dot, underscore, or hyphen and begin with a letter or digit."
        if mode not in {"ro", "rw"}:
            return None, "Volume mount mode must be ro or rw."
        try:
            destination_bytes = destination.encode("utf-8", errors="strict")
        except UnicodeError:
            return None, "Container mount targets must contain valid UTF-8 text."
        if (
            not destination.startswith("/")
            or destination.startswith("//")
            or any(part in {"", ".", ".."} for part in destination[1:].split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in destination)
            or ":" in destination
            or "," in destination
            or len(destination_bytes) > 4096
        ):
            return None, "Container mount targets must be normalized absolute paths without empty, dot, parent components, control characters, colons, or commas."
        if any(
            destination == previous
            or destination.startswith(previous.rstrip("/") + "/")
            or previous.startswith(destination.rstrip("/") + "/")
            for previous in destinations
        ):
            return None, "Named volume mount targets must not overlap."
        destinations.add(destination)
        normalized.append((name, destination, mode == "ro"))
    return tuple(normalized), None


def _host_path_snapshot(raw_path: object) -> tuple[str | None, tuple[int, ...] | None, str | None]:
    if not isinstance(raw_path, str) or not raw_path.strip() or len(raw_path) > 4096:
        return None, None, "Host mount paths must be non-empty absolute paths with at most 4096 characters."
    try:
        encoded_path = raw_path.encode("utf-8", errors="strict")
    except UnicodeError:
        return None, None, "Host mount paths must contain valid UTF-8 text."
    if len(encoded_path) > 4096:
        return None, None, "Host mount paths are limited to 4096 UTF-8 bytes."
    if any(ord(character) < 32 or ord(character) == 127 for character in raw_path):
        return None, None, "Host mount paths cannot contain control characters."
    try:
        raw = Path(raw_path).expanduser()
        if not raw.is_absolute():
            return None, None, "Host mount paths must be absolute; '~' is expanded to the current user's home directory."
        lexical = Path(os.path.abspath(raw))
        blocked_roots = (Path("/proc"), Path("/sys"), Path("/dev"), Path("/run"))
        if any(lexical == root or root in lexical.parents for root in blocked_roots):
            return None, None, "Host paths under /proc, /sys, /dev, and /run cannot be mounted."
        resolved = raw.resolve(strict=True)
        if resolved == Path("/") or any(resolved == root or root in resolved.parents for root in blocked_roots):
            return None, None, "The host mount source must be a non-root path outside /proc, /sys, /dev, and /run."
        components = resolved.parts[1:]
        path_flags = getattr(os, "O_PATH", os.O_RDONLY) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_flags = path_flags | getattr(os, "O_DIRECTORY", 0)
        parent_fd = os.open("/", directory_flags)
        try:
            for component in components[:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
            if not components:
                return None, None, "Mounting the host root directory is not supported."
            source_fd = os.open(components[-1], path_flags, dir_fd=parent_fd)
            try:
                opened = os.fstat(source_fd)
                current = os.stat(resolved, follow_symlinks=False)
            finally:
                os.close(source_fd)
        finally:
            os.close(parent_fd)
    except (OSError, RuntimeError, ValueError) as exc:
        return None, None, f"The host mount source could not be safely inspected: {getattr(exc, 'strerror', None) or type(exc).__name__}."
    if not (stat.S_ISREG(opened.st_mode) or stat.S_ISDIR(opened.st_mode)):
        return None, None, "Host mounts are limited to existing regular files and directories."
    if (
        opened.st_dev != current.st_dev
        or opened.st_ino != current.st_ino
        or opened.st_mode != current.st_mode
        or opened.st_size != current.st_size
        or opened.st_mtime_ns != current.st_mtime_ns
        or opened.st_ctime_ns != current.st_ctime_ns
    ):
        return None, None, "The host mount source changed while it was being inspected."
    snapshot = (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode), stat.S_IMODE(opened.st_mode))
    return str(resolved), snapshot, None


def _normalize_host_path_mounts(
    value: object,
) -> tuple[tuple[tuple[str, str, bool, tuple[int, ...]], ...] | None, str | None]:
    if value is None:
        return (), None
    if not isinstance(value, list) or len(value) > 32:
        return None, "host_path_mounts must be an array of at most 32 existing host-path mount strings."
    normalized: list[tuple[str, str, bool, tuple[int, ...]]] = []
    destinations: set[str] = set()
    for specification in value:
        if not isinstance(specification, str) or "\x00" in specification:
            return None, "Each host-path mount must be a NUL-free /host/path:/container/path[:ro|rw] string."
        parts = specification.split(":")
        if len(parts) not in {2, 3}:
            return None, "Host-path mounts must use /host/path:/container/path[:ro|rw]; host source paths containing ':' are unsupported."
        source, destination = parts[:2]
        mode = parts[2] if len(parts) == 3 else "ro"
        if mode not in {"ro", "rw"}:
            return None, "Host-path mount mode must be ro or rw."
        if "," in source:
            return None, "Host source paths containing commas are unsupported by the selected runtimes."
        try:
            destination_bytes = destination.encode("utf-8", errors="strict")
        except UnicodeError:
            return None, "Container mount targets must contain valid UTF-8 text."
        if (
            not destination.startswith("/")
            or destination.startswith("//")
            or any(part in {"", ".", ".."} for part in destination[1:].split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in destination)
            or ":" in destination
            or "," in destination
            or len(destination_bytes) > 4096
        ):
            return None, "Container mount targets must be normalized absolute paths without empty, dot, parent components, control characters, colons, or commas."
        if any(
            destination == previous
            or destination.startswith(previous.rstrip("/") + "/")
            or previous.startswith(destination.rstrip("/") + "/")
            for previous in destinations
        ):
            return None, "Host-path mount targets must not overlap."
        canonical_source, identity, path_error = _host_path_snapshot(source)
        if path_error or canonical_source is None or identity is None:
            return None, path_error or "The host mount source could not be verified."
        destinations.add(destination)
        normalized.append((canonical_source, destination, mode == "ro", identity))
    return tuple(normalized), None


def container_create_confirmation_details(
    runtime: str,
    scope: str,
    name: str,
    image: str,
    command: object = None,
    port_mappings: object = None,
    memory_limit_bytes: object = None,
    cpu_limit_millicores: object = None,
    volume_mounts: object = None,
    host_path_mounts: object = None,
    environment_variables: object = None,
    container_user: object = None,
    read_only_rootfs: object = False,
    no_new_privileges: object = False,
    drop_capabilities: object = None,
    network_name: object = None,
) -> tuple[_ContainerCreateTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Container creation is available only on Linux."
    if not isinstance(runtime, str) or runtime not in {"docker", "podman"}:
        return None, None, "runtime must be docker or podman."
    if not isinstance(scope, str) or scope not in {"system", "user"}:
        return None, None, "scope must be system or user."
    if not isinstance(name, str) or not CONTAINER_NAME_RE.fullmatch(name):
        return None, None, "name must be 1-128 characters using letters, digits, dot, underscore, or hyphen, and begin with a letter or digit."
    if network_name is not None and (
        not isinstance(network_name, str)
        or not CONTAINER_NAME_RE.fullmatch(network_name)
    ):
        return None, None, "network_name must be the exact name of one existing local non-default network."
    if not isinstance(image, str) or not IMAGE_REF_RE.fullmatch(image) or image.startswith(("/", ".")):
        return None, None, "image must be one exact local image tag, digest, or ID without whitespace or control characters."
    if command is None:
        command_values: tuple[str, ...] = ()
    elif isinstance(command, list) and len(command) <= 64:
        normalized_command: list[str] = []
        total_bytes = 0
        for argument in command:
            if not isinstance(argument, str) or "\x00" in argument:
                return None, None, "command must be an array of at most 64 NUL-free text arguments."
            try:
                argument_bytes = argument.encode("utf-8", errors="strict")
            except UnicodeError:
                return None, None, "command arguments must contain valid UTF-8 text."
            if len(argument_bytes) > 4096:
                return None, None, "Each command argument is limited to 4096 UTF-8 bytes."
            total_bytes += len(argument_bytes)
            normalized_command.append(argument)
        if total_bytes > 16 * 1024:
            return None, None, "The combined command arguments exceed the 16 KiB limit."
        command_values = tuple(normalized_command)
    else:
        return None, None, "command must be an array of at most 64 NUL-free text arguments."

    normalized_environment, environment_error = _normalize_container_environment(environment_variables)
    if environment_error or normalized_environment is None:
        return None, None, environment_error or "Environment variables could not be verified."
    normalized_user, user_error = _normalize_container_user(container_user)
    if user_error:
        return None, None, user_error
    if not isinstance(read_only_rootfs, bool):
        return None, None, "read_only_rootfs must be a boolean."
    if not isinstance(no_new_privileges, bool):
        return None, None, "no_new_privileges must be a boolean."
    normalized_capabilities, capability_error = _normalize_dropped_capabilities(drop_capabilities)
    if capability_error or normalized_capabilities is None:
        return None, None, capability_error or "Dropped capabilities could not be verified."

    normalized_ports, port_error = _normalize_port_mappings(port_mappings)
    if port_error or normalized_ports is None:
        return None, None, port_error or "Port mappings could not be verified."
    if memory_limit_bytes is not None and (
        isinstance(memory_limit_bytes, bool)
        or not isinstance(memory_limit_bytes, int)
        or not 1 <= memory_limit_bytes <= 1024 * 1024 * 1024 * 1024
    ):
        return None, None, "memory_limit_bytes must be an integer from 1 byte to 1 TiB."
    if cpu_limit_millicores is not None and (
        isinstance(cpu_limit_millicores, bool)
        or not isinstance(cpu_limit_millicores, int)
        or not 1 <= cpu_limit_millicores <= 256_000
    ):
        return None, None, "cpu_limit_millicores must be an integer from 1 to 256000 (up to 256 CPUs in 0.001 CPU steps)."
    normalized_volume_mounts, volume_mount_error = _normalize_volume_mounts(volume_mounts)
    if volume_mount_error or normalized_volume_mounts is None:
        return None, None, volume_mount_error or "Named volume mounts could not be verified."
    normalized_host_path_mounts, host_path_mount_error = _normalize_host_path_mounts(host_path_mounts)
    if host_path_mount_error or normalized_host_path_mounts is None:
        return None, None, host_path_mount_error or "Host-path mounts could not be verified."
    all_destinations = [destination for _name, destination, _read_only in normalized_volume_mounts]
    all_destinations.extend(destination for _source, destination, _read_only, _identity in normalized_host_path_mounts)
    if any(
        destination == previous
        or destination.startswith(previous.rstrip("/") + "/")
        or previous.startswith(destination.rstrip("/") + "/")
        for index, destination in enumerate(all_destinations)
        for previous in all_destinations[:index]
    ):
        return None, None, "Named-volume and host-path mount targets must not overlap."

    candidates = [endpoint for endpoint in _available_endpoints(runtime) if endpoint.runtime == runtime and endpoint.scope == scope]
    if len(candidates) != 1:
        return None, None, "Exactly one accessible local endpoint for the selected runtime and scope is required."
    endpoint = candidates[0]
    endpoint_identity = _endpoint_identity(endpoint)
    if endpoint_identity is None:
        return None, None, "The selected local runtime endpoint identity could not be verified."
    api_prefix: str | None = None
    if not endpoint.podman_binary:
        api_prefix, error = _api_prefix(endpoint)
        if error or api_prefix is None:
            return None, None, error or "The local runtime API version could not be verified."
        api_version = tuple(int(part) for part in api_prefix.removeprefix("/v").split("."))
        if (normalized_volume_mounts or normalized_host_path_mounts) and api_version < (1, 30):
            return None, None, "Volume mounts require Docker-compatible Engine API 1.30 or newer."
        if cpu_limit_millicores is not None and api_version < (1, 25):
            return None, None, "CPU limits require Docker-compatible Engine API 1.25 or newer."
    images, error, images_truncated = _read_image_list(endpoint, api_prefix)
    if error or images_truncated:
        return None, None, error or "The local image inventory is incomplete; container creation is refused."
    image_matches = [
        item for item in images
        if image == str(item.get("image_id", ""))
        or any(image == str(tag) for tag in item.get("tags", []) if isinstance(tag, str))
    ]
    if len(image_matches) != 1:
        return None, None, "The exact image is not present uniquely in the selected local runtime."
    image_id = str(image_matches[0]["image_id"])
    containers, error, containers_truncated = _read_container_list(endpoint, api_prefix)
    if error or containers_truncated:
        return None, None, error or "The local container inventory is incomplete; unique name availability cannot be verified."
    if any(str(item.get("name", "")).casefold() == name.casefold() for item in containers):
        return None, None, "A container with this name already exists in the selected runtime and scope."

    selected_volume_mounts: tuple[tuple[str, str, bool, str | None, str | None, str | None], ...] = ()
    selected_network: tuple[str, str, str, str | None] | None = None
    if network_name is not None:
        # Import after this module has finished loading to avoid the resource
        # adapter's shared helpers creating an import cycle.
        from wayland_mcp.tools.container_resources import _read_resources

        networks, network_error, networks_truncated = _read_resources(endpoint, api_prefix, "network")
        if network_error or networks_truncated:
            return None, None, network_error or "The local network inventory is incomplete; container creation is refused."
        matches = [item for item in networks if item.get("name") == network_name]
        if len(matches) != 1:
            return None, None, "The exact network name is not present uniquely in the selected local runtime and scope."
        selected = matches[0]
        if selected.get("is_default") == "true":
            return None, None, "Container creation can select only an existing non-default local network."
        network_id = selected.get("resource_id")
        network_driver = selected.get("driver")
        if not isinstance(network_id, str) or not network_id or not isinstance(network_driver, str) or not network_driver:
            return None, None, "The selected network ID and driver could not be verified."
        selected_network = (
            network_name,
            network_id,
            network_driver,
            selected.get("created_at"),
        )
    if normalized_volume_mounts:
        # Import after this module has finished loading to avoid the resource
        # adapter's shared helpers creating an import cycle.
        from wayland_mcp.tools.container_resources import _read_resources

        volumes, volume_error, volumes_truncated = _read_resources(endpoint, api_prefix, "volume")
        if volume_error or volumes_truncated:
            return None, None, volume_error or "The local named-volume inventory is incomplete; container creation is refused."
        resolved: list[tuple[str, str, bool, str | None, str | None, str | None]] = []
        for volume_name, destination, read_only in normalized_volume_mounts:
            matches = [item for item in volumes if item.get("name") == volume_name]
            if len(matches) != 1:
                return None, None, f"Existing named volume {volume_name!r} was not found uniquely in the selected runtime and scope."
            selected = matches[0]
            driver = selected.get("driver")
            if not isinstance(driver, str) or not driver:
                return None, None, f"The storage driver for named volume {volume_name!r} could not be verified."
            resolved.append((
                volume_name,
                destination,
                read_only,
                selected.get("resource_id"),
                driver,
                selected.get("created_at"),
            ))
        selected_volume_mounts = tuple(resolved)

    details = {
        "runtime": runtime,
        "scope": scope,
        "endpoint_identity": endpoint_identity,
        "api_prefix": api_prefix,
        "image": image,
        "image_id": image_id,
        "name": name,
        "command": command_values,
        "port_mappings": normalized_ports,
        "memory_limit_bytes": memory_limit_bytes,
        "cpu_limit_millicores": cpu_limit_millicores,
        "volume_mounts": selected_volume_mounts,
        "host_path_mounts": normalized_host_path_mounts,
        "environment_variables": normalized_environment,
        "container_user": normalized_user,
        "read_only_rootfs": read_only_rootfs,
        "no_new_privileges": no_new_privileges,
        "drop_capabilities": normalized_capabilities,
        "selected_network": selected_network,
        "existing_containers": sorted(
            (
                str(item.get("container_id", "")),
                str(item.get("name", "")),
                str(item.get("image", "")),
                str(item.get("state", "")),
            )
            for item in containers
        ),
    }
    digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = _ContainerCreateTarget(
        endpoint=endpoint,
        api_prefix=api_prefix,
        image=image,
        image_id=image_id,
        name=name,
        command=command_values,
        port_mappings=normalized_ports,
        memory_limit_bytes=memory_limit_bytes,
        cpu_limit_millicores=cpu_limit_millicores,
        volume_mounts=selected_volume_mounts,
        host_path_mounts=normalized_host_path_mounts,
        environment_variables=normalized_environment,
        container_user=normalized_user,
        read_only_rootfs=read_only_rootfs,
        no_new_privileges=no_new_privileges,
        dropped_capabilities=normalized_capabilities,
        network_name=selected_network[0] if selected_network else None,
        network_id=selected_network[1] if selected_network else None,
        network_driver=selected_network[2] if selected_network else None,
        network_created_at=selected_network[3] if selected_network else None,
        state_digest=digest,
    )
    phrase = hmac.new(
        _CONFIRMATION_KEY,
        ("create:" + digest).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]
    return target, f"container create {phrase}", None


def perform_container_create(
    runtime: ContainerRuntime,
    scope: str,
    name: str,
    image: str,
    command: object,
    port_mappings: object = None,
    memory_limit_bytes: object = None,
    cpu_limit_millicores: object = None,
    volume_mounts: object = None,
    host_path_mounts: object = None,
    environment_variables: object = None,
    container_user: object = None,
    read_only_rootfs: object = False,
    no_new_privileges: object = False,
    drop_capabilities: object = None,
    network_name: object = None,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> ContainerCreateResponse:
    target, phrase, error = container_create_confirmation_details(
        runtime, scope, name, image, command, port_mappings, memory_limit_bytes, cpu_limit_millicores,
        volume_mounts, host_path_mounts, environment_variables, container_user, read_only_rootfs,
        no_new_privileges, drop_capabilities, network_name,
    )
    if error or target is None or phrase is None:
        return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=confirmed is True, message=error or "The container creation request could not be verified.")
    if confirmed is not True:
        return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=False, message="Explicit client confirmation is required; no container was created.")
    if not isinstance(confirmation_phrase, str) or not secrets.compare_digest(confirmation_phrase, phrase):
        return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=True, message="Confirmation did not match the exact local image, runtime, name, network, command, environment, port bindings, mounts, user, security settings, and resource limits.")
    current, current_phrase, error = container_create_confirmation_details(
        runtime, scope, name, image, command, port_mappings, memory_limit_bytes, cpu_limit_millicores,
        volume_mounts, host_path_mounts, environment_variables, container_user, read_only_rootfs,
        no_new_privileges, drop_capabilities, network_name,
    )
    if error or current is None or current_phrase != phrase:
        return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=True, message=error or "The selected runtime or its image/container state changed after confirmation; no container was created.")

    container_id: str | None = None
    if target.endpoint.podman_binary:
        arguments = ["container", "create", "--pull=never", "--name", target.name]
        if target.network_name is not None:
            arguments.extend(["--network", target.network_name])
        environment_fd = _anonymous_environment_file(target.environment_variables) if target.environment_variables else None
        if target.environment_variables and environment_fd is None:
            return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=True, message="An anonymous in-memory environment file could not be prepared; no container was created.")
        # Avoid Podman's default host-proxy environment passthrough. Callers
        # can provide explicit proxy variables through environment_variables.
        arguments.append("--http-proxy=false")
        if environment_fd is not None:
            arguments.extend(["--env-file", f"/proc/self/fd/{environment_fd}"])
        if target.container_user is not None:
            arguments.extend(["--user", target.container_user])
        if target.read_only_rootfs:
            arguments.append("--read-only")
        if target.no_new_privileges:
            arguments.extend(["--security-opt", "no-new-privileges"])
        for capability in target.dropped_capabilities:
            arguments.extend(["--cap-drop", capability])
        for host_ip, host_port, container_port, protocol in target.port_mappings:
            arguments.extend(["--publish", f"{host_ip}:{host_port}:{container_port}/{protocol}"])
        for volume_name, destination, read_only, _resource_id, _driver, _created_at in target.volume_mounts:
            mode = "ro" if read_only else "rw"
            arguments.extend(["--volume", f"{volume_name}:{destination}:{mode},nocopy,nocreate"])
        for source, destination, read_only, _identity in target.host_path_mounts:
            mode = "ro" if read_only else "rw"
            arguments.extend(["--volume", f"{source}:{destination}:{mode}"])
        if target.memory_limit_bytes is not None:
            arguments.extend(["--memory", str(target.memory_limit_bytes)])
        if target.cpu_limit_millicores is not None:
            cpu_whole, cpu_fraction = divmod(target.cpu_limit_millicores, 1000)
            cpu_value = f"{cpu_whole}.{cpu_fraction:03d}".rstrip("0").rstrip(".")
            arguments.extend(["--cpus", cpu_value])
        # Resolve by the image ID captured in the confirmation digest so a
        # concurrent tag change cannot redirect creation to another image.
        arguments.extend([target.image_id, *target.command])
        try:
            output, error, truncated = _run_podman(
                target.endpoint,
                arguments,
                pass_fds=(environment_fd,) if environment_fd is not None else (),
            )
        finally:
            if environment_fd is not None:
                os.close(environment_fd)
        if error or truncated:
            return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=True, message="The local Podman create request failed or timed out; inspect the container inventory before retrying.")
        last_line = (output or "").strip().splitlines()[-1:]
        container_id = _container_id(last_line[0]) if last_line else None
    else:
        if target.api_prefix is None:
            return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=True, message="The local Docker API version is unavailable.")
        # Use the immutable local image ID that was revalidated after the
        # confirmation instead of resolving a potentially retagged name.
        payload: dict[str, object] = {"Image": target.image_id}
        if target.network_name is not None:
            payload["NetworkingConfig"] = {"EndpointsConfig": {target.network_name: {}}}
            payload["HostConfig"] = {"NetworkMode": target.network_name}
        if target.command:
            payload["Cmd"] = list(target.command)
        if target.environment_variables:
            payload["Env"] = [f"{key}={value}" for key, value in target.environment_variables]
        if target.container_user is not None:
            payload["User"] = target.container_user
        if target.port_mappings:
            exposed_ports: dict[str, dict[str, object]] = {}
            port_bindings: dict[str, list[dict[str, str]]] = {}
            for host_ip, host_port, container_port, protocol in target.port_mappings:
                key = f"{container_port}/{protocol}"
                exposed_ports[key] = {}
                port_bindings.setdefault(key, []).append({"HostIp": host_ip, "HostPort": str(host_port)})
            payload["ExposedPorts"] = exposed_ports
            host_config = payload.get("HostConfig")
            if not isinstance(host_config, dict):
                host_config = {}
                payload["HostConfig"] = host_config
            host_config["PortBindings"] = port_bindings
        if target.volume_mounts or target.host_path_mounts:
            host_config = payload.get("HostConfig")
            if not isinstance(host_config, dict):
                host_config = {}
                payload["HostConfig"] = host_config
            mounts = [
                {
                    "Type": "volume",
                    "Source": volume_name,
                    "Target": destination,
                    "ReadOnly": read_only,
                    "VolumeOptions": {"NoCopy": True},
                }
                for volume_name, destination, read_only, _resource_id, _driver, _created_at in target.volume_mounts
            ]
            mounts.extend(
                {
                    "Type": "bind",
                    "Source": source,
                    "Target": destination,
                    "ReadOnly": read_only,
                }
                for source, destination, read_only, _identity in target.host_path_mounts
            )
            host_config["Mounts"] = mounts
        host_config = payload.get("HostConfig")
        if (
            target.memory_limit_bytes is not None
            or target.cpu_limit_millicores is not None
            or target.read_only_rootfs
            or target.no_new_privileges
            or target.dropped_capabilities
        ):
            if not isinstance(host_config, dict):
                host_config = {}
                payload["HostConfig"] = host_config
            if target.memory_limit_bytes is not None:
                host_config["Memory"] = target.memory_limit_bytes
            if target.cpu_limit_millicores is not None:
                host_config["NanoCpus"] = target.cpu_limit_millicores * 1_000_000
            if target.read_only_rootfs:
                host_config["ReadonlyRootfs"] = True
            if target.no_new_privileges:
                host_config["SecurityOpt"] = ["no-new-privileges:true"]
            if target.dropped_capabilities:
                host_config["CapDrop"] = list(target.dropped_capabilities)
        try:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        except (TypeError, UnicodeError):
            return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=True, message="The container configuration could not be encoded safely.")
        result = _request(
            target.endpoint,
            "POST",
            f"{target.api_prefix}/containers/create?name={quote(target.name, safe='')}",
            body,
        )
        if result.error:
            return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=True, message=result.error)
        response, error = _decode_json(result, expected_status=201)
        if error or not isinstance(response, dict):
            return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=True, message="The local Docker engine rejected container creation or returned an unreadable result.")
        container_id = _container_id(response.get("Id"))
    if container_id is None:
        return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, name=name, image=image, user_confirmed=True, message="The runtime accepted or may have accepted creation, but did not return a valid container ID; inspect the inventory before retrying.")

    record = _TokenRecord(
        endpoint=target.endpoint,
        api_prefix=target.api_prefix,
        container_id=container_id,
        name=target.name,
        image=target.image_id,
        expires_at=time.monotonic() + TOKEN_TTL_SECONDS,
    )
    verified, verify_error = _read_target(record)
    if (
        verify_error
        or verified is None
        or verified.state not in {"created", "initialized"}
        or not _container_create_config_matches(target, verified)
    ):
        return ContainerCreateResponse(success=False, runtime=runtime, scope=scope, container_id=container_id, name=name, image=image, user_confirmed=True, message="The runtime created a container or may have done so, but its stopped state or requested configuration could not be verified; inspect the inventory before retrying.")
    return ContainerCreateResponse(
        success=True,
        runtime=runtime,
        scope=scope,
        container_id=container_id,
        name=name,
        image=image,
        port_mappings=[
            f"{host_ip}:{host_port}:{container_port}/{protocol}"
            for host_ip, host_port, container_port, protocol in target.port_mappings
        ],
        memory_limit_bytes=target.memory_limit_bytes,
        cpu_limit_millicores=target.cpu_limit_millicores,
        volume_mounts=[
            f"{volume_name}:{destination}:{'ro' if read_only else 'rw'}"
            for volume_name, destination, read_only, _resource_id, _driver, _created_at in target.volume_mounts
        ],
        host_path_mounts=[
            f"{source}:{destination}:{'ro' if read_only else 'rw'}"
            for source, destination, read_only, _identity in target.host_path_mounts
        ],
        environment_names=[key for key, _value in target.environment_variables],
        network_name=target.network_name,
        container_user=target.container_user,
        read_only_rootfs=target.read_only_rootfs,
        no_new_privileges=target.no_new_privileges,
        dropped_capabilities=list(target.dropped_capabilities),
        user_confirmed=True,
        message="Created the stopped container; its identity, stopped state, and requested environment/hardening fields were verified. Environment values are not returned. It was not started; use list_containers for a fresh token before starting it.",
    )


def list_containers(
    runtime: str = "auto",
    query: str = "",
    limit: int = 100,
) -> ContainerListResponse:
    """List containers from fixed local Docker, Podman, containerd, and CRI-O endpoints."""
    if not sys.platform.startswith("linux"):
        return ContainerListResponse(success=False, message="Container inventory is available only on Linux.")
    if not isinstance(runtime, str) or runtime not in {"auto", *RUNTIMES}:
        return ContainerListResponse(success=False, message="runtime must be 'auto', 'docker', 'podman', 'containerd', or 'cri-o'.")
    if not isinstance(query, str) or len(query) > 256 or any(ord(character) < 32 or ord(character) == 127 for character in query):
        return ContainerListResponse(success=False, message="query must be text with at most 256 characters and no control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return ContainerListResponse(success=False, message="limit must be an integer.")
    limit = max(1, min(limit, MAX_CONTAINERS_RETURNED))

    endpoints = _available_endpoints(runtime)
    if not endpoints:
        reason = (
            "No standard local Docker API socket was found."
            if runtime == "docker"
            else "No standard local Podman API socket or local Podman executable was found."
            if runtime == "podman"
            else "No supported local Docker, Podman, containerd, or CRI-O runtime endpoint was found."
        )
        return ContainerListResponse(
            success=False,
            limit=limit,
            message=reason,
        )

    collected: list[tuple[dict[str, str | None], _Endpoint, str | None]] = []
    errors: list[str] = []
    truncated = False
    successful_endpoints = 0
    for endpoint in endpoints:
        api_prefix: str | None = None
        if not endpoint.podman_binary and not endpoint.crictl_binary:
            api_prefix, error = _api_prefix(endpoint)
            if error or api_prefix is None:
                errors.append(error or f"The local {endpoint.runtime} API version was unavailable.")
                continue
        items, error, endpoint_truncated = _read_container_list(endpoint, api_prefix)
        truncated |= endpoint_truncated
        if error:
            errors.append(error)
            continue
        successful_endpoints += 1
        collected.extend((item, endpoint, api_prefix) for item in items)

    needle = query.strip().casefold()
    filtered = [
        entry for entry in collected
        if not needle or any(
            needle in str(entry[0].get(field, "")).casefold()
            for field in ("container_id", "name", "image", "state", "status")
        )
    ]
    filtered.sort(key=lambda entry: (
        str(entry[0]["runtime"]),
        str(entry[0]["scope"]),
        str(entry[0]["name"]).casefold(),
        str(entry[0]["container_id"]),
    ))
    containers = [
        ContainerInfo(
            runtime=str(item["runtime"]),
            scope=str(item["scope"]),
            container_id=str(item["container_id"]),
            name=str(item["name"]),
            image=str(item["image"]),
            state=str(item["state"]),
            status=str(item["status"]),
            created_at=item["created_at"],
            identity_token=(
                _issue_token(endpoint, api_prefix, item)
                if endpoint.runtime in ACTION_RUNTIMES else None
            ),
        )
        for item, endpoint, api_prefix in filtered[:limit]
    ]
    truncated |= len(filtered) > limit
    messages = errors[:4]
    if errors and successful_endpoints:
        messages.append("Some local container engines could not be queried.")
    if truncated:
        messages.append("The container inventory was capped by scan, response-size, or result limits.")
    return ContainerListResponse(
        success=successful_endpoints > 0,
        total_containers=len(filtered),
        returned_containers=len(containers),
        containers=containers,
        limit=limit,
        truncated=truncated,
        partial=bool(errors) or truncated,
        message=" ".join(messages) or None,
    )


def _token_record(identity_token: str) -> tuple[_TokenRecord | None, str | None]:
    if not isinstance(identity_token, str) or not 32 <= len(identity_token) <= 100:
        return None, "A fresh identity token from list_containers is required."
    with _TOKEN_LOCK:
        _prune_tokens_locked()
        record = _TOKENS.get(identity_token)
    if record is None:
        return None, "The container identity token is unknown or expired; list containers again."
    return record, None


def _read_target(record: _TokenRecord) -> tuple[_ContainerTarget | None, str | None]:
    if record.endpoint.runtime not in ACTION_RUNTIMES:
        return None, "Container actions are unavailable for read-only CRI inventory entries."
    if record.endpoint.podman_binary:
        output, error, truncated = _run_podman(
            record.endpoint,
            ["container", "inspect", record.container_id],
        )
        if error:
            return None, "The local Podman container identity could not be revalidated."
        if truncated:
            return None, "The local Podman inspect response exceeded the output limit."
        try:
            payload = json.loads(output or "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, "Local Podman returned malformed JSON while revalidating the container."
        if isinstance(payload, list):
            payload = payload[0] if payload else None
    else:
        if record.api_prefix is None:
            return None, "The local container API version is unavailable."
        escaped_id = quote(record.container_id, safe="")
        result = _request(record.endpoint, "GET", f"{record.api_prefix}/containers/{escaped_id}/json")
        payload, error = _decode_json(result)
        if error:
            return None, error
    if not isinstance(payload, dict):
        return None, "Container engine returned an unexpected inspect response."
    current_id = _container_id(payload.get("Id", payload.get("ID")))
    if current_id != record.container_id:
        return None, "The inspected container no longer matches the fresh identity token."
    raw_name = payload.get("Name")
    name = _clean_text(raw_name.lstrip("/") if isinstance(raw_name, str) else "", 128)
    config = payload.get("Config")
    image_value = config.get("Image") if isinstance(config, dict) else None
    # Podman reports the configured tag in Config.Image and the immutable
    # image ID in the top-level Image field. Prefer an ID so the identity
    # check below can compare it with the one captured at confirmation.
    if _image_id(image_value) is None:
        image_value = payload.get("Image") or payload.get("ImageName")
    image = _clean_text(image_value or payload.get("ImageName"), 256)
    if not name:
        name = record.name
    if not image:
        image = record.image
    state_data = payload.get("State")
    state = _clean_text(state_data.get("Status"), 32).casefold() if isinstance(state_data, dict) else "unknown"
    current_image_id = _image_id(image)
    recorded_image_id = _image_id(record.image)
    same_image = image == record.image or (
        current_image_id is not None
        and recorded_image_id is not None
        and current_image_id.removeprefix("sha256:") == recorded_image_id.removeprefix("sha256:")
    )
    if name != record.name or not same_image:
        return None, "The container name or image changed since it was listed; list containers again before acting."

    environment_values: dict[str, str] = {}
    raw_environment = config.get("Env") if isinstance(config, dict) else None
    if isinstance(raw_environment, list):
        for entry in raw_environment:
            if isinstance(entry, str) and "=" in entry:
                key, value = entry.split("=", 1)
                if ENVIRONMENT_NAME_RE.fullmatch(key):
                    environment_values[key] = value
    configured_user = config.get("User") if isinstance(config, dict) else None
    if not isinstance(configured_user, str):
        configured_user = None
    host_config = payload.get("HostConfig")
    read_only = host_config.get("ReadonlyRootfs") if isinstance(host_config, dict) else None
    if not isinstance(read_only, bool):
        read_only = None
    security_options = host_config.get("SecurityOpt") if isinstance(host_config, dict) else None
    no_new_privileges: bool | None = None
    if isinstance(security_options, list) and all(isinstance(option, str) for option in security_options):
        no_new_privileges = any(
            option.casefold() in {"no-new-privileges", "no-new-privileges:true"}
            for option in security_options
        )
    raw_capabilities = host_config.get("CapDrop") if isinstance(host_config, dict) else None
    normalized_capabilities: list[str] = []
    if isinstance(raw_capabilities, list):
        for capability in raw_capabilities:
            if isinstance(capability, str):
                normalized = capability.upper()
                if normalized.startswith("CAP_"):
                    normalized = normalized[4:]
                normalized_capabilities.append(normalized)
    network_settings = payload.get("NetworkSettings")
    raw_networks = network_settings.get("Networks") if isinstance(network_settings, dict) else None
    network_names = tuple(
        sorted(
            name
            for name in raw_networks
            if isinstance(name, str) and _clean_text(name, 128)
        )
    ) if isinstance(raw_networks, dict) else ()
    network_mode = host_config.get("NetworkMode") if isinstance(host_config, dict) else None
    if not isinstance(network_mode, str):
        network_mode = None
    return _ContainerTarget(
        record.endpoint,
        record.api_prefix,
        current_id,
        name,
        image,
        state,
        tuple(sorted(environment_values.items())),
        configured_user,
        read_only,
        no_new_privileges,
        tuple(sorted(set(normalized_capabilities))),
        network_names,
        network_mode,
    ), None


def _container_create_config_matches(
    target: _ContainerCreateTarget,
    observed: _ContainerTarget,
) -> bool:
    if target.network_name is not None and target.network_name not in observed.network_names:
        if observed.network_mode not in {target.network_name, target.network_id}:
            return False
    observed_environment = dict(observed.environment_variables)
    if any(observed_environment.get(name) != value for name, value in target.environment_variables):
        return False
    if target.container_user is not None and observed.container_user != target.container_user:
        return False
    if target.read_only_rootfs and observed.read_only_rootfs is not True:
        return False
    if target.no_new_privileges and observed.no_new_privileges is not True:
        return False
    if target.dropped_capabilities and not set(target.dropped_capabilities).issubset(observed.dropped_capabilities):
        return False
    return True


def container_action_confirmation_details(
    action: str,
    identity_token: str,
) -> tuple[_ContainerTarget | None, str | None]:
    if not isinstance(action, str) or action not in CONTAINER_ACTIONS:
        return None, "Choose one supported container action: start, stop, restart, pause, unpause, or remove."
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, error
    if record.endpoint.runtime not in ACTION_RUNTIMES:
        return None, "Container actions are unavailable for read-only CRI inventory entries."
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.expires_at <= time.monotonic():
            _TOKENS.pop(identity_token, None)
            return None, "The container identity token expired; list containers again."
        if record.claimed:
            return None, "This container token is already being used for an action. List containers again."
        record.claimed = True
    target, error = _read_target(record)
    if error or target is None:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
        return None, error
    return target, None


def _action_path(action: str, container_id: str) -> tuple[str, str]:
    escaped_id = quote(container_id, safe="")
    if action == "remove":
        return "DELETE", f"/containers/{escaped_id}?force=false&v=false"
    suffix = f"?t={CONTAINER_STOP_GRACE_SECONDS}" if action in {"stop", "restart"} else ""
    return "POST", f"/containers/{escaped_id}/{action}{suffix}"


def perform_container_action(
    action: str,
    identity_token: str,
    *,
    confirmed: bool,
) -> ContainerActionResponse:
    safe_action = action if isinstance(action, str) and action in CONTAINER_ACTIONS else "start"
    record, error = _token_record(identity_token)
    if error or record is None:
        return ContainerActionResponse(
            success=False,
            action=safe_action,
            message=error or "A fresh container token is required.",
        )
    if record.endpoint.runtime not in ACTION_RUNTIMES:
        return ContainerActionResponse(
            success=False,
            action=safe_action,
            user_confirmed=confirmed,
            message="Container actions are unavailable for read-only CRI inventory entries.",
        )
    response_info = {
        "action": safe_action,
        "runtime": record.endpoint.runtime,
        "scope": record.endpoint.scope,
        "container_id": record.container_id,
        "name": record.name,
    }
    try:
        if not confirmed:
            return ContainerActionResponse(
                success=False,
                **response_info,
                message="Explicit client confirmation is required; no container action was run.",
            )
        if not isinstance(action, str) or action not in CONTAINER_ACTIONS:
            return ContainerActionResponse(success=False, **response_info, message="Unsupported container action.")
        if not record.claimed:
            return ContainerActionResponse(success=False, **response_info, message="The action was not confirmed from a fresh container identity token.")
        target, error = _read_target(record)
        if error or target is None:
            return ContainerActionResponse(success=False, **response_info, user_confirmed=True, message=error or "Container identity could not be revalidated.")
        if target.endpoint.podman_binary:
            podman_action = "rm" if safe_action == "remove" else safe_action
            arguments = ["container", podman_action]
            if safe_action in {"stop", "restart"}:
                arguments.extend(["--time", str(CONTAINER_STOP_GRACE_SECONDS)])
            arguments.append(record.container_id)
            timeout_seconds = (
                CONTAINER_ACTION_TIMEOUT_SECONDS
                if safe_action in {"stop", "restart"}
                else API_TIMEOUT_SECONDS
            )
            _output, error, output_truncated = _run_podman(
                target.endpoint,
                arguments,
                timeout_seconds=timeout_seconds,
            )
            if error or output_truncated:
                message = (
                    "The local Podman action may have completed before timing out; verify current state before retrying."
                    if error and "timed out" in error.casefold()
                    else "The local Podman runtime rejected or could not confirm the action; verify current state before retrying."
                )
                return ContainerActionResponse(success=False, **response_info, user_confirmed=True, message=message)
        else:
            if target.api_prefix is None:
                return ContainerActionResponse(success=False, **response_info, user_confirmed=True, message="The local container API version is unavailable.")
            method, path = _action_path(safe_action, record.container_id)
            timeout_seconds = (
                CONTAINER_ACTION_TIMEOUT_SECONDS
                if safe_action in {"stop", "restart"}
                else API_TIMEOUT_SECONDS
            )
            result = _request(
                target.endpoint,
                method,
                f"{target.api_prefix}{path}",
                timeout_seconds=timeout_seconds,
            )
            if result.error:
                return ContainerActionResponse(success=False, **response_info, user_confirmed=True, message=result.error)
            if result.status not in {200, 201, 204, 304}:
                return ContainerActionResponse(
                    success=False,
                    **response_info,
                    user_confirmed=True,
                    message=f"The local {target.endpoint.runtime} engine rejected the action with HTTP {result.status}; verify current state before retrying.",
                )
        return ContainerActionResponse(
            success=True,
            **response_info,
            user_confirmed=True,
            message=(
                "The container was removed; attached and named volumes were not requested for removal."
                if safe_action == "remove" else "The container action was accepted. Call list_containers to verify the current state."
            ),
        )
    finally:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
