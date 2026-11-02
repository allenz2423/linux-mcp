from __future__ import annotations

import json
from pathlib import Path

import pytest

from wayland_mcp.tools import containers


def _action_fixtures(runtime: str) -> tuple[containers._TokenRecord, containers._ContainerTarget]:
    endpoint = containers._Endpoint(
        runtime=runtime,
        scope="system",
        socket_path=Path("/tmp/docker.sock") if runtime == "docker" else None,
        podman_binary="/usr/bin/podman" if runtime == "podman" else None,
    )
    container_id = "a" * 64
    record = containers._TokenRecord(
        endpoint=endpoint,
        api_prefix="/v1.45" if runtime == "docker" else None,
        container_id=container_id,
        name="test-container",
        image="sha256:" + "b" * 64,
        expires_at=0.0,
        claimed=True,
    )
    target = containers._ContainerTarget(
        endpoint=endpoint,
        api_prefix=record.api_prefix,
        container_id=container_id,
        name=record.name,
        image=record.image,
        state="running",
    )
    return record, target


@pytest.mark.parametrize("action", ["stop", "restart"])
def test_docker_graceful_actions_allow_the_configured_stop_timeout(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    record, target = _action_fixtures("docker")
    monkeypatch.setattr(containers, "_token_record", lambda _token: (record, None))
    monkeypatch.setattr(containers, "_read_target", lambda _record: (target, None))
    observed: dict[str, object] = {}

    def request(endpoint, method: str, path: str, **kwargs):
        observed.update(endpoint=endpoint, method=method, path=path, **kwargs)
        return containers._APIResult(status=204, body=b"")

    monkeypatch.setattr(containers, "_request", request)

    result = containers.perform_container_action(action, "fresh-token", confirmed=True)

    assert result.success is True
    assert observed["method"] == "POST"
    assert observed["path"] == f"/v1.45/containers/{record.container_id}/{action}?t=10"
    assert observed["timeout_seconds"] == containers.CONTAINER_ACTION_TIMEOUT_SECONDS
    assert observed["timeout_seconds"] > containers.CONTAINER_STOP_GRACE_SECONDS


@pytest.mark.parametrize("action", ["stop", "restart"])
def test_podman_graceful_actions_allow_the_configured_stop_timeout(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    record, target = _action_fixtures("podman")
    monkeypatch.setattr(containers, "_token_record", lambda _token: (record, None))
    monkeypatch.setattr(containers, "_read_target", lambda _record: (target, None))
    observed: dict[str, object] = {}

    def run_podman(endpoint, arguments: list[str], **kwargs):
        observed.update(endpoint=endpoint, arguments=arguments, **kwargs)
        return "", None, False

    monkeypatch.setattr(containers, "_run_podman", run_podman)

    result = containers.perform_container_action(action, "fresh-token", confirmed=True)

    assert result.success is True
    assert observed["arguments"] == [
        "container",
        action,
        "--time",
        str(containers.CONTAINER_STOP_GRACE_SECONDS),
        record.container_id,
    ]
    assert observed["timeout_seconds"] == containers.CONTAINER_ACTION_TIMEOUT_SECONDS
    assert observed["timeout_seconds"] > containers.CONTAINER_STOP_GRACE_SECONDS


def test_podman_inspect_uses_immutable_image_id_over_configured_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image_id = "a" * 64
    container_id = "b" * 64
    tag = "localhost/test-image:latest"
    record = containers._TokenRecord(
        endpoint=containers._Endpoint("podman", "user", podman_binary="/usr/bin/podman"),
        api_prefix=None,
        container_id=container_id,
        name="test-container",
        image="sha256:" + image_id,
        expires_at=0.0,
    )
    inspect = {
        "Id": container_id,
        "Image": image_id,
        "ImageName": tag,
        "Name": "test-container",
        "Config": {"Image": tag, "User": "65534:65534", "Env": []},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "SecurityOpt": ["no-new-privileges"],
        },
        "State": {"Status": "created"},
        "NetworkSettings": {"Networks": {}},
    }

    monkeypatch.setattr(
        containers,
        "_run_podman",
        lambda *_args, **_kwargs: (json.dumps([inspect]), None, False),
    )

    target, error = containers._read_target(record)

    assert error is None
    assert target is not None
    assert target.image == image_id
    assert target.container_user == "65534:65534"
    assert target.read_only_rootfs is True
    assert target.no_new_privileges is True


def test_podman_container_token_uses_image_id_from_list_item() -> None:
    image_id = "a" * 64
    endpoint = containers._Endpoint("podman", "user", podman_binary="/usr/bin/podman")
    item, error = containers._parse_list_item(
        {
            "Id": "b" * 64,
            "Names": ["test-container"],
            "Image": "localhost/test-image:latest",
            "ImageID": image_id,
            "State": "created",
        },
        endpoint,
    )

    assert error is None
    assert item is not None
    assert item["image"] == "localhost/test-image:latest"
    token = containers._issue_token(endpoint, None, item)
    try:
        record, error = containers._token_record(token)
        assert error is None
        assert record is not None
        assert record.image == image_id
    finally:
        with containers._TOKEN_LOCK:
            containers._TOKENS.pop(token, None)
