from __future__ import annotations

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
