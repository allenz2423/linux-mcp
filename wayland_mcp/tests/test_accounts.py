from __future__ import annotations

import pytest

from wayland_mcp.tools import accounts


@pytest.mark.parametrize(
    ("kind", "identity", "database", "output"),
    [
        ("user", "alice", "passwd", "alice:x:1000:1000:Alice:/home/alice:/bin/sh\n"),
        ("group", "staff", "group", "staff:x:1000:alice\n"),
    ],
)
def test_lookup_nss_identity_uses_getent_database_name(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    identity: str,
    database: str,
    output: str,
) -> None:
    calls: list[list[str]] = []

    monkeypatch.setattr(accounts, "get_sanitized_env", lambda _env=None: {"PATH": "/usr/bin"})
    monkeypatch.setattr(accounts, "find_session_binary", lambda *_args: "/usr/bin/getent")

    def fake_run(command, *_args, **_kwargs):
        calls.append(command)
        return output, None, False

    monkeypatch.setattr(accounts, "run_bounded_command", fake_run)

    result = accounts.lookup_nss_identity(kind, identity)

    assert result.success is True
    assert result.found is True
    assert calls == [["/usr/bin/getent", database, identity]]
