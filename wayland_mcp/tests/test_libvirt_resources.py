from __future__ import annotations

from wayland_mcp.tools import libvirt_resources
from wayland_mcp.tools.libvirt_resources import _table_rows


def test_table_rows_accepts_quiet_empty_inventory() -> None:
    rows, truncated, error = _table_rows(
        "",
        {"name", "state", "autostart", "persistent"},
    )

    assert rows == []
    assert truncated is False
    assert error is None


def test_table_rows_parses_header_and_rows() -> None:
    rows, truncated, error = _table_rows(
        " Name       State    Autostart   Persistent\n"
        "----------------------------------------\n"
        " default    active   yes         yes\n",
        {"name", "state", "autostart", "persistent"},
    )

    assert error is None
    assert truncated is False
    assert rows == [
        {"name": "default", "state": "active", "autostart": "yes", "persistent": "yes"}
    ]


def test_read_table_preserves_virsh_headers_for_nonempty_tables(monkeypatch) -> None:
    observed_command: list[str] = []

    def fake_run(command, _env, **_kwargs):
        observed_command.extend(command)
        return (
            " Name       State    Autostart   Persistent\n"
            "----------------------------------------\n"
            " audit-net  inactive no          yes\n",
            None,
            False,
        )

    monkeypatch.setattr(libvirt_resources, "virsh_environment", lambda: {})
    monkeypatch.setattr(libvirt_resources, "find_session_binary", lambda *_args: "/usr/bin/virsh")
    monkeypatch.setattr(libvirt_resources, "run_bounded_command", fake_run)

    rows, error, truncated = libvirt_resources._read_table(
        "session",
        ["net-list", "--all", "--table"],
        {"name", "state", "autostart", "persistent"},
        "test libvirt inventory",
        "/usr/bin/virsh",
        {},
    )

    assert error is None
    assert truncated is False
    assert rows == [{"name": "audit-net", "state": "inactive", "autostart": "no", "persistent": "yes"}]
    assert "--quiet" not in observed_command
