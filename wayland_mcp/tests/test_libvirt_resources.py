from __future__ import annotations

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
