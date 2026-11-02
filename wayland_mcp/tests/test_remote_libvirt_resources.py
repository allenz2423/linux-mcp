from __future__ import annotations

from wayland_mcp.tools import remote_libvirt_resources


def test_remote_network_inventory_keeps_nonempty_table_headers(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(_endpoint, arguments, **kwargs):
        observed["arguments"] = arguments
        observed.update(kwargs)
        return (
            " Name       State    Autostart   Persistent\n"
            "----------------------------------------\n"
            " audit-net  inactive no          yes\n",
            None,
            False,
        )

    monkeypatch.setattr(remote_libvirt_resources, "remote_virsh_available", lambda: True)
    monkeypatch.setattr(remote_libvirt_resources, "_run_remote_virsh", fake_run)

    result = remote_libvirt_resources.list_remote_libvirt_networks(
        "qemu+ssh://test.example/system"
    )

    assert result.success is True
    assert result.returned_networks == 1
    assert result.networks[0].name == "audit-net"
    assert observed["quiet"] is False
    assert observed["readonly"] is True
