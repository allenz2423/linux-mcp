from __future__ import annotations

import asyncio
from pathlib import Path

from mcp.server.mcpserver import Elicit

from wayland_mcp import server
from wayland_mcp.models import RadioDeviceActionConfirmation
from wayland_mcp.tools import network_control, radios


def test_capture_interface_uses_socket_interface_index(monkeypatch, tmp_path):
    monkeypatch.setattr(network_control.socket, "if_nametoindex", lambda name: 7)
    monkeypatch.setattr(
        network_control,
        "_read_sysfs_value",
        lambda path: {
            "address": "00:11:22:33:44:55",
            "mtu": "1500",
            "flags": "0x1003",
        }[Path(path).name],
    )
    monkeypatch.setattr(network_control, "SYS_CLASS_NET", tmp_path)

    snapshot, error = network_control.capture_interface("eth0")

    assert error is None
    assert snapshot is not None
    assert snapshot.index == 7
    assert snapshot.administrative_up


def test_radio_inventory_uses_names_from_scandir_entries(monkeypatch, tmp_path):
    (tmp_path / "rfkill0").mkdir()
    monkeypatch.setattr(radios, "RFKILL_ROOT", tmp_path)
    monkeypatch.setattr(
        radios,
        "_read_radio",
        lambda index: (
            radios._Radio(
                index=index,
                name="Wireless adapter",
                radio_type="wlan",
                soft_blocked=False,
                hard_blocked=False,
                sysfs_path=str(tmp_path / f"rfkill{index}"),
            ),
            None,
        ),
    )
    monkeypatch.setattr(radios, "find_session_binary", lambda *_args, **_kwargs: None)

    result = radios.list_radio_devices()

    assert result.success
    assert result.total_radios == 1
    assert result.devices[0].radio_index == 0
    assert result.devices[0].name == "Wireless adapter"


def test_radio_action_confirmation_returns_typed_elicitation(monkeypatch):
    target = radios.RadioDeviceTarget(
        radio_index=1,
        name="phy0",
        radio_type="wlan",
        soft_blocked=False,
        hard_blocked=False,
        confirmation_token="state-token",
    )
    monkeypatch.setattr(
        server,
        "_radio_action_confirmation_details",
        lambda action, identity_token: (target, None),
    )

    result = asyncio.run(server._confirm_radio_device_action("unblock", "identity-token"))

    assert isinstance(result, Elicit)
    assert result.schema is RadioDeviceActionConfirmation
    assert 'Confirm unblock for rfkill device 1, name "phy0", type wlan?' in result.message
    assert "Current state: software-unblocked." in result.message
    assert "State token: state-token." in result.message
