from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

from wayland_mcp.tools import systemd_network_device_control as control
from wayland_mcp.tools.filesystem_write import TextFileCreationTarget


def _patch_environment(monkeypatch, states=()):
    monkeypatch.setattr(control.os, "geteuid", lambda: 0)
    monkeypatch.setattr(control, "_safe_systemd_network_directory", lambda: (1, 2, 0o40755, 1, 0, 0, 0, 0, 0))
    monkeypatch.setattr(control, "_collect_network_state", lambda: (tuple(states), None))
    monkeypatch.setattr(control, "_networkd_virtual_devices", lambda _states: {})
    monkeypatch.setattr(control, "NETDEV_SYSFS_ROOT", Path("/definitely-not-a-live-network-interface-directory"))

    def file_target(path, content):
        payload = content.encode("utf-8")
        return TextFileCreationTarget(
            path=Path(path),
            content_sha256=hashlib.sha256(payload).hexdigest(),
            byte_count=len(payload),
            parent_device=1,
            parent_inode=2,
        ), None

    monkeypatch.setattr(control, "text_file_creation_confirmation_details", file_target)


def test_netdev_creation_generates_typed_vlan_profile(monkeypatch):
    _patch_environment(monkeypatch)

    target, error = control.systemd_netdev_creation_confirmation_details(
        "vlan42.netdev", "vlan42", "vlan", vlan_id=42,
    )

    assert error is None
    assert target is not None
    assert target.kind == "vlan"
    assert target.configured_settings == ("Id",)
    assert target.content == "[NetDev]\nName=vlan42\nKind=vlan\n\n[VLAN]\nId=42\n"


def test_netdev_creation_rejects_invalid_kind_settings_and_vlan_id(monkeypatch):
    _patch_environment(monkeypatch)

    target, error = control.systemd_netdev_creation_confirmation_details(
        "vlan42.netdev", "vlan42", "vlan", vlan_id=4095,
    )

    assert target is None
    assert error is not None and "1 through 4094" in error

    target, error = control.systemd_netdev_creation_confirmation_details(
        "bridge0.netdev", "bridge0", "bridge", bond_mode="active-backup",
    )

    assert target is None
    assert error is not None and "do not apply to bridge" in error


def test_netdev_creation_rechecks_state_after_confirmation(monkeypatch):
    _patch_environment(monkeypatch)
    target, error = control.systemd_netdev_creation_confirmation_details(
        "br-test.netdev", "br-test", "bridge", bridge_stp=True,
    )
    assert error is None and target is not None

    changed_state = SimpleNamespace(
        path="/usr/lib/systemd/network/10-existing.netdev",
        source="usr_lib",
        filename="10-existing.netdev",
        profile_filename=None,
        file_type="netdev",
        is_drop_in=False,
        identity=(1, 2, 3),
        sha256="changed-state",
    )
    scans = iter([((), None), ((changed_state,), None)])
    monkeypatch.setattr(control, "_collect_network_state", lambda: next(scans))
    writes = []
    monkeypatch.setattr(control, "create_text_file", lambda *args, **kwargs: writes.append(args))

    response = control.create_systemd_netdev_profile(
        "br-test.netdev",
        "br-test",
        "bridge",
        bridge_stp=True,
        confirmed=True,
        confirmed_filename=target.filename,
        confirmed_name=target.name,
        confirmed_kind=target.kind,
        state_token=target.state_token,
    )

    assert not response.success
    assert not writes
    assert "changed after confirmation" in response.message
