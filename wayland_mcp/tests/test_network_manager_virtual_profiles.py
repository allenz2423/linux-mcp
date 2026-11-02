from __future__ import annotations

from wayland_mcp.tools import network_manager_virtual_profiles as profiles


BRIDGE_UUID = "4bcee369-b714-4a85-827d-0f6b0e3901be"
ETHERNET_UUID = "f0562773-085e-30ae-af6d-83309779c585"


def _patch_profile_commands(monkeypatch, interface_names):
    inventory = (
        f"{BRIDGE_UUID}:br-existing:bridge:--:no\n"
        f"{ETHERNET_UUID}:Wired connection:802-3-ethernet:--:yes\n"
    )
    calls = []

    def run(command, _env, **kwargs):
        calls.append((command, kwargs))
        if "--get-values" in command:
            profile_uuid = command[-1]
            if profile_uuid not in interface_names:
                return None, "unknown UUID", False
            value = interface_names[profile_uuid]
            return (f"{value}\n" if value else ""), None, False
        return inventory, None, False

    monkeypatch.setattr(profiles, "run_bounded_command", run)
    return calls


def test_profile_inventory_reads_interface_binding_with_profile_property_query(monkeypatch):
    calls = _patch_profile_commands(
        monkeypatch,
        {BRIDGE_UUID: "br-existing", ETHERNET_UUID: "enp42s0"},
    )

    inventory, error = profiles._read_profiles("/usr/bin/nmcli", {})

    assert error is None
    assert inventory is not None
    assert [profile.interface_name for profile in inventory] == ["br-existing", "enp42s0"]
    list_command = calls[0][0]
    assert list_command[list_command.index("--fields") + 1] == "UUID,NAME,TYPE,DEVICE,AUTOCONNECT"
    assert "connection.interface-name" not in list_command
    assert len(calls) == 3


def test_profile_inventory_fails_closed_when_interface_binding_cannot_be_read(monkeypatch):
    _patch_profile_commands(monkeypatch, {BRIDGE_UUID: "br-existing"})

    inventory, error = profiles._read_profiles("/usr/bin/nmcli", {})

    assert inventory is None
    assert error == "A NetworkManager profile interface binding could not be read."


def test_virtual_profile_snapshot_detects_inactive_saved_interface_binding(monkeypatch):
    _patch_profile_commands(
        monkeypatch,
        {BRIDGE_UUID: "br-collision", ETHERNET_UUID: "enp42s0"},
    )
    monkeypatch.setattr(profiles, "_interface_index", lambda _name: (None, None))

    snapshot, error = profiles._read_snapshot(
        "bridge", "new-bridge", "br-collision", None, "/usr/bin/nmcli", {}
    )

    assert snapshot is None
    assert error == "A NetworkManager profile already targets that interface name."


def test_port_membership_reader_parses_nmcli_multiline_selected_properties(monkeypatch):
    output = (
        f"connection.uuid:{ETHERNET_UUID}\n"
        "connection.interface-name:enp42s0\n"
        "connection.autoconnect:no\n"
        "connection.controller:br-test\n"
        "connection.port-type:bridge\n"
    )
    calls = []

    def run(command, _env, **kwargs):
        calls.append((command, kwargs))
        return output, None, False

    monkeypatch.setattr(profiles, "run_bounded_command", run)

    membership, error = profiles._read_port_membership("/usr/bin/nmcli", {}, ETHERNET_UUID)

    assert error is None
    assert membership[:5] == (
        ETHERNET_UUID,
        "enp42s0",
        "no",
        "br-test",
        "bridge",
    )
    assert membership[5:] == ("",) * len(profiles.PORT_MEMBERSHIP_FIELDS[5:])
    command = calls[0][0]
    assert command[command.index("--mode") + 1] == "multiline"


def test_membership_add_accepts_only_default_ip_settings():
    defaults = tuple(
        profiles.PORT_DEFAULT_IP_SETTINGS.get(field, "")
        for field in profiles.PORT_MEMBERSHIP_FIELDS[5:]
    )
    membership = (ETHERNET_UUID, "enp42s0", "no", "", "", *defaults)

    assert profiles._default_port_ip_settings(membership)
    assert not profiles._default_port_ip_settings(
        membership[:5] + ("manual",) + membership[6:]
    )


def test_port_profile_device_check_uses_nmcli_managed_property(monkeypatch):
    calls = []

    def run(command, _env, **kwargs):
        calls.append((command, kwargs))
        return "ethernet\nyes\n", None, False

    monkeypatch.setattr(profiles, "run_bounded_command", run)

    device_type, error = profiles._read_ethernet_device_type(
        "/usr/bin/nmcli", {}, "enp42s0"
    )

    assert error is None
    assert device_type == "ethernet"
    assert calls[0][0][calls[0][0].index("--get-values") + 1] == "GENERAL.TYPE,GENERAL.NM-MANAGED"
