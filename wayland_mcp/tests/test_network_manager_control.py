from __future__ import annotations

from wayland_mcp.tools import network_manager_control as control


TARGET_UUID = "f0562773-085e-30ae-af6d-83309779c585"
OTHER_UUID = "4bcee369-b714-4a85-827d-0f6b0e3901be"


def test_exact_profile_reader_selects_from_valid_networkmanager_profile_list(monkeypatch):
    output = (
        f"{OTHER_UUID}:br-existing:bridge:--:no\n"
        f"{TARGET_UUID}:Wired\\: connection 2:802-3-ethernet:enp42s0:yes\n"
    )
    calls = []

    def command(_binary, arguments, _env, **kwargs):
        calls.append((arguments, kwargs))
        return output, None, False

    monkeypatch.setattr(control, "_command", command)

    profile, error = control._read_exact_profile("/usr/bin/nmcli", {}, TARGET_UUID)

    assert error is None
    assert profile is not None
    assert profile.uuid == TARGET_UUID
    assert profile.name == "Wired: connection 2"
    assert profile.connection_type == "802-3-ethernet"
    assert profile.device == "enp42s0"
    assert profile.autoconnect is True
    arguments = calls[0][0]
    assert arguments[-2:] == ["connection", "show"]
    assert arguments[arguments.index("--fields") + 1] == control.PROFILE_FIELDS


def test_exact_profile_reader_fails_closed_on_duplicate_uuid(monkeypatch):
    row = f"{TARGET_UUID}:Wired connection 2:802-3-ethernet:enp42s0:yes"
    monkeypatch.setattr(
        control,
        "_command",
        lambda *_args, **_kwargs: (f"{row}\n{row}\n", None, False),
    )

    profile, error = control._read_exact_profile("/usr/bin/nmcli", {}, TARGET_UUID)

    assert profile is None
    assert error == "NetworkManager returned a duplicate profile UUID."
