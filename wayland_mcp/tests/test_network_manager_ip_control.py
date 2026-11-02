from __future__ import annotations

from wayland_mcp.tools import network_manager_ip_control as ip_control


PROFILE_UUID = "4bcee369-b714-4a85-827d-0f6b0e3901be"


def _patch_nmcli(monkeypatch, output):
    calls = []

    def run(command, _env, **kwargs):
        calls.append((command, kwargs))
        return output, None, False

    monkeypatch.setattr(ip_control, "find_session_binary", lambda *_args: "/usr/bin/nmcli")
    monkeypatch.setattr(ip_control, "get_sanitized_env", lambda env: env)
    monkeypatch.setattr(ip_control, "run_bounded_command", run)
    return calls


def test_ip_profile_reader_parses_nmcli_multiline_selected_properties(monkeypatch):
    output = (
        f"connection.uuid:{PROFILE_UUID}\n"
        "connection.id:Bridge\\: lab\n"
        "connection.type:bridge\n"
        "ipv4.method:manual\n"
        "ipv4.addresses:192.0.2.2/24\n"
        "ipv4.gateway:192.0.2.1\n"
    )
    calls = _patch_nmcli(monkeypatch, output)

    response = ip_control.get_network_manager_profile_ip(PROFILE_UUID, "ipv4")

    assert response.success
    assert response.profile_name == "Bridge: lab"
    assert response.method == "manual"
    assert response.addresses == ["192.0.2.2/24"]
    assert response.gateway == "192.0.2.1"
    command = calls[0][0]
    assert command[command.index("--mode") + 1] == "multiline"


def test_ip_profile_reader_parses_ipv6_colons_in_multiline_values(monkeypatch):
    output = (
        f"connection.uuid:{PROFILE_UUID}\n"
        "connection.id:Audit bridge\n"
        "connection.type:bridge\n"
        "ipv6.method:manual\n"
        "ipv6.addresses:2001:db8::20/64\n"
        "ipv6.gateway:\n"
    )
    _patch_nmcli(monkeypatch, output)

    response = ip_control.get_network_manager_profile_ip(PROFILE_UUID, "ipv6")

    assert response.success
    assert response.method == "manual"
    assert response.addresses == ["2001:db8::20/64"]
    assert response.gateway is None


def test_ip_profile_reader_fails_closed_on_missing_property(monkeypatch):
    output = (
        f"connection.uuid:{PROFILE_UUID}\n"
        "connection.id:Bridge\n"
        "connection.type:bridge\n"
        "ipv4.method:disabled\n"
        "ipv4.addresses:\n"
    )
    _patch_nmcli(monkeypatch, output)

    response = ip_control.get_network_manager_profile_ip(PROFILE_UUID, "ipv4")

    assert not response.success
    assert response.message == "NetworkManager did not return exactly one complete saved profile row."
