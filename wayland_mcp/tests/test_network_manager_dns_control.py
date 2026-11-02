from __future__ import annotations

from wayland_mcp.models import NetworkManagerDNSFamilySettings, NetworkManagerProfileDNSResponse
from wayland_mcp.tools import network_manager_dns_control as dns_control


PROFILE_UUID = "4bcee369-b714-4a85-827d-0f6b0e3901be"


def _profile(method: str) -> NetworkManagerProfileDNSResponse:
    return NetworkManagerProfileDNSResponse(
        success=True,
        profile_uuid=PROFILE_UUID,
        profile_name="Temporary bridge",
        ipv4=NetworkManagerDNSFamilySettings(method=method),
        ipv6=NetworkManagerDNSFamilySettings(method="disabled"),
    )


def _patch_snapshot(monkeypatch, profile):
    monkeypatch.setattr(dns_control, "get_sanitized_env", lambda env: env)
    monkeypatch.setattr(dns_control, "find_session_binary", lambda *_args: "/usr/bin/nmcli")
    monkeypatch.setattr(dns_control, "_profile_snapshot", lambda *_args: (profile, None))


def test_dns_configuration_rejects_disabled_family_before_confirmation(monkeypatch):
    _patch_snapshot(monkeypatch, _profile("disabled"))

    target, error = dns_control.network_manager_profile_dns_confirmation_details(
        PROFILE_UUID,
        ipv4_dns_servers=["192.0.2.53"],
    )

    assert target is None
    assert error == "IPv4 DNS settings cannot be saved while the profile IPv4 method is disabled; configure the IPv4 method first."


def test_dns_configuration_accepts_manual_family_settings_for_confirmation(monkeypatch):
    _patch_snapshot(monkeypatch, _profile("manual"))

    target, error = dns_control.network_manager_profile_dns_confirmation_details(
        PROFILE_UUID,
        ipv4_dns_servers=["192.0.2.53"],
    )

    assert error is None
    assert target is not None
    assert target.profile.ipv4 is not None
    assert target.profile.ipv4.method == "manual"
