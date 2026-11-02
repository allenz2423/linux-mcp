from __future__ import annotations

import base64

from dbus_next import Variant

from wayland_mcp.tools import network_manager_vpn_control as vpn_control


PRIVATE_KEY = base64.b64encode(bytes(range(32))).decode("ascii")
PUBLIC_KEY = base64.b64encode(bytes(range(32, 64))).decode("ascii")
PRESHARED_KEY = base64.b64encode(bytes(reversed(range(32)))).decode("ascii")


def test_wireguard_settings_map_to_an_inactive_native_networkmanager_profile():
    payload = (
        "[Interface]\n"
        f"PrivateKey = {PRIVATE_KEY}\n"
        "Address = 10.8.0.2/24, 2001:db8::2/64\n"
        "Address = 10.8.0.3/24\n"
        "DNS = 1.1.1.1, 2001:4860:4860::8888\n"
        "MTU = 1360\n"
        "ListenPort = 51820\n"
        "FwMark = 0x1a\n"
        "\n[Peer]\n"
        f"PublicKey = {PUBLIC_KEY}\n"
        f"PresharedKey = {PRESHARED_KEY}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "Endpoint = [2001:db8::1]:51820\n"
        "PersistentKeepalive = 25\n"
    ).encode()

    settings = vpn_control._wireguard_connection_settings(
        payload,
        "work-vpn",
        "01234567-89ab-cdef-0123-456789abcdef",
        "wg1234567890",
    )

    connection = settings["connection"]
    wireguard = settings["wireguard"]
    ipv4 = settings["ipv4"]
    ipv6 = settings["ipv6"]
    assert connection["id"] == Variant("s", "work-vpn")
    assert connection["type"] == Variant("s", "wireguard")
    assert connection["interface-name"] == Variant("s", "wg1234567890")
    assert connection["autoconnect"] == Variant("b", False)
    assert wireguard["private-key"] == Variant("s", PRIVATE_KEY)
    assert wireguard["listen-port"] == Variant("u", 51820)
    assert wireguard["fwmark"] == Variant("u", 26)
    assert wireguard["mtu"] == Variant("u", 1360)

    peers = wireguard["peers"].value
    assert len(peers) == 1
    assert peers[0]["public-key"] == Variant("s", PUBLIC_KEY)
    assert peers[0]["preshared-key"] == Variant("s", PRESHARED_KEY)
    assert peers[0]["endpoint"] == Variant("s", "[2001:db8::1]:51820")
    assert peers[0]["allowed-ips"] == Variant("as", ["0.0.0.0/0", "::/0"])
    assert peers[0]["persistent-keepalive"] == Variant("u", 25)

    assert ipv4["method"] == Variant("s", "manual")
    assert ipv4["address-data"].signature == "aa{sv}"
    assert ipv4["address-data"].value == [
        {"address": Variant("s", "10.8.0.2"), "prefix": Variant("u", 24)},
        {"address": Variant("s", "10.8.0.3"), "prefix": Variant("u", 24)},
    ]
    assert ipv4["dns-data"] == Variant("as", ["1.1.1.1"])
    assert ipv6["method"] == Variant("s", "manual")
    assert ipv6["address-data"].value == [
        {"address": Variant("s", "2001:db8::2"), "prefix": Variant("u", 64)},
    ]
    assert ipv6["dns-data"] == Variant("as", ["2001:4860:4860::8888"])


def test_wireguard_settings_without_addresses_disable_ip_and_zero_keepalive():
    payload = (
        "[Interface]\n"
        f"PrivateKey = {PRIVATE_KEY}\n"
        "FwMark = off\n"
        "\n[Peer]\n"
        f"PublicKey = {PUBLIC_KEY}\n"
        "AllowedIPs = 198.51.100.8/32\n"
        "PersistentKeepalive = 0\n"
    ).encode()

    settings = vpn_control._wireguard_connection_settings(
        payload,
        "dns-only-vpn",
        "01234567-89ab-cdef-0123-456789abcdef",
        "wg1234567890",
    )

    wireguard = settings["wireguard"]
    assert wireguard["fwmark"] == Variant("u", 0)
    assert "persistent-keepalive" not in wireguard["peers"].value[0]
    assert settings["ipv4"]["method"] == Variant("s", "disabled")
    assert settings["ipv6"]["method"] == Variant("s", "disabled")
    assert "dns-data" not in settings["ipv4"]
    assert "dns-data" not in settings["ipv6"]


def test_wireguard_rejects_dns_for_an_ip_family_without_an_interface_address():
    payload = (
        "[Interface]\n"
        f"PrivateKey = {PRIVATE_KEY}\n"
        "Address = 10.8.0.2/24\n"
        "DNS = 2001:db8::53\n"
        "\n[Peer]\n"
        f"PublicKey = {PUBLIC_KEY}\n"
        "AllowedIPs = 198.51.100.8/32\n"
    ).encode()

    assert vpn_control._validate_wireguard_config(payload) == (
        "Each WireGuard DNS address family must also have a configured Interface Address; "
        "NetworkManager cannot apply DNS to a disabled IP family."
    )


def test_wireguard_legacy_dns_fallback_uses_networkmanager_dbus_types():
    settings = {
        "ipv4": {"dns-data": Variant("as", ["192.0.2.53", "198.51.100.53"])},
        "ipv6": {"dns-data": Variant("as", ["2001:db8::53"])},
    }

    legacy = vpn_control._legacy_wireguard_dns_settings(settings)

    assert legacy["ipv4"]["dns"] == Variant(
        "au", [int.from_bytes(bytes((192, 0, 2, 53)), "big"), int.from_bytes(bytes((198, 51, 100, 53)), "big")]
    )
    assert legacy["ipv6"]["dns"] == Variant("aay", [bytes.fromhex("20010db8000000000000000000000053")])
    assert "dns-data" not in legacy["ipv4"]
    assert "dns-data" not in legacy["ipv6"]
