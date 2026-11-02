from __future__ import annotations

from wayland_mcp.tools import firewalld_rich_protocol_control as protocol_control


def test_protocol_name_generates_one_exact_typed_rich_rule(monkeypatch):
    monkeypatch.setattr(protocol_control.socket, "getprotobyname", lambda name: 6 if name == "tcp" else 17)

    request, error = protocol_control._normalize_request(
        "add",
        "runtime",
        "public",
        "tcp",
        source_cidr="192.0.2.0/24",
        destination_cidr="198.51.100.7/32",
        verdict="drop",
        log_enabled=True,
        log_prefix="mcp test",
        log_level="info",
        audit_enabled=True,
        priority=-10,
    )

    assert error is None
    assert request is not None
    assert request[3:5] == ("tcp", 6)
    assert request[-1] == (
        'rule family="ipv4" priority="-10" source address="192.0.2.0/24" '
        'destination address="198.51.100.7/32" protocol value="6" '
        'log prefix="mcp test" level="info" limit value="1/m" '
        'audit limit value="1/m" drop'
    )


def test_numeric_protocol_is_bounded_to_the_ip_protocol_field():
    request, error = protocol_control._normalize_request(
        "add", "permanent", "public", "255",
    )
    assert error is None
    assert request is not None and request[4] == 255
    assert request[-1] == 'rule protocol value="255" accept'

    request, error = protocol_control._normalize_request(
        "add", "permanent", "public", "256",
    )
    assert request is None
    assert "0 through 255" in (error or "")


def test_source_and_destination_cidrs_must_share_an_address_family():
    request, error = protocol_control._normalize_request(
        "add",
        "runtime",
        "public",
        "6",
        source_cidr="192.0.2.0/24",
        destination_cidr="2001:db8::/32",
    )
    assert request is None
    assert error == "source_cidr and destination_cidr must use the same IP version."
