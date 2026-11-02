from __future__ import annotations

import pytest

from wayland_mcp.models import NetworkManagerProfileRoute
from wayland_mcp.tools import network_manager_profile_routes as route_tools
from wayland_mcp.tools.network_manager_profile_routes import (
    _normalize_request,
    _parse_routes,
    _route_value,
)


def test_parses_saved_ipv4_routes_and_attributes() -> None:
    routes = _parse_routes(
        "192.0.2.0/24 192.0.2.1 77, 198.51.100.0/24 table=100 mtu=1400",
        "ipv4",
    )

    assert routes is not None
    assert routes[0].payload() == {
        "destination": "192.0.2.0/24",
        "gateway": "192.0.2.1",
        "metric": 77,
        "attributes": [],
    }
    assert routes[1].attributes == ("table=100", "mtu=1400")


def test_parses_saved_ipv6_routes_and_empty_route_lists() -> None:
    routes = _parse_routes("2001:db8:1::/64 fe80::1 5", "ipv6")

    assert routes is not None
    assert routes[0].destination == "2001:db8:1::/64"
    assert routes[0].gateway == "fe80::1"
    assert _parse_routes("--", "ipv4") == ()


def test_reads_multiline_nmcli_fields_with_escaped_ipv6_colons(monkeypatch: pytest.MonkeyPatch) -> None:
    profile_uuid = "01234567-89ab-cdef-0123-456789abcdef"
    output = (
        f"connection.uuid:{profile_uuid}\n"
        "connection.id:home\n"
        "connection.type:802-3-ethernet\n"
        r"ipv6.routes:2001\:db8\:1\:\:/64 fe80\:\:1 5" + "\n"
    )
    monkeypatch.setattr(route_tools.sys, "platform", "linux")
    monkeypatch.setattr(route_tools, "find_session_binary", lambda *_args: "/usr/bin/nmcli")
    monkeypatch.setattr(route_tools, "run_bounded_command", lambda *_args, **_kwargs: (output, None, False))

    snapshot, error = route_tools._read_snapshot(profile_uuid, "ipv6")

    assert error is None
    assert snapshot is not None
    assert snapshot.routes[0].destination == "2001:db8:1::/64"
    assert snapshot.routes[0].gateway == "fe80::1"


@pytest.mark.parametrize(
    ("raw", "family"),
    [
        ("192.0.2.0/24 2001:db8::1", "ipv4"),
        ("2001:db8::/64 192.0.2.1", "ipv6"),
        ("default 192.0.2.1", "ipv4"),
        ("192.0.2.0/24 invalid gateway", "ipv4"),
        ("192.0.2.0/24,", "ipv4"),
    ],
)
def test_fails_closed_on_malformed_saved_route(raw: str, family: str) -> None:
    assert _parse_routes(raw, family) is None  # type: ignore[arg-type]


def test_normalizes_simple_route_request_and_cli_value() -> None:
    normalized = _normalize_request(
        "01234567-89ab-cdef-0123-456789abcdef",
        "ipv4",
        "add",
        "192.0.2.42/24",
        "192.0.2.1",
        42,
    )

    uuid, family, action, route, error = normalized
    assert error is None
    assert uuid == "01234567-89ab-cdef-0123-456789abcdef"
    assert family == "ipv4"
    assert action == "add"
    assert route is not None
    assert route.destination == "192.0.2.0/24"
    assert _route_value(route) == "192.0.2.0/24 192.0.2.1 42"


def test_treats_networkmanagers_zero_next_hop_as_an_omitted_gateway() -> None:
    direct_route = route_tools._Route("192.0.2.0/24", "0.0.0.0", 10)

    assert route_tools._gateway_matches(direct_route, None)
    assert _route_value(route_tools._Route("192.0.2.0/24", None, 10)) == "192.0.2.0/24 0.0.0.0 10"


def test_rejects_metric_without_gateway_and_cross_family_route() -> None:
    no_gateway_metric = _normalize_request(
        "01234567-89ab-cdef-0123-456789abcdef", "ipv4", "add", "192.0.2.0/24", None, 10
    )
    cross_family = _normalize_request(
        "01234567-89ab-cdef-0123-456789abcdef", "ipv4", "add", "2001:db8::/64", None, None
    )

    assert "metric" in (no_gateway_metric[-1] or "")
    assert "IPv4" in (cross_family[-1] or "")


def test_confirmed_add_updates_only_the_saved_route_list(monkeypatch: pytest.MonkeyPatch) -> None:
    profile_uuid = "01234567-89ab-cdef-0123-456789abcdef"
    before = route_tools._Snapshot(profile_uuid, "home", "802-3-ethernet", "ipv4", ())
    added = route_tools._Route("192.0.2.0/24", "192.0.2.1", 42)
    after = route_tools._Snapshot(profile_uuid, "home", "802-3-ethernet", "ipv4", (added,))
    current = {"snapshot": before}
    captured: dict[str, object] = {}

    def read_snapshot(_uuid: object, _family: object):
        return current["snapshot"], None

    def run_command(arguments, *_args, **_kwargs):
        captured["arguments"] = arguments
        current["snapshot"] = after
        return "", None, False

    monkeypatch.setattr(route_tools, "_read_snapshot", read_snapshot)
    monkeypatch.setattr(route_tools, "find_session_binary", lambda *_args: "/usr/bin/nmcli")
    monkeypatch.setattr(route_tools, "run_bounded_command", run_command)
    details, error = route_tools.network_manager_profile_route_confirmation_details(
        profile_uuid, "ipv4", "add", "192.0.2.0/24", "192.0.2.1", 42
    )
    assert error is None and details is not None

    response = route_tools.perform_network_manager_profile_route_action(
        profile_uuid,
        "ipv4",
        "add",
        "192.0.2.0/24",
        "192.0.2.1",
        42,
        confirmed=True,
        confirmed_profile_uuid=profile_uuid,
        confirmed_phrase=details["confirmation_phrase"],
    )

    assert response.success
    assert response.routes == [NetworkManagerProfileRoute(destination="192.0.2.0/24", gateway="192.0.2.1", metric=42)]
    assert captured["arguments"][-2:] == ["+ipv4.routes", "192.0.2.0/24 192.0.2.1 42"]
