from __future__ import annotations

import pytest

from wayland_mcp.tools import route_control
from wayland_mcp.tools.network_control import InterfaceSnapshot


DESTINATION = "198.51.100.0/24"


@pytest.mark.parametrize(
    ("action", "routes", "expected_existing"),
    [
        ("add", [], None),
        (
            "remove",
            [
                route_control.RouteEntry(
                    destination=DESTINATION,
                    gateway=None,
                    interface="lo",
                    table=100,
                    metric=7,
                    protocol=4,
                    route_type="unicast",
                    scope="link",
                    preferred_source=None,
                    preference=None,
                    unsupported_attributes=False,
                )
            ],
            route_control.RouteEntry(
                destination=DESTINATION,
                gateway=None,
                interface="lo",
                table=100,
                metric=7,
                protocol=4,
                route_type="unicast",
                scope="link",
                preferred_source=None,
                preference=None,
                unsupported_attributes=False,
            ),
        ),
    ],
)
def test_resolves_exact_route_targets(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    routes: list[route_control.RouteEntry],
    expected_existing: route_control.RouteEntry | None,
) -> None:
    snapshot = InterfaceSnapshot("lo", 1, "00:00:00:00:00:00", 65536, True, True)
    monkeypatch.setattr(route_control, "iproute2_route_control_available", lambda: True)
    monkeypatch.setattr(route_control, "capture_interface", lambda _name: (snapshot, None))
    monkeypatch.setattr(route_control, "_read_exact_routes", lambda _spec: (routes, None))

    target, error = route_control.route_action_confirmation_details(
        action, DESTINATION, "", "lo", 100, 7
    )

    assert error is None
    assert target is not None
    assert target.spec.action == action
    assert target.existing_route == expected_existing


def test_treats_an_uninitialized_routing_table_as_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = InterfaceSnapshot("lo", 1, "00:00:00:00:00:00", 65536, True, True)
    spec = route_control.RouteSpec(
        action="add",
        family="ipv4",
        family_flag="-4",
        destination=DESTINATION,
        gateway=None,
        interface="lo",
        table=100,
        metric=7,
        interface_snapshot=snapshot,
    )
    monkeypatch.setattr(route_control, "find_session_binary", lambda *_args: "/usr/bin/ip")
    monkeypatch.setattr(route_control, "get_sanitized_env", lambda env: env)
    monkeypatch.setattr(
        route_control,
        "run_bounded_command",
        lambda *_args, **_kwargs: (None, "Error: ipv4: FIB table does not exist.\nDump terminated", False),
    )

    routes, error = route_control._read_exact_routes(spec)

    assert error is None
    assert routes == []


def test_accepts_dynamic_linkdown_flag_but_rejects_unsupported_route_flags() -> None:
    snapshot = InterfaceSnapshot("lo", 1, "00:00:00:00:00:00", 65536, True, True)
    spec = route_control.RouteSpec(
        action="remove",
        family="ipv4",
        family_flag="-4",
        destination=DESTINATION,
        gateway=None,
        interface="lo",
        table=100,
        metric=7,
        interface_snapshot=snapshot,
    )
    base = {
        "dst": DESTINATION,
        "dev": "lo",
        "protocol": "static",
        "scope": "link",
        "metric": 7,
    }

    linkdown = route_control._parse_route_entry({**base, "flags": ["linkdown"]}, spec)
    onlink = route_control._parse_route_entry({**base, "flags": ["onlink"]}, spec)

    assert linkdown is not None and not linkdown.unsupported_attributes
    assert onlink is not None and onlink.unsupported_attributes
