from __future__ import annotations

import pytest
from dbus_next.errors import InterfaceNotFoundError, InvalidMemberNameError

from wayland_mcp.portal import PortalError, RemoteDesktopPortal, _PortalBus, _parse_portal_introspection


def test_portal_introspection_drops_invalid_properties_and_keeps_methods():
    xml = """<node>
      <interface name="org.freedesktop.portal.RemoteDesktop">
        <property name="power-saver-enabled" type="b" access="read"/>
        <method name="NotifyKeyboardKeysym">
          <arg name="session_handle" type="o" direction="in"/>
          <arg name="options" type="a{sv}" direction="in"/>
          <arg name="keysym" type="i" direction="in"/>
          <arg name="state" type="u" direction="in"/>
        </method>
      </interface>
    </node>"""

    node = _parse_portal_introspection(xml)

    assert node.interfaces[0].properties == []
    assert [method.name for method in node.interfaces[0].methods] == ["NotifyKeyboardKeysym"]


def test_portal_introspection_still_rejects_invalid_method_names():
    xml = """<node>
      <interface name="org.freedesktop.portal.RemoteDesktop">
        <method name="notify-keyboard">
          <arg name="state" type="u" direction="in"/>
        </method>
      </interface>
    </node>"""

    with pytest.raises(InvalidMemberNameError):
        _parse_portal_introspection(xml)


@pytest.mark.asyncio
async def test_missing_remote_desktop_interface_returns_clear_portal_error(monkeypatch):
    portal = RemoteDesktopPortal()

    async def missing_interface(*_args, **_kwargs):
        raise InterfaceNotFoundError("not exposed")

    monkeypatch.setattr(portal, "proxy", missing_interface)

    with pytest.raises(PortalError, match="does not expose RemoteDesktop"):
        await portal.ensure_session()


@pytest.mark.asyncio
async def test_portal_response_preserves_bounded_backend_rejection_reason():
    bus = _PortalBus()
    bus._early_responses["/request"] = (2, {"error": "prompt executable unavailable"})

    with pytest.raises(PortalError, match="prompt executable unavailable"):
        await bus.wait_response("/request")


@pytest.mark.asyncio
async def test_input_session_requests_both_devices_once_and_is_reported_for_fresh_observation(monkeypatch):
    portal = RemoteDesktopPortal()

    class Remote:
        def __init__(self):
            self.select_types = []
            self.create_calls = 0

        async def call_create_session(self, _options):
            self.create_calls += 1
            return "create"

        async def call_select_devices(self, _session, options):
            self.select_types.append(options["types"].value)
            return "select"

        async def call_start(self, _session, _parent, _options):
            return "start"

    remote = Remote()

    async def fake_proxy(_interface_name, _path="/org/freedesktop/portal/desktop"):
        return remote

    async def fake_wait_response(request_path, timeout=120.0):
        if request_path == "create":
            return {"session_handle": "/org/freedesktop/portal/desktop/session/1_20/session_test"}
        if request_path == "start":
            return {"devices": 3}
        return {}

    monkeypatch.setattr(portal, "proxy", fake_proxy)
    monkeypatch.setattr(portal, "wait_response", fake_wait_response)

    first = await portal.ensure_session()
    keyboard = await portal.ensure_session()
    pointer = await portal.ensure_session(pointer=True)

    assert first[0] == keyboard[0] == pointer[0]
    assert first[2] == keyboard[2] == pointer[2] == 3
    assert first[3] is True
    assert keyboard[3] is False
    assert pointer[3] is False
    assert remote.select_types == [3]
    assert remote.create_calls == 1


@pytest.mark.asyncio
async def test_combined_input_session_fails_if_portal_grants_only_one_device(monkeypatch):
    portal = RemoteDesktopPortal()

    class Remote:
        async def call_create_session(self, _options):
            return "create"

        async def call_select_devices(self, _session, options):
            assert options["types"].value == 3
            return "select"

        async def call_start(self, _session, _parent, _options):
            return "start"

    remote = Remote()

    async def fake_proxy(_interface_name, _path="/org/freedesktop/portal/desktop"):
        return remote

    async def fake_wait_response(request_path, timeout=120.0):
        if request_path == "create":
            return {"session_handle": "/org/freedesktop/portal/desktop/session/1_20/session_test"}
        if request_path == "start":
            return {"devices": 1}
        return {}

    monkeypatch.setattr(portal, "proxy", fake_proxy)
    monkeypatch.setattr(portal, "wait_response", fake_wait_response)

    with pytest.raises(PortalError, match="both keyboard and pointer"):
        await portal.ensure_session()
