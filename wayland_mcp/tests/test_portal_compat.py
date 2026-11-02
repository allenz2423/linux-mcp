from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from dbus_next.errors import DBusError, InterfaceNotFoundError, InvalidAddressError, InvalidMemberNameError

from wayland_mcp.portal import (
    PortalError,
    RemoteDesktopPortal,
    ScreenshotPortal,
    StartupScreenCastSession,
    _PortalBus,
    _parse_portal_introspection,
)


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
async def test_screenshot_method_dbus_error_becomes_a_bounded_portal_error(monkeypatch):
    portal = ScreenshotPortal()

    class ScreenshotInterface:
        async def call_screenshot(self, *_args):
            raise DBusError("org.freedesktop.DBus.Error.Failed", "Unavailable screenshot target 8")

    async def fake_proxy(*_args, **_kwargs):
        return ScreenshotInterface()

    monkeypatch.setattr(portal, "proxy", fake_proxy)

    with pytest.raises(PortalError, match="The screenshot portal rejected the request.*Unavailable screenshot target 8"):
        await portal.capture(scope="window")


@pytest.mark.asyncio
async def test_missing_session_bus_address_becomes_a_bounded_portal_error(monkeypatch):
    portal = _PortalBus()
    monkeypatch.setattr("wayland_mcp.portal.get_sanitized_env", lambda: {})

    def missing_bus_address(**_kwargs):
        raise InvalidAddressError("DBUS_SESSION_BUS_ADDRESS not set")

    monkeypatch.setattr("wayland_mcp.portal.MessageBus", missing_bus_address)

    with pytest.raises(PortalError, match="The session D-Bus is unavailable"):
        await portal.connect()

    assert portal.bus is None


@pytest.mark.asyncio
async def test_portal_bus_negotiates_unix_file_descriptors(monkeypatch):
    created_options = []

    class FakeBus:
        connected = True

        async def connect(self):
            return self

        def add_message_handler(self, _handler):
            pass

    def fake_message_bus(**options):
        created_options.append(options)
        return FakeBus()

    monkeypatch.setattr("wayland_mcp.portal.get_sanitized_env", lambda: {
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/test-session-bus",
    })
    monkeypatch.setattr("wayland_mcp.portal.MessageBus", fake_message_bus)

    connected = await _PortalBus().connect()

    assert connected.connected is True
    assert created_options == [{
        "bus_address": "unix:path=/tmp/test-session-bus",
        "negotiate_unix_fd": True,
    }]


@pytest.mark.asyncio
async def test_startup_combines_input_and_screen_permissions_and_never_prompts_again(monkeypatch):
    portal = RemoteDesktopPortal()

    class Remote:
        def __init__(self):
            self.create_calls = 0
            self.device_types = []
            self.sessions = []

        async def call_create_session(self, _options):
            self.create_calls += 1
            return "create"

        async def call_select_devices(self, session, options):
            self.sessions.append(session)
            self.device_types.append(options["types"].value)
            return "devices"

        async def call_start(self, session, _parent, _options):
            self.sessions.append(session)
            return "start"

    class ScreenCast:
        def __init__(self):
            self.selected_sessions = []

        async def call_select_sources(self, session, options):
            self.selected_sessions.append(session)
            assert options["types"].value == 1
            assert options["multiple"].value is False
            return "sources"

        async def call_open_pipe_wire_remote(self, session, _options):
            assert session == "/org/freedesktop/portal/desktop/session/startup"
            read_fd, write_fd = os.pipe()
            os.close(write_fd)
            return read_fd

    remote = Remote()
    screencast = ScreenCast()

    async def fake_proxy(interface_name, _path="/org/freedesktop/portal/desktop"):
        return remote if interface_name == "org.freedesktop.portal.RemoteDesktop" else screencast

    async def fake_wait_response(request_path, timeout=120.0):
        if request_path == "create":
            return {"session_handle": "/org/freedesktop/portal/desktop/session/startup"}
        if request_path == "start":
            return {
                "devices": 7,
                "streams": [(42, {
                    "position": (0, 0),
                    "logical_size": (1920, 1080),
                    "source_type": 1,
                    "pipewire-serial": 987,
                })],
            }
        return {}

    monkeypatch.setattr(portal, "proxy", fake_proxy)
    monkeypatch.setattr(portal, "wait_response", fake_wait_response)
    monkeypatch.setattr(portal, "portal_methods", lambda _name: _ready({"NotifyPointerMotionAbsolute"}))
    monkeypatch.setattr("wayland_mcp.portal.get_sanitized_env", lambda: {"WAYLAND_DISPLAY": "wayland-test", "PATH": "/usr/bin"})

    task = portal.start_startup_permission_request()
    assert task is not None
    await task

    keyboard_session = await portal.ensure_session()
    touch_session = await portal.ensure_touch_session()
    absolute_pointer_session = await portal.ensure_absolute_pointer_session()
    assert remote.create_calls == 1
    assert remote.device_types == [7]
    assert screencast.selected_sessions == ["/org/freedesktop/portal/desktop/session/startup"]
    assert keyboard_session[2] == 7 and keyboard_session[3] is False
    assert touch_session.granted_devices == 7 and touch_session.newly_authorized is False
    assert absolute_pointer_session.stream_id == 42

    closed_sessions = []

    async def record_close(path):
        closed_sessions.append(path)

    monkeypatch.setattr(portal, "_close_session_path", record_close)
    await portal.close_touch_session()
    await portal.close_absolute_pointer_session()
    assert closed_sessions == []
    assert await portal.ensure_touch_session() == touch_session

    monkeypatch.setattr("wayland_mcp.portal.shutil.which", lambda *_args, **_kwargs: "/usr/bin/gst-launch-1.0")
    monkeypatch.setattr(
        "wayland_mcp.portal.asyncio.create_subprocess_exec",
        lambda *command, **kwargs: _pipewire_process(command, kwargs),
    )
    image, monitor = await portal.capture_startup_screen_frame()
    assert image == b"startup-authorized-frame"
    assert monitor.pipewire_serial == 987


async def _pipewire_process(command, kwargs):
    assert command[0] == "/usr/bin/gst-launch-1.0"
    assert "pipewiresrc" in command
    assert "fd=" + str(kwargs["pass_fds"][0]) in command
    assert "target-object=987" in command
    assert kwargs["close_fds"] is True
    return _FakePipewireProcess()


class _PipewireOutput:
    def __init__(self, payload=b"startup-authorized-frame"):
        self.read_calls = 0
        self.payload = payload

    async def read(self, _limit):
        self.read_calls += 1
        return self.payload if self.read_calls == 1 else b""


class _FakePipewireProcess:
    def __init__(self):
        self.returncode = None
        self.stdout = _PipewireOutput()
        self.killed = False

    async def wait(self):
        self.returncode = 0
        return 0

    def kill(self):
        self.killed = True
        self.returncode = -9


@pytest.mark.asyncio
async def test_startup_screencast_frame_enforces_output_limit(monkeypatch):
    portal = RemoteDesktopPortal()
    portal._startup_only = True
    portal._startup_status = "ready"
    portal._startup_monitor_session = StartupScreenCastSession(
        path="/org/freedesktop/portal/desktop/session/screen",
        stream_id=42,
        position=(0, 0),
        size=(2, 2),
        pipewire_serial=987,
    )

    class ScreenCast:
        async def call_open_pipe_wire_remote(self, _session, _options):
            read_fd, write_fd = os.pipe()
            os.close(write_fd)
            return read_fd

    portal._screen_cast_interface = ScreenCast()
    process = _FakePipewireProcess()
    process.stdout = _PipewireOutput(payload=b"too-large")

    async def fake_create_process(*_command, **_kwargs):
        return process

    monkeypatch.setattr("wayland_mcp.portal.shutil.which", lambda *_args, **_kwargs: "/usr/bin/gst-launch-1.0")
    monkeypatch.setattr("wayland_mcp.portal.get_sanitized_env", lambda: {"PATH": "/usr/bin"})
    monkeypatch.setattr("wayland_mcp.portal.MAX_SCREENSHOT_BYTES", 4)
    monkeypatch.setattr("wayland_mcp.portal.asyncio.create_subprocess_exec", fake_create_process)

    with pytest.raises(PortalError, match="exceeds the 32 MiB output limit"):
        await portal.capture_startup_screen_frame()
    assert process.killed


async def _ready(value):
    return value


@pytest.mark.asyncio
async def test_startup_denial_prevents_tool_time_reprompt(monkeypatch):
    portal = RemoteDesktopPortal()

    class Remote:
        def __init__(self):
            self.create_calls = 0

        async def call_create_session(self, _options):
            self.create_calls += 1
            return "create"

        async def call_select_devices(self, _session, _options):
            return "devices"

        async def call_start(self, _session, _parent, _options):
            return "start"

    remote = Remote()

    async def fake_proxy(interface_name, _path="/org/freedesktop/portal/desktop"):
        if interface_name == "org.freedesktop.portal.RemoteDesktop":
            return remote
        return SimpleNamespace(call_select_sources=_fake_select_sources)

    async def fake_wait_response(request_path, timeout=120.0):
        if request_path == "create":
            return {"session_handle": "/org/freedesktop/portal/desktop/session/denied"}
        if request_path == "start":
            return {"devices": 0}
        return {}

    monkeypatch.setattr(portal, "proxy", fake_proxy)
    monkeypatch.setattr(portal, "wait_response", fake_wait_response)
    monkeypatch.setattr("wayland_mcp.portal.get_sanitized_env", lambda: {"WAYLAND_DISPLAY": "wayland-test"})

    task = portal.start_startup_permission_request()
    assert task is not None
    await task

    with pytest.raises(PortalError, match="not granted during MCP startup"):
        await portal.ensure_session()
    assert remote.create_calls == 1


async def _fake_select_sources(*_args, **_kwargs):
    return "sources"


@pytest.mark.asyncio
async def test_startup_falls_back_when_touchscreen_device_type_is_unsupported(monkeypatch):
    portal = RemoteDesktopPortal()

    class Remote:
        def __init__(self):
            self.create_calls = 0
            self.device_types = []
            self.start_calls = 0

        async def call_create_session(self, _options):
            self.create_calls += 1
            return f"create-{self.create_calls}"

        async def call_select_devices(self, _session, options):
            device_types = options["types"].value
            self.device_types.append(device_types)
            return f"devices-{device_types}"

        async def call_start(self, _session, _parent, _options):
            self.start_calls += 1
            return f"start-{self.start_calls}"

    class ScreenCast:
        def __init__(self):
            self.sessions = []

        async def call_create_session(self, _options):
            return "screen-create"

        async def call_select_sources(self, session, _options):
            self.sessions.append(session)
            return "screen-sources"

        async def call_start(self, _session, _parent, _options):
            return "screen-start"

    remote = Remote()
    screencast = ScreenCast()

    async def fake_proxy(interface_name, _path="/org/freedesktop/portal/desktop"):
        return remote if interface_name == "org.freedesktop.portal.RemoteDesktop" else screencast

    async def fake_wait_response(request_path, timeout=120.0):
        if request_path.startswith("create-"):
            index = int(request_path.rsplit("-", 1)[-1])
            return {"session_handle": f"/org/freedesktop/portal/desktop/session/session{index}"}
        if request_path == "screen-create":
            return {"session_handle": "/org/freedesktop/portal/desktop/session/screen"}
        if request_path == "devices-7":
            raise PortalError("The desktop portal rejected the request. unsupported device type requested")
        if request_path == "start-1":
            return {"devices": 3}
        if request_path == "screen-start":
            return {
                "streams": [(84, {
                    "position": (0, 0),
                    "logical_size": (1920, 1080),
                    "source_type": 1,
                })],
            }
        return {}

    monkeypatch.setattr(portal, "proxy", fake_proxy)
    monkeypatch.setattr(portal, "wait_response", fake_wait_response)
    monkeypatch.setattr(portal, "portal_methods", lambda _name: _ready({"NotifyPointerMotionAbsolute"}))
    monkeypatch.setattr("wayland_mcp.portal.get_sanitized_env", lambda: {"WAYLAND_DISPLAY": "wayland-test"})

    task = portal.start_startup_permission_request()
    assert task is not None
    await task

    keyboard_session = await portal.ensure_session()
    assert keyboard_session[2] == 3
    assert remote.device_types == [7, 3]
    assert remote.create_calls == 2
    assert remote.start_calls == 1
    assert screencast.sessions == ["/org/freedesktop/portal/desktop/session/screen"]
    assert portal.startup_capability_state()["monitor_stream"] is True
    with pytest.raises(PortalError, match="No matching touchscreen/monitor permission"):
        await portal.ensure_touch_session()
    assert remote.create_calls == 2


@pytest.mark.asyncio
async def test_startup_uses_remote_desktop_only_when_combined_screencast_session_is_rejected(monkeypatch):
    portal = RemoteDesktopPortal()

    class Remote:
        def __init__(self):
            self.create_calls = 0
            self.device_types = []
            self.start_calls = 0

        async def call_create_session(self, _options):
            self.create_calls += 1
            return f"create-{self.create_calls}"

        async def call_select_devices(self, _session, options):
            self.device_types.append(options["types"].value)
            return f"devices-{len(self.device_types)}"

        async def call_start(self, _session, _parent, _options):
            self.start_calls += 1
            return "remote-start"

    class ScreenCast:
        def __init__(self):
            self.select_calls = 0
            self.sessions = []

        async def call_create_session(self, _options):
            return "screen-create"

        async def call_select_sources(self, session, _options):
            self.select_calls += 1
            self.sessions.append(session)
            return "sources" if "/session/session" in session else "screen-sources"

        async def call_start(self, _session, _parent, _options):
            return "screen-start"

        async def call_open_pipe_wire_remote(self, _session, _options):
            read_fd, write_fd = os.pipe()
            os.close(write_fd)
            return read_fd

    remote = Remote()
    screencast = ScreenCast()

    async def fake_proxy(interface_name, _path="/org/freedesktop/portal/desktop"):
        return remote if interface_name == "org.freedesktop.portal.RemoteDesktop" else screencast

    async def fake_wait_response(request_path, timeout=120.0):
        if request_path.startswith("create-"):
            index = int(request_path.rsplit("-", 1)[-1])
            return {"session_handle": f"/org/freedesktop/portal/desktop/session/session{index}"}
        if request_path == "sources":
            raise PortalError("The desktop portal rejected the request. Invalid session")
        if request_path == "screen-create":
            return {"session_handle": "/org/freedesktop/portal/desktop/session/screen"}
        if request_path == "screen-sources":
            return {}
        if request_path == "remote-start":
            return {"devices": 7}
        if request_path == "screen-start":
            return {"streams": [(42, {
                "position": (0, 0),
                "logical_size": (1920, 1080),
                "source_type": 1,
                "pipewire-serial": 987,
            })]}
        return {}

    monkeypatch.setattr(portal, "proxy", fake_proxy)
    monkeypatch.setattr(portal, "wait_response", fake_wait_response)
    monkeypatch.setattr("wayland_mcp.portal.get_sanitized_env", lambda: {"WAYLAND_DISPLAY": "wayland-test"})

    closed_sessions = []

    async def record_close(path):
        closed_sessions.append(path)

    monkeypatch.setattr(portal, "_close_session_path", record_close)

    task = portal.start_startup_permission_request()
    assert task is not None
    await task

    session = await portal.ensure_session()
    assert session[2] == 7
    assert remote.create_calls == 2
    assert remote.device_types == [7, 7]
    assert remote.start_calls == 1
    assert screencast.select_calls == 2
    assert screencast.sessions == [
        "/org/freedesktop/portal/desktop/session/session1",
        "/org/freedesktop/portal/desktop/session/screen",
    ]
    assert closed_sessions == ["/org/freedesktop/portal/desktop/session/session1"]
    monkeypatch.setattr("wayland_mcp.portal.shutil.which", lambda *_args, **_kwargs: "/usr/bin/gst-launch-1.0")
    monkeypatch.setattr(
        "wayland_mcp.portal.asyncio.create_subprocess_exec",
        lambda *command, **kwargs: _pipewire_process(command, kwargs),
    )
    image, monitor = await portal.capture_startup_screen_frame()
    assert image == b"startup-authorized-frame"
    assert monitor.path == "/org/freedesktop/portal/desktop/session/screen"
    assert monitor.pipewire_serial == 987
    assert remote.create_calls == 2


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
