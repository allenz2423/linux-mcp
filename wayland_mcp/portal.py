"""Small XDG portal client for consent-mediated screenshots and desktop input.

This module keeps all portal interaction behind the user's session D-Bus. It
does not use compositor-bypass injection or a browser automation protocol.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import math
import os
import secrets
import shutil
import stat
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from dbus_next import BusType, Message, MessageType, Variant
from dbus_next.aio import MessageBus
from dbus_next.errors import DBusError, InterfaceNotFoundError, InvalidAddressError
from dbus_next.introspection import Node
from dbus_next.validators import is_member_name_valid

from wayland_mcp.session import get_sanitized_env, logger

PORTAL_NAME = "org.freedesktop.portal.Desktop"
PORTAL_PATH = "/org/freedesktop/portal/desktop"
MAX_SCREENSHOT_BYTES = 32 * 1024 * 1024
PORTAL_REQUEST_TIMEOUT = 120.0


class PortalError(RuntimeError):
    """A portal method failed, timed out, or was denied by the user."""


class _PortalScreenCastSetupError(PortalError):
    """ScreenCast could not be joined to an otherwise valid RemoteDesktop session."""


@dataclass(frozen=True, slots=True)
class RemoteMonitorInputSession:
    path: str
    remote: Any
    granted_devices: int
    stream_id: int
    position: tuple[int, int]
    size: tuple[int, int]
    newly_authorized: bool
    pipewire_serial: int | None = None


@dataclass(frozen=True, slots=True)
class StartupScreenCastSession:
    path: str
    stream_id: int
    position: tuple[int, int]
    size: tuple[int, int]
    pipewire_serial: int | None = None


def _single_monitor_stream(started: dict[str, Any]) -> tuple[int, tuple[int, int], tuple[int, int], int | None] | None:
    streams = started.get("streams")
    if not isinstance(streams, (list, tuple)) or len(streams) != 1:
        return None
    stream = streams[0]
    if not isinstance(stream, (list, tuple)) or len(stream) != 2:
        return None
    stream_id, properties = stream
    if (
        not isinstance(stream_id, int) or isinstance(stream_id, bool)
        or not 0 <= stream_id <= 0xFFFFFFFF
        or not isinstance(properties, dict)
    ):
        return None
    source_type = properties.get("source_type")
    if source_type is not None and (
        not isinstance(source_type, int) or isinstance(source_type, bool) or source_type != 1
    ):
        return None

    def pair(value: Any) -> tuple[int, int] | None:
        if (
            not isinstance(value, (list, tuple)) or len(value) != 2
            or any(not isinstance(part, int) or isinstance(part, bool) for part in value)
        ):
            return None
        return int(value[0]), int(value[1])

    position = pair(properties.get("position"))
    size = pair(properties.get("logical_size", properties.get("size")))
    if (
        position is None or size is None or min(size) <= 0
        or max(size) > 32768 or any(abs(value) > 131072 for value in position)
    ):
        return None
    pipewire_serial = properties.get("pipewire-serial")
    if not isinstance(pipewire_serial, int) or isinstance(pipewire_serial, bool) or pipewire_serial < 0:
        pipewire_serial = None
    return stream_id, position, size, pipewire_serial


def _parse_portal_introspection(xml: str) -> Node:
    """Parse portal methods while discarding only invalid property declarations."""
    root = ET.fromstring(xml)
    if root.tag != "node":
        raise PortalError("The desktop portal returned an invalid interface description.")
    parents = {child: parent for parent in root.iter() for child in parent}
    for property_node in list(root.iter("property")):
        if not is_member_name_valid(property_node.get("name", "")):
            parent = parents.get(property_node)
            if parent is not None:
                parent.remove(property_node)
    return Node.from_xml(root, is_root=True)


def _unwrap(value: Any) -> Any:
    if isinstance(value, Variant):
        return _unwrap(value.value)
    if isinstance(value, dict):
        return {key: _unwrap(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_unwrap(item) for item in value)
    return value


class _PortalBus:
    def __init__(self) -> None:
        self.bus: MessageBus | None = None
        self._requests: dict[str, asyncio.Future] = {}
        self._early_responses: dict[str, tuple[int, dict[str, Any]]] = {}
        self._introspection_cache: dict[str, Node] = {}
        self._lock = asyncio.Lock()

    async def connect(self) -> MessageBus:
        if self.bus and self.bus.connected:
            return self.bus
        env = get_sanitized_env()
        address = env.get("DBUS_SESSION_BUS_ADDRESS")
        try:
            if address:
                bus = MessageBus(bus_address=address, negotiate_unix_fd=True)
            else:
                bus = MessageBus(bus_type=BusType.SESSION, negotiate_unix_fd=True)
            self.bus = await bus.connect()
        except (DBusError, InvalidAddressError, OSError, asyncio.TimeoutError) as exc:
            self.bus = None
            raise PortalError("The session D-Bus is unavailable for desktop portal access.") from exc
        self.bus.add_message_handler(self._on_message)
        return self.bus

    def _on_message(self, message: Message) -> bool:
        if (message.message_type == MessageType.SIGNAL
                and message.interface == "org.freedesktop.portal.Session"
                and message.member == "Closed"):
            self._on_session_closed(str(message.path or ""))
            return False
        if (message.message_type != MessageType.SIGNAL or
                message.interface != "org.freedesktop.portal.Request" or
                message.member != "Response" or len(message.body or []) < 2):
            return False
        path = str(message.path or "")
        code = int(message.body[0])
        results = _unwrap(message.body[1])
        if not isinstance(results, dict):
            results = {}
        waiter = self._requests.get(path)
        if waiter and not waiter.done():
            waiter.set_result((code, results))
        else:
            self._early_responses[path] = (code, results)
            if len(self._early_responses) > 32:
                self._early_responses.pop(next(iter(self._early_responses)))
        return False

    def _on_session_closed(self, _path: str) -> None:
        """Hook for portal clients that retain session handles."""

    async def proxy(self, interface_name: str, path: str = PORTAL_PATH):
        node = await self.introspection(path)
        obj = (await self.connect()).get_proxy_object(PORTAL_NAME, path, node)
        return obj.get_interface(interface_name)

    async def introspection(self, path: str = PORTAL_PATH) -> Node:
        cached = self._introspection_cache.get(path)
        if cached is not None:
            return cached
        bus = await self.connect()
        # Some portal implementations expose a hyphenated property name in
        # their root introspection XML. D-Bus properties use member-name rules,
        # so dbus-next rejects the entire XML document before we can access
        # otherwise valid portal methods. These clients use methods only; drop
        # malformed property declarations and keep method/interface validation
        # strict.
        reply = await bus.call(
            Message(
                destination=PORTAL_NAME,
                path=path,
                interface="org.freedesktop.DBus.Introspectable",
                member="Introspect",
            )
        )
        if reply is None:
            raise PortalError("The desktop portal returned no interface description.")
        if reply.message_type == MessageType.ERROR:
            raise DBusError._from_message(reply)
        if reply.message_type != MessageType.METHOD_RETURN or not reply.body or not isinstance(reply.body[0], str):
            raise PortalError("The desktop portal returned an invalid interface description.")
        introspection = _parse_portal_introspection(reply.body[0])
        self._introspection_cache[path] = introspection
        return introspection

    async def portal_interfaces(self, path: str = PORTAL_PATH) -> set[str]:
        node = await self.introspection(path)
        return {interface.name for interface in node.interfaces}

    async def wait_response(self, request_path: str, timeout: float = PORTAL_REQUEST_TIMEOUT) -> dict[str, Any]:
        async with self._lock:
            early = self._early_responses.pop(request_path, None)
            if early is not None:
                code, data = early
            else:
                future = asyncio.get_running_loop().create_future()
                self._requests[request_path] = future
                try:
                    code, data = await asyncio.wait_for(future, timeout=timeout)
                except asyncio.TimeoutError as exc:
                    raise PortalError("The desktop permission request timed out.") from exc
                finally:
                    self._requests.pop(request_path, None)
        if code != 0:
            reason = data.get("error")
            if isinstance(reason, str):
                reason = " ".join(reason.split())[:240]
            else:
                reason = ""
            if code == 1:
                message = "The desktop permission request was cancelled."
            else:
                message = "The desktop portal rejected the request."
            if reason:
                message += f" {reason}"
            raise PortalError(message)
        return data

    async def close_bus(self) -> None:
        if self.bus and self.bus.connected:
            self.bus.disconnect()
        self.bus = None


def _path_from_file_uri(uri: str) -> Path:
    parsed = urlsplit(uri)
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        raise PortalError("The screenshot portal returned a non-local file URI.")
    path = Path(unquote(parsed.path))
    if not path.is_absolute():
        raise PortalError("The screenshot portal returned an invalid file path.")
    return path


class ScreenshotPortal(_PortalBus):
    async def capture(self, *, scope: str) -> tuple[bytes, int, int]:
        if scope not in {"desktop", "window"}:
            raise PortalError("Screenshot scope must be 'desktop' or 'window'.")
        iface = await self.proxy("org.freedesktop.portal.Screenshot")
        options = {
            "handle_token": Variant("s", "wm_" + secrets.token_hex(10)),
            # The portal chooses the active window when scope is window. It
            # cannot promise an arbitrary compositor window ID.
            "target": Variant("u", 1 if scope == "desktop" else 8),
            "modal": Variant("b", True),
        }
        try:
            request_path = await iface.call_screenshot("", options)
        except DBusError as exc:
            reason = " ".join((exc.text or "").split())[:240]
            message = "The screenshot portal rejected the request."
            if reason:
                message += f" {reason}"
            raise PortalError(message) from exc
        response = await self.wait_response(request_path)
        uri = response.get("uri")
        if not isinstance(uri, str):
            raise PortalError("The screenshot portal returned no screenshot URI.")
        path = _path_from_file_uri(uri)
        fd = None
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or not 8 <= metadata.st_size <= MAX_SCREENSHOT_BYTES:
                raise PortalError("The screenshot file is empty or exceeds the 32 MiB size limit.")
            with os.fdopen(fd, "rb", closefd=True) as stream:
                fd = None
                image = stream.read(MAX_SCREENSHOT_BYTES + 1)
            if len(image) > MAX_SCREENSHOT_BYTES:
                raise PortalError("The screenshot exceeds the 32 MiB size limit.")
        except OSError as exc:
            raise PortalError("The portal screenshot file could not be read.") from exc
        finally:
            if fd is not None:
                os.close(fd)
        if not image.startswith(b"\x89PNG\r\n\x1a\n") or len(image) < 24:
            raise PortalError("The portal returned an invalid PNG screenshot.")
        width = int.from_bytes(image[16:20], "big")
        height = int.from_bytes(image[20:24], "big")
        if not (1 <= width <= 32768 and 1 <= height <= 32768):
            raise PortalError("The portal returned invalid screenshot dimensions.")
        return image, width, height


class RemoteDesktopPortal(_PortalBus):
    """Portal-approved sessions for keyboard, pointer, and touchscreen input."""

    def __init__(self) -> None:
        super().__init__()
        self._session_lock = asyncio.Lock()
        self._keyboard_session: tuple[str, Any, int] | None = None
        self._pointer_session: tuple[str, Any, int] | None = None
        self._touch_session: RemoteMonitorInputSession | None = None
        self._absolute_pointer_session: RemoteMonitorInputSession | None = None
        self._startup_monitor_session: RemoteMonitorInputSession | StartupScreenCastSession | None = None
        self._screen_cast_interface: Any | None = None
        self._startup_only = False
        self._startup_status = "not_started"
        self._startup_error: str | None = None
        self._startup_task: asyncio.Task | None = None
        self._startup_touch_unsupported = False

    def startup_capability_state(self) -> dict[str, Any]:
        """Return the process-local startup portal grants for capability reporting."""
        input_session = self._keyboard_session or self._pointer_session
        monitor_session = self._startup_monitor_session
        return {
            "managed": self._startup_only,
            "status": self._startup_status,
            "error": self._startup_error,
            "devices": int(input_session[2]) if input_session else 0,
            "touch": self._touch_session is not None,
            "absolute_pointer": self._absolute_pointer_session is not None,
            "monitor_stream": monitor_session is not None,
            "integrated_stream": bool(
                input_session is not None and monitor_session is not None
                and input_session[0] == monitor_session.path
            ),
            "touch_unsupported": self._startup_touch_unsupported,
        }

    def start_startup_permission_request(self) -> asyncio.Task | None:
        """Begin the Wayland permission flow as the server starts.

        Stdio clients can connect while the desktop consent dialog is open.
        In startup-only mode, action tools wait for this one request and never
        open another portal prompt later in the session.
        """
        if self._startup_status != "not_started":
            return self._startup_task
        self._startup_only = True
        env = get_sanitized_env()
        if not env.get("WAYLAND_DISPLAY"):
            self._startup_status = "ready"
            return None
        self._startup_status = "pending"
        self._startup_task = asyncio.create_task(self._prepare_startup_permissions())
        return self._startup_task

    async def _prepare_startup_permissions(self) -> None:
        try:
            await self._create_startup_session()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._startup_error = str(exc)[:240] or type(exc).__name__
            logger.warning("Wayland portal permissions were unavailable at MCP startup: %s", self._startup_error)
        finally:
            self._startup_status = "ready"
            self._startup_task = None

    async def _wait_for_startup_permission_request(self) -> None:
        if not self._startup_only or asyncio.current_task() is self._startup_task:
            return
        if self._startup_status == "pending" and self._startup_task is not None:
            await asyncio.shield(self._startup_task)
        if self._startup_error:
            raise PortalError(
                "Wayland portal permissions were not granted during MCP startup. Restart the MCP server to try again."
            )

    async def _create_startup_session(self) -> None:
        """Request every supported desktop input and screen permission at startup."""
        async with self._session_lock:
            if self.bus is not None and not self.bus.connected:
                self._keyboard_session = None
                self._pointer_session = None
                self._touch_session = None
                self._absolute_pointer_session = None
                self._startup_monitor_session = None
                self._screen_cast_interface = None

            remote = await self.proxy("org.freedesktop.portal.RemoteDesktop")
            try:
                screencast = await self.proxy("org.freedesktop.portal.ScreenCast")
            except InterfaceNotFoundError:
                # Keyboard and relative pointer control still work without a
                # ScreenCast interface; touch and screenshot fallback do not.
                screencast = None
            screen_cast_portal = screencast
            use_separate_screencast = False

            async def create_session(device_types: int, *, include_screencast: bool = True):
                token = secrets.token_hex(12)
                create_request = await remote.call_create_session({
                    "handle_token": Variant("s", "rd_startup_" + token),
                    "session_handle_token": Variant("s", "session_startup_" + token),
                })
                created = await self.wait_response(create_request)
                session = created.get("session_handle")
                if not isinstance(session, str) or not session.startswith("/"):
                    raise PortalError("The remote-desktop portal returned an invalid startup session handle.")

                selected_screencast = screencast if include_screencast else None
                try:
                    select_devices = await remote.call_select_devices(session, {
                        "handle_token": Variant("s", "dev_startup_" + token),
                        "types": Variant("u", device_types),
                        "persist_mode": Variant("u", 1),
                    })
                    await self.wait_response(select_devices)
                    if selected_screencast is not None:
                        try:
                            select_sources = await selected_screencast.call_select_sources(session, {
                                "handle_token": Variant("s", "source_startup_" + token),
                                "types": Variant("u", 1),
                                "multiple": Variant("b", False),
                            })
                            await self.wait_response(select_sources)
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            raise _PortalScreenCastSetupError(
                                "The startup ScreenCast session could not be selected."
                            ) from exc

                    start_request = await remote.call_start(session, "", {
                        "handle_token": Variant("s", "start_startup_" + token),
                    })
                    started = await self.wait_response(start_request)
                except BaseException:
                    await self._close_session_path(session)
                    raise
                return session, started, selected_screencast

            try:
                session, started, screencast = await create_session(7)
            except _PortalScreenCastSetupError as exc:
                logger.info("The portal cannot combine ScreenCast with startup RemoteDesktop: %s", str(exc))
                use_separate_screencast = True
                try:
                    session, started, screencast = await create_session(7, include_screencast=False)
                except PortalError as input_error:
                    if "unsupported device type" not in str(input_error).casefold():
                        raise
                    self._startup_touch_unsupported = True
                    logger.info("The portal does not support startup touchscreen permission; retrying keyboard and pointer only.")
                    session, started, screencast = await create_session(3, include_screencast=False)
            except PortalError as exc:
                if "unsupported device type" not in str(exc).casefold():
                    raise
                self._startup_touch_unsupported = True
                # Some portal backends do not implement the touchscreen bit.
                # Retry with all supported features while staying inside the
                # startup flow; tool calls never retry permission requests.
                logger.info("The portal does not support startup touchscreen permission; retrying keyboard and pointer only.")
                try:
                    session, started, screencast = await create_session(3)
                except _PortalScreenCastSetupError as screen_error:
                    logger.info("The portal cannot combine ScreenCast with startup RemoteDesktop: %s", str(screen_error))
                    use_separate_screencast = True
                    session, started, screencast = await create_session(3, include_screencast=False)

            granted_devices = int(started.get("devices", 0) or 0)
            if not granted_devices & 7:
                await self._close_session_path(session)
                raise PortalError("The user did not grant any requested desktop input permissions.")

            shared_session = (session, remote, granted_devices)
            self._keyboard_session = shared_session
            self._pointer_session = shared_session
            self._screen_cast_interface = screencast

            stream_data = _single_monitor_stream(started)
            if screencast is None or stream_data is None:
                if screen_cast_portal is not None and (use_separate_screencast or screencast is not None):
                    standalone_stream = await self._create_startup_screencast_session(screen_cast_portal)
                    if standalone_stream is not None:
                        self._startup_monitor_session = standalone_stream
                        self._screen_cast_interface = screen_cast_portal
                return

            stream_id, position, size, pipewire_serial = stream_data
            monitor_session = RemoteMonitorInputSession(
                path=session,
                remote=remote,
                granted_devices=granted_devices,
                stream_id=stream_id,
                position=position,
                size=size,
                newly_authorized=False,
                pipewire_serial=pipewire_serial,
            )
            self._startup_monitor_session = monitor_session
            if granted_devices & 4:
                self._touch_session = monitor_session
            try:
                methods = await self.portal_methods("org.freedesktop.portal.RemoteDesktop")
            except Exception as exc:
                logger.info("Could not inspect startup RemoteDesktop methods: %s", type(exc).__name__)
                methods = set()
            if granted_devices & 2 and "NotifyPointerMotionAbsolute" in methods:
                self._absolute_pointer_session = monitor_session

    async def _create_startup_screencast_session(self, screencast: Any) -> StartupScreenCastSession | None:
        """Request a startup-only screenshot stream when combined sessions are unsupported."""
        token = secrets.token_hex(12)
        session: str | None = None
        try:
            create_request = await screencast.call_create_session({
                "handle_token": Variant("s", "sc_startup_" + token),
                "session_handle_token": Variant("s", "sc_session_startup_" + token),
            })
            created = await self.wait_response(create_request)
            session_value = created.get("session_handle")
            if not isinstance(session_value, str) or not session_value.startswith("/"):
                raise PortalError("The ScreenCast portal returned an invalid startup session handle.")
            session = session_value
            select_sources = await screencast.call_select_sources(session, {
                "handle_token": Variant("s", "sc_sources_startup_" + token),
                "types": Variant("u", 1),
                "multiple": Variant("b", False),
            })
            await self.wait_response(select_sources)
            start_request = await screencast.call_start(session, "", {
                "handle_token": Variant("s", "sc_start_startup_" + token),
            })
            started = await self.wait_response(start_request)
        except asyncio.CancelledError:
            if session is not None:
                await self._close_session_path(session)
            raise
        except Exception as exc:
            if session is not None:
                await self._close_session_path(session)
            logger.info("The standalone startup ScreenCast request was unavailable: %s", str(exc)[:240])
            return None

        stream_data = _single_monitor_stream(started)
        if stream_data is None:
            await self._close_session_path(session)
            logger.info("The standalone startup ScreenCast session returned no validated monitor stream.")
            return None
        stream_id, position, size, pipewire_serial = stream_data
        return StartupScreenCastSession(
            path=session,
            stream_id=stream_id,
            position=position,
            size=size,
            pipewire_serial=pipewire_serial,
        )

    async def capture_startup_screen_frame(self) -> tuple[bytes, RemoteMonitorInputSession | StartupScreenCastSession]:
        """Capture one frame from the ScreenCast stream approved at startup."""
        await self._wait_for_startup_permission_request()
        monitor_session = self._startup_monitor_session
        screencast = self._screen_cast_interface
        if monitor_session is None or screencast is None:
            raise PortalError("No monitor ScreenCast permission was granted during MCP startup.")
        gst_launch = shutil.which("gst-launch-1.0", path=get_sanitized_env().get("PATH"))
        if not gst_launch:
            raise PortalError("A startup ScreenCast session is active, but GStreamer is unavailable for frame capture.")
        try:
            fd = await screencast.call_open_pipe_wire_remote(monitor_session.path, {})
        except Exception as exc:
            raise PortalError("The startup ScreenCast session could not open its PipeWire stream.") from exc
        if not isinstance(fd, int) or isinstance(fd, bool) or fd < 0:
            raise PortalError("The startup ScreenCast session returned an invalid PipeWire descriptor.")

        source = ["pipewiresrc", f"fd={fd}"]
        if monitor_session.pipewire_serial is not None:
            source.append(f"target-object={monitor_session.pipewire_serial}")
        else:
            source.append(f"path={monitor_session.stream_id}")
        command = [
            gst_launch, "-q", *source, "num-buffers=1", "do-timestamp=true",
            "!", "videoconvert", "!", "pngenc", "!", "fdsink", "fd=1",
        ]

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=get_sanitized_env(),
                pass_fds=(fd,),
                close_fds=True,
            )

            async def read_frame() -> bytes:
                output = bytearray()
                assert process is not None and process.stdout is not None
                while True:
                    chunk = await process.stdout.read(min(64 * 1024, MAX_SCREENSHOT_BYTES + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_SCREENSHOT_BYTES:
                        raise PortalError("The startup ScreenCast frame exceeds the 32 MiB output limit.")
                return_code = await process.wait()
                if return_code != 0 or not output:
                    raise PortalError("GStreamer could not read a frame from the startup ScreenCast stream.")
                return bytes(output)

            try:
                image = await asyncio.wait_for(read_frame(), timeout=8)
            except asyncio.TimeoutError as exc:
                raise PortalError("Capturing a frame from the startup ScreenCast stream timed out.") from exc
        except OSError as exc:
            raise PortalError(f"Could not capture the startup ScreenCast stream: {exc.strerror or type(exc).__name__}.") from exc
        finally:
            if process is not None and process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await process.wait()
            try:
                os.close(fd)
            except OSError:
                pass
        return image, monitor_session

    def _on_session_closed(self, path: str) -> None:
        if self._keyboard_session and self._keyboard_session[0] == path:
            self._keyboard_session = None
        if self._pointer_session and self._pointer_session[0] == path:
            self._pointer_session = None
        if self._touch_session and self._touch_session.path == path:
            self._touch_session = None
        if self._absolute_pointer_session and self._absolute_pointer_session.path == path:
            self._absolute_pointer_session = None
        if self._startup_monitor_session and self._startup_monitor_session.path == path:
            self._startup_monitor_session = None
            self._screen_cast_interface = None

    async def ensure_session(self, *, pointer: bool = False) -> tuple[str, Any, int, bool]:
        """Return the shared keyboard-and-pointer input session.

        The server startup flow requests its input devices together with one
        monitor stream. Standalone callers retain the input-only request.
        Pointer coordinates are still checked against fresh compositor
        observations. The final value reports whether this call created a
        session and may have waited for a permission dialog.
        """
        if self.bus is not None and not self.bus.connected:
            self._keyboard_session = None
            self._pointer_session = None
            self._touch_session = None
            self._absolute_pointer_session = None
            self._startup_monitor_session = None
            self._screen_cast_interface = None
        cached = self._pointer_session or self._keyboard_session
        if cached is not None:
            return (*cached, False)
        await self._wait_for_startup_permission_request()
        if self._startup_only:
            cached = self._pointer_session or self._keyboard_session
            if cached is None:
                raise PortalError("No desktop input permission was granted at MCP startup; restart the server to retry.")
            return (*cached, False)

        async with self._session_lock:
            if self.bus is not None and not self.bus.connected:
                self._keyboard_session = None
                self._pointer_session = None
                self._touch_session = None
                self._absolute_pointer_session = None
            cached = self._pointer_session or self._keyboard_session
            if cached is not None:
                return (*cached, False)

            remote_name = "org.freedesktop.portal.RemoteDesktop"
            try:
                remote = await self.proxy(remote_name)
            except InterfaceNotFoundError as exc:
                raise PortalError(
                    "The session portal does not expose RemoteDesktop; keyboard and pointer input cannot be authorized."
                ) from exc
            token = secrets.token_hex(12)
            create_request = await remote.call_create_session({
                "handle_token": Variant("s", "rd_" + token),
                "session_handle_token": Variant("s", "session_" + token),
            })
            created = await self.wait_response(create_request)
            session = created.get("session_handle")
            if not isinstance(session, str) or not session.startswith("/"):
                raise PortalError("The remote-desktop portal returned an invalid session handle.")
            try:
                select_devices = await remote.call_select_devices(session, {
                    "handle_token": Variant("s", "dev_" + token),
                    "types": Variant("u", 3),  # keyboard and pointer in one consent request
                    "persist_mode": Variant("u", 1),  # this process lifetime only
                })
                await self.wait_response(select_devices)
                start_request = await remote.call_start(session, "", {
                    "handle_token": Variant("s", "start_" + token),
                })
                started = await self.wait_response(start_request)
                granted_devices = int(started.get("devices", 0) or 0)
                if granted_devices & 3 != 3:
                    raise PortalError("The user did not grant both keyboard and pointer control.")

            except Exception:
                await self._close_session_path(session)
                raise

            shared_session = (session, remote, granted_devices)
            self._keyboard_session = shared_session
            self._pointer_session = shared_session
            return (*shared_session, True)

    async def portal_methods(self, interface_name: str) -> set[str]:
        node = await self.introspection()
        interface = next((item for item in node.interfaces if item.name == interface_name), None)
        return {method.name for method in interface.methods} if interface is not None else set()

    async def _ensure_monitor_input_session(
        self, *, device_type: int, session_kind: str,
    ) -> RemoteMonitorInputSession:
        """Create a device-granted RemoteDesktop session paired with one monitor source.

        The monitor stream supplies only coordinate metadata here; this client
        does not open its PipeWire remote or read screen pixels.
        """
        if session_kind not in {"touch", "absolute_pointer"} or device_type not in {2, 4}:
            raise PortalError("Unsupported monitor-mapped input session type.")
        if self.bus is not None and not self.bus.connected:
            self._keyboard_session = None
            self._pointer_session = None
            self._touch_session = None
            self._absolute_pointer_session = None
            self._startup_monitor_session = None
            self._screen_cast_interface = None
        cached = self._touch_session if session_kind == "touch" else self._absolute_pointer_session
        if cached is not None:
            return replace(cached, newly_authorized=False)
        await self._wait_for_startup_permission_request()
        if self._startup_only:
            cached = self._touch_session if session_kind == "touch" else self._absolute_pointer_session
            if cached is None:
                raise PortalError("No matching touchscreen/monitor permission was granted at MCP startup; restart the server to retry.")
            return replace(cached, newly_authorized=False)

        async with self._session_lock:
            if self.bus is not None and not self.bus.connected:
                self._keyboard_session = None
                self._pointer_session = None
                self._touch_session = None
                self._absolute_pointer_session = None
            cached = self._touch_session if session_kind == "touch" else self._absolute_pointer_session
            if cached is not None:
                return replace(cached, newly_authorized=False)

            try:
                remote = await self.proxy("org.freedesktop.portal.RemoteDesktop")
                screencast = await self.proxy("org.freedesktop.portal.ScreenCast")
            except InterfaceNotFoundError as exc:
                raise PortalError(
                    "The session portal must expose RemoteDesktop and ScreenCast for monitor-mapped input."
                ) from exc

            if session_kind == "absolute_pointer":
                methods = await self.portal_methods("org.freedesktop.portal.RemoteDesktop")
                if "NotifyPointerMotionAbsolute" not in methods:
                    raise PortalError("The RemoteDesktop portal does not support absolute pointer motion.")

            token = secrets.token_hex(12)
            create_request = await remote.call_create_session({
                "handle_token": Variant("s", "rd_" + session_kind + "_" + token),
                "session_handle_token": Variant("s", "session_" + session_kind + "_" + token),
            })
            created = await self.wait_response(create_request)
            session = created.get("session_handle")
            if not isinstance(session, str) or not session.startswith("/"):
                raise PortalError("The remote-desktop portal returned an invalid monitor-mapped session handle.")

            try:
                select_devices = await remote.call_select_devices(session, {
                    "handle_token": Variant("s", "dev_" + session_kind + "_" + token),
                    "types": Variant("u", device_type),
                    "persist_mode": Variant("u", 1),  # this process lifetime only
                })
                await self.wait_response(select_devices)

                # Select one existing monitor. The portal's consent flow lets
                # the user choose which monitor; later code requires the
                # returned logical bounds to match exactly one compositor output.
                select_sources = await screencast.call_select_sources(session, {
                    "handle_token": Variant("s", "source_" + session_kind + "_" + token),
                    "types": Variant("u", 1),  # monitor sources only
                    "multiple": Variant("b", False),
                })
                await self.wait_response(select_sources)

                start_request = await remote.call_start(session, "", {
                    "handle_token": Variant("s", "start_" + session_kind + "_" + token),
                })
                started = await self.wait_response(start_request)
                granted_devices = int(started.get("devices", 0) or 0)
                if granted_devices & device_type != device_type:
                    label = "touchscreen" if device_type == 4 else "pointer"
                    raise PortalError(f"The user did not grant {label} control.")

                streams = started.get("streams")
                if not isinstance(streams, (list, tuple)) or len(streams) != 1:
                    raise PortalError("The portal did not return exactly one selected monitor stream for input mapping.")
                stream = streams[0]
                if not isinstance(stream, (list, tuple)) or len(stream) != 2:
                    raise PortalError("The portal returned malformed monitor stream metadata.")
                stream_id, properties = stream
                if (
                    not isinstance(stream_id, int) or isinstance(stream_id, bool)
                    or not 0 <= stream_id <= 0xFFFFFFFF
                    or not isinstance(properties, dict)
                ):
                    raise PortalError("The portal returned an invalid monitor stream identity.")
                source_type = properties.get("source_type")
                if source_type is not None and (
                    not isinstance(source_type, int) or isinstance(source_type, bool) or source_type != 1
                ):
                    raise PortalError("The selected portal stream is not a monitor stream.")

                position = properties.get("position")
                size = properties.get("logical_size", properties.get("size"))
                if "logical_size" in properties and "size" in properties and properties["logical_size"] != properties["size"]:
                    raise PortalError("The portal returned conflicting monitor coordinate sizes.")

                def pair(value: Any) -> tuple[int, int] | None:
                    if (
                        not isinstance(value, (list, tuple)) or len(value) != 2
                        or any(not isinstance(part, int) or isinstance(part, bool) for part in value)
                    ):
                        return None
                    return int(value[0]), int(value[1])

                logical_position = pair(position)
                logical_size = pair(size)
                if logical_position is None or logical_size is None or min(logical_size) <= 0:
                    raise PortalError("The portal omitted verified compositor-space monitor position or size.")
                if max(logical_size) > 32768 or any(abs(value) > 131072 for value in logical_position):
                    raise PortalError("The portal monitor coordinate bounds exceed the supported range.")

            except Exception:
                await self._close_session_path(session)
                raise

            monitor_session = RemoteMonitorInputSession(
                path=session,
                remote=remote,
                granted_devices=granted_devices,
                stream_id=stream_id,
                position=logical_position,
                size=logical_size,
                newly_authorized=True,
            )
            if session_kind == "touch":
                self._touch_session = replace(monitor_session, newly_authorized=False)
            else:
                self._absolute_pointer_session = replace(monitor_session, newly_authorized=False)
            return monitor_session

    async def ensure_touch_session(self) -> RemoteMonitorInputSession:
        """Create a process-scoped touchscreen session mapped to one monitor."""
        return await self._ensure_monitor_input_session(device_type=4, session_kind="touch")

    async def ensure_absolute_pointer_session(self) -> RemoteMonitorInputSession:
        """Create a process-scoped absolute-pointer session mapped to one monitor."""
        return await self._ensure_monitor_input_session(device_type=2, session_kind="absolute_pointer")

    def _validate_monitor_input_session(
        self, monitor_session: RemoteMonitorInputSession, *, device_type: int,
    ) -> None:
        if not monitor_session.granted_devices & device_type:
            label = "touchscreen" if device_type == 4 else "pointer"
            raise PortalError(f"The user did not grant {label} control.")
        cached = self._touch_session if device_type == 4 else self._absolute_pointer_session
        if self.bus is None or not self.bus.connected or cached is None:
            raise PortalError("The monitor-mapped input portal session closed; observe again and retry.")
        if cached.path != monitor_session.path:
            raise PortalError("The monitor-mapped input portal session changed; observe again and retry.")

    @staticmethod
    def _validate_monitor_point(monitor_session: RemoteMonitorInputSession, x: float, y: float) -> tuple[float, float]:
        if not math.isfinite(x) or not math.isfinite(y):
            raise PortalError("Input coordinates must be finite numbers.")
        if not (0 <= x < monitor_session.size[0] and 0 <= y < monitor_session.size[1]):
            raise PortalError("Input coordinates fall outside the selected monitor stream.")
        return float(x), float(y)

    async def touch_down(self, monitor_session: RemoteMonitorInputSession, x: float, y: float) -> None:
        self._validate_monitor_input_session(monitor_session, device_type=4)
        x, y = self._validate_monitor_point(monitor_session, x, y)
        await monitor_session.remote.call_notify_touch_down(
            monitor_session.path, {}, monitor_session.stream_id, 0, x, y,
        )

    async def touch_motion(self, monitor_session: RemoteMonitorInputSession, x: float, y: float) -> None:
        self._validate_monitor_input_session(monitor_session, device_type=4)
        x, y = self._validate_monitor_point(monitor_session, x, y)
        await monitor_session.remote.call_notify_touch_motion(
            monitor_session.path, {}, monitor_session.stream_id, 0, x, y,
        )

    async def touch_up(self, monitor_session: RemoteMonitorInputSession) -> None:
        self._validate_monitor_input_session(monitor_session, device_type=4)
        await monitor_session.remote.call_notify_touch_up(monitor_session.path, {}, 0)

    async def pointer_move_absolute(
        self, monitor_session: RemoteMonitorInputSession, x: float, y: float,
    ) -> None:
        self._validate_monitor_input_session(monitor_session, device_type=2)
        x, y = self._validate_monitor_point(monitor_session, x, y)
        await monitor_session.remote.call_notify_pointer_motion_absolute(
            monitor_session.path, {}, monitor_session.stream_id, x, y,
        )

    async def pointer_button_absolute(
        self, monitor_session: RemoteMonitorInputSession, button: int, pressed: bool,
    ) -> None:
        self._validate_monitor_input_session(monitor_session, device_type=2)
        await monitor_session.remote.call_notify_pointer_button(
            monitor_session.path, {}, int(button), 1 if pressed else 0,
        )

    async def pointer_scroll_absolute(
        self, monitor_session: RemoteMonitorInputSession, dx: int, dy: int,
    ) -> None:
        self._validate_monitor_input_session(monitor_session, device_type=2)
        await monitor_session.remote.call_notify_pointer_axis(
            monitor_session.path, {"finish": Variant("b", True)}, float(dx), float(dy),
        )

    async def close_touch_session(self) -> None:
        touch_session = self._touch_session
        shared_input_session = self._keyboard_session or self._pointer_session
        if touch_session is not None and shared_input_session is not None and touch_session.path == shared_input_session[0]:
            # Startup combines these capabilities in one RemoteDesktop session.
            return
        self._touch_session = None
        if touch_session is not None:
            await self._close_session_path(touch_session.path)

    async def close_absolute_pointer_session(self) -> None:
        pointer_session = self._absolute_pointer_session
        shared_input_session = self._keyboard_session or self._pointer_session
        if pointer_session is not None and shared_input_session is not None and pointer_session.path == shared_input_session[0]:
            return
        self._absolute_pointer_session = None
        if pointer_session is not None:
            await self._close_session_path(pointer_session.path)

    async def _close_session_path(self, session: str) -> None:
        try:
            iface = await self.proxy("org.freedesktop.portal.Session", session)
            await iface.call_close()
        except Exception:
            pass

    async def pointer_move_relative(self, dx: float, dy: float) -> None:
        session, remote, granted_devices, _newly_authorized = await self.ensure_session(pointer=True)
        if not granted_devices & 2:
            raise PortalError("The user did not grant pointer control.")
        if abs(dx) > 10000 or abs(dy) > 10000:
            raise PortalError("Relative pointer movement exceeds the portal safety bound.")
        await remote.call_notify_pointer_motion(session, {}, float(dx), float(dy))

    async def pointer_button(self, button: int, pressed: bool) -> None:
        session, remote, granted_devices, _newly_authorized = await self.ensure_session(pointer=True)
        if not granted_devices & 2:
            raise PortalError("The user did not grant pointer control.")
        await remote.call_notify_pointer_button(
            session, {}, int(button), 1 if pressed else 0,
        )

    async def pointer_scroll(self, dx: int, dy: int) -> None:
        session, remote, granted_devices, _newly_authorized = await self.ensure_session(pointer=True)
        if not granted_devices & 2:
            raise PortalError("The user did not grant pointer control.")
        await remote.call_notify_pointer_axis(
            session, {"finish": Variant("b", True)}, float(dx), float(dy),
        )

    async def keyboard_keysym(self, keysym: int, pressed: bool) -> None:
        session, remote, granted_devices, _newly_authorized = await self.ensure_session(pointer=False)
        if not granted_devices & 1:
            raise PortalError("The user did not grant keyboard control.")
        await remote.call_notify_keyboard_keysym(
            session, {}, int(keysym), 1 if pressed else 0,
        )

    async def close(self) -> None:
        startup_task = self._startup_task
        if startup_task is not None and not startup_task.done() and startup_task is not asyncio.current_task():
            startup_task.cancel()
            await asyncio.gather(startup_task, return_exceptions=True)
        bus = self.bus
        sessions = [
            session for session in (
                self._keyboard_session[0] if self._keyboard_session else None,
                self._pointer_session[0] if self._pointer_session else None,
                self._touch_session.path if self._touch_session else None,
                self._absolute_pointer_session.path if self._absolute_pointer_session else None,
                self._startup_monitor_session.path if self._startup_monitor_session else None,
            ) if session
        ]
        if bus and bus.connected:
            for session in dict.fromkeys(sessions):
                try:
                    await self._close_session_path(session)
                except Exception:
                    pass
        self._keyboard_session = None
        self._pointer_session = None
        self._touch_session = None
        self._absolute_pointer_session = None
        self._startup_monitor_session = None
        self._screen_cast_interface = None
        self._introspection_cache.clear()
        await self.close_bus()
        self._startup_only = False
        self._startup_status = "not_started"
        self._startup_error = None
        self._startup_task = None
        self._startup_touch_unsupported = False


remote_desktop_portal = RemoteDesktopPortal()
