"""KDE Plasma window and workspace access through KWin's scripting API.

KWin does not publish its complete window model as a D-Bus object model. This
adapter loads a short-lived, one-shot KWin script for each request and returns
the result over the same user's session D-Bus. The script never persists in
KWin and is unloaded in a ``finally`` block.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import tempfile
import threading
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any

from dbus_next import BusType
from dbus_next.aio import MessageBus
from dbus_next.service import ServiceInterface, method

from wayland_mcp.backends.base import BaseCompositorBackend
from wayland_mcp.models import (
    ActionResult,
    CompositorCapabilities,
    FocusedWindowResponse,
    OutputInfo,
    OutputListResponse,
    WindowGeometry,
    WindowInfo,
    WindowListResponse,
    WindowState,
    WorkspaceInfo,
    WorkspaceListResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env, logger

KWINSCRIPTING_SERVICE = "org.kde.KWin"
KWINSCRIPTING_PATH = "/Scripting"
KWINSCRIPTING_INTERFACE = "org.kde.kwin.Scripting"
BRIDGE_PATH = "/org/waylandmcp/ResultBridge"
BRIDGE_INTERFACE = "org.waylandmcp.ResultBridge"
SCRIPT_TIMEOUT_SECONDS = 6.0


class _ResultBridge(ServiceInterface):
    def __init__(self, on_result):
        super().__init__(BRIDGE_INTERFACE)
        self._on_result = on_result

    @method(name="Result")
    def result(self, token: "s", payload: "s") -> "":
        self._on_result(token, payload)


class _KWinScriptClient:
    """Owns the D-Bus connection and KWin calls on a private worker loop."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._start_error: str | None = None
        self._bus: MessageBus | None = None
        self._kwin = None
        self._bridge: _ResultBridge | None = None
        self._pending: dict[str, asyncio.Future[str]] = {}
        self._operation_lock: asyncio.Lock | None = None
        self._lock = threading.Lock()

    def call(self, operation: str, **arguments: Any) -> dict[str, Any]:
        loop = self._ensure_worker()
        coro = self._run_script(operation, arguments)
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            result = future.result(timeout=SCRIPT_TIMEOUT_SECONDS + 6.0)
        except FutureTimeout as exc:
            future.cancel()
            raise RuntimeError("KWin did not return a result before the bounded request timeout.") from exc
        if not isinstance(result, dict):
            raise RuntimeError("KWin returned an invalid response.")
        if result.get("error"):
            raise RuntimeError(str(result["error"])[:400])
        return result

    def available(self) -> tuple[bool, str | None]:
        try:
            response = self.call("probe")
            available = bool(response.get("available"))
            return available, None if available else str(response.get("reason") or "KWin scripting is unavailable.")
        except Exception as exc:
            return False, str(exc)[:300]

    def _ensure_worker(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._ready.clear()
                self._start_error = None
                self._thread = threading.Thread(
                    target=self._worker_main,
                    name="linux-mcp-kwin-dbus",
                    daemon=True,
                )
                self._thread.start()
        if not self._ready.wait(timeout=3.0):
            raise RuntimeError("The KWin D-Bus worker did not start in time.")
        if self._start_error:
            raise RuntimeError(self._start_error)
        if self._loop is None:
            raise RuntimeError("The KWin D-Bus worker has no event loop.")
        return self._loop

    def _worker_main(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        # asyncio primitives belong to the worker loop. If a previous worker
        # died and this client reconnects, do not reuse a lock bound to the
        # old loop.
        self._operation_lock = None
        try:
            loop.run_until_complete(self._connect())
        except Exception as exc:
            self._start_error = f"KWin session D-Bus is unavailable: {str(exc)[:250]}"
            self._ready.set()
            try:
                loop.run_until_complete(self._disconnect())
            except Exception:
                pass
            loop.close()
            self._loop = None
            return
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            try:
                loop.run_until_complete(self._disconnect())
            except Exception:
                pass
            loop.close()
            self._loop = None

    async def _connect(self) -> None:
        if self._operation_lock is None:
            self._operation_lock = asyncio.Lock()
        env = get_sanitized_env()
        address = env.get("DBUS_SESSION_BUS_ADDRESS")
        if address:
            bus = MessageBus(bus_address=address)
        else:
            bus = MessageBus(bus_type=BusType.SESSION)
        self._bus = await asyncio.wait_for(bus.connect(), timeout=2.0)
        self._bridge = _ResultBridge(self._receive_result)
        self._bus.export(BRIDGE_PATH, self._bridge)
        intro = await asyncio.wait_for(
            self._bus.introspect(KWINSCRIPTING_SERVICE, KWINSCRIPTING_PATH), timeout=2.0,
        )
        proxy = self._bus.get_proxy_object(KWINSCRIPTING_SERVICE, KWINSCRIPTING_PATH, intro)
        self._kwin = proxy.get_interface(KWINSCRIPTING_INTERFACE)

    def _receive_result(self, token: str, payload: str) -> None:
        future = self._pending.get(token)
        if future is not None and not future.done():
            future.set_result(payload)

    async def _run_script(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self._operation_lock is None:
            self._operation_lock = asyncio.Lock()
        async with self._operation_lock:
            return await self._run_script_once(operation, arguments)

    async def _run_script_once(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self._bus is None or not self._bus.connected or self._kwin is None:
            await self._disconnect()
            await self._connect()
        token = secrets.token_urlsafe(24)
        plugin_name = "wayland_mcp_" + secrets.token_hex(12)
        script_text = _build_script(
            operation=operation,
            arguments=arguments,
            token=token,
            bus_name=self._bus.unique_name,
        )
        fd, temp_path = tempfile.mkstemp(prefix="linux-mcp-kwin-", suffix=".js")
        script_id = None
        future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        self._pending[token] = future
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(script_text)
            script_id = await asyncio.wait_for(
                self._kwin.call_load_script(temp_path, plugin_name), timeout=2.0,
            )
            if not isinstance(script_id, int) or script_id < 0:
                raise RuntimeError("KWin refused to load its temporary query script.")
            await self._run_loaded_script(script_id)
            payload = await asyncio.wait_for(future, timeout=SCRIPT_TIMEOUT_SECONDS)
            try:
                result = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise RuntimeError("KWin returned malformed JSON from its temporary query script.") from exc
            if not isinstance(result, dict):
                raise RuntimeError("KWin returned a non-object response.")
            return result
        finally:
            self._pending.pop(token, None)
            if script_id is not None:
                try:
                    await asyncio.wait_for(self._kwin.call_unload_script(plugin_name), timeout=1.0)
                except Exception:
                    pass
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    async def _run_loaded_script(self, script_id: int) -> None:
        # KWin may register the script before its per-script object is visible.
        paths = (f"/Scripting/Script{script_id}", f"/Script{script_id}")
        last_error: Exception | None = None
        deadline = asyncio.get_running_loop().time() + 1.5
        while asyncio.get_running_loop().time() < deadline:
            for path in paths:
                try:
                    intro = await asyncio.wait_for(
                        self._bus.introspect(KWINSCRIPTING_SERVICE, path), timeout=0.35,
                    )
                    proxy = self._bus.get_proxy_object(KWINSCRIPTING_SERVICE, path, intro)
                    iface = proxy.get_interface("org.kde.kwin.Script")
                    await asyncio.wait_for(iface.call_run(), timeout=0.5)
                    return
                except Exception as exc:
                    last_error = exc
            await asyncio.sleep(0.04)
        raise RuntimeError(f"KWin did not expose the temporary script runner: {last_error}")

    async def _disconnect(self) -> None:
        if self._bus is not None:
            try:
                if self._bridge is not None:
                    self._bus.unexport(BRIDGE_PATH, BRIDGE_INTERFACE)
            except Exception:
                pass
            if self._bus.connected:
                self._bus.disconnect()
        self._bus = None
        self._kwin = None
        self._bridge = None

    def close(self) -> None:
        loop = self._loop
        thread = self._thread
        if loop is None or thread is None or not thread.is_alive():
            return
        try:
            asyncio.run_coroutine_threadsafe(self._disconnect(), loop).result(timeout=2)
        except Exception:
            pass
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=2)
        self._thread = None
        self._loop = None


_SCRIPT_BODY = r'''(function () {
  var request = JSON.parse(__REQUEST_JSON__);
  var token = __TOKEN_JSON__;
  function value(object, key) {
    if (object === null || object === undefined) return undefined;
    var item = object[key];
    if (typeof item === "function") {
      try { return item.call(object); } catch (e) { return undefined; }
    }
    return item;
  }
  function number(value) {
    var n = Number(value);
    return isFinite(n) ? Math.round(n) : 0;
  }
  function rectOf(object) {
    var rect = value(object, "frameGeometry") || value(object, "geometry") || object;
    var x = value(rect, "x"), y = value(rect, "y");
    var width = value(rect, "width"), height = value(rect, "height");
    if (x === undefined || y === undefined || width === undefined || height === undefined) return null;
    var values = [Number(x), Number(y), Number(width), Number(height)];
    for (var i = 0; i < values.length; i++) {
      if (!isFinite(values[i]) || Math.abs(values[i] - Math.round(values[i])) > 0.000001) return null;
    }
    var result = {x: number(values[0]), y: number(values[1]), width: number(values[2]), height: number(values[3])};
    if (result.width <= 0 || result.height <= 0) return null;
    return result;
  }
  function windowId(window) {
    var id = value(window, "internalId");
    if (id !== undefined && id !== null && String(id) !== "") return String(id);
    id = value(window, "windowId");
    return id === undefined || id === null ? "" : String(id);
  }
  function rawWindows() {
    // KWin 6 documents WorkspaceWrapper.stackingOrder as the managed-window
    // list.
    var stacked = value(workspace, "stackingOrder");
    if (stacked && typeof stacked.length === "number") return stacked;
    return [];
  }
  function supportsWindowListing() {
    var stacked = value(workspace, "stackingOrder");
    return !!(stacked && typeof stacked.length === "number");
  }
  function windows() {
    var list = rawWindows();
    var out = [];
    for (var i = 0; i < list.length; i++) {
      var w = list[i];
      if (!w || value(w, "deleted") === true) continue;
      var id = windowId(w);
      if (!id) continue;
      var desktopList = value(w, "desktops");
      var desktop = desktopList && desktopList.length ? desktopList[0] : value(w, "desktop");
      if (value(w, "onAllDesktops") === true) desktop = value(workspace, "currentDesktop") || desktop;
      var desktopId = desktop && typeof desktop === "object" ? value(desktop, "id") : desktop;
      var desktopName = desktop && typeof desktop === "object" ? value(desktop, "name") : undefined;
      var output = value(w, "output") || value(w, "screen");
      var geometry = rectOf(w);
      var minimized = value(w, "minimized") === true;
      var fullScreen = value(w, "fullScreen") === true;
      out.push({
        id: id,
        app_id: String(value(w, "desktopFileName") || value(w, "resourceClass") || value(w, "resourceName") || "unknown"),
        title: String(value(w, "caption") || ""),
        workspace_id: desktopId === undefined || desktopId === null ? null : String(desktopId),
        workspace_name: desktopName === undefined || desktopName === null ? null : String(desktopName),
        is_focused: value(w, "active") === true || w === value(workspace, "activeWindow"),
        geometry: geometry,
        output: output ? String(value(output, "name") || "") : null,
        state: {
          is_focused: value(w, "active") === true || w === value(workspace, "activeWindow"),
          is_minimized: minimized,
          // KWin 6 exposes setMaximize() but no maximized-state property.
          is_maximized: null,
          is_fullscreen: fullScreen,
          is_floating: !value(w, "tile")
        }
      });
    }
    return out;
  }
  function desktops() {
    var list = value(workspace, "desktops") || [];
    var current = value(workspace, "currentDesktop");
    var currentId = current ? String(value(current, "id") || value(current, "x11DesktopNumber") || "") : "";
    var counts = {};
    var ws = windows();
    for (var i = 0; i < ws.length; i++) {
      if (ws[i].workspace_id !== null) counts[ws[i].workspace_id] = (counts[ws[i].workspace_id] || 0) + 1;
    }
    var out = [];
    for (var j = 0; j < list.length; j++) {
      var d = list[j];
      var id = value(d, "id");
      if (id === undefined || id === null) id = value(d, "x11DesktopNumber");
      if (id === undefined || id === null) id = j + 1;
      var idText = String(id);
      var name = value(d, "name");
      out.push({id: idText, name: String(name || ("Desktop " + (j + 1))),
        is_active: idText === currentId, is_focused: idText === currentId,
        monitor: null, windows_count: counts[idText] || 0});
    }
    return out;
  }
  function outputs() {
    var list = value(workspace, "screens") || [];
    var active = value(workspace, "activeScreen");
    var out = [];
    for (var i = 0; i < list.length; i++) {
      var screen = list[i], geometry = rectOf(value(screen, "geometry"));
      var scale = Number(value(screen, "devicePixelRatio"));
      if (!isFinite(scale) || scale <= 0) scale = 1;
      out.push({
        id: String(value(screen, "name") || ("screen-" + i)),
        name: String(value(screen, "name") || ("Screen " + (i + 1))),
        make: value(screen, "manufacturer") ? String(value(screen, "manufacturer")) : null,
        model: value(screen, "model") ? String(value(screen, "model")) : null,
        enabled: true,
        is_focused: screen === active,
        width_pixels: geometry ? Math.round(geometry.width * scale) : null,
        height_pixels: geometry ? Math.round(geometry.height * scale) : null,
        refresh_rate_hz: null,
        scale: scale,
        logical_geometry: geometry
      });
    }
    return out;
  }
  function findWindow(id) {
    var list = windows();
    for (var i = 0; i < list.length; i++) if (list[i].id === String(id)) return list[i];
    var raw = rawWindows();
    for (var j = 0; j < raw.length; j++) if (windowId(raw[j]) === String(id)) return raw[j];
    return null;
  }
  function findDesktop(id) {
    var list = value(workspace, "desktops") || [];
    for (var i = 0; i < list.length; i++) {
      var candidate = value(list[i], "id");
      if (candidate === undefined || candidate === null) candidate = value(list[i], "x11DesktopNumber");
      if (String(candidate) === String(id)) return list[i];
    }
    return null;
  }
  function respond(result) {
    callDBus(__BUS_NAME__, "/org/waylandmcp/ResultBridge", "org.waylandmcp.ResultBridge", "Result", token, JSON.stringify(result));
  }
  try {
    if (request.operation !== "probe" && !supportsWindowListing()) {
      respond({error: "KWin did not expose a supported managed-window list."});
    } else if (request.operation === "probe") {
      var modernKWin = supportsWindowListing();
      respond({available: modernKWin, api: modernKWin ? "kwin6" : "unsupported",
        reason: modernKWin ? null : "KWin did not expose WorkspaceWrapper.stackingOrder."});
    } else if (request.operation === "list_windows") {
      var listed = windows();
      var focused = null;
      for (var i = 0; i < listed.length; i++) if (listed[i].is_focused) focused = listed[i];
      respond({windows: listed, focused_window: focused});
    } else if (request.operation === "list_workspaces") {
      var items = desktops(), active = null;
      for (var i = 0; i < items.length; i++) if (items[i].is_active) active = items[i];
      respond({workspaces: items, active_workspace: active});
    } else if (request.operation === "list_outputs") {
      respond({outputs: outputs()});
    } else if (request.operation === "focus_window" || request.operation === "close_window" ||
               request.operation === "resize_window" || request.operation === "minimize_window" ||
               request.operation === "maximize_window") {
      var w = findWindow(request.target);
      if (!w) { respond({success: false, message: "Exact KWin window ID was not found."}); }
      else if (request.operation === "focus_window") {
        if (w.minimized === true) w.minimized = false;
        if (w.desktops && w.desktops.length && typeof workspace.currentDesktop !== "undefined") workspace.currentDesktop = w.desktops[0];
        if (typeof workspace.activeWindow !== "undefined") workspace.activeWindow = w;
        else workspace.activeClient = w;
        var activeWindow = value(workspace, "activeWindow") || value(workspace, "activeClient");
        respond({success: activeWindow === w, message: activeWindow === w ?
          "KWin focused the exact observed window." : "KWin did not confirm focus on the exact target window."});
      } else if (request.operation === "close_window") {
        if (value(w, "closeable") === false) respond({success: false, message: "KWin reports that this window cannot be closed."});
        else { w.closeWindow(); respond({success: true, message: "KWin sent a close request to the exact observed window."}); }
      } else if (request.operation === "resize_window") {
        var old = rectOf(w), width = Number(request.width), height = Number(request.height);
        if (!old || !isFinite(width) || !isFinite(height)) respond({success: false, message: "KWin did not provide usable window geometry."});
        else if (Math.floor(width) !== width || Math.floor(height) !== height || width < 1 || height < 1 || width > 8192 || height > 8192)
          respond({success: false, message: "Window size must be whole pixels between 1 and 8192."});
        else if (value(w, "resizeable") === false) respond({success: false, message: "KWin reports that this window cannot be resized."});
        else {
          w.frameGeometry = {x: old.x, y: old.y, width: width, height: height};
          var resized = rectOf(w);
          var confirmed = resized && resized.width === width && resized.height === height;
          respond({success: !!confirmed, message: confirmed ? "KWin applied the requested frame size." :
            "KWin constrained or did not confirm the requested frame size."});
        }
      } else if (request.operation === "minimize_window") {
        if (value(w, "minimizable") === false) respond({success: false, message: "KWin reports that this window cannot be minimized."});
        else { w.minimized = true; var minimized = value(w, "minimized") === true;
          respond({success: minimized, message: minimized ? "KWin minimized the exact observed window." : "KWin did not confirm minimization."}); }
      } else {
        if (value(w, "maximizable") === false) respond({success: false, message: "KWin reports that this window cannot be maximized."});
        else if (typeof w.setMaximize !== "function") respond({success: false, message: "This KWin version does not expose per-window maximize controls."});
        else { w.setMaximize(true, true); respond({success: true, message: "KWin sent the maximize request to the exact observed window."}); }
      }
    } else if (request.operation === "switch_workspace") {
      var d = findDesktop(request.workspace);
      if (!d) respond({success: false, message: "Exact KWin workspace ID was not found."});
      else {
        workspace.currentDesktop = d;
        var activeDesktop = value(workspace, "currentDesktop");
        var activeId = activeDesktop ? String(value(activeDesktop, "id") || value(activeDesktop, "x11DesktopNumber") || "") : "";
        var switched = activeId === String(request.workspace);
        respond({success: switched, message: switched ? "KWin switched to the exact observed workspace." : "KWin did not confirm the requested workspace."});
      }
    } else if (request.operation === "move_window_to_workspace") {
      var targetWindow = findWindow(request.target), targetDesktop = findDesktop(request.workspace);
      if (!targetWindow || !targetDesktop) respond({success: false, message: "Exact KWin window or workspace ID was not found."});
      else {
        targetWindow.desktops = [targetDesktop];
        var assigned = value(targetWindow, "desktops") || [];
        var moved = false;
        for (var k = 0; k < assigned.length; k++) if (String(value(assigned[k], "id")) === String(request.workspace)) moved = true;
        respond({success: moved, message: moved ? "KWin moved the exact window to the exact workspace." : "KWin did not confirm the requested workspace move."});
      }
    } else {
      respond({error: "Unknown KWin adapter operation."});
    }
  } catch (error) {
    respond({error: String(error)});
  }
})();
'''


def _build_script(*, operation: str, arguments: dict[str, Any], token: str, bus_name: str) -> str:
    request_json = json.dumps(json.dumps({"operation": operation, **arguments}, ensure_ascii=False))
    return (
        _SCRIPT_BODY
        .replace("__REQUEST_JSON__", request_json)
        .replace("__TOKEN_JSON__", json.dumps(token))
        .replace("__BUS_NAME__", json.dumps(bus_name))
    )


class KWinBackend(BaseCompositorBackend):
    """KWin's documented scripting API, exposed as bounded MCP operations."""

    name = "kde_plasma"

    def __init__(self, env: dict[str, str] | None = None) -> None:
        super().__init__(env or get_sanitized_env())
        self._client = kwin_script_client

    def get_capabilities(self) -> CompositorCapabilities:
        available, reason = self._client.available()
        if not available:
            return CompositorCapabilities(
                screenshot=bool(find_session_binary("grim", self.env)),
                bounded_input=False,
                app_discovery=True,
                unsupported_operations=[reason or "KWin scripting interface is unavailable."],
            )
        return CompositorCapabilities(
            window_list=True,
            window_detail=True,
            window_focus=True,
            window_close=True,
            window_resize=True,
            window_minimize=True,
            window_maximize=True,
            workspace_list=True,
            output_list=True,
            workspace_switch=True,
            window_move=True,
            screenshot=bool(find_session_binary("grim", self.env)),
            bounded_input=True,
            app_discovery=True,
            app_launch=True,
            clipboard_read=True,
            clipboard_write=True,
            notifications=True,
        )

    def _call(self, operation: str, **arguments: Any) -> dict[str, Any]:
        try:
            return self._client.call(operation, **arguments)
        except Exception as exc:
            logger.warning("KWin %s failed: %s", operation, exc)
            raise RuntimeError(str(exc)) from exc

    def list_windows(self) -> WindowListResponse:
        try:
            result = self._call("list_windows")
            windows = [WindowInfo.model_validate(item) for item in result.get("windows", [])]
            focused_data = result.get("focused_window")
            focused = WindowInfo.model_validate(focused_data) if isinstance(focused_data, dict) else None
            return WindowListResponse(success=True, total_windows=len(windows), windows=windows,
                                      focused_window=focused, compositor=self.name)
        except Exception as exc:
            return WindowListResponse(success=False, total_windows=0, windows=[], compositor=self.name,
                                      message=f"KWin window listing failed: {exc}")

    def get_focused_window(self) -> FocusedWindowResponse:
        response = self.list_windows()
        if not response.success:
            return FocusedWindowResponse(success=False, message=response.message)
        return FocusedWindowResponse(success=True, window=response.focused_window,
                                     message=None if response.focused_window else "KWin reported no focused window.")

    def list_workspaces(self) -> WorkspaceListResponse:
        try:
            result = self._call("list_workspaces")
            workspaces = [WorkspaceInfo.model_validate(item) for item in result.get("workspaces", [])]
            active_data = result.get("active_workspace")
            active = WorkspaceInfo.model_validate(active_data) if isinstance(active_data, dict) else None
            return WorkspaceListResponse(success=True, total_workspaces=len(workspaces), workspaces=workspaces,
                                         active_workspace=active, compositor=self.name)
        except Exception as exc:
            return WorkspaceListResponse(success=False, total_workspaces=0, workspaces=[], compositor=self.name,
                                         message=f"KWin workspace listing failed: {exc}")

    def list_outputs(self) -> OutputListResponse:
        try:
            result = self._call("list_outputs")
            outputs = [OutputInfo.model_validate(item) for item in result.get("outputs", [])]
            return OutputListResponse(success=bool(outputs), total_outputs=len(outputs), outputs=outputs,
                                      compositor=self.name,
                                      message=None if outputs else "KWin returned no display outputs.")
        except Exception as exc:
            return OutputListResponse(success=False, total_outputs=0, outputs=[], compositor=self.name,
                                      message=f"KWin output listing failed: {exc}")

    def _action(self, operation: str, target: str, **arguments: Any) -> ActionResult:
        try:
            result = self._call(operation, target=target, **arguments)
            return ActionResult(success=bool(result.get("success")), action=operation, target=target,
                                message=str(result.get("message") or "KWin returned no action status."))
        except Exception as exc:
            return ActionResult(success=False, action=operation, target=target,
                                message=f"KWin action failed: {exc}")

    def focus_window(self, target: str) -> ActionResult:
        return self._action("focus_window", target)

    def close_window(self, target: str) -> ActionResult:
        return self._action("close_window", target)

    def resize_window(self, target: str, width: int, height: int) -> ActionResult:
        return self._action("resize_window", target, width=width, height=height)

    def minimize_window(self, target: str) -> ActionResult:
        return self._action("minimize_window", target)

    def maximize_window(self, target: str) -> ActionResult:
        return self._action("maximize_window", target)

    def switch_workspace(self, workspace: str) -> ActionResult:
        try:
            result = self._call("switch_workspace", workspace=workspace)
            return ActionResult(success=bool(result.get("success")), action="switch_workspace", target=workspace,
                                message=str(result.get("message") or "KWin returned no action status."))
        except Exception as exc:
            return ActionResult(success=False, action="switch_workspace", target=workspace,
                                message=f"KWin workspace switch failed: {exc}")

    def move_window_to_workspace(self, target: str, workspace: str) -> ActionResult:
        label = f"{target} -> {workspace}"
        try:
            result = self._call("move_window_to_workspace", target=target, workspace=workspace)
            return ActionResult(success=bool(result.get("success")), action="move_window_to_workspace",
                                target=label,
                                message=str(result.get("message") or "KWin returned no action status."))
        except Exception as exc:
            return ActionResult(success=False, action="move_window_to_workspace", target=label,
                                message=f"KWin workspace move failed: {exc}")

    def capture_screenshot(self, scope="window", target=None):
        """Use grim, cropping only from current geometry returned by KWin."""
        grim = find_session_binary("grim", self.env)
        if not grim:
            return False, b"", None, "grim binary not found in session PATH."
        geometry = None
        if scope == "desktop":
            command = [grim, "-"]
        elif scope == "window":
            if target is None:
                window = self.get_focused_window().window
            else:
                detail = self.get_window_detail(target)
                window = detail.window if detail.success else None
            if window is None or window.geometry is None:
                return False, b"", None, "KWin did not provide verified geometry for the exact screenshot target."
            geometry = window.geometry
            command = [grim, "-g", f"{geometry.x},{geometry.y} {geometry.width}x{geometry.height}", "-"]
        else:
            return False, b"", None, "Screenshot scope must be 'desktop' or 'window'."
        try:
            result = subprocess.run(command, capture_output=True, timeout=3.0, env=self.env)
            if result.returncode == 0 and result.stdout.startswith(b"\x89PNG\r\n\x1a\n"):
                return True, result.stdout, geometry, "Screenshot captured successfully with grim using KWin geometry."
            error = result.stderr.decode("utf-8", errors="replace").strip()[:300]
            return False, b"", geometry, f"grim screenshot failed: {error or 'no diagnostic output'}"
        except subprocess.TimeoutExpired:
            return False, b"", geometry, "grim screenshot timed out after 3.0s."
        except OSError as exc:
            return False, b"", geometry, f"grim could not be started: {exc}"

    def close(self) -> None:
        self._client.close()


kwin_script_client = _KWinScriptClient()
