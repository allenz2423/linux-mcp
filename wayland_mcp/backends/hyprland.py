import json
import math
import re
import subprocess
from typing import Dict, Optional, List, Tuple, Any
from wayland_mcp.backends.base import BaseCompositorBackend
from wayland_mcp.matching import find_best_window
from wayland_mcp.models import (
    ActionResult,
    PerCapabilityStatus,
    WindowGeometry,
    WindowInfo,
    WindowState,
    WindowListResponse,
    WindowDetailResponse,
    WorkspaceInfo,
    WorkspaceListResponse,
    OutputInfo,
    OutputListResponse,
)
from wayland_mcp.session import find_session_binary, logger

SCREENSHOT_TIMEOUT_SECONDS = 10.0


def _lua_quote(s: str) -> str:
    escaped = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


class HyprlandBackend(BaseCompositorBackend):
    name: str = "hyprland"
    _is_lua_capable: Optional[bool] = None

    def __init__(self, env: Optional[Dict[str, str]] = None) -> None:
        super().__init__(env)
        self.hyprctl = find_session_binary("hyprctl", self.env)

    def _check_lua_support(self) -> bool:
        if HyprlandBackend._is_lua_capable is not None:
            return HyprlandBackend._is_lua_capable
        if not self.hyprctl:
            HyprlandBackend._is_lua_capable = False
            return False
        try:
            res = subprocess.run(
                [self.hyprctl, "version"],
                capture_output=True,
                text=True,
                timeout=2,
                env=self.env,
            )
            match = re.search(r"Hyprland\s+(\d+)\.(\d+)", res.stdout)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                HyprlandBackend._is_lua_capable = (major, minor) >= (0, 55)
            else:
                HyprlandBackend._is_lua_capable = False
        except Exception:
            HyprlandBackend._is_lua_capable = False
        return HyprlandBackend._is_lua_capable

    def _dispatch(self, legacy_cmd: str, legacy_args: str = "", *, lua_expr: str) -> subprocess.CompletedProcess:
        if not self.hyprctl:
            raise RuntimeError("hyprctl binary not found in session PATH")

        if self._check_lua_support():
            cmd = [self.hyprctl, "dispatch", lua_expr]
        else:
            cmd = [self.hyprctl, "dispatch", legacy_cmd]
            if legacy_args:
                cmd.append(legacy_args)

        return subprocess.run(cmd, capture_output=True, text=True, timeout=3, env=self.env)

    def get_capabilities(self) -> Dict[str, PerCapabilityStatus]:
        has_hyprctl = bool(self.hyprctl)
        has_grim = bool(find_session_binary("grim", self.env))
        has_launcher = bool(find_session_binary("gtk-launch", self.env) or find_session_binary("gio", self.env))
        has_wl_paste = bool(find_session_binary("wl-paste", self.env))
        has_wl_copy = bool(find_session_binary("wl-copy", self.env))
        has_notify = bool(find_session_binary("notify-send", self.env))

        return {
            "window_list": PerCapabilityStatus(
                supported=True,
                available=has_hyprctl,
                reason=None if has_hyprctl else "hyprctl not found in session PATH",
                required_dependency="hyprctl",
            ),
            "window_detail": PerCapabilityStatus(
                supported=True,
                available=has_hyprctl,
                reason=None if has_hyprctl else "hyprctl not found in session PATH",
                required_dependency="hyprctl",
            ),
            "window_focus": PerCapabilityStatus(
                supported=True,
                available=has_hyprctl,
                reason=None if has_hyprctl else "hyprctl not found in session PATH",
                required_dependency="hyprctl",
            ),
            "window_close": PerCapabilityStatus(
                supported=True,
                available=has_hyprctl,
                reason=None if has_hyprctl else "hyprctl not found in session PATH",
                required_dependency="hyprctl",
            ),
            "window_resize": PerCapabilityStatus(
                supported=True,
                available=has_hyprctl,
                reason=None if has_hyprctl else "hyprctl not found in session PATH",
                required_dependency="hyprctl",
            ),
            "window_minimize": PerCapabilityStatus(
                supported=False,
                available=False,
                reason="Hyprland tiling paradigm does not have standard minimization; use special workspace or scratchpad",
            ),
            "window_maximize": PerCapabilityStatus(
                supported=False,
                available=False,
                reason="Hyprland fullscreen dispatch is not equivalent to per-window maximize; no maximize action is exposed.",
            ),
            "workspace_list": PerCapabilityStatus(
                supported=True,
                available=has_hyprctl,
                reason=None if has_hyprctl else "hyprctl not found in session PATH",
                required_dependency="hyprctl",
            ),
            "output_list": PerCapabilityStatus(
                supported=True,
                available=has_hyprctl,
                reason=None if has_hyprctl else "hyprctl not found in session PATH",
                required_dependency="hyprctl",
            ),
            "workspace_switch": PerCapabilityStatus(
                supported=True,
                available=has_hyprctl,
                reason=None if has_hyprctl else "hyprctl not found in session PATH",
                required_dependency="hyprctl",
            ),
            "window_move_workspace": PerCapabilityStatus(
                supported=True,
                available=has_hyprctl,
                reason=None if has_hyprctl else "hyprctl not found in session PATH",
                required_dependency="hyprctl",
            ),
            "screenshot": PerCapabilityStatus(
                supported=True,
                available=has_grim,
                reason=None if has_grim else "grim binary not found in session PATH",
                required_dependency="grim",
            ),
            "accessibility": PerCapabilityStatus(
                supported=True,
                available=bool(find_session_binary("busctl", self.env)),
                reason=None if find_session_binary("busctl", self.env) else "busctl binary not found in session PATH",
                required_dependency="busctl / AT-SPI2 D-Bus",
            ),
            "input_pointer": PerCapabilityStatus(
                supported=True,
                available=True,
                reason=None,
                required_dependency="XDG RemoteDesktop portal and session D-Bus",
                required_permission="RemoteDesktop session grant",
            ),
            "input_keyboard": PerCapabilityStatus(
                supported=True,
                available=True,
                reason=None,
                required_dependency="XDG RemoteDesktop portal and session D-Bus",
                required_permission="RemoteDesktop session grant",
            ),
            "app_discovery": PerCapabilityStatus(
                supported=True,
                available=True,
                reason=None,
                required_dependency="XDG desktop directories",
            ),
            "app_launch": PerCapabilityStatus(
                supported=True,
                available=has_launcher,
                reason=None if has_launcher else "gtk-launch or gio not found",
                required_dependency="gtk-launch / gio",
            ),
            "clipboard_read": PerCapabilityStatus(
                supported=True,
                available=has_wl_paste,
                reason=None if has_wl_paste else "wl-paste not found in session PATH",
                required_dependency="wl-clipboard",
            ),
            "clipboard_write": PerCapabilityStatus(
                supported=True,
                available=has_wl_copy,
                reason=None if has_wl_copy else "wl-copy not found in session PATH",
                required_dependency="wl-clipboard",
            ),
            "notifications": PerCapabilityStatus(
                supported=True,
                available=has_notify,
                reason=None if has_notify else "notify-send not found in session PATH",
                required_dependency="notify-send / D-Bus",
            ),
        }

    def _run_hyprctl(self, args: List[str], timeout: float = 2.0) -> Optional[Any]:
        if not self.hyprctl:
            return None
        cmd = [self.hyprctl] + args
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self.env,
            )
            if res.returncode == 0 and res.stdout.strip():
                return json.loads(res.stdout)
            else:
                logger.debug(f"hyprctl {args} exited with code {res.returncode}: {res.stderr}")
        except subprocess.TimeoutExpired:
            logger.warning(f"hyprctl {args} timed out after {timeout}s")
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse hyprctl {args} JSON: {e}")
        except Exception as e:
            logger.error(f"Error executing hyprctl {args}: {e}")
        return None

    def list_windows(self) -> WindowListResponse:
        clients_data = self._run_hyprctl(["clients", "-j"])
        if clients_data is None:
            return WindowListResponse(
                success=False,
                total_windows=0,
                windows=[],
                compositor=self.name,
                message="Failed to query windows via hyprctl clients -j",
            )

        active_data = self._run_hyprctl(["activewindow", "-j"])
        active_addr = str(active_data.get("address", "")) if isinstance(active_data, dict) else ""

        windows: List[WindowInfo] = []
        focused_window: Optional[WindowInfo] = None

        if isinstance(clients_data, list):
            for c in clients_data:
                addr = str(c.get("address", ""))
                geom = None
                at = c.get("at", [0, 0])
                size = c.get("size", [0, 0])
                if len(at) >= 2 and len(size) >= 2:
                    geom = WindowGeometry(x=at[0], y=at[1], width=size[0], height=size[1])

                ws = c.get("workspace", {})
                is_foc = (addr == active_addr) and bool(addr)

                w_state = WindowState(
                    is_focused=is_foc,
                    is_minimized=False,
                    # Hyprland reports fullscreen independently and does not
                    # expose a separate maximized flag in this client record.
                    is_maximized=None,
                    is_fullscreen=bool(c.get("fullscreen", False)),
                    is_floating=bool(c.get("floating", False)),
                )

                win_info = WindowInfo(
                    id=addr,
                    app_id=str(c.get("class", "Unknown")),
                    title=str(c.get("title", "")),
                    workspace_id=str(ws.get("id")) if ws.get("id") is not None else None,
                    workspace_name=str(ws.get("name")) if ws.get("name") is not None else None,
                    is_focused=is_foc,
                    geometry=geom,
                    state=w_state,
                )
                windows.append(win_info)
                if is_foc:
                    focused_window = win_info

        return WindowListResponse(
            success=True,
            total_windows=len(windows),
            windows=windows,
            focused_window=focused_window,
            compositor=self.name,
            message=f"Discovered {len(windows)} active window(s) on Hyprland",
        )

    def get_window_detail(self, target: str) -> WindowDetailResponse:
        t = (target or "").strip()
        if not t:
            return WindowDetailResponse(
                success=False,
                window=None,
                compositor=self.name,
                message="Target window identifier is required.",
            )

        list_resp = self.list_windows()
        if not list_resp.success:
            return WindowDetailResponse(
                success=False,
                window=None,
                compositor=self.name,
                message=list_resp.message or "Failed to query windows.",
            )

        match = find_best_window(t, list_resp.windows)
        if match:
            return WindowDetailResponse(
                success=True,
                window=match,
                compositor=self.name,
                message=f"Retrieved window details for '{match.title[:45]}'.",
            )

        return WindowDetailResponse(
            success=False,
            window=None,
            compositor=self.name,
            message=f"No window matching '{t}' was found.",
        )

    def focus_window(self, target: str) -> ActionResult:
        t = (target or "").strip()
        if not t:
            return ActionResult(
                success=False,
                action="focus_window",
                target=target,
                message="Target window identifier is required.",
                requires_reobservation=True,
            )

        list_resp = self.list_windows()
        match = find_best_window(t, list_resp.windows) if list_resp.success else None

        if not match:
            return ActionResult(
                success=False,
                action="focus_window",
                target=target,
                message=f"Could not find window matching '{t}' on Hyprland. Focus aborted.",
                requires_reobservation=True,
            )

        # Strictly target by address - NEVER fall back to class selector
        selector = f"address:{match.id}"
        title = match.title or match.app_id
        lua = f"hl.dsp.focus({{ window = {_lua_quote(selector)} }})"
        try:
            res = self._dispatch("focuswindow", selector, lua_expr=lua)
            if "ok" in res.stdout.lower() or res.returncode == 0:
                return ActionResult(
                    success=True,
                    action="focus_window",
                    target=target,
                    message=f"Focused '{title[:45]}' (address: {match.id}).",
                    requires_reobservation=True,
                )
            return ActionResult(
                success=False,
                action="focus_window",
                target=target,
                message=f"Hyprland focus failed: {res.stdout.strip() or res.stderr.strip()}",
                requires_reobservation=True,
            )
        except Exception as e:
            return ActionResult(
                success=False,
                action="focus_window",
                target=target,
                message=f"Error executing hyprctl dispatch: {e}",
                requires_reobservation=True,
            )

    def close_window(self, target: str) -> ActionResult:
        t = (target or "").strip()
        list_resp = self.list_windows()
        match = find_best_window(t, list_resp.windows) if list_resp.success else None

        if not match:
            return ActionResult(
                success=False,
                action="close_window",
                target=target,
                message=f"Could not find open window matching '{t}' to close.",
                requires_reobservation=True,
            )

        selector = f"address:{match.id}"
        title = match.title or match.app_id
        lua = f"hl.dsp.window.close({{ window = {_lua_quote(selector)} }})"
        try:
            res = self._dispatch("closewindow", selector, lua_expr=lua)
            if "ok" in res.stdout.lower() or res.returncode == 0:
                return ActionResult(
                    success=True,
                    action="close_window",
                    target=target,
                    message=f"Dispatched window close request for '{title[:45]}' (address: {match.id}).",
                    requires_reobservation=True,
                )
            return ActionResult(
                success=False,
                action="close_window",
                target=target,
                message=f"Hyprland close failed: {res.stdout.strip() or res.stderr.strip()}",
                requires_reobservation=True,
            )
        except Exception as e:
            return ActionResult(
                success=False,
                action="close_window",
                target=target,
                message=f"Error executing hyprctl closewindow: {e}",
                requires_reobservation=True,
            )

    def resize_window(self, target: str, width: int, height: int) -> ActionResult:
        t = (target or "").strip()
        if not (1 <= width <= 8192 and 1 <= height <= 8192):
            return ActionResult(
                success=False,
                action="resize_window",
                target=target,
                message="Window dimensions must be between 1 and 8192 pixels.",
                requires_reobservation=True,
            )

        list_resp = self.list_windows()
        match = find_best_window(t, list_resp.windows) if list_resp.success else None

        if not match:
            return ActionResult(
                success=False,
                action="resize_window",
                target=target,
                message=f"Could not find window matching '{t}' to resize.",
                requires_reobservation=True,
            )

        selector = f"address:{match.id}"
        # Hyprland dispatch: resizewindowpixel [pixel_w] [pixel_h],address:<addr>
        args = f"exact {width} {height},{selector}"
        lua = f"hl.dsp.window.resize({{ window = {_lua_quote(selector)}, x = {width}, y = {height} }})"
        try:
            res = self._dispatch("resizewindowpixel", args, lua_expr=lua)
            if "ok" in res.stdout.lower() or res.returncode == 0:
                return ActionResult(
                    success=True,
                    action="resize_window",
                    target=target,
                    message=f"Resized '{match.title[:45]}' to {width}x{height}px.",
                    requires_reobservation=True,
                )
            return ActionResult(
                success=False,
                action="resize_window",
                target=target,
                message=f"Hyprland resize failed: {res.stdout.strip() or res.stderr.strip()}",
                requires_reobservation=True,
            )
        except Exception as e:
            return ActionResult(
                success=False,
                action="resize_window",
                target=target,
                message=f"Error executing hyprctl resize: {e}",
                requires_reobservation=True,
            )

    def minimize_window(self, target: str) -> ActionResult:
        return ActionResult(
            success=False,
            action="minimize_window",
            target=target,
            message="Hyprland does not support window minimization in its tiling layout.",
            requires_reobservation=True,
        )

    def maximize_window(self, target: str) -> ActionResult:
        return ActionResult(
            success=False,
            action="maximize_window",
            target=target,
            message="Per-window maximize is not implemented for Hyprland; use an explicit fullscreen action if desired.",
            requires_reobservation=False,
        )

    def list_workspaces(self) -> WorkspaceListResponse:
        ws_data = self._run_hyprctl(["workspaces", "-j"])
        active_ws_data = self._run_hyprctl(["activeworkspace", "-j"])
        active_ids = set()
        if isinstance(active_ws_data, dict) and active_ws_data.get("id") is not None:
            active_ids.add(str(active_ws_data["id"]))
        monitors = self._run_hyprctl(["monitors", "-j"])
        if isinstance(monitors, list):
            for monitor in monitors:
                active_workspace = monitor.get("activeWorkspace") if isinstance(monitor, dict) else None
                if isinstance(active_workspace, dict) and active_workspace.get("id") is not None:
                    active_ids.add(str(active_workspace["id"]))

        if not isinstance(ws_data, list):
            return WorkspaceListResponse(
                success=False,
                total_workspaces=0,
                workspaces=[],
                compositor=self.name,
                message="Failed to query workspaces via hyprctl workspaces -j",
            )

        workspaces: List[WorkspaceInfo] = []
        active_ws: Optional[WorkspaceInfo] = None

        for w in ws_data:
            w_id = str(w.get("id", ""))
            is_act = w_id in active_ids
            info = WorkspaceInfo(
                id=w_id,
                name=str(w.get("name", w_id)),
                is_active=is_act,
                is_focused=(isinstance(active_ws_data, dict) and w_id == str(active_ws_data.get("id"))),
                monitor=str(w.get("monitor", "")),
                windows_count=int(w.get("windows", 0)),
            )
            workspaces.append(info)
            if info.is_focused or (active_ws is None and is_act):
                active_ws = info

        return WorkspaceListResponse(
            success=True,
            total_workspaces=len(workspaces),
            workspaces=workspaces,
            active_workspace=active_ws,
            compositor=self.name,
            message=f"Discovered {len(workspaces)} workspace(s) on Hyprland",
        )

    def list_outputs(self) -> OutputListResponse:
        raw = self._run_hyprctl(["monitors", "-j"])
        if not isinstance(raw, list):
            return OutputListResponse(success=False, total_outputs=0, outputs=[], compositor=self.name,
                                      message="Failed to query outputs via hyprctl monitors -j.")
        outputs = []
        for item in raw:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            logical_geometry = None
            try:
                refresh = float(item["refreshRate"]) if item.get("refreshRate") is not None else None
                scale = float(item["scale"]) if item.get("scale") is not None else None
                width = int(item["width"]) if item.get("width") is not None else None
                height = int(item["height"]) if item.get("height") is not None else None
                transform = int(item.get("transform", 0))
                if (
                    scale is not None and scale > 0 and width is not None and height is not None
                    and item.get("x") is not None and item.get("y") is not None
                    and transform in {0, 2, 4, 6}
                ):
                    logical_width = width / scale
                    logical_height = height / scale
                    rounded_width = round(logical_width)
                    rounded_height = round(logical_height)
                    # Do not invent fractional layout bounds. Pointer actions
                    # stay disabled unless the monitor geometry is exact.
                    if (abs(logical_width - rounded_width) < 1e-6
                            and abs(logical_height - rounded_height) < 1e-6):
                        logical_geometry = WindowGeometry(
                            x=int(item["x"]), y=int(item["y"]),
                            width=rounded_width, height=rounded_height,
                        )
            except (TypeError, ValueError):
                refresh = scale = None
                width = height = None
            outputs.append(OutputInfo(
                id=str(item["name"]), name=str(item["name"]),
                make=str(item["make"]) if item.get("make") else None,
                model=str(item["model"]) if item.get("model") else None,
                enabled=bool(item.get("active", True)),
                is_focused=bool(item.get("focused", False)),
                width_pixels=width, height_pixels=height, refresh_rate_hz=refresh, scale=scale,
                logical_geometry=logical_geometry,
            ))
        return OutputListResponse(success=True, total_outputs=len(outputs), outputs=outputs,
                                  compositor=self.name, message=f"Discovered {len(outputs)} display output(s) on Hyprland.")

    def get_pointer_position(self) -> Optional[Tuple[float, float]]:
        raw = self._run_hyprctl(["cursorpos", "-j"])
        if not isinstance(raw, dict):
            return None
        x, y = raw.get("x"), raw.get("y")
        if not isinstance(x, (int, float)) or isinstance(x, bool):
            return None
        if not isinstance(y, (int, float)) or isinstance(y, bool):
            return None
        if not math.isfinite(float(x)) or not math.isfinite(float(y)):
            return None
        return float(x), float(y)

    def _all_active_outputs_dpms_off(self) -> bool:
        monitors = self._run_hyprctl(["monitors", "-j"])
        if not isinstance(monitors, list):
            return False
        active = [
            monitor for monitor in monitors
            if isinstance(monitor, dict) and monitor.get("disabled") is not True
        ]
        return bool(active) and all(monitor.get("dpmsStatus") is False for monitor in active)

    def switch_workspace(self, workspace: str) -> ActionResult:
        ws = (workspace or "").strip()
        if not re.fullmatch(r"-?\d+", ws):
            return ActionResult(
                success=False,
                action="switch_workspace",
                target=workspace,
                message="Hyprland workspace actions require an exact numeric ID from list_workspaces.",
                requires_reobservation=True,
            )

        lua = f"hl.dsp.focus({{ workspace = {_lua_quote(ws)} }})"
        try:
            res = self._dispatch("workspace", ws, lua_expr=lua)
            if "ok" in res.stdout.lower() or res.returncode == 0:
                return ActionResult(
                    success=True,
                    action="switch_workspace",
                    target=workspace,
                    message=f"Switched active workspace to '{ws}'.",
                    requires_reobservation=True,
                )
            return ActionResult(
                success=False,
                action="switch_workspace",
                target=workspace,
                message=f"Failed to switch workspace: {res.stdout.strip() or res.stderr.strip()}",
                requires_reobservation=True,
            )
        except Exception as e:
            return ActionResult(
                success=False,
                action="switch_workspace",
                target=workspace,
                message=f"Error executing hyprctl workspace: {e}",
                requires_reobservation=True,
            )

    def move_window_to_workspace(self, target: str, workspace: str) -> ActionResult:
        t = (target or "").strip()
        ws = (workspace or "").strip()
        if not re.fullmatch(r"-?\d+", ws):
            return ActionResult(success=False, action="move_window_to_workspace", target=f"{t} -> {ws}",
                                message="Hyprland workspace actions require an exact numeric ID from list_workspaces.")
        list_resp = self.list_windows()
        match = find_best_window(t, list_resp.windows) if list_resp.success else None

        if not match:
            return ActionResult(
                success=False,
                action="move_window_to_workspace",
                target=f"{t} -> {ws}",
                message=f"Could not find window matching '{t}' to move.",
                requires_reobservation=True,
            )

        selector = f"address:{match.id}"
        title = match.title or match.app_id
        args = f"{ws},{selector}"
        lua = f"hl.dsp.window.move({{ workspace = {_lua_quote(ws)}, window = {_lua_quote(selector)}, follow = false }})"
        try:
            res = self._dispatch("movetoworkspacesilent", args, lua_expr=lua)
            stdout_clean = res.stdout.strip().lower()
            if "ok" in stdout_clean and "invalid" not in stdout_clean:
                return ActionResult(
                    success=True,
                    action="move_window_to_workspace",
                    target=f"{t} -> {ws}",
                    message=f"Moved '{title[:45]}' to workspace '{ws}'.",
                    requires_reobservation=True,
                )
            return ActionResult(
                success=False,
                action="move_window_to_workspace",
                target=f"{t} -> {ws}",
                message=f"Failed to move window: {res.stdout.strip() or res.stderr.strip()}",
                requires_reobservation=True,
            )
        except Exception as e:
            return ActionResult(
                success=False,
                action="move_window_to_workspace",
                target=f"{t} -> {ws}",
                message=f"Error executing hyprctl movetoworkspace: {e}",
                requires_reobservation=True,
            )

    def capture_screenshot(
        self, scope: str = "window", target: Optional[str] = None
    ) -> Tuple[bool, bytes, Optional[WindowGeometry], str]:
        grim = find_session_binary("grim", self.env)
        if not grim:
            return (False, b"", None, "grim binary not found in session PATH.")

        target_geom: Optional[WindowGeometry] = None
        cmd = [grim]

        if scope == "window":
            win_info: Optional[WindowInfo] = None
            if target:
                list_resp = self.list_windows()
                if list_resp.success:
                    win_info = find_best_window(target, list_resp.windows)
            else:
                list_resp = self.list_windows()
                if list_resp.success and list_resp.focused_window:
                    win_info = list_resp.focused_window

            # FAILS CLOSED: Never widen window scope to full desktop!
            if not win_info or not win_info.geometry or win_info.geometry.width <= 0 or win_info.geometry.height <= 0:
                return (
                    False,
                    b"",
                    None,
                    f"Window-scoped screenshot failed closed: target '{target or 'focused'}' window or bounds unavailable. Full desktop fallback is prohibited.",
                )

            target_geom = win_info.geometry
            cmd.extend(["-g", f"{target_geom.x},{target_geom.y} {target_geom.width}x{target_geom.height}"])

        if self._all_active_outputs_dpms_off():
            return (
                False,
                b"",
                target_geom,
                "All active Hyprland outputs are DPMS-off; wake a display and capture a fresh screenshot.",
            )

        cmd.append("-")  # output PNG to stdout

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                timeout=SCREENSHOT_TIMEOUT_SECONDS,
                env=self.env,
            )
            if res.returncode == 0 and res.stdout.startswith(b"\x89PNG\r\n\x1a\n"):
                return (True, res.stdout, target_geom, "Screenshot captured successfully.")
            err_msg = res.stderr.decode("utf-8", errors="replace").strip()
            return (False, b"", target_geom, f"grim screenshot failed: {err_msg}")
        except subprocess.TimeoutExpired as exc:
            partial_stderr = exc.stderr or b""
            if isinstance(partial_stderr, bytes):
                partial_stderr = partial_stderr.decode("utf-8", errors="replace")
            detail = " ".join(str(partial_stderr).split())[:240]
            return (
                False,
                b"",
                target_geom,
                f"grim screenshot timed out after {SCREENSHOT_TIMEOUT_SECONDS:.1f}s."
                + (f" stderr: {detail}" if detail else ""),
            )
        except Exception as e:
            return (False, b"", target_geom, f"Error capturing screenshot: {e}")
