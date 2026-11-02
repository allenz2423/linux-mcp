import json
import math
import socket
import subprocess
from typing import Dict, Optional, List, Any, Tuple
from wayland_mcp.backends.base import BaseCompositorBackend
from wayland_mcp.matching import find_best_window
from wayland_mcp.models import (
    ActionResult,
    CompositorCapabilities,
    WindowGeometry,
    WindowInfo,
    WindowState,
    WindowListResponse,
    FocusedWindowResponse,
    WorkspaceInfo,
    WorkspaceListResponse,
    OutputInfo,
    OutputListResponse,
)
from wayland_mcp.session import find_session_binary, logger


class NiriBackend(BaseCompositorBackend):
    name: str = "niri"

    def __init__(self, env: Optional[Dict[str, str]] = None) -> None:
        super().__init__(env)
        self.niri = find_session_binary("niri", self.env)

    def get_capabilities(self) -> CompositorCapabilities:
        available = bool(self.niri and self.env.get("NIRI_SOCKET"))
        has_grim = bool(find_session_binary("grim", self.env) and available)
        unsupported = []
        if not self.niri:
            unsupported.append("niri binary not found in PATH")
        if not self.env.get("NIRI_SOCKET"):
            unsupported.append("NIRI_SOCKET environment variable not set")
        if not has_grim:
            unsupported.append("grim binary not found in session PATH for screenshots")
        unsupported.extend(["window_resize", "window_minimize", "window_maximize"])
        return CompositorCapabilities(
            window_list=available,
            window_detail=available,
            window_focus=available,
            window_close=available,
            window_move=available,
            workspace_list=available,
            output_list=available,
            workspace_switch=available,
            screenshot=has_grim,
            bounded_input=False,
            app_discovery=True,
            app_launch=False,
            unsupported_operations=unsupported,
        )

    def _run_niri_msg(self, args: List[str], timeout: float = 2.0) -> Optional[Any]:
        if not self.niri:
            return None
        cmd = [self.niri, "msg", "--json"] + args
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
                logger.debug(f"niri msg {args} failed: {res.stderr}")
        except Exception as e:
            logger.warning(f"Error running niri msg {args}: {e}")
        return None

    def _send_action(self, action: dict, timeout: float = 2.0) -> tuple[bool, str]:
        """Send one exact Niri IPC action through its documented Unix socket."""
        socket_path = self.env.get("NIRI_SOCKET")
        if not socket_path:
            return False, "NIRI_SOCKET is not set."
        request = json.dumps({"Action": action}, separators=(",", ":")).encode("utf-8") + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout)
                connection.connect(socket_path)
                connection.sendall(request)
                connection.shutdown(socket.SHUT_WR)
                chunks: list[bytes] = []
                total = 0
                while total <= 1024 * 1024:
                    chunk = connection.recv(min(65536, 1024 * 1024 + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if b"\n" in chunk:
                        break
            raw = b"".join(chunks).split(b"\n", 1)[0]
            if not raw:
                return False, "Niri returned an empty IPC response."
            reply = json.loads(raw)
            if isinstance(reply, dict) and "Ok" in reply:
                return True, "Niri accepted the action."
            if isinstance(reply, dict) and "Err" in reply:
                return False, str(reply["Err"])[:300]
            return False, "Niri returned an unrecognized IPC response."
        except socket.timeout:
            return False, f"Niri IPC action timed out after {timeout:.1f}s."
        except (OSError, json.JSONDecodeError) as exc:
            return False, f"Niri IPC action failed: {type(exc).__name__}."

    @staticmethod
    def _exact_int(value: Any) -> Optional[int]:
        """Return an integer coordinate only when the IPC value is exact."""
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if not isinstance(value, float) or not math.isfinite(value) or value != round(value):
            return None
        return int(value)

    @classmethod
    def _exact_pair(cls, value: Any) -> Optional[tuple[int, int]]:
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            return None
        first = cls._exact_int(value[0])
        second = cls._exact_int(value[1])
        if first is None or second is None:
            return None
        return first, second

    def _visible_workspace_outputs(self) -> dict[str, WindowGeometry]:
        """Map only workspaces known to be visible to exact output bounds."""
        workspaces = self._run_niri_msg(["workspaces"])
        if not isinstance(workspaces, list):
            return {}
        output_response = self.list_outputs()
        if not output_response.success:
            return {}
        outputs: dict[str, list[WindowGeometry]] = {}
        for output in output_response.outputs:
            if output.enabled and output.logical_geometry is not None:
                outputs.setdefault(output.name, []).append(output.logical_geometry)

        result: dict[str, WindowGeometry] = {}
        for workspace in workspaces:
            if not isinstance(workspace, dict):
                continue
            workspace_id = workspace.get("id")
            output_name = workspace.get("output")
            is_visible = workspace.get("is_active") is True or workspace.get("is_focused") is True
            if workspace_id is None or not isinstance(output_name, str) or not output_name or not is_visible:
                continue
            matching_outputs = outputs.get(output_name, [])
            if len(matching_outputs) == 1:
                result[str(workspace_id)] = matching_outputs[0]
        return result

    @staticmethod
    def _window_geometry(window: dict, output: Optional[WindowGeometry]) -> Optional[WindowGeometry]:
        """Project an exactly positioned visible Niri tile into compositor coordinates.

        Niri may omit tile positions, including for tiled windows. Fractional
        logical pixels also cannot be represented exactly by WindowGeometry;
        both cases intentionally remain geometry-less.
        """
        if output is None:
            return None
        layout = window.get("layout")
        if not isinstance(layout, dict):
            return None
        position = NiriBackend._exact_pair(layout.get("tile_pos_in_workspace_view"))
        size = NiriBackend._exact_pair(layout.get("tile_size"))
        if position is None or size is None:
            return None
        local_x, local_y = position
        width, height = size
        if width <= 0 or height <= 0:
            return None
        x = output.x + local_x
        y = output.y + local_y
        if x < output.x or y < output.y or x + width > output.x + output.width or y + height > output.y + output.height:
            return None
        return WindowGeometry(x=x, y=y, width=width, height=height)

    def list_windows(self) -> WindowListResponse:
        data = self._run_niri_msg(["windows"])
        if not isinstance(data, list):
            return WindowListResponse(
                success=False,
                total_windows=0,
                windows=[],
                compositor=self.name,
                message="Failed to retrieve windows from niri msg -j windows",
            )

        windows: List[WindowInfo] = []
        focused: Optional[WindowInfo] = None
        needs_geometry = any(
            isinstance(window, dict)
            and isinstance(window.get("layout"), dict)
            and window["layout"].get("tile_pos_in_workspace_view") is not None
            for window in data
        )
        visible_outputs = self._visible_workspace_outputs() if needs_geometry else {}

        for w in data:
            if not isinstance(w, dict):
                continue
            is_focused = bool(w.get("is_focused", False))
            workspace_id = str(w.get("workspace_id")) if w.get("workspace_id") is not None else None
            output = visible_outputs.get(workspace_id) if workspace_id is not None else None
            win = WindowInfo(
                id=str(w.get("id", "")),
                app_id=str(w.get("app_id") or "Unknown"),
                title=str(w.get("title", "")),
                workspace_id=workspace_id,
                workspace_name=workspace_id,
                is_focused=is_focused,
                geometry=self._window_geometry(w, output),
                state=WindowState(
                    is_focused=is_focused,
                    is_floating=w.get("is_floating") is True,
                    is_fullscreen=w.get("is_fullscreen") is True,
                ),
            )
            windows.append(win)
            if is_focused:
                focused = win

        return WindowListResponse(
            success=True,
            total_windows=len(windows),
            windows=windows,
            focused_window=focused,
            compositor=self.name,
            message=f"Discovered {len(windows)} active window(s) on Niri",
        )

    def get_focused_window(self) -> FocusedWindowResponse:
        windows_resp = self.list_windows()
        if not windows_resp.success:
            return FocusedWindowResponse(
                success=False,
                window=None,
                message=windows_resp.message,
            )
        if windows_resp.focused_window:
            return FocusedWindowResponse(
                success=True,
                window=windows_resp.focused_window,
            )
        return FocusedWindowResponse(
            success=True,
            window=None,
            message="No window currently focused on Niri",
        )

    def list_workspaces(self) -> WorkspaceListResponse:
        data = self._run_niri_msg(["workspaces"])
        if not isinstance(data, list):
            return WorkspaceListResponse(
                success=False, total_workspaces=0, workspaces=[], compositor=self.name,
                message="Failed to retrieve workspaces from niri msg -j workspaces.",
            )
        window_response = self.list_windows()
        window_counts: dict[str, int] = {}
        if window_response.success:
            for window in window_response.windows:
                if window.workspace_id:
                    window_counts[window.workspace_id] = window_counts.get(window.workspace_id, 0) + 1
        workspaces: List[WorkspaceInfo] = []
        active = None
        for item in data:
            workspace_id = str(item.get("id", ""))
            if not workspace_id:
                continue
            is_active = bool(item.get("is_active", item.get("is_focused", False)))
            info = WorkspaceInfo(
                id=workspace_id,
                name=str(item.get("name") or item.get("idx") or workspace_id),
                is_active=is_active,
                is_focused=bool(item.get("is_focused", False)),
                monitor=str(item.get("output")) if item.get("output") else None,
                windows_count=window_counts.get(workspace_id, 0),
            )
            workspaces.append(info)
            if info.is_focused or (active is None and is_active):
                active = info
        return WorkspaceListResponse(
            success=True, total_workspaces=len(workspaces), workspaces=workspaces,
            active_workspace=active, compositor=self.name,
            message=f"Discovered {len(workspaces)} workspace(s) on Niri.",
        )

    def list_outputs(self) -> OutputListResponse:
        raw = self._run_niri_msg(["outputs"])
        if isinstance(raw, dict):
            items = [(str(name), value) for name, value in raw.items()]
        elif isinstance(raw, list):
            items = [(str(item.get("name", "")), item) for item in raw if isinstance(item, dict)]
        else:
            return OutputListResponse(success=False, total_outputs=0, outputs=[], compositor=self.name,
                                      message="Failed to retrieve outputs from Niri IPC.")
        outputs = []
        for name, item in items:
            if not isinstance(item, dict) or not name:
                continue
            logical = item.get("logical") if isinstance(item.get("logical"), dict) else None
            mode = None
            modes = item.get("modes")
            current_mode = item.get("current_mode")
            if isinstance(modes, list) and isinstance(current_mode, int) and 0 <= current_mode < len(modes):
                candidate = modes[current_mode]
                mode = candidate if isinstance(candidate, dict) else None
            logical_geometry = None
            width = height = None
            refresh = scale = None
            try:
                if logical and all(key in logical for key in ("x", "y", "width", "height")):
                    coordinates = [self._exact_int(logical[key]) for key in ("x", "y", "width", "height")]
                    if all(value is not None for value in coordinates):
                        logical_geometry = WindowGeometry(
                            x=coordinates[0], y=coordinates[1], width=coordinates[2], height=coordinates[3]
                        )
                    scale = float(logical["scale"]) if logical.get("scale") is not None else None
                if mode:
                    width = self._exact_int(mode["width"]) if mode.get("width") is not None else None
                    height = self._exact_int(mode["height"]) if mode.get("height") is not None else None
                    refresh = float(mode["refresh_rate"]) / 1000.0 if mode.get("refresh_rate") is not None else None
            except (TypeError, ValueError, OverflowError):
                logical_geometry = None
                width = height = None
                refresh = scale = None
            outputs.append(OutputInfo(
                id=name, name=name,
                make=str(item["make"]) if item.get("make") else None,
                model=str(item["model"]) if item.get("model") else None,
                enabled=current_mode is not None,
                width_pixels=width, height_pixels=height, refresh_rate_hz=refresh, scale=scale,
                logical_geometry=logical_geometry,
            ))
        return OutputListResponse(success=True, total_outputs=len(outputs), outputs=outputs,
                                  compositor=self.name, message=f"Discovered {len(outputs)} display output(s) on Niri.")

    def focus_window(self, target: str) -> ActionResult:
        t = (target or "").strip()
        list_resp = self.list_windows()
        match = find_best_window(t, list_resp.windows) if list_resp.success else None

        if match:
            if not match.id.isdigit():
                return ActionResult(
                    success=False,
                    action="focus_window",
                    target=target,
                    message=f"Invalid window ID '{match.id}' for Niri.",
                    requires_reobservation=True,
                )
            ok, detail = self._send_action({"FocusWindow": {"id": int(match.id)}})
            return ActionResult(
                success=ok, action="focus_window", target=target,
                message=(f"Focused '{match.title[:45]}' on Niri." if ok else f"Niri focus-window failed: {detail}"),
                requires_reobservation=True,
            )

        return ActionResult(
            success=False,
            action="focus_window",
            target=target,
            message=f"Could not find window matching '{t}' on Niri.",
            requires_reobservation=True,
        )

    def close_window(self, target: str) -> ActionResult:
        t = (target or "").strip()
        list_resp = self.list_windows()
        match = find_best_window(t, list_resp.windows) if list_resp.success else None

        if match:
            if not match.id.isdigit():
                return ActionResult(
                    success=False,
                    action="close_window",
                    target=target,
                    message=f"Invalid window ID '{match.id}' for Niri.",
                    requires_reobservation=True,
                )
            ok, detail = self._send_action({"CloseWindow": {"id": int(match.id)}})
            return ActionResult(
                success=ok, action="close_window", target=target,
                message=(f"Sent Niri's close request for '{match.title[:45]}'." if ok else f"Niri close-window failed: {detail}"),
                requires_reobservation=True,
            )

        return ActionResult(
            success=False,
            action="close_window",
            target=target,
            message=f"Could not find window matching '{t}' to close on Niri.",
            requires_reobservation=True,
        )

    def switch_workspace(self, workspace: str) -> ActionResult:
        ws = (workspace or "").strip()
        if not ws.isdigit():
            return ActionResult(success=False, action="switch_workspace", target=workspace,
                                message="Niri workspace IDs must be numeric.")
        ok, detail = self._send_action({"FocusWorkspace": {"reference": {"Id": int(ws)}}})
        return ActionResult(
            success=ok, action="switch_workspace", target=workspace,
            message=(f"Focused Niri workspace ID {ws}." if ok else f"Failed to switch workspace on Niri: {detail}"),
            requires_reobservation=True,
        )

    def move_window_to_workspace(self, target: str, workspace: str) -> ActionResult:
        t = (target or "").strip()
        ws = (workspace or "").strip()
        list_resp = self.list_windows()
        match = find_best_window(t, list_resp.windows) if list_resp.success else None

        if not match:
            return ActionResult(
                success=False,
                action="move_window_to_workspace",
                target=f"{t} -> {ws}",
                message=f"Could not find window matching '{t}' on Niri to move.",
                requires_reobservation=True,
            )

        if not match.id.isdigit():
            return ActionResult(
                success=False,
                action="move_window_to_workspace",
                target=f"{t} -> {ws}",
                message=f"Invalid window ID '{match.id}' for Niri; expected numeric ID.",
                requires_reobservation=True,
            )

        if not ws.isdigit():
            return ActionResult(success=False, action="move_window_to_workspace", target=f"{t} -> {ws}",
                                message="Niri workspace IDs must be numeric.")
        ok, detail = self._send_action({
            "MoveWindowToWorkspace": {
                "window_id": int(match.id),
                "reference": {"Id": int(ws)},
                "focus": False,
            }
        })
        return ActionResult(
            success=ok, action="move_window_to_workspace", target=f"{t} -> {ws}",
            message=(f"Moved window '{match.title[:45]}' (ID {match.id}) to workspace ID {ws}."
                     if ok else f"Failed to move window on Niri: {detail}"),
            requires_reobservation=True,
        )

    def capture_screenshot(
        self, scope: str = "window", target: Optional[str] = None
    ) -> Tuple[bool, bytes, Optional[WindowGeometry], str]:
        grim = find_session_binary("grim", self.env)
        if not grim:
            return (False, b"", None, "grim binary not found in session PATH.")

        if scope not in {"window", "desktop"}:
            return (False, b"", None, "Screenshot scope must be 'window' or 'desktop'.")
        if scope == "window":
            listed = self.list_windows()
            if not listed.success:
                return (False, b"", None, "Could not verify the current Niri window list for a targeted screenshot.")
            selected = (
                next((window for window in listed.windows if window.id == target), None)
                if target is not None else listed.focused_window
            )
            if selected is None:
                return (False, b"", None, "Exact target window ID was not found; targeted screenshot failed closed.")
            if selected.geometry is None:
                return (
                    False, b"", None,
                    "Niri did not provide exact visible bounds for this window; targeted screenshot failed closed.",
                )
            geometry = selected.geometry
            region = f"{geometry.x},{geometry.y} {geometry.width}x{geometry.height}"
            try:
                res = subprocess.run(
                    [grim, "-g", region, "-"], capture_output=True, timeout=3.0, env=self.env
                )
                if res.returncode == 0 and res.stdout.startswith(b"\x89PNG\r\n\x1a\n"):
                    return (True, res.stdout, geometry, "Niri window region captured via grim.")
                detail = res.stderr.decode("utf-8", errors="replace").strip()
                return (False, b"", None, f"Niri window screenshot failed: {detail or 'grim returned an error'}")
            except subprocess.TimeoutExpired:
                return (False, b"", None, "Niri window screenshot timed out after 3.0s.")
            except Exception as e:
                return (False, b"", None, f"Error capturing Niri window screenshot: {e}")

        cmd = [grim, "-"]
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=3.0, env=self.env)
            if res.returncode == 0 and res.stdout.startswith(b"\x89PNG\r\n\x1a\n"):
                return (True, res.stdout, None, "Screenshot captured via grim.")
            return (False, b"", None, f"Screenshot capture failed: {res.stderr.decode('utf-8', errors='replace').strip()}")
        except subprocess.TimeoutExpired:
            return (False, b"", None, "Screenshot capture timed out after 3.0s.")
        except Exception as e:
            return (False, b"", None, f"Error capturing screenshot: {e}")
