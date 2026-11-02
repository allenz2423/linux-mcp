import json
import subprocess
from typing import Dict, Optional, List, Any, Tuple
from wayland_mcp.backends.base import BaseCompositorBackend
from wayland_mcp.matching import find_best_window
from wayland_mcp.models import (
    ActionResult,
    CompositorCapabilities,
    WindowGeometry,
    WindowInfo,
    WindowListResponse,
    FocusedWindowResponse,
    WorkspaceInfo,
    WorkspaceListResponse,
    OutputInfo,
    OutputListResponse,
)
from wayland_mcp.session import find_session_binary, logger


def _escape_sway_string(s: str) -> str:
    """Escape backslashes and double quotes for Sway command/criteria syntax."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _valid_workspace_name(value: str) -> bool:
    return bool(value) and len(value) <= 128 and all(ord(char) >= 0x20 and ord(char) != 0x7F for char in value)


class SwayBackend(BaseCompositorBackend):
    name: str = "sway"

    def __init__(self, env: Optional[Dict[str, str]] = None) -> None:
        super().__init__(env)
        self.swaymsg = find_session_binary("swaymsg", self.env)

    def get_capabilities(self) -> CompositorCapabilities:
        available = bool(self.swaymsg and self.env.get("SWAYSOCK"))
        has_grim = bool(find_session_binary("grim", self.env) and available)
        unsupported = []
        if not self.swaymsg:
            unsupported.append("swaymsg binary not found in PATH")
        if not self.env.get("SWAYSOCK"):
            unsupported.append("SWAYSOCK environment variable not set")
        if not has_grim:
            unsupported.append("grim binary not found in session PATH for screenshots")
        unsupported.extend(["window_minimize", "window_maximize"])
        return CompositorCapabilities(
            window_list=available,
            window_detail=available,
            window_focus=available,
            window_close=available,
            window_resize=available,
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

    def _run_swaymsg(self, args: List[str], timeout: float = 2.0) -> Optional[Any]:
        if not self.swaymsg:
            return None
        cmd = [self.swaymsg] + args
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
                logger.debug(f"swaymsg {args} failed: {res.stderr}")
        except Exception as e:
            logger.warning(f"Error running swaymsg {args}: {e}")
        return None

    def _extract_nodes(self, tree: dict, workspace_name: Optional[str] = None) -> List[tuple[dict, Optional[str]]]:
        results: List[tuple[dict, Optional[str]]] = []
        current_ws = workspace_name
        if tree.get("type") == "workspace":
            current_ws = tree.get("name")

        # Leaf containers that represent windows have an id and either app_id or window_properties
        if tree.get("type") in ("con", "floating_con") and (tree.get("app_id") or tree.get("name") or tree.get("window_properties")):
            # If it has sub-nodes, only treat as leaf if it has no children nodes
            children = tree.get("nodes", []) + tree.get("floating_nodes", [])
            if not children:
                results.append((tree, current_ws))

        for child in tree.get("nodes", []):
            results.extend(self._extract_nodes(child, current_ws))
        for child in tree.get("floating_nodes", []):
            results.extend(self._extract_nodes(child, current_ws))

        return results

    def _node_to_window_info(self, node: dict, workspace_name: Optional[str]) -> WindowInfo:
        rect = node.get("rect", {})
        geom = WindowGeometry(
            x=rect.get("x", 0),
            y=rect.get("y", 0),
            width=rect.get("width", 0),
            height=rect.get("height", 0),
        )
        app_id = (
            node.get("app_id")
            or (node.get("window_properties", {}).get("class") if isinstance(node.get("window_properties"), dict) else None)
            or "Unknown"
        )
        return WindowInfo(
            id=str(node.get("id", "")),
            app_id=str(app_id),
            title=str(node.get("name", "")),
            workspace_id=workspace_name,
            workspace_name=workspace_name,
            is_focused=bool(node.get("focused", False)),
            geometry=geom,
        )

    def list_windows(self) -> WindowListResponse:
        tree = self._run_swaymsg(["-t", "get_tree"])
        if not tree or not isinstance(tree, dict):
            return WindowListResponse(
                success=False,
                total_windows=0,
                windows=[],
                compositor=self.name,
                message="Failed to retrieve tree via swaymsg -t get_tree",
            )

        raw_nodes = self._extract_nodes(tree)
        windows: List[WindowInfo] = []
        focused: Optional[WindowInfo] = None

        for node, ws_name in raw_nodes:
            win = self._node_to_window_info(node, ws_name)
            windows.append(win)
            if win.is_focused:
                focused = win

        return WindowListResponse(
            success=True,
            total_windows=len(windows),
            windows=windows,
            focused_window=focused,
            compositor=self.name,
            message=f"Discovered {len(windows)} active window(s) on Sway",
        )

    def get_focused_window(self) -> FocusedWindowResponse:
        tree = self._run_swaymsg(["-t", "get_tree"])
        if not tree or not isinstance(tree, dict):
            return FocusedWindowResponse(
                success=False,
                window=None,
                message="Could not inspect Sway window tree",
            )

        raw_nodes = self._extract_nodes(tree)
        for node, ws_name in raw_nodes:
            if node.get("focused"):
                return FocusedWindowResponse(
                    success=True,
                    window=self._node_to_window_info(node, ws_name),
                )

        return FocusedWindowResponse(
            success=True,
            window=None,
            message="No window currently focused on Sway",
        )

    def list_workspaces(self) -> WorkspaceListResponse:
        raw = self._run_swaymsg(["-t", "get_workspaces"])
        if not isinstance(raw, list):
            return WorkspaceListResponse(
                success=False, total_workspaces=0, workspaces=[], compositor=self.name,
                message="Failed to retrieve workspaces via swaymsg -t get_workspaces.",
            )
        tree = self._run_swaymsg(["-t", "get_tree"])
        counts: Dict[str, int] = {}
        if isinstance(tree, dict):
            for _, workspace_name in self._extract_nodes(tree):
                if workspace_name:
                    counts[workspace_name] = counts.get(workspace_name, 0) + 1
        workspaces: List[WorkspaceInfo] = []
        active = None
        for item in raw:
            name = str(item.get("name", ""))
            if not name:
                continue
            info = WorkspaceInfo(
                id=name,
                name=name,
                is_active=bool(item.get("visible", item.get("focused", False))),
                is_focused=bool(item.get("focused", False)),
                monitor=str(item.get("output")) if item.get("output") else None,
                windows_count=counts.get(name, 0),
            )
            workspaces.append(info)
            if info.is_focused or (active is None and info.is_active):
                active = info
        return WorkspaceListResponse(
            success=True, total_workspaces=len(workspaces), workspaces=workspaces,
            active_workspace=active, compositor=self.name,
            message=f"Discovered {len(workspaces)} workspace(s) on Sway.",
        )

    def list_outputs(self) -> OutputListResponse:
        raw = self._run_swaymsg(["-t", "get_outputs"])
        if not isinstance(raw, list):
            return OutputListResponse(success=False, total_outputs=0, outputs=[], compositor=self.name,
                                      message="Failed to retrieve outputs via swaymsg -t get_outputs.")
        outputs = []
        for item in raw:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            mode = item.get("current_mode") if isinstance(item.get("current_mode"), dict) else {}
            rect = item.get("rect") if isinstance(item.get("rect"), dict) else {}
            logical_geometry = None
            try:
                if all(key in rect for key in ("x", "y", "width", "height")):
                    logical_geometry = WindowGeometry(x=int(rect["x"]), y=int(rect["y"]),
                                                      width=int(rect["width"]), height=int(rect["height"]))
                refresh_raw = mode.get("refresh")
                refresh = float(refresh_raw) / 1000.0 if refresh_raw is not None else None
                width = int(mode["width"]) if mode.get("width") is not None else None
                height = int(mode["height"]) if mode.get("height") is not None else None
                scale = float(item["scale"]) if item.get("scale") is not None else None
            except (TypeError, ValueError):
                refresh = scale = None
                width = height = None
                logical_geometry = None
            outputs.append(OutputInfo(
                id=str(item["name"]), name=str(item["name"]),
                make=str(item["make"]) if item.get("make") else None,
                model=str(item["model"]) if item.get("model") else None,
                enabled=bool(item.get("active", False)), is_focused=bool(item.get("focused", False)),
                width_pixels=width, height_pixels=height, refresh_rate_hz=refresh, scale=scale,
                logical_geometry=logical_geometry,
            ))
        return OutputListResponse(success=True, total_outputs=len(outputs), outputs=outputs,
                                  compositor=self.name, message=f"Discovered {len(outputs)} display output(s) on Sway.")

    def resize_window(self, target: str, width: int, height: int) -> ActionResult:
        listed = self.list_windows()
        match = find_best_window(target, listed.windows) if listed.success else None
        if not match or not match.id.isdigit():
            return ActionResult(success=False, action="resize_window", target=target,
                                message="Exact observed Sway window ID was not found.")
        if not (1 <= width <= 8192 and 1 <= height <= 8192):
            return ActionResult(success=False, action="resize_window", target=target,
                                message="Window dimensions must be between 1 and 8192 pixels.")
        cmd = [self.swaymsg or "swaymsg",
               f"[con_id={match.id}] resize set width {width} px height {height} px"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0, env=self.env)
            ok = res.returncode == 0 and "false" not in res.stdout.lower()
            return ActionResult(
                success=ok, action="resize_window", target=target,
                message=(f"Requested {width}x{height}px size for '{match.title[:45]}'." if ok
                         else f"Sway rejected resize request: {res.stderr.strip() or res.stdout.strip()}"),
            )
        except subprocess.TimeoutExpired:
            return ActionResult(success=False, action="resize_window", target=target,
                                message="Sway resize request timed out after 2.0s.")

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

        if not match or not match.id.isdigit() or not self.swaymsg:
            return ActionResult(
                success=False, action="focus_window", target=target,
                message="Exact observed Sway window ID was not found; focus aborted.",
            )
        cmd = [self.swaymsg, f"[con_id={match.id}] focus"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0, env=self.env)
            if res.returncode == 0 and "false" not in res.stdout.lower():
                return ActionResult(
                    success=True,
                    action="focus_window",
                    target=target,
                    message=f"Focused '{match.title[:45]}' on Sway.",
                    requires_reobservation=True,
                )
        except subprocess.TimeoutExpired:
            return ActionResult(
                success=False,
                action="focus_window",
                target=target,
                message="Sway focus-window command timed out after 2.0s.",
                requires_reobservation=True,
            )
        except Exception as e:
            return ActionResult(
                success=False,
                action="focus_window",
                target=target,
                message=f"Error executing swaymsg: {e}",
                requires_reobservation=True,
            )

        return ActionResult(success=False, action="focus_window", target=target,
                            message="Sway rejected the exact window focus request.")

    def close_window(self, target: str) -> ActionResult:
        t = (target or "").strip()
        list_resp = self.list_windows()
        match = find_best_window(t, list_resp.windows) if list_resp.success else None

        if match and match.id.isdigit():
            cmd = [self.swaymsg or "swaymsg", f"[con_id={match.id}] kill"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0, env=self.env)
                if res.returncode == 0 and "false" not in res.stdout.lower():
                    return ActionResult(
                        success=True,
                        action="close_window",
                        target=target,
                        message=f"Sent Sway's kill request to window '{match.title[:45]}'.",
                        requires_reobservation=True,
                    )
                return ActionResult(
                    success=False,
                    action="close_window",
                    target=target,
                    message=f"Failed to close window on Sway: {res.stderr or res.stdout}",
                    requires_reobservation=True,
                )
            except subprocess.TimeoutExpired:
                return ActionResult(
                    success=False,
                    action="close_window",
                    target=target,
                    message="Sway close-window command timed out after 2.0s.",
                    requires_reobservation=True,
                )
            except Exception as e:
                return ActionResult(
                    success=False,
                    action="close_window",
                    target=target,
                    message=f"Error executing swaymsg: {e}",
                    requires_reobservation=True,
                )

        return ActionResult(
            success=False,
            action="close_window",
            target=target,
            message=f"Could not find window matching '{t}' to close on Sway.",
            requires_reobservation=True,
        )

    def switch_workspace(self, workspace: str) -> ActionResult:
        ws = (workspace or "").strip()
        if not _valid_workspace_name(ws):
            return ActionResult(
                success=False,
                action="switch_workspace",
                target=workspace,
                message="Target workspace identifier is invalid or contains unsafe characters.",
                requires_reobservation=True,
            )

        escaped_ws = _escape_sway_string(ws)
        cmd = [self.swaymsg or "swaymsg", f'workspace "{escaped_ws}"']
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0, env=self.env)
            if res.returncode == 0 and "false" not in res.stdout.lower():
                return ActionResult(
                    success=True,
                    action="switch_workspace",
                    target=workspace,
                    message=f"Switched active workspace to '{ws}' on Sway.",
                    requires_reobservation=True,
                )
            return ActionResult(
                success=False,
                action="switch_workspace",
                target=workspace,
                message=f"Failed to switch workspace on Sway: {res.stderr or res.stdout}",
                requires_reobservation=True,
            )
        except subprocess.TimeoutExpired:
            return ActionResult(
                success=False,
                action="switch_workspace",
                target=workspace,
                message="Sway switch-workspace command timed out after 2.0s.",
                requires_reobservation=True,
            )
        except Exception as e:
            return ActionResult(
                success=False,
                action="switch_workspace",
                target=workspace,
                message=f"Error executing swaymsg: {e}",
                requires_reobservation=True,
            )

    def move_window_to_workspace(self, target: str, workspace: str) -> ActionResult:
        t = (target or "").strip()
        ws = (workspace or "").strip()
        if not _valid_workspace_name(ws):
            return ActionResult(
                success=False,
                action="move_window_to_workspace",
                target=f"{t} -> {ws}",
                message="Target workspace identifier contains invalid characters.",
                requires_reobservation=True,
            )

        list_resp = self.list_windows()
        match = find_best_window(t, list_resp.windows) if list_resp.success else None

        if match and match.id.isdigit():
            escaped_ws = _escape_sway_string(ws)
            cmd = [self.swaymsg or "swaymsg", f'[con_id={match.id}] move container to workspace "{escaped_ws}"']
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0, env=self.env)
                if res.returncode == 0 and "false" not in res.stdout.lower():
                    return ActionResult(
                        success=True,
                        action="move_window_to_workspace",
                        target=f"{t} -> {ws}",
                        message=f"Moved window '{match.title[:45]}' to workspace '{ws}' on Sway.",
                        requires_reobservation=True,
                    )
                return ActionResult(
                    success=False,
                    action="move_window_to_workspace",
                    target=f"{t} -> {ws}",
                    message=f"Failed to move window on Sway: {res.stderr or res.stdout}",
                    requires_reobservation=True,
                )
            except subprocess.TimeoutExpired:
                return ActionResult(
                    success=False,
                    action="move_window_to_workspace",
                    target=f"{t} -> {ws}",
                    message="Sway move-window-to-workspace command timed out after 2.0s.",
                    requires_reobservation=True,
                )
            except Exception as e:
                return ActionResult(
                    success=False,
                    action="move_window_to_workspace",
                    target=f"{t} -> {ws}",
                    message=f"Error executing swaymsg: {e}",
                    requires_reobservation=True,
                )

        return ActionResult(
            success=False,
            action="move_window_to_workspace",
            target=f"{t} -> {ws}",
            message=f"Could not find valid window matching '{t}' on Sway.",
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

        if scope not in {"window", "desktop"}:
            return (False, b"", None, "Screenshot scope must be 'window' or 'desktop'.")
        if scope == "window":
            listed = self.list_windows()
            if not listed.success:
                return (False, b"", None, listed.message or "Window listing failed.")
            win_info = (
                find_best_window(target, listed.windows)
                if target is not None
                else listed.focused_window
            )
            if not win_info or not win_info.geometry or win_info.geometry.width <= 0 or win_info.geometry.height <= 0:
                return (False, b"", None, "Window-scoped screenshot failed closed: exact target or geometry unavailable.")
            target_geom = win_info.geometry
            cmd.extend(["-g", f"{target_geom.x},{target_geom.y} {target_geom.width}x{target_geom.height}"])

        cmd.append("-")

        try:
            res = subprocess.run(cmd, capture_output=True, timeout=3.0, env=self.env)
            if res.returncode == 0 and res.stdout.startswith(b"\x89PNG\r\n\x1a\n"):
                return (True, res.stdout, target_geom, "Screenshot captured successfully.")
            err_msg = res.stderr.decode("utf-8", errors="replace").strip()
            return (False, b"", target_geom, f"grim screenshot failed: {err_msg}")
        except subprocess.TimeoutExpired:
            return (False, b"", target_geom, "grim screenshot timed out after 3.0s.")
        except Exception as e:
            return (False, b"", target_geom, f"Error capturing screenshot: {e}")
