"""COSMIC Wayland window control through its native toplevel protocols."""

from __future__ import annotations

import json
import subprocess
from typing import Any, Optional

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
from wayland_mcp.session import find_session_binary

MAX_HELPER_OUTPUT = 2 * 1024 * 1024
MAX_WINDOWS = 512
MAX_WORKSPACES = 256
MAX_OUTPUTS = 64


class CosmicBackend(BaseCompositorBackend):
    """Use COSMIC's supported Wayland window and workspace protocols."""

    name = "cosmic"

    def __init__(self, env: Optional[dict[str, str]] = None) -> None:
        super().__init__(env)
        self.helper = find_session_binary("linux-mcp-cosmic-wm", self.env)

    def _label(self) -> str:
        return {"cosmic": "COSMIC", "gnome": "GNOME"}.get(self.name, self.name.capitalize())

    def _request(self, *arguments: str, timeout: float = 3.0) -> tuple[dict[str, Any] | None, str | None]:
        if not self.helper:
            return None, f"The {self._label()} window-control helper is not installed in the session PATH."
        try:
            result = subprocess.run(
                [self.helper, *arguments],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=self.env,
            )
        except subprocess.TimeoutExpired:
            return None, f"The {self._label()} window-control helper exceeded its request time limit."
        except OSError as exc:
            return None, f"The {self._label()} window-control helper could not start: {exc.strerror or type(exc).__name__}."
        if len(result.stdout) > MAX_HELPER_OUTPUT or len(result.stderr) > 16 * 1024:
            return None, f"The {self._label()} helper response exceeded its size bound."
        try:
            response = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError):
            detail = result.stderr.strip()[:250]
            return None, detail or f"The {self._label()} helper returned invalid JSON."
        if not isinstance(response, dict):
            return None, f"The {self._label()} helper returned an invalid response shape."
        if result.returncode != 0 or response.get("success") is not True:
            message = response.get("message")
            return response, message[:300] if isinstance(message, str) else f"The {self._label()} request failed."
        return response, None

    @classmethod
    def _string(cls, value: Any, *, limit: int = 1024, default: str = "") -> str:
        return value[:limit] if isinstance(value, str) else default

    @staticmethod
    def _integer(value: Any) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value

    @classmethod
    def _geometry(cls, value: Any) -> WindowGeometry | None:
        if not isinstance(value, dict):
            return None
        coords = [cls._integer(value.get(key)) for key in ("x", "y", "width", "height")]
        if any(item is None for item in coords):
            return None
        x, y, width, height = coords
        if width <= 0 or height <= 0 or max(abs(x), abs(y), width, height) > 1_000_000:
            return None
        return WindowGeometry(x=x, y=y, width=width, height=height)

    @classmethod
    def _window(cls, value: Any) -> WindowInfo | None:
        if not isinstance(value, dict):
            return None
        identifier = cls._string(value.get("id"), limit=64)
        if not identifier:
            return None
        raw_state = value.get("state") if isinstance(value.get("state"), dict) else {}
        max_value = raw_state.get("is_maximized")
        is_maximized = max_value if isinstance(max_value, bool) else None
        focused = raw_state.get("is_focused") is True or value.get("is_focused") is True
        return WindowInfo(
            id=identifier,
            app_id=cls._string(value.get("app_id"), limit=512, default="Unknown") or "Unknown",
            title=cls._string(value.get("title")),
            workspace_id=cls._string(value.get("workspace_id"), limit=512) or None,
            workspace_name=cls._string(value.get("workspace_name"), limit=256) or None,
            is_focused=focused,
            geometry=cls._geometry(value.get("geometry")),
            state=WindowState(
                is_focused=focused,
                is_minimized=raw_state.get("is_minimized") is True,
                is_maximized=is_maximized,
                is_fullscreen=raw_state.get("is_fullscreen") is True,
                is_floating=raw_state.get("is_floating") is True,
            ),
        )

    def _capability_names(self) -> tuple[set[str], str | None]:
        response, error = self._request("probe", timeout=3.0)
        if error or response is None:
            return set(), error
        values = response.get("capabilities")
        if not isinstance(values, list) or len(values) > 64:
            return set(), f"The {self._label()} helper returned invalid capability data."
        return {value for value in values if isinstance(value, str)}, None

    def get_capabilities(self) -> CompositorCapabilities:
        capabilities, error = self._capability_names()
        available = lambda name: name in capabilities
        unsupported = [name for name in (
            "window_resize", "screenshot", "bounded_input", "app_launch",
            "clipboard_read", "clipboard_write", "notifications", "accessibility",
        )]
        if error:
            unsupported.append(error)
        return CompositorCapabilities(
            window_list=available("window_list"),
            window_detail=available("window_detail"),
            window_focus=available("focus"),
            window_close=available("close"),
            window_minimize=available("minimize"),
            window_maximize=available("maximize"),
            workspace_list=available("workspace_list"),
            output_list=available("output_list"),
            workspace_switch=available("workspace_switch"),
            window_move=available("window_move"),
            screenshot=False,
            bounded_input=False,
            app_discovery=False,
            app_launch=False,
            unsupported_operations=unsupported,
        )

    def list_windows(self) -> WindowListResponse:
        response, error = self._request("list")
        if error or response is None:
            return WindowListResponse(success=False, total_windows=0, windows=[], compositor=self.name,
                                      message=f"{self._label()} window listing failed: {error}")
        raw_windows = response.get("windows")
        if not isinstance(raw_windows, list) or len(raw_windows) > MAX_WINDOWS:
            return WindowListResponse(success=False, total_windows=0, windows=[], compositor=self.name,
                                      message=f"The {self._label()} helper returned invalid or excessive window data.")
        windows = [window for row in raw_windows if (window := self._window(row)) is not None]
        focused_row = response.get("focused_window")
        focused = self._window(focused_row) if isinstance(focused_row, dict) else None
        return WindowListResponse(
            success=True,
            total_windows=len(windows),
            windows=windows,
            focused_window=focused,
            compositor=self.name,
            message=f"Discovered {len(windows)} {self._label()} window(s) using native window identifiers.",
        )

    def get_focused_window(self) -> FocusedWindowResponse:
        response = self.list_windows()
        if not response.success:
            return FocusedWindowResponse(success=False, message=response.message)
        return FocusedWindowResponse(
            success=True,
            window=response.focused_window,
            message=None if response.focused_window else "COSMIC reported no focused window.",
        )

    def list_workspaces(self) -> WorkspaceListResponse:
        response, error = self._request("workspaces")
        if error or response is None:
            return WorkspaceListResponse(success=False, total_workspaces=0, workspaces=[], compositor=self.name,
                                         message=f"{self._label()} workspace listing failed: {error}")
        raw = response.get("workspaces")
        if not isinstance(raw, list) or len(raw) > MAX_WORKSPACES:
            return WorkspaceListResponse(success=False, total_workspaces=0, workspaces=[], compositor=self.name,
                                         message=f"The {self._label()} helper returned invalid or excessive workspace data.")
        workspaces: list[WorkspaceInfo] = []
        for row in raw:
            if not isinstance(row, dict):
                continue
            identifier = self._string(row.get("id"), limit=512)
            if not identifier:
                continue
            count = self._integer(row.get("windows_count"))
            workspaces.append(WorkspaceInfo(
                id=identifier,
                name=self._string(row.get("name"), limit=256) or identifier,
                is_active=row.get("is_active") is True,
                is_focused=row.get("is_focused") is True,
                monitor=self._string(row.get("monitor"), limit=256) or None,
                windows_count=max(0, count or 0),
            ))
        active_row = response.get("active_workspace")
        active_id = self._string(active_row.get("id"), limit=512) if isinstance(active_row, dict) else ""
        active = next((item for item in workspaces if item.id == active_id), None)
        return WorkspaceListResponse(success=True, total_workspaces=len(workspaces), workspaces=workspaces,
                                     active_workspace=active, compositor=self.name)

    def list_outputs(self) -> OutputListResponse:
        response, error = self._request("outputs")
        if error or response is None:
            return OutputListResponse(success=False, total_outputs=0, outputs=[], compositor=self.name,
                                      message=f"{self._label()} output listing failed: {error}")
        raw = response.get("outputs")
        if not isinstance(raw, list) or len(raw) > MAX_OUTPUTS:
            return OutputListResponse(success=False, total_outputs=0, outputs=[], compositor=self.name,
                                      message=f"The {self._label()} helper returned invalid or excessive output data.")
        outputs: list[OutputInfo] = []
        for row in raw:
            if not isinstance(row, dict):
                continue
            identifier = self._string(row.get("id"), limit=256)
            name = self._string(row.get("name"), limit=256)
            if not identifier or not name:
                continue
            values: dict[str, Any] = {
                "id": identifier,
                "name": name,
                "make": self._string(row.get("make"), limit=256) or None,
                "model": self._string(row.get("model"), limit=256) or None,
                "enabled": row.get("enabled") is True,
                "is_focused": row.get("is_focused") is True,
            }
            for field in ("width_pixels", "height_pixels"):
                number = self._integer(row.get(field))
                if number is not None and number > 0:
                    values[field] = number
            refresh = row.get("refresh_rate_hz")
            if isinstance(refresh, (int, float)) and not isinstance(refresh, bool) and 0 < refresh <= 1000:
                values["refresh_rate_hz"] = float(refresh)
            scale = row.get("scale")
            if isinstance(scale, (int, float)) and not isinstance(scale, bool) and 0 < scale <= 16:
                values["scale"] = float(scale)
            values["logical_geometry"] = self._geometry(row.get("logical_geometry"))
            outputs.append(OutputInfo(**values))
        return OutputListResponse(success=True, total_outputs=len(outputs), outputs=outputs, compositor=self.name)

    def _action(self, operation: str, target: str, *arguments: str) -> ActionResult:
        if not isinstance(target, str) or not target or len(target) > 1024 or "\x00" in target:
            return ActionResult(success=False, action=operation, target=target,
                                message="An exact COSMIC window or workspace identifier is required.")
        _response, error = self._request(*arguments)
        return ActionResult(success=error is None, action=operation, target=target,
                            message=(f"{self._label()} accepted the {operation.replace('_', ' ')} request."
                                     if error is None else f"{self._label()} {operation.replace('_', ' ')} failed: {error}"))

    def focus_window(self, target: str) -> ActionResult:
        return self._action("focus_window", target, "focus", target)

    def close_window(self, target: str) -> ActionResult:
        return self._action("close_window", target, "close", target)

    def minimize_window(self, target: str) -> ActionResult:
        return self._action("minimize_window", target, "minimize", target)

    def maximize_window(self, target: str) -> ActionResult:
        return self._action("maximize_window", target, "maximize", target)

    def switch_workspace(self, workspace: str) -> ActionResult:
        return self._action("switch_workspace", workspace, "switch-workspace", workspace)

    def move_window_to_workspace(self, target: str, workspace: str) -> ActionResult:
        if (not isinstance(target, str) or not target or len(target) > 64 or "\x00" in target
                or not isinstance(workspace, str) or not workspace or len(workspace) > 512 or "\x00" in workspace):
            return ActionResult(success=False, action="move_window_to_workspace", target=f"{target} -> {workspace}",
                                message="Exact observed COSMIC window and workspace identifiers are required.")
        label = f"{target} -> {workspace}"
        return self._action("move_window_to_workspace", label, "move-window", target, workspace)

    def capture_screenshot(self, scope="window", target=None):
        return False, b"", None, f"{self._label()} screenshot capture is not implemented by the native window adapter."
