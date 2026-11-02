from typing import Dict, Optional, Tuple
from wayland_mcp.backends.base import BaseCompositorBackend
from wayland_mcp.models import (
    ActionResult,
    CompositorCapabilities,
    WindowGeometry,
    WindowListResponse,
    FocusedWindowResponse,
)


class UnsupportedBackend(BaseCompositorBackend):
    """
    Fallback backend for unsupported compositors, headless environments, or missing IPC.
    Never crashes; gracefully communicates limitations to the client.
    """

    name: str = "unsupported"

    def __init__(
        self,
        env: Optional[Dict[str, str]] = None,
        reason: str = "Unrecognized or unsupported compositor",
        name: str = "unsupported",
    ) -> None:
        super().__init__(env)
        self.reason = reason
        self.name = name

    def get_capabilities(self) -> CompositorCapabilities:
        return CompositorCapabilities(
            window_list=False,
            window_focus=False,
            window_close=False,
            window_move=False,
            workspace_switch=False,
            screenshot=False,
            bounded_input=False,
            app_launch=False,
            unsupported_operations=[
                self.reason,
                "window_list",
                "window_focus",
                "window_close",
                "window_move",
                "workspace_switch",
                "screenshot",
            ],
        )

    def list_windows(self) -> WindowListResponse:
        return WindowListResponse(
            success=False,
            total_windows=0,
            windows=[],
            compositor=self.name,
            message=f"Window listing unavailable: {self.reason}",
        )

    def get_focused_window(self) -> FocusedWindowResponse:
        return FocusedWindowResponse(
            success=False,
            window=None,
            message=f"Focused window query unavailable: {self.reason}",
        )

    def focus_window(self, target: str) -> ActionResult:
        return ActionResult(
            success=False,
            action="focus_window",
            target=target,
            message=f"Focus window unavailable: {self.reason}",
            requires_reobservation=False,
        )

    def close_window(self, target: str) -> ActionResult:
        return ActionResult(
            success=False,
            action="close_window",
            target=target,
            message=f"Close window unavailable: {self.reason}",
            requires_reobservation=False,
        )

    def switch_workspace(self, workspace: str) -> ActionResult:
        return ActionResult(
            success=False,
            action="switch_workspace",
            target=workspace,
            message=f"Switch workspace unavailable: {self.reason}",
            requires_reobservation=False,
        )

    def move_window_to_workspace(self, target: str, workspace: str) -> ActionResult:
        return ActionResult(
            success=False,
            action="move_window_to_workspace",
            target=f"{target} -> {workspace}",
            message=f"Move window unavailable: {self.reason}",
            requires_reobservation=False,
        )

    def capture_screenshot(
        self, scope: str = "window", target: Optional[str] = None
    ) -> Tuple[bool, bytes, Optional[WindowGeometry], str]:
        return (False, b"", None, f"Screenshot capture unavailable: {self.reason}")
