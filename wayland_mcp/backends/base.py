from abc import ABC, abstractmethod
from typing import Dict, Optional, List, Tuple
from wayland_mcp.models import (
    ActionResult,
    PerCapabilityStatus,
    WindowGeometry,
    WindowListResponse,
    WindowDetailResponse,
    WorkspaceListResponse,
    OutputListResponse,
)


class BaseCompositorBackend(ABC):
    """
    Abstract base class for compositor-specific desktop interaction adapters.
    Encapsulates window introspection, workspace navigation, window transformations,
    and screenshot capture while reporting exact per-capability support.
    """

    name: str = "base"

    def __init__(self, env: Optional[Dict[str, str]] = None) -> None:
        self.env = env or {}

    @abstractmethod
    def get_capabilities(self) -> Dict[str, PerCapabilityStatus]:
        """Returns typed capability status matrix detailing supported, available, and missing features."""
        pass

    @abstractmethod
    def list_windows(self) -> WindowListResponse:
        """Enumerates open windows on this compositor."""
        pass

    def get_window_detail(self, target: str) -> WindowDetailResponse:
        """Returns details only for an exact compositor window ID."""
        listed = self.list_windows()
        if not listed.success:
            return WindowDetailResponse(success=False, compositor=self.name, message=listed.message)
        match = next((window for window in listed.windows if window.id == target), None)
        if match is None:
            return WindowDetailResponse(success=False, compositor=self.name, message="Exact window ID was not found.")
        return WindowDetailResponse(success=True, window=match, compositor=self.name)

    def get_focused_window(self):
        """Returns the focused window derived from the current compositor listing."""
        from wayland_mcp.models import FocusedWindowResponse
        listed = self.list_windows()
        if not listed.success:
            return FocusedWindowResponse(success=False, message=listed.message)
        return FocusedWindowResponse(
            success=True,
            window=listed.focused_window,
            message=None if listed.focused_window else "No focused window was reported.",
        )

    @abstractmethod
    def focus_window(self, target: str) -> ActionResult:
        """Focuses a window matching target identifier."""
        pass

    @abstractmethod
    def close_window(self, target: str) -> ActionResult:
        """Requests window closure / container termination from compositor."""
        pass

    def resize_window(self, target: str, width: int, height: int) -> ActionResult:
        """Resizes a window to specified dimensions where supported."""
        return self._unsupported("resize_window", target, "Window resizing is not implemented for this compositor.")

    def minimize_window(self, target: str) -> ActionResult:
        """Minimizes a window where supported."""
        return self._unsupported("minimize_window", target, "Window minimization is not implemented for this compositor.")

    def maximize_window(self, target: str) -> ActionResult:
        """Toggles or sets maximization for a window where supported."""
        return self._unsupported("maximize_window", target, "Window maximization is not implemented for this compositor.")

    def list_workspaces(self) -> WorkspaceListResponse:
        """Lists active and available workspaces."""
        return WorkspaceListResponse(
            success=False, total_workspaces=0, workspaces=[], compositor=self.name,
            message="Workspace listing is not implemented for this compositor.",
        )

    def list_outputs(self) -> OutputListResponse:
        """Lists connected display outputs without changing their configuration."""
        return OutputListResponse(
            success=False, total_outputs=0, outputs=[], compositor=self.name,
            message="Display output listing is not implemented for this compositor.",
        )

    def get_pointer_position(self) -> Optional[Tuple[float, float]]:
        """Returns a fresh compositor-observed global cursor position when available."""
        return None

    @abstractmethod
    def switch_workspace(self, workspace: str) -> ActionResult:
        """Switches active workspace to the designated identifier or name."""
        pass

    @abstractmethod
    def move_window_to_workspace(self, target: str, workspace: str) -> ActionResult:
        """Moves designated window to target workspace."""
        pass

    @abstractmethod
    def capture_screenshot(
        self, scope: str = "window", target: Optional[str] = None
    ) -> Tuple[bool, bytes, Optional[WindowGeometry], str]:
        """
        Captures a visual screenshot frame (PNG).
        Fails closed if window scope is requested but target window/geometry is unavailable.
        Returns: (success, png_bytes, geometry, status_message)
        """
        pass

    def _unsupported(self, action: str, target: Optional[str], message: str) -> ActionResult:
        return ActionResult(
            success=False, action=action, target=target, message=message, requires_reobservation=False
        )
