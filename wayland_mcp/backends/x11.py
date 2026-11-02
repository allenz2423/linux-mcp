"""Bounded window and workspace control through an EWMH-compatible X11 WM."""

from __future__ import annotations

import re
import subprocess
from collections import Counter
from typing import Optional

from wayland_mcp.backends.base import BaseCompositorBackend
from wayland_mcp.models import (
    ActionResult,
    CompositorCapabilities,
    FocusedWindowResponse,
    WindowGeometry,
    WindowInfo,
    WindowListResponse,
    WindowState,
    WorkspaceInfo,
    WorkspaceListResponse,
)
from wayland_mcp.session import find_session_binary

WINDOW_ID_RE = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
ACTIVE_WINDOW_RE = re.compile(r"window id # (0x[0-9a-fA-F]{1,16})")
MAX_COMMAND_OUTPUT = 512 * 1024
MAX_WINDOWS = 512
MAX_WORKSPACES = 256
MAX_SCREENSHOT_BYTES = 32 * 1024 * 1024
SCREENSHOT_TIMEOUT_SECONDS = 5
POINTER_OUTPUT_BYTES = 4096


class X11Backend(BaseCompositorBackend):
    """Use wmctrl only when an X11 session and its EWMH window manager respond."""

    name = "x11"

    def __init__(self, env: Optional[dict[str, str]] = None) -> None:
        super().__init__(env)
        self.wmctrl = find_session_binary("wmctrl", self.env)
        self.xprop = find_session_binary("xprop", self.env)
        self.xdotool = find_session_binary("xdotool", self.env)
        self.maim = find_session_binary("maim", self.env)

    def _run(self, arguments: list[str]) -> tuple[str | None, str | None]:
        if not self.wmctrl:
            return None, "wmctrl is not installed."
        try:
            result = subprocess.run(
                [self.wmctrl, *arguments],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=3.0,
                env=self.env,
            )
        except subprocess.TimeoutExpired:
            return None, "wmctrl exceeded the three-second request limit."
        except (OSError, UnicodeError) as exc:
            return None, f"wmctrl could not be started: {exc.strerror or type(exc).__name__}."
        if len(result.stdout) > MAX_COMMAND_OUTPUT or len(result.stderr) > 16 * 1024:
            return None, "wmctrl output exceeded the response bound."
        if result.returncode != 0:
            detail = result.stderr.strip()[:300]
            return None, detail or f"wmctrl exited with status {result.returncode}."
        return result.stdout, None

    def _workspace_rows(self) -> tuple[list[WorkspaceInfo], str | None]:
        output, error = self._run(["-d"])
        if error or output is None:
            return [], error
        workspaces: list[WorkspaceInfo] = []
        for line_number, line in enumerate(output.splitlines(), start=1):
            if line_number > MAX_WORKSPACES:
                return [], f"The X11 desktop count exceeds the {MAX_WORKSPACES}-desktop limit."
            fields = line.split(maxsplit=9)
            if len(fields) < 9 or not fields[0].isdigit() or fields[1] not in {"*", "-"}:
                continue
            try:
                workspace_id = str(int(fields[0], 10))
            except ValueError:
                continue
            name = fields[9].strip()[:256] if len(fields) > 9 else ""
            if not name:
                name = f"Desktop {int(workspace_id) + 1}"
            active = fields[1] == "*"
            workspaces.append(WorkspaceInfo(
                id=workspace_id,
                name=name,
                is_active=active,
                is_focused=active,
            ))
        if not workspaces:
            return [], "wmctrl returned no parseable X11 desktops."
        return workspaces, None

    def _window_rows(self) -> tuple[list[tuple[str, str, WindowGeometry, str]], str | None]:
        output, error = self._run(["-l", "-G"])
        if error or output is None:
            return [], error
        rows: list[tuple[str, str, WindowGeometry, str]] = []
        for line in output.splitlines():
            fields = line.split(maxsplit=7)
            if len(fields) < 8 or not WINDOW_ID_RE.fullmatch(fields[0]):
                continue
            try:
                desktop = str(int(fields[1], 10)) if fields[1] != "-1" else ""
                x, y, width, height = (int(value, 10) for value in fields[2:6])
            except ValueError:
                continue
            if width <= 0 or height <= 0:
                continue
            title = "".join(character for character in fields[7] if character.isprintable())[:1024]
            if len(rows) >= MAX_WINDOWS:
                return [], f"The X11 window count exceeds the {MAX_WINDOWS}-window limit."
            rows.append((fields[0].lower(), desktop, WindowGeometry(x=x, y=y, width=width, height=height), title))
        return rows, None

    def _active_window_id(self) -> str | None:
        if not self.xprop:
            return None
        try:
            result = subprocess.run(
                [self.xprop, "-root", "_NET_ACTIVE_WINDOW"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=2.0,
                env=self.env,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0 or len(result.stdout) > 4096:
            return None
        match = ACTIVE_WINDOW_RE.search(result.stdout)
        return match.group(1).lower() if match else None

    def get_pointer_position(self) -> tuple[float, float] | None:
        """Read the current X11 pointer position through bounded xdotool output."""
        if not self.xdotool:
            return None
        # Import lazily because wayland_mcp.tools.__init__ imports discovery,
        # which loads the backend registry and would loop back into this module.
        from wayland_mcp.tools.commands import run_bounded_command

        output, error, truncated = run_bounded_command(
            [self.xdotool, "getmouselocation", "--shell"],
            self.env,
            command_label="X11 pointer-position query",
            timeout_seconds=2.0,
            max_output_bytes=POINTER_OUTPUT_BYTES,
        )
        if error or output is None or truncated:
            return None
        values: dict[str, int] = {}
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"X", "Y"} and re.fullmatch(r"-?\d{1,7}", value):
                values[key] = int(value, 10)
        if set(values) != {"X", "Y"}:
            return None
        return float(values["X"]), float(values["Y"])

    def get_capabilities(self) -> CompositorCapabilities:
        workspaces, workspace_error = self._workspace_rows()
        _windows, window_error = self._window_rows()
        windows_available = bool(self.wmctrl and window_error is None)
        workspaces_available = bool(self.wmctrl and workspace_error is None)
        unsupported = []
        if not self.wmctrl:
            unsupported.append("wmctrl binary not found in the session PATH")
        else:
            if window_error:
                unsupported.append(window_error)
            if workspace_error:
                unsupported.append(workspace_error)
        unsupported.append("output_list")
        if not self.maim:
            unsupported.append("screenshot: maim binary not found in the session PATH")
        if not self.xdotool:
            unsupported.append("bounded_input: xdotool binary not found in the session PATH")
        elif not self.xprop:
            unsupported.append("bounded_input: xprop is required to identify the exact focused window")
        return CompositorCapabilities(
            window_list=windows_available,
            window_detail=windows_available,
            window_focus=windows_available,
            window_close=windows_available,
            window_resize=windows_available,
            window_minimize=windows_available,
            window_maximize=windows_available,
            workspace_list=workspaces_available,
            workspace_switch=workspaces_available,
            window_move=bool(workspaces_available and windows_available),
            screenshot=bool(windows_available and self.maim),
            bounded_input=bool(windows_available and self.xdotool and self.xprop),
            app_discovery=True,
            app_launch=False,
            unsupported_operations=unsupported,
        )

    def list_windows(self) -> WindowListResponse:
        rows, error = self._window_rows()
        if error:
            return WindowListResponse(
                success=False,
                total_windows=0,
                windows=[],
                compositor=self.name,
                message=f"X11 window listing failed: {error}",
            )
        workspaces, _workspace_error = self._workspace_rows()
        names = {workspace.id: workspace.name for workspace in workspaces}
        active_id = self._active_window_id()
        windows = [
            WindowInfo(
                id=window_id,
                app_id="Unknown",
                title=title,
                workspace_id=desktop or None,
                workspace_name=names.get(desktop),
                is_focused=window_id == active_id,
                geometry=geometry,
                state=WindowState(is_focused=window_id == active_id),
            )
            for window_id, desktop, geometry, title in rows
        ]
        focused = next((window for window in windows if window.is_focused), None)
        message = f"Discovered {len(windows)} X11 window(s) across {len(workspaces)} desktop(s)."
        if not self.xprop:
            message += " Install xprop to identify the currently focused window."
        return WindowListResponse(
            success=True,
            total_windows=len(windows),
            windows=windows,
            focused_window=focused,
            compositor=self.name,
            message=message,
        )

    def get_focused_window(self) -> FocusedWindowResponse:
        if not self.xprop:
            return FocusedWindowResponse(
                success=False,
                message="Focused-window lookup requires the optional xprop command.",
            )
        return super().get_focused_window()

    def list_workspaces(self) -> WorkspaceListResponse:
        workspaces, error = self._workspace_rows()
        if error:
            return WorkspaceListResponse(
                success=False,
                total_workspaces=0,
                workspaces=[],
                compositor=self.name,
                message=f"X11 desktop listing failed: {error}",
            )
        rows, _window_error = self._window_rows()
        counts = Counter(desktop for _window_id, desktop, _geometry, _title in rows if desktop)
        for workspace in workspaces:
            workspace.windows_count = counts.get(workspace.id, 0)
        active = next((workspace for workspace in workspaces if workspace.is_active), None)
        return WorkspaceListResponse(
            success=True,
            total_workspaces=len(workspaces),
            workspaces=workspaces,
            active_workspace=active,
            compositor=self.name,
        )

    def _window_exists(self, target: str) -> bool:
        if not isinstance(target, str) or not WINDOW_ID_RE.fullmatch(target):
            return False
        rows, error = self._window_rows()
        return error is None and any(window_id == target.lower() for window_id, *_rest in rows)

    def _perform(
        self,
        operation: str,
        target: str,
        arguments: list[str],
        *,
        window_id: str | None = None,
    ) -> ActionResult:
        identity = window_id if window_id is not None else target
        if not self._window_exists(identity):
            return ActionResult(success=False, action=operation, target=target,
                                message="The exact observed X11 window ID is no longer present.")
        _output, error = self._run(arguments)
        return ActionResult(
            success=error is None,
            action=operation,
            target=target,
            message=(f"X11 accepted {operation.replace('_', ' ')} for window {target}."
                     if error is None else f"X11 {operation.replace('_', ' ')} failed: {error}"),
        )

    def focus_window(self, target: str) -> ActionResult:
        if not isinstance(target, str) or not WINDOW_ID_RE.fullmatch(target):
            return ActionResult(success=False, action="focus_window", target=target,
                                message="An exact hexadecimal X11 window ID is required.")
        return self._perform("focus_window", target, ["-i", "-a", target])

    def close_window(self, target: str) -> ActionResult:
        if not isinstance(target, str) or not WINDOW_ID_RE.fullmatch(target):
            return ActionResult(success=False, action="close_window", target=target,
                                message="An exact hexadecimal X11 window ID is required.")
        return self._perform("close_window", target, ["-i", "-c", target])

    def resize_window(self, target: str, width: int, height: int) -> ActionResult:
        if not isinstance(target, str) or not WINDOW_ID_RE.fullmatch(target):
            return ActionResult(success=False, action="resize_window", target=target,
                                message="An exact hexadecimal X11 window ID is required.")
        if any(not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 32768 for value in (width, height)):
            return ActionResult(success=False, action="resize_window", target=target,
                                message="Window width and height must be integers between 1 and 32768 pixels.")
        if not self._window_exists(target):
            return ActionResult(success=False, action="resize_window", target=target,
                                message="The exact observed X11 window ID is no longer present.")
        _output, error = self._run(["-i", "-r", target, "-e", f"0,-1,-1,{width},{height}"])
        if error:
            return ActionResult(success=False, action="resize_window", target=target,
                                message=f"X11 resize request failed: {error}")
        rows, verify_error = self._window_rows()
        resized = next((geometry for window_id, _desktop, geometry, _title in rows
                        if window_id == target.lower()), None)
        if verify_error or resized is None or (resized.width, resized.height) != (width, height):
            return ActionResult(
                success=False,
                action="resize_window",
                target=target,
                message=("The X11 window manager accepted the resize request but did not report the requested dimensions; "
                         "the window may enforce size constraints. Observe the window again."),
            )
        return ActionResult(success=True, action="resize_window", target=target,
                            message=f"Resized the exact X11 window to {width} by {height} pixels.")

    def minimize_window(self, target: str) -> ActionResult:
        if not isinstance(target, str) or not WINDOW_ID_RE.fullmatch(target):
            return ActionResult(success=False, action="minimize_window", target=target,
                                message="An exact hexadecimal X11 window ID is required.")
        return self._perform("minimize_window", target, ["-i", "-r", target, "-b", "add,hidden"])

    def maximize_window(self, target: str) -> ActionResult:
        if not isinstance(target, str) or not WINDOW_ID_RE.fullmatch(target):
            return ActionResult(success=False, action="maximize_window", target=target,
                                message="An exact hexadecimal X11 window ID is required.")
        return self._perform(
            "maximize_window", target,
            ["-i", "-r", target, "-b", "add,maximized_vert,maximized_horz"],
        )

    def switch_workspace(self, workspace: str) -> ActionResult:
        workspaces, error = self._workspace_rows()
        if error or not isinstance(workspace, str) or not workspace.isdigit() or workspace not in {item.id for item in workspaces}:
            return ActionResult(success=False, action="switch_workspace", target=workspace,
                                message=error or "An exact observed X11 desktop ID is required.")
        _output, action_error = self._run(["-s", workspace])
        return ActionResult(success=action_error is None, action="switch_workspace", target=workspace,
                            message=("Switched to the exact X11 desktop." if action_error is None
                                     else f"X11 desktop switch failed: {action_error}"))

    def move_window_to_workspace(self, target: str, workspace: str) -> ActionResult:
        workspaces, error = self._workspace_rows()
        if error or not isinstance(workspace, str) or not workspace.isdigit() or workspace not in {item.id for item in workspaces}:
            return ActionResult(success=False, action="move_window_to_workspace", target=f"{target} -> {workspace}",
                                message=error or "An exact observed X11 desktop ID is required.")
        if not isinstance(target, str) or not WINDOW_ID_RE.fullmatch(target):
            return ActionResult(success=False, action="move_window_to_workspace", target=f"{target} -> {workspace}",
                                message="An exact hexadecimal X11 window ID is required.")
        return self._perform(
            "move_window_to_workspace", f"{target} -> {workspace}",
            ["-i", "-r", target, "-t", workspace],
            window_id=target,
        )

    def capture_screenshot(self, scope="window", target=None):
        if not self.maim:
            return False, b"", None, "The optional maim screenshot tool is unavailable in the session PATH."
        from wayland_mcp.tools.commands import run_bounded_binary_command

        if scope not in {"window", "desktop"}:
            return False, b"", None, "Screenshot scope must be 'window' or 'desktop'."
        geometry = None
        arguments = ["--format=png", "--hidecursor"]
        if scope == "window":
            if target is None or not isinstance(target, str) or not WINDOW_ID_RE.fullmatch(target):
                return False, b"", None, "An exact observed X11 window ID is required for a window screenshot."
            rows, error = self._window_rows()
            if error:
                return False, b"", None, f"X11 screenshot target could not be verified: {error}"
            geometry = next(
                (item_geometry for window_id, _desktop, item_geometry, _title in rows if window_id == target.lower()),
                None,
            )
            if geometry is None:
                return False, b"", None, "The exact observed X11 window ID is no longer present."
            arguments.extend(["--window", target])
        image, error, truncated = run_bounded_binary_command(
            [self.maim, *arguments],
            self.env,
            command_label=f"X11 {scope} screenshot",
            timeout_seconds=SCREENSHOT_TIMEOUT_SECONDS,
            max_output_bytes=MAX_SCREENSHOT_BYTES,
        )
        if error or image is None or truncated:
            return False, b"", geometry, error or "The X11 screenshot exceeded the 32 MiB output limit."
        if not image.startswith(b"\x89PNG\r\n\x1a\n"):
            return False, b"", geometry, "maim did not return a valid PNG screenshot."
        if scope == "window":
            rows_after, error = self._window_rows()
            geometry_after = next(
                (item_geometry for window_id, _desktop, item_geometry, _title in rows_after if window_id == target.lower()),
                None,
            ) if rows_after is not None else None
            if error or geometry_after != geometry:
                return False, b"", None, "The exact X11 screenshot target changed bounds during capture; capture was discarded."
        return True, image, geometry, f"X11 {scope} screenshot captured from the exact {'window' if scope == 'window' else 'root window'}."
