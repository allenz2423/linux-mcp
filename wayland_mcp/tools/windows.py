"""Desktop observations and target-bound snapshot issuance."""

from __future__ import annotations

from typing import Any

from wayland_mcp.backends.registry import detect_backend
from wayland_mcp.models import (
    DesktopObservationResponse,
    FocusedWindowResponse,
    WindowDetailResponse,
    WindowListResponse,
    WorkspaceListResponse,
)
from wayland_mcp.safety.tokens import snapshot_token_manager
from wayland_mcp.session import logger

WINDOW_OPERATIONS = {
    "window_focus": "focus_window",
    "window_close": "close_window",
    "window_resize": "resize_window",
    "window_minimize": "minimize_window",
    "window_maximize": "maximize_window",
    "input_pointer": "pointer_action",
    "input_keyboard": "keyboard_action",
    "input_touch": "touch_action",
}


def _capability_values(backend) -> dict[str, bool]:
    result: dict[str, bool] = {}
    raw = backend.get_capabilities()
    if isinstance(raw, dict):
        for name, value in raw.items():
            result[name] = bool(getattr(value, "available", value))
    elif hasattr(raw, "model_dump"):
        result = {key: bool(value) for key, value in raw.model_dump(exclude={"unsupported_operations"}).items()}
    return result


def _allowed_window_operations(backend) -> set[str]:
    caps = _capability_values(backend)
    allowed = {
        action for capability, action in WINDOW_OPERATIONS.items()
        if caps.get(capability, caps.get({"window_focus": "window_focus", "window_close": "window_close"}.get(capability, capability), False))
    }
    if caps.get("window_move_workspace", caps.get("window_move", False)):
        allowed.add("move_window_to_workspace")
    if backend.name == "x11" and caps.get("bounded_input", False) and caps.get("window_list", False):
        # X11 input is global XTEST input, so authorize it only when the adapter
        # can identify and recheck the exact focused window and its geometry.
        allowed.update({"pointer_action", "keyboard_action"})
    if backend.env.get("WAYLAND_DISPLAY") and caps.get("window_list", False):
        # Keyboard input can be bound to an observed focused window wherever
        # window IDs are available. Absolute touch coordinates additionally
        # require verified compositor-global window and output geometry.
        allowed.add("keyboard_action")
        outputs = backend.list_outputs()
        if outputs is not None and outputs.success and any(
            output.enabled and output.logical_geometry is not None for output in outputs.outputs
        ):
            allowed.add("touch_action")
            if backend.name == "niri" or backend.get_pointer_position() is not None:
                allowed.add("pointer_action")
    return allowed


def _workspace_ids(backend) -> list[str]:
    response = backend.list_workspaces()
    if response.success:
        return [workspace.id for workspace in response.workspaces if workspace.id]
    return []


def _window_snapshot_token(backend, windows, workspaces=None, *, scope="windows"):
    capabilities = _capability_values(backend)
    operations = _allowed_window_operations(backend)
    if capabilities.get("workspace_switch", False):
        operations.add("switch_workspace")
    if capabilities.get("window_move_workspace", capabilities.get("window_move", False)):
        operations.add("move_window_to_workspace")
    return snapshot_token_manager.create_token(
        scope=scope,
        allowed_operations=operations,
        observed_windows=windows,
        observed_workspaces=workspaces if workspaces is not None else _workspace_ids(backend),
    )


def list_windows() -> WindowListResponse:
    logger.debug("Executing list_windows")
    backend = detect_backend()
    response = backend.list_windows()
    if response.success:
        token = _window_snapshot_token(backend, response.windows)
        response.token_id = token.token_id
        response.message = f"{response.message or ''} Snapshot token: {token.token_id}.".strip()
    return response


def get_focused_window() -> FocusedWindowResponse:
    logger.debug("Executing get_focused_window")
    backend = detect_backend()
    response = backend.get_focused_window()
    if response.success and response.window:
        token = _window_snapshot_token(backend, [response.window])
        response.token_id = token.token_id
        response.message = f"{response.message or ''} Snapshot token: {token.token_id}.".strip()
    return response


def get_window_detail(target: str) -> WindowDetailResponse:
    logger.debug("Executing get_window_detail")
    backend = detect_backend()
    response = backend.get_window_detail(target)
    if response.success and response.window:
        token = _window_snapshot_token(backend, [response.window])
        response.token_id = token.token_id
        response.message = f"{response.message or ''} Snapshot token: {token.token_id}.".strip()
    return response


def list_workspaces() -> WorkspaceListResponse:
    logger.debug("Executing list_workspaces")
    backend = detect_backend()
    response = backend.list_workspaces()
    if response.success:
        windows = backend.list_windows()
        observed_windows = windows.windows if windows.success else []
        token = _window_snapshot_token(
            backend, observed_windows,
            [workspace.id for workspace in response.workspaces],
            scope="workspaces",
        )
        response.token_id = token.token_id
        response.message = f"{response.message or ''} Snapshot token: {token.token_id}.".strip()
    return response


def observe_desktop() -> DesktopObservationResponse:
    logger.debug("Executing observe_desktop")
    backend = detect_backend()
    window_response = backend.list_windows()
    workspace_response = backend.list_workspaces()
    windows = window_response.windows if window_response.success else []
    workspaces = workspace_response.workspaces if workspace_response.success else []
    token = snapshot_token_manager.create_token(
        scope="desktop",
        allowed_operations={"clipboard_read", "clipboard_write", "send_notification"},
        observed_windows=windows,
        observed_workspaces=[workspace.id for workspace in workspaces],
    )
    ok = window_response.success or workspace_response.success
    return DesktopObservationResponse(
        success=ok,
        compositor=backend.name,
        windows=windows,
        workspaces=workspaces,
        token_id=token.token_id,
        message="Current desktop state observed. The token authorizes one clipboard or notification action.",
    )
