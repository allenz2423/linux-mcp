from __future__ import annotations

import pytest

from wayland_mcp.models import (
    FocusedWindowResponse,
    OutputInfo,
    OutputListResponse,
    WindowGeometry,
    WindowInfo,
    WindowListResponse,
    WorkspaceInfo,
    WorkspaceListResponse,
)
from wayland_mcp.safety.tokens import TokenManager
from wayland_mcp.tools import input as desktop_input


class _Backend:
    name = "hyprland"

    def __init__(self):
        self.cursor = (10.0, 20.0)
        self.window = WindowInfo(
            id="window-1",
            app_id="org.example.Browser",
            title="Browser",
            workspace_id="1",
            is_focused=True,
            geometry=WindowGeometry(x=10, y=20, width=500, height=300),
        )

    def list_windows(self):
        return WindowListResponse(
            success=True,
            total_windows=1,
            windows=[self.window],
            focused_window=self.window,
            compositor=self.name,
        )

    def get_focused_window(self):
        return FocusedWindowResponse(success=True, window=self.window)

    def list_workspaces(self):
        return WorkspaceListResponse(
            success=True,
            total_workspaces=1,
            workspaces=[WorkspaceInfo(id="1", name="1", is_active=True)],
            active_workspace=WorkspaceInfo(id="1", name="1", is_active=True),
            compositor=self.name,
        )

    def list_outputs(self):
        return OutputListResponse(
            success=True,
            total_outputs=1,
            outputs=[OutputInfo(
                id="DP-1",
                name="DP-1",
                logical_geometry=WindowGeometry(x=0, y=0, width=1920, height=1080),
            )],
            compositor=self.name,
        )

    def get_pointer_position(self):
        return self.cursor


class _Portal:
    def __init__(self, backend: _Backend, *, reach_target: bool = True, newly_authorized: bool = False):
        self.backend = backend
        self.reach_target = reach_target
        self.newly_authorized = newly_authorized
        self.moves: list[tuple[float, float]] = []
        self.buttons: list[tuple[int, bool]] = []
        self.scrolls: list[tuple[int, int]] = []
        self.keysyms: list[tuple[int, bool]] = []
        self.pointer_grants = 0
        self.keyboard_grants = 0

    async def ensure_session(self, *, pointer: bool = False):
        if pointer:
            self.pointer_grants += 1
            devices = 2
        else:
            self.keyboard_grants += 1
            devices = 1
        return ("session", self, devices, self.newly_authorized)

    async def pointer_move_relative(self, dx: float, dy: float):
        self.moves.append((dx, dy))
        if self.reach_target:
            self.backend.cursor = (
                self.backend.cursor[0] + dx,
                self.backend.cursor[1] + dy,
            )

    async def pointer_button(self, button: int, pressed: bool):
        self.buttons.append((button, pressed))

    async def pointer_scroll(self, dx: int, dy: int):
        self.scrolls.append((dx, dy))

    async def keyboard_keysym(self, keysym: int, pressed: bool):
        self.keysyms.append((keysym, pressed))


def _token(manager: TokenManager, backend: _Backend, operation: str = "pointer_action") -> str:
    return manager.create_token(
        scope="windows",
        allowed_operations={operation},
        observed_windows=[backend.window],
    ).token_id


def test_uppercase_shortcut_notation_does_not_add_an_implicit_shift():
    assert desktop_input._key_and_modifiers("Ctrl+T") == (ord("t"), [0xFFE3])
    assert desktop_input._key_and_modifiers("Ctrl+L") == (ord("l"), [0xFFE3])
    assert desktop_input._key_and_modifiers("Ctrl+Shift+T") == (
        ord("t"), [0xFFE3, 0xFFE1],
    )


@pytest.mark.asyncio
async def test_pointer_click_moves_to_verified_target_before_clicking(monkeypatch):
    backend = _Backend()
    portal = _Portal(backend)
    manager = TokenManager()
    monkeypatch.setattr(desktop_input, "detect_backend", lambda: backend)
    monkeypatch.setattr(desktop_input, "remote_desktop_portal", portal)
    monkeypatch.setattr(desktop_input, "snapshot_token_manager", manager)

    result = await desktop_input.pointer_action(
        "window-1", _token(manager, backend), "click", x=200, y=100,
    )

    assert result.success
    assert portal.pointer_grants == 1
    assert portal.moves == [(200.0, 100.0)]
    assert portal.buttons == [(0x110, True), (0x110, False)]


@pytest.mark.asyncio
async def test_pointer_miss_fails_closed_without_click(monkeypatch):
    backend = _Backend()
    portal = _Portal(backend, reach_target=False)
    manager = TokenManager()
    monkeypatch.setattr(desktop_input, "detect_backend", lambda: backend)
    monkeypatch.setattr(desktop_input, "remote_desktop_portal", portal)
    monkeypatch.setattr(desktop_input, "snapshot_token_manager", manager)

    result = await desktop_input.pointer_action(
        "window-1", _token(manager, backend), "click", x=200, y=100,
    )

    assert not result.success
    assert "did not reach" in result.message
    assert portal.buttons == []


@pytest.mark.asyncio
async def test_scroll_uses_requested_scroll_delta_not_pointer_motion(monkeypatch):
    backend = _Backend()
    portal = _Portal(backend)
    manager = TokenManager()
    monkeypatch.setattr(desktop_input, "detect_backend", lambda: backend)
    monkeypatch.setattr(desktop_input, "remote_desktop_portal", portal)
    monkeypatch.setattr(desktop_input, "snapshot_token_manager", manager)

    result = await desktop_input.pointer_action(
        "window-1", _token(manager, backend), "scroll", delta_x=0, delta_y=480,
    )

    assert result.success
    assert portal.moves == [(250.0, 150.0)]
    assert portal.scrolls == [(0, 480)]


@pytest.mark.asyncio
async def test_new_pointer_permission_requires_fresh_screenshot_before_moving(monkeypatch):
    backend = _Backend()
    portal = _Portal(backend, newly_authorized=True)
    manager = TokenManager()
    monkeypatch.setattr(desktop_input, "detect_backend", lambda: backend)
    monkeypatch.setattr(desktop_input, "remote_desktop_portal", portal)
    monkeypatch.setattr(desktop_input, "snapshot_token_manager", manager)

    result = await desktop_input.pointer_action(
        "window-1", _token(manager, backend), "click", x=200, y=100,
    )

    assert not result.success
    assert "fresh screenshot" in result.message
    assert portal.moves == []
    assert portal.buttons == []


@pytest.mark.asyncio
async def test_new_keyboard_permission_requires_fresh_screenshot_before_keypress(monkeypatch):
    backend = _Backend()
    portal = _Portal(backend, newly_authorized=True)
    manager = TokenManager()
    monkeypatch.setattr(desktop_input, "detect_backend", lambda: backend)
    monkeypatch.setattr(desktop_input, "remote_desktop_portal", portal)
    monkeypatch.setattr(desktop_input, "snapshot_token_manager", manager)

    result = await desktop_input.keyboard_action(
        "window-1", _token(manager, backend, "keyboard_action"), "press_key", key="Ctrl+T",
    )

    assert not result.success
    assert "fresh screenshot" in result.message
    assert portal.keysyms == []
