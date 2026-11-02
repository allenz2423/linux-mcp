from __future__ import annotations

import struct
import zlib
from types import SimpleNamespace

import pytest

from wayland_mcp.models import (
    OutputInfo,
    OutputListResponse,
    WindowDetailResponse,
    WindowGeometry,
    WindowInfo,
    WindowListResponse,
)
from wayland_mcp.png import PNG_SIGNATURE, png_dimensions
from wayland_mcp.tools import vision


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(4, "big") + kind + payload
        + (zlib.crc32(kind + payload) & 0xFFFFFFFF).to_bytes(4, "big")
    )


def _rgb_png(width: int, height: int) -> bytes:
    rows = b"".join(
        b"\x00" + bytes(component for x in range(width) for component in (x, y, 100))
        for y in range(height)
    )
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        PNG_SIGNATURE
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(rows))
        + _chunk(b"IEND", b"")
    )


@pytest.mark.asyncio
async def test_window_screenshot_falls_back_to_startup_stream_and_keeps_exact_target(monkeypatch):
    geometry = WindowGeometry(x=1, y=1, width=2, height=2)
    window = WindowInfo(
        id="window-1",
        app_id="org.example.Test",
        title="Test",
        is_focused=True,
        geometry=geometry,
    )

    class Backend:
        name = "hyprland"

        def list_windows(self):
            return WindowListResponse(
                success=True,
                total_windows=1,
                windows=[window],
                focused_window=window,
                compositor="hyprland",
            )

        def capture_screenshot(self, *, scope, target):
            assert (scope, target) == ("window", "window-1")
            return False, b"", geometry, "native screenshot unavailable"

        def list_outputs(self):
            return OutputListResponse(
                success=True,
                total_outputs=1,
                outputs=[OutputInfo(
                    id="monitor-1",
                    name="monitor-1",
                    logical_geometry=WindowGeometry(x=0, y=0, width=4, height=4),
                )],
                compositor="hyprland",
            )

        def get_window_detail(self, window_id):
            assert window_id == "window-1"
            return WindowDetailResponse(success=True, window=window, compositor="hyprland")

    monitor_session = SimpleNamespace(position=(0, 0), size=(4, 4))
    frame = _rgb_png(4, 4)

    async def startup_frame():
        return frame, monitor_session

    monkeypatch.setattr(vision, "detect_backend", lambda: Backend())
    monkeypatch.setattr(vision.remote_desktop_portal, "capture_startup_screen_frame", startup_frame)
    monkeypatch.setattr(vision, "_allowed_window_operations", lambda _backend: set())
    monkeypatch.setattr(
        vision.snapshot_token_manager,
        "create_token",
        lambda **_kwargs: SimpleNamespace(token_id="snapshot-test"),
    )

    response, image = await vision.capture_screenshot(scope="window")

    assert response.success
    assert response.target == "window-1"
    assert response.geometry == geometry
    assert png_dimensions(image) == (2, 2)
    assert "ScreenCast permission granted at MCP startup" in response.message
