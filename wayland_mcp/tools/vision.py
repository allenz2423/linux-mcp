"""Screenshot capture with fail-closed target scope and MCP image output."""

from __future__ import annotations

from typing import Optional

from wayland_mcp.backends.registry import detect_backend
from wayland_mcp.models import ScreenshotResponse, WindowGeometry
from wayland_mcp.portal import PortalError, ScreenshotPortal
from wayland_mcp.safety.tokens import snapshot_token_manager
from wayland_mcp.tools.windows import _allowed_window_operations

MAX_SCREENSHOT_BYTES = 32 * 1024 * 1024
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _png_dimensions(image: bytes) -> tuple[int, int]:
    if len(image) < 24 or not image.startswith(PNG_SIGNATURE):
        raise ValueError("Screenshot provider did not return a PNG image.")
    width = int.from_bytes(image[16:20], "big")
    height = int.from_bytes(image[20:24], "big")
    if not (1 <= width <= 32768 and 1 <= height <= 32768):
        raise ValueError("Screenshot dimensions are invalid.")
    return width, height


async def capture_screenshot(
    scope: str = "window",
    target: Optional[str] = None,
) -> tuple[ScreenshotResponse, bytes]:
    if scope not in {"window", "desktop"}:
        return ScreenshotResponse(success=False, scope=scope, target=target, message="Scope must be 'window' or 'desktop'."), b""
    if scope == "desktop" and target is not None:
        return ScreenshotResponse(success=False, scope=scope, target=target,
                                  message="A target ID can only be used with window scope."), b""
    if target is not None and (not isinstance(target, str) or not target.strip()):
        return ScreenshotResponse(success=False, scope=scope, target=target, message="Target must be an exact window ID."), b""
    backend = detect_backend()
    selected_window = None
    if scope == "window":
        listed = backend.list_windows()
        if listed.success:
            selected_window = (
                next((window for window in listed.windows if window.id == target), None)
                if target is not None else listed.focused_window
            )
        if target is not None and selected_window is None:
            return ScreenshotResponse(success=False, scope=scope, target=target,
                                      message="Exact target window ID was not found; screenshot aborted."), b""

    success, image, geometry, message = backend.capture_screenshot(scope=scope, target=selected_window.id if selected_window else None)
    if (
        backend.name == "niri"
        and scope == "window"
        and success
        and selected_window is not None
        and geometry != selected_window.geometry
    ):
        return ScreenshotResponse(
            success=False,
            scope=scope,
            target=selected_window.id,
            geometry=geometry,
            message="Niri window bounds changed after observation; screenshot and snapshot token were discarded. Observe again.",
        ), b""
    portal_used = False
    if (not success or not image) and scope == "window" and target is not None:
        # A user-selected portal window cannot prove it is the requested ID.
        return ScreenshotResponse(success=False, scope=scope, target=target, geometry=geometry,
                                  message=message or "Exact window screenshot unavailable."), b""
    if not success or not image:
        portal = ScreenshotPortal()
        try:
            image, width, height = await portal.capture(scope=scope)
            geometry = WindowGeometry(x=0, y=0, width=width, height=height)
            success = True
            portal_used = True
            message = "Screenshot captured through the XDG Screenshot portal."
        except PortalError as exc:
            return ScreenshotResponse(success=False, scope=scope, target=target,
                                      message=f"{message or 'Compositor screenshot unavailable.'} Portal fallback: {exc}"), b""
        finally:
            await portal.close_bus()
    if len(image) > MAX_SCREENSHOT_BYTES:
        return ScreenshotResponse(success=False, scope=scope, target=target,
                                  message="Screenshot exceeds the 32 MiB output limit."), b""
    try:
        width, height = _png_dimensions(image)
    except ValueError as exc:
        return ScreenshotResponse(success=False, scope=scope, target=target, message=str(exc)), b""

    observed_windows = [selected_window] if selected_window is not None and not portal_used else []
    allowed = set() if portal_used or scope == "desktop" else _allowed_window_operations(backend)
    token = snapshot_token_manager.create_token(
        scope="screenshot_window" if scope == "window" else "screenshot_desktop",
        allowed_operations=allowed,
        observed_windows=observed_windows,
        observed_geometry=(geometry.model_dump() if scope == "desktop" and geometry else None),
    )
    response = ScreenshotResponse(
        success=True,
        scope=scope,
        target=selected_window.id if selected_window is not None and not portal_used else None,
        geometry=geometry or WindowGeometry(x=0, y=0, width=width, height=height),
        mime_type="image/png",
        # The MCP server attaches an image content block. Do not duplicate a
        # large raster as base64 inside structured JSON.
        image_base64="",
        token_id=token.token_id,
        message=f"{message} Image dimensions: {width}x{height}. Snapshot token: {token.token_id}.",
    )
    return response, image
