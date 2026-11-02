"""Screenshot capture with fail-closed target scope and MCP image output."""

from __future__ import annotations

from typing import Optional

from wayland_mcp.backends.registry import detect_backend
from wayland_mcp.models import ScreenshotResponse, WindowGeometry
from wayland_mcp.png import crop_png, png_dimensions
from wayland_mcp.portal import PortalError, remote_desktop_portal
from wayland_mcp.safety.tokens import snapshot_token_manager
from wayland_mcp.tools.windows import _allowed_window_operations

MAX_SCREENSHOT_BYTES = 32 * 1024 * 1024


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
    if not success or not image:
        try:
            image, monitor_session = await remote_desktop_portal.capture_startup_screen_frame()
            width, height = png_dimensions(image)
            monitor_bounds = (*monitor_session.position, *monitor_session.size)
            outputs = backend.list_outputs()
            matching_outputs = [
                output for output in outputs.outputs
                if output.enabled and output.logical_geometry is not None
                and (
                    output.logical_geometry.x,
                    output.logical_geometry.y,
                    output.logical_geometry.width,
                    output.logical_geometry.height,
                ) == monitor_bounds
            ] if outputs.success else []
            if len(matching_outputs) != 1:
                raise PortalError(
                    "The startup ScreenCast monitor does not match exactly one current compositor output."
                )

            if scope == "desktop":
                enabled_outputs = [
                    output for output in outputs.outputs
                    if output.enabled and output.logical_geometry is not None
                ] if outputs.success else []
                if len(enabled_outputs) != 1:
                    raise PortalError(
                        "The startup ScreenCast session covers one monitor; desktop-wide capture needs a native compositor screenshot."
                    )
                geometry = WindowGeometry(x=0, y=0, width=width, height=height)
            else:
                if selected_window is None or selected_window.geometry is None:
                    raise PortalError("No exact observed window with verified geometry is available to crop from the startup ScreenCast stream.")
                detail = backend.get_window_detail(selected_window.id)
                if (
                    not detail.success or detail.window is None
                    or detail.window.id != selected_window.id
                    or detail.window.geometry is None
                    or detail.window.geometry.model_dump() != selected_window.geometry.model_dump()
                ):
                    raise PortalError("The exact window changed during startup ScreenCast capture; observe again.")
                logical = selected_window.geometry
                left, top, monitor_width, monitor_height = monitor_bounds
                if (
                    logical.x < left or logical.y < top
                    or logical.x + logical.width > left + monitor_width
                    or logical.y + logical.height > top + monitor_height
                ):
                    raise PortalError("The exact window is not fully inside the startup ScreenCast monitor.")
                scale_x = width / monitor_width
                scale_y = height / monitor_height
                pixel_x = round((logical.x - left) * scale_x)
                pixel_y = round((logical.y - top) * scale_y)
                pixel_width = round(logical.width * scale_x)
                pixel_height = round(logical.height * scale_y)
                image = crop_png(image, pixel_x, pixel_y, pixel_width, pixel_height)
                width, height = png_dimensions(image)
                geometry = logical
            success = True
            message = "Screenshot captured from the ScreenCast permission granted at MCP startup."
        except PortalError as exc:
            return ScreenshotResponse(success=False, scope=scope, target=target,
                                      geometry=geometry,
                                      message=f"{message or 'Compositor screenshot unavailable.'} Startup ScreenCast fallback: {exc}"), b""
        except ValueError as exc:
            return ScreenshotResponse(success=False, scope=scope, target=target,
                                      geometry=geometry,
                                      message=f"Startup ScreenCast image validation failed: {exc}"), b""
    if len(image) > MAX_SCREENSHOT_BYTES:
        return ScreenshotResponse(success=False, scope=scope, target=target,
                                  message="Screenshot exceeds the 32 MiB output limit."), b""
    try:
        width, height = png_dimensions(image)
    except ValueError as exc:
        return ScreenshotResponse(success=False, scope=scope, target=target, message=str(exc)), b""

    observed_windows = [selected_window] if selected_window is not None and scope == "window" else []
    allowed = set() if scope == "desktop" else _allowed_window_operations(backend)
    token = snapshot_token_manager.create_token(
        scope="screenshot_window" if scope == "window" else "screenshot_desktop",
        allowed_operations=allowed,
        observed_windows=observed_windows,
        observed_geometry=(geometry.model_dump() if scope == "desktop" and geometry else None),
    )
    response = ScreenshotResponse(
        success=True,
        scope=scope,
        target=selected_window.id if selected_window is not None else None,
        geometry=geometry or WindowGeometry(x=0, y=0, width=width, height=height),
        mime_type="image/png",
        # The MCP server attaches an image content block. Do not duplicate a
        # large raster as base64 inside structured JSON.
        image_base64="",
        token_id=token.token_id,
        message=f"{message} Image dimensions: {width}x{height}. Snapshot token: {token.token_id}.",
    )
    return response, image
