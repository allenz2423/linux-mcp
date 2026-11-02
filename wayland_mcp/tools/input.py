"""Bounded keyboard and pointer input through XDG portals or verified X11 focus."""

from __future__ import annotations

import asyncio
import math
import re

from wayland_mcp.backends.registry import detect_backend
from wayland_mcp.models import KeyboardActionResult, PointerActionResult, TouchActionResult
from wayland_mcp.portal import PortalError, remote_desktop_portal
from wayland_mcp.safety.tokens import snapshot_token_manager
from wayland_mcp.tools.commands import run_bounded_command

MAX_TYPED_CHARACTERS = 1000
MAX_SCROLL_DELTA = 1200
MAX_POINTER_MOTION = 10000
MAX_TOUCH_MOTION = 4000
MAX_TOUCH_DURATION_MS = 2000
POINTER_POSITION_TOLERANCE = 2.0
X11_TEXT_CHUNK_SIZE = 32
X11_COMMAND_TIMEOUT_SECONDS = 3.0
X11_BUTTONS = {
    "left": 1,
    "middle": 2,
    "right": 3,
    "side": 8,
    "extra": 9,
    "forward": 10,
    "back": 11,
    "task": 12,
}
X11_NAMED_KEYS = {
    "backspace": "BackSpace",
    "tab": "Tab",
    "return": "Return",
    "enter": "Return",
    "escape": "Escape",
    "delete": "Delete",
    "home": "Home",
    "left": "Left",
    "up": "Up",
    "right": "Right",
    "down": "Down",
    "page_up": "Page_Up",
    "page_down": "Page_Down",
    "end": "End",
    "print": "Print",
    "insert": "Insert",
    "menu": "Menu",
    "pause": "Pause",
    "num_lock": "Num_Lock",
    "scroll_lock": "Scroll_Lock",
    "caps_lock": "Caps_Lock",
    "space": "space",
    **{f"f{number}": f"F{number}" for number in range(1, 13)},
}
BUTTONS = {
    "left": 0x110,
    "right": 0x111,
    "middle": 0x112,
    "side": 0x113,
    "extra": 0x114,
    "forward": 0x115,
    "back": 0x116,
    "task": 0x117,
}
MODIFIERS = {
    "ctrl": 0xFFE3, "control": 0xFFE3, "alt": 0xFFE9,
    "shift": 0xFFE1, "super": 0xFFEB, "meta": 0xFFEB,
}
KEYSYMS = {
    "Backspace": 0xFF08, "Tab": 0xFF09, "Return": 0xFF0D,
    "Enter": 0xFF0D, "Escape": 0xFF1B, "Delete": 0xFFFF,
    "Home": 0xFF50, "Left": 0xFF51, "Up": 0xFF52, "Right": 0xFF53,
    "Down": 0xFF54, "Page_Up": 0xFF55, "Page_Down": 0xFF56,
    "End": 0xFF57, "Print": 0xFF61, "Insert": 0xFF63,
    "Menu": 0xFF67, "Pause": 0xFF13, "Num_Lock": 0xFF7F,
    "Scroll_Lock": 0xFF14, "Caps_Lock": 0xFFE5, "space": 0x20,
}
KEYSYMS.update({f"F{number}": 0xFFBD + number for number in range(1, 13)})
_KEYSYMS_CASEFOLD = {name.casefold(): code for name, code in KEYSYMS.items()}
_NAMED_KEY_PATTERN = "|".join(re.escape(name) for name in sorted(KEYSYMS, key=len, reverse=True))
_KEY_ATOM_PATTERN = rf"(?:[A-Za-z0-9]|{_NAMED_KEY_PATTERN})"
KEYS_RE = re.compile(
    rf"^(?:Ctrl|Control|Alt|Shift|Super|Meta)(?:\+(?:Ctrl|Control|Alt|Shift|Super|Meta))*\+{_KEY_ATOM_PATTERN}$",
    re.I,
)


def _authorize(token_id: str, operation: str, target_window_id: str):
    return snapshot_token_manager.validate_and_consume(
        token_id,
        operation=operation,
        target=target_window_id,
        target_type="window",
    )


def _focused_window_matches(backend, target_window_id: str, geometry: dict[str, int]) -> bool:
    current = backend.list_windows()
    if not current.success:
        return False
    window = next((item for item in current.windows if item.id == target_window_id), None)
    return bool(
        window is not None
        and window.is_focused
        and window.geometry is not None
        and window.geometry.model_dump() == geometry
    )


async def _run_x11_command(backend, arguments: list[str], *, label: str) -> str | None:
    """Run one bounded xdotool argument vector without using a shell."""
    executable = getattr(backend, "xdotool", None)
    if not executable:
        return "The optional xdotool input tool is unavailable in the session PATH."
    output, error, truncated = await asyncio.to_thread(
        run_bounded_command,
        [executable, *arguments],
        backend.env,
        command_label=label,
        timeout_seconds=X11_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=16 * 1024,
    )
    if error:
        return error
    if truncated:
        return f"{label} output exceeded its 16 KiB limit."
    return None


def _x11_pointer_matches(backend, screen_x: int, screen_y: int) -> bool:
    position = backend.get_pointer_position()
    return bool(
        position is not None
        and abs(position[0] - screen_x) <= POINTER_POSITION_TOLERANCE
        and abs(position[1] - screen_y) <= POINTER_POSITION_TOLERANCE
    )


async def _x11_move_to_window_point(
    backend,
    target_window_id: str,
    geometry: dict[str, int],
    x: int,
    y: int,
) -> str | None:
    if not _focused_window_matches(backend, target_window_id, geometry):
        return "The exact target window is no longer focused or changed bounds; observe again."
    position = backend.get_pointer_position()
    if position is None:
        return "X11 could not verify the current pointer position; input was aborted."
    screen_x, screen_y = geometry["x"] + x, geometry["y"] + y
    if abs(screen_x - position[0]) > MAX_POINTER_MOTION or abs(screen_y - position[1]) > MAX_POINTER_MOTION:
        return "The target point is too far from the current pointer for one bounded X11 motion."
    error = await _run_x11_command(
        backend,
        ["mousemove", "--sync", str(screen_x), str(screen_y)],
        label="X11 pointer motion",
    )
    if error:
        return error
    if not _x11_pointer_matches(backend, screen_x, screen_y):
        return "The X11 pointer did not reach the observed target point; no button or scroll event was sent."
    if not _focused_window_matches(backend, target_window_id, geometry):
        return "The exact target window lost focus or changed bounds during pointer motion; observe again."
    return None


async def _x11_pointer_action(
    backend,
    target_window_id: str,
    geometry,
    action: str,
    x: int,
    y: int,
    button: str,
    delta_x: int,
    delta_y: int,
    start_x: int | None,
    start_y: int | None,
) -> PointerActionResult:
    observed_geometry = geometry.model_dump()
    move_x = start_x if action == "drag" else x
    move_y = start_y if action == "drag" else y
    error = await _x11_move_to_window_point(
        backend, target_window_id, observed_geometry, move_x, move_y,
    )
    if error:
        return PointerActionResult(success=False, actions_performed=0, message=error)
    actions_performed = 1

    if action == "move":
        return PointerActionResult(
            success=True,
            actions_performed=actions_performed,
            message="X11 pointer moved to the requested point in the observed focused window.",
        )

    if action == "scroll":
        wheel_events = []
        if delta_y:
            wheel_events.append((5 if delta_y > 0 else 4, max(1, round(abs(delta_y) / 120))))
        if delta_x:
            wheel_events.append((7 if delta_x > 0 else 6, max(1, round(abs(delta_x) / 120))))
        for wheel_button, count in wheel_events:
            if not _focused_window_matches(backend, target_window_id, observed_geometry):
                return PointerActionResult(
                    success=False,
                    actions_performed=actions_performed,
                    message="The exact target window lost focus or changed bounds before scrolling; observe again.",
                )
            error = await _run_x11_command(
                backend,
                ["click", "--clearmodifiers", "--repeat", str(count), "--delay", "20", str(wheel_button)],
                label="X11 wheel input",
            )
            if error:
                return PointerActionResult(success=False, actions_performed=actions_performed, message=error)
            actions_performed += count * 2
        return PointerActionResult(
            success=True,
            actions_performed=actions_performed,
            message="X11 scroll sent as bounded wheel-button events; each axis is quantized to discrete wheel steps.",
        )

    x11_button = X11_BUTTONS[button]
    if action in {"click", "double_click"}:
        click_count = 2 if action == "double_click" else 1
        for click_index in range(click_count):
            if not _focused_window_matches(backend, target_window_id, observed_geometry):
                return PointerActionResult(
                    success=False,
                    actions_performed=actions_performed,
                    message="The exact target window lost focus or changed bounds before clicking; observe again.",
                )
            if not _x11_pointer_matches(
                backend, observed_geometry["x"] + x, observed_geometry["y"] + y,
            ):
                return PointerActionResult(
                    success=False,
                    actions_performed=actions_performed,
                    message="The X11 pointer moved away from the observed target; no further click was sent.",
                )
            error = await _run_x11_command(
                backend,
                ["click", "--clearmodifiers", str(x11_button)],
                label="X11 pointer click",
            )
            if error:
                return PointerActionResult(success=False, actions_performed=actions_performed, message=error)
            actions_performed += 2
            if click_index + 1 < click_count:
                await asyncio.sleep(0.1)
        return PointerActionResult(
            success=True,
            actions_performed=actions_performed,
            message=f"X11 {action.replace('_', ' ')} sent to the observed focused window.",
        )

    if action == "drag":
        pressed = False
        success = False
        message = "X11 drag did not complete."
        error = await _run_x11_command(
            backend,
            ["mousedown", "--clearmodifiers", str(x11_button)],
            label="X11 drag button press",
        )
        if error:
            return PointerActionResult(success=False, actions_performed=actions_performed, message=error)
        pressed = True
        actions_performed += 1
        try:
            if not _focused_window_matches(backend, target_window_id, observed_geometry):
                message = "The exact target window lost focus or changed bounds before the drag; observe again."
            else:
                destination_x = observed_geometry["x"] + x
                destination_y = observed_geometry["y"] + y
                error = await _run_x11_command(
                    backend,
                    ["mousemove", "--sync", str(destination_x), str(destination_y)],
                    label="X11 drag motion",
                )
                if error:
                    message = error
                else:
                    actions_performed += 1
                    if not _x11_pointer_matches(backend, destination_x, destination_y):
                        message = "The X11 drag did not reach the observed destination."
                    elif not _focused_window_matches(backend, target_window_id, observed_geometry):
                        message = "The exact target window changed bounds or lost focus during the drag; observe again."
                    else:
                        success = True
                        message = "X11 drag sent within the observed focused window."
        finally:
            if pressed:
                release_error = await _run_x11_command(
                    backend,
                    ["mouseup", str(x11_button)],
                    label="X11 drag button release",
                )
                if release_error:
                    release_error = await _run_x11_command(
                        backend,
                        ["mouseup", str(x11_button)],
                        label="X11 drag button release retry",
                    )
                if release_error:
                    success = False
                    message = "X11 could not confirm drag-button release; the desktop may still consider the button pressed."
                else:
                    actions_performed += 1
        return PointerActionResult(success=success, actions_performed=actions_performed, message=message)

    return PointerActionResult(success=False, actions_performed=actions_performed, message="Unsupported X11 pointer action.")


async def touch_action(
    target_window_id: str,
    token_id: str,
    action: str,
    x: int,
    y: int,
    end_x: int | None = None,
    end_y: int | None = None,
    duration_ms: int | None = None,
) -> TouchActionResult:
    """Send one bounded single-finger gesture through consented XDG portals."""
    ok, error, observed = _authorize(token_id, "touch_action", target_window_id)
    if not ok or observed is None:
        return TouchActionResult(success=False, message=f"Touch action rejected: {error}")
    if observed.geometry is None:
        return TouchActionResult(success=False, message="This observation has no verified window geometry.")
    geometry = observed.geometry.model_dump()
    if geometry["width"] <= 0 or geometry["height"] <= 0:
        return TouchActionResult(success=False, message="The observed window geometry is empty or invalid.")
    if action not in {"tap", "double_tap", "long_press", "swipe"}:
        return TouchActionResult(success=False, message="Supported touch actions are tap, double_tap, long_press, and swipe.")
    if any(not isinstance(value, int) or isinstance(value, bool) for value in (x, y)):
        return TouchActionResult(success=False, message="Touch coordinates must be integers relative to the observed window.")
    if not (0 <= x < geometry["width"] and 0 <= y < geometry["height"]):
        return TouchActionResult(success=False, message="Touch coordinates fall outside the observed window bounds.")
    if action == "swipe":
        if any(value is None or not isinstance(value, int) or isinstance(value, bool) for value in (end_x, end_y)):
            return TouchActionResult(success=False, message="Swipe requires end_x and end_y coordinates relative to the observed window.")
        if not (0 <= end_x < geometry["width"] and 0 <= end_y < geometry["height"]):
            return TouchActionResult(success=False, message="Swipe destination falls outside the observed window bounds.")
        if end_x == x and end_y == y:
            return TouchActionResult(success=False, message="Swipe start and destination must differ.")
        if abs(end_x - x) > MAX_TOUCH_MOTION or abs(end_y - y) > MAX_TOUCH_MOTION:
            return TouchActionResult(success=False, message="Swipe distance exceeds the bounded touch motion limit.")
    elif end_x is not None or end_y is not None:
        return TouchActionResult(success=False, message="end_x and end_y are accepted only for a swipe.")
    if duration_ms is not None:
        if action not in {"long_press", "swipe"}:
            return TouchActionResult(success=False, message="duration_ms is accepted only for long_press or swipe.")
        if not isinstance(duration_ms, int) or isinstance(duration_ms, bool) or not 50 <= duration_ms <= MAX_TOUCH_DURATION_MS:
            return TouchActionResult(success=False, message=f"duration_ms must be between 50 and {MAX_TOUCH_DURATION_MS}.")
    duration = duration_ms if duration_ms is not None else (600 if action == "long_press" else 300)

    actions_performed = 0
    try:
        touch_session = await remote_desktop_portal.ensure_touch_session()
        if touch_session.newly_authorized:
            return TouchActionResult(
                success=False,
                actions_performed=0,
                message=(
                    "Touchscreen and monitor-sharing permission was just granted; the portal dialog may have changed "
                    "focus. Confirm the selected monitor, refocus the exact window, observe again, then retry."
                ),
            )

        backend = detect_backend()
        if not _focused_window_matches(backend, target_window_id, geometry):
            return TouchActionResult(success=False, message="The exact target window is no longer focused or changed bounds; observe again.")
        workspaces = backend.list_workspaces()
        visible_workspace_ids = {item.id for item in workspaces.workspaces if item.is_active} if workspaces.success else set()
        current = backend.list_windows()
        current_window = next((item for item in current.windows if item.id == target_window_id), None) if current.success else None
        if current_window is None or not current_window.workspace_id or current_window.workspace_id not in visible_workspace_ids:
            return TouchActionResult(success=False, message="The target window is not on a confirmed visible workspace; observe again.")

        outputs = backend.list_outputs()
        stream_bounds = (*touch_session.position, *touch_session.size)
        matching_outputs = [
            output for output in outputs.outputs
            if output.enabled and output.logical_geometry is not None
            and (
                output.logical_geometry.x,
                output.logical_geometry.y,
                output.logical_geometry.width,
                output.logical_geometry.height,
            ) == stream_bounds
        ] if outputs.success else []
        if len(matching_outputs) != 1:
            await remote_desktop_portal.close_touch_session()
            return TouchActionResult(
                success=False,
                message=(
                    "The selected portal monitor does not map exactly to one current compositor output; no touch was sent. "
                    "Observe again and retry to select a monitor with matching logical bounds."
                ),
            )

        screen_x, screen_y = geometry["x"] + x, geometry["y"] + y
        stream_x, stream_y = screen_x - touch_session.position[0], screen_y - touch_session.position[1]
        stream_end_x = stream_end_y = None
        if action == "swipe":
            stream_end_x = geometry["x"] + end_x - touch_session.position[0]
            stream_end_y = geometry["y"] + end_y - touch_session.position[1]
        if not (0 <= stream_x < touch_session.size[0] and 0 <= stream_y < touch_session.size[1]):
            await remote_desktop_portal.close_touch_session()
            return TouchActionResult(success=False, message="The touch point is outside the selected monitor; no touch was sent.")
        if action == "swipe" and not (
            0 <= stream_end_x < touch_session.size[0] and 0 <= stream_end_y < touch_session.size[1]
        ):
            await remote_desktop_portal.close_touch_session()
            return TouchActionResult(success=False, message="The swipe destination is outside the selected monitor; no touch was sent.")

        if not _focused_window_matches(backend, target_window_id, geometry):
            return TouchActionResult(success=False, message="The exact target window changed or lost focus before touch input; observe again.")

        async def perform_contact() -> None:
            nonlocal actions_performed
            if not _focused_window_matches(backend, target_window_id, geometry):
                raise PortalError("The exact target window changed or lost focus before touch input; observe again.")
            pressed = False
            try:
                await remote_desktop_portal.touch_down(touch_session, stream_x, stream_y)
                pressed = True
                actions_performed += 1
                if action == "swipe":
                    dx = stream_end_x - stream_x
                    dy = stream_end_y - stream_y
                    steps = max(2, min(32, math.ceil(max(abs(dx), abs(dy)) / 80)))
                    delay = duration / 1000 / steps
                    for step in range(1, steps + 1):
                        if not _focused_window_matches(backend, target_window_id, geometry):
                            raise PortalError("The exact target window changed or lost focus during the swipe.")
                        fraction = step / steps
                        await remote_desktop_portal.touch_motion(
                            touch_session,
                            stream_x + dx * fraction,
                            stream_y + dy * fraction,
                        )
                        actions_performed += 1
                        await asyncio.sleep(delay)
                else:
                    hold_ms = duration if action == "long_press" else 70
                    await asyncio.sleep(hold_ms / 1000)
            finally:
                if pressed:
                    try:
                        await remote_desktop_portal.touch_up(touch_session)
                        actions_performed += 1
                    except Exception:
                        try:
                            await remote_desktop_portal.touch_up(touch_session)
                            actions_performed += 1
                        except Exception as exc:
                            await remote_desktop_portal.close_touch_session()
                            raise PortalError("Touch release failed; the portal session was closed to clear the contact.") from exc

        contacts = 2 if action == "double_tap" else 1
        for index in range(contacts):
            await perform_contact()
            if action == "double_tap" and index == 0:
                await asyncio.sleep(0.12)
        return TouchActionResult(
            success=True,
            actions_performed=actions_performed,
            message=f"Touch {action.replace('_', ' ')} sent within the observed focused window.",
        )
    except PortalError as exc:
        return TouchActionResult(success=False, actions_performed=actions_performed, message=str(exc))
    except Exception as exc:
        return TouchActionResult(
            success=False,
            actions_performed=actions_performed,
            message=f"Touch input failed: {type(exc).__name__}.",
        )


async def _niri_absolute_pointer_action(
    backend,
    target_window_id: str,
    geometry,
    action: str,
    x: int,
    y: int,
    button: str,
    delta_x: int,
    delta_y: int,
    start_x: int | None,
    start_y: int | None,
) -> PointerActionResult:
    actions_performed = 0
    observed_geometry = geometry.model_dump()
    try:
        monitor_session = await remote_desktop_portal.ensure_absolute_pointer_session()
        if monitor_session.newly_authorized:
            return PointerActionResult(
                success=False,
                actions_performed=0,
                message=(
                    "Absolute pointer and monitor-sharing permission was just granted; the portal dialog may have changed "
                    "focus. Confirm the selected monitor, refocus the exact window, observe again, then retry."
                ),
            )

        if not _focused_window_matches(backend, target_window_id, observed_geometry):
            return PointerActionResult(success=False, actions_performed=0, message="The exact target window is no longer focused or changed bounds; observe again.")
        workspaces = backend.list_workspaces()
        visible_workspace_ids = {item.id for item in workspaces.workspaces if item.is_active} if workspaces.success else set()
        current = backend.list_windows()
        current_window = next((item for item in current.windows if item.id == target_window_id), None) if current.success else None
        if current_window is None or not current_window.workspace_id or current_window.workspace_id not in visible_workspace_ids:
            return PointerActionResult(success=False, actions_performed=0, message="The target window is not on a confirmed visible workspace; observe again.")

        outputs = backend.list_outputs()
        stream_bounds = (*monitor_session.position, *monitor_session.size)
        matching_outputs = [
            output for output in outputs.outputs
            if output.enabled and output.logical_geometry is not None
            and (
                output.logical_geometry.x,
                output.logical_geometry.y,
                output.logical_geometry.width,
                output.logical_geometry.height,
            ) == stream_bounds
        ] if outputs.success else []
        if len(matching_outputs) != 1:
            await remote_desktop_portal.close_absolute_pointer_session()
            return PointerActionResult(
                success=False,
                actions_performed=0,
                message=(
                    "The selected portal monitor does not map exactly to one current compositor output; no pointer event was sent. "
                    "Observe again and retry to select a monitor with matching logical bounds."
                ),
            )

        move_x = start_x if action == "drag" else x
        move_y = start_y if action == "drag" else y
        stream_x = geometry.x + move_x - monitor_session.position[0]
        stream_y = geometry.y + move_y - monitor_session.position[1]
        stream_end_x = geometry.x + x - monitor_session.position[0]
        stream_end_y = geometry.y + y - monitor_session.position[1]
        if not (
            0 <= stream_x < monitor_session.size[0]
            and 0 <= stream_y < monitor_session.size[1]
            and 0 <= stream_end_x < monitor_session.size[0]
            and 0 <= stream_end_y < monitor_session.size[1]
        ):
            await remote_desktop_portal.close_absolute_pointer_session()
            return PointerActionResult(
                success=False,
                actions_performed=0,
                message="The pointer target falls outside the selected monitor stream; no pointer event was sent.",
            )

        if not _focused_window_matches(backend, target_window_id, observed_geometry):
            return PointerActionResult(
                success=False,
                actions_performed=0,
                message="The exact target window changed or lost focus before pointer input; observe again.",
            )
        await remote_desktop_portal.pointer_move_absolute(monitor_session, stream_x, stream_y)
        actions_performed += 1
        if not _focused_window_matches(backend, target_window_id, observed_geometry):
            return PointerActionResult(
                success=False,
                actions_performed=actions_performed,
                message="The exact target window lost focus or changed bounds during pointer movement; observe again.",
            )
        if action == "move":
            return PointerActionResult(success=True, actions_performed=actions_performed, message="Pointer moved within the observed window.")
        if action == "scroll":
            await remote_desktop_portal.pointer_scroll_absolute(monitor_session, delta_x, delta_y)
            actions_performed += 1
            return PointerActionResult(success=True, actions_performed=actions_performed, message="Scroll sent within the observed window.")

        if action == "drag":
            button_code = BUTTONS[button]
            pressed = False
            try:
                pressed = True
                await remote_desktop_portal.pointer_button_absolute(monitor_session, button_code, True)
                actions_performed += 1
                dx, dy = stream_end_x - stream_x, stream_end_y - stream_y
                steps = max(2, min(32, math.ceil(max(abs(dx), abs(dy)) / 80)))
                for step in range(1, steps + 1):
                    if not _focused_window_matches(backend, target_window_id, observed_geometry):
                        raise PortalError("The exact target window changed or lost focus during the drag.")
                    fraction = step / steps
                    await remote_desktop_portal.pointer_move_absolute(
                        monitor_session,
                        stream_x + dx * fraction,
                        stream_y + dy * fraction,
                    )
                    actions_performed += 1
                    await asyncio.sleep(0.01)
                if not _focused_window_matches(backend, target_window_id, observed_geometry):
                    raise PortalError("The exact target window changed or lost focus at the end of the drag.")
                return PointerActionResult(
                    success=True,
                    actions_performed=actions_performed + 1,
                    message="Drag sent within the observed window using absolute portal coordinates.",
                )
            finally:
                if pressed:
                    try:
                        await remote_desktop_portal.pointer_button_absolute(monitor_session, button_code, False)
                        actions_performed += 1
                    except Exception:
                        try:
                            await remote_desktop_portal.pointer_button_absolute(monitor_session, button_code, False)
                        except Exception:
                            pass
                        await remote_desktop_portal.close_absolute_pointer_session()
                        raise PortalError("Pointer release failed; the portal session was closed to clear the button state.")

        click_count = 2 if action == "double_click" else 1
        for index in range(click_count):
            if not _focused_window_matches(backend, target_window_id, observed_geometry):
                raise PortalError("The exact target window changed or lost focus before clicking; observe again.")
            pressed = False
            try:
                pressed = True
                await remote_desktop_portal.pointer_button_absolute(monitor_session, BUTTONS[button], True)
                actions_performed += 1
            finally:
                if pressed:
                    try:
                        await remote_desktop_portal.pointer_button_absolute(monitor_session, BUTTONS[button], False)
                        actions_performed += 1
                    except Exception:
                        try:
                            await remote_desktop_portal.pointer_button_absolute(monitor_session, BUTTONS[button], False)
                        except Exception:
                            pass
                        await remote_desktop_portal.close_absolute_pointer_session()
                        raise PortalError("Pointer release failed; the portal session was closed to clear the button state.")
            if click_count == 2 and index == 0:
                await asyncio.sleep(0.08)
        return PointerActionResult(
            success=True,
            actions_performed=actions_performed,
            message=f"{action.replace('_', ' ').capitalize()} sent within the observed window.",
        )
    except PortalError as exc:
        return PointerActionResult(success=False, actions_performed=actions_performed, message=str(exc))
    except Exception as exc:
        return PointerActionResult(
            success=False,
            actions_performed=actions_performed,
            message=f"Absolute pointer input failed: {type(exc).__name__}.",
        )


async def pointer_action(
    target_window_id: str,
    token_id: str,
    action: str,
    x: int | None = None,
    y: int | None = None,
    button: str = "left",
    delta_x: int = 0,
    delta_y: int = 0,
    start_x: int | None = None,
    start_y: int | None = None,
) -> PointerActionResult:
    ok, error, observed = _authorize(token_id, "pointer_action", target_window_id)
    if not ok or observed is None:
        return PointerActionResult(success=False, actions_performed=0, message=f"Pointer action rejected: {error}")
    if observed.geometry is None:
        return PointerActionResult(success=False, actions_performed=0, message="This observation has no verified window geometry.")
    geometry = observed.geometry
    if action not in {"click", "double_click", "move", "scroll", "drag"}:
        return PointerActionResult(success=False, actions_performed=0, message="Supported pointer actions are click, double_click, move, scroll, and drag.")
    if action in {"click", "double_click", "move", "drag"} and (x is None or y is None):
        return PointerActionResult(success=False, actions_performed=0, message="This pointer action requires x and y coordinates relative to the observed window.")
    if action == "drag" and (start_x is None or start_y is None):
        return PointerActionResult(success=False, actions_performed=0, message="Drag requires start_x and start_y as well as destination x and y coordinates.")
    if x is None or y is None:
        x, y = geometry["width"] // 2, geometry["height"] // 2
    if not (0 <= x < geometry["width"] and 0 <= y < geometry["height"]):
        return PointerActionResult(success=False, actions_performed=0, message="Pointer coordinates fall outside the observed window bounds.")
    if action == "drag" and not (0 <= start_x < geometry["width"] and 0 <= start_y < geometry["height"]):
        return PointerActionResult(success=False, actions_performed=0, message="Drag start coordinates fall outside the observed window bounds.")
    if action == "scroll" and not (-MAX_SCROLL_DELTA <= delta_x <= MAX_SCROLL_DELTA and -MAX_SCROLL_DELTA <= delta_y <= MAX_SCROLL_DELTA):
        return PointerActionResult(success=False, actions_performed=0, message=f"Scroll deltas must be within ±{MAX_SCROLL_DELTA}.")
    if action in {"click", "double_click", "drag"} and button not in BUTTONS:
        return PointerActionResult(success=False, actions_performed=0, message="Button must be left, middle, right, side, extra, forward, back, or task.")
    move_x = start_x if action == "drag" else x
    move_y = start_y if action == "drag" else y
    screen_x, screen_y = geometry["x"] + move_x, geometry["y"] + move_y
    drag_dx = x - start_x if action == "drag" else 0
    drag_dy = y - start_y if action == "drag" else 0
    if action == "drag" and (abs(drag_dx) > MAX_POINTER_MOTION or abs(drag_dy) > MAX_POINTER_MOTION):
        return PointerActionResult(success=False, actions_performed=0, message="The drag distance exceeds the bounded portal motion limit.")
    backend = detect_backend()
    if backend.name == "x11":
        return await _x11_pointer_action(
            backend,
            target_window_id,
            geometry,
            action,
            x,
            y,
            button,
            delta_x,
            delta_y,
            start_x,
            start_y,
        )
    if backend.name == "niri" and backend.get_pointer_position() is None:
        return await _niri_absolute_pointer_action(
            backend,
            target_window_id,
            geometry,
            action,
            x,
            y,
            button,
            delta_x,
            delta_y,
            start_x,
            start_y,
        )
    actions_performed = 0
    try:
        session = await remote_desktop_portal.ensure_session(pointer=True)
        if session[3]:
            return PointerActionResult(
                success=False,
                actions_performed=0,
                message=(
                    "Input permission was just granted for keyboard and pointer together; the consent dialog may have "
                    "changed focus. Confirm the exact browser focus, refocus if needed, capture a fresh screenshot, "
                    "then retry."
                ),
            )
        current = backend.list_windows()
        current_window = (
            next((window for window in current.windows if window.id == target_window_id), None)
            if current.success else None
        )
        if current_window is None or current_window.geometry is None:
            return PointerActionResult(success=False, actions_performed=0,
                                       message="The exact target window is no longer observable; observe again.")
        if not current_window.is_focused:
            return PointerActionResult(success=False, actions_performed=0,
                                       message="The exact target window is not focused; focus it and observe again before pointer input.")
        if current_window.geometry.model_dump() != geometry:
            return PointerActionResult(success=False, actions_performed=0,
                                       message="The target window bounds changed after observation; observe again.")
        workspaces = backend.list_workspaces()
        visible_workspace_ids = {item.id for item in workspaces.workspaces if item.is_active} if workspaces.success else set()
        if not current_window.workspace_id or current_window.workspace_id not in visible_workspace_ids:
            return PointerActionResult(success=False, actions_performed=0,
                                       message="The target window is not on a confirmed visible workspace; observe again.")
        outputs = backend.list_outputs()
        output_matches = [
            output for output in outputs.outputs
            if output.enabled and output.logical_geometry is not None
            and output.logical_geometry.x <= screen_x < output.logical_geometry.x + output.logical_geometry.width
            and output.logical_geometry.y <= screen_y < output.logical_geometry.y + output.logical_geometry.height
        ] if outputs.success else []
        if len(output_matches) != 1:
            return PointerActionResult(
                success=False, actions_performed=0,
                message="The target point does not map to exactly one verified compositor output; pointer input aborted.",
            )
        cursor_before = backend.get_pointer_position()
        if cursor_before is None:
            return PointerActionResult(
                success=False, actions_performed=0,
                message="This compositor cannot report a fresh cursor position, so accurate portal pointer movement is unavailable.",
            )
        cursor_x, cursor_y = cursor_before
        cursor_outputs = [
            output for output in outputs.outputs
            if output.enabled and output.logical_geometry is not None
            and output.logical_geometry.x <= cursor_x < output.logical_geometry.x + output.logical_geometry.width
            and output.logical_geometry.y <= cursor_y < output.logical_geometry.y + output.logical_geometry.height
        ]
        if len(cursor_outputs) != 1:
            return PointerActionResult(
                success=False, actions_performed=0,
                message="The compositor cursor does not map to exactly one verified output; pointer input aborted.",
            )
        motion_dx, motion_dy = screen_x - cursor_x, screen_y - cursor_y
        if abs(motion_dx) > MAX_POINTER_MOTION or abs(motion_dy) > MAX_POINTER_MOTION:
            return PointerActionResult(
                success=False, actions_performed=0,
                message="The target point is too far from the current cursor for one bounded portal motion.",
            )
        await remote_desktop_portal.pointer_move_relative(motion_dx, motion_dy)
        actions_performed += 1
        await asyncio.sleep(0.08)
        cursor_after = backend.get_pointer_position()
        if cursor_after is None or (
            abs(cursor_after[0] - screen_x) > POINTER_POSITION_TOLERANCE
            or abs(cursor_after[1] - screen_y) > POINTER_POSITION_TOLERANCE
        ):
            return PointerActionResult(
                success=False, actions_performed=actions_performed,
                message="The portal pointer did not reach the observed target point; no click or scroll was sent.",
            )

        # Moving the pointer can change focus on some compositors. Recheck the
        # same window and geometry immediately before any button or scroll.
        current = backend.list_windows()
        current_window = (
            next((window for window in current.windows if window.id == target_window_id), None)
            if current.success else None
        )
        if (
            current_window is None
            or not current_window.is_focused
            or current_window.geometry is None
            or current_window.geometry.model_dump() != geometry
        ):
            return PointerActionResult(
                success=False, actions_performed=actions_performed,
                message="The exact target window lost focus or changed bounds during pointer movement; observe again before clicking.",
            )
        if action == "move":
            return PointerActionResult(success=True, actions_performed=1, message="Pointer moved within the observed window.")
        if action == "scroll":
            await remote_desktop_portal.pointer_scroll(delta_x, delta_y)
            actions_performed += 1
            return PointerActionResult(success=True, actions_performed=actions_performed, message="Scroll sent within the observed window.")
        if action == "drag":
            button_code = BUTTONS[button]
            pressed = False
            try:
                pressed = True
                await remote_desktop_portal.pointer_button(button_code, True)
                actions_performed += 1
                await remote_desktop_portal.pointer_move_relative(drag_dx, drag_dy)
                actions_performed += 1
                await asyncio.sleep(0.08)
                cursor_after_drag = backend.get_pointer_position()
                destination_x, destination_y = geometry["x"] + x, geometry["y"] + y
                if cursor_after_drag is None or (
                    abs(cursor_after_drag[0] - destination_x) > POINTER_POSITION_TOLERANCE
                    or abs(cursor_after_drag[1] - destination_y) > POINTER_POSITION_TOLERANCE
                ):
                    return PointerActionResult(
                        success=False,
                        actions_performed=actions_performed,
                        message="The portal drag did not reach its observed destination; the button was released.",
                    )
                after_drag = backend.list_windows()
                after_window = (
                    next((window for window in after_drag.windows if window.id == target_window_id), None)
                    if after_drag.success else None
                )
                if (
                    after_window is None
                    or not after_window.is_focused
                    or after_window.geometry is None
                    or after_window.geometry.model_dump() != geometry
                ):
                    return PointerActionResult(
                        success=False,
                        actions_performed=actions_performed,
                        message="The target window changed or lost focus during the drag; observe again.",
                    )
                return PointerActionResult(
                    success=True,
                    actions_performed=actions_performed + 1,
                    message="Drag sent within the observed window.",
                )
            finally:
                if pressed:
                    try:
                        await remote_desktop_portal.pointer_button(button_code, False)
                    except Exception:
                        try:
                            await remote_desktop_portal.pointer_button(button_code, False)
                        except Exception:
                            pass
                        raise
        click_count = 2 if action == "double_click" else 1
        for _ in range(click_count):
            pressed = False
            try:
                pressed = True
                await remote_desktop_portal.pointer_button(BUTTONS[button], True)
                actions_performed += 1
            finally:
                if pressed:
                    try:
                        await remote_desktop_portal.pointer_button(BUTTONS[button], False)
                        actions_performed += 1
                    except Exception:
                        try:
                            await remote_desktop_portal.pointer_button(BUTTONS[button], False)
                        except Exception:
                            pass
                        raise
        return PointerActionResult(success=True, actions_performed=actions_performed, message=f"{action.replace('_', ' ').capitalize()} sent.")
    except PortalError as exc:
        return PointerActionResult(success=False, actions_performed=actions_performed, message=str(exc))
    except Exception as exc:
        return PointerActionResult(success=False, actions_performed=actions_performed, message=f"Pointer input failed: {type(exc).__name__}.")


def _keysym(character: str) -> int:
    if len(character) != 1:
        raise ValueError("Expected one character")
    codepoint = ord(character)
    if codepoint <= 0xFF:
        return codepoint
    return 0x01000000 | codepoint


def _key_and_modifiers(value: str) -> tuple[int, list[int]]:
    if len(value) == 1:
        return _keysym(value), []
    named_code = _KEYSYMS_CASEFOLD.get(value.casefold())
    if named_code is not None:
        return named_code, []
    if not KEYS_RE.fullmatch(value):
        raise ValueError("Key must be one character, a supported named key, or a modifier chord such as Ctrl+C or Alt+F4")
    parts = value.split("+")
    key = parts[-1]
    modifiers = []
    for item in parts[:-1]:
        keycode = MODIFIERS.get(item.casefold())
        if keycode is None:
            raise ValueError("Unsupported key modifier")
        if keycode not in modifiers:
            modifiers.append(keycode)
    # Chord notation is case-insensitive for the key itself: Ctrl+T means
    # Control plus the T key, not Control+Shift+T. Shift is sent only when it
    # is named explicitly in the modifier list.
    if len(key) == 1:
        if key.isalpha():
            key = key.lower()
        return _keysym(key), modifiers
    named_code = _KEYSYMS_CASEFOLD.get(key.casefold())
    if named_code is None:
        raise ValueError("Key chord ends with an unsupported named key")
    return named_code, modifiers


def _xdotool_chord(value: str) -> str:
    """Convert the already-validated public chord syntax to xdotool syntax."""
    if len(value) == 1:
        raise ValueError("A one-character key is typed through xdotool type.")
    parts = value.split("+")
    modifier_names = {
        "ctrl": "ctrl",
        "control": "ctrl",
        "alt": "alt",
        "shift": "shift",
        "super": "super",
        "meta": "meta",
    }
    modifiers: list[str] = []
    for part in parts[:-1]:
        name = modifier_names[part.casefold()]
        if name not in modifiers:
            modifiers.append(name)
    key = parts[-1]
    if len(key) == 1:
        if key.isalpha():
            key = key.lower()
    else:
        key = X11_NAMED_KEYS[key.casefold()]
    return "+".join([*modifiers, key])


async def _x11_keyboard_action(
    backend,
    target_window_id: str,
    geometry: dict[str, int],
    *,
    text: str | None = None,
    key: str | None = None,
) -> KeyboardActionResult:
    if not getattr(backend, "xdotool", None):
        return KeyboardActionResult(success=False, message="The optional xdotool input tool is unavailable in the session PATH.")
    if not _focused_window_matches(backend, target_window_id, geometry):
        return KeyboardActionResult(
            success=False,
            message="The exact target window is no longer focused or changed bounds; observe again before keyboard input.",
        )
    if text is not None:
        normalized = text.replace("\r", "\n")
        sent = 0
        for offset in range(0, len(normalized), X11_TEXT_CHUNK_SIZE):
            chunk = normalized[offset:offset + X11_TEXT_CHUNK_SIZE]
            if not _focused_window_matches(backend, target_window_id, geometry):
                return KeyboardActionResult(
                    success=False,
                    text_length=sent,
                    message="The target window lost focus or changed bounds while typing; the reported prefix was sent. Observe again.",
                )
            error = await _run_x11_command(
                backend,
                ["type", "--clearmodifiers", "--delay", "1", "--", chunk],
                label="X11 text input",
            )
            if error:
                return KeyboardActionResult(success=False, text_length=sent, message=error)
            sent += len(chunk)
        return KeyboardActionResult(
            success=True,
            text_length=sent,
            message=f"Typed {sent} character(s) into the observed focused X11 window.",
        )

    if not isinstance(key, str):
        return KeyboardActionResult(success=False, message="A key or key chord is required.")
    try:
        _key_and_modifiers(key)
        if len(key) == 1:
            arguments = ["type", "--clearmodifiers", "--delay", "1", "--", key.replace("\r", "\n")]
        else:
            arguments = ["key", "--clearmodifiers", "--delay", "1", _xdotool_chord(key)]
    except (ValueError, KeyError) as exc:
        return KeyboardActionResult(success=False, message=str(exc))
    if not _focused_window_matches(backend, target_window_id, geometry):
        return KeyboardActionResult(
            success=False,
            message="The exact target window lost focus or changed bounds before key input; observe again.",
        )
    error = await _run_x11_command(backend, arguments, label="X11 key input")
    if error:
        return KeyboardActionResult(success=False, message=error)
    return KeyboardActionResult(
        success=True,
        key_pressed=key,
        message=f"Key {key} sent to the observed focused X11 window.",
    )


async def keyboard_action(
    target_window_id: str,
    token_id: str,
    action: str,
    text: str | None = None,
    key: str | None = None,
) -> KeyboardActionResult:
    ok, error, observed = _authorize(token_id, "keyboard_action", target_window_id)
    if not ok or observed is None:
        return KeyboardActionResult(success=False, message=f"Keyboard action rejected: {error}")
    if not observed.is_focused:
        return KeyboardActionResult(success=False, message="Keyboard input requires a fresh observation showing this exact window focused.")
    backend = detect_backend()
    if backend.name == "x11":
        if observed.geometry is None:
            return KeyboardActionResult(success=False, message="This observation has no verified X11 window geometry.")
        geometry = observed.geometry.model_dump()
        if action == "type_text":
            if not isinstance(text, str) or len(text) > MAX_TYPED_CHARACTERS:
                return KeyboardActionResult(success=False, message=f"Text must be at most {MAX_TYPED_CHARACTERS} characters.")
            if any(ord(char) < 0x20 and char not in "\n\t\r" for char in text):
                return KeyboardActionResult(success=False, message="Text contains unsupported control characters.")
            return await _x11_keyboard_action(
                backend, target_window_id, geometry, text=text,
            )
        if action == "press_key":
            return await _x11_keyboard_action(
                backend, target_window_id, geometry, key=key,
            )
        return KeyboardActionResult(success=False, message="Action must be type_text or press_key.")
    if action == "type_text":
        if not isinstance(text, str) or len(text) > MAX_TYPED_CHARACTERS:
            return KeyboardActionResult(success=False, message=f"Text must be at most {MAX_TYPED_CHARACTERS} characters.")
        sequence = list(text)
        if any(ord(char) < 0x20 and char not in "\n\t\r" for char in sequence):
            return KeyboardActionResult(success=False, message="Text contains unsupported control characters.")
        try:
            session = await remote_desktop_portal.ensure_session()
            if session[3]:
                return KeyboardActionResult(
                    success=False,
                    message=(
                        "Input permission was just granted for keyboard and pointer together; the consent dialog may "
                        "have changed focus. Confirm the exact browser focus, refocus if needed, capture a fresh "
                        "screenshot, then retry."
                    ),
                )
            focused = detect_backend().get_focused_window()
            if not focused.success or focused.window is None or focused.window.id != target_window_id:
                return KeyboardActionResult(success=False,
                                            message="The target is no longer the focused window; observe again before typing.")
            sent = 0
            for char in sequence:
                symbol = KEYSYMS.get("Return") if char in "\r\n" else KEYSYMS.get("Tab") if char == "\t" else _keysym(char)
                await remote_desktop_portal.keyboard_keysym(symbol, True)
                try:
                    await remote_desktop_portal.keyboard_keysym(symbol, False)
                except Exception:
                    try:
                        await remote_desktop_portal.keyboard_keysym(symbol, False)
                    except Exception:
                        pass
                    raise
                sent += 1
            return KeyboardActionResult(success=True, text_length=sent, message=f"Typed {sent} character(s) into the observed focused window.")
        except PortalError as exc:
            return KeyboardActionResult(success=False, message=str(exc))
        except Exception as exc:
            return KeyboardActionResult(success=False, message=f"Keyboard input failed: {type(exc).__name__}.")
    if action == "press_key":
        if not isinstance(key, str):
            return KeyboardActionResult(success=False, message="A key or key chord is required.")
        pressed_modifiers: list[int] = []
        symbol: int | None = None
        symbol_pressed = False
        try:
            symbol, modifiers = _key_and_modifiers(key)
            session = await remote_desktop_portal.ensure_session()
            if session[3]:
                return KeyboardActionResult(
                    success=False,
                    message=(
                        "Input permission was just granted for keyboard and pointer together; the consent dialog may "
                        "have changed focus. Confirm the exact browser focus, refocus if needed, capture a fresh "
                        "screenshot, then retry."
                    ),
                )
            focused = detect_backend().get_focused_window()
            if not focused.success or focused.window is None or focused.window.id != target_window_id:
                return KeyboardActionResult(success=False,
                                            message="The target is no longer the focused window; observe again before sending keys.")
            for modifier in modifiers:
                await remote_desktop_portal.keyboard_keysym(modifier, True)
                pressed_modifiers.append(modifier)
            await remote_desktop_portal.keyboard_keysym(symbol, True)
            symbol_pressed = True
            await remote_desktop_portal.keyboard_keysym(symbol, False)
            symbol_pressed = False
            for modifier in reversed(modifiers):
                await remote_desktop_portal.keyboard_keysym(modifier, False)
                pressed_modifiers.pop()
            return KeyboardActionResult(success=True, key_pressed=key, message=f"Key {key} sent to the observed focused window.")
        except (PortalError, ValueError) as exc:
            return KeyboardActionResult(success=False, message=str(exc))
        except Exception as exc:
            return KeyboardActionResult(success=False, message=f"Keyboard input failed: {type(exc).__name__}.")
        finally:
            if symbol_pressed and symbol is not None:
                try:
                    await remote_desktop_portal.keyboard_keysym(symbol, False)
                except Exception:
                    pass
            for modifier in reversed(pressed_modifiers):
                try:
                    await remote_desktop_portal.keyboard_keysym(modifier, False)
                except Exception:
                    pass
    return KeyboardActionResult(success=False, message="Action must be type_text or press_key.")
