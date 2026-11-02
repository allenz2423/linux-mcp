from typing import Dict, Optional, Tuple
from wayland_mcp.backends.base import BaseCompositorBackend
from wayland_mcp.backends.hyprland import HyprlandBackend
from wayland_mcp.backends.sway import SwayBackend
from wayland_mcp.backends.niri import NiriBackend
from wayland_mcp.backends.kwin import KWinBackend
from wayland_mcp.backends.x11 import X11Backend
from wayland_mcp.backends.cosmic import CosmicBackend
from wayland_mcp.backends.gnome import GnomeBackend
from wayland_mcp.backends.unsupported import UnsupportedBackend
from wayland_mcp.models import SessionInfo
from wayland_mcp.session import find_session_binary, get_sanitized_env, logger


def detect_session_info(env: Optional[Dict[str, str]] = None) -> SessionInfo:
    """Extracts typed SessionInfo from the sanitized session environment."""
    e = env or get_sanitized_env()
    session_type = e.get("XDG_SESSION_TYPE", "").strip().lower()
    wayland_display = e.get("WAYLAND_DISPLAY")
    x11_display = e.get("DISPLAY")

    is_wayland = (session_type == "wayland") or bool(wayland_display)
    if not session_type:
        session_type = "wayland" if is_wayland else ("x11" if x11_display else "headless")

    desktop_name = e.get("XDG_CURRENT_DESKTOP") or e.get("DESKTOP_SESSION") or "Unknown"

    # Identify backend key
    backend = detect_backend(e)

    return SessionInfo(
        session_type=session_type,
        is_wayland=is_wayland,
        wayland_display=wayland_display,
        x11_display=x11_display,
        desktop_name=desktop_name,
        compositor_backend=backend.name,
    )


def detect_backend(env: Optional[Dict[str, str]] = None) -> BaseCompositorBackend:
    """
    Detects and returns the best matching compositor backend instance
    based on environment variables, active sockets, and session identifiers.
    """
    e = env or get_sanitized_env()
    xdg_current = e.get("XDG_CURRENT_DESKTOP", "").lower()
    desktop_session = e.get("DESKTOP_SESSION", "").lower()

    # 1. Hyprland check
    if "hyprland" in xdg_current or "hyprland" in desktop_session or bool(e.get("HYPRLAND_INSTANCE_SIGNATURE")):
        logger.debug("Detected Hyprland compositor session")
        return HyprlandBackend(e)

    # 2. Sway check
    if "sway" in xdg_current or "sway" in desktop_session or bool(e.get("SWAYSOCK")):
        logger.debug("Detected Sway compositor session")
        return SwayBackend(e)

    # 3. Niri check
    if "niri" in xdg_current or "niri" in desktop_session or bool(e.get("NIRI_SOCKET")):
        logger.debug("Detected Niri compositor session")
        return NiriBackend(e)

    # KWin exposes its Wayland window API through the user's session D-Bus
    # scripting interface. The adapter probes that API before advertising it.
    if "kde" in xdg_current or "plasma" in xdg_current or "kde" in desktop_session or "plasma" in desktop_session:
        logger.debug("Detected KDE Plasma / KWin session")
        return KWinBackend(e)

    desktop_key = " ".join((e.get("XDG_CURRENT_DESKTOP", "") + " " + e.get("DESKTOP_SESSION", "")).lower().replace("_", " ").split())
    is_wayland_session = e.get("XDG_SESSION_TYPE", "").strip().lower() == "wayland" or bool(e.get("WAYLAND_DISPLAY"))
    if "cosmic" in desktop_key and is_wayland_session:
        cosmic = CosmicBackend(e)
        capabilities, error = cosmic._capability_names()
        if error is None and "window_list" in capabilities:
            logger.debug("Detected COSMIC's native Wayland toplevel protocols")
            return cosmic
        reason = error or "The COSMIC compositor did not advertise usable toplevel and workspace protocols."
        logger.debug("COSMIC window adapter unavailable: %s", reason)
        return UnsupportedBackend(e, reason=reason, name="cosmic")
    if ("gnome" in desktop_key or "mutter" in desktop_key) and is_wayland_session:
        gnome = GnomeBackend(e)
        capabilities, error = gnome._capability_names()
        if error is None and "window_list" in capabilities:
            logger.debug("Detected GNOME Shell window-control extension")
            return gnome
        reason = error or "The GNOME Shell window-control extension is not enabled."
        logger.debug("GNOME Wayland window adapter unavailable: %s", reason)
        return UnsupportedBackend(e, reason=reason, name="gnome")

    session_type = e.get("XDG_SESSION_TYPE", "").strip().lower()
    is_x11_session = session_type == "x11" or (
        not session_type and bool(e.get("DISPLAY")) and not e.get("WAYLAND_DISPLAY")
    )
    if is_x11_session and e.get("DISPLAY") and find_session_binary("wmctrl", e):
        logger.debug("Detected EWMH-compatible X11 session with wmctrl")
        return X11Backend(e)

    # 4. Check if GUI session exists at all
    if not e.get("WAYLAND_DISPLAY") and not e.get("DISPLAY"):
        logger.debug("No GUI display found; returning UnsupportedBackend for headless session")
        return UnsupportedBackend(e, reason="No active WAYLAND_DISPLAY or DISPLAY variable found")

    desktop_ident = e.get("XDG_CURRENT_DESKTOP") or e.get("DESKTOP_SESSION") or "Generic"
    if "gnome" in desktop_key or "mutter" in desktop_key:
        backend_name = "gnome"
    elif "cosmic" in desktop_key:
        backend_name = "cosmic"
    else:
        backend_name = "unsupported"
    logger.debug("Compositor %s does not have a native window-management adapter", desktop_ident)
    return UnsupportedBackend(
        e,
        reason=f"Compositor '{desktop_ident}' has no native window-management adapter; portal-based screenshots/input may still be available.",
        name=backend_name,
    )
