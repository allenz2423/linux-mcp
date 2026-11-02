from wayland_mcp.backends.base import BaseCompositorBackend
from wayland_mcp.backends.hyprland import HyprlandBackend
from wayland_mcp.backends.sway import SwayBackend
from wayland_mcp.backends.niri import NiriBackend
from wayland_mcp.backends.x11 import X11Backend
from wayland_mcp.backends.cosmic import CosmicBackend
from wayland_mcp.backends.gnome import GnomeBackend
from wayland_mcp.backends.unsupported import UnsupportedBackend
from wayland_mcp.backends.registry import detect_backend, detect_session_info

__all__ = [
    "BaseCompositorBackend",
    "HyprlandBackend",
    "SwayBackend",
    "NiriBackend",
    "X11Backend",
    "CosmicBackend",
    "GnomeBackend",
    "UnsupportedBackend",
    "detect_backend",
    "detect_session_info",
]
