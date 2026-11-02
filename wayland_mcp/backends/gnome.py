"""GNOME Shell window control through the optional local extension helper."""

from __future__ import annotations

from typing import Optional

from wayland_mcp.backends.cosmic import CosmicBackend
from wayland_mcp.session import find_session_binary


class GnomeBackend(CosmicBackend):
    """Reuse the bounded JSON adapter contract for the GNOME helper."""

    name = "gnome"

    def __init__(self, env: Optional[dict[str, str]] = None) -> None:
        super().__init__(env)
        self.helper = find_session_binary("linux-mcp-gnome-wm", self.env)
