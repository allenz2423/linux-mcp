from typing import List, Optional
from wayland_mcp.models import WindowInfo


def find_best_window(target: str, windows: List[WindowInfo]) -> Optional[WindowInfo]:
    """Resolve only an exact compositor-issued window ID; never fuzzy-match actions."""
    if not target or not windows:
        return None
    return next((window for window in windows if window.id == target), None)
