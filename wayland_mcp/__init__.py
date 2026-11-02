"""Linux MCP server package; ``wayland_mcp`` remains its import namespace."""

from wayland_mcp.server import create_server, run_server

__version__ = "0.1.0"
__all__ = ["create_server", "run_server"]
