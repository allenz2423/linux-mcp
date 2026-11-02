from __future__ import annotations

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from wayland_mcp import server


@pytest.mark.asyncio
async def test_unavailable_initramfs_target_is_an_anticipated_tool_error(monkeypatch):
    message = "A standard current-kernel initramfs target could not be inspected."
    monkeypatch.setattr(
        server,
        "_initramfs_rebuild_confirmation_details",
        lambda: (None, message),
    )

    with pytest.raises(ToolError, match="standard current-kernel initramfs target"):
        await server._confirm_initramfs_rebuild()
