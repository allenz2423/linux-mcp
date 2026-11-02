"""Shared local libvirt connection helpers."""

from __future__ import annotations

import sys

from wayland_mcp.session import find_session_binary, get_sanitized_env

SCOPED_URIS = {"system": "qemu:///system", "session": "qemu:///session"}


def virsh_available(env: dict[str, str] | None = None) -> bool:
    selected_env = env or virsh_environment()
    return sys.platform.startswith("linux") and find_session_binary(
        "virsh", selected_env
    ) is not None


def virsh_environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env
