from __future__ import annotations

import subprocess
from types import SimpleNamespace

from wayland_mcp.backends import registry, x11
from wayland_mcp.backends.unsupported import UnsupportedBackend
from wayland_mcp.backends.x11 import X11Backend


WINDOWS = (
    "0x01200001 0 10 20 800 600 localhost Editor - Draft\n"
    "0x01200002 -1 900 20 200 200 localhost Sticky window\n"
)
DESKTOPS = (
    "0 * DG: 1920x1080 VP: 0,0 WA: 0,24 1920x1056 Workspace A\n"
    "1 - DG: 1920x1080 VP: 0,0 WA: 0,24 1920x1056 Workspace B\n"
)


def _backend(monkeypatch, *, output=WINDOWS, active_id="0x01200001") -> X11Backend:
    monkeypatch.setattr(
        x11,
        "find_session_binary",
        lambda name, _env: f"/usr/bin/{name}" if name in {"wmctrl", "xprop"} else None,
    )

    def run(arguments, **_kwargs):
        if arguments[0].endswith("xprop"):
            return SimpleNamespace(returncode=0, stdout=f"_NET_ACTIVE_WINDOW(WINDOW): window id # {active_id}\n", stderr="")
        if arguments[0].endswith("wmctrl"):
            if arguments[1:] == ["-d"]:
                return SimpleNamespace(returncode=0, stdout=DESKTOPS, stderr="")
            if arguments[1:] == ["-l", "-G"]:
                return SimpleNamespace(returncode=0, stdout=output, stderr="")
        raise AssertionError(arguments)

    monkeypatch.setattr(subprocess, "run", run)
    return X11Backend({"DISPLAY": ":99", "PATH": "/usr/bin"})


def test_x11_lists_exact_windows_and_desktops(monkeypatch):
    backend = _backend(monkeypatch)

    windows = backend.list_windows()
    desktops = backend.list_workspaces()

    assert windows.success
    assert windows.total_windows == 2
    assert windows.focused_window is not None
    assert windows.focused_window.id == "0x01200001"
    assert windows.windows[0].title == "Editor - Draft"
    assert windows.windows[0].geometry is not None
    assert windows.windows[0].geometry.model_dump() == {"x": 10, "y": 20, "width": 800, "height": 600}
    assert windows.windows[1].workspace_id is None
    assert desktops.success
    assert [item.name for item in desktops.workspaces] == ["Workspace A", "Workspace B"]
    assert desktops.active_workspace is not None and desktops.active_workspace.id == "0"


def test_x11_matches_focused_window_when_xprop_omits_leading_zeroes(monkeypatch):
    backend = _backend(monkeypatch, active_id="0x1200001")

    windows = backend.list_windows()
    focused = backend.get_focused_window()

    assert windows.focused_window is not None
    assert windows.focused_window.id == "0x01200001"
    assert focused.success
    assert focused.window is not None
    assert focused.window.id == "0x01200001"


def test_x11_resize_rechecks_the_reported_geometry(monkeypatch):
    state = {"width": 800, "height": 600}
    monkeypatch.setattr(
        x11,
        "find_session_binary",
        lambda name, _env: f"/usr/bin/{name}" if name in {"wmctrl", "xprop"} else None,
    )

    def run(arguments, **_kwargs):
        if arguments[0].endswith("wmctrl") and arguments[1:] == ["-l", "-G"]:
            windows = f"0x01200001 0 10 20 {state['width']} {state['height']} localhost Editor\n"
            return SimpleNamespace(returncode=0, stdout=windows, stderr="")
        if arguments[0].endswith("wmctrl") and arguments[1:5] == ["-i", "-r", "0x01200001", "-e"]:
            _gravity, _x, _y, width, height = arguments[5].split(",")
            state["width"], state["height"] = int(width), int(height)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(arguments)

    monkeypatch.setattr(subprocess, "run", run)
    backend = X11Backend({"DISPLAY": ":99", "PATH": "/usr/bin"})

    result = backend.resize_window("0x01200001", 1024, 768)

    assert result.success
    assert state == {"width": 1024, "height": 768}


def test_x11_actions_reject_non_numeric_window_targets(monkeypatch):
    backend = _backend(monkeypatch)

    result = backend.focus_window("0x12; touch /tmp/unexpected")

    assert not result.success
    assert "exact hexadecimal" in result.message


def test_x11_window_input_capabilities_do_not_depend_on_workspace_metadata(monkeypatch):
    monkeypatch.setattr(
        x11,
        "find_session_binary",
        lambda name, _env: f"/usr/bin/{name}" if name in {"wmctrl", "xprop", "xdotool"} else None,
    )

    def run(arguments, **_kwargs):
        if arguments[0].endswith("wmctrl") and arguments[1:] == ["-d"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="workspace metadata unavailable")
        if arguments[0].endswith("wmctrl") and arguments[1:] == ["-l", "-G"]:
            return SimpleNamespace(returncode=0, stdout=WINDOWS, stderr="")
        raise AssertionError(arguments)

    monkeypatch.setattr(subprocess, "run", run)
    backend = X11Backend({"DISPLAY": ":99", "PATH": "/usr/bin"})

    capabilities = backend.get_capabilities()

    assert capabilities.window_list
    assert not capabilities.workspace_list
    assert capabilities.bounded_input


def test_registry_selects_wmctrl_only_for_x11_sessions(monkeypatch):
    monkeypatch.setattr(registry, "find_session_binary", lambda _name, _env: "/usr/bin/wmctrl")

    x11_backend = registry.detect_backend({
        "DISPLAY": ":99",
        "PATH": "/usr/bin",
        "XDG_CURRENT_DESKTOP": "GNOME",
        "XDG_SESSION_TYPE": "x11",
    })
    wayland_backend = registry.detect_backend({
        "DISPLAY": ":99",
        "PATH": "/usr/bin",
        "WAYLAND_DISPLAY": "wayland-0",
        "XDG_CURRENT_DESKTOP": "GNOME",
        "XDG_SESSION_TYPE": "wayland",
    })

    assert isinstance(x11_backend, X11Backend)
    assert isinstance(wayland_backend, UnsupportedBackend)
