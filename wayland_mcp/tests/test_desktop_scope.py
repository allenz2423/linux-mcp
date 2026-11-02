from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from wayland_mcp.backends import hyprland
from wayland_mcp.backends.hyprland import HyprlandBackend
from wayland_mcp.backends.registry import detect_backend
from wayland_mcp.backends.unsupported import UnsupportedBackend
from wayland_mcp.server import create_server
from wayland_mcp.models import (
    AppLaunchResult,
    CapabilitiesResponse,
    OutputInfo,
    OutputListResponse,
    PerCapabilityStatus,
    SessionInfo,
    WindowGeometry,
    WindowInfo,
    WindowListResponse,
)
from wayland_mcp.safety.tokens import TokenManager
from wayland_mcp.tools import apps, discovery


DESKTOP_TOOLS = {
    "get_session_capabilities",
    "observe_desktop",
    "list_windows",
    "get_window_detail",
    "get_focused_window",
    "list_workspaces",
    "list_outputs",
    "focus_window",
    "close_window",
    "resize_window",
    "minimize_window",
    "maximize_window",
    "switch_workspace",
    "move_window_to_workspace",
    "capture_screenshot",
    "inspect_accessibility_tree",
    "pointer_action",
    "keyboard_action",
    "list_desktop_apps",
    "launch_app",
    "read_clipboard",
    "write_clipboard",
    "send_notification",
}

GENERAL_PURPOSE_TOOLS = {
    "get_linux_system_info",
    "list_cpu_inventory",
    "list_services",
    "list_installed_packages",
    "list_network_interfaces",
    "list_containers",
}


def test_mcp_registers_desktop_and_general_purpose_tools():
    actual_tools = asyncio.run(create_server().list_tools())
    actual_names = {tool.name for tool in actual_tools}
    assert DESKTOP_TOOLS <= actual_names
    assert GENERAL_PURPOSE_TOOLS <= actual_names

    package_root = Path(__file__).resolve().parents[1]
    server_path = package_root / "server.py"
    tree = ast.parse(server_path.read_text(), filename=str(server_path))
    registered: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not (
                isinstance(decorator, ast.Call)
                and (
                    (isinstance(decorator.func, ast.Attribute) and decorator.func.attr == "tool")
                    or (isinstance(decorator.func, ast.Name) and decorator.func.id == "tool")
                )
            ):
                continue
            for keyword in decorator.keywords:
                if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    registered.add(str(keyword.value.value))
    assert registered == actual_names

    tool_dir = package_root / "tools"
    modules = {path.stem for path in tool_dir.glob("*.py")} - {"__init__"}
    assert {"apps", "discovery", "input", "management", "system", "vision", "windows"} <= modules


def test_package_does_not_use_shell_execution():
    package_root = Path(__file__).resolve().parents[1]
    forbidden_calls = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
    violations = []
    for path in package_root.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                name = f"{node.func.value.id}.{node.func.attr}"
                if name in forbidden_calls:
                    violations.append(f"{path}:{node.lineno}: {name}")
            if any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                violations.append(f"{path}:{node.lineno}: shell=True")
    assert violations == []


def test_session_detection_selects_native_compositors_and_gnome_fallback():
    path = "/nonexistent"
    assert detect_backend({"PATH": path, "HYPRLAND_INSTANCE_SIGNATURE": "instance"}).name == "hyprland"
    assert detect_backend({"PATH": path, "SWAYSOCK": "/run/user/1000/sway.sock"}).name == "sway"
    assert detect_backend({"PATH": path, "NIRI_SOCKET": "/run/user/1000/niri.sock"}).name == "niri"
    assert detect_backend({"PATH": path, "XDG_CURRENT_DESKTOP": "KDE"}).name == "kde_plasma"

    gnome = detect_backend({
        "PATH": path,
        "XDG_CURRENT_DESKTOP": "GNOME",
        "XDG_SESSION_TYPE": "wayland",
        "WAYLAND_DISPLAY": "wayland-0",
    })
    assert isinstance(gnome, UnsupportedBackend)
    assert gnome.name == "gnome"


def test_observation_tokens_are_exact_single_use_and_bind_workspace_targets():
    manager = TokenManager()
    window = WindowInfo(id="42", app_id="org.example.Editor", title="Draft")
    token = manager.create_token(
        scope="windows",
        allowed_operations={"move_window_to_workspace"},
        observed_windows=[window],
        observed_workspaces=["2", "3"],
    )

    valid, error, observed = manager.validate_and_consume(
        token.token_id,
        operation="move_window_to_workspace",
        target="42",
        target_type="window_and_workspace",
        secondary_target="3",
    )
    assert valid and error is None and observed is not None and observed.id == "42"

    replayed, replay_error, _ = manager.validate_and_consume(
        token.token_id,
        operation="move_window_to_workspace",
        target="42",
        target_type="window_and_workspace",
        secondary_target="3",
    )
    assert not replayed
    assert "already used" in (replay_error or "")


def test_wrong_exact_target_consumes_token():
    manager = TokenManager()
    token = manager.create_token(
        scope="windows",
        allowed_operations={"focus_window"},
        observed_windows=[WindowInfo(id="window-a", app_id="app", title="A")],
    )
    valid, error, _ = manager.validate_and_consume(
        token.token_id,
        operation="focus_window",
        target="window-b",
    )
    assert not valid
    assert "not in this observation" in (error or "")

    replayed, replay_error, _ = manager.validate_and_consume(
        token.token_id,
        operation="focus_window",
        target="window-a",
    )
    assert not replayed
    assert "already used" in (replay_error or "")


def test_app_launch_uses_only_a_discovered_desktop_id_without_shell(monkeypatch):
    manager = TokenManager()
    app_id = "org.example.Editor.desktop"
    token = manager.create_token(scope="apps", allowed_operations={"launch_app"}, observed_apps=[app_id])
    monkeypatch.setattr(apps, "get_sanitized_env", lambda: {"PATH": "/usr/bin"})
    monkeypatch.setattr(
        apps,
        "_desktop_entries",
        lambda _env: {app_id: SimpleNamespace(info=SimpleNamespace(name="Editor"))},
    )
    monkeypatch.setattr(apps, "find_session_binary", lambda binary, _env: "/usr/bin/gtk-launch" if binary == "gtk-launch" else None)
    popen_calls = []
    monkeypatch.setattr(apps.subprocess, "Popen", lambda *args, **kwargs: popen_calls.append((args, kwargs)))
    monkeypatch.setattr(apps, "snapshot_token_manager", manager)

    result = apps.launch_app(app_id, token.token_id)
    assert isinstance(result, AppLaunchResult)
    assert result.success
    assert popen_calls[0][0][0] == ["/usr/bin/gtk-launch", "org.example.Editor"]
    assert "shell" not in popen_calls[0][1]


def test_browser_desktop_app_is_not_exposed_by_general_purpose_app_discovery(monkeypatch, tmp_path):
    apps_dir = tmp_path / "applications"
    apps_dir.mkdir()
    (apps_dir / "firefox.desktop").write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Firefox Web Browser\n"
        "GenericName=Web Browser\n"
        "Categories=Network;WebBrowser;\n"
        "Exec=/usr/bin/firefox %u\n",
        encoding="utf-8",
    )
    env = {"HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path), "XDG_DATA_DIRS": ""}
    monkeypatch.setattr(apps, "get_sanitized_env", lambda: env)
    monkeypatch.setattr(
        apps,
        "find_session_binary",
        lambda binary, _env: "/usr/bin/gtk-launch" if binary == "gtk-launch" else None,
    )
    listing = apps.list_desktop_apps(query="Firefox")
    assert listing.applications == []
    assert listing.total_apps == 0


def test_hyprland_screenshot_uses_bounded_timeout_and_reports_expiry(monkeypatch):
    backend = HyprlandBackend(env={"PATH": "/usr/bin"})
    window = WindowInfo(
        id="window-1",
        app_id="org.example.Browser",
        title="Browser",
        geometry=WindowGeometry(x=10, y=20, width=800, height=600),
    )
    monkeypatch.setattr(
        hyprland,
        "find_session_binary",
        lambda binary, _env: "/usr/bin/grim" if binary == "grim" else None,
    )
    monkeypatch.setattr(
        backend,
        "list_windows",
        lambda: WindowListResponse(
            success=True,
            total_windows=1,
            compositor="hyprland",
            windows=[window],
            focused_window=window,
        ),
    )
    monkeypatch.setattr(backend, "_run_hyprctl", lambda _args: None)
    calls = []

    def timeout_run(command, *, capture_output, timeout, env):
        calls.append((command, capture_output, timeout, env))
        raise hyprland.subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(hyprland.subprocess, "run", timeout_run)
    success, image, geometry, message = backend.capture_screenshot(scope="window", target="window-1")

    assert not success
    assert image == b""
    assert geometry == window.geometry
    assert f"timed out after {hyprland.SCREENSHOT_TIMEOUT_SECONDS:.1f}s" in message
    assert calls[0][2] == hyprland.SCREENSHOT_TIMEOUT_SECONDS
    assert calls[0][0] == ["/usr/bin/grim", "-g", "10,20 800x600", "-"]


def test_hyprland_screenshot_fails_fast_when_all_active_outputs_are_dpms_off(monkeypatch):
    backend = HyprlandBackend(env={"PATH": "/usr/bin"})
    window = WindowInfo(
        id="window-1",
        app_id="org.example.Browser",
        title="Browser",
        geometry=WindowGeometry(x=10, y=20, width=800, height=600),
    )
    monkeypatch.setattr(
        hyprland,
        "find_session_binary",
        lambda binary, _env: "/usr/bin/grim" if binary == "grim" else None,
    )
    monkeypatch.setattr(
        backend,
        "list_windows",
        lambda: WindowListResponse(
            success=True,
            total_windows=1,
            compositor="hyprland",
            windows=[window],
            focused_window=window,
        ),
    )
    monkeypatch.setattr(
        backend,
        "_run_hyprctl",
        lambda _args: [{"name": "DP-5", "disabled": False, "dpmsStatus": False}],
    )
    monkeypatch.setattr(
        hyprland.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("grim must not run when all active outputs are DPMS-off"),
    )

    success, image, geometry, message = backend.capture_screenshot(scope="window", target="window-1")

    assert not success
    assert image == b""
    assert geometry == window.geometry
    assert "DPMS-off" in message


def test_hyprland_cursor_position_requires_finite_numeric_coordinates(monkeypatch):
    backend = HyprlandBackend(env={"PATH": "/usr/bin"})
    monkeypatch.setattr(backend, "_run_hyprctl", lambda _args: {"x": 41, "y": 82.5})
    assert backend.get_pointer_position() == (41.0, 82.5)

    for result in (
        None,
        {"x": "41", "y": 82},
        {"x": True, "y": 82},
        {"x": float("inf"), "y": 82},
        {"x": 41, "y": float("nan")},
    ):
        monkeypatch.setattr(backend, "_run_hyprctl", lambda _args, result=result: result)
        assert backend.get_pointer_position() is None


class _ReadyWaylandBackend:
    name = "hyprland"

    def get_capabilities(self):
        return {
            "window_list": PerCapabilityStatus(supported=True, available=True, state="ready"),
            "output_list": PerCapabilityStatus(supported=True, available=True, state="ready"),
            "screenshot": PerCapabilityStatus(supported=True, available=False, state="dependency_missing"),
        }

    def list_outputs(self):
        return OutputListResponse(
            success=True,
            total_outputs=1,
            compositor=self.name,
            outputs=[OutputInfo(
                id="DP-1",
                name="DP-1",
                logical_geometry=WindowGeometry(x=0, y=0, width=1920, height=1080),
            )],
        )

    def get_pointer_position(self):
        return (100.0, 100.0)


def test_capability_report_marks_portal_input_as_permission_gated(monkeypatch, tmp_path):
    apps_dir = tmp_path / "applications"
    apps_dir.mkdir()
    env = {
        "PATH": "/usr/bin",
        "HOME": str(tmp_path),
        "XDG_RUNTIME_DIR": str(tmp_path),
        "XDG_SESSION_TYPE": "wayland",
        "WAYLAND_DISPLAY": "wayland-0",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
        "AT_SPI_BUS_ADDRESS": "unix:path=/run/user/1000/at-spi/bus_0",
    }
    session = SessionInfo(
        session_type="wayland",
        is_wayland=True,
        wayland_display="wayland-0",
        desktop_name="Hyprland",
        compositor_backend="hyprland",
    )
    backend = _ReadyWaylandBackend()
    monkeypatch.setattr(discovery, "get_sanitized_env", lambda: env)
    monkeypatch.setattr(discovery, "detect_session_info", lambda _env: session)
    monkeypatch.setattr(discovery, "detect_backend", lambda _env: backend)
    monkeypatch.setattr(discovery, "_desktop_paths", lambda _env: [apps_dir])
    monkeypatch.setattr(discovery, "_session_bus_available", lambda _env: True)
    monkeypatch.setattr(discovery, "find_session_binary", lambda binary, _env: f"/usr/bin/{binary}")
    monkeypatch.setattr(discovery.importlib.util, "find_spec", lambda _name: object())

    response = discovery.get_session_capabilities()
    assert response.capabilities["input_keyboard"].state == "permission_required"
    assert response.capabilities["input_pointer"].state == "permission_required"
    assert response.capabilities["screenshot"].state == "permission_required"
    assert response.capabilities["input_pointer"].required_permission


@pytest.mark.asyncio
async def test_live_capability_report_marks_missing_portal_interfaces(monkeypatch):
    response = CapabilitiesResponse(
        session=SessionInfo(
            session_type="wayland",
            is_wayland=True,
            desktop_name="Hyprland",
            compositor_backend="hyprland",
        ),
        capabilities={
            "input_keyboard": PerCapabilityStatus(
                supported=True, available=False, state="permission_required",
                required_permission="keyboard grant",
            ),
            "input_pointer": PerCapabilityStatus(
                supported=True, available=False, state="permission_required",
                required_permission="pointer grant",
            ),
            "input_touch": PerCapabilityStatus(
                supported=True, available=False, state="permission_required",
                required_permission="touchscreen grant",
            ),
        },
        summary="",
    )

    async def interfaces():
        return {"org.freedesktop.portal.ScreenCast"}

    from wayland_mcp import portal

    monkeypatch.setattr(discovery, "get_session_capabilities", lambda: response)
    monkeypatch.setattr(portal.remote_desktop_portal, "portal_interfaces", interfaces)

    live = await discovery.get_session_capabilities_async()

    assert live.capabilities["input_keyboard"].state == "dependency_missing"
    assert live.capabilities["input_pointer"].state == "dependency_missing"
    assert "RemoteDesktop" in live.capabilities["input_keyboard"].reason
    assert live.capabilities["input_keyboard"].required_permission is None
    assert "portal permissions pending: 0" in live.summary


@pytest.mark.asyncio
async def test_live_capability_report_keeps_portal_grants_pending_when_interfaces_exist(monkeypatch):
    response = CapabilitiesResponse(
        session=SessionInfo(
            session_type="wayland",
            is_wayland=True,
            desktop_name="Hyprland",
            compositor_backend="hyprland",
        ),
        capabilities={
            "input_keyboard": PerCapabilityStatus(
                supported=True, available=False, state="permission_required",
                required_permission="keyboard grant",
            ),
            "input_pointer": PerCapabilityStatus(
                supported=True, available=False, state="permission_required",
                required_permission="pointer grant",
            ),
            "input_touch": PerCapabilityStatus(
                supported=True, available=False, state="permission_required",
                required_permission="touchscreen grant",
            ),
        },
        summary="",
    )

    async def interfaces():
        return {"org.freedesktop.portal.RemoteDesktop"}

    from wayland_mcp import portal

    monkeypatch.setattr(discovery, "get_session_capabilities", lambda: response)
    monkeypatch.setattr(portal.remote_desktop_portal, "portal_interfaces", interfaces)

    live = await discovery.get_session_capabilities_async()

    assert live.capabilities["input_keyboard"].state == "permission_required"
    assert live.capabilities["input_pointer"].state == "permission_required"


def test_gnome_capabilities_do_not_invent_exact_window_input(monkeypatch, tmp_path):
    env = {
        "PATH": "/usr/bin",
        "HOME": str(tmp_path),
        "XDG_RUNTIME_DIR": str(tmp_path),
        "XDG_SESSION_TYPE": "wayland",
        "WAYLAND_DISPLAY": "wayland-0",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
        "AT_SPI_BUS_ADDRESS": "unix:path=/run/user/1000/at-spi/bus_0",
    }
    session = SessionInfo(
        session_type="wayland",
        is_wayland=True,
        wayland_display="wayland-0",
        desktop_name="GNOME",
        compositor_backend="gnome",
    )
    backend = UnsupportedBackend(env=env, name="gnome", reason="No native window adapter")
    monkeypatch.setattr(discovery, "get_sanitized_env", lambda: env)
    monkeypatch.setattr(discovery, "detect_session_info", lambda _env: session)
    monkeypatch.setattr(discovery, "detect_backend", lambda _env: backend)
    monkeypatch.setattr(discovery, "_desktop_paths", lambda _env: [])
    monkeypatch.setattr(discovery, "_session_bus_available", lambda _env: True)
    monkeypatch.setattr(discovery, "find_session_binary", lambda binary, _env: f"/usr/bin/{binary}")
    monkeypatch.setattr(discovery.importlib.util, "find_spec", lambda _name: object())

    response = discovery.get_session_capabilities()
    assert response.capabilities["window_list"].supported is False
    assert response.capabilities["screenshot"].state == "permission_required"
    assert response.capabilities["input_keyboard"].state == "not_supported"
    assert response.capabilities["input_pointer"].state == "not_supported"
