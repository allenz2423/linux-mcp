import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Set

# Diagnostic logger strictly targeted to stderr to protect MCP stdio framing
logger = logging.getLogger("wayland_mcp")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("[%(asctime)s] [linux-mcp] %(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

ALLOWLISTED_ENV_VARS: Set[str] = {
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "XDG_RUNTIME_DIR",
    "XDG_CURRENT_DESKTOP",
    "XDG_DATA_HOME",
    "XDG_DATA_DIRS",
    "XDG_SESSION_TYPE",
    "XDG_SESSION_DESKTOP",
    "DESKTOP_SESSION",
    "HYPRLAND_INSTANCE_SIGNATURE",
    "SWAYSOCK",
    "NIRI_SOCKET",
    "I3SOCK",
    "KDE_SESSION_VERSION",
    "KDE_FULL_SESSION",
    "DBUS_SESSION_BUS_ADDRESS",
    "AT_SPI_BUS_ADDRESS",
    "PATH",
    "USER",
    "HOME",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
}


def ensure_gui_environment() -> Dict[str, str]:
    """
    Acquires GUI display variables from process environment, systemd user environment,
    or runtime sockets without mutating global secrets.
    """
    env = dict(os.environ)

    # Check systemd user environment if WAYLAND_DISPLAY or DISPLAY is missing
    if not env.get("WAYLAND_DISPLAY") or not env.get("DISPLAY"):
        try:
            res = subprocess.run(
                ["systemctl", "--user", "show-environment"],
                capture_output=True,
                text=True,
                timeout=1,
                env={key: value for key, value in env.items() if key in ALLOWLISTED_ENV_VARS},
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k in ALLOWLISTED_ENV_VARS and v and k not in env:
                            env[k] = v
        except Exception as e:
            logger.debug(f"Failed to query systemctl user environment: {e}")

    # Ensure D-Bus user bus address
    if not env.get("DBUS_SESSION_BUS_ADDRESS"):
        uid = os.getuid()
        bus_path = Path(f"/run/user/{uid}/bus")
        if bus_path.is_socket():
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus_path}"

    runtime_dir = Path(env.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))

    # Fallback search for wayland socket in runtime dir
    if not env.get("WAYLAND_DISPLAY") and runtime_dir.exists():
        for sock in runtime_dir.glob("wayland-*"):
            if sock.is_socket():
                env["WAYLAND_DISPLAY"] = sock.name
                break

    # Discover Hyprland instance signature socket
    if not env.get("HYPRLAND_INSTANCE_SIGNATURE") and runtime_dir.exists():
        hypr_dir = runtime_dir / "hypr"
        if hypr_dir.exists():
            for inst in hypr_dir.iterdir():
                if inst.is_dir() and (inst / ".socket.sock").is_socket():
                    env["HYPRLAND_INSTANCE_SIGNATURE"] = inst.name
                    break

    # Discover Sway IPC socket
    if not env.get("SWAYSOCK") and runtime_dir.exists():
        for sock in runtime_dir.glob("sway-ipc.*.sock"):
            if sock.is_socket():
                env["SWAYSOCK"] = str(sock)
                break

    # Discover Niri socket
    if not env.get("NIRI_SOCKET") and runtime_dir.exists():
        for sock in runtime_dir.glob("niri*.sock"):
            if sock.is_socket():
                env["NIRI_SOCKET"] = str(sock)
                break

    return env


def get_sanitized_env(base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Returns a deliberately stripped environment dictionary suitable for subprocesses.
    Prevents leaking credentials, LLM keys, or unintended host secrets to child tools.
    """
    source = base_env if base_env is not None else ensure_gui_environment()
    sanitized: Dict[str, str] = {}
    for key in ALLOWLISTED_ENV_VARS:
        val = source.get(key)
        if key == "AT_SPI_BUS_ADDRESS" and val and not _is_local_atspi_address(val, source):
            continue
        if val is not None:
            sanitized[key] = val
    return sanitized


def _is_local_atspi_address(address: str, env: Dict[str, str]) -> bool:
    """Accept only an existing AT-SPI Unix socket inside this user's runtime dir."""
    runtime = Path(env.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    atspi_root = (runtime / "at-spi").resolve()
    endpoints = address.split(";")
    if not endpoints:
        return False
    for endpoint in endpoints:
        if not endpoint.startswith("unix:path="):
            return False
        raw_path = endpoint[len("unix:path="):].split(",", 1)[0]
        try:
            candidate = Path(raw_path).resolve(strict=True)
            if not candidate.is_socket() or not candidate.is_relative_to(atspi_root):
                return False
        except (OSError, ValueError):
            return False
    return True


def find_session_binary(binary: str, env: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Resolves an executable strictly using the session's sanitized PATH."""
    environ = env or get_sanitized_env()
    path = environ.get("PATH", "")
    return shutil.which(binary, path=path)
