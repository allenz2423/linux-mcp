"""Freedesktop application discovery and exact-ID launch."""

from __future__ import annotations

import configparser
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import AppLaunchResult, AppListResponse, DesktopAppInfo
from wayland_mcp.safety.tokens import snapshot_token_manager
from wayland_mcp.session import find_session_binary, get_sanitized_env

MAX_DESKTOP_FILE_BYTES = 256 * 1024
APP_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,200}\.desktop$")
BROWSER_MARKERS = (
    "chromium", "chrome", "firefox", "microsoftedge", "bravebrowser",
    "vivaldi", "operabrowser", "zenbrowser", "torbrowser", "librewolf",
    "waterfox", "floorp", "falkon", "epiphany", "gnomeweb", "midori",
    "surf", "ladybird", "thorium", "mullvadbrowser", "qutebrowser",
)


@dataclass(frozen=True)
class _DesktopEntry:
    info: DesktopAppInfo
    path: Path


def _is_browser_entry(desktop_id: str, name: str, generic_name: str, categories: list[str]) -> bool:
    if any(category.casefold() == "webbrowser" for category in categories):
        return True
    identity = re.sub(r"[^a-z0-9]", "", f"{desktop_id} {name} {generic_name}".casefold())
    return any(marker in identity for marker in BROWSER_MARKERS)


def _application_roots(env: dict[str, str]) -> list[Path]:
    home = Path(env.get("HOME") or str(Path.home()))
    data_home = Path(env.get("XDG_DATA_HOME") or (home / ".local/share"))
    data_dirs = env.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share")
    roots = [data_home / "applications"]
    roots.extend(Path(item) / "applications" for item in data_dirs.split(":") if item)
    seen: set[str] = set()
    result: list[Path] = []
    for root in roots:
        key = str(root)
        if key not in seen:
            seen.add(key)
            result.append(root)
    return result


def _desktop_entries(env: dict[str, str]) -> dict[str, _DesktopEntry]:
    entries: dict[str, _DesktopEntry] = {}
    claimed_ids: set[str] = set()
    for root in _application_roots(env):
        try:
            real_root = root.resolve(strict=True)
        except OSError:
            continue
        for path in root.rglob("*.desktop"):
            try:
                real_path = path.resolve(strict=True)
                if not real_path.is_relative_to(real_root) or real_path.stat().st_size > MAX_DESKTOP_FILE_BYTES:
                    continue
                desktop_id = path.relative_to(root).as_posix().replace("/", "-")
                if not APP_ID_RE.fullmatch(desktop_id) or desktop_id in claimed_ids:
                    continue
                parser = configparser.ConfigParser(interpolation=None, strict=False)
                parser.optionxform = str
                with real_path.open("r", encoding="utf-8", errors="replace") as stream:
                    parser.read_file(stream)
                section = parser["Desktop Entry"] if parser.has_section("Desktop Entry") else None
                if section is None or section.get("Type", "Application") != "Application":
                    continue
                # A valid higher-priority Hidden/NoDisplay entry shadows a
                # system entry with the same desktop ID under the XDG lookup
                # rules, even though Adam should not return it to callers.
                claimed_ids.add(desktop_id)
                hidden = section.get("Hidden", "false").strip().lower() == "true"
                nodisplay = section.get("NoDisplay", "false").strip().lower() == "true"
                if hidden or nodisplay:
                    continue
                name = section.get("Name", "").strip()
                if not name:
                    continue
                categories = [item for item in section.get("Categories", "").split(";") if item][:32]
                generic_name = section.get("GenericName", "").strip()
                if _is_browser_entry(desktop_id, name, generic_name, categories):
                    continue
                info = DesktopAppInfo(
                    id=desktop_id,
                    name=name[:256],
                    generic_name=(generic_name or None),
                    comment=(section.get("Comment", "").strip() or None),
                    categories=categories,
                    icon=(section.get("Icon", "").strip() or None),
                    nodisplay=False,
                )
                entries[desktop_id] = _DesktopEntry(info=info, path=real_path)
            except (OSError, UnicodeError, configparser.Error, ValueError):
                continue
    return entries


def list_desktop_apps(query: str = "", limit: int = 100) -> AppListResponse:
    env = get_sanitized_env()
    if not isinstance(query, str) or len(query) > 256:
        return AppListResponse(success=False, total_apps=0, applications=[], message="Query must be at most 256 characters.")
    limit = max(1, min(int(limit), 250))
    entries = _desktop_entries(env)
    needle = query.casefold().strip()
    matches = [
        entry.info for entry in entries.values()
        if not needle or needle in " ".join((entry.info.name, entry.info.generic_name or "", entry.info.comment or "", entry.info.id)).casefold()
    ]
    matches.sort(key=lambda app: (app.name.casefold(), app.id.casefold()))
    visible = matches[:limit]
    token = snapshot_token_manager.create_token(
        scope="apps",
        allowed_operations={"launch_app"},
        observed_apps=[app.id for app in visible],
    )
    return AppListResponse(
        success=True,
        total_apps=len(matches),
        applications=visible,
        token_id=token.token_id,
        message=f"Found {len(matches)} application(s); returned {len(visible)}. Launch only an exact listed ID.",
    )


def launch_app(app_id: str, token_id: str) -> AppLaunchResult:
    if not isinstance(app_id, str) or not APP_ID_RE.fullmatch(app_id):
        return AppLaunchResult(success=False, app_id=str(app_id)[:200], message="Application ID is invalid.")
    valid, error, _ = snapshot_token_manager.validate_and_consume(
        token_id, operation="launch_app", target=app_id, target_type="app",
    )
    if not valid:
        return AppLaunchResult(success=False, app_id=app_id, message=f"Launch rejected: {error}")
    env = get_sanitized_env()
    entry = _desktop_entries(env).get(app_id)
    if entry is None:
        return AppLaunchResult(success=False, app_id=app_id, message="Application is no longer installed; list applications again.")

    gtk_launch = find_session_binary("gtk-launch", env)
    gio = find_session_binary("gio", env)
    if gtk_launch:
        command = [gtk_launch, app_id[:-len(".desktop")]]
    elif gio:
        command = [gio, "launch", str(entry.path)]
    else:
        return AppLaunchResult(success=False, app_id=app_id, message="gtk-launch and gio are unavailable.")
    try:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
        return AppLaunchResult(success=True, app_id=app_id, message=f"Launch requested for {entry.info.name}.")
    except OSError as exc:
        return AppLaunchResult(success=False, app_id=app_id, message=f"Could not launch application: {exc.strerror or type(exc).__name__}.")
