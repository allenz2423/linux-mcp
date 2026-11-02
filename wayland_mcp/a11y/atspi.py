"""Bounded AT-SPI2 inspection using the session bus and busctl."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple

from wayland_mcp.models import AccessibilityNode, AccessibilityTreeResponse
from wayland_mcp.session import logger, find_session_binary, get_sanitized_env, _is_local_atspi_address

MAX_TREE_NODES = 80
MAX_TREE_SECONDS = 4.0
MAX_CHILDREN = 8


@dataclass
class _Budget:
    deadline: float
    nodes: int = 0

    def timeout(self, ceiling: float = 0.7) -> float:
        return max(0.0, min(ceiling, self.deadline - time.monotonic()))

    @property
    def exhausted(self) -> bool:
        return self.nodes >= MAX_TREE_NODES or time.monotonic() >= self.deadline


def get_atspi_bus_address(env: Optional[Dict[str, str]] = None, budget: _Budget | None = None) -> Optional[str]:
    environ = env if env is not None else get_sanitized_env()
    addr = environ.get("AT_SPI_BUS_ADDRESS")
    if addr:
        return addr
    busctl = find_session_binary("busctl", environ)
    if not busctl:
        return None
    timeout = budget.timeout(1.0) if budget else 1.0
    if timeout > 0:
        try:
            res = subprocess.run(
                [busctl, "--user", "call", "org.a11y.Bus", "/org/a11y/bus", "org.a11y.Bus", "GetAddress"],
                capture_output=True, text=True, timeout=timeout, env=environ,
            )
            if res.returncode == 0 and res.stdout.strip():
                match = re.search(r'"([^"]+)"', res.stdout)
                if match and _is_local_atspi_address(match.group(1), environ):
                    return match.group(1)
        except Exception as exc:
            logger.debug("Failed to query AT-SPI bus address: %s", exc)
    runtime = environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    for name in ("bus_0", "bus_1"):
        candidate = os.path.join(runtime, "at-spi", name)
        try:
            if stat.S_ISSOCK(os.stat(candidate).st_mode):
                return f"unix:path={candidate}"
        except OSError:
            pass
    return None


def _query_property(busctl: str, addr: str, service: str, path: str, iface: str, prop: str,
                    env: dict, budget: _Budget) -> str:
    timeout = budget.timeout()
    if timeout <= 0:
        return ""
    try:
        res = subprocess.run(
            [busctl, f"--address={addr}", "get-property", service, path, iface, prop],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
        if res.returncode == 0 and res.stdout.strip():
            match = re.search(r'^[a-z]\s+"?(.*?)"?$', res.stdout.strip())
            if match:
                return match.group(1).strip('"')
            return res.stdout.strip()
    except Exception:
        pass
    return ""


def _query_children(busctl: str, addr: str, service: str, path: str, env: dict,
                    budget: _Budget) -> List[Tuple[str, str]]:
    timeout = budget.timeout()
    if timeout <= 0:
        return []
    try:
        res = subprocess.run(
            [busctl, f"--address={addr}", "call", service, path,
             "org.a11y.atspi.Accessible", "GetChildren"],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
        if res.returncode == 0 and res.stdout.strip():
            return re.findall(r'"(:[^"]+)"\s+"(/[^"]+)"', res.stdout)[:MAX_CHILDREN * 4]
    except Exception:
        pass
    return []


def _extract_node(busctl: str, addr: str, service: str, path: str, env: dict,
                  budget: _Budget, depth: int, max_depth: int) -> Optional[AccessibilityNode]:
    if budget.exhausted:
        return None
    budget.nodes += 1
    name = _query_property(busctl, addr, service, path, "org.a11y.atspi.Accessible", "Name", env, budget)
    description = _query_property(busctl, addr, service, path, "org.a11y.atspi.Accessible", "Description", env, budget)
    role = ""
    timeout = budget.timeout()
    if timeout > 0:
        try:
            res = subprocess.run(
                [busctl, f"--address={addr}", "call", service, path,
                 "org.a11y.atspi.Accessible", "GetRoleName"],
                capture_output=True, text=True, timeout=timeout, env=env,
            )
            if res.returncode == 0:
                match = re.search(r'"([^"]+)"', res.stdout)
                if match:
                    role = match.group(1)
        except Exception:
            pass
    raw_children = _query_children(busctl, addr, service, path, env, budget)
    children: list[AccessibilityNode] = []
    if depth < max_depth:
        for child_service, child_path in raw_children[:MAX_CHILDREN]:
            if budget.exhausted:
                break
            child = _extract_node(busctl, addr, child_service, child_path, env, budget, depth + 1, max_depth)
            if child is not None:
                children.append(child)
    return AccessibilityNode(
        name=name,
        role=role or "unknown",
        description=description or None,
        children_count=len(raw_children),
        children=children,
    )


def inspect_accessibility_tree(application: Optional[str] = None, max_depth: int = 2) -> AccessibilityTreeResponse:
    started = time.monotonic()
    budget = _Budget(deadline=started + MAX_TREE_SECONDS)
    env = get_sanitized_env()
    addr = get_atspi_bus_address(env, budget)
    busctl = find_session_binary("busctl", env)
    if not addr or not busctl:
        return AccessibilityTreeResponse(
            success=False, application=application, root=None,
            message="AT-SPI2 daemon, bus address, or busctl is unavailable.",
            time_elapsed_ms=round((time.monotonic() - started) * 1000, 1),
        )
    try:
        app_children = _query_children(
            busctl, addr, "org.a11y.atspi.Registry", "/org/a11y/atspi/accessible/root", env, budget,
        )
        target_service = "org.a11y.atspi.Registry"
        target_path = "/org/a11y/atspi/accessible/root"
        matched_name = application or "Desktop"
        available_apps: list[str] = []
        if application:
            app_norm = application.strip().casefold()
            found = False
            for service, path in app_children:
                if budget.exhausted:
                    break
                name = _query_property(busctl, addr, service, path,
                                       "org.a11y.atspi.Accessible", "Name", env, budget)
                if name:
                    available_apps.append(name)
                    if app_norm in name.casefold():
                        target_service, target_path, matched_name = service, path, name
                        found = True
                        break
            if not found:
                return AccessibilityTreeResponse(
                    success=False, application=application, root=None,
                    total_nodes_collected=budget.nodes,
                    time_elapsed_ms=round((time.monotonic() - started) * 1000, 1),
                    message=(f"Application '{application}' was not found. "
                             f"Bounded available app names: {available_apps[:20]}"),
                )
        root = _extract_node(
            busctl, addr, target_service, target_path, env, budget,
            depth=0, max_depth=max(0, min(int(max_depth), 3)),
        )
        elapsed = round((time.monotonic() - started) * 1000, 1)
        return AccessibilityTreeResponse(
            success=root is not None,
            application=matched_name,
            root=root,
            total_nodes_collected=budget.nodes,
            time_elapsed_ms=elapsed,
            token_id=None,
            message=(
                "Collected accessible names, roles, descriptions, and child counts."
                if root is not None and not budget.exhausted
                else "Collected a partial accessibility tree before the node or time budget ended."
            ),
        )
    except Exception as exc:
        logger.warning("AT-SPI tree query failed: %s", type(exc).__name__)
        return AccessibilityTreeResponse(
            success=False, application=application, root=None,
            total_nodes_collected=budget.nodes,
            time_elapsed_ms=round((time.monotonic() - started) * 1000, 1),
            message="AT-SPI2 query failed.",
        )
