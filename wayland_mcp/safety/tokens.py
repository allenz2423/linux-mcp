"""Short-lived, single-use authorization for desktop mutations.

Tokens are deliberately process-local and are never persisted. They bind one
observation to one exact operation and exact target identifiers. A failed
mutation attempt consumes an otherwise valid token as well.
"""

from __future__ import annotations

import os
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

SERVER_INSTANCE_ID = uuid.uuid4().hex
DEFAULT_TTL_SECONDS = 15.0
SAFE_WORKSPACE_REGEX = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


@dataclass(frozen=True)
class ObservedWindow:
    id: str
    app_id: str = ""
    title: str = ""
    workspace_id: str | None = None
    geometry: dict[str, int] | None = None
    is_focused: bool = False


@dataclass
class SnapshotToken:
    token_id: str
    observation_id: str
    server_instance_id: str
    server_pid: int
    scope: str
    created_monotonic: float
    ttl_seconds: float
    allowed_operations: frozenset[str]
    observed_windows: dict[str, ObservedWindow] = field(default_factory=dict)
    observed_workspaces: frozenset[str] = frozenset()
    observed_apps: frozenset[str] = frozenset()
    observed_geometry: dict[str, int] | None = None
    consumed: bool = False

    @property
    def is_expired(self) -> bool:
        return time.monotonic() >= self.created_monotonic + self.ttl_seconds


class TokenManager:
    """Thread-safe one-shot observation tokens used by MCP tool handlers."""

    def __init__(self, default_ttl: float = DEFAULT_TTL_SECONDS) -> None:
        self.default_ttl = max(1.0, min(float(default_ttl), 60.0))
        self._tokens: dict[str, SnapshotToken] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _get(value: Any, key: str, default: Any = None) -> Any:
        if isinstance(value, dict):
            return value.get(key, default)
        return getattr(value, key, default)

    @classmethod
    def _window_snapshot(cls, window: Any) -> ObservedWindow | None:
        window_id = cls._get(window, "id")
        if window_id is None or not str(window_id):
            return None
        geometry = cls._get(window, "geometry")
        if hasattr(geometry, "model_dump"):
            geometry = geometry.model_dump()
        if not isinstance(geometry, dict):
            geometry = None
        elif not all(isinstance(geometry.get(k), int) for k in ("x", "y", "width", "height")):
            geometry = None
        else:
            geometry = {k: int(geometry[k]) for k in ("x", "y", "width", "height")}
        return ObservedWindow(
            id=str(window_id),
            app_id=str(cls._get(window, "app_id", "") or ""),
            title=str(cls._get(window, "title", "") or ""),
            workspace_id=(
                str(cls._get(window, "workspace_id"))
                if cls._get(window, "workspace_id") is not None
                else None
            ),
            geometry=geometry,
            is_focused=bool(cls._get(window, "is_focused", False)),
        )

    def create_token(
        self,
        scope: str,
        allowed_operations: Iterable[str] | None = None,
        observed_windows: Iterable[Any] | None = None,
        observed_workspaces: Iterable[str] | None = None,
        observed_apps: Iterable[str] | None = None,
        observed_geometry: dict[str, int] | None = None,
        ttl: float | None = None,
    ) -> SnapshotToken:
        now = time.monotonic()
        ttl_seconds = self.default_ttl if ttl is None else max(1.0, min(float(ttl), 60.0))
        windows = {
            snap.id: snap
            for item in (observed_windows or ())
            if (snap := self._window_snapshot(item)) is not None
        }
        workspaces = frozenset(str(value) for value in (observed_workspaces or ()) if str(value))
        operations = frozenset(str(op) for op in (allowed_operations or ()) if str(op))
        token = SnapshotToken(
            token_id=secrets.token_urlsafe(24),
            observation_id=f"obs_{secrets.token_hex(12)}",
            server_instance_id=SERVER_INSTANCE_ID,
            server_pid=os.getpid(),
            scope=str(scope),
            created_monotonic=now,
            ttl_seconds=ttl_seconds,
            allowed_operations=operations,
            observed_windows=windows,
            observed_workspaces=workspaces,
            observed_apps=frozenset(str(value) for value in (observed_apps or ()) if str(value)),
            observed_geometry=(dict(observed_geometry) if observed_geometry else None),
        )
        with self._lock:
            self._purge_locked(now)
            self._tokens[token.token_id] = token
        return token

    def validate_and_consume(
        self,
        token_id: str | None,
        *,
        operation: str,
        target: str | None = None,
        target_type: str = "window",
        secondary_target: str | None = None,
    ) -> tuple[bool, str | None, ObservedWindow | None]:
        if not isinstance(token_id, str) or not token_id.strip():
            return False, "A fresh observation token is required.", None

        with self._lock:
            token = self._tokens.get(token_id.strip())
            if token is None:
                return False, "Observation token is unknown or expired; observe again.", None
            if token.consumed:
                return False, "Observation token was already used; observe again.", None
            if token.is_expired:
                token.consumed = True
                return False, "Observation token expired; observe again.", None

            # Burn first so wrong-target and wrong-operation attempts cannot
            # probe or reuse the same observation.
            token.consumed = True
            if token.server_instance_id != SERVER_INSTANCE_ID or token.server_pid != os.getpid():
                return False, "Observation token belongs to another server process.", None
            if operation not in token.allowed_operations:
                return False, f"This observation does not authorize {operation}.", None

            if target_type == "window":
                if not isinstance(target, str) or not target.strip():
                    return False, "An exact observed window ID is required.", None
                window = token.observed_windows.get(target.strip())
                if window is None:
                    return False, "That exact window ID was not in this observation; observe again.", None
                if operation == "move_window_to_workspace":
                    if secondary_target not in token.observed_workspaces:
                        return False, "The exact destination workspace was not in this observation; observe again.", None
                return True, None, window

            if target_type == "workspace":
                if not isinstance(target, str) or target not in token.observed_workspaces:
                    return False, "That exact workspace ID was not in this observation; observe again.", None
                if operation == "move_window_to_workspace":
                    if secondary_target not in token.observed_windows:
                        return False, "The exact window ID was not in this observation; observe again.", None
                return True, None, None

            if target_type == "desktop":
                if target != "desktop" or token.observed_geometry is None:
                    return False, "This observation is not bound to desktop coordinates.", None
                return True, None, None

            if target_type == "clipboard":
                if target != "clipboard" or token.scope not in {"desktop", "system"}:
                    return False, "This observation does not authorize clipboard access.", None
                return True, None, None

            if target_type == "notification":
                if target != "notification" or token.scope not in {"desktop", "system"}:
                    return False, "This observation does not authorize notifications.", None
                return True, None, None

            if target_type == "app":
                if not isinstance(target, str) or target not in token.observed_apps:
                    return False, "The application ID was not in this observation.", None
                return True, None, None

            if target_type == "window_and_workspace":
                window = token.observed_windows.get(str(target or ""))
                if window is None:
                    return False, "That exact window ID was not in this observation; observe again.", None
                if secondary_target not in token.observed_workspaces:
                    return False, "The exact destination workspace was not in this observation; observe again.", None
                return True, None, window

            return False, f"Unsupported authorization target type: {target_type}.", None

    def _purge_locked(self, now: float) -> None:
        stale = [
            token_id
            for token_id, token in self._tokens.items()
            if token.consumed or now >= token.created_monotonic + token.ttl_seconds
        ]
        for token_id in stale:
            self._tokens.pop(token_id, None)


snapshot_token_manager = TokenManager()
