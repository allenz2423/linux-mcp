"""Snapshot-bound compositor mutations."""

from __future__ import annotations

from wayland_mcp.backends.registry import detect_backend
from wayland_mcp.models import ActionResult
from wayland_mcp.safety.tokens import snapshot_token_manager
from wayland_mcp.session import logger


def _reject(action: str, target: str, error: str | None) -> ActionResult:
    return ActionResult(
        success=False,
        action=action,
        target=target,
        message=f"Action rejected: {error or 'invalid observation token'}",
        requires_reobservation=True,
    )


def _window_mutation(action: str, target: str, token_id: str, **args) -> ActionResult:
    valid, err, observed = snapshot_token_manager.validate_and_consume(
        token_id, operation=action, target=target, target_type="window",
    )
    if not valid or observed is None:
        return _reject(action, target, err)
    backend = detect_backend()
    operation = getattr(backend, action)
    return operation(observed.id, **args)


def focus_window(target: str, token_id: str) -> ActionResult:
    logger.debug("Executing focus_window")
    return _window_mutation("focus_window", target, token_id)


def close_window(target: str, token_id: str) -> ActionResult:
    logger.debug("Executing close_window")
    return _window_mutation("close_window", target, token_id)


def resize_window(target: str, width: int, height: int, token_id: str) -> ActionResult:
    logger.debug("Executing resize_window")
    return _window_mutation("resize_window", target, token_id, width=width, height=height)


def minimize_window(target: str, token_id: str) -> ActionResult:
    logger.debug("Executing minimize_window")
    return _window_mutation("minimize_window", target, token_id)


def maximize_window(target: str, token_id: str) -> ActionResult:
    logger.debug("Executing maximize_window")
    return _window_mutation("maximize_window", target, token_id)


def switch_workspace(workspace: str, token_id: str) -> ActionResult:
    logger.debug("Executing switch_workspace")
    valid, err, _ = snapshot_token_manager.validate_and_consume(
        token_id, operation="switch_workspace", target=workspace, target_type="workspace",
    )
    if not valid:
        return _reject("switch_workspace", workspace, err)
    return detect_backend().switch_workspace(workspace)


def move_window_to_workspace(target: str, workspace: str, token_id: str) -> ActionResult:
    logger.debug("Executing move_window_to_workspace")
    valid, err, observed = snapshot_token_manager.validate_and_consume(
        token_id,
        operation="move_window_to_workspace",
        target=target,
        target_type="window_and_workspace",
        secondary_target=workspace,
    )
    target_label = f"{target} -> {workspace}"
    if not valid or observed is None:
        return _reject("move_window_to_workspace", target_label, err)
    return detect_backend().move_window_to_workspace(observed.id, workspace)
