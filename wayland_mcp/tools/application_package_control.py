"""Exact, explicitly confirmed Flatpak app and runtime transactions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import ApplicationPackageActionResponse
from wayland_mcp.session import get_sanitized_env
from wayland_mcp.tools.application_packages import (
    detect_application_package_tools,
    flatpak_named_installations,
)
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.package_control import (
    PACKAGE_ACTION_TIMEOUT_SECONDS,
    _run_transaction_command,
)

FlatpakPackageAction = Literal["install", "update", "remove"]
FLATPAK_ACTIONS = {"install", "update", "remove"}
FLATPAK_SCOPE_SWITCHES = {"system": "--system", "user": "--user"}
FLATPAK_INSTALLATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
FLATPAK_REF_RE = re.compile(
    r"^(app|runtime)/([A-Za-z0-9][A-Za-z0-9._+-]{0,255})/"
    r"([A-Za-z0-9][A-Za-z0-9._+-]{0,63})/([A-Za-z0-9][A-Za-z0-9._+-]{0,127})$"
)
FLATPAK_REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
FLATPAK_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{64}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
FLATPAK_STATUS_TIMEOUT_SECONDS = 15
FLATPAK_STATUS_OUTPUT_BYTES = 64 * 1024
FLATPAK_LIST_OUTPUT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class FlatpakPackageSnapshot:
    action: FlatpakPackageAction
    scope: Literal["system", "user"]
    installation: str
    installation_config_fingerprint: str
    ref: str
    remote: str
    binary: str
    installed_ref: str | None
    origin: str | None
    commit: str | None
    remote_fingerprint: str | None
    context_fingerprint: str
    state_token: str


def flatpak_package_control_available(env: dict[str, str] | None = None) -> bool:
    return sys.platform.startswith("linux") and bool(
        detect_application_package_tools(env).get("flatpak")
    )


def _environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["TERM"] = "dumb"
    return env


def _run_status(
    binary: str,
    arguments: list[str],
    env: dict[str, str],
    *,
    label: str,
    output_limit: int = FLATPAK_STATUS_OUTPUT_BYTES,
) -> tuple[str | None, str | None, bool]:
    return run_bounded_command(
        [binary, *arguments],
        env,
        command_label=label,
        timeout_seconds=FLATPAK_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=output_limit,
    )


def _single_field(
    binary: str,
    scope_switch: str,
    ref: str,
    flag: str,
    env: dict[str, str],
    *,
    allow_empty: bool = False,
) -> tuple[str | None, str | None]:
    output, error, truncated = _run_status(
        binary,
        [scope_switch, "info", flag, ref],
        env,
        label="Flatpak exact-ref metadata",
    )
    if output is None or error or truncated:
        return None, "The exact Flatpak ref metadata could not be verified."
    values = [line.strip() for line in output.splitlines() if line.strip()]
    if not values and allow_empty:
        return "", None
    if len(values) != 1 or any(ord(char) < 32 or ord(char) == 127 for char in values[0]):
        return None, "Flatpak returned an ambiguous exact-ref metadata value."
    return values[0], None


def _installed_ref(
    binary: str,
    scope_switch: str,
    ref: str,
    env: dict[str, str],
) -> tuple[str | None, str | None, str | None, str | None]:
    output, error, truncated = _run_status(
        binary,
        [scope_switch, "--columns=ref:full", "list"],
        env,
        label="Flatpak installed-ref inventory",
        output_limit=FLATPAK_LIST_OUTPUT_BYTES,
    )
    if output is None or error or truncated:
        return None, None, None, "The selected Flatpak installation could not be enumerated exactly."
    installed = any(line.strip() == ref for line in output.splitlines())
    if not installed:
        return None, None, None, None

    reported_ref, error = _single_field(binary, scope_switch, ref, "--show-ref", env)
    if error or reported_ref != ref:
        return None, None, None, error or "Flatpak did not return the requested full ref."
    origin, error = _single_field(
        binary,
        scope_switch,
        ref,
        "--show-origin",
        env,
        allow_empty=True,
    )
    if error:
        return None, None, None, error
    commit, error = _single_field(binary, scope_switch, ref, "--show-commit", env)
    if error or commit is None or not FLATPAK_COMMIT_RE.fullmatch(commit):
        return None, None, None, error or "Flatpak returned an unrecognized installed commit identifier."
    return reported_ref, origin or None, commit.lower(), None


def _remote_state(
    binary: str,
    scope_switch: str,
    target_remote: str,
    env: dict[str, str],
) -> tuple[set[str] | None, str | None, str | None]:
    names_output, error, truncated = _run_status(
        binary,
        [scope_switch, "remotes", "--columns=name"],
        env,
        label="Flatpak configured-remote inventory",
    )
    if names_output is None or error or truncated:
        return None, None, "The selected Flatpak remote configuration could not be inspected."
    names: set[str] = set()
    for line in names_output.splitlines():
        name = line.strip()
        if not name or name.casefold() == "name":
            continue
        if FLATPAK_REMOTE_RE.fullmatch(name):
            names.add(name)

    details_output, error, truncated = _run_status(
        binary,
        [scope_switch, "remotes", "--show-details"],
        env,
        label="Flatpak remote-configuration snapshot",
        output_limit=FLATPAK_LIST_OUTPUT_BYTES,
    )
    if details_output is None or error or truncated:
        return None, None, "The selected Flatpak remote configuration could not be bound to confirmation."
    fingerprint_source = f"{names_output}\0{details_output}".encode("utf-8", errors="replace")
    fingerprint = hashlib.sha256(fingerprint_source).hexdigest()
    if target_remote not in names:
        return names, fingerprint, "The exact Flatpak remote is not configured in the selected installation."
    return names, fingerprint, None


def _context_fingerprint(
    scope: str,
    installation: str,
    installation_config_fingerprint: str,
    env: dict[str, str],
) -> str:
    context = {
        "scope": scope,
        "installation": installation,
        "installation_config_fingerprint": installation_config_fingerprint,
        "home": env.get("HOME", "") if scope == "user" else "",
        "xdg_data_home": env.get("XDG_DATA_HOME", "") if scope == "user" else "",
    }
    serialized = json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _capture_snapshot(
    action: FlatpakPackageAction,
    scope: Literal["system", "user"],
    ref: str,
    remote: str,
    installation: str = "",
) -> tuple[FlatpakPackageSnapshot | None, str | None]:
    tools = detect_application_package_tools()
    binary = tools.get("flatpak")
    if not binary:
        return None, "The optional flatpak command is unavailable."
    env = _environment()
    installation_config_fingerprint = ""
    if installation:
        named_installations, installation_error = flatpak_named_installations()
        if installation_error:
            return None, installation_error
        configured = named_installations.get(installation)
        if configured is None:
            return None, "The exact named Flatpak installation is not configured in the system installation list."
        _installation_path, installation_config_fingerprint = configured
        scope_switch = f"--installation={installation}"
    else:
        scope_switch = FLATPAK_SCOPE_SWITCHES[scope]
    installed_ref, origin, commit, error = _installed_ref(binary, scope_switch, ref, env)
    if error:
        return None, error

    remote_to_check = remote if action == "install" else origin if action == "update" else ""
    remote_fingerprint: str | None = None
    if remote_to_check:
        remotes, remote_fingerprint, remote_error = _remote_state(
            binary,
            scope_switch,
            remote_to_check,
            env,
        )
        if remote_error:
            return None, remote_error
        if remotes is None:
            return None, "The selected Flatpak remote state could not be confirmed."
    elif action == "update" and installed_ref:
        return None, "The installed Flatpak ref has no configured remote origin to update from."

    context_fingerprint = _context_fingerprint(scope, installation, installation_config_fingerprint, env)
    payload = {
        "action": action,
        "scope": scope,
        "installation": installation,
        "installation_config_fingerprint": installation_config_fingerprint,
        "ref": ref,
        "remote": remote,
        "binary": binary,
        "installed_ref": installed_ref,
        "origin": origin,
        "commit": commit,
        "remote_fingerprint": remote_fingerprint,
        "context_fingerprint": context_fingerprint,
    }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return FlatpakPackageSnapshot(
        action=action,
        scope=scope,
        installation=installation,
        installation_config_fingerprint=installation_config_fingerprint,
        ref=ref,
        remote=remote,
        binary=binary,
        installed_ref=installed_ref,
        origin=origin,
        commit=commit,
        remote_fingerprint=remote_fingerprint,
        context_fingerprint=context_fingerprint,
        state_token=hashlib.sha256(encoded).hexdigest(),
    ), None


def flatpak_action_confirmation_details(
    action: str,
    scope: str,
    ref: str,
    remote: str = "",
    installation: str = "",
) -> FlatpakPackageSnapshot | str:
    if not sys.platform.startswith("linux"):
        return "Flatpak package operations are available only on Linux."
    if not isinstance(action, str) or action not in FLATPAK_ACTIONS:
        return "Action must be install, update, or remove."
    if not isinstance(scope, str) or scope not in FLATPAK_SCOPE_SWITCHES:
        return "Scope must be system or user."
    if not isinstance(installation, str) or (installation and (scope != "system" or not FLATPAK_INSTALLATION_RE.fullmatch(installation) or installation == "default")):
        return "installation must be empty for the default/user scope or an exact configured named system-installation ID."
    if not isinstance(ref, str) or not FLATPAK_REF_RE.fullmatch(ref):
        return "Ref must be one exact full Flatpak app/runtime ref: type/ID/architecture/branch."
    if not isinstance(remote, str):
        return "Remote must be text."
    if action == "install":
        if not FLATPAK_REMOTE_RE.fullmatch(remote):
            return "Install requires one exact configured Flatpak remote name."
    elif remote:
        return "Remote must be empty for update or remove; those actions use the installed ref's exact origin."

    snapshot, error = _capture_snapshot(action, scope, ref, remote, installation)
    if snapshot is None:
        return error or "The exact Flatpak package state could not be inspected."
    if action == "install" and snapshot.installed_ref is not None:
        return "The exact Flatpak ref is already installed in the selected scope; no install was prepared."
    if action in {"update", "remove"} and snapshot.installed_ref is None:
        return "The exact full Flatpak ref is not installed in the selected scope."
    if action == "update" and not snapshot.origin:
        return "The installed Flatpak ref has no configured remote origin to update from."
    return snapshot


def _command_for_snapshot(snapshot: FlatpakPackageSnapshot) -> list[str]:
    selector = f"--installation={snapshot.installation}" if snapshot.installation else FLATPAK_SCOPE_SWITCHES[snapshot.scope]
    command = [snapshot.binary, selector]
    if snapshot.action == "install":
        return command + [
            "install",
            "--assumeyes",
            "--noninteractive",
            "--no-related",
            snapshot.remote,
            snapshot.ref,
        ]
    if snapshot.action == "update":
        return command + [
            "update",
            "--assumeyes",
            "--noninteractive",
            "--no-related",
            "--no-deps",
            snapshot.ref,
        ]
    return command + [
        "uninstall",
        "--assumeyes",
        "--noninteractive",
        "--no-related",
        snapshot.ref,
    ]


def _response(
    action: FlatpakPackageAction,
    scope: Literal["system", "user"],
    ref: str,
    remote: str,
    installation: str,
    *,
    success: bool,
    confirmed: bool,
    state_verified: bool = False,
    return_code: int | None = None,
    timed_out: bool = False,
    message: str,
) -> ApplicationPackageActionResponse:
    return ApplicationPackageActionResponse(
        success=success,
        action=action,
        scope=scope,
        ref=ref,
        installation=installation or None,
        remote=remote or None,
        state_verified=state_verified,
        return_code=return_code,
        timed_out=timed_out,
        user_confirmed=confirmed,
        message=message,
    )


def perform_flatpak_package_action(
    action: FlatpakPackageAction,
    scope: Literal["system", "user"],
    ref: str,
    remote: str,
    expected_state_token: str,
    installation: str = "",
    *,
    confirmed: bool = False,
) -> ApplicationPackageActionResponse:
    valid_action = isinstance(action, str) and action in FLATPAK_ACTIONS
    valid_scope = isinstance(scope, str) and scope in FLATPAK_SCOPE_SWITCHES
    safe_action: FlatpakPackageAction = action if valid_action else "install"
    safe_scope: Literal["system", "user"] = scope if valid_scope else "system"
    safe_installation = installation[:128] if isinstance(installation, str) else ""
    safe_ref = ref[:300] if isinstance(ref, str) else ""
    safe_remote = remote[:128] if isinstance(remote, str) else ""
    if not valid_action:
        return _response(safe_action, safe_scope, safe_ref, safe_remote, safe_installation, success=False, confirmed=False, message="Unsupported Flatpak package action; no command was run.")
    if not valid_scope:
        return _response(safe_action, safe_scope, safe_ref, safe_remote, safe_installation, success=False, confirmed=False, message="Unsupported Flatpak installation scope; no command was run.")
    if confirmed is not True:
        return _response(safe_action, safe_scope, safe_ref, safe_remote, safe_installation, success=False, confirmed=False, message="Explicit MCP client confirmation is required; no Flatpak command was run.")

    target_or_error = flatpak_action_confirmation_details(action, scope, ref, remote, installation)
    target = target_or_error if isinstance(target_or_error, FlatpakPackageSnapshot) else None
    if target is None:
        return _response(safe_action, safe_scope, safe_ref, safe_remote, safe_installation, success=False, confirmed=True, message=str(target_or_error))
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return _response(safe_action, safe_scope, safe_ref, safe_remote, safe_installation, success=False, confirmed=True, message="A valid state token from the exact Flatpak confirmation is required; no change was made.")
    if target.state_token != expected_state_token:
        return _response(safe_action, safe_scope, safe_ref, safe_remote, safe_installation, success=False, confirmed=True, message="The selected Flatpak ref, installation scope, or remote configuration changed after confirmation; review and confirm again.")

    env = _environment()
    if _context_fingerprint(scope, installation, target.installation_config_fingerprint, env) != target.context_fingerprint:
        return _response(safe_action, safe_scope, safe_ref, safe_remote, safe_installation, success=False, confirmed=True, message="The selected Flatpak installation context changed after confirmation; review and confirm again.")
    command = _command_for_snapshot(target)
    deadline = time.monotonic() + PACKAGE_ACTION_TIMEOUT_SECONDS
    return_code, timed_out, error = _run_transaction_command(command, env, deadline)
    if error:
        return _response(safe_action, safe_scope, safe_ref, target.remote or target.origin or "", safe_installation, success=False, confirmed=True, message=f"{error} Flatpak output was withheld; inspect package state before retrying.")
    if timed_out:
        return _response(safe_action, safe_scope, safe_ref, target.remote or target.origin or "", safe_installation, success=False, confirmed=True, timed_out=True, message=f"The Flatpak operation exceeded {PACKAGE_ACTION_TIMEOUT_SECONDS} seconds and was asked to stop. Package state may be incomplete; inspect it before retrying.")
    if return_code != 0:
        return _response(safe_action, safe_scope, safe_ref, target.remote or target.origin or "", safe_installation, success=False, confirmed=True, return_code=return_code, message=f"Flatpak exited with status {return_code}. Output was withheld; inspect Flatpak history and current package state.")

    post_snapshot, verify_error = _capture_snapshot(action, scope, ref, remote, installation)
    if post_snapshot is None:
        return _response(safe_action, safe_scope, safe_ref, target.remote or target.origin or "", safe_installation, success=False, confirmed=True, return_code=return_code, message=verify_error or "The Flatpak result could not be verified; inspect package state before retrying.")
    same_context = (
        post_snapshot.binary == target.binary
        and post_snapshot.installation == target.installation
        and post_snapshot.installation_config_fingerprint == target.installation_config_fingerprint
        and post_snapshot.context_fingerprint == target.context_fingerprint
        and post_snapshot.remote_fingerprint == target.remote_fingerprint
    )
    if action == "install":
        verified = post_snapshot.installed_ref == ref and post_snapshot.origin == remote
    elif action == "update":
        verified = post_snapshot.installed_ref == ref and post_snapshot.origin == target.origin
    else:
        verified = post_snapshot.installed_ref is None
    verified = verified and same_context
    if not verified:
        return _response(
            safe_action,
            safe_scope,
            safe_ref,
            target.remote or target.origin or "",
            safe_installation,
            success=False,
            confirmed=True,
            state_verified=False,
            return_code=return_code,
            message="Flatpak exited successfully but the requested exact-ref state or its installation context did not verify; inspect package state before retrying.",
        )
    state = "installed" if action == "install" else "updated" if action == "update" else "removed"
    detail = "Related extensions were excluded."
    if action == "remove":
        detail += " Application data was not requested for deletion."
    return _response(
        safe_action,
        safe_scope,
        safe_ref,
        target.remote or target.origin or "",
        safe_installation,
        success=True,
        confirmed=True,
        state_verified=True,
        return_code=return_code,
        message=f"The exact Flatpak ref was {state} in the selected {scope} installation and the result was verified. {detail}",
    )
