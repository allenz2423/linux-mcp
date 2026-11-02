"""Confirmed package additions and exact-entry changes to the current user's default Nix profile."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import NixProfileActionResponse
from wayland_mcp.session import get_sanitized_env
from wayland_mcp.tools.application_packages import detect_application_package_tools
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.package_control import (
    PACKAGE_ACTION_TIMEOUT_SECONDS,
    _run_transaction_command,
)

NixProfileAction = Literal["install", "upgrade", "remove"]
NIX_PROFILE_ACTIONS = {"install", "upgrade", "remove"}
NIX_ENTRY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._@-]{0,255}$")
NIX_PACKAGE_ATTRIBUTE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*){0,15}$")
NIX_STATUS_TIMEOUT_SECONDS = 20
NIX_PROFILE_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_NIX_PROFILE_ENTRIES = 50_000
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class NixProfileEntrySnapshot:
    action: NixProfileAction
    entry_name: str
    binary: str
    attribute: str
    active: bool | None
    original_url: str
    locked_url: str
    profile_fingerprint: str
    home_fingerprint: str
    uid: int
    euid: int
    state_token: str
    profile_entries: dict[str, object]


def nix_profile_control_available(env: dict[str, str] | None = None) -> bool:
    return sys.platform.startswith("linux") and bool(
        detect_application_package_tools(env).get("nix")
    )


def _environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["TERM"] = "dumb"
    return env


def _home_fingerprint(env: dict[str, str]) -> str:
    home = env.get("HOME", "")
    return hashlib.sha256(home.encode("utf-8", errors="replace")).hexdigest()


def _profile_elements(binary: str, env: dict[str, str]) -> tuple[dict[str, object] | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "profile", "list", "--json"],
        env,
        command_label="Nix default-profile inventory",
        timeout_seconds=NIX_STATUS_TIMEOUT_SECONDS,
        max_output_bytes=NIX_PROFILE_OUTPUT_BYTES,
    )
    if output is None or error or truncated:
        return None, "The current user's default Nix profile could not be inspected exactly."
    try:
        payload = json.loads(
            output,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (json.JSONDecodeError, ValueError):
        return None, "The Nix profile returned malformed JSON."
    if not isinstance(payload, dict):
        return None, "The Nix profile returned an unsupported JSON structure."
    elements = payload.get("elements")
    if not isinstance(elements, dict) or len(elements) > MAX_NIX_PROFILE_ENTRIES:
        return None, "The Nix profile did not return a bounded elements map."
    if any(not isinstance(name, str) or not isinstance(value, dict) for name, value in elements.items()):
        return None, "The Nix profile contains an invalid entry record."
    return elements, None


def _matches_package_attribute(value: object, attribute: str) -> bool:
    if not isinstance(value, dict):
        return False
    attr_path = value.get("attrPath")
    return isinstance(attr_path, str) and (
        attr_path == attribute or attr_path.endswith("." + attribute)
    )


def _capture_snapshot(
    action: NixProfileAction,
    entry_name: str,
) -> tuple[NixProfileEntrySnapshot | None, str | None]:
    binary = detect_application_package_tools().get("nix")
    if not binary:
        return None, "The optional nix command is unavailable."
    env = _environment()
    elements, error = _profile_elements(binary, env)
    if error or elements is None:
        return None, error or "The current user's default profile could not be confirmed."
    if action == "install":
        if (
            not isinstance(entry_name, str)
            or len(entry_name) > 512
            or not NIX_PACKAGE_ATTRIBUTE_RE.fullmatch(entry_name)
        ):
            return None, "Install requires one simple nixpkgs attribute path, such as hello or python3Packages.requests."
        value = None
        active = None
        safe_attribute = entry_name
        original_url = ""
        locked_url = ""
    else:
        value = elements.get(entry_name)
        if not isinstance(value, dict):
            return None, "The exact Nix profile entry is not present in the current user's default profile."
        active_value = value.get("active")
        active = active_value if isinstance(active_value, bool) else None
        attribute = value.get("attrPath")
        original_url = value.get("originalUrl")
        locked_url = value.get("url")
        if isinstance(attribute, str) and (len(attribute) > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in attribute)):
            return None, "The exact Nix profile entry has an invalid attribute name."
        safe_attribute = attribute if isinstance(attribute, str) and attribute else entry_name
        if action == "upgrade" and (
            not isinstance(original_url, str)
            or not original_url
            or not isinstance(locked_url, str)
            or not locked_url
        ):
            return None, "The exact Nix profile entry does not include recognized flake source metadata for upgrade."
        original_url = original_url if isinstance(original_url, str) else ""
        locked_url = locked_url if isinstance(locked_url, str) else ""
        if any(len(item) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in item) for item in (original_url, locked_url)):
            return None, "The exact Nix profile entry has invalid or oversized source metadata."

    serialized_profile = json.dumps(elements, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    profile_fingerprint = hashlib.sha256(serialized_profile).hexdigest()
    home_fingerprint = _home_fingerprint(env)
    uid = os.getuid()
    euid = os.geteuid()
    token_payload = {
        "action": action,
        "entry_name": entry_name,
        "binary": binary,
        "profile_fingerprint": profile_fingerprint,
        "home_fingerprint": home_fingerprint,
        "uid": uid,
        "euid": euid,
    }
    state_token = hashlib.sha256(
        json.dumps(token_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return NixProfileEntrySnapshot(
        action=action,
        entry_name=entry_name,
        binary=binary,
        attribute=safe_attribute,
        active=active,
        original_url=original_url,
        locked_url=locked_url,
        profile_fingerprint=profile_fingerprint,
        home_fingerprint=home_fingerprint,
        uid=uid,
        euid=euid,
        state_token=state_token,
        profile_entries=elements,
    ), None


def nix_profile_action_confirmation_details(action: str, entry_name: str) -> NixProfileEntrySnapshot | str:
    if not sys.platform.startswith("linux"):
        return "Nix profile operations are available only on Linux."
    if not isinstance(action, str) or action not in NIX_PROFILE_ACTIONS:
        return "Action must be install, upgrade, or remove."
    if not isinstance(entry_name, str):
        return "The Nix profile selector must be text."
    if action == "install":
        if len(entry_name) > 512 or not NIX_PACKAGE_ATTRIBUTE_RE.fullmatch(entry_name):
            return "Install requires one simple nixpkgs attribute path, such as hello or python3Packages.requests."
    elif not NIX_ENTRY_NAME_RE.fullmatch(entry_name):
        return "Entry name must be one exact Nix profile name or numeric index."
    snapshot, error = _capture_snapshot(action, entry_name)
    if snapshot is None:
        return error or "The exact Nix profile entry could not be inspected."
    if action == "upgrade":
        if snapshot.active is not True:
            return "Only an active Nix profile entry can be upgraded."
        if snapshot.original_url == snapshot.locked_url:
            return "This entry uses a locked flake reference; Nix cannot upgrade it to a newer source revision."
    return snapshot


def _command_for_snapshot(snapshot: NixProfileEntrySnapshot) -> list[str]:
    if snapshot.action == "install":
        return [
            snapshot.binary,
            "profile",
            "install",
            f"nixpkgs#{snapshot.attribute}",
        ]
    return [
        snapshot.binary,
        "profile",
        snapshot.action,
        snapshot.entry_name,
    ]


def _response(
    action: NixProfileAction,
    entry_name: str,
    *,
    success: bool,
    confirmed: bool,
    state_verified: bool = False,
    return_code: int | None = None,
    timed_out: bool = False,
    message: str,
) -> NixProfileActionResponse:
    return NixProfileActionResponse(
        success=success,
        action=action,
        entry_name=entry_name,
        state_verified=state_verified,
        return_code=return_code,
        timed_out=timed_out,
        user_confirmed=confirmed,
        message=message,
    )


def perform_nix_profile_action(
    action: NixProfileAction,
    entry_name: str,
    expected_state_token: str,
    *,
    confirmed: bool = False,
) -> NixProfileActionResponse:
    valid_action = isinstance(action, str) and action in NIX_PROFILE_ACTIONS
    safe_action: NixProfileAction = action if valid_action else "remove"
    safe_name = entry_name[:512] if isinstance(entry_name, str) else ""
    if not valid_action:
        return _response(safe_action, safe_name, success=False, confirmed=False, message="Unsupported Nix profile action; no command was run.")
    if confirmed is not True:
        return _response(safe_action, safe_name, success=False, confirmed=False, message="Explicit MCP client confirmation is required; no Nix command was run.")

    target_or_error = nix_profile_action_confirmation_details(action, entry_name)
    target = target_or_error if isinstance(target_or_error, NixProfileEntrySnapshot) else None
    if target is None:
        return _response(safe_action, safe_name, success=False, confirmed=True, message=str(target_or_error))
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return _response(safe_action, safe_name, success=False, confirmed=True, message="A valid state token from the exact Nix profile confirmation is required; no change was made.")
    if target.state_token != expected_state_token:
        return _response(safe_action, safe_name, success=False, confirmed=True, message="The selected Nix profile or entry state changed after confirmation; review and confirm again.")

    command = _command_for_snapshot(target)
    env = _environment()
    if _home_fingerprint(env) != target.home_fingerprint or os.getuid() != target.uid or os.geteuid() != target.euid:
        return _response(safe_action, safe_name, success=False, confirmed=True, message="The current user's Nix profile context changed after confirmation; review and confirm again.")
    deadline = time.monotonic() + PACKAGE_ACTION_TIMEOUT_SECONDS
    return_code, timed_out, error = _run_transaction_command(command, env, deadline)
    if error:
        return _response(safe_action, safe_name, success=False, confirmed=True, message=f"{error} Nix output was withheld; inspect the default profile before retrying.")
    if timed_out:
        return _response(safe_action, safe_name, success=False, confirmed=True, timed_out=True, message=f"The Nix profile operation exceeded {PACKAGE_ACTION_TIMEOUT_SECONDS} seconds and was asked to stop. Profile state may be incomplete; inspect it before retrying.")
    if return_code != 0:
        return _response(safe_action, safe_name, success=False, confirmed=True, return_code=return_code, message=f"Nix exited with status {return_code}. Output was withheld; inspect profile state and Nix history.")

    post_elements, verify_error = _profile_elements(target.binary, env)
    if post_elements is None:
        return _response(safe_action, safe_name, success=False, confirmed=True, return_code=return_code, message=verify_error or "The Nix profile result could not be inspected.")
    post_value = post_elements.get(entry_name)
    if action == "install":
        old_names = set(target.profile_entries)
        new_names = set(post_elements)
        changed_existing = [
            name
            for name in old_names & new_names
            if post_elements[name] != target.profile_entries[name]
        ]
        added_names = new_names - old_names
        removed_names = old_names - new_names
        if not removed_names and not changed_existing and len(added_names) == 1:
            added_value = post_elements[next(iter(added_names))]
            verified = (
                len(post_elements) == len(target.profile_entries) + 1
                and isinstance(added_value, dict)
                and added_value.get("active") is True
                and _matches_package_attribute(added_value, target.attribute)
            )
        elif not removed_names and not added_names and len(changed_existing) == 1:
            changed_name = changed_existing[0]
            old_value = target.profile_entries[changed_name]
            new_value = post_elements[changed_name]
            verified = (
                isinstance(old_value, dict)
                and old_value.get("active") is not True
                and isinstance(new_value, dict)
                and new_value.get("active") is True
                and _matches_package_attribute(new_value, target.attribute)
            )
        else:
            verified = False
    elif action == "remove":
        verified = post_value is None
    else:
        verified = isinstance(post_value, dict) and post_value.get("active") is True
    if not verified:
        return _response(safe_action, safe_name, success=False, confirmed=True, return_code=return_code, message="Nix exited successfully but the requested exact profile-entry state did not verify; inspect the profile.")
    if action == "install":
        state = "installed"
        detail = " It was added to the current user's default profile using the configured nixpkgs flake registry reference."
    elif action == "remove":
        state = "removed"
        detail = " The profile entry was removed; Nix store data is not explicitly garbage-collected."
    else:
        state = "upgraded"
        detail = " The exact unlocked source entry remains active."
    return _response(safe_action, safe_name, success=True, confirmed=True, state_verified=True, return_code=return_code, message=f"The exact Nix profile entry was {state} and the result was verified.{detail}")
