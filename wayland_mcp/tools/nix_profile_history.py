"""Bounded Nix default-profile history inventory and confirmed history actions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date
from typing import Literal

from wayland_mcp.models import (
    NixProfileGenerationInfo,
    NixProfileHistoryActionResponse,
    NixProfileHistoryListResponse,
)
from wayland_mcp.tools.application_package_control import detect_application_package_tools
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.nix_profile_control import _environment, _profile_elements

NixProfileHistoryAction = Literal["rollback", "wipe_history"]
NIX_PROFILE_HISTORY_ACTIONS = {"rollback", "wipe_history"}
VERSION_LINE_RE = re.compile(r"^Version ([0-9]{1,10}) \(([0-9]{4}-[0-9]{2}-[0-9]{2})\)(?: <- ([0-9]{1,10}))?:$")
ANSI_SGR_RE = re.compile(r"\x1b\[([0-9;]*)m")
VERSION_PREFIX_STYLE_RE = re.compile(r"^Version ((?:\x1b\[[0-9;]*m)*)([0-9]{1,10})")
WIPE_LINE_RE = re.compile(r"^(?:would remove|removing|would delete|deleting) profile version ([0-9]{1,10})$", re.IGNORECASE)
ROLLBACK_RESULT_RE = re.compile(r"^switching profile from version ([0-9]{1,10}) to ([0-9]{1,10})$", re.IGNORECASE)
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_HISTORY_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_HISTORY_VERSIONS = 10_000
MAX_HISTORY_PREVIEW_REMOVALS = 100
MAX_HISTORY_LIMIT = 500
HISTORY_TIMEOUT_SECONDS = 30
ACTION_TIMEOUT_SECONDS = 300
MIN_WIPE_AGE_DAYS = 30
MAX_WIPE_AGE_DAYS = 36_500


@dataclass(frozen=True, slots=True)
class NixProfileHistorySnapshot:
    action: NixProfileHistoryAction
    binary: str
    target_version: int
    older_than_days: int
    profile_fingerprint: str
    history_fingerprint: str
    home: str
    uid: int
    euid: int
    current_version: int
    records: tuple[NixProfileGenerationInfo, ...]
    affected_versions: tuple[int, ...]
    state_token: str


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _profile_snapshot(binary: str, env: dict[str, str]) -> tuple[str | None, str | None]:
    entries, error = _profile_elements(binary, env)
    if error or entries is None:
        return None, error or "The current user's default Nix profile could not be inspected."
    return _digest(entries), None


def _read_history(binary: str, env: dict[str, str]) -> tuple[tuple[NixProfileGenerationInfo, ...] | None, int | None, str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "profile", "history"],
        env,
        command_label="Nix default-profile history",
        timeout_seconds=HISTORY_TIMEOUT_SECONDS,
        max_output_bytes=MAX_HISTORY_OUTPUT_BYTES,
        cwd="/",
    )
    if output is None or error or truncated:
        return None, None, None, "The current user's default Nix profile history could not be inspected exactly."
    records: list[NixProfileGenerationInfo] = []
    seen: set[int] = set()
    changed_counts: list[int] = []
    current_version: int | None = None
    for raw_line in output.splitlines():
        line = raw_line.rstrip("\r")
        plain_line = ANSI_SGR_RE.sub("", line)
        if "\x1b" in plain_line:
            return None, None, None, "Nix returned an unsupported control sequence in profile-history output."
        match = VERSION_LINE_RE.fullmatch(plain_line)
        if match:
            if len(records) >= MAX_HISTORY_VERSIONS:
                return None, None, None, "The Nix profile history contains too many versions."
            version = int(match.group(1))
            previous_version = int(match.group(3)) if match.group(3) else None
            try:
                date.fromisoformat(match.group(2))
            except ValueError:
                return None, None, None, "The Nix profile history contains an invalid date."
            if version in seen or (records and version <= records[-1].version):
                return None, None, None, "The Nix profile history contains duplicate or unordered versions."
            if previous_version is not None and previous_version >= version:
                return None, None, None, "The Nix profile history contains an invalid parent-version reference."
            # Nix marks the selected generation with ANSI_GREEN in its header;
            # the other versions use ANSI_BOLD. Keep that explicit signal rather
            # than assuming the greatest generation number is active after a rollback.
            prefix_match = VERSION_PREFIX_STYLE_RE.match(line)
            if not prefix_match or int(prefix_match.group(2)) != version:
                return None, None, None, "Nix returned an unsupported profile-history version header."
            is_current = any(
                "32" in style.split(";")
                for style in ANSI_SGR_RE.findall(prefix_match.group(1))
            )
            if is_current:
                if current_version is not None:
                    return None, None, None, "Nix marked more than one profile-history version as current."
                current_version = version
            records.append(
                NixProfileGenerationInfo(
                    version=version,
                    date=match.group(2),
                    previous_version=previous_version,
                    changed_entry_count=0,
                    is_current=is_current,
                )
            )
            changed_counts.append(0)
            seen.add(version)
            continue
        if not line.strip():
            continue
        if plain_line.startswith("  ") and records:
            if plain_line.strip().casefold() == "no changes.":
                continue
            changed_counts[-1] += 1
            continue
        if plain_line.casefold().startswith("warning:"):
            continue
        return None, None, None, "Nix returned an unsupported profile-history format."
    if not records:
        return None, None, None, "Nix did not return any recognized default-profile history versions."
    if current_version is None:
        return None, None, None, "Nix did not identify the active profile generation; no history action can be confirmed safely."
    finalized = tuple(
        NixProfileGenerationInfo(
            version=record.version,
            date=record.date,
            previous_version=record.previous_version,
            changed_entry_count=changed_counts[index],
            is_current=record.is_current,
        )
        for index, record in enumerate(records)
    )
    return finalized, current_version, _digest(output), None


def _nix_binary() -> str | None:
    return detect_application_package_tools().get("nix")


def _capture_history_action(
    action: str,
    target_version: int,
    older_than_days: int,
) -> tuple[NixProfileHistorySnapshot | None, str | None]:
    if not isinstance(action, str) or action not in NIX_PROFILE_HISTORY_ACTIONS:
        return None, "Action must be rollback or wipe_history."
    if isinstance(target_version, bool) or not isinstance(target_version, int):
        return None, "target_version must be an integer."
    if isinstance(older_than_days, bool) or not isinstance(older_than_days, int):
        return None, "older_than_days must be an integer."
    binary = _nix_binary()
    if not binary:
        return None, "The optional nix command is unavailable."
    env = _environment()
    profile_fingerprint, error = _profile_snapshot(binary, env)
    if error or profile_fingerprint is None:
        return None, error or "The current user's default Nix profile could not be inspected."
    records, current_version, history_fingerprint, error = _read_history(binary, env)
    if error or records is None or history_fingerprint is None:
        return None, error or "The current user's default Nix profile history could not be inspected."
    if current_version is None:
        return None, "Nix did not identify the active profile generation; no history action can be confirmed safely."
    versions = {record.version for record in records}
    affected_versions: tuple[int, ...] = ()

    if action == "rollback":
        if target_version < 1 or target_version not in versions or target_version == current_version:
            return None, "rollback requires one existing, non-current version from the current user's default profile history."
        if older_than_days != 0:
            return None, "older_than_days must be zero for rollback."
    else:
        if target_version != 0:
            return None, "target_version must be zero for wipe_history."
        if not MIN_WIPE_AGE_DAYS <= older_than_days <= MAX_WIPE_AGE_DAYS:
            return None, f"older_than_days must be from {MIN_WIPE_AGE_DAYS} through {MAX_WIPE_AGE_DAYS}; recent rollback versions are protected."
        preview, error, truncated = run_bounded_command(
            [binary, "profile", "wipe-history", "--older-than", f"{older_than_days}d", "--dry-run"],
            env,
            command_label="Nix default-profile history cleanup preview",
            timeout_seconds=HISTORY_TIMEOUT_SECONDS,
            max_output_bytes=MAX_HISTORY_OUTPUT_BYTES,
            cwd="/",
        )
        if preview is None or error or truncated:
            return None, "The Nix default-profile history cleanup preview failed; no history was changed."
        removal_versions: list[int] = []
        for raw_line in preview.splitlines():
            line = ANSI_SGR_RE.sub("", raw_line).strip()
            if "\x1b" in line:
                return None, "Nix returned an unsupported control sequence in the history-cleanup preview; no history was changed."
            if not line or line.casefold().startswith("warning:"):
                continue
            match = WIPE_LINE_RE.fullmatch(line)
            if not match:
                return None, "Nix returned an unsupported history-cleanup preview; no history was changed."
            removal_versions.append(int(match.group(1)))
        if not removal_versions:
            return None, "The selected age would remove no non-current profile history versions."
        if len(removal_versions) > MAX_HISTORY_PREVIEW_REMOVALS:
            return None, f"The cleanup preview exceeds {MAX_HISTORY_PREVIEW_REMOVALS} versions; choose an older cutoff to keep the confirmation bounded."
        if len(removal_versions) != len(set(removal_versions)) or current_version in removal_versions or not set(removal_versions) <= versions:
            return None, "The cleanup preview did not match the current profile history; no history was changed."
        affected_versions = tuple(sorted(removal_versions))

    home = env.get("HOME", "")
    uid, euid = os.getuid(), os.geteuid()
    token_payload = {
        "action": action,
        "binary": binary,
        "target_version": target_version,
        "older_than_days": older_than_days,
        "profile_fingerprint": profile_fingerprint,
        "history_fingerprint": history_fingerprint,
        "home": home,
        "uid": uid,
        "euid": euid,
        "current_version": current_version,
        "affected_versions": affected_versions,
    }
    return NixProfileHistorySnapshot(
        action=action,  # type: ignore[arg-type]
        binary=binary,
        target_version=target_version,
        older_than_days=older_than_days,
        profile_fingerprint=profile_fingerprint,
        history_fingerprint=history_fingerprint,
        home=home,
        uid=uid,
        euid=euid,
        current_version=current_version,
        records=records,
        affected_versions=affected_versions,
        state_token=_digest(token_payload),
    ), None


def nix_profile_history_action_confirmation_details(
    action: str,
    target_version: int = 0,
    older_than_days: int = 0,
) -> NixProfileHistorySnapshot | str:
    if not sys.platform.startswith("linux"):
        return "Nix profile history operations are available only on Linux."
    snapshot, error = _capture_history_action(action, target_version, older_than_days)
    return snapshot if snapshot is not None else (error or "The exact Nix profile history action could not be inspected.")


def list_nix_profile_history(limit: int = 100) -> NixProfileHistoryListResponse:
    if not sys.platform.startswith("linux"):
        return NixProfileHistoryListResponse(success=False, message="Nix profile history is available only on Linux.")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_HISTORY_LIMIT:
        return NixProfileHistoryListResponse(success=False, limit=100, message=f"limit must be from 1 through {MAX_HISTORY_LIMIT}.")
    binary = _nix_binary()
    if not binary:
        return NixProfileHistoryListResponse(success=False, limit=limit, message="The optional nix command is unavailable.")
    records, current_version, _fingerprint, error = _read_history(binary, _environment())
    if error or records is None:
        return NixProfileHistoryListResponse(success=False, limit=limit, message=error or "The Nix default-profile history could not be inspected.")
    if current_version is None:
        return NixProfileHistoryListResponse(success=False, limit=limit, message="Nix did not identify the active profile generation.")
    selected_records = sorted(records, key=lambda record: record.version, reverse=True)[:limit]
    if current_version not in {record.version for record in selected_records}:
        current_record = next(record for record in records if record.version == current_version)
        selected_records[-1] = current_record
        selected_records.sort(key=lambda record: record.version, reverse=True)
    selected = tuple(selected_records)
    return NixProfileHistoryListResponse(
        success=True,
        current_version=current_version,
        total_versions=len(records),
        returned_versions=len(selected),
        generations=list(selected),
        limit=limit,
        truncated=len(records) > limit,
        message="Returns version IDs, dates, parent IDs, change counts, and the active-generation marker only; package names and source URLs from Nix history output are withheld.",
    )


def _action_response(
    action: NixProfileHistoryAction,
    *,
    success: bool,
    confirmed: bool,
    state_verified: bool = False,
    current_version: int | None = None,
    target_version: int | None = None,
    older_than_days: int | None = None,
    affected_versions: tuple[int, ...] = (),
    timed_out: bool = False,
    message: str,
) -> NixProfileHistoryActionResponse:
    return NixProfileHistoryActionResponse(
        success=success,
        action=action,
        current_version=current_version,
        target_version=target_version,
        older_than_days=older_than_days,
        affected_versions=list(affected_versions),
        state_verified=state_verified,
        timed_out=timed_out,
        user_confirmed=confirmed,
        message=message,
    )


def perform_nix_profile_history_action(
    action: str,
    target_version: int,
    older_than_days: int,
    expected_state_token: str,
    *,
    confirmed: bool = False,
) -> NixProfileHistoryActionResponse:
    valid_action = isinstance(action, str) and action in NIX_PROFILE_HISTORY_ACTIONS
    safe_action: NixProfileHistoryAction = action if valid_action else "rollback"
    safe_target = target_version if isinstance(target_version, int) and not isinstance(target_version, bool) else None
    safe_days = older_than_days if isinstance(older_than_days, int) and not isinstance(older_than_days, bool) else None
    if not valid_action:
        return _action_response(safe_action, success=False, confirmed=False, target_version=safe_target, older_than_days=safe_days, message="Unsupported Nix profile history action; no command was run.")
    if confirmed is not True:
        return _action_response(safe_action, success=False, confirmed=False, target_version=safe_target, older_than_days=safe_days, message="Explicit MCP client confirmation is required; no Nix history change was run.")
    if not isinstance(expected_state_token, str) or not TOKEN_RE.fullmatch(expected_state_token):
        return _action_response(safe_action, success=False, confirmed=True, target_version=safe_target, older_than_days=safe_days, message="A valid state token from the exact Nix history confirmation is required; no change was made.")
    target, error = _capture_history_action(action, target_version, older_than_days)
    if error or target is None:
        return _action_response(safe_action, success=False, confirmed=True, target_version=safe_target, older_than_days=safe_days, message=error or "The exact Nix history action could not be inspected.")
    if target.state_token != expected_state_token:
        return _action_response(safe_action, success=False, confirmed=True, current_version=target.current_version, target_version=target.target_version or None, older_than_days=target.older_than_days or None, affected_versions=target.affected_versions, message="The default Nix profile or history changed after confirmation; review and confirm again.")
    env = _environment()
    if env.get("HOME", "") != target.home or (os.getuid(), os.geteuid()) != (target.uid, target.euid):
        return _action_response(safe_action, success=False, confirmed=True, current_version=target.current_version, target_version=target.target_version or None, older_than_days=target.older_than_days or None, affected_versions=target.affected_versions, message="The current user's Nix profile context changed after confirmation; no command was run.")
    if action == "rollback":
        command = [target.binary, "profile", "rollback", "--to", str(target.target_version)]
    else:
        command = [target.binary, "profile", "wipe-history", "--older-than", f"{target.older_than_days}d"]
    output, run_error, truncated = run_bounded_command(
        command,
        env,
        command_label="Nix default-profile history action",
        timeout_seconds=ACTION_TIMEOUT_SECONDS,
        max_output_bytes=MAX_HISTORY_OUTPUT_BYTES,
        cwd="/",
        kill_process_group=True,
    )
    if output is None or run_error or truncated:
        timed_out = bool(run_error and "timed out after" in run_error)
        message = (
            "The Nix profile history action timed out and was asked to stop; profile state may be incomplete. Inspect it before retrying."
            if timed_out
            else "The Nix profile history action did not complete successfully; output was withheld. Inspect history before retrying."
        )
        return _action_response(safe_action, success=False, confirmed=True, current_version=target.current_version, target_version=target.target_version or None, older_than_days=target.older_than_days or None, affected_versions=target.affected_versions, timed_out=timed_out, message=message)

    post_profile, profile_error = _profile_snapshot(target.binary, env)
    post_records, post_current_version, _post_history_fingerprint, history_error = _read_history(target.binary, env)
    if profile_error or post_profile is None or history_error or post_records is None:
        return _action_response(safe_action, success=False, confirmed=True, current_version=target.current_version, target_version=target.target_version or None, older_than_days=target.older_than_days or None, affected_versions=target.affected_versions, message="The command completed, but the resulting Nix profile history could not be verified. Inspect it before retrying.")

    if action == "rollback":
        results = [
            match
            for line in output.splitlines()
            if (match := ROLLBACK_RESULT_RE.fullmatch(ANSI_SGR_RE.sub("", line).strip())) is not None
        ]
        verified = (
            len(results) == 1
            and int(results[0].group(1)) == target.current_version
            and int(results[0].group(2)) == target.target_version
            and sum(record.is_current for record in post_records) == 1
            and post_current_version == target.target_version
            and target.target_version in {record.version for record in post_records}
        )
        current_after = post_current_version
        success_message = f"The default Nix profile switched to version {target.target_version}; the selected generation was verified."
    else:
        before_versions = {record.version for record in target.records}
        after_versions = {record.version for record in post_records}
        expected_versions = before_versions - set(target.affected_versions)
        verified = (
            post_profile == target.profile_fingerprint
            and sum(record.is_current for record in post_records) == 1
            and post_current_version == target.current_version
            and after_versions == expected_versions
        )
        current_after = post_current_version
        success_message = "The selected non-current Nix history versions were removed; the current profile and remaining history were verified."
    if not verified:
        return _action_response(safe_action, success=False, confirmed=True, current_version=current_after, target_version=target.target_version or None, older_than_days=target.older_than_days or None, affected_versions=target.affected_versions, message="Nix exited successfully, but the requested exact history state could not be verified. Inspect the profile before retrying.")
    return _action_response(safe_action, success=True, confirmed=True, state_verified=True, current_version=current_after, target_version=target.target_version or None, older_than_days=target.older_than_days or None, affected_versions=target.affected_versions, message=success_message)
