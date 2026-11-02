"""Exact, confirmed firewalld ICMP block-list changes for one zone."""

from __future__ import annotations

import hashlib
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import FirewalldICMPBlockActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

FirewalldICMPBlockAction = Literal["add_block", "remove_block"]
FirewalldConfiguration = Literal["runtime", "permanent"]
ZONE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ICMP_TYPE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,100}$")
TOKEN_TTL_SECONDS = 180
MAX_PENDING_TOKENS = 1_024
COMMAND_TIMEOUT_SECONDS = 5
MAX_COMMAND_OUTPUT_BYTES = 128 * 1024
MAX_ZONES = 256
MAX_ZONE_LINE_LENGTH = 2_048
MAX_ICMP_TYPES = 512
MAX_ICMP_BLOCKS = 512
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _ICMPBlockSnapshot:
    configuration: str
    zone: str
    zone_active: bool | None
    icmp_type: str
    icmp_type_digest: str
    inversion_enabled: bool
    matching_count: int


@dataclass(slots=True)
class _ICMPBlockToken:
    action: str
    configuration: str
    zone: str
    zone_active: bool | None
    icmp_type: str
    icmp_type_digest: str
    inversion_enabled: bool
    matching_count: int
    expires_at: float
    claimed: bool = False


@dataclass(frozen=True, slots=True)
class FirewalldICMPBlockActionTarget:
    action: str
    configuration: str
    zone: str
    zone_active: bool | None
    icmp_type: str
    inversion_enabled: bool
    matching_count: int
    confirmation_token: str


_TOKENS: dict[str, _ICMPBlockToken] = {}


def _normalize_request(
    action: object,
    configuration: object,
    zone: object,
    icmp_type: object,
) -> str | None:
    if not isinstance(action, str) or action not in {"add_block", "remove_block"}:
        return "Choose add_block or remove_block."
    if not isinstance(configuration, str) or configuration not in {"runtime", "permanent"}:
        return "Choose runtime or permanent configuration."
    if not isinstance(zone, str) or not ZONE_NAME_RE.fullmatch(zone):
        return "Use one exact existing firewalld zone name from the frontend inventory."
    if not isinstance(icmp_type, str) or not ICMP_TYPE_RE.fullmatch(icmp_type):
        return "Use one exact ICMP type name from firewall-cmd --get-icmptypes."
    return None


def _command(
    binary: str,
    arguments: list[str],
    env: dict[str, str],
    *,
    label: str,
    accept_nonzero_exit: bool = False,
) -> tuple[str | None, str | None, bool]:
    return run_bounded_command(
        [binary, *arguments],
        env,
        command_label=label,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
        accept_nonzero_exit=accept_nonzero_exit,
    )


def _read_zone_names(
    binary: str,
    env: dict[str, str],
    configuration: str,
) -> tuple[set[str] | None, str | None]:
    arguments = ["--get-zones"]
    if configuration == "permanent":
        arguments.insert(0, "--permanent")
    output, error, truncated = _command(
        binary, arguments, env, label=f"firewalld {configuration} zone inventory"
    )
    if error or output is None or truncated:
        return None, "Firewalld zones could not be read completely."
    values = output.split()
    if len(values) > MAX_ZONES or any(not ZONE_NAME_RE.fullmatch(value) for value in values):
        return None, "Firewalld returned an invalid or oversized zone inventory."
    return set(values), None


def _read_active_zones(
    binary: str,
    env: dict[str, str],
) -> tuple[set[str] | None, str | None]:
    output, error, truncated = _command(
        binary, ["--get-active-zones"], env, label="firewalld active-zone inventory"
    )
    if error or output is None or truncated:
        return None, "Firewalld active zones could not be read."
    lines = output.splitlines()
    if len(lines) > MAX_ZONES * 16:
        return None, "Firewalld returned an oversized active-zone inventory."
    active: set[str] = set()
    for line in lines:
        if len(line) > MAX_ZONE_LINE_LENGTH:
            return None, "Firewalld returned an oversized active-zone record."
        if not line or line[0].isspace():
            continue
        name = line.strip().removesuffix(":")
        if not ZONE_NAME_RE.fullmatch(name):
            return None, "Firewalld returned an invalid active-zone name."
        active.add(name)
        if len(active) > MAX_ZONES:
            return None, "Firewalld returned too many active zones."
    return active, None


def _read_icmp_type(
    binary: str,
    env: dict[str, str],
    configuration: str,
    icmp_type: str,
) -> tuple[str | None, str | None]:
    arguments = [f"--info-icmptype={icmp_type}"]
    if configuration == "permanent":
        arguments.insert(0, "--permanent")
    output, error, truncated = _command(
        binary,
        arguments,
        env,
        label=f"firewalld {configuration} ICMP type definition",
    )
    if error or output is None or truncated or not output.strip():
        return None, "The exact firewalld ICMP type definition could not be read completely."
    if len(output.splitlines()) > 128 or any(len(line) > MAX_ZONE_LINE_LENGTH for line in output.splitlines()):
        return None, "Firewalld returned an oversized ICMP type definition."
    return hashlib.sha256(output.encode("utf-8", errors="replace")).hexdigest(), None


def _read_icmp_type_names(
    binary: str,
    env: dict[str, str],
    configuration: str,
) -> tuple[set[str] | None, str | None]:
    arguments = ["--get-icmptypes"]
    if configuration == "permanent":
        arguments.insert(0, "--permanent")
    output, error, truncated = _command(
        binary,
        arguments,
        env,
        label=f"firewalld {configuration} ICMP type inventory",
    )
    if error or output is None or truncated:
        return None, "Firewalld ICMP types could not be read completely."
    values = output.split()
    if len(values) > MAX_ICMP_TYPES or any(not ICMP_TYPE_RE.fullmatch(value) for value in values):
        return None, "Firewalld returned an invalid or oversized ICMP type inventory."
    return set(values), None


def _read_inversion_state(
    binary: str,
    env: dict[str, str],
    configuration: str,
    zone: str,
) -> tuple[bool | None, str | None]:
    arguments = [f"--zone={zone}", "--list-all"]
    if configuration == "permanent":
        arguments.insert(0, "--permanent")
    output, error, truncated = _command(
        binary,
        arguments,
        env,
        label=f"firewalld {configuration} zone ICMP inversion inventory",
    )
    if error or output is None or truncated:
        return None, "The zone's ICMP block-inversion state could not be read."
    if len(output.splitlines()) > 128 or any(len(line) > MAX_ZONE_LINE_LENGTH for line in output.splitlines()):
        return None, "Firewalld returned an oversized zone inventory."
    values: list[str] = []
    for line in output.splitlines():
        key, separator, value = line.strip().partition(":")
        if separator and key == "icmp-block-inversion":
            values.append(value.strip().casefold())
    if len(values) != 1 or values[0] not in {"yes", "no"}:
        return None, "Firewalld returned an invalid or ambiguous ICMP block-inversion state."
    enabled = values[0] == "yes"
    if enabled:
        return True, "ICMP block inversion is enabled for this zone; the tool refuses to change ICMP blocks because inversion changes their meaning."
    return False, None


def _read_snapshot(
    configuration: str,
    zone: str,
    icmp_type: str,
    binary: str,
    env: dict[str, str],
) -> tuple[_ICMPBlockSnapshot | None, str | None]:
    state, error, truncated = _command(
        binary,
        ["--state"],
        env,
        label="firewalld daemon state query",
        accept_nonzero_exit=True,
    )
    if error or state is None or truncated or state.strip().casefold() != "running":
        return None, "Firewalld is not running or its state could not be verified."
    zones, error = _read_zone_names(binary, env, configuration)
    if error or zones is None:
        return None, error or "The selected firewalld configuration could not be read."
    if zone not in zones:
        return None, "The exact zone is not present in the selected firewalld configuration."

    zone_active: bool | None = None
    if configuration == "runtime":
        active_zones, error = _read_active_zones(binary, env)
        if error or active_zones is None:
            return None, error or "Firewalld active zones could not be read."
        zone_active = zone in active_zones
        if not zone_active:
            return None, "Runtime ICMP block changes require an exact zone currently bound to an interface or source."

    types, error = _read_icmp_type_names(binary, env, configuration)
    if error or types is None:
        return None, error or "Firewalld ICMP types could not be read."
    if icmp_type not in types:
        return None, "The exact ICMP type is not available in the selected firewalld configuration."
    type_digest, error = _read_icmp_type(binary, env, configuration, icmp_type)
    if error or type_digest is None:
        return None, error or "The exact ICMP type definition could not be verified."

    arguments = [f"--zone={zone}", "--list-icmp-blocks"]
    if configuration == "permanent":
        arguments.insert(0, "--permanent")
    output, error, truncated = _command(
        binary,
        arguments,
        env,
        label=f"firewalld {configuration} zone ICMP block inventory",
    )
    if error or output is None or truncated:
        return None, "The firewalld ICMP block list could not be read completely."
    entries = output.split()
    if len(entries) > MAX_ICMP_BLOCKS or any(not ICMP_TYPE_RE.fullmatch(item) for item in entries):
        return None, "Firewalld returned an invalid or oversized ICMP block list."
    matching_count = sum(item == icmp_type for item in entries)
    if matching_count > 1:
        return None, "Firewalld returned duplicate copies of this ICMP block; inspect the zone before changing it."

    inversion_enabled, error = _read_inversion_state(binary, env, configuration, zone)
    if error or inversion_enabled is None:
        return None, error or "The zone's ICMP block-inversion state could not be verified."
    return _ICMPBlockSnapshot(
        configuration=configuration,
        zone=zone,
        zone_active=zone_active,
        icmp_type=icmp_type,
        icmp_type_digest=type_digest,
        inversion_enabled=inversion_enabled,
        matching_count=matching_count,
    ), None


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env


def _binary(env: dict[str, str]) -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    return find_session_binary("firewall-cmd", env)


def firewalld_icmp_block_confirmation_details(
    action: str,
    configuration: str,
    zone: str,
    icmp_type: str,
) -> tuple[FirewalldICMPBlockActionTarget | None, str | None]:
    validation_error = _normalize_request(action, configuration, zone, icmp_type)
    if validation_error:
        return None, validation_error
    env = _environment()
    binary = _binary(env)
    if not binary:
        return None, "The optional firewall-cmd tool is unavailable on this Linux host."
    snapshot, error = _read_snapshot(configuration, zone, icmp_type, binary, env)
    if error or snapshot is None:
        return None, error or "The exact firewalld ICMP block state could not be verified."
    desired_count = 0 if action == "add_block" else 1
    if snapshot.matching_count != desired_count:
        return None, (
            "That exact ICMP block already exists in the selected configuration."
            if snapshot.matching_count
            else "That exact ICMP block is not present in the selected configuration."
        )

    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    record = _ICMPBlockToken(
        action=action,
        configuration=configuration,
        zone=zone,
        zone_active=snapshot.zone_active,
        icmp_type=icmp_type,
        icmp_type_digest=snapshot.icmp_type_digest,
        inversion_enabled=snapshot.inversion_enabled,
        matching_count=snapshot.matching_count,
        expires_at=now + TOKEN_TTL_SECONDS,
    )
    with _ACTION_LOCK:
        for key in [key for key, item in _TOKENS.items() if item.expires_at <= now]:
            _TOKENS.pop(key, None)
        if len(_TOKENS) >= MAX_PENDING_TOKENS:
            return None, "Too many pending firewalld confirmations; retry after existing prompts expire."
        _TOKENS[token] = record
    return FirewalldICMPBlockActionTarget(
        action=action,
        configuration=configuration,
        zone=zone,
        zone_active=snapshot.zone_active,
        icmp_type=icmp_type,
        inversion_enabled=snapshot.inversion_enabled,
        matching_count=snapshot.matching_count,
        confirmation_token=token,
    ), None


def _response(
    *,
    success: bool,
    action: str,
    configuration: str,
    zone: str,
    icmp_type: str,
    zone_active: bool | None,
    rule_present: bool | None,
    state_verified: bool,
    user_confirmed: bool,
    message: str,
) -> FirewalldICMPBlockActionResponse:
    return FirewalldICMPBlockActionResponse(
        success=success,
        action=action if action in {"add_block", "remove_block"} else "add_block",
        configuration=configuration if configuration in {"runtime", "permanent"} else "runtime",
        zone=zone[:64] if isinstance(zone, str) else None,
        icmp_type=icmp_type[:80] if isinstance(icmp_type, str) else None,
        zone_active=zone_active,
        rule_present=rule_present,
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_firewalld_icmp_block_action(
    action: str,
    configuration: str,
    zone: str,
    icmp_type: str,
    expected_state_token: str,
    *,
    confirmed: bool,
) -> FirewalldICMPBlockActionResponse:
    with _ACTION_LOCK:
        record = (
            _TOKENS.get(expected_state_token)
            if isinstance(expected_state_token, str)
            and len(expected_state_token) <= 100
            and TOKEN_RE.fullmatch(expected_state_token)
            else None
        )
        if record is None or record.expires_at <= time.monotonic():
            if isinstance(expected_state_token, str) and len(expected_state_token) <= 100:
                _TOKENS.pop(expected_state_token, None)
            return _response(
                success=False,
                action=action,
                configuration=configuration,
                zone=zone,
                icmp_type=icmp_type,
                zone_active=None,
                rule_present=None,
                state_verified=False,
                user_confirmed=confirmed is True,
                message="A fresh firewalld confirmation token is required; inspect the exact ICMP block and try again.",
            )
        if record.claimed:
            return _response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                icmp_type=record.icmp_type,
                zone_active=record.zone_active,
                rule_present=record.matching_count == 1,
                state_verified=False,
                user_confirmed=confirmed is True,
                message="This firewalld confirmation token is already in use; request a fresh confirmation.",
            )
        record.claimed = True

    try:
        if confirmed is not True:
            return _response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                icmp_type=record.icmp_type,
                zone_active=record.zone_active,
                rule_present=record.matching_count == 1,
                state_verified=False,
                user_confirmed=False,
                message="Explicit client confirmation is required; no firewalld command was run.",
            )
        if (
            _normalize_request(action, configuration, zone, icmp_type)
            or action != record.action
            or configuration != record.configuration
            or zone != record.zone
            or icmp_type != record.icmp_type
        ):
            return _response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                icmp_type=record.icmp_type,
                zone_active=record.zone_active,
                rule_present=record.matching_count == 1,
                state_verified=False,
                user_confirmed=True,
                message="Confirmation did not match the exact action, configuration, zone, and ICMP type; no command was run.",
            )

        env = _environment()
        binary = _binary(env)
        if not binary:
            return _response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                icmp_type=record.icmp_type,
                zone_active=record.zone_active,
                rule_present=record.matching_count == 1,
                state_verified=False,
                user_confirmed=True,
                message="The optional firewall-cmd tool became unavailable; no command was run.",
            )

        current, error = _read_snapshot(
            record.configuration, record.zone, record.icmp_type, binary, env
        )
        if error or current is None:
            return _response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                icmp_type=record.icmp_type,
                zone_active=None,
                rule_present=None,
                state_verified=False,
                user_confirmed=True,
                message=error or "The firewalld state could not be revalidated; no command was run.",
            )
        if (
            current.zone_active != record.zone_active
            or current.matching_count != record.matching_count
            or current.icmp_type_digest != record.icmp_type_digest
            or current.inversion_enabled != record.inversion_enabled
        ):
            return _response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                icmp_type=record.icmp_type,
                zone_active=current.zone_active,
                rule_present=current.matching_count == 1,
                state_verified=False,
                user_confirmed=True,
                message="The zone binding, ICMP type definition, inversion state, or block list changed after confirmation; inspect it and confirm again.",
            )

        command_name = "--add-icmp-block" if record.action == "add_block" else "--remove-icmp-block"
        arguments = [f"--zone={record.zone}", f"{command_name}={record.icmp_type}"]
        if record.configuration == "permanent":
            arguments.insert(0, "--permanent")
        _output, command_error, command_truncated = _command(
            binary,
            arguments,
            env,
            label=f"firewalld {record.configuration} ICMP block update",
        )
        after, verify_error = _read_snapshot(
            record.configuration, record.zone, record.icmp_type, binary, env
        )
        expected_present = record.action == "add_block"
        verified = (
            after is not None
            and after.zone_active == record.zone_active
            and after.icmp_type_digest == record.icmp_type_digest
            and after.inversion_enabled is False
            and (after.matching_count == 1) is expected_present
        )
        if command_error or command_truncated:
            message = (
                "The firewalld command timed out; inspect the selected configuration before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "Firewalld reported an ICMP block update error; inspect the selected configuration before retrying."
            )
            if verified:
                message += " The requested ICMP block state is visible."
            elif verify_error:
                message += " The resulting state could not be verified."
            return _response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                icmp_type=record.icmp_type,
                zone_active=after.zone_active if after is not None else None,
                rule_present=(after.matching_count == 1) if after is not None else None,
                state_verified=verified,
                user_confirmed=True,
                message=message,
            )
        if not verified:
            message = "Firewalld returned from the update, but the requested exact ICMP block state is not visible."
            if verify_error:
                message += " The resulting state could not be read."
            return _response(
                success=False,
                action=record.action,
                configuration=record.configuration,
                zone=record.zone,
                icmp_type=record.icmp_type,
                zone_active=after.zone_active if after is not None else None,
                rule_present=(after.matching_count == 1) if after is not None else None,
                state_verified=False,
                user_confirmed=True,
                message=message,
            )

        effect = "added" if expected_present else "removed"
        persistence = (
            " This runtime-only change lasts until firewalld reloads, restarts, or the host reboots."
            if record.configuration == "runtime"
            else " This changes saved configuration only; runtime rules change after a firewalld reload or restart."
        )
        return _response(
            success=True,
            action=record.action,
            configuration=record.configuration,
            zone=record.zone,
            icmp_type=record.icmp_type,
            zone_active=after.zone_active,
            rule_present=after.matching_count == 1,
            state_verified=True,
            user_confirmed=True,
            message=f"The exact ICMP block for {record.icmp_type!r} was {effect} in zone {record.zone}.{persistence}",
        )
    finally:
        with _ACTION_LOCK:
            _TOKENS.pop(expected_state_token, None)
