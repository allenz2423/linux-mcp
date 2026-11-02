"""Typed, confirmed firewalld rich ICMP-type rules for one exact zone."""

from __future__ import annotations

import ipaddress
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import FirewalldRichICMPRuleActionResponse
from wayland_mcp.tools.firewalld_icmp_control import (
    ICMP_TYPE_RE,
    ZONE_NAME_RE,
    _binary,
    _environment,
    _read_icmp_type,
    _read_icmp_type_names,
)
from wayland_mcp.tools.firewalld_rich_rule_control import (
    LOG_PREFIX_RE,
    TOKEN_RE,
    _command,
    _read_snapshot,
)

FirewalldRichICMPRuleAction = Literal["add", "remove"]
FirewalldRichICMPRuleVerdict = Literal["accept", "reject", "drop"]
FirewalldRichICMPRuleLogLevel = Literal[
    "emerg", "alert", "crit", "error", "warning", "notice", "info", "debug",
]

ACTION_LOCK = threading.Lock()
TOKEN_TTL_SECONDS = 180
MAX_PENDING_TOKENS = 1_024
ALLOWED_LOG_LEVELS = {"emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"}


@dataclass(frozen=True, slots=True)
class _RuleSnapshot:
    zone_active: bool | None
    icmp_type_digest: str
    matching_count: int


@dataclass(slots=True)
class _RuleToken:
    request: tuple[object, ...]
    zone_active: bool | None
    icmp_type_digest: str
    matching_count: int
    rich_rule: str
    expires_at: float
    claimed: bool = False


@dataclass(frozen=True, slots=True)
class FirewalldRichICMPRuleTarget:
    action: str
    configuration: str
    zone: str
    icmp_type: str
    source_cidr: str | None
    destination_cidr: str | None
    verdict: str
    log_enabled: bool
    log_prefix: str | None
    log_level: str | None
    audit_enabled: bool
    priority: int | None
    zone_active: bool | None
    icmp_type_digest: str
    rich_rule: str
    matching_count: int
    confirmation_token: str


_TOKENS: dict[str, _RuleToken] = {}


def _normalize_request(
    action: object,
    configuration: object,
    zone: object,
    icmp_type: object,
    source_cidr: object = None,
    destination_cidr: object = None,
    verdict: object = "accept",
    log_enabled: object = False,
    log_prefix: object = None,
    log_level: object = None,
    audit_enabled: object = False,
    priority: object = None,
) -> tuple[tuple[object, ...] | None, str | None]:
    if not isinstance(action, str) or action not in {"add", "remove"}:
        return None, "Choose add or remove."
    if not isinstance(configuration, str) or configuration not in {"runtime", "permanent"}:
        return None, "Choose runtime or permanent configuration."
    if not isinstance(zone, str) or not ZONE_NAME_RE.fullmatch(zone):
        return None, "Use one exact existing firewalld zone name from the frontend inventory."
    if not isinstance(icmp_type, str) or not ICMP_TYPE_RE.fullmatch(icmp_type):
        return None, "Use one exact ICMP type name from firewall-cmd --get-icmptypes."
    if not isinstance(verdict, str) or verdict not in {"accept", "reject", "drop"}:
        return None, "Verdict must be accept, reject, or drop."
    if not isinstance(log_enabled, bool) or not isinstance(audit_enabled, bool):
        return None, "log_enabled and audit_enabled must be booleans."
    if not log_enabled and (log_prefix is not None or log_level is not None):
        return None, "log_prefix and log_level require log_enabled=true."
    if log_prefix is not None and (
        not isinstance(log_prefix, str) or not LOG_PREFIX_RE.fullmatch(log_prefix)
    ):
        return None, "log_prefix must contain 1-127 safe printable characters."
    if log_level is not None and (
        not isinstance(log_level, str) or log_level not in ALLOWED_LOG_LEVELS
    ):
        return None, "log_level must be one of emerg, alert, crit, error, warning, notice, info, or debug."
    if priority is not None and (
        not isinstance(priority, int)
        or isinstance(priority, bool)
        or not -32_768 <= priority <= 32_767
    ):
        return None, "priority must be an integer from -32768 through 32767, or omitted."

    def normalize_cidr(value: object, field: str) -> tuple[str | None, str | None]:
        if value is None or value == "":
            return None, None
        if not isinstance(value, str) or len(value) > 64:
            return None, f"{field} must be a canonical IPv4/IPv6 address or CIDR, or empty."
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            return None, f"{field} must use canonical IP address or network notation."
        if str(network) != value:
            return None, f"{field} must use canonical IP address or network notation."
        return str(network), None

    normalized_source, error = normalize_cidr(source_cidr, "source_cidr")
    if error:
        return None, error
    normalized_destination, error = normalize_cidr(destination_cidr, "destination_cidr")
    if error:
        return None, error
    families = {
        "ipv6" if ":" in value else "ipv4"
        for value in (normalized_source, normalized_destination)
        if value is not None
    }
    if len(families) > 1:
        return None, "source_cidr and destination_cidr must use the same IP version."

    family_clause = f' family="{next(iter(families))}"' if families else ""
    priority_clause = f' priority="{priority}"' if priority is not None else ""
    source_clause = f' source address="{normalized_source}"' if normalized_source else ""
    destination_clause = (
        f' destination address="{normalized_destination}"' if normalized_destination else ""
    )
    log_clause = ""
    if log_enabled:
        log_attributes = ""
        if log_prefix is not None:
            log_attributes += f' prefix="{log_prefix}"'
        if log_level is not None:
            log_attributes += f' level="{log_level}"'
        log_clause = f" log{log_attributes} limit value=\"1/m\""
    audit_clause = ' audit limit value="1/m"' if audit_enabled else ""
    rich_rule = (
        f'rule{family_clause}{priority_clause}{source_clause}{destination_clause} '
        f'icmp-type name="{icmp_type}"{log_clause}{audit_clause} {verdict}'
    )
    normalized_prefix = log_prefix if isinstance(log_prefix, str) else None
    return (
        (
            action, configuration, zone, icmp_type, normalized_source,
            normalized_destination, verdict, log_enabled, normalized_prefix,
            log_level, audit_enabled, priority, rich_rule,
        ),
        None,
    )


def _read_rule_snapshot(
    configuration: str,
    zone: str,
    icmp_type: str,
    rich_rule: str,
    binary: str,
    env: dict[str, str],
) -> tuple[_RuleSnapshot | None, str | None]:
    names, error = _read_icmp_type_names(binary, env, configuration)
    if error or names is None:
        return None, error or "Firewalld ICMP types could not be read."
    if icmp_type not in names:
        return None, "The exact ICMP type is not available in the selected firewalld configuration."
    digest, error = _read_icmp_type(binary, env, configuration, icmp_type)
    if error or digest is None:
        return None, error or "The exact ICMP type definition could not be verified."
    snapshot, error = _read_snapshot(configuration, zone, rich_rule, binary, env)
    if error or snapshot is None:
        return None, error or "The exact firewalld rich-rule state could not be verified."
    return _RuleSnapshot(
        zone_active=snapshot.zone_active,
        icmp_type_digest=digest,
        matching_count=snapshot.matching_count,
    ), None


def firewalld_rich_icmp_rule_confirmation_details(
    action: str,
    configuration: str,
    zone: str,
    icmp_type: str,
    source_cidr: str | None = None,
    destination_cidr: str | None = None,
    verdict: str = "accept",
    log_enabled: bool = False,
    log_prefix: str | None = None,
    log_level: str | None = None,
    audit_enabled: bool = False,
    priority: int | None = None,
) -> tuple[FirewalldRichICMPRuleTarget | None, str | None]:
    request, error = _normalize_request(
        action, configuration, zone, icmp_type, source_cidr, destination_cidr,
        verdict, log_enabled, log_prefix, log_level, audit_enabled, priority,
    )
    if error or request is None:
        return None, error or "The rich ICMP rule request is invalid."
    (
        action, configuration, zone, icmp_type, source_cidr,
        destination_cidr, verdict, log_enabled, log_prefix, log_level,
        audit_enabled, priority, rich_rule,
    ) = request
    env = _environment()
    binary = _binary(env)
    if not binary:
        return None, "The optional firewall-cmd tool is unavailable on this Linux host."
    snapshot, error = _read_rule_snapshot(configuration, zone, icmp_type, rich_rule, binary, env)
    if error or snapshot is None:
        return None, error or "The exact rich ICMP rule state could not be verified."
    desired_count = 0 if action == "add" else 1
    if snapshot.matching_count != desired_count:
        return None, (
            "That exact rich ICMP rule already exists in the selected configuration."
            if snapshot.matching_count
            else "That exact rich ICMP rule is not present in the selected configuration."
        )
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with ACTION_LOCK:
        for key in [key for key, item in _TOKENS.items() if item.expires_at <= now]:
            _TOKENS.pop(key, None)
        if len(_TOKENS) >= MAX_PENDING_TOKENS:
            return None, "Too many pending firewalld confirmations; retry after existing prompts expire."
        _TOKENS[token] = _RuleToken(
            request=request,
            zone_active=snapshot.zone_active,
            icmp_type_digest=snapshot.icmp_type_digest,
            matching_count=snapshot.matching_count,
            rich_rule=rich_rule,
            expires_at=now + TOKEN_TTL_SECONDS,
        )
    return FirewalldRichICMPRuleTarget(
        action=action,
        configuration=configuration,
        zone=zone,
        icmp_type=icmp_type,
        source_cidr=source_cidr,
        destination_cidr=destination_cidr,
        verdict=verdict,
        log_enabled=log_enabled,
        log_prefix=log_prefix,
        log_level=log_level,
        audit_enabled=audit_enabled,
        priority=priority,
        zone_active=snapshot.zone_active,
        icmp_type_digest=snapshot.icmp_type_digest,
        rich_rule=rich_rule,
        matching_count=snapshot.matching_count,
        confirmation_token=token,
    ), None


def _response(
    *,
    success: bool,
    action: object,
    configuration: object,
    zone: object,
    icmp_type: object,
    source_cidr: object,
    destination_cidr: object,
    verdict: object,
    rich_rule: object,
    rule_present: bool | None,
    state_verified: bool,
    user_confirmed: bool,
    message: str,
) -> FirewalldRichICMPRuleActionResponse:
    return FirewalldRichICMPRuleActionResponse(
        success=success,
        action=action if action in {"add", "remove"} else "add",
        configuration=configuration if configuration in {"runtime", "permanent"} else "runtime",
        zone=zone[:64] if isinstance(zone, str) else None,
        icmp_type=icmp_type[:80] if isinstance(icmp_type, str) else None,
        source_cidr=source_cidr[:64] if isinstance(source_cidr, str) else None,
        destination_cidr=destination_cidr[:64] if isinstance(destination_cidr, str) else None,
        verdict=verdict if verdict in {"accept", "reject", "drop"} else None,
        rich_rule=rich_rule[:2_048] if isinstance(rich_rule, str) else None,
        rule_present=rule_present,
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_firewalld_rich_icmp_rule_action(
    action: str,
    configuration: str,
    zone: str,
    icmp_type: str,
    source_cidr: str | None,
    destination_cidr: str | None,
    verdict: str,
    log_enabled: bool,
    log_prefix: str | None,
    log_level: str | None,
    audit_enabled: bool,
    priority: int | None,
    expected_state_token: str,
    *,
    confirmed: bool,
) -> FirewalldRichICMPRuleActionResponse:
    with ACTION_LOCK:
        token = (
            expected_state_token
            if isinstance(expected_state_token, str)
            and len(expected_state_token) <= 100
            and TOKEN_RE.fullmatch(expected_state_token)
            else None
        )
        record = _TOKENS.get(token) if token else None
        if record is None or record.expires_at <= time.monotonic():
            if token:
                _TOKENS.pop(token, None)
            return _response(
                success=False, action=action, configuration=configuration, zone=zone,
                icmp_type=icmp_type, source_cidr=source_cidr, destination_cidr=destination_cidr,
                verdict=verdict, rich_rule=None, rule_present=None, state_verified=False,
                user_confirmed=confirmed is True,
                message="A fresh firewalld confirmation token is required; inspect the exact rich ICMP rule and try again.",
            )
        if record.claimed:
            return _response(
                success=False, action=action, configuration=configuration, zone=zone,
                icmp_type=icmp_type, source_cidr=source_cidr, destination_cidr=destination_cidr,
                verdict=verdict, rich_rule=record.rich_rule,
                rule_present=record.matching_count == 1, state_verified=False,
                user_confirmed=confirmed is True,
                message="This firewalld confirmation token is already in use; request a fresh confirmation.",
            )
        record.claimed = True

    try:
        request, error = _normalize_request(
            action, configuration, zone, icmp_type, source_cidr, destination_cidr,
            verdict, log_enabled, log_prefix, log_level, audit_enabled, priority,
        )
        if confirmed is not True:
            error = "Explicit client confirmation is required; no firewalld command was run."
        elif error or request != record.request:
            error = error or "Confirmation did not match the exact rich ICMP rule and modifiers; no command was run."
        if error:
            return _response(
                success=False, action=record.request[0], configuration=record.request[1],
                zone=record.request[2], icmp_type=record.request[3],
                source_cidr=record.request[4], destination_cidr=record.request[5],
                verdict=record.request[6], rich_rule=record.rich_rule,
                rule_present=record.matching_count == 1, state_verified=False,
                user_confirmed=confirmed is True, message=error,
            )

        env = _environment()
        binary = _binary(env)
        if not binary:
            error = "The optional firewall-cmd tool became unavailable; no firewall command was run."
            return _response(
                success=False, action=record.request[0], configuration=record.request[1],
                zone=record.request[2], icmp_type=record.request[3],
                source_cidr=record.request[4], destination_cidr=record.request[5],
                verdict=record.request[6], rich_rule=record.rich_rule,
                rule_present=record.matching_count == 1, state_verified=False,
                user_confirmed=True, message=error,
            )
        current, error = _read_rule_snapshot(
            record.request[1], record.request[2], record.request[3],
            record.rich_rule, binary, env,
        )
        if error or current is None:
            return _response(
                success=False, action=record.request[0], configuration=record.request[1],
                zone=record.request[2], icmp_type=record.request[3],
                source_cidr=record.request[4], destination_cidr=record.request[5],
                verdict=record.request[6], rich_rule=record.rich_rule,
                rule_present=None, state_verified=False, user_confirmed=True,
                message=error or "The firewalld state could not be revalidated; no command was run.",
            )
        if (
            current.zone_active != record.zone_active
            or current.icmp_type_digest != record.icmp_type_digest
            or current.matching_count != record.matching_count
        ):
            return _response(
                success=False, action=record.request[0], configuration=record.request[1],
                zone=record.request[2], icmp_type=record.request[3],
                source_cidr=record.request[4], destination_cidr=record.request[5],
                verdict=record.request[6], rich_rule=record.rich_rule,
                rule_present=current.matching_count == 1, state_verified=False,
                user_confirmed=True,
                message="The zone binding, ICMP type definition, or rich-rule list changed after confirmation; inspect it and confirm again.",
            )

        command_name = "--add-rich-rule" if action == "add" else "--remove-rich-rule"
        arguments = [f"--zone={zone}", f"{command_name}={record.rich_rule}"]
        if configuration == "permanent":
            arguments.insert(0, "--permanent")
        _output, command_error, command_truncated = _command(
            binary, arguments, env, label=f"firewalld {configuration} rich ICMP rule update",
        )
        after, verify_error = _read_rule_snapshot(
            configuration, zone, icmp_type, record.rich_rule, binary, env,
        )
        expected_present = action == "add"
        verified = (
            after is not None
            and after.zone_active == record.zone_active
            and after.icmp_type_digest == record.icmp_type_digest
            and (after.matching_count == 1) is expected_present
        )
        if command_error or command_truncated or not verified:
            message = (
                "The firewalld command timed out; inspect the selected configuration before retrying."
                if command_error and "timed out" in command_error.casefold()
                else "Firewalld reported a rich ICMP rule update error; inspect the selected configuration before retrying."
                if command_error or command_truncated
                else "Firewalld returned from the update, but the exact rich ICMP rule state is not visible."
            )
            if verified:
                message += " The requested rule state is visible."
            elif verify_error:
                message += " The resulting state could not be verified."
            return _response(
                success=False, action=action, configuration=configuration, zone=zone,
                icmp_type=icmp_type, source_cidr=source_cidr, destination_cidr=destination_cidr,
                verdict=verdict, rich_rule=record.rich_rule,
                rule_present=(after.matching_count == 1) if after is not None else None,
                state_verified=verified, user_confirmed=True, message=message,
            )
        persistence = (
            "This runtime-only change lasts until firewalld reloads, restarts, or the host reboots."
            if configuration == "runtime"
            else "This changes saved configuration only; runtime rules change after a firewalld reload or restart."
        )
        effect = "added" if expected_present else "removed"
        return _response(
            success=True, action=action, configuration=configuration, zone=zone,
            icmp_type=icmp_type, source_cidr=source_cidr, destination_cidr=destination_cidr,
            verdict=verdict, rich_rule=record.rich_rule,
            rule_present=after.matching_count == 1, state_verified=True, user_confirmed=True,
            message=f"The exact firewalld rich ICMP rule was {effect} in zone {zone}. {persistence}",
        )
    finally:
        with ACTION_LOCK:
            _TOKENS.pop(expected_state_token, None)
