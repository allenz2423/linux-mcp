"""State-bound persistent DNS changes for exact NetworkManager profiles."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sys
import threading
import uuid as uuid_module
from dataclasses import dataclass

from wayland_mcp.models import (
    NetworkManagerProfileDNSConfigResponse,
    NetworkManagerProfileDNSResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.network_manager import UUID_PATTERN
from wayland_mcp.tools.network_manager_dns import _read_network_manager_profile_dns

MAX_OUTPUT_BYTES = 128 * 1024
QUERY_TIMEOUT_SECONDS = 5
ACTION_TIMEOUT_SECONDS = 15
MAX_VALUES = 32
DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class NetworkManagerDNSChanges:
    ipv4_dns_servers: tuple[str, ...] | None = None
    ipv4_search_domains: tuple[str, ...] | None = None
    ipv4_ignore_auto_dns: bool | None = None
    ipv6_dns_servers: tuple[str, ...] | None = None
    ipv6_search_domains: tuple[str, ...] | None = None
    ipv6_ignore_auto_dns: bool | None = None

    def as_payload(self) -> dict[str, object]:
        return {
            key: list(value) if isinstance(value, tuple) else value
            for key, value in (
                ("ipv4_dns_servers", self.ipv4_dns_servers),
                ("ipv4_search_domains", self.ipv4_search_domains),
                ("ipv4_ignore_auto_dns", self.ipv4_ignore_auto_dns),
                ("ipv6_dns_servers", self.ipv6_dns_servers),
                ("ipv6_search_domains", self.ipv6_search_domains),
                ("ipv6_ignore_auto_dns", self.ipv6_ignore_auto_dns),
            )
            if value is not None
        }

    def properties(self) -> list[str]:
        mapping = (
            ("ipv4_dns_servers", "ipv4.dns"),
            ("ipv4_search_domains", "ipv4.dns-search"),
            ("ipv4_ignore_auto_dns", "ipv4.ignore-auto-dns"),
            ("ipv6_dns_servers", "ipv6.dns"),
            ("ipv6_search_domains", "ipv6.dns-search"),
            ("ipv6_ignore_auto_dns", "ipv6.ignore-auto-dns"),
        )
        return [property_name for field, property_name in mapping if getattr(self, field) is not None]


@dataclass(frozen=True, slots=True)
class NetworkManagerDNSConfigTarget:
    profile: NetworkManagerProfileDNSResponse
    changes: NetworkManagerDNSChanges
    confirmation_phrase: str


def _normalize_uuid(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not UUID_PATTERN.fullmatch(value):
        return None, "profile_uuid must be one exact NetworkManager UUID from list_network_manager_profiles."
    try:
        return str(uuid_module.UUID(value)), None
    except ValueError:
        return None, "profile_uuid is not a valid NetworkManager UUID."


def _canonical_domains(values: object, field_name: str) -> tuple[str, ...] | None:
    if not isinstance(values, list):
        raise ValueError(f"{field_name} must be a list when supplied.")
    if len(values) > MAX_VALUES:
        raise ValueError(f"{field_name} may contain at most {MAX_VALUES} entries.")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or len(value) > 254 or not value:
            raise ValueError(f"Every {field_name} entry must be a non-empty DNS domain of at most 254 characters.")
        routing_only = value.startswith("~")
        domain = value[1:] if routing_only else value
        if domain == ".":
            canonical = "~." if routing_only else "."
        else:
            if domain.endswith("."):
                domain = domain[:-1]
            labels = domain.split(".")
            if not domain or len(domain) > 253 or any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
                raise ValueError(f"{field_name} contains a domain outside the supported DNS label syntax.")
            canonical = ("~" if routing_only else "") + domain.casefold()
        if canonical not in normalized:
            normalized.append(canonical)
    return tuple(normalized)


def _canonical_servers(values: object, family: int, field_name: str) -> tuple[str, ...] | None:
    if not isinstance(values, list):
        raise ValueError(f"{field_name} must be a list when supplied.")
    if len(values) > MAX_VALUES:
        raise ValueError(f"{field_name} may contain at most {MAX_VALUES} entries.")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError(f"Every {field_name} entry must be one literal IP address.")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"Every {field_name} entry must be one literal IP address.") from exc
        if address.version != family:
            raise ValueError(f"{field_name} entries must be IPv{family} addresses.")
        canonical = str(address)
        if canonical not in normalized:
            normalized.append(canonical)
    return tuple(normalized)


def _normalize_changes(
    ipv4_dns_servers: object,
    ipv4_search_domains: object,
    ipv4_ignore_auto_dns: object,
    ipv6_dns_servers: object,
    ipv6_search_domains: object,
    ipv6_ignore_auto_dns: object,
) -> tuple[NetworkManagerDNSChanges | None, str | None]:
    try:
        if ipv4_ignore_auto_dns is not None and not isinstance(ipv4_ignore_auto_dns, bool):
            raise ValueError("ipv4_ignore_auto_dns must be true, false, or null.")
        if ipv6_ignore_auto_dns is not None and not isinstance(ipv6_ignore_auto_dns, bool):
            raise ValueError("ipv6_ignore_auto_dns must be true, false, or null.")
        changes = NetworkManagerDNSChanges(
            ipv4_dns_servers=(
                _canonical_servers(ipv4_dns_servers, 4, "ipv4_dns_servers")
                if ipv4_dns_servers is not None else None
            ),
            ipv4_search_domains=(
                _canonical_domains(ipv4_search_domains, "ipv4_search_domains")
                if ipv4_search_domains is not None else None
            ),
            ipv4_ignore_auto_dns=ipv4_ignore_auto_dns,
            ipv6_dns_servers=(
                _canonical_servers(ipv6_dns_servers, 6, "ipv6_dns_servers")
                if ipv6_dns_servers is not None else None
            ),
            ipv6_search_domains=(
                _canonical_domains(ipv6_search_domains, "ipv6_search_domains")
                if ipv6_search_domains is not None else None
            ),
            ipv6_ignore_auto_dns=ipv6_ignore_auto_dns,
        )
    except ValueError as exc:
        return None, str(exc)
    if not changes.properties():
        return None, "Supply at least one IPv4 or IPv6 DNS server, search-domain, or automatic-DNS setting."
    return changes, None


def _profile_snapshot(
    binary: str,
    env: dict[str, str],
    profile_uuid: str,
) -> tuple[NetworkManagerProfileDNSResponse | None, str | None]:
    profile = _read_network_manager_profile_dns(profile_uuid, binary, env)
    if not profile.success or profile.profile_uuid != profile_uuid:
        return None, profile.message or "The exact saved profile could not be read."
    if profile.partial or profile.truncated or profile.ipv4 is None or profile.ipv6 is None:
        return None, "The saved DNS profile inventory is incomplete; no profile change was prepared."
    return profile, None


def _confirmation_phrase(
    profile: NetworkManagerProfileDNSResponse,
    changes: NetworkManagerDNSChanges,
) -> str:
    state = profile.model_dump(mode="json", exclude={"message"})
    payload = json.dumps(
        {"profile": state, "requested_changes": changes.as_payload()},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    digest = hashlib.sha256(payload).hexdigest()
    return f"SET DNS {profile.profile_uuid} {digest[:16]}"


def _get_tool_target(
    profile_uuid: object,
    ipv4_dns_servers: object,
    ipv4_search_domains: object,
    ipv4_ignore_auto_dns: object,
    ipv6_dns_servers: object,
    ipv6_search_domains: object,
    ipv6_ignore_auto_dns: object,
) -> tuple[NetworkManagerDNSConfigTarget | None, str | None]:
    normalized_uuid, error = _normalize_uuid(profile_uuid)
    if error or normalized_uuid is None:
        return None, error
    changes, error = _normalize_changes(
        ipv4_dns_servers,
        ipv4_search_domains,
        ipv4_ignore_auto_dns,
        ipv6_dns_servers,
        ipv6_search_domains,
        ipv6_ignore_auto_dns,
    )
    if error or changes is None:
        return None, error
    if not sys.platform.startswith("linux"):
        return None, "Persistent NetworkManager profile DNS control is available only on Linux."
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    binary = find_session_binary("nmcli", env)
    if not binary:
        return None, "NetworkManager profile DNS control requires the nmcli command."
    profile, error = _profile_snapshot(binary, env, normalized_uuid)
    if error or profile is None:
        return None, error or "The exact saved profile could not be verified."
    expected = _expected_profile(profile, changes)
    if _comparison_snapshot(expected) == _comparison_snapshot(profile):
        return None, "The requested DNS values already match this profile; no change is needed."
    return NetworkManagerDNSConfigTarget(
        profile=profile,
        changes=changes,
        confirmation_phrase=_confirmation_phrase(profile, changes),
    ), None


def _comparison_snapshot(profile: NetworkManagerProfileDNSResponse) -> dict[str, object]:
    return profile.model_dump(mode="json", exclude={"message"})


def _expected_profile(
    profile: NetworkManagerProfileDNSResponse,
    changes: NetworkManagerDNSChanges,
) -> NetworkManagerProfileDNSResponse:
    ipv4 = profile.ipv4.model_copy(deep=True)
    ipv6 = profile.ipv6.model_copy(deep=True)
    if changes.ipv4_dns_servers is not None:
        ipv4.dns_servers = list(changes.ipv4_dns_servers)
    if changes.ipv4_search_domains is not None:
        ipv4.search_domains = list(changes.ipv4_search_domains)
    if changes.ipv4_ignore_auto_dns is not None:
        ipv4.ignore_auto_dns = changes.ipv4_ignore_auto_dns
    if changes.ipv6_dns_servers is not None:
        ipv6.dns_servers = list(changes.ipv6_dns_servers)
    if changes.ipv6_search_domains is not None:
        ipv6.search_domains = list(changes.ipv6_search_domains)
    if changes.ipv6_ignore_auto_dns is not None:
        ipv6.ignore_auto_dns = changes.ipv6_ignore_auto_dns
    return profile.model_copy(update={"ipv4": ipv4, "ipv6": ipv6})


def network_manager_profile_dns_confirmation_details(
    profile_uuid: str,
    ipv4_dns_servers: list[str] | None = None,
    ipv4_search_domains: list[str] | None = None,
    ipv4_ignore_auto_dns: bool | None = None,
    ipv6_dns_servers: list[str] | None = None,
    ipv6_search_domains: list[str] | None = None,
    ipv6_ignore_auto_dns: bool | None = None,
) -> tuple[NetworkManagerDNSConfigTarget | None, str | None]:
    """Read and bind selected persistent DNS changes to the full observed DNS state."""
    return _get_tool_target(
        profile_uuid,
        ipv4_dns_servers,
        ipv4_search_domains,
        ipv4_ignore_auto_dns,
        ipv6_dns_servers,
        ipv6_search_domains,
        ipv6_ignore_auto_dns,
    )


def _run_dns_modify(
    binary: str,
    env: dict[str, str],
    profile_uuid: str,
    changes: NetworkManagerDNSChanges,
) -> tuple[bool, str | None]:
    arguments = ["--wait", "12", "connection", "modify", "uuid", profile_uuid]
    property_values = (
        ("ipv4.dns", changes.ipv4_dns_servers),
        ("ipv4.dns-search", changes.ipv4_search_domains),
        ("ipv4.ignore-auto-dns", changes.ipv4_ignore_auto_dns),
        ("ipv6.dns", changes.ipv6_dns_servers),
        ("ipv6.dns-search", changes.ipv6_search_domains),
        ("ipv6.ignore-auto-dns", changes.ipv6_ignore_auto_dns),
    )
    for property_name, value in property_values:
        if value is None:
            continue
        if isinstance(value, tuple):
            serialized = ",".join(value)
        else:
            serialized = "yes" if value else "no"
        arguments.extend((property_name, serialized))
    _output, error, truncated = run_bounded_command(
        [binary, *arguments],
        env,
        command_label="Update confirmed NetworkManager DNS profile settings",
        timeout_seconds=ACTION_TIMEOUT_SECONDS,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if error and "timed out" in error.casefold():
        return False, "The NetworkManager DNS update timed out; the saved profile may be partially changed. Inspect it before retrying."
    if error or truncated:
        return False, "NetworkManager rejected or could not complete the DNS profile update. Inspect the profile before retrying."
    return True, None


def _response(
    *,
    success: bool,
    profile_uuid: str | None,
    profile_name: str | None,
    changes: NetworkManagerDNSChanges | None,
    user_confirmed: bool,
    message: str,
) -> NetworkManagerProfileDNSConfigResponse:
    return NetworkManagerProfileDNSConfigResponse(
        success=success,
        profile_uuid=profile_uuid,
        profile_name=profile_name,
        changed_properties=changes.properties() if changes is not None else [],
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_network_manager_profile_dns_configuration(
    profile_uuid: str,
    ipv4_dns_servers: list[str] | None = None,
    ipv4_search_domains: list[str] | None = None,
    ipv4_ignore_auto_dns: bool | None = None,
    ipv6_dns_servers: list[str] | None = None,
    ipv6_search_domains: list[str] | None = None,
    ipv6_ignore_auto_dns: bool | None = None,
    *,
    confirmed: bool,
    confirmed_profile_uuid: str | None = None,
    confirmed_phrase: str | None = None,
) -> NetworkManagerProfileDNSConfigResponse:
    target, error = _get_tool_target(
        profile_uuid,
        ipv4_dns_servers,
        ipv4_search_domains,
        ipv4_ignore_auto_dns,
        ipv6_dns_servers,
        ipv6_search_domains,
        ipv6_ignore_auto_dns,
    )
    normalized_uuid, uuid_error = _normalize_uuid(profile_uuid)
    if not confirmed:
        return _response(
            success=False,
            profile_uuid=normalized_uuid,
            profile_name=target.profile.profile_name if target else None,
            changes=target.changes if target else None,
            user_confirmed=False,
            message="Explicit client confirmation is required; no NetworkManager profile change was run.",
        )
    if uuid_error or normalized_uuid is None:
        return _response(
            success=False,
            profile_uuid=None,
            profile_name=None,
            changes=None,
            user_confirmed=True,
            message=uuid_error or "The exact NetworkManager profile UUID could not be validated.",
        )
    confirmed_uuid, uuid_error = _normalize_uuid(confirmed_profile_uuid)
    if uuid_error or confirmed_uuid != normalized_uuid:
        return _response(
            success=False,
            profile_uuid=normalized_uuid,
            profile_name=None,
            changes=None,
            user_confirmed=True,
            message="The confirmation did not repeat the exact profile UUID; no change was run.",
        )
    if error or target is None:
        return _response(
            success=False,
            profile_uuid=normalized_uuid,
            profile_name=None,
            changes=None,
            user_confirmed=True,
            message=error or "The requested NetworkManager DNS update could not be verified.",
        )
    if not isinstance(confirmed_phrase, str) or confirmed_phrase != target.confirmation_phrase:
        return _response(
            success=False,
            profile_uuid=normalized_uuid,
            profile_name=target.profile.profile_name,
            changes=target.changes,
            user_confirmed=True,
            message="The confirmation phrase did not match the current profile state and requested DNS changes; no update was run.",
        )

    with _ACTION_LOCK:
        env = get_sanitized_env(dict(os.environ))
        env["LANG"] = "C"
        env["LC_ALL"] = "C"
        env["NO_COLOR"] = "1"
        binary = find_session_binary("nmcli", env)
        if not binary:
            return _response(
                success=False,
                profile_uuid=normalized_uuid,
                profile_name=target.profile.profile_name,
                changes=target.changes,
                user_confirmed=True,
                message="NetworkManager's nmcli command became unavailable; no change was run.",
            )
        current, read_error = _profile_snapshot(binary, env, normalized_uuid)
        if read_error or current is None:
            return _response(
                success=False,
                profile_uuid=normalized_uuid,
                profile_name=target.profile.profile_name,
                changes=target.changes,
                user_confirmed=True,
                message=read_error or "The exact DNS profile could not be revalidated; no change was run.",
            )
        if _comparison_snapshot(current) != _comparison_snapshot(target.profile):
            return _response(
                success=False,
                profile_uuid=normalized_uuid,
                profile_name=current.profile_name,
                changes=target.changes,
                user_confirmed=True,
                message="The saved DNS profile changed after confirmation was prepared; no update was run.",
            )
        completed, run_error = _run_dns_modify(binary, env, normalized_uuid, target.changes)
        if not completed:
            return _response(
                success=False,
                profile_uuid=normalized_uuid,
                profile_name=current.profile_name,
                changes=target.changes,
                user_confirmed=True,
                message=run_error or "The NetworkManager DNS update failed; inspect the profile before retrying.",
            )
        updated, verify_error = _profile_snapshot(binary, env, normalized_uuid)
        if verify_error or updated is None:
            return _response(
                success=False,
                profile_uuid=normalized_uuid,
                profile_name=current.profile_name,
                changes=target.changes,
                user_confirmed=True,
                message="The NetworkManager command completed but the saved DNS settings could not be verified; inspect the profile before retrying.",
            )
        expected = _expected_profile(current, target.changes)
        if _comparison_snapshot(updated) != _comparison_snapshot(expected):
            return _response(
                success=False,
                profile_uuid=normalized_uuid,
                profile_name=updated.profile_name,
                changes=target.changes,
                user_confirmed=True,
                message="The saved profile DNS settings did not match the requested values after the update; inspect the profile before retrying.",
            )
        return _response(
            success=True,
            profile_uuid=normalized_uuid,
            profile_name=updated.profile_name,
            changes=target.changes,
            user_confirmed=True,
            message=(
                "The saved NetworkManager DNS profile settings were updated and verified. "
                "The profile was not activated or reapplied; the new settings take effect when NetworkManager applies the profile."
            ),
        )
