"""Read the DNS-related saved fields of one exact NetworkManager profile."""

from __future__ import annotations

import re
import sys
import uuid as uuid_module

from wayland_mcp.models import (
    NetworkManagerDNSFamilySettings,
    NetworkManagerProfileDNSResponse,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.network_manager import UUID_PATTERN

MAX_OUTPUT_BYTES = 128 * 1024
MAX_SCAN_LINES = 512
MAX_LINE_LENGTH = 2_048
MAX_VALUES = 32
COMMAND_TIMEOUT_SECONDS = 5
PROFILE_DNS_FIELDS = (
    "connection.uuid",
    "connection.id",
    "ipv4.method",
    "ipv4.dns",
    "ipv4.dns-search",
    "ipv4.dns-options",
    "ipv4.ignore-auto-dns",
    "ipv4.dns-priority",
    "ipv6.method",
    "ipv6.dns",
    "ipv6.dns-search",
    "ipv6.dns-options",
    "ipv6.ignore-auto-dns",
    "ipv6.dns-priority",
)
DNS_SERVER_RE = re.compile(r"^[\w\[][\w.:_%#\[\]+/~!-]{0,511}$")
DNS_DOMAIN_RE = re.compile(r"^[\w~*][\w_.~+*-]{0,252}$")
DNS_OPTION_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}(?::[A-Za-z0-9._-]{1,64})?$")
DNS_METHOD_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def _split_terse_field(line: str) -> tuple[str, str] | None:
    key: list[str] = []
    value: list[str] = []
    current = key
    escaped = False
    found_separator = False
    for character in line:
        if escaped:
            if character not in {"\\", ":"}:
                return None
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":" and not found_separator:
            current = value
            found_separator = True
        else:
            if not character.isprintable():
                return None
            current.append(character)
    if escaped or not found_separator:
        return None
    parsed_key = "".join(key).strip().casefold()
    if not parsed_key:
        return None
    return parsed_key, "".join(value).strip()


def _parse_list_value(
    raw_value: str,
    pattern: re.Pattern[str],
) -> tuple[list[str], bool]:
    if raw_value in {"", "--"}:
        return [], False
    values: list[str] = []
    partial = False
    for token in raw_value.split(","):
        token = token.strip()
        if not token:
            partial = True
            continue
        if not pattern.fullmatch(token):
            partial = True
            continue
        if token in values:
            continue
        if len(values) >= MAX_VALUES:
            partial = True
            continue
        values.append(token)
    return values, partial


def _parse_boolean(raw_value: str) -> tuple[bool | None, bool]:
    normalized = raw_value.casefold()
    if normalized in {"yes", "true", "1"}:
        return True, False
    if normalized in {"no", "false", "0"}:
        return False, False
    if normalized in {"", "--"}:
        return None, False
    return None, True


def _parse_priority(raw_value: str) -> tuple[int | None, bool]:
    if raw_value in {"", "--"}:
        return None, False
    if not re.fullmatch(r"-?[0-9]{1,11}", raw_value):
        return None, True
    value = int(raw_value)
    if value < -2_147_483_648 or value > 2_147_483_647:
        return None, True
    return value, False


def _family_settings(
    values: dict[str, str],
    family: str,
) -> tuple[NetworkManagerDNSFamilySettings, bool]:
    prefix = f"ipv{family}."
    partial = False
    method: str | None = None
    raw_method = values.get(prefix + "method", "")
    if raw_method not in {"", "--"}:
        if DNS_METHOD_RE.fullmatch(raw_method):
            method = raw_method
        else:
            partial = True
    dns_servers, invalid = _parse_list_value(values.get(prefix + "dns", ""), DNS_SERVER_RE)
    partial = partial or invalid
    search_domains, invalid = _parse_list_value(values.get(prefix + "dns-search", ""), DNS_DOMAIN_RE)
    partial = partial or invalid
    dns_options, invalid = _parse_list_value(values.get(prefix + "dns-options", ""), DNS_OPTION_RE)
    partial = partial or invalid
    ignore_auto_dns, invalid = _parse_boolean(values.get(prefix + "ignore-auto-dns", ""))
    partial = partial or invalid
    dns_priority, invalid = _parse_priority(values.get(prefix + "dns-priority", ""))
    partial = partial or invalid
    return NetworkManagerDNSFamilySettings(
        method=method,
        dns_servers=dns_servers,
        search_domains=search_domains,
        dns_options=dns_options,
        ignore_auto_dns=ignore_auto_dns,
        dns_priority=dns_priority,
    ), partial


def _read_network_manager_profile_dns(
    normalized_uuid: str,
    nmcli: str,
    env: dict[str, str],
) -> NetworkManagerProfileDNSResponse:
    """Read fixed non-secret DNS fields using a selected nmcli and environment."""
    output, error, truncated = run_bounded_command(
        [
            nmcli,
            "--wait", "4",
            "--terse", "--escape", "yes", "--mode", "multiline",
            "--fields", ",".join(PROFILE_DNS_FIELDS),
            "connection", "show", "uuid", normalized_uuid,
        ],
        env,
        command_label="NetworkManager saved-profile DNS inventory",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if output is None or error:
        return NetworkManagerProfileDNSResponse(
            success=False,
            profile_uuid=normalized_uuid,
            truncated=truncated,
            message="The exact NetworkManager profile DNS settings could not be read.",
        )

    values: dict[str, str] = {}
    malformed = 0
    lines = output.splitlines()
    scan_truncated = truncated or len(lines) > MAX_SCAN_LINES
    if len(lines) > MAX_SCAN_LINES:
        lines = lines[:MAX_SCAN_LINES]
    for raw_line in lines:
        if len(raw_line) > MAX_LINE_LENGTH:
            malformed += 1
            continue
        if not raw_line:
            continue
        parsed = _split_terse_field(raw_line)
        if parsed is None:
            malformed += 1
            continue
        key, value = parsed
        if key not in PROFILE_DNS_FIELDS:
            malformed += 1
            continue
        if key in values:
            malformed += 1
        values[key] = value

    try:
        returned_uuid = str(uuid_module.UUID(values.get("connection.uuid", "")))
    except ValueError:
        returned_uuid = None
    if returned_uuid != normalized_uuid:
        return NetworkManagerProfileDNSResponse(
            success=False,
            profile_uuid=normalized_uuid,
            partial=malformed > 0,
            truncated=scan_truncated,
            message="NetworkManager did not return the requested exact profile identity.",
        )

    ipv4, invalid_ipv4 = _family_settings(values, "4")
    ipv6, invalid_ipv6 = _family_settings(values, "6")
    missing_fields = set(PROFILE_DNS_FIELDS) - values.keys()
    partial = malformed > 0 or invalid_ipv4 or invalid_ipv6 or bool(missing_fields) or scan_truncated
    profile_name = values.get("connection.id")
    if profile_name in {"", "--"}:
        profile_name = None
        partial = True
    elif profile_name is not None and (
        len(profile_name) > 256 or any(not character.isprintable() for character in profile_name)
    ):
        profile_name = None
        partial = True

    messages = ["Only the saved profile identity and selected IPv4/IPv6 DNS properties were requested; secret fields were not requested."]
    if partial:
        messages.append("Some DNS properties were unavailable, malformed, or beyond the scan bound.")
    return NetworkManagerProfileDNSResponse(
        success=True,
        profile_uuid=normalized_uuid,
        profile_name=profile_name,
        ipv4=ipv4,
        ipv6=ipv6,
        partial=partial,
        truncated=scan_truncated,
        message=" ".join(messages),
    )


def get_network_manager_profile_dns(profile_uuid: str) -> NetworkManagerProfileDNSResponse:
    """Read allowlisted saved DNS settings for one exact NetworkManager profile UUID."""
    if not sys.platform.startswith("linux"):
        return NetworkManagerProfileDNSResponse(
            success=False,
            message="NetworkManager profile DNS inventory is available only on Linux.",
        )
    if not isinstance(profile_uuid, str) or not UUID_PATTERN.fullmatch(profile_uuid):
        return NetworkManagerProfileDNSResponse(
            success=False,
            message="Supply one exact profile UUID returned by list_network_manager_profiles.",
        )
    try:
        normalized_uuid = str(uuid_module.UUID(profile_uuid))
    except ValueError:
        return NetworkManagerProfileDNSResponse(success=False, message="The profile UUID is invalid.")

    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    nmcli = find_session_binary("nmcli", env)
    if not nmcli:
        return NetworkManagerProfileDNSResponse(
            success=False,
            profile_uuid=normalized_uuid,
            message="NetworkManager's nmcli command is unavailable.",
        )
    return _read_network_manager_profile_dns(normalized_uuid, nmcli, env)
