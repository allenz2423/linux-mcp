"""Bounded read-only resolver, systemd-resolved, and NetworkManager DNS inventory."""

from __future__ import annotations

import ipaddress
import os
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from wayland_mcp.models import (
    DNSConfigurationResponse,
    DNSConfigurationSource,
    DNSLinkInfo,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

RESOLV_CONF = Path("/etc/resolv.conf")
ALLOWED_RESOLV_CONF_TARGETS = frozenset({
    Path("/run/systemd/resolve/stub-resolv.conf"),
    Path("/run/systemd/resolve/resolv.conf"),
    Path("/run/NetworkManager/resolv.conf"),
    Path("/run/NetworkManager/no-stub-resolv.conf"),
    Path("/run/resolvconf/resolv.conf"),
    Path("/run/openresolv/resolv.conf"),
    Path("/run/connman/resolv.conf"),
    Path("/run/dhclient/resolv.conf"),
    Path("/run/dhcpcd/resolv.conf"),
    Path("/etc/resolvconf/run/resolv.conf"),
})
MAX_RESOLV_CONF_BYTES = 256 * 1024
MAX_SCAN_LINES = 10_000
MAX_LINE_LENGTH = 4_096
MAX_DNS_VALUES = 128
MAX_RESOLVED_LINKS = 256
MAX_COMMAND_BYTES = 512 * 1024
COMMAND_TIMEOUT_SECONDS = 5
MAX_TEXT_LENGTH = 512
MAX_NETWORKMANAGER_DEVICES = 256
RESOLVED_LINK_RE = re.compile(r"^Link\s+([0-9]{1,10})\s+\((.{1,256})\)$")
SAFE_NM_DEVICE_RE = re.compile(r"^[A-Za-z0-9_.:@+-]{1,128}$")
NETWORKMANAGER_DNS_FIELD_RE = re.compile(r"^IP([46])\.(DNS|DOMAIN|SEARCHES)(?:\[[0-9]{1,3}\])?$")
NETWORKMANAGER_DNS_FIELDS = (
    "GENERAL.DEVICE",
    "IP4.DNS", "IP4.DOMAIN", "IP4.SEARCHES",
    "IP6.DNS", "IP6.DOMAIN", "IP6.SEARCHES",
)
RESOLVED_PROPERTIES = {
    "current dns server": "current_dns_server",
    "dnssec setting": "dnssec_setting",
    "dnssec supported": "dnssec_supported",
    "dns over tls setting": "dns_over_tls_setting",
    "llmnr setting": "llmnr_setting",
    "mdns setting": "mdns_setting",
    "defaultroute setting": "default_route_setting",
    "current scopes": "current_scopes",
    "resolv.conf mode": "resolv_conf_mode",
    "dnssec nta": "dnssec_nta",
    "protocols": "protocols",
}
SAFE_RESOLV_OPTIONS = frozenset({
    "attempts", "debug", "edns0", "inet6", "ip6-bytestring", "ip6-dotint",
    "no-aaaa", "no-check-names", "no-ip6-dotint", "no-reload", "no-tld-query",
    "rotate", "single-request", "single-request-reopen", "trust-ad", "use-vc",
})
NUMERIC_RESOLV_OPTIONS = frozenset({"attempts", "ndots", "timeout"})


@dataclass(slots=True)
class _ResolvedSection:
    link: str | None
    link_index: int | None
    is_global: bool
    current_dns_server: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    fallback_dns_servers: list[str] = field(default_factory=list)
    search_domains: list[str] = field(default_factory=list)
    settings: dict[str, str] = field(default_factory=dict)
    last_list: str | None = None


def _safe_text(value: str, maximum: int = MAX_TEXT_LENGTH) -> tuple[str, bool]:
    cleaned = "".join(
        character
        for character in value
        if unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
    ).strip()
    return cleaned[:maximum], len(cleaned) > maximum


def _safe_dns_value(value: str, *, domain: bool = False) -> str | None:
    candidate = value.strip()
    maximum = 253 if domain else 256
    if not candidate or len(candidate) > maximum or any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zs"}
        for character in candidate
    ):
        return None
    allowed_extra = "._~+-*" if domain else ":._%#[]-+"
    if not all(character.isalnum() or character in allowed_extra for character in candidate):
        return None
    return candidate


def _safe_ip_value(value: str) -> str | None:
    candidate = _safe_dns_value(value)
    if candidate is None:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _resolv_conf_file() -> tuple[Path | None, str | None, str | None]:
    try:
        initial = RESOLV_CONF.lstat()
    except FileNotFoundError:
        return None, None, "The fixed /etc/resolv.conf source is unavailable."
    except OSError as exc:
        return None, None, f"Could not inspect /etc/resolv.conf: {exc.strerror or type(exc).__name__}."
    if stat.S_ISREG(initial.st_mode):
        return RESOLV_CONF, None, None
    if not stat.S_ISLNK(initial.st_mode):
        return None, None, "/etc/resolv.conf is neither a regular file nor a symbolic link."
    try:
        raw_target = os.readlink(RESOLV_CONF)
        if len(raw_target) > 512:
            return None, None, "/etc/resolv.conf has an oversized symbolic-link target."
        target_hint, target_hint_truncated = _safe_text(raw_target, 512)
        if target_hint_truncated:
            return None, target_hint, "/etc/resolv.conf has an oversized symbolic-link target."
    except FileNotFoundError:
        return None, None, "/etc/resolv.conf points to a missing file."
    except OSError as exc:
        return None, None, f"Could not resolve /etc/resolv.conf: {exc.strerror or type(exc).__name__}."
    raw_path = Path(raw_target)
    target = raw_path if raw_path.is_absolute() else RESOLV_CONF.parent / raw_path
    target = Path(os.path.normpath(str(target)))
    allowed_targets = ALLOWED_RESOLV_CONF_TARGETS
    if target not in allowed_targets:
        return None, target_hint, "The /etc/resolv.conf link target is outside the supported resolver-file locations."
    return target, target_hint, None


def dns_configuration_available(env: dict[str, str] | None = None) -> bool:
    """Report whether a fixed resolver source or supported resolver client is present."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        file_present = os.path.lexists(RESOLV_CONF)
    except OSError:
        file_present = False
    child_env = env if env is not None else get_sanitized_env()
    return (
        file_present
        or find_session_binary("resolvectl", child_env) is not None
        or find_session_binary("nmcli", child_env) is not None
    )


def _read_resolv_conf() -> DNSConfigurationSource:
    if not sys.platform.startswith("linux"):
        return DNSConfigurationSource(
            source="resolv.conf",
            available=False,
            success=False,
            message="Resolver-file inventory is available only on Linux.",
        )
    path, target_hint, error = _resolv_conf_file()
    if error or path is None:
        available = os.path.lexists(RESOLV_CONF)
        return DNSConfigurationSource(
            source="resolv.conf",
            available=available,
            success=False,
            source_target=target_hint,
            message=error or "The fixed resolver file could not be selected safely.",
        )

    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("resolver source is not a regular file")
        if info.st_size > MAX_RESOLV_CONF_BYTES:
            return DNSConfigurationSource(
                source="resolv.conf",
                available=True,
                success=False,
                source_target=target_hint,
                truncated=True,
                message="The resolver file exceeds the bounded read size.",
            )
        contents = bytearray()
        while len(contents) <= MAX_RESOLV_CONF_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_RESOLV_CONF_BYTES + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
        if len(contents) > MAX_RESOLV_CONF_BYTES:
            return DNSConfigurationSource(
                source="resolv.conf",
                available=True,
                success=False,
                source_target=target_hint,
                truncated=True,
                message="The resolver file grew beyond the bounded read size.",
            )
        text = contents.decode("utf-8", errors="replace")
    except OSError as exc:
        return DNSConfigurationSource(
            source="resolv.conf",
            available=True,
            success=False,
            source_target=target_hint,
            message=f"Could not read the resolver file: {exc.strerror or str(exc) or type(exc).__name__}.",
        )
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    nameservers: list[str] = []
    search_domains: list[str] = []
    domain_directive: str | None = None
    options: list[str] = []
    malformed = 0
    truncated = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if line_number > MAX_SCAN_LINES:
            truncated = True
            break
        if len(raw_line) > MAX_LINE_LENGTH:
            malformed += 1
            continue
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        fields = line.split()
        directive = fields[0].casefold()
        if directive == "nameserver":
            if len(fields) != 2:
                malformed += 1
                continue
            try:
                address = ipaddress.ip_address(fields[1])
            except ValueError:
                malformed += 1
                continue
            if len(nameservers) < MAX_DNS_VALUES:
                nameservers.append(str(address))
            else:
                truncated = True
        elif directive in {"search", "domain"}:
            values = fields[1:]
            if not values or (directive == "domain" and len(values) != 1):
                malformed += 1
                continue
            cleaned_domains = [
                safe for value in values
                if (safe := _safe_dns_value(value, domain=True)) is not None
            ]
            malformed += len(values) - len(cleaned_domains)
            if len(cleaned_domains) > MAX_DNS_VALUES:
                cleaned_domains = cleaned_domains[:MAX_DNS_VALUES]
                truncated = True
            search_domains = cleaned_domains
            domain_directive = cleaned_domains[0] if directive == "domain" and cleaned_domains else None
        elif directive == "options":
            for option in fields[1:]:
                key, separator, value = option.partition(":")
                key = key.casefold()
                if key in NUMERIC_RESOLV_OPTIONS and separator and value.isdigit():
                    normalized = f"{key}:{value}"
                elif key in SAFE_RESOLV_OPTIONS and not separator:
                    normalized = key
                else:
                    continue
                if normalized not in options:
                    if len(options) < MAX_DNS_VALUES:
                        options.append(normalized)
                    else:
                        truncated = True

    messages = []
    if malformed:
        messages.append(f"Skipped {malformed} malformed or unsupported resolver entries.")
    if not nameservers:
        messages.append("No nameserver directive was present; libc resolver defaults may apply.")
    return DNSConfigurationSource(
        source="resolv.conf",
        available=True,
        success=True,
        partial=malformed > 0 or truncated,
        source_target=target_hint,
        nameservers=nameservers,
        search_domains=search_domains,
        domain=domain_directive,
        resolver_options=options,
        malformed_records=malformed,
        truncated=truncated,
        message=" ".join(messages) if messages else None,
    )


def _parse_resolvectl_status(output: str) -> tuple[list[DNSLinkInfo], int, bool]:
    sections: list[_ResolvedSection] = []
    current: _ResolvedSection | None = None
    malformed = 0
    truncated = False
    lines = output.splitlines()
    if len(lines) > MAX_SCAN_LINES:
        lines = lines[:MAX_SCAN_LINES]
        truncated = True

    def append_values(section: _ResolvedSection, field_name: str, raw_values: str) -> None:
        nonlocal malformed, truncated
        domain = field_name == "search_domains"
        values = section.search_domains if domain else section.dns_servers
        if field_name == "fallback_dns_servers":
            values = section.fallback_dns_servers
        for token in raw_values.split():
            safe = _safe_dns_value(token, domain=True) if domain else _safe_ip_value(token)
            if safe is None:
                malformed += 1
                continue
            if safe not in values:
                if len(values) < MAX_DNS_VALUES:
                    values.append(safe)
                else:
                    truncated = True

    for raw_line in lines:
        if len(raw_line) > MAX_LINE_LENGTH:
            malformed += 1
            if current is not None:
                current.last_list = None
            continue
        stripped = raw_line.strip()
        if not stripped:
            if current is not None:
                current.last_list = None
            continue
        if not raw_line[0].isspace():
            if stripped.casefold() == "global":
                if len(sections) >= MAX_RESOLVED_LINKS:
                    truncated = True
                    current = None
                    continue
                current = _ResolvedSection(link=None, link_index=None, is_global=True)
                sections.append(current)
            else:
                match = RESOLVED_LINK_RE.fullmatch(stripped)
                if match:
                    if len(sections) >= MAX_RESOLVED_LINKS:
                        truncated = True
                        current = None
                        continue
                    link_name, clipped = _safe_text(match.group(2), 128)
                    current = _ResolvedSection(
                        link=link_name,
                        link_index=int(match.group(1)),
                        is_global=False,
                    )
                    sections.append(current)
                    truncated = truncated or clipped
                else:
                    current = None
            continue
        if current is None:
            continue

        key, separator, raw_value = stripped.partition(":")
        normalized_key = key.casefold()
        if separator and normalized_key == "dns servers":
            append_values(current, "dns_servers", raw_value)
            current.last_list = "dns_servers"
        elif separator and normalized_key == "fallback dns servers":
            append_values(current, "fallback_dns_servers", raw_value)
            current.last_list = "fallback_dns_servers"
        elif separator and normalized_key == "dns domain":
            append_values(current, "search_domains", raw_value)
            current.last_list = "search_domains"
        elif separator and normalized_key == "current dns server":
            tokens = raw_value.split()
            safe = _safe_ip_value(tokens[0]) if len(tokens) == 1 else None
            if safe is None:
                malformed += 1
            current.current_dns_server = safe
            current.last_list = None
        elif separator and normalized_key in RESOLVED_PROPERTIES:
            property_name = RESOLVED_PROPERTIES[normalized_key]
            value, clipped = _safe_text(raw_value, MAX_TEXT_LENGTH)
            if value:
                current.settings[property_name] = value
            current.last_list = None
            truncated = truncated or clipped
        elif not separator and current.last_list and raw_line[0].isspace():
            append_values(current, current.last_list, stripped)
        else:
            current.last_list = None

    links = [
        DNSLinkInfo(
            link=section.link,
            link_index=section.link_index,
            is_global=section.is_global,
            current_dns_server=section.current_dns_server,
            dns_servers=section.dns_servers,
            fallback_dns_servers=section.fallback_dns_servers,
            search_domains=section.search_domains,
            settings=section.settings,
        )
        for section in sections
        if section.current_dns_server or section.dns_servers or section.fallback_dns_servers or section.search_domains or section.settings
    ]
    if not links:
        malformed += 1
    return links, malformed, truncated


def _read_systemd_resolved(binary: str, env: dict[str, str]) -> DNSConfigurationSource:
    output, error, command_truncated = run_bounded_command(
        [binary, "--no-pager", "status"],
        env,
        command_label="systemd-resolved DNS status query",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_BYTES,
    )
    if output is None:
        return DNSConfigurationSource(
            source="systemd-resolved",
            available=True,
            success=False,
            truncated=command_truncated,
            message=error or "systemd-resolved DNS status could not be read.",
        )
    links, malformed, parse_truncated = _parse_resolvectl_status(output)
    return DNSConfigurationSource(
        source="systemd-resolved",
        available=True,
        success=bool(links),
        partial=command_truncated or malformed > 0 or parse_truncated,
        links=links,
        malformed_records=malformed,
        truncated=command_truncated or parse_truncated,
        message=(
            f"Skipped {malformed} malformed or unrecognized resolver records."
            if malformed else error
        ),
    )


def _split_nmcli_field(line: str) -> tuple[str, str] | None:
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
    parsed_key = "".join(key).strip().upper()
    if not parsed_key:
        return None
    return parsed_key, "".join(value).strip()


def _parse_networkmanager_dns_status(output: str) -> tuple[list[DNSLinkInfo], int, bool]:
    links: list[DNSLinkInfo] = []
    current: DNSLinkInfo | None = None
    malformed = 0
    truncated = False
    lines = output.splitlines()
    if len(lines) > MAX_SCAN_LINES:
        lines = lines[:MAX_SCAN_LINES]
        truncated = True

    def finish_current() -> None:
        if current is not None and (current.dns_servers or current.domains or current.search_domains):
            links.append(current)

    def append_values(target: list[str], raw_value: str, *, domain: bool) -> None:
        nonlocal malformed, truncated
        if raw_value in {"", "--"}:
            return
        for token in raw_value.split(","):
            token = token.strip()
            if not token:
                malformed += 1
                continue
            safe = _safe_dns_value(token, domain=True) if domain else _safe_ip_value(token)
            if safe is None:
                malformed += 1
                continue
            if safe in target:
                continue
            if len(target) >= MAX_DNS_VALUES:
                truncated = True
                continue
            target.append(safe)

    devices_seen = 0
    for raw_line in lines:
        if len(raw_line) > MAX_LINE_LENGTH:
            malformed += 1
            continue
        if not raw_line.strip():
            continue
        parsed = _split_nmcli_field(raw_line)
        if parsed is None:
            malformed += 1
            continue
        key, value = parsed
        if key == "GENERAL.DEVICE":
            finish_current()
            if devices_seen >= MAX_NETWORKMANAGER_DEVICES:
                current = None
                truncated = True
                continue
            devices_seen += 1
            if not SAFE_NM_DEVICE_RE.fullmatch(value):
                current = None
                malformed += 1
                continue
            current = DNSLinkInfo(link=value, is_global=False)
            continue
        match = NETWORKMANAGER_DNS_FIELD_RE.fullmatch(key)
        if match is None:
            continue
        if current is None:
            malformed += 1
            continue
        field_name = match.group(2)
        if field_name == "DNS":
            append_values(current.dns_servers, value, domain=False)
        elif field_name == "DOMAIN":
            append_values(current.domains, value, domain=True)
        elif field_name == "SEARCHES":
            append_values(current.search_domains, value, domain=True)
    finish_current()
    if devices_seen == 0 and output.strip():
        malformed += 1
    return links, malformed, truncated


def _read_networkmanager(binary: str, env: dict[str, str]) -> DNSConfigurationSource:
    output, error, command_truncated = run_bounded_command(
        [
            binary,
            "--wait", "4",
            "--terse", "--escape", "yes", "--mode", "multiline",
            "--fields", ",".join(NETWORKMANAGER_DNS_FIELDS),
            "device", "show",
        ],
        env,
        command_label="NetworkManager active DNS status query",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_BYTES,
    )
    if output is None:
        return DNSConfigurationSource(
            source="NetworkManager",
            available=True,
            success=False,
            truncated=command_truncated,
            message=error or "NetworkManager active DNS status could not be read.",
        )
    links, malformed, parse_truncated = _parse_networkmanager_dns_status(output)
    partial = command_truncated or malformed > 0 or parse_truncated
    message_parts: list[str] = []
    if malformed:
        message_parts.append(f"Skipped {malformed} malformed or unsupported NetworkManager DNS records.")
    if not links:
        message_parts.append("No active NetworkManager devices reported DNS servers, domains, or search domains.")
    if command_truncated or parse_truncated:
        message_parts.append("The NetworkManager DNS output reached its configured bound.")
    return DNSConfigurationSource(
        source="NetworkManager",
        available=True,
        success=not malformed or bool(links),
        partial=partial,
        links=links,
        malformed_records=malformed,
        truncated=command_truncated or parse_truncated,
        message=" ".join(message_parts) if message_parts else error,
    )


def get_dns_configuration() -> DNSConfigurationResponse:
    """Return bounded resolver-file and optional resolver-manager DNS state."""
    if not sys.platform.startswith("linux"):
        return DNSConfigurationResponse(success=False, message="DNS configuration inventory is available only on Linux.")
    sources = [_read_resolv_conf()]
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    env["SYSTEMD_PAGER"] = "cat"
    env["PAGER"] = "cat"
    resolvectl = find_session_binary("resolvectl", env)
    if resolvectl:
        sources.append(_read_systemd_resolved(resolvectl, env))
    nmcli = find_session_binary("nmcli", env)
    if nmcli:
        sources.append(_read_networkmanager(nmcli, env))
    successful = any(source.success for source in sources)
    return DNSConfigurationResponse(
        success=successful,
        sources=sources,
        message=None if successful else "Resolver-file, systemd-resolved, and NetworkManager DNS state could not be read.",
    )
