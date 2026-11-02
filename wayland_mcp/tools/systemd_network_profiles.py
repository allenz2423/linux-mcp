"""Read-only, allowlisted systemd .network/.netdev/.link profile inventory."""

from __future__ import annotations

import configparser
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import SystemdNetworkProfileInfo, SystemdNetworkProfileListResponse

NETWORK_CONFIG_ROOTS: tuple[tuple[str, Path], ...] = (
    ("etc", Path("/etc/systemd/network")),
    ("run", Path("/run/systemd/network")),
    ("usr_local_lib", Path("/usr/local/lib/systemd/network")),
    ("usr_lib", Path("/usr/lib/systemd/network")),
    ("lib_compat", Path("/lib/systemd/network")),
)

PROFILE_SUFFIXES = {".network", ".netdev", ".link"}
DROP_IN_DIRECTORY_RE = re.compile(r"^([A-Za-z0-9_.@+-]{1,255}\.(?:network|netdev|link))\.d$")
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.@+-]{1,255}$")
SAFE_PATTERN_RE = re.compile(r"^[A-Za-z0-9_.:*?!@+-]{1,128}$")
SAFE_INTERFACE_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
SAFE_KIND_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
SAFE_DNS_SERVER_RE = re.compile(r"^[\w\[][\w.:_%#\[\]+/~!-]{0,511}$")
SAFE_DNS_DOMAIN_RE = re.compile(r"^[\w_.~+*-]{1,253}$")
MAX_CONFIG_LINE_LENGTH = 4_096
MAX_DNS_VALUES = 64

MAX_QUERY_LENGTH = 256
MAX_FILE_BYTES = 128 * 1024
MAX_TOTAL_FILE_BYTES = 8 * 1024 * 1024
MAX_SCAN_FILES = 1024
MAX_SCAN_ENTRIES = 20_000
MAX_RETURNED_PROFILES = 300
MAX_MATCH_PATTERNS = 32

DHCP_VALUES = {"yes", "no", "ipv4", "ipv6"}
SOURCE_ORDER = {name: rank for rank, (name, _path) in enumerate(NETWORK_CONFIG_ROOTS)}


@dataclass(frozen=True)
class _ProfileCandidate:
    path: Path
    source: str
    filename: str
    profile_filename: str | None
    file_type: str
    is_drop_in: bool
    is_symlink: bool


def _file_type(filename: str) -> str | None:
    suffix = Path(filename).suffix
    return suffix[1:] if suffix in PROFILE_SUFFIXES else None


def _candidate_name_safe(filename: str) -> bool:
    return bool(SAFE_FILENAME_RE.fullmatch(filename))


def _bounded_names(path: Path, limit: int) -> tuple[list[str], bool, bool]:
    names: list[str] = []
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if len(names) >= limit:
                    return names, True, False
                names.append(entry.name)
    except OSError:
        return names, False, True
    return names, False, False


def _path_kind(path: Path) -> str | None:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return None
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


def _collect_candidates() -> tuple[list[_ProfileCandidate], bool, bool]:
    candidates: list[_ProfileCandidate] = []
    partial = False
    truncated = False
    entries_scanned = 0
    visited_roots: set[str] = set()

    for source, root in NETWORK_CONFIG_ROOTS:
        if not root.is_dir():
            continue
        canonical_root = os.path.realpath(root)
        if canonical_root in visited_roots:
            continue
        visited_roots.add(canonical_root)

        remaining_entries = max(0, MAX_SCAN_ENTRIES - entries_scanned)
        root_names, root_truncated, root_error = _bounded_names(root, remaining_entries)
        if root_error:
            partial = True
            continue
        entries_scanned += len(root_names)
        partial = partial or root_truncated
        truncated = truncated or root_truncated

        stop_scan = False
        for entry_name in root_names:
            if not _candidate_name_safe(entry_name):
                if Path(entry_name).suffix in PROFILE_SUFFIXES or DROP_IN_DIRECTORY_RE.fullmatch(entry_name):
                    partial = True
                continue
            entry_path = root / entry_name
            entry_kind = _path_kind(entry_path)
            profile_type = _file_type(entry_name)
            if profile_type is not None:
                if entry_kind not in {"file", "symlink"}:
                    if entry_kind is None:
                        partial = True
                    continue
                candidates.append(_ProfileCandidate(
                    path=entry_path,
                    source=source,
                    filename=entry_name,
                    profile_filename=None,
                    file_type=profile_type,
                    is_drop_in=False,
                    is_symlink=entry_kind == "symlink",
                ))
            else:
                drop_in_match = DROP_IN_DIRECTORY_RE.fullmatch(entry_name)
                if drop_in_match is None:
                    continue
                if entry_kind != "directory":
                    partial = True
                    continue
                remaining_entries = max(0, MAX_SCAN_ENTRIES - entries_scanned)
                nested_names, nested_truncated, nested_error = _bounded_names(entry_path, remaining_entries)
                if nested_error:
                    partial = True
                    continue
                entries_scanned += len(nested_names)
                partial = partial or nested_truncated
                truncated = truncated or nested_truncated
                profile_filename = drop_in_match.group(1)
                profile_type = _file_type(profile_filename)
                if profile_type is None:
                    partial = True
                    continue
                for nested_name in nested_names:
                    if not nested_name.endswith(".conf") or not _candidate_name_safe(nested_name):
                        if nested_name.endswith(".conf"):
                            partial = True
                        continue
                    nested_path = entry_path / nested_name
                    nested_kind = _path_kind(nested_path)
                    if nested_kind not in {"file", "symlink"}:
                        if nested_kind is None:
                            partial = True
                        continue
                    candidates.append(_ProfileCandidate(
                        path=nested_path,
                        source=source,
                        filename=nested_name,
                        profile_filename=profile_filename,
                        file_type=profile_type,
                        is_drop_in=True,
                        is_symlink=nested_kind == "symlink",
                    ))
                    if len(candidates) >= MAX_SCAN_FILES:
                        truncated = True
                        stop_scan = True
                        break

            if len(candidates) >= MAX_SCAN_FILES:
                truncated = True
                stop_scan = True
            if stop_scan:
                break
        if stop_scan or root_truncated or entries_scanned >= MAX_SCAN_ENTRIES:
            break

    candidates.sort(key=lambda candidate: (
        (candidate.profile_filename or candidate.filename).casefold(),
        SOURCE_ORDER.get(candidate.source, len(SOURCE_ORDER)),
        candidate.is_drop_in,
        candidate.filename.casefold(),
    ))
    return candidates, partial, truncated


def _read_regular_file(path: Path) -> tuple[bytes | None, bool]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None, False
        if metadata.st_size > MAX_FILE_BYTES:
            return None, True
        content = bytearray()
        while True:
            chunk = os.read(descriptor, min(32 * 1024, MAX_FILE_BYTES + 1 - len(content)))
            if not chunk:
                return bytes(content), False
            content.extend(chunk)
            if len(content) > MAX_FILE_BYTES:
                return None, True
    except OSError:
        return None, False
    finally:
        os.close(descriptor)


def _is_dev_null_symlink(path: Path) -> bool:
    try:
        target = os.readlink(path)
    except OSError:
        return False
    if os.path.isabs(target):
        resolved_text = os.path.normpath(target)
    else:
        resolved_text = os.path.normpath(os.path.join(str(path.parent), target))
    return resolved_text == "/dev/null"


def _option(parser: configparser.ConfigParser, section: str, name: str) -> str:
    value = parser.get(section, name, fallback="")
    return value.strip() if isinstance(value, str) else ""


def _pattern_values(value: str) -> tuple[list[str], bool]:
    result: list[str] = []
    partial = False
    for token in value.split():
        if len(result) >= MAX_MATCH_PATTERNS:
            return result, True
        if SAFE_PATTERN_RE.fullmatch(token):
            result.append(token)
        else:
            partial = True
    return result, partial


def _safe_value(value: str, pattern: re.Pattern[str]) -> tuple[str | None, bool]:
    if not value:
        return None, False
    if pattern.fullmatch(value):
        return value, False
    return None, True


def _parse_dns_values(
    content: str,
) -> tuple[list[str], list[str], bool | None, dict[str, bool], dict[str, str], bool]:
    dns_servers: list[str] = []
    dns_domains: list[str] = []
    dns_default_route: bool | None = None
    dhcp_dns_settings: dict[str, bool] = {}
    use_domains_settings: dict[str, str] = {}
    section = ""
    partial = False
    sections = {
        "dhcpv4": "DHCPv4",
        "dhcpv6": "DHCPv6",
        "ipv6acceptra": "IPv6AcceptRA",
    }

    def append_tokens(target: list[str], raw_value: str, pattern: re.Pattern[str]) -> None:
        nonlocal partial
        if not raw_value.strip():
            target.clear()
            return
        for token in raw_value.split():
            safe, invalid = _safe_value(token, pattern)
            partial = partial or invalid
            if safe is None:
                continue
            if safe in target:
                continue
            if len(target) >= MAX_DNS_VALUES:
                partial = True
                continue
            target.append(safe)

    for raw_line in content.splitlines():
        if len(raw_line) > MAX_CONFIG_LINE_LENGTH:
            partial = True
            continue
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        line = re.split(r"\s+[;#]", line, maxsplit=1)[0].rstrip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().casefold()
            continue
        key, separator, raw_value = line.partition("=")
        if not separator:
            continue
        normalized_key = key.strip().casefold()
        value = raw_value.strip()
        if section == "network":
            if normalized_key == "dns":
                append_tokens(dns_servers, value, SAFE_DNS_SERVER_RE)
            elif normalized_key == "domains":
                append_tokens(dns_domains, value, SAFE_DNS_DOMAIN_RE)
            elif normalized_key == "dnsdefaultroute":
                if not value:
                    dns_default_route = None
                    continue
                parsed = _parse_systemd_boolean(value)
                if parsed is None:
                    partial = True
                else:
                    dns_default_route = parsed
            elif normalized_key == "usedomains":
                if not value:
                    use_domains_settings.pop("Network.UseDomains", None)
                    continue
                parsed = _parse_systemd_domain_mode(value)
                if parsed is None:
                    partial = True
                else:
                    use_domains_settings["Network.UseDomains"] = parsed
        elif section in sections:
            prefix = sections[section]
            if normalized_key in {"usedns", "usednr"}:
                setting_name = "UseDNS" if normalized_key == "usedns" else "UseDNR"
                setting_key = f"{prefix}.{setting_name}"
                if not value:
                    dhcp_dns_settings.pop(setting_key, None)
                    continue
                parsed = _parse_systemd_boolean(value)
                if parsed is None:
                    partial = True
                else:
                    dhcp_dns_settings[setting_key] = parsed
            elif normalized_key == "usedomains":
                setting_key = f"{prefix}.UseDomains"
                if not value:
                    use_domains_settings.pop(setting_key, None)
                    continue
                parsed = _parse_systemd_domain_mode(value)
                if parsed is None:
                    partial = True
                else:
                    use_domains_settings[setting_key] = parsed
    return dns_servers, dns_domains, dns_default_route, dhcp_dns_settings, use_domains_settings, partial


def _parse_systemd_boolean(value: str) -> bool | None:
    normalized = value.casefold()
    if normalized in {"yes", "true", "1", "on"}:
        return True
    if normalized in {"no", "false", "0", "off"}:
        return False
    return None


def _parse_systemd_domain_mode(value: str) -> str | None:
    normalized = value.casefold()
    if normalized in {"yes", "true", "1", "on"}:
        return "yes"
    if normalized in {"no", "false", "0", "off"}:
        return "no"
    if normalized == "route":
        return normalized
    return None


def _extract_profile(
    candidate: _ProfileCandidate,
    content: bytes,
) -> tuple[SystemdNetworkProfileInfo | None, bool]:
    if not content:
        return SystemdNetworkProfileInfo(
            source=candidate.source,
            filename=candidate.filename,
            profile_filename=candidate.profile_filename,
            file_type=candidate.file_type,
            is_drop_in=candidate.is_drop_in,
            empty=True,
            masked=not candidate.is_drop_in,
        ), False
    try:
        decoded = content.decode("utf-8", errors="strict")
        parser = configparser.ConfigParser(
            interpolation=None,
            strict=False,
            delimiters=("=",),
            comment_prefixes=("#", ";"),
            allow_no_value=True,
            empty_lines_in_values=False,
        )
        parser.optionxform = str.casefold
        parser.read_string(decoded)
    except (UnicodeDecodeError, configparser.Error, ValueError):
        return None, True

    partial = False
    dns_servers: list[str] = []
    dns_domains: list[str] = []
    dns_default_route: bool | None = None
    dhcp_dns_settings: dict[str, bool] = {}
    use_domains_settings: dict[str, str] = {}
    match_section = "Match"
    match_name_key = "Name" if candidate.file_type == "network" else "OriginalName"
    if candidate.file_type == "netdev":
        match_names: list[str] = []
        match_drivers: list[str] = []
        name_value, invalid_name = _safe_value(
            _option(parser, "NetDev", "Name"),
            SAFE_INTERFACE_NAME_RE,
        )
        kind_value, invalid_kind = _safe_value(
            _option(parser, "NetDev", "Kind"),
            SAFE_KIND_RE,
        )
        partial = partial or invalid_name or invalid_kind
        dhcp_value = None
    else:
        raw_names = _option(parser, match_section, match_name_key)
        raw_drivers = _option(parser, match_section, "Driver")
        match_names, names_partial = _pattern_values(raw_names)
        match_drivers, drivers_partial = _pattern_values(raw_drivers)
        partial = partial or names_partial or drivers_partial
        if candidate.file_type == "link":
            name_value, invalid_name = _safe_value(
                _option(parser, "Link", "Name"),
                SAFE_INTERFACE_NAME_RE,
            )
            kind_value = None
            partial = partial or invalid_name
            dhcp_value = None
        else:
            name_value = None
            kind_value = None
            raw_dhcp = _option(parser, "Network", "DHCP").casefold()
            if raw_dhcp and raw_dhcp not in DHCP_VALUES:
                dhcp_value = None
                partial = True
            else:
                dhcp_value = raw_dhcp or None

    if candidate.file_type == "network":
        (
            dns_servers,
            dns_domains,
            dns_default_route,
            dhcp_dns_settings,
            use_domains_settings,
            dns_partial,
        ) = _parse_dns_values(decoded)
        partial = partial or dns_partial

    return SystemdNetworkProfileInfo(
        source=candidate.source,
        filename=candidate.filename,
        profile_filename=candidate.profile_filename,
        file_type=candidate.file_type,
        is_drop_in=candidate.is_drop_in,
        name=name_value,
        kind=kind_value,
        match_name_patterns=match_names,
        match_driver_patterns=match_drivers,
        dhcp=dhcp_value,
        configured_dns_servers=dns_servers,
        dns_domains=dns_domains,
        dns_default_route=dns_default_route,
        dhcp_dns_settings=dhcp_dns_settings,
        use_domains_settings=use_domains_settings,
    ), partial


def _query_matches(profile: SystemdNetworkProfileInfo, query: str) -> bool:
    if not query:
        return True
    fields = [
        profile.source,
        profile.filename,
        profile.profile_filename or "",
        profile.file_type,
        profile.name or "",
        profile.kind or "",
        profile.dhcp or "",
        *profile.configured_dns_servers,
        *profile.dns_domains,
        str(profile.dns_default_route) if profile.dns_default_route is not None else "",
        *(f"{key}={value}" for key, value in profile.dhcp_dns_settings.items()),
        *(f"{key}={value}" for key, value in profile.use_domains_settings.items()),
        *profile.match_name_patterns,
        *profile.match_driver_patterns,
    ]
    return query in " ".join(fields).casefold()


def list_systemd_network_profiles(
    query: str = "",
    limit: int = 100,
) -> SystemdNetworkProfileListResponse:
    """List selected systemd network configuration metadata; never return raw settings."""
    if not sys.platform.startswith("linux"):
        return SystemdNetworkProfileListResponse(
            success=False,
            message="systemd network profile inventory is available only on Linux.",
        )
    if not isinstance(query, str) or len(query) > MAX_QUERY_LENGTH:
        return SystemdNetworkProfileListResponse(
            success=False,
            message=f"Query must be text with at most {MAX_QUERY_LENGTH} characters.",
        )
    if any(not character.isprintable() for character in query):
        return SystemdNetworkProfileListResponse(success=False, message="Query cannot contain control characters.")
    if not isinstance(limit, int) or isinstance(limit, bool):
        return SystemdNetworkProfileListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_PROFILES))

    candidates, partial, truncated = _collect_candidates()
    roots_available = any(root.is_dir() for _source, root in NETWORK_CONFIG_ROOTS)
    if not roots_available:
        return SystemdNetworkProfileListResponse(
            success=False,
            limit=limit,
            message="No systemd network configuration directory is available.",
        )

    profiles: list[SystemdNetworkProfileInfo] = []
    skipped_files = 0
    bytes_read = 0
    for candidate in candidates:
        if candidate.is_symlink:
            masked = _is_dev_null_symlink(candidate.path)
            profiles.append(SystemdNetworkProfileInfo(
                source=candidate.source,
                filename=candidate.filename,
                profile_filename=candidate.profile_filename,
                file_type=candidate.file_type,
                is_drop_in=candidate.is_drop_in,
                is_symlink=True,
                masked=masked,
            ))
            if not masked:
                partial = True
                skipped_files += 1
            continue
        if bytes_read >= MAX_TOTAL_FILE_BYTES:
            truncated = True
            break
        content, file_truncated = _read_regular_file(candidate.path)
        if content is None:
            partial = True
            skipped_files += 1
            truncated = truncated or file_truncated
            continue
        if bytes_read + len(content) > MAX_TOTAL_FILE_BYTES:
            partial = True
            truncated = True
            skipped_files += 1
            break
        bytes_read += len(content)
        profile, profile_partial = _extract_profile(candidate, content)
        if profile is None:
            partial = True
            skipped_files += 1
            continue
        partial = partial or profile_partial
        if _query_matches(profile, query.strip().casefold()):
            profiles.append(profile)

    total_profiles = len(profiles)
    truncated = truncated or total_profiles > limit
    messages: list[str] = [
        "Only profile filename/source/type, mask/empty/symlink status, match-name/driver patterns, netdev name/kind, DHCP mode, and allowlisted .network DNS settings are returned. Secret keys, interface addresses, MAC addresses, comments, and raw config text are excluded; files and drop-ins are not merged or resolved to the effective configuration."
    ]
    if partial:
        messages.append(f"Some configuration files or allowlisted fields were unavailable, malformed, or omitted ({skipped_files} files skipped).")
    if truncated:
        messages.append("The profile scan or result list reached its configured bound.")
    if len(profiles) > limit:
        messages.append(f"Results capped at {limit} profiles.")

    return SystemdNetworkProfileListResponse(
        success=True,
        total_profiles=total_profiles,
        returned_profiles=min(total_profiles, limit),
        profiles=profiles[:limit],
        limit=limit,
        partial=partial,
        truncated=truncated,
        skipped_files=skipped_files,
        message=" ".join(messages),
    )
