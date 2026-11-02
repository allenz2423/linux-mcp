"""Confirmed import of one OpenVPN or WireGuard configuration into NetworkManager."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import shlex
import stat
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import NetworkManagerVPNImportResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.filesystem import MAX_PATH_LENGTH, _open_resolved_path, _resolve_path
from wayland_mcp.tools.network_manager import (
    MAX_OUTPUT_BYTES as PROFILE_OUTPUT_BYTES,
    MAX_SCAN_ROWS as MAX_PROFILE_ROWS,
    NetworkManagerProfileInfo,
    _parse_profile_row,
)

VPNType = Literal["openvpn", "wireguard"]
MAX_VPN_CONFIG_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
QUERY_TIMEOUT_SECONDS = 6
ACTION_TIMEOUT_SECONDS = 20
_ACTION_LOCK = threading.Lock()
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
_INLINE_BLOCK_NAMES = frozenset({
    "ca", "cert", "crl-verify", "dh", "extra-certs", "key", "pkcs12", "secret",
    "tls-auth", "tls-crypt", "tls-crypt-v2",
})
_EXTERNAL_FILE_DIRECTIVES = frozenset({
    "askpass", "ca", "cd", "cert", "chroot", "client-config-dir", "client-connect",
    "client-disconnect", "config", "crl-verify", "dh", "extra-certs", "ifconfig-pool-persist",
    "key", "learn-address", "log", "log-append", "pkcs11-providers", "pkcs12", "plugin",
    "route-pre-down", "route-up", "secret", "status", "tls-auth", "tls-crypt", "tls-crypt-v2",
    "tls-export-cert", "tls-verify", "tmp-dir", "up", "down", "ipchange", "writepid",
    "auth-user-pass-verify", "http-proxy-user-pass", "management", "management-client",
    "management-external-key",
})
_INLINE_TAG = re.compile(r"^<(/?)([A-Za-z0-9_-]+)>$")


@dataclass(frozen=True, slots=True)
class VPNSource:
    requested_path: str
    canonical_path: Path
    file_name: str
    size_bytes: int
    snapshot: tuple[int, ...]
    sha256: str

    def payload(self) -> dict[str, object]:
        return {
            "canonical_path": str(self.canonical_path),
            "file_name": self.file_name,
            "size_bytes": self.size_bytes,
            "snapshot": list(self.snapshot),
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class VPNImportTarget:
    vpn_type: VPNType
    source: VPNSource
    profile_name: str
    profiles_before: tuple[NetworkManagerProfileInfo, ...]
    confirmation_phrase: str


def network_manager_vpn_import_available() -> bool:
    return sys.platform.startswith("linux") and bool(
        find_session_binary("nmcli", get_sanitized_env(dict(os.environ)))
    )


def _environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env


def _file_snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_source(raw_path: object) -> tuple[VPNSource | None, bytes | None, str | None]:
    if not isinstance(raw_path, str) or not raw_path.strip() or len(raw_path) > MAX_PATH_LENGTH:
        return None, None, f"source_path must be non-empty text with at most {MAX_PATH_LENGTH} characters."
    resolved, error = _resolve_path(raw_path)
    if error or resolved is None:
        return None, None, error or "The VPN source file could not be resolved."
    fd: int | None = None
    try:
        fd = _open_resolved_path(resolved, _READ_FLAGS)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            return None, None, "The VPN source must be a regular file."
        if before.st_size < 1 or before.st_size > MAX_VPN_CONFIG_BYTES:
            return None, None, f"The VPN source must contain 1 byte through {MAX_VPN_CONFIG_BYTES} bytes."
        chunks: list[bytes] = []
        remaining = MAX_VPN_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(fd)
        if _file_snapshot(before) != _file_snapshot(after) or len(payload) != before.st_size:
            return None, None, "The VPN source changed while it was being read."
        if b"\x00" in payload:
            return None, None, "The VPN source contains a NUL byte and is not accepted as a text configuration."
        source = VPNSource(
            requested_path=raw_path,
            canonical_path=resolved,
            file_name=resolved.name,
            size_bytes=len(payload),
            snapshot=_file_snapshot(after),
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        return source, payload, None
    except OSError as exc:
        return None, None, f"The VPN source could not be read: {exc.strerror or type(exc).__name__}."
    finally:
        if fd is not None:
            os.close(fd)


def _read_profile_inventory(
    binary: str,
    env: dict[str, str],
) -> tuple[tuple[NetworkManagerProfileInfo, ...] | None, str | None]:
    output, error, truncated = run_bounded_command(
        [
            binary,
            "--wait", str(QUERY_TIMEOUT_SECONDS),
            "--terse", "--escape", "yes", "--fields", "UUID,NAME,TYPE,DEVICE,AUTOCONNECT",
            "connection", "show",
        ],
        env,
        command_label="Complete NetworkManager profile inventory for VPN import",
        timeout_seconds=QUERY_TIMEOUT_SECONDS + 1,
        max_output_bytes=PROFILE_OUTPUT_BYTES,
    )
    if error or output is None:
        return None, "The complete NetworkManager profile inventory could not be read."
    if truncated:
        return None, "The NetworkManager profile inventory exceeded its output limit."
    rows = [row for row in output.splitlines() if row]
    if len(rows) > MAX_PROFILE_ROWS:
        return None, "The NetworkManager profile inventory exceeded its row limit."
    profiles: list[NetworkManagerProfileInfo] = []
    seen: set[str] = set()
    for row in rows:
        profile = _parse_profile_row(row)
        if profile is None or profile.uuid in seen:
            return None, "NetworkManager returned a malformed or duplicate profile row."
        seen.add(profile.uuid)
        profiles.append(profile)
    profiles.sort(key=lambda profile: (profile.uuid, profile.name.casefold()))
    return tuple(profiles), None


def _profile_payload(profile: NetworkManagerProfileInfo) -> dict[str, object]:
    return {
        "uuid": profile.uuid,
        "name": profile.name,
        "connection_type": profile.connection_type,
        "device": profile.device,
        "autoconnect": profile.autoconnect,
    }


def _normalize_request(
    vpn_type: object,
    source_path: object,
    profile_name: object,
) -> tuple[VPNType | None, VPNSource | None, str | None, bytes | None, str | None]:
    if vpn_type not in {"openvpn", "wireguard"}:
        return None, None, None, None, "vpn_type must be openvpn or wireguard."
    if (
        not isinstance(profile_name, str)
        or not profile_name.strip()
        or len(profile_name) > 128
        or profile_name.startswith("-")
        or any(not character.isprintable() for character in profile_name)
    ):
        return None, None, None, None, "profile_name must be 1-128 printable characters and cannot start with a dash."
    source, payload, error = _read_source(source_path)
    if error or source is None or payload is None:
        return None, None, None, None, error or "The VPN source file could not be verified."
    validation_error = _validate_self_contained_config(vpn_type, payload)
    if validation_error:
        return None, None, None, None, validation_error
    return vpn_type, source, profile_name, payload, None


def _validate_openvpn_config(payload: bytes) -> str | None:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError:
        return "The OpenVPN source must be UTF-8 text."
    inline_block: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        tag = _INLINE_TAG.fullmatch(line)
        if inline_block is not None:
            if tag and tag.group(1) == "/" and tag.group(2).casefold() == inline_block:
                inline_block = None
            continue
        if tag and not tag.group(1) and tag.group(2).casefold() in _INLINE_BLOCK_NAMES:
            inline_block = tag.group(2).casefold()
            continue
        try:
            lexer = shlex.shlex(line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#;"
            tokens = list(lexer)
        except ValueError:
            return "The OpenVPN source contains malformed quoting and was not imported."
        if not tokens:
            continue
        directive = tokens[0].removeprefix("--").casefold()
        if directive == "auth-user-pass" and len(tokens) == 1:
            # Without an argument OpenVPN requests credentials when activated;
            # it does not name a file to read during import.
            continue
        if directive in _EXTERNAL_FILE_DIRECTIVES or directive == "auth-user-pass":
            return (
                "This import accepts self-contained OpenVPN text configurations. "
                "Known external file, include, management-socket, or helper-command directives are refused."
            )
    if inline_block is not None:
        return "The OpenVPN source has an unterminated inline credential block."
    return None


def _validate_wireguard_config(payload: bytes) -> str | None:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError:
        return "The WireGuard source must be UTF-8 text."
    interface_allowed = {"PrivateKey", "Address", "DNS", "MTU", "ListenPort", "FwMark"}
    peer_allowed = {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}
    interface_values: dict[str, list[str]] = {}
    peers: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] | None = None
    current_kind: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.partition("#")[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if section == "Interface":
                if current_kind is not None or interface_values:
                    return "The WireGuard source must have one Interface section before its Peer sections."
                current = interface_values
                current_kind = "interface"
            elif section == "Peer" and current_kind is not None:
                current = {}
                peers.append(current)
                current_kind = "peer"
            else:
                return "The WireGuard source contains an unsupported or out-of-order section."
            continue
        if current is None or "=" not in line:
            return "The WireGuard source contains a setting outside a supported section or a malformed setting."
        key, value = (part.strip() for part in line.split("=", 1))
        allowed = interface_allowed if current_kind == "interface" else peer_allowed
        if key not in allowed or not value:
            return "The WireGuard source contains an unsupported setting or empty value. Shell hooks and file-based keys are not accepted."
        if key in current and key not in {"Address", "DNS"}:
            return "The WireGuard source repeats a single-value setting."
        current.setdefault(key, []).append(value)

    if not interface_values or len(peers) < 1 or len(peers) > 128:
        return "The WireGuard source must contain one Interface section and between 1 and 128 Peer sections."
    private_keys = interface_values.get("PrivateKey", [])
    if len(private_keys) != 1 or not _valid_wireguard_key(private_keys[0]):
        return "The WireGuard Interface must contain one valid 32-byte base64 PrivateKey."
    for list_key in ("Address", "DNS"):
        for raw_value in interface_values.get(list_key, []):
            values = [item.strip() for item in raw_value.split(",")]
            if not values or any(not item for item in values):
                return f"The WireGuard {list_key} setting is malformed."
            for item in values:
                try:
                    if list_key == "Address":
                        ipaddress.ip_interface(item)
                    else:
                        ipaddress.ip_address(item)
                except ValueError:
                    return f"The WireGuard {list_key} setting must contain literal IP addresses/prefixes."
    for key, minimum, maximum in (("MTU", 576, 65535), ("ListenPort", 0, 65535)):
        for value in interface_values.get(key, []):
            if not _integer_in_range(value, minimum, maximum):
                return f"The WireGuard {key} setting is outside its supported numeric range."
    for value in interface_values.get("FwMark", []):
        if value.casefold() == "off":
            continue
        try:
            number = int(value, 16 if value.lower().startswith("0x") else 10)
        except ValueError:
            return "The WireGuard FwMark setting must be off or a decimal or hexadecimal integer."
        if not 0 <= number <= 0xFFFFFFFF:
            return "The WireGuard FwMark setting is outside the 32-bit range."

    public_keys: set[str] = set()
    for peer in peers:
        public = peer.get("PublicKey", [])
        allowed_ips = peer.get("AllowedIPs", [])
        if len(public) != 1 or not _valid_wireguard_key(public[0]) or len(allowed_ips) != 1:
            return "Each WireGuard Peer must contain one valid PublicKey and one AllowedIPs setting."
        if public[0] in public_keys:
            return "The WireGuard source repeats a Peer PublicKey."
        public_keys.add(public[0])
        if peer.get("PresharedKey") and (
            len(peer["PresharedKey"]) != 1 or not _valid_wireguard_key(peer["PresharedKey"][0])
        ):
            return "A WireGuard Peer contains an invalid PresharedKey."
        ranges = [item.strip() for item in allowed_ips[0].split(",")]
        if not ranges or any(not item for item in ranges):
            return "A WireGuard Peer has malformed AllowedIPs."
        try:
            for item in ranges:
                ipaddress.ip_network(item, strict=False)
        except ValueError:
            return "A WireGuard Peer AllowedIPs setting must contain valid IP networks."
        if peer.get("Endpoint") and (
            len(peer["Endpoint"]) != 1 or not _valid_wireguard_endpoint(peer["Endpoint"][0])
        ):
            return "A WireGuard Peer Endpoint must be a literal IP or hostname with a valid port."
        if peer.get("PersistentKeepalive") and (
            len(peer["PersistentKeepalive"]) != 1
            or (
                peer["PersistentKeepalive"][0].casefold() != "off"
                and not _integer_in_range(peer["PersistentKeepalive"][0], 0, 65535)
            )
        ):
            return "A WireGuard Peer PersistentKeepalive setting is outside its supported range."
    return None


def _valid_wireguard_key(value: str) -> bool:
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, UnicodeError):
        return False


def _integer_in_range(value: str, minimum: int, maximum: int) -> bool:
    if not re.fullmatch(r"[0-9]+", value):
        return False
    number = int(value, 10)
    return minimum <= number <= maximum


def _valid_wireguard_endpoint(value: str) -> bool:
    if value.startswith("["):
        close = value.find("]")
        if close <= 1 or value[close + 1:close + 2] != ":":
            return False
        host, port_text = value[1:close], value[close + 2:]
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator or not host or ":" in host:
            return False
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            domain = host.rstrip(".")
            if len(domain) > 253 or not domain or any(
                not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in domain.split(".")
            ):
                return False
    return _integer_in_range(port_text, 1, 65535)


def _validate_self_contained_config(vpn_type: VPNType, payload: bytes) -> str | None:
    if vpn_type == "openvpn":
        return _validate_openvpn_config(payload)
    return _validate_wireguard_config(payload)


def network_manager_vpn_import_confirmation_details(
    vpn_type: str,
    source_path: str,
    profile_name: str,
) -> tuple[VPNImportTarget | None, str | None]:
    selected_type, source, selected_name, _payload, error = _normalize_request(vpn_type, source_path, profile_name)
    if error or selected_type is None or source is None or selected_name is None:
        return None, error or "The requested VPN import could not be validated."
    if not network_manager_vpn_import_available():
        return None, "NetworkManager VPN import requires Linux and nmcli."
    env = _environment()
    binary = find_session_binary("nmcli", env)
    if not binary:
        return None, "NetworkManager's nmcli command is unavailable."
    profiles, error = _read_profile_inventory(binary, env)
    if error or profiles is None:
        return None, error or "NetworkManager profile state could not be verified."
    if any(profile.name == selected_name for profile in profiles):
        return None, "A NetworkManager profile already uses that exact requested name."
    material = {
        "vpn_type": selected_type,
        "source": source.payload(),
        "profile_name": selected_name,
        "profiles_before": [_profile_payload(profile) for profile in profiles],
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()[:16]
    return VPNImportTarget(
        vpn_type=selected_type,
        source=source,
        profile_name=selected_name,
        profiles_before=profiles,
        confirmation_phrase=f"IMPORT {selected_type.upper()} {selected_name} {digest}",
    ), None


def _write_staged_source(payload: bytes, vpn_type: VPNType) -> str | None:
    fd: int | None = None
    path: str | None = None
    try:
        prefix, suffix = (
            ("linux-mcp-openvpn-", ".ovpn")
            if vpn_type == "openvpn"
            else ("linux-mcp-wireguard-", ".conf")
        )
        fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir="/tmp")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return path
    except OSError:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                pass
        return None


def _run_command(
    binary: str,
    arguments: list[str],
    env: dict[str, str],
    *,
    label: str,
    timeout: int,
) -> tuple[str | None, str | None, bool]:
    return run_bounded_command(
        [binary, *arguments],
        env,
        command_label=label,
        timeout_seconds=timeout,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


def _failure(
    vpn_type: str | None,
    profile_name: str | None,
    source_name: str | None,
    size_bytes: int | None,
    message: str,
    *,
    user_confirmed: bool,
    profile_uuid: str | None = None,
) -> NetworkManagerVPNImportResponse:
    return NetworkManagerVPNImportResponse(
        success=False,
        vpn_type=vpn_type,
        profile_name=profile_name,
        profile_uuid=profile_uuid,
        source_name=source_name,
        size_bytes=size_bytes,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_network_manager_vpn_import(
    vpn_type: str,
    source_path: str,
    profile_name: str,
    *,
    confirmed: bool,
    confirmed_vpn_type: str | None = None,
    confirmed_source_path: str | None = None,
    confirmed_profile_name: str | None = None,
    confirmed_phrase: str | None = None,
) -> NetworkManagerVPNImportResponse:
    target, error = network_manager_vpn_import_confirmation_details(vpn_type, source_path, profile_name)
    if error or target is None:
        return _failure(
            vpn_type if vpn_type in {"openvpn", "wireguard"} else None,
            profile_name if isinstance(profile_name, str) else None,
            None,
            None,
            error or "The requested VPN import could not be verified.",
            user_confirmed=confirmed is True,
        )
    source_name = target.source.file_name
    size_bytes = target.source.size_bytes
    if not confirmed:
        return _failure(
            target.vpn_type,
            target.profile_name,
            source_name,
            size_bytes,
            "Explicit client confirmation is required; no VPN profile was imported.",
            user_confirmed=False,
        )
    if (
        confirmed_vpn_type != target.vpn_type
        or confirmed_source_path != source_path
        or confirmed_profile_name != target.profile_name
        or confirmed_phrase != target.confirmation_phrase
    ):
        return _failure(
            target.vpn_type,
            target.profile_name,
            source_name,
            size_bytes,
            "Confirmation did not repeat the exact source, profile name, type, and state-bound phrase.",
            user_confirmed=True,
        )

    with _ACTION_LOCK:
        current, error = network_manager_vpn_import_confirmation_details(vpn_type, source_path, profile_name)
        if error or current is None or current.confirmation_phrase != target.confirmation_phrase:
            return _failure(
                target.vpn_type,
                target.profile_name,
                source_name,
                size_bytes,
                error or "The source file or NetworkManager profile inventory changed after confirmation; no import was run.",
                user_confirmed=True,
            )
        current_source, payload, source_error = _read_source(source_path)
        if (
            source_error
            or current_source is None
            or payload is None
            or current_source.payload() != current.source.payload()
        ):
            return _failure(
                target.vpn_type,
                target.profile_name,
                source_name,
                size_bytes,
                source_error or "The VPN source changed after confirmation; no import was run.",
                user_confirmed=True,
            )
        env = _environment()
        binary = find_session_binary("nmcli", env)
        if not binary:
            return _failure(
                target.vpn_type,
                target.profile_name,
                source_name,
                size_bytes,
                "NetworkManager's nmcli command became unavailable; no import was run.",
                user_confirmed=True,
            )
        staged_path = _write_staged_source(payload, target.vpn_type)
        if staged_path is None:
            return _failure(
                target.vpn_type,
                target.profile_name,
                source_name,
                size_bytes,
                "A private temporary copy of the confirmed VPN source could not be staged; no import was run.",
                user_confirmed=True,
            )
        try:
            _output, import_error, truncated = _run_command(
                binary,
                ["--wait", "12", "connection", "import", "type", target.vpn_type, "file", staged_path],
                env,
                label=f"Import confirmed {target.vpn_type} configuration into NetworkManager",
                timeout=ACTION_TIMEOUT_SECONDS,
            )
        finally:
            try:
                os.unlink(staged_path)
            except OSError:
                pass
        if import_error or _output is None or truncated:
            return _failure(
                target.vpn_type,
                target.profile_name,
                source_name,
                size_bytes,
                f"NetworkManager did not complete the {target.vpn_type} import. Inspect its profile inventory before retrying; command output is withheld.",
                user_confirmed=True,
            )
        profiles, read_error = _read_profile_inventory(binary, env)
        old_uuids = {profile.uuid for profile in current.profiles_before}
        created_profiles = [profile for profile in profiles or () if profile.uuid not in old_uuids]
        if (
            read_error
            or profiles is None
            or len(created_profiles) != 1
            or created_profiles[0].connection_type.casefold()
            != ("vpn" if target.vpn_type == "openvpn" else "wireguard")
            or created_profiles[0].device is not None
        ):
            return _failure(
                target.vpn_type,
                target.profile_name,
                source_name,
                size_bytes,
                "The import command ran, but NetworkManager did not produce exactly one inactive VPN profile. Inspect profiles before retrying.",
                user_confirmed=True,
            )
        created = created_profiles[0]
        before_rows = tuple(_profile_payload(profile) for profile in current.profiles_before)
        after_import_rows = tuple(_profile_payload(profile) for profile in profiles if profile.uuid != created.uuid)
        if len(profiles) != len(current.profiles_before) + 1 or before_rows != after_import_rows:
            return _failure(
                target.vpn_type,
                target.profile_name,
                source_name,
                size_bytes,
                "NetworkManager changed profile state outside the exact import; inspect profiles before retrying.",
                user_confirmed=True,
                profile_uuid=created.uuid,
            )
        _modify_output, modify_error, modify_truncated = _run_command(
            binary,
            [
                "--wait", "12", "connection", "modify", "uuid", created.uuid,
                "connection.id", current.profile_name,
                "connection.autoconnect", "no",
            ],
            env,
            label="Set confirmed imported VPN profile name and autoconnect state",
            timeout=ACTION_TIMEOUT_SECONDS,
        )
        if modify_error or _modify_output is None or modify_truncated:
            return _failure(
                target.vpn_type,
                target.profile_name,
                source_name,
                size_bytes,
                "The VPN profile was imported but its requested name or autoconnect setting could not be saved. Inspect it before retrying.",
                user_confirmed=True,
                profile_uuid=created.uuid,
            )
        final_profiles, verify_error = _read_profile_inventory(binary, env)
        if verify_error or final_profiles is None:
            return _failure(
                target.vpn_type,
                target.profile_name,
                source_name,
                size_bytes,
                "The VPN import completed, but the saved profile could not be verified. Inspect it before retrying.",
                user_confirmed=True,
                profile_uuid=created.uuid,
            )
        final_created = next((profile for profile in final_profiles if profile.uuid == created.uuid), None)
        final_old_rows = tuple(
            _profile_payload(profile) for profile in final_profiles if profile.uuid != created.uuid
        )
        verified = (
            final_created is not None
            and final_created.name == target.profile_name
            and final_created.connection_type.casefold()
            == ("vpn" if target.vpn_type == "openvpn" else "wireguard")
            and final_created.device is None
            and final_created.autoconnect is False
            and final_old_rows == before_rows
            and len(final_profiles) == len(current.profiles_before) + 1
        )
        if not verified:
            return _failure(
                target.vpn_type,
                target.profile_name,
                source_name,
                size_bytes,
                "The imported profile exists but its final saved identity or inactive state did not match; inspect it before activation.",
                user_confirmed=True,
                profile_uuid=created.uuid,
            )
        return NetworkManagerVPNImportResponse(
            success=True,
            vpn_type=target.vpn_type,
            profile_name=target.profile_name,
            profile_uuid=created.uuid,
            source_name=source_name,
            size_bytes=size_bytes,
            user_confirmed=True,
            message=(
                f"Imported and verified one persistent {target.vpn_type} profile. It remains inactive with autoconnect disabled; "
                "NetworkManager profile secrets were not queried or returned. The imported configuration may contain "
                "private keys or credentials stored by NetworkManager."
            ),
        )
