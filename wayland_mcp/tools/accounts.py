"""Bounded inventory of local Linux users and groups."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    LocalGroupInfo,
    LocalGroupListResponse,
    LocalUserInfo,
    LocalUserListResponse,
    NSSGroupInfo,
    NSSIdentityLookupResponse,
    NSSUserInfo,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_ACCOUNT_FILE_BYTES = 4 * 1024 * 1024
MAX_ACCOUNT_RECORDS = 20_000
MAX_ACCOUNT_RECORD_BYTES = 64 * 1024
MAX_ACCOUNT_RESULTS = 200
MAX_GROUP_MEMBERS = 128
MAX_NAME_LENGTH = 128
NSS_LOOKUP_TIMEOUT_SECONDS = 6
MAX_NSS_LOOKUP_BYTES = 64 * 1024
MAX_NSS_IDENTITY_LENGTH = 256


def _read_records(path: Path) -> tuple[list[str] | None, bool, str | None]:
    lines: list[str] = []
    bytes_read = 0
    truncated = False
    try:
        with path.open("rb") as stream:
            while len(lines) < MAX_ACCOUNT_RECORDS:
                remaining = MAX_ACCOUNT_FILE_BYTES - bytes_read
                if remaining <= 0:
                    truncated = bool(stream.read(1))
                    break
                raw_line = stream.readline(min(MAX_ACCOUNT_RECORD_BYTES + 1, remaining + 1))
                if not raw_line:
                    break
                if len(raw_line) > remaining or len(raw_line) > MAX_ACCOUNT_RECORD_BYTES:
                    truncated = True
                    break
                bytes_read += len(raw_line)
                lines.append(raw_line.decode("utf-8", errors="replace").rstrip("\r\n"))
                if bytes_read == MAX_ACCOUNT_FILE_BYTES:
                    truncated = bool(stream.read(1))
                    break
            if len(lines) == MAX_ACCOUNT_RECORDS and stream.read(1):
                truncated = True
    except OSError as exc:
        return None, False, f"Could not read {path}: {exc.strerror or 'read error'}."
    return lines, truncated, None


def _safe_name(value: str) -> str | None:
    if value != value.strip():
        return None
    if not value or len(value) > MAX_NAME_LENGTH or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value


def _bounded_query_and_limit(query: str, limit: int) -> tuple[str | None, int | None, str | None]:
    if not isinstance(query, str) or len(query) > 256:
        return None, None, "Query must be text with at most 256 characters."
    if not isinstance(limit, int) or isinstance(limit, bool):
        return None, None, "Limit must be an integer."
    return query.strip().casefold(), max(1, min(limit, MAX_ACCOUNT_RESULTS)), None


def list_local_users(query: str = "", limit: int = 100) -> LocalUserListResponse:
    if not sys.platform.startswith("linux"):
        return LocalUserListResponse(success=False, message="Local account inventory is available only on Linux.")
    needle, bounded_limit, error = _bounded_query_and_limit(query, limit)
    if error or needle is None or bounded_limit is None:
        return LocalUserListResponse(success=False, message=error)

    lines, truncated, error = _read_records(Path("/etc/passwd"))
    if lines is None:
        return LocalUserListResponse(success=False, message=error)

    users: list[LocalUserInfo] = []
    for line in lines:
        fields = line.split(":")
        if len(fields) != 7:
            continue
        username = _safe_name(fields[0])
        try:
            uid, primary_gid = int(fields[2]), int(fields[3])
        except ValueError:
            continue
        if username is None or uid < 0 or primary_gid < 0:
            continue
        if needle and needle not in username.casefold() and needle not in str(uid) and needle not in str(primary_gid):
            continue
        users.append(LocalUserInfo(username=username, uid=uid, primary_gid=primary_gid))

    users.sort(key=lambda item: (item.username.casefold(), item.uid))
    message = "Local /etc/passwd entries only; NSS, LDAP, and other external identity sources are not queried."
    if truncated:
        message += " The account file scan reached its size or record limit."
    return LocalUserListResponse(
        success=True,
        total_users=len(users),
        returned_users=min(len(users), bounded_limit),
        users=users[:bounded_limit],
        limit=bounded_limit,
        truncated=truncated or len(users) > bounded_limit,
        message=message,
    )


def list_local_groups(query: str = "", limit: int = 100) -> LocalGroupListResponse:
    if not sys.platform.startswith("linux"):
        return LocalGroupListResponse(success=False, message="Local account inventory is available only on Linux.")
    needle, bounded_limit, error = _bounded_query_and_limit(query, limit)
    if error or needle is None or bounded_limit is None:
        return LocalGroupListResponse(success=False, message=error)

    lines, truncated, error = _read_records(Path("/etc/group"))
    if lines is None:
        return LocalGroupListResponse(success=False, message=error)

    groups: list[LocalGroupInfo] = []
    for line in lines:
        fields = line.split(":")
        if len(fields) != 4:
            continue
        name = _safe_name(fields[0])
        try:
            gid = int(fields[2])
        except ValueError:
            continue
        if name is None or gid < 0:
            continue
        if needle and needle not in name.casefold() and needle not in str(gid):
            continue
        members = [member for raw in fields[3].split(",") if (member := _safe_name(raw)) is not None]
        groups.append(LocalGroupInfo(
            name=name,
            gid=gid,
            members=members[:MAX_GROUP_MEMBERS],
            member_count=len(members),
            members_truncated=len(members) > MAX_GROUP_MEMBERS,
        ))

    groups.sort(key=lambda item: (item.name.casefold(), item.gid))
    message = "Local /etc/group entries only; NSS, LDAP, and other external identity sources are not queried."
    if truncated:
        message += " The group file scan reached its size or record limit."
    return LocalGroupListResponse(
        success=True,
        total_groups=len(groups),
        returned_groups=min(len(groups), bounded_limit),
        groups=groups[:bounded_limit],
        limit=bounded_limit,
        truncated=truncated or len(groups) > bounded_limit,
        message=message,
    )


def lookup_nss_identity(kind: Literal["user", "group"], identity: str) -> NSSIdentityLookupResponse:
    """Resolve one exact passwd/group key using the configured system NSS stack."""
    if not sys.platform.startswith("linux"):
        return NSSIdentityLookupResponse(
            success=False,
            kind=str(kind),
            identity=identity if isinstance(identity, str) else "",
            message="NSS identity lookup is available only on Linux.",
        )
    if not isinstance(kind, str) or kind not in {"user", "group"}:
        return NSSIdentityLookupResponse(
            success=False,
            kind=str(kind),
            identity=identity if isinstance(identity, str) else "",
            message="Kind must be 'user' or 'group'.",
        )
    if (
        not isinstance(identity, str)
        or not identity
        or len(identity) > MAX_NSS_IDENTITY_LENGTH
        or identity != identity.strip()
        or identity.startswith("-")
        or ":" in identity
        or any(ord(char) < 32 or ord(char) == 127 for char in identity)
    ):
        return NSSIdentityLookupResponse(
            success=False,
            kind=kind,
            identity=identity[:MAX_NSS_IDENTITY_LENGTH] if isinstance(identity, str) else "",
            message="Identity must be a non-empty NSS name or numeric ID up to 256 characters, without control characters or colons.",
        )

    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    getent = find_session_binary("getent", env)
    if not getent:
        return NSSIdentityLookupResponse(
            success=False,
            kind=kind,
            identity=identity,
            message="The optional getent command is unavailable.",
        )

    database = "passwd" if kind == "user" else "group"
    output, error, output_truncated = run_bounded_command(
        [getent, database, identity],
        env,
        command_label="NSS identity lookup",
        timeout_seconds=NSS_LOOKUP_TIMEOUT_SECONDS,
        max_output_bytes=MAX_NSS_LOOKUP_BYTES,
    )
    if output is None:
        if error and error.rstrip().endswith("status 2."):
            return NSSIdentityLookupResponse(
                success=True,
                kind=kind,
                identity=identity,
                found=False,
                message="No matching record was returned by the configured NSS sources.",
            )
        return NSSIdentityLookupResponse(
            success=False,
            kind=kind,
            identity=identity,
            message="The configured NSS sources could not complete this lookup; a remote directory may be unavailable or access may be restricted.",
        )
    if output_truncated:
        return NSSIdentityLookupResponse(
            success=False,
            kind=kind,
            identity=identity,
            message="The NSS response exceeded the output limit; no partial identity was returned.",
        )

    lines = output.splitlines()
    if len(lines) != 1:
        return NSSIdentityLookupResponse(
            success=False,
            kind=kind,
            identity=identity,
            message="The NSS lookup returned no record or an unexpected number of records.",
        )
    fields = lines[0].split(":")
    if kind == "user" and len(fields) == 7:
        username = _safe_name(fields[0])
        try:
            uid, primary_gid = int(fields[2]), int(fields[3])
        except ValueError:
            username = None
            uid = primary_gid = -1
        if username is None or uid < 0 or primary_gid < 0:
            return NSSIdentityLookupResponse(
                success=False,
                kind=kind,
                identity=identity,
                message="The NSS passwd response was malformed; sensitive passwd fields were discarded.",
            )
        return NSSIdentityLookupResponse(
            success=True,
            kind=kind,
            identity=identity,
            found=True,
            user=NSSUserInfo(username=username, uid=uid, primary_gid=primary_gid),
            message="Resolved through the configured NSS stack. Password, GECOS, home-directory, and shell fields are omitted.",
        )
    if kind == "group" and len(fields) == 4:
        name = _safe_name(fields[0])
        try:
            gid = int(fields[2])
        except ValueError:
            name = None
            gid = -1
        if name is None or gid < 0:
            return NSSIdentityLookupResponse(
                success=False,
                kind=kind,
                identity=identity,
                message="The NSS group response was malformed; password fields were discarded.",
            )
        members = [member for raw in fields[3].split(",") if (member := _safe_name(raw)) is not None]
        return NSSIdentityLookupResponse(
            success=True,
            kind=kind,
            identity=identity,
            found=True,
            group=NSSGroupInfo(
                name=name,
                gid=gid,
                members=members[:MAX_GROUP_MEMBERS],
                member_count=len(members),
                members_truncated=len(members) > MAX_GROUP_MEMBERS,
            ),
            message="Resolved through the configured NSS stack. Password fields are omitted.",
        )
    return NSSIdentityLookupResponse(
        success=False,
        kind=kind,
        identity=identity,
        message="The NSS response did not match the expected passwd or group record format.",
    )
