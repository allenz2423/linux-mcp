"""Read-only, credential-free NetworkManager connection-profile inventory."""

from __future__ import annotations

import re
import sys
import uuid as uuid_module

from wayland_mcp.models import NetworkManagerProfileInfo, NetworkManagerProfileListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_SCAN_ROWS = 5_000
MAX_RESULT_ROWS = 500
COMMAND_TIMEOUT_SECONDS = 5
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _split_terse_row(row: str) -> list[str] | None:
    fields: list[str] = []
    field: list[str] = []
    escaped = False
    for character in row:
        if escaped:
            if character not in {"\\", ":"}:
                return None
            field.append(character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(field))
            field.clear()
        elif not character.isprintable():
            return None
        else:
            field.append(character)
    if escaped:
        return None
    fields.append("".join(field))
    return fields if len(fields) == 5 else None


def _parse_profile_row(row: str) -> NetworkManagerProfileInfo | None:
    fields = _split_terse_row(row)
    if fields is None:
        return None
    raw_uuid, name, connection_type, device, autoconnect = fields
    if not UUID_PATTERN.fullmatch(raw_uuid) or not name or not connection_type:
        return None
    try:
        profile_uuid = str(uuid_module.UUID(raw_uuid))
    except ValueError:
        return None
    if len(name) > 256 or len(connection_type) > 64 or len(device) > 64:
        return None
    autoconnect_value = autoconnect.casefold()
    parsed_autoconnect = True if autoconnect_value in {"yes", "true"} else False if autoconnect_value in {"no", "false"} else None
    return NetworkManagerProfileInfo(
        uuid=profile_uuid,
        name=name,
        connection_type=connection_type,
        device=None if device in {"", "--"} else device,
        autoconnect=parsed_autoconnect,
    )


def list_network_manager_profiles(
    query: str = "",
    limit: int = 100,
) -> NetworkManagerProfileListResponse:
    """List selected NetworkManager profile metadata without reading secrets."""
    if not sys.platform.startswith("linux"):
        return NetworkManagerProfileListResponse(
            success=False,
            message="NetworkManager profile inventory is available only on Linux.",
        )
    if not isinstance(query, str) or len(query) > 256:
        return NetworkManagerProfileListResponse(
            success=False,
            message="Query must be text with at most 256 characters.",
        )
    if any(not character.isprintable() for character in query):
        return NetworkManagerProfileListResponse(
            success=False,
            message="Query cannot contain control characters.",
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        return NetworkManagerProfileListResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RESULT_ROWS))

    env = get_sanitized_env()
    env["LC_ALL"] = "C"
    nmcli = find_session_binary("nmcli", env)
    if not nmcli:
        return NetworkManagerProfileListResponse(
            success=False,
            limit=limit,
            message="NetworkManager's nmcli command is unavailable.",
        )

    output, error, output_truncated = run_bounded_command(
        [
            nmcli,
            "--wait", "4",
            "--terse",
            "--escape", "yes",
            "--fields", "UUID,NAME,TYPE,DEVICE,AUTOCONNECT",
            "connection", "show",
        ],
        env,
        command_label="NetworkManager connection-profile inventory",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if output is None:
        return NetworkManagerProfileListResponse(
            success=False,
            limit=limit,
            truncated=output_truncated,
            message=error or "NetworkManager connection profiles could not be read.",
        )

    profiles: list[NetworkManagerProfileInfo] = []
    malformed_rows = 0
    scan_truncated = output_truncated
    rows = output.splitlines()
    if len(rows) > MAX_SCAN_ROWS:
        rows = rows[:MAX_SCAN_ROWS]
        scan_truncated = True
    query_key = query.strip().casefold()
    for row in rows:
        if not row:
            continue
        profile = _parse_profile_row(row)
        if profile is None:
            malformed_rows += 1
            continue
        searchable = " ".join((profile.uuid, profile.name, profile.connection_type, profile.device or "")).casefold()
        if not query_key or query_key in searchable:
            profiles.append(profile)
    profiles.sort(key=lambda item: (item.name.casefold(), item.uuid))
    truncated = scan_truncated or len(profiles) > limit or malformed_rows > 0
    message_parts = [
        "Only UUID, profile name, type, attached device, and autoconnect state are requested; secret fields are not queried."
    ]
    if error:
        message_parts.append(error)
    if malformed_rows:
        message_parts.append(f"Skipped {malformed_rows} malformed profile rows.")
    if scan_truncated:
        message_parts.append("The nmcli output or profile scan reached its configured bound.")
    if len(profiles) > limit:
        message_parts.append(f"Results capped at {limit} profiles.")
    return NetworkManagerProfileListResponse(
        success=True,
        total_profiles=len(profiles),
        returned_profiles=min(len(profiles), limit),
        profiles=profiles[:limit],
        limit=limit,
        truncated=truncated,
        malformed_rows=malformed_rows,
        message=" ".join(message_parts),
    )
