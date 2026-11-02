"""Bounded read-only status for chrony and systemd-timesyncd."""

from __future__ import annotations

import re
import sys

from wayland_mcp.models import TimeSyncProviderStatus, TimeSyncStatusResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.host import _detect_init_system

TIMEOUT_SECONDS = 5
MAX_OUTPUT_BYTES = 64 * 1024
MAX_SCAN_LINES = 512
MAX_LINE_LENGTH = 1_024
MAX_PROPERTIES = 32
MAX_SOURCES = 128
MAX_VALUE_LENGTH = 512
TIMESYNCD_PROPERTIES = (
    "ServerName",
    "ServerAddress",
    "LinkNTPServers",
    "SystemNTPServers",
    "RuntimeNTPServers",
    "FallbackNTPServers",
    "RootDistanceMaxUSec",
    "PollIntervalMinUSec",
    "PollIntervalMaxUSec",
    "PollIntervalUSec",
    "Frequency",
)
TIMESYNCD_CORE_PROPERTIES = (
    "ServerName",
    "ServerAddress",
    "RootDistanceMaxUSec",
    "PollIntervalMinUSec",
    "PollIntervalMaxUSec",
    "PollIntervalUSec",
    "Frequency",
)
CHRONY_TRACKING_FIELDS = {
    "Reference ID",
    "Stratum",
    "Ref time (UTC)",
    "System time",
    "Last offset",
    "RMS offset",
    "Frequency",
    "Residual freq",
    "Skew",
    "Root delay",
    "Root dispersion",
    "Update interval",
    "Leap status",
}
CHRONY_SOURCE_RE = re.compile(r"^([\^=#][*?+\-x~])\s+(\S+)(?:\s+(.*))?$")


def _environment() -> dict[str, str]:
    env = get_sanitized_env()
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    env["SYSTEMD_PAGER"] = "cat"
    env["PAGER"] = "cat"
    return env


def _available_commands(env: dict[str, str]) -> dict[str, str | None]:
    if not sys.platform.startswith("linux"):
        return {"chrony": None, "systemd-timesyncd": None}
    chronyc = find_session_binary("chronyc", env)
    timedatectl = (
        find_session_binary("timedatectl", env)
        if _detect_init_system() == "systemd"
        else None
    )
    return {"chrony": chronyc, "systemd-timesyncd": timedatectl}


def time_sync_status_available(env: dict[str, str] | None = None) -> bool:
    """Report whether a supported local time-sync query client is installed."""
    return any(_available_commands(env or _environment()).values())


def _run(
    binary: str,
    arguments: list[str],
    *,
    label: str,
    env: dict[str, str],
) -> tuple[str | None, str | None, bool]:
    return run_bounded_command(
        [binary, *arguments],
        env,
        command_label=label,
        timeout_seconds=TIMEOUT_SECONDS,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


def _clean(value: str) -> tuple[str, bool]:
    cleaned = "".join(character for character in value if character.isprintable()).strip()
    return cleaned[:MAX_VALUE_LENGTH], len(cleaned) > MAX_VALUE_LENGTH


def _parse_timesyncd_properties(output: str) -> tuple[dict[str, str], int, bool]:
    properties: dict[str, str] = {}
    malformed = 0
    truncated = False
    lines = output.splitlines()
    if len(lines) > MAX_SCAN_LINES:
        lines = lines[:MAX_SCAN_LINES]
        truncated = True
    allowed = set(TIMESYNCD_PROPERTIES)
    for line in lines:
        if len(line) > MAX_LINE_LENGTH:
            malformed += 1
            continue
        key, separator, raw_value = line.partition("=")
        if not separator or key not in allowed:
            malformed += 1
            continue
        if key in properties:
            malformed += 1
            continue
        value, clipped = _clean(raw_value)
        properties[key] = value
        truncated = truncated or clipped
        if len(properties) > MAX_PROPERTIES:
            truncated = True
            break
    return properties, malformed, truncated


def _parse_chrony_tracking(output: str) -> tuple[dict[str, str], int, bool]:
    properties: dict[str, str] = {}
    malformed = 0
    truncated = False
    lines = output.splitlines()
    if len(lines) > MAX_SCAN_LINES:
        lines = lines[:MAX_SCAN_LINES]
        truncated = True
    for line in lines:
        if len(line) > MAX_LINE_LENGTH:
            malformed += 1
            continue
        key, separator, raw_value = line.partition(":")
        key = key.strip()
        if not separator or key not in CHRONY_TRACKING_FIELDS:
            continue
        if key in properties:
            malformed += 1
            continue
        value, clipped = _clean(raw_value)
        properties[key] = value
        truncated = truncated or clipped
        if len(properties) > MAX_PROPERTIES:
            truncated = True
            break
    return properties, malformed, truncated


def _parse_chrony_sources(output: str) -> tuple[list[str], int, bool]:
    sources: list[str] = []
    malformed = 0
    truncated = False
    lines = output.splitlines()
    if len(lines) > MAX_SCAN_LINES:
        lines = lines[:MAX_SCAN_LINES]
        truncated = True
    for line in lines:
        if not line.strip() or line.lstrip().startswith(("MS ", "Number of sources")):
            continue
        if set(line.strip()) <= {"=", "-"}:
            continue
        if len(line) > MAX_LINE_LENGTH:
            malformed += 1
            continue
        match = CHRONY_SOURCE_RE.fullmatch(line.strip())
        if not match:
            malformed += 1
            continue
        marker, name, metrics = match.groups()
        name, name_clipped = _clean(name)
        metrics, metrics_clipped = _clean(metrics or "")
        if not name:
            malformed += 1
            continue
        sources.append(" ".join(part for part in (marker, name, metrics) if part))
        truncated = truncated or name_clipped or metrics_clipped
        if len(sources) >= MAX_SOURCES:
            truncated = True
            break
    return sources, malformed, truncated


def _read_chrony(binary: str, env: dict[str, str]) -> TimeSyncProviderStatus:
    tracking_output, tracking_error, tracking_truncated = _run(
        binary,
        ["-n", "tracking"],
        label="chronyc tracking status query",
        env=env,
    )
    source_output, source_error, source_truncated = _run(
        binary,
        ["-n", "sources"],
        label="chronyc source status query",
        env=env,
    )
    properties: dict[str, str] = {}
    sources: list[str] = []
    malformed = 0
    parse_truncated = False
    if tracking_output is not None:
        properties, bad_tracking, tracking_parse_truncated = _parse_chrony_tracking(tracking_output)
        malformed += bad_tracking
        parse_truncated = parse_truncated or tracking_parse_truncated
    if source_output is not None:
        sources, bad_sources, sources_parse_truncated = _parse_chrony_sources(source_output)
        malformed += bad_sources
        parse_truncated = parse_truncated or sources_parse_truncated
    successful_queries = sum(output is not None for output in (tracking_output, source_output))
    partial = (
        successful_queries < 2
        or malformed > 0
        or tracking_truncated
        or source_truncated
        or parse_truncated
    )
    messages = [error for error in (tracking_error, source_error) if error]
    if not properties and tracking_output is not None:
        messages.append("chronyc tracking returned no recognized status fields.")
        partial = True
    return TimeSyncProviderStatus(
        provider="chrony",
        available=True,
        success=successful_queries > 0,
        partial=partial,
        properties=properties,
        sources=sources,
        malformed_records=malformed,
        truncated=tracking_truncated or source_truncated or parse_truncated,
        message=" ".join(messages) if messages else None,
    )


def _read_timesyncd(binary: str, env: dict[str, str]) -> TimeSyncProviderStatus:
    arguments = ["--no-pager", "show-timesync"]
    arguments.extend(f"--property={name}" for name in TIMESYNCD_PROPERTIES)
    output, error, command_truncated = _run(
        binary,
        arguments,
        label="systemd-timesyncd status query",
        env=env,
    )
    optional_properties_error: str | None = None
    if output is None and not command_truncated:
        optional_properties_error = error
        core_arguments = ["--no-pager", "show-timesync"]
        core_arguments.extend(f"--property={name}" for name in TIMESYNCD_CORE_PROPERTIES)
        output, error, fallback_truncated = _run(
            binary,
            core_arguments,
            label="systemd-timesyncd core status query",
            env=env,
        )
        command_truncated = command_truncated or fallback_truncated
    properties: dict[str, str] = {}
    malformed = 0
    parse_truncated = False
    if output is not None:
        properties, malformed, parse_truncated = _parse_timesyncd_properties(output)
    success = output is not None
    partial = command_truncated or malformed > 0 or parse_truncated or not properties or optional_properties_error is not None
    if success and not properties:
        error = "systemd-timesyncd returned no recognized status properties."
    elif success and optional_properties_error:
        error = "Some configured-server properties were unavailable; core active-server status was read."
    return TimeSyncProviderStatus(
        provider="systemd-timesyncd",
        available=True,
        success=success,
        partial=partial,
        properties=properties,
        sources=[],
        malformed_records=malformed,
        truncated=command_truncated or parse_truncated,
        message=error,
    )


def get_time_sync_status() -> TimeSyncStatusResponse:
    """Read provider status and bounded current source information where available."""
    env = _environment()
    commands = _available_commands(env)
    if not sys.platform.startswith("linux"):
        return TimeSyncStatusResponse(success=False, message="Time synchronization status is available only on Linux.")
    providers: list[TimeSyncProviderStatus] = []
    if commands["chrony"]:
        providers.append(_read_chrony(commands["chrony"], env))
    if commands["systemd-timesyncd"]:
        providers.append(_read_timesyncd(commands["systemd-timesyncd"], env))
    if not providers:
        return TimeSyncStatusResponse(
            success=False,
            message="Neither chronyc nor systemd timedatectl is available for time synchronization status.",
        )
    successful = sum(provider.success for provider in providers)
    return TimeSyncStatusResponse(
        success=successful > 0,
        providers=providers,
        message=None if successful else "Supported time synchronization providers could not be queried.",
    )
