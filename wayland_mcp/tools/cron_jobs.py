"""Bounded schedule-only inventory for cron, Anacron, and at jobs."""

from __future__ import annotations

import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Iterable, Literal

from wayland_mcp.models import CronJobInfo, CronJobListResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

MAX_RETURNED_JOBS = 500
MAX_JOB_ROWS = 10_000
MAX_TOTAL_JOBS = 10_000
MAX_CRON_D_FILES = 128
MAX_CRON_D_ENTRIES = 2_048
MAX_CONFIG_FILE_BYTES = 256 * 1024
MAX_TOTAL_CONFIG_BYTES = 2 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 5
CRON_D_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
ANACRON_PERIODS = {"@daily", "@weekly", "@monthly"}
MAX_MESSAGES = 24


def _read_fixed_config(path: Path, byte_budget: int) -> tuple[str | None, int, str | None]:
    """Read one fixed regular config file without following a final symlink."""
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None, 0, "not a regular file"
        limit = min(MAX_CONFIG_FILE_BYTES, max(0, byte_budget))
        if info.st_size > limit:
            return None, 0, "file exceeds the bounded read size"
        contents = bytearray()
        while len(contents) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
        if len(contents) > limit:
            return None, 0, "file grew beyond the bounded read size"
        return contents.decode("utf-8", errors="replace"), len(contents), None
    except FileNotFoundError:
        return None, 0, None
    except (OSError, ValueError) as exc:
        reason = getattr(exc, "strerror", None) or type(exc).__name__
        return None, 0, reason
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _safe_text(value: str, maximum: int) -> str:
    return "".join(character for character in value if unicodedata.category(character) not in {"Cc", "Cf", "Cs"})[:maximum]


def _cron_jobs_from_text(
    text: str,
    *,
    source: str,
    system_crontab: bool,
) -> tuple[list[CronJobInfo], int]:
    jobs: list[CronJobInfo] = []
    malformed = 0
    cron_timezone: str | None = None
    scheduling_settings: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ENV_ASSIGNMENT_RE.match(line):
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
            if match and match.group(1) in {"CRON_TZ", "RANDOM_DELAY"}:
                key, raw_value = match.groups()
                safe_value = _safe_text(raw_value, 128)
                scheduling_settings[key] = safe_value
                if key == "CRON_TZ":
                    cron_timezone = safe_value or None
            continue
        # Cronie allows a leading '-' to suppress the usual execution log entry.
        if line.startswith("-"):
            line = line[1:].lstrip()
        if line.startswith("@"):
            fields = line.split(None, 2 if system_crontab else 1)
            required = 3 if system_crontab else 2
            if len(fields) < required:
                malformed += 1
                continue
            schedule = _safe_text(fields[0], 512)
            user = _safe_text(fields[1], 256) if system_crontab else None
        else:
            fields = line.split(None, 6 if system_crontab else 5)
            required = 7 if system_crontab else 6
            if len(fields) < required:
                malformed += 1
                continue
            schedule = _safe_text(" ".join(fields[:5]), 512)
            user = _safe_text(fields[5], 256) if system_crontab else None
        jobs.append(CronJobInfo(
            scheduler="cron",
            source=source,
            schedule=schedule,
            user=user,
            line_number=line_number,
            timezone=cron_timezone,
            schedule_settings=[f"{key}={value}" for key, value in scheduling_settings.items()],
        ))
        if len(jobs) >= MAX_JOB_ROWS:
            break
    return jobs, malformed


def _anacron_jobs_from_text(text: str, source: str) -> tuple[list[CronJobInfo], int]:
    jobs: list[CronJobInfo] = []
    malformed = 0
    scheduling_settings: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ENV_ASSIGNMENT_RE.match(line):
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
            if match and match.group(1) in {"START_HOURS_RANGE", "RANDOM_DELAY"}:
                key, raw_value = match.groups()
                scheduling_settings[key] = _safe_text(raw_value, 128)
            continue
        fields = line.split(None, 3)
        if len(fields) < 4:
            malformed += 1
            continue
        period, delay, identifier = fields[:3]
        if len(period) > 32 or len(delay) > 32 or len(identifier) > 256:
            malformed += 1
            continue
        numeric_period = period.isascii() and period.isdigit() and int(period) > 0
        if not (numeric_period or period in ANACRON_PERIODS) or not (delay.isascii() and delay.isdigit()):
            malformed += 1
            continue
        jobs.append(CronJobInfo(
            scheduler="anacron",
            source=source,
            schedule=_safe_text(f"period {period}; delay {delay} minutes", 512),
            line_number=line_number,
            job_id=_safe_text(identifier, 256),
            schedule_settings=[f"{key}={value}" for key, value in scheduling_settings.items()],
        ))
        if len(jobs) >= MAX_JOB_ROWS:
            break
    return jobs, malformed


def _at_jobs_from_output(output: str) -> tuple[list[CronJobInfo], int, bool]:
    jobs: list[CronJobInfo] = []
    malformed = 0
    truncated = False
    for line_number, line in enumerate(output.splitlines(), start=1):
        if line_number > MAX_JOB_ROWS:
            truncated = True
            break
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 8 or not fields[0].isascii() or not fields[0].isdigit():
            malformed += 1
            continue
        jobs.append(CronJobInfo(
            scheduler="at",
            source="at queue",
            schedule=_safe_text(" ".join(fields[1:6]), 256),
            job_id=_safe_text(fields[0], 64),
            queue=_safe_text(fields[6], 16),
            user=_safe_text(fields[7], 256),
        ))
    return jobs, malformed, truncated


def _filter_jobs(jobs: Iterable[CronJobInfo], query: str) -> list[CronJobInfo]:
    needle = query.strip().casefold()
    selected = list(jobs)
    if not needle:
        return selected
    return [
        job for job in selected
        if needle in " ".join((job.scheduler, job.source, job.schedule, job.user or "", job.job_id or "", job.queue or "", job.timezone or "", *job.schedule_settings)).casefold()
    ]


def _extend_bounded_jobs(target: list[CronJobInfo], incoming: list[CronJobInfo]) -> bool:
    remaining = max(0, MAX_TOTAL_JOBS - len(target))
    target.extend(incoming[:remaining])
    return len(incoming) > remaining or len(target) >= MAX_TOTAL_JOBS


def list_cron_jobs(query: str = "", limit: int = 200) -> CronJobListResponse:
    """Read supported cron/Anacron schedules and visible at-queue metadata.

    Command bodies are parsed only to identify schedule metadata and are never
    included in the returned model. Only the current user's individual
    crontab is queried; system crontabs are read from fixed /etc paths.
    """
    if not sys.platform.startswith("linux"):
        return CronJobListResponse(success=False, message="Cron and Anacron inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256:
        return CronJobListResponse(success=False, message="Query must be text with at most 256 characters.")
    try:
        bounded_limit = max(1, min(int(limit), MAX_RETURNED_JOBS))
    except (TypeError, ValueError, OverflowError):
        return CronJobListResponse(success=False, message="Limit must be an integer from 1 to 500.")

    jobs: list[CronJobInfo] = []
    sources_checked: list[str] = []
    messages: list[str] = []
    malformed_rows = 0
    config_bytes = 0
    rows_truncated = False

    fixed_cron_files = (Path("/etc/crontab"), Path("/etc/anacrontab"))
    for path in fixed_cron_files:
        contents, read_bytes, error = _read_fixed_config(path, MAX_TOTAL_CONFIG_BYTES - config_bytes)
        config_bytes += read_bytes
        if error:
            sources_checked.append(str(path))
            messages.append(f"Could not inspect {path}: {error}.")
            continue
        if contents is None:
            continue
        sources_checked.append(str(path))
        if path.name == "anacrontab":
            parsed, malformed = _anacron_jobs_from_text(contents, str(path))
        else:
            parsed, malformed = _cron_jobs_from_text(
                contents,
                source=str(path),
                system_crontab=True,
            )
        rows_truncated |= _extend_bounded_jobs(jobs, parsed)
        malformed_rows += malformed
        rows_truncated |= len(parsed) >= MAX_JOB_ROWS

    cron_d = Path("/etc/cron.d")
    cron_d_files: list[Path] = []
    try:
        with os.scandir(cron_d) as entries:
            sources_checked.append(str(cron_d))
            for index, entry in enumerate(entries, start=1):
                if index > MAX_CRON_D_ENTRIES:
                    rows_truncated = True
                    break
                if not CRON_D_NAME_RE.fullmatch(entry.name):
                    continue
                try:
                    if entry.is_file(follow_symlinks=False):
                        cron_d_files.append(cron_d / entry.name)
                except OSError:
                    continue
    except FileNotFoundError:
        pass
    except OSError as exc:
        sources_checked.append(str(cron_d))
        messages.append(f"Could not inspect {cron_d}: {exc.strerror or 'directory read error'}.")
    cron_d_files.sort(key=lambda item: item.name.casefold())
    if len(cron_d_files) > MAX_CRON_D_FILES:
        cron_d_files = cron_d_files[:MAX_CRON_D_FILES]
        rows_truncated = True
    for path in cron_d_files:
        if len(jobs) >= MAX_TOTAL_JOBS:
            rows_truncated = True
            break
        if config_bytes >= MAX_TOTAL_CONFIG_BYTES:
            rows_truncated = True
            break
        contents, read_bytes, error = _read_fixed_config(path, MAX_TOTAL_CONFIG_BYTES - config_bytes)
        config_bytes += read_bytes
        if error:
            sources_checked.append(str(path))
            messages.append(f"Could not inspect {path}: {error}.")
            continue
        if contents is None:
            continue
        parsed, malformed = _cron_jobs_from_text(
            contents,
            source=str(path),
            system_crontab=True,
        )
        rows_truncated |= _extend_bounded_jobs(jobs, parsed)
        malformed_rows += malformed
        rows_truncated |= len(parsed) >= MAX_JOB_ROWS

    env = dict(get_sanitized_env())
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    crontab = find_session_binary("crontab", env)
    if crontab:
        source = "current-user crontab"
        sources_checked.append(source)
        output, error, output_truncated = run_bounded_command(
            [crontab, "-l"],
            env,
            command_label="current-user crontab listing",
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
        )
        if output is None:
            if not error or "no crontab for" not in error.casefold():
                messages.append(f"Could not inspect {source}: {error or 'command failed'}.")
        else:
            parsed, malformed = _cron_jobs_from_text(
                output,
                source=source,
                system_crontab=False,
            )
            rows_truncated |= _extend_bounded_jobs(jobs, parsed)
            malformed_rows += malformed
            rows_truncated |= output_truncated or len(parsed) >= MAX_JOB_ROWS
    else:
        messages.append("The crontab command is unavailable; the current user's individual crontab was not checked.")

    atq = find_session_binary("atq", env)
    if atq:
        sources_checked.append("at queue")
        output, error, output_truncated = run_bounded_command(
            [atq],
            env,
            command_label="at queue listing",
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
        )
        if output is None:
            messages.append(f"Could not inspect the at queue: {error or 'command failed'}.")
        else:
            parsed, malformed, parse_truncated = _at_jobs_from_output(output)
            rows_truncated |= _extend_bounded_jobs(jobs, parsed)
            malformed_rows += malformed
            rows_truncated |= output_truncated or parse_truncated
            if os.geteuid() == 0:
                messages.append("Because this process runs as root, atq may include queued jobs owned by all users; command bodies remain hidden.")
    else:
        messages.append("The atq command is unavailable; queued one-shot at jobs were not checked.")

    if malformed_rows:
        messages.append(f"Skipped {malformed_rows} lines that did not match the supported cron, Anacron, or at format.")
    selected = _filter_jobs(jobs, query)
    if not sources_checked:
        messages.append("No supported scheduler source was available.")
    if len(messages) > MAX_MESSAGES:
        omitted = len(messages) - MAX_MESSAGES + 1
        messages = messages[:MAX_MESSAGES - 1] + [f"Suppressed {omitted} additional source warnings."]
    if not messages:
        messages.append(
            "No matching scheduled jobs were found in the checked sources."
            if not selected
            else "Scheduled command text is omitted from this inventory."
        )
    return CronJobListResponse(
        success=bool(sources_checked),
        total_jobs=len(selected),
        returned_jobs=min(len(selected), bounded_limit),
        jobs=selected[:bounded_limit],
        sources_checked=sources_checked,
        limit=bounded_limit,
        truncated=len(selected) > bounded_limit or rows_truncated,
        message=" ".join(messages) or "Scheduled command contents are never included in this result.",
    )
