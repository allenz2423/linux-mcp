"""Bounded read-only snapshots of the active Linux Netfilter rulesets."""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Literal

from wayland_mcp.models import (
    FirewallEntry,
    FirewallInventoryResponse,
    FirewallSourceStatus,
)
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

FirewallSource = Literal["nftables", "iptables_ipv4", "iptables_ipv6"]
FIREWALL_COMMANDS: dict[FirewallSource, str] = {
    "nftables": "nft",
    "iptables_ipv4": "iptables-save",
    "iptables_ipv6": "ip6tables-save",
}
TABLE_NAME_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,128}$")
CHAIN_NAME_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,128}$")
MAX_FIREWALL_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_FIREWALL_LINE_BYTES = 64 * 1024
MAX_SOURCE_ENTRIES = 20_000
MAX_TOTAL_ENTRIES = 50_000
MAX_RETURNED_ENTRIES = 200
MAX_DETAIL_STRING = 4096
MAX_DETAIL_ITEMS = 64
MAX_DETAIL_DEPTH = 8
COMMAND_TIMEOUT_SECONDS = 6


def detect_firewall_tools(env: dict[str, str] | None = None) -> dict[FirewallSource, str | None]:
    """Find optional firewall inspection commands through the sanitized PATH."""
    child_env = env if env is not None else get_sanitized_env(dict(os.environ))
    return {
        source: find_session_binary(binary, child_env)
        for source, binary in FIREWALL_COMMANDS.items()
    }


def _clean_text(value: Any, limit: int = 512) -> tuple[str | None, bool]:
    if not isinstance(value, str):
        return None, False
    cleaned = "".join(char for char in value if ord(char) >= 32 and ord(char) != 127)
    return cleaned[:limit] if cleaned else None, len(cleaned) > limit


def _safe_json_value(value: Any, depth: int = 0) -> tuple[Any, bool]:
    if value is None or isinstance(value, bool):
        return value, False
    if isinstance(value, int):
        if value.bit_length() > 63:
            return str(value)[:MAX_DETAIL_STRING], True
        return value, False
    if isinstance(value, float):
        return (value, False) if value == value and abs(value) != float("inf") else (None, True)
    if isinstance(value, str):
        return _clean_text(value, MAX_DETAIL_STRING)
    if depth >= MAX_DETAIL_DEPTH:
        return None, True
    if isinstance(value, list):
        cleaned: list[Any] = []
        truncated = len(value) > MAX_DETAIL_ITEMS
        for item in value[:MAX_DETAIL_ITEMS]:
            safe_item, item_truncated = _safe_json_value(item, depth + 1)
            cleaned.append(safe_item)
            truncated = truncated or item_truncated
        return cleaned, truncated
    if isinstance(value, dict):
        cleaned_dict: dict[str, Any] = {}
        items = list(value.items())
        truncated = len(items) > MAX_DETAIL_ITEMS
        for key, item in items[:MAX_DETAIL_ITEMS]:
            safe_key, key_truncated = _clean_text(key, 128)
            if not safe_key:
                truncated = True
                continue
            if safe_key == "handle":
                continue
            safe_item, item_truncated = _safe_json_value(item, depth + 1)
            cleaned_dict[safe_key] = safe_item
            truncated = truncated or key_truncated or item_truncated
        return cleaned_dict, truncated
    return None, True


def _scalar_text(value: Any, limit: int = 128) -> str | None:
    if isinstance(value, str):
        return _clean_text(value, limit)[0]
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)[:limit]
    return None


def _entry_matches(entry: FirewallEntry, needle: str) -> bool:
    if not needle:
        return True
    values = (
        entry.source,
        entry.object_type,
        entry.family or "",
        entry.table or "",
        entry.chain or "",
        entry.name or "",
        entry.policy or "",
        entry.hook or "",
        entry.priority or "",
        json.dumps(entry.details, ensure_ascii=True, sort_keys=True),
    )
    return any(needle in value.casefold() for value in values)


def _nft_entries(
    output: str,
    needle: str,
    output_truncated: bool,
) -> tuple[list[FirewallEntry] | None, bool, str | None]:
    if output_truncated:
        return None, True, "The nftables JSON ruleset exceeded the output limit; no partial JSON was returned."
    try:
        payload = json.loads(
            output,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (json.JSONDecodeError, RecursionError, ValueError):
        return None, False, "The nftables command returned malformed JSON."
    if not isinstance(payload, dict) or not isinstance(payload.get("nftables"), list):
        return None, False, "The nftables command returned an unsupported JSON structure."

    rows = payload["nftables"]
    truncated = len(rows) > MAX_SOURCE_ENTRIES
    entries: list[FirewallEntry] = []
    for row in rows[:MAX_SOURCE_ENTRIES]:
        if not isinstance(row, dict) or len(row) != 1:
            continue
        object_type, raw_details = next(iter(row.items()))
        if object_type == "metainfo" or not isinstance(raw_details, dict):
            continue
        safe_details, details_truncated = _safe_json_value(raw_details)
        if not isinstance(safe_details, dict):
            continue
        truncated = truncated or details_truncated
        family = _scalar_text(safe_details.get("family"))
        table = _scalar_text(safe_details.get("table"))
        chain = _scalar_text(safe_details.get("chain"))
        name = _scalar_text(safe_details.get("name"))
        policy = _scalar_text(safe_details.get("policy"))
        hook = _scalar_text(safe_details.get("hook"))
        priority = _scalar_text(safe_details.get("prio")) or _scalar_text(safe_details.get("priority"))
        entry = FirewallEntry(
            source="nftables",
            object_type=str(object_type)[:128],
            family=family,
            table=table,
            chain=chain,
            name=name,
            policy=policy,
            hook=hook,
            priority=priority,
            details=safe_details,
        )
        if _entry_matches(entry, needle):
            entries.append(entry)
    return entries, truncated, None


def _iptables_entries(
    output: str,
    source: Literal["iptables_ipv4", "iptables_ipv6"],
    family: Literal["ip", "ip6"],
    needle: str,
    output_truncated: bool,
) -> tuple[list[FirewallEntry], bool]:
    lines = output.splitlines()
    truncated = output_truncated or len(lines) > MAX_SOURCE_ENTRIES
    if output_truncated and output and not output.endswith("\n") and lines:
        lines = lines[:-1]
    entries: list[FirewallEntry] = []
    current_table: str | None = None
    for line in lines[:MAX_SOURCE_ENTRIES]:
        if len(line.encode("utf-8", errors="replace")) > MAX_FIREWALL_LINE_BYTES:
            truncated = True
            continue
        if line.startswith("*"):
            table, clipped = _clean_text(line[1:], 128)
            if not table or not TABLE_NAME_RE.fullmatch(table):
                current_table = None
                continue
            current_table = table
            truncated = truncated or clipped
            entry = FirewallEntry(
                source=source,
                object_type="table",
                family=family,
                table=table,
                name=table,
            )
        elif current_table and line.startswith(":"):
            fields = line[1:].split()
            if len(fields) < 2:
                truncated = True
                continue
            chain, chain_clipped = _clean_text(fields[0], 128)
            policy, policy_clipped = _clean_text(fields[1], 128)
            if not chain or not CHAIN_NAME_RE.fullmatch(chain) or not policy:
                truncated = True
                continue
            truncated = truncated or chain_clipped or policy_clipped
            entry = FirewallEntry(
                source=source,
                object_type="chain",
                family=family,
                table=current_table,
                chain=chain,
                name=chain,
                policy=None if policy == "-" else policy,
                details={"policy": policy},
            )
        elif current_table and line.startswith("-A "):
            match = re.match(r"^-A\s+(\S+)(?:\s+(.*))?$", line)
            if not match:
                truncated = True
                continue
            chain, chain_clipped = _clean_text(match.group(1), 128)
            spec, spec_clipped = _clean_text(match.group(2) or "", MAX_DETAIL_STRING)
            if not chain or not CHAIN_NAME_RE.fullmatch(chain):
                truncated = True
                continue
            truncated = truncated or chain_clipped or spec_clipped
            entry = FirewallEntry(
                source=source,
                object_type="rule",
                family=family,
                table=current_table,
                chain=chain,
                details={"spec": spec or ""},
            )
        elif line == "COMMIT":
            current_table = None
            continue
        else:
            continue
        if _entry_matches(entry, needle):
            entries.append(entry)
    return entries, truncated


def _source_status(
    source: FirewallSource,
    *,
    available: bool,
    success: bool,
    entry_count: int = 0,
    truncated: bool = False,
    message: str | None = None,
) -> FirewallSourceStatus:
    return FirewallSourceStatus(
        source=source,
        available=available,
        success=success,
        entry_count=entry_count,
        truncated=truncated,
        message=message,
    )


def list_firewall_rules(query: str = "", limit: int = 100) -> FirewallInventoryResponse:
    """List bounded active nftables and IPv4/IPv6 xtables ruleset entries."""
    if not sys.platform.startswith("linux"):
        return FirewallInventoryResponse(success=False, message="Firewall inventory is available only on Linux.")
    if not isinstance(query, str) or len(query) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in query):
        return FirewallInventoryResponse(
            success=False,
            message="Query must be text with at most 256 characters and no control characters.",
        )
    if not isinstance(limit, int) or isinstance(limit, bool):
        return FirewallInventoryResponse(success=False, message="Limit must be an integer.")
    limit = max(1, min(limit, MAX_RETURNED_ENTRIES))

    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    tools = detect_firewall_tools(env)
    needle = query.strip().casefold()
    sources: list[FirewallSourceStatus] = []
    entries: list[FirewallEntry] = []
    source_commands: tuple[tuple[FirewallSource, Literal["ip", "ip6"] | None, list[str]], ...] = (
        ("nftables", None, ["--stateless", "--json", "list", "ruleset"]),
        ("iptables_ipv4", "ip", []),
        ("iptables_ipv6", "ip6", []),
    )

    for source, family, arguments in source_commands:
        executable = tools[source]
        if not executable:
            sources.append(_source_status(
                source,
                available=False,
                success=False,
                message=f"The optional {FIREWALL_COMMANDS[source]} command is unavailable.",
            ))
            continue
        output, _error, output_truncated = run_bounded_command(
            [executable, *arguments],
            env,
            command_label=f"{source} firewall inventory",
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            max_output_bytes=MAX_FIREWALL_OUTPUT_BYTES,
        )
        if output is None:
            sources.append(_source_status(
                source,
                available=True,
                success=False,
                truncated=output_truncated,
                message="The active ruleset could not be read; current permissions, kernel support, or firewall state may limit access.",
            ))
            continue
        if source == "nftables":
            found, source_truncated, parse_error = _nft_entries(output, needle, output_truncated)
            if found is None:
                sources.append(_source_status(
                    source,
                    available=True,
                    success=False,
                    truncated=source_truncated,
                    message=parse_error or "The nftables ruleset could not be parsed.",
                ))
                continue
        else:
            assert family is not None
            found, source_truncated = _iptables_entries(
                output,
                source,
                family,
                needle,
                output_truncated,
            )
        if len(entries) + len(found) > MAX_TOTAL_ENTRIES:
            found = found[: max(0, MAX_TOTAL_ENTRIES - len(entries))]
            source_truncated = True
        entries.extend(found)
        sources.append(_source_status(
            source,
            available=True,
            success=True,
            entry_count=len(found),
            truncated=source_truncated,
            message="The firewall inventory reached an output, detail, or record limit." if source_truncated else None,
        ))

    success = any(source.success for source in sources)
    partial = any(source.available and not source.success for source in sources)
    truncated = any(source.truncated for source in sources) or len(entries) > limit
    if not success:
        message = "No available firewall ruleset source could be read; per-source status reports missing commands and access failures."
    elif partial:
        message = "Some available firewall sources could not be read; results include successful sources only."
    else:
        message = "Results contain bounded active Netfilter ruleset entries visible in the current network namespace."
    if truncated:
        message += " One or more sources or the returned list reached a configured limit."
    return FirewallInventoryResponse(
        success=success,
        partial=partial,
        sources=sources,
        total_entries=len(entries),
        returned_entries=min(len(entries), limit),
        entries=entries[:limit],
        limit=limit,
        truncated=truncated,
        message=message,
    )
