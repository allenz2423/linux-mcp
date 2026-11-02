"""Exact, transient inbound port-block rules in a dedicated nftables table."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import threading
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import FirewallRuleActionResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

FirewallRuleAction = Literal["add_block", "remove_block"]
FirewallFamily = Literal["ipv4", "ipv6"]
FAMILY_MAP: dict[FirewallFamily, tuple[str, int, str]] = {
    "ipv4": ("ip", 4, "linux_mcp"),
    "ipv6": ("ip6", 6, "linux_mcp6"),
}
RULE_COMMENT_PREFIX = "linux-mcp:block:"
TABLE_MARKER_COMMENT = "linux-mcp:table-marker:v1"
CHAIN_NAME = "input"
MAX_RULESET_OUTPUT_BYTES = 512 * 1024
MAX_RULESET_ROWS = 4_096
MAX_MANAGED_RULES = 2_048
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 5
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class FirewallRuleSpec:
    action: FirewallRuleAction
    family: FirewallFamily
    protocol: Literal["tcp", "udp"]
    port: int
    source_cidr: str | None


@dataclass(frozen=True, slots=True)
class ManagedRule:
    handle: int
    spec: FirewallRuleSpec


@dataclass(frozen=True, slots=True)
class ManagedTableState:
    table_exists: bool
    chain_exists: bool
    marker_present: bool = False
    rules: tuple[ManagedRule, ...] = ()


@dataclass(frozen=True, slots=True)
class FirewallRuleTarget:
    spec: FirewallRuleSpec
    table_state: ManagedTableState
    existing_rule: ManagedRule | None


def nftables_rule_control_available() -> bool:
    return sys.platform.startswith("linux") and bool(
        find_session_binary("nft", get_sanitized_env(dict(os.environ)))
    )


def _normalize_request(
    action: object,
    family: object,
    protocol: object,
    port: object,
    source_cidr: object,
) -> tuple[FirewallRuleSpec | None, str | None]:
    if not isinstance(action, str) or action not in {"add_block", "remove_block"}:
        return None, "Choose one supported firewall action: add_block or remove_block."
    if not isinstance(family, str) or family not in FAMILY_MAP:
        return None, "Choose one supported address family: ipv4 or ipv6."
    if not isinstance(protocol, str) or protocol not in {"tcp", "udp"}:
        return None, "Protocol must be tcp or udp."
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65_535:
        return None, "Port must be an integer from 1 through 65535."
    if not isinstance(source_cidr, str) or len(source_cidr) > 128 or source_cidr != source_cidr.strip():
        return None, "source_cidr must be one canonical network prefix or an empty string for any source."
    normalized_source: str | None = None
    if source_cidr:
        if any(ord(character) < 33 or ord(character) == 127 for character in source_cidr):
            return None, "source_cidr must not contain control or whitespace characters."
        try:
            network = ipaddress.ip_network(source_cidr, strict=True)
        except ValueError:
            return None, "source_cidr must be a canonical network prefix with no host bits set."
        _nft_family, version, _table = FAMILY_MAP[family]
        if network.version != version:
            return None, "source_cidr and family must use the same address family."
        if network.is_multicast:
            return None, "Multicast sources are not supported by this firewall action."
        if network.prefixlen:
            normalized_source = str(network)
    return FirewallRuleSpec(
        action=action,
        family=family,
        protocol=protocol,
        port=port,
        source_cidr=normalized_source,
    ), None


def _rule_comment(spec: FirewallRuleSpec) -> str:
    source = spec.source_cidr or "any"
    return f"{RULE_COMMENT_PREFIX}{spec.family}:{spec.protocol}:{spec.port}:{source}"


def _comment_spec(value: object) -> FirewallRuleSpec | None:
    if not isinstance(value, str) or not value.startswith(RULE_COMMENT_PREFIX):
        return None
    parts = value[len(RULE_COMMENT_PREFIX):].split(":", maxsplit=3)
    if len(parts) != 4:
        return None
    family, protocol, raw_port, raw_source = parts
    if len(raw_port) > 5 or not raw_port.isascii() or not raw_port.isdecimal():
        return None
    port = int(raw_port)
    source = "" if raw_source == "any" else raw_source
    spec, error = _normalize_request("add_block", family, protocol, port, source)
    if error or spec is None or _rule_comment(spec) != value:
        return None
    return spec


def _expected_expression(spec: FirewallRuleSpec) -> list[dict[str, object]]:
    nft_family, _version, _table = FAMILY_MAP[spec.family]
    expression: list[dict[str, object]] = []
    if spec.source_cidr:
        network = ipaddress.ip_network(spec.source_cidr, strict=True)
        expression.append({
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": nft_family, "field": "saddr"}},
                "right": {"prefix": {"addr": str(network.network_address), "len": network.prefixlen}},
            }
        })
    expression.extend((
        {
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": spec.protocol, "field": "dport"}},
                "right": spec.port,
            }
        },
        {"drop": None},
    ))
    return expression


def _expression_matches_spec(expression: object, spec: FirewallRuleSpec) -> bool:
    expected = _expected_expression(spec)
    if expression == expected:
        return True
    if not spec.source_cidr:
        return False
    network = ipaddress.ip_network(spec.source_cidr, strict=True)
    source_match = expected[0]["match"]
    if not isinstance(source_match, dict):
        return False
    alternatives: list[object] = [str(network)]
    if network.prefixlen == network.max_prefixlen:
        alternatives.append(str(network.network_address))
    for source_right in alternatives:
        variant = [dict(expected[0]), *expected[1:]]
        variant_match = dict(source_match)
        variant_match["right"] = source_right
        variant[0] = {"match": variant_match}
        if expression == variant:
            return True
    return False


def _query_json(
    binary: str,
    env: dict[str, str],
    arguments: list[str],
    label: str,
) -> tuple[object | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "--json", *arguments],
        env,
        command_label=label,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_RULESET_OUTPUT_BYTES,
    )
    if error or output is None:
        return None, "The current nftables state could not be read; permissions or kernel support may limit access."
    if truncated:
        return None, "The current nftables state exceeded its output limit."
    try:
        payload = json.loads(
            output,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (json.JSONDecodeError, RecursionError, ValueError):
        return None, "nftables returned malformed JSON."
    if not isinstance(payload, dict) or not isinstance(payload.get("nftables"), list):
        return None, "nftables returned an unsupported JSON structure."
    rows = payload["nftables"]
    if len(rows) > MAX_RULESET_ROWS:
        return None, "The nftables response contained too many objects to inspect safely."
    return rows, None


def _valid_handle(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 0xFFFFFFFFFFFFFFFF:
        return value
    return None


def _read_table_state(
    spec: FirewallRuleSpec,
    binary: str,
    env: dict[str, str],
) -> tuple[ManagedTableState | None, str | None]:
    nft_family, _version, table = FAMILY_MAP[spec.family]
    table_rows, error = _query_json(binary, env, ["list", "tables", nft_family], "nftables table inventory")
    if error or table_rows is None:
        return None, error
    table_found = False
    for row in table_rows:
        if not isinstance(row, dict) or len(row) != 1:
            return None, "nftables returned a malformed table inventory row."
        if "metainfo" in row:
            continue
        raw_table = row.get("table")
        if not isinstance(raw_table, dict):
            return None, "nftables returned an unexpected object while listing tables."
        if raw_table.get("family") == nft_family and raw_table.get("name") == table:
            table_found = True
    if not table_found:
        return ManagedTableState(table_exists=False, chain_exists=False), None

    object_rows, error = _query_json(
        binary,
        env,
        ["--handle", "list", "table", nft_family, table],
        "managed nftables table inspection",
    )
    if error or object_rows is None:
        return None, error
    table_objects: list[dict[str, object]] = []
    chains: list[dict[str, object]] = []
    rule_objects: list[dict[str, object]] = []
    for row in object_rows:
        if not isinstance(row, dict) or len(row) != 1:
            return None, "The managed nftables table contains a malformed object."
        object_type, raw_object = next(iter(row.items()))
        if object_type == "metainfo":
            continue
        if not isinstance(raw_object, dict):
            return None, "The managed nftables table contains an unexpected object."
        if object_type == "table":
            table_objects.append(raw_object)
        elif object_type == "chain":
            chains.append(raw_object)
        elif object_type == "rule":
            rule_objects.append(raw_object)
        else:
            return None, "The dedicated nftables table contains unsupported objects; no change was made."

    if len(table_objects) != 1:
        return None, "The dedicated nftables table could not be uniquely verified."
    table_object = table_objects[0]
    if (
        table_object.get("family") != nft_family
        or table_object.get("name") != table
        or set(table_object) - {"family", "name", "handle"}
    ):
        return None, "A table with the reserved Linux MCP name exists but does not match its managed schema."
    if _valid_handle(table_object.get("handle")) is None:
        return None, "The dedicated nftables table handle could not be verified."

    if not chains:
        if rule_objects:
            return None, "The dedicated nftables table has rules without its managed input chain."
        return None, "The reserved nftables table has no managed input chain; no change was made."
    if len(chains) != 1:
        return None, "The dedicated nftables table contains unexpected chains; no change was made."
    chain = chains[0]
    priority = chain.get("prio")
    valid_priority = (
        (isinstance(priority, int) and not isinstance(priority, bool) and priority == 0)
        or priority in {"0", "filter"}
    )
    if (
        chain.get("family") != nft_family
        or chain.get("table") != table
        or chain.get("name") != CHAIN_NAME
        or chain.get("type") != "filter"
        or chain.get("hook") != "input"
        or not valid_priority
        or chain.get("policy") != "accept"
        or set(chain) - {"family", "table", "name", "type", "hook", "prio", "policy", "handle"}
        or _valid_handle(chain.get("handle")) is None
    ):
        return None, "The dedicated nftables input chain does not match the managed filter/accept chain."

    if len(rule_objects) > MAX_MANAGED_RULES + 1:
        return None, "The dedicated nftables table contains too many rules to manage safely."
    managed_rules: list[ManagedRule] = []
    marker_count = 0
    for raw_rule in rule_objects:
        if (
            raw_rule.get("family") != nft_family
            or raw_rule.get("table") != table
            or raw_rule.get("chain") != CHAIN_NAME
            or set(raw_rule) - {"family", "table", "chain", "handle", "index", "comment", "expr"}
        ):
            return None, "The dedicated nftables table contains a rule outside the managed schema."
        handle = _valid_handle(raw_rule.get("handle"))
        comment = raw_rule.get("comment")
        expression = raw_rule.get("expr")
        if handle is None or not isinstance(expression, list):
            return None, "The dedicated nftables table contains an unsupported or modified rule."
        if comment == TABLE_MARKER_COMMENT:
            if (
                len(expression) != 1
                or not isinstance(expression[0], dict)
                or set(expression[0]) != {"counter"}
                or not isinstance(expression[0]["counter"], dict)
                or set(expression[0]["counter"]) - {"packets", "bytes"}
                or any(
                    not isinstance(value, int) or isinstance(value, bool) or value < 0
                    for value in expression[0]["counter"].values()
                )
            ):
                return None, "The nftables table marker rule does not match its harmless counter-only identity."
            marker_count += 1
            continue
        marker_spec = _comment_spec(comment)
        if marker_spec is None or not _expression_matches_spec(expression, marker_spec):
            return None, "The dedicated nftables table contains an unsupported or modified rule."
        managed_rules.append(ManagedRule(handle=handle, spec=marker_spec))
    if marker_count != 1:
        return None, "The reserved nftables table does not contain exactly one Linux MCP ownership marker."
    return ManagedTableState(
        table_exists=True,
        chain_exists=True,
        marker_present=True,
        rules=tuple(managed_rules),
    ), None


def _matching_rules(state: ManagedTableState, spec: FirewallRuleSpec) -> list[ManagedRule]:
    return [
        rule for rule in state.rules
        if (
            rule.spec.family == spec.family
            and rule.spec.protocol == spec.protocol
            and rule.spec.port == spec.port
            and rule.spec.source_cidr == spec.source_cidr
        )
    ]


def _validate_action_target(
    spec: FirewallRuleSpec,
    state: ManagedTableState,
) -> tuple[FirewallRuleTarget | None, str | None]:
    matches = _matching_rules(state, spec)
    if spec.action == "add_block":
        if state.table_exists and (not state.chain_exists or not state.marker_present):
            return None, "The reserved nftables table is not verified as Linux MCP-managed."
        if matches:
            return None, "An identical managed block rule already exists; no duplicate rule was added."
        if len(state.rules) >= MAX_MANAGED_RULES:
            return None, "The dedicated nftables table reached its managed-rule limit."
        return FirewallRuleTarget(spec=spec, table_state=state, existing_rule=None), None
    if not state.table_exists or not state.chain_exists or len(matches) != 1:
        return None, "Remove requires exactly one matching managed block rule in the dedicated nftables table."
    return FirewallRuleTarget(spec=spec, table_state=state, existing_rule=matches[0]), None


def firewall_rule_confirmation_details(
    action: str,
    family: str,
    protocol: str,
    port: int,
    source_cidr: str,
) -> tuple[FirewallRuleTarget | None, str | None]:
    """Validate one firewall action and capture its current managed-table state."""
    if not nftables_rule_control_available():
        return None, "Firewall rule control requires Linux and the nft command."
    spec, error = _normalize_request(action, family, protocol, port, source_cidr)
    if error or spec is None:
        return None, error
    env = get_sanitized_env(dict(os.environ))
    binary = find_session_binary("nft", env)
    if not binary:
        return None, "The nft command became unavailable."
    state, error = _read_table_state(spec, binary, env)
    if error or state is None:
        return None, error or "The dedicated nftables table could not be verified."
    return _validate_action_target(spec, state)


def _safe_response_values(
    action: object,
    family: object,
    protocol: object,
    port: object,
    source_cidr: object,
) -> dict[str, object]:
    return {
        "action": action if isinstance(action, str) and action in {"add_block", "remove_block"} else "add_block",
        "family": family if isinstance(family, str) and family in FAMILY_MAP else None,
        "protocol": protocol if isinstance(protocol, str) and protocol in {"tcp", "udp"} else None,
        "port": port if isinstance(port, int) and not isinstance(port, bool) else None,
        "source_cidr": source_cidr[:128] if isinstance(source_cidr, str) and source_cidr else None,
    }


def _run_nft(
    binary: str,
    env: dict[str, str],
    arguments: list[str],
    *,
    label: str,
) -> tuple[bool, str | None]:
    _output, error, truncated = run_bounded_command(
        [binary, *arguments],
        env,
        command_label=label,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
    )
    if error and "timed out" in error.casefold():
        return False, "The nftables command timed out; its state may be partial. Inspect list_firewall_rules before retrying."
    if error or truncated:
        return False, "nftables rejected or could not complete the change. Inspect list_firewall_rules before retrying."
    return True, None


def _create_table(
    spec: FirewallRuleSpec,
    binary: str,
    env: dict[str, str],
) -> tuple[bool, str | None]:
    nft_family, _version, table = FAMILY_MAP[spec.family]
    return _run_nft(
        binary,
        env,
        ["create", "table", nft_family, table],
        label="Create managed nftables table",
    )


def _create_chain(
    spec: FirewallRuleSpec,
    binary: str,
    env: dict[str, str],
) -> tuple[bool, str | None]:
    nft_family, _version, table = FAMILY_MAP[spec.family]
    return _run_nft(
        binary,
        env,
        [
            "create", "chain", nft_family, table, CHAIN_NAME,
            "{", "type", "filter", "hook", "input", "priority", "filter", ";",
            "policy", "accept", ";", "}",
        ],
        label="Create managed nftables input chain",
    )


def _add_table_marker(
    spec: FirewallRuleSpec,
    binary: str,
    env: dict[str, str],
) -> tuple[bool, str | None]:
    nft_family, _version, table = FAMILY_MAP[spec.family]
    return _run_nft(
        binary,
        env,
        ["add", "rule", nft_family, table, CHAIN_NAME, "counter", "comment", f'"{TABLE_MARKER_COMMENT}"'],
        label="Mark managed nftables table",
    )


def _add_rule(
    spec: FirewallRuleSpec,
    binary: str,
    env: dict[str, str],
) -> tuple[bool, str | None]:
    nft_family, _version, table = FAMILY_MAP[spec.family]
    arguments = ["add", "rule", nft_family, table, CHAIN_NAME]
    if spec.source_cidr:
        address_keyword = "ip" if spec.family == "ipv4" else "ip6"
        arguments.extend((address_keyword, "saddr", spec.source_cidr))
    arguments.extend((spec.protocol, "dport", str(spec.port), "drop", "comment", f'"{_rule_comment(spec)}"'))
    return _run_nft(binary, env, arguments, label="Add managed nftables block rule")


def _delete_rule(
    spec: FirewallRuleSpec,
    handle: int,
    binary: str,
    env: dict[str, str],
) -> tuple[bool, str | None]:
    nft_family, _version, table = FAMILY_MAP[spec.family]
    return _run_nft(
        binary,
        env,
        ["delete", "rule", nft_family, table, CHAIN_NAME, "handle", str(handle)],
        label="Remove managed nftables block rule",
    )


def _safe_readback(
    spec: FirewallRuleSpec,
    binary: str,
    env: dict[str, str],
) -> tuple[ManagedTableState | None, str | None]:
    state, error = _read_table_state(spec, binary, env)
    if error or state is None:
        return None, error or "The managed firewall state could not be re-read."
    return state, None


def _response_failure(
    values: dict[str, object],
    message: str,
    *,
    user_confirmed: bool,
    handle: int | None = None,
) -> FirewallRuleActionResponse:
    return FirewallRuleActionResponse(
        success=False,
        **values,
        rule_handle=handle,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_firewall_rule_action(
    action: str,
    family: str,
    protocol: str,
    port: int,
    source_cidr: str,
    *,
    confirmed: bool,
) -> FirewallRuleActionResponse:
    values = _safe_response_values(action, family, protocol, port, source_cidr)
    if not confirmed:
        return _response_failure(values, "Explicit client confirmation is required; no firewall change was run.", user_confirmed=False)
    if not nftables_rule_control_available():
        return _response_failure(values, "Firewall rule control requires Linux and the nft command; no change was run.", user_confirmed=True)
    spec, error = _normalize_request(action, family, protocol, port, source_cidr)
    if error or spec is None:
        return _response_failure(values, error or "The exact firewall action could not be validated.", user_confirmed=True)
    values["source_cidr"] = spec.source_cidr

    with _ACTION_LOCK:
        env = get_sanitized_env(dict(os.environ))
        binary = find_session_binary("nft", env)
        if not binary:
            return _response_failure(values, "The nft command became unavailable; no firewall change was run.", user_confirmed=True)
        state, error = _read_table_state(spec, binary, env)
        if error or state is None:
            return _response_failure(values, error or "The managed firewall state could not be revalidated.", user_confirmed=True)
        target, error = _validate_action_target(spec, state)
        if error or target is None:
            return _response_failure(values, error or "The exact firewall target could not be revalidated.", user_confirmed=True)

        handle: int | None = None
        if spec.action == "add_block":
            if not state.table_exists:
                completed, error = _create_table(spec, binary, env)
                if not completed:
                    return _response_failure(values, error or "The managed nftables table could not be created.", user_confirmed=True)
                completed, error = _create_chain(spec, binary, env)
                if not completed:
                    return _response_failure(values, error or "The managed nftables chain could not be created; inspect list_firewall_rules.", user_confirmed=True)
                completed, error = _add_table_marker(spec, binary, env)
                if not completed:
                    return _response_failure(values, error or "The managed nftables table marker could not be installed; inspect list_firewall_rules.", user_confirmed=True)
                state, error = _safe_readback(spec, binary, env)
                if error or state is None or not state.marker_present:
                    return _response_failure(values, error or "The nftables table marker could not be verified; inspect list_firewall_rules.", user_confirmed=True)
            target, error = _validate_action_target(spec, state)
            if error or target is None:
                return _response_failure(values, error or "The exact firewall target changed before rule insertion.", user_confirmed=True)
            completed, error = _add_rule(spec, binary, env)
            if not completed:
                return _response_failure(values, error or "The block rule could not be added.", user_confirmed=True)
        else:
            if target.existing_rule is None:
                return _response_failure(values, "The exact managed block rule disappeared after confirmation; no firewall change was run.", user_confirmed=True)
            handle = target.existing_rule.handle
            completed, error = _delete_rule(spec, handle, binary, env)
            if not completed:
                return _response_failure(values, error or "The exact managed block rule could not be removed.", user_confirmed=True, handle=handle)

        updated, error = _safe_readback(spec, binary, env)
        if error or updated is None:
            return _response_failure(values, error or "The firewall command completed but its result could not be verified; inspect list_firewall_rules.", user_confirmed=True, handle=handle)
        matches = _matching_rules(updated, spec)
        expected = len(matches) == 1 if spec.action == "add_block" else not matches
        if not expected:
            return _response_failure(values, "The command completed, but the exact firewall rule is not in the requested state; inspect list_firewall_rules.", user_confirmed=True, handle=handle)
        result_handle = matches[0].handle if matches else handle
        action_word = "Added" if spec.action == "add_block" else "Removed"
        source = f" from {spec.source_cidr}" if spec.source_cidr else " from any source"
        return FirewallRuleActionResponse(
            success=True,
            **values,
            rule_handle=result_handle,
            user_confirmed=True,
            message=(
                f"{action_word} and verified the inbound {spec.protocol.upper()} port {spec.port} block{source} "
                f"in the dedicated {spec.family} nftables table. Unmatched traffic follows the chain's accept policy; "
                "the rule is runtime-only and is not persisted across reboot."
            ),
        )
