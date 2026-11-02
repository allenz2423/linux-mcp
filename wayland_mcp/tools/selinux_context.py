"""Exact-path restoration of the policy-defined SELinux file-context type."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import SELinuxContextRestoreResponse, SELinuxFContextRuleResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.selinux_booleans import selinux_booleans_available

MAX_CONTEXT_PATH_CHARS = 4095
MAX_CONTEXT_OUTPUT_BYTES = 16 * 1024
MAX_CONTEXT_CHARS = 1024
CONTEXT_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
PSEUDO_CONTEXT_PATHS = (Path("/proc"), Path("/sys"), Path("/dev"), Path("/run"))
CONTEXT_COMMAND_TIMEOUT_SECONDS = 10
FCONTEXT_COMMAND_TIMEOUT_SECONDS = 60
MAX_FCONTEXT_OUTPUT_BYTES = 1024 * 1024
MAX_FCONTEXT_RULES = 16_384
SELINUX_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,126}_t$")
_FCONTEXT_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class SELinuxContextTarget:
    path: Path
    path_identity: tuple[int, ...]
    current_context: str | None
    expected_context: str
    restorecon: str
    restorecon_identity: tuple[int, ...]
    matchpathcon: str
    matchpathcon_identity: tuple[int, ...]
    state_digest: str


@dataclass(frozen=True, slots=True)
class SELinuxFContextRuleTarget:
    action: str
    path: Path
    path_identity: tuple[int, ...]
    context_type: str
    file_type: str
    rule_expression: str
    existing_type: str | None
    existing_file_type: str | None
    semanage: str
    semanage_identity: tuple[int, ...]
    inventory_digest: str
    state_digest: str


def _binary_identity(binary: str) -> tuple[int, ...] | None:
    try:
        info = os.stat(binary, follow_symlinks=False)
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or not info.st_mode & 0o111
        or info.st_mode & 0o022
    ):
        return None
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _resolve_binary(name: str) -> tuple[str | None, tuple[int, ...] | None, str | None]:
    env = get_sanitized_env(dict(os.environ))
    binary = find_session_binary(name, env)
    if not binary:
        return None, None, f"The optional {name} command is unavailable."
    try:
        resolved = str(Path(binary).resolve(strict=True))
    except (OSError, RuntimeError):
        return None, None, f"The selected {name} executable could not be resolved safely."
    identity = _binary_identity(resolved)
    if identity is None:
        return None, None, f"The selected {name} executable identity could not be verified."
    return resolved, identity, None


def _path_identity(path: object) -> tuple[Path | None, tuple[int, ...] | None, str | None]:
    if (
        not isinstance(path, str)
        or not path
        or len(path) > MAX_CONTEXT_PATH_CHARS
        or not os.path.isabs(path)
        or CONTEXT_CONTROL_RE.search(path)
    ):
        return None, None, "path must be one absolute path without control characters."
    try:
        if stat.S_ISLNK(os.lstat(path).st_mode):
            return None, None, "Symbolic-link paths are not supported; supply the canonical target path."
        canonical = Path(path).resolve(strict=True)
        info = canonical.stat(follow_symlinks=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return None, None, f"The exact SELinux target path could not be verified: {getattr(exc, 'strerror', None) or type(exc).__name__}."
    if canonical == Path("/"):
        return None, None, "The filesystem root cannot be selected."
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        return None, None, "SELinux context restoration is limited to existing regular files and directories."
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        return None, None, "Hard-linked files cannot be selected because a context change affects every link to the inode."
    if any(canonical == blocked or blocked in canonical.parents for blocked in PSEUDO_CONTEXT_PATHS):
        return None, None, "Targets under /proc, /sys, /dev, and /run are not supported."
    identity = (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )
    return canonical, identity, None


def _parse_context(value: object, *, label: str) -> tuple[str | None, str | None]:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_CONTEXT_CHARS
        or CONTEXT_CONTROL_RE.search(value)
    ):
        return None, f"The {label} SELinux context was empty, oversized, or malformed."
    parts = value.split(":", 3)
    if len(parts) not in {3, 4} or any(not part for part in parts[:3]) or (len(parts) == 4 and not parts[3]):
        return None, f"The {label} SELinux context did not have a recognized user:role:type format."
    return parts[2], None


def _read_current_context(path: Path) -> tuple[str | None, str | None]:
    try:
        value = os.getxattr(path, "security.selinux", follow_symlinks=False)
    except OSError as exc:
        no_label_codes = {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}
        if exc.errno in no_label_codes:
            return None, None
        return None, f"The current SELinux context could not be read: {exc.strerror or type(exc).__name__}."
    try:
        context = value.rstrip(b"\x00").decode("ascii")
    except UnicodeDecodeError:
        return None, "The current SELinux context was not valid ASCII."
    _context_type, error = _parse_context(context, label="current")
    return (None, error) if error else (context, None)


def _read_expected_context(
    path: Path,
    binary: str,
    env: dict[str, str],
) -> tuple[str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "-n", "-N", str(path)],
        env,
        command_label="SELinux default-context query",
        timeout_seconds=CONTEXT_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_CONTEXT_OUTPUT_BYTES,
    )
    if output is None or error or truncated:
        return None, "The active SELinux file-context policy could not be queried safely."
    lines = output.splitlines()
    if len(lines) != 1:
        return None, "The SELinux default-context query returned an unexpected number of lines."
    context = lines[0].strip()
    _context_type, context_error = _parse_context(context, label="policy")
    if context_error:
        return None, context_error
    return context, None


def selinux_context_control_available() -> bool:
    if not sys.platform.startswith("linux") or not selinux_booleans_available():
        return False
    restorecon, restorecon_identity, error = _resolve_binary("restorecon")
    matchpathcon, matchpathcon_identity, match_error = _resolve_binary("matchpathcon")
    return not error and not match_error and bool(
        restorecon and restorecon_identity and matchpathcon and matchpathcon_identity
    )


def selinux_context_restore_confirmation_details(
    path: str,
) -> tuple[SELinuxContextTarget | None, str | None, str | None]:
    """Bind a single nonrecursive restorecon operation to exact path and policy state."""
    if not sys.platform.startswith("linux"):
        return None, None, "SELinux context restoration is available only on Linux."
    if not selinux_booleans_available():
        return None, None, "The SELinux boolean interface is not visible in selinuxfs."
    canonical, path_identity, error = _path_identity(path)
    if error or canonical is None or path_identity is None:
        return None, None, error or "The exact SELinux target path could not be verified."
    restorecon, restorecon_identity, error = _resolve_binary("restorecon")
    if error or restorecon is None or restorecon_identity is None:
        return None, None, error or "The restorecon executable could not be verified."
    matchpathcon, matchpathcon_identity, error = _resolve_binary("matchpathcon")
    if error or matchpathcon is None or matchpathcon_identity is None:
        return None, None, error or "The matchpathcon executable could not be verified."
    env = get_sanitized_env(dict(os.environ))
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    current_context, error = _read_current_context(canonical)
    if error:
        return None, None, error
    expected_context, error = _read_expected_context(canonical, matchpathcon, env)
    if error or expected_context is None:
        return None, None, error or "The policy-defined SELinux context could not be read."
    material = {
        "path": str(canonical),
        "path_identity": path_identity,
        "current_context": current_context,
        "expected_context": expected_context,
        "restorecon": restorecon,
        "restorecon_identity": restorecon_identity,
        "matchpathcon": matchpathcon,
        "matchpathcon_identity": matchpathcon_identity,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = SELinuxContextTarget(
        path=canonical,
        path_identity=path_identity,
        current_context=current_context,
        expected_context=expected_context,
        restorecon=restorecon,
        restorecon_identity=restorecon_identity,
        matchpathcon=matchpathcon,
        matchpathcon_identity=matchpathcon_identity,
        state_digest=digest,
    )
    phrase = f"SELINUX {hashlib.sha256(('restore:' + digest).encode('ascii')).hexdigest()[:16]}"
    return target, phrase, None


def perform_selinux_context_restore(
    path: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> SELinuxContextRestoreResponse:
    target, phrase, error = selinux_context_restore_confirmation_details(path)
    if error or target is None or phrase is None:
        return SELinuxContextRestoreResponse(
            success=False,
            path=path if isinstance(path, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The exact SELinux context restore could not be verified.",
        )
    if confirmed is not True:
        return SELinuxContextRestoreResponse(
            success=False,
            path=str(target.path),
            current_context=target.current_context,
            expected_context=target.expected_context,
            user_confirmed=False,
            message="Explicit client confirmation is required; no SELinux context was changed.",
        )
    if confirmation_phrase != phrase:
        return SELinuxContextRestoreResponse(
            success=False,
            path=str(target.path),
            current_context=target.current_context,
            expected_context=target.expected_context,
            user_confirmed=True,
            message="Confirmation did not match this path, current label, policy label, or helper identity.",
        )
    current, current_phrase, error = selinux_context_restore_confirmation_details(str(target.path))
    if error or current is None or current_phrase != phrase or current.state_digest != target.state_digest:
        return SELinuxContextRestoreResponse(
            success=False,
            path=str(target.path),
            current_context=target.current_context,
            expected_context=target.expected_context,
            user_confirmed=True,
            message=error or "The target, current label, policy label, or helper changed after confirmation.",
        )
    current_type, _ = _parse_context(target.current_context, label="current") if target.current_context else (None, None)
    expected_type, _ = _parse_context(target.expected_context, label="policy")
    if current_type == expected_type:
        return SELinuxContextRestoreResponse(
            success=True,
            path=str(target.path),
            current_context=target.current_context,
            expected_context=target.expected_context,
            resulting_context=target.current_context,
            user_confirmed=True,
            message="The SELinux type already matches policy; no command was run.",
        )
    if (
        _binary_identity(target.restorecon) != target.restorecon_identity
        or _binary_identity(target.matchpathcon) != target.matchpathcon_identity
    ):
        return SELinuxContextRestoreResponse(
            success=False,
            path=str(target.path),
            current_context=target.current_context,
            expected_context=target.expected_context,
            user_confirmed=True,
            message="An SELinux helper changed after confirmation; no relabel command was run.",
        )
    env = get_sanitized_env(dict(os.environ))
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    _output, command_error, truncated = run_bounded_command(
        [target.restorecon, str(target.path)],
        env,
        command_label="SELinux policy-type restoration",
        timeout_seconds=CONTEXT_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_CONTEXT_OUTPUT_BYTES,
    )
    resulting_path, resulting_identity, path_error = _path_identity(str(target.path))
    resulting_context, context_error = _read_current_context(target.path)
    # restorecon changes the security xattr, which updates ctime on the same inode.
    if (
        path_error
        or resulting_path != target.path
        or resulting_identity is None
        or resulting_identity[:-1] != target.path_identity[:-1]
    ):
        return SELinuxContextRestoreResponse(
            success=False,
            path=str(target.path),
            current_context=target.current_context,
            expected_context=target.expected_context,
            resulting_context=resulting_context,
            user_confirmed=True,
            message="The target path changed during the operation; inspect its current label before retrying.",
        )
    if command_error or truncated:
        return SELinuxContextRestoreResponse(
            success=False,
            path=str(target.path),
            current_context=target.current_context,
            expected_context=target.expected_context,
            resulting_context=resulting_context,
            user_confirmed=True,
            message="restorecon failed, timed out, or exceeded its output limit; inspect the resulting label before retrying.",
        )
    if context_error or resulting_context is None:
        return SELinuxContextRestoreResponse(
            success=False,
            path=str(target.path),
            current_context=target.current_context,
            expected_context=target.expected_context,
            user_confirmed=True,
            message=context_error or "The resulting SELinux context could not be read.",
        )
    resulting_type, type_error = _parse_context(resulting_context, label="resulting")
    if type_error or resulting_type != expected_type:
        return SELinuxContextRestoreResponse(
            success=False,
            path=str(target.path),
            current_context=target.current_context,
            expected_context=target.expected_context,
            resulting_context=resulting_context,
            user_confirmed=True,
            message="restorecon returned, but the resulting SELinux type still does not match policy; a customizable label or local policy rule may explain the difference.",
        )
    return SELinuxContextRestoreResponse(
        success=True,
        path=str(target.path),
        current_context=target.current_context,
        expected_context=target.expected_context,
        resulting_context=resulting_context,
        user_confirmed=True,
        message="The SELinux policy-defined type was restored for this exact path. User, role, and range fields were not forcibly reset, and the operation did not recurse.",
    )


def _fcontext_rule_expression(path: Path) -> str:
    """Build a byte-oriented PCRE expression matching one literal path only."""
    escaped: list[str] = []
    regex_metacharacters = frozenset(b".^$*+?{}[]()|\\")
    for value in os.fsencode(str(path)):
        if value == 0x20:
            escaped.append("\\x20")
        elif value in regex_metacharacters:
            escaped.append("\\" + chr(value))
        elif value < 0x20 or value >= 0x7F:
            escaped.append(f"\\x{value:02x}")
        else:
            escaped.append(chr(value))
    return "^" + "".join(escaped) + "$"


def _fcontext_environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env


def _read_local_fcontext_rules(
    semanage: str,
    rule_expression: str,
) -> tuple[str | None, tuple[tuple[str, str], ...] | None, str | None]:
    output, error, truncated = run_bounded_command(
        [semanage, "fcontext", "--list", "--locallist", "--noheading"],
        _fcontext_environment(),
        command_label="Read local SELinux file-context rules",
        timeout_seconds=FCONTEXT_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_FCONTEXT_OUTPUT_BYTES,
        cwd="/",
        kill_process_group=True,
    )
    if output is None or error or truncated:
        return None, None, "The local SELinux file-context rules could not be read completely."
    lines = output.splitlines()
    if len(lines) > MAX_FCONTEXT_RULES:
        return None, None, "The local SELinux file-context rule inventory exceeded its record limit."
    matches: list[tuple[str, str]] = []
    for line in lines:
        fields = line.split()
        if not fields or fields[0] != rule_expression:
            continue
        if len(fields) < 3:
            return None, None, "A matching local SELinux file-context rule had an unexpected format."
        remainder = line[len(fields[0]):].strip()
        try:
            file_type_label, context = remainder.rsplit(None, 1)
        except ValueError:
            return None, None, "A matching local SELinux file-context rule had an unexpected format."
        if not file_type_label:
            return None, None, "A matching local SELinux file-context rule omitted its file type."
        context_type, context_error = _parse_context(context, label="local rule")
        if context_error or context_type is None:
            return None, None, context_error or "A matching local SELinux file-context rule was malformed."
        matches.append((file_type_label, context_type))
    return output, tuple(matches), None


def selinux_fcontext_rule_control_available() -> bool:
    if not sys.platform.startswith("linux") or not selinux_booleans_available():
        return False
    semanage, identity, error = _resolve_binary("semanage")
    return not error and bool(semanage and identity)


def selinux_fcontext_rule_confirmation_details(
    action: str,
    path: str,
    context_type: str,
) -> tuple[SELinuxFContextRuleTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "SELinux file-context rule administration is available only on Linux."
    if os.geteuid() != 0:
        return None, None, "Persistent SELinux file-context rules require the MCP server to already run as root; no privilege elevation is requested."
    if action not in {"add", "remove"}:
        return None, None, "action must be 'add' or 'remove'."
    if not isinstance(context_type, str) or not SELINUX_TYPE_RE.fullmatch(context_type):
        return None, None, "context_type must be one SELinux type name ending in _t."
    canonical, path_identity, error = _path_identity(path)
    if error or canonical is None or path_identity is None:
        return None, None, error or "The exact SELinux target path could not be verified."
    if len(canonical.as_posix()) > MAX_FCONTEXT_OUTPUT_BYTES // 2:
        return None, None, "The exact SELinux path is too long to represent as a bounded literal rule."
    file_type = "d" if stat.S_ISDIR(path_identity[2]) else "f"
    rule_expression = _fcontext_rule_expression(canonical)
    if len(rule_expression.encode("utf-8")) > MAX_FCONTEXT_OUTPUT_BYTES // 2:
        return None, None, "The exact SELinux path is too long to represent as a bounded literal rule."
    semanage, semanage_identity, error = _resolve_binary("semanage")
    if error or semanage is None or semanage_identity is None:
        return None, None, error or "The semanage executable could not be verified."
    inventory, matching_types, error = _read_local_fcontext_rules(semanage, rule_expression)
    if error or inventory is None or matching_types is None:
        return None, None, error or "The local SELinux file-context rules could not be inspected."
    if len(matching_types) > 1:
        return None, None, "Multiple local rules use this exact path expression; no rule will be changed."
    existing_file_type = matching_types[0][0] if matching_types else None
    existing_type = matching_types[0][1] if matching_types else None
    if action == "add" and existing_type is not None:
        return None, None, "A local SELinux file-context rule already exists for this exact path expression."
    if action == "remove" and existing_type is None:
        return None, None, "No local SELinux file-context rule exists for this exact path expression."
    if action == "remove" and existing_type != context_type:
        return None, None, f"The exact local rule uses type {existing_type!r}; repeat that type to remove it."
    expected_file_type = "directory" if file_type == "d" else "regular file"
    if action == "remove" and existing_file_type != expected_file_type:
        return None, None, (
            f"The exact local rule applies to {existing_file_type!r}, not this path's {expected_file_type} type; "
            "this tool removes only rules matching the selected path type."
        )
    inventory_digest = hashlib.sha256(inventory.encode("utf-8", errors="replace")).hexdigest()
    material = {
        "action": action,
        "path": str(canonical),
        "path_identity": path_identity,
        "context_type": context_type,
        "file_type": file_type,
        "rule_expression": rule_expression,
        "existing_type": existing_type,
        "existing_file_type": existing_file_type,
        "semanage": semanage,
        "semanage_identity": semanage_identity,
        "inventory_digest": inventory_digest,
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = SELinuxFContextRuleTarget(
        action=action,
        path=canonical,
        path_identity=path_identity,
        context_type=context_type,
        file_type=file_type,
        rule_expression=rule_expression,
        existing_type=existing_type,
        existing_file_type=existing_file_type,
        semanage=semanage,
        semanage_identity=semanage_identity,
        inventory_digest=inventory_digest,
        state_digest=digest,
    )
    phrase = f"SELINUX FCONTEXT {hashlib.sha256(('fcontext:' + digest).encode('ascii')).hexdigest()[:16]}"
    return target, phrase, None


def perform_selinux_fcontext_rule_action(
    action: str,
    path: str,
    context_type: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> SELinuxFContextRuleResponse:
    target, phrase, error = selinux_fcontext_rule_confirmation_details(action, path, context_type)
    if error or target is None or phrase is None:
        return SELinuxFContextRuleResponse(
            success=False,
            action=action if action in {"add", "remove"} else None,
            path=path if isinstance(path, str) else None,
            context_type=context_type if isinstance(context_type, str) else None,
            user_confirmed=confirmed is True,
            message=error or "The SELinux file-context rule could not be verified.",
        )
    if confirmed is not True:
        return SELinuxFContextRuleResponse(
            success=False,
            action=target.action,
            path=str(target.path),
            context_type=target.context_type,
            file_type="directory" if target.file_type == "d" else "regular file",
            rule_expression=target.rule_expression,
            message="Explicit client confirmation is required; the local SELinux policy was not changed.",
        )
    if confirmation_phrase != phrase:
        return SELinuxFContextRuleResponse(
            success=False,
            action=target.action,
            path=str(target.path),
            context_type=target.context_type,
            file_type="directory" if target.file_type == "d" else "regular file",
            rule_expression=target.rule_expression,
            user_confirmed=True,
            message="Confirmation did not match this exact path, rule state, type, and semanage executable.",
        )
    with _FCONTEXT_ACTION_LOCK:
        current, current_phrase, error = selinux_fcontext_rule_confirmation_details(
            target.action,
            str(target.path),
            target.context_type,
        )
        if error or current is None or current_phrase != phrase or current.state_digest != target.state_digest:
            return SELinuxFContextRuleResponse(
                success=False,
                action=target.action,
                path=str(target.path),
                context_type=target.context_type,
                file_type="directory" if target.file_type == "d" else "regular file",
                rule_expression=target.rule_expression,
                user_confirmed=True,
                message=error or "The path, local rule inventory, or semanage executable changed after confirmation.",
            )
        if _binary_identity(target.semanage) != target.semanage_identity:
            return SELinuxFContextRuleResponse(
                success=False,
                action=target.action,
                path=str(target.path),
                context_type=target.context_type,
                file_type="directory" if target.file_type == "d" else "regular file",
                rule_expression=target.rule_expression,
                user_confirmed=True,
                message="The semanage executable changed after confirmation; no policy command was run.",
            )
        if target.action == "add":
            arguments = [
                target.semanage,
                "fcontext",
                "--add",
                "--ftype",
                target.file_type,
                "--type",
                target.context_type,
                target.rule_expression,
            ]
        else:
            arguments = [
                target.semanage,
                "fcontext",
                "--delete",
                "--ftype",
                target.file_type,
                "--type",
                target.context_type,
                target.rule_expression,
            ]
        _output, command_error, truncated = run_bounded_command(
            arguments,
            _fcontext_environment(),
            command_label="Change one exact local SELinux file-context rule",
            timeout_seconds=FCONTEXT_COMMAND_TIMEOUT_SECONDS,
            max_output_bytes=MAX_FCONTEXT_OUTPUT_BYTES,
            cwd="/",
            kill_process_group=True,
        )
        if command_error or truncated:
            return SELinuxFContextRuleResponse(
                success=False,
                action=target.action,
                path=str(target.path),
                context_type=target.context_type,
                file_type="directory" if target.file_type == "d" else "regular file",
                rule_expression=target.rule_expression,
                user_confirmed=True,
                message="semanage failed, timed out, or exceeded its output limit; inspect the local policy before retrying.",
            )
        resulting_path, resulting_identity, path_error = _path_identity(str(target.path))
        _inventory, resulting_types, inventory_error = _read_local_fcontext_rules(
            target.semanage,
            target.rule_expression,
        )
        if (
            path_error
            or resulting_path != target.path
            or resulting_identity != target.path_identity
            or inventory_error
            or resulting_types is None
            or (target.action == "add" and resulting_types != (("directory" if target.file_type == "d" else "regular file", target.context_type),))
            or (target.action == "remove" and resulting_types != ())
        ):
            return SELinuxFContextRuleResponse(
                success=False,
                action=target.action,
                path=str(target.path),
                context_type=target.context_type,
                file_type="directory" if target.file_type == "d" else "regular file",
                rule_expression=target.rule_expression,
                user_confirmed=True,
                message="The command returned, but the exact local rule or target identity did not verify; inspect policy state before retrying.",
            )
    return SELinuxFContextRuleResponse(
        success=True,
        action=target.action,
        path=str(target.path),
        context_type=target.context_type,
        file_type="directory" if target.file_type == "d" else "regular file",
        rule_expression=target.rule_expression,
        user_confirmed=True,
        message=(
            "The exact local SELinux file-context rule was added. Existing file labels were not changed; use the confirmed policy-type restoration tool to relabel this exact path."
            if target.action == "add"
            else "The exact local SELinux file-context rule was removed. The current file label was not changed."
        ),
    )
