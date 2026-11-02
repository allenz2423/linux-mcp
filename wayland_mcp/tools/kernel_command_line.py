"""Confirmed kernel command-line changes through grubby or a bounded GRUB config path."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import stat
import sys
import threading
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from wayland_mcp.models import KernelCommandLineResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

KernelCommandLineAction = Literal["add", "remove"]
MAX_OUTPUT_BYTES = 512 * 1024
MAX_ENTRIES = 512
QUERY_TIMEOUT_SECONDS = 8
ACTION_TIMEOUT_SECONDS = 30
GRUB_OUTPUT_LIMIT = 8 * 1024 * 1024
GRUB_DEFAULT_LIMIT = 64 * 1024
GRUB_HOOK_FILE_LIMIT = 2 * 1024 * 1024
GRUB_HOOK_TOTAL_LIMIT = 16 * 1024 * 1024
GRUB_HOOK_COUNT_LIMIT = 128
GRUB_OUTPUT_PATHS = (Path("/boot/grub/grub.cfg"), Path("/boot/grub2/grub.cfg"))
GRUB_DEFAULTS_PATH = Path("/etc/default/grub")
GRUB_HOOKS_PATH = Path("/etc/grub.d")
GRUB_DEFAULT_DROPINS_PATH = Path("/etc/default/grub.d")
GRUB_LIBRARY_PATHS = (Path("/usr/share/grub/grub-mkconfig_lib"), Path("/usr/lib/grub/grub-mkconfig_lib"))
ARGUMENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}(?:=[A-Za-z0-9_.,:/+=@%-]{1,191})?$")
GRUB_LINUX_LINE_RE = re.compile(r"^[ \t]*(linux(?:efi|16)?)[ \t]+(.+?)[ \t]*$")
GRUB_DEFAULT_ASSIGNMENT_RE = re.compile(
    r"^[ \t]*(?:export[ \t]+)?(GRUB_CMDLINE_LINUX(?:_DEFAULT)?)[ \t]*=(.*)$"
)
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class BootEntry:
    index: int
    kernel: str
    arguments: tuple[str, ...]

    @property
    def identity(self) -> tuple[int, str]:
        return self.index, self.kernel


@dataclass(frozen=True, slots=True)
class KernelCommandLineTarget:
    backend: Literal["grubby", "grub_config"]
    action: KernelCommandLineAction
    argument: str
    entries: tuple[BootEntry, ...]
    inventory_digest: str
    binary: str
    binary_identity: tuple[int, ...]
    state_token: str
    grub_config: GrubConfigSnapshot | None = None


@dataclass(frozen=True, slots=True)
class GrubConfigSnapshot:
    defaults_path: Path
    defaults_bytes: bytes
    defaults_identity: tuple[int, ...]
    defaults_parent_identity: tuple[int, ...]
    defaults_xattrs: tuple[tuple[str, bytes], ...]
    defaults_arguments: tuple[tuple[str, tuple[str, ...]], ...]
    output_path: Path
    output_bytes: bytes
    output_identity: tuple[int, ...]
    output_parent_identity: tuple[int, ...]
    output_xattrs: tuple[tuple[str, bytes], ...]
    generator: str
    generator_identity: tuple[int, ...]
    hooks_state: tuple[object, ...]
    dropins_state: tuple[object, ...]
    helper_state: tuple[object, ...]
    replacement_bytes: bytes


def _environment() -> dict[str, str]:
    env = get_sanitized_env(dict(os.environ))
    env["LANG"] = "C"
    env["LC_ALL"] = "C"
    env["NO_COLOR"] = "1"
    return env


def _identity(info: os.stat_result) -> tuple[int, ...]:
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


def _same_directory_identity(actual: tuple[int, ...], expected: tuple[int, ...]) -> bool:
    """Compare directory identity without child-entry size and timestamp changes."""
    # GRUB generation stages its output in the target directory. Creating that
    # reserved file updates directory size and timestamps, so those fields are
    # not stable across the action. Device/inode/type/link-count/owner remain
    # bound to the directory that was confirmed.
    return actual[:6] == expected[:6]


def _safe_system_binary(name: str, env: dict[str, str]) -> tuple[str | None, tuple[int, ...] | None]:
    if not sys.platform.startswith("linux"):
        return None, None
    binary = find_session_binary(name, env)
    if not binary:
        return None, None
    try:
        resolved = os.path.realpath(binary, strict=True)
        info = os.stat(resolved, follow_symlinks=False)
    except (OSError, RuntimeError, ValueError):
        return None, None
    for parent in reversed(Path(resolved).parents):
        try:
            parent_info = parent.stat(follow_symlinks=False)
        except OSError:
            return None, None
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or parent_info.st_mode & 0o022
        ):
            return None, None
    if (
        not stat.S_ISREG(info.st_mode)
        or not os.access(resolved, os.X_OK)
        or info.st_uid != 0
        or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
    ):
        return None, None
    return resolved, _identity(info)


def _safe_rooted_directory(path: Path, label: str) -> tuple[int, ...] | None:
    try:
        if path.resolve(strict=True) != path:
            return None
        info = path.stat(follow_symlinks=False)
        for parent in reversed(path.parents):
            parent_info = parent.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != 0
                or parent_info.st_mode & 0o022
            ):
                return None
    except (OSError, RuntimeError, ValueError):
        return None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
    ):
        return None
    return _identity(info)


def _read_xattrs(descriptor: int) -> tuple[tuple[str, bytes], ...] | None:
    try:
        names = sorted(os.listxattr(descriptor))
        return tuple((name, os.getxattr(descriptor, name)) for name in names)
    except (OSError, NotImplementedError, TypeError):
        return None


def _read_rooted_file(
    path: Path,
    label: str,
    max_bytes: int,
) -> tuple[bytes | None, tuple[int, ...] | None, tuple[tuple[str, bytes], ...] | None, str | None]:
    descriptor: int | None = None
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            return None, None, None, f"The {label} must have a canonical path without symlinked components."
        for parent in reversed(path.parents):
            parent_info = parent.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != 0
                or parent_info.st_mode & 0o022
            ):
                return None, None, None, f"A {label} parent is not a root-owned directory protected from group/other writes."
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or before.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
            or before.st_size < 1
            or before.st_size > max_bytes
        ):
            return None, None, None, f"The {label} must be a bounded, root-owned, single-link regular file without group/other write or set-id bits."
        before_xattrs = _read_xattrs(descriptor)
        if before_xattrs is None:
            return None, None, None, f"The extended attributes on the {label} could not be read safely."
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        after_xattrs = _read_xattrs(descriptor)
        if len(data) > max_bytes:
            return None, None, None, f"The {label} exceeds its supported size limit."
        if _identity(before) != _identity(after) or before_xattrs != after_xattrs:
            return None, None, None, f"The {label} changed while it was being inspected."
        return bytes(data), _identity(after), after_xattrs, None
    except (OSError, RuntimeError, ValueError):
        return None, None, None, f"The {label} could not be opened safely."
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _grub_hooks_state() -> tuple[object, ...] | None:
    directory_identity = _safe_rooted_directory(GRUB_HOOKS_PATH, "GRUB generator hook directory")
    if directory_identity is None:
        return None
    try:
        with os.scandir(GRUB_HOOKS_PATH) as scan:
            entries = sorted(list(scan), key=lambda entry: entry.name)
    except OSError:
        return None
    if len(entries) > GRUB_HOOK_COUNT_LIMIT:
        return None
    total = 0
    files: list[tuple[object, ...]] = []
    for entry in entries:
        try:
            entry_info = entry.stat(follow_symlinks=False)
        except OSError:
            return None
        if stat.S_ISLNK(entry_info.st_mode) or not stat.S_ISREG(entry_info.st_mode):
            return None
        path = GRUB_HOOKS_PATH / entry.name
        contents, identity, xattrs, error = _read_rooted_file(path, "GRUB generator hook", GRUB_HOOK_FILE_LIMIT)
        if error or contents is None or identity is None or xattrs is None or _identity(entry_info) != identity:
            return None
        total += len(contents)
        if total > GRUB_HOOK_TOTAL_LIMIT:
            return None
        files.append((entry.name, identity, hashlib.sha256(contents).hexdigest(), xattrs))
    try:
        after = _identity(GRUB_HOOKS_PATH.stat(follow_symlinks=False))
    except OSError:
        return None
    if after != directory_identity:
        return None
    return (directory_identity, tuple(files))


def _grub_default_dropins_state() -> tuple[object, ...] | None:
    path = GRUB_DEFAULT_DROPINS_PATH
    try:
        resolved = path.resolve(strict=True)
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        try:
            if path.parent.resolve(strict=True) != path.parent:
                return None
            parent_info = path.parent.stat(follow_symlinks=False)
        except (OSError, RuntimeError, ValueError):
            return None
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or parent_info.st_mode & 0o022
        ):
            return None
        return ("absent", _identity(parent_info))
    except (OSError, RuntimeError, ValueError):
        return None
    if (
        resolved != path
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
    ):
        return None
    try:
        with os.scandir(path) as scan:
            entries = list(scan)
    except OSError:
        return None
    if entries:
        return None
    try:
        after = _identity(path.stat(follow_symlinks=False))
    except OSError:
        return None
    return ("empty", after) if after == _identity(info) else None


def _grub_helper_state() -> tuple[object, ...] | None:
    found: list[tuple[object, ...]] = []
    for path in GRUB_LIBRARY_PATHS:
        if not path.exists():
            continue
        contents, identity, xattrs, error = _read_rooted_file(path, "grub-mkconfig support library", GRUB_HOOK_FILE_LIMIT)
        if error or contents is None or identity is None or xattrs is None:
            return None
        found.append((str(path), identity, hashlib.sha256(contents).hexdigest(), xattrs))
    if len(found) != 1:
        return None
    return tuple(found)


def _grub_auxiliary_state(env: dict[str, str]) -> tuple[str, tuple[int, ...], tuple[object, ...], tuple[object, ...], tuple[object, ...]] | None:
    generator, generator_identity = _safe_system_binary("grub-mkconfig", env)
    hooks_state = _grub_hooks_state()
    dropins_state = _grub_default_dropins_state()
    helper_state = _grub_helper_state()
    if (
        generator is None
        or generator_identity is None
        or hooks_state is None
        or dropins_state is None
        or helper_state is None
    ):
        return None
    return generator, generator_identity, hooks_state, dropins_state, helper_state


def _parse_grub_entries(contents: bytes) -> tuple[BootEntry, ...] | None:
    try:
        text = contents.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    entries: list[BootEntry] = []
    for raw_line in text.splitlines():
        match = GRUB_LINUX_LINE_RE.match(raw_line)
        if not match:
            continue
        try:
            words = shlex.split(match.group(2), posix=True)
        except ValueError:
            return None
        if not words or not words[0] or any(not word or "\x00" in word for word in words):
            return None
        entries.append(BootEntry(index=len(entries), kernel=words[0], arguments=tuple(words[1:])))
        if len(entries) > MAX_ENTRIES:
            return None
    return tuple(entries) if entries else None


def _split_shell_comment(value: str) -> tuple[str, str]:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            continue
        if character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index], value[index:]
    return value, ""


def _parse_grub_defaults(contents: bytes) -> tuple[str, dict[str, tuple[tuple[str, ...], int]], str | None]:
    try:
        text = contents.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "", {}, "The GRUB defaults file is not valid UTF-8."
    assignments: dict[str, tuple[tuple[str, ...], int]] = {}
    for index, raw_line in enumerate(text.splitlines(keepends=True)):
        line = raw_line.rstrip("\r\n")
        match = GRUB_DEFAULT_ASSIGNMENT_RE.match(line)
        if not match:
            if re.match(r"^[ \t]*(?:export[ \t]+)?GRUB_CMDLINE_LINUX(?:_DEFAULT)?(?:\+)?[ \t]*=", line):
                return "", {}, "The GRUB kernel argument assignment uses unsupported shell syntax."
            continue
        name = match.group(1)
        if name in assignments:
            return "", {}, f"The GRUB defaults file repeats {name}; refusing ambiguous shell semantics."
        code, _comment = _split_shell_comment(match.group(2))
        try:
            words = shlex.split(code, posix=True)
        except ValueError:
            return "", {}, f"The GRUB defaults value {name} has malformed quoting."
        if len(words) > 1:
            return "", {}, f"The GRUB defaults value {name} must be one static quoted argument string."
        value = words[0] if words and words[0] else ""
        arguments = tuple(value.split())
        if any(not ARGUMENT_RE.fullmatch(item) for item in arguments):
            return "", {}, f"The GRUB defaults value {name} contains a dynamic or unsupported kernel argument."
        assignments[name] = (arguments, index)
    return text, assignments, None


def _rewrite_grub_defaults(
    contents: bytes,
    assignments: dict[str, tuple[tuple[str, ...], int]],
    action: KernelCommandLineAction,
    argument: str,
) -> bytes | None:
    text = contents.decode("utf-8", errors="strict")
    lines = text.splitlines(keepends=True)
    if action == "add":
        updated = list(dict(assignments).get("GRUB_CMDLINE_LINUX", ((), -1))[0])
        updated.append(argument)
        targets = {"GRUB_CMDLINE_LINUX": tuple(updated)}
    else:
        targets = {
            name: tuple(item for item in values if item != argument)
            for name, (values, _index) in assignments.items()
            if argument in values
        }
    for name, new_arguments in targets.items():
        current = assignments.get(name)
        quoted = shlex.quote(" ".join(new_arguments))
        if current is None:
            if action != "add" or name != "GRUB_CMDLINE_LINUX":
                continue
            if lines and not lines[-1].endswith(("\n", "\r")):
                lines[-1] += "\n"
            lines.append(f"{name}={quoted}\n")
            continue
        line_index = current[1]
        line = lines[line_index]
        newline = "\n" if line.endswith("\n") else ""
        if line.endswith("\r\n"):
            newline = "\r\n"
        body = line[:-len(newline)] if newline else line
        equals_index = body.find("=")
        if equals_index < 0:
            return None
        _code, comment = _split_shell_comment(body[equals_index + 1:])
        comment_spacing = " " if comment and not body[equals_index + 1:].rstrip().endswith(" ") else ""
        lines[line_index] = f"{body[:equals_index + 1]}{quoted}{comment_spacing}{comment}{newline}"
    if action == "remove" and not targets:
        return None
    return "".join(lines).encode("utf-8")


def _read_grub_configuration(
    env: dict[str, str],
) -> tuple[GrubConfigSnapshot | None, tuple[BootEntry, ...] | None, str | None]:
    auxiliary = _grub_auxiliary_state(env)
    if auxiliary is None:
        return None, None, "A safe grub-mkconfig executable, trusted generator inputs, and an unambiguous supported GRUB layout are required."
    generator, generator_identity, hooks_state, dropins_state, helper_state = auxiliary
    defaults_bytes, defaults_identity, defaults_xattrs, error = _read_rooted_file(
        GRUB_DEFAULTS_PATH, "GRUB defaults file", GRUB_DEFAULT_LIMIT
    )
    if error or defaults_bytes is None or defaults_identity is None or defaults_xattrs is None:
        return None, None, error or "The GRUB defaults file could not be verified."
    _defaults_text, assignments, error = _parse_grub_defaults(defaults_bytes)
    if error:
        return None, None, error

    existing_outputs = [path for path in GRUB_OUTPUT_PATHS if path.exists()]
    if len(existing_outputs) != 1:
        return None, None, "Exactly one existing standard GRUB configuration at /boot/grub/grub.cfg or /boot/grub2/grub.cfg is required."
    output_path = existing_outputs[0]
    output_bytes, output_identity, output_xattrs, error = _read_rooted_file(
        output_path, "generated GRUB configuration", GRUB_OUTPUT_LIMIT
    )
    if error or output_bytes is None or output_identity is None or output_xattrs is None:
        return None, None, error or "The generated GRUB configuration could not be verified."
    for attr_name, _value in (*defaults_xattrs, *output_xattrs):
        if attr_name in {"security.capability", "security.ima", "security.evm"}:
            return None, None, "GRUB configuration files with capability or integrity-protection attributes are not supported."
    entries = _parse_grub_entries(output_bytes)
    if entries is None:
        return None, None, "The generated GRUB configuration has no supported Linux entries or contains malformed command lines."

    defaults_parent_identity = _safe_rooted_directory(GRUB_DEFAULTS_PATH.parent, "GRUB defaults directory")
    output_parent_identity = _safe_rooted_directory(output_path.parent, "GRUB configuration directory")
    if (
        defaults_parent_identity is None
        or output_parent_identity is None
        or not os.access(GRUB_DEFAULTS_PATH.parent, os.W_OK)
        or not os.access(output_path.parent, os.W_OK)
    ):
        return None, None, "The GRUB defaults and output directories must be safely owned and writable with current OS permissions."
    defaults_arguments = tuple(sorted((name, values) for name, (values, _index) in assignments.items()))
    state = GrubConfigSnapshot(
        defaults_path=GRUB_DEFAULTS_PATH,
        defaults_bytes=defaults_bytes,
        defaults_identity=defaults_identity,
        defaults_parent_identity=defaults_parent_identity,
        defaults_xattrs=defaults_xattrs,
        defaults_arguments=defaults_arguments,
        output_path=output_path,
        output_bytes=output_bytes,
        output_identity=output_identity,
        output_parent_identity=output_parent_identity,
        output_xattrs=output_xattrs,
        generator=generator,
        generator_identity=generator_identity,
        hooks_state=hooks_state,
        dropins_state=dropins_state,
        helper_state=helper_state,
        replacement_bytes=defaults_bytes,
    )
    return state, entries, None


def _normalized_grub_output(contents: bytes, argument: str) -> tuple[str, ...] | None:
    try:
        text = contents.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    normalized: list[str] = []
    for line in text.splitlines(keepends=True):
        newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        body = line[:-len(newline)] if newline else line
        match = GRUB_LINUX_LINE_RE.match(body)
        if not match:
            normalized.append(line)
            continue
        try:
            words = shlex.split(match.group(2), posix=True)
        except ValueError:
            return None
        if not words:
            return None
        words = [words[0], *(word for word in words[1:] if word != argument)]
        prefix = body[:match.start(2)]
        normalized.append(f"{prefix}{shlex.join(words)}{newline}")
    return tuple(normalized)


def _grub_config_target(
    action: str,
    argument: str,
) -> tuple[KernelCommandLineTarget | None, str | None]:
    if action not in {"add", "remove"}:
        return None, "action must be add or remove."
    normalized_argument = _normalize_argument(argument)
    if normalized_argument is None:
        return None, "argument must be one simple kernel token; root= and leading-dash options are refused."
    env = _environment()
    snapshot, entries, error = _read_grub_configuration(env)
    if error or snapshot is None or entries is None:
        return None, error or "The generated GRUB state could not be verified."
    try:
        _text, assignments, error = _parse_grub_defaults(snapshot.defaults_bytes)
    except (UnicodeDecodeError, ValueError):
        return None, "The GRUB defaults file could not be parsed safely."
    if error:
        return None, error
    key = normalized_argument.partition("=")[0]
    matching_entries = sum(normalized_argument in entry.arguments for entry in entries)
    configured = [item for _name, values in snapshot.defaults_arguments for item in values]
    if action == "add":
        conflicts = [
            entry.index for entry in entries
            if any(item.partition("=")[0] == key and item != normalized_argument for item in entry.arguments)
        ]
        if conflicts or any(
            item.partition("=")[0] == key and item != normalized_argument for item in configured
        ):
            return None, "A current Linux entry or GRUB defaults assignment has a different value for this argument key; remove that exact value first."
        if normalized_argument in configured:
            return None, "The exact argument is already present in a supported GRUB defaults assignment."
        if matching_entries:
            return None, "The argument already appears in generated Linux entries; refusing to duplicate or partially change it."
    else:
        if matching_entries == 0:
            return None, "The exact argument is not present in any generated Linux entry."
        if matching_entries != len(entries):
            return None, "The exact argument is not present in every generated Linux entry; refusing a partial GRUB defaults change."
        if not any(normalized_argument in values for _name, values in snapshot.defaults_arguments):
            return None, "The argument is present in generated entries but not in a supported static GRUB defaults assignment."

    replacement = _rewrite_grub_defaults(snapshot.defaults_bytes, assignments, action, normalized_argument)
    if replacement is None or len(replacement) > GRUB_DEFAULT_LIMIT:
        return None, "The GRUB defaults update could not be represented as a bounded static assignment."
    if replacement == snapshot.defaults_bytes:
        return None, "The requested GRUB defaults change would not change the configuration."
    target_snapshot = replace(snapshot, replacement_bytes=replacement)
    material = {
        "backend": "grub_config",
        "action": action,
        "argument": normalized_argument,
        "entries": [
            {"index": entry.index, "kernel": entry.kernel, "arguments": list(entry.arguments)}
            for entry in entries
        ],
        "defaults_sha256": hashlib.sha256(snapshot.defaults_bytes).hexdigest(),
        "defaults_identity": list(snapshot.defaults_identity),
        "defaults_parent_identity": list(snapshot.defaults_parent_identity),
        "defaults_xattrs": snapshot.defaults_xattrs,
        "output_path": str(snapshot.output_path),
        "output_sha256": hashlib.sha256(snapshot.output_bytes).hexdigest(),
        "output_identity": list(snapshot.output_identity),
        "output_parent_identity": list(snapshot.output_parent_identity),
        "output_xattrs": snapshot.output_xattrs,
        "generator": snapshot.generator,
        "generator_identity": list(snapshot.generator_identity),
        "hooks_state": snapshot.hooks_state,
        "dropins_state": snapshot.dropins_state,
        "helper_state": snapshot.helper_state,
    }
    token = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("ascii")).hexdigest()
    return KernelCommandLineTarget(
        backend="grub_config",
        action=action,  # type: ignore[arg-type]
        argument=normalized_argument,
        entries=entries,
        inventory_digest=hashlib.sha256(snapshot.output_bytes).hexdigest(),
        binary=snapshot.generator,
        binary_identity=snapshot.generator_identity,
        state_token=token,
        grub_config=target_snapshot,
    ), None


def _grubby_binary(env: dict[str, str]) -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    binary = find_session_binary("grubby", env)
    if not binary:
        return None
    try:
        resolved = os.path.realpath(binary, strict=True)
        info = os.stat(resolved, follow_symlinks=False)
    except (OSError, RuntimeError, ValueError):
        return None
    candidate = Path(resolved)
    for parent in reversed(candidate.parents):
        try:
            parent_info = parent.stat(follow_symlinks=False)
        except OSError:
            return None
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or parent_info.st_mode & 0o022
        ):
            return None
    if (
        not stat.S_ISREG(info.st_mode)
        or not os.access(resolved, os.X_OK)
        or info.st_uid != 0
        or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
    ):
        return None
    return resolved


def kernel_command_line_control_available(env: dict[str, str] | None = None) -> bool:
    sanitized = env or _environment()
    if _grubby_binary(sanitized) is not None:
        return True
    snapshot, entries, error = _read_grub_configuration(sanitized)
    return snapshot is not None and entries is not None and error is None


def _binary_snapshot(binary: str) -> tuple[int, ...] | None:
    try:
        info = os.stat(binary, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _parse_value(raw: str) -> str | None:
    try:
        parts = shlex.split(raw, posix=True)
    except ValueError:
        return None
    if len(parts) != 1:
        return None
    return parts[0]


def _parse_arguments(raw: str) -> tuple[str, ...] | None:
    try:
        outer = shlex.split(raw, posix=True)
    except ValueError:
        return None
    if raw.lstrip().startswith(("'", '"')):
        if len(outer) != 1:
            return None
        encoded = outer[0]
        try:
            return tuple(shlex.split(encoded, posix=True)) if encoded else ()
        except ValueError:
            return None
    return tuple(outer)


def _parse_inventory(output: str) -> tuple[BootEntry, ...] | None:
    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        key, separator, raw_value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", key):
            return None
        if key == "index":
            if current is not None:
                records.append(current)
            current = {}
        if current is None or key in current:
            return None
        current[key] = raw_value
    if current is not None:
        records.append(current)
    if not records or len(records) > MAX_ENTRIES:
        return None

    entries: list[BootEntry] = []
    seen: set[tuple[int, str]] = set()
    for record in records:
        index_text = record.get("index")
        kernel_text = record.get("kernel")
        args_text = record.get("args")
        if (
            index_text is None
            or not re.fullmatch(r"[0-9]{1,5}", index_text)
            or kernel_text is None
            or args_text is None
        ):
            return None
        kernel = _parse_value(kernel_text)
        arguments = _parse_arguments(args_text)
        if not kernel or arguments is None or any(not item or "\x00" in item for item in arguments):
            return None
        index = int(index_text, 10)
        entry = BootEntry(index=index, kernel=kernel, arguments=arguments)
        if entry.identity in seen:
            return None
        seen.add(entry.identity)
        entries.append(entry)
    entries.sort(key=lambda entry: (entry.index, entry.kernel))
    return tuple(entries)


def _read_inventory(
    binary: str,
    env: dict[str, str],
) -> tuple[tuple[BootEntry, ...] | None, str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "--info=ALL"],
        env,
        command_label="grubby boot-entry inventory",
        timeout_seconds=QUERY_TIMEOUT_SECONDS,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    if error or output is None:
        return None, None, "The complete grubby boot-entry inventory could not be read with current permissions."
    if truncated:
        return None, None, "The grubby boot-entry inventory exceeded its output limit."
    entries = _parse_inventory(output)
    if entries is None:
        return None, None, "The grubby boot-entry inventory was malformed, empty, or over its entry limit."
    return entries, hashlib.sha256(output.encode("utf-8")).hexdigest(), None


def _normalize_argument(value: object) -> str | None:
    if not isinstance(value, str) or not ARGUMENT_RE.fullmatch(value) or value.startswith("-"):
        return None
    key = value.partition("=")[0]
    # grubby gives root= special treatment; refusing it keeps this tool from
    # changing how the system locates its root filesystem.
    if key.casefold() == "root":
        return None
    return value


def kernel_command_line_confirmation_details(
    action: str,
    argument: str,
) -> tuple[KernelCommandLineTarget | None, str | None]:
    if action not in {"add", "remove"}:
        return None, "action must be add or remove."
    normalized_argument = _normalize_argument(argument)
    if normalized_argument is None:
        return None, "argument must be one simple kernel token; root= and leading-dash options are refused."
    env = _environment()
    binary = _grubby_binary(env)
    if binary is None:
        return _grub_config_target(action, normalized_argument)
    binary_identity = _binary_snapshot(binary)
    if binary_identity is None:
        return None, "The grubby executable identity could not be verified."
    entries, inventory_digest, error = _read_inventory(binary, env)
    if error or entries is None or inventory_digest is None:
        return None, error or "The complete boot-entry inventory could not be verified."

    key = normalized_argument.partition("=")[0]
    matching_entries = sum(normalized_argument in entry.arguments for entry in entries)
    if action == "add":
        conflicts = [
            entry.index
            for entry in entries
            if any(
                item.partition("=")[0] == key and item != normalized_argument
                for item in entry.arguments
            )
        ]
        if conflicts:
            return None, "A boot entry has a different value for this argument key; remove that exact value before adding another."
        if matching_entries == len(entries):
            return None, "The exact argument is already present in every current boot entry."
    elif matching_entries == 0:
        return None, "The exact argument is not present in any current boot entry."

    material = {
        "backend": "grubby",
        "action": action,
        "argument": normalized_argument,
        "entries": [
            {"index": entry.index, "kernel": entry.kernel, "arguments": list(entry.arguments)}
            for entry in entries
        ],
        "inventory_digest": inventory_digest,
        "binary": binary,
        "binary_identity": list(binary_identity),
    }
    state_token = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return KernelCommandLineTarget(
        backend="grubby",
        action=action,  # type: ignore[arg-type]
        argument=normalized_argument,
        entries=entries,
        inventory_digest=inventory_digest,
        binary=binary,
        binary_identity=binary_identity,
        state_token=state_token,
    ), None


def _verify_expected_arguments(
    before: tuple[BootEntry, ...],
    after: tuple[BootEntry, ...],
    action: KernelCommandLineAction,
    argument: str,
) -> bool:
    before_by_id = {entry.identity: entry for entry in before}
    after_by_id = {entry.identity: entry for entry in after}
    if before_by_id.keys() != after_by_id.keys():
        return False
    for identity, old_entry in before_by_id.items():
        new_entry = after_by_id[identity]
        if action == "add":
            expected = Counter(old_entry.arguments)
            if argument not in expected:
                expected[argument] += 1
        else:
            expected = Counter(old_entry.arguments)
            expected.pop(argument, None)
        if Counter(new_entry.arguments) != expected:
            return False
    return True


def _response(
    action: KernelCommandLineAction,
    argument: str,
    *,
    success: bool,
    affected_entries: int = 0,
    user_confirmed: bool,
    message: str,
) -> KernelCommandLineResponse:
    return KernelCommandLineResponse(
        success=success,
        action=action,
        argument=argument,
        affected_entries=affected_entries,
        user_confirmed=user_confirmed,
        message=message,
    )


def _write_all(descriptor: int, contents: bytes) -> None:
    view = memoryview(contents)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("The filesystem accepted no bytes while writing the temporary file.")
        view = view[written:]


def _copy_file_xattrs(descriptor: int, attributes: tuple[tuple[str, bytes], ...]) -> None:
    for name, value in attributes:
        os.setxattr(descriptor, name, value)


def _temporary_file_at(
    directory_fd: int,
    prefix: str,
    contents: bytes,
    *,
    uid: int,
    gid: int,
    mode: int,
    xattrs: tuple[tuple[str, bytes], ...],
) -> tuple[str, tuple[int, ...]]:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    for _attempt in range(12):
        name = f".{prefix}.{secrets.token_hex(10)}.tmp"
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError:
            continue
        try:
            _write_all(descriptor, contents)
            current = os.fstat(descriptor)
            if (current.st_uid, current.st_gid) != (uid, gid):
                os.fchown(descriptor, uid, gid)
            _copy_file_xattrs(descriptor, xattrs)
            os.fchmod(descriptor, stat.S_IMODE(mode))
            os.fsync(descriptor)
            return name, _identity(os.fstat(descriptor))
        except Exception:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)
    raise OSError("A unique temporary file name could not be reserved.")


def _read_at(
    directory_fd: int,
    name: str,
    *,
    max_bytes: int,
    expected_identity: tuple[int, ...] | None = None,
    require_root: bool = True,
) -> tuple[bytes | None, tuple[int, ...] | None, tuple[tuple[str, bytes], ...] | None]:
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (require_root and before.st_uid != 0)
            or before.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or before.st_size < 1
            or before.st_size > max_bytes
            or (expected_identity is not None and (before.st_dev, before.st_ino) != expected_identity[:2])
        ):
            return None, None, None
        attrs_before = _read_xattrs(descriptor)
        if attrs_before is None:
            return None, None, None
        contents = bytearray()
        while len(contents) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
        after = os.fstat(descriptor)
        attrs_after = _read_xattrs(descriptor)
        if (
            len(contents) > max_bytes
            or _identity(before) != _identity(after)
            or attrs_before != attrs_after
            or (expected_identity is not None and _identity(after) != expected_identity)
        ):
            return None, None, None
        return bytes(contents), _identity(after), attrs_after
    except OSError:
        return None, None, None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _atomic_replace_rooted_file(
    path: Path,
    *,
    expected_parent_identity: tuple[int, ...],
    expected_identity: tuple[int, ...],
    expected_sha256: str,
    replacement: bytes,
    replacement_xattrs: tuple[tuple[str, bytes], ...],
    owner_uid: int,
    owner_gid: int,
    mode: int,
    max_bytes: int,
) -> tuple[int, ...]:
    parent_fd: int | None = None
    temp_name: str | None = None
    backup_name: str | None = None
    published = False
    try:
        parent_fd = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        parent_info = os.fstat(parent_fd)
        expected_parent = _safe_rooted_directory(path.parent, "GRUB configuration directory")
        if (
            expected_parent is None
            or expected_parent != expected_parent_identity
            or _identity(parent_info) != expected_parent_identity
        ):
            raise OSError("The GRUB configuration directory changed after confirmation.")
        current_bytes, current_identity, current_xattrs, error = _read_rooted_file(path, "GRUB configuration file", max_bytes)
        if (
            error
            or current_bytes is None
            or current_identity != expected_identity
            or hashlib.sha256(current_bytes).hexdigest() != expected_sha256
            or current_xattrs is None
            or current_xattrs != replacement_xattrs
        ):
            raise OSError("The exact GRUB configuration file changed after confirmation.")
        current_stat = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity(current_stat) != expected_identity:
            raise OSError("The GRUB configuration path changed after confirmation.")
        temp_name, temp_identity = _temporary_file_at(
            parent_fd,
            path.name,
            replacement,
            uid=owner_uid,
            gid=owner_gid,
            mode=mode,
            xattrs=replacement_xattrs,
        )
        if temp_identity[0:2] == expected_identity[0:2]:
            raise OSError("The temporary file unexpectedly shares the target identity.")
        backup_name = f".{path.name}.backup.{secrets.token_hex(10)}"
        os.link(path.name, backup_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        backup_info = os.stat(backup_name, dir_fd=parent_fd, follow_symlinks=False)
        linked_target = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (backup_info.st_dev, backup_info.st_ino) != expected_identity[:2]
            or (linked_target.st_dev, linked_target.st_ino) != expected_identity[:2]
            or linked_target.st_nlink != expected_identity[3] + 1
        ):
            if (backup_info.st_dev, backup_info.st_ino) != (linked_target.st_dev, linked_target.st_ino):
                raise OSError(
                    f"The GRUB configuration changed during the rollback check; the prior file is preserved at {path.parent / backup_name}."
                )
            raise OSError("The GRUB configuration changed while its rollback link was created.")
        os.replace(temp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_name = None
        published = True
        os.fsync(parent_fd)
        after_bytes, after_identity, after_xattrs = _read_at(
            parent_fd, path.name, max_bytes=max_bytes, require_root=True
        )
        if (
            after_bytes != replacement
            or after_identity is None
            or after_identity[4] != owner_uid
            or after_identity[5] != owner_gid
            or stat.S_IMODE(after_identity[2]) != stat.S_IMODE(mode)
            or after_xattrs != replacement_xattrs
        ):
            os.replace(backup_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            backup_name = None
            published = False
            os.fsync(parent_fd)
            raise OSError("The GRUB configuration did not match after atomic replacement.")
        os.unlink(backup_name, dir_fd=parent_fd)
        backup_name = None
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        return after_identity
    except OSError as replacement_error:
        if published and backup_name is not None and parent_fd is not None:
            try:
                backup_info = os.stat(backup_name, dir_fd=parent_fd, follow_symlinks=False)
                current_info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                if (current_info.st_dev, current_info.st_ino) != (backup_info.st_dev, backup_info.st_ino):
                    os.replace(backup_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                else:
                    os.unlink(backup_name, dir_fd=parent_fd)
                backup_name = None
                os.fsync(parent_fd)
            except OSError as restore_error:
                # Keep the hard-link backup if restoration fails so the prior file is recoverable.
                recovery_path = path.parent / backup_name
                raise OSError(
                    f"Atomic replacement failed ({replacement_error}); the prior file may need recovery from {recovery_path} ({restore_error})."
                ) from restore_error
        raise
    finally:
        if temp_name is not None and parent_fd is not None:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:
                pass
        if parent_fd is not None:
            if backup_name is not None:
                try:
                    backup_info = os.stat(backup_name, dir_fd=parent_fd, follow_symlinks=False)
                    current_info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                    if (current_info.st_dev, current_info.st_ino) == (backup_info.st_dev, backup_info.st_ino):
                        os.unlink(backup_name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)


def _create_grub_output_temp(snapshot: GrubConfigSnapshot) -> tuple[str, tuple[int, ...]]:
    directory_fd = os.open(
        snapshot.output_path.parent,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        directory_info = os.fstat(directory_fd)
        expected_directory = _safe_rooted_directory(snapshot.output_path.parent, "GRUB configuration directory")
        if (
            expected_directory is None
            or expected_directory != snapshot.output_parent_identity
            or _identity(directory_info) != snapshot.output_parent_identity
        ):
            raise OSError("The GRUB configuration directory changed after confirmation.")
        name, identity = _temporary_file_at(
            directory_fd,
            snapshot.output_path.name,
            b"\n",
            uid=snapshot.output_identity[4],
            gid=snapshot.output_identity[5],
            mode=snapshot.output_identity[2],
            xattrs=snapshot.output_xattrs,
        )
        return name, identity
    finally:
        os.close(directory_fd)


def _prepare_generated_output(
    snapshot: GrubConfigSnapshot,
    temp_name: str,
    temp_identity: tuple[int, ...],
) -> tuple[bytes | None, str | None]:
    directory_fd: int | None = None
    descriptor: int | None = None
    try:
        directory_fd = os.open(
            snapshot.output_path.parent,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        directory_identity = _safe_rooted_directory(snapshot.output_path.parent, "GRUB configuration directory")
        if (
            directory_identity is None
            or not _same_directory_identity(directory_identity, snapshot.output_parent_identity)
            or not _same_directory_identity(_identity(os.fstat(directory_fd)), snapshot.output_parent_identity)
        ):
            return None, "The GRUB configuration directory changed after confirmation."
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(temp_name, flags, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != temp_identity[:2]
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > GRUB_OUTPUT_LIMIT
        ):
            return None, "grub-mkconfig did not produce a bounded regular configuration at the reserved temporary path."
        data = bytearray()
        os.lseek(descriptor, 0, os.SEEK_SET)
        while len(data) <= GRUB_OUTPUT_LIMIT:
            chunk = os.read(descriptor, min(64 * 1024, GRUB_OUTPUT_LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > GRUB_OUTPUT_LIMIT:
            return None, "The generated GRUB configuration exceeded its supported size limit."
        if _parse_grub_entries(bytes(data)) is None:
            return None, "The generated GRUB configuration contains no supported Linux entries or malformed command lines."
        current = os.fstat(descriptor)
        if _identity(before) != _identity(current):
            return None, "The temporary GRUB configuration changed while it was being inspected."
        if (current.st_uid, current.st_gid) != (snapshot.output_identity[4], snapshot.output_identity[5]):
            os.fchown(descriptor, snapshot.output_identity[4], snapshot.output_identity[5])
        _copy_file_xattrs(descriptor, snapshot.output_xattrs)
        os.fchmod(descriptor, stat.S_IMODE(snapshot.output_identity[2]))
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        attrs = _read_xattrs(descriptor)
        if (
            attrs != snapshot.output_xattrs
            or (final.st_uid, final.st_gid) != (snapshot.output_identity[4], snapshot.output_identity[5])
            or stat.S_IMODE(final.st_mode) != stat.S_IMODE(snapshot.output_identity[2])
        ):
            return None, "The generated GRUB configuration could not preserve the existing file metadata."
        return bytes(data), None
    except OSError as exc:
        return None, f"The generated GRUB configuration could not be verified or prepared: {exc.strerror or 'filesystem error'}."
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)


def _publish_grub_output(
    snapshot: GrubConfigSnapshot,
    temp_name: str,
    generated: bytes,
) -> tuple[bool, str | None]:
    directory_fd: int | None = None
    backup_name: str | None = None
    verified_new_output = False
    try:
        directory_fd = os.open(
            snapshot.output_path.parent,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        directory_identity = _safe_rooted_directory(snapshot.output_path.parent, "GRUB configuration directory")
        if (
            directory_identity is None
            or not _same_directory_identity(directory_identity, snapshot.output_parent_identity)
            or not _same_directory_identity(_identity(os.fstat(directory_fd)), snapshot.output_parent_identity)
        ):
            return False, None
        old_bytes, old_identity, old_xattrs, error = _read_rooted_file(
            snapshot.output_path, "generated GRUB configuration", GRUB_OUTPUT_LIMIT
        )
        if (
            error
            or old_bytes != snapshot.output_bytes
            or old_identity != snapshot.output_identity
            or old_xattrs != snapshot.output_xattrs
        ):
            return False, None
        name = f".{snapshot.output_path.name}.backup.{secrets.token_hex(10)}"
        os.link(
            snapshot.output_path.name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        backup_name = name
        linked = os.stat(snapshot.output_path.name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            (linked.st_dev, linked.st_ino) != snapshot.output_identity[:2]
            or linked.st_nlink != snapshot.output_identity[3] + 1
        ):
            backup_info = os.stat(backup_name, dir_fd=directory_fd, follow_symlinks=False)
            if (backup_info.st_dev, backup_info.st_ino) != (linked.st_dev, linked.st_ino):
                backup_path = str(snapshot.output_path.parent / backup_name)
                backup_name = None
                return False, f" The prior generated config is preserved at {backup_path}; inspect the active config before retrying."
            return False, None
        os.replace(temp_name, snapshot.output_path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
        new_bytes, new_identity, new_xattrs = _read_at(
            directory_fd, snapshot.output_path.name, max_bytes=GRUB_OUTPUT_LIMIT, require_root=True
        )
        if (
            new_bytes != generated
            or new_identity is None
            or new_identity[4] != snapshot.output_identity[4]
            or new_identity[5] != snapshot.output_identity[5]
            or stat.S_IMODE(new_identity[2]) != stat.S_IMODE(snapshot.output_identity[2])
            or new_xattrs != snapshot.output_xattrs
        ):
            os.replace(backup_name, snapshot.output_path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            backup_name = None
            os.fsync(directory_fd)
            return False, None
        verified_new_output = True
        backup_path = str(snapshot.output_path.parent / backup_name)
        try:
            os.unlink(backup_name, dir_fd=directory_fd)
            backup_name = None
        except OSError:
            # Keep the old config as a recovery copy if cleanup fails after verified publication.
            backup_name = None
            return True, f" The previous generated config remains as a recovery copy at {backup_path}."
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        return True, None
    except OSError:
        if verified_new_output:
            if backup_name is not None:
                backup_path = str(snapshot.output_path.parent / backup_name)
                backup_name = None
                return True, f" The previous generated config remains as a recovery copy at {backup_path}."
            return True, " The new config was verified, but syncing the directory after backup cleanup failed."
        if backup_name is not None and directory_fd is not None:
            try:
                # If publication happened but verification failed, restore the original file.
                current = os.stat(snapshot.output_path.name, dir_fd=directory_fd, follow_symlinks=False)
                original_link = os.stat(backup_name, dir_fd=directory_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (original_link.st_dev, original_link.st_ino):
                    os.replace(backup_name, snapshot.output_path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                else:
                    os.unlink(backup_name, dir_fd=directory_fd)
                backup_name = None
                os.fsync(directory_fd)
            except OSError:
                if backup_name is not None:
                    backup_path = str(snapshot.output_path.parent / backup_name)
                    backup_name = None
                    return False, f" The previous generated config remains as a recovery copy at {backup_path}; inspect the active config before retrying."
        return False, None
    finally:
        if backup_name is not None and directory_fd is not None:
            try:
                backup_info = os.stat(backup_name, dir_fd=directory_fd, follow_symlinks=False)
                current_info = os.stat(snapshot.output_path.name, dir_fd=directory_fd, follow_symlinks=False)
                if (current_info.st_dev, current_info.st_ino) == (backup_info.st_dev, backup_info.st_ino):
                    os.unlink(backup_name, dir_fd=directory_fd)
            except OSError:
                pass
        if directory_fd is not None:
            os.close(directory_fd)


def _perform_grub_config_change(target: KernelCommandLineTarget, env: dict[str, str]) -> KernelCommandLineResponse:
    snapshot = target.grub_config
    if snapshot is None:
        return _response(target.action, target.argument, success=False, user_confirmed=True, message="The confirmed GRUB configuration snapshot is missing.")
    defaults_sha = hashlib.sha256(snapshot.defaults_bytes).hexdigest()
    current, error = _grub_config_target(target.action, target.argument)
    if error or current is None or current.state_token != target.state_token:
        return _response(
            target.action, target.argument, success=False, user_confirmed=True,
            message=error or "The GRUB defaults, generated config, generator, or hook state changed after confirmation; no update was run.",
        )
    directory_fd: int | None = None
    temp_name: str | None = None
    defaults_new_identity: tuple[int, ...] | None = None
    publication_attempted = False
    try:
        try:
            defaults_new_identity = _atomic_replace_rooted_file(
                snapshot.defaults_path,
                expected_parent_identity=snapshot.defaults_parent_identity,
                expected_identity=snapshot.defaults_identity,
                expected_sha256=defaults_sha,
                replacement=snapshot.replacement_bytes,
                replacement_xattrs=snapshot.defaults_xattrs,
                owner_uid=snapshot.defaults_identity[4],
                owner_gid=snapshot.defaults_identity[5],
                mode=snapshot.defaults_identity[2],
                max_bytes=GRUB_DEFAULT_LIMIT,
            )
        except OSError:
            # The atomic rename may have succeeded before a later metadata/fsync check failed.
            current_bytes, current_identity, current_xattrs, current_error = _read_rooted_file(
                snapshot.defaults_path, "GRUB defaults file", GRUB_DEFAULT_LIMIT
            )
            if (
                current_error is None
                and current_bytes == snapshot.replacement_bytes
                and current_xattrs == snapshot.defaults_xattrs
            ):
                defaults_new_identity = current_identity
            raise
        # Recheck generator inputs after the defaults replacement and before executing hooks.
        auxiliary = _grub_auxiliary_state(env)
        if auxiliary != (
            snapshot.generator,
            snapshot.generator_identity,
            snapshot.hooks_state,
            snapshot.dropins_state,
            snapshot.helper_state,
        ):
            raise OSError("The GRUB generator or its hook/config inputs changed after confirmation.")
        temp_name, temp_identity = _create_grub_output_temp(snapshot)
        temp_path = snapshot.output_path.parent / temp_name
        _output, command_error, truncated = run_bounded_command(
            [snapshot.generator, "-o", str(temp_path)],
            env,
            command_label="confirmed grub-mkconfig generation",
            timeout_seconds=180,
            max_output_bytes=MAX_OUTPUT_BYTES,
        )
        if command_error or _output is None or truncated:
            raise OSError("grub-mkconfig did not complete within its output and time limits.")
        if _grub_auxiliary_state(env) != (
            snapshot.generator,
            snapshot.generator_identity,
            snapshot.hooks_state,
            snapshot.dropins_state,
            snapshot.helper_state,
        ):
            raise OSError("The GRUB generator or its hook/config inputs changed during generation.")
        defaults_now, defaults_identity_now, defaults_xattrs_now, defaults_error = _read_rooted_file(
            snapshot.defaults_path, "GRUB defaults file", GRUB_DEFAULT_LIMIT
        )
        if (
            defaults_error
            or defaults_now != snapshot.replacement_bytes
            or defaults_identity_now != defaults_new_identity
            or defaults_xattrs_now != snapshot.defaults_xattrs
        ):
            raise OSError("The GRUB defaults file changed while generation was running.")
        generated, generated_error = _prepare_generated_output(snapshot, temp_name, temp_identity)
        if generated_error or generated is None:
            raise OSError(generated_error or "The generated GRUB configuration could not be read.")
        before_normalized = _normalized_grub_output(snapshot.output_bytes, target.argument)
        after_normalized = _normalized_grub_output(generated, target.argument)
        after_entries = _parse_grub_entries(generated)
        if (
            before_normalized is None
            or after_normalized is None
            or before_normalized != after_normalized
            or after_entries is None
            or not _verify_expected_arguments(target.entries, after_entries, target.action, target.argument)
        ):
            raise OSError("The generated config changed content beyond the requested argument or failed entry verification.")
        publication_attempted = True
        published, publish_warning = _publish_grub_output(snapshot, temp_name, generated)
        temp_name = None if published else temp_name
        if not published:
            raise OSError(
                "The generated GRUB config could not be atomically installed and verified."
                f"{publish_warning or ''}"
            )
        affected = sum(
            (target.argument not in old.arguments) if target.action == "add" else (target.argument in old.arguments)
            for old in target.entries
        )
        return _response(
            target.action,
            target.argument,
            success=True,
            affected_entries=affected,
            user_confirmed=True,
            message=(
                f"The exact argument was {('added to' if target.action == 'add' else 'removed from')} "
                f"{affected} generated GRUB Linux entr{'y' if affected == 1 else 'ies'}; "
                "the static /etc/default/grub assignment and generated config were verified."
                f"{publish_warning or ''}"
            ),
        )
    except OSError as exc:
        if temp_name is not None:
            try:
                directory_fd = os.open(
                    snapshot.output_path.parent,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                )
                os.unlink(temp_name, dir_fd=directory_fd)
            except OSError:
                pass
            finally:
                if directory_fd is not None:
                    os.close(directory_fd)
                    directory_fd = None
        rollback_message = ""
        if defaults_new_identity is not None:
            try:
                _atomic_replace_rooted_file(
                    snapshot.defaults_path,
                    expected_parent_identity=snapshot.defaults_parent_identity,
                    expected_identity=defaults_new_identity,
                    expected_sha256=hashlib.sha256(snapshot.replacement_bytes).hexdigest(),
                    replacement=snapshot.defaults_bytes,
                    replacement_xattrs=snapshot.defaults_xattrs,
                    owner_uid=snapshot.defaults_identity[4],
                    owner_gid=snapshot.defaults_identity[5],
                    mode=snapshot.defaults_identity[2],
                    max_bytes=GRUB_DEFAULT_LIMIT,
                )
                rollback_message = (
                    " The original GRUB defaults file was restored; inspect the active generated config and any recovery copy because publication was attempted."
                    if publication_attempted
                    else " The original GRUB defaults file was restored; the generated boot config was not installed."
                )
            except OSError:
                rollback_message = " The GRUB defaults file may still contain the requested change; inspect it and the generated config before retrying."
        return _response(
            target.action,
            target.argument,
            success=False,
            user_confirmed=True,
            message=f"GRUB generation was not committed: {exc}.{rollback_message}",
        )


def perform_kernel_command_line_change(
    action: str,
    argument: str,
    *,
    confirmed: bool,
    confirmed_action: str | None = None,
    confirmed_argument: str | None = None,
    state_token: str | None = None,
) -> KernelCommandLineResponse:
    safe_action: KernelCommandLineAction = action if action in {"add", "remove"} else "add"
    safe_argument = argument if isinstance(argument, str) else ""
    target, error = kernel_command_line_confirmation_details(action, argument)
    if error or target is None:
        return _response(
            safe_action, safe_argument, success=False, user_confirmed=confirmed is True,
            message=error or "The boot-entry update could not be verified.",
        )
    if not confirmed:
        return _response(
            target.action, target.argument, success=False, user_confirmed=False,
            message="Explicit client confirmation is required; no kernel command-line entry was changed.",
        )
    if (
        confirmed_action != target.action
        or confirmed_argument != target.argument
        or state_token != target.state_token
    ):
        return _response(
            target.action, target.argument, success=False, user_confirmed=True,
            message="Confirmation did not repeat the exact action, argument, and state-bound phrase.",
        )

    with _ACTION_LOCK:
        current, error = kernel_command_line_confirmation_details(action, argument)
        if error or current is None or current.state_token != target.state_token:
            return _response(
                target.action, target.argument, success=False, user_confirmed=True,
                message=error or "The boot configuration or its generator state changed after confirmation; no update was run.",
            )
        env = _environment()
        if target.backend == "grub_config":
            return _perform_grub_config_change(target, env)
        binary_identity = _binary_snapshot(target.binary)
        if binary_identity != target.binary_identity:
            return _response(
                target.action, target.argument, success=False, user_confirmed=True,
                message="The grubby executable changed after confirmation; no update was run.",
            )
        option = "--args" if target.action == "add" else "--remove-args"
        _output, command_error, truncated = run_bounded_command(
            [target.binary, "--update-kernel=ALL", f"{option}={target.argument}"],
            env,
            command_label=f"grubby {target.action} confirmed kernel command-line argument",
            timeout_seconds=ACTION_TIMEOUT_SECONDS,
            max_output_bytes=MAX_OUTPUT_BYTES,
        )
        if command_error or _output is None or truncated:
            return _response(
                target.action, target.argument, success=False, user_confirmed=True,
                message="grubby did not complete the requested update. Inspect current boot entries before retrying; command output is withheld.",
            )
        after, _digest, read_error = _read_inventory(target.binary, env)
        if after is None or read_error:
            return _response(
                target.action, target.argument, success=False, user_confirmed=True,
                message="grubby ran, but the resulting boot-entry state could not be verified. Inspect current entries before retrying.",
            )
        if not _verify_expected_arguments(target.entries, after, target.action, target.argument):
            return _response(
                target.action, target.argument, success=False, user_confirmed=True,
                message="The resulting entries did not match the exact requested argument change. Inspect them before retrying.",
            )
        affected = sum(
            (argument not in old.arguments) if target.action == "add" else (argument in old.arguments)
            for old in target.entries
        )
        return _response(
            target.action, target.argument, success=True, affected_entries=affected,
            user_confirmed=True,
            message=(
                f"The exact argument was {('added to' if target.action == 'add' else 'removed from')} "
                f"{affected} current grubby boot entr{'y' if affected == 1 else 'ies'}. Future entries may use separate distributor templates."
            ),
        )
