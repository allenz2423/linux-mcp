"""Bounded, local-context Docker/Podman image builds with exact confirmation."""

from __future__ import annotations

import hashlib
import fnmatch
from functools import lru_cache
import io
import json
import os
import posixpath
import re
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlencode

from wayland_mcp.models import ContainerImageBuildResponse
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.containers import (
    ACTION_RUNTIMES,
    IMAGE_REF_RE,
    MAX_IMAGE_PULL_RESPONSE_BYTES,
    _Endpoint,
    _api_prefix,
    _available_endpoints,
    _endpoint_identity,
    _exact_image_match,
    _podman_env,
    _read_image_list,
    _request,
)

ContainerImageBuildRuntime = Literal["docker", "podman"]
MAX_CONTEXT_FILES = 2_000
MAX_CONTEXT_ENTRIES = 4_000
MAX_CONTEXT_FILE_BYTES = 32 * 1024 * 1024
MAX_CONTEXT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_CONTEXT_ARCHIVE_BYTES = 72 * 1024 * 1024
MAX_CONTEXT_PATH_BYTES = 4_096
MAX_IGNORE_RULES = 512
MAX_IGNORE_PATTERN_BYTES = 256
MAX_BUILD_TIMEOUT_SECONDS = 60 * 60.0
SPECIAL_CONTEXT_ROOTS = (Path("/proc"), Path("/sys"), Path("/dev"), Path("/run"))
IMAGE_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,254}$")


@dataclass(frozen=True, slots=True)
class _ContextEntry:
    path: str
    is_directory: bool
    mode: int
    contents: bytes | None


@dataclass(frozen=True, slots=True)
class _ContextSnapshot:
    root: Path
    dockerfile: str
    entries: tuple[_ContextEntry, ...]
    effective_entries: tuple[_ContextEntry, ...]
    archive: bytes
    digest: str
    file_count: int
    entry_count: int
    total_bytes: int
    included_file_count: int
    included_bytes: int


@dataclass(frozen=True, slots=True)
class _ImageBuildTarget:
    runtime: ContainerImageBuildRuntime
    scope: str
    endpoint: _Endpoint
    api_prefix: str | None
    tag: str
    context_path: str
    dockerfile: str
    context_archive: bytes
    context_entries: tuple[_ContextEntry, ...]
    context_digest: str
    file_count: int
    entry_count: int
    context_bytes: int
    included_file_count: int
    included_bytes: int
    state_digest: str
    endpoint_identity: tuple[object, ...]
    image_snapshot: tuple[tuple[str, tuple[str, ...]], ...]


def _open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def _same_file_snapshot(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_mode == after.st_mode
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _check_name(name: str, relative: str) -> None:
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise ValueError("The build context contains an unsafe path component.")
    try:
        name.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("The build context contains a filename that is not valid UTF-8.") from exc
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise ValueError("The build context contains a filename with control characters.")
    if len(relative.encode("utf-8")) > MAX_CONTEXT_PATH_BYTES:
        raise ValueError("A build-context path exceeds the length limit.")


def _read_exact_file(parent_fd: int, name: str, before: os.stat_result, root_device: int) -> bytes:
    file_fd = os.open(name, _open_flags(), dir_fd=parent_fd)
    try:
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_file_snapshot(before, opened) or opened.st_dev != root_device:
            raise ValueError("A build-context file changed or crossed a filesystem boundary during inspection.")
        if opened.st_size < 0 or opened.st_size > MAX_CONTEXT_FILE_BYTES:
            raise ValueError("A build-context file exceeds the per-file size limit.")
        contents = bytearray()
        while len(contents) <= opened.st_size:
            chunk = os.read(file_fd, min(1024 * 1024, opened.st_size + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
            if len(contents) > opened.st_size:
                raise ValueError("A build-context file grew while it was being read.")
        after = os.fstat(file_fd)
        if len(contents) != opened.st_size or not _same_file_snapshot(opened, after):
            raise ValueError("A build-context file changed while it was being read.")
        return bytes(contents)
    finally:
        os.close(file_fd)


@dataclass(frozen=True, slots=True)
class _IgnoreRule:
    parts: tuple[str | re.Pattern[str], ...]
    negate: bool


def _compile_ignore_glob(pattern: str) -> tuple[re.Pattern[str] | None, str | None]:
    """Compile the supported Go filepath.Match subset used by Docker ignore rules."""
    normalized: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern[index] != "[":
            normalized.append(pattern[index])
            index += 1
            continue
        class_start = index + 1
        negated = class_start < len(pattern) and pattern[class_start] == "^"
        if negated:
            class_start += 1
        close = pattern.find("]", class_start)
        if close < 0:
            return None, "The selected ignore file contains an unclosed character class."
        members = pattern[class_start:close]
        if not members:
            return None, "The selected ignore file contains an empty character class."
        if not negated and members.startswith("!"):
            return None, "A leading exclamation mark in a character class is unsupported; Docker uses ^ for class negation."
        if members.startswith("-") or members.endswith("-"):
            return None, "A leading or trailing hyphen in an ignore character class is unsupported."
        class_contents = ("!" if negated else "") + members
        normalized.append("[" + class_contents + "]")
        index = close + 1
    try:
        return re.compile(fnmatch.translate("".join(normalized))), None
    except re.error:
        return None, "The selected ignore file contains a malformed character class."


def _parse_ignore_rules(contents: bytes) -> tuple[list[_IgnoreRule] | None, str | None]:
    try:
        source = contents.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, "The selected ignore file must contain UTF-8 patterns."
    if source.startswith("\ufeff"):
        source = source[1:]
    rules: list[_IgnoreRule] = []
    for raw_line in source.splitlines():
        if raw_line.startswith("#"):
            continue
        line = raw_line.strip()
        if not line:
            continue
        negate = line.startswith("!")
        if negate:
            line = line[1:].strip()
        if not line:
            return None, "The selected ignore file contains an empty exception rule."
        if len(line.encode("utf-8")) > MAX_IGNORE_PATTERN_BYTES or "\\" in line:
            return None, "An ignore pattern exceeds its size limit or uses unsupported escaping."
        pattern = posixpath.normpath(line.strip("/"))
        if pattern in {"", "."}:
            continue
        parts = tuple(pattern.split("/"))
        if any(part in {"", "."} for part in parts):
            return None, "The selected ignore file contains a malformed path pattern."
        if any("**" in part and part != "**" for part in parts):
            return None, "Double-star wildcards must occupy a complete path component."
        compiled_parts: list[str | re.Pattern[str]] = []
        for part in parts:
            if part == "**":
                compiled_parts.append(part)
                continue
            compiled, error = _compile_ignore_glob(part)
            if error or compiled is None:
                return None, error or "The selected ignore file contains an unsupported path pattern."
            compiled_parts.append(compiled)
        rules.append(_IgnoreRule(parts=tuple(compiled_parts), negate=negate))
        if len(rules) > MAX_IGNORE_RULES:
            return None, "The selected ignore file exceeds the rule-count limit."
    return rules, None


def _matches_ignore_rule(rule: _IgnoreRule, path: str) -> bool:
    path_parts = tuple(path.split("/"))

    @lru_cache(maxsize=None)
    def matches(pattern_index: int, path_index: int) -> bool:
        if pattern_index == len(rule.parts):
            return path_index == len(path_parts)
        pattern = rule.parts[pattern_index]
        if pattern == "**":
            return matches(pattern_index + 1, path_index) or (
                path_index < len(path_parts) and matches(pattern_index, path_index + 1)
            )
        return (
            path_index < len(path_parts)
            and isinstance(pattern, re.Pattern)
            and pattern.fullmatch(path_parts[path_index]) is not None
            and matches(pattern_index + 1, path_index + 1)
        )

    # A directory match also applies to every descendant of that directory.
    return any(matches(0, end) for end in range(1, len(path_parts) + 1))


def _effective_context_entries(
    entries: list[_ContextEntry],
    runtime: str,
    dockerfile: str,
) -> tuple[tuple[_ContextEntry, ...] | None, int, str | None]:
    by_path = {entry.path: entry for entry in entries}
    if runtime == "docker":
        candidates = (f"{dockerfile}.dockerignore", ".dockerignore")
    else:
        candidates = (".containerignore", ".dockerignore")
    ignore_file = next((name for name in candidates if name in by_path and not by_path[name].is_directory), None)
    rules: list[_IgnoreRule] = []
    if ignore_file is not None:
        rules, error = _parse_ignore_rules(by_path[ignore_file].contents or b"")
        if error or rules is None:
            return None, 0, error or "The selected ignore file could not be parsed."

    direct_include: dict[str, bool] = {}
    for entry in entries:
        include = True
        for rule in rules:
            if _matches_ignore_rule(rule, entry.path):
                include = rule.negate
        direct_include[entry.path] = include

    included_paths = {path for path, include in direct_include.items() if include}
    included_paths.add(dockerfile)
    if ignore_file is not None:
        included_paths.add(ignore_file)
    for path in tuple(included_paths):
        parent = posixpath.dirname(path)
        while parent:
            included_paths.add(parent)
            parent = posixpath.dirname(parent)
    effective = tuple(entry for entry in entries if entry.path in included_paths)
    included_bytes = sum(
        len(entry.contents or b"") for entry in effective if not entry.is_directory
    )
    return effective, included_bytes, None


def _capture_context(context_dir: str, runtime: str) -> tuple[_ContextSnapshot | None, str | None]:
    if not isinstance(context_dir, str) or not context_dir or len(context_dir) > MAX_CONTEXT_PATH_BYTES:
        return None, "context_dir must be an absolute path of at most 4096 characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in context_dir):
        return None, "context_dir must not contain control characters."
    requested = Path(context_dir)
    if not requested.is_absolute():
        return None, "context_dir must be absolute."
    try:
        requested_info = requested.lstat()
        if stat.S_ISLNK(requested_info.st_mode):
            return None, "context_dir must be a real directory path, not a symlink."
        root = requested.resolve(strict=True)
        root_info = root.lstat()
        if not stat.S_ISDIR(root_info.st_mode):
            return None, "context_dir must name a directory."
        if any(root == blocked or blocked in root.parents for blocked in SPECIAL_CONTEXT_ROOTS):
            return None, "Build contexts under /proc, /sys, /dev, and /run are not accepted."
        root_fd = os.open(root, _open_flags(directory=True))
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"context_dir could not be opened safely: {type(exc).__name__}."

    entries: list[_ContextEntry] = []
    raw_bytes = 0
    error: str | None = None
    try:
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_dev != root_info.st_dev or root_stat.st_ino != root_info.st_ino:
            return None, "context_dir changed while it was being opened."

        def walk(directory_fd: int, parent: str) -> None:
            nonlocal raw_bytes
            before_dir = os.fstat(directory_fd)
            if not stat.S_ISDIR(before_dir.st_mode) or before_dir.st_dev != root_stat.st_dev:
                raise ValueError("The build context contains a mount point or changed directory.")
            try:
                names = sorted(os.listdir(directory_fd))
            except OSError as exc:
                raise ValueError("A build-context directory could not be listed safely.") from exc
            for name in names:
                relative = f"{parent}/{name}" if parent else name
                _check_name(name, relative)
                if len(entries) >= MAX_CONTEXT_ENTRIES:
                    raise ValueError("The build context exceeds the entry-count limit.")
                try:
                    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as exc:
                    raise ValueError("A build-context entry changed during inspection.") from exc
                if before.st_dev != root_stat.st_dev:
                    raise ValueError("The build context contains a nested mount point; crossing filesystems is not allowed.")
                if stat.S_ISDIR(before.st_mode):
                    if os.path.ismount(root / relative):
                        raise ValueError("The build context contains a nested mount point; traversal into it is refused.")
                    child_fd = os.open(name, _open_flags(directory=True), dir_fd=directory_fd)
                    try:
                        opened = os.fstat(child_fd)
                        if not _same_file_snapshot(before, opened):
                            raise ValueError("A build-context directory changed during inspection.")
                        entries.append(_ContextEntry(relative, True, stat.S_IMODE(before.st_mode) & 0o777, None))
                        walk(child_fd, relative)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(before.st_mode):
                    if sum(1 for entry in entries if not entry.is_directory) >= MAX_CONTEXT_FILES:
                        raise ValueError("The build context exceeds the regular-file limit.")
                    contents = _read_exact_file(directory_fd, name, before, root_stat.st_dev)
                    raw_bytes += len(contents)
                    if raw_bytes > MAX_CONTEXT_TOTAL_BYTES:
                        raise ValueError("The build context exceeds the total uncompressed size limit.")
                    entries.append(_ContextEntry(relative, False, stat.S_IMODE(before.st_mode) & 0o777, contents))
                else:
                    raise ValueError("The build context contains a symlink or unsupported special file.")
            after_dir = os.fstat(directory_fd)
            if not _same_file_snapshot(before_dir, after_dir):
                raise ValueError("A build-context directory changed while it was being inspected.")

        walk(root_fd, "")
    except (OSError, RuntimeError, ValueError) as exc:
        error = str(exc) or "The build context could not be inspected safely."
    finally:
        os.close(root_fd)
    if error:
        return None, error

    entries.sort(key=lambda entry: (entry.path.casefold(), entry.path))
    by_path = {entry.path: entry for entry in entries}
    dockerfile = "Dockerfile" if "Dockerfile" in by_path else "Containerfile" if "Containerfile" in by_path else ""
    if not dockerfile or by_path[dockerfile].is_directory:
        return None, "The build context must contain a regular root-level Dockerfile or Containerfile."

    effective_entries, included_bytes, error = _effective_context_entries(entries, runtime, dockerfile)
    if error or effective_entries is None:
        return None, error or "The build context ignore rules could not be applied."

    digest = hashlib.sha256()
    digest.update(b"linux-mcp-build-context-v1\0")
    file_count = 0
    for entry in entries:
        path_bytes = entry.path.encode("utf-8")
        digest.update((b"d" if entry.is_directory else b"f") + len(path_bytes).to_bytes(4, "big") + path_bytes)
        digest.update(entry.mode.to_bytes(4, "big"))
        data = entry.contents or b""
        if not entry.is_directory:
            file_count += 1
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(hashlib.sha256(data).digest())
    digest.update(dockerfile.encode("ascii"))
    digest.update(runtime.encode("ascii"))
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for entry in effective_entries:
            data = entry.contents or b""
            info = tarfile.TarInfo(entry.path + ("/" if entry.is_directory else ""))
            info.mode = entry.mode
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            if entry.is_directory:
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    archive_bytes = archive_buffer.getvalue()
    if len(archive_bytes) > MAX_CONTEXT_ARCHIVE_BYTES:
        return None, "The build context exceeds the archive-size limit."
    return _ContextSnapshot(
        root=root,
        dockerfile=dockerfile,
        entries=tuple(entries),
        effective_entries=effective_entries,
        archive=archive_bytes,
        digest=digest.hexdigest(),
        file_count=file_count,
        entry_count=len(entries),
        total_bytes=raw_bytes,
        included_file_count=sum(1 for entry in effective_entries if not entry.is_directory),
        included_bytes=included_bytes,
    ), None


def _image_inventory(endpoint: _Endpoint, prefix: str | None) -> tuple[list[dict[str, object]], str | None, bool]:
    return _read_image_list(endpoint, prefix)


def _image_snapshot(images: list[dict[str, object]]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple(sorted(
        (
            str(item.get("image_id", "")),
            tuple(str(value) for value in item.get("tags", []) if isinstance(value, str)),
        )
        for item in images
    ))


def container_image_build_readiness() -> tuple[bool, bool]:
    """Return whether a Docker API socket or local Podman build CLI is present/accessible."""
    docker_endpoints = _available_endpoints("docker")
    docker_found = bool(docker_endpoints)
    docker_access = any(
        endpoint.socket_path is not None and os.access(endpoint.socket_path, os.W_OK)
        for endpoint in docker_endpoints
    )
    podman_binary = find_session_binary("podman", _podman_env())
    return docker_found or bool(podman_binary), docker_access or bool(podman_binary)


def _select_build_endpoint(runtime: str, scope: str) -> tuple[_Endpoint | None, str | None, str | None]:
    if runtime == "docker":
        endpoints = [
            endpoint for endpoint in _available_endpoints("docker")
            if endpoint.runtime == "docker" and endpoint.scope == scope
            and endpoint.socket_path is not None and os.access(endpoint.socket_path, os.W_OK)
        ]
        if len(endpoints) != 1:
            return None, None, "Exactly one writable local Docker API socket for the selected scope is required."
        endpoint = endpoints[0]
        if _endpoint_identity(endpoint) is None:
            return None, None, "The selected Docker API socket identity could not be verified."
        prefix, error = _api_prefix(endpoint)
        if error or prefix is None:
            return None, None, error or "The local Docker API version could not be verified."
        return endpoint, prefix, None

    actual_scope = "system" if os.getuid() == 0 else "user"
    if scope != actual_scope:
        return None, None, "Local Podman builds are limited to the current user's Podman scope."
    binary = find_session_binary("podman", _podman_env())
    if not binary:
        return None, None, "The local Podman executable is unavailable."
    endpoint = _Endpoint("podman", scope, podman_binary=binary)
    if _endpoint_identity(endpoint) is None:
        return None, None, "The selected local Podman executable identity could not be verified."
    return endpoint, None, None


def container_image_build_confirmation_details(
    runtime: str,
    scope: str,
    tag: str,
    context_dir: str,
) -> tuple[_ImageBuildTarget | None, str | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, None, "Container image builds are available only on Linux."
    if not isinstance(runtime, str) or runtime not in ACTION_RUNTIMES:
        return None, None, "runtime must be docker or podman."
    if not isinstance(scope, str) or scope not in {"system", "user"}:
        return None, None, "scope must be system or user."
    if not isinstance(tag, str) or not IMAGE_TAG_RE.fullmatch(tag) or not IMAGE_REF_RE.fullmatch(tag) or "@" in tag:
        return None, None, "tag must be one exact local image repository tag with an explicit tag suffix, not a digest."
    separator = tag.rfind(":")
    slash = tag.rfind("/")
    if separator <= slash or separator == len(tag) - 1:
        return None, None, "tag must include a non-empty explicit tag suffix."
    effective_tag = f"localhost/{tag}" if runtime == "podman" and "/" not in tag else tag

    context, error = _capture_context(context_dir, runtime)
    if error or context is None:
        return None, None, error or "The build context could not be captured."
    endpoint, prefix, error = _select_build_endpoint(runtime, scope)
    if error or endpoint is None:
        return None, None, error or "The local build endpoint could not be verified."
    images, error, truncated = _image_inventory(endpoint, prefix)
    if error or truncated:
        return None, None, error or "The local image inventory is incomplete; the build is refused."
    if _exact_image_match(images, effective_tag) is not None:
        return None, None, "The destination image tag already exists; overwriting a tag is refused."

    identity = _endpoint_identity(endpoint)
    if identity is None:
        return None, None, "The selected local build endpoint identity could not be verified."
    image_snapshot = _image_snapshot(images)
    details = {
        "runtime": runtime,
        "scope": scope,
        "tag": effective_tag,
        "context_path": str(context.root),
        "dockerfile": context.dockerfile,
        "context_digest": context.digest,
        "context_file_count": context.file_count,
        "context_entry_count": context.entry_count,
        "context_bytes": context.total_bytes,
        "included_file_count": context.included_file_count,
        "included_bytes": context.included_bytes,
        "endpoint_identity": identity,
        "api_prefix": prefix,
        "image_snapshot": image_snapshot,
    }
    state_digest = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    target = _ImageBuildTarget(
        runtime=runtime,  # type: ignore[arg-type]
        scope=scope,
        endpoint=endpoint,
        api_prefix=prefix,
        tag=effective_tag,
        context_path=str(context.root),
        dockerfile=context.dockerfile,
        context_archive=context.archive,
        context_entries=context.effective_entries,
        context_digest=context.digest,
        file_count=context.file_count,
        entry_count=context.entry_count,
        context_bytes=context.total_bytes,
        included_file_count=context.included_file_count,
        included_bytes=context.included_bytes,
        state_digest=state_digest,
        endpoint_identity=identity,
        image_snapshot=image_snapshot,
    )
    phrase = hashlib.sha256(("container-image-build:" + state_digest).encode("utf-8")).hexdigest()[:16]
    return target, f"build {phrase}", None


def _docker_build_has_error(body: bytes) -> bool:
    if not body.strip():
        return False
    for line in body.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return True
        if not isinstance(payload, dict) or payload.get("error") or payload.get("errorDetail"):
            return True
    return False


def perform_container_image_build(
    runtime: ContainerImageBuildRuntime,
    scope: str,
    tag: str,
    context_dir: str,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> ContainerImageBuildResponse:
    target, phrase, error = container_image_build_confirmation_details(runtime, scope, tag, context_dir)
    if error or target is None or phrase is None:
        return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, user_confirmed=confirmed is True, message=error or "The image build could not be verified.")
    if confirmed is not True:
        return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, context_digest=target.context_digest, user_confirmed=False, message="Explicit client confirmation is required; no image build was run.")
    if confirmation_phrase != phrase:
        return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, context_digest=target.context_digest, user_confirmed=True, message="Confirmation did not match the local image inventory or captured build-context digest.")
    tag = target.tag

    current_images, inventory_error, inventory_truncated = _image_inventory(target.endpoint, target.api_prefix)
    if inventory_error or inventory_truncated or _endpoint_identity(target.endpoint) != target.endpoint_identity:
        return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, context_digest=target.context_digest, user_confirmed=True, message="The selected endpoint or complete image inventory changed after confirmation; no build was run.")
    if _image_snapshot(current_images) != target.image_snapshot or _exact_image_match(current_images, tag) is not None:
        return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, context_digest=target.context_digest, user_confirmed=True, message="The local image inventory changed after confirmation or the destination tag appeared; no build was run.")

    if runtime == "docker":
        query = urlencode({"t": tag, "dockerfile": target.dockerfile, "rm": "1", "pull": "0"})
        result = _request(
            target.endpoint,
            "POST",
            f"{target.api_prefix}/build?{query}",
            target.context_archive,
            content_type="application/x-tar",
            timeout_seconds=MAX_BUILD_TIMEOUT_SECONDS,
            max_response_bytes=MAX_IMAGE_PULL_RESPONSE_BYTES,
        )
        if result.error or result.status != 200 or _docker_build_has_error(result.body):
            return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, context_digest=target.context_digest, user_confirmed=True, message="The Docker build failed, timed out, or returned incomplete output; inspect local image and builder state before retrying.")
    else:
        temporary: tempfile.TemporaryDirectory[str] | None = None
        staged_root: Path | None = None
        try:
            temporary = tempfile.TemporaryDirectory(prefix="linux-mcp-build-context-")
            staged_root = Path(temporary.name)
            for entry in target.context_entries:
                destination = staged_root.joinpath(*entry.path.split("/"))
                if entry.is_directory:
                    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with destination.open("xb") as output:
                        output.write(entry.contents or b"")
                    os.chmod(destination, entry.mode)
            for entry in sorted((item for item in target.context_entries if item.is_directory), key=lambda item: item.path.count("/"), reverse=True):
                directory_path = staged_root.joinpath(*entry.path.split("/"))
                os.chmod(directory_path, entry.mode)
                if not os.access(directory_path, os.R_OK | os.X_OK):
                    return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, context_digest=target.context_digest, user_confirmed=True, message="A staged context directory is not readable by the current Podman identity; no build was run.")
            if any(not entry.is_directory and not os.access(staged_root.joinpath(*entry.path.split("/")), os.R_OK) for entry in target.context_entries):
                return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, context_digest=target.context_digest, user_confirmed=True, message="A staged context file is not readable by the current Podman identity; no build was run.")
            _output, command_error, command_truncated = run_bounded_command(
                [target.endpoint.podman_binary or "podman", "--remote=false", "build", "--tag", tag, "--file", target.dockerfile, str(staged_root)],
                _podman_env(),
                command_label="local Podman image build",
                timeout_seconds=MAX_BUILD_TIMEOUT_SECONDS,
                max_output_bytes=MAX_IMAGE_PULL_RESPONSE_BYTES,
                kill_process_group=True,
            )
            if command_error or command_truncated:
                return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, context_digest=target.context_digest, user_confirmed=True, message="The Podman build failed, timed out, or exceeded the output limit; inspect local image and builder state before retrying.")
        except (OSError, RuntimeError, ValueError) as exc:
            return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, context_digest=target.context_digest, user_confirmed=True, message=f"The Podman build context could not be staged safely: {type(exc).__name__}.")
        finally:
            if temporary is not None:
                if staged_root is not None:
                    for entry in sorted((item for item in target.context_entries if item.is_directory), key=lambda item: item.path.count("/")):
                        try:
                            os.chmod(staged_root.joinpath(*entry.path.split("/")), 0o700)
                        except OSError:
                            pass
                temporary.cleanup()

    resulting, result_error, result_truncated = _image_inventory(target.endpoint, target.api_prefix)
    if result_error or result_truncated:
        return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, context_digest=target.context_digest, user_confirmed=True, message="The build returned, but the exact image tag could not be verified; inspect the local image inventory before retrying.")
    built = _exact_image_match(resulting, tag)
    if built is None:
        return ContainerImageBuildResponse(success=False, runtime=runtime, scope=scope, tag=tag, user_confirmed=True, message="The build returned without creating the exact requested local image tag.")
    return ContainerImageBuildResponse(
        success=True,
        runtime=runtime,
        scope=scope,
        tag=tag,
        image_id=str(built.get("image_id")),
        context_digest=target.context_digest,
        context_file_count=target.included_file_count,
        context_bytes=target.included_bytes,
        user_confirmed=True,
        message="Built and verified the exact local image tag. No container was started.",
    )
