"""Redacted LUKS2 token inventory and confirmed token binding controls."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from wayland_mcp.models import (
    LUKSTokenActionResponse,
    LUKSTokenInfo,
    LUKSTokenListResponse,
)
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.luks_control import (
    _device_readonly,
    _device_size_bytes,
    _environment,
    _resolve_block_device,
    _run_mutation,
    _run_readonly,
)

LUKSTokenAction = Literal["remove", "unassign", "import", "export"]
LUKS_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
MAX_TOKEN_ID = 31
MAX_KEY_SLOT = 31
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_TOKEN_JSON_BYTES = MAX_METADATA_BYTES
MAX_TOKEN_TYPE_DISPLAY_LENGTH = 128


@dataclass(frozen=True, slots=True)
class TokenRecord:
    token_id: int
    token_type: str
    keyslots: tuple[int, ...]
    extra_digest: str


@dataclass(frozen=True, slots=True)
class LUKSTokenState:
    luks_uuid: str
    active_keyslots: tuple[int, ...]
    tokens: tuple[TokenRecord, ...]
    metadata_digest: str
    keyslots_digest: str
    other_metadata_digest: str


@dataclass(frozen=True, slots=True)
class LUKSTokenTarget:
    action: LUKSTokenAction
    device_path: str
    device_major: int
    device_minor: int
    device_size_bytes: int
    luks_uuid: str
    token_id: int
    token_type: str
    previous_keyslots: tuple[int, ...]
    active_keyslots: tuple[int, ...]
    expected_tokens: tuple[TokenRecord, ...]
    metadata_digest: str
    keyslots_digest: str
    other_metadata_digest: str
    cryptsetup_path: str
    cryptsetup_identity: tuple[int, int, int, int, int]
    digest: str
    token_json_file: str | None = None
    token_json_identity: tuple[int, int, int, int, int, int, int, int] | None = None
    token_json_digest: str | None = None
    token_json_bytes: bytes | None = None
    imported_token: TokenRecord | None = None
    export_file: str | None = None
    export_parent_path: str | None = None
    export_parent_identity: tuple[int, int, int, int] | None = None


def _canonical_digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _token_digest_values(tokens: tuple[TokenRecord, ...]) -> tuple[tuple[int, str, tuple[int, ...], str], ...]:
    return tuple((item.token_id, item.token_type, item.keyslots, item.extra_digest) for item in tokens)


def _display_token_type(token_type: str) -> str:
    """Escape untrusted token type text and bound its client-visible projection."""
    escaped = token_type.encode("unicode_escape").decode("ascii")
    if len(escaped) > MAX_TOKEN_TYPE_DISPLAY_LENGTH:
        return escaped[: MAX_TOKEN_TYPE_DISPLAY_LENGTH - 14] + "...[truncated]"
    return escaped


def _binary_identity(path: str) -> tuple[str | None, tuple[int, int, int, int, int] | None]:
    try:
        resolved = Path(path).resolve(strict=True)
        info = resolved.stat()
    except (OSError, RuntimeError):
        return None, None
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        return None, None
    return str(resolved), (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode)


def _token_file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
    )


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("The token JSON contains duplicate object keys.")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"Unsupported JSON constant: {value}")


def _parse_token_json(
    raw: bytes,
    token_id: int,
    active_keyslots: tuple[int, ...],
) -> tuple[TokenRecord | None, str | None]:
    if not raw or len(raw) > MAX_TOKEN_JSON_BYTES:
        return None, "The token JSON file is empty or exceeds the bounded import limit."
    try:
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
        return None, "The token JSON file is not valid, unambiguous UTF-8 JSON."
    if not isinstance(parsed, dict):
        return None, "The token JSON root must be one object."
    token_type = parsed.get("type")
    raw_keyslots = parsed.get("keyslots")
    if not isinstance(token_type, str) or not isinstance(raw_keyslots, list) or len(raw_keyslots) > 32:
        return None, "The token JSON must contain a string type and a bounded keyslots array."
    active = set(active_keyslots)
    slots: list[int] = []
    for value in raw_keyslots:
        if (
            not isinstance(value, str)
            or not value.isascii()
            or not value.isdecimal()
            or len(value) > 2
            or str(int(value, 10)) != value
        ):
            return None, "The token JSON keyslots must be canonical decimal string IDs."
        slot = int(value, 10)
        if not 0 <= slot <= MAX_KEY_SLOT or slot not in active or slot in slots:
            return None, "The token JSON references an invalid, inactive, or duplicate keyslot."
        slots.append(slot)
    extras = {key: value for key, value in parsed.items() if key not in {"type", "keyslots"}}
    return TokenRecord(token_id, token_type, tuple(sorted(slots)), _canonical_digest(extras)), None


def _read_private_token_json(
    token_json_file: object,
    active_keyslots: tuple[int, ...],
    token_id: int,
) -> tuple[str | None, tuple[int, int, int, int, int, int, int, int] | None, bytes | None, str | None, TokenRecord | None, str | None]:
    if not isinstance(token_json_file, str) or not token_json_file.startswith("/") or len(token_json_file) > 4096:
        return None, None, None, None, None, "token_json_file must be an absolute path to a private regular file."
    supplied = Path(token_json_file)
    try:
        resolved = supplied.resolve(strict=True)
        if resolved != supplied:
            return None, None, None, None, None, "token_json_file may not contain symlink or non-canonical path components."
        descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except (OSError, RuntimeError):
        return None, None, None, None, None, "token_json_file must resolve to an accessible existing regular file."
    try:
        info = os.fstat(descriptor)
        identity = _token_file_identity(info)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or not 1 <= info.st_size <= MAX_TOKEN_JSON_BYTES
        ):
            return None, None, None, None, None, "token_json_file must be server-owned, mode 0600 or stricter, single-link, and at most 4 MiB."
        path_info = resolved.lstat()
        if not stat.S_ISREG(path_info.st_mode) or (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino):
            return None, None, None, None, None, "token_json_file identity changed while being opened."
        chunks: list[bytes] = []
        remaining = MAX_TOKEN_JSON_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        final_path_info = resolved.lstat()
        if (
            _token_file_identity(after) != identity
            or len(data) != info.st_size
            or not stat.S_ISREG(final_path_info.st_mode)
            or (final_path_info.st_dev, final_path_info.st_ino) != (info.st_dev, info.st_ino)
        ):
            return None, None, None, None, None, "token_json_file changed while being read."
        record, error = _parse_token_json(data, token_id, active_keyslots)
        if error or record is None:
            return None, None, None, None, None, error or "The token JSON file could not be validated."
        return str(resolved), identity, data, hashlib.sha256(data).hexdigest(), record, None
    except OSError:
        return None, None, None, None, None, "token_json_file could not be read safely."
    finally:
        os.close(descriptor)


def _export_parent_state(
    export_file: object,
) -> tuple[str | None, str | None, tuple[int, int, int, int] | None, str | None]:
    if not isinstance(export_file, str) or not export_file.startswith("/") or len(export_file) > 4096:
        return None, None, None, "export_file must be an absolute path for a new private token JSON file."
    supplied = Path(export_file)
    name = supplied.name
    parent = supplied.parent
    if not name or name in {".", ".."} or len(os.fsencode(name)) > 255:
        return None, None, None, "export_file must end in one valid filename."
    try:
        resolved_parent = parent.resolve(strict=True)
        if resolved_parent != parent:
            return None, None, None, "export_file parent may not contain symlink or non-canonical path components."
        info = resolved_parent.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
            return None, None, None, "export_file parent must be an existing directory owned by root or the server identity."
        if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            return None, None, None, "export_file parent must not be group/world writable unless it is root-owned and sticky."
        identity = (info.st_dev, info.st_ino, info.st_uid, info.st_mode)
        try:
            supplied.lstat()
        except FileNotFoundError:
            pass
        else:
            return None, None, None, "export_file must not already exist; exports never overwrite a file."
    except (OSError, RuntimeError):
        return None, None, None, "export_file parent must resolve to an existing safe directory."
    return str(resolved_parent / name), str(resolved_parent), identity, None


def _write_private_export(
    export_file: str,
    parent_identity: tuple[int, int, int, int],
    data: bytes,
) -> tuple[bool, str | None]:
    parent = str(Path(export_file).parent)
    name = Path(export_file).name
    parent_descriptor = -1
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    temporary_name: str | None = None
    published = False
    success = False
    try:
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        parent_info = os.fstat(parent_descriptor)
        if (parent_info.st_dev, parent_info.st_ino, parent_info.st_uid, parent_info.st_mode) != parent_identity:
            return False, "export_file parent identity changed after confirmation."
        try:
            os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            return False, "export_file appeared after confirmation; no file was overwritten."
        temporary_name = f".linux-mcp-luks-token-{secrets.token_hex(16)}.tmp"
        descriptor = os.open(
            temporary_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        info = os.fstat(descriptor)
        created_identity = (info.st_dev, info.st_ino)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            return False, "The private export file identity could not be verified."
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = len(data) + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        written_data = b"".join(chunks)
        final = os.fstat(descriptor)
        if (
            written_data != data
            or not stat.S_ISREG(final.st_mode)
            or final.st_uid != os.geteuid()
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_nlink != 1
            or (final.st_dev, final.st_ino) != created_identity
        ):
            return False, "The private token export file failed post-write verification."
        temporary_entry = os.stat(temporary_name, dir_fd=parent_descriptor, follow_symlinks=False)
        current_parent = os.stat(parent)
        if (
            (temporary_entry.st_dev, temporary_entry.st_ino) != created_identity
            or (current_parent.st_dev, current_parent.st_ino, current_parent.st_uid, current_parent.st_mode) != parent_identity
        ):
            return False, "The private token export path changed during publication."
        os.link(
            temporary_name,
            name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        published = True
        final_entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (final_entry.st_dev, final_entry.st_ino) != created_identity or final_entry.st_nlink != 2:
            return False, "The private token export was not published as the verified file."
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        final_entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        final = os.fstat(descriptor)
        if (
            (final_entry.st_dev, final_entry.st_ino) != created_identity
            or final_entry.st_nlink != 1
            or final.st_nlink != 1
        ):
            return False, "The private token export file link state could not be verified."
        os.fsync(parent_descriptor)
        success = True
        return True, None
    except OSError:
        return False, "The private token export file could not be created or verified; inspect the target path before retrying."
    finally:
        if descriptor >= 0:
            if created_identity is not None and not success:
                cleanup_names = [temporary_name] if temporary_name is not None else []
                if published:
                    cleanup_names.append(name)
                for cleanup_name in cleanup_names:
                    try:
                        current = os.stat(cleanup_name, dir_fd=parent_descriptor, follow_symlinks=False)
                        if (current.st_dev, current.st_ino) == created_identity:
                            os.unlink(cleanup_name, dir_fd=parent_descriptor)
                    except OSError:
                        pass
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _parse_metadata(raw: str, luks_uuid: str) -> tuple[LUKSTokenState | None, str | None]:
    if len(raw.encode("utf-8")) > MAX_METADATA_BYTES:
        return None, "The LUKS2 metadata exceeds the bounded token-inspection limit."
    try:
        metadata = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
        return None, "The LUKS2 metadata could not be parsed safely."
    if not isinstance(metadata, dict):
        return None, "The LUKS2 metadata has an unsupported structure."
    raw_slots = metadata.get("keyslots")
    raw_tokens = metadata.get("tokens")
    if not isinstance(raw_slots, dict) or not isinstance(raw_tokens, dict):
        return None, "The LUKS2 keyslot or token metadata could not be read completely."
    if len(raw_slots) > 32 or len(raw_tokens) > 32:
        return None, "The LUKS2 metadata reports more keyslots or tokens than the supported format limit."

    active_slots: set[int] = set()
    for identifier, record in raw_slots.items():
        if (
            not isinstance(identifier, str)
            or not identifier.isascii()
            or not identifier.isdecimal()
            or len(identifier) > 2
            or str(int(identifier, 10)) != identifier
            or not isinstance(record, dict)
        ):
            return None, "The LUKS2 keyslot inventory contains an unsupported entry."
        slot = int(identifier, 10)
        if not 0 <= slot <= MAX_KEY_SLOT or slot in active_slots:
            return None, "The LUKS2 keyslot inventory contains an invalid or duplicate slot number."
        active_slots.add(slot)

    tokens: list[TokenRecord] = []
    seen_ids: set[int] = set()
    for identifier, record in raw_tokens.items():
        if (
            not isinstance(identifier, str)
            or not identifier.isascii()
            or not identifier.isdecimal()
            or len(identifier) > 2
            or str(int(identifier, 10)) != identifier
            or not isinstance(record, dict)
        ):
            return None, "The LUKS2 token inventory contains an unsupported entry."
        token_id = int(identifier, 10)
        token_type = record.get("type")
        if not 0 <= token_id <= MAX_TOKEN_ID or token_id in seen_ids:
            return None, "The LUKS2 token inventory contains an invalid or duplicate token ID."
        if not isinstance(token_type, str):
            return None, "A LUKS2 token has an unsupported type name."
        seen_ids.add(token_id)
        raw_bound_slots = record.get("keyslots", [])
        if not isinstance(raw_bound_slots, list):
            return None, "A LUKS2 token has an unsupported keyslot binding list."
        bound_slots: list[int] = []
        for value in raw_bound_slots:
            if not isinstance(value, str) or not value.isascii() or not value.isdecimal() or len(value) > 2 or str(int(value, 10)) != value:
                return None, "A LUKS2 token contains an invalid keyslot reference."
            slot = int(value, 10)
            if not 0 <= slot <= MAX_KEY_SLOT or slot not in active_slots or slot in bound_slots:
                return None, "A LUKS2 token references an invalid, inactive, or duplicate keyslot."
            bound_slots.append(slot)
        extras = {key: value for key, value in record.items() if key not in {"type", "keyslots"}}
        tokens.append(TokenRecord(token_id, token_type, tuple(sorted(bound_slots)), _canonical_digest(extras)))

    stable_metadata = {key: value for key, value in metadata.items() if key not in {"keyslots", "tokens"}}
    state = LUKSTokenState(
        luks_uuid=luks_uuid,
        active_keyslots=tuple(sorted(active_slots)),
        tokens=tuple(sorted(tokens, key=lambda item: item.token_id)),
        metadata_digest=_canonical_digest(metadata),
        keyslots_digest=_canonical_digest(raw_slots),
        other_metadata_digest=_canonical_digest(stable_metadata),
    )
    return state, None


def _read_luks2_state(
    device_path: str,
    cryptsetup: str,
    *,
    pass_fds: tuple[int, ...] = (),
) -> tuple[LUKSTokenState | None, str | None]:
    check = _run_readonly(
        [cryptsetup, "isLuks", "--type", "luks2", device_path],
        pass_fds=pass_fds,
    )
    if check is None or check[0] != 0:
        return None, "The exact device is not a readable LUKS2 device."
    uuid_result = _run_readonly([cryptsetup, "luksUUID", device_path], pass_fds=pass_fds)
    if uuid_result is None or uuid_result[0] != 0:
        return None, "The LUKS2 UUID could not be verified."
    luks_uuid = uuid_result[1].strip()
    if not LUKS_UUID_RE.fullmatch(luks_uuid):
        return None, "The LUKS2 UUID has an unsupported format."
    metadata_result = _run_readonly(
        [cryptsetup, "luksDump", "--type", "luks2", "--dump-json-metadata", device_path],
        limit=MAX_METADATA_BYTES,
        pass_fds=pass_fds,
    )
    if metadata_result is None or metadata_result[0] != 0:
        return None, "The LUKS2 token metadata could not be read."
    final_uuid_result = _run_readonly([cryptsetup, "luksUUID", device_path], pass_fds=pass_fds)
    if final_uuid_result is None or final_uuid_result[0] != 0 or final_uuid_result[1].strip() != luks_uuid:
        return None, "The LUKS2 UUID changed while token metadata was being read."
    return _parse_metadata(metadata_result[1], luks_uuid)


def list_luks_tokens(device_path: str) -> LUKSTokenListResponse:
    resolved, info, error = _resolve_block_device(device_path)
    if error or resolved is None or info is None:
        return LUKSTokenListResponse(success=False, device_path=device_path, message=error or "The block device could not be verified.")
    cryptsetup = find_session_binary("cryptsetup", _environment())
    if not cryptsetup:
        return LUKSTokenListResponse(success=False, device_path=str(resolved), message="The cryptsetup command is unavailable.")
    state, error = _read_luks2_state(str(resolved), cryptsetup)
    if error or state is None:
        return LUKSTokenListResponse(success=False, device_path=str(resolved), message=error or "The LUKS2 token state could not be read.")
    tokens = [
        LUKSTokenInfo(
            token_id=token.token_id,
            token_type=_display_token_type(token.token_type),
            keyslots=list(token.keyslots),
            bound=bool(token.keyslots),
        )
        for token in state.tokens
    ]
    return LUKSTokenListResponse(
        success=True,
        device_path=str(resolved),
        luks_uuid=state.luks_uuid,
        active_keyslots=list(state.active_keyslots),
        total_tokens=len(tokens),
        returned_tokens=len(tokens),
        tokens=tokens,
        message="Token JSON payloads and provider-specific fields are omitted.",
    )


def _expected_tokens(
    tokens: tuple[TokenRecord, ...],
    action: LUKSTokenAction,
    token_id: int,
    key_slot: int | None,
) -> tuple[TokenRecord, ...]:
    result: list[TokenRecord] = []
    for token in tokens:
        if token.token_id != token_id:
            result.append(token)
        elif action == "unassign" and key_slot is not None:
            result.append(TokenRecord(
                token.token_id,
                token.token_type,
                tuple(slot for slot in token.keyslots if slot != key_slot),
                token.extra_digest,
            ))
    return tuple(result)


def luks_token_confirmation_details(
    action: str,
    device_path: str,
    token_id: int,
    key_slot: int | None = None,
    token_json_file: str | None = None,
    export_file: str | None = None,
) -> tuple[LUKSTokenTarget | None, str | None, str | None]:
    if not isinstance(action, str) or action not in {"remove", "unassign", "import", "export"}:
        return None, None, "action must be remove, unassign, import, or export."
    if type(token_id) is not int or not 0 <= token_id <= MAX_TOKEN_ID:
        return None, None, f"token_id must be an integer from 0 through {MAX_TOKEN_ID}."
    if action == "unassign":
        if type(key_slot) is not int or not 0 <= key_slot <= MAX_KEY_SLOT:
            return None, None, f"key_slot must be an integer from 0 through {MAX_KEY_SLOT} for unassign."
    elif key_slot is not None:
        return None, None, "key_slot is used only for unassign."
    if action == "import":
        if token_json_file is None or export_file is not None:
            return None, None, "import requires token_json_file and does not accept export_file."
    elif action == "export":
        if export_file is None or token_json_file is not None:
            return None, None, "export requires export_file and does not accept token_json_file."
    elif token_json_file is not None or export_file is not None:
        return None, None, "token_json_file and export_file are used only for import or export."

    resolved, info, error = _resolve_block_device(device_path)
    if error or resolved is None or info is None:
        return None, None, error or "The block device could not be verified."
    if action in {"remove", "unassign", "import"} and _device_readonly(info) is not False:
        return None, None, "LUKS token changes require a block device verified as writable."
    size_bytes = _device_size_bytes(info)
    if size_bytes is None:
        return None, None, "The block-device size could not be verified in sysfs."
    cryptsetup_found = find_session_binary("cryptsetup", _environment())
    if not cryptsetup_found:
        return None, None, "The cryptsetup command is unavailable."
    cryptsetup, executable_identity = _binary_identity(cryptsetup_found)
    if cryptsetup is None or executable_identity is None:
        return None, None, "The cryptsetup executable identity could not be verified."
    state, error = _read_luks2_state(str(resolved), cryptsetup)
    if error or state is None:
        return None, None, error or "The LUKS2 token state could not be read."
    selected = next((item for item in state.tokens if item.token_id == token_id), None)
    imported_token: TokenRecord | None = None
    token_json_identity = None
    token_json_digest = None
    token_json_bytes = None
    canonical_token_json_file = None
    canonical_export_file = None
    export_parent_path = None
    export_parent_identity = None

    if action == "import":
        if selected is not None:
            return None, None, "The requested token ID is already active; import never replaces an existing token."
        (
            canonical_token_json_file,
            token_json_identity,
            token_json_bytes,
            token_json_digest,
            imported_token,
            error,
        ) = _read_private_token_json(token_json_file, state.active_keyslots, token_id)
        if error or imported_token is None or token_json_bytes is None or token_json_identity is None:
            return None, None, error or "The token JSON file could not be validated."
        selected = imported_token
        expected_tokens = tuple(sorted((*state.tokens, imported_token), key=lambda item: item.token_id))
        previous_keyslots: tuple[int, ...] = ()
    elif action == "export":
        if selected is None:
            return None, None, "The requested LUKS2 token ID is not active on this device."
        canonical_export_file, export_parent_path, export_parent_identity, error = _export_parent_state(export_file)
        if error or canonical_export_file is None or export_parent_path is None or export_parent_identity is None:
            return None, None, error or "The export path could not be verified."
        expected_tokens = state.tokens
        previous_keyslots = selected.keyslots
    else:
        if selected is None:
            return None, None, "The requested LUKS2 token ID is not active on this device."
        if action == "unassign" and key_slot not in selected.keyslots:
            return None, None, "The requested keyslot is not currently assigned to this token."
        expected_tokens = _expected_tokens(state.tokens, action, token_id, key_slot)
        previous_keyslots = selected.keyslots

    if selected is None:
        return None, None, "The requested LUKS2 token could not be verified."
    major, minor = os.major(info.st_rdev), os.minor(info.st_rdev)
    details = {
        "action": action,
        "device_path": str(resolved),
        "device_major": major,
        "device_minor": minor,
        "device_size_bytes": size_bytes,
        "luks_uuid": state.luks_uuid,
        "token_id": token_id,
        "token_type": selected.token_type,
        "key_slot": key_slot,
        "previous_keyslots": previous_keyslots,
        "active_keyslots": state.active_keyslots,
        "tokens": _token_digest_values(state.tokens),
        "expected_tokens": _token_digest_values(expected_tokens),
        "metadata_digest": state.metadata_digest,
        "keyslots_digest": state.keyslots_digest,
        "other_metadata_digest": state.other_metadata_digest,
        "cryptsetup_path": cryptsetup,
        "cryptsetup_identity": executable_identity,
        "token_json_file": canonical_token_json_file,
        "token_json_identity": token_json_identity,
        "token_json_digest": token_json_digest,
        "export_file": canonical_export_file,
        "export_parent_path": export_parent_path,
        "export_parent_identity": export_parent_identity,
    }
    digest = _canonical_digest(details)
    target = LUKSTokenTarget(
        action=action,  # type: ignore[arg-type]
        device_path=str(resolved),
        device_major=major,
        device_minor=minor,
        device_size_bytes=size_bytes,
        luks_uuid=state.luks_uuid,
        token_id=token_id,
        token_type=_display_token_type(selected.token_type),
        previous_keyslots=previous_keyslots,
        active_keyslots=state.active_keyslots,
        expected_tokens=expected_tokens,
        metadata_digest=state.metadata_digest,
        keyslots_digest=state.keyslots_digest,
        other_metadata_digest=state.other_metadata_digest,
        cryptsetup_path=cryptsetup,
        cryptsetup_identity=executable_identity,
        digest=digest,
        token_json_file=canonical_token_json_file,
        token_json_identity=token_json_identity,
        token_json_digest=token_json_digest,
        token_json_bytes=token_json_bytes,
        imported_token=imported_token,
        export_file=canonical_export_file,
        export_parent_path=export_parent_path,
        export_parent_identity=export_parent_identity,
    )
    phrase = f"LUKS token {hashlib.sha256((action + ':' + digest).encode('utf-8')).hexdigest()[:16]}"
    return target, phrase, None


def perform_luks_token_action(
    action: LUKSTokenAction,
    device_path: str,
    token_id: int,
    key_slot: int | None = None,
    token_json_file: str | None = None,
    export_file: str | None = None,
    *,
    confirmed: bool,
    confirmation_phrase: str | None = None,
) -> LUKSTokenActionResponse:
    if not isinstance(action, str) or action not in {"remove", "unassign", "import", "export"}:
        return LUKSTokenActionResponse(
            success=False,
            action="remove",
            device_path=device_path if isinstance(device_path, str) else "",
            token_id=token_id if type(token_id) is int and 0 <= token_id <= MAX_TOKEN_ID else 0,
            user_confirmed=confirmed is True,
            message="action must be remove, unassign, import, or export.",
        )
    target, phrase, error = luks_token_confirmation_details(
        action,
        device_path,
        token_id,
        key_slot,
        token_json_file,
        export_file,
    )
    if error or target is None or phrase is None:
        return LUKSTokenActionResponse(success=False, action=action, device_path=device_path, token_id=token_id, key_slot=key_slot, user_confirmed=confirmed is True, message=error or "The LUKS token action could not be verified.")

    def response(
        success: bool,
        message: str,
        *,
        user_confirmed: bool,
        resulting_keyslots: tuple[int, ...] = (),
        result_size_bytes: int | None = None,
    ) -> LUKSTokenActionResponse:
        return LUKSTokenActionResponse(
            success=success,
            action=action,
            device_path=target.device_path,
            token_id=token_id,
            token_type=target.token_type,
            key_slot=key_slot,
            previous_keyslots=list(target.previous_keyslots),
            resulting_keyslots=list(resulting_keyslots),
            token_json_file=target.token_json_file,
            export_file=target.export_file,
            result_size_bytes=result_size_bytes,
            user_confirmed=user_confirmed,
            message=message,
        )

    if confirmed is not True:
        return response(False, "Explicit client confirmation is required; no LUKS token command was run.", user_confirmed=False)
    if confirmation_phrase != phrase:
        return response(False, "Confirmation did not match the exact LUKS2 token, binding, file, and device metadata state.", user_confirmed=True)
    current, current_phrase, error = luks_token_confirmation_details(
        action,
        device_path,
        token_id,
        key_slot,
        token_json_file,
        export_file,
    )
    if error or current is None or current_phrase != phrase:
        return response(False, error or "LUKS2 token, file, or device metadata changed after confirmation; no command was run.", user_confirmed=True)

    descriptor = -1
    try:
        open_mode = os.O_RDONLY if action == "export" else os.O_RDWR
        descriptor = os.open(target.device_path, open_mode | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        info = os.fstat(descriptor)
        if (
            not stat.S_ISBLK(info.st_mode)
            or os.major(info.st_rdev) != target.device_major
            or os.minor(info.st_rdev) != target.device_minor
            or _device_size_bytes(info) != target.device_size_bytes
            or (action != "export" and _device_readonly(info) is not False)
        ):
            return response(False, "The opened block-device identity, capacity, or writable state changed after confirmation; no command was run.", user_confirmed=True)
        binary_path, binary_identity = _binary_identity(target.cryptsetup_path)
        if binary_path != target.cryptsetup_path or binary_identity != target.cryptsetup_identity:
            return response(False, "The cryptsetup executable changed after confirmation; no command was run.", user_confirmed=True)
        fd_path = f"/proc/self/fd/{descriptor}"
        before_fd_state, before_error = _read_luks2_state(fd_path, target.cryptsetup_path, pass_fds=(descriptor,))
        if (
            before_error
            or before_fd_state is None
            or before_fd_state.luks_uuid != target.luks_uuid
            or before_fd_state.metadata_digest != target.metadata_digest
        ):
            return response(False, "The opened device metadata differs from the confirmed LUKS2 token state; no command was run.", user_confirmed=True)

        if action == "export":
            if target.export_file is None or target.export_parent_identity is None:
                return response(False, "The confirmed private export path is incomplete; no command was run.", user_confirmed=True)
            export_now, parent_now, parent_identity_now, path_error = _export_parent_state(target.export_file)
            if (
                path_error
                or export_now != target.export_file
                or parent_now != target.export_parent_path
                or parent_identity_now != target.export_parent_identity
            ):
                return response(False, path_error or "The private export path changed after confirmation; no command was run.", user_confirmed=True)
            command = [target.cryptsetup_path, "--disable-external-tokens", "token", "export", "--token-id", str(token_id), "--json-file=-", fd_path]
            exported = _run_readonly(command, limit=MAX_METADATA_BYTES, pass_fds=(descriptor,))
            if exported is None or exported[0] != 0:
                return response(False, "cryptsetup could not export this token; no output file was created.", user_confirmed=True)
            exported_bytes = exported[1].encode("utf-8")
            exported_record, export_error = _parse_token_json(exported_bytes, token_id, before_fd_state.active_keyslots)
            selected = next((item for item in before_fd_state.tokens if item.token_id == token_id), None)
            if export_error or exported_record is None or exported_record != selected:
                return response(False, export_error or "Exported JSON did not match the exact confirmed token; no output file was created.", user_confirmed=True)
            after_state, after_error = _read_luks2_state(fd_path, target.cryptsetup_path, pass_fds=(descriptor,))
            after_binary_path, after_binary_identity = _binary_identity(target.cryptsetup_path)
            if (
                after_error
                or after_state is None
                or after_state.luks_uuid != target.luks_uuid
                or after_state.metadata_digest != target.metadata_digest
                or after_state.tokens != target.expected_tokens
                or after_state.keyslots_digest != target.keyslots_digest
                or after_state.other_metadata_digest != target.other_metadata_digest
                or after_binary_path != target.cryptsetup_path
                or after_binary_identity != target.cryptsetup_identity
            ):
                return response(False, "The LUKS2 header changed during export; no output file was created.", user_confirmed=True)
            written, write_error = _write_private_export(target.export_file, target.export_parent_identity, exported_bytes)
            if not written:
                return response(False, write_error or "The private token export could not be verified.", user_confirmed=True)
            return response(
                True,
                "The exact provider token JSON was exported to a new mode-0600 file and verified; contents were not returned.",
                user_confirmed=True,
                resulting_keyslots=target.previous_keyslots,
                result_size_bytes=len(exported_bytes),
            )

        if action == "import":
            if (
                target.token_json_file is None
                or target.token_json_identity is None
                or target.token_json_digest is None
                or target.imported_token is None
            ):
                return response(False, "The confirmed token JSON input is incomplete; no command was run.", user_confirmed=True)
            (
                _current_file,
                current_file_identity,
                current_file_bytes,
                current_file_digest,
                current_imported_token,
                file_error,
            ) = _read_private_token_json(target.token_json_file, before_fd_state.active_keyslots, token_id)
            if (
                file_error
                or current_file_identity != target.token_json_identity
                or current_file_digest != target.token_json_digest
                or current_file_bytes != target.token_json_bytes
                or current_imported_token != target.imported_token
            ):
                return response(False, file_error or "The private token JSON changed after confirmation; no command was run.", user_confirmed=True)
            command = [target.cryptsetup_path, "--disable-external-tokens", "token", "import", "--token-id", str(token_id), "--json-file=-", fd_path]
            if not _run_mutation(command, current_file_bytes, device_fd=descriptor):
                return response(False, "cryptsetup did not complete the token import; inspect the current LUKS2 header before retrying.", user_confirmed=True)
        else:
            command = [target.cryptsetup_path, "--disable-external-tokens", "token", action, "--token-id", str(token_id)]
            if action == "unassign":
                command.extend(["--key-slot", str(key_slot)])
            command.append(fd_path)
            if not _run_mutation(command, None, device_fd=descriptor):
                return response(False, "cryptsetup did not complete the token operation; inspect the current LUKS2 header before retrying.", user_confirmed=True)

        after_state, after_error = _read_luks2_state(fd_path, target.cryptsetup_path, pass_fds=(descriptor,))
        after_binary_path, after_binary_identity = _binary_identity(target.cryptsetup_path)
        if (
            after_error
            or after_state is None
            or after_state.luks_uuid != target.luks_uuid
            or after_state.active_keyslots != target.active_keyslots
            or after_state.tokens != target.expected_tokens
            or after_state.keyslots_digest != target.keyslots_digest
            or after_state.other_metadata_digest != target.other_metadata_digest
            or after_binary_path != target.cryptsetup_path
            or after_binary_identity != target.cryptsetup_identity
        ):
            return response(False, "cryptsetup returned success, but the exact token change or unchanged keyslot/device metadata could not be verified.", user_confirmed=True, resulting_keyslots=next((item.keyslots for item in after_state.tokens if item.token_id == token_id), ()) if after_state else ())
        resulting = next((item.keyslots for item in after_state.tokens if item.token_id == token_id), ())
        return response(
            True,
            "The exact LUKS2 token operation was verified. Token JSON was not returned.",
            user_confirmed=True,
            resulting_keyslots=resulting,
            result_size_bytes=len(target.token_json_bytes) if action == "import" and target.token_json_bytes is not None else None,
        )
    except OSError:
        return response(False, "The block device or selected file could not be opened with current permissions; no elevation was requested.", user_confirmed=True)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
