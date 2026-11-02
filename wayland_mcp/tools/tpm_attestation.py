"""Confirmed TPM 2.0 quote creation using an existing persistent signing key."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import TPMAttestationResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

TPM_HANDLE_RE = re.compile(r"^0x81[0-9a-fA-F]{6}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_PCR_COUNT = 24
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 128 * 1024
COMMAND_TIMEOUT_SECONDS = 30
TPM_DEVICES = (Path("/dev/tpmrm0"), Path("/dev/tpm0"))
TPM_BINARIES = ("tpm2_quote", "tpm2_readpublic", "tpm2_checkquote")
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_ACTION_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class TPMAttestationTarget:
    persistent_handle: str
    pcr_indices: tuple[int, ...]
    pcr_selection: str
    nonce: str
    tpm_device: str
    device_snapshot: tuple[int, ...]
    binaries: dict[str, str]
    binary_snapshots: tuple[tuple[str, tuple[int, ...]], ...]
    public_key_pem: bytes
    key_name: bytes
    state_token: str


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
        info.st_rdev,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _safe_binary(binary_name: str, env: dict[str, str]) -> tuple[str | None, tuple[int, ...] | None]:
    raw_path = find_session_binary(binary_name, env)
    if not raw_path:
        return None, None
    try:
        resolved = os.path.realpath(raw_path, strict=True)
        info = os.stat(resolved, follow_symlinks=False)
    except (OSError, RuntimeError, ValueError):
        return None, None
    candidate = Path(resolved)
    for parent in reversed(candidate.parents):
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


def _safe_tools() -> tuple[dict[str, str] | None, tuple[tuple[str, tuple[int, ...]], ...] | None]:
    env = _environment()
    binaries: dict[str, str] = {}
    snapshots: list[tuple[str, tuple[int, ...]]] = []
    for binary_name in TPM_BINARIES:
        path, snapshot = _safe_binary(binary_name, env)
        if path is None or snapshot is None:
            return None, None
        binaries[binary_name] = path
        snapshots.append((binary_name, snapshot))
    return binaries, tuple(snapshots)


def _safe_device() -> tuple[str | None, tuple[int, ...] | None]:
    for path in TPM_DEVICES:
        try:
            info = path.stat(follow_symlinks=False)
        except OSError:
            continue
        if (
            stat.S_ISCHR(info.st_mode)
            and os.access(path, os.R_OK | os.W_OK)
        ):
            return str(path), _identity(info)
    return None, None


def _run_tool(
    binary: str,
    arguments: list[str],
    *,
    label: str,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
) -> bool:
    _output, error, truncated = run_bounded_command(
        [binary, *arguments],
        _environment(),
        command_label=label,
        timeout_seconds=timeout_seconds,
        max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
        cwd="/",
        kill_process_group=True,
    )
    return error is None and _output is not None and not truncated


def _read_artifact(path: Path, maximum: int = MAX_ARTIFACT_BYTES) -> bytes | None:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, _READ_FLAGS)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > maximum:
            return None
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(descriptor, min(16 * 1024, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if len(result) > maximum or len(result) != info.st_size:
            return None
        return bytes(result)
    except OSError:
        return None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_public_key(
    binaries: dict[str, str],
    persistent_handle: str,
    tpm_device: str,
) -> tuple[bytes | None, bytes | None]:
    try:
        with tempfile.TemporaryDirectory(prefix="linux-mcp-tpm-quote-") as directory:
            public_path = Path(directory) / "ak-public.pem"
            name_path = Path(directory) / "ak-name.bin"
            succeeded = _run_tool(
                binaries["tpm2_readpublic"],
                [
                    "-Q", "-T", f"device:{tpm_device}", "-c", persistent_handle,
                    "-f", "pem", "-o", str(public_path), "-n", str(name_path),
                ],
                label="Read persistent TPM attestation-key public data",
            )
            if not succeeded:
                return None, None
            public_key = _read_artifact(public_path)
            key_name = _read_artifact(name_path, maximum=1024)
            if (
                public_key is None
                or key_name is None
                or not public_key.startswith(b"-----BEGIN ")
                or b"PUBLIC KEY-----" not in public_key[:128]
            ):
                return None, None
            return public_key, key_name
    except OSError:
        return None, None


def _prepare_target(
    persistent_handle: str,
    pcr_indices: list[int] | tuple[int, ...],
    nonce: str,
) -> tuple[TPMAttestationTarget | None, str | None]:
    if not sys.platform.startswith("linux"):
        return None, "TPM quote requests are available only on Linux."
    if not TPM_HANDLE_RE.fullmatch(persistent_handle):
        return None, "The attestation key must be an exact TPM 2.0 persistent handle in the 0x81 range."
    if not NONCE_RE.fullmatch(nonce):
        return None, "The verifier nonce must be exactly 32 bytes encoded as 64 lowercase hexadecimal characters."
    if (
        not pcr_indices
        or len(pcr_indices) > MAX_PCR_COUNT
        or any(type(index) is not int or index < 0 or index > 23 for index in pcr_indices)
        or len(set(pcr_indices)) != len(pcr_indices)
    ):
        return None, "Select one to 24 unique TPM PCR indexes between 0 and 23."

    binaries, binary_snapshots = _safe_tools()
    if binaries is None or binary_snapshots is None:
        return None, "Root-owned, non-writable tpm2_quote, tpm2_readpublic, and tpm2_checkquote executables are required."
    tpm_device, device_snapshot = _safe_device()
    if tpm_device is None or device_snapshot is None:
        return None, "An accessible TPM character device at /dev/tpmrm0 or /dev/tpm0 is required."

    indices = tuple(sorted(pcr_indices))
    pcr_selection = "sha256:" + ",".join(str(index) for index in indices)
    public_key_pem, key_name = _read_public_key(binaries, persistent_handle, tpm_device)
    if public_key_pem is None or key_name is None:
        return None, "The persistent handle could not be read as a public TPM key; no quote was requested."

    material = {
        "persistent_handle": persistent_handle.lower(),
        "pcr_indices": list(indices),
        "nonce": nonce,
        "tpm_device": tpm_device,
        "device_snapshot": list(device_snapshot),
        "binary_snapshots": [[name, list(snapshot)] for name, snapshot in binary_snapshots],
        "public_key_sha256": hashlib.sha256(public_key_pem).hexdigest(),
        "key_name_sha256": hashlib.sha256(key_name).hexdigest(),
    }
    state_token = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return TPMAttestationTarget(
        persistent_handle=persistent_handle.lower(),
        pcr_indices=indices,
        pcr_selection=pcr_selection,
        nonce=nonce,
        tpm_device=tpm_device,
        device_snapshot=device_snapshot,
        binaries=binaries,
        binary_snapshots=binary_snapshots,
        public_key_pem=public_key_pem,
        key_name=key_name,
        state_token=state_token,
    ), None


def tpm_attestation_available() -> bool:
    binaries, snapshots = _safe_tools()
    device, device_snapshot = _safe_device()
    return binaries is not None and snapshots is not None and device is not None and device_snapshot is not None


def tpm_attestation_confirmation_details(
    persistent_handle: str,
    pcr_indices: list[int],
    nonce: str,
) -> tuple[TPMAttestationTarget | None, str | None]:
    return _prepare_target(persistent_handle, pcr_indices, nonce)


def _response(
    *,
    success: bool,
    persistent_handle: str,
    pcr_indices: list[int] | tuple[int, ...],
    nonce: str,
    user_confirmed: bool,
    message: str,
    target: TPMAttestationTarget | None = None,
    quote_message: bytes | None = None,
    signature: bytes | None = None,
    pcr_values: bytes | None = None,
) -> TPMAttestationResponse:
    return TPMAttestationResponse(
        success=success,
        persistent_handle=persistent_handle,
        pcr_bank="sha256",
        pcr_indices=list(target.pcr_indices if target else pcr_indices),
        nonce=nonce,
        ak_public_key_pem=(target.public_key_pem.decode("ascii") if target else None),
        ak_name_base64=(base64.b64encode(target.key_name).decode("ascii") if target else None),
        quote_message_base64=(base64.b64encode(quote_message).decode("ascii") if quote_message else None),
        signature_base64=(base64.b64encode(signature).decode("ascii") if signature else None),
        pcr_values_base64=(base64.b64encode(pcr_values).decode("ascii") if pcr_values else None),
        signature_verified=success,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_tpm_attestation(
    *,
    persistent_handle: str,
    pcr_indices: list[int],
    nonce: str,
    confirmed: bool,
    confirmed_handle: str | None = None,
    confirmed_pcr_indices: list[int] | None = None,
    confirmed_nonce: str | None = None,
    state_token: str | None = None,
) -> TPMAttestationResponse:
    target, error = tpm_attestation_confirmation_details(persistent_handle, pcr_indices, nonce)
    if error or target is None:
        return _response(
            success=False,
            persistent_handle=persistent_handle,
            pcr_indices=pcr_indices,
            nonce=nonce,
            user_confirmed=confirmed is True,
            message=error or "The TPM key and device state could not be verified.",
        )
    if not confirmed:
        return _response(
            success=False,
            persistent_handle=persistent_handle,
            pcr_indices=pcr_indices,
            nonce=nonce,
            user_confirmed=False,
            message="Explicit client confirmation is required; no TPM quote was requested.",
            target=target,
        )
    if (
        confirmed_handle != target.persistent_handle
        or confirmed_pcr_indices != list(target.pcr_indices)
        or confirmed_nonce != target.nonce
        or state_token != target.state_token
    ):
        return _response(
            success=False,
            persistent_handle=persistent_handle,
            pcr_indices=pcr_indices,
            nonce=nonce,
            user_confirmed=True,
            message="Confirmation did not repeat the exact persistent handle, PCR selection, nonce, and state token.",
            target=target,
        )

    with _ACTION_LOCK:
        current, error = tpm_attestation_confirmation_details(persistent_handle, pcr_indices, nonce)
        if error or current is None or current.state_token != target.state_token:
            return _response(
                success=False,
                persistent_handle=persistent_handle,
                pcr_indices=pcr_indices,
                nonce=nonce,
                user_confirmed=True,
                message=error or "The TPM device, attestation key, or selected state changed after confirmation; no quote was requested.",
            )

        try:
            with tempfile.TemporaryDirectory(prefix="linux-mcp-tpm-quote-") as directory:
                base = Path(directory)
                public_path = base / "ak-public.pem"
                message_path = base / "quote-message.bin"
                signature_path = base / "quote-signature.bin"
                pcr_path = base / "quote-pcr-values.bin"
                descriptor = os.open(public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(target.public_key_pem)
                except OSError:
                    return _response(
                        success=False,
                        persistent_handle=persistent_handle,
                        pcr_indices=pcr_indices,
                        nonce=nonce,
                        user_confirmed=True,
                        message="The public attestation key could not be staged for quote verification.",
                    )
                quote_ok = _run_tool(
                    target.binaries["tpm2_quote"],
                    [
                        "-Q", "-T", f"device:{target.tpm_device}", "-c", target.persistent_handle,
                        "-l", target.pcr_selection, "-q", target.nonce,
                        "-g", "sha256", "-m", str(message_path), "-s", str(signature_path),
                        "-o", str(pcr_path),
                    ],
                    label="Create the TPM 2.0 PCR quote",
                )
                if not quote_ok:
                    return _response(
                        success=False,
                        persistent_handle=persistent_handle,
                        pcr_indices=pcr_indices,
                        nonce=nonce,
                        user_confirmed=True,
                        message="The TPM did not produce a bounded quote for this key and PCR selection; command output is withheld.",
                    )
                quote_message = _read_artifact(message_path)
                signature = _read_artifact(signature_path)
                pcr_values = _read_artifact(pcr_path)
                if (
                    quote_message is None
                    or signature is None
                    or pcr_values is None
                    or len(quote_message) + len(signature) + len(pcr_values) + len(target.public_key_pem) + len(target.key_name)
                    > MAX_TOTAL_ARTIFACT_BYTES
                ):
                    return _response(
                        success=False,
                        persistent_handle=persistent_handle,
                        pcr_indices=pcr_indices,
                        nonce=nonce,
                        user_confirmed=True,
                        message="The TPM quote artifacts were missing or exceeded the bounded response size.",
                    )
                verified = _run_tool(
                    target.binaries["tpm2_checkquote"],
                    [
                        "-Q", "-u", str(public_path), "-m", str(message_path), "-s", str(signature_path),
                        "-f", str(pcr_path), "-g", "sha256", "-q", target.nonce,
                    ],
                    label="Verify the TPM quote signature, nonce, and included PCR values",
                )
                if not verified:
                    return _response(
                        success=False,
                        persistent_handle=persistent_handle,
                        pcr_indices=pcr_indices,
                        nonce=nonce,
                        user_confirmed=True,
                        message="The generated quote did not pass local signature, nonce, and PCR-value verification; artifacts were withheld.",
                    )
                latest, latest_error = tpm_attestation_confirmation_details(persistent_handle, pcr_indices, nonce)
                if latest_error or latest is None or latest.state_token != target.state_token:
                    return _response(
                        success=False,
                        persistent_handle=persistent_handle,
                        pcr_indices=pcr_indices,
                        nonce=nonce,
                        user_confirmed=True,
                        message="The attestation key or TPM device changed during quote creation; artifacts were withheld.",
                    )
                return _response(
                    success=True,
                    persistent_handle=persistent_handle,
                    pcr_indices=pcr_indices,
                    nonce=nonce,
                    user_confirmed=True,
                    target=target,
                    quote_message=quote_message,
                    signature=signature,
                    pcr_values=pcr_values,
                    message=(
                        "Created a TPM quote and locally verified its signature, nonce, and included PCR values. "
                        "A trusted verifier must still validate the attestation-key identity and decide whether the measurements are acceptable."
                    ),
                )
        except OSError:
            return _response(
                success=False,
                persistent_handle=persistent_handle,
                pcr_indices=pcr_indices,
                nonce=nonce,
                user_confirmed=True,
                message="Temporary quote artifacts could not be safely created or read.",
            )
