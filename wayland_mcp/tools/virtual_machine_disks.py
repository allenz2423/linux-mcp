"""Confirmed persistent attachment of one local libvirt volume to a shut-off VM."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import VirtualMachineDiskAttachResponse
from wayland_mcp.session import find_session_binary
from wayland_mcp.tools.commands import run_bounded_command
from wayland_mcp.tools.libvirt_common import SCOPED_URIS, virsh_environment
from wayland_mcp.tools.libvirt_resources import (
    _read_created_volume_definition,
    _read_pool_type,
    _read_pool_volume_names,
    _read_resource_info,
    _validate_resource_name,
)
from wayland_mcp.tools.virtual_machines import (
    TOKEN_RE,
    _ActionToken,
    _TOKEN_LOCK,
    _TOKENS,
    _lookup_current,
    _read_scope,
    _token_record,
)

COMMAND_TIMEOUT_SECONDS = 20
MAX_XML_BYTES = 128 * 1024
MAX_DOMAINS_TO_SCAN = 256
MAX_DOMAIN_SCAN_SECONDS = 10
_TARGET_RE = re.compile(r"^vd[b-z]$")
_LOCK = threading.RLock()


@dataclass(frozen=True, slots=True)
class _DiskTarget:
    identity_token: str
    action_digest: str
    confirmation_phrase: str
    scope: str
    uuid: str
    vm_name: str
    pool_name: str
    pool_uuid: str
    volume_name: str
    capacity_bytes: int
    volume_format: str
    disk_target: str
    disk_path: str
    disk_identity: tuple[int, int, int, int, int, int, int, int]


_TARGETS: dict[str, _DiskTarget] = {}


def _read_domain_xml(
    record: _ActionToken,
    env: dict[str, str],
    *,
    inactive: bool = True,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
) -> tuple[ET.Element | None, bytes | None, str | None]:
    command = [
        record.virsh,
        "--quiet",
        "--no-pkttyagent",
        "--connect",
        SCOPED_URIS[record.scope],
        "--readonly",
        "dumpxml",
    ]
    if inactive:
        command.append("--inactive")
    command.append(record.uuid)
    output, error, truncated = run_bounded_command(
        command,
        env,
        command_label=f"local libvirt {record.scope} VM definition",
        timeout_seconds=timeout_seconds,
        max_output_bytes=MAX_XML_BYTES,
    )
    if error or output is None or truncated:
        return None, None, "The exact persistent VM definition could not be read safely."
    if "<!doctype" in output.casefold() or "<!entity" in output.casefold():
        return None, None, "The libvirt domain definition contains unsupported XML declarations."
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return None, None, "Libvirt returned malformed persistent VM XML."
    if root.tag != "domain" or root.findtext("name") != record.name:
        return None, None, "The persistent VM definition identity does not match the listed VM."
    return root, output.encode("utf-8"), None


def _path_identity(path_text: str) -> tuple[str | None, tuple[int, int, int, int, int, int, int, int] | None]:
    if not path_text.startswith("/") or len(path_text) > 4096:
        return None, None
    try:
        reported = Path(path_text)
        before = reported.lstat()
        resolved = reported.resolve(strict=True)
        info = resolved.lstat()
    except (OSError, RuntimeError):
        return None, None
    if (
        str(resolved) != path_text
        or stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        return None, None
    identity = (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )
    return str(resolved), identity


def _read_volume_path(
    scope: str,
    pool_uuid: str,
    volume_name: str,
    binary: str,
    env: dict[str, str],
) -> tuple[str | None, tuple[int, int, int, int, int, int, int, int] | None, str | None]:
    output, error, truncated = run_bounded_command(
        [
            binary,
            "--quiet",
            "--no-pkttyagent",
            "--connect",
            SCOPED_URIS[scope],
            "--readonly",
            "vol-path",
            "--pool",
            pool_uuid,
            volume_name,
        ],
        env,
        command_label=f"local libvirt {scope} selected disk path",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=16 * 1024,
    )
    if error or output is None or truncated:
        return None, None, "The selected volume path could not be inspected."
    lines = output.splitlines()
    if len(lines) != 1:
        return None, None, "Libvirt returned an invalid selected volume path."
    path, identity = _path_identity(lines[0])
    if path is None or identity is None:
        return None, None, "The selected volume is not a safe local regular file."
    return path, identity, None


def _read_all_disk_references(
    scope: str,
    binary: str,
    env: dict[str, str],
) -> tuple[list[dict[str, str]] | None, str | None]:
    domains, error, truncated = _read_scope(scope, binary)
    if error or domains is None or truncated or len(domains) > MAX_DOMAINS_TO_SCAN:
        return None, "A complete bounded local VM inventory is required to check disk reuse."
    references: list[dict[str, str]] = []
    started = time.monotonic()
    for domain in domains:
        if time.monotonic() - started >= MAX_DOMAIN_SCAN_SECONDS:
            return None, "The bounded local disk-reference scan exceeded its time limit."
        record = _ActionToken(
            scope=scope,
            uuid=domain.uuid,
            name=domain.name,
            state=domain.state,
            domain_id=domain.domain_id,
            virsh=binary,
            expires_at=time.monotonic() + 1,
        )
        roots: list[ET.Element] = []
        root, _raw, xml_error = _read_domain_xml(
            record,
            env,
            inactive=domain.state == "shut off",
            timeout_seconds=3,
        )
        if xml_error or root is None:
            return None, "A local VM definition could not be read to check whether the volume is already attached."
        roots.append(root)
        if domain.state != "shut off":
            inactive_root, _raw, xml_error = _read_domain_xml(
                record,
                env,
                inactive=True,
                timeout_seconds=3,
            )
            if xml_error or inactive_root is None:
                return None, "A local VM persistent definition could not be read to check whether the volume is already attached."
            roots.append(inactive_root)
        for root in roots:
            for disk in root.findall("./devices/disk"):
                target = disk.find("target")
                for source in disk.findall(".//source"):
                    reference = {
                        "uuid": domain.uuid,
                        "name": domain.name,
                        "target": target.get("dev", "") if target is not None else "",
                        "file": source.get("file", ""),
                        "dev": source.get("dev", ""),
                        "volume": source.get("volume", ""),
                        "pool": source.get("pool", ""),
                    }
                    references.append(reference)
    return references, None


def _observe_target(
    identity_token: str,
    pool_name: str,
    volume_name: str,
    disk_target: str,
) -> tuple[_DiskTarget | None, str | None]:
    if not isinstance(pool_name, str) or _validate_resource_name("storage_pool", pool_name):
        return None, "Choose an exact local libvirt storage-pool name."
    if not isinstance(volume_name, str) or _validate_resource_name("volume", volume_name):
        return None, "Choose an exact local libvirt volume name."
    if not isinstance(disk_target, str) or not _TARGET_RE.fullmatch(disk_target):
        return None, "disk_target must be one virtio slot from vdb through vdz."
    if not isinstance(identity_token, str) or not TOKEN_RE.fullmatch(identity_token):
        return None, "A fresh identity_token from list_virtual_machines is required."
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, error or "The exact local VM identity is unavailable."
    current, error = _lookup_current(record)
    if error or current is None:
        return None, error or "The exact local VM could not be verified."
    if current.state != "shut off" or current.domain_id is not None:
        return None, "Persistent disk attachment is limited to a shut-off VM; stop it and list it again first."

    env = virsh_environment()
    binary = record.virsh
    pool, error = _read_resource_info("storage_pool", record.scope, pool_name, binary, env)
    if error or pool is None:
        return None, error or "The exact local storage pool could not be verified."
    if pool.persistent is not True or not pool.active or pool.state != "running":
        return None, "Disk attachment requires a persistent, running storage pool."
    pool_type, error = _read_pool_type(record.scope, pool.uuid, binary, env)
    if error or pool_type != "dir":
        return None, error or "Disk attachment supports only directory-backed storage pools."
    names, error = _read_pool_volume_names(record.scope, pool.uuid, binary, env)
    if error or names is None or volume_name not in names:
        return None, error or "The exact volume was not found in the selected pool."
    volume_info, error = _read_created_volume_definition(record.scope, pool.uuid, volume_name, binary, env)
    if error or volume_info is None:
        return None, error or "The selected volume format and capacity could not be verified."
    capacity_bytes, volume_format = volume_info
    disk_path, disk_identity, error = _read_volume_path(record.scope, pool.uuid, volume_name, binary, env)
    if error or disk_path is None or disk_identity is None:
        return None, error or "The selected volume path could not be verified."

    domain_root, domain_xml, error = _read_domain_xml(record, env)
    if error or domain_root is None or domain_xml is None:
        return None, error or "The exact VM definition could not be verified."
    occupied = {
        target_element.get("dev")
        for target_element in domain_root.findall("./devices/disk/target")
        if target_element.get("dev")
    }
    if disk_target in occupied:
        return None, "That virtio disk slot is already present in the VM definition."

    all_references: list[dict[str, str]] = []
    scope_references: dict[str, list[dict[str, str]]] = {}
    for selected_scope in ("system", "session"):
        references, error = _read_all_disk_references(selected_scope, binary, env)
        if error or references is None:
            return None, error or "Local disk attachments could not be fully inspected."
        scope_references[selected_scope] = references
        all_references.extend(references)
    for reference in all_references:
        same_volume_ref = reference["volume"] == volume_name and reference["pool"] in {"", pool.name}
        same_path_ref = reference["file"] == disk_path or reference["dev"] == disk_path
        if not same_path_ref:
            for source_path in (reference["file"], reference["dev"]):
                if not source_path.startswith("/"):
                    continue
                try:
                    other_path = Path(source_path).resolve(strict=True)
                    other_info = other_path.stat(follow_symlinks=False)
                except (OSError, RuntimeError):
                    continue
                if stat.S_ISREG(other_info.st_mode) and (other_info.st_dev, other_info.st_ino) == disk_identity[:2]:
                    same_path_ref = True
                    break
        if same_volume_ref or same_path_ref:
            return None, "The selected volume is already attached to a local VM; disk sharing is refused."

    material = {
        "scope": record.scope,
        "uuid": record.uuid,
        "name": record.name,
        "domain_state": current.state,
        "domain_id": current.domain_id,
        "domain_xml_digest": hashlib.sha256(domain_xml).hexdigest(),
        "pool": [pool.name, pool.uuid, pool.state, pool.persistent, pool.autostart],
        "volume_names_digest": hashlib.sha256(
            json.dumps(sorted(names), separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "volume": [volume_name, capacity_bytes, volume_format],
        "disk_path": disk_path,
        "disk_identity": list(disk_identity),
        "disk_target": disk_target,
        "disk_references_digest": hashlib.sha256(
            json.dumps(scope_references, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return _DiskTarget(
        identity_token=identity_token,
        action_digest=digest,
        confirmation_phrase="ATTACH-DISK-" + digest[:16].upper(),
        scope=record.scope,
        uuid=record.uuid,
        vm_name=record.name,
        pool_name=pool.name,
        pool_uuid=pool.uuid,
        volume_name=volume_name,
        capacity_bytes=capacity_bytes,
        volume_format=volume_format,
        disk_target=disk_target,
        disk_path=disk_path,
        disk_identity=disk_identity,
    ), None


def virtual_machine_disk_attach_confirmation_details(
    identity_token: str,
    pool_name: str,
    volume_name: str,
    disk_target: str,
) -> tuple[_DiskTarget | None, str | None, str | None]:
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, None, error or "A fresh VM identity token is required."
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.claimed or record.expires_at <= time.monotonic():
            return None, None, "The VM identity token is expired or already reserved; list virtual machines again."
    target, error = _observe_target(identity_token, pool_name, volume_name, disk_target)
    if error or target is None:
        return None, None, error or "The exact persistent disk attachment could not be prepared."
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.claimed:
            return None, None, "The VM identity token changed while preparing confirmation; list virtual machines again."
        record.claimed = True
        record.action = "disk:attach"
        record.confirmation_token = target.action_digest
        _TARGETS[identity_token] = target
    return target, target.confirmation_phrase, None


def _disk_xml(target: _DiskTarget) -> bytes:
    root = ET.Element("disk", {"type": "file", "device": "disk"})
    ET.SubElement(root, "driver", {"name": "qemu", "type": target.volume_format})
    ET.SubElement(root, "source", {"file": target.disk_path})
    ET.SubElement(root, "target", {"dev": target.disk_target, "bus": "virtio"})
    xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    if len(xml) > MAX_XML_BYTES:
        raise ValueError("The generated disk definition exceeded its size limit.")
    return xml


def _write_xml(xml: bytes, directory: str) -> str | None:
    descriptor = -1
    try:
        descriptor, path = tempfile.mkstemp(prefix="disk-", suffix=".xml", dir=directory)
        os.fchmod(descriptor, 0o600)
        view = memoryview(xml)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("The disk XML file accepted no bytes.")
            view = view[written:]
        os.fsync(descriptor)
        return path
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _attachment_verified(target: _DiskTarget, record: _ActionToken, env: dict[str, str]) -> bool:
    current, error = _lookup_current(record)
    if error or current is None or current.state != "shut off" or current.domain_id is not None:
        return False
    root, _raw, error = _read_domain_xml(record, env)
    if error or root is None:
        return False
    matches = []
    for disk in root.findall("./devices/disk"):
        disk_target = disk.find("target")
        source = disk.find("source")
        driver = disk.find("driver")
        if (
            disk_target is not None
            and disk_target.get("dev") == target.disk_target
            and disk_target.get("bus") == "virtio"
            and source is not None
            and source.get("file") == target.disk_path
            and driver is not None
            and driver.get("type") == target.volume_format
        ):
            matches.append(disk)
    return len(matches) == 1


def perform_virtual_machine_disk_attach(
    identity_token: str,
    pool_name: str,
    volume_name: str,
    disk_target: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> VirtualMachineDiskAttachResponse:
    record, error = _token_record(identity_token)
    if error or record is None:
        return VirtualMachineDiskAttachResponse(success=False, user_confirmed=confirmed is True, message=error or "A fresh VM identity token is required.")
    with _TOKEN_LOCK:
        target = _TARGETS.get(identity_token)
    response = VirtualMachineDiskAttachResponse(
        success=False,
        scope=record.scope,
        uuid=record.uuid,
        vm_name=record.name,
        pool_name=pool_name if isinstance(pool_name, str) else None,
        volume_name=volume_name if isinstance(volume_name, str) else None,
        volume_capacity_bytes=target.capacity_bytes if target is not None else None,
        volume_format=target.volume_format if target is not None else None,
        disk_target=disk_target if isinstance(disk_target, str) else None,
        user_confirmed=confirmed is True,
    )
    try:
        if confirmed is not True:
            return response.model_copy(update={"success": False, "message": "Explicit client confirmation is required; no VM definition was changed."})
        if (
            target is None
            or not record.claimed
            or record.action != "disk:attach"
            or record.confirmation_token != target.action_digest
            or target.identity_token != identity_token
            or target.pool_name != pool_name
            or target.volume_name != volume_name
            or target.disk_target != disk_target
            or not isinstance(confirmation_phrase, str)
            or not hmac.compare_digest(confirmation_phrase, target.confirmation_phrase)
        ):
            return response.model_copy(update={"success": False, "message": "Confirmation did not match the exact VM, volume, disk slot, or current state; no VM definition was changed."})
        with _LOCK:
            current, error = _observe_target(identity_token, pool_name, volume_name, disk_target)
            if error or current is None or current.action_digest != target.action_digest:
                return response.model_copy(update={"success": False, "message": error or "VM, pool, volume, or disk-attachment state changed before the action; inspect it and confirm again."})
            disk_file, disk_identity = _path_identity(target.disk_path)
            if disk_file != target.disk_path or disk_identity != target.disk_identity:
                return response.model_copy(update={"success": False, "message": "The selected volume changed after confirmation; no VM definition was changed."})
            env = virsh_environment()
            try:
                xml = _disk_xml(target)
            except ValueError:
                return response.model_copy(update={"success": False, "message": "A bounded disk definition could not be generated; no VM definition was changed."})
            command_error: str | None = None
            command_output: str | None = None
            try:
                with tempfile.TemporaryDirectory(prefix="linux-mcp-vm-disk-") as temp_dir:
                    os.chmod(temp_dir, 0o700)
                    xml_path = _write_xml(xml, temp_dir)
                    if xml_path is None:
                        return response.model_copy(update={"success": False, "message": "A private temporary disk definition could not be written; no VM definition was changed."})
                    command_output, command_error, truncated = run_bounded_command(
                        [record.virsh, "--quiet", "--no-pkttyagent", "--connect", SCOPED_URIS[record.scope], "attach-device", record.uuid, xml_path, "--config"],
                        env,
                        command_label=f"local libvirt {record.scope} persistent disk attachment",
                        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                        max_output_bytes=16 * 1024,
                    )
                    if truncated:
                        command_error = command_error or "virsh attachment output exceeded its limit"
            except OSError:
                command_error = "a private temporary directory could not be created"
            verified = _attachment_verified(target, record, env)
            if command_error:
                message = "The disk command reported an error; inspect the VM definition before retrying."
            elif verified:
                message = "The existing volume is attached to the stopped VM's persistent configuration and was verified; the VM remains stopped."
            else:
                message = "The attachment command returned, but the saved VM definition could not be verified; inspect it before retrying."
            return response.model_copy(update={"success": command_error is None and command_output is not None and verified, "state_verified": verified, "message": message})
    finally:
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
            _TARGETS.pop(identity_token, None)
