"""Confirmed attachment of one existing remote libvirt volume to a shut-off VM."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from wayland_mcp.models import RemoteVirtualMachineDiskAttachResponse
from wayland_mcp.tools.libvirt_resources import MAX_RETURNED_ROWS
from wayland_mcp.tools.remote_libvirt_resources import (
    _resource_name_error,
    list_remote_libvirt_storage,
)
from wayland_mcp.tools.remote_virtual_machines import (
    COMMAND_TIMEOUT_SECONDS,
    MAX_VIRSH_OUTPUT_BYTES,
    _RemoteActionToken,
    _TOKEN_LOCK,
    _TOKENS,
    _lookup_current,
    _parse_endpoint,
    _read_remote_domains,
    _run_remote_virsh,
    _token_record,
)
from wayland_mcp.tools.virtual_machines import TOKEN_RE, _Domain

MAX_XML_BYTES = 128 * 1024
MAX_DOMAIN_SCAN = 256
MAX_DOMAIN_SCAN_SECONDS = 10.0
MAX_CONFIRMATION_TARGETS = 128
CONFIRMATION_TTL_SECONDS = 90.0
ATTACH_TIMEOUT_SECONDS = 45
_TARGET_RE = re.compile(r"^vd[b-z]$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class _RemoteDiskAttachTarget:
    identity_token: str
    endpoint: str
    scope: str
    uuid: str
    vm_name: str
    domain_state: str
    domain_id: int | None
    domain_xml_digest: str
    pool_name: str
    pool_uuid: str
    pool_xml_digest: str
    volume_name: str
    volume_xml_digest: str
    volume_capacity_bytes: int
    volume_format: str
    volume_path: str
    disk_target: str
    expected_state_token: str
    expires_at: float


_TARGETS: dict[str, _RemoteDiskAttachTarget] = {}
_TARGET_LOCK = threading.Lock()


def _read_xml(
    endpoint: str,
    identity: str,
    *,
    command: str,
    inactive: bool,
    label: str,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
) -> tuple[ET.Element | None, bytes | None, str | None]:
    arguments = [command]
    if inactive:
        arguments.append("--inactive")
    arguments.append(identity)
    output, error, truncated = _run_remote_virsh(
        endpoint,
        arguments,
        readonly=True,
        timeout_seconds=timeout_seconds,
        max_output_bytes=MAX_XML_BYTES,
        command_label=label,
    )
    if error or output is None or truncated or len(output.encode("utf-8")) > MAX_XML_BYTES:
        return None, None, f"The exact remote {label} could not be read safely."
    if "<!doctype" in output.casefold() or "<!entity" in output.casefold():
        return None, None, f"The remote {label} contains unsupported XML declarations."
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return None, None, f"Remote libvirt returned malformed {label} XML."
    return root, output.encode("utf-8"), None


def _read_domain_xml(
    endpoint: str,
    domain: _Domain,
    *,
    inactive: bool,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
) -> tuple[ET.Element | None, bytes | None, str | None]:
    root, raw, error = _read_xml(
        endpoint,
        domain.uuid,
        command="dumpxml",
        inactive=inactive,
        label="remote VM definition",
        timeout_seconds=timeout_seconds,
    )
    if error or root is None or raw is None:
        return None, None, error or "The remote VM definition is unavailable."
    if (
        root.tag != "domain"
        or root.findtext("name") != domain.name
        or root.findtext("uuid", "").casefold() != domain.uuid.casefold()
    ):
        return None, None, "Remote libvirt returned a domain definition with mismatched identity."
    return root, raw, None


def _remote_disk_references(
    endpoint: str,
    *,
    volume_path: str,
    pool_name: str,
    volume_name: str,
) -> tuple[bool | None, str | None]:
    domains, error, truncated = _read_remote_domains(endpoint)
    if error or domains is None or truncated or len(domains) > MAX_DOMAIN_SCAN:
        return None, "A complete bounded remote VM inventory is required to check disk reuse."
    started = time.monotonic()
    for domain in domains:
        if time.monotonic() - started >= MAX_DOMAIN_SCAN_SECONDS:
            return None, "The bounded remote disk-reference scan exceeded its time limit."
        roots: list[ET.Element] = []
        inactive_root, _raw, xml_error = _read_domain_xml(
            endpoint,
            domain,
            inactive=True,
            timeout_seconds=3,
        )
        if xml_error or inactive_root is None:
            return None, "A remote persistent VM definition could not be read to check whether the volume is already attached."
        roots.append(inactive_root)
        if domain.domain_id is not None:
            active_root, _raw, xml_error = _read_domain_xml(
                endpoint,
                domain,
                inactive=False,
                timeout_seconds=3,
            )
            if xml_error or active_root is None:
                return None, "A running remote VM definition could not be read to check whether the volume is already attached."
            roots.append(active_root)
        for root in roots:
            for disk in root.findall("./devices/disk"):
                for source in disk.iter("source"):
                    if (
                        source.get("file") == volume_path
                        or source.get("dev") == volume_path
                        or (
                            source.get("pool") == pool_name
                            and source.get("volume") == volume_name
                        )
                    ):
                        return True, None
    return False, None


def _pool_and_volume(
    endpoint: str,
    pool_name: str,
    volume_name: str,
) -> tuple[str | None, bytes | None, bytes | None, str | None, int | None, str | None, str | None]:
    inventory = list_remote_libvirt_storage(
        endpoint,
        pool_name=pool_name,
        limit=MAX_RETURNED_ROWS,
    )
    if not inventory.success or inventory.partial or inventory.truncated:
        return None, None, None, None, None, None, "A complete remote storage-pool and volume inventory is required."
    pools = [pool for pool in inventory.pools if pool.name == pool_name]
    volumes = [volume for volume in inventory.volumes if volume.name == volume_name]
    if len(pools) != 1 or len(volumes) != 1:
        return None, None, None, None, None, None, "The exact remote pool and volume must each appear once in a complete inventory."
    pool = pools[0]
    if pool.state != "running" or pool.persistent is not True:
        return None, None, None, None, None, None, "Disk attachment requires an active persistent remote storage pool."

    pool_root, pool_xml, error = _read_xml(
        endpoint,
        pool_name,
        command="pool-dumpxml",
        inactive=True,
        label="remote storage-pool definition",
    )
    if error or pool_root is None or pool_xml is None:
        return None, None, None, None, None, None, error or "The remote storage-pool definition is unavailable."
    if pool_root.tag != "pool" or pool_root.findtext("name") != pool_name:
        return None, None, None, None, None, None, "Remote libvirt returned a storage-pool definition with mismatched identity."
    if pool_root.get("type") != "dir":
        return None, None, None, None, None, None, "Remote disk attachment is limited to directory-backed storage pools."

    uuid_output, uuid_error, uuid_truncated = _run_remote_virsh(
        endpoint,
        ["pool-uuid", pool_name],
        readonly=True,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=4096,
        command_label="remote storage-pool UUID",
    )
    pool_uuid = uuid_output.strip().casefold() if uuid_output and not uuid_error and not uuid_truncated else ""
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", pool_uuid):
        return None, None, None, None, None, None, "Remote libvirt returned an invalid storage-pool UUID."

    # virsh volume commands take a pool option and a separate volume argument.
    volume_output, volume_error, volume_truncated = _run_remote_virsh(
        endpoint,
        ["vol-dumpxml", "--pool", pool_uuid, volume_name],
        readonly=True,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_XML_BYTES,
        command_label="remote storage-volume definition",
    )
    if volume_error or volume_output is None or volume_truncated or len(volume_output.encode("utf-8")) > MAX_XML_BYTES:
        return None, None, None, None, None, None, "The exact remote volume definition could not be read safely."
    if "<!doctype" in volume_output.casefold() or "<!entity" in volume_output.casefold():
        return None, None, None, None, None, None, "The remote volume definition contains unsupported XML declarations."
    volume_xml = volume_output.encode("utf-8")
    try:
        volume_root = ET.fromstring(volume_xml)
    except ET.ParseError:
        return None, None, None, None, None, None, "Remote libvirt returned malformed storage-volume XML."
    if volume_root.tag != "volume" or volume_root.findtext("name") != volume_name:
        return None, None, None, None, None, None, "Remote libvirt returned a volume definition with mismatched identity."
    capacity_element = volume_root.find("capacity")
    format_element = volume_root.find("./target/format")
    if (
        capacity_element is None
        or capacity_element.get("unit", "bytes").casefold() != "bytes"
        or format_element is None
        or format_element.get("type") not in {"raw", "qcow2"}
    ):
        return None, None, None, None, None, None, "The selected remote volume must be a byte-sized raw or qcow2 disk."
    try:
        capacity = int(capacity_element.text or "")
    except ValueError:
        capacity = 0
    if capacity <= 0:
        return None, None, None, None, None, None, "Remote libvirt returned an invalid volume capacity."
    path_output, path_error, path_truncated = _run_remote_virsh(
        endpoint,
        ["vol-path", "--pool", pool_uuid, volume_name],
        readonly=True,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=16 * 1024,
        command_label="remote storage-volume path",
    )
    if path_error or path_output is None or path_truncated:
        return None, None, None, None, None, None, "The exact remote volume path could not be read."
    path_lines = path_output.splitlines()
    if (
        len(path_lines) != 1
        or not path_lines[0].startswith("/")
        or len(path_lines[0]) > 4096
        or _CONTROL_RE.search(path_lines[0])
    ):
        return None, None, None, None, None, None, "Remote libvirt returned an invalid selected volume path."
    return (
        pool_uuid,
        pool_xml,
        volume_xml,
        format_element.get("type"),
        capacity,
        path_lines[0],
        None,
    )


def _observe_target(
    identity_token: str,
    pool_name: str,
    volume_name: str,
    disk_target: str,
    *,
    allow_claimed: bool = False,
) -> tuple[_RemoteDiskAttachTarget | None, str | None]:
    if not isinstance(pool_name, str) or _resource_name_error("storage_pool", pool_name):
        return None, "Choose an exact remote libvirt storage-pool name."
    if not isinstance(volume_name, str) or _resource_name_error("volume", volume_name):
        return None, "Choose an exact remote libvirt volume name."
    if not isinstance(disk_target, str) or not _TARGET_RE.fullmatch(disk_target):
        return None, "disk_target must be one virtio slot from vdb through vdz."
    if not isinstance(identity_token, str) or not TOKEN_RE.fullmatch(identity_token):
        return None, "A fresh identity_token from list_remote_virtual_machines is required."
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, error or "The exact remote VM identity is unavailable."
    with _TOKEN_LOCK:
        if (
            _TOKENS.get(identity_token) is not record
            or (record.claimed and not allow_claimed)
            or record.expires_at <= time.monotonic()
        ):
            return None, "The remote VM token is expired or already reserved; list remote VMs again."
    current, error = _lookup_current(record)
    if error or current is None:
        return None, error or "The exact remote VM could not be verified."
    if current.state != record.state or current.domain_id != record.domain_id:
        return None, "The remote VM state changed after it was listed; list remote VMs again."
    if current.state != "shut off" or current.domain_id is not None:
        return None, "Persistent disk attachment is limited to a shut-off remote VM; stop it and list it again first."

    domain_root, domain_xml, error = _read_domain_xml(record.endpoint, current, inactive=True)
    if error or domain_root is None or domain_xml is None:
        return None, error or "The remote VM definition could not be read."
    for disk in domain_root.findall("./devices/disk"):
        target = disk.find("target")
        if target is not None and target.get("dev") == disk_target:
            return None, "The requested virtio target is already occupied in the remote VM definition."

    pool_uuid, pool_xml, volume_xml, volume_format, capacity, path, error = _pool_and_volume(
        record.endpoint,
        pool_name,
        volume_name,
    )
    if error or pool_uuid is None or pool_xml is None or volume_xml is None or volume_format is None or capacity is None or path is None:
        return None, error or "The exact remote pool volume could not be inspected."
    referenced, error = _remote_disk_references(
        record.endpoint,
        volume_path=path,
        pool_name=pool_name,
        volume_name=volume_name,
    )
    if error or referenced is None:
        return None, error or "Remote VM disk references could not be checked."
    if referenced:
        return None, "The selected remote volume is already referenced by a visible remote VM definition."

    return _RemoteDiskAttachTarget(
        identity_token=identity_token,
        endpoint=record.endpoint,
        scope=record.scope,
        uuid=record.uuid,
        vm_name=record.name,
        domain_state=current.state,
        domain_id=current.domain_id,
        domain_xml_digest=hashlib.sha256(domain_xml).hexdigest(),
        pool_name=pool_name,
        pool_uuid=pool_uuid,
        pool_xml_digest=hashlib.sha256(pool_xml).hexdigest(),
        volume_name=volume_name,
        volume_xml_digest=hashlib.sha256(volume_xml).hexdigest(),
        volume_capacity_bytes=capacity,
        volume_format=volume_format,
        volume_path=path,
        disk_target=disk_target,
        expected_state_token=secrets.token_urlsafe(12),
        expires_at=time.monotonic() + CONFIRMATION_TTL_SECONDS,
    ), None


def remote_virtual_machine_disk_attach_confirmation_details(
    identity_token: str,
    pool_name: str,
    volume_name: str,
    disk_target: str,
) -> tuple[_RemoteDiskAttachTarget | None, str | None]:
    target, error = _observe_target(identity_token, pool_name, volume_name, disk_target)
    if error or target is None:
        return None, error or "The exact remote disk attachment could not be prepared."
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, error or "The remote VM identity expired while preparing confirmation."
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.claimed or record.expires_at <= time.monotonic():
            return None, "The remote VM token changed while preparing confirmation; list remote VMs again."
        record.claimed = True
        record.action = "disk:attach"
        record.confirmation_token = target.expected_state_token
    with _TARGET_LOCK:
        now = time.monotonic()
        for key in [key for key, value in _TARGETS.items() if value.expires_at <= now]:
            _TARGETS.pop(key, None)
        if len(_TARGETS) >= MAX_CONFIRMATION_TARGETS:
            oldest = min(_TARGETS, key=lambda key: _TARGETS[key].expires_at)
            _TARGETS.pop(oldest, None)
        _TARGETS[identity_token] = target
    return target, None


def _target_matches_record(target: _RemoteDiskAttachTarget, record: _RemoteActionToken) -> bool:
    return (
        target.endpoint == record.endpoint
        and target.scope == record.scope
        and target.uuid == record.uuid
        and target.vm_name == record.name
        and target.domain_state == record.state == "shut off"
        and target.domain_id is None
        and record.domain_id is None
    )


def _attached_exactly(target: _RemoteDiskAttachTarget) -> bool:
    domain, error = _lookup_current(
        _RemoteActionToken(
            endpoint=target.endpoint,
            scope=target.scope,
            uuid=target.uuid,
            name=target.vm_name,
            state="shut off",
            domain_id=None,
            expires_at=time.monotonic() + 1,
        )
    )
    if error or domain is None or domain.state != "shut off" or domain.domain_id is not None:
        return False
    root, _xml, error = _read_domain_xml(target.endpoint, domain, inactive=True)
    if error or root is None:
        return False
    matches = []
    for disk in root.findall("./devices/disk"):
        slot = disk.find("target")
        source = disk.find("source")
        driver = disk.find("driver")
        if (
            slot is not None
            and slot.get("dev") == target.disk_target
            and slot.get("bus") == "virtio"
            and source is not None
            and source.get("file") == target.volume_path
            and driver is not None
            and driver.get("name") == "qemu"
            and driver.get("type") == target.volume_format
        ):
            matches.append(disk)
    return len(matches) == 1


def perform_remote_virtual_machine_disk_attach(
    identity_token: str,
    pool_name: str,
    volume_name: str,
    disk_target: str,
    expected_state_token: str,
    confirmed_endpoint: str,
    confirmed_scope: str,
    confirmed_uuid: str,
    confirmed_name: str,
    confirmed_pool_name: str,
    confirmed_volume_name: str,
    confirmed_disk_target: str,
    *,
    confirmed: bool,
) -> RemoteVirtualMachineDiskAttachResponse:
    record, token_error = _token_record(identity_token)
    if token_error or record is None:
        return RemoteVirtualMachineDiskAttachResponse(
            success=False,
            user_confirmed=confirmed is True,
            message=token_error or "A fresh remote VM identity token is required.",
        )
    target = None
    with _TARGET_LOCK:
        target = _TARGETS.get(identity_token)
    response = RemoteVirtualMachineDiskAttachResponse(
        success=False,
        endpoint=record.endpoint,
        scope=record.scope,
        uuid=record.uuid,
        vm_name=record.name,
        pool_name=pool_name if isinstance(pool_name, str) else None,
        volume_name=volume_name if isinstance(volume_name, str) else None,
        volume_capacity_bytes=target.volume_capacity_bytes if target is not None else None,
        volume_format=target.volume_format if target is not None else None,
        disk_target=disk_target if isinstance(disk_target, str) else None,
        user_confirmed=confirmed is True,
    )
    try:
        if confirmed is not True:
            return response.model_copy(update={"message": "Explicit client confirmation is required; no remote VM definition was changed."})
        if (
            target is None
            or target.identity_token != identity_token
            or target.expires_at <= time.monotonic()
            or not record.claimed
            or record.action != "disk:attach"
            or record.confirmation_token != target.expected_state_token
            or not _target_matches_record(target, record)
            or target.pool_name != pool_name
            or target.volume_name != volume_name
            or target.disk_target != disk_target
            or target.expected_state_token != expected_state_token
            or target.endpoint != confirmed_endpoint
            or target.scope != confirmed_scope
            or target.uuid != confirmed_uuid
            or target.vm_name != confirmed_name
            or target.pool_name != confirmed_pool_name
            or target.volume_name != confirmed_volume_name
            or target.disk_target != confirmed_disk_target
            or not isinstance(expected_state_token, str)
            or not hmac.compare_digest(target.expected_state_token, expected_state_token)
        ):
            return response.model_copy(update={"message": "Confirmation did not match the exact endpoint, VM, pool, volume, target, or current-state token; no command was run."})

        with _TARGET_LOCK:
            _TARGETS.pop(identity_token, None)
        refreshed, error = _observe_target(
            identity_token,
            pool_name,
            volume_name,
            disk_target,
            allow_claimed=True,
        )
        if error or refreshed is None:
            return response.model_copy(update={"message": error or "The exact remote disk attachment could not be revalidated."})
        if (
            refreshed.domain_xml_digest != target.domain_xml_digest
            or refreshed.pool_uuid != target.pool_uuid
            or refreshed.pool_xml_digest != target.pool_xml_digest
            or refreshed.volume_xml_digest != target.volume_xml_digest
            or refreshed.volume_capacity_bytes != target.volume_capacity_bytes
            or refreshed.volume_format != target.volume_format
            or refreshed.volume_path != target.volume_path
        ):
            return response.model_copy(update={"message": "The VM, pool, or volume changed after confirmation; inspect the remote host and confirm again."})

        _output, command_error, command_truncated = _run_remote_virsh(
            record.endpoint,
            [
                "attach-disk",
                record.uuid,
                target.volume_path,
                target.disk_target,
                "--config",
                "--targetbus",
                "virtio",
                "--driver",
                "qemu",
                "--subdriver",
                target.volume_format,
            ],
            readonly=False,
            timeout_seconds=ATTACH_TIMEOUT_SECONDS,
            max_output_bytes=MAX_VIRSH_OUTPUT_BYTES,
            command_label="remote libvirt persistent disk attachment",
        )
        if command_truncated:
            command_error = command_error or "Remote virsh output exceeded the configured limit."
        verified = _attached_exactly(target)
        if command_error:
            return response.model_copy(update={
                "state_verified": verified,
                "message": f"Remote virsh reported an error: {command_error[:400]}" + (" The attachment is present; inspect the VM before retrying." if verified else " Verify the VM and volume before retrying."),
            })
        if not verified:
            return response.model_copy(update={
                "message": "Remote virsh returned without a verified persistent attachment. Inspect the remote VM before retrying.",
            })
        return response.model_copy(update={
            "success": True,
            "state_verified": True,
            "message": "The existing remote volume is attached to the shut-off VM's persistent configuration; the VM was not started.",
        })
    except Exception as exc:
        return response.model_copy(update={
            "message": f"Remote disk attachment failed: {type(exc).__name__}. Inspect the remote VM before retrying if the result is uncertain.",
        })
    finally:
        if target is not None:
            with _TARGET_LOCK:
                _TARGETS.pop(identity_token, None)
