"""Confirmed creation of one stopped remote QEMU/libvirt VM and sparse disk."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import posixpath
import re
import tempfile
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Literal

from wayland_mcp.models import RemoteVirtualMachineCreateResponse
from wayland_mcp.tools.libvirt_resources import MAX_RETURNED_ROWS
from wayland_mcp.tools.remote_libvirt_resources import (
    _resource_name_error,
    list_remote_libvirt_networks,
    list_remote_libvirt_storage,
)
from wayland_mcp.tools.remote_virtual_machine_disks import (
    MAX_XML_BYTES,
    _pool_and_volume,
    _read_xml,
    _remote_disk_references,
)
from wayland_mcp.tools.remote_virtual_machines import (
    MAX_VIRSH_OUTPUT_BYTES,
    _parse_endpoint,
    _read_remote_domains,
    _run_remote_virsh,
    remote_virsh_available,
)

MIN_DISK_BYTES = 1 << 20
MAX_DISK_BYTES = 1 << 40
MIN_MEMORY_MIB = 256
MAX_MEMORY_MIB = 1 << 20
MAX_VCPUS = 128
MAX_DOMAIN_NAME_BYTES = 64
COMMAND_TIMEOUT_SECONDS = 20
VOLUME_TIMEOUT_SECONDS = 120
DEFINE_TIMEOUT_SECONDS = 45
_DOMAIN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _RemoteCreateTarget:
    endpoint: str
    scope: Literal["system", "session"]
    name: str
    memory_mib: int
    vcpus: int
    pool_name: str
    pool_uuid: str
    pool_xml_digest: str
    disk_volume_name: str
    disk_capacity_bytes: int
    network_name: str | None
    network_uuid: str | None
    network_xml_digest: str | None
    domain_type: str
    architecture: str
    emulator: str
    state_digest: str


def _request_error(
    endpoint: object,
    name: object,
    memory_mib: object,
    vcpus: object,
    pool_name: object,
    disk_volume_name: object,
    disk_capacity_bytes: object,
    network_name: object,
) -> str | None:
    if not isinstance(endpoint, str):
        return "Choose a validated remote qemu+ssh endpoint ending in /system or /session."
    _parsed, endpoint_error = _parse_endpoint(endpoint)
    if endpoint_error:
        return endpoint_error
    if (
        not isinstance(name, str)
        or len(name.encode("utf-8", errors="ignore")) > MAX_DOMAIN_NAME_BYTES
        or not _DOMAIN_NAME_RE.fullmatch(name)
    ):
        return "VM names must start with a letter or digit and contain at most 64 letters, digits, dots, underscores, or hyphens."
    if not isinstance(memory_mib, int) or isinstance(memory_mib, bool) or not MIN_MEMORY_MIB <= memory_mib <= MAX_MEMORY_MIB:
        return f"memory_mib must be an integer from {MIN_MEMORY_MIB} through {MAX_MEMORY_MIB}."
    if not isinstance(vcpus, int) or isinstance(vcpus, bool) or not 1 <= vcpus <= MAX_VCPUS:
        return f"vcpus must be an integer from 1 through {MAX_VCPUS}."
    pool_error = _resource_name_error("storage_pool", pool_name) if isinstance(pool_name, str) else "Choose an exact remote storage-pool name."
    if pool_error:
        return pool_error
    if not isinstance(disk_volume_name, str) or not _VOLUME_NAME_RE.fullmatch(disk_volume_name):
        return "disk_volume_name must be a new volume name containing at most 128 letters, digits, dots, underscores, or hyphens."
    if not isinstance(disk_capacity_bytes, int) or isinstance(disk_capacity_bytes, bool) or not MIN_DISK_BYTES <= disk_capacity_bytes <= MAX_DISK_BYTES:
        return f"disk_capacity_bytes must be an integer from {MIN_DISK_BYTES} bytes through {MAX_DISK_BYTES} bytes."
    if not isinstance(network_name, str) or len(network_name) > 256:
        return "network_name must be empty or an exact remote libvirt network name of at most 256 characters."
    if _CONTROL_RE.search(network_name):
        return "network_name cannot contain control characters."
    if network_name:
        network_error = _resource_name_error("network", network_name)
        if network_error:
            return network_error
    return None


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _read_remote_emulator(endpoint: str) -> tuple[str | None, str | None, str | None, str | None]:
    output, error, truncated = _run_remote_virsh(
        endpoint,
        ["capabilities"],
        readonly=True,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_VIRSH_OUTPUT_BYTES,
        command_label="remote libvirt host capabilities",
    )
    if error or output is None or truncated:
        return None, None, None, "Remote libvirt host capabilities could not be read safely."
    if "<!doctype" in output.casefold() or "<!entity" in output.casefold():
        return None, None, None, "The remote capabilities document contains unsupported XML declarations."
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return None, None, None, "Remote libvirt returned malformed host capabilities."
    if root.tag != "capabilities":
        return None, None, None, "Remote libvirt returned an unrecognized host-capabilities document."
    architecture = (root.findtext("./host/cpu/arch") or "").strip()
    if not architecture or len(architecture) > 64 or _CONTROL_RE.search(architecture):
        return None, None, None, "Remote libvirt did not report a valid host architecture."
    candidates: list[tuple[str, str]] = []
    for guest in root.findall("guest"):
        arch = guest.find("arch")
        if arch is None or arch.get("name") != architecture or (guest.findtext("os_type") or "").strip() != "hvm":
            continue
        for domain in arch.findall("domain"):
            domain_type = domain.get("type", "")
            emulator = (domain.findtext("emulator") or "").strip()
            if (
                domain_type in {"kvm", "qemu"}
                and emulator.startswith("/")
                and len(emulator) <= 4096
                and not _CONTROL_RE.search(emulator)
                and ".." not in emulator.split("/")
                and posixpath.normpath(emulator) == emulator
            ):
                candidates.append((domain_type, emulator))
    candidates.sort(key=lambda item: (item[0] != "kvm", item[1]))
    if not candidates:
        return None, None, None, "Remote libvirt reports no safe QEMU emulator for its host architecture."
    domain_type, emulator = candidates[0]
    return domain_type, architecture, emulator, None


def _pool_state(endpoint: str, pool_name: str):
    inventory = list_remote_libvirt_storage(endpoint, pool_name=pool_name, limit=MAX_RETURNED_ROWS)
    if not inventory.success or inventory.partial or inventory.truncated:
        return None, None, None, None, "A complete remote storage-pool and volume inventory is required."
    pools = [pool for pool in inventory.pools if pool.name == pool_name]
    if len(pools) != 1:
        return None, None, None, None, "The exact remote storage pool must appear once in a complete inventory."
    pool = pools[0]
    if pool.state != "running" or pool.persistent is not True:
        return None, None, None, None, "Remote VM creation requires an active persistent storage pool."
    root, raw, error = _read_xml(
        endpoint,
        pool_name,
        command="pool-dumpxml",
        inactive=True,
        label="remote storage-pool definition",
    )
    if error or root is None or raw is None:
        return None, None, None, None, error or "The remote storage-pool definition is unavailable."
    if root.tag != "pool" or root.findtext("name") != pool_name or root.get("type") != "dir":
        return None, None, None, None, "Remote VM creation supports only the exact directory-backed storage pool."
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
        return None, None, None, None, "Remote libvirt returned an invalid storage-pool UUID."
    return pool, pool_uuid, raw, inventory, None


def _network_state(endpoint: str, network_name: str):
    if not network_name:
        return None, None, None, None
    inventory = list_remote_libvirt_networks(endpoint, limit=MAX_RETURNED_ROWS)
    if not inventory.success or inventory.partial or inventory.truncated:
        return None, None, None, "A complete remote network inventory is required."
    matches = [network for network in inventory.networks if network.name == network_name]
    if len(matches) != 1 or matches[0].persistent is not True:
        return None, None, None, "The exact selected remote network must be persistent and appear once."
    network = matches[0]
    root, raw, error = _read_xml(
        endpoint,
        network_name,
        command="net-dumpxml",
        inactive=True,
        label="remote virtual-network definition",
    )
    if error or root is None or raw is None:
        return None, None, None, error or "The remote network definition is unavailable."
    if root.tag != "network" or root.findtext("name") != network_name:
        return None, None, None, "Remote libvirt returned a network definition with mismatched identity."
    uuid_output, uuid_error, uuid_truncated = _run_remote_virsh(
        endpoint,
        ["net-uuid", network_name],
        readonly=True,
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=4096,
        command_label="remote virtual-network UUID",
    )
    network_uuid = uuid_output.strip().casefold() if uuid_output and not uuid_error and not uuid_truncated else ""
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", network_uuid):
        return None, None, None, "Remote libvirt returned an invalid virtual-network UUID."
    return network, network_uuid, raw, None


def _prepare_target(
    endpoint: str,
    name: str,
    memory_mib: int,
    vcpus: int,
    pool_name: str,
    disk_volume_name: str,
    disk_capacity_bytes: int,
    network_name: str,
    *,
    allow_created_disk: bool = False,
) -> tuple[_RemoteCreateTarget | None, str | None]:
    error = _request_error(endpoint, name, memory_mib, vcpus, pool_name, disk_volume_name, disk_capacity_bytes, network_name)
    if error:
        return None, error
    parsed, error = _parse_endpoint(endpoint)
    if error or parsed is None:
        return None, error or "Remote endpoint is invalid."
    if not remote_virsh_available():
        return None, "Remote VM creation requires virsh and the OpenSSH client."

    pool, pool_uuid, pool_xml, storage_inventory, error = _pool_state(parsed.canonical, pool_name)
    if error or pool is None or pool_uuid is None or pool_xml is None or storage_inventory is None:
        return None, error or "The exact remote storage pool could not be verified."
    named_volumes = [volume for volume in storage_inventory.volumes if volume.name == disk_volume_name]
    if allow_created_disk:
        if len(named_volumes) != 1:
            return None, "The newly created remote disk volume could not be found uniquely."
        volume_pool, _pool_xml, _volume_xml, volume_format, capacity, volume_path, error = _pool_and_volume(
            parsed.canonical, pool_name, disk_volume_name
        )
        if error or volume_pool != pool_uuid or volume_format != "qcow2" or capacity != disk_capacity_bytes or volume_path is None:
            return None, error or "The newly created disk does not match the requested capacity and qcow2 format."
        referenced, error = _remote_disk_references(
            parsed.canonical,
            volume_path=volume_path,
            pool_name=pool_name,
            volume_name=disk_volume_name,
        )
        if error or referenced is not False:
            return None, error or "The newly created disk is unexpectedly referenced by a remote VM."
    elif named_volumes:
        return None, "A volume with that exact new disk name already exists in the selected remote pool."

    domains, domain_error, truncated = _read_remote_domains(parsed.canonical)
    if domain_error or domains is None or truncated:
        return None, domain_error or "A complete bounded remote domain inventory is required."
    if any(domain.name == name for domain in domains):
        return None, "A remote VM with that exact name already exists in the selected libvirt scope."

    network = None
    network_uuid = None
    network_xml = None
    if network_name:
        network, network_uuid, network_xml, error = _network_state(parsed.canonical, network_name)
        if error or network is None or network_uuid is None or network_xml is None:
            return None, error or "The selected remote virtual network could not be verified."

    domain_type, architecture, emulator, error = _read_remote_emulator(parsed.canonical)
    if error or domain_type is None or architecture is None or emulator is None:
        return None, error or "A safe remote QEMU emulator could not be selected."
    details = {
        "endpoint": parsed.canonical,
        "scope": parsed.scope,
        "name": name,
        "memory_mib": memory_mib,
        "vcpus": vcpus,
        "pool": [pool.name, pool_uuid, hashlib.sha256(pool_xml).hexdigest(), pool.state, pool.persistent],
        "disk_volume_name": disk_volume_name,
        "disk_capacity_bytes": disk_capacity_bytes,
        "network": (
            [network.name, network_uuid, hashlib.sha256(network_xml).hexdigest(), network.state, network.persistent]
            if network is not None and network_xml is not None
            else None
        ),
        "domains": sorted((domain.uuid, domain.name, domain.state, domain.domain_id) for domain in domains),
        "emulator": [domain_type, architecture, emulator],
        "uid": os.getuid(),
        "euid": os.geteuid(),
    }
    return _RemoteCreateTarget(
        endpoint=parsed.canonical,
        scope=parsed.scope,
        name=name,
        memory_mib=memory_mib,
        vcpus=vcpus,
        pool_name=pool.name,
        pool_uuid=pool_uuid,
        pool_xml_digest=hashlib.sha256(pool_xml).hexdigest(),
        disk_volume_name=disk_volume_name,
        disk_capacity_bytes=disk_capacity_bytes,
        network_name=network.name if network is not None else None,
        network_uuid=network_uuid,
        network_xml_digest=hashlib.sha256(network_xml).hexdigest() if network_xml is not None else None,
        domain_type=domain_type,
        architecture=architecture,
        emulator=emulator,
        state_digest=_digest(details),
    ), None


def remote_virtual_machine_create_confirmation_details(
    endpoint: str,
    name: str,
    memory_mib: int,
    vcpus: int,
    pool_name: str,
    disk_volume_name: str,
    disk_capacity_bytes: int,
    network_name: str = "",
) -> tuple[_RemoteCreateTarget | None, str | None, str | None]:
    target, error = _prepare_target(endpoint, name, memory_mib, vcpus, pool_name, disk_volume_name, disk_capacity_bytes, network_name)
    if error or target is None:
        return None, None, error or "The exact remote VM creation request could not be verified."
    phrase = "CREATE-REMOTE-VM-" + target.state_digest[:16].upper()
    return target, phrase, None


def _build_domain_xml(target: _RemoteCreateTarget, disk_path: str) -> bytes:
    if not disk_path.startswith("/") or len(disk_path) > 4096 or _CONTROL_RE.search(disk_path):
        raise ValueError("Remote libvirt returned an invalid disk path.")
    root = ET.Element("domain", {"type": target.domain_type})
    ET.SubElement(root, "name").text = target.name
    ET.SubElement(root, "memory", {"unit": "MiB"}).text = str(target.memory_mib)
    ET.SubElement(root, "currentMemory", {"unit": "MiB"}).text = str(target.memory_mib)
    ET.SubElement(root, "vcpu", {"placement": "static"}).text = str(target.vcpus)
    os_element = ET.SubElement(root, "os")
    ET.SubElement(os_element, "type", {"arch": target.architecture}).text = "hvm"
    ET.SubElement(os_element, "boot", {"dev": "hd"})
    ET.SubElement(root, "on_poweroff").text = "destroy"
    ET.SubElement(root, "on_reboot").text = "restart"
    ET.SubElement(root, "on_crash").text = "destroy"
    devices = ET.SubElement(root, "devices")
    ET.SubElement(devices, "emulator").text = target.emulator
    disk = ET.SubElement(devices, "disk", {"type": "file", "device": "disk"})
    ET.SubElement(disk, "driver", {"name": "qemu", "type": "qcow2"})
    ET.SubElement(disk, "source", {"file": disk_path})
    ET.SubElement(disk, "target", {"dev": "vda", "bus": "virtio"})
    if target.network_name:
        interface = ET.SubElement(devices, "interface", {"type": "network"})
        ET.SubElement(interface, "source", {"network": target.network_name})
        ET.SubElement(interface, "model", {"type": "virtio"})
    serial = ET.SubElement(devices, "serial", {"type": "pty"})
    ET.SubElement(serial, "target", {"port": "0"})
    console = ET.SubElement(devices, "console", {"type": "pty"})
    ET.SubElement(console, "target", {"type": "serial", "port": "0"})
    xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    if len(xml) > MAX_XML_BYTES:
        raise ValueError("The generated remote VM definition exceeded its size limit.")
    return xml


def _write_xml(xml: bytes, directory: str) -> str | None:
    descriptor = -1
    try:
        descriptor, path = tempfile.mkstemp(prefix="remote-domain-", suffix=".xml", dir=directory)
        os.fchmod(descriptor, 0o600)
        view = memoryview(xml)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("The remote VM XML file accepted no bytes.")
            view = view[written:]
        os.fsync(descriptor)
        return path
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_domain(target: _RemoteCreateTarget, uuid: str, disk_path: str) -> bool:
    root, _raw, error = _read_xml(
        target.endpoint,
        uuid,
        command="dumpxml",
        inactive=True,
        label="remote defined-VM verification",
    )
    if error or root is None or root.tag != "domain" or root.findtext("name") != target.name:
        return False
    if root.findtext("uuid", "").casefold() != uuid.casefold():
        return False
    if root.get("type") != target.domain_type or root.findtext("./devices/emulator") != target.emulator:
        return False
    memory = root.find("memory")
    vcpu = (root.findtext("vcpu") or "").strip()
    units = {"b": 1, "bytes": 1, "kib": 1024, "mib": 1 << 20, "gib": 1 << 30}
    if memory is None or memory.text is None or vcpu != str(target.vcpus):
        return False
    unit = memory.get("unit", "KiB").casefold()
    if not memory.text.strip().isdigit() or int(memory.text.strip()) * units.get(unit, 0) != target.memory_mib * (1 << 20):
        return False
    disks = []
    for disk in root.findall("./devices/disk"):
        source, slot, driver = disk.find("source"), disk.find("target"), disk.find("driver")
        if (
            source is not None and source.get("file") == disk_path
            and slot is not None and slot.get("dev") == "vda" and slot.get("bus") == "virtio"
            and driver is not None and driver.get("name") == "qemu" and driver.get("type") == "qcow2"
        ):
            disks.append(disk)
    if len(disks) != 1:
        return False
    networks = [
        source.get("network")
        for interface in root.findall("./devices/interface")
        if (source := interface.find("source")) is not None and interface.get("type") == "network"
    ]
    if target.network_name:
        return networks.count(target.network_name) == 1
    return not networks


def _response(target: _RemoteCreateTarget | None, *, success: bool, confirmed: bool, verified: bool, uuid: str | None = None, message: str) -> RemoteVirtualMachineCreateResponse:
    return RemoteVirtualMachineCreateResponse(
        success=success,
        endpoint=target.endpoint if target else None,
        scope=target.scope if target else None,
        uuid=uuid,
        name=target.name if target else None,
        memory_mib=target.memory_mib if target else None,
        vcpus=target.vcpus if target else None,
        pool_name=target.pool_name if target else None,
        disk_volume_name=target.disk_volume_name if target else None,
        disk_capacity_bytes=target.disk_capacity_bytes if target else None,
        network_name=target.network_name if target else None,
        state_verified=verified,
        user_confirmed=confirmed,
        message=message,
    )


def perform_remote_virtual_machine_create(
    endpoint: str,
    name: str,
    memory_mib: int,
    vcpus: int,
    pool_name: str,
    disk_volume_name: str,
    disk_capacity_bytes: int,
    network_name: str,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> RemoteVirtualMachineCreateResponse:
    target, error = _prepare_target(endpoint, name, memory_mib, vcpus, pool_name, disk_volume_name, disk_capacity_bytes, network_name)
    if error or target is None:
        return _response(None, success=False, confirmed=confirmed is True, verified=False, message=error or "The remote VM creation request could not be verified.")
    if confirmed is not True:
        return _response(target, success=False, confirmed=False, verified=False, message="Explicit client confirmation is required; no remote storage or VM definition was changed.")
    expected_phrase = "CREATE-REMOTE-VM-" + target.state_digest[:16].upper()
    if not isinstance(confirmation_phrase, str) or not hmac.compare_digest(confirmation_phrase, expected_phrase):
        return _response(target, success=False, confirmed=True, verified=False, message="Confirmation did not match the exact remote VM configuration and current state.")

    with _LOCK:
        current, error = _prepare_target(endpoint, name, memory_mib, vcpus, pool_name, disk_volume_name, disk_capacity_bytes, network_name)
        if error or current is None or current.state_digest != target.state_digest:
            return _response(target, success=False, confirmed=True, verified=False, message=error or "Remote VM, pool, network, or host capability state changed after confirmation.")
        volume_output, volume_error, volume_truncated = _run_remote_virsh(
            target.endpoint,
            ["vol-create-as", target.pool_uuid, target.disk_volume_name, str(target.disk_capacity_bytes), "--allocation", "0", "--format", "qcow2"],
            readonly=False,
            timeout_seconds=VOLUME_TIMEOUT_SECONDS,
            max_output_bytes=16 * 1024,
            command_label="remote sparse qcow2 disk creation",
        )
        if volume_error or volume_output is None or volume_truncated:
            return _response(target, success=False, confirmed=True, verified=False, message="Remote VM creation stopped because sparse disk creation was not confirmed. The pool may contain a partial new volume; inspect it before retrying.")
        after_volume, error = _prepare_target(
            target.endpoint, target.name, target.memory_mib, target.vcpus, target.pool_name,
            target.disk_volume_name, target.disk_capacity_bytes, target.network_name or "", allow_created_disk=True,
        )
        if error or after_volume is None or after_volume.state_digest != target.state_digest:
            return _response(target, success=False, confirmed=True, verified=False, message=error or "Remote VM, pool, network, or host capability state changed after disk creation; inspect the new volume before retrying.")
        pool_uuid, _pool_xml, _volume_xml, volume_format, capacity, disk_path, volume_error = _pool_and_volume(
            target.endpoint, target.pool_name, target.disk_volume_name
        )
        if volume_error or pool_uuid != target.pool_uuid or volume_format != "qcow2" or capacity != target.disk_capacity_bytes or disk_path is None:
            return _response(target, success=False, confirmed=True, verified=False, message=volume_error or "The new sparse qcow2 disk could not be verified; inspect the remote pool before retrying.")
        try:
            xml = _build_domain_xml(target, disk_path)
        except (ValueError, ET.ParseError):
            return _response(target, success=False, confirmed=True, verified=False, message="A valid bounded remote VM definition could not be generated; inspect the new volume before retrying.")

        define_error: str | None = None
        output: str | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="linux-mcp-remote-vm-", dir="/tmp") as temp_dir:
                os.chmod(temp_dir, 0o700)
                xml_path = _write_xml(xml, temp_dir)
                if xml_path is None:
                    return _response(target, success=False, confirmed=True, verified=False, message="A private temporary remote VM definition could not be written; inspect the new volume before retrying.")
                output, define_error, truncated = _run_remote_virsh(
                    target.endpoint,
                    ["define", "--validate", xml_path],
                    readonly=False,
                    timeout_seconds=DEFINE_TIMEOUT_SECONDS,
                    max_output_bytes=16 * 1024,
                    command_label="remote libvirt VM definition",
                )
                if truncated:
                    define_error = define_error or "Remote virsh definition output exceeded its limit."
        except OSError:
            define_error = "A private temporary directory could not be created."

        domains, inventory_error, truncated = _read_remote_domains(target.endpoint)
        if domains is None or inventory_error or truncated:
            return _response(target, success=False, confirmed=True, verified=False, message="The remote definition was attempted but its state could not be verified. Inspect remote libvirt and the new disk before retrying.")
        matches = [domain for domain in domains if domain.name == target.name]
        if len(matches) != 1:
            detail = define_error or "the remote VM name is missing or ambiguous after definition"
            return _response(target, success=False, confirmed=True, verified=False, message=f"The disk was created, but the remote VM definition was not verified ({detail[:300]}). Inspect libvirt and the pool before retrying.")
        domain = matches[0]
        if domain.state != "shut off" or not _verify_domain(target, domain.uuid, disk_path):
            return _response(target, success=False, confirmed=True, verified=False, uuid=domain.uuid, message="A remote VM definition exists, but its exact configuration or stopped state could not be verified. Inspect it before retrying.")
        if define_error or output is None:
            return _response(target, success=False, confirmed=True, verified=True, uuid=domain.uuid, message="The remote VM definition is present and matches the requested stopped configuration, but virsh reported an uncertain result. Inspect it before retrying.")
        return _response(
            target,
            success=True,
            confirmed=True,
            verified=True,
            uuid=domain.uuid,
            message="The stopped remote VM and its new sparse qcow2 disk were defined and verified. No operating system was installed and the VM was not started.",
        )
