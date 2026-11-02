"""Confirmed creation of one stopped local QEMU/libvirt VM and fresh disk."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import stat
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import VirtualMachineCreateResponse
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
from wayland_mcp.tools.virtual_machines import _read_scope

MIN_DISK_BYTES = 1 << 20
MAX_DISK_BYTES = 1 << 40
MIN_MEMORY_MIB = 256
MAX_MEMORY_MIB = 1 << 20
MAX_VCPUS = 128
MAX_DOMAIN_NAME_BYTES = 64
MAX_VIRSH_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_XML_BYTES = 128 * 1024
COMMAND_TIMEOUT_SECONDS = 20
VOLUME_TIMEOUT_SECONDS = 120
_DOMAIN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_LOCK = threading.RLock()


@dataclass(frozen=True, slots=True)
class _DomainCreateTarget:
    scope: str
    name: str
    memory_mib: int
    vcpus: int
    pool_name: str
    pool_uuid: str
    disk_volume_name: str
    disk_capacity_bytes: int
    network_name: str | None
    network_uuid: str | None
    domain_type: str
    architecture: str
    emulator: str
    state_digest: str


def _validate_request(
    scope: object,
    name: object,
    memory_mib: object,
    vcpus: object,
    pool_name: object,
    disk_volume_name: object,
    disk_capacity_bytes: object,
    network_name: object,
) -> str | None:
    if not isinstance(scope, str) or scope not in SCOPED_URIS:
        return "Choose the local system or user-session libvirt scope."
    if (
        not isinstance(name, str)
        or len(name.encode("utf-8", errors="ignore")) > MAX_DOMAIN_NAME_BYTES
        or not _DOMAIN_NAME_RE.fullmatch(name)
    ):
        return "VM names must start with a letter or digit and contain at most 64 letters, digits, dots, underscores, or hyphens."
    if (
        not isinstance(memory_mib, int)
        or isinstance(memory_mib, bool)
        or not MIN_MEMORY_MIB <= memory_mib <= MAX_MEMORY_MIB
    ):
        return f"memory_mib must be an integer from {MIN_MEMORY_MIB} through {MAX_MEMORY_MIB}."
    if not isinstance(vcpus, int) or isinstance(vcpus, bool) or not 1 <= vcpus <= MAX_VCPUS:
        return f"vcpus must be an integer from 1 through {MAX_VCPUS}."
    pool_error = _validate_resource_name("storage_pool", pool_name)
    if pool_error:
        return pool_error
    if not isinstance(disk_volume_name, str) or not _VOLUME_NAME_RE.fullmatch(disk_volume_name):
        return "disk_volume_name must be a new volume name containing at most 128 letters, digits, dots, underscores, or hyphens."
    if (
        not isinstance(disk_capacity_bytes, int)
        or isinstance(disk_capacity_bytes, bool)
        or not MIN_DISK_BYTES <= disk_capacity_bytes <= MAX_DISK_BYTES
    ):
        return f"disk_capacity_bytes must be an integer from {MIN_DISK_BYTES} bytes through {MAX_DISK_BYTES} bytes."
    if not isinstance(network_name, str) or len(network_name) > 256:
        return "network_name must be empty or an exact local libvirt network name of at most 256 characters."
    if any(ord(character) < 32 or ord(character) == 127 for character in network_name):
        return "network_name cannot contain control characters."
    if network_name:
        network_error = _validate_resource_name("network", network_name)
        if network_error:
            return network_error
    return None


def _libvirt_architecture() -> str:
    machine = platform.machine().casefold()
    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "arm64": "aarch64",
        "armv8l": "aarch64",
        "ppc64el": "ppc64le",
    }
    return aliases.get(machine, machine)


def _read_emulator(
    scope: str,
    binary: str,
    env: dict[str, str],
) -> tuple[str | None, str | None, str | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "--quiet", "--no-pkttyagent", "--connect", SCOPED_URIS[scope], "--readonly", "capabilities"],
        env,
        command_label=f"local libvirt {scope} host capabilities",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_VIRSH_OUTPUT_BYTES,
    )
    if error or output is None or truncated:
        return None, None, None, "Local libvirt host capabilities could not be read safely."
    if "<!doctype" in output.casefold() or "<!entity" in output.casefold():
        return None, None, None, "The libvirt capabilities document contains unsupported XML declarations."
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return None, None, None, "Libvirt returned malformed host capabilities."
    if root.tag != "capabilities":
        return None, None, None, "Libvirt returned an unrecognized host-capabilities document."
    wanted_arch = _libvirt_architecture()
    candidates: list[tuple[str, str, str]] = []
    for guest in root.findall("guest"):
        arch = guest.find("arch")
        if arch is None or arch.get("name") != wanted_arch:
            continue
        for domain in arch.findall("domain"):
            domain_type = domain.get("type", "")
            emulator = (domain.findtext("emulator") or "").strip()
            if domain_type in {"kvm", "qemu"} and emulator.startswith("/"):
                candidates.append((domain_type, wanted_arch, emulator))
    candidates.sort(key=lambda item: (item[0] != "kvm", item[2]))
    for domain_type, architecture, reported_emulator in candidates:
        try:
            emulator_path = Path(reported_emulator).resolve(strict=True)
            info = emulator_path.stat(follow_symlinks=False)
        except (OSError, RuntimeError):
            continue
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in {0, os.geteuid()}
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not info.st_mode & stat.S_IXUSR
            or len(str(emulator_path)) > 4096
        ):
            continue
        return domain_type, architecture, str(emulator_path), None
    return None, None, None, "Libvirt reports no safe QEMU emulator for the host architecture."


def _read_domain_inventory(
    scope: str,
    binary: str,
) -> tuple[list[object] | None, str | None, bool]:
    domains, error, truncated = _read_scope(scope, binary)
    if domains is None or error:
        return None, error or "The local libvirt domain inventory could not be read. ", truncated
    return domains, None, truncated


def _prepare_target(
    scope: str,
    name: str,
    memory_mib: int,
    vcpus: int,
    pool_name: str,
    disk_volume_name: str,
    disk_capacity_bytes: int,
    network_name: str,
) -> tuple[_DomainCreateTarget | None, str | None]:
    error = _validate_request(
        scope, name, memory_mib, vcpus, pool_name, disk_volume_name, disk_capacity_bytes, network_name
    )
    if error:
        return None, error
    if not sys.platform.startswith("linux"):
        return None, "Virtual-machine creation is available only on Linux."
    env = virsh_environment()
    binary = find_session_binary("virsh", env)
    if not binary:
        return None, "The optional virsh command is unavailable."

    pool, error = _read_resource_info("storage_pool", scope, pool_name, binary, env)
    if error or pool is None:
        return None, error or "The exact local storage pool could not be verified."
    if pool.persistent is not True or not pool.active or pool.state != "running":
        return None, "VM creation requires a persistent, running libvirt storage pool."
    pool_type, error = _read_pool_type(scope, pool.uuid, binary, env)
    if error or pool_type != "dir":
        return None, error or "VM creation supports only directory-backed libvirt pools."
    volume_names, error = _read_pool_volume_names(scope, pool.uuid, binary, env)
    if error or volume_names is None:
        return None, error or "The selected pool's volume names could not be fully inspected."
    if disk_volume_name in volume_names:
        return None, "A volume with that exact disk name already exists in the selected pool."

    domains, error, truncated = _read_domain_inventory(scope, binary)
    if error or domains is None:
        return None, error or "The exact local domain inventory could not be read."
    if truncated:
        return None, "The local domain inventory was truncated; VM name uniqueness cannot be verified."
    if any(getattr(domain, "name", None) == name for domain in domains):
        return None, "A local VM with that exact name already exists in the selected libvirt scope."

    network = None
    if network_name:
        network, error = _read_resource_info("network", scope, network_name, binary, env)
        if error or network is None:
            return None, error or "The exact virtual network could not be verified."
        if network.persistent is not True:
            return None, "The VM can attach only to a persistent virtual network."

    domain_type, architecture, emulator, error = _read_emulator(scope, binary, env)
    if error or domain_type is None or architecture is None or emulator is None:
        return None, error or "A safe host QEMU emulator could not be selected."

    details = {
        "scope": scope,
        "name": name,
        "memory_mib": memory_mib,
        "vcpus": vcpus,
        "pool": [pool.name, pool.uuid, pool.state, pool.persistent, pool.autostart],
        "volume_names_digest": hashlib.sha256(
            json.dumps(sorted(volume_names), separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "disk_volume_name": disk_volume_name,
        "disk_capacity_bytes": disk_capacity_bytes,
        "network": (
            [network.name, network.uuid, network.state, network.persistent, network.autostart]
            if network is not None
            else None
        ),
        "domain_type": domain_type,
        "architecture": architecture,
        "emulator": emulator,
        "uid": os.getuid(),
        "euid": os.geteuid(),
    }
    state_digest = hashlib.sha256(
        json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return _DomainCreateTarget(
        scope=scope,
        name=name,
        memory_mib=memory_mib,
        vcpus=vcpus,
        pool_name=pool.name,
        pool_uuid=pool.uuid,
        disk_volume_name=disk_volume_name,
        disk_capacity_bytes=disk_capacity_bytes,
        network_name=network.name if network is not None else None,
        network_uuid=network.uuid if network is not None else None,
        domain_type=domain_type,
        architecture=architecture,
        emulator=emulator,
        state_digest=state_digest,
    ), None


def virtual_machine_create_confirmation_details(
    scope: str,
    name: str,
    memory_mib: int,
    vcpus: int,
    pool_name: str,
    disk_volume_name: str,
    disk_capacity_bytes: int,
    network_name: str = "",
) -> tuple[_DomainCreateTarget | None, str | None, str | None]:
    target, error = _prepare_target(
        scope, name, memory_mib, vcpus, pool_name, disk_volume_name, disk_capacity_bytes, network_name
    )
    if error or target is None:
        return None, None, error or "The exact VM creation request could not be verified."
    phrase = "CREATE-VM-" + target.state_digest[:16].upper()
    return target, phrase, None


def _read_volume_path(
    target: _DomainCreateTarget,
    binary: str,
    env: dict[str, str],
) -> tuple[str | None, tuple[int, int, int, int, int, int, int, int] | None, str | None]:
    output, error, truncated = run_bounded_command(
        [binary, "--quiet", "--no-pkttyagent", "--connect", SCOPED_URIS[target.scope], "--readonly", "vol-path", "--pool", target.pool_uuid, target.disk_volume_name],
        env,
        command_label=f"local libvirt {target.scope} disk-path lookup",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=16 * 1024,
    )
    if error or output is None or truncated:
        return None, None, "The new disk volume path could not be verified."
    lines = output.splitlines()
    if len(lines) != 1 or not lines[0].startswith("/") or len(lines[0]) > 4096:
        return None, None, "Libvirt returned an invalid disk volume path."
    try:
        reported_path = Path(lines[0])
        reported_info = reported_path.lstat()
        path = reported_path.resolve(strict=True)
        info = path.lstat()
    except (OSError, RuntimeError):
        return None, None, "The new disk volume is not a readable local regular file."
    if (
        str(path) != lines[0]
        or stat.S_ISLNK(reported_info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        return None, None, "The new disk volume is not a safe regular file."
    identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    return str(path), identity, None


def _build_domain_xml(target: _DomainCreateTarget, disk_path: str) -> bytes:
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
        raise ValueError("The generated VM configuration exceeded its size limit.")
    return xml


def _write_xml_file(xml: bytes, directory: str) -> str | None:
    descriptor = -1
    try:
        descriptor, path = tempfile.mkstemp(prefix="domain-", suffix=".xml", dir=directory)
        os.fchmod(descriptor, 0o600)
        view = memoryview(xml)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("The VM XML file accepted no bytes.")
            view = view[written:]
        os.fsync(descriptor)
        return path
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_domain_xml(
    target: _DomainCreateTarget,
    uuid: str,
    expected_disk_path: str,
    binary: str,
    env: dict[str, str],
) -> bool:
    output, error, truncated = run_bounded_command(
        [binary, "--quiet", "--no-pkttyagent", "--connect", SCOPED_URIS[target.scope], "--readonly", "dumpxml", "--inactive", uuid],
        env,
        command_label=f"local libvirt {target.scope} defined-domain verification",
        timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        max_output_bytes=MAX_XML_BYTES,
    )
    if error or output is None or truncated or "<!doctype" in output.casefold() or "<!entity" in output.casefold():
        return False
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return False
    if root.tag != "domain" or root.findtext("name") != target.name:
        return False
    if root.get("type") != target.domain_type or root.findtext("./devices/emulator") != target.emulator:
        return False
    memory = root.find("memory")
    vcpu = (root.findtext("vcpu") or "").strip()
    if memory is None or memory.text is None or vcpu != str(target.vcpus):
        return False
    unit = memory.get("unit", "KiB").casefold()
    units = {"b": 1, "bytes": 1, "kib": 1024, "mib": 1 << 20, "gib": 1 << 30}
    if not memory.text.strip().isdigit() or int(memory.text.strip()) * units.get(unit, 0) != target.memory_mib * (1 << 20):
        return False
    disks = root.findall("./devices/disk")
    disk_matches = []
    for disk in disks:
        target_element = disk.find("target")
        source_element = disk.find("source")
        driver = disk.find("driver")
        if (
            target_element is not None
            and target_element.get("dev") == "vda"
            and source_element is not None
            and source_element.get("file") == expected_disk_path
            and driver is not None
            and driver.get("type") == "qcow2"
        ):
            disk_matches.append(disk)
    if len(disk_matches) != 1:
        return False
    networks = [
        source.get("network")
        for interface in root.findall("./devices/interface")
        if (source := interface.find("source")) is not None
        and interface.get("type") == "network"
    ]
    if target.network_name:
        return networks.count(target.network_name) == 1
    return not networks


def _create_response(
    *,
    target: _DomainCreateTarget | None,
    success: bool,
    user_confirmed: bool,
    state_verified: bool,
    uuid: str | None = None,
    message: str,
) -> VirtualMachineCreateResponse:
    return VirtualMachineCreateResponse(
        success=success,
        scope=target.scope if target else None,
        uuid=uuid,
        name=target.name if target else None,
        memory_mib=target.memory_mib if target else None,
        vcpus=target.vcpus if target else None,
        pool_name=target.pool_name if target else None,
        disk_volume_name=target.disk_volume_name if target else None,
        disk_capacity_bytes=target.disk_capacity_bytes if target else None,
        network_name=target.network_name if target else None,
        state_verified=state_verified,
        user_confirmed=user_confirmed,
        message=message,
    )


def perform_virtual_machine_create(
    scope: str,
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
) -> VirtualMachineCreateResponse:
    target, error = _prepare_target(
        scope, name, memory_mib, vcpus, pool_name, disk_volume_name, disk_capacity_bytes, network_name
    )
    if error or target is None:
        return _create_response(target=None, success=False, user_confirmed=confirmed is True, state_verified=False, message=error or "The exact VM creation request could not be verified.")
    if confirmed is not True:
        return _create_response(target=target, success=False, user_confirmed=False, state_verified=False, message="Explicit client confirmation is required; no libvirt command was run.")
    phrase = "CREATE-VM-" + target.state_digest[:16].upper()
    if not isinstance(confirmation_phrase, str) or not hmac.compare_digest(confirmation_phrase, phrase):
        return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message="Confirmation did not match the exact VM configuration and current libvirt state.")

    with _LOCK:
        current, error = _prepare_target(
            scope, name, memory_mib, vcpus, pool_name, disk_volume_name, disk_capacity_bytes, network_name
        )
        if error or current is None or current.state_digest != target.state_digest:
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message=error or "The VM, pool, volume, network, or host-capability state changed after confirmation.")
        env = virsh_environment()
        binary = find_session_binary("virsh", env)
        if not binary:
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message="The optional virsh command became unavailable; no VM was created.")

        create_volume = [
            binary, "--quiet", "--no-pkttyagent", "--connect", SCOPED_URIS[target.scope],
            "vol-create-as", target.pool_uuid, target.disk_volume_name,
            str(target.disk_capacity_bytes), "--allocation", "0", "--format", "qcow2",
        ]
        _output, volume_error, volume_truncated = run_bounded_command(
            create_volume,
            env,
            command_label=f"local libvirt {target.scope} VM disk creation",
            timeout_seconds=VOLUME_TIMEOUT_SECONDS,
            max_output_bytes=16 * 1024,
        )
        created_volume, volume_verify_error = _read_created_volume_definition(
            target.scope, target.pool_uuid, target.disk_volume_name, binary, env
        )
        if volume_error or volume_truncated or created_volume != (target.disk_capacity_bytes, "qcow2"):
            detail = volume_error or volume_verify_error or "the disk capacity/format could not be verified"
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message=f"VM creation stopped because its fresh disk could not be verified ({detail[:300]}). Inspect the storage pool before retrying.")

        disk_path, disk_identity, path_error = _read_volume_path(target, binary, env)
        if path_error or disk_path is None or disk_identity is None:
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message=path_error or "The new disk path could not be verified; inspect the storage pool before retrying.")
        try:
            current_path_info = Path(disk_path).lstat()
        except OSError:
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message="The new disk changed after verification; inspect the storage pool before retrying.")
        if (current_path_info.st_dev, current_path_info.st_ino, current_path_info.st_mode, current_path_info.st_uid, current_path_info.st_gid, current_path_info.st_size, current_path_info.st_mtime_ns, current_path_info.st_ctime_ns) != disk_identity:
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message="The new disk changed after verification; inspect the storage pool before retrying.")

        # Recheck name and network identity after disk creation and before defining the guest.
        domains, error, truncated = _read_domain_inventory(target.scope, binary)
        if error or domains is None or truncated or any(getattr(domain, "name", None) == target.name for domain in domains):
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message=error or "The VM name became occupied or domain inventory changed after disk creation; inspect the pool before retrying.")
        pool, error = _read_resource_info("storage_pool", target.scope, target.pool_name, binary, env)
        if error or pool is None or pool.uuid != target.pool_uuid or pool.state != "running" or pool.persistent is not True:
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message=error or "The storage pool changed after disk creation; inspect the pool before retrying.")
        if target.network_name:
            network, error = _read_resource_info("network", target.scope, target.network_name, binary, env)
            if error or network is None or network.uuid != target.network_uuid or network.persistent is not True:
                return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message=error or "The selected virtual network changed after disk creation; inspect the pool before retrying.")

        try:
            xml = _build_domain_xml(target, disk_path)
        except (ValueError, ET.ParseError):
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message="A valid bounded libvirt domain definition could not be generated; inspect the new disk before retrying.")
        define_error: str | None = None
        output: str | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="linux-mcp-vm-") as temp_dir:
                os.chmod(temp_dir, 0o700)
                xml_path = _write_xml_file(xml, temp_dir)
                if xml_path is None:
                    return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message="A private temporary VM definition could not be written; inspect the new disk before retrying.")
                try:
                    final_disk_info = Path(disk_path).lstat()
                except OSError:
                    return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message="The new disk changed before VM definition; inspect the storage pool before retrying.")
                final_disk_identity = (final_disk_info.st_dev, final_disk_info.st_ino, final_disk_info.st_mode, final_disk_info.st_uid, final_disk_info.st_gid, final_disk_info.st_size, final_disk_info.st_mtime_ns, final_disk_info.st_ctime_ns)
                if final_disk_identity != disk_identity or not stat.S_ISREG(final_disk_info.st_mode):
                    return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message="The new disk changed before VM definition; inspect the storage pool before retrying.")
                output, define_error, truncated = run_bounded_command(
                    [binary, "--quiet", "--no-pkttyagent", "--connect", SCOPED_URIS[target.scope], "define", "--validate", xml_path],
                    env,
                    command_label=f"local libvirt {target.scope} VM definition",
                    timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                    max_output_bytes=16 * 1024,
                )
                if truncated:
                    define_error = define_error or "virsh definition output exceeded its limit"
        except OSError as exc:
            define_error = exc.strerror or "a private temporary directory could not be created"

        domains, inventory_error, truncated = _read_domain_inventory(target.scope, binary)
        if domains is None or inventory_error or truncated:
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message="The VM definition was attempted but its state could not be verified. Inspect libvirt and the new disk before retrying.")
        matches = [domain for domain in domains if getattr(domain, "name", None) == target.name]
        if define_error or output is None or len(matches) != 1:
            detail = define_error or ("the VM name is missing or ambiguous after definition" if len(matches) != 1 else "the definition did not return a verification result")
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, message=f"The disk was created, but the VM definition was not verified ({detail[:300]}). Inspect libvirt and the pool before retrying.")
        domain = matches[0]
        if getattr(domain, "state", None) != "shut off" or not _verify_domain_xml(target, getattr(domain, "uuid", ""), disk_path, binary, env):
            return _create_response(target=target, success=False, user_confirmed=True, state_verified=False, uuid=getattr(domain, "uuid", None), message="A VM definition exists, but its exact configuration or stopped state could not be verified. Inspect it before retrying.")
        return _create_response(
            target=target,
            success=True,
            user_confirmed=True,
            state_verified=True,
            uuid=getattr(domain, "uuid", None),
            message="The persistent VM and its new blank qcow2 disk were defined and verified. The VM remains stopped; no operating system was installed or started.",
        )
