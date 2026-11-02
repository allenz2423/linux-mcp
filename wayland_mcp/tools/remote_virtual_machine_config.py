"""Confirmed persistent memory and vCPU configuration for a shut-off remote VM."""

from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from wayland_mcp.models import RemoteVirtualMachineConfigResponse
from wayland_mcp.tools.remote_virtual_machine_disks import MAX_XML_BYTES, _read_xml
from wayland_mcp.tools.remote_virtual_machines import (
    COMMAND_TIMEOUT_SECONDS,
    MAX_VIRSH_OUTPUT_BYTES,
    _RemoteActionToken,
    _TOKEN_LOCK,
    _TOKENS,
    _lookup_current,
    _run_remote_virsh,
    _token_record,
)
from wayland_mcp.tools.virtual_machines import TOKEN_RE

MIN_MEMORY_MIB = 256
MAX_MEMORY_MIB = 1 << 20
MAX_VCPUS = 128
CONFIRMATION_TTL_SECONDS = 90.0
_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class _RemoteConfigTarget:
    identity_token: str
    endpoint: str
    scope: str
    uuid: str
    name: str
    domain_state: str
    domain_id: int | None
    xml_digest: str
    previous_max_memory_mib: int
    previous_current_memory_mib: int
    previous_vcpus: int
    memory_mib: int
    vcpus: int
    confirmation_phrase: str
    expires_at: float


_TARGETS: dict[str, _RemoteConfigTarget] = {}


def _memory_mib(element: ET.Element | None) -> int | None:
    if element is None or element.text is None or not element.text.strip().isdigit() or len(element.text.strip()) > 20:
        return None
    units = {"b": 1, "bytes": 1, "kib": 1024, "mib": 1 << 20, "gib": 1 << 30}
    unit = element.get("unit", "KiB").casefold()
    multiplier = units.get(unit)
    if multiplier is None:
        return None
    try:
        byte_count = int(element.text.strip()) * multiplier
    except ValueError:
        return None
    if byte_count <= 0 or byte_count % (1 << 20):
        return None
    return byte_count // (1 << 20)


def _read_target_xml(record: _RemoteActionToken) -> tuple[ET.Element | None, bytes | None, int | None, int | None, int | None, str | None]:
    root, raw, error = _read_xml(
        record.endpoint,
        record.uuid,
        command="dumpxml",
        inactive=True,
        label="remote VM persistent definition",
    )
    if error or root is None or raw is None:
        return None, None, None, None, None, error or "The remote VM definition is unavailable."
    if (
        root.tag != "domain"
        or root.findtext("name") != record.name
        or root.findtext("uuid", "").casefold() != record.uuid.casefold()
    ):
        return None, None, None, None, None, "Remote libvirt returned a domain definition with mismatched identity."
    maximum = _memory_mib(root.find("memory"))
    current = _memory_mib(root.find("currentMemory"))
    vcpu_text = (root.findtext("vcpu") or "").strip()
    if maximum is None or current is None or not vcpu_text.isdigit() or len(vcpu_text) > 3 or int(vcpu_text) < 1:
        return None, None, None, None, None, "The remote VM memory or vCPU values are missing or use unsupported units."
    if current > maximum:
        return None, None, None, None, None, "The remote VM's current memory exceeds its configured maximum."
    return root, raw, maximum, current, int(vcpu_text), None


def _prepare_target(
    identity_token: str,
    memory_mib: int,
    vcpus: int,
) -> tuple[_RemoteActionToken | None, ET.Element | None, bytes | None, int | None, int | None, int | None, str | None]:
    if not isinstance(identity_token, str) or not TOKEN_RE.fullmatch(identity_token):
        return None, None, None, None, None, None, "A fresh identity_token from list_remote_virtual_machines is required."
    if not isinstance(memory_mib, int) or isinstance(memory_mib, bool) or not MIN_MEMORY_MIB <= memory_mib <= MAX_MEMORY_MIB:
        return None, None, None, None, None, None, f"memory_mib must be an integer from {MIN_MEMORY_MIB} through {MAX_MEMORY_MIB}."
    if not isinstance(vcpus, int) or isinstance(vcpus, bool) or not 1 <= vcpus <= MAX_VCPUS:
        return None, None, None, None, None, None, f"vcpus must be an integer from 1 through {MAX_VCPUS}."
    record, error = _token_record(identity_token)
    if error or record is None:
        return None, None, None, None, None, None, error or "The exact remote VM identity is unavailable."
    current, error = _lookup_current(record)
    if error or current is None:
        return None, None, None, None, None, None, error or "The exact remote VM could not be verified."
    if current.state != record.state or current.domain_id != record.domain_id:
        return None, None, None, None, None, None, "The remote VM state changed after it was listed; list remote VMs again."
    if current.state != "shut off" or current.domain_id is not None:
        return None, None, None, None, None, None, "Persistent resource configuration is limited to a shut-off remote VM."
    root, raw, maximum, current_memory, current_vcpus, error = _read_target_xml(record)
    if error or root is None or raw is None or maximum is None or current_memory is None or current_vcpus is None:
        return None, None, None, None, None, None, error or "The remote VM definition could not be inspected."
    return record, root, raw, maximum, current_memory, current_vcpus, None


def remote_virtual_machine_config_confirmation_details(
    identity_token: str,
    memory_mib: int,
    vcpus: int,
) -> tuple[_RemoteConfigTarget | None, str | None]:
    record, root, raw, maximum, current_memory, current_vcpus, error = _prepare_target(identity_token, memory_mib, vcpus)
    if error or record is None or root is None or raw is None or maximum is None or current_memory is None or current_vcpus is None:
        return None, error or "The exact remote VM configuration could not be prepared."
    digest = hashlib.sha256(raw).hexdigest()
    phrase_data = "\0".join((record.endpoint, record.scope, record.uuid, record.name, digest, str(memory_mib), str(vcpus), str(os.getuid()), str(os.geteuid())))
    phrase = "CONFIGURE-REMOTE-VM-" + hashlib.sha256(phrase_data.encode("utf-8")).hexdigest()[:16].upper()
    target = _RemoteConfigTarget(
        identity_token=identity_token,
        endpoint=record.endpoint,
        scope=record.scope,
        uuid=record.uuid,
        name=record.name,
        domain_state=record.state,
        domain_id=record.domain_id,
        xml_digest=digest,
        previous_max_memory_mib=maximum,
        previous_current_memory_mib=current_memory,
        previous_vcpus=current_vcpus,
        memory_mib=memory_mib,
        vcpus=vcpus,
        confirmation_phrase=phrase,
        expires_at=time.monotonic() + CONFIRMATION_TTL_SECONDS,
    )
    with _TOKEN_LOCK:
        if _TOKENS.get(identity_token) is not record or record.claimed or record.expires_at <= time.monotonic():
            return None, "The remote VM token is expired or already reserved; list remote VMs again."
        record.claimed = True
        record.action = "config:resources"
        record.confirmation_token = phrase
    with _LOCK:
        now = time.monotonic()
        for key in [key for key, value in _TARGETS.items() if value.expires_at <= now]:
            _TARGETS.pop(key, None)
        if len(_TARGETS) >= 256:
            oldest = min(_TARGETS, key=lambda key: _TARGETS[key].expires_at)
            _TARGETS.pop(oldest, None)
        _TARGETS[identity_token] = target
    return target, None


def _write_xml(xml: bytes, directory: str) -> str | None:
    descriptor = -1
    try:
        descriptor, path = tempfile.mkstemp(prefix="remote-vm-config-", suffix=".xml", dir=directory)
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


def _set_memory(element: ET.Element, value: int) -> None:
    element.set("unit", "MiB")
    element.text = str(value)


def _configuration_matches(root: ET.Element, target: _RemoteConfigTarget) -> bool:
    if (
        root.tag != "domain"
        or root.findtext("name") != target.name
        or root.findtext("uuid", "").casefold() != target.uuid.casefold()
    ):
        return False
    vcpu_element = root.find("vcpu")
    return (
        _memory_mib(root.find("memory")) == target.memory_mib
        and _memory_mib(root.find("currentMemory")) == target.memory_mib
        and vcpu_element is not None
        and (vcpu_element.text or "").strip() == str(target.vcpus)
        and (vcpu_element.get("current") is None or vcpu_element.get("current") == str(target.vcpus))
    )


def perform_remote_virtual_machine_config(
    identity_token: str,
    memory_mib: int,
    vcpus: int,
    confirmation_phrase: str,
    *,
    confirmed: bool,
) -> RemoteVirtualMachineConfigResponse:
    record, error = _token_record(identity_token)
    if error or record is None:
        return RemoteVirtualMachineConfigResponse(success=False, user_confirmed=confirmed is True, message=error or "A fresh remote VM identity token is required.")
    with _LOCK:
        target = _TARGETS.get(identity_token)
    response = RemoteVirtualMachineConfigResponse(
        success=False,
        endpoint=record.endpoint,
        scope=record.scope,
        uuid=record.uuid,
        name=record.name,
        memory_mib=memory_mib if isinstance(memory_mib, int) and not isinstance(memory_mib, bool) else None,
        vcpus=vcpus if isinstance(vcpus, int) and not isinstance(vcpus, bool) else None,
        previous_max_memory_mib=target.previous_max_memory_mib if target else None,
        previous_current_memory_mib=target.previous_current_memory_mib if target else None,
        previous_vcpus=target.previous_vcpus if target else None,
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
            or record.action != "config:resources"
            or record.confirmation_token != target.confirmation_phrase
            or target.endpoint != record.endpoint
            or target.scope != record.scope
            or target.uuid != record.uuid
            or target.name != record.name
            or target.domain_state != "shut off"
            or target.domain_id is not None
            or target.memory_mib != memory_mib
            or target.vcpus != vcpus
            or not isinstance(confirmation_phrase, str)
            or not hmac.compare_digest(target.confirmation_phrase, confirmation_phrase)
        ):
            return response.model_copy(update={"message": "Confirmation did not match the exact remote VM, requested resources, or current-state phrase; no command was run."})

        with _LOCK:
            _TARGETS.pop(identity_token, None)
        current, error = _lookup_current(record)
        if error or current is None or current.state != "shut off" or current.domain_id is not None:
            return response.model_copy(update={"message": error or "The remote VM state changed after confirmation; list it again and confirm again."})
        root, raw, maximum, current_memory, current_vcpus, error = _read_target_xml(record)
        if error or root is None or raw is None or maximum is None or current_memory is None or current_vcpus is None:
            return response.model_copy(update={"message": error or "The remote VM definition could not be revalidated."})
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), target.xml_digest):
            return response.model_copy(update={"message": "The remote VM definition changed after confirmation; inspect it and confirm again."})

        memory = root.find("memory")
        current_element = root.find("currentMemory")
        vcpu_element = root.find("vcpu")
        if memory is None or current_element is None or vcpu_element is None:
            return response.model_copy(update={"message": "The remote VM definition no longer contains the selected resource fields."})
        _set_memory(memory, target.memory_mib)
        _set_memory(current_element, target.memory_mib)
        vcpu_element.text = str(target.vcpus)
        if "current" in vcpu_element.attrib:
            vcpu_element.set("current", str(target.vcpus))
        xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        if len(xml) > MAX_XML_BYTES:
            return response.model_copy(update={"message": "The updated remote VM definition exceeded its size limit; no command was run."})

        define_error: str | None = None
        output: str | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="linux-mcp-remote-vm-config-", dir="/tmp") as temp_dir:
                os.chmod(temp_dir, 0o700)
                xml_path = _write_xml(xml, temp_dir)
                if xml_path is None:
                    return response.model_copy(update={"message": "A private temporary VM definition could not be written; no command was run."})
                output, define_error, truncated = _run_remote_virsh(
                    target.endpoint,
                    ["define", "--validate", xml_path],
                    readonly=False,
                    timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                    max_output_bytes=MAX_VIRSH_OUTPUT_BYTES,
                    command_label="remote libvirt VM resource configuration",
                )
                if truncated:
                    define_error = define_error or "Remote virsh output exceeded its configured limit."
        except OSError:
            define_error = "A private temporary directory could not be created."

        after, state_error = _lookup_current(record)
        verified_root = None
        verify_error = None
        if after is not None and after.state == "shut off" and after.domain_id is None:
            verified_root, _verified_xml, verify_error = _read_xml(
                target.endpoint,
                target.uuid,
                command="dumpxml",
                inactive=True,
                label="remote VM resource-configuration verification",
            )
        verified = (
            after is not None
            and after.uuid == target.uuid
            and after.name == target.name
            and after.state == "shut off"
            and after.domain_id is None
            and verified_root is not None
            and _configuration_matches(verified_root, target)
        )
        if not verified:
            detail = define_error or state_error or verify_error or "the saved resource values or shut-off state did not match"
            return response.model_copy(update={"message": f"Remote VM configuration was attempted but could not be verified ({detail[:300]}). Inspect the VM before retrying."})
        if define_error or output is None:
            return response.model_copy(update={"success": False, "state_verified": True, "message": "The saved remote VM resource values match the request, but virsh reported an uncertain result. Inspect the VM before retrying."})
        return response.model_copy(update={"success": True, "state_verified": True, "message": "The shut-off remote VM's persistent memory and vCPU configuration was updated and verified; the guest was not started."})
    finally:
        with _LOCK:
            _TARGETS.pop(identity_token, None)
        with _TOKEN_LOCK:
            _TOKENS.pop(identity_token, None)
