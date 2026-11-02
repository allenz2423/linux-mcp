"""Session detection and honest, per-capability readiness reporting."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import shutil
import signal
import sys
from pathlib import Path

from wayland_mcp.backends.registry import detect_backend, detect_session_info
from wayland_mcp.models import CapabilitiesResponse, PerCapabilityStatus
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.host import _detect_init_system
from wayland_mcp.tools.packages import detect_package_manager, package_inventory_available
from wayland_mcp.tools.package_control import package_control_readiness
from wayland_mcp.tools.application_packages import detect_application_package_tools
from wayland_mcp.tools.application_package_control import flatpak_package_control_available
from wayland_mcp.tools.snap_package_control import snap_package_control_available
from wayland_mcp.tools.nix_profile_control import nix_profile_control_available
from wayland_mcp.tools.python_environments import python_environment_readiness
from wayland_mcp.tools.native_package_environments import native_package_environment_readiness
from wayland_mcp.tools.firewall import detect_firewall_tools
from wayland_mcp.tools.firewall_frontends import detect_firewall_frontends
from wayland_mcp.tools.containers import container_runtime_readiness
from wayland_mcp.tools.block_health import smartctl_available
from wayland_mcp.tools.system_logs import system_log_source_readiness
from wayland_mcp.tools.hardware import firmware_identity_available
from wayland_mcp.tools.services import runit_service_directories_available
from wayland_mcp.tools.security import kernel_security_posture_available
from wayland_mcp.tools.audit import audit_rule_control_available, linux_audit_tools_available
from wayland_mcp.tools.apparmor import apparmor_profiles_available
from wayland_mcp.tools.apparmor_control import apparmor_profile_control_available
from wayland_mcp.tools.selinux_booleans import (
    selinux_boolean_control_available,
    selinux_booleans_available,
)
from wayland_mcp.tools.selinux_context import (
    selinux_context_control_available,
    selinux_fcontext_rule_control_available,
)
from wayland_mcp.tools.ima import ima_measurements_available
from wayland_mcp.tools.ima_policy import ima_policy_available
from wayland_mcp.tools.tpm_event_log import tpm_event_log_available
from wayland_mcp.tools.tpm_attestation import tpm_attestation_available
from wayland_mcp.tools.numa import SYS_NODE_ROOT
from wayland_mcp.tools.systemd_network_profiles import NETWORK_CONFIG_ROOTS
from wayland_mcp.tools.systemd_network_profile_control import systemd_network_profile_control_available
from wayland_mcp.tools.fstab import fstab_inventory_available
from wayland_mcp.tools.crypttab import crypttab_inventory_available
from wayland_mcp.tools.storage import lvm_inventory_available
from wayland_mcp.tools.lvm_control import lvm_group_control_available, lvm_volume_control_available
from wayland_mcp.tools.luks_control import luks_control_available
from wayland_mcp.tools.ext4_control import ext4_control_available
from wayland_mcp.tools.xfs_control import xfs_control_available
from wayland_mcp.tools.raid_control import md_raid_control_available
from wayland_mcp.tools.btrfs_snapshots import btrfs_snapshot_tools_available
from wayland_mcp.tools.btrfs_control import btrfs_filesystem_control_available
from wayland_mcp.tools.kernel_control import kernel_module_control_available
from wayland_mcp.tools.kernel_module_startup import kernel_module_startup_control_available
from wayland_mcp.tools.kernel_parameters import kernel_parameter_control_available
from wayland_mcp.tools.kernel_parameter_persistence import persistent_kernel_parameter_control_available
from wayland_mcp.tools.kernel_command_line import kernel_command_line_control_available
from wayland_mcp.tools.initramfs_control import initramfs_rebuild_available
from wayland_mcp.tools.accounts_control import local_identity_control_available
from wayland_mcp.tools.cron_control import cron_control_available
from wayland_mcp.tools.mount_control import mount_control_available
from wayland_mcp.tools.openrc_startup import openrc_startup_control_available
from wayland_mcp.tools.runit_startup import runit_startup_control_available
from wayland_mcp.tools.s6_startup import s6_startup_set_available
from wayland_mcp.tools.printer_control import printer_control_available
from wayland_mcp.tools.time_settings import timedatectl_available
from wayland_mcp.tools.time_sync import time_sync_status_available
from wayland_mcp.tools.dns_configuration import dns_configuration_available
from wayland_mcp.tools.virtual_machines import virsh_available
from wayland_mcp.tools.remote_virtual_machines import remote_virsh_available
from wayland_mcp.tools.radios import radio_inventory_available, rfkill_available
from wayland_mcp.tools.bluetooth import bluetooth_tools_available
from wayland_mcp.tools.container_pods import container_pod_readiness
from wayland_mcp.tools.container_build import container_image_build_readiness
from wayland_mcp.tools.local_passwords import local_password_control_available
from wayland_mcp.tools.local_ssh_keys import local_ssh_key_control_available
from wayland_mcp.tools.sudo_policy import sudo_policy_control_available
from wayland_mcp.tools.sssd_config import sssd_domain_inventory_available, sssd_domain_control_available
from wayland_mcp.tools.pam_profiles import pam_profile_inventory_available, pam_profile_control_available
from wayland_mcp.tools.network_manager_virtual_profiles import network_manager_virtual_profile_control_available
from wayland_mcp.tools.backlight import backlight_control_available
from wayland_mcp.tools.systemd_timer_definition import systemd_timer_definition_control_available
from wayland_mcp.tools.systemd_service_definition import systemd_service_definition_control_available
from wayland_mcp.tools.at_control import at_control_available

CAPABILITIES = (
    "linux_system_info", "command_execution", "terminal_sessions", "resource_usage", "pressure_stall_info", "resource_history", "process_history", "cgroup_history", "process_execution_context", "namespace_inventory", "container_inventory", "container_control", "container_create", "container_image_inventory", "container_image_control", "container_image_build", "container_resource_inventory", "container_resource_control", "container_pod_inventory", "container_pod_control", "virtual_machine_inventory", "virtual_machine_control", "virtual_machine_configuration", "remote_virtual_machine_inventory", "remote_virtual_machine_control", "remote_virtual_machine_snapshot_inventory", "remote_virtual_machine_snapshot_control", "remote_virtual_machine_disk_attachment", "remote_virtual_machine_creation", "remote_virtual_machine_configuration", "remote_libvirt_network_inventory", "remote_libvirt_storage_inventory", "remote_libvirt_resource_control", "virtual_machine_creation", "virtual_machine_disk_attachment", "virtual_machine_snapshot_inventory", "virtual_machine_snapshot_control", "virtual_network_inventory", "virtual_network_creation", "virtual_network_ipv4_control", "virtualization_storage_inventory", "libvirt_resource_control", "libvirt_volume_creation", "cpu_inventory", "numa_inventory", "gpu_inventory", "gpu_power_limit_inventory", "gpu_power_limit_control", "powercap_limit_inventory", "powercap_limit_control", "gpu_frequency_limit_inventory", "gpu_frequency_limit_control", "fan_control_inventory", "fan_control", "process_list", "process_detail", "process_tree", "process_control", "filesystem_list", "filesystem_access", "filesystem_write", "filesystem_permissions", "block_devices", "storage_topology", "lvm_inventory", "lvm_control", "lvm_group_control", "luks_control", "luks_token_inventory", "luks_token_control", "luks_header_control", "ext4_control", "xfs_control", "btrfs_filesystem_control", "md_raid_control", "btrfs_snapshot_inventory", "btrfs_snapshot_control", "block_device_stats", "block_device_health", "hardware_devices", "udev_inventory", "sensor_readings", "display_backlight_inventory", "display_brightness_control", "audio_inventory", "audio_server_inventory", "audio_server_control", "power_supply_inventory", "power_state", "power_inhibitor_inventory", "power_control", "power_profile_inventory", "power_profile_control", "printer_inventory", "printer_control", "kernel_modules", "kernel_module_control", "kernel_module_startup_control", "kernel_parameter_inventory", "kernel_parameter_control", "kernel_parameter_persistence", "kernel_command_line_control", "initramfs_control", "kernel_security_posture", "linux_audit", "linux_audit_rule_control", "apparmor_profiles", "apparmor_profile_control", "selinux_booleans", "selinux_boolean_control", "selinux_context_control", "selinux_fcontext_rule_control", "ima_measurements", "ima_policy", "tpm_inventory", "tpm_event_log", "tpm_attestation",
    "network_interfaces", "radio_inventory", "radio_control", "bluetooth_device_inventory", "bluetooth_pairing", "network_control", "network_addresses", "dns_configuration", "network_routes", "network_policy", "network_route_lookup", "route_control", "network_manager_profiles", "network_manager_profile_dns", "network_manager_profile_dns_control", "network_manager_profile_ip", "network_manager_profile_ip_control", "network_manager_profile_routes", "network_manager_profile_route_control", "network_manager_virtual_profile_control", "network_manager_vpn_import", "network_manager_control", "systemd_network_profiles", "systemd_network_profile_control", "firewall_rules", "firewall_control", "firewall_frontend_inventory", "firewalld_port_control", "firewalld_icmp_block_control", "firewalld_service_control", "firewalld_rich_rule_control", "ufw_port_control", "network_sockets", "network_unix_raw_sockets", "network_socket_owners", "network_protocol_stats", "service_inventory", "service_control", "openrc_service_startup", "runit_service_startup", "s6_service_startup", "systemd_timers", "systemd_timer_control", "systemd_timer_definition_control", "systemd_service_definition_control", "cron_inventory", "cron_control", "at_control", "fstab_inventory", "crypttab_inventory", "mount_control", "boot_target_inventory", "boot_target_control", "time_settings", "time_control", "time_sync_status", "session_inventory", "journal_inventory", "system_log_inventory", "local_users", "local_groups", "nss_identity_lookup", "local_identity_control", "local_password_control", "local_ssh_key_control", "sudo_policy_control", "sssd_domain_inventory", "sssd_domain_control", "pam_profile_inventory", "pam_profile_control", "package_inventory", "package_control", "application_package_inventory", "application_package_control", "nix_profile_history_inventory", "nix_profile_history_control", "python_environment_inventory", "python_environment_control", "native_package_environment_inventory", "native_package_environment_control",
    "window_list", "window_detail", "window_focus", "window_close", "window_resize",
    "window_minimize", "window_maximize", "workspace_list", "output_list", "workspace_switch",
    "window_move_workspace", "screenshot", "input_pointer", "input_keyboard", "input_touch",
    "app_discovery", "app_launch", "clipboard_read", "clipboard_write",
    "notifications", "accessibility",
)

LEGACY_NAMES = {
    "window_move": "window_move_workspace",
    "bounded_input": "input_pointer",
}


def _status_from(value, name: str) -> PerCapabilityStatus:
    if isinstance(value, PerCapabilityStatus):
        status = value.model_copy()
    else:
        available = bool(value)
        status = PerCapabilityStatus(
            supported=available,
            available=available,
            state="ready" if available else "not_supported",
            reason=None if available else "Not implemented for this compositor backend.",
        )
    if status.available and status.state != "partial":
        status.state = "ready"
        status.reason = None
    elif status.supported:
        if status.required_permission:
            status.state = "permission_required"
        elif status.required_dependency:
            status.state = "dependency_missing"
        elif status.state == "not_supported":
            status.state = "partial"
    else:
        status.state = "not_supported"
        if not status.reason:
            status.reason = "Not implemented for this compositor backend."
    return status


def _session_bus_available(env: dict[str, str]) -> bool:
    if env.get("DBUS_SESSION_BUS_ADDRESS"):
        return True
    runtime_dir = env.get("XDG_RUNTIME_DIR")
    return bool(runtime_dir and (Path(runtime_dir) / "bus").is_socket())


def _portal_prerequisites(env: dict[str, str], session) -> tuple[bool, str | None]:
    if not session.is_wayland or not env.get("WAYLAND_DISPLAY"):
        return False, "An active Wayland display is unavailable."
    if not _session_bus_available(env):
        return False, "The user's session D-Bus is unavailable."
    if importlib.util.find_spec("dbus_next") is None:
        return False, "The dbus-next package is unavailable."
    return True, None


def _desktop_paths(env: dict[str, str]) -> list[Path]:
    home = Path(env.get("HOME") or str(Path.home()))
    data_home = Path(env.get("XDG_DATA_HOME") or (home / ".local/share"))
    data_dirs = env.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share")
    return [data_home / "applications", *(Path(item) / "applications" for item in data_dirs.split(":") if item)]


def get_session_capabilities() -> CapabilitiesResponse:
    env = get_sanitized_env()
    session = detect_session_info(env)
    backend = detect_backend(env)
    raw = backend.get_capabilities()
    raw_map: dict[str, object] = {}
    if isinstance(raw, dict):
        raw_map.update(raw)
    elif hasattr(raw, "model_dump"):
        raw_map.update(raw.model_dump(exclude={"unsupported_operations"}))
    for old_name, new_name in LEGACY_NAMES.items():
        if old_name in raw_map and new_name not in raw_map:
            raw_map[new_name] = raw_map[old_name]

    statuses: dict[str, PerCapabilityStatus] = {
        name: _status_from(raw_map.get(name, False), name) for name in CAPABILITIES
    }

    # Host inspection is independent of the active desktop and uses only Linux
    # kernel interfaces; no helper process or elevated permission is required.
    is_linux = sys.platform.startswith("linux")
    proc_available = is_linux and Path("/proc").is_dir()
    host_capabilities = {
        "linux_system_info": (is_linux, "Linux distribution and kernel information is unavailable on this host."),
        "resource_usage": (is_linux and (Path("/proc/meminfo").is_file() or Path("/proc/loadavg").is_file()), "Linux procfs memory and load data are unavailable."),
        "process_list": (proc_available, "Linux procfs is unavailable."),
        "process_detail": (proc_available, "Linux procfs is unavailable."),
        "process_tree": (proc_available, "Linux procfs is unavailable."),
        "filesystem_list": (is_linux and Path("/proc/self/mounts").is_file(), "Linux procfs mount information is unavailable."),
    }
    for name, (available, reason) in host_capabilities.items():
        statuses[name] = PerCapabilityStatus(
            supported=is_linux,
            available=available,
            state="ready" if available else ("dependency_missing" if is_linux else "not_supported"),
            reason=None if available else reason,
            required_dependency="Linux procfs" if is_linux and not available else None,
        )
    shell_available = is_linux and Path("/bin/sh").is_file() and os.access("/bin/sh", os.X_OK)
    root_execution_available = is_linux and (
        os.geteuid() == 0 or shutil.which("sudo", path=os.defpath) is not None
    )
    statuses["command_execution"] = PerCapabilityStatus(
        supported=is_linux,
        available=shell_available,
        state="partial" if shell_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Arbitrary /bin/sh commands are available after exact-request MCP confirmation and run with the server's OS permissions; "
            + (
                "root mode can use this already-root server or sudo, subject to sudoers policy."
                if root_execution_available
                else "root mode is unavailable because the server is unprivileged and sudo is not installed."
            )
            if shell_available else "The standard Linux /bin/sh executable is unavailable."
        ),
        required_dependency="/bin/sh" if is_linux and not shell_available else None,
    )
    terminal_sessions_available = shell_available and Path("/dev/ptmx").exists()
    statuses["terminal_sessions"] = PerCapabilityStatus(
        supported=is_linux,
        available=terminal_sessions_available,
        state="partial" if terminal_sessions_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Interactive PTY sessions are available after confirmation and are limited by session count, lifetime, and retained-output bounds."
            if terminal_sessions_available else "A Linux PTY multiplexer at /dev/ptmx is unavailable."
        ),
        required_dependency="Linux devpts PTY support at /dev/ptmx" if is_linux and not terminal_sessions_available else None,
    )
    pressure_available = is_linux and Path("/proc/pressure").is_dir()
    statuses["pressure_stall_info"] = PerCapabilityStatus(
        supported=is_linux,
        available=pressure_available,
        state="partial" if pressure_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "System-wide CPU, memory, and I/O PSI snapshots are read from fixed procfs files; availability varies by kernel configuration."
            if pressure_available else "Linux procfs Pressure Stall Information is unavailable."
        ),
        required_dependency="kernel PSI interface at /proc/pressure" if is_linux and not pressure_available else None,
    )
    process_control_available = (
        proc_available
        and callable(getattr(os, "kill", None))
        and callable(getattr(signal, "valid_signals", None))
    )
    statuses["process_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=process_control_available,
        state=("partial" if process_control_available else ("dependency_missing" if is_linux else "not_supported")),
        reason=(
            "Named process signals are available after exact process-instance observation and client confirmation; OS permissions vary by target, and pidfds are used where supported."
            if process_control_available else "Linux procfs or symbolic signal APIs are unavailable."
        ),
        required_dependency="Linux procfs and Python signal APIs" if is_linux and not process_control_available else None,
    )
    resource_history_available = is_linux and Path("/proc/stat").is_file()
    statuses["resource_history"] = PerCapabilityStatus(
        supported=is_linux,
        available=resource_history_available,
        state="partial" if resource_history_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded CPU, memory, swap, load, and uptime sampling is available; selected-PID history has a separate capability and device-specific telemetry is not included."
            if resource_history_available else "Linux /proc/stat CPU counters are unavailable."
        ),
        required_dependency="Linux /proc/stat" if is_linux and not resource_history_available else None,
    )
    process_history_available = is_linux and Path("/proc").is_dir()
    statuses["process_history"] = PerCapabilityStatus(
        supported=is_linux,
        available=process_history_available,
        state="partial" if process_history_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded CPU-time, resident/virtual-memory, thread-count, and storage-layer read/write history is available for explicit PIDs; procfs permissions may limit I/O counters and process identity is checked between samples."
            if process_history_available else "Linux procfs process status is unavailable."
        ),
        required_dependency="Linux /proc/PID/stat and /proc/PID/status" if is_linux and not process_history_available else None,
    )
    cgroup_history_available = is_linux and Path("/sys/fs/cgroup/cgroup.controllers").is_file()
    statuses["cgroup_history"] = PerCapabilityStatus(
        supported=is_linux,
        available=cgroup_history_available,
        state="partial" if cgroup_history_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Cgroup-v2 CPU, memory, swap, and PID snapshots can be sampled for explicit PIDs when the hierarchy and matching cgroup namespace are visible."
            if cgroup_history_available else "A unified cgroup-v2 hierarchy is not visible at /sys/fs/cgroup."
        ),
        required_dependency="Cgroup v2 mounted at /sys/fs/cgroup" if is_linux and not cgroup_history_available else None,
    )
    process_context_available = is_linux and Path("/proc/self/stat").is_file()
    statuses["process_execution_context"] = PerCapabilityStatus(
        supported=is_linux,
        available=process_context_available,
        state="partial" if process_context_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Explicit-PID scheduler, affinity, cgroup, namespace, seccomp, and capability metadata are available from procfs; cgroup-v2 limits and counters are included only when the path is safely visible in the same cgroup namespace."
            if process_context_available else "Linux procfs process stat data is unavailable."
        ),
        required_dependency="Linux /proc/PID/stat" if is_linux and not process_context_available else None,
    )
    namespace_inventory_available = is_linux and Path("/proc/self/ns").is_dir()
    statuses["namespace_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=namespace_inventory_available,
        state="partial" if namespace_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Namespace inode references can be grouped for stable process entries visible through procfs; kernel namespace types and process visibility vary."
            if namespace_inventory_available else "Linux procfs namespace links are unavailable."
        ),
        required_dependency="Linux /proc/PID/ns entries" if is_linux and not namespace_inventory_available else None,
    )
    (
        container_inventory_found,
        container_inventory_access,
        container_control_found,
        container_control_access,
    ) = container_runtime_readiness() if is_linux else (False, False, False, False)
    for capability in ("container_inventory", "container_control"):
        inventory_capability = capability == "container_inventory"
        runtime_found = container_inventory_found if inventory_capability else container_control_found
        runtime_access = container_inventory_access if inventory_capability else container_control_access
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=runtime_access,
            state=(
                "partial" if runtime_access
                else "permission_required" if runtime_found and is_linux
                else "dependency_missing" if is_linux
                else "not_supported"
            ),
            reason=(
                "Docker/Podman containers are inventoried from local engine sockets or forced-local Podman CLI; when crictl and standard local CRI sockets are available, containerd/CRI-O inventory is also exposed read-only."
                if inventory_capability and runtime_access
                else "Docker/Podman container inventory and confirmation-gated lifecycle actions use accessible local sockets or a forced-local Podman CLI; engine APIs and permissions vary."
                if not inventory_capability and runtime_access
                else "A supported local container runtime is present, but its API socket is not accessible to the current user."
                if runtime_found and is_linux
                else "No standard local Docker/Podman endpoint or crictl-accessible containerd/CRI-O socket was found."
                if inventory_capability and is_linux
                else "No local Docker/Podman action runtime endpoint or Podman CLI was found."
                if is_linux
                else "Container runtime APIs are available only on Linux."
            ),
            required_dependency=(
                "Local Docker/Podman endpoint or crictl plus standard containerd/CRI-O socket"
                if inventory_capability and is_linux and not runtime_found
                else "Local Docker/Podman API socket or Podman executable"
                if not inventory_capability and is_linux and not runtime_found
                else None
            ),
            required_permission=(
                "Current-user access to the selected local container runtime socket"
                if is_linux and runtime_found and not runtime_access else None
            ),
        )
    container_engine_available = container_control_access
    statuses["container_create"] = PerCapabilityStatus(
        supported=is_linux,
        available=container_engine_available,
        state=("partial" if container_engine_available else "permission_required" if container_control_found and is_linux else "dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed creation of stopped containers from exact locally present Docker/Podman images is available; creation uses runtime defaults and does not pull, build, publish ports, mount host paths, or start the workload."
            if container_engine_available
            else "An accessible local Docker/Podman engine or forced-local Podman CLI is required for container creation."
        ),
        required_dependency="accessible Docker/Podman local endpoint or Podman CLI" if is_linux and not container_engine_available else None,
        required_permission="Current-user access to a local Docker/Podman engine" if is_linux and container_control_found and not container_engine_available else None,
    )
    statuses["container_image_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=container_engine_available,
        state=("partial" if container_engine_available else "permission_required" if container_control_found and is_linux else "dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded local image ID and tag inventory is available from Docker/Podman endpoints."
            if container_engine_available
            else "An accessible local Docker/Podman engine or forced-local Podman CLI is required for image inventory."
        ),
        required_dependency="accessible Docker/Podman local endpoint or Podman CLI" if is_linux and not container_engine_available else None,
        required_permission="Current-user access to a local Docker/Podman engine" if is_linux and container_control_found and not container_engine_available else None,
    )
    statuses["container_image_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=container_engine_available,
        state=("partial" if container_engine_available else "permission_required" if container_control_found and is_linux else "dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed local image pull, tag, and non-forced exact-tag removal are available for Docker/Podman endpoints."
            if container_engine_available
            else "An accessible local Docker/Podman engine or forced-local Podman CLI is required for image control."
        ),
        required_dependency="accessible Docker/Podman local endpoint or Podman CLI" if is_linux and not container_engine_available else None,
        required_permission="Current-user access to a local Docker/Podman engine" if is_linux and container_control_found and not container_engine_available else None,
    )
    build_found, build_access = container_image_build_readiness() if is_linux else (False, False)
    statuses["container_image_build"] = PerCapabilityStatus(
        supported=is_linux,
        available=build_access,
        state=("partial" if build_access else "permission_required" if build_found and is_linux else "dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed bounded local-context image builds are available through writable local Docker API sockets or a local Podman CLI."
            if build_access
            else "A writable local Docker API socket or local Podman CLI is required for image builds."
        ),
        required_dependency="writable local Docker API socket or Podman executable" if is_linux and not build_found else None,
        required_permission="Current-user access to the Docker API socket" if is_linux and build_found and not build_access else None,
    )
    for capability in ("container_resource_inventory", "container_resource_control"):
        inventory_capability = capability == "container_resource_inventory"
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=container_engine_available,
            state=("partial" if container_engine_available else "permission_required" if container_control_found and is_linux else "dependency_missing" if is_linux else "not_supported"),
            reason=(
                "Bounded local Docker/Podman named-volume and network inventory is available; mount paths and network configuration are omitted."
                if inventory_capability and container_engine_available
                else "Confirmed creation of default local volumes/bridge networks and non-forced removal of exact unused resources is available."
                if container_engine_available
                else "An accessible local Docker/Podman engine or forced-local Podman CLI is required for container resource access."
            ),
            required_dependency="accessible Docker/Podman local endpoint or Podman CLI" if is_linux and not container_engine_available else None,
            required_permission="Current-user access to a local Docker/Podman engine" if is_linux and container_control_found and not container_engine_available else None,
        )
    podman_found, podman_access = container_pod_readiness() if is_linux else (False, False)
    for capability in ("container_pod_inventory", "container_pod_control"):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=podman_access,
            state=("partial" if podman_access else "dependency_missing" if is_linux else "not_supported"),
            reason=(
                "Bounded current-scope Podman pod inventory and confirmed create/start/stop/empty-pod removal are available through a forced-local Podman CLI."
                if podman_access
                else "A local Podman executable is required for pod inventory and control."
                if is_linux
                else "Podman pod tools are available only on Linux."
            ),
            required_dependency="local Podman executable" if is_linux and not podman_found else None,
        )
    virsh_ready = virsh_available(env) if is_linux else False
    for capability in (
        "virtual_machine_inventory",
        "virtual_machine_control",
        "virtual_machine_configuration",
        "virtual_machine_creation",
        "virtual_machine_disk_attachment",
        "virtual_machine_snapshot_inventory",
        "virtual_machine_snapshot_control",
    ):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=virsh_ready,
            state="partial" if virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
            reason=(
                "Local QEMU/libvirt system and user-session domain inventory, confirmed lifecycle actions, shut-off VM persistent memory/current-memory/vCPU configuration, creation of a stopped VM with a new sparse qcow2 disk and optional existing network, persistent attachment of an existing raw/qcow2 volume to a shut-off VM, bounded snapshot inventory, and confirmed snapshot create/revert/leaf-delete actions are available through fixed qemu:///system and qemu:///session URIs; VM configuration and disk changes require shut-off guests, disk operations use persistent running directory pools, snapshot creation is limited to shut-off VMs, and daemon connectivity and per-URI authorization are checked on each call."
                if virsh_ready
                else "The optional virsh command is unavailable."
                if is_linux
                else "Libvirt VM tools are available only on Linux."
            ),
            required_dependency="virsh from libvirt clients" if is_linux and not virsh_ready else None,
        )
    remote_virsh_ready = remote_virsh_available(env) if is_linux else False
    remote_dependency = None
    if is_linux and not remote_virsh_ready:
        remote_dependency = "virsh and OpenSSH client executables"
    for capability in ("remote_virtual_machine_inventory", "remote_virtual_machine_control"):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=remote_virsh_ready,
            state="partial" if remote_virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
            reason=(
                "Constrained remote QEMU/libvirt inventory and confirmed lifecycle actions are available through qemu+ssh URIs ending in /system or /session. SSH config and agent forwarding are disabled, password prompts and unknown host keys are refused, and each call rechecks the exact remote endpoint and domain state."
                if remote_virsh_ready
                else "The optional virsh and OpenSSH client commands are required for remote qemu+ssh connections."
                if is_linux
                else "Remote libvirt VM tools are available only on Linux."
            ),
            required_dependency=remote_dependency,
        )
    for capability in ("remote_virtual_machine_disk_attachment",):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=remote_virsh_ready,
            state="partial" if remote_virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
            reason=(
                "A shut-off remote VM can receive one existing raw/qcow2 volume from an active persistent directory pool in an unused virtio slot after full bounded VM, pool, volume, and disk-reference revalidation."
                if remote_virsh_ready
                else "The optional virsh and OpenSSH client commands are required for remote qemu+ssh connections."
                if is_linux
                else "Remote libvirt VM tools are available only on Linux."
            ),
            required_dependency=remote_dependency,
        )
    statuses["remote_virtual_machine_creation"] = PerCapabilityStatus(
        supported=is_linux,
        available=remote_virsh_ready,
        state="partial" if remote_virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed remote definition of one stopped QEMU/libvirt VM with bounded memory/vCPU, a newly created sparse qcow2 disk in an active persistent directory pool, and an optional existing persistent network is available over validated qemu+ssh endpoints; the generated XML is validated and the saved configuration is checked afterward."
            if remote_virsh_ready
            else "The optional virsh and OpenSSH client commands are required for remote qemu+ssh connections."
            if is_linux
            else "Remote libvirt VM creation is available only on Linux."
        ),
        required_dependency=remote_dependency,
    )
    statuses["remote_virtual_machine_configuration"] = PerCapabilityStatus(
        supported=is_linux,
        available=remote_virsh_ready,
        state="partial" if remote_virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "A shut-off remote VM's persistent memory/current-memory and vCPU settings can be changed with exact state and full-definition revalidation; the verified update redefines only the saved configuration and does not start the guest."
            if remote_virsh_ready
            else "The optional virsh and OpenSSH client commands are required for remote qemu+ssh connections."
            if is_linux
            else "Remote libvirt VM configuration is available only on Linux."
        ),
        required_dependency=remote_dependency,
    )
    for capability in (
        "remote_virtual_machine_snapshot_inventory",
        "remote_virtual_machine_snapshot_control",
    ):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=remote_virsh_ready,
            state="partial" if remote_virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
            reason=(
                "Bounded remote QEMU/libvirt snapshot inventory and confirmed disk-only creation for shut-off VMs, exact snapshot reversion, and leaf-only deletion are available over the validated qemu+ssh endpoint. The full snapshot inventory and selected metadata are rechecked before dispatch, and the requested result is verified afterward."
                if remote_virsh_ready
                else "The optional virsh and OpenSSH client commands are required for remote qemu+ssh connections."
                if is_linux
                else "Remote libvirt snapshot tools are available only on Linux."
            ),
            required_dependency=remote_dependency,
        )
    for capability, available_reason in (
        (
            "remote_libvirt_network_inventory",
            "Bounded remote virtual-network inventory is available through validated qemu+ssh endpoints; XML, bridge names, addresses, DHCP data, and ports are omitted.",
        ),
        (
            "remote_libvirt_storage_inventory",
            "Bounded remote storage-pool and selected volume inventory is available through validated qemu+ssh endpoints; storage paths, volume keys, and XML are omitted.",
        ),
        (
            "remote_libvirt_resource_control",
            "Confirmed remote network and storage-pool start/stop/autostart actions are available with UUID/state revalidation and post-action verification.",
        ),
    ):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=remote_virsh_ready,
            state="partial" if remote_virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
            reason=(
                available_reason
                if remote_virsh_ready
                else "The optional virsh and OpenSSH client commands are required for remote qemu+ssh connections."
                if is_linux
                else "Remote libvirt resource tools are available only on Linux."
            ),
            required_dependency=remote_dependency,
        )
    for capability in ("virtual_network_inventory", "virtualization_storage_inventory"):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=virsh_ready,
            state="partial" if virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
            reason=(
                "Read-only local virtual-network and storage-pool inventory is available through fixed QEMU system/session URIs; volume details can be requested for one explicitly scoped storage pool, while daemon connectivity and per-URI authorization are checked on each call."
                if virsh_ready
                else "The optional virsh command is unavailable."
                if is_linux
                else "Libvirt resource inventory is available only on Linux."
            ),
            required_dependency="virsh from libvirt clients" if is_linux and not virsh_ready else None,
        )
    statuses["virtual_network_creation"] = PerCapabilityStatus(
        supported=is_linux,
        available=virsh_ready,
        state="partial" if virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed definition of persistent inactive isolated, NAT, routed, or existing-Linux-bridge libvirt networks is available; NAT/routed modes require iproute2 and reject IPv4 subnets overlapping current host routes or addresses, bridge mode does not create or manage its host bridge, and starting any network is a separate action."
            if virsh_ready
            else "The optional virsh command is unavailable."
            if is_linux
            else "Libvirt virtual-network creation is available only on Linux."
        ),
        required_dependency="virsh from libvirt clients" if is_linux and not virsh_ready else None,
    )
    statuses["virtual_network_ipv4_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=virsh_ready,
        state="partial" if virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed IPv4 bridge-address and DHCP-range updates are available for existing persistent inactive NAT/routed libvirt networks in the supported XML subset; the mode, bridge, UUID, and autostart state are preserved, subnets are checked against host routes and addresses, and other network modes remain unavailable."
            if virsh_ready
            else "The optional virsh command is unavailable."
            if is_linux
            else "Libvirt virtual-network configuration is available only on Linux."
        ),
        required_dependency="virsh from libvirt clients" if is_linux and not virsh_ready else None,
    )
    statuses["libvirt_resource_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=virsh_ready,
        state="partial" if virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact local virtual networks and storage pools support confirmed start/stop and persistent autostart changes with UUID/state revalidation; network stop is immediate, pool stop leaves data intact but may disrupt guests, and connection authorization is checked per request."
            if virsh_ready
            else "The optional virsh command is unavailable."
            if is_linux
            else "Libvirt resource control is available only on Linux."
        ),
        required_dependency="virsh from libvirt clients" if is_linux and not virsh_ready else None,
    )
    statuses["libvirt_volume_creation"] = PerCapabilityStatus(
        supported=is_linux,
        available=virsh_ready,
        state="partial" if virsh_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed raw/qcow2 creation of sparse volumes from 1 MiB through 1 TiB is available for persistent, running, directory-backed local libvirt pools, with pool UUID/state and name-availability revalidation; guest writes can overcommit pool storage."
            if virsh_ready
            else "The optional virsh command is unavailable."
            if is_linux
            else "Libvirt volume creation is available only on Linux."
        ),
        required_dependency="virsh from libvirt clients" if is_linux and not virsh_ready else None,
    )
    filesystem_access_available = is_linux and Path("/").is_dir() and os.access("/", os.R_OK | os.X_OK)
    statuses["filesystem_access"] = PerCapabilityStatus(
        supported=is_linux,
        available=filesystem_access_available,
        state="partial" if filesystem_access_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded metadata, directory listings, regular text reads, and visible extended attributes/POSIX ACLs are available for explicit absolute paths; these inspection tools do not mutate files."
            if filesystem_access_available else "The root filesystem is unavailable or unreadable."
        ),
        required_dependency="readable root filesystem" if is_linux and not filesystem_access_available else None,
    )
    filesystem_write_available = is_linux and all(
        hasattr(os, name) for name in ("open", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_DIRECTORY")
    )
    statuses["filesystem_write"] = PerCapabilityStatus(
        supported=is_linux,
        available=filesystem_write_available,
        state="partial" if filesystem_write_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed UTF-8 file creation/replacement/deletion and binary create/atomic-replace/append/deletion are available for exact absolute regular-file paths. Text payloads are capped at 64 KiB; binary writes are capped at 4 MiB per call and reads are paged up to 1 MiB. Binary deletion binds approval to the canonical path, parent identity, and current file metadata; it unlinks one path and is not secure erasure. Recursive directory creation/deletion, symlink creation/removal, numeric UID/GID ownership, general xattr changes, and POSIX access/default ACL changes are exposed through separate confirmed operations. Creation refuses existing paths; text replacement rechecks content digests, writes in place, preserves owner/mode/ACL and checked xattrs, and attempts rollback after write failures. Protected pseudo-filesystems and special files are excluded; append refuses hard-linked files, while unlinking one hard link leaves other names intact. Standard rwx mode changes are reported separately through filesystem_permissions."
            if filesystem_write_available else "Linux descriptor-relative filesystem mutation support is unavailable."
        ),
        required_dependency="Linux openat/O_EXCL/O_NOFOLLOW filesystem support" if is_linux and not filesystem_write_available else None,
    )
    filesystem_permissions_available = (
        is_linux
        and hasattr(os, "O_PATH")
        and hasattr(os, "chmod")
        and hasattr(os, "listxattr")
        and Path("/proc/self/fd").is_dir()
    )
    statuses["filesystem_permissions"] = PerCapabilityStatus(
        supported=is_linux,
        available=filesystem_permissions_available,
        state="partial" if filesystem_permissions_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed nonrecursive standard rwx-mode changes are available for exact regular files and directories. Special mode bits, symlinks, multiply linked files, visible protected security attributes, and pseudo-filesystem paths are excluded. Linux chmod also updates mode-corresponding access ACL entries and can change the ACL mask/effective permissions; ownership and direct ACL/xattr changes are available through separate confirmed tools."
            if filesystem_permissions_available else "Linux O_PATH, chmod, xattr inspection, or /proc/self/fd support is unavailable."
        ),
        required_dependency="Linux O_PATH, chmod, xattr inspection, and /proc/self/fd" if is_linux and not filesystem_permissions_available else None,
    )
    cpu_inventory_available = is_linux and (
        Path("/proc/cpuinfo").is_file() or Path("/sys/devices/system/cpu").is_dir()
    )
    statuses["cpu_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=cpu_inventory_available,
        state="partial" if cpu_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Logical CPU IDs and available topology/frequency attributes are exposed as a snapshot; utilization history and frequency controls are excluded."
            if cpu_inventory_available else "Linux CPU procfs and sysfs inventory are unavailable."
        ),
        required_dependency="Linux /proc/cpuinfo or CPU sysfs" if is_linux and not cpu_inventory_available else None,
    )
    numa_inventory_available = is_linux and SYS_NODE_ROOT.is_dir() and (SYS_NODE_ROOT / "online").is_file()
    statuses["numa_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=numa_inventory_available,
        state="partial" if numa_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "NUMA nodes, CPU membership, per-node memory, and distance snapshots are read from sysfs; individual fields depend on kernel and architecture support."
            if numa_inventory_available else "Linux NUMA node sysfs topology is unavailable."
        ),
        required_dependency="Linux NUMA node sysfs" if is_linux and not numa_inventory_available else None,
    )
    gpu_inventory_available = is_linux and Path("/sys/class/drm").is_dir()
    statuses["gpu_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=gpu_inventory_available,
        state="partial" if gpu_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "DRM card identity and driver metadata can be inventoried; AMDGPU busy-percent/VRAM, Intel i915/Xe hwmon temperature/energy, Xe actual per-GT frequency, Nouveau temperature, and optional NVIDIA utilization/memory/temperature/power are driver-specific snapshots. Unsupported metrics remain unavailable rather than inferred."
            if gpu_inventory_available else "Linux DRM sysfs inventory is unavailable."
        ),
        required_dependency="Linux DRM sysfs under /sys/class/drm" if is_linux and not gpu_inventory_available else None,
    )
    for capability, description in (
        ("gpu_power_limit_inventory", "Standard hwmon GPU power-cap channels are available only when exposed by a driver."),
        ("gpu_power_limit_control", "Confirmed power-cap changes require a writable standard hwmon attribute and OS permission."),
        ("gpu_frequency_limit_inventory", "Xe per-GT frequency limits are available only when the Intel Xe sysfs interface is exposed."),
        ("gpu_frequency_limit_control", "Confirmed Xe frequency changes require a writable freq0/max_freq attribute and OS permission."),
    ):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=gpu_inventory_available,
            state="partial" if gpu_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
            reason=description if gpu_inventory_available else "Linux DRM sysfs inventory is unavailable.",
            required_dependency="Linux DRM sysfs under /sys/class/drm" if is_linux and not gpu_inventory_available else None,
        )
    powercap_available = is_linux and Path("/sys/class/powercap").is_dir()
    for capability, description in (
        ("powercap_limit_inventory", "Power zones and constraints are read from the standard Linux powercap sysfs hierarchy."),
        ("powercap_limit_control", "Only constraints with valid driver-reported minimum and maximum power limits can be changed."),
    ):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=powercap_available,
            state="partial" if powercap_available else ("dependency_missing" if is_linux else "not_supported"),
            reason=description if powercap_available else "The Linux powercap sysfs hierarchy is unavailable.",
            required_dependency="Linux powercap sysfs under /sys/class/powercap" if is_linux and not powercap_available else None,
        )
    fan_inventory_available = is_linux and Path("/sys/class/hwmon").is_dir()
    for capability, description in (
        ("fan_control_inventory", "Standard hwmon PWM channels can be listed when the kernel exposes /sys/class/hwmon."),
        ("fan_control", "Confirmed maximum-speed or automatic-mode changes require a writable standard PWM attribute and OS permission."),
    ):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=fan_inventory_available,
            state="partial" if fan_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
            reason=description if fan_inventory_available else "Linux hwmon sysfs inventory is unavailable.",
            required_dependency="Linux hwmon sysfs under /sys/class/hwmon" if is_linux and not fan_inventory_available else None,
        )
    network_available = is_linux and Path("/sys/class/net").is_dir()
    iproute2_available = is_linux and bool(find_session_binary("ip", env))
    statuses["network_interfaces"] = PerCapabilityStatus(
        supported=is_linux,
        available=network_available,
        state="partial" if network_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Interface state, primary IPv4/IPv6 addresses, default gateways, and counters are available; full address enumeration has a separate iproute2 capability. Route and socket snapshots have separate capabilities."
            if network_available else "Linux network interface sysfs is unavailable."
        ),
        required_dependency="sysfs network interface data" if is_linux and not network_available else None,
    )
    rfkill_sysfs_available = radio_inventory_available() if is_linux else False
    statuses["radio_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=rfkill_sysfs_available,
        state="partial" if rfkill_sysfs_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Kernel rfkill devices expose bounded radio names, types, indexes, and separate soft/hard block states through fixed sysfs entries."
            if rfkill_sysfs_available
            else "Linux rfkill sysfs is unavailable or the kernel exposes no rfkill class."
            if is_linux
            else "Radio inventory is available only on Linux."
        ),
        required_dependency="Linux rfkill sysfs under /sys/class/rfkill" if is_linux and not rfkill_sysfs_available else None,
    )
    rfkill_control_ready = rfkill_sysfs_available and rfkill_available(env)
    statuses["radio_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=rfkill_control_ready,
        state="partial" if rfkill_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact per-device rfkill soft block/unblock actions are available after client confirmation; hard blocks cannot be overridden, and current OS permissions apply."
            if rfkill_control_ready
            else "The rfkill command or Linux rfkill sysfs is unavailable."
            if is_linux
            else "Radio controls are available only on Linux."
        ),
        required_dependency="rfkill command and Linux rfkill sysfs" if is_linux and not rfkill_control_ready else None,
    )
    bluetooth_ready = bluetooth_tools_available(env) if is_linux else False
    bluetooth_reason = (
        "The local BlueZ command and system D-Bus are available for cached-device inventory and confirmation-gated pairing."
        if bluetooth_ready
        else "bluetoothctl and an active system D-Bus socket are required for BlueZ device inventory and pairing."
        if is_linux
        else "Bluetooth inventory and pairing are available only on Linux."
    )
    for capability in ("bluetooth_device_inventory", "bluetooth_pairing"):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=bluetooth_ready,
            state="partial" if bluetooth_ready else ("dependency_missing" if is_linux else "not_supported"),
            reason=bluetooth_reason,
            required_dependency="bluetoothctl and system D-Bus" if is_linux and not bluetooth_ready else None,
        )
    nmcli_available = is_linux and bool(find_session_binary("nmcli", env))
    statuses["network_manager_profiles"] = PerCapabilityStatus(
        supported=is_linux,
        available=nmcli_available,
        state="partial" if nmcli_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "NetworkManager connection profiles can be inventoried with a fixed metadata field list; daemon availability is checked when queried and secret fields are not requested."
            if nmcli_available else "NetworkManager's nmcli command is unavailable."
        ),
        required_dependency="NetworkManager nmcli command" if is_linux and not nmcli_available else None,
    )
    statuses["network_manager_profile_dns"] = PerCapabilityStatus(
        supported=is_linux,
        available=nmcli_available,
        state="partial" if nmcli_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Allowlisted saved IPv4/IPv6 DNS properties can be read for one exact NetworkManager profile UUID; the daemon is checked per request and secret fields are not requested."
            if nmcli_available else "NetworkManager's nmcli command is unavailable."
        ),
        required_dependency="NetworkManager nmcli command" if is_linux and not nmcli_available else None,
    )
    statuses["network_manager_profile_dns_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=nmcli_available,
        state="partial" if nmcli_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "State-bound, confirmed persistent IPv4/IPv6 DNS server, search-domain, and automatic-DNS changes are available for one exact NetworkManager profile; the profile is not activated or reapplied."
            if nmcli_available else "NetworkManager's nmcli command is unavailable."
        ),
        required_dependency="NetworkManager nmcli command" if is_linux and not nmcli_available else None,
    )
    statuses["network_manager_profile_ip"] = PerCapabilityStatus(
        supported=is_linux,
        available=nmcli_available,
        state="partial" if nmcli_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "The saved IPv4/IPv6 method, address/prefix list, and gateway can be read for one exact NetworkManager profile UUID; secret fields are not requested."
            if nmcli_available else "NetworkManager's nmcli command is unavailable."
        ),
        required_dependency="NetworkManager nmcli command" if is_linux and not nmcli_available else None,
    )
    statuses["network_manager_profile_ip_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=nmcli_available,
        state="partial" if nmcli_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "State-bound, confirmed persistent IPv4/IPv6 automatic/manual method, address/prefix, and gateway changes are available for one exact saved profile; no activation or reapply is issued."
            if nmcli_available else "NetworkManager's nmcli command is unavailable."
        ),
        required_dependency="NetworkManager nmcli command" if is_linux and not nmcli_available else None,
    )
    statuses["network_manager_profile_routes"] = PerCapabilityStatus(
        supported=is_linux,
        available=nmcli_available,
        state="partial" if nmcli_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Saved IPv4/IPv6 route entries can be read for one exact NetworkManager profile; route attributes are reported and secret fields are not requested."
            if nmcli_available else "NetworkManager's nmcli command is unavailable."
        ),
        required_dependency="NetworkManager nmcli command" if is_linux and not nmcli_available else None,
    )
    statuses["network_manager_profile_route_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=nmcli_available,
        state="partial" if nmcli_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "State-bound, confirmed addition or removal of one simple persistent IPv4/IPv6 route is available for an exact saved profile; advanced attributes, replacement, duplicate destinations, activation, and reapply are not supported."
            if nmcli_available else "NetworkManager's nmcli command is unavailable."
        ),
        required_dependency="NetworkManager nmcli command" if is_linux and not nmcli_available else None,
    )
    virtual_profile_ready = is_linux and network_manager_virtual_profile_control_available()
    statuses["network_manager_virtual_profile_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=virtual_profile_ready,
        state="partial" if virtual_profile_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed creation of inactive persistent NetworkManager bridge, bond, and VLAN profiles plus inactive Ethernet port profiles attached to an exact bridge/bond UUID is available; inactive Ethernet profiles with autoconnect and IP disabled can also be attached to or detached from exact bridge/bond profiles. VPN setup and broader profile editing are separate capabilities."
            if virtual_profile_ready else "NetworkManager's nmcli command is unavailable."
        ),
        required_dependency="NetworkManager nmcli command" if is_linux and not virtual_profile_ready else None,
    )
    statuses["network_manager_vpn_import"] = PerCapabilityStatus(
        supported=is_linux,
        available=nmcli_available,
        state="partial" if nmcli_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed self-contained OpenVPN and bounded wg-quick WireGuard profile imports are available through NetworkManager; the OpenVPN plugin is checked when requested, and profile secrets are not queried."
            if nmcli_available else "NetworkManager's nmcli command is unavailable."
        ),
        required_dependency="NetworkManager nmcli command" if is_linux and not nmcli_available else None,
    )
    statuses["network_manager_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=nmcli_available,
        state="partial" if nmcli_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact UUID-bound NetworkManager profile activation/deactivation and persistent autoconnect changes are supported after explicit confirmation; authorization depends on the current account."
            if nmcli_available else "NetworkManager's nmcli command is unavailable."
        ),
        required_dependency="NetworkManager nmcli command" if is_linux and not nmcli_available else None,
    )
    systemd_profile_roots_available = is_linux and any(root.is_dir() for _source, root in NETWORK_CONFIG_ROOTS)
    statuses["systemd_network_profiles"] = PerCapabilityStatus(
        supported=is_linux,
        available=systemd_profile_roots_available,
        state="partial" if systemd_profile_roots_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Systemd .network, .netdev, and .link profile candidates can be read from fixed configuration roots with a strict metadata allowlist, including configured DNS, selected UseDNS/UseDNR flags, and UseDomains modes on .network candidates; files and drop-ins are not merged into an effective configuration."
            if systemd_profile_roots_available else "Systemd network configuration directories are unavailable."
        ),
        required_dependency="systemd network configuration directories" if is_linux and not systemd_profile_roots_available else None,
    )
    systemd_profile_control_ready = is_linux and systemd_network_profile_control_available()
    statuses["systemd_network_profile_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=systemd_profile_control_ready,
        state="partial" if systemd_profile_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed edits to one exact existing root-owned /etc/systemd/network .network file, creation/deletion of a literal-interface .network profile, and creation of one typed bridge/bond/VLAN .netdev definition are available after bounded state checks. Drop-ins and same-named fallback profiles are refused for .network deletion; creation requires the server to already run as root, and these operations do not reload networkd."
            if systemd_profile_control_ready else "The safe, writable /etc/systemd/network configuration directory is unavailable."
        ),
        required_dependency="writable /etc/systemd/network directory" if is_linux and not systemd_profile_control_ready else None,
    )
    statuses["network_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=iproute2_available,
        state="partial" if iproute2_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Administrative link state and MTU plus exact IPv4/IPv6 address add/remove actions are available after client confirmation for a freshly observed interface; current-user permissions apply, and changes are not persistent."
            if iproute2_available else "The iproute2 'ip' command is unavailable."
        ),
        required_dependency="iproute2 'ip' command" if is_linux and not iproute2_available else None,
    )
    statuses["network_addresses"] = PerCapabilityStatus(
        supported=is_linux,
        available=iproute2_available,
        state="partial" if iproute2_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "All visible IPv4/IPv6 addresses, including secondary addresses, labels, flags, and lifetimes, are available through iproute2 in the current network namespace."
            if iproute2_available else "The iproute2 'ip' command is unavailable."
        ),
        required_dependency="iproute2 'ip' command" if is_linux and not iproute2_available else None,
    )
    dns_configuration_ready = dns_configuration_available(env) if is_linux else False
    statuses["dns_configuration"] = PerCapabilityStatus(
        supported=is_linux,
        available=dns_configuration_ready,
        state="partial" if dns_configuration_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "The tool reads /etc/resolv.conf when present and adds systemd-resolved global/per-link state or active NetworkManager per-device IPv4/IPv6 DNS servers, domains, and search domains from a fixed field list when the corresponding client is installed; source-specific availability is reported per request, and the output may reveal local network configuration."
            if dns_configuration_ready
            else "Neither /etc/resolv.conf nor the resolvectl or NetworkManager nmcli client is available."
            if is_linux
            else "DNS configuration inventory is available only on Linux."
        ),
        required_dependency="/etc/resolv.conf, resolvectl, or NetworkManager nmcli" if is_linux and not dns_configuration_ready else None,
    )
    socket_tables_available = is_linux and any(Path("/proc/net", name).is_file() for name in ("tcp", "udp", "tcp6", "udp6"))
    statuses["network_sockets"] = PerCapabilityStatus(
        supported=is_linux,
        available=socket_tables_available,
        state="partial" if socket_tables_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "TCP/UDP sockets visible in the current network namespace are available with kernel-visible UID/inode metadata; visible process associations and UNIX/raw sockets have separate capabilities."
            if socket_tables_available else "Linux procfs TCP/UDP socket tables are unavailable."
        ),
        required_dependency="Linux procfs /proc/net socket tables" if is_linux and not socket_tables_available else None,
    )
    unix_raw_tables_available = is_linux and any(
        Path("/proc/net", name).is_file() for name in ("unix", "raw", "raw6")
    )
    statuses["network_unix_raw_sockets"] = PerCapabilityStatus(
        supported=is_linux,
        available=unix_raw_tables_available,
        state="partial" if unix_raw_tables_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "UNIX-domain sockets and available IPv4/IPv6 raw sockets are listed from current-namespace procfs; visible process associations have a separate capability."
            if unix_raw_tables_available else "Linux procfs UNIX/raw socket tables are unavailable."
        ),
        required_dependency="Linux procfs /proc/net/unix, raw, or raw6" if is_linux and not unix_raw_tables_available else None,
    )
    socket_owner_available = is_linux and Path("/proc/self/fd").is_dir()
    statuses["network_socket_owners"] = PerCapabilityStatus(
        supported=is_linux,
        available=socket_owner_available,
        state="partial" if socket_owner_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Socket inodes can be mapped to visible process descriptors with bounded procfs scanning; hidepid and ptrace permissions may limit results."
            if socket_owner_available else "Linux procfs process descriptor links are unavailable."
        ),
        required_dependency="Linux procfs /proc/PID/fd links" if is_linux and not socket_owner_available else None,
    )
    network_stats_available = is_linux and any(
        Path("/proc/net", name).is_file() for name in ("snmp", "netstat", "snmp6")
    )
    statuses["network_protocol_stats"] = PerCapabilityStatus(
        supported=is_linux,
        available=network_stats_available,
        state="partial" if network_stats_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Cumulative IPv4/IPv6 and transport protocol counters are available from current-namespace procfs snapshots."
            if network_stats_available else "Linux procfs protocol-statistics tables are unavailable."
        ),
        required_dependency="Linux procfs /proc/net/snmp, netstat, or snmp6" if is_linux and not network_stats_available else None,
    )
    route_tables_available = is_linux and any(Path("/proc/net", name).is_file() for name in ("route", "ipv6_route"))
    statuses["network_routes"] = PerCapabilityStatus(
        supported=is_linux,
        available=route_tables_available,
        state="partial" if route_tables_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "IPv4/IPv6 procfs route snapshots are available in the current network namespace; iproute2 policy rules, all-table routes, and destination-specific route selection are reported by separate capabilities."
            if route_tables_available else "Linux procfs route tables are unavailable."
        ),
        required_dependency="Linux procfs /proc/net route tables" if is_linux and not route_tables_available else None,
    )
    statuses["network_policy"] = PerCapabilityStatus(
        supported=is_linux,
        available=iproute2_available,
        state="partial" if iproute2_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "IPv4/IPv6 policy rules and routes from all routing tables are available through bounded read-only iproute2 JSON queries."
            if iproute2_available else "The iproute2 'ip' command is unavailable."
        ),
        required_dependency="iproute2 'ip' command" if is_linux and not iproute2_available else None,
    )
    statuses["network_route_lookup"] = PerCapabilityStatus(
        supported=is_linux,
        available=iproute2_available,
        state="partial" if iproute2_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "A literal IPv4 or IPv6 destination can be checked with a bounded read-only iproute2 route lookup in the current network namespace."
            if iproute2_available else "The iproute2 'ip' command is unavailable."
        ),
        required_dependency="iproute2 'ip' command" if is_linux and not iproute2_available else None,
    )
    statuses["route_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=iproute2_available,
        state="partial" if iproute2_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact transient unicast static-route add/remove actions are available after client confirmation; removal excludes kernel and dynamic routes, and the current account must have route-management permission."
            if iproute2_available else "The iproute2 'ip' command is unavailable."
        ),
        required_dependency="iproute2 'ip' command" if is_linux and not iproute2_available else None,
    )
    firewall_tools = detect_firewall_tools(env) if is_linux else {}
    firewall_available = is_linux and any(firewall_tools.values())
    statuses["firewall_rules"] = PerCapabilityStatus(
        supported=is_linux,
        available=firewall_available,
        state=(
            "partial" if firewall_available
            else "dependency_missing" if is_linux
            else "not_supported"
        ),
        reason=(
            "Active nftables and IPv4/IPv6 xtables entries can be queried from the current network namespace; permissions may restrict rule visibility."
            if firewall_available
            else "No optional nft, iptables-save, or ip6tables-save command is available."
            if is_linux
            else "Firewall inventory is available only on Linux."
        ),
        required_dependency="nft, iptables-save, or ip6tables-save" if is_linux and not firewall_available else None,
    )
    nft_control_available = is_linux and bool(find_session_binary("nft", env))
    statuses["firewall_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=nft_control_available,
        state="partial" if nft_control_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact confirmed transient inbound TCP/UDP block rules are supported in a dedicated nftables table; default policy and unrelated rules are unchanged, and the current account must have firewall-management permission."
            if nft_control_available else "The nft command is unavailable."
        ),
        required_dependency="nft command" if is_linux and not nft_control_available else None,
    )
    frontend_tools = detect_firewall_frontends(env) if is_linux else {}
    frontend_available = is_linux and any(frontend_tools.values())
    statuses["firewall_frontend_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=frontend_available,
        state="partial" if frontend_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Runtime firewalld zones/bindings and UFW active state, default policies, logging, and displayed rules can be queried when the corresponding frontend is running and readable."
            if frontend_available else "Neither firewall-cmd nor ufw is available in the sanitized session PATH."
        ),
        required_dependency="firewalld firewall-cmd and/or UFW" if is_linux and not frontend_available else None,
    )
    firewalld_control_available = is_linux and bool(frontend_tools.get("firewalld"))
    statuses["firewalld_port_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=firewalld_control_available,
        state="partial" if firewalld_control_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact TCP/UDP zone port-list entries can be added or removed in a verified active runtime zone or in saved permanent zone configuration, with state confirmation and revalidation; adding an entry may expose it through all zone bindings, and other rules may independently allow the same port."
            if firewalld_control_available
            else "The optional firewall-cmd command is unavailable."
            if is_linux
            else "Firewalld port control is available only on Linux."
        ),
        required_dependency="firewalld firewall-cmd" if is_linux and not firewalld_control_available else None,
    )
    statuses["firewalld_icmp_block_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=firewalld_control_available,
        state="partial" if firewalld_control_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact supported ICMP type blocks can be added or removed in a verified active runtime zone or in saved permanent configuration, with the type definition, block list, inversion state, and zone binding revalidated; zones with ICMP block inversion enabled are refused."
            if firewalld_control_available
            else "The optional firewall-cmd command is unavailable."
            if is_linux
            else "Firewalld ICMP block control is available only on Linux."
        ),
        required_dependency="firewalld firewall-cmd" if is_linux and not firewalld_control_available else None,
    )
    statuses["firewalld_service_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=firewalld_control_available,
        state="partial" if firewalld_control_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact firewalld service membership can be added or removed in a verified active runtime zone or saved permanent zone configuration after state confirmation and revalidation; a service definition may contain several traffic effects and other entries may independently allow traffic."
            if firewalld_control_available
            else "The optional firewall-cmd command is unavailable."
            if is_linux
            else "Firewalld service control is available only on Linux."
        ),
        required_dependency="firewalld firewall-cmd" if is_linux and not firewalld_control_available else None,
    )
    statuses["firewalld_rich_rule_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=firewalld_control_available,
        state="partial" if firewalld_control_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Typed TCP/UDP port/range, ICMP-type, and IP-protocol rich rules with optional same-family source/destination CIDRs, accept/reject/drop verdicts, optional rate-limited kernel logging and audit records, and optional priority can be added or removed in a verified active runtime zone or saved permanent configuration after exact state confirmation; other rules and policies can affect the resulting traffic decision. Protocol names resolve through the host's local protocol database and are encoded as numeric IP protocol values."
            if firewalld_control_available
            else "The optional firewall-cmd command is unavailable."
            if is_linux
            else "Firewalld rich-rule control is available only on Linux."
        ),
        required_dependency="firewalld firewall-cmd" if is_linux and not firewalld_control_available else None,
    )
    ufw_control_available = is_linux and bool(frontend_tools.get("ufw"))
    statuses["ufw_port_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=ufw_control_available,
        state="partial" if ufw_control_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact TCP/UDP numeric-port, contiguous inclusive-range, or strictly increasing list of up to 15 distinct numeric-port allow/deny/reject/limit entries, with ranges and lists mutually exclusive can be added or removed in active UFW with inbound/outbound direction and literal source/destination IP or CIDR filters after state confirmation and revalidation; interfaces, routed rules, and other UFW rule forms are outside this control, and rule precedence or non-UFW rules may change effective traffic handling."
            if ufw_control_available
            else "The optional ufw command is unavailable."
            if is_linux
            else "UFW port control is available only on Linux."
        ),
        required_dependency="ufw command" if is_linux and not ufw_control_available else None,
    )
    systemctl_available = bool(find_session_binary("systemctl", env))
    rc_status_available = bool(find_session_binary("rc-status", env))
    rc_service_available = bool(find_session_binary("rc-service", env))
    sv_available = bool(find_session_binary("sv", env))
    s6_rc_available = bool(find_session_binary("s6-rc", env))
    init_scripts_available = Path("/etc/init.d").is_dir()
    runit_directories_available = runit_service_directories_available()
    init_system = _detect_init_system() if is_linux else None
    if is_linux and init_system == "systemd":
        available = systemctl_available
        statuses["service_inventory"] = PerCapabilityStatus(
            supported=True,
            available=available,
            state="ready" if available else "dependency_missing",
            reason=None if available else "systemctl is unavailable on this systemd host.",
            required_dependency="systemctl" if not available else None,
        )
    elif is_linux and init_system == "openrc" and rc_status_available:
        statuses["service_inventory"] = PerCapabilityStatus(
            supported=True, available=True, state="partial",
            reason="OpenRC system-service states and runlevel/dynamic contexts are available through rc-status; script-only entries may have unknown state.",
        )
    elif is_linux and init_system == "runit" and runit_directories_available:
        statuses["service_inventory"] = PerCapabilityStatus(
            supported=True, available=True, state="partial",
            reason=(
                "Runit service directories can be listed and bounded runtime/normal-startup states are available through sv status; permissions may leave some states unknown."
                if sv_available
                else "Runit service directories can be listed, but sv is unavailable; runtime and normal-startup states are unknown."
            ),
        )
    elif is_linux and init_system == "s6-svscan" and s6_rc_available:
        statuses["service_inventory"] = PerCapabilityStatus(
            supported=True, available=True, state="partial",
            reason="The active s6-rc database provides bounded atomic-service type and up/down state; when s6-frontend is installed, the offline current working-set prescriptions are also listed and may include services absent from the live database.",
        )
    elif is_linux and init_scripts_available:
        statuses["service_inventory"] = PerCapabilityStatus(
            supported=True, available=True, state="partial",
            reason="Init script names can be listed; runtime and startup states are not available for this init system.",
        )
    else:
        statuses["service_inventory"] = PerCapabilityStatus(
            supported=is_linux, available=False,
            state="dependency_missing" if is_linux else "not_supported",
            reason="No supported systemd manager, standard runit service directory, s6-rc database, or /etc/init.d service inventory was found.",
            required_dependency="systemd/systemctl, OpenRC rc-status, runit service directories, s6-rc, or /etc/init.d" if is_linux else None,
        )
    service_control_supported = is_linux and init_system in {"systemd", "openrc", "runit", "s6-svscan"}
    service_control_available = (
        is_linux and (
            init_system == "systemd" and systemctl_available
            or init_system == "openrc" and rc_service_available
            or init_system == "runit" and sv_available and runit_directories_available
            or init_system == "s6-svscan" and s6_rc_available
        )
    )
    statuses["service_control"] = PerCapabilityStatus(
        supported=service_control_supported,
        available=service_control_available,
        state=(
            "partial" if service_control_available
            else "dependency_missing" if service_control_supported
            else "not_supported"
        ),
        reason=(
            "Exact systemd service actions are available after explicit client confirmation and run with current-user permissions."
            if init_system == "systemd" and service_control_available
            else "Exact OpenRC start/stop/restart/reload actions are available after explicit client confirmation; dependency actions may affect related services."
            if init_system == "openrc" and service_control_available
            else "Exact runit start/stop/restart/reload actions are available after explicit client confirmation for services under standard runsvdir paths."
            if init_system == "runit" and service_control_available
            else "Exact s6-rc start/stop/restart/reload actions are available after explicit client confirmation; each target is revalidated in the active atomic-service database, the current user must control the supervision tree, and transition dependencies may affect related services."
            if init_system == "s6-svscan" and service_control_available
            else "systemctl is unavailable on this systemd host."
            if is_linux and init_system == "systemd"
            else "rc-service is unavailable on this OpenRC host."
            if is_linux and init_system == "openrc"
            else "sv or a standard runit service directory is unavailable on this runit host."
            if is_linux and init_system == "runit"
            else "s6-rc is unavailable on this s6 host."
            if is_linux and init_system == "s6-svscan"
            else "Service actions are implemented for systemd, OpenRC, runit, and s6-rc."
        ),
        required_dependency=(
            "systemctl" if is_linux and init_system == "systemd" and not systemctl_available
            else "rc-service" if is_linux and init_system == "openrc" and not rc_service_available
            else "sv and standard runit service directories" if is_linux and init_system == "runit" and not service_control_available
            else "s6-rc" if is_linux and init_system == "s6-svscan" and not service_control_available
            else None
        ),
    )
    openrc_startup_supported = is_linux and init_system == "openrc"
    openrc_startup_available = openrc_startup_supported and openrc_startup_control_available()
    statuses["openrc_service_startup"] = PerCapabilityStatus(
        supported=openrc_startup_supported,
        available=openrc_startup_available,
        state=(
            "partial" if openrc_startup_available
            else "dependency_missing" if openrc_startup_supported
            else "not_supported"
        ),
        reason=(
            "Existing OpenRC runlevels and service-link membership are readable; exact confirmed enable/disable actions use rc-update and do not start or stop the service."
            if openrc_startup_available
            else "rc-update, /etc/runlevels, or a standard init.d directory is unavailable on this OpenRC host."
            if openrc_startup_supported
            else "OpenRC startup management requires OpenRC as the active init system."
        ),
        required_dependency=(
            "rc-update, /etc/runlevels, and /etc/init.d or /usr/local/etc/init.d"
            if openrc_startup_supported and not openrc_startup_available
            else None
        ),
    )
    runit_startup_supported = is_linux and init_system == "runit"
    runit_startup_available = runit_startup_supported and runit_startup_control_available()
    statuses["runit_service_startup"] = PerCapabilityStatus(
        supported=runit_startup_supported,
        available=runit_startup_available,
        state=(
            "partial" if runit_startup_available
            else "dependency_missing" if runit_startup_supported
            else "not_supported"
        ),
        reason=(
            "Exact supervised runit services support confirmed down-marker changes for their initial state; changes apply when runsv next starts and do not alter a currently running service."
            if runit_startup_available
            else "A readable standard runsvdir service directory is unavailable on this runit host."
            if runit_startup_supported
            else "Runit startup management requires runit as the active init system."
        ),
        required_dependency=(
            "a readable standard runsvdir service directory"
            if runit_startup_supported and not runit_startup_available
            else None
        ),
    )
    s6_startup_supported = is_linux and init_system == "s6-svscan"
    s6_startup_available = s6_startup_supported and s6_startup_set_available()
    statuses["s6_service_startup"] = PerCapabilityStatus(
        supported=s6_startup_supported,
        available=s6_startup_available,
        state=(
            "partial" if s6_startup_available
            else "dependency_missing" if s6_startup_supported
            else "not_supported"
        ),
        reason=(
            "Exact s6-frontend enable/disable changes are available for the offline working set after confirmation; they do not change the live database and require a later commit/install."
            if s6_startup_available
            else "s6-frontend's s6 command is unavailable on this s6 host."
            if s6_startup_supported
            else "s6 startup-set control requires s6-svscan as the active init system."
        ),
        required_dependency=(
            "s6-frontend s6 command" if s6_startup_supported and not s6_startup_available else None
        ),
    )
    systemd_timers_supported = is_linux and init_system == "systemd"
    systemd_timers_available = systemd_timers_supported and systemctl_available
    statuses["systemd_timers"] = PerCapabilityStatus(
        supported=systemd_timers_supported,
        available=systemd_timers_available,
        state=("partial" if systemd_timers_available else "dependency_missing" if systemd_timers_supported else "not_supported"),
        reason=(
            "Loaded timer units and next/last run times can be queried from system or user systemd managers."
            if systemd_timers_available
            else "systemctl is unavailable on this systemd host."
            if systemd_timers_supported
            else "Systemd timer inventory requires a systemd host."
        ),
        required_dependency="systemctl" if systemd_timers_supported and not systemd_timers_available else None,
    )
    statuses["systemd_timer_control"] = PerCapabilityStatus(
        supported=systemd_timers_supported,
        available=systemd_timers_available,
        state=("partial" if systemd_timers_available else "dependency_missing" if systemd_timers_supported else "not_supported"),
        reason=(
            "Exact timer start/stop and persistent enable/disable actions are available after explicit client confirmation; generated timer definitions have a separate capability."
            if systemd_timers_available
            else "systemctl is unavailable on this systemd host."
            if systemd_timers_supported
            else "Systemd timer control requires a systemd host."
        ),
        required_dependency="systemctl" if systemd_timers_supported and not systemd_timers_available else None,
    )
    timer_definition_available = systemd_timer_definition_control_available()
    statuses["systemd_timer_definition_control"] = PerCapabilityStatus(
        supported=systemd_timers_supported,
        available=timer_definition_available,
        state=("partial" if timer_definition_available else "dependency_missing" if systemd_timers_supported else "not_supported"),
        reason=(
            "Confirmed creation and replacement of generated systemd timer files is available for an already-loaded service in system or user scope; deletion is limited to marked timers that are inactive, disabled, and have no drop-ins or enablement links. Timers remain inactive unless separately started."
            if timer_definition_available
            else "systemctl and systemd-analyze are required on a systemd host for timer-definition control."
            if systemd_timers_supported
            else "Systemd timer-definition control requires a systemd host."
        ),
        required_dependency=(
            "systemctl and systemd-analyze" if systemd_timers_supported and not timer_definition_available else None
        ),
    )
    service_definition_available = systemd_service_definition_control_available()
    statuses["systemd_service_definition_control"] = PerCapabilityStatus(
        supported=systemd_timers_supported,
        available=service_definition_available,
        state=("partial" if service_definition_available else "dependency_missing" if systemd_timers_supported else "not_supported"),
        reason=(
            "Confirmed creation and replacement of generated Type=oneshot systemd service files is available in system and user scope; files are loaded but services are not started or enabled."
            if service_definition_available
            else "systemctl and systemd-analyze are required on a systemd host for service-definition control."
            if systemd_timers_supported
            else "Systemd service-definition control requires a systemd host."
        ),
        required_dependency=(
            "systemctl and systemd-analyze" if systemd_timers_supported and not service_definition_available else None
        ),
    )
    cron_inventory_available = is_linux and (
        bool(find_session_binary("crontab", env))
        or bool(find_session_binary("atq", env))
        or Path("/etc/crontab").is_file()
        or Path("/etc/cron.d").is_dir()
        or Path("/etc/anacrontab").is_file()
    )
    statuses["cron_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=cron_inventory_available,
        state="partial" if cron_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "One or more standard cron, Anacron, or at-queue sources are available for bounded schedule metadata; command text is omitted."
            if cron_inventory_available
            else "No standard crontab, Anacron, crontab command, or atq source is available."
        ),
        required_dependency="standard cron/Anacron files, crontab, or atq" if is_linux and not cron_inventory_available else None,
    )
    cron_control_supported = is_linux
    cron_control_available_now = cron_control_supported and cron_control_available(env)
    statuses["cron_control"] = PerCapabilityStatus(
        supported=cron_control_supported,
        available=cron_control_available_now,
        state=("partial" if cron_control_available_now else "dependency_missing" if cron_control_supported else "not_supported"),
        reason=(
            "Marked jobs can be added, updated, or removed from the current user's crontab; when the server already runs as root and /etc/cron.d passes fixed ownership checks, one generated system cron file can also be managed for an exact local account."
            if cron_control_available_now
            else "Neither the crontab command nor an already-root-managed /etc/cron.d source is available."
            if cron_control_supported
            else "Cron job control requires Linux."
        ),
        required_dependency="crontab or root-owned /etc/cron.d" if cron_control_supported and not cron_control_available_now else None,
    )
    at_control_supported = is_linux
    at_control_available_now = at_control_supported and at_control_available(env)
    statuses["at_control"] = PerCapabilityStatus(
        supported=at_control_supported,
        available=at_control_available_now,
        state=("partial" if at_control_available_now else "dependency_missing" if at_control_supported else "not_supported"),
        reason=(
            "One-shot at jobs can be added or removed for the current server identity after exact client confirmation."
            if at_control_available_now
            else "The at, atq, and atrm commands are required for current-user one-shot job control."
            if at_control_supported
            else "One-shot at-job control requires Linux."
        ),
        required_dependency="at, atq, and atrm" if at_control_supported and not at_control_available_now else None,
    )
    fstab_available = is_linux and fstab_inventory_available()
    statuses["fstab_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=fstab_available,
        state="partial" if fstab_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "The fixed /etc/fstab file is available for bounded, read-only configuration metadata."
            if fstab_available
            else "The fixed /etc/fstab file is unavailable, unreadable, or larger than the bounded inventory limit."
        ),
        required_dependency="readable regular /etc/fstab no larger than 512 KiB" if is_linux and not fstab_available else None,
    )
    crypttab_available = is_linux and crypttab_inventory_available()
    statuses["crypttab_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=crypttab_available,
        state="partial" if crypttab_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "The fixed /etc/crypttab file is available for bounded, read-only encryption metadata."
            if crypttab_available
            else "The fixed /etc/crypttab file is unavailable, unreadable, or larger than the bounded inventory limit."
        ),
        required_dependency="readable regular /etc/crypttab no larger than 512 KiB" if is_linux and not crypttab_available else None,
    )
    mount_control_ready = is_linux and fstab_inventory_available() and mount_control_available(env)
    statuses["mount_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=mount_control_ready,
        state="partial" if mount_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact /etc/fstab targets can be mounted or unmounted in the current mount namespace after explicit client confirmation; util-linux, fstab rules, and current permissions determine authorization."
            if mount_control_ready else "Mount control requires readable /etc/fstab, current mount-namespace data, and the util-linux mount and umount commands."
        ),
        required_dependency=(
            "readable /etc/fstab, /proc/self/mountinfo, and util-linux mount/umount"
            if is_linux and not mount_control_ready else None
        ),
    )
    journalctl = find_session_binary("journalctl", env) if is_linux else None
    statuses["journal_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=bool(journalctl),
        state="partial" if journalctl else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded system and user journal queries are available through journalctl; a selected journal may still require user or group permissions."
            if journalctl else "journalctl is unavailable on this system."
        ),
        required_dependency="journalctl" if is_linux and not journalctl else None,
    )
    system_log_sources, blocked_log_sources, log_directory_blocked = (
        system_log_source_readiness() if is_linux else ((), (), False)
    )
    log_permission_blocked = bool(blocked_log_sources) or log_directory_blocked
    statuses["system_log_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=bool(system_log_sources),
        state=(
            "partial" if system_log_sources
            else "permission_required" if log_permission_blocked
            else "dependency_missing" if is_linux
            else "not_supported"
        ),
        reason=(
            f"Readable fixed /var/log sources: {', '.join(system_log_sources)}."
            + (f" Permission blocks affect: {', '.join(blocked_log_sources)}." if blocked_log_sources else "")
            + " Arbitrary paths and rotated archives are excluded."
            if system_log_sources
            else "The fixed /var/log directory or candidate source files are not readable with current permissions."
            if log_permission_blocked
            else "No readable regular files were found for the fixed /var/log syslog, messages, kern.log, dmesg, auth.log, or secure sources."
        ),
        required_dependency=(
            "A readable regular file under /var/log"
            if is_linux and not system_log_sources and not log_permission_blocked else None
        ),
        required_permission=(
            "Read access to /var/log and the selected fixed log source"
            if is_linux and log_permission_blocked else None
        ),
    )
    statuses["boot_target_inventory"] = PerCapabilityStatus(
        supported=is_linux and init_system == "systemd",
        available=is_linux and init_system == "systemd" and systemctl_available,
        state=(
            "partial" if is_linux and init_system == "systemd" and systemctl_available
            else "dependency_missing" if is_linux and init_system == "systemd"
            else "not_supported"
        ),
        reason=(
            "Installed and loaded systemd targets plus the default target are available; other init systems use different boot models."
            if is_linux and init_system == "systemd" and systemctl_available
            else "systemctl is unavailable on this systemd host."
            if is_linux and init_system == "systemd"
            else "Boot target inventory is implemented for systemd; this host uses another or unknown init system."
        ),
        required_dependency="systemctl" if is_linux and init_system == "systemd" and not systemctl_available else None,
    )
    boot_target_control_available = is_linux and init_system == "systemd" and systemctl_available
    statuses["boot_target_control"] = PerCapabilityStatus(
        supported=is_linux and init_system == "systemd",
        available=boot_target_control_available,
        state=(
            "partial" if boot_target_control_available
            else "dependency_missing" if is_linux and init_system == "systemd"
            else "not_supported"
        ),
        reason=(
            "An exact installed target can be set for the next boot after explicit client confirmation; the active session is unchanged."
            if boot_target_control_available
            else "systemctl is unavailable on this systemd host."
            if is_linux and init_system == "systemd"
            else "Default boot-target changes are implemented only for systemd."
        ),
        required_dependency="systemctl" if is_linux and init_system == "systemd" and not systemctl_available else None,
    )
    time_settings_ready = timedatectl_available(env) if is_linux else False
    time_supported = is_linux and init_system == "systemd"
    time_state = "partial" if time_settings_ready else "dependency_missing" if time_supported else "not_supported"
    time_reason = (
        "Fixed systemd timedated clock, timezone, RTC-mode, and network-time status fields are available; timedated/D-Bus state is checked when called."
        if time_settings_ready
        else "timedatectl is unavailable on this systemd host."
        if time_supported
        else "Time tools require a Linux systemd host; this host does not meet that requirement."
    )
    for capability in ("time_settings", "time_control"):
        statuses[capability] = PerCapabilityStatus(
            supported=time_supported,
            available=time_settings_ready,
            state=time_state,
            reason=(
                time_reason
                if capability == "time_settings"
                else "Exact timezone and network-time changes require client confirmation and noninteractive timedated authorization; current account permissions are checked by timedated."
                if time_settings_ready
                else time_reason
            ),
            required_dependency="systemd timedatectl" if time_supported and not time_settings_ready else None,
        )
    time_sync_ready = time_sync_status_available(env) if is_linux else False
    statuses["time_sync_status"] = PerCapabilityStatus(
        supported=is_linux,
        available=time_sync_ready,
        state="partial" if time_sync_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded read-only chrony tracking/source data and systemd-timesyncd provider properties can be queried when their clients are installed; each provider daemon and permission state is checked at call time."
            if time_sync_ready
            else "Neither chronyc nor systemd timedatectl is available for time synchronization status."
            if is_linux
            else "Time synchronization status is available only on Linux."
        ),
        required_dependency="chronyc or systemd timedatectl" if is_linux and not time_sync_ready else None,
    )
    loginctl = find_session_binary("loginctl", env) if is_linux else None
    statuses["session_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=bool(loginctl),
        state="partial" if loginctl else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded logind session metadata is available through loginctl; visible sessions depend on host permissions and manager support."
            if loginctl else "loginctl is unavailable on this host."
        ),
        required_dependency="loginctl" if is_linux and not loginctl else None,
    )
    for capability, account_file in (("local_users", "/etc/passwd"), ("local_groups", "/etc/group")):
        available = is_linux and Path(account_file).is_file() and os.access(account_file, os.R_OK)
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=available,
            state="partial" if available else ("dependency_missing" if is_linux else "not_supported"),
            reason=(
                "Local account-file entries are available; NSS, LDAP, and other external identity sources are not queried."
                if available else f"Readable {account_file} is unavailable."
            ),
            required_dependency=account_file if is_linux and not available else None,
        )
    getent_available = is_linux and bool(find_session_binary("getent", env))
    statuses["nss_identity_lookup"] = PerCapabilityStatus(
        supported=is_linux,
        available=getent_available,
        state="partial" if getent_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact passwd/group keys can be resolved through configured NSS sources; remote source availability and access depend on the host configuration. Identity enumeration is not exposed."
            if getent_available
            else "The optional getent command is unavailable."
            if is_linux
            else "NSS identity lookup is available only on Linux."
        ),
        required_dependency="getent" if is_linux and not getent_available else None,
    )
    local_identity_control_ready = is_linux and local_identity_control_available(env)
    statuses["local_identity_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=local_identity_control_ready,
        state="partial" if local_identity_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed local user/group creation and deletion, password lock/unlock, selected shell changes, secondary group membership, optional home creation for new users, and bounded existing-home relocation beneath /home or /var/home are available; password values use the separate local password-control capability, and remote NSS identities are not changed."
            if local_identity_control_ready else "Shadow-utils user/group commands and readable local /etc/passwd and /etc/group are required."
        ),
        required_dependency="shadow-utils useradd/userdel/usermod/groupadd/groupdel/gpasswd/passwd and local passwd/group files" if is_linux and not local_identity_control_ready else None,
    )
    local_password_control_ready = is_linux and local_password_control_available(env)
    statuses["local_password_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=local_password_control_ready,
        state="partial" if local_password_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed password setting for one exact local account, including root, is available through chpasswd stdin; local account, password status, and shadow-file identity are rechecked, while current permissions and PAM policy determine whether it succeeds."
            if local_password_control_ready else "A local root-owned non-group/world-writable /etc/shadow and the chpasswd/passwd/usermod commands are required."
        ),
        required_dependency="local chpasswd, passwd, and usermod commands plus root-owned non-group/world-writable /etc/shadow" if is_linux and not local_password_control_ready else None,
    )
    local_ssh_key_control_ready = is_linux and local_ssh_key_control_available(env)
    statuses["local_ssh_key_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=local_ssh_key_control_ready,
        state="partial" if local_ssh_key_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed add/remove of a validated plain public key in one local account's authorized_keys file is available; the tool rechecks the account home and file identity and does not change sshd configuration."
            if local_ssh_key_control_ready else "A safe local /etc/passwd and the ssh-keygen command are required."
        ),
        required_dependency="OpenSSH ssh-keygen and root-owned non-group/world-writable /etc/passwd" if is_linux and not local_ssh_key_control_ready else None,
    )
    sudo_policy_control_ready = is_linux and sudo_policy_control_available(env)
    statuses["sudo_policy_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=sudo_policy_control_ready,
        state="partial" if sudo_policy_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed per-user rules for one exact root-owned executable and literal argument string can be managed in /etc/sudoers.d with the PASSWD tag; visudo validates the full configuration. Other matching host rules and Defaults exempt_group can affect effective authentication. The MCP server must already run as root, and NOPASSWD rules are not written."
            if sudo_policy_control_ready else "A safe /etc/sudoers and /etc/sudoers.d with an includedir directive plus visudo are required."
        ),
        required_dependency="visudo and a safe included /etc/sudoers.d directory; the server must run as root to apply changes" if is_linux and not sudo_policy_control_ready else None,
    )
    sssd_domain_inventory_ready = is_linux and sssd_domain_inventory_available()
    statuses["sssd_domain_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=sssd_domain_inventory_ready,
        state="partial" if sssd_domain_inventory_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Existing SSSD domain sections and their [sssd] domains membership can be listed without exposing provider settings or credentials; configurations with conf.d snippets are outside this bounded inventory."
            if sssd_domain_inventory_ready else "A safe root-owned mode-0600 /etc/sssd/sssd.conf with simple domain sections and no conf.d snippets is required."
        ),
        required_dependency="SSSD configuration at /etc/sssd/sssd.conf" if is_linux and not sssd_domain_inventory_ready else None,
    )
    sssd_domain_control_ready = is_linux and sssd_domain_control_available()
    statuses["sssd_domain_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=sssd_domain_control_ready,
        state=(
            "partial" if sssd_domain_control_ready
            else "permission_required" if is_linux and sssd_domain_inventory_ready and os.geteuid() != 0
            else "dependency_missing" if is_linux
            else "not_supported"
        ),
        reason=(
            "One existing SSSD domain can be enabled or disabled by changing only its [sssd] domains membership; candidate configuration is checked with sssctl config-check and the last enabled domain cannot be disabled."
            if sssd_domain_control_ready else "A root-owned sssctl executable and safe SSSD configuration without conf.d snippets are required; the MCP server must already run as root."
        ),
        required_permission="MCP server must already run as root" if is_linux and sssd_domain_inventory_ready and os.geteuid() != 0 else None,
        required_dependency="sssctl from sssd-tools" if is_linux and os.geteuid() == 0 and sssd_domain_inventory_ready and not sssd_domain_control_ready else None,
    )
    pam_profile_inventory_ready = is_linux and pam_profile_inventory_available()
    statuses["pam_profile_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=pam_profile_inventory_ready,
        state=(
            "partial" if pam_profile_inventory_ready
            else "permission_required" if is_linux and os.geteuid() != 0
            else "dependency_missing" if is_linux
            else "not_supported"
        ),
        reason=(
            "Lists package-supplied pam-auth-update profiles and their debconf selection state; profile contents are omitted, and selection does not prove local common-* files match the generated stack."
            if pam_profile_inventory_ready
            else "A safe Debian-style /usr/share/pam-configs inventory, common PAM stack, debconf profile state, and pam-auth-update tools with enable/disable support are required."
        ),
        required_permission="MCP server must already run as root" if is_linux and os.geteuid() != 0 else None,
        required_dependency="pam-auth-update, debconf-communicate, and safe packaged PAM configuration files" if is_linux and os.geteuid() == 0 and not pam_profile_inventory_ready else None,
    )
    pam_profile_control_ready = is_linux and pam_profile_control_available()
    statuses["pam_profile_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=pam_profile_control_ready,
        state=(
            "partial" if pam_profile_control_ready
            else "permission_required" if is_linux and os.geteuid() != 0
            else "dependency_missing" if is_linux
            else "not_supported"
        ),
        reason=(
            "One package-supplied profile can be enabled or disabled through pam-auth-update after exact confirmation and state revalidation; the operation uses no --force and may affect every login service."
            if pam_profile_control_ready
            else "A safe Debian-style PAM profile inventory and root-owned pam-auth-update with --enable/--disable support are required; the MCP server must already run as root."
        ),
        required_permission="MCP server must already run as root" if is_linux and os.geteuid() != 0 else None,
        required_dependency="pam-auth-update with --enable/--disable and debconf-communicate" if is_linux and os.geteuid() == 0 and not pam_profile_control_ready else None,
    )
    block_devices_available = is_linux and Path("/sys/class/block").is_dir()
    statuses["block_devices"] = PerCapabilityStatus(
        supported=is_linux,
        available=block_devices_available,
        state="partial" if block_devices_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded block-device capacity and basic sysfs attributes are available; cumulative I/O statistics, optional on-demand SMART health, and separate confirmed LVM, LUKS1/LUKS2, and ext4 controls have dedicated capabilities."
            if block_devices_available else "Linux sysfs block-device inventory is unavailable."
        ),
        required_dependency="sysfs block-device data" if is_linux and not block_devices_available else None,
    )
    statuses["storage_topology"] = PerCapabilityStatus(
        supported=is_linux,
        available=block_devices_available,
        state="partial" if block_devices_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Active block-device component and holder relationships plus selected device-mapper and MD RAID metadata, including current sync action, completed/total sectors, and mismatch sectors when exposed, are available from sysfs; LVM tools and storage mutations are not used."
            if block_devices_available else "Linux sysfs block-device topology is unavailable."
        ),
        required_dependency="sysfs /sys/class/block relationships" if is_linux and not block_devices_available else None,
    )
    lvm_available = is_linux and lvm_inventory_available(env)
    statuses["lvm_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=lvm_available,
        state="partial" if lvm_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Read-only LVM2 volume-group and logical-volume reports are available; physical-volume identifiers and active/in-use state are omitted."
            if lvm_available else "Both the LVM2 vgs and lvs commands are required."
        ),
        required_dependency="LVM2 vgs and lvs commands" if is_linux and not lvm_available else None,
    )
    lvm_control_available = is_linux and lvm_volume_control_available(env)
    statuses["lvm_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=lvm_control_available,
        state="partial" if lvm_control_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed creation/growth of logical volumes, restricted shrink of linear raw/ext4 volumes, LVM snapshot creation/removal, and restore of an exact classic copy-on-write snapshot into its origin are available. Restore requires an already-root server, lvconvert, dmsetup, fuser, active but closed LV devices, and a healthy classic COW snapshot below 100% usage. Ext4 shrink requires an unmounted volume and resizes ext4 before the LV; other filesystems/layouts are refused. PV/VG creation and membership changes have a separate capability; RAID, LUKS, and filesystem creation/growth use dedicated controls."
            if lvm_control_available else "LVM2 vgs, lvs, lvcreate, lvextend, and lvremove commands are required."
        ),
        required_dependency="LVM2 vgs, lvs, lvcreate, lvextend, and lvremove commands" if is_linux and not lvm_control_available else None,
    )
    lvm_group_available = is_linux and lvm_group_control_available(env)
    pvmove_available = is_linux and find_session_binary("pvmove", env) is not None
    statuses["lvm_group_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=lvm_group_available,
        state="partial" if lvm_group_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed creation of new LVM volume groups, addition of blank PVs to existing groups, removal of exact PVs with zero allocated extents, and pvmove --atomic migration between exact PVs when pvmove is installed are available. PV/VG membership and migration extents are re-read and verified."
            if lvm_group_available else "LVM2 vgs, pvs, vgcreate, vgextend, vgreduce, util-linux wipefs, and Linux block-device state are required."
        ),
        required_dependency=(
            "LVM2 vgs/pvs/vgcreate/vgextend/vgreduce, util-linux wipefs, and Linux block-device sysfs"
            if is_linux and not lvm_group_available
            else "LVM2 pvmove for allocated-extent migration"
            if lvm_group_available and not pvmove_available
            else None
        ),
    )
    luks_available = is_linux and luks_control_available(env)
    statuses["luks_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=luks_available,
        state="partial" if luks_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed LUKS1/LUKS2 mapping and keyslot operations plus private header backup and guarded header restore are available for exact block devices. Formatting requires a verified blank unused device; keyslot changes refuse the last active slot and token-bound LUKS2 slots."
            if luks_available else "The cryptsetup and util-linux wipefs commands are required."
        ),
        required_dependency="cryptsetup and util-linux wipefs commands" if is_linux and not luks_available else None,
    )
    statuses["luks_header_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=luks_available,
        state="partial" if luks_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Private LUKS1/LUKS2 header backup and confirmation-gated restore are available. Restore binds the exact backup digest and device, requires an unused target, and verifies the resulting UUID and keyslot/token state."
            if luks_available else "The cryptsetup and util-linux wipefs commands are required."
        ),
        required_dependency="cryptsetup and util-linux wipefs commands" if is_linux and not luks_available else None,
    )
    luks_token_available = is_linux and bool(find_session_binary("cryptsetup", env))
    statuses["luks_token_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=luks_token_available,
        state="partial" if luks_token_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "LUKS2 token IDs, type names, and keyslot bindings can be inventoried without returning token JSON payloads."
            if luks_token_available else "The cryptsetup command is unavailable."
        ),
        required_dependency="cryptsetup command" if is_linux and not luks_token_available else None,
    )
    statuses["luks_token_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=luks_token_available,
        state="partial" if luks_token_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed removal/unassignment and bounded token JSON import/export are available with cryptsetup external-token plugin loading disabled for token actions. Imports use a private file and an unused token ID without replacement; exports create a new private mode-0600 file and do not return JSON to the client. Native keyring-token enrollment and full reencryption are not covered."
            if luks_token_available else "The cryptsetup command is unavailable."
        ),
        required_dependency="cryptsetup command" if is_linux and not luks_token_available else None,
    )
    ext4_available = is_linux and ext4_control_available(env)
    statuses["ext4_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=ext4_available,
        state="partial" if ext4_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed ext4 creation on verified blank devices and growth of existing ext4 filesystems are available; formatting refuses recognized signatures and resize never shrinks."
            if ext4_available else "The util-linux wipefs/blkid and e2fsprogs ext4 utilities are required."
        ),
        required_dependency="util-linux wipefs/blkid and e2fsprogs mkfs.ext4, dumpe2fs, and resize2fs commands" if is_linux and not ext4_available else None,
    )
    xfs_available = is_linux and xfs_control_available(env)
    statuses["xfs_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=xfs_available,
        state="partial" if xfs_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed XFS creation on devices without recognized signatures and online growth for one mounted XFS filesystem are available; growth requires a writable unambiguous mountpoint, and real-time-section filesystems and shrinking are unsupported."
            if xfs_available else "The util-linux wipefs/blkid and xfsprogs mkfs.xfs, xfs_info, and xfs_growfs utilities are required."
        ),
        required_dependency="util-linux wipefs/blkid and xfsprogs mkfs.xfs, xfs_info, and xfs_growfs commands" if is_linux and not xfs_available else None,
    )
    md_raid_available = is_linux and md_raid_control_available(env)
    statuses["md_raid_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=md_raid_available,
        state="partial" if md_raid_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed RAID0/RAID1/RAID4/RAID5/RAID6/RAID10 creation, spare add/remove, healthy active-member replacement, exact healthy-member failure marking, removal of an already-faulty member, check-only consistency scrubbing on healthy idle redundant arrays, and stopping exact active idle arrays with mount/swap/holder checks are available. RAID4 uses a dedicated parity member. Failure marking requires an active, idle, non-degraded redundant array and can reduce redundancy or start spare recovery; faulty-member removal requires the array to be idle. RAID4 and RAID5 require at least three members and RAID6 at least four. Array assembly/start, repair scrubbing, reshape, and boot-time assembly configuration are not exposed."
            if md_raid_available else "The mdadm and util-linux wipefs commands plus Linux sysfs block-device inventory are required."
        ),
        required_dependency="mdadm, util-linux wipefs, and /sys/class/block" if is_linux and not md_raid_available else None,
    )
    btrfs_snapshots_available = is_linux and btrfs_snapshot_tools_available(env)
    statuses["btrfs_snapshot_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=btrfs_snapshots_available,
        state="partial" if btrfs_snapshots_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded local and received Btrfs snapshot inventory is available for an explicitly supplied mounted top-level subvolume (ID 5); paths and current-user permissions are checked per request."
            if btrfs_snapshots_available
            else "The btrfs-progs 'btrfs' command is required."
        ),
        required_dependency="btrfs-progs 'btrfs' command" if is_linux and not btrfs_snapshots_available else None,
    )
    statuses["btrfs_snapshot_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=btrfs_snapshots_available,
        state="partial" if btrfs_snapshots_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed Btrfs read-write/read-only snapshot creation, exact local/received snapshot deletion, and constrained restoration of a read-only snapshot as a writable clone at an exact unmounted non-default subvolume are available; restoration preserves the old target at a new sibling path and refuses nested subvolumes."
            if btrfs_snapshots_available
            else "The btrfs-progs 'btrfs' command is required."
        ),
        required_dependency="btrfs-progs 'btrfs' command" if is_linux and not btrfs_snapshots_available else None,
    )
    btrfs_filesystem_available = is_linux and btrfs_filesystem_control_available(env)
    statuses["btrfs_filesystem_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=btrfs_filesystem_available,
        state="partial" if btrfs_filesystem_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed creation on verified unused single-device block devices, online growth after backing-device expansion, and online shrink to an explicit sector-aligned size above Btrfs's reported minimum are available; shrink requires the server to already run as root and may relocate data with high I/O; active swapfiles in the target region can prevent it. Recognized signatures, active use during creation, and multi-device filesystems are refused."
            if btrfs_filesystem_available
            else "The btrfs-progs btrfs/mkfs.btrfs and util-linux wipefs commands are required."
        ),
        required_dependency=(
            "btrfs-progs btrfs/mkfs.btrfs and util-linux wipefs commands"
            if is_linux and not btrfs_filesystem_available
            else None
        ),
    )
    statuses["block_device_stats"] = PerCapabilityStatus(
        supported=is_linux,
        available=block_devices_available,
        state="partial" if block_devices_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Cumulative read/write/discard/flush counters are available from per-device sysfs stat files; some kernels or devices may expose fewer optional fields."
            if block_devices_available else "Linux sysfs block-device statistics are unavailable."
        ),
        required_dependency="sysfs /sys/class/block/<device>/stat" if is_linux and not block_devices_available else None,
    )
    smartctl_found = is_linux and block_devices_available and smartctl_available()
    statuses["block_device_health"] = PerCapabilityStatus(
        supported=is_linux,
        available=smartctl_found,
        state="partial" if smartctl_found else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "On-demand SMART health snapshots are available for one exact whole block device; support and visibility depend on its protocol, driver, and current-user access to /dev."
            if smartctl_found else "The optional smartmontools 'smartctl' command is unavailable."
            if block_devices_available else "Linux sysfs block-device inventory is unavailable."
        ),
        required_dependency=(
            "smartmontools 'smartctl' command" if is_linux and block_devices_available and not smartctl_found
            else "Linux sysfs block-device inventory" if is_linux and not block_devices_available
            else None
        ),
    )
    hardware_bus_paths = (Path("/sys/bus/pci/devices"), Path("/sys/bus/usb/devices"))
    hardware_bus_available = is_linux and any(path.is_dir() for path in hardware_bus_paths)
    dmi_identity_available = firmware_identity_available() if is_linux else False
    hardware_inventory_available = hardware_bus_available or dmi_identity_available
    statuses["hardware_devices"] = PerCapabilityStatus(
        supported=is_linux,
        available=hardware_inventory_available,
        state="partial" if hardware_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded PCI/USB identifiers and selected DMI system, board, chassis, and BIOS fields are available where exposed; explicit DMI serial/UUID attributes and device labels are omitted."
            if hardware_inventory_available else "Linux PCI/USB device directories and allowlisted DMI identity attributes are unavailable."
        ),
        required_dependency="PCI/USB sysfs inventory or DMI identity attributes" if is_linux and not hardware_inventory_available else None,
    )
    udevadm_found = is_linux and bool(find_session_binary("udevadm", env))
    statuses["udev_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=udevadm_found,
        state="partial" if udevadm_found else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Bounded kernel-device paths, subsystem/type, attached driver, device-node numbers, and numeric vendor/product IDs can be read; serials, labels, and symlinks are excluded. The udev database must be available."
            if udevadm_found else "The optional udevadm command is unavailable in the sanitized session PATH."
        ),
        required_dependency="udevadm and a readable udev database" if is_linux and not udevadm_found else None,
    )
    sensor_paths = (Path("/sys/class/hwmon"), Path("/sys/class/thermal"))
    sensor_interfaces_available = is_linux and any(path.is_dir() for path in sensor_paths)
    statuses["sensor_readings"] = PerCapabilityStatus(
        supported=is_linux,
        available=sensor_interfaces_available,
        state="partial" if sensor_interfaces_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Read-only hwmon and thermal-zone input snapshots are available; exposed channels and driver unit conventions vary by device."
            if sensor_interfaces_available else "Linux hwmon and thermal-zone sysfs interfaces are unavailable."
        ),
        required_dependency="sysfs hwmon or thermal-zone inputs" if is_linux and not sensor_interfaces_available else None,
    )
    backlight_available = is_linux and backlight_control_available()
    backlight_reason = (
        "Linux backlight devices can be inventoried; brightness writes depend on each device's current OS permissions and driver behavior."
        if backlight_available else "Linux backlight sysfs at /sys/class/backlight is unavailable."
    )
    for capability in ("display_backlight_inventory", "display_brightness_control"):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=backlight_available,
            state="partial" if backlight_available else ("dependency_missing" if is_linux else "not_supported"),
            reason=backlight_reason,
            required_dependency="Linux backlight sysfs at /sys/class/backlight" if is_linux and not backlight_available else None,
        )
    alsa_proc_paths = (Path("/proc/asound/cards"), Path("/proc/asound/pcm"))
    audio_inventory_available = is_linux and any(path.is_file() for path in alsa_proc_paths)
    statuses["audio_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=audio_inventory_available,
        state="partial" if audio_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Kernel ALSA card and PCM endpoint metadata are available; userspace endpoints are reported by a separate capability."
            if audio_inventory_available else "ALSA procfs card and PCM inventories are unavailable; userspace audio-server readiness is reported separately."
        ),
        required_dependency="ALSA procfs card or PCM inventory" if is_linux and not audio_inventory_available else None,
    )
    audio_server_available = is_linux and bool(
        find_session_binary("pactl", env) or find_session_binary("wpctl", env)
    )
    statuses["audio_server_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=audio_server_available,
        state="partial" if audio_server_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Audio sink and source inventory is available through pactl or wpctl when a current-user audio session is running; endpoints may include network audio tunnels, while active streams and audio content are excluded."
            if audio_server_available else "Neither pactl nor wpctl is available in the sanitized session PATH."
        ),
        required_dependency="pactl or wpctl" if is_linux and not audio_server_available else None,
    )
    statuses["audio_server_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=audio_server_available,
        state="partial" if audio_server_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed current-session sink/source volume (0-100%), mute, and default-endpoint changes are available through pactl or wpctl; selected endpoints may include network audio tunnels, and their state is rechecked before and after each action."
            if audio_server_available else "Neither pactl nor wpctl is available in the sanitized session PATH."
        ),
        required_dependency="pactl or wpctl" if is_linux and not audio_server_available else None,
    )
    power_supply_path = Path("/sys/class/power_supply")
    power_supply_available = is_linux and power_supply_path.is_dir()
    statuses["power_supply_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=power_supply_available,
        state="partial" if power_supply_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Allowlisted power-supply status and telemetry attributes are available as read-only snapshots; writable charge controls and identifying fields are excluded."
            if power_supply_available else "Linux sysfs power-supply inventory is unavailable."
        ),
        required_dependency="sysfs power-supply inventory" if is_linux and not power_supply_available else None,
    )
    power_state_available = is_linux and Path("/sys/power/state").is_file()
    statuses["power_state"] = PerCapabilityStatus(
        supported=is_linux,
        available=power_state_available,
        state="partial" if power_state_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Kernel-exported suspend/hibernate choices and optional selected modes can be read; logind inhibitors are reported separately, and firmware readiness or transition success is not predicted."
            if power_state_available else "The Linux /sys/power/state interface is unavailable."
        ),
        required_dependency="Linux /sys/power/state" if is_linux and not power_state_available else None,
    )
    inhibitor_inventory_available = is_linux and bool(find_session_binary("busctl", env))
    statuses["power_inhibitor_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=inhibitor_inventory_available,
        state="partial" if inhibitor_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Current logind inhibitor owner, PID/UID, operation, reason, and mode fields can be read; command lines and derived process names are excluded. A running system logind service is required."
            if inhibitor_inventory_available else "busctl is unavailable in the sanitized session PATH."
        ),
        required_dependency="busctl and a system logind service" if is_linux and not inhibitor_inventory_available else None,
    )
    power_control_available = is_linux and bool(find_session_binary("busctl", env))
    statuses["power_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=power_control_available,
        state="partial" if power_control_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Logind power-action readiness and explicit-confirmation system transitions are available; actual firmware and hardware transition success cannot be predicted. Firmware-setup reboot also requires systemctl."
            if power_control_available else "busctl is unavailable in the sanitized session PATH."
        ),
        required_dependency="busctl and a system logind service" if is_linux and not power_control_available else None,
    )
    power_profile_available = is_linux and bool(find_session_binary("powerprofilesctl", env))
    statuses["power_profile_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=power_profile_available,
        state="partial" if power_profile_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "The active and available power-profiles-daemon profile names can be read through powerprofilesctl; hardware effects depend on the installed drivers and firmware."
            if power_profile_available else "powerprofilesctl is unavailable in the sanitized session PATH."
        ),
        required_dependency="powerprofilesctl from power-profiles-daemon" if is_linux and not power_profile_available else None,
    )
    statuses["power_profile_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=power_profile_available,
        state="partial" if power_profile_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "State-bound, confirmed power-profiles-daemon profile selection is available with post-change verification; profile effects depend on the installed drivers and firmware."
            if power_profile_available else "powerprofilesctl is unavailable in the sanitized session PATH."
        ),
        required_dependency="powerprofilesctl from power-profiles-daemon" if is_linux and not power_profile_available else None,
    )
    lpstat_available = is_linux and bool(find_session_binary("lpstat", env))
    statuses["printer_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=lpstat_available,
        state="partial" if lpstat_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Configured CUPS queue and default-destination metadata can be queried; server availability and configured queues vary by host."
            if lpstat_available else "The CUPS lpstat command is unavailable."
        ),
        required_dependency="CUPS lpstat command" if is_linux and not lpstat_available else None,
    )
    printer_control_supported = is_linux
    printer_control_ready = printer_control_supported and printer_control_available()
    statuses["printer_control"] = PerCapabilityStatus(
        supported=printer_control_supported,
        available=printer_control_ready,
        state=("partial" if printer_control_ready else "dependency_missing" if printer_control_supported else "not_supported"),
        reason=(
            "Exact configured CUPS queues can be enabled/disabled or set to accept/reject new jobs after explicit confirmation; enabling a queue may resume queued jobs."
            if printer_control_ready
            else "CUPS lpstat and all four queue-control commands are required."
            if printer_control_supported
            else "CUPS printer control is available only on Linux."
        ),
        required_dependency=(
            "CUPS lpstat, cupsenable, cupsdisable, cupsaccept, and cupsreject commands"
            if printer_control_supported and not printer_control_ready
            else None
        ),
    )
    kernel_modules_available = is_linux and Path("/proc/modules").is_file()
    statuses["kernel_modules"] = PerCapabilityStatus(
        supported=is_linux,
        available=kernel_modules_available,
        state="partial" if kernel_modules_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Loaded module names, sizes, reference counts, and states are available; module addresses and dependency details are omitted."
            if kernel_modules_available else "Linux procfs loaded-module inventory is unavailable."
        ),
        required_dependency="Linux procfs /proc/modules" if is_linux and not kernel_modules_available else None,
    )
    kernel_module_control_ready = is_linux and kernel_module_control_available(env)
    statuses["kernel_module_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=kernel_module_control_ready,
        state="partial" if kernel_module_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed runtime loading of an exact installed module and unloading of an exact live module with no reported references or holders are available; startup configuration is not changed."
            if kernel_module_control_ready else "modinfo, modprobe, rmmod, and Linux sysfs module state are required."
        ),
        required_dependency="modinfo, modprobe, rmmod, and /sys/module" if is_linux and not kernel_module_control_ready else None,
    )
    kernel_module_startup_ready = is_linux and kernel_module_startup_control_available(env)
    statuses["kernel_module_startup_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=kernel_module_startup_ready,
        state="partial" if kernel_module_startup_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed creation and removal of one generated exact-module entry in root-owned systemd modules-load.d configuration is available; changes affect future boot only."
            if kernel_module_startup_ready else "A systemd host, root-owned /etc/modules-load.d directory, and modinfo are required."
        ),
        required_dependency=(
            "systemd modules-load.d, root-owned /etc/modules-load.d, and modinfo"
            if is_linux and not kernel_module_startup_ready else None
        ),
    )
    kernel_parameters_ready = is_linux and kernel_parameter_control_available()
    kernel_parameter_reason = (
        "A fixed allowlist of runtime sysctl values and exact confirmed updates is available; persistent settings are managed separately."
        if kernel_parameters_ready
        else "Linux procfs must expose at least one supported runtime sysctl file."
        if is_linux
        else "Kernel parameter controls are available only on Linux."
    )
    for capability in ("kernel_parameter_inventory", "kernel_parameter_control"):
        statuses[capability] = PerCapabilityStatus(
            supported=is_linux,
            available=kernel_parameters_ready,
            state="partial" if kernel_parameters_ready else ("dependency_missing" if is_linux else "not_supported"),
            reason=kernel_parameter_reason,
            required_dependency="an available allowlisted file under /proc/sys" if is_linux and not kernel_parameters_ready else None,
        )
    persistent_kernel_parameters_ready = is_linux and persistent_kernel_parameter_control_available(env)
    statuses["kernel_parameter_persistence"] = PerCapabilityStatus(
        supported=is_linux,
        available=persistent_kernel_parameters_ready,
        state="partial" if persistent_kernel_parameters_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed create/update/removal of one generated sysctl.d file for an allowlisted key is available; this is systemd boot configuration and does not change the running value."
            if persistent_kernel_parameters_ready
            else "A systemd host, systemd-sysctl, and a root-owned non-writable /etc/sysctl.d directory are required."
        ),
        required_dependency=(
            "systemd-sysctl and /etc/sysctl.d"
            if is_linux and not persistent_kernel_parameters_ready else None
        ),
    )
    kernel_command_line_ready = is_linux and kernel_command_line_control_available(env)
    statuses["kernel_command_line_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=kernel_command_line_ready,
        state="partial" if kernel_command_line_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed add/remove of one simple argument is available through grubby or bounded static GRUB_CMDLINE_LINUX/GRUB_CMDLINE_LINUX_DEFAULT assignments with direct grub-mkconfig regeneration; the fallback binds root-owned generator hooks and verifies the generated entries."
            if kernel_command_line_ready else "A safe grubby executable or supported static GRUB defaults/configuration layout is unavailable."
        ),
        required_dependency="grubby or safe static GRUB defaults and grub-mkconfig" if is_linux and not kernel_command_line_ready else None,
    )
    initramfs_ready = is_linux and initramfs_rebuild_available()
    statuses["initramfs_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=initramfs_ready,
        state="partial" if initramfs_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed rebuilding of the exact current-kernel image through dracut, update-initramfs, or a simple literal mkinitcpio preset is available; shell presets, extra default options, UKI output, and nonstandard targets are refused."
            if initramfs_ready else "Exactly one verified standard current-kernel image and its safe dracut, update-initramfs, or supported literal mkinitcpio preset are required."
        ),
        required_dependency="a safe initramfs manager and a standard /boot image" if is_linux and not initramfs_ready else None,
    )
    security_posture_available = is_linux and kernel_security_posture_available()
    statuses["kernel_security_posture"] = PerCapabilityStatus(
        supported=is_linux,
        available=security_posture_available,
        state=("partial" if security_posture_available else ("dependency_missing" if is_linux else "not_supported")),
        reason=(
            "At least one selected Linux security interface is available; the response reports each source separately and covers only a bounded subset of host security policy."
            if security_posture_available else "No selected kernel security sysfs/procfs or EFI variable interface is visible."
        ),
        required_dependency="Selected kernel security sysfs/procfs or EFI variable interfaces" if is_linux and not security_posture_available else None,
    )
    linux_audit_available = is_linux and linux_audit_tools_available(env)
    statuses["linux_audit"] = PerCapabilityStatus(
        supported=is_linux,
        available=linux_audit_available,
        state=("partial" if linux_audit_available else ("dependency_missing" if is_linux else "not_supported")),
        reason=(
            "At least one auditctl, ausearch, or aureport client is installed; auditctl also enables narrowly scoped confirmed runtime watch-rule changes when kernel authorization allows them. Each status, rule, event, or summary operation reports its own dependency and permission result."
            if linux_audit_available else "The optional auditctl, ausearch, and aureport clients are unavailable."
        ),
        required_dependency="auditctl, ausearch, and/or aureport (Linux audit-userspace)" if is_linux and not linux_audit_available else None,
    )
    audit_rule_control_ready = is_linux and audit_rule_control_available(env)
    statuses["linux_audit_rule_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=audit_rule_control_ready,
        state=("partial" if audit_rule_control_ready else ("dependency_missing" if is_linux else "not_supported")),
        reason=(
            "auditctl is installed; exact runtime file-watch changes still require kernel audit-control authorization and are refused when audit rules are immutable."
            if audit_rule_control_ready else "The optional auditctl executable is unavailable."
        ),
        required_dependency="auditctl (Linux audit-userspace)" if is_linux and not audit_rule_control_ready else None,
    )
    selinux_booleans_ready = is_linux and selinux_booleans_available()
    statuses["selinux_booleans"] = PerCapabilityStatus(
        supported=is_linux,
        available=selinux_booleans_ready,
        state="partial" if selinux_booleans_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "The SELinux boolean directory is visible; current and pending values are read-only snapshots."
            if selinux_booleans_ready else "The SELinux boolean directory is not visible in selinuxfs."
        ),
        required_dependency="SELinux-enabled kernel and readable selinuxfs booleans directory" if is_linux and not selinux_booleans_ready else None,
    )
    selinux_boolean_control_ready = is_linux and selinux_boolean_control_available()
    statuses["selinux_boolean_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=selinux_boolean_control_ready,
        state="partial" if selinux_boolean_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Exact runtime or persistent SELinux boolean changes are available after confirmation; current-user authorization is determined by host policy."
            if selinux_boolean_control_ready else "An active SELinux boolean interface and the setsebool command are required."
        ),
        required_dependency="SELinux-enabled kernel, readable selinuxfs booleans, and setsebool" if is_linux and not selinux_boolean_control_ready else None,
    )
    selinux_context_control_ready = is_linux and selinux_context_control_available()
    statuses["selinux_context_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=selinux_context_control_ready,
        state="partial" if selinux_context_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "One exact nonrecursive restorecon operation is available after confirmation; customizable labels and user/role/range fields are not forcibly reset."
            if selinux_context_control_ready else "An active SELinux interface plus restorecon and matchpathcon are required."
        ),
        required_dependency="SELinux-enabled kernel, restorecon, and matchpathcon" if is_linux and not selinux_context_control_ready else None,
    )
    selinux_fcontext_dependency_ready = is_linux and selinux_fcontext_rule_control_available()
    selinux_fcontext_rule_ready = selinux_fcontext_dependency_ready and os.geteuid() == 0
    statuses["selinux_fcontext_rule_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=selinux_fcontext_rule_ready,
        state=(
            "partial" if selinux_fcontext_rule_ready
            else "permission_required" if selinux_fcontext_dependency_ready
            else "dependency_missing" if is_linux
            else "not_supported"
        ),
        reason=(
            "Confirmed exact-path persistent SELinux file-context rule add/remove is available; root is required, and changing the rule does not relabel the current object."
            if selinux_fcontext_rule_ready
            else "The MCP server must already run as root to change persistent SELinux file-context rules."
            if selinux_fcontext_dependency_ready
            else "An active SELinux interface and semanage are required."
        ),
        required_dependency="SELinux-enabled kernel and semanage" if is_linux and not selinux_fcontext_dependency_ready else None,
        required_permission="Run the MCP server as root" if selinux_fcontext_dependency_ready and not selinux_fcontext_rule_ready else None,
    )
    apparmor_profiles_ready = is_linux and apparmor_profiles_available()
    statuses["apparmor_profiles"] = PerCapabilityStatus(
        supported=is_linux,
        available=apparmor_profiles_ready,
        state="partial" if apparmor_profiles_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "The kernel-exported AppArmor profile list is visible; pages contain loaded names and modes only."
            if apparmor_profiles_ready else "The AppArmor profile list is not visible in securityfs."
        ),
        required_dependency="AppArmor-enabled kernel and readable securityfs profile list" if is_linux and not apparmor_profiles_ready else None,
    )
    apparmor_profile_control_ready = is_linux and apparmor_profile_control_available()
    statuses["apparmor_profile_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=apparmor_profile_control_ready,
        state="partial" if apparmor_profile_control_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed enforce/complain changes are available for exact loaded profiles when both AppArmor utilities support --profile; the kernel-reported mode and helper identity are checked before each change, and the resulting mode is verified."
            if apparmor_profile_control_ready else "The AppArmor profile list, a writable standard profile directory, and aa-enforce/aa-complain utilities with exact --profile support are required."
        ),
        required_dependency="AppArmor-enabled kernel, readable profile list, writable /etc/apparmor.d, and aa-enforce/aa-complain with --profile support" if is_linux and not apparmor_profile_control_ready else None,
    )
    ima_available = is_linux and ima_measurements_available()
    statuses["ima_measurements"] = PerCapabilityStatus(
        supported=is_linux,
        available=ima_available,
        state="partial" if ima_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "The ASCII IMA runtime-measurement interface is visible; pages are bounded and optional counters are reported separately."
            if ima_available else "The IMA ASCII runtime-measurement interface in securityfs is unavailable."
        ),
        required_dependency="IMA-enabled kernel and readable securityfs measurement interface" if is_linux and not ima_available else None,
    )
    ima_policy_ready = is_linux and ima_policy_available()
    statuses["ima_policy"] = PerCapabilityStatus(
        supported=is_linux,
        available=ima_policy_ready,
        state="partial" if ima_policy_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "The active IMA policy readback path is visible; access may still require CONFIG_IMA_READ_POLICY and CAP_SYS_ADMIN."
            if ima_policy_ready else "The active IMA policy readback path is unavailable in securityfs."
        ),
        required_dependency="IMA policy readback support and readable securityfs policy interface" if is_linux and not ima_policy_ready else None,
    )
    tpm_inventory_available = is_linux and Path("/sys/class/tpm").is_dir()
    statuses["tpm_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=tpm_inventory_available,
        state="partial" if tpm_inventory_available else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "TPM device specification version and optional bound-driver metadata are available when exposed by the kernel and driver."
            if tpm_inventory_available else "Linux TPM class sysfs is unavailable."
        ),
        required_dependency="Linux /sys/class/tpm" if is_linux and not tpm_inventory_available else None,
    )
    tpm_event_log_ready = is_linux and tpm_event_log_available()
    statuses["tpm_event_log"] = PerCapabilityStatus(
        supported=is_linux,
        available=tpm_event_log_ready,
        state="partial" if tpm_event_log_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "A kernel-exported TPM firmware event log is visible in securityfs; record paging is bounded."
            if tpm_event_log_ready else "No kernel-exported TPM firmware event log is visible in securityfs."
        ),
        required_dependency="TPM firmware event log and mounted securityfs" if is_linux and not tpm_event_log_ready else None,
    )
    tpm_attestation_ready = is_linux and tpm_attestation_available()
    statuses["tpm_attestation"] = PerCapabilityStatus(
        supported=is_linux,
        available=tpm_attestation_ready,
        state="partial" if tpm_attestation_ready else ("dependency_missing" if is_linux else "not_supported"),
        reason=(
            "TPM 2.0 quote tools and an accessible TPM character device are available; a caller-selected persistent attestation key is checked when requested."
            if tpm_attestation_ready else "Safe tpm2-tools executables and an accessible TPM character device are required."
        ),
        required_dependency="tpm2-tools and an accessible TPM 2.0 device" if is_linux and not tpm_attestation_ready else None,
    )
    package_manager, package_executable = detect_package_manager(env) if is_linux else ("unsupported", None)
    package_available = is_linux and package_inventory_available(package_manager, package_executable)
    manager_supported = is_linux and package_manager != "unsupported"
    if package_available:
        package_state = "partial"
        package_reason = None
        package_dependency = None
    elif manager_supported:
        package_state = "dependency_missing"
        package_reason = f"The {package_manager} package database was detected, but its read-only inventory source is unavailable."
        package_dependency = "Readable APK installed database" if package_manager == "apk" else f"{package_manager} query executable"
    else:
        package_state = "not_supported"
        package_reason = "No supported dpkg, RPM, pacman, or APK package database was detected."
        package_dependency = None
    statuses["package_inventory"] = PerCapabilityStatus(
        supported=manager_supported,
        available=package_available,
        state=package_state,
        reason=package_reason,
        required_dependency=package_dependency,
    )
    package_control_ready, control_manager, package_frontend, package_control_error = (
        package_control_readiness() if is_linux else (False, "unsupported", None, "System package operations are available only on Linux.")
    )
    package_control_supported = is_linux and control_manager != "unsupported"
    statuses["package_control"] = PerCapabilityStatus(
        supported=package_control_supported,
        available=package_control_ready,
        state=(
            "partial" if package_control_ready
            else "dependency_missing" if package_control_supported
            else "not_supported"
        ),
        reason=(
            f"Explicitly confirmed {control_manager} transactions are available through {package_frontend}; they use current OS permissions without elevation, so authorization depends on this account."
            if package_control_ready
            else package_control_error
        ),
        required_dependency=(
            "installed-package database and supported transaction frontend"
            if package_control_supported and not package_control_ready else None
        ),
    )
    python_readiness = python_environment_readiness(env) if is_linux else None
    statuses["python_environment_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=is_linux,
        state="partial" if is_linux else "not_supported",
        reason=(
            "Lists only Linux MCP-managed virtual environments beneath the current user's home directory; package details come from bounded distribution metadata without running venv Python, pip, or installed package code."
            if is_linux else "Python environment inventory is available only on Linux."
        ),
    )
    python_control_ready = bool(python_readiness and python_readiness.available)
    statuses["python_environment_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=python_control_ready,
        state=(
            "partial" if python_control_ready
            else "permission_required" if python_readiness and python_readiness.required_permission
            else "dependency_missing" if is_linux
            else "not_supported"
        ),
        reason=(
            "Confirmed Python venv creation and exact pip install/upgrade/uninstall actions are available for the current unprivileged user; package builds may execute code and use the public package index."
            if python_control_ready
            else python_readiness.reason if python_readiness else "Python environment control is available only on Linux."
        ),
        required_dependency=python_readiness.required_dependency if python_readiness else None,
        required_permission=python_readiness.required_permission if python_readiness else None,
    )
    native_readiness = native_package_environment_readiness(env) if is_linux else None
    native_inventory_ready = bool(native_readiness and (native_readiness.npm_available or native_readiness.cargo_available))
    statuses["native_package_environment_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=native_inventory_ready,
        state=("partial" if native_inventory_ready else "dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Lists managed npm prefixes and Cargo install roots for the current user; package names and versions are read from bounded npm manifests or Cargo's install-list command without running installed package code."
            if native_inventory_ready
            else native_readiness.reason if native_readiness else "Native package environment inventory is available only on Linux."
        ),
        required_dependency="npm and node, or Cargo" if is_linux and not native_inventory_ready else None,
    )
    native_control_ready = bool(native_readiness and native_readiness.mutation_available)
    statuses["native_package_environment_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=native_control_ready,
        state=(
            "partial" if native_control_ready
            else "permission_required" if native_readiness and (native_readiness.npm_available or native_readiness.cargo_available)
            else "dependency_missing" if is_linux
            else "not_supported"
        ),
        reason=(
            native_readiness.reason if native_readiness else "Native package environment control is available only on Linux."
        ),
        required_dependency="npm and node, or Cargo" if is_linux and native_readiness and not (native_readiness.npm_available or native_readiness.cargo_available) else None,
        required_permission="matching non-root real and effective server UIDs" if is_linux and native_readiness and (native_readiness.npm_available or native_readiness.cargo_available) and not native_readiness.mutation_available else None,
    )
    application_package_tools = detect_application_package_tools(env) if is_linux else {}
    application_package_available = is_linux and any(application_package_tools.values())
    statuses["application_package_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=application_package_available,
        state=(
            "partial" if application_package_available
            else "dependency_missing" if is_linux
            else "not_supported"
        ),
        reason=(
            "Flatpak, Snap, or Nix inventory is available; results include default and configured named Flatpak system installations plus the current-user installation, system Snaps, and the current user's default Nix profile."
            if application_package_available
            else "No optional Flatpak, Snap, or Nix package CLI is available."
            if is_linux
            else "Application package inventory is available only on Linux."
        ),
        required_dependency="flatpak, snap, or nix" if is_linux and not application_package_available else None,
    )
    flatpak_package_control_ready = flatpak_package_control_available(env) if is_linux else False
    snap_package_control_ready = snap_package_control_available(env) if is_linux else False
    nix_profile_control_ready = nix_profile_control_available(env) if is_linux else False
    application_package_control_ready = (
        flatpak_package_control_ready or snap_package_control_ready or nix_profile_control_ready
    )
    available_application_package_controls = [
        name for name, available in (
            ("Flatpak exact-ref", flatpak_package_control_ready),
            ("Snap exact-name", snap_package_control_ready),
            ("Nix exact-profile-entry and history", nix_profile_control_ready),
        ) if available
    ]
    statuses["application_package_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=application_package_control_ready,
        state=(
            "partial" if application_package_control_ready
            else "dependency_missing" if is_linux
            else "not_supported"
        ),
        reason=(
            f"Confirmed {', '.join(available_application_package_controls)} package actions are available. Flatpak covers the default and configured named system installations plus the current-user installation; Snap supports latest/stable and digest-bound local-file installs, channel refresh/switch, enable/disable, retained-revision revert, per-Snap and all-Snap refresh holds on snapd 2.58 or newer, and all-revision removal; global holds affect automatic refreshes only and the complete installed Snap inventory is rechecked. Nix can add a simple nixpkgs attribute, upgrade/remove exact entries, roll back to a selected history version, and remove non-current history older than 30 days from the current user's default profile. Flatpak remote/permission management remains unavailable. Nix profile/flake features must be available in the host configuration."
            if application_package_control_ready
            else "The optional Flatpak, Snap, and Nix commands are unavailable."
            if is_linux
            else "Application package control is available only on Linux."
        ),
        required_dependency="flatpak, snap, or nix CLI" if is_linux and not application_package_control_ready else None,
    )
    statuses["nix_profile_history_inventory"] = PerCapabilityStatus(
        supported=is_linux,
        available=nix_profile_control_ready,
        state=("partial" if nix_profile_control_ready else "dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Lists bounded current-user default-profile version IDs, dates, parent IDs, change counts, and the active-generation marker; package names and source URLs are withheld."
            if nix_profile_control_ready else "The optional nix command is unavailable."
        ),
        required_dependency="nix CLI" if is_linux and not nix_profile_control_ready else None,
    )
    statuses["nix_profile_history_control"] = PerCapabilityStatus(
        supported=is_linux,
        available=nix_profile_control_ready,
        state=("partial" if nix_profile_control_ready else "dependency_missing" if is_linux else "not_supported"),
        reason=(
            "Confirmed rollback to one exact existing default-profile version and age-bounded removal of non-current history after a bounded exact dry-run preview."
            if nix_profile_control_ready else "The optional nix command is unavailable."
        ),
        required_dependency="nix CLI" if is_linux and not nix_profile_control_ready else None,
    )

    # Common window operations derived from an available compositor listing.
    if statuses["window_list"].available:
        for name in ("window_detail", "window_focus"):
            if not statuses[name].supported:
                statuses[name] = PerCapabilityStatus(supported=True, available=True, state="ready")
        if backend.name in {"sway", "niri"}:
            statuses["workspace_list"] = PerCapabilityStatus(supported=True, available=True, state="ready")
        if backend.name == "sway":
            statuses["window_resize"] = PerCapabilityStatus(supported=True, available=True, state="ready")
    # Portable session tools are independent of the window-management adapter.
    app_dirs_exist = any(path.is_dir() for path in _desktop_paths(env))
    statuses["app_discovery"] = PerCapabilityStatus(
        supported=True, available=app_dirs_exist,
        state="ready" if app_dirs_exist else "dependency_missing",
        reason=None if app_dirs_exist else "No Freedesktop applications directory was found.",
        required_dependency="XDG applications directories",
    )
    launcher = find_session_binary("gtk-launch", env) or find_session_binary("gio", env)
    gui_session = bool((session.is_wayland and env.get("WAYLAND_DISPLAY")) or env.get("DISPLAY"))
    statuses["app_launch"] = PerCapabilityStatus(
        supported=True, available=bool(launcher and gui_session),
        state="ready" if launcher and gui_session else "dependency_missing",
        reason=None if launcher and gui_session else ("gtk-launch or gio is unavailable." if not launcher else "An active graphical session is unavailable."),
        required_dependency="gtk-launch or gio and an active graphical session",
    )
    for capability, binary in (("clipboard_read", "wl-paste"), ("clipboard_write", "wl-copy")):
        executable = find_session_binary(binary, env)
        available = bool(executable and session.is_wayland and env.get("WAYLAND_DISPLAY"))
        statuses[capability] = PerCapabilityStatus(
            supported=True, available=available,
            state="ready" if available else "dependency_missing",
            reason=None if available else (f"{binary} is unavailable." if not executable else "An active Wayland display is unavailable."),
            required_dependency=f"{binary} and Wayland session",
        )
    notify_send = find_session_binary("notify-send", env)
    notification_available = bool(notify_send and _session_bus_available(env))
    statuses["notifications"] = PerCapabilityStatus(
        supported=True, available=notification_available,
        state="ready" if notification_available else "dependency_missing",
        reason=None if notification_available else "notify-send or the user's session D-Bus is unavailable.",
        required_dependency="notify-send and session D-Bus",
    )

    portal_ready, portal_missing_reason = _portal_prerequisites(env, session)
    can_observe_window_ids = statuses["window_list"].available

    # Wayland input is never reported as usable unless this backend can issue
    # a fresh exact window token. Pointer input additionally requires current
    # compositor cursor state and verified output geometry.
    keyboard_supported = can_observe_window_ids and session.is_wayland
    if keyboard_supported and portal_ready:
        statuses["input_keyboard"] = PerCapabilityStatus(
            supported=True, available=False, state="permission_required",
            reason="The XDG RemoteDesktop portal requests keyboard and pointer control together on first input use.",
            required_dependency="dbus-next, session D-Bus, and XDG RemoteDesktop portal",
            required_permission="Remote desktop keyboard and pointer grant",
        )
    elif keyboard_supported:
        statuses["input_keyboard"] = PerCapabilityStatus(
            supported=True, available=False, state="dependency_missing",
            reason=portal_missing_reason,
            required_dependency="dbus-next, session D-Bus, and XDG RemoteDesktop portal",
        )
    else:
        statuses["input_keyboard"] = PerCapabilityStatus(
            supported=False, available=False, state="not_supported",
            reason="This compositor adapter cannot provide the focused window ID required to bind keyboard input.",
        )

    output_response = backend.list_outputs() if backend.name in {"hyprland", "sway", "niri", "kde_plasma", "cosmic", "gnome"} else None
    has_verified_output_geometry = bool(
        output_response is not None and output_response.success
        and any(output.enabled and output.logical_geometry is not None for output in output_response.outputs)
    )
    pointer_supported = bool(
        keyboard_supported
        and (backend.get_pointer_position() is not None or backend.name == "niri")
        and has_verified_output_geometry
    )
    if pointer_supported and portal_ready:
        niri_absolute = backend.name == "niri" and backend.get_pointer_position() is None
        statuses["input_pointer"] = PerCapabilityStatus(
            supported=True, available=False, state="permission_required",
            reason=(
                "Niri pointer control uses absolute coordinates through a user-selected monitor ScreenCast stream; "
                "the stream bounds must match current compositor output geometry."
                if niri_absolute else
                "Keyboard and pointer control share one XDG RemoteDesktop grant requested on first input use."
            ),
            required_dependency=(
                "dbus-next, session D-Bus, XDG RemoteDesktop and ScreenCast portals, and compositor output geometry"
                if niri_absolute else
                "dbus-next, session D-Bus, XDG RemoteDesktop portal, and compositor cursor position"
            ),
            required_permission=(
                "Remote desktop pointer control and monitor screen sharing"
                if niri_absolute else
                "Remote desktop keyboard and pointer grant"
            ),
        )
    elif pointer_supported:
        statuses["input_pointer"] = PerCapabilityStatus(
            supported=True, available=False, state="dependency_missing",
            reason=portal_missing_reason,
            required_dependency="dbus-next, session D-Bus, and XDG RemoteDesktop portal",
        )
    else:
        statuses["input_pointer"] = PerCapabilityStatus(
            supported=False, available=False, state="not_supported",
            reason="Pointer input requires exact focused-window and monitor geometry plus either fresh cursor state or Niri absolute-coordinate portal support.",
        )

    touch_supported = bool(keyboard_supported and has_verified_output_geometry)
    if touch_supported and portal_ready:
        statuses["input_touch"] = PerCapabilityStatus(
            supported=True, available=False, state="permission_required",
            reason=(
                "Touch input needs an XDG RemoteDesktop touchscreen grant and a user-selected monitor ScreenCast stream; "
                "stream bounds must match one current compositor output before input is sent."
            ),
            required_dependency="dbus-next, session D-Bus, XDG RemoteDesktop and ScreenCast portals, and compositor output geometry",
            required_permission="Remote desktop touchscreen control and monitor screen sharing",
        )
    elif touch_supported:
        statuses["input_touch"] = PerCapabilityStatus(
            supported=True, available=False, state="dependency_missing",
            reason=portal_missing_reason,
            required_dependency="dbus-next, session D-Bus, XDG RemoteDesktop and ScreenCast portals",
        )
    else:
        statuses["input_touch"] = PerCapabilityStatus(
            supported=False, available=False, state="not_supported",
            reason="Touch input requires an exact observed window plus verified compositor output geometry.",
        )

    if statuses["screenshot"].available and backend.name == "niri":
        statuses["screenshot"] = PerCapabilityStatus(
            supported=True, available=True, state="partial",
            reason="Desktop and portal active-window capture are available; exact Niri crops work for visible tiles when IPC reports integral positions and bounds.",
            required_dependency="grim",
        )
    elif not statuses["screenshot"].available:
        if portal_ready:
            statuses["screenshot"] = PerCapabilityStatus(
                supported=True, available=False, state="permission_required",
                reason="The XDG Screenshot portal may request user confirmation; arbitrary window-ID capture is unavailable through this fallback.",
                required_dependency="dbus-next and XDG Screenshot portal",
                required_permission="Screenshot request grant",
            )
        else:
            statuses["screenshot"] = PerCapabilityStatus(
                supported=True, available=False, state="dependency_missing",
                reason=portal_missing_reason,
                required_dependency="XDG Screenshot portal, dbus-next, and a Wayland session D-Bus",
            )
    busctl = find_session_binary("busctl", env)
    runtime_dir = Path(env.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    atspi_dir = runtime_dir / "at-spi"
    has_atspi_socket = any((atspi_dir / name).is_socket() for name in ("bus_0", "bus_1"))
    has_atspi_address = bool(env.get("AT_SPI_BUS_ADDRESS"))
    available = bool(busctl and _session_bus_available(env) and (has_atspi_socket or has_atspi_address))
    statuses["accessibility"] = PerCapabilityStatus(
        supported=True, available=available,
        state="ready" if available else "dependency_missing",
        reason=None if available else "AT-SPI2 bus address/socket, session D-Bus, or busctl is unavailable.",
        required_dependency="AT-SPI2 D-Bus registry and busctl",
    )

    summary = (
        f"Linux: {'yes' if is_linux else 'no'}; compositor: {backend.name}; session: {session.session_type}; "
        f"Wayland: {'yes' if session.is_wayland else 'no'}; "
        f"available capabilities: {sum(status.available for status in statuses.values())}/{len(statuses)}."
    )
    return CapabilitiesResponse(session=session, capabilities=statuses, summary=summary)


async def get_session_capabilities_async() -> CapabilitiesResponse:
    """Include live XDG RemoteDesktop portal interface availability."""
    response = await asyncio.to_thread(get_session_capabilities)
    keyboard = response.capabilities["input_keyboard"]
    pointer = response.capabilities["input_pointer"]
    touch = response.capabilities["input_touch"]
    pending = [status for status in (keyboard, pointer, touch) if status.state == "permission_required"]
    if not pending:
        return response

    from wayland_mcp.portal import remote_desktop_portal

    try:
        interfaces = await remote_desktop_portal.portal_interfaces()
    except Exception:
        interfaces = None

    if interfaces is None:
        reason = "The session portal interface list could not be read; desktop input cannot be authorized yet."
        dependency = "XDG RemoteDesktop portal interface and session D-Bus"
        for status in pending:
            status.state = "dependency_missing"
            status.reason = reason
            status.required_dependency = dependency
            status.required_permission = None
    elif "org.freedesktop.portal.RemoteDesktop" not in interfaces:
        for status in pending:
            status.state = "dependency_missing"
            status.reason = "The session portal does not expose org.freedesktop.portal.RemoteDesktop."
            status.required_dependency = "XDG RemoteDesktop portal backend"
            status.required_permission = None
    elif "org.freedesktop.portal.ScreenCast" not in interfaces:
        for status in (touch, pointer):
            needs_monitor_stream = status is touch or response.session.compositor_backend == "niri"
            if needs_monitor_stream and status.state == "permission_required":
                status.state = "dependency_missing"
                status.reason = "The session portal does not expose org.freedesktop.portal.ScreenCast for monitor coordinate mapping."
                status.required_dependency = "XDG ScreenCast portal backend"
                status.required_permission = None
    elif response.session.compositor_backend == "niri" and pointer.state == "permission_required":
        try:
            methods = await remote_desktop_portal.portal_methods("org.freedesktop.portal.RemoteDesktop")
        except Exception:
            methods = set()
        if "NotifyPointerMotionAbsolute" not in methods:
            pointer.state = "dependency_missing"
            pointer.reason = "The XDG RemoteDesktop portal does not expose absolute pointer motion required by Niri."
            pointer.required_dependency = "XDG RemoteDesktop NotifyPointerMotionAbsolute support"
            pointer.required_permission = None

    ready_count = sum(status.available for status in response.capabilities.values())
    permission_count = sum(
        status.state == "permission_required"
        for status in response.capabilities.values()
    )
    response.summary = (
        f"Linux: yes; compositor: {response.session.compositor_backend}; "
        f"session: {response.session.session_type}; Wayland: {'yes' if response.session.is_wayland else 'no'}; "
        f"ready: {ready_count}/{len(response.capabilities)}; portal permissions pending: {permission_count}."
    )
    return response
