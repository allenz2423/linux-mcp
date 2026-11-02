"""Startup tool/category selection for the Linux MCP server."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, TypeVar


_TOOLS_BY_CATEGORY: dict[str, str] = {
    "system": """
        get_session_capabilities get_linux_system_info get_resource_usage
        get_pressure_stall_info sample_resource_history list_journal_entries
        list_system_log_entries get_time_settings list_time_zones manage_time_settings
    """,
    "command_execution": """
        run_shell_command start_terminal_session read_terminal_session
        write_terminal_session close_terminal_session
    """,
    "processes": """
        sample_process_history sample_cgroup_history get_process_execution_context
        list_processes get_process_detail list_namespace_inventory get_process_tree
        signal_process
    """,
    "filesystem": """
        list_filesystems manage_mount list_fstab_entries list_crypttab_entries
        inspect_path list_path_extended_attributes list_directory read_text_file
        read_binary_file write_binary_file delete_binary_file
        begin_binary_file_upload append_binary_file_upload commit_binary_file_upload abort_binary_file_upload
        create_text_file replace_text_file
        delete_text_file set_file_mode manage_symlink change_path_owner
        manage_directory manage_directory_tree manage_extended_attribute manage_posix_acl
    """,
    "networking": """
        list_network_interfaces list_radio_devices list_network_manager_profiles
        get_network_manager_profile_dns configure_network_manager_profile_dns get_network_manager_profile_ip
        configure_network_manager_profile_ip get_network_manager_profile_routes manage_network_manager_profile_route
        create_network_manager_virtual_profile create_network_manager_port_profile
        manage_network_manager_port_membership import_network_manager_vpn_profile
        manage_network_manager_profile
        list_systemd_network_profiles configure_systemd_network_profile create_systemd_network_profile create_systemd_netdev_profile configure_systemd_netdev_profile delete_systemd_netdev_profile delete_systemd_network_profile
        manage_network_interface manage_radio_device
        manage_network_address list_network_addresses get_dns_configuration
        list_network_sockets list_unix_raw_sockets list_socket_owners
        list_network_protocol_stats list_network_routes lookup_network_route
        list_network_policy manage_network_route list_firewall_rules
        manage_firewall_rule list_firewall_frontends manage_firewalld_port
        manage_firewalld_icmp_block manage_firewalld_service manage_firewalld_rich_rule
        manage_firewalld_rich_icmp_rule manage_firewalld_rich_protocol_rule
        manage_ufw_port_rule get_time_sync_status
    """,
    "scheduling": """
        list_openrc_runlevels list_services list_systemd_timers manage_systemd_timer
        manage_systemd_timer_definition delete_systemd_timer_definition
        manage_systemd_service_definition
        list_cron_jobs manage_cron_job manage_at_job manage_service manage_openrc_service_startup
        manage_runit_service_startup manage_s6_startup_set
    """,
    "boot_kernel": """
        set_default_boot_target list_boot_targets list_kernel_modules manage_kernel_module
        manage_kernel_module_startup list_kernel_parameters manage_kernel_parameter
        manage_persistent_kernel_parameter manage_kernel_command_line manage_initramfs_rebuild
    """,
    "containers": """
        manage_container create_container list_containers list_container_images
        manage_container_image list_container_resources manage_container_resource
        list_container_pods manage_container_pod build_container_image
        list_container_network_attachments manage_container_network_attachment
    """,
    "virtualization": """
        create_virtual_machine attach_virtual_machine_disk manage_virtual_machine list_virtual_machines list_libvirt_networks
        list_remote_virtual_machines manage_remote_virtual_machine
        list_remote_virtual_machine_snapshots manage_remote_virtual_machine_snapshot
        attach_remote_virtual_machine_disk create_remote_virtual_machine configure_remote_virtual_machine
        configure_virtual_machine
        list_remote_libvirt_networks list_remote_libvirt_storage manage_remote_libvirt_resource
        create_libvirt_isolated_network
        create_libvirt_network
        configure_libvirt_network_ipv4
        list_libvirt_storage manage_libvirt_resource create_libvirt_storage_volume
        list_virtual_machine_snapshots manage_virtual_machine_snapshot
    """,
    "users_identity": """
        list_local_users list_local_groups lookup_nss_identity manage_local_identity
        set_local_user_password manage_local_ssh_key manage_sudo_policy manage_sudo_group_policy
        list_sssd_domains manage_sssd_domain list_pam_profiles manage_pam_profile list_login_sessions
    """,
    "storage": """
        list_block_devices list_storage_topology list_lvm_inventory manage_lvm_volume_group manage_lvm_volume
        manage_luks_mapping list_luks_tokens manage_luks_token manage_luks_header manage_ext4_filesystem manage_xfs_filesystem manage_btrfs_filesystem manage_md_raid
        list_btrfs_snapshots manage_btrfs_snapshot
        get_block_device_health list_block_device_stats
    """,
    "hardware": """
        list_cpu_inventory list_numa_nodes list_gpu_devices list_gpu_power_limits
        manage_gpu_power_limit list_xe_gpu_frequency_limits manage_xe_gpu_frequency_limit
        list_hardware_devices
        list_udev_devices list_sensor_readings list_fan_controls manage_fan_control
        list_powercap_limits manage_powercap_limit
        list_display_backlights manage_display_brightness list_audio_devices
        list_bluetooth_devices manage_bluetooth_pairing
        list_audio_server_devices manage_audio_endpoint list_printers manage_printer
    """,
    "power": """
        list_power_supplies get_power_state list_power_inhibitors
        get_power_action_readiness manage_power_action get_power_profile manage_power_profile
    """,
    "security": """
        get_kernel_security_posture get_linux_audit_status list_linux_audit_events
        summarize_linux_audit manage_linux_audit_rule list_apparmor_profiles manage_apparmor_profile
        list_selinux_booleans manage_selinux_boolean manage_selinux_context manage_selinux_fcontext_rule
        list_ima_measurements list_ima_policy list_tpm_devices list_tpm_event_log
        create_tpm_attestation
    """,
    "packages": """
        list_installed_packages manage_package manage_flatpak_package
        manage_snap_package manage_nix_profile_entry list_application_packages
        list_nix_profile_history manage_nix_profile_history
        list_python_environments list_python_environment_packages manage_python_environment
        list_native_package_environments list_native_environment_packages manage_native_package_environment
    """,
    "desktop": """
        observe_desktop list_windows get_window_detail get_focused_window
        list_workspaces list_outputs focus_window close_window resize_window
        minimize_window maximize_window switch_workspace move_window_to_workspace
        capture_screenshot inspect_accessibility_tree pointer_action keyboard_action touch_action
        list_desktop_apps launch_app read_clipboard write_clipboard send_notification
    """,
}

# A few tools belong to one product area and also expose capabilities assigned
# to another. Disabling either category should hide those shared tools.
_ADDITIONAL_TOOL_CATEGORIES: dict[str, frozenset[str]] = {
    # Arbitrary shell and PTY sessions can inspect network state directly, so
    # disabling networking also hides the generic command-execution surface.
    "run_shell_command": frozenset({"networking"}),
    "start_terminal_session": frozenset({"networking"}),
    "read_terminal_session": frozenset({"networking"}),
    "write_terminal_session": frozenset({"networking"}),
    "close_terminal_session": frozenset({"networking"}),
    # Starting/restarting these workloads can attach them to configured networks.
    "manage_container": frozenset({"networking"}),
    "manage_container_pod": frozenset({"networking"}),
    "manage_virtual_machine": frozenset({"networking"}),
    # Reverting a saved running snapshot can resume a network-connected guest.
    "manage_virtual_machine_snapshot": frozenset({"networking"}),
    # Host identity and generic udev records can expose the host name and
    # network-interface names/paths even though their primary area is broader.
    "get_linux_system_info": frozenset({"networking"}),
    # PCI/USB class codes can identify installed network adapters.
    "list_hardware_devices": frozenset({"networking"}),
    "list_udev_devices": frozenset({"networking"}),
    # Bluetooth device names and addresses are wireless-device metadata, and
    # pairing can create a Bluetooth connection; the network privacy filter
    # therefore hides both Bluetooth inventory and pairing controls.
    "list_bluetooth_devices": frozenset({"networking"}),
    "manage_bluetooth_pairing": frozenset({"networking"}),
    # These combined system-time tools expose or change NTP state as well as
    # timezone settings, so the networking category must hide them too.
    "get_time_settings": frozenset({"networking"}),
    "manage_time_settings": frozenset({"networking"}),
    # These process/NSS views can reveal or query network-backed state.
    "get_process_execution_context": frozenset({"networking"}),
    "list_namespace_inventory": frozenset({"networking"}),
    "lookup_nss_identity": frozenset({"networking"}),
    # SSSD domain names and enablement expose/configure remote identity sources.
    "list_sssd_domains": frozenset({"networking"}),
    "manage_sssd_domain": frozenset({"networking"}),
    # Marked cron and one-shot at commands execute arbitrary shell text later.
    "manage_cron_job": frozenset({"command_execution", "networking"}),
    "manage_at_job": frozenset({"command_execution", "networking"}),
    # Journal, traditional system logs, and audit records can include peer
    # addresses or hostnames even though their primary purpose is broader.
    "list_journal_entries": frozenset({"networking"}),
    "list_system_log_entries": frozenset({"networking"}),
    "get_linux_audit_status": frozenset({"networking"}),
    "list_linux_audit_events": frozenset({"networking"}),
    "summarize_linux_audit": frozenset({"networking"}),
    # The generic audit watch can monitor network configuration paths.
    "manage_linux_audit_rule": frozenset({"networking"}),
    # Network-backed mounts appear in generic filesystem/fstab inventory, and
    # the fstab mount action can activate one of those configured targets.
    "list_filesystems": frozenset({"networking"}),
    "list_fstab_entries": frozenset({"networking"}),
    "manage_mount": frozenset({"networking"}),
    # crypttab's allowlisted _netdev flag exposes network-backed mappings.
    "list_crypttab_entries": frozenset({"networking"}),
    "list_container_resources": frozenset({"networking"}),
    "manage_container_resource": frozenset({"networking"}),
    # Image references can disclose registry hosts, and pulls contact registries.
    "list_containers": frozenset({"networking"}),
    "list_container_images": frozenset({"networking"}),
    "manage_container_image": frozenset({"networking"}),
    # Container creation can publish ports or attach external-driver volumes,
    # and can mount host paths, so network and filesystem exclusions also hide it.
    "create_container": frozenset({"networking", "filesystem"}),
    # Image builds capture local filesystem contexts and may fetch/run networked steps.
    "build_container_image": frozenset({"filesystem", "networking"}),
    # Package transactions can contact configured repositories or registries.
    "manage_package": frozenset({"networking"}),
    "manage_flatpak_package": frozenset({"networking"}),
    "manage_snap_package": frozenset({"networking"}),
    "manage_nix_profile_entry": frozenset({"networking"}),
    "manage_python_environment": frozenset({"networking"}),
    "manage_native_package_environment": frozenset({"networking"}),
    "list_container_network_attachments": frozenset({"networking"}),
    "manage_container_network_attachment": frozenset({"networking"}),
    "list_libvirt_networks": frozenset({"networking"}),
    "create_libvirt_isolated_network": frozenset({"networking"}),
    "create_libvirt_network": frozenset({"networking"}),
    "configure_libvirt_network_ipv4": frozenset({"networking"}),
    "manage_libvirt_resource": frozenset({"networking"}),
    "list_remote_virtual_machines": frozenset({"networking"}),
    "manage_remote_virtual_machine": frozenset({"networking"}),
    "list_remote_virtual_machine_snapshots": frozenset({"networking"}),
    "manage_remote_virtual_machine_snapshot": frozenset({"networking"}),
    "attach_remote_virtual_machine_disk": frozenset({"networking"}),
    "create_remote_virtual_machine": frozenset({"networking"}),
    "configure_remote_virtual_machine": frozenset({"networking"}),
    "list_remote_libvirt_networks": frozenset({"networking"}),
    "list_remote_libvirt_storage": frozenset({"networking"}),
    "manage_remote_libvirt_resource": frozenset({"networking"}),
    "create_virtual_machine": frozenset({"networking"}),
    # System power profiles affect hardware power behavior as well as host power policy.
    "get_power_profile": frozenset({"hardware"}),
    "manage_power_profile": frozenset({"hardware"}),
    # Generic powercap constraints can govern CPU or platform power behavior.
    "list_powercap_limits": frozenset({"power"}),
    "manage_powercap_limit": frozenset({"power"}),
    # Userspace audio-server sinks/sources may be network tunnels.
    "list_audio_server_devices": frozenset({"networking"}),
    "manage_audio_endpoint": frozenset({"networking"}),
}

TOOL_CATEGORIES: dict[str, str] = {
    tool_name: category
    for category, tool_names in _TOOLS_BY_CATEGORY.items()
    for tool_name in tool_names.split()
}
TOOL_CATEGORY_MEMBERSHIPS: dict[str, frozenset[str]] = {
    tool_name: frozenset({category}) | _ADDITIONAL_TOOL_CATEGORIES.get(tool_name, frozenset())
    for category, tool_names in _TOOLS_BY_CATEGORY.items()
    for tool_name in tool_names.split()
}
CATEGORIES = tuple(_TOOLS_BY_CATEGORY)
_KNOWN_TOOLS = frozenset(TOOL_CATEGORIES)
_T = TypeVar("_T")


def _parse_csv(value: str, *, variable: str) -> frozenset[str]:
    names = frozenset(item.strip() for item in value.split(",") if item.strip())
    if any("\x00" in item for item in names):
        raise ValueError(f"{variable} contains an invalid NUL byte.")
    return names


def _validate_names(values: frozenset[str], known: frozenset[str], *, kind: str) -> None:
    unknown = sorted(values - known)
    if unknown:
        choices = ", ".join(unknown)
        raise ValueError(f"Unknown {kind}: {choices}")


@dataclass(frozen=True)
class ToolSelection:
    """Startup exclusions, with explicit tool exceptions.

    A shared tool is excluded if any of its category memberships is disabled.
    """

    disabled_categories: frozenset[str] = frozenset()
    enabled_categories: frozenset[str] = frozenset()
    disabled_tools: frozenset[str] = frozenset()
    enabled_tools: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _validate_names(self.disabled_categories | self.enabled_categories, frozenset(CATEGORIES), kind="tool category")
        _validate_names(self.disabled_tools | self.enabled_tools, _KNOWN_TOOLS, kind="tool name")
        if self.disabled_categories & self.enabled_categories:
            raise ValueError("A category cannot be both enabled and disabled.")
        if self.disabled_tools & self.enabled_tools:
            raise ValueError("A tool cannot be both enabled and disabled.")

    @classmethod
    def from_environment(cls) -> ToolSelection:
        disabled_categories = _parse_csv(
            os.environ.get("LINUX_MCP_DISABLE_CATEGORIES", ""),
            variable="LINUX_MCP_DISABLE_CATEGORIES",
        )
        enabled_categories = _parse_csv(
            os.environ.get("LINUX_MCP_ENABLE_CATEGORIES", ""),
            variable="LINUX_MCP_ENABLE_CATEGORIES",
        )
        disabled_tools = _parse_csv(
            os.environ.get("LINUX_MCP_DISABLE_TOOLS", ""),
            variable="LINUX_MCP_DISABLE_TOOLS",
        )
        enabled_tools = _parse_csv(
            os.environ.get("LINUX_MCP_ENABLE_TOOLS", ""),
            variable="LINUX_MCP_ENABLE_TOOLS",
        )
        values = {
            # At the environment layer, an explicit enable clears the matching
            # disable. CLI overrides are applied afterward and can make their
            # own explicit choice without mutating the source environment.
            "disabled_categories": disabled_categories - enabled_categories,
            "enabled_categories": enabled_categories,
            "disabled_tools": disabled_tools - enabled_tools,
            "enabled_tools": enabled_tools,
        }
        return cls(**values)

    def with_cli_overrides(
        self,
        *,
        disable_categories: list[str],
        enable_categories: list[str],
        disable_tools: list[str],
        enable_tools: list[str],
    ) -> ToolSelection:
        cli_disable_categories = frozenset(disable_categories)
        cli_enable_categories = frozenset(enable_categories)
        cli_disable_tools = frozenset(disable_tools)
        cli_enable_tools = frozenset(enable_tools)
        _validate_names(cli_disable_categories | cli_enable_categories, frozenset(CATEGORIES), kind="tool category")
        _validate_names(cli_disable_tools | cli_enable_tools, _KNOWN_TOOLS, kind="tool name")
        if cli_disable_categories & cli_enable_categories:
            raise ValueError("A category cannot be both enabled and disabled in command-line options.")
        if cli_disable_tools & cli_enable_tools:
            raise ValueError("A tool cannot be both enabled and disabled in command-line options.")
        disabled_categories = (self.disabled_categories | cli_disable_categories) - cli_enable_categories
        enabled_categories = (self.enabled_categories | cli_enable_categories) - cli_disable_categories
        disabled_tools = (self.disabled_tools | cli_disable_tools) - cli_enable_tools
        enabled_tools = (self.enabled_tools | cli_enable_tools) - cli_disable_tools
        return ToolSelection(disabled_categories, enabled_categories, disabled_tools, enabled_tools)

    def category_for(self, tool_name: str) -> str:
        try:
            return TOOL_CATEGORIES[tool_name]
        except KeyError as exc:
            raise RuntimeError(f"Tool {tool_name!r} has no startup category; add it to tool_config.py.") from exc

    def categories_for(self, tool_name: str) -> frozenset[str]:
        try:
            return TOOL_CATEGORY_MEMBERSHIPS[tool_name]
        except KeyError as exc:
            raise RuntimeError(f"Tool {tool_name!r} has no startup category; add it to tool_config.py.") from exc

    def is_enabled(self, tool_name: str) -> bool:
        if tool_name in self.enabled_tools:
            return True
        if tool_name in self.disabled_tools:
            return False
        memberships = self.categories_for(tool_name)
        return not bool(memberships & self.disabled_categories)

    def status_text(self) -> str:
        disabled: list[str] = []
        if self.disabled_categories:
            disabled.append("categories=" + ",".join(sorted(self.disabled_categories)))
        if self.disabled_tools:
            disabled.append("tools=" + ",".join(sorted(self.disabled_tools)))
        enabled_exceptions = self.enabled_categories | self.enabled_tools
        if enabled_exceptions:
            disabled.append("explicitly_enabled=" + ",".join(sorted(enabled_exceptions)))
        if not disabled:
            return "All registered tools are enabled."
        return "Startup tool selection: " + "; ".join(disabled) + "."


def selected_tool_decorator(server, selection: ToolSelection) -> Callable[..., Callable[[_T], _T]]:
    """Return a decorator that omits disabled tools from MCP registration."""
    register = server.tool

    def tool(*args, **kwargs):
        decorator = register(*args, **kwargs)
        declared_name = kwargs.get("name")

        def apply(fn: _T) -> _T:
            name = declared_name or getattr(fn, "__name__", None)
            if not isinstance(name, str):
                raise TypeError("MCP tools need an explicit name or a named function.")
            if selection.is_enabled(name):
                return decorator(fn)
            return fn

        return apply

    return tool
