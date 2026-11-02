from wayland_mcp.tools.discovery import get_session_capabilities
from wayland_mcp.tools.host import (
    get_linux_system_info,
    get_process_detail,
    get_resource_usage,
    list_filesystems,
    list_processes,
)
from wayland_mcp.tools.network import list_network_interfaces
from wayland_mcp.tools.pressure import get_pressure_stall_info
from wayland_mcp.tools.namespace_inventory import list_namespace_inventory
from wayland_mcp.tools.network_manager import list_network_manager_profiles
from wayland_mcp.tools.network_manager_dns import get_network_manager_profile_dns
from wayland_mcp.tools.network_manager_dns_control import (
    perform_network_manager_profile_dns_configuration as configure_network_manager_profile_dns,
)
from wayland_mcp.tools.xfs_control import perform_xfs_action as manage_xfs_filesystem
from wayland_mcp.tools.network_manager_control import (
    perform_network_manager_profile_action as manage_network_manager_profile,
)
from wayland_mcp.tools.systemd_network_profiles import list_systemd_network_profiles
from wayland_mcp.tools.systemd_network_profile_control import (
    configure_systemd_network_profile,
    create_systemd_network_profile,
)
from wayland_mcp.tools.services import list_services
from wayland_mcp.tools.openrc_startup import (
    list_openrc_runlevels,
    perform_openrc_startup_action as manage_openrc_service_startup,
)
from wayland_mcp.tools.runit_startup import perform_runit_startup_action as manage_runit_service_startup
from wayland_mcp.tools.s6_startup import perform_s6_startup_set as manage_s6_startup_set
from wayland_mcp.tools.systemd_timers import list_systemd_timers
from wayland_mcp.tools.timer_control import perform_systemd_timer_action as manage_systemd_timer
from wayland_mcp.tools.printers import list_printers
from wayland_mcp.tools.printer_control import perform_printer_action as manage_printer
from wayland_mcp.tools.cron_jobs import list_cron_jobs
from wayland_mcp.tools.fstab import list_fstab_entries
from wayland_mcp.tools.crypttab import list_crypttab_entries
from wayland_mcp.tools.accounts import list_local_groups, list_local_users
from wayland_mcp.tools.storage import list_block_devices, list_lvm_inventory, list_storage_topology
from wayland_mcp.tools.btrfs_snapshots import (
    list_btrfs_snapshots,
    perform_btrfs_snapshot_action as manage_btrfs_snapshot,
)
from wayland_mcp.tools.btrfs_control import perform_btrfs_filesystem_action as manage_btrfs_filesystem
from wayland_mcp.tools.mount_control import perform_mount_action as manage_mount
from wayland_mcp.tools.kernel import list_kernel_modules
from wayland_mcp.tools.kernel_parameters import (
    list_kernel_parameters,
    perform_kernel_parameter_change as manage_kernel_parameter,
)
from wayland_mcp.tools.kernel_parameter_persistence import (
    perform_persistent_kernel_parameter_change as manage_persistent_kernel_parameter,
)
from wayland_mcp.tools.security import get_kernel_security_posture
from wayland_mcp.tools.audit import perform_audit_watch_rule_action as manage_linux_audit_rule
from wayland_mcp.tools.apparmor import list_apparmor_profiles
from wayland_mcp.tools.selinux_booleans import (
    list_selinux_booleans,
    perform_selinux_boolean_action as manage_selinux_boolean,
)
from wayland_mcp.tools.selinux_context import perform_selinux_context_restore as manage_selinux_context
from wayland_mcp.tools.selinux_context import perform_selinux_fcontext_rule_action as manage_selinux_fcontext_rule
from wayland_mcp.tools.ima import list_ima_measurements
from wayland_mcp.tools.ima_policy import list_ima_policy
from wayland_mcp.tools.tpm import list_tpm_devices
from wayland_mcp.tools.tpm_event_log import list_tpm_event_log
from wayland_mcp.tools.firewall_frontends import list_firewall_frontends
from wayland_mcp.tools.firewall_control import perform_firewall_rule_action as manage_firewall_rule
from wayland_mcp.tools.firewalld_control import perform_firewalld_port_action as manage_firewalld_port
from wayland_mcp.tools.firewalld_icmp_control import perform_firewalld_icmp_block_action as manage_firewalld_icmp_block
from wayland_mcp.tools.firewalld_service_control import perform_firewalld_service_action as manage_firewalld_service
from wayland_mcp.tools.firewalld_rich_rule_control import perform_firewalld_rich_rule_action as manage_firewalld_rich_rule
from wayland_mcp.tools.ufw_control import perform_ufw_port_rule_action as manage_ufw_port_rule
from wayland_mcp.tools.packages import list_installed_packages
from wayland_mcp.tools.package_control import perform_package_action as manage_package
from wayland_mcp.tools.application_package_control import perform_flatpak_package_action as manage_flatpak_package
from wayland_mcp.tools.snap_package_control import perform_snap_package_action as manage_snap_package
from wayland_mcp.tools.nix_profile_control import perform_nix_profile_action as manage_nix_profile_entry
from wayland_mcp.tools.nix_profile_history import (
    list_nix_profile_history,
    perform_nix_profile_history_action as manage_nix_profile_history,
)
from wayland_mcp.tools.python_environments import (
    list_python_environment_packages,
    list_python_environments,
    perform_python_environment_action as manage_python_environment,
)
from wayland_mcp.tools.native_package_environments import (
    list_native_environment_packages,
    list_native_package_environments,
    perform_native_package_environment_action as manage_native_package_environment,
)
from wayland_mcp.tools.sockets import list_network_sockets
from wayland_mcp.tools.routes import list_network_routes
from wayland_mcp.tools.route_lookup import lookup_network_route
from wayland_mcp.tools.audio_control import perform_audio_endpoint_action as manage_audio_endpoint
from wayland_mcp.tools.route_control import perform_route_action as manage_network_route
from wayland_mcp.tools.journal import list_journal_entries
from wayland_mcp.tools.boot import list_boot_targets
from wayland_mcp.tools.time_settings import (
    get_time_settings,
    list_time_zones,
    perform_time_action as manage_time_settings,
)
from wayland_mcp.tools.time_sync import get_time_sync_status
from wayland_mcp.tools.dns_configuration import get_dns_configuration
from wayland_mcp.tools.virtual_machines import (
    list_virtual_machines,
    perform_virtual_machine_action as manage_virtual_machine,
)
from wayland_mcp.tools.libvirt_resources import (
    list_libvirt_networks,
    list_libvirt_storage,
    perform_libvirt_resource_action as manage_libvirt_resource,
    perform_libvirt_volume_create as create_libvirt_storage_volume,
)
from wayland_mcp.tools.radios import (
    list_radio_devices,
    perform_radio_device_action as manage_radio_device,
)
from wayland_mcp.tools.bluetooth import (
    list_bluetooth_devices,
    perform_bluetooth_pairing as manage_bluetooth_pairing,
)
from wayland_mcp.tools.hardware import list_hardware_devices
from wayland_mcp.tools.filesystem import (
    inspect_path,
    list_directory,
    list_path_extended_attributes,
    read_text_file,
)
from wayland_mcp.tools.filesystem_write import create_text_file
from wayland_mcp.tools.filesystem_write import delete_text_file
from wayland_mcp.tools.filesystem_write import replace_text_file
from wayland_mcp.tools.filesystem_uploads import (
    abort_binary_file_upload,
    append_binary_file_upload,
    begin_binary_file_upload,
    commit_binary_file_upload,
)
from wayland_mcp.tools.filesystem_permissions import set_file_mode
from wayland_mcp.tools.cpu import list_cpu_inventory
from wayland_mcp.tools.numa import list_numa_nodes
from wayland_mcp.tools.windows import list_windows, get_focused_window
from wayland_mcp.tools.management import (
    focus_window,
    close_window,
    switch_workspace,
    move_window_to_workspace,
)
from wayland_mcp.tools.vision import capture_screenshot
from wayland_mcp.a11y.atspi import inspect_accessibility_tree

__all__ = [
    "get_session_capabilities",
    "get_linux_system_info",
    "get_resource_usage",
    "get_pressure_stall_info",
    "list_namespace_inventory",
    "list_processes",
    "get_process_detail",
    "list_filesystems",
    "list_network_interfaces",
    "list_network_manager_profiles",
    "get_network_manager_profile_dns",
    "configure_network_manager_profile_dns",
    "manage_xfs_filesystem",
    "list_systemd_network_profiles",
    "configure_systemd_network_profile",
    "create_systemd_network_profile",
    "list_services",
    "list_openrc_runlevels",
    "manage_openrc_service_startup",
    "manage_runit_service_startup",
    "manage_s6_startup_set",
    "list_systemd_timers",
    "manage_systemd_timer",
    "list_printers",
    "manage_printer",
    "list_cron_jobs",
    "list_fstab_entries",
    "list_crypttab_entries",
    "list_local_users",
    "list_local_groups",
    "list_block_devices",
    "list_storage_topology",
    "list_lvm_inventory",
    "list_btrfs_snapshots",
    "manage_btrfs_snapshot",
    "manage_btrfs_filesystem",
    "manage_mount",
    "list_kernel_modules",
    "list_kernel_parameters",
    "manage_kernel_parameter",
    "manage_persistent_kernel_parameter",
    "list_firewall_frontends",
    "get_kernel_security_posture",
    "manage_linux_audit_rule",
    "list_apparmor_profiles",
    "list_selinux_booleans",
    "manage_selinux_boolean",
    "manage_selinux_context",
    "manage_selinux_fcontext_rule",
    "list_ima_measurements",
    "list_ima_policy",
    "list_tpm_devices",
    "list_tpm_event_log",
    "list_installed_packages",
    "manage_package",
    "manage_flatpak_package",
    "manage_snap_package",
    "manage_nix_profile_entry",
    "list_nix_profile_history",
    "manage_nix_profile_history",
    "list_python_environments",
    "list_python_environment_packages",
    "manage_python_environment",
    "list_native_package_environments",
    "list_native_environment_packages",
    "manage_native_package_environment",
    "manage_firewalld_port",
    "manage_firewalld_icmp_block",
    "manage_firewalld_service",
    "manage_firewalld_rich_rule",
    "manage_ufw_port_rule",
    "list_network_sockets",
    "list_network_routes",
    "lookup_network_route",
    "manage_audio_endpoint",
    "list_journal_entries",
    "list_boot_targets",
    "get_time_settings",
    "get_time_sync_status",
    "get_dns_configuration",
    "list_time_zones",
    "manage_time_settings",
    "list_virtual_machines",
    "manage_virtual_machine",
    "list_libvirt_networks",
    "list_libvirt_storage",
    "manage_libvirt_resource",
    "create_libvirt_storage_volume",
    "list_radio_devices",
    "manage_radio_device",
    "list_bluetooth_devices",
    "manage_bluetooth_pairing",
    "list_hardware_devices",
    "inspect_path",
    "list_path_extended_attributes",
    "list_directory",
    "read_text_file",
    "begin_binary_file_upload",
    "append_binary_file_upload",
    "commit_binary_file_upload",
    "abort_binary_file_upload",
    "create_text_file",
    "delete_text_file",
    "replace_text_file",
    "set_file_mode",
    "list_cpu_inventory",
    "list_numa_nodes",
    "list_windows",
    "get_focused_window",
    "focus_window",
    "close_window",
    "switch_workspace",
    "move_window_to_workspace",
    "capture_screenshot",
    "inspect_accessibility_tree",
]
