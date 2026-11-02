"""MCP stdio server and complete tool registration."""

from __future__ import annotations

import asyncio
import argparse
import hashlib
import json
import stat
import sys
from contextlib import asynccontextmanager
from typing import Annotated, Literal
from pydantic import Field as PydanticField, SecretStr, StrictInt

from mcp.server.mcpserver import Elicit, ElicitationResult, Image, MCPServer, Resolve
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, ImageContent, TextContent

from wayland_mcp.models import (
    AccessibilityTreeResponse,
    ACLWriteEntry,
    BinaryFileReadResponse,
    BinaryFileWriteConfirmation,
    BinaryFileWriteResponse,
    BinaryFileUploadConfirmation,
    BinaryFileUploadResponse,
    CommandExecutionConfirmation,
    CommandExecutionResponse,
    TerminalSessionConfirmation,
    TerminalSessionCloseResponse,
    TerminalSessionOutputResponse,
    TerminalSessionStartResponse,
    TerminalSessionWriteResponse,
    AudioEndpointActionConfirmation,
    AudioEndpointActionResponse,
    AppArmorProfileListResponse,
    AppArmorProfileActionConfirmation,
    AppArmorProfileActionResponse,
    SELinuxBooleanListResponse,
    SELinuxBooleanActionConfirmation,
    SELinuxBooleanActionResponse,
    SELinuxContextRestoreConfirmation,
    SELinuxContextRestoreResponse,
    SELinuxFContextRuleConfirmation,
    SELinuxFContextRuleResponse,
    AudioInventoryResponse,
    AudioServerInventoryResponse,
    ActionResult,
    ApplicationPackageInventoryResponse,
    ApplicationPackageActionConfirmation,
    ApplicationPackageActionResponse,
    SnapPackageActionConfirmation,
    SnapPackageActionResponse,
    NixProfileActionConfirmation,
    NixProfileActionResponse,
    NixProfileHistoryActionConfirmation,
    NixProfileHistoryActionResponse,
    NixProfileHistoryListResponse,
    PythonEnvironmentActionConfirmation,
    PythonEnvironmentActionResponse,
    PythonEnvironmentListResponse,
    PythonEnvironmentPackageListResponse,
    NativePackageEnvironmentActionConfirmation,
    NativePackageEnvironmentActionResponse,
    NativePackageEnvironmentListResponse,
    NativeEnvironmentPackageListResponse,
    AppLaunchResult,
    AppListResponse,
    BootTargetActionResponse,
    BootTargetConfirmation,
    BootTargetListResponse,
    TimeActionResponse,
    TimeSyncStatusResponse,
    TimeSettingsActionConfirmation,
    TimeSettingsResponse,
    TimeZoneListResponse,
    BlockDeviceHealthResponse,
    BlockDeviceIOStatsResponse,
    BlockDeviceListResponse,
    StorageTopologyResponse,
    LVMInventoryResponse,
    LVMVolumeActionConfirmation,
    LVMVolumeActionResponse,
    LVMVolumeGroupActionConfirmation,
    LVMVolumeGroupActionResponse,
    BtrfsSnapshotListResponse,
    BtrfsSnapshotActionConfirmation,
    BtrfsSnapshotActionResponse,
    MDRaidActionConfirmation,
    MDRaidActionResponse,
    LUKSActionConfirmation,
    LUKSActionResponse,
    LUKSHeaderActionConfirmation,
    LUKSHeaderActionResponse,
    LUKSTokenActionConfirmation,
    LUKSTokenActionResponse,
    LUKSTokenListResponse,
    BtrfsFilesystemActionConfirmation,
    BtrfsFilesystemActionResponse,
    Ext4FilesystemActionConfirmation,
    Ext4FilesystemActionResponse,
    XFSFilesystemActionConfirmation,
    XFSFilesystemActionResponse,
    CapabilitiesResponse,
    ClipboardContent,
    ClipboardWriteResult,
    AtJobActionConfirmation,
    AtJobActionResponse,
    CronJobListResponse,
    CronJobActionConfirmation,
    CronJobActionResponse,
    CrypttabEntryListResponse,
    FstabEntryListResponse,
    ContainerActionConfirmation,
    ContainerActionResponse,
    ContainerCreateConfirmation,
    ContainerCreateResponse,
    ContainerListResponse,
    ContainerImageListResponse,
    ContainerImageActionConfirmation,
    ContainerImageActionResponse,
    ContainerImageBuildConfirmation,
    ContainerImageBuildResponse,
    ContainerNetworkAttachmentActionResponse,
    ContainerNetworkAttachmentConfirmation,
    ContainerNetworkAttachmentResponse,
    ContainerResourceListResponse,
    ContainerResourceActionConfirmation,
    ContainerResourceActionResponse,
    ContainerPodListResponse,
    ContainerPodActionConfirmation,
    ContainerPodActionResponse,
    LibvirtNetworkListResponse,
    LibvirtNetworkCreateConfirmation,
    LibvirtNetworkDefinitionConfirmation,
    LibvirtNetworkIPv4ConfigurationConfirmation,
    LibvirtNetworkIPv4ConfigurationResponse,
    LibvirtNetworkCreateResponse,
    LibvirtResourceActionConfirmation,
    LibvirtResourceActionResponse,
    LibvirtStorageInventoryResponse,
    LibvirtVolumeCreateConfirmation,
    LibvirtVolumeCreateResponse,
    VirtualMachineActionConfirmation,
    VirtualMachineActionResponse,
    RemoteVirtualMachineActionConfirmation,
    RemoteVirtualMachineActionResponse,
    RemoteVirtualMachineDiskAttachConfirmation,
    RemoteVirtualMachineDiskAttachResponse,
    RemoteVirtualMachineCreateConfirmation,
    RemoteVirtualMachineCreateResponse,
    RemoteVirtualMachineConfigConfirmation,
    RemoteVirtualMachineConfigResponse,
    RemoteVirtualMachineListResponse,
    RemoteLibvirtNetworkListResponse,
    RemoteLibvirtStorageInventoryResponse,
    RemoteLibvirtResourceActionConfirmation,
    RemoteLibvirtResourceActionResponse,
    VirtualMachineCreateConfirmation,
    VirtualMachineCreateResponse,
    VirtualMachineConfigConfirmation,
    VirtualMachineConfigResponse,
    VirtualMachineDiskAttachConfirmation,
    VirtualMachineDiskAttachResponse,
    VirtualMachineListResponse,
    VirtualMachineSnapshotActionConfirmation,
    VirtualMachineSnapshotActionResponse,
    VirtualMachineSnapshotListResponse,
    CPUInventoryResponse,
    DesktopObservationResponse,
    DirectoryListResponse,
    DNSConfigurationResponse,
    FilesystemListResponse,
    MountActionConfirmation,
    MountActionResponse,
    FirewallInventoryResponse,
    FirewallRuleActionConfirmation,
    FirewallRuleActionResponse,
    FirewalldPortActionConfirmation,
    FirewalldPortActionResponse,
    FirewalldICMPBlockActionConfirmation,
    FirewalldICMPBlockActionResponse,
    FirewalldServiceActionConfirmation,
    FirewalldServiceActionResponse,
    FirewalldRichRuleActionConfirmation,
    FirewalldRichRuleActionResponse,
    FirewalldRichICMPRuleActionConfirmation,
    FirewalldRichICMPRuleActionResponse,
    FirewalldRichProtocolRuleActionConfirmation,
    FirewalldRichProtocolRuleActionResponse,
    UFWPortRuleActionConfirmation,
    UFWPortRuleActionResponse,
    FirewallFrontendInventoryResponse,
    GPUInventoryResponse,
    GPUPowerLimitListResponse,
    GPUPowerLimitActionConfirmation,
    GPUPowerLimitActionResponse,
    PowercapLimitListResponse,
    PowercapLimitActionConfirmation,
    PowercapLimitActionResponse,
    GPUFrequencyLimitListResponse,
    GPUFrequencyLimitConfirmation,
    GPUFrequencyLimitActionResponse,
    PathExtendedAttributeResponse,
    PathMetadataResponse,
    PackageAction,
    PackageActionConfirmation,
    PackageActionResponse,
    FocusedWindowResponse,
    HardwareDeviceListResponse,
    DisplayBacklightListResponse,
    DisplayBrightnessConfirmation,
    DisplayBrightnessResponse,
    UdevDeviceListResponse,
    InstalledPackageListResponse,
    IMAMeasurementListResponse,
    IMAPolicyListResponse,
    JournalEntryListResponse,
    KeyboardActionResult,
    KernelModuleListResponse,
    KernelModuleActionConfirmation,
    KernelModuleActionResponse,
    KernelModuleStartupConfirmation,
    KernelModuleStartupResponse,
    KernelParameterChangeConfirmation,
    KernelParameterChangeResponse,
    KernelParameterListResponse,
    KernelParameterPersistenceConfirmation,
    KernelParameterPersistenceResponse,
    KernelCommandLineConfirmation,
    KernelCommandLineResponse,
    InitramfsRebuildConfirmation,
    InitramfsRebuildResponse,
    LocalIdentityActionConfirmation,
    LocalIdentityActionResponse,
    LocalPasswordSetConfirmation,
    LocalPasswordSetResponse,
    LocalSSHKeyActionConfirmation,
    LocalSSHKeyActionResponse,
    SudoPolicyActionConfirmation,
    SudoPolicyActionResponse,
    SSSDDomainActionConfirmation,
    SSSDDomainActionResponse,
    SSSDDomainListResponse,
    PAMProfileActionConfirmation,
    PAMProfileActionResponse,
    PAMProfileListResponse,
    KernelSecurityPostureResponse,
    LinuxAuditEventListResponse,
    LinuxAuditSummaryResponse,
    LinuxAuditStatusResponse,
    LinuxAuditRuleActionConfirmation,
    LinuxAuditRuleActionResponse,
    LoginSessionListResponse,
    LocalGroupListResponse,
    LocalUserListResponse,
    LinuxSystemInfoResponse,
    NetworkAddressActionConfirmation,
    NetworkAddressActionResponse,
    NetworkRouteActionConfirmation,
    NetworkRouteActionResponse,
    NetworkInterfaceActionConfirmation,
    NetworkInterfaceActionResponse,
    NetworkInterfaceListResponse,
    BluetoothDeviceListResponse,
    BluetoothPairingConfirmation,
    BluetoothPairingResponse,
    RadioDeviceActionConfirmation,
    RadioDeviceActionResponse,
    RadioDeviceListResponse,
    NetworkManagerProfileListResponse,
    NetworkManagerProfileDNSResponse,
    NetworkManagerProfileDNSConfigConfirmation,
    NetworkManagerProfileDNSConfigResponse,
    NetworkManagerProfileIPResponse,
    NetworkManagerProfileIPConfigConfirmation,
    NetworkManagerProfileIPConfigResponse,
    NetworkManagerProfileRoutesResponse,
    NetworkManagerProfileRouteActionConfirmation,
    NetworkManagerProfileRouteActionResponse,
    NetworkManagerProfileActionConfirmation,
    NetworkManagerProfileActionResponse,
    NetworkManagerVirtualProfileCreateConfirmation,
    NetworkManagerVirtualProfileCreateResponse,
    NetworkManagerPortProfileCreateConfirmation,
    NetworkManagerPortProfileCreateResponse,
    NetworkManagerPortMembershipConfirmation,
    NetworkManagerPortMembershipResponse,
    NetworkManagerVPNImportConfirmation,
    NetworkManagerVPNImportResponse,
    SystemdNetworkProfileListResponse,
    SystemdNetworkProfileConfigConfirmation,
    SystemdNetworkProfileConfigResponse,
    SystemdNetworkProfileCreateConfirmation,
    SystemdNetworkProfileCreateResponse,
    SystemdNetworkProfileDeleteConfirmation,
    SystemdNetworkProfileDeleteResponse,
    SystemdNetDevConfigConfirmation,
    SystemdNetDevConfigResponse,
    SystemdNetDevCreateConfirmation,
    SystemdNetDevCreateResponse,
    SystemdNetDevDeleteConfirmation,
    SystemdNetDevDeleteResponse,
    NetworkAddressListResponse,
    NetworkProtocolStatsResponse,
    NetworkPolicySnapshotResponse,
    NetworkRouteListResponse,
    NetworkRouteLookupResponse,
    NetworkSocketListResponse,
    NamespaceInventoryResponse,
    NUMANodeListResponse,
    NSSIdentityLookupResponse,
    SocketOwnerListResponse,
    UnixRawSocketResponse,
    NotificationResult,
    TouchActionResult,
    OpenRCRunlevelListResponse,
    OpenRCServiceStartupConfirmation,
    OpenRCServiceStartupResponse,
    RunitServiceStartupConfirmation,
    RunitServiceStartupResponse,
    S6StartupSetConfirmation,
    S6StartupSetResponse,
    OutputListResponse,
    PointerActionResult,
    PressureStallInfoResponse,
    ProcessDetailResponse,
    ProcessCgroupHistoryResponse,
    ProcessExecutionContextResponse,
    ProcessListResponse,
    ProcessSignalConfirmation,
    ProcessSignalResponse,
    ProcessTreeResponse,
    ProcessResourceHistoryResponse,
    TPMInventoryResponse,
    TPMEventLogResponse,
    TPMAttestationConfirmation,
    TPMAttestationResponse,
    PrinterListResponse,
    PowerSupplyListResponse,
    PowerStateResponse,
    PowerInhibitorListResponse,
    PrinterActionConfirmation,
    PrinterActionResponse,
    PowerActionConfirmation,
    PowerActionReadinessResponse,
    PowerActionResponse,
    PowerProfileActionResponse,
    PowerProfileConfirmation,
    PowerProfileResponse,
    ResourceHistoryResponse,
    ResourceUsageResponse,
    ScreenshotResponse,
    SensorReadingListResponse,
    FanControlListResponse,
    FanControlActionConfirmation,
    FanControlActionResponse,
    ServiceActionConfirmation,
    ServiceActionResponse,
    ServiceListResponse,
    SystemdTimerActionConfirmation,
    SystemdTimerActionResponse,
    SystemdTimerDefinitionDeleteConfirmation,
    SystemdTimerDefinitionDeleteResponse,
    SystemdTimerDefinitionConfirmation,
    SystemdTimerDefinitionResponse,
    SystemdServiceDefinitionConfirmation,
    SystemdServiceDefinitionResponse,
    SystemdTimerListResponse,
    SystemLogListResponse,
    SystemLogSource,
    TextFileCreationConfirmation,
    TextFileCreationResponse,
    TextFileDeletionConfirmation,
    TextFileDeletionResponse,
    FileModeChangeConfirmation,
    FileModeChangeResponse,
    PathAdminConfirmation,
    PathAdminResponse,
    TextFileReplacementConfirmation,
    TextFileReplacementResponse,
    TextFileReadResponse,
    WindowDetailResponse,
    WindowListResponse,
    WorkspaceListResponse,
)
from wayland_mcp.tool_config import (
    CATEGORIES,
    TOOL_CATEGORIES,
    TOOL_CATEGORY_MEMBERSHIPS,
    ToolSelection,
    selected_tool_decorator,
)
from wayland_mcp.portal import remote_desktop_portal
from wayland_mcp.backends.kwin import kwin_script_client
from wayland_mcp.session import logger
from wayland_mcp.tools.apps import launch_app as _launch_app
from wayland_mcp.tools.apps import list_desktop_apps as _list_desktop_apps
from wayland_mcp.tools.discovery import get_session_capabilities_async as _get_session_capabilities
from wayland_mcp.tools.input import keyboard_action as _keyboard_action
from wayland_mcp.tools.input import pointer_action as _pointer_action
from wayland_mcp.tools.input import touch_action as _touch_action
from wayland_mcp.tools.management import (
    close_window as _close_window,
    focus_window as _focus_window,
    maximize_window as _maximize_window,
    minimize_window as _minimize_window,
    move_window_to_workspace as _move_window_to_workspace,
    resize_window as _resize_window,
    switch_workspace as _switch_workspace,
)
from wayland_mcp.tools.system import (
    read_clipboard as _read_clipboard,
    send_notification as _send_notification,
    write_clipboard as _write_clipboard,
)
from wayland_mcp.tools.vision import capture_screenshot as _capture_screenshot
from wayland_mcp.tools.windows import (
    get_focused_window as _get_focused_window,
    get_window_detail as _get_window_detail,
    list_windows as _list_windows,
    list_workspaces as _list_workspaces,
    observe_desktop as _observe_desktop,
)
from wayland_mcp.a11y.atspi import inspect_accessibility_tree as _inspect_accessibility_tree
from wayland_mcp.tools.host import (
    _detect_init_system,
    get_linux_system_info as _get_linux_system_info,
    get_process_detail as _get_process_detail,
    get_process_tree as _get_process_tree,
    get_resource_usage as _get_resource_usage,
    list_filesystems as _list_filesystems,
    list_processes as _list_processes,
)
from wayland_mcp.tools.network import list_network_interfaces as _list_network_interfaces
from wayland_mcp.tools.radios import (
    RadioDeviceAction,
    list_radio_devices as _list_radio_devices,
    perform_radio_device_action as _perform_radio_device_action,
    radio_action_confirmation_details as _radio_action_confirmation_details,
)
from wayland_mcp.tools.bluetooth import (
    bluetooth_pairing_confirmation_details as _bluetooth_pairing_confirmation_details,
    list_bluetooth_devices as _list_bluetooth_devices,
    perform_bluetooth_pairing as _perform_bluetooth_pairing,
)
from wayland_mcp.tools.pressure import get_pressure_stall_info as _get_pressure_stall_info
from wayland_mcp.tools.network_manager import list_network_manager_profiles as _list_network_manager_profiles
from wayland_mcp.tools.network_manager_dns import get_network_manager_profile_dns as _get_network_manager_profile_dns
from wayland_mcp.tools.network_manager_dns_control import (
    network_manager_profile_dns_confirmation_details as _network_manager_profile_dns_confirmation_details,
    perform_network_manager_profile_dns_configuration as _perform_network_manager_profile_dns_configuration,
)
from wayland_mcp.tools.network_manager_ip_control import (
    IPFamily as NetworkManagerIPFamily,
    IPMethod as NetworkManagerIPMethod,
    get_network_manager_profile_ip as _get_network_manager_profile_ip,
    network_manager_profile_ip_confirmation_details as _network_manager_profile_ip_confirmation_details,
    perform_network_manager_profile_ip_configuration as _perform_network_manager_profile_ip_configuration,
)
from wayland_mcp.tools.network_manager_profile_routes import (
    IPFamily as NetworkManagerRouteFamily,
    RouteAction as NetworkManagerRouteAction,
    get_network_manager_profile_routes as _get_network_manager_profile_routes,
    network_manager_profile_route_confirmation_details as _network_manager_profile_route_confirmation_details,
    perform_network_manager_profile_route_action as _perform_network_manager_profile_route_action,
)
from wayland_mcp.tools.network_manager_control import (
    NetworkManagerProfileAction,
    network_manager_profile_confirmation_details as _network_manager_profile_confirmation_details,
    perform_network_manager_profile_action as _perform_network_manager_profile_action,
)
from wayland_mcp.tools.network_manager_virtual_profiles import (
    BondMode as NetworkManagerBondMode,
    VirtualProfileKind as NetworkManagerVirtualProfileKind,
    network_manager_virtual_profile_confirmation_details as _network_manager_virtual_profile_confirmation_details,
    perform_network_manager_virtual_profile_creation as _perform_network_manager_virtual_profile_creation,
    network_manager_port_profile_confirmation_details as _network_manager_port_profile_confirmation_details,
    perform_network_manager_port_profile_creation as _perform_network_manager_port_profile_creation,
    network_manager_port_membership_confirmation_details as _network_manager_port_membership_confirmation_details,
    perform_network_manager_port_membership_action as _perform_network_manager_port_membership_action,
)
from wayland_mcp.tools.network_manager_vpn_control import (
    VPNType as NetworkManagerVPNType,
    network_manager_vpn_import_confirmation_details as _network_manager_vpn_import_confirmation_details,
    perform_network_manager_vpn_import as _perform_network_manager_vpn_import,
)
from wayland_mcp.tools.systemd_network_profiles import list_systemd_network_profiles as _list_systemd_network_profiles
from wayland_mcp.tools.systemd_network_profile_control import (
    configure_systemd_network_profile as _configure_systemd_network_profile,
    systemd_network_profile_confirmation_details as _systemd_network_profile_confirmation_details,
    create_systemd_network_profile as _create_systemd_network_profile,
    systemd_network_profile_creation_confirmation_details as _systemd_network_profile_creation_confirmation_details,
    delete_systemd_network_profile as _delete_systemd_network_profile,
    systemd_network_profile_deletion_confirmation_details as _systemd_network_profile_deletion_confirmation_details,
)
from wayland_mcp.tools.systemd_network_device_control import (
    BondMode as SystemdBondMode,
    DeviceKind as SystemdNetDevKind,
    configure_systemd_netdev_profile as _configure_systemd_netdev_profile,
    create_systemd_netdev_profile as _create_systemd_netdev_profile,
    delete_systemd_netdev_profile as _delete_systemd_netdev_profile,
    systemd_netdev_config_confirmation_details as _systemd_netdev_config_confirmation_details,
    systemd_netdev_creation_confirmation_details as _systemd_netdev_creation_confirmation_details,
    systemd_netdev_deletion_confirmation_details as _systemd_netdev_deletion_confirmation_details,
)
from wayland_mcp.tools.network_control import (
    NetworkAddressAction,
    NetworkInterfaceAction,
    address_action_confirmation_details as _address_action_confirmation_details,
    interface_action_confirmation_details as _interface_action_confirmation_details,
    perform_address_action as _perform_address_action,
    perform_interface_action as _perform_interface_action,
)
from wayland_mcp.tools.network_stats import list_network_protocol_stats as _list_network_protocol_stats
from wayland_mcp.tools.network_details import (
    list_network_addresses as _list_network_addresses,
    list_network_policy as _list_network_policy,
)
from wayland_mcp.tools.dns_configuration import get_dns_configuration as _get_dns_configuration
from wayland_mcp.tools.firewall import list_firewall_rules as _list_firewall_rules
from wayland_mcp.tools.firewall_control import (
    FirewallFamily,
    FirewallRuleAction,
    firewall_rule_confirmation_details as _firewall_rule_confirmation_details,
    perform_firewall_rule_action as _perform_firewall_rule_action,
)
from wayland_mcp.tools.firewall_frontends import list_firewall_frontends as _list_firewall_frontends
from wayland_mcp.tools.firewalld_control import (
    FirewalldConfiguration as FirewalldConfigurationName,
    FirewalldPortAction as FirewalldPortActionName,
    firewalld_port_action_confirmation_details as _firewalld_port_action_confirmation_details,
    perform_firewalld_port_action as _perform_firewalld_port_action,
)
from wayland_mcp.tools.firewalld_icmp_control import (
    FirewalldICMPBlockAction as FirewalldICMPBlockActionName,
    firewalld_icmp_block_confirmation_details as _firewalld_icmp_block_confirmation_details,
    perform_firewalld_icmp_block_action as _perform_firewalld_icmp_block_action,
)
from wayland_mcp.tools.firewalld_service_control import (
    FirewalldServiceAction as FirewalldServiceActionName,
    firewalld_service_action_confirmation_details as _firewalld_service_action_confirmation_details,
    perform_firewalld_service_action as _perform_firewalld_service_action,
)
from wayland_mcp.tools.firewalld_rich_rule_control import (
    FirewalldRichRuleAction as FirewalldRichRuleActionName,
    FirewalldRichRuleLogLevel as FirewalldRichRuleLogLevelName,
    FirewalldRichRuleVerdict as FirewalldRichRuleVerdictName,
    firewalld_rich_rule_confirmation_details as _firewalld_rich_rule_confirmation_details,
    perform_firewalld_rich_rule_action as _perform_firewalld_rich_rule_action,
)
from wayland_mcp.tools.firewalld_rich_icmp_control import (
    FirewalldRichICMPRuleAction as FirewalldRichICMPRuleActionName,
    FirewalldRichICMPRuleVerdict as FirewalldRichICMPRuleVerdictName,
    FirewalldRichICMPRuleLogLevel as FirewalldRichICMPRuleLogLevelName,
    firewalld_rich_icmp_rule_confirmation_details as _firewalld_rich_icmp_rule_confirmation_details,
    perform_firewalld_rich_icmp_rule_action as _perform_firewalld_rich_icmp_rule_action,
)
from wayland_mcp.tools.firewalld_rich_protocol_control import (
    FirewalldRichProtocolRuleAction as FirewalldRichProtocolRuleActionName,
    FirewalldRichProtocolRuleLogLevel as FirewalldRichProtocolRuleLogLevelName,
    FirewalldRichProtocolRuleVerdict as FirewalldRichProtocolRuleVerdictName,
    firewalld_rich_protocol_rule_confirmation_details as _firewalld_rich_protocol_rule_confirmation_details,
    perform_firewalld_rich_protocol_rule_action as _perform_firewalld_rich_protocol_rule_action,
)
from wayland_mcp.tools.ufw_control import (
    UFWPortRuleAction as UFWPortRuleActionName,
    _canonical_address as _canonical_ufw_address,
    ufw_port_rule_confirmation_details as _ufw_port_rule_confirmation_details,
    perform_ufw_port_rule_action as _perform_ufw_port_rule_action,
)
from wayland_mcp.tools.services import (
    list_services as _list_services,
    perform_service_action as _perform_service_action,
    validate_service_action as _validate_service_action,
)
from wayland_mcp.tools.openrc_startup import (
    list_openrc_runlevels as _list_openrc_runlevels,
    openrc_startup_confirmation_details as _openrc_startup_confirmation_details,
    perform_openrc_startup_action as _perform_openrc_startup_action,
)
from wayland_mcp.tools.runit_startup import (
    runit_startup_confirmation_details as _runit_startup_confirmation_details,
    perform_runit_startup_action as _perform_runit_startup_action,
)
from wayland_mcp.tools.s6_startup import (
    s6_startup_confirmation_details as _s6_startup_confirmation_details,
    perform_s6_startup_set as _perform_s6_startup_set,
)
from wayland_mcp.tools.systemd_timers import list_systemd_timers as _list_systemd_timers
from wayland_mcp.tools.timer_control import (
    perform_systemd_timer_action as _perform_systemd_timer_action,
    timer_action_confirmation_details as _timer_action_confirmation_details,
)
from wayland_mcp.tools.systemd_timer_definition import (
    perform_systemd_timer_definition_deletion as _perform_systemd_timer_definition_deletion,
    perform_systemd_timer_definition as _perform_systemd_timer_definition,
    timer_definition_deletion_confirmation_details as _timer_definition_deletion_confirmation_details,
    timer_definition_confirmation_details as _timer_definition_confirmation_details,
)
from wayland_mcp.tools.systemd_service_definition import (
    perform_systemd_service_definition as _perform_systemd_service_definition,
    service_definition_confirmation_details as _service_definition_confirmation_details,
)
from wayland_mcp.tools.cron_jobs import list_cron_jobs as _list_cron_jobs
from wayland_mcp.tools.cron_control import (
    CronJobAction as CronJobActionName,
    cron_job_action_confirmation_details as _cron_job_action_confirmation_details,
    perform_cron_job_action as _perform_cron_job_action,
)
from wayland_mcp.tools.at_control import (
    AtJobAction as AtJobActionName,
    at_job_confirmation_details as _at_job_confirmation_details,
    perform_at_job_action as _perform_at_job_action,
)
from wayland_mcp.tools.fstab import list_fstab_entries as _list_fstab_entries
from wayland_mcp.tools.crypttab import list_crypttab_entries as _list_crypttab_entries
from wayland_mcp.tools.accounts import (
    list_local_groups as _list_local_groups,
    list_local_users as _list_local_users,
    lookup_nss_identity as _lookup_nss_identity,
)
from wayland_mcp.tools.accounts_control import (
    LocalIdentityAction as LocalIdentityActionName,
    local_identity_action_confirmation_details as _local_identity_action_confirmation_details,
    perform_local_identity_action as _perform_local_identity_action,
)
from wayland_mcp.tools.local_passwords import (
    local_password_control_available as _local_password_control_available,
    local_password_set_confirmation_details as _local_password_set_confirmation_details,
    perform_local_password_set as _perform_local_password_set,
)
from wayland_mcp.tools.local_ssh_keys import (
    SSHKeyAction as SSHKeyActionName,
    local_ssh_key_confirmation_details as _local_ssh_key_confirmation_details,
    perform_local_ssh_key_action as _perform_local_ssh_key_action,
)
from wayland_mcp.tools.sudo_policy import (
    SudoPolicyAction as SudoPolicyActionName,
    sudo_group_policy_confirmation_details as _sudo_group_policy_confirmation_details,
    sudo_policy_confirmation_details as _sudo_policy_confirmation_details,
    perform_sudo_policy_action as _perform_sudo_policy_action,
)
from wayland_mcp.tools.sssd_config import (
    SSSDDomainAction as SSSDDomainActionName,
    list_sssd_domains as _list_sssd_domains,
    sssd_domain_confirmation_details as _sssd_domain_confirmation_details,
    perform_sssd_domain_action as _perform_sssd_domain_action,
)
from wayland_mcp.tools.pam_profiles import (
    PAMProfileAction as PAMProfileActionName,
    list_pam_profiles as _list_pam_profiles,
    pam_profile_confirmation_details as _pam_profile_confirmation_details,
    perform_pam_profile_action as _perform_pam_profile_action,
)
from wayland_mcp.tools.storage import (
    list_block_devices as _list_block_devices,
    list_lvm_inventory as _list_lvm_inventory,
    list_storage_topology as _list_storage_topology,
)
from wayland_mcp.tools.lvm_control import (
    LVMVolumeGroupAction as LVMVolumeGroupActionName,
    LVMVolumeAction as LVMVolumeActionName,
    lvm_volume_action_confirmation_details as _lvm_volume_action_confirmation_details,
    perform_lvm_volume_action as _perform_lvm_volume_action,
    lvm_group_action_confirmation_details as _lvm_group_action_confirmation_details,
    perform_lvm_group_action as _perform_lvm_group_action,
)
from wayland_mcp.tools.btrfs_snapshots import (
    BtrfsSnapshotAction as BtrfsSnapshotActionName,
    btrfs_snapshot_action_confirmation_details as _btrfs_snapshot_action_confirmation_details,
    list_btrfs_snapshots as _list_btrfs_snapshots,
    perform_btrfs_snapshot_action as _perform_btrfs_snapshot_action,
)
from wayland_mcp.tools.luks_control import (
    LUKSAction as LUKSActionName,
    LUKSVersion as LUKSVersionName,
    LUKSHeaderAction as LUKSHeaderActionName,
    luks_action_confirmation_details as _luks_action_confirmation_details,
    perform_luks_action as _perform_luks_action,
    luks_header_action_confirmation_details as _luks_header_action_confirmation_details,
    perform_luks_header_action as _perform_luks_header_action,
)
from wayland_mcp.tools.luks_tokens import (
    LUKSTokenAction as LUKSTokenActionName,
    list_luks_tokens as _list_luks_tokens,
    luks_token_confirmation_details as _luks_token_confirmation_details,
    perform_luks_token_action as _perform_luks_token_action,
)
from wayland_mcp.tools.ext4_control import (
    Ext4FilesystemAction as Ext4FilesystemActionName,
    ext4_action_confirmation_details as _ext4_action_confirmation_details,
    perform_ext4_action as _perform_ext4_action,
)
from wayland_mcp.tools.xfs_control import (
    XFSFilesystemAction as XFSFilesystemActionName,
    perform_xfs_action as _perform_xfs_action,
    xfs_action_confirmation_details as _xfs_action_confirmation_details,
)
from wayland_mcp.tools.btrfs_control import (
    BtrfsFilesystemAction as BtrfsFilesystemActionName,
    btrfs_action_confirmation_details as _btrfs_filesystem_action_confirmation_details,
    perform_btrfs_filesystem_action as _perform_btrfs_filesystem_action,
)
from wayland_mcp.tools.raid_control import (
    MDRaidAction as MDRaidActionName,
    md_raid_action_confirmation_details as _md_raid_action_confirmation_details,
    perform_md_raid_action as _perform_md_raid_action,
)
from wayland_mcp.tools.mount_control import (
    MountAction as MountActionName,
    mount_action_confirmation_details as _mount_action_confirmation_details,
    perform_mount_action as _perform_mount_action,
)
from wayland_mcp.tools.block_stats import list_block_device_stats as _list_block_device_stats
from wayland_mcp.tools.block_health import get_block_device_health as _get_block_device_health
from wayland_mcp.tools.kernel import list_kernel_modules as _list_kernel_modules
from wayland_mcp.tools.kernel_control import (
    KernelModuleAction as KernelModuleActionName,
    kernel_module_action_confirmation_details as _kernel_module_action_confirmation_details,
    perform_kernel_module_action as _perform_kernel_module_action,
)
from wayland_mcp.tools.kernel_module_startup import (
    KernelModuleStartupAction as KernelModuleStartupActionName,
    kernel_module_startup_confirmation_details as _kernel_module_startup_confirmation_details,
    perform_kernel_module_startup_action as _perform_kernel_module_startup_action,
)
from wayland_mcp.tools.kernel_parameters import (
    kernel_parameter_confirmation_details as _kernel_parameter_confirmation_details,
    list_kernel_parameters as _list_kernel_parameters,
    perform_kernel_parameter_change as _perform_kernel_parameter_change,
)
from wayland_mcp.tools.kernel_parameter_persistence import (
    KernelParameterPersistenceAction as KernelParameterPersistenceActionName,
    persistent_kernel_parameter_confirmation_details as _persistent_kernel_parameter_confirmation_details,
    perform_persistent_kernel_parameter_change as _perform_persistent_kernel_parameter_change,
)
from wayland_mcp.tools.kernel_command_line import (
    KernelCommandLineAction as KernelCommandLineActionName,
    kernel_command_line_confirmation_details as _kernel_command_line_confirmation_details,
    perform_kernel_command_line_change as _perform_kernel_command_line_change,
)
from wayland_mcp.tools.initramfs_control import (
    initramfs_rebuild_confirmation_details as _initramfs_rebuild_confirmation_details,
    perform_initramfs_rebuild as _perform_initramfs_rebuild,
)
from wayland_mcp.tools.tpm_attestation import (
    perform_tpm_attestation as _perform_tpm_attestation,
    tpm_attestation_confirmation_details as _tpm_attestation_confirmation_details,
)
from wayland_mcp.tools.security import get_kernel_security_posture as _get_kernel_security_posture
from wayland_mcp.tools.audit import (
    get_linux_audit_status as _get_linux_audit_status,
    audit_watch_rule_confirmation_details as _audit_watch_rule_confirmation_details,
    list_linux_audit_events as _list_linux_audit_events,
    perform_audit_watch_rule_action as _perform_audit_watch_rule_action,
    summarize_linux_audit as _summarize_linux_audit,
)
from wayland_mcp.tools.apparmor import list_apparmor_profiles as _list_apparmor_profiles
from wayland_mcp.tools.apparmor_control import (
    apparmor_profile_confirmation_details as _apparmor_profile_confirmation_details,
    perform_apparmor_profile_action as _perform_apparmor_profile_action,
)
from wayland_mcp.tools.selinux_booleans import list_selinux_booleans as _list_selinux_booleans
from wayland_mcp.tools.selinux_booleans import (
    perform_selinux_boolean_action as _perform_selinux_boolean_action,
    selinux_boolean_confirmation_details as _selinux_boolean_confirmation_details,
)
from wayland_mcp.tools.selinux_context import (
    perform_selinux_context_restore as _perform_selinux_context_restore,
    selinux_context_restore_confirmation_details as _selinux_context_restore_confirmation_details,
    perform_selinux_fcontext_rule_action as _perform_selinux_fcontext_rule_action,
    selinux_fcontext_rule_confirmation_details as _selinux_fcontext_rule_confirmation_details,
)
from wayland_mcp.tools.ima import list_ima_measurements as _list_ima_measurements
from wayland_mcp.tools.ima_policy import list_ima_policy as _list_ima_policy
from wayland_mcp.tools.tpm import list_tpm_devices as _list_tpm_devices
from wayland_mcp.tools.tpm_event_log import list_tpm_event_log as _list_tpm_event_log
from wayland_mcp.tools.packages import list_installed_packages as _list_installed_packages
from wayland_mcp.tools.package_control import (
    package_action_confirmation_details as _package_action_confirmation_details,
    perform_package_action as _perform_package_action,
)
from wayland_mcp.tools.application_package_control import (
    flatpak_action_confirmation_details as _flatpak_action_confirmation_details,
    perform_flatpak_package_action as _perform_flatpak_package_action,
)
from wayland_mcp.tools.snap_package_control import (
    snap_action_confirmation_details as _snap_action_confirmation_details,
    perform_snap_package_action as _perform_snap_package_action,
)
from wayland_mcp.tools.nix_profile_control import (
    nix_profile_action_confirmation_details as _nix_profile_action_confirmation_details,
    perform_nix_profile_action as _perform_nix_profile_action,
)
from wayland_mcp.tools.nix_profile_history import (
    list_nix_profile_history as _list_nix_profile_history,
    nix_profile_history_action_confirmation_details as _nix_profile_history_action_confirmation_details,
    perform_nix_profile_history_action as _perform_nix_profile_history_action,
)
from wayland_mcp.tools.python_environments import (
    list_python_environment_packages as _list_python_environment_packages,
    list_python_environments as _list_python_environments,
    perform_python_environment_action as _perform_python_environment_action,
    python_environment_action_confirmation_details as _python_environment_action_confirmation_details,
)
from wayland_mcp.tools.native_package_environments import (
    list_native_environment_packages as _list_native_environment_packages,
    list_native_package_environments as _list_native_package_environments,
    native_package_action_confirmation_details as _native_package_action_confirmation_details,
    perform_native_package_environment_action as _perform_native_package_environment_action,
)
from wayland_mcp.tools.application_packages import list_application_packages as _list_application_packages
from wayland_mcp.tools.sockets import (
    list_network_sockets as _list_network_sockets,
    list_unix_raw_sockets as _list_unix_raw_sockets,
)
from wayland_mcp.tools.socket_owners import list_socket_owners as _list_socket_owners
from wayland_mcp.tools.routes import list_network_routes as _list_network_routes
from wayland_mcp.tools.route_lookup import lookup_network_route as _lookup_network_route
from wayland_mcp.tools.route_control import (
    RouteAction as NetworkRouteAction,
    perform_route_action as _perform_route_action,
    route_action_confirmation_details as _route_action_confirmation_details,
)
from wayland_mcp.tools.journal import list_journal_entries as _list_journal_entries
from wayland_mcp.tools.system_logs import list_system_log_entries as _list_system_log_entries
from wayland_mcp.tools.boot import (
    list_boot_targets as _list_boot_targets,
    set_default_boot_target as _set_default_boot_target,
    validate_default_boot_target as _validate_default_boot_target,
)
from wayland_mcp.tools.time_settings import (
    get_time_settings as _get_time_settings,
    list_time_zones as _list_time_zones,
    perform_time_action as _perform_time_action,
    time_action_confirmation_details as _time_action_confirmation_details,
)
from wayland_mcp.tools.time_sync import get_time_sync_status as _get_time_sync_status
from wayland_mcp.tools.hardware import list_hardware_devices as _list_hardware_devices
from wayland_mcp.tools.udev_devices import list_udev_devices as _list_udev_devices
from wayland_mcp.tools.sensors import list_sensor_readings as _list_sensor_readings
from wayland_mcp.tools.fan_control import (
    FanControlAction as FanControlActionName,
    fan_control_confirmation_details as _fan_control_confirmation_details,
    list_fan_controls as _list_fan_controls,
    perform_fan_control as _perform_fan_control,
)
from wayland_mcp.tools.backlight import (
    display_brightness_confirmation_details as _display_brightness_confirmation_details,
    list_display_backlights as _list_display_backlights,
    perform_display_brightness_change as _perform_display_brightness_change,
)
from wayland_mcp.tools.audio import list_audio_devices as _list_audio_devices
from wayland_mcp.tools.audio_server import list_audio_server_devices as _list_audio_server_devices
from wayland_mcp.tools.audio_control import (
    AudioAction as AudioActionName,
    AudioDirection as AudioDirectionName,
    audio_action_confirmation_details as _audio_action_confirmation_details,
    perform_audio_endpoint_action as _perform_audio_endpoint_action,
)
from wayland_mcp.tools.power import list_power_supplies as _list_power_supplies
from wayland_mcp.tools.power_state import get_power_state as _get_power_state
from wayland_mcp.tools.power_inhibitors import list_power_inhibitors as _list_power_inhibitors
from wayland_mcp.tools.power_control import (
    get_power_action_readiness as _get_power_action_readiness,
    perform_power_action as _perform_power_action,
    validate_power_action as _validate_power_action,
)
from wayland_mcp.tools.power_profiles import (
    PowerProfile as PowerProfileName,
    get_power_profile as _get_power_profile,
    perform_power_profile_change as _perform_power_profile_change,
    power_profile_confirmation_details as _power_profile_confirmation_details,
)
from wayland_mcp.tools.printers import list_printers as _list_printers
from wayland_mcp.tools.printer_control import (
    printer_action_confirmation_details as _printer_action_confirmation_details,
    perform_printer_action as _perform_printer_action,
)
from wayland_mcp.tools.filesystem import (
    inspect_path as _inspect_path,
    list_directory as _list_directory,
    list_path_extended_attributes as _list_path_extended_attributes,
    read_text_file as _read_text_file,
)
from wayland_mcp.tools.filesystem_admin import (
    binary_file_delete_confirmation_details as _binary_file_delete_confirmation_details,
    binary_file_write_confirmation_details as _binary_file_write_confirmation_details,
    delete_binary_file as _delete_binary_file,
    read_binary_file as _read_binary_file,
    write_binary_file as _write_binary_file,
)
from wayland_mcp.tools.filesystem_uploads import (
    MAX_BINARY_UPLOAD_BYTES,
    abort_binary_file_upload as _abort_binary_file_upload,
    append_binary_file_upload as _append_binary_file_upload,
    begin_binary_file_upload as _begin_binary_file_upload,
    binary_file_upload_confirmation_details as _binary_file_upload_confirmation_details,
    close_all_binary_file_uploads as _close_all_binary_file_uploads,
    commit_binary_file_upload as _commit_binary_file_upload,
    expire_binary_file_uploads as _expire_binary_file_uploads,
)
from wayland_mcp.tools.filesystem_path_admin import (
    change_path_owner as _change_path_owner,
    directory_action_confirmation_details as _directory_action_confirmation_details,
    extended_attribute_confirmation_details as _extended_attribute_confirmation_details,
    manage_extended_attribute as _manage_extended_attribute,
    manage_directory as _manage_directory,
    manage_posix_acl as _manage_posix_acl,
    manage_symlink as _manage_symlink,
    owner_change_confirmation_details as _owner_change_confirmation_details,
    posix_acl_confirmation_details as _posix_acl_confirmation_details,
    symlink_action_confirmation_details as _symlink_action_confirmation_details,
)
from wayland_mcp.tools.filesystem_tree import (
    directory_tree_action_confirmation_details as _directory_tree_action_confirmation_details,
    manage_directory_tree as _manage_directory_tree,
)
from wayland_mcp.tools.filesystem_write import (
    create_text_file as _create_text_file,
    delete_text_file as _delete_text_file,
    replace_text_file as _replace_text_file,
    text_file_creation_confirmation_details as _text_file_creation_confirmation_details,
    text_file_deletion_confirmation_details as _text_file_deletion_confirmation_details,
    text_file_replacement_confirmation_details as _text_file_replacement_confirmation_details,
)
from wayland_mcp.tools.filesystem_permissions import (
    file_mode_change_confirmation_details as _file_mode_change_confirmation_details,
    set_file_mode as _set_file_mode,
)
from wayland_mcp.tools.cpu import list_cpu_inventory as _list_cpu_inventory
from wayland_mcp.tools.numa import list_numa_nodes as _list_numa_nodes
from wayland_mcp.tools.sessions import list_login_sessions as _list_login_sessions
from wayland_mcp.tools.process_control import (
    perform_process_signal as _perform_process_signal,
    process_signal_confirmation_details as _process_signal_confirmation_details,
    signal_effect as _signal_effect,
)
from wayland_mcp.tools.command_execution import (
    failed_command_response as _failed_command_response,
    prepare_command as _prepare_command,
    run_prepared_command as _run_prepared_command,
)
from wayland_mcp.tools.terminal_sessions import (
    MAX_TERMINAL_BUFFER_BYTES as _MAX_TERMINAL_BUFFER_BYTES,
    MAX_TERMINAL_COLUMNS as _MAX_TERMINAL_COLUMNS,
    MAX_TERMINAL_INPUT_BYTES as _MAX_TERMINAL_INPUT_BYTES,
    MAX_TERMINAL_ROWS as _MAX_TERMINAL_ROWS,
    MAX_TERMINAL_WAIT_SECONDS as _MAX_TERMINAL_WAIT_SECONDS,
    terminal_sessions as _terminal_sessions,
)
from wayland_mcp.tools.resource_history import sample_resource_history as _sample_resource_history
from wayland_mcp.tools.process_history import sample_process_history as _sample_process_history
from wayland_mcp.tools.cgroup_history import sample_cgroup_history as _sample_cgroup_history
from wayland_mcp.tools.process_context import get_process_execution_context as _get_process_execution_context
from wayland_mcp.tools.namespace_inventory import list_namespace_inventory as _list_namespace_inventory
from wayland_mcp.tools.gpu import list_gpu_devices as _list_gpu_devices
from wayland_mcp.tools.gpu_power import (
    gpu_power_limit_confirmation_details as _gpu_power_limit_confirmation_details,
    list_gpu_power_limits as _list_gpu_power_limits,
    perform_gpu_power_limit_action as _perform_gpu_power_limit_action,
)
from wayland_mcp.tools.powercap import (
    list_powercap_limits as _list_powercap_limits,
    perform_powercap_limit_action as _perform_powercap_limit_action,
    powercap_limit_confirmation_details as _powercap_limit_confirmation_details,
)
from wayland_mcp.tools.gpu_frequency import (
    gpu_frequency_limit_confirmation_details as _gpu_frequency_limit_confirmation_details,
    list_gpu_frequency_limits as _list_gpu_frequency_limits,
    perform_gpu_frequency_limit_action as _perform_gpu_frequency_limit_action,
)
from wayland_mcp.tools.containers import (
    ContainerAction,
    ContainerImageAction as ContainerImageActionName,
    ContainerRuntime as ContainerRuntimeName,
    container_image_action_confirmation_details as _container_image_action_confirmation_details,
    container_create_confirmation_details as _container_create_confirmation_details,
    list_container_images as _list_container_images,
    container_action_confirmation_details as _container_action_confirmation_details,
    list_containers as _list_containers,
    perform_container_create as _perform_container_create,
    perform_container_image_action as _perform_container_image_action,
    perform_container_action as _perform_container_action,
)
from wayland_mcp.tools.container_resources import (
    ContainerResourceAction as ContainerResourceActionName,
    ContainerResourceKind as ContainerResourceKindName,
    container_resource_action_confirmation_details as _container_resource_action_confirmation_details,
    list_container_resources as _list_container_resources,
    perform_container_resource_action as _perform_container_resource_action,
)
from wayland_mcp.tools.container_network_attachments import (
    ContainerNetworkAction as ContainerNetworkActionName,
    container_network_attachment_action_confirmation_details as _container_network_attachment_action_confirmation_details,
    list_container_network_attachments as _list_container_network_attachments,
    perform_container_network_attachment_action as _perform_container_network_attachment_action,
)
from wayland_mcp.tools.container_pods import (
    ContainerPodAction as ContainerPodActionName,
    container_pod_action_confirmation_details as _container_pod_action_confirmation_details,
    list_container_pods as _list_container_pods,
    perform_container_pod_action as _perform_container_pod_action,
)
from wayland_mcp.tools.container_build import (
    ContainerImageBuildRuntime as ContainerImageBuildRuntimeName,
    container_image_build_confirmation_details as _container_image_build_confirmation_details,
    perform_container_image_build as _perform_container_image_build,
)
from wayland_mcp.tools.virtual_machines import (
    list_virtual_machines as _list_virtual_machines,
    perform_virtual_machine_action as _perform_virtual_machine_action,
    virtual_machine_action_confirmation_details as _virtual_machine_action_confirmation_details,
)
from wayland_mcp.tools.remote_virtual_machines import (
    _parse_endpoint as _parse_remote_libvirt_endpoint,
    list_remote_virtual_machines as _list_remote_virtual_machines,
    perform_remote_virtual_machine_action as _perform_remote_virtual_machine_action,
    remote_virtual_machine_action_confirmation_details as _remote_virtual_machine_action_confirmation_details,
)
from wayland_mcp.tools.remote_virtual_machine_disks import (
    perform_remote_virtual_machine_disk_attach as _perform_remote_virtual_machine_disk_attach,
    remote_virtual_machine_disk_attach_confirmation_details as _remote_virtual_machine_disk_attach_confirmation_details,
)
from wayland_mcp.tools.remote_virtual_machine_create import (
    perform_remote_virtual_machine_create as _perform_remote_virtual_machine_create,
    remote_virtual_machine_create_confirmation_details as _remote_virtual_machine_create_confirmation_details,
)
from wayland_mcp.tools.remote_virtual_machine_config import (
    perform_remote_virtual_machine_config as _perform_remote_virtual_machine_config,
    remote_virtual_machine_config_confirmation_details as _remote_virtual_machine_config_confirmation_details,
)
from wayland_mcp.tools.virtual_machine_config import (
    perform_virtual_machine_config as _perform_virtual_machine_config,
    virtual_machine_config_confirmation_details as _virtual_machine_config_confirmation_details,
)
from wayland_mcp.tools.virtual_machine_create import (
    perform_virtual_machine_create as _perform_virtual_machine_create,
    virtual_machine_create_confirmation_details as _virtual_machine_create_confirmation_details,
)
from wayland_mcp.tools.virtual_machine_disks import (
    perform_virtual_machine_disk_attach as _perform_virtual_machine_disk_attach,
    virtual_machine_disk_attach_confirmation_details as _virtual_machine_disk_attach_confirmation_details,
)
from wayland_mcp.tools.virtual_machine_snapshots import (
    list_virtual_machine_snapshots as _list_virtual_machine_snapshots,
    perform_virtual_machine_snapshot_action as _perform_virtual_machine_snapshot_action,
    snapshot_action_confirmation_details as _snapshot_action_confirmation_details,
)
from wayland_mcp.tools.remote_virtual_machine_snapshots import (
    list_remote_virtual_machine_snapshots as _list_remote_virtual_machine_snapshots,
    perform_remote_virtual_machine_snapshot_action as _perform_remote_virtual_machine_snapshot_action,
    remote_snapshot_action_confirmation_details as _remote_snapshot_action_confirmation_details,
)
from wayland_mcp.tools.remote_libvirt_resources import (
    RemoteLibvirtResourceAction as RemoteLibvirtResourceActionName,
    RemoteLibvirtResourceType as RemoteLibvirtResourceTypeName,
    list_remote_libvirt_networks as _list_remote_libvirt_networks,
    list_remote_libvirt_storage as _list_remote_libvirt_storage,
    perform_remote_libvirt_resource_action as _perform_remote_libvirt_resource_action,
    remote_libvirt_resource_action_confirmation_details as _remote_libvirt_resource_action_confirmation_details,
)
from wayland_mcp.tools.libvirt_resources import (
    LibvirtResourceAction as LibvirtResourceActionName,
    LibvirtResourceType as LibvirtResourceTypeName,
    LibvirtVolumeFormat as LibvirtVolumeFormatName,
    libvirt_resource_action_confirmation_details as _libvirt_resource_action_confirmation_details,
    libvirt_volume_create_confirmation_details as _libvirt_volume_create_confirmation_details,
    list_libvirt_networks as _list_libvirt_networks,
    list_libvirt_storage as _list_libvirt_storage,
    perform_libvirt_resource_action as _perform_libvirt_resource_action,
    perform_libvirt_volume_create as _perform_libvirt_volume_create,
)
from wayland_mcp.tools.libvirt_network_create import (
    libvirt_network_create_confirmation_details as _libvirt_network_create_confirmation_details,
    libvirt_network_definition_confirmation_details as _libvirt_network_definition_confirmation_details,
    libvirt_network_ipv4_configuration_confirmation_details as _libvirt_network_ipv4_configuration_confirmation_details,
    perform_libvirt_network_create as _perform_libvirt_network_create,
    perform_libvirt_network_definition as _perform_libvirt_network_definition,
    perform_libvirt_network_ipv4_configuration as _perform_libvirt_network_ipv4_configuration,
)


ServiceAction = Literal["start", "stop", "restart", "reload", "enable", "disable"]
ServiceScope = Literal["system", "user"]
SystemdTimerActionName = Literal["start", "stop", "enable", "disable"]
SystemdTimerScopeName = Literal["system", "user"]
SystemdTimerDefinitionActionName = Literal["create", "update"]
SystemdServiceDefinitionActionName = Literal["create", "update"]
PowerAction = Literal[
    "poweroff",
    "reboot",
    "halt",
    "suspend",
    "hibernate",
    "hybrid_sleep",
    "suspend_then_hibernate",
    "reboot_to_firmware_setup",
]
PowerReadinessAction = PowerAction
TimeActionName = Literal["set_timezone", "set_ntp"]
VirtualMachineActionName = Literal["start", "shutdown", "reboot", "suspend", "resume"]
RemoteVirtualMachineActionName = Literal["start", "shutdown", "reboot", "suspend", "resume"]
VirtualMachineSnapshotActionName = Literal["create", "revert", "delete"]
RadioDeviceActionName = Literal["block", "unblock"]


async def _confirm_systemd_timer_action(
    action: SystemdTimerActionName,
    unit: str,
    scope: SystemdTimerScopeName,
) -> Elicit[SystemdTimerActionConfirmation]:
    snapshot, validation_error = await asyncio.to_thread(
        _timer_action_confirmation_details,
        action,
        unit,
        scope,
    )
    if snapshot is None:
        raise ValueError(validation_error or "Systemd timer validation failed.")

    safe_unit = json.dumps(unit, ensure_ascii=True)
    triggers = ", ".join(json.dumps(value, ensure_ascii=True) for value in snapshot.trigger_units)
    triggers = triggers or "not reported by systemd"
    current_state = (
        f"Current state: active={snapshot.active_state}, unit-file={snapshot.unit_file_state}; "
        f"trigger unit(s): {triggers}; persistent={snapshot.persistent if snapshot.persistent is not None else 'unknown'}; "
        f"calendar schedule={snapshot.on_calendar if snapshot.on_calendar is not None else 'unknown'}."
    )
    if action == "start":
        effect = (
            " This arms the timer; its associated unit can run when the schedule elapses. "
            "A timer with Persistent=yes and an OnCalendar schedule may immediately catch up a missed event."
        )
    elif action == "stop":
        effect = " This stops future timer events; it does not stop a service that the timer already triggered."
    elif action == "enable":
        effect = " This creates persistent startup links but does not start the timer now. systemd may also enable units declared by the timer's Also= setting."
    else:
        effect = (
            " This removes the timer's enablement links, including manually created links, and systemd may also disable units declared by its Also= setting. "
            "It does not stop an active timer."
        )
    return Elicit(
        f"Confirm systemd timer action {action} for exact unit {safe_unit} in {scope} scope? "
        f"{current_state} State token: {snapshot.state_token}.{effect} "
        "The command uses the current user's systemd manager permissions and does not request elevation. "
        "A client disconnect does not cancel an action after confirmation.",
        SystemdTimerActionConfirmation,
    )


async def _confirm_systemd_timer_definition(
    action: SystemdTimerDefinitionActionName,
    unit: str,
    scope: SystemdTimerScopeName,
    service_unit: str,
    on_calendar: str | None = None,
    on_boot_seconds: int | None = None,
    on_unit_active_seconds: int | None = None,
    persistent: bool = False,
) -> Elicit[SystemdTimerDefinitionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _timer_definition_confirmation_details,
        action,
        scope,
        unit,
        service_unit,
        on_calendar,
        on_boot_seconds,
        on_unit_active_seconds,
        persistent,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The systemd timer definition could not be verified.")

    schedule = []
    if target.on_calendar is not None:
        schedule.append(f"OnCalendar={target.on_calendar}")
    if target.on_boot_seconds is not None:
        schedule.append(f"OnBootSec={target.on_boot_seconds}s")
    if target.on_unit_active_seconds is not None:
        schedule.append(f"OnUnitActiveSec={target.on_unit_active_seconds}s")
    if target.persistent:
        schedule.append("Persistent=true")
    schedule_text = ", ".join(json.dumps(value, ensure_ascii=True) for value in schedule)
    if action == "create":
        effect = " The new timer file will remain inactive and disabled; it will not start or enable the target service."
    else:
        effect = (
            f" The existing timer is currently {target.unit_file_state}; update preserves its enablement and requires it to be inactive."
        )
    if target.persistent:
        effect += " When later started, Persistent=true may immediately catch up one missed calendar event."
    return Elicit(
        f"Confirm {action} of generated timer unit {target.unit!r} in {target.scope} scope at {str(target.path)!r}? "
        f"It will activate the already-loaded service {target.service_unit!r} on {schedule_text}. "
        "The calendar expression was checked by systemd-analyze. A system-scope timer runs the target service "
        "with that service's configured identity and permissions; system services commonly run with root privileges. "
        "The server writes only a generated .timer file and reloads the selected systemd manager; it does not create or edit the service unit, "
        "start the timer, enable it, or request privilege elevation. "
        f"State token: {target.state_token}. Type {target.confirmation_phrase!r} and confirm.{effect}",
        SystemdTimerDefinitionConfirmation,
    )


async def _confirm_systemd_timer_definition_deletion(
    unit: str,
    scope: SystemdTimerScopeName,
) -> Elicit[SystemdTimerDefinitionDeleteConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _timer_definition_deletion_confirmation_details,
        scope,
        unit,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The systemd timer definition could not be verified for deletion.")
    return Elicit(
        f"Confirm deletion of generated timer unit {target.unit!r} from {target.scope} scope at {str(target.path)!r}? "
        "The timer must already be inactive and disabled. Only a timer file carrying the linux-mcp generated-file marker, "
        "with no drop-ins and no other enablement links, is eligible. The file will be unlinked and the selected systemd "
        "manager reloaded; this does not delete the service unit or stop a service already started by the timer. "
        "The file content digest, file identity, unit state, and parent directory identity are bound to this confirmation. "
        f"State token: {target.state_token}. Type {target.confirmation_phrase!r} and confirm.",
        SystemdTimerDefinitionDeleteConfirmation,
    )


async def _confirm_systemd_service_definition(
    action: SystemdServiceDefinitionActionName,
    unit: str,
    scope: SystemdTimerScopeName,
    executable: str,
    arguments: list[str],
) -> Elicit[SystemdServiceDefinitionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _service_definition_confirmation_details,
        action,
        scope,
        unit,
        executable,
        arguments,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The systemd service definition could not be verified.")
    argv_text = json.dumps([target.executable, *target.arguments], ensure_ascii=True)
    if action == "create":
        effect = " The new service file will remain inactive and disabled."
    else:
        effect = (
            f" The existing service is currently {target.unit_file_state}; update preserves its enablement and requires it to be inactive."
        )
        if target.unit_file_state == "enabled":
            effect += " Its updated command may run on the next boot or other future activation."
    scope_warning = (
        " A system-scope service runs with its configured identity; generated files use systemd's default root identity unless separately configured."
        if scope == "system"
        else " The command runs as the current user through that user's systemd manager."
    )
    arguments_json = json.dumps(list(target.arguments), ensure_ascii=True, separators=(",", ":"))
    return Elicit(
        f"Confirm {action} of generated one-shot service {target.unit!r} in {target.scope} scope at {str(target.path)!r}? "
        f"Exact argv vector: {argv_text}. Confirmation arguments_json: {arguments_json}. "
        "The tool passes these values directly to ExecStart without a shell; "
        "the executable and arguments will be stored in readable unit-file text, so do not include secrets. "
        "The service uses Type=oneshot and an enableable default.target installation section. "
        "The server writes only this generated .service file and reloads the selected systemd manager; it does not start or enable the service, "
        "and it does not request privilege elevation."
        f"{scope_warning} State token: {target.state_token}. Type {target.confirmation_phrase!r} and confirm.{effect}",
        SystemdServiceDefinitionConfirmation,
    )


async def _confirm_cron_job_action(
    action: CronJobActionName,
    schedule: str,
    command: str,
    new_schedule: str | None = None,
    new_command: str | None = None,
    scope: Literal["user", "system"] = "user",
    run_as_user: str = "",
    job_id: str = "",
) -> Elicit[CronJobActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _cron_job_action_confirmation_details,
        action,
        schedule,
        command,
        new_schedule,
        new_command,
        scope,
        run_as_user,
        job_id,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The current-user cron job could not be verified.")
    operation = {"add": "add", "update": "update", "remove": "remove"}[action]
    exact_command = json.dumps(target.command, ensure_ascii=True)
    if action == "update":
        replacement_command = json.dumps(target.new_command, ensure_ascii=True)
        exact_job = (
            f"Exact existing schedule: {target.schedule}; exact existing command: {exact_command}. "
            f"Replacement schedule: {target.new_schedule}; replacement command: {replacement_command}. "
        )
    else:
        exact_job = f"Exact schedule: {target.schedule}; exact command: {exact_command}. "
    if target.scope == "system":
        prompt_target = f"marked system cron file /etc/cron.d/linux-mcp-{target.job_id} for local account {target.username} (UID {target.uid})"
        boundaries = (
            "The tool creates or updates only this exact generated file, owned by root with mode 0644; it never edits another system cron file. "
            "The server must already run as root; the tool does not elevate. An external edit in the final read/replace interval may race the update. "
            f"The cron daemon will later run the command with {target.username}'s permissions; command text is visible to local administrators. "
        )
    else:
        prompt_target = f"the current user's crontab ({target.username}, UID {target.uid})"
        boundaries = (
            "The change is limited to this marked job in the server identity's crontab; other users and system cron files are not changed. "
            "The full crontab is re-read before installation, but an external edit in the final read/install interval may race this update. "
            "The command will run later with the current user's cron permissions and environment; secret values in the command remain visible in the crontab. "
        )
    return Elicit(
        f"Confirm {operation} for {prompt_target}? "
        f"{exact_job}{boundaries}"
        f"Type {phrase!r} and confirm.",
        CronJobActionConfirmation,
    )


async def _confirm_at_job_action(
    action: AtJobActionName,
    run_at: str = "",
    command: str = "",
    job_id: str = "",
) -> Elicit[AtJobActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _at_job_confirmation_details,
        action,
        run_at,
        command,
        job_id,
    )
    if validation_error or target is None or phrase is None or target.run_at is None:
        raise ValueError(validation_error or "The current-user at job could not be verified.")
    if action == "add":
        command_text = json.dumps(target.command, ensure_ascii=True)
        effect = (
            f"Schedule this exact command {command_text} for {target.run_at.isoformat(timespec='minutes')} local host time? "
            "The command is stored in the local at queue and may be visible to host administrators; do not include secrets. "
        )
    else:
        effect = (
            f"Remove at job {target.job_id!r}, scheduled for {target.run_at.isoformat(timespec='minutes')} local host time? "
            "Its command body is inspected only to bind the confirmation and is never returned. "
        )
    return Elicit(
        f"Confirm {action} for the current server identity's at queue ({target.username}, UID {target.uid})? "
        f"{effect}The one-shot command runs later through /bin/sh with this account's permissions and captured environment; execution depends on atd. "
        "The queue is re-read before the action; an external edit in the final read/action interval may race it. "
        f"Type {phrase!r} and confirm.",
        AtJobActionConfirmation,
    )


async def _confirm_service_action(
    action: ServiceAction,
    unit: str,
    scope: ServiceScope,
) -> Elicit[ServiceActionConfirmation]:
    validation_error = await asyncio.to_thread(_validate_service_action, action, unit, scope)
    if validation_error:
        raise ValueError(validation_error)

    manager = _detect_init_system() or "unknown"
    if manager == "systemd":
        command = f"systemctl {action} {unit} in {scope} scope"
        effect = (
            " This changes whether the unit starts automatically at boot or user-session startup."
            if action in {"enable", "disable"}
            else " This may interrupt processes using the service."
            if action in {"stop", "restart"}
            else ""
        )
    elif manager == "openrc":
        command = f"OpenRC rc-service {unit} {action} in system scope"
        effect = " OpenRC may also change related services to satisfy dependencies."
    elif manager == "s6-svscan":
        command = (
            f"run s6-rc stop then start for exact atomic service {unit} in system scope"
            if action == "restart"
            else f"s6-rc {action} {unit} in system scope"
        )
        effect = (
            " s6-rc may also start or stop prerequisite services as it resolves dependencies; essential services are never forcibly stopped."
            if action in {"start", "stop", "restart"}
            else " Reload sends SIGHUP to longrun services or runs the configured reload script for a oneshot; the service must be up."
        )
        if action == "restart":
            effect += " If the start phase fails after stopping, the service may remain down."
    else:
        command = f"runit sv {action} {unit}"
        effect = " This targets one supervised service; reload sends SIGHUP." if action == "reload" else " This may interrupt processes using the service." if action in {"stop", "restart"} else ""
    if manager == "s6-svscan":
        effect += " If s6-rc times out, the state may be partial and transition scripts may continue; inspect service state before retrying."
    return Elicit(
        f"Confirm {command}?{effect} The request uses the current user's permissions and does not use sudo. A client disconnect does not cancel an action after confirmation; inspect service state if the request is interrupted.",
        ServiceActionConfirmation,
    )


async def _confirm_openrc_service_startup(
    action: Literal["enable", "disable"],
    unit: str,
    runlevel: str,
) -> Elicit[OpenRCServiceStartupConfirmation]:
    snapshot, validation_error = await asyncio.to_thread(
        _openrc_startup_confirmation_details,
        action,
        unit,
        runlevel,
    )
    if snapshot is None:
        raise ValueError(validation_error or "OpenRC startup validation failed.")
    safe_unit = json.dumps(unit, ensure_ascii=True)
    safe_runlevel = json.dumps(runlevel, ensure_ascii=True)
    state = "present" if snapshot.enabled else "absent"
    effect = (
        " This adds this exact service to the selected runlevel; OpenRC may act on it when switching to that runlevel, but no immediate service action is requested."
        if action == "enable"
        else " This removes this exact service from the selected runlevel; OpenRC may act on it when switching to that runlevel, but no immediate service action is requested."
    )
    return Elicit(
        f"Confirm OpenRC {action} for service {safe_unit} in runlevel {safe_runlevel}? Current membership is {state}. "
        f"State token: {snapshot.state_token}.{effect} The command uses the current user's permissions and does not request elevation. "
        "A client disconnect does not cancel an action after confirmation.",
        OpenRCServiceStartupConfirmation,
    )


async def _confirm_runit_service_startup(
    action: Literal["enable", "disable"],
    unit: str,
) -> Elicit[RunitServiceStartupConfirmation]:
    snapshot, validation_error = await asyncio.to_thread(
        _runit_startup_confirmation_details,
        action,
        unit,
    )
    if snapshot is None:
        raise ValueError(validation_error or "Runit startup validation failed.")
    safe_unit = json.dumps(unit, ensure_ascii=True)
    state = "enabled" if snapshot.enabled else "disabled"
    effect = (
        " This removes the exact service directory's down marker, so runsv will start the service when its supervisor next starts."
        if action == "enable"
        else " This creates an empty down marker, so a future runsv supervisor start will leave the service down."
    )
    return Elicit(
        f"Confirm runit {action} for service {safe_unit}? Current initial state is {state}; service directory {json.dumps(str(snapshot.service_directory), ensure_ascii=True)}. "
        f"State token: {snapshot.state_token}.{effect} This does not change a currently running service or supervisor. The filesystem change uses current-user permissions and does not request elevation. "
        "A client disconnect does not cancel an action after confirmation.",
        RunitServiceStartupConfirmation,
    )


async def _confirm_s6_startup_set(
    action: Literal["enable", "disable"],
    unit: str,
) -> Elicit[S6StartupSetConfirmation]:
    snapshot, validation_error = await asyncio.to_thread(
        _s6_startup_confirmation_details,
        action,
        unit,
    )
    if snapshot is None:
        raise ValueError(validation_error or "s6 startup-set validation failed.")
    safe_unit = json.dumps(unit, ensure_ascii=True)
    current = "enabled" if snapshot.prescription == "active" else "disabled"
    target = "enabled" if action == "enable" else "disabled"
    return Elicit(
        f"Confirm s6 {action} for exact atomic service {safe_unit} in the current offline working set? "
        f"Current staged state is {current}; the requested staged state is {target}. State token: {snapshot.state_token}. "
        "This changes only the s6-frontend offline working set. It does not change the live service database or current service state; "
        "the working set must be committed and installed before it affects boot. The dependency check refuses an inconsistent change and does not modify other service prescriptions. "
        "The command uses the current user's permissions without elevation. A client disconnect does not cancel an action after confirmation.",
        S6StartupSetConfirmation,
    )


async def _confirm_printer_action(
    action: Literal["enable", "disable", "accept", "reject"],
    printer: str,
) -> Elicit[PrinterActionConfirmation]:
    snapshot, validation_error = await asyncio.to_thread(
        _printer_action_confirmation_details,
        action,
        printer,
    )
    if snapshot is None:
        raise ValueError(validation_error or "CUPS printer validation failed.")
    enabled_state = "enabled" if snapshot.enabled else "disabled"
    acceptance_state = "accepting jobs" if snapshot.accepting_jobs else "rejecting jobs"
    effects = {
        "enable": " This resumes processing for the queue; queued documents may print.",
        "disable": " This stops the printer queue without passing CUPS's job-cancellation option.",
        "accept": " This allows new jobs to be submitted; an enabled queue may begin printing them.",
        "reject": " This rejects new job submissions; jobs already queued are not canceled.",
    }
    return Elicit(
        f"Confirm CUPS {action} for exact printer queue {json.dumps(snapshot.printer, ensure_ascii=True)}? "
        f"Current state: {enabled_state}, {acceptance_state}, printer status {snapshot.state}. State token: {snapshot.state_token}."
        f"{effects[action]} The command uses the configured CUPS server and current-user permissions; it does not provide credentials or request elevation."
        " A client disconnect does not cancel an action after confirmation.",
        PrinterActionConfirmation,
    )


async def _confirm_package_action(
    action: PackageAction,
    package: str,
) -> Elicit[PackageActionConfirmation]:
    target = _package_action_confirmation_details(action, package)
    if isinstance(target, str):
        raise ValueError(target)
    safe_package = json.dumps(package, ensure_ascii=True)
    if action == "upgrade_all":
        operation = f"upgrade all eligible installed system packages with {target.frontend}"
        effect = " This may refresh repository metadata, download packages, replace or remove software, change dependencies, execute package scripts, and interrupt services."
    elif target.manager == "pacman" and action in {"install", "upgrade"}:
        operation = f"{action} {safe_package} and run the required full system upgrade with pacman"
        effect = " This updates all eligible installed packages as well as the requested package."
    else:
        operation = f"{action} exact system package {safe_package} with {target.frontend}"
        effect = " The package manager may change dependencies, download packages, execute package scripts, and affect services or configuration files."
    return Elicit(
        f"Confirm {operation}?{effect} The command uses current OS permissions and does not request privilege elevation. "
        "Package-manager output is withheld because it can contain repository credentials. A client disconnect does not cancel a confirmed transaction; after a 30-minute timeout it is asked to stop and package state may be incomplete. Inspect package state before retrying.",
        PackageActionConfirmation,
    )


async def _confirm_flatpak_package_action(
    action: Literal["install", "update", "remove"],
    scope: Literal["system", "user"],
    ref: str,
    remote: str,
    installation: str = "",
) -> Elicit[ApplicationPackageActionConfirmation]:
    target = await asyncio.to_thread(
        _flatpak_action_confirmation_details,
        action,
        scope,
        ref,
        remote,
        installation,
    )
    if isinstance(target, str):
        raise ValueError(target)
    safe_ref = json.dumps(ref, ensure_ascii=True)
    if action == "install":
        operation = f"install exact Flatpak ref {safe_ref} from configured remote {json.dumps(remote, ensure_ascii=True)}"
        effect = " The selected app or runtime and required dependencies may be downloaded and deployed; related extensions are excluded."
    elif action == "update":
        operation = f"update exact installed Flatpak ref {safe_ref} from its configured origin {json.dumps(target.origin, ensure_ascii=True)} at current commit {target.commit}"
        effect = " Runtime dependencies and related extensions are excluded from updating. Flatpak may also remove unused end-of-life runtimes when answering its prompts yes."
    else:
        operation = f"remove exact installed Flatpak ref {safe_ref} at current commit {target.commit}"
        effect = " Related extensions are excluded. The command does not request deletion of the app's data or force removal."
    if installation:
        installation_details = (
            f"This targets the configured named system installation {json.dumps(installation, ensure_ascii=True)}. "
            "Its configured path is not exposed. System operations follow Flatpak's host authorization policy and may require polkit authentication; this tool does not invoke sudo."
        )
        installation_label = f"named system installation {json.dumps(installation, ensure_ascii=True)}"
    elif scope == "system":
        installation_details = "This targets the default system installation. System operations follow Flatpak's host authorization policy and may require polkit authentication; this tool does not invoke sudo."
        installation_label = "default system installation"
    else:
        installation_details = "This targets the current user's default Flatpak installation."
        installation_label = "current-user installation"
    return Elicit(
        f"Confirm {operation} in the {installation_label}?{effect} {installation_details} "
        f"Flatpak output is withheld. The operation has a 30-minute timeout; after timeout, package state may be incomplete. "
        f"A client disconnect does not cancel an already confirmed transaction. Review the current ref and installation state before retrying. "
        f"State token: {target.state_token}.",
        ApplicationPackageActionConfirmation,
    )


async def _confirm_snap_package_action(
    action: Literal["install", "update", "switch_channel", "remove", "enable", "disable", "revert", "hold", "unhold", "hold_all", "unhold_all"],
    package_name: str = "",
    target_channel: str = "",
    classic: bool = False,
    snap_file_path: str = "",
    dangerous: bool = False,
    devmode: bool = False,
    revision: int | None = None,
    hold_duration: str = "",
) -> Elicit[SnapPackageActionConfirmation]:
    target = await asyncio.to_thread(
        _snap_action_confirmation_details,
        action,
        package_name,
        target_channel,
        classic,
        snap_file_path,
        dangerous,
        devmode,
        revision,
        hold_duration,
    )
    if isinstance(target, str):
        raise ValueError(target)
    safe_name = json.dumps(package_name, ensure_ascii=True)
    if action == "hold_all":
        operation = f"hold automatic refreshes for all installed Snaps for {target.hold_duration}"
        effect = " This requires snapd 2.58 or newer and affects automatic refreshes only; general and specifically targeted refresh requests can still proceed."
    elif action == "unhold_all":
        operation = "remove the system-wide automatic refresh hold and any per-Snap refresh holds"
        effect = " This requires snapd 2.58 or newer. Automatic refreshes may proceed again."
    elif action == "install":
        if snap_file_path:
            operation = (
                f"install exact local Snap {safe_name} from file {json.dumps(snap_file_path, ensure_ascii=True)} "
                f"(SHA-256 {target.local_file_digest}, {target.local_file_size} bytes)"
            )
            effect = " This file is installed as the package source; it will not be deleted."
            if dangerous:
                effect += " Dangerous mode bypasses Snap assertion and signature checks, so the file is not verified as coming from its claimed publisher or as unchanged. Snap hooks and the installed software may run with system privileges."
            elif devmode:
                effect += " Snap will check assertions but may continue if they cannot be verified; in that case developer mode has an effect similar to dangerous mode."
            else:
                effect += " Snap must already trust a valid assertion for this file; assertion checks remain enabled."
            if classic:
                operation += " with classic confinement"
                effect += " Classic confinement gives the snap broad access to system resources and reduces Snap's usual isolation."
            if devmode:
                operation += " in developer mode"
                effect += (
                    " Developer mode grants full access to system resources and logs policy violations. "
                    "Developer-mode installs do not automatically refresh."
                )
        else:
            operation = f"install exact Snap Store name {safe_name} from the configured store on the latest/stable channel"
            effect = " Snap may automatically install required base snaps alongside the selected package."
            if classic:
                operation += " with classic confinement"
                effect += " Classic confinement gives the snap broad access to system resources, much like a traditional package, and reduces Snap's usual isolation. The stable-channel candidate was verified as classic before confirmation."
    elif action == "update":
        operation = (
            f"refresh exact installed Snap {safe_name} from its current tracking channel "
            f"{json.dumps(target.tracking, ensure_ascii=True)} at revision {target.active_revision}"
        )
        effect = " The channel is not changed by this action."
    elif action == "switch_channel":
        operation = (
            f"switch and refresh exact installed Snap {safe_name} from tracking channel "
            f"{json.dumps(target.tracking, ensure_ascii=True)} to {json.dumps(target.target_channel, ensure_ascii=True)} "
            f"(requested as {json.dumps(target_channel, ensure_ascii=True)})"
        )
        effect = " This may immediately replace the installed revision and changes the channel used for future automatic refreshes. If the selected channel has no release, Snap may use a more stable release from the same track."
    elif action == "remove":
        operation = f"remove exact installed Snap {safe_name} and all of its installed revisions"
        effect = (
            " Snap removal deletes the installed package and its active data. On classic systems with snapd 2.39 or newer, "
            "snapd normally creates an automatic data snapshot retained for 31 days by default; that snapshot may contain "
            "private app data and consume disk space. Ubuntu Core and older "
            "snapd versions may not create that snapshot. The command does not use --purge."
        )
    elif action == "enable":
        operation = f"enable exact disabled Snap {safe_name} at installed revision {target.installed_revision}"
        effect = " Its commands will become available again and its services may start."
    elif action == "disable":
        operation = f"disable exact Snap {safe_name} at active revision {target.active_revision}"
        effect = " Its commands will become unavailable and its services will not start while it remains disabled."
    elif action == "revert":
        operation = f"revert exact Snap {safe_name} from active revision {target.active_revision} to retained revision {target.target_revision}"
        effect = " Snap restores the revision-specific configuration data associated with the selected revision. This can discard newer configuration changes and may restart or stop services; shared data may remain changed."
    elif action == "hold":
        operation = f"hold refreshes for exact Snap {safe_name} for {target.hold_duration}"
        effect = " A per-Snap hold applies to automatic and general refreshes but does not block a specifically targeted refresh. Finite holds are limited to 90 days."
    else:
        operation = f"remove the refresh hold from exact Snap {safe_name}"
        effect = " Automatic or general refreshes may proceed again."
    return Elicit(
        f"Confirm {operation}?{effect} The action runs with the MCP server account's current permissions and does not invoke sudo or elevate. "
        "Snap output is withheld. The operation has a 30-minute timeout; after timeout, package state may be incomplete. "
        f"A client disconnect does not cancel an already confirmed transaction. Review current Snap state before retrying. State token: {target.state_token}.",
        SnapPackageActionConfirmation,
    )


async def _confirm_nix_profile_action(
    action: Literal["install", "upgrade", "remove"],
    entry_name: str,
) -> Elicit[NixProfileActionConfirmation]:
    target = await asyncio.to_thread(
        _nix_profile_action_confirmation_details,
        action,
        entry_name,
    )
    if isinstance(target, str):
        raise ValueError(target)
    safe_name = json.dumps(entry_name, ensure_ascii=True)
    safe_attribute = json.dumps(target.attribute, ensure_ascii=True)
    if action == "install":
        operation = f"install nixpkgs flake attribute {safe_attribute} in the current user's default Nix profile"
        effects = " Nix will use the host's configured flake registry, may fetch/evaluate its source, and may download package outputs or execute build steps for the package and dependencies under the host's Nix build configuration."
    elif action == "upgrade":
        operation = f"upgrade exact active Nix profile entry {safe_name} (flake attribute {safe_attribute}) using its existing unlocked source reference"
        effects = " Nix will fetch/evaluate that source and may download package outputs or execute build steps for the package and its dependencies under the host's Nix build configuration."
    else:
        operation = f"remove exact Nix profile entry {safe_name} (flake attribute {safe_attribute}) from the current user's default profile"
        effects = " This removes the profile reference; it does not request garbage collection or delete Nix store data."
    return Elicit(
        f"Confirm {operation}?{effects} This is limited to the current user's default profile and runs with the server account's permissions without elevation. "
        "Nix output is withheld. The operation has a 30-minute timeout; after timeout, profile state may be incomplete. "
        f"A client disconnect does not cancel an already confirmed operation. Review profile state before retrying. State token: {target.state_token}.",
        NixProfileActionConfirmation,
    )


async def _confirm_nix_profile_history_action(
    action: Literal["rollback", "wipe_history"],
    target_version: int,
    older_than_days: int,
) -> Elicit[NixProfileHistoryActionConfirmation]:
    target = await asyncio.to_thread(
        _nix_profile_history_action_confirmation_details,
        action,
        target_version,
        older_than_days,
    )
    if isinstance(target, str):
        raise ValueError(target)
    if action == "rollback":
        operation = (
            f"switch the current user's default Nix profile from version {target.current_version} "
            f"to exact historical version {target.target_version}"
        )
        effects = " This changes the package set and PATH entries provided by the default profile."
    else:
        versions = ", ".join(str(version) for version in target.affected_versions)
        operation = (
            f"delete non-current versions older than {target.older_than_days} days from the current user's default Nix profile history"
        )
        effects = f" This permanently removes rollback choices for these exact versions: {versions}. The current profile remains selected."
    return Elicit(
        f"Confirm {operation}?{effects} The operation uses the current user's default profile and current OS permissions without elevation. "
        "Nix profile commands are experimental and may vary with the installed Nix version. Nix command output is withheld. "
        f"Current version: {target.current_version}. State token: {target.state_token}.",
        NixProfileHistoryActionConfirmation,
    )


async def _confirm_python_environment_action(
    action: Literal["create", "install", "upgrade", "uninstall"],
    environment_name: str,
    package_name: str = "",
    version: str = "",
) -> Elicit[PythonEnvironmentActionConfirmation]:
    target = await asyncio.to_thread(
        _python_environment_action_confirmation_details,
        action,
        environment_name,
        package_name,
        version,
    )
    if isinstance(target, str):
        raise ValueError(target)
    if action == "create":
        operation = f"create a new isolated Python virtual environment named {json.dumps(environment_name, ensure_ascii=True)}"
        effects = " Python's venv module will create a private environment under the current user's home directory and bootstrap pip if ensurepip is available."
    elif action == "install":
        specifier = f"{package_name}=={version}" if version else package_name
        operation = f"install exact Python project specifier {json.dumps(specifier, ensure_ascii=True)} in environment {json.dumps(environment_name, ensure_ascii=True)}"
        effects = " pip may access the public package index, download dependencies, and execute package build-backend or installation code as the current user."
    elif action == "upgrade":
        operation = f"upgrade exact installed Python project {json.dumps(package_name, ensure_ascii=True)} in environment {json.dumps(environment_name, ensure_ascii=True)}"
        effects = " pip may access the public package index, change dependencies, and execute package build-backend or installation code as the current user."
    else:
        operation = f"uninstall exact Python project {json.dumps(package_name, ensure_ascii=True)} from environment {json.dumps(environment_name, ensure_ascii=True)}"
        effects = " Files belonging to that distribution will be removed; other packages that depend on it are not automatically uninstalled."
    return Elicit(
        f"Confirm {operation}?{effects} Managed environments are restricted to {str(target.environment_path)!r} beneath the current user's home directory. "
        "This structured tool requires matching real/effective non-root user IDs and uses no sudo. Pip configuration files and PIP_* environment overrides are disabled; command output is withheld. "
        f"State token: {target.state_token}. A client disconnect does not cancel an already confirmed operation.",
        PythonEnvironmentActionConfirmation,
    )


async def _confirm_native_package_environment_action(
    ecosystem: Literal["npm", "cargo"],
    action: Literal["create", "install", "upgrade", "uninstall"],
    environment_name: str,
    package_name: str = "",
    version: str = "",
) -> Elicit[NativePackageEnvironmentActionConfirmation]:
    target = await asyncio.to_thread(
        _native_package_action_confirmation_details,
        ecosystem,
        action,
        environment_name,
        package_name,
        version,
    )
    if isinstance(target, str):
        raise ValueError(target)
    safe_environment = json.dumps(environment_name, ensure_ascii=True)
    if action == "create":
        operation = f"create a private {ecosystem} environment named {safe_environment}"
        effects = " This creates an isolated prefix/root under the current user's home directory and does not install packages."
    elif action == "install":
        operation = f"install exact {ecosystem} package {json.dumps(package_name, ensure_ascii=True)} in environment {safe_environment}"
        effects = (
            " npm will use the public npm registry and may fetch dependencies, run lifecycle scripts, and compile native modules."
            if ecosystem == "npm"
            else " Cargo will use crates.io, may resolve newer dependency versions, fetch crate sources, and run build scripts while compiling binaries. Only crates with binary targets can be installed."
        )
    elif action == "upgrade":
        operation = f"upgrade exact {ecosystem} package {json.dumps(package_name, ensure_ascii=True)} in environment {safe_environment}"
        effects = (
            " npm will request the latest compatible registry release and may fetch dependencies, run lifecycle scripts, and compile native modules."
            if ecosystem == "npm"
            else " Cargo will resolve the latest crates.io release, may resolve newer dependency versions, fetch crate sources, and run build scripts while compiling binaries. Only crates with binary targets can be installed."
        )
    else:
        operation = f"uninstall exact {ecosystem} package {json.dumps(package_name, ensure_ascii=True)} from environment {safe_environment}"
        effects = (
            " npm removes that top-level package and the files npm installed on its behalf from this prefix."
            if ecosystem == "npm"
            else " Cargo removes the binaries recorded for that crate from this installation root."
        )
    if version:
        operation += f" at exact version {json.dumps(version, ensure_ascii=True)}"
    return Elicit(
        f"Confirm {operation}?{effects} The environment is restricted to {str(target.environment_path)!r} beneath the current user's home directory. "
        "Package builds and lifecycle code run with the server account's current non-root permissions; no sudo or privilege elevation is used. "
        "The tool accepts registry package names only, does not accept URLs, paths, git sources, or package-manager options, withholds output, and has a 30-minute timeout. "
        f"State token: {target.state_token}. A client disconnect does not cancel an already confirmed action.",
        NativePackageEnvironmentActionConfirmation,
    )


async def _confirm_time_settings_action(
    action: TimeActionName,
    timezone: str | None = None,
    ntp_enabled: bool | None = None,
) -> Elicit[TimeSettingsActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _time_action_confirmation_details,
        action,
        timezone,
        ntp_enabled,
    )
    if target is None:
        raise ValueError(validation_error or "The exact time-setting action could not be validated.")
    if action == "set_timezone":
        effect = (
            f" This changes the system timezone to {json.dumps(timezone, ensure_ascii=True)} and updates /etc/localtime."
        )
        if target.local_rtc:
            effect += " Because the hardware RTC is configured for local time, timedated also updates the RTC value."
        elif target.local_rtc is False:
            effect += " The current clock instant is not directly changed."
        else:
            effect += " The RTC-local setting is unavailable, so whether timedated also updates the hardware RTC is unknown."
        current = f"Current timezone: {json.dumps(target.current_timezone, ensure_ascii=True)}."
    else:
        effect = (
            " This enables and starts the first available network time synchronization service, which may adjust the system clock as it synchronizes."
            if ntp_enabled
            else " This disables and stops the known network time synchronization services."
        )
        current = (
            f"Current network-time setting: {target.current_ntp_enabled if target.current_ntp_enabled is not None else 'unknown'}; "
            f"service support: {target.current_can_ntp if target.current_can_ntp is not None else 'unknown'}; "
            f"clock synchronized: {target.current_ntp_synchronized if target.current_ntp_synchronized is not None else 'unknown'}."
        )
    return Elicit(
        f"Confirm system time action {action}? {current} State token: {target.state_token}.{effect} "
        "This is system-wide configuration. timedatectl runs with --no-ask-password and does not invoke sudo; "
        "timedated and local authorization policy determine whether the current account may make the change. "
        "No interactive authentication is requested. A client disconnect does not cancel a command after confirmation; "
        "if the command times out or reports an error, inspect the current settings before retrying.",
        TimeSettingsActionConfirmation,
    )


async def _confirm_default_boot_target(target: str) -> Elicit[BootTargetConfirmation]:
    validation_error = _validate_default_boot_target(target)
    if validation_error:
        raise ValueError(validation_error)
    return Elicit(
        f"Set {target} as the default systemd target for the next boot? "
        "This persistently changes the boot configuration and does not change the running session. "
        "The request uses the current user's permissions and does not use sudo.",
        BootTargetConfirmation,
    )


async def _confirm_kernel_module_action(
    action: KernelModuleActionName,
    module: str,
) -> Elicit[KernelModuleActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _kernel_module_action_confirmation_details,
        action,
        module,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The kernel module action could not be verified.")
    if action == "load":
        operation = "load"
        effects = " Modprobe may also load required dependency modules."
    else:
        operation = "unload"
        effects = " The module has no reported references or dependent holders, but device/driver state can still change concurrently."
    return Elicit(
        f"Confirm {operation} of kernel module {target.module!r} for running kernel {target.kernel_release!r}?{effects} "
        "This changes runtime state only and does not add a persistent modules-load configuration. It uses current OS permissions without sudo. "
        f"Type {phrase!r} and confirm.",
        KernelModuleActionConfirmation,
    )


async def _confirm_kernel_module_startup_action(
    action: KernelModuleStartupActionName,
    module: str,
) -> Elicit[KernelModuleStartupConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _kernel_module_startup_confirmation_details,
        action,
        module,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The persistent kernel-module change could not be verified.")
    operation = "add" if action == "enable" else "remove"
    effect = (
        " This adds a modules-load.d entry for a future boot; it does not load the module now."
        if action == "enable"
        else " This removes only the matching generated entry; an already-loaded module remains loaded, and other aliases or kernel-command-line settings may still request it."
    )
    return Elicit(
        f"Confirm {operation} of persistent startup configuration for kernel module {target.module!r} "
        f"in {str(target.path)!r} for installed kernel {target.kernel_release!r}? The module file identity was verified. "
        "systemd-modules-load reads modules-load.d configuration during boot. This changes system-wide boot configuration, "
        "uses current OS permissions, and does not request elevation."
        f"{effect} State token: {target.state_token}. Type {target.confirmation_phrase!r} and confirm.",
        KernelModuleStartupConfirmation,
    )


async def _confirm_kernel_parameter_change(
    identity_token: str,
    new_value: int,
) -> Elicit[KernelParameterChangeConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _kernel_parameter_confirmation_details,
        identity_token,
        new_value,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact runtime kernel parameter could not be verified.")
    return Elicit(
        f"Change {target.name} from {target.current_value} to {target.new_value} at runtime? "
        f"Allowed range: {target.minimum_value} through {target.maximum_value}. {target.description} "
        "This affects the running kernel immediately and is not persisted to sysctl.d, GRUB, or the kernel command line. "
        "The current OS account must already have write access; the tool does not request sudo. "
        f"State token: {target.state_token}. Repeat the exact parameter, old value, and new value.",
        KernelParameterChangeConfirmation,
    )


async def _confirm_persistent_kernel_parameter_change(
    action: KernelParameterPersistenceActionName,
    name: str,
    value: int | None,
) -> Elicit[KernelParameterPersistenceConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _persistent_kernel_parameter_confirmation_details,
        action,
        name,
        value,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The persistent kernel parameter change could not be verified.")
    old_value = str(target.previous_value) if target.previous_value is not None else "no generated setting"
    if action == "set":
        operation = f"save {name}={value}"
    else:
        operation = f"remove the generated setting for {name}"
    other_paths = target.other_matching_paths + target.filename_collision_paths
    paths_text = ", ".join(other_paths[:8]) if other_paths else "none"
    if len(other_paths) > 8:
        paths_text += f", and {len(other_paths) - 8} more"
    risk_note = ""
    if action == "set" and name == "vm.vfs_cache_pressure" and value == 0:
        risk_note = (
            " Risk: zero prevents reclaim of dentry/inode caches under memory pressure and can lead to out-of-memory conditions."
        )
    elif action == "set" and name == "vm.vfs_cache_pressure" and value is not None and value > 100:
        risk_note = (
            " Values above 100 make dentry/inode reclaim more aggressive; significantly higher values may reduce performance."
        )
    elif action == "set" and name == "vm.swappiness" and value == 0:
        risk_note = (
            " At zero, the kernel delays starting swap until free and file-backed pages fall below a zone's high watermark."
        )
    elif action == "set" and name == "vm.swappiness" and value is not None and value > 100:
        risk_note = (
            " Values above 100 treat swap as cheaper than filesystem paging and are workload/device dependent."
        )
    elif action == "set" and name == "fs.inotify.max_user_watches":
        risk_note = (
            " The limit is per real user ID; increasing it can allow workloads to consume more kernel memory if they create more watches."
        )
    elif action == "set" and name == "fs.inotify.max_user_instances":
        risk_note = " The limit is per real user ID and controls how many inotify instances that user may create."
    return Elicit(
        f"Confirm {operation} in generated file {str(target.path)!r}? Existing generated value: {old_value}. "
        f"Other matching sysctl.d files: {paths_text}. systemd-sysctl reads this configuration during boot; "
        "this operation does not change the running kernel value or invoke a sysctl reload. "
        "Later boot services or other host configuration may change the effective value. "
        "The operation uses current OS permissions without sudo and refuses conflicting settings when saving."
        f"{risk_note} State token: {target.state_token}. Repeat the exact action, parameter, value, and token.",
        KernelParameterPersistenceConfirmation,
    )


async def _confirm_kernel_command_line_change(
    action: KernelCommandLineActionName,
    argument: str,
) -> Elicit[KernelCommandLineConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _kernel_command_line_confirmation_details,
        action,
        argument,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The current boot configuration state could not be verified.")
    matching_entries = sum(argument in entry.arguments for entry in target.entries)
    operation = "add" if action == "add" else "remove"
    backend_details = (
        " This updates a static GRUB_CMDLINE_LINUX or GRUB_CMDLINE_LINUX_DEFAULT assignment in /etc/default/grub and regenerates the current GRUB config. grub-mkconfig executes the confirmed root-owned /etc/grub.d hooks; the tool does not invoke privilege elevation."
        if target.backend == "grub_config"
        else " Only entries currently visible to grubby are changed; future kernel entries may use separate distributor templates. The tool does not invoke privilege elevation."
    )
    return Elicit(
        f"{operation.capitalize()} kernel argument {target.argument!r} across "
        f"{len(target.entries)} current {'generated GRUB Linux entries' if target.backend == 'grub_config' else 'grubby boot entries'} ({matching_entries} currently contain it)? "
        "This changes persistent boot configuration and may prevent startup or change security, device, or root-filesystem behavior. "
        f"{backend_details} "
        "Concurrent external boot-entry changes can race the final command; verification can detect a mismatch but cannot roll it back. "
        "The tool does not rebuild initramfs. "
        f"State token: {target.state_token}. Repeat the exact action, argument, and token.",
        KernelCommandLineConfirmation,
    )


async def _confirm_initramfs_rebuild() -> Elicit[InitramfsRebuildConfirmation]:
    target, validation_error = await asyncio.to_thread(_initramfs_rebuild_confirmation_details)
    if validation_error or target is None:
        raise ToolError(validation_error or "The current initramfs target could not be verified.")
    mkinitcpio_details = (
        f" For mkinitcpio, the selected literal preset resolves to direct arguments {target.command_arguments!r}; "
        f"it uses config {target.config_path} and "
        f"{'the default config drop-ins' if target.uses_default_config_dropins else 'no config drop-ins because the preset selects an explicit config'}."
        if target.backend == "mkinitcpio"
        else ""
    )
    return Elicit(
        f"Rebuild {target.image_path} for the running kernel {target.kernel_release} with {target.backend}? "
        "This overwrites the current initramfs and can affect whether the system boots. The generator's configured modules, "
        "scripts, and post-update hooks may run with the MCP server's current OS permissions; the tool does not request elevation. "
        "A concurrent external change can race the final command, and a failed rebuild may leave the image unusable. "
        f"{mkinitcpio_details} State token: {target.state_token}. Repeat the exact backend, kernel release, image path, and token.",
        InitramfsRebuildConfirmation,
    )


async def _confirm_tpm_attestation(
    persistent_handle: str,
    pcr_indices: list[int],
    nonce: str,
) -> Elicit[TPMAttestationConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _tpm_attestation_confirmation_details,
        persistent_handle,
        pcr_indices,
        nonce,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The persistent TPM key could not be verified.")
    pcr_list = ", ".join(str(index) for index in target.pcr_indices)
    pcr_indices_json = json.dumps(list(target.pcr_indices), separators=(",", ":"))
    public_fingerprint = hashlib.sha256(target.public_key_pem).hexdigest()
    return Elicit(
        f"Request a TPM 2.0 quote from persistent key {target.persistent_handle} for SHA-256 PCRs [{pcr_list}] "
        f"using nonce {target.nonce}? The quote and PCR data may disclose measured boot/software state. "
        f"The key's public-key SHA-256 fingerprint is {public_fingerprint}. The tool locally checks the signature, nonce, "
        "and included PCR values; it does not establish trust in this key or decide whether measurements are acceptable. "
        "Keys that require a secret authorization value are not supported. The server does not send the quote to a verifier; "
        f"the artifacts are returned to this MCP client. Repeat the exact handle, PCR indexes JSON {pcr_indices_json}, nonce, and state token. "
        f"State token: {target.state_token}.",
        TPMAttestationConfirmation,
    )


async def _confirm_selinux_boolean_action(
    name: str,
    enabled: bool,
    persistent: bool = False,
) -> Elicit[SELinuxBooleanActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _selinux_boolean_confirmation_details,
        name,
        enabled,
        persistent,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact SELinux boolean could not be verified.")
    operation = "enable" if enabled else "disable"
    persistence = (
        " and persist the policy default across reboots" if persistent
        else " for the running system only"
    )
    return Elicit(
        f"Confirm {operation} of SELinux boolean {target.name!r}{persistence}? "
        f"Current runtime value: {target.current}; pending value: {target.pending}. "
        "This changes SELinux policy behavior for services and files governed by the boolean. "
        + ("The persistent operation can rebuild policy and may take several minutes. " if persistent else "")
        + "The command uses current-user permissions without sudo; host policy may deny it. "
        f"Type {phrase!r} and confirm.",
        SELinuxBooleanActionConfirmation,
    )


async def _confirm_selinux_context_restore(
    path: str,
) -> Elicit[SELinuxContextRestoreConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _selinux_context_restore_confirmation_details,
        path,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact SELinux context restore could not be verified.")
    old_context = target.current_context or "(no current label)"
    return Elicit(
        f"Restore the policy-defined SELinux type for the exact path {str(target.path)!r}? "
        f"Current context: {old_context}; policy context: {target.expected_context}. "
        "This runs restorecon on one existing regular file or directory without recursive traversal or force-reset options. "
        "It restores the policy-defined type and preserves customizable labels and the current SELinux user, role, and range fields. "
        "A changed type can affect which processes can access the path. The operation uses current OS permissions and does not invoke sudo. "
        f"Type {phrase!r} and confirm.",
        SELinuxContextRestoreConfirmation,
    )


async def _confirm_selinux_fcontext_rule(
    action: Literal["add", "remove"],
    path: str,
    context_type: str,
) -> Elicit[SELinuxFContextRuleConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _selinux_fcontext_rule_confirmation_details,
        action,
        path,
        context_type,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact local SELinux file-context rule could not be verified.")
    operation = "Add" if action == "add" else "Remove"
    file_kind = "directory" if target.file_type == "d" else "regular file"
    change = (
        f"The persistent local rule will assign type {target.context_type!r} to this exact {file_kind} path."
        if action == "add"
        else f"The persistent local rule assigning type {target.context_type!r} to this exact {file_kind} path will be removed."
    )
    return Elicit(
        f"{operation} SELinux file-context rule for {str(target.path)!r}? {change} "
        f"Literal anchored expression: {target.rule_expression!r}. The rule is limited to this path and file type; "
        "it does not relabel the current object or recurse. The server must already run as root. After adding a rule, "
        "use the separate confirmed SELinux context restoration action to apply its type to this exact path. "
        f"Type {phrase!r} and confirm.",
        SELinuxFContextRuleConfirmation,
    )


async def _confirm_audit_watch_rule_action(
    action: Literal["add", "remove"],
    path: str,
    permissions: str,
    key: str,
) -> Elicit[LinuxAuditRuleActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _audit_watch_rule_confirmation_details,
        action,
        path,
        permissions,
        key,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact audit watch rule could not be verified.")
    operation = "add" if action == "add" else "remove"
    scope_note = (
        "This is a runtime kernel audit rule and is not persistent across reboot. "
        "Legacy auditctl watch rules are deprecated, may affect system performance, and may increase audit log volume. "
    )
    return Elicit(
        f"Confirm {operation} of audit watch for {str(target.path)!r} with permissions {target.permissions!r} and key {target.key!r}? "
        "Permissions mean audit read, write, execute, and attribute-change events; this does not change file access. "
        f"{scope_note}The current audit rule set and watched path identity are bound to this confirmation. "
        f"Type {phrase!r} and confirm.",
        LinuxAuditRuleActionConfirmation,
    )


async def _confirm_apparmor_profile_action(
    name: str,
    action: Literal["enforce", "complain"],
) -> Elicit[AppArmorProfileActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _apparmor_profile_confirmation_details,
        name,
        action,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact loaded AppArmor profile could not be verified.")
    effect = (
        " Enforce mode denies accesses that the profile does not allow and may interrupt the confined application."
        if action == "enforce"
        else " Complain mode generally allows accesses that the profile does not allow and logs them; explicit deny rules still deny. This weakens protection while active."
    )
    return Elicit(
        f"Confirm setting loaded AppArmor profile {target.name!r} from {target.mode_before} to {target.mode_after}? "
        "The matching local profile file will be updated and reloaded; replacing a profile can affect processes already confined by it. "
        f"The operation uses the current account's permissions and does not invoke sudo.{effect} "
        f"Type {phrase!r} and confirm.",
        AppArmorProfileActionConfirmation,
    )


async def _confirm_mount_action(
    action: MountActionName,
    mount_point: str,
) -> Elicit[MountActionConfirmation]:
    entry, validation_error = _mount_action_confirmation_details(action, mount_point)
    if entry is None:
        raise ValueError(validation_error or "Mount target validation failed.")
    safe_target = json.dumps(mount_point, ensure_ascii=True)
    if action == "mount":
        operation = f"mount the configured {entry.filesystem_type} filesystem at {safe_target}"
        impact = (
            " This uses the exact /etc/fstab entry and its configured options; it may run a filesystem-specific helper "
            "and make the mounted filesystem's contents visible at the target."
        )
    else:
        operation = f"unmount the configured {entry.filesystem_type} filesystem at {safe_target}"
        impact = " This may interrupt processes using the filesystem or run a filesystem-specific unmount helper; busy filesystems are not forcibly or lazily unmounted."
    return Elicit(
        f"Confirm {operation}?{impact} The action is limited to this exact existing fstab target. It does not invoke sudo, polkit, "
        "or interactive elevation; util-linux, fstab rules, and current mount-namespace permissions determine authorization. "
        "The configured source identifier and option values are not shown.",
        MountActionConfirmation,
    )


async def _confirm_lvm_volume_action(
    action: LVMVolumeActionName,
    volume_group: str,
    logical_volume: str,
    size_bytes: int | None = None,
    snapshot_origin: str | None = None,
) -> Elicit[LVMVolumeActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _lvm_volume_action_confirmation_details,
        action,
        volume_group,
        logical_volume,
        size_bytes,
        snapshot_origin,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The LVM logical-volume action could not be verified.")
    if action == "create":
        effect = f"allocate approximately {size_bytes} bytes for a new logical volume"
    elif action == "resize":
        effect = (
            f"grow this logical volume from {target.current_size_bytes} to approximately {size_bytes} bytes. "
            "The filesystem inside it will not be resized by this operation"
        )
    elif action == "shrink":
        if target.filesystem_type == "ext4":
            effect = (
                f"shrink the unmounted ext4 logical volume from {target.current_size_bytes} bytes to "
                f"{target.normalized_size_bytes} bytes (rounded to a VG extent boundary), resizing ext4 first. "
                f"The current ext4 size is {target.filesystem_size_bytes} bytes; lvreduce will fail without reducing the LV if filesystem shrink fails"
            )
        else:
            effect = (
                f"shrink the raw logical volume from {target.current_size_bytes} bytes to "
                f"{target.normalized_size_bytes} bytes (rounded to a VG extent boundary). "
                "Any data in the removed tail will be lost"
            )
    elif action == "create_snapshot":
        effect = (
            f"create a copy-on-write snapshot named {logical_volume!r} of origin {snapshot_origin!r} "
            f"with approximately {size_bytes} bytes of snapshot capacity"
        )
    elif action == "restore_snapshot":
        effect = (
            f"merge copy-on-write snapshot {logical_volume!r} into origin {snapshot_origin!r}, replacing the origin's current contents "
            "with the snapshot point-in-time state and removing the snapshot LV"
        )
    else:
        effect = f"remove snapshot {logical_volume!r} ({target.current_size_bytes} bytes)"
    state_description = (
        "The exact volume-group/LV inventory, unmounted state, open block-device users, and filesystem geometry will be re-read after confirmation. "
        if action == "shrink"
        else "The exact snapshot/origin relationship, LV inventory, mount/swap state, device-mapper open counts, process open users, and holder identities will be re-read after confirmation. Both devices must remain closed; the server must already run as root. "
        if action == "restore_snapshot"
        else "The exact volume-group/LV inventory and free capacity will be re-read after confirmation. "
    )
    return Elicit(
        f"Confirm LVM action to {effect} in volume group {volume_group!r}? "
        f"Verified free capacity before the action: {target.free_bytes} bytes. "
        f"{state_description}"
        "The command uses current OS permissions and does not invoke sudo. "
        f"Type {phrase!r} and confirm.",
        LVMVolumeActionConfirmation,
    )


async def _confirm_lvm_group_action(
    volume_group: str,
    physical_device_paths: list[str],
    action: LVMVolumeGroupActionName = "create",
) -> Elicit[LVMVolumeGroupActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _lvm_group_action_confirmation_details,
        action,
        volume_group,
        physical_device_paths,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The LVM volume-group action could not be verified.")
    devices = ", ".join(f"{device.path} ({device.size_bytes} bytes)" for device in target.devices)
    if action == "create":
        operation = f"create the new volume group {target.volume_group!r} from {len(target.devices)} blank devices"
        impact = " vgcreate will initialize each selected device as an LVM physical volume and write LVM metadata; existing data may become inaccessible."
    elif action == "add_pv":
        operation = f"add {len(target.devices)} blank physical volume(s) to existing group {target.volume_group!r}"
        impact = " vgextend will initialize each selected device as an LVM physical volume and add its capacity to the group; existing raw data may become inaccessible."
    elif action == "move_pv":
        operation = (
            f"atomically move {target.source_allocated_extents} allocated extents "
            f"({target.move_bytes} bytes) from {target.devices[0].path} to {target.devices[1].path} "
            f"inside group {target.volume_group!r}"
        )
        impact = " pvmove --atomic requires twice the current source allocation free on the destination; it may run for up to 30 minutes and can affect storage performance."
    else:
        operation = f"remove {len(target.devices)} unused physical volume(s) from group {target.volume_group!r}"
        impact = " Only PVs with zero allocated extents are eligible; the group loses their capacity and their LVM labels remain in place."
    if action in {"create", "add_pv"}:
        preflight = "Recognized signatures, mounted/swap devices, active holders, and disks with child partitions are refused, but raw data cannot be detected. "
        if action == "create":
            preflight += "A new group may use at most one selected PV per physical disk. "
    elif action == "remove_pv":
        preflight = "Only exact PVs in this group with zero allocated extents and no mounted, swap, or block-layer holder use are eligible. "
    else:
        preflight = "The source and destination must be distinct PV members of this group; mounted-as-a-filesystem or swap PVs and read-only devices are refused. Active LVs may use the PVs during migration. "
    return Elicit(
        f"Confirm LVM action to {operation}: {devices}?{impact} "
        f"{preflight}"
        "The exact volume-group/PV inventory, allocated extents, and block-device identities will be re-read after confirmation; blank-device signatures are checked before create/add. "
        "The command uses current OS permissions and does not invoke sudo or interactive elevation. "
        f"Type {phrase!r} and confirm.",
        LVMVolumeGroupActionConfirmation,
    )


async def _confirm_btrfs_snapshot_action(
    action: BtrfsSnapshotActionName,
    filesystem_top_level_path: str,
    snapshot_path: str,
    source_path: str | None = None,
    read_only: bool = False,
    target_path: str | None = None,
    backup_path: str | None = None,
) -> Elicit[BtrfsSnapshotActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _btrfs_snapshot_action_confirmation_details,
        action,
        filesystem_top_level_path,
        snapshot_path,
        source_path,
        read_only,
        target_path,
        backup_path,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The Btrfs snapshot action could not be verified.")
    if action == "create":
        assert target.source is not None
        operation = (
            f"create a {'read-only ' if target.read_only else ''}Btrfs snapshot at {str(target.snapshot_path)!r} "
            f"from {str(target.source.path)!r}"
        )
        effects = (
            " Btrfs snapshots share file extents through copy-on-write and are not independent backups. "
            "Snapshot creation may flush dirty data, and nested subvolumes are not recursively captured."
        )
    elif action == "restore":
        assert target.snapshot is not None and target.restore_target is not None and target.backup_path is not None
        operation = (
            f"replace unmounted subvolume {str(target.restore_target.path)!r} "
            f"(ID {target.restore_target.subvolume_id}) with a writable clone of read-only snapshot "
            f"{str(target.snapshot_path)!r} (UUID {target.snapshot.uuid})"
        )
        effects = (
            f" The target and staged clone are exchanged atomically, then the original is moved to {str(target.backup_path)!r} without replacing an existing path. "
            "If interrupted between those steps, the original may remain at the staging path while the clone occupies the target path. "
            "The selected read-only snapshot remains unchanged. The target must remain unmounted, non-default, and free of nested subvolumes. "
            "The operation does not change /etc/fstab or the Btrfs default subvolume, and the new clone will be writable."
        )
    else:
        assert target.snapshot is not None
        origin = (
            f" Parent snapshot UUID: {target.snapshot.parent_uuid}."
            if target.snapshot.parent_uuid != "-"
            else f" Received source UUID: {target.snapshot.received_uuid}."
        )
        operation = f"delete Btrfs snapshot {str(target.snapshot_path)!r} (subvolume ID {target.snapshot.subvolume_id})"
        effects = (
            f"{origin} The snapshot directory is removed and its storage blocks are cleaned asynchronously; "
            "the tool refuses mounted snapshots, the default subvolume, and snapshots containing nested subvolumes."
        )
    return Elicit(
        f"Confirm Btrfs action to {operation}?{effects} The top-level filesystem, exact paths, and current subvolume identities/state "
        "will be re-read after confirmation. The command uses current OS permissions and does not invoke sudo or interactive elevation. "
        f"Type {phrase!r} and confirm.",
        BtrfsSnapshotActionConfirmation,
    )


async def _confirm_luks_action(
    action: LUKSActionName,
    device_path: str,
    mapping_name: str | None = None,
    key_file: str | None = None,
    luks_version: LUKSVersionName = "luks2",
    new_key_file: str | None = None,
    key_slot: int | None = None,
) -> Elicit[LUKSActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _luks_action_confirmation_details,
        action,
        device_path,
        mapping_name,
        key_file,
        luks_version,
        new_key_file,
        key_slot,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The LUKS action could not be verified.")
    if action == "format":
        operation = f"write a new {target.luks_version.upper()} encryption header to the blank, unmounted block device"
        impact = " This will replace the device metadata and can make existing data inaccessible; it does not securely erase the data area."
    elif action == "open":
        operation = f"unlock the {target.luks_version.upper()} device and create mapping {mapping_name!r}"
        impact = " This makes the decrypted block device available in the current host namespace; it does not mount a filesystem."
    elif action == "close":
        operation = f"close the active {target.luks_version.upper()} mapping {mapping_name!r}"
        impact = " This can interrupt users of the mapped device; cryptsetup will refuse a busy mapping and no force option is used."
    elif action == "add_key":
        operation = f"add a new unlock key from private file {target.new_key_file!r}"
        impact = f" Active keyslots before the change: {list(target.active_keyslots)}. The existing unlock key is required, and the new key file must remain available to whoever needs to unlock this device."
    elif action == "remove_key":
        operation = f"remove active keyslot {target.key_slot}"
        impact = f" Active keyslots before the change: {list(target.active_keyslots)}. Credentials associated only with this slot will no longer unlock the device; at least one other active slot will remain."
    else:
        operation = f"grow active {target.luks_version.upper()} mapping {mapping_name!r} to match the larger backing device"
        impact = " This changes the mapped device size only; any filesystem or LVM layer above it must be resized separately."
    key_note = " The existing private key-file identity is bound to confirmation; its contents are passed to cryptsetup through standard input and are not returned." if target.key_file_digest else ""
    if target.new_key_file_digest:
        key_note += " The new key file identity is also bound to confirmation; its contents are passed through an anonymous in-memory file and are not returned or written to a temporary disk file."
    return Elicit(
        f"Confirm {operation} on {target.device_path}?{impact} The block-device identity, capacity, and current LUKS header, keyslot, token-to-keyslot association, or mapping state will be rechecked after confirmation."
        f"{key_note} Commands use current OS permissions and do not invoke sudo or interactive elevation. Type {phrase!r} and confirm.",
        LUKSActionConfirmation,
    )


async def _confirm_luks_token_action(
    action: LUKSTokenActionName,
    device_path: str,
    token_id: int,
    key_slot: int | None = None,
    token_json_file: str | None = None,
    export_file: str | None = None,
) -> Elicit[LUKSTokenActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _luks_token_confirmation_details,
        action,
        device_path,
        token_id,
        key_slot,
        token_json_file,
        export_file,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The LUKS2 token action could not be verified.")
    if action == "remove":
        operation = f"remove LUKS2 token {token_id} of type {target.token_type!r}"
        impact = (
            f" It is currently associated with keyslots {list(target.previous_keyslots)}. "
            "This removes the token metadata for any token type and can disable token-based unlocking; it does not remove keyslots or encrypted data."
        )
    elif action == "unassign":
        resulting = [slot for slot in target.previous_keyslots if slot != key_slot]
        operation = f"unassign LUKS2 token {token_id} from keyslot {key_slot}"
        impact = (
            f" Current token bindings are {list(target.previous_keyslots)}; the remaining bindings will be {resulting}. "
            "If this removes the last binding, the token remains present but unbound and cannot unlock through a keyslot."
        )
    elif action == "import":
        operation = f"import token JSON as LUKS2 token {token_id} of type {target.token_type!r}"
        impact = (
            f" The private source file is {target.token_json_file!r}; its identity and content digest are bound to the confirmation. "
            f"Its keyslot bindings will be {list(target.imported_token.keyslots) if target.imported_token else []}. "
            "Token JSON can contain provider-specific authentication or enrollment data; its contents are not shown or sent to this client. "
            "An existing token ID is never replaced."
        )
    else:
        operation = f"export LUKS2 token {token_id} of type {target.token_type!r}"
        impact = (
            f" The provider-specific JSON will be written to new private file {target.export_file!r} with mode 0600 and no overwrite. "
            "That file may contain sensitive provider metadata; its contents will not be returned to this client."
        )
    return Elicit(
        f"Confirm {operation} on {target.device_path}?{impact} The exact block device, LUKS2 UUID, full bounded header metadata, token fields, cryptsetup executable, and relevant import/export file identity are bound to this confirmation and rechecked. "
        "Cryptsetup external-token plugin loading is disabled for this action. The command uses current OS permissions and does not invoke sudo or interactive elevation. "
        f"Type {phrase!r} and confirm.",
        LUKSTokenActionConfirmation,
    )


async def _confirm_luks_header_action(
    action: LUKSHeaderActionName,
    device_path: str,
    backup_file: str,
    expected_luks_uuid: str | None = None,
) -> Elicit[LUKSHeaderActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _luks_header_action_confirmation_details,
        action,
        device_path,
        backup_file,
        expected_luks_uuid,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The LUKS header action could not be verified.")
    if action == "backup":
        operation = f"create a LUKS{target.luks_version[-1]} header backup from {target.device_path} at {target.backup_file}"
        impact = (
            f" This file contains the LUKS header and keyslot area ({target.device_size_bytes} byte device; UUID {target.luks_uuid}). "
            "A passphrase valid when the backup was made may continue to decrypt the data even after it is later changed or removed. "
            "Keep the backup private and securely erase it when no longer needed."
        )
    else:
        operation = f"restore the LUKS{target.luks_version[-1]} header backup at {target.backup_file} onto {target.device_path}"
        impact = (
            f" The backup is {target.backup_file_size_bytes} bytes with SHA-256 {target.backup_file_digest}; its UUID is {target.luks_uuid}. "
            "Restore replaces the current header, every keyslot, and LUKS2 token metadata. Credentials added after the backup may stop working, "
            "while credentials present in the backup may become valid again."
        )
    return Elicit(
        f"Confirm {operation}?{impact} Device identity, header UUID/version, keyslot/token state, backup-file identity/digest, and restore safety state will be rechecked after confirmation. "
        "Cryptsetup performs its own compatibility checks. The command uses current OS permissions and does not invoke sudo or interactive elevation. "
        f"Type the exact phrase {phrase!r} and confirm.",
        LUKSHeaderActionConfirmation,
    )


async def _confirm_ext4_action(
    action: Ext4FilesystemActionName,
    device_path: str,
    target_size_bytes: int | None = None,
) -> Elicit[Ext4FilesystemActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _ext4_action_confirmation_details,
        action,
        device_path,
        target_size_bytes,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The ext4 action could not be verified.")
    if action == "create":
        operation = "create a new ext4 filesystem on the verified blank block device"
        impact = " This writes filesystem metadata and can make existing data inaccessible; signatures are checked but never erased first."
    elif action == "grow":
        current_size = (target.block_count or 0) * (target.block_size_bytes or 0)
        operation = f"grow the ext4 filesystem from approximately {current_size} bytes to use the larger block device"
        impact = " A mounted ext4 filesystem may be grown online when supported by the kernel; an offline filesystem can also be grown."
    else:
        current_size = (target.block_count or 0) * (target.block_size_bytes or 0)
        operation = f"shrink the offline ext4 filesystem from {current_size} bytes to exactly {target_size_bytes} bytes"
        impact = (
            " The filesystem must be unmounted and unused, including as swap, with no block-device holders. "
            "A forced read-only e2fsck check must report it clean before and after the resize; this tool does not repair errors. "
            "resize2fs may reject a target that is too small. This changes only the filesystem size, not the block device, partition, or LVM volume, and may run for up to one hour."
        )
    mount_state = " It is currently mounted." if target.mounted else " It is not currently mounted."
    return Elicit(
        f"Confirm {operation} at {target.device_path}?{impact}{mount_state} Device identity and filesystem state will be rechecked after confirmation."
        " The operation uses current OS permissions and does not invoke sudo or interactive elevation. Type the exact phrase "
        f"{phrase!r} and confirm.",
        Ext4FilesystemActionConfirmation,
    )


async def _confirm_xfs_action(
    action: XFSFilesystemActionName,
    device_path: str,
) -> Elicit[XFSFilesystemActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _xfs_action_confirmation_details,
        action,
        device_path,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The XFS action could not be verified.")
    if action == "create":
        operation = "create a new XFS filesystem on the block device with no recognized signatures"
        impact = " This writes filesystem metadata and may make existing data inaccessible; recognized signatures are checked and mkfs.xfs is not forced over them, but arbitrary raw data cannot be detected."
    else:
        current_size = (target.block_count or 0) * (target.block_size_bytes or 0)
        operation = f"grow the mounted XFS filesystem from approximately {current_size} bytes"
        impact = " XFS growth is online-only and expands the data section to the device's available size; XFS does not support shrinking."
    mount_state = (
        f" It is mounted at {target.mountpoint!r}."
        if target.mountpoint is not None
        else " It is not mounted."
    )
    return Elicit(
        f"Confirm {operation} at {target.device_path}?{impact}{mount_state} Device identity, capacity, signatures, and filesystem geometry will be rechecked after confirmation."
        " The operation uses current OS permissions and does not invoke sudo or interactive elevation. Type the exact phrase "
        f"{phrase!r} and confirm.",
        XFSFilesystemActionConfirmation,
    )


async def _confirm_btrfs_filesystem_action(
    action: BtrfsFilesystemActionName,
    target_path: str,
    target_size_bytes: int | None = None,
) -> Elicit[BtrfsFilesystemActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _btrfs_filesystem_action_confirmation_details,
        action,
        target_path,
        target_size_bytes,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The Btrfs filesystem action could not be verified.")
    if action == "create":
        operation = f"create a new single-device Btrfs filesystem on {target.device_path}"
        impact = (
            " This writes filesystem metadata and may make existing data inaccessible. Recognized signatures are checked and never forced over, "
            "but arbitrary raw data cannot be detected. Whole devices with child partitions, active holders, mounted devices, and swap devices are refused."
        )
        location = f"Block-device capacity: {target.device_capacity_bytes} bytes."
    elif action == "grow":
        operation = f"grow the single-device Btrfs filesystem mounted at {target.target_path} to use its larger backing device"
        impact = " The underlying block device must already have been enlarged; this is an online growth operation and does not shrink the filesystem."
        location = (
            f"Current Btrfs device size: {target.filesystem_device_size_bytes} bytes; backing device capacity: "
            f"{target.device_capacity_bytes} bytes; filesystem UUID: {target.filesystem_uuid}."
        )
    else:
        operation = (
            f"shrink the single-device Btrfs filesystem mounted at {target.target_path} from "
            f"{target.filesystem_device_size_bytes} bytes to {target.target_size_bytes} bytes"
        )
        impact = (
            " This is an online operation that may relocate a large amount of data and cause heavy I/O. "
            "The confirmed size is checked against Btrfs's current minimum and sector alignment, but concurrent writes can change that minimum and make the operation fail. "
            "An active Btrfs swapfile can also prevent shrinking when its extents overlap the target region. The command may run for up to one hour. "
            "This changes only the filesystem size; any partition, LVM, LUKS, or backing-device resize must be a separate later action after verification."
        )
        location = (
            f"Current minimum device size: {target.minimum_device_size_bytes} bytes; Btrfs sector size: "
            f"{target.filesystem_sector_size_bytes} bytes; backing device capacity: {target.device_capacity_bytes} bytes; "
            f"filesystem UUID: {target.filesystem_uuid}."
        )
    return Elicit(
        f"Confirm {operation}?{impact} {location} Device or mount identity, filesystem state, and capacity will be rechecked after confirmation. "
        f"The command uses current OS permissions and does not invoke sudo or interactive elevation. Type the exact phrase {phrase!r} and confirm.",
        BtrfsFilesystemActionConfirmation,
    )


async def _confirm_md_raid_action(
    action: MDRaidActionName,
    array_path: str,
    device_paths: list[str],
    raid_level: Literal["raid0", "raid1", "raid4", "raid5", "raid6", "raid10"] | None = None,
    chunk_size_kib: int | None = None,
    read_only: bool = True,
) -> Elicit[MDRaidActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _md_raid_action_confirmation_details,
        action,
        array_path,
        device_paths,
        raid_level,
        chunk_size_kib,
        read_only,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The MD RAID action could not be verified.")
    members = ", ".join(target_device.path for target_device in target.devices)
    if action == "create":
        operation = (
            f"create and activate {target.raid_level} array {target.array_path} from {len(target.devices)} selected block devices"
        )
        impact = (
            " This writes RAID metadata to each device and starts array initialization; existing data may become inaccessible. "
            "The tool refuses recognized signatures but cannot prove that raw data is disposable."
        )
        if target.chunk_size_kib is not None:
            impact += f" Chunk size: {target.chunk_size_kib} KiB."
        if target.raid_level == "raid4":
            impact += " RAID4 dedicates one member to parity, so parity writes use that member."
    elif action == "assemble":
        mode = "read-only" if target.read_only else "read-write"
        operation = f"assemble the complete clean {target.raid_level} array at {target.array_path} in {mode} mode from {len(target.devices)} exact components"
        if target.read_only:
            impact = " The array will be activated read-only; mdadm will not start resync, recovery, or reshape writes. The tool does not request metadata updates or degraded startup."
        else:
            impact = " The array will be activated read-write. MD metadata or redundancy recovery may be written, and applications that later mount or open it can modify all member data. The tool does not use --force, scan for other components, or start a degraded array."
    elif action == "add_spare":
        operation = f"add {members} as a spare to {target.array_path}"
        impact = " This writes RAID metadata to the blank device; no active member is failed or removed."
    elif action == "replace_member":
        old_member, replacement = target.devices
        operation = f"replace active member {old_member.path} with blank device {replacement.path} in {target.array_path}"
        impact = (
            " The blank device is first added as a spare, then mdadm starts replacement recovery while the old member remains in service. "
            "Recovery may continue in the background; the array must be healthy and idle before starting."
        )
    elif action == "mark_faulty":
        operation = f"mark active member {members} faulty in {target.array_path}"
        impact = (
            " This removes the member from active service and may degrade the array or start recovery onto a configured spare. "
            "Data remains available only while the remaining array has sufficient redundancy; another failure may cause data loss."
        )
    elif action == "remove_faulty":
        operation = f"remove already-faulty member {members} from {target.array_path}"
        impact = " This does not restore redundancy or erase RAID metadata from the member device."
    elif action == "check":
        operation = f"start a non-repairing consistency check on {target.array_path}"
        impact = (
            " This reads every block on every member and may run for hours. Mismatches are recorded rather than corrected, "
            "but read errors can still trigger MD's normal recovery writes to a member. The request runs in the background; "
            "no member path is required."
        )
    elif action == "stop":
        operation = f"stop the active MD array {target.array_path}"
        impact = (
            " This makes the array block device unavailable until it is assembled again; it does not erase member data or RAID metadata. "
            f"Current array state: {target.array.array_state}; degraded member count: {target.array.degraded}; sync action: {target.array.sync_action}. "
            "The array must be idle, read-write, unmounted, unused by swap, and have no block-layer holders."
        )
    else:
        operation = f"remove the inactive spare {members} from {target.array_path}"
        impact = " The device's existing RAID metadata is left in place."
    if action == "check":
        recheck_scope = "The exact array identity, member identities, and current sync state will be re-read after confirmation. "
    elif action == "stop":
        recheck_scope = "The exact array block-device identity, array sync state, mount/swap use, and block-layer holders will be re-read after confirmation. "
    elif action == "assemble":
        recheck_scope = "The UUID, metadata version, RAID geometry, clean state, event counter, unique member roles, component UUIDs, and exact block-device identities will be re-read after confirmation. "
    else:
        recheck_scope = "The exact array identity/state and selected block-device identities, signatures, and active-use state will be re-read after confirmation. "
    return Elicit(
        f"Confirm MD RAID action to {operation}?{impact} {recheck_scope}"
        "The command uses current OS permissions and does not invoke sudo or interactive elevation. "
        f"Type {phrase!r} and confirm.",
        MDRaidActionConfirmation,
    )


async def _confirm_local_identity_action(
    action: LocalIdentityActionName,
    username: str | None = None,
    group_name: str | None = None,
    login_shell: str | None = None,
    create_home: bool = False,
    home_directory: str | None = None,
    remove_home: bool = False,
) -> Elicit[LocalIdentityActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _local_identity_action_confirmation_details,
        action,
        username,
        group_name,
        login_shell,
        create_home,
        home_directory,
        remove_home,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The local identity action could not be verified.")
    if action == "create_user":
        change = f"create user {username!r} in primary group {group_name!r}"
        if target.create_home and target.home_directory:
            home_effect = f" and create home directory {target.home_directory!r} from the confirmed /etc/skel template"
        else:
            home_effect = " and create no home directory"
        effects = f" The account will use shell {target.login_shell!r}{home_effect}. It will start with its password locked."
    elif action == "delete_user":
        change = f"delete local user {username!r}"
        if target.remove_home and target.source_home_directory:
            effects = (
                f" The exact existing home tree at {target.source_home_directory!r} will be recursively removed after account deletion "
                f"({target.home_tree_entries} entries, approximately {target.home_tree_bytes} file bytes). "
                "The tree must remain unchanged and contain no mounted filesystems. Its files are permanently unlinked, not securely erased. "
                "The mail spool is left in place; no force mode is used, and userdel refuses users with active processes."
            )
        else:
            effects = " The home directory and files are left in place; no force mode is used, and userdel refuses users with active processes."
    elif action == "lock_user":
        change = f"lock the password for local user {username!r}"
        effects = " Existing sessions remain active; this does not change the account shell or SSH keys."
    elif action == "unlock_user":
        change = f"unlock the existing password for local user {username!r}"
        effects = " This restores password authentication only if the account already has a password hash; it does not set or reveal a password."
    elif action == "set_shell":
        change = f"set the login shell for local user {username!r} to {target.login_shell!r}"
        effects = " This does not change the password or account membership."
    elif action == "move_home":
        change = f"move local user {username!r}'s home directory from {target.source_home_directory!r} to {target.home_directory!r}"
        effects = (
            " The destination must be a new directory directly managed beneath /home or /var/home. "
            "The account must have no running processes; usermod enforces this on Linux. "
            "Cross-filesystem moves may take up to 30 minutes, may need extra destination space, and may require manual ACL/xattr ownership adjustments. "
            "A concurrent path or home-tree change can race after the final recheck. A failed or interrupted move may leave partial state; inspect both paths and the account before retrying."
        )
    elif action == "create_group":
        change = f"create local group {group_name!r}"
        effects = " The system selects the new numeric GID."
    elif action == "delete_group":
        change = f"delete empty local group {group_name!r}"
        effects = " Groups with primary users or secondary members are refused."
    elif action == "add_user_to_group":
        change = f"add local user {username!r} to secondary group {group_name!r}"
        effects = " This changes the user's supplementary group membership and may grant privileges defined by host policy, including administrative or sudo-equivalent access through this group."
    else:
        change = f"remove local user {username!r} from secondary group {group_name!r}"
        effects = " A primary group cannot be removed by this operation."
    if target.side_effect_notes:
        effects += " " + " ".join(target.side_effect_notes)
    return Elicit(
        f"Confirm {change}?{effects} Local passwd/group state is bound to this request and rechecked before execution. "
        "Commands use current OS permissions without sudo. This tool does not return plaintext passwords, home-file contents, or SSH-key contents. "
        "The unlock action checks only whether /etc/shadow contains a usable local password hash and never returns it. "
        f"Type {phrase!r} and confirm.",
        LocalIdentityActionConfirmation,
    )


async def _confirm_local_password_set(
    username: str,
    password: SecretStr,
) -> Elicit[LocalPasswordSetConfirmation]:
    target_username, phrase, validation_error = await asyncio.to_thread(
        _local_password_set_confirmation_details,
        username,
        password.get_secret_value(),
    )
    if validation_error or target_username is None or phrase is None:
        raise ValueError(validation_error or "The local password change could not be verified.")
    return Elicit(
        f"Set a new password for exact local account {target_username!r}? "
        "The password is not included in this confirmation prompt. It will be sent to the local chpasswd command over stdin, "
        "not in command arguments; system password policy may reject it. Password-aging metadata may update. "
        "If the account was password-locked, the tool preserves that lock; use the separate unlock action when password login should be enabled. "
        "This action does not change the account's shell or group membership. "
        "The current local account, password status, and shadow-file identity are rechecked before the command. "
        "No sudo or interactive elevation is requested. "
        f"Type {phrase!r} and confirm.",
        LocalPasswordSetConfirmation,
    )


async def _confirm_local_ssh_key_action(
    action: SSHKeyActionName,
    username: str,
    public_key: str,
) -> Elicit[LocalSSHKeyActionConfirmation]:
    target_username, fingerprint, phrase, validation_error = await asyncio.to_thread(
        _local_ssh_key_confirmation_details,
        action,
        username,
        public_key,
    )
    if validation_error or target_username is None or fingerprint is None or phrase is None:
        raise ValueError(validation_error or "The local SSH key change could not be verified.")
    verb = "add" if action == "add" else "remove"
    effects = (
        " The operation accepts a plain OpenSSH public key only, keeps existing unrelated entries, and rechecks the account home and authorized_keys identity."
    )
    if action == "add":
        effects += " A missing .ssh directory is created with mode 0700 and a new authorized_keys file with mode 0600."
    else:
        effects += " Every exact matching key entry is removed; other entries are preserved."
    if target_username == "root":
        effects += " This may permit root SSH login if the active sshd configuration allows it."
    return Elicit(
        f"Confirm {verb} public key {fingerprint} for exact local account {target_username!r}?{effects} "
        "The key fingerprint is shown instead of the full public key. This does not change sshd configuration or guarantee SSH login is enabled. "
        "Commands use current OS permissions without sudo. "
        f"Type {phrase!r} and confirm.",
        LocalSSHKeyActionConfirmation,
    )


async def _confirm_sudo_policy_action(
    action: SudoPolicyActionName,
    username: str,
    command_path: str,
    arguments: str = "",
) -> Elicit[SudoPolicyActionConfirmation]:
    target_username, phrase, validation_error = await asyncio.to_thread(
        _sudo_policy_confirmation_details,
        action,
        username,
        command_path,
        arguments,
    )
    if validation_error or target_username is None or phrase is None:
        raise ValueError(validation_error or "The sudo policy request could not be verified.")
    command_text = command_path if not arguments else f"{command_path} {arguments}"
    verb = "grant" if action == "grant" else "revoke"
    effects = (
        " The rule applies to this exact local user and root-run command. Arguments match exactly; sudoers wildcards are not accepted. "
        "The rule carries the sudoers PASSWD tag and does not use NOPASSWD. The exempt_group setting or other matching host rules may still affect effective authentication. The executable may itself perform broad system changes. "
        "The generated drop-in is checked with visudo before and after the change."
    )
    return Elicit(
        f"Confirm {verb} the PASSWD-tagged sudoers rule for {target_username!r} and {command_text!r}?{effects} "
        "The MCP server must already be root; this tool does not invoke sudo. "
        f"Type {phrase!r} and confirm.",
        SudoPolicyActionConfirmation,
    )


async def _confirm_sudo_group_policy_action(
    action: SudoPolicyActionName,
    group_name: str,
    command_path: str,
    arguments: str = "",
) -> Elicit[SudoPolicyActionConfirmation]:
    target_group, phrase, validation_error = await asyncio.to_thread(
        _sudo_group_policy_confirmation_details,
        action,
        group_name,
        command_path,
        arguments,
    )
    if validation_error or target_group is None or phrase is None:
        raise ValueError(validation_error or "The sudo group policy request could not be verified.")
    command_text = command_path if not arguments else f"{command_path} {arguments}"
    verb = "grant" if action == "grant" else "revoke"
    return Elicit(
        f"Confirm {verb} the PASSWD-tagged sudoers rule for local group {target_group!r} and command {command_text!r}? "
        "Every member of the group may run this exact root-owned executable as root with the listed literal arguments. "
        "Arguments cannot use sudoers wildcards. Other matching host rules or Defaults exempt_group may affect effective authentication, "
        "and the executable may itself provide broad root capability. The generated mode-0440 drop-in and full sudoers configuration "
        "are checked with visudo before and after the change. The MCP server must already run as root and does not invoke sudo. "
        f"Type {phrase!r} and confirm.",
        SudoPolicyActionConfirmation,
    )


async def _confirm_sssd_domain_action(
    action: SSSDDomainActionName,
    domain: str,
) -> Elicit[SSSDDomainActionConfirmation]:
    target_domain, phrase, validation_error = await asyncio.to_thread(
        _sssd_domain_confirmation_details,
        action,
        domain,
    )
    if validation_error or target_domain is None or phrase is None:
        raise ValueError(validation_error or "The SSSD domain request could not be verified.")
    verb = "enable" if action == "enable" else "disable"
    effects = (
        " This changes only membership in the [sssd] domains list; the existing [domain/NAME] settings, PAM stack, and service state are not edited. "
        "Enabling a domain lets SSSD query that configured identity provider. Disabling it can remove remote users from NSS lookups and prevent their logins. "
        "The candidate is checked with sssctl config-check and installed atomically; no service restart is requested, though SSSD may reload configuration automatically. "
        "This control refuses conf.d snippets and refuses disabling the last enabled domain."
    )
    return Elicit(
        f"Confirm {verb} the existing SSSD domain {target_domain!r}?{effects} "
        "The MCP server must already run as root; this tool does not invoke sudo. "
        f"Type {phrase!r} and confirm.",
        SSSDDomainActionConfirmation,
    )


async def _confirm_pam_profile_action(
    action: PAMProfileActionName,
    profile: str,
) -> Elicit[PAMProfileActionConfirmation]:
    title, phrase, validation_error = await asyncio.to_thread(
        _pam_profile_confirmation_details,
        action,
        profile,
    )
    if validation_error or title is None or phrase is None:
        raise ValueError(validation_error or "The PAM profile request could not be verified.")
    verb = "enable" if action == "enable" else "disable"
    effects = (
        " This updates the selection for one package-supplied PAM profile through pam-auth-update and may rewrite the common-* stack used by all installed services. "
        "The profile can affect SSH, sudo, console, display-manager login, account checks, password changes, or session setup; an unsuitable profile can prevent logins. "
        "No direct /etc/pam.d stack edits or --force option are used. Existing local edits may be preserved or cause pam-auth-update to refuse regeneration. "
        "Keep the current session open and verify a separate authentication path before closing it. "
        "The server must already run as root; this tool does not invoke sudo."
    )
    return Elicit(
        f"Confirm {verb} the packaged PAM profile {title!r} ({profile!r})?{effects} "
        f"Type {phrase!r} and confirm.",
        PAMProfileActionConfirmation,
    )


async def _confirm_audio_endpoint_action(
    action: AudioActionName,
    direction: AudioDirectionName,
    endpoint_id: str,
    endpoint_name: str,
    volume_percent: int | None = None,
    muted: bool | None = None,
) -> Elicit[AudioEndpointActionConfirmation]:
    snapshot, validation_error = await asyncio.to_thread(
        _audio_action_confirmation_details,
        action,
        direction,
        endpoint_id,
        endpoint_name,
        volume_percent,
        muted,
    )
    if snapshot is None:
        raise ValueError(validation_error or "Audio endpoint validation failed.")

    safe_name = json.dumps(endpoint_name, ensure_ascii=True)
    current_volume = ", ".join(f"{channel} {value}" for channel, value in snapshot.volume_channels)
    current_volume = current_volume or "unavailable"
    current_mute = "muted" if snapshot.muted else "unmuted" if snapshot.muted is not None else "mute state unavailable"
    default_state = "is the current default" if snapshot.is_default else "is not the current default" if snapshot.is_default is not None else "default state unavailable"
    if action == "set_volume":
        operation = f"set the {direction} volume to {volume_percent}%"
        effect = " This sets every endpoint channel to at most 100% and affects all audio clients using this endpoint."
    elif action == "set_mute":
        operation = f"{'mute' if muted else 'unmute'} the {direction}"
        effect = " This affects all audio clients using this endpoint."
    else:
        operation = f"make this {direction} the current default endpoint"
        effect = " New streams may use it according to audio-server policy; WirePlumber remembers the selection across restarts."
    return Elicit(
        f"Confirm {operation} for endpoint {safe_name} (ID {endpoint_id})? "
        f"Current state: channels {current_volume}; {current_mute}; it {default_state}. "
        f"The endpoint state token is {snapshot.state_token}. This uses the current user's audio session and does not request elevation.{effect} "
        "Audio endpoint controls may affect every client using that sink or source. A client disconnect does not cancel a command after confirmation.",
        AudioEndpointActionConfirmation,
    )


async def _confirm_display_brightness_change(
    device_name: str,
    brightness: int,
) -> Elicit[DisplayBrightnessConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _display_brightness_confirmation_details,
        device_name,
        brightness,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The requested display brightness change could not be verified.")
    current = target.before
    effect = (
        " A brightness of zero can turn off the panel backlight and make the display difficult to read."
        if target.requested_brightness == 0
        else ""
    )
    return Elicit(
        f"Confirm setting backlight {current.name!r} from {current.brightness}/{current.max_brightness} "
        f"to {target.requested_brightness}/{current.max_brightness}? "
        f"The hardware-reported brightness is {current.actual_brightness if current.actual_brightness is not None else 'unavailable'}. "
        "The exact sysfs device, current value, maximum, and requested value are bound to confirmation and checked again. "
        "The server uses current OS permissions and does not request elevation."
        f"{effect} Type {target.confirmation_phrase!r} and confirm.",
        DisplayBrightnessConfirmation,
    )


async def _confirm_fan_control(
    controller: str,
    pwm_index: int,
    action: FanControlActionName,
) -> Elicit[FanControlActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _fan_control_confirmation_details,
        controller,
        pwm_index,
        action,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The requested fan controller could not be verified.")
    if action == "set_full":
        operation = f"set PWM channel {pwm_index} on {target.chip_name!r} to maximum speed"
        impact = (
            f" The current mode/value are {target.control_mode}/{target.pwm_value}; the tool requests manual mode and PWM 255 (100%). "
            "The write may be denied by current permissions. After switching to manual mode, an interrupted operation could leave manual control active."
        )
    else:
        operation = f"return PWM channel {pwm_index} on {target.chip_name!r} to automatic fan control"
        impact = f" The current mode/value are {target.control_mode}/{target.pwm_value}; automatic mode is requested as pwm_enable=2."
    rpm = f" Current tachometer reading: {target.fan_rpm} RPM." if target.fan_rpm is not None else " No matching fan RPM input is exposed."
    return Elicit(
        f"Confirm {operation} on {target.controller_path}?{impact}{rpm} A driver may map this PWM channel to one or more fans, and hardware may not follow the requested value; verify fan RPM and temperature readings. "
        "The controller, channel, current values, and sysfs attribute identity are bound to this confirmation and rechecked before writing. "
        f"The command uses current OS permissions without sudo. Type {phrase!r} and confirm.",
        FanControlActionConfirmation,
    )


async def _confirm_gpu_power_limit(
    drm_card: str,
    controller: str,
    power_index: int,
    target_micro_watts: int,
) -> Elicit[GPUPowerLimitActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _gpu_power_limit_confirmation_details,
        drm_card,
        controller,
        power_index,
        target_micro_watts,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The requested GPU power cap could not be verified.")
    current_watts = target.current_limit_micro_watts / 1_000_000
    target_watts = target_micro_watts / 1_000_000
    minimum_watts = target.minimum_limit_micro_watts / 1_000_000
    maximum_watts = target.maximum_limit_micro_watts / 1_000_000
    direction = "raise" if target_micro_watts > target.current_limit_micro_watts else "lower"
    return Elicit(
        f"Confirm {direction} the {target.chip_name!r} GPU power cap on {target.drm_card} ({target.pci_address}) "
        f"from {current_watts:g} W to {target_watts:g} W? The driver reports an allowed range of {minimum_watts:g}–{maximum_watts:g} W. "
        "A higher cap can increase power draw and heat; a lower cap can reduce performance. The change uses the current user's permissions, "
        "and may be refused by the driver or kernel. GPU identity, cap range, current value, and the sysfs attribute are bound to this confirmation and rechecked. "
        f"Type {phrase!r} and confirm.",
        GPUPowerLimitActionConfirmation,
    )


async def _confirm_powercap_limit(
    zone: str,
    constraint_index: int,
    target_power_limit_uw: int,
) -> Elicit[PowercapLimitActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _powercap_limit_confirmation_details,
        zone,
        constraint_index,
        target_power_limit_uw,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The requested powercap constraint could not be verified.")
    current_watts = target.current_power_limit_uw / 1_000_000
    target_watts = target_power_limit_uw / 1_000_000
    minimum_watts = target.minimum_power_limit_uw / 1_000_000
    maximum_watts = target.maximum_power_limit_uw / 1_000_000
    direction = "raise" if target_power_limit_uw > target.current_power_limit_uw else "lower"
    constraint = target.constraint_name or f"constraint {constraint_index}"
    window = f" The current time window is {target.time_window_us} microseconds." if target.time_window_us is not None else ""
    return Elicit(
        f"Confirm {direction} the {constraint!r} power limit in zone {target.zone!r} ({target.zone_name!r}) "
        f"from {current_watts:g} W to {target_watts:g} W? The driver reports an allowed range of {minimum_watts:g}–{maximum_watts:g} W.{window} "
        "A higher limit can increase power use and heat; a lower limit can reduce performance. The change uses current OS permissions without elevation. "
        "The exact zone, constraint, current value, range, and sysfs identities are bound to this confirmation and rechecked before writing. "
        f"Type {phrase!r} and confirm.",
        PowercapLimitActionConfirmation,
    )


async def _confirm_gpu_frequency_limit(
    drm_card: str,
    tile_id: int,
    gt_id: int,
    target_max_frequency_mhz: int,
) -> Elicit[GPUFrequencyLimitConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _gpu_frequency_limit_confirmation_details,
        drm_card,
        tile_id,
        gt_id,
        target_max_frequency_mhz,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The requested Xe GT frequency limit could not be verified.")
    state = target.state
    direction = "raise" if target_max_frequency_mhz > state.current_max_mhz else "lower"
    return Elicit(
        f"Confirm {direction} the Xe maximum frequency for {state.drm_card} ({state.pci_address}), tile {state.tile_id}, GT {state.gt_id} "
        f"from {state.current_max_mhz} MHz to {target.target_max_mhz} MHz? The current minimum is {state.current_min_mhz} MHz "
        f"and the driver reports a hardware range of {state.hardware_min_mhz}–{state.hardware_max_mhz} MHz. "
        "A higher ceiling can increase power draw and heat; a lower ceiling can reduce performance. The kernel or hardware may still run below the requested maximum. "
        "The change uses current OS permissions. GPU, tile, GT, current range, hardware range, and sysfs attribute identity are bound to this confirmation and rechecked. "
        f"Type {phrase!r} and confirm.",
        GPUFrequencyLimitConfirmation,
    )


async def _confirm_power_action(action: PowerAction) -> Elicit[PowerActionConfirmation]:
    validation_error = _validate_power_action(action)
    if validation_error:
        raise ValueError(validation_error)
    effects = {
        "poweroff": " This will end active sessions and power off the machine.",
        "reboot": " This will end active sessions and restart the machine.",
        "halt": " This will end active sessions and halt the machine.",
        "suspend": " This will suspend the machine; unsaved work and active sessions may be interrupted.",
        "hibernate": " This will hibernate the machine; resume depends on host configuration.",
        "hybrid_sleep": " This will suspend and hibernate the machine; resume depends on host configuration.",
        "suspend_then_hibernate": " This will suspend the machine and later attempt hibernation; resume depends on host configuration.",
        "reboot_to_firmware_setup": " This will reboot and request the firmware setup interface on the next boot, where supported.",
    }
    return Elicit(
        f"Confirm the system-wide {action.replace('_', ' ')} action?{effects[action]} "
        "The request uses the current user's permissions, does not use sudo, and does not request interactive authentication.",
        PowerActionConfirmation,
    )


async def _confirm_power_profile(
    requested_profile: PowerProfileName,
) -> Elicit[PowerProfileConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _power_profile_confirmation_details,
        requested_profile,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The system power profile could not be verified.")
    return Elicit(
        f"Confirm changing the active system power profile from {target.before.active_profile!r} "
        f"to {target.requested_profile!r}? Available profiles are "
        f"{', '.join(target.before.available_profiles)}. Power-profiles-daemon may change CPU or platform "
        "power behavior according to the installed driver and firmware. Other system components, battery "
        "state, and power-profile holds can affect the result. The exact current profile, available profile "
        "set, and requested profile are bound to confirmation and rechecked. The selected profile is stored "
        "for restoration at startup. Current OS permissions apply; no privilege elevation is requested. "
        f"Type {target.confirmation_phrase!r} and confirm.",
        PowerProfileConfirmation,
    )


async def _confirm_process_signal(
    pid: int,
    identity_token: str,
    signal_name: str,
) -> Elicit[ProcessSignalConfirmation]:
    target = _process_signal_confirmation_details(pid, identity_token, signal_name)
    if isinstance(target, str):
        raise ValueError(target)
    process, canonical_name, number = target
    safe_name = json.dumps(process.name, ensure_ascii=True)
    return Elicit(
        f"Send {canonical_name} ({number}) to PID {pid}, process {safe_name}, UID {process.uid}?"
        f"{_signal_effect(canonical_name)} The request uses current-user permissions and does not use sudo.",
        ProcessSignalConfirmation,
    )


async def _confirm_shell_command(
    command: str,
    working_directory: str = "",
    timeout_seconds: int = 60,
    max_output_bytes: int = 65536,
    stdin_text: str = "",
    environment: dict[str, str] | None = None,
    run_as: Literal["server", "root"] = "server",
) -> Elicit[CommandExecutionConfirmation]:
    prepared, error = _prepare_command(
        command,
        working_directory,
        timeout_seconds,
        max_output_bytes,
        stdin_text,
        environment,
        run_as,
    )
    if error or prepared is None:
        raise ValueError(error or "The command request could not be prepared.")
    display_command = json.dumps(command, ensure_ascii=True)
    display_cwd = json.dumps(prepared.working_directory, ensure_ascii=True)
    env_keys = ", ".join(sorted(prepared.environment)) or "none"
    privilege = (
        "the server's current OS identity"
        if run_as == "server"
        else "root through noninteractive sudo, or the already-root server identity"
    )
    return Elicit(
        f"Run this exact /bin/sh command: {display_command}. Working directory: {display_cwd}. "
        f"Execution identity: {privilege}. Timeout: {timeout_seconds} seconds; combined output cap: "
        f"{max_output_bytes} bytes; stdin: {len(stdin_text.encode('utf-8'))} bytes; environment override names: {env_keys}. "
        "The request is bound to every parameter, including environment values and stdin, without echoing those values. "
        "The command can make any change allowed to its execution identity. Commands that detach or create new sessions "
        "may outlive the timeout. To proceed, enter the exact phrase "
        f"{prepared.phrase!r} and confirm.",
        CommandExecutionConfirmation,
    )


def _terminal_start_request(
    command: str,
    working_directory: str,
    timeout_seconds: int,
    environment: dict[str, str] | None,
    run_as: Literal["server", "root"],
    rows: int,
    columns: int,
):
    if any(isinstance(value, bool) or not isinstance(value, int) for value in (rows, columns)):
        return None, None, "Terminal rows and columns must be integers."
    if not (1 <= rows <= _MAX_TERMINAL_ROWS and 1 <= columns <= _MAX_TERMINAL_COLUMNS):
        return None, None, f"Terminal size must be between 1 and {_MAX_TERMINAL_ROWS} rows and columns."
    prepared, error = _prepare_command(
        command,
        working_directory,
        timeout_seconds,
        _MAX_TERMINAL_BUFFER_BYTES,
        "",
        environment,
        run_as,
    )
    if error or prepared is None:
        return None, None, error or "The terminal request could not be prepared."
    digest = hashlib.sha256(
        json.dumps(
            {"prepared_request": prepared.command_sha256, "rows": rows, "columns": columns},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    return prepared, digest, None


async def _confirm_terminal_session_start(
    command: str,
    working_directory: str = "",
    timeout_seconds: int = 1800,
    environment: dict[str, str] | None = None,
    run_as: Literal["server", "root"] = "server",
    rows: int = 24,
    columns: int = 80,
) -> Elicit[TerminalSessionConfirmation]:
    prepared, digest, error = _terminal_start_request(
        command, working_directory, timeout_seconds, environment, run_as, rows, columns
    )
    if error or prepared is None or digest is None:
        raise ValueError(error or "The terminal request could not be prepared.")
    privilege = (
        "the server's current OS identity"
        if run_as == "server"
        else "root through noninteractive sudo, or the already-root server identity"
    )
    env_keys = ", ".join(sorted(prepared.environment)) or "none"
    return Elicit(
        f"Start this exact interactive /bin/sh command: {json.dumps(command, ensure_ascii=True)}. "
        f"Working directory: {json.dumps(prepared.working_directory, ensure_ascii=True)}. "
        f"Identity: {privilege}. Terminal size: {rows} rows by {columns} columns. "
        f"Maximum lifetime: {timeout_seconds} seconds; retained output cap: {_MAX_TERMINAL_BUFFER_BYTES} bytes; "
        f"environment override names: {env_keys}. The terminal request is bound to all overrides without echoing values. "
        f"Type {('RUN ' + digest[:16])!r} and confirm to start it.",
        TerminalSessionConfirmation,
    )


def _terminal_write_digest(session_id: str, text: str, rows: int | None, columns: int | None) -> str:
    material = json.dumps(
        {"session_id": session_id, "text": text, "rows": rows, "columns": columns},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


async def _confirm_terminal_session_write(
    session_id: str,
    text: str = "",
    rows: int | None = None,
    columns: int | None = None,
) -> Elicit[TerminalSessionConfirmation]:
    if not isinstance(session_id, str) or not 16 <= len(session_id) <= 128:
        raise ValueError("A current opaque terminal session ID is required.")
    if not isinstance(text, str) or "\x00" in text:
        raise ValueError("Terminal input must be text without NUL bytes.")
    try:
        input_size = len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("Terminal input must contain valid UTF-8 text.") from exc
    if input_size > _MAX_TERMINAL_INPUT_BYTES:
        raise ValueError(f"Terminal input is capped at {_MAX_TERMINAL_INPUT_BYTES} bytes per call.")
    if (rows is None) != (columns is None):
        raise ValueError("Both rows and columns are required to resize the terminal.")
    if rows is not None and columns is not None:
        if any(isinstance(value, bool) or not isinstance(value, int) for value in (rows, columns)):
            raise ValueError("Terminal rows and columns must be integers.")
        if not (1 <= rows <= _MAX_TERMINAL_ROWS and 1 <= columns <= _MAX_TERMINAL_COLUMNS):
            raise ValueError(f"Terminal size must be between 1 and {_MAX_TERMINAL_ROWS} rows and columns.")
    if not text and rows is None:
        raise ValueError("Provide terminal input or a new terminal size.")
    digest = _terminal_write_digest(session_id, text, rows, columns)
    resize = f" Resize to {rows} rows by {columns} columns." if rows is not None else ""
    return Elicit(
        f"Send this exact input to terminal session {session_id}: {json.dumps(text, ensure_ascii=True)}.{resize} "
        f"Input length: {input_size} UTF-8 bytes. Type {('SEND ' + digest[:16])!r} and confirm.",
        TerminalSessionConfirmation,
    )


def _terminal_close_digest(session_id: str) -> str:
    return hashlib.sha256(f"close-terminal-session:{session_id}".encode("utf-8")).hexdigest()


async def _confirm_terminal_session_close(
    session_id: str,
) -> Elicit[TerminalSessionConfirmation]:
    if not isinstance(session_id, str) or not 16 <= len(session_id) <= 128:
        raise ValueError("A current opaque terminal session ID is required.")
    digest = _terminal_close_digest(session_id)
    return Elicit(
        f"Terminate the process group attached to terminal session {session_id}? "
        f"Type {('CLOSE ' + digest[:16])!r} and confirm.",
        TerminalSessionConfirmation,
    )


async def _confirm_container_action(
    action: ContainerAction,
    identity_token: str,
) -> Elicit[ContainerActionConfirmation]:
    target, validation_error = _container_action_confirmation_details(action, identity_token)
    if validation_error or target is None:
        raise ValueError(validation_error or "The container identity could not be verified.")

    effects = {
        "start": " This starts the container's configured workload, which may run processes and access configured networks or mounts.",
        "stop": " This stops the workload after a fixed 10-second grace period and may interrupt services.",
        "restart": " This restarts the workload after a fixed 10-second grace period and may interrupt services.",
        "pause": " This freezes the container's processes until they are resumed or stopped.",
        "unpause": " This resumes the container's frozen processes.",
        "remove": " This permanently removes the stopped container and its writable layer; volume deletion is not requested.",
    }
    return Elicit(
        f"Confirm {action} for {target.name} (ID {target.container_id}) on the local "
        f"{target.endpoint.runtime} {target.endpoint.scope} engine?{effects[action]} "
        "The action is revalidated after confirmation. The server requests no privilege elevation, but a rootful engine socket can perform host-privileged operations.",
        ContainerActionConfirmation,
    )


async def _confirm_container_create(
    runtime: ContainerRuntimeName,
    scope: Literal["system", "user"],
    name: str,
    image: str,
    command: list[str] | None = None,
    port_mappings: list[str] | None = None,
    memory_limit_bytes: int | None = None,
    cpu_limit_millicores: int | None = None,
    volume_mounts: list[str] | None = None,
    host_path_mounts: list[str] | None = None,
    environment_variables: dict[str, str] | None = None,
    container_user: str | None = None,
    read_only_rootfs: bool = False,
    no_new_privileges: bool = False,
    drop_capabilities: list[str] | None = None,
    network_name: str | None = None,
) -> Elicit[ContainerCreateConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _container_create_confirmation_details,
        runtime,
        scope,
        name,
        image,
        command,
        port_mappings,
        memory_limit_bytes,
        cpu_limit_millicores,
        volume_mounts,
        host_path_mounts,
        environment_variables,
        container_user,
        read_only_rootfs,
        no_new_privileges,
        drop_capabilities,
        network_name,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The local image and container configuration could not be verified.")
    exact_command = json.dumps(list(target.command), ensure_ascii=True)
    exact_ports = json.dumps(
        [f"{host_ip}:{host_port}:{container_port}/{protocol}" for host_ip, host_port, container_port, protocol in target.port_mappings],
        ensure_ascii=True,
    )
    exact_volumes = json.dumps(
        [
            {
                "mount": f"{volume_name}:{destination}:{'ro' if read_only else 'rw'}",
                "driver": driver,
                "volume_id": resource_id,
                "created_at": created_at,
            }
            for volume_name, destination, read_only, resource_id, driver, created_at in target.volume_mounts
        ],
        ensure_ascii=True,
    )
    exact_host_paths = json.dumps(
        [
            {
                "mount": f"{source}:{destination}:{'ro' if read_only else 'rw'}",
                "source_type": "directory" if identity[2] == stat.S_IFDIR else "file",
                "source_device": identity[0],
                "source_inode": identity[1],
            }
            for source, destination, read_only, identity in target.host_path_mounts
        ],
        ensure_ascii=True,
    )
    limits = []
    if target.memory_limit_bytes is not None:
        limits.append(f"memory={target.memory_limit_bytes} bytes")
    if target.cpu_limit_millicores is not None:
        limits.append(f"CPU={target.cpu_limit_millicores} millicores")
    environment_names = json.dumps([key for key, _value in target.environment_variables], ensure_ascii=True)
    security_settings = []
    if target.container_user is not None:
        security_settings.append(f"numeric user={target.container_user}")
    if target.read_only_rootfs:
        security_settings.append("read-only root filesystem")
    if target.no_new_privileges:
        security_settings.append("no-new-privileges")
    if target.dropped_capabilities:
        security_settings.append(f"drop capabilities={list(target.dropped_capabilities)}")
    selected_network = (
        f"existing non-default network {target.network_name!r} (ID {target.network_id}, driver {target.network_driver})"
        if target.network_name is not None
        else "the runtime default network"
    )
    return Elicit(
        f"Create a stopped container named {target.name!r} from local image {target.image!r} "
        f"(image ID {target.image_id}) on the {runtime} {scope} endpoint? Command arguments: {exact_command}. "
        f"Network: {selected_network}. An existing custom network can expose traffic to its other attached workloads. "
        f"Published ports (host IPv4:host port:container port/protocol): {exact_ports}. Empty ports bind nothing. "
        f"Existing named-volume mounts: {exact_volumes}. An empty list attaches no named volumes; `:ro` is read-only and `:rw` allows writes after start. "
        f"Host-path mounts: {exact_host_paths}. Host paths are canonical existing regular files or directories outside /proc, /sys, /dev, and /run; `:ro` is requested by default and `:rw` allows host-file changes after start. Nested submount behavior can depend on the runtime and kernel. "
        f"Resource limits: {', '.join(limits) if limits else 'none; runtime defaults apply'}. "
        f"Environment variable names: {environment_names}; values are hidden in this prompt but bound to confirmation. "
        f"Security settings: {', '.join(security_settings) if security_settings else 'runtime defaults; no additional hardening selected'}. "
        "A numeric UID of 0 runs as root inside the container. "
        "A port without an explicit host IPv4 address binds to 127.0.0.1; 0.0.0.0 binds on all IPv4 interfaces and can expose the service to the network. "
        "Volume copy-up is disabled and missing named volumes are not created. "
        "Volume drivers and their runtime configuration may access external storage. "
        "When started, Podman may adjust ownership on a new or empty named volume to match the container UID/GID. "
        "This does not start the container or pull/build an image. "
        "An image-declared VOLUME may still cause the runtime to create an anonymous volume. When started later, it runs the image's configured workload with the selected network, user, root-filesystem, privilege, capability, environment, port, and resource settings. "
        "Resource-limit support depends on runtime permissions and host cgroup configuration; some rootless Podman configurations reject limits. "
        "The endpoint, image identity, name availability, network identity/driver, command, environment values, port bindings, volume identity/driver, host path identity, user, security settings, and resource limits are rechecked after confirmation. The stopped state, container identity, selected network, and requested environment and hardening fields are checked after creation. "
        "A rootful engine can create host-privileged resources even though this server does not elevate. "
        f"Type {phrase!r} and confirm.",
        ContainerCreateConfirmation,
    )


async def _confirm_container_image_action(
    action: ContainerImageActionName,
    runtime: ContainerRuntimeName,
    scope: Literal["system", "user"],
    image: str,
    target_tag: str | None = None,
) -> Elicit[ContainerImageActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _container_image_action_confirmation_details,
        action,
        runtime,
        scope,
        image,
        target_tag,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The selected local image could not be verified.")
    if action == "pull":
        effect = (
            " This contacts the fully qualified registry reference and may download a large amount of data or consume substantial local storage. "
            "Podman may use credentials already configured for the current server identity. This Docker API request does not forward client registry credentials, so private-registry pulls may fail."
        )
    elif action == "tag":
        effect = f" This adds local tag {target.target_tag!r} to the same image ID; an existing destination tag is refused."
    else:
        effect = (
            " This removes the exact local tag without force. If it is the image's last tag and no container uses it, the image data may also be removed; "
            "images referenced by containers are not force-removed."
        )
    return Elicit(
        f"Confirm local container image action {action} for {runtime} {scope}: {target.image!r} "
        f"(current image ID {target.image_id or 'not present yet'})?{effect} "
        "The current image inventory and runtime endpoint are rechecked after confirmation. A concurrent external tag assignment during the final read/action interval may race a Docker tag request. "
        "Command output is withheld; inspect list_container_images before retrying an operation with an uncertain result. "
        f"Type {phrase!r} and confirm.",
        ContainerImageActionConfirmation,
    )


async def _confirm_container_image_build(
    runtime: ContainerImageBuildRuntimeName,
    scope: Literal["system", "user"],
    tag: str,
    context_dir: str,
) -> Elicit[ContainerImageBuildConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _container_image_build_confirmation_details,
        runtime,
        scope,
        tag,
        context_dir,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The local image tag and captured build context could not be verified.")
    return Elicit(
        f"Build local image tag {target.tag!r} with {runtime} {scope} from {target.context_path!r}, using root-level {target.dockerfile!r}; "
        f"captured tree: {target.file_count} regular files, {target.entry_count} total entries, {target.context_bytes} bytes; "
        f"effective context after ignore rules: {target.included_file_count} regular files, {target.included_bytes} bytes; source-tree SHA-256 {target.context_digest}. "
        "The destination tag must not already exist. The Dockerfile/Containerfile instructions execute in the runtime's builder and can download base images, access the network, and consume substantial CPU, memory, storage, and time depending on the file and engine configuration. Podman may use credentials configured for the server identity; the Docker API request does not forward client registry credentials, so private base images may fail. "
        "No container is started. The tool packages only regular files and directories from the selected tree, applies bounded Docker/Podman ignore rules, refuses symlinks, special files, and nested mount points, strips host ownership/timestamps/xattrs, and caps the scanned tree at 64 MiB. Unsupported ignore escaping and unsupported character-class forms are refused. "
        "The endpoint, complete bounded image inventory, and captured content digest are rechecked after confirmation. Podman builder failures may leave intermediate build containers. Rootful engines can perform host-privileged operations. "
        f"Type {phrase!r} and confirm.",
        ContainerImageBuildConfirmation,
    )


async def _confirm_container_resource_action(
    action: ContainerResourceActionName,
    runtime: ContainerRuntimeName,
    scope: Literal["system", "user"],
    kind: ContainerResourceKindName,
    name: str,
    network_subnet: str | None = None,
    network_gateway: str | None = None,
    network_internal: bool | None = None,
    network_bridge_name: str | None = None,
    network_mtu: int | None = None,
    network_subnets: list[str] | None = None,
    network_gateways: list[str | None] | None = None,
) -> Elicit[ContainerResourceActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _container_resource_action_confirmation_details,
        action,
        runtime,
        scope,
        kind,
        name,
        network_subnet,
        network_gateway,
        network_internal,
        network_bridge_name,
        network_mtu,
        network_subnets,
        network_gateways,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The selected local container resource could not be verified.")
    if action == "create" and kind == "volume":
        effect = " This creates a named local-driver volume using the runtime default storage location; it does not populate or attach the volume."
    elif action == "create":
        requested = []
        for subnet, gateway in zip(target.network_subnets, target.network_gateways):
            version = "IPv4" if ":" not in subnet else "IPv6"
            requested.append(f"{version} subnet={subnet}, gateway={gateway or 'automatic'}")
        if target.network_internal is not None:
            requested.append(f"internal={str(target.network_internal).lower()}")
        if target.network_bridge_name is not None:
            requested.append(f"host bridge={target.network_bridge_name}")
        if target.network_mtu is not None:
            requested.append(f"MTU={target.network_mtu}")
        selected = ", ".join(requested) if requested else "runtime default settings"
        effect = (
            f" This creates a local bridge network with {selected}. The runtime may add a host bridge, route, or firewall configuration. "
            "A subnet can overlap a host or VPN route; the engine rejects detected conflicts. Internal mode limits external connectivity through this network, but does not constrain other networks attached to a container or all access to host services."
        )
    elif kind == "volume":
        effect = " This removes the exact unused volume without force and can permanently delete its stored data. Volumes in use are refused."
    else:
        effect = " This removes the exact non-default network without force. Containers are not stopped or detached; networks still in use are refused."
    return Elicit(
        f"Confirm local container {kind} action {action} for {runtime} {scope}: {name!r}?{effect} "
        "The endpoint and complete bounded resource inventory are rechecked after confirmation. A concurrent runtime change in the final read/action interval can race. "
        "The server uses current-user permissions only; access to a rootful engine can still perform host-privileged operations. "
        "Command output is withheld; inspect list_container_resources before retrying an operation with an uncertain result. "
        f"Type {phrase!r} and confirm.",
        ContainerResourceActionConfirmation,
    )


async def _confirm_container_network_attachment_action(
    action: ContainerNetworkActionName,
    runtime: ContainerRuntimeName,
    scope: Literal["system", "user"],
    container: str,
    network: str,
) -> Elicit[ContainerNetworkAttachmentConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _container_network_attachment_action_confirmation_details,
        action,
        runtime,
        scope,
        container,
        network,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The selected local container and network could not be verified.")
    if action == "connect":
        effect = " This connects the container to the named network using runtime-assigned endpoint settings; a running container may immediately exchange traffic on that network."
    else:
        effect = " This disconnects the container from the named network without force and may interrupt its traffic; at least one other attached network must remain."
    return Elicit(
        f"Confirm local {runtime} {scope} container {target.container_name!r} ({target.container_id}) {action} to network {target.network!r}?{effect} "
        "The exact container identity, network identity, attached-network state, and complete bounded resource inventory are rechecked after confirmation. "
        "A concurrent runtime change in the final read/action interval can race. The server uses current-user permissions only; access to a rootful engine can still perform host-privileged operations. "
        f"Type {phrase!r} and confirm.",
        ContainerNetworkAttachmentConfirmation,
    )


async def _confirm_container_pod_action(
    action: ContainerPodActionName,
    name: str,
) -> Elicit[ContainerPodActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _container_pod_action_confirmation_details,
        action,
        name,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The selected local Podman pod could not be verified.")
    if action == "create":
        effect = " This creates an empty pod without the usual infra container and does not start any workload. Pod network and namespace defaults are supplied by the current Podman configuration."
    elif action == "start":
        names = ", ".join(repr(value) for value in target.container_names[:20]) or "the verified attached containers"
        effect = f" This starts every container currently attached to the pod ({names}); those workloads may access their configured host resources and networks."
    elif action == "stop":
        names = ", ".join(repr(value) for value in target.container_names[:20]) or "the verified attached containers"
        effect = f" This stops every container currently attached to the pod ({names}) and may interrupt their workloads."
    else:
        effect = " This removes only an empty, non-running pod; member containers are never removed by this tool."
    return Elicit(
        f"Confirm Podman pod action {action} for current {target.scope} scope: {name!r} "
        f"(pod ID {target.pod_id or 'new'}; {len(target.container_ids)} attached container IDs)?{effect} "
        "The current pod and member inventory is rechecked after confirmation. A concurrent change during the final read/action interval can race. "
        "The server uses current-user permissions only; rootful Podman can perform host-privileged operations. "
        "Command output is withheld; inspect list_container_pods and list_containers before retrying an uncertain action. "
        f"Type {phrase!r} and confirm.",
        ContainerPodActionConfirmation,
    )


async def _confirm_virtual_machine_action(
    action: VirtualMachineActionName,
    identity_token: str,
) -> Elicit[VirtualMachineActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _virtual_machine_action_confirmation_details,
        action,
        identity_token,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact libvirt domain could not be verified.")
    effects = {
        "start": " This starts the configured guest, either restoring managed-save state or booting it; its workload can access configured host resources and networks.",
        "shutdown": " This asks the guest to shut down gracefully. The guest may ignore the request or take time to stop; no force-off action is provided.",
        "reboot": " This requests a guest reboot and may interrupt its workloads; reboot completion is asynchronous.",
        "suspend": " This pauses guest CPU scheduling while its memory remains allocated on the host.",
        "resume": " This resumes scheduling for the paused guest.",
    }
    already_reached = (
        action == "start" and target.state in {"running", "idle", "paused"}
        or action == "shutdown" and target.state in {"shut off", "in shutdown"}
        or action == "suspend" and target.state == "paused"
        or action == "resume" and target.state in {"running", "idle"}
    )
    state_note = " The requested state is already present, so confirmation will result in no command." if already_reached else ""
    safe_name = json.dumps(target.name, ensure_ascii=True)
    return Elicit(
        f"Confirm libvirt {action} for exact domain {safe_name} (UUID {target.uuid}) in {target.scope} scope? "
        f"Current state: {target.state}; domain ID: {target.domain_id if target.domain_id is not None else 'inactive or unavailable'}. "
        f"State token: {target.confirmation_token}.{effects[action]}{state_note} "
        "The command uses the fixed local QEMU URI for this scope and the current account's libvirt permissions; it does not invoke sudo or register virsh's terminal polkit agent. Libvirt and host authorization policy still determine whether it can proceed. "
        "A system-scope libvirt connection can control guests with host resources. A client disconnect does not cancel a command after confirmation; inspect the VM before retrying after an interrupted request.",
        VirtualMachineActionConfirmation,
    )


async def _confirm_remote_virtual_machine_action(
    action: RemoteVirtualMachineActionName,
    identity_token: str,
) -> Elicit[RemoteVirtualMachineActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _remote_virtual_machine_action_confirmation_details,
        action,
        identity_token,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact remote libvirt domain could not be verified.")
    effects = {
        "start": " This starts the configured guest, whose workload can access resources and networks configured on the remote host.",
        "shutdown": " This asks the guest to shut down gracefully; it may ignore the request or take time to stop.",
        "reboot": " This requests a guest reboot and may interrupt its workloads; completion is asynchronous.",
        "suspend": " This pauses guest CPU scheduling while its memory remains allocated on the remote host.",
        "resume": " This resumes scheduling for the paused guest.",
    }
    already_reached = (
        action == "start" and target.state in {"running", "idle", "paused"}
        or action == "shutdown" and target.state in {"shut off", "in shutdown"}
        or action == "suspend" and target.state == "paused"
        or action == "resume" and target.state in {"running", "idle"}
    )
    state_note = " The requested state is already present, so confirmation will result in no command." if already_reached else ""
    safe_name = json.dumps(target.name, ensure_ascii=True)
    return Elicit(
        f"Confirm remote libvirt {action} for exact domain {safe_name} (UUID {target.uuid}) "
        f"at {target.endpoint}, {target.scope} scope? Current state: {target.state}; domain ID: "
        f"{target.domain_id if target.domain_id is not None else 'inactive or unavailable'}. "
        f"State token: {target.confirmation_token}.{effects[action]}{state_note} "
        "The tool uses this account's default SSH keys and SSH_AUTH_SOCK when it is an owned Unix socket; "
        "it disables SSH config, agent forwarding, password prompts, and unknown host-key acceptance. "
        "Remote libvirt permissions decide whether the action can proceed. A system-scope guest may use "
        "privileged host resources on the remote machine. Inspect the remote VM before retrying after an interrupted request.",
        RemoteVirtualMachineActionConfirmation,
    )


async def _confirm_remote_libvirt_resource_action(
    action: RemoteLibvirtResourceActionName,
    resource_type: RemoteLibvirtResourceTypeName,
    endpoint: str,
    name: str,
) -> Elicit[RemoteLibvirtResourceActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _remote_libvirt_resource_action_confirmation_details,
        action,
        resource_type,
        endpoint,
        name,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact remote libvirt resource could not be verified.")
    resource_label = "network" if resource_type == "network" else "storage pool"
    effects = {
        "start": " This starts the configured remote resource.",
        "stop": (
            " This immediately stops the virtual network and disconnects its guests."
            if resource_type == "network"
            else " This stops libvirt managing the pool; guests using its volumes may lose storage access, while the stored data remains."
        ),
        "enable_autostart": " This enables the resource to start automatically with its libvirt connection.",
        "disable_autostart": " This disables automatic startup without stopping the resource.",
    }
    already_reached = (
        action == "start" and target.active
        or action == "stop" and not target.active
        or action == "enable_autostart" and target.autostart is True
        or action == "disable_autostart" and target.autostart is False
    )
    state_note = " The requested state is already present, so confirmation will run no action command." if already_reached else ""
    safe_name = json.dumps(target.name, ensure_ascii=True)
    return Elicit(
        f"Confirm remote libvirt {action} for exact {resource_label} {safe_name} "
        f"(UUID {target.uuid}) at {target.endpoint}, {target.scope} scope? Current state: "
        f"{target.state}; autostart: {target.autostart if target.autostart is not None else 'unavailable'}. "
        f"State token: {target.confirmation_token}.{effects[action]}{state_note} "
        "The tool uses the validated qemu+ssh endpoint, this account's default SSH keys, and an owned "
        "SSH_AUTH_SOCK when available; SSH config, agent forwarding, password prompts, and unknown host-key "
        "acceptance are disabled. Remote libvirt permissions decide whether the action can proceed; no sudo "
        "is invoked. A concurrent change in the final read/action interval can still race. Inspect the resource "
        "before retrying if the client disconnects or the result is uncertain.",
        RemoteLibvirtResourceActionConfirmation,
    )


async def _confirm_virtual_machine_create(
    scope: Literal["system", "session"],
    name: str,
    memory_mib: int,
    vcpus: int,
    pool_name: str,
    disk_volume_name: str,
    disk_capacity_bytes: int,
    network_name: str = "",
) -> Elicit[VirtualMachineCreateConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _virtual_machine_create_confirmation_details,
        scope,
        name,
        memory_mib,
        vcpus,
        pool_name,
        disk_volume_name,
        disk_capacity_bytes,
        network_name,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact libvirt VM creation request could not be verified.")
    network_text = (
        f"It will attach to existing network {target.network_name!r}."
        if target.network_name
        else "It will have no network interface."
    )
    return Elicit(
        f"Confirm defining stopped VM {target.name!r} in {target.scope} scope with {target.memory_mib} MiB memory and {target.vcpus} vCPU(s), plus a new sparse qcow2 disk {target.disk_volume_name!r} ({target.disk_capacity_bytes} bytes) in pool {target.pool_name!r}? {network_text} "
        "This creates a persistent domain definition and a blank disk; it does not install an operating system or start the VM. The disk can later consume its full virtual capacity. It uses only fixed local QEMU URIs and current-account libvirt permissions, without sudo or virsh's terminal polkit agent. A partial failure may leave the new disk volume for inspection. "
        f"State-bound phrase: {phrase!r}. Type the phrase and confirm.",
        VirtualMachineCreateConfirmation,
    )


async def _confirm_virtual_machine_disk_attach(
    identity_token: str,
    pool_name: str,
    volume_name: str,
    disk_target: str,
) -> Elicit[VirtualMachineDiskAttachConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _virtual_machine_disk_attach_confirmation_details,
        identity_token,
        pool_name,
        volume_name,
        disk_target,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact local VM disk attachment could not be verified.")
    return Elicit(
        f"Attach existing volume {target.volume_name!r} ({target.capacity_bytes} bytes, {target.volume_format}) from pool {target.pool_name!r} to VM {target.vm_name!r} in {target.scope} scope as {target.disk_target!r}? "
        "This updates only the persistent configuration of a shut-off local QEMU/libvirt VM; it does not start the VM. The volume must be a local file-backed raw or qcow2 disk, and attachment is refused if the target slot is occupied or the volume is already referenced by a visible local VM definition. The operation does not format the disk, but the guest may change or erase its contents when it starts; preserve a backup if the volume contains data. It uses fixed local QEMU URIs and current-account libvirt permissions without sudo. "
        f"State-bound phrase: {phrase!r}. Type the phrase and confirm.",
        VirtualMachineDiskAttachConfirmation,
    )


async def _confirm_virtual_machine_snapshot_action(
    action: VirtualMachineSnapshotActionName,
    identity_token: str,
    snapshot_name: str,
    description: str = "",
) -> Elicit[VirtualMachineSnapshotActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _snapshot_action_confirmation_details,
        action,
        identity_token,
        snapshot_name,
        description,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact local VM snapshot action could not be verified.")
    if action == "create":
        effect = (
            " This creates a disk snapshot for the shut-off VM, named "
            f"{snapshot_name!r}; it does not capture running memory or change the guest's runtime state."
        )
        if target.description:
            effect += f" Description: {target.description!r}."
    elif action == "revert":
        effect = (
            f" This rolls the VM disks and saved execution state back to snapshot {snapshot_name!r} "
            f"(snapshot state {target.snapshot_state!r}); guest changes since that point may be lost, "
            "and a saved running state may resume the guest."
        )
    else:
        effect = (
            f" This deletes leaf snapshot {snapshot_name!r} and its snapshot data. "
            "Snapshots with children are refused to avoid child merging."
        )
    return Elicit(
        f"Confirm local libvirt snapshot action {action} for exact VM {target.domain_name!r} "
        f"(UUID {target.uuid}, {target.scope} scope; current VM state {target.domain_state!r})?{effect} "
        "The full bounded snapshot inventory and selected snapshot metadata are rechecked after confirmation. "
        "A concurrent libvirt change in the final read/action interval can still race. The server uses the "
        "current account's libvirt permissions and fixed local QEMU URIs; it does not invoke sudo or register "
        "virsh's terminal polkit agent. Inspect the VM before retrying if the client disconnects or the result is uncertain. "
        f"Type {phrase!r} and confirm.",
        VirtualMachineSnapshotActionConfirmation,
    )


async def _confirm_remote_virtual_machine_snapshot_action(
    action: VirtualMachineSnapshotActionName,
    identity_token: str,
    snapshot_name: str,
    description: str = "",
) -> Elicit[VirtualMachineSnapshotActionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _remote_snapshot_action_confirmation_details,
        action,
        identity_token,
        snapshot_name,
        description,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact remote VM snapshot action could not be verified.")
    if action == "create":
        effect = (
            f" This creates a disk-only snapshot named {snapshot_name!r} for the shut-off remote VM; "
            "it does not capture running memory or change the guest runtime state."
        )
        if target.description:
            effect += f" Description: {target.description!r}."
    elif action == "revert":
        effect = (
            f" This rolls the remote VM disks and saved execution state back to snapshot {snapshot_name!r} "
            f"(snapshot state {target.snapshot_state!r}); later guest changes may be lost, and a saved "
            "running state may resume the guest."
        )
    else:
        effect = (
            f" This deletes leaf snapshot {snapshot_name!r} and its remote snapshot data. "
            "Snapshots with children are refused to avoid child merging."
        )
    return Elicit(
        f"Confirm remote libvirt snapshot action {action} for exact VM {target.domain_name!r} "
        f"(UUID {target.uuid}, endpoint {target.endpoint!r}, {target.scope} scope; current VM state {target.domain_state!r})?{effect} "
        "The full bounded remote snapshot inventory and selected metadata are rechecked after confirmation. "
        "The action uses the validated qemu+ssh endpoint, default SSH identity, and pretrusted host key; "
        "SSH config and agent forwarding are disabled, and the server does not invoke sudo. A concurrent "
        "remote libvirt change in the final read/action interval can still race. Inspect the VM before retrying "
        "if the client disconnects or the result is uncertain. "
        f"Type {phrase!r} and confirm.",
        VirtualMachineSnapshotActionConfirmation,
    )


async def _confirm_remote_virtual_machine_disk_attach(
    identity_token: str,
    pool_name: str,
    volume_name: str,
    disk_target: str,
) -> Elicit[RemoteVirtualMachineDiskAttachConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _remote_virtual_machine_disk_attach_confirmation_details,
        identity_token,
        pool_name,
        volume_name,
        disk_target,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact remote VM disk attachment could not be verified.")
    return Elicit(
        f"Attach existing remote volume {target.volume_name!r} ({target.volume_capacity_bytes} bytes, "
        f"{target.volume_format}) from directory pool {target.pool_name!r} at {target.endpoint} to VM "
        f"{target.vm_name!r} (UUID {target.uuid}, {target.scope} scope) as {target.disk_target!r}? This "
        "updates only the persistent configuration of a shut-off remote QEMU/libvirt VM; it does not start "
        "the VM or format the volume. The volume must be an existing raw or qcow2 volume in an active "
        "persistent directory pool, the target slot must be unused, and the volume must not be referenced by "
        "a visible remote VM definition. Guest writes may change or erase existing volume contents when the "
        "VM next starts. The endpoint, domain XML, pool UUID/definition, volume definition/path, and bounded "
        "remote disk-reference inventory are rechecked after confirmation; a concurrent remote change between the last read and attach can still race. This uses trusted SSH host keys "
        "and current remote libvirt permissions; SSH config, agent forwarding, and privilege elevation are not "
        "used. Repeat the exact endpoint, domain, pool, volume, and target in the form. "
        f"State token: {target.expected_state_token}.",
        RemoteVirtualMachineDiskAttachConfirmation,
    )


async def _confirm_remote_virtual_machine_create(
    endpoint: str,
    name: str,
    memory_mib: int,
    vcpus: int,
    pool_name: str,
    disk_volume_name: str,
    disk_capacity_bytes: int,
    network_name: str = "",
) -> Elicit[RemoteVirtualMachineCreateConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _remote_virtual_machine_create_confirmation_details,
        endpoint,
        name,
        memory_mib,
        vcpus,
        pool_name,
        disk_volume_name,
        disk_capacity_bytes,
        network_name,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact remote VM creation request could not be verified.")
    network_text = (
        f"It will attach to existing remote network {target.network_name!r}."
        if target.network_name
        else "It will have no network interface."
    )
    return Elicit(
        f"Create stopped remote VM {target.name!r} at {target.endpoint} ({target.scope} scope) with "
        f"{target.memory_mib} MiB memory, {target.vcpus} vCPU(s), and a new sparse qcow2 disk "
        f"{target.disk_volume_name!r} ({target.disk_capacity_bytes} bytes) in directory pool "
        f"{target.pool_name!r}? {network_text} This creates a persistent domain and blank disk; it does "
        "not install an operating system or start the VM. The disk may later consume its full virtual "
        "capacity. A partial failure can leave the new remote disk for inspection. The action uses a "
        "pretrusted SSH host key, disables SSH config and agent forwarding, and uses current remote "
        "libvirt permissions without sudo. Endpoint, pool, network, domain-name availability, and host "
        "capabilities are rechecked after confirmation; a concurrent remote change in the final "
        "read/action interval can still race. Inspect the remote pool and VM before retrying if the "
        f"result is uncertain. State-bound phrase: {phrase!r}. Type the phrase and confirm.",
        RemoteVirtualMachineCreateConfirmation,
    )


async def _confirm_remote_virtual_machine_config(
    identity_token: str,
    memory_mib: int,
    vcpus: int,
) -> Elicit[RemoteVirtualMachineConfigConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _remote_virtual_machine_config_confirmation_details,
        identity_token,
        memory_mib,
        vcpus,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact remote VM resource configuration could not be verified.")
    return Elicit(
        f"Change shut-off remote VM {target.name!r} (UUID {target.uuid}, endpoint {target.endpoint}, "
        f"{target.scope} scope) from maximum/current memory {target.previous_max_memory_mib}/"
        f"{target.previous_current_memory_mib} MiB and {target.previous_vcpus} vCPU(s) to "
        f"{target.memory_mib} MiB and {target.vcpus} vCPU(s)? The action changes only the persistent "
        "memory, current-memory, and vCPU values; it does not start the VM. The complete domain XML "
        "and stopped state are rechecked after confirmation, and the saved values are read back after "
        "virsh define --validate. A concurrent remote change in the final read/action interval can still "
        "race. The operation uses a pretrusted SSH host key, disables SSH config and agent forwarding, "
        "and uses current remote libvirt permissions without sudo. Inspect the VM before retrying if "
        f"the result is uncertain. State-bound phrase: {target.confirmation_phrase!r}. Type the phrase and confirm.",
        RemoteVirtualMachineConfigConfirmation,
    )


async def _confirm_virtual_machine_config(
    identity_token: str,
    memory_mib: int,
    vcpus: int,
) -> Elicit[VirtualMachineConfigConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _virtual_machine_config_confirmation_details,
        identity_token,
        memory_mib,
        vcpus,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact local VM resource configuration could not be verified.")
    return Elicit(
        f"Change shut-off local VM {target.name!r} (UUID {target.uuid}, {target.scope} scope) from "
        f"maximum/current memory {target.previous_max_memory_mib}/{target.previous_current_memory_mib} MiB "
        f"and {target.previous_vcpus} vCPU(s) to {target.memory_mib} MiB and {target.vcpus} vCPU(s)? "
        "The action changes only the persistent memory, current-memory, and vCPU values; it does not start "
        "the VM. The complete domain XML and shut-off state are rechecked after confirmation, and the saved "
        "values are read back after virsh define --validate. A concurrent local libvirt change in the final "
        "read/action interval can still race. The operation uses fixed local QEMU system/session URIs and "
        "current-account libvirt permissions without sudo. Inspect the VM before retrying if the result is "
        f"uncertain. State-bound phrase: {target.confirmation_phrase!r}. Type the phrase and confirm.",
        VirtualMachineConfigConfirmation,
    )


async def _confirm_libvirt_resource_action(
    action: LibvirtResourceActionName,
    resource_type: LibvirtResourceTypeName,
    scope: Literal["system", "session"],
    name: str,
) -> Elicit[LibvirtResourceActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _libvirt_resource_action_confirmation_details,
        action,
        resource_type,
        scope,
        name,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact libvirt resource could not be verified.")

    resource_label = "virtual network" if resource_type == "network" else "storage pool"
    current_state = target.state
    autostart = (
        "enabled" if target.autostart is True
        else "disabled" if target.autostart is False
        else "unavailable"
    )
    effects = {
        "start": (
            " This starts the configured virtual network, which may create host networking services and connect guests."
            if resource_type == "network"
            else " This starts the configured storage pool and may activate local or remote storage resources."
        ),
        "stop": (
            " This stops the network immediately and can disconnect guests using it. The persistent network definition remains."
            if resource_type == "network"
            else " This stops libvirt managing the pool; raw storage data remains, but guests using its volumes may receive I/O errors."
        ),
        "enable_autostart": " This saves a persistent setting to start the resource automatically when the host boots; it does not start it now.",
        "disable_autostart": " This saves a persistent setting to stop automatic startup at host boot; it does not stop an active resource.",
    }
    desired = {
        "start": "active" if resource_type == "network" else "running",
        "stop": "inactive",
        "enable_autostart": "autostart enabled",
        "disable_autostart": "autostart disabled",
    }[action]
    state_note = (
        " The requested state is already present, so confirmation will result in no command."
        if (action == "start" and target.active)
        or (action == "stop" and not target.active)
        or (action == "enable_autostart" and target.autostart is True)
        or (action == "disable_autostart" and target.autostart is False)
        else ""
    )
    return Elicit(
        f"Confirm libvirt {action} for exact {resource_label} {json.dumps(target.name, ensure_ascii=True)} "
        f"(UUID {target.uuid}) in {target.scope} scope? Current state: {current_state}; "
        f"autostart: {autostart}; requested state: {desired}. State token: {target.confirmation_token}."
        f"{effects[action]}{state_note} The request uses only the fixed local QEMU URI and current-account libvirt permissions. "
        "It does not invoke sudo or register virsh's terminal polkit agent. A client disconnect does not cancel an action after confirmation; inspect the resource before retrying.",
        LibvirtResourceActionConfirmation,
    )


async def _confirm_libvirt_network_create(
    scope: Literal["system", "session"],
    name: str,
) -> Elicit[LibvirtNetworkCreateConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _libvirt_network_create_confirmation_details,
        scope,
        name,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact isolated libvirt network request could not be verified.")
    return Elicit(
        f"Define persistent libvirt network {target.name!r} in {target.scope} scope? "
        "This creates an inactive isolated network definition with a libvirt-assigned bridge name. The XML contains no forwarding, IP addresses, DHCP, or custom bridge configuration. Defining it does not create a host bridge or start the network; starting it later is a separate confirmed action and connects guests only to this isolated segment. Network names and current inventory are rechecked before definition, though an external libvirt change in the final check/define interval can race. The operation uses fixed local QEMU URIs and current-account libvirt permissions without sudo. "
        f"State-bound phrase: {phrase!r}. Type the phrase and confirm.",
        LibvirtNetworkCreateConfirmation,
    )


async def _confirm_libvirt_network_definition(
    scope: Literal["system", "session"],
    name: str,
    forward_mode: Literal["isolated", "nat", "route", "bridge"],
    bridge_name: str = "",
    ipv4_cidr: str = "",
    dhcp_start: str = "",
    dhcp_end: str = "",
) -> Elicit[LibvirtNetworkDefinitionConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _libvirt_network_definition_confirmation_details,
        scope,
        name,
        forward_mode,
        bridge_name,
        ipv4_cidr,
        dhcp_start,
        dhcp_end,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact virtual-network request could not be verified.")
    definition = target.definition
    if definition.forward_mode == "isolated":
        effects = "Guests share only an isolated L2 segment; the XML has no forwarding, IP address, or DHCP range."
    elif definition.forward_mode == "nat":
        effects = (
            f"IPv4 bridge address: {definition.ipv4_cidr}; DHCP range: "
            f"{definition.dhcp_start + '–' + definition.dhcp_end if definition.dhcp_start and definition.dhcp_end else 'disabled'}. Guest traffic can reach external networks through host NAT; "
            "inbound connections to guests are blocked by the standard libvirt NAT rules, while guest-to-guest and host-to-guest traffic is allowed."
        )
    elif definition.forward_mode == "route":
        effects = (
            f"IPv4 bridge address: {definition.ipv4_cidr}; DHCP range: "
            f"{definition.dhcp_start + '–' + definition.dhcp_end if definition.dhcp_start and definition.dhcp_end else 'disabled'}. Traffic is routed without NAT; the upstream LAN needs a return route, "
            "and libvirt allows inbound and outbound sessions on this network."
        )
    else:
        effects = (
            f"Guests connect directly to existing Linux bridge {definition.bridge_name!r}. "
            "Libvirt does not create or manage that bridge and adds no network firewall, IP, DNS, or DHCP configuration; "
            "guests can be exposed to devices on the bridge's LAN."
        )
    address_check = (
        " The selected IPv4 subnet was checked against current host routes and interface addresses."
        if definition.forward_mode in {"nat", "route"}
        else ""
    )
    return Elicit(
        f"Define persistent inactive libvirt network {target.name!r} in {target.scope} scope with forward mode "
        f"{definition.forward_mode!r}? {effects} The network remains inactive; starting it later is a separate confirmed action."
        f"{address_check} Network-name and relevant host state are rechecked before definition. The operation uses fixed local QEMU URIs and current-account libvirt permissions without sudo. "
        f"State-bound phrase: {phrase!r}. Type the phrase and confirm.",
        LibvirtNetworkDefinitionConfirmation,
    )


async def _confirm_libvirt_network_ipv4_configuration(
    scope: Literal["system", "session"],
    name: str,
    ipv4_cidr: str,
    dhcp_action: Literal["keep", "set", "disable"] = "keep",
    dhcp_start: str = "",
    dhcp_end: str = "",
) -> Elicit[LibvirtNetworkIPv4ConfigurationConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _libvirt_network_ipv4_configuration_confirmation_details,
        scope,
        name,
        ipv4_cidr,
        dhcp_action,
        dhcp_start,
        dhcp_end,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The exact existing libvirt network configuration could not be verified.")
    current = target.current_definition
    requested = target.definition
    previous_dhcp = (
        f"{current.dhcp_start}–{current.dhcp_end}"
        if current.dhcp_start and current.dhcp_end
        else "disabled"
    )
    new_dhcp = (
        f"{requested.dhcp_start}–{requested.dhcp_end}"
        if requested.dhcp_start and requested.dhcp_end
        else "disabled"
    )
    return Elicit(
        f"Update the persistent IPv4/DHCP definition for inactive libvirt network {target.name!r} "
        f"(UUID {target.uuid}, {target.scope} scope)? Existing mode and bridge are preserved: "
        f"{target.forward_mode}, bridge {target.bridge_name!r}. IPv4 bridge address changes from "
        f"{current.ipv4_cidr} to {requested.ipv4_cidr}; DHCP range changes from {previous_dhcp} to {new_dhcp}. "
        "This changes saved configuration only; the network must be started separately, and guests will use "
        "the new address and DHCP settings the next time the network starts. The selected subnet is checked "
        "against current host routes and addresses. The current network XML, UUID, inactive/persistent state, "
        "autostart setting, and relevant host state are rechecked before redefining it. The operation uses "
        "fixed local QEMU URIs and current-account libvirt permissions without sudo. "
        f"State-bound phrase: {phrase!r}. Type the phrase and confirm.",
        LibvirtNetworkIPv4ConfigurationConfirmation,
    )


async def _confirm_libvirt_volume_create(
    scope: Literal["system", "session"],
    pool_name: str,
    volume_name: str,
    capacity_bytes: int,
    volume_format: LibvirtVolumeFormatName,
) -> Elicit[LibvirtVolumeCreateConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _libvirt_volume_create_confirmation_details,
        scope,
        pool_name,
        volume_name,
        capacity_bytes,
        volume_format,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact libvirt storage pool could not be verified.")
    return Elicit(
        f"Confirm creating libvirt volume {json.dumps(target.volume_name, ensure_ascii=True)} "
        f"in exact directory-backed pool {json.dumps(target.pool_name, ensure_ascii=True)} "
        f"(UUID {target.pool_uuid}, {target.scope} scope)? Current pool state: {target.pool_state}. "
        f"Requested virtual capacity: {target.capacity_bytes} bytes; format: {target.volume_format}. "
        f"State token: {target.confirmation_token}. The request sets initial allocation to zero, "
        "so the volume is sparse; format metadata may still use space, and guest writes can later consume "
        "up to its virtual capacity and overcommit pool storage. "
        "Creation requires a persistent, running directory-backed pool. This creates a new volume only and "
        "does not attach it to a guest. The request uses a fixed local QEMU URI and current-account libvirt "
        "permissions; it does not invoke sudo or register virsh's terminal polkit agent. A client disconnect "
        "does not cancel a command after confirmation; inspect the pool before retrying.",
        LibvirtVolumeCreateConfirmation,
    )


async def _confirm_radio_device_action(
    action: RadioDeviceActionName,
    identity_token: str,
) -> Elicit[RadioDeviceActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _radio_action_confirmation_details,
        action,
        identity_token,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact rfkill device could not be verified.")
    effect = (
        " This turns off the selected radio and may interrupt Wi-Fi, Bluetooth, WWAN, or this MCP connection."
        if action == "block"
        else " This enables the software radio state but does not connect to a network; a network manager may react."
    )
    current = "soft-blocked" if target.soft_blocked else "software-unblocked"
    if target.hard_blocked:
        current += " and hard-blocked by hardware/platform"
    safe_name = json.dumps(target.name, ensure_ascii=True)
    return Elicit(
        f"Confirm {action} for rfkill device {target.radio_index}, name {safe_name}, type {target.radio_type}? "
        f"Current state: {current}. State token: {target.confirmation_token}.{effect} "
        "Only this device's software rfkill state is changed. The hard block cannot be overridden. "
        "The command uses current OS permissions and does not invoke sudo; network managers or platform policy may affect the resulting radio state.",
        RadioDeviceActionConfirmation,
    )


async def _confirm_bluetooth_pairing(
    identity_token: str,
) -> Elicit[BluetoothPairingConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _bluetooth_pairing_confirmation_details,
        identity_token,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact BlueZ device could not be verified.")
    safe_name = json.dumps(target.name or "", ensure_ascii=True)
    return Elicit(
        f"Pair with Bluetooth device {target.address}, name {safe_name}? BlueZ currently reports it as unpaired. "
        "The pairing procedure initiates a Bluetooth connection and may show an authentication prompt through the system's BlueZ agent; bluetoothctl may also mark the device trusted depending on BlueZ version. "
        "No discovery scan or controller power change is started. The target address, name, and paired/trusted/connected state are rechecked before the command. "
        "Current BlueZ policy and OS permissions apply; the tool does not invoke sudo. Repeat the exact address, name, and state token.",
        BluetoothPairingConfirmation,
    )


async def _confirm_network_interface_action(
    action: NetworkInterfaceAction,
    identity_token: str,
    mtu: int | None,
) -> Elicit[NetworkInterfaceActionConfirmation]:
    snapshot, validation_error = _interface_action_confirmation_details(action, identity_token, mtu)
    if validation_error or snapshot is None:
        raise ValueError(validation_error or "The network interface identity could not be verified.")
    effects = {
        "set_up": " This enables the link; a network manager may start configuring it.",
        "set_down": " This disables the link and may disconnect network sessions, including this MCP client.",
        "set_mtu": " This changes packet-size behavior and may disrupt traffic using this link.",
    }
    state = "up" if snapshot.administrative_up else "down"
    if action == "set_mtu":
        change = f"set MTU from {snapshot.mtu} to {mtu}"
    else:
        target_state = "up" if action == "set_up" else "down"
        change = f"set administrative state from {state} to {target_state}"
    return Elicit(
        f"Confirm {change} on interface {snapshot.name} (ifindex {snapshot.index})?{effects[action]} "
        "The change applies only to the current network namespace and is not persisted across reboot. "
        "The server requests no privilege elevation; current OS permissions apply.",
        NetworkInterfaceActionConfirmation,
    )


async def _confirm_network_address_action(
    action: NetworkAddressAction,
    identity_token: str,
    address: str,
) -> Elicit[NetworkAddressActionConfirmation]:
    snapshot, canonical_address, validation_error = _address_action_confirmation_details(
        action,
        identity_token,
        address,
    )
    if validation_error or snapshot is None or canonical_address is None:
        raise ValueError(validation_error or "The network interface or address could not be verified.")
    effect = (
        " This may add a connected route and change where traffic can flow."
        if action == "add"
        else " This may disconnect active traffic or this MCP client; a network manager may restore the address."
    )
    return Elicit(
        f"Confirm {action} address {canonical_address} on interface {snapshot.name} "
        f"(ifindex {snapshot.index})?{effect} The change applies only to the current network namespace "
        "and is not persisted across reboot. Current OS permissions apply; the server requests no privilege elevation.",
        NetworkAddressActionConfirmation,
    )


async def _confirm_network_manager_profile_action(
    action: NetworkManagerProfileAction,
    profile_uuid: str,
) -> Elicit[NetworkManagerProfileActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _network_manager_profile_confirmation_details,
        action,
        profile_uuid,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact NetworkManager profile could not be verified.")
    profile = target.profile
    device = profile.device or "no active device"
    autoconnect = (
        "yes" if profile.autoconnect is True
        else "no" if profile.autoconnect is False
        else "unavailable"
    )
    changes = {
        "activate": "activate",
        "deactivate": "deactivate",
        "enable_autoconnect": "enable persistent autoconnect for",
        "disable_autoconnect": "disable persistent autoconnect for",
    }
    impact = {
        "activate": "Activation may change routes or disconnect this MCP client.",
        "deactivate": (
            "Deactivation disconnects this profile; NetworkManager may activate another eligible profile, "
            "and this profile will not autoconnect again until reboot or a later user action."
        ),
        "enable_autoconnect": (
            "This saves the autoconnect setting in the profile. NetworkManager may activate the profile as a "
            "result of this change or later when suitable resources are available; the tool does not issue a "
            "separate activation command."
        ),
        "disable_autoconnect": (
            "This saves the autoconnect setting in the profile and affects future automatic activation; "
            "it does not deactivate an already active connection."
        ),
    }[action]
    vpn_autoconnect_note = (
        " NetworkManager stores this setting but does not implement automatic activation for VPN profiles."
        if action == "enable_autoconnect" and profile.connection_type.casefold() == "vpn"
        else ""
    )
    return Elicit(
        f"Confirm {changes[action]} NetworkManager profile {profile.name!r} "
        f"(UUID {profile.uuid}, type {profile.connection_type}, device {device}, "
        f"currently active {target.active_count > 0}, autoconnect {autoconnect})? "
        f"{impact}{vpn_autoconnect_note} Current OS permissions apply; the server requests no privilege elevation. "
        "Repeat the exact profile UUID in the confirmation form.",
        NetworkManagerProfileActionConfirmation,
    )


async def _confirm_network_manager_profile_dns_configuration(
    profile_uuid: str,
    ipv4_dns_servers: list[str] | None = None,
    ipv4_search_domains: list[str] | None = None,
    ipv4_ignore_auto_dns: bool | None = None,
    ipv6_dns_servers: list[str] | None = None,
    ipv6_search_domains: list[str] | None = None,
    ipv6_ignore_auto_dns: bool | None = None,
) -> Elicit[NetworkManagerProfileDNSConfigConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _network_manager_profile_dns_confirmation_details,
        profile_uuid,
        ipv4_dns_servers,
        ipv4_search_domains,
        ipv4_ignore_auto_dns,
        ipv6_dns_servers,
        ipv6_search_domains,
        ipv6_ignore_auto_dns,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The NetworkManager DNS profile could not be verified.")
    changes = target.changes.as_payload()
    current = target.profile
    previous: dict[str, object] = {}
    for field, value in changes.items():
        family = "ipv4" if field.startswith("ipv4_") else "ipv6"
        setting = getattr(current, family)
        if field.endswith("dns_servers"):
            previous[field] = setting.dns_servers
        elif field.endswith("search_domains"):
            previous[field] = setting.search_domains
        elif field.endswith("ignore_auto_dns"):
            previous[field] = setting.ignore_auto_dns
    diff = "; ".join(
        f"{name}: {json.dumps(previous.get(name), ensure_ascii=True)} → {json.dumps(value, ensure_ascii=True)}"
        for name, value in changes.items()
    )
    return Elicit(
        f"Confirm persistent DNS changes for NetworkManager profile {current.profile_name!r} "
        f"(UUID {current.profile_uuid}): {diff}. These changes update only the saved profile; "
        "the tool will not activate or reapply it. DNS may change when NetworkManager next applies the profile. "
        "The complete selected DNS profile state is re-read after confirmation. Current OS permissions apply; "
        "the server requests no privilege elevation. Repeat the exact profile UUID and state-bound phrase in the form. "
        f"Type {target.confirmation_phrase!r} and confirm.",
        NetworkManagerProfileDNSConfigConfirmation,
    )


async def _confirm_network_manager_profile_ip_configuration(
    profile_uuid: str,
    family: NetworkManagerIPFamily,
    method: NetworkManagerIPMethod,
    addresses: list[str] | None = None,
    gateway: str | None = None,
) -> Elicit[NetworkManagerProfileIPConfigConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _network_manager_profile_ip_confirmation_details,
        profile_uuid,
        family,
        method,
        addresses,
        gateway,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The NetworkManager IP profile could not be verified.")
    current = target.before
    requested_addresses = list(target.addresses)
    diff = (
        f"method {current.method!r} → {target.method!r}, "
        f"addresses {json.dumps(list(current.addresses), ensure_ascii=True)} → "
        f"{json.dumps(requested_addresses, ensure_ascii=True)}, "
        f"gateway {current.gateway!r} → {target.gateway!r}"
    )
    return Elicit(
        f"Confirm saved {family.upper()} settings for NetworkManager profile {current.profile_name!r} "
        f"(UUID {current.profile_uuid}, type {current.connection_type}): {diff}. "
        "This updates the saved profile only; the tool will not activate or reapply it. "
        "NetworkManager may use these values the next time it applies the profile. The full selected IP state "
        "is re-read after confirmation. Current OS permissions apply; the server requests no privilege elevation. "
        f"Type {target.confirmation_phrase!r} and confirm.",
        NetworkManagerProfileIPConfigConfirmation,
    )


async def _confirm_network_manager_profile_route_action(
    profile_uuid: str,
    family: NetworkManagerRouteFamily,
    action: NetworkManagerRouteAction,
    destination: str,
    gateway: str | None = None,
    metric: int | None = None,
) -> Elicit[NetworkManagerProfileRouteActionConfirmation]:
    details, validation_error = await asyncio.to_thread(
        _network_manager_profile_route_confirmation_details,
        profile_uuid,
        family,
        action,
        destination,
        gateway,
        metric,
    )
    if validation_error or details is None:
        raise ValueError(validation_error or "The NetworkManager profile routes could not be verified.")
    route_text = json.dumps(details["route"], ensure_ascii=True, sort_keys=True)
    return Elicit(
        f"Confirm {action} of saved {family.upper()} route {route_text} on NetworkManager profile "
        f"{details['profile_name']!r} (UUID {details['profile_uuid']}, type {details['connection_type']}). "
        "This edits only the saved profile; it will not activate or reapply it. The route may affect traffic "
        "the next time NetworkManager applies the profile. Existing routes and profile identity are bound to "
        "the confirmation and re-read before the change. Current OS permissions apply; the server requests "
        "no privilege elevation. Repeat the exact profile UUID and state-bound phrase in the form. "
        f"Type {details['confirmation_phrase']!r} and confirm.",
        NetworkManagerProfileRouteActionConfirmation,
    )


async def _confirm_systemd_network_profile_configuration(
    filename: str,
    interface: str,
    dhcp: Literal["yes", "no", "ipv4", "ipv6"] | None = None,
    addresses: list[str] | None = None,
    gateway: str | None = None,
    clear_gateway: bool = False,
    dns_servers: list[str] | None = None,
    domains: list[str] | None = None,
    dns_default_route: bool | None = None,
    bridge: str | None = None,
    clear_bridge_membership: bool = False,
    bond: str | None = None,
    clear_bond_membership: bool = False,
    vlans: list[str] | None = None,
) -> Elicit[SystemdNetworkProfileConfigConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _systemd_network_profile_confirmation_details,
        filename,
        interface,
        dhcp,
        addresses,
        gateway,
        clear_gateway,
        dns_servers,
        domains,
        dns_default_route,
        bridge,
        clear_bridge_membership,
        bond,
        clear_bond_membership,
        vlans,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The systemd-networkd profile could not be verified.")

    values = {
        "dhcp": target.dhcp,
        "addresses": target.addresses,
        "gateway": target.gateway,
        "dns_servers": target.dns_servers,
        "domains": target.domains,
        "dns_default_route": target.dns_default_route,
        "bridge": target.bridge,
        "bond": target.bond,
        "vlans": target.vlans,
    }
    diff = "; ".join(
        f"{name}: {json.dumps(previous, ensure_ascii=True)} → {json.dumps(values[name], ensure_ascii=True)}"
        for name, previous in target.previous_settings
    )
    return Elicit(
        f"Confirm persistent systemd-networkd changes to {target.filename!r} for interface "
        f"{target.interface}: {diff}. This edits the exact existing profile after checking matching-file "
        "precedence and related virtual-device definitions. It does not run networkctl reload or reconfigure. "
        "The saved values may change routes, DNS, or link membership when systemd-networkd next applies them. "
        "The complete scanned profile state is rechecked before writing; current OS permissions apply, with "
        "no privilege elevation requested. Repeat the exact filename, interface, and state token in the form. "
        f"State token: {target.state_token}",
        SystemdNetworkProfileConfigConfirmation,
    )


async def _confirm_systemd_network_profile_creation(
    filename: str,
    interface: str,
    dhcp: Literal["yes", "no", "ipv4", "ipv6"],
    addresses: list[str] | None = None,
    gateway: str | None = None,
    dns_servers: list[str] | None = None,
    domains: list[str] | None = None,
    dns_default_route: bool | None = None,
    bridge: str | None = None,
    bond: str | None = None,
    vlans: list[str] | None = None,
) -> Elicit[SystemdNetworkProfileCreateConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _systemd_network_profile_creation_confirmation_details,
        filename,
        interface,
        dhcp,
        addresses,
        gateway,
        dns_servers,
        domains,
        dns_default_route,
        bridge,
        bond,
        vlans,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The new systemd-networkd profile could not be verified.")
    settings = ", ".join(target.changed_settings)
    return Elicit(
        f"Confirm creation of /etc/systemd/network/{target.filename} for literal interface "
        f"{target.interface} with settings {settings}? The exact generated file is:\n\n{target.content}"
        "\nThe file is created with mode 0600 and requires the MCP server to already run as root. "
        "The full bounded .network/.netdev state, filename availability, matching-file precedence, and "
        "referenced virtual devices are checked again before creation. This action does not run "
        "networkctl reload or reconfigure; systemd documents reload as the step that loads changed "
        "network files, so this tool does not explicitly apply the new profile. A later reload or service "
        "restart can change routes, DNS, or connectivity. No privilege elevation is requested. Repeat the "
        "exact filename, interface, and state token in the form. State token: "
        f"{target.state_token}",
        SystemdNetworkProfileCreateConfirmation,
    )


async def _confirm_systemd_netdev_creation(
    filename: str,
    name: str,
    kind: SystemdNetDevKind,
    bridge_stp: bool | None = None,
    vlan_filtering: bool | None = None,
    bond_mode: SystemdBondMode | None = None,
    vlan_id: StrictInt | None = None,
) -> Elicit[SystemdNetDevCreateConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _systemd_netdev_creation_confirmation_details,
        filename,
        name,
        kind,
        bridge_stp,
        vlan_filtering,
        bond_mode,
        vlan_id,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The systemd .netdev profile could not be verified.")
    details = ", ".join(target.configured_settings) or "no optional tuning directives"
    return Elicit(
        f"Confirm creation of /etc/systemd/network/{target.filename} defining {target.kind} interface "
        f"{target.name!r} with {details}? The exact generated file is:\n\n{target.content}"
        "It is created with mode 0600 and requires the MCP server to already run as root. The full bounded "
        ".network/.netdev state, filename availability, and virtual-interface name are checked again before "
        "creation and verified after writing. This does not run networkctl reload or reconfigure; a later "
        "reload or service restart can create the interface and may change connectivity. No privilege elevation "
        "is requested. Repeat the exact filename, interface name, kind, and state token. "
        f"State token: {target.state_token}",
        SystemdNetDevCreateConfirmation,
    )


async def _confirm_systemd_netdev_configuration(
    filename: str,
    name: str,
    kind: SystemdNetDevKind,
    bridge_stp: bool | None = None,
    vlan_filtering: bool | None = None,
    bond_mode: SystemdBondMode | None = None,
    vlan_id: StrictInt | None = None,
) -> Elicit[SystemdNetDevConfigConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _systemd_netdev_config_confirmation_details,
        filename, name, kind, bridge_stp, vlan_filtering, bond_mode, vlan_id,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The systemd .netdev profile could not be verified for editing.")
    old_values = dict(target.previous_settings)
    new_values = dict(target.new_settings)
    changes = "; ".join(
        f"{setting}: {old_values.get(setting, '(unset)')} -> {new_values[setting]}"
        for setting in target.changed_settings
    )
    return Elicit(
        f"Update /etc/systemd/network/{target.filename} for {target.kind} interface {target.name!r}: {changes}? "
        "The operation changes only these typed directives and preserves the other file content. The exact file, "
        "its root ownership, precedence, and complete bounded networkd state are rebound to confirmation and "
        "checked after writing. No networkctl reload or reconfigure is requested; a later reload or restart can "
        "alter bridge, bond, VLAN, routes, or connectivity. Current OS permissions apply; no privilege elevation "
        "is requested. Repeat the exact filename, name, kind, and state token: "
        f"{target.state_token}",
        SystemdNetDevConfigConfirmation,
    )


async def _confirm_systemd_netdev_deletion(
    filename: str,
    name: str,
    kind: SystemdNetDevKind,
) -> Elicit[SystemdNetDevDeleteConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _systemd_netdev_deletion_confirmation_details, filename, name, kind,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact systemd .netdev profile could not be verified for deletion.")
    return Elicit(
        f"Delete /etc/systemd/network/{target.filename}, defining {target.kind} interface {target.name!r}? "
        f"The file is {len(target.file_target.original)} bytes with SHA-256 {target.file_target.current_sha256}. "
        "Deletion unlinks the exact file without secure erasure or recovery. It is limited to an inactive virtual "
        "interface with no detected .network profile references; drop-ins, same-named fallback definitions, and "
        "ambiguous networkd state are refused. No networkd reload or reconfigure is requested. A later reload or "
        "restart changes persistent device availability. Current OS permissions apply; no privilege elevation is "
        "requested. Repeat the exact filename, name, kind, and state token: "
        f"{target.state_token}",
        SystemdNetDevDeleteConfirmation,
    )


async def _confirm_systemd_network_profile_deletion(
    filename: str,
    interface: str,
) -> Elicit[SystemdNetworkProfileDeleteConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _systemd_network_profile_deletion_confirmation_details,
        filename,
        interface,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact systemd-networkd profile could not be verified for deletion.")
    return Elicit(
        f"Delete /etc/systemd/network/{target.filename} for interface {target.interface!r}? "
        f"The file is {len(target.file_target.original)} bytes with SHA-256 {target.file_target.current_sha256}. "
        "This unlinks only that exact profile; it is not secure erasure and has no recovery step. Matching "
        "is restricted to one literal interface, and drop-ins, "
        "ambiguous precedence, and same-named fallback profiles are refused. A later networkd reload or "
        "restart may select a different profile or leave this interface unmatched. This tool will not reload "
        "or reconfigure networkd. The full bounded network configuration and file identity are rechecked after "
        "confirmation. Current OS permissions apply; no privilege elevation is requested. Repeat the exact "
        f"filename, interface, and state token: {target.state_token}",
        SystemdNetworkProfileDeleteConfirmation,
    )


async def _confirm_network_manager_vpn_import(
    vpn_type: NetworkManagerVPNType,
    source_path: str,
    profile_name: str,
) -> Elicit[NetworkManagerVPNImportConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _network_manager_vpn_import_confirmation_details,
        vpn_type,
        source_path,
        profile_name,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The VPN source and NetworkManager profile state could not be verified.")
    if target.vpn_type == "openvpn":
        supported_format = (
            "Inline credential blocks are supported; known external file, include, management-socket, and helper-command directives are refused."
        )
        credential_note = "Inline certificates, private keys, or passwords may be stored by NetworkManager."
    else:
        supported_format = (
            "Only the bounded wg-quick Interface/Peer subset is accepted; shell hooks, file-based keys, and unsupported settings are refused. Each DNS address family must also have an Interface Address."
        )
        credential_note = "The WireGuard private key and optional peer preshared keys may be stored by NetworkManager."
    if target.vpn_type == "openvpn":
        handling_note = "The source is copied to a private temporary file for import; the original file is not changed."
    else:
        handling_note = "NetworkManager receives the WireGuard settings over system D-Bus with autoconnect disabled when the profile is created; the original file is not changed."
    return Elicit(
        f"Confirm importing {target.vpn_type} file {target.source.requested_path!r} ({target.source.size_bytes} bytes) "
        f"as persistent NetworkManager profile {target.profile_name!r}? The complete source content and profile "
        f"inventory are bound to this confirmation. {handling_note} The result will remain inactive with autoconnect disabled. {supported_format} "
        f"{credential_note} The configuration is not displayed by this tool. "
        "Activating the profile later may change routes or disconnect this client. Current OS permissions apply; "
        "the server requests no privilege elevation. Repeat the type, exact source path, profile name, and "
        f"state-bound phrase. Type {target.confirmation_phrase!r} and confirm.",
        NetworkManagerVPNImportConfirmation,
    )


async def _confirm_network_manager_port_profile_creation(
    controller_uuid: str,
    profile_name: str,
    interface_name: str,
) -> Elicit[NetworkManagerPortProfileCreateConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _network_manager_port_profile_confirmation_details,
        controller_uuid,
        profile_name,
        interface_name,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The requested NetworkManager port profile could not be verified.")
    return Elicit(
        f"Confirm saving inactive Ethernet port profile {target.profile_name!r} for interface "
        f"{target.interface_name!r} on NetworkManager {target.controller_type} profile "
        f"{target.controller_name!r} (UUID {target.controller_uuid})? Autoconnect will be disabled. "
        "NetworkManager does not store IPv4/IPv6 settings on an attached Ethernet port profile; the selected "
        "bridge or bond controller supplies IP configuration. The complete profile inventory, controller identity, "
        "and Ethernet device identity are re-read after confirmation. The live interface will not be switched; "
        "activating this profile later may interrupt traffic. Current OS permissions apply; the server requests no privilege "
        "elevation. Repeat the exact controller UUID, profile name, interface name, and state-bound phrase. "
        f"Type {target.confirmation_phrase!r} and confirm.",
        NetworkManagerPortProfileCreateConfirmation,
    )


async def _confirm_network_manager_port_membership(
    action: Literal["add", "remove"],
    profile_uuid: str,
    controller_uuid: str,
) -> Elicit[NetworkManagerPortMembershipConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _network_manager_port_membership_confirmation_details,
        action,
        profile_uuid,
        controller_uuid,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The requested NetworkManager port membership could not be verified.")
    verb = "attach" if target.action == "add" else "detach"
    activity = "active" if target.profile_active else "inactive"
    autoconnect = target.before_membership[2]
    ip_effect = (
        "The current profile has automatic IPv4/IPv6 methods with no saved addresses, gateways, DNS overrides, or static routes. "
        "NetworkManager omits per-port IP settings while attached; the bridge/bond controller supplies IP configuration."
        if target.action == "add"
        else "NetworkManager omits per-port IP settings while attached. Detaching will leave IPv4/IPv6 methods automatic "
        "with no saved addresses, gateways, DNS overrides, or static routes; the profile remains inactive unless activated later."
    )
    return Elicit(
        f"Confirm saving the {verb} of {activity} Ethernet profile {target.profile_name!r} "
        f"(UUID {target.profile_uuid}, interface {target.interface_name}) "
        f"{'to' if target.action == 'add' else 'from'} NetworkManager {target.controller_type} profile "
        f"{target.controller_name!r} (UUID {target.controller_uuid})? Current autoconnect={autoconnect}. {ip_effect} "
        "The full profile inventory, "
        "selected membership properties, and interface identity are bound to this confirmation and re-read "
        "before and after the saved change. It does not activate, deactivate, or reapply either profile; if the "
        "profile is active, its applied settings remain in use until NetworkManager reapplies or reactivates it. "
        "A later activation or reapply may change traffic. Current OS "
        "permissions apply; the server requests no privilege elevation. Repeat the exact action and both UUIDs. "
        f"Type {target.confirmation_phrase!r} and confirm.",
        NetworkManagerPortMembershipConfirmation,
    )


async def _confirm_network_manager_virtual_profile_creation(
    kind: NetworkManagerVirtualProfileKind,
    profile_name: str,
    interface_name: str,
    parent_interface: str | None = None,
    vlan_id: int | None = None,
    bond_mode: NetworkManagerBondMode | None = None,
) -> Elicit[NetworkManagerVirtualProfileCreateConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _network_manager_virtual_profile_confirmation_details,
        kind,
        profile_name,
        interface_name,
        parent_interface,
        vlan_id,
        bond_mode,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The requested NetworkManager virtual profile could not be verified.")
    topology = (
        f"VLAN {target.vlan_id} on parent interface {target.parent_interface}"
        if target.kind == "vlan"
        else f"bond mode {target.bond_mode}"
        if target.kind == "bond"
        else "bridge with spanning tree enabled"
    )
    membership = (
        "No bridge or bond ports will be attached; separate port profiles are needed before forwarding traffic."
        if target.kind in {"bridge", "bond"}
        else "The VLAN parent must exist in the current network namespace."
    )
    return Elicit(
        f"Confirm creation of persistent NetworkManager {target.kind} profile {target.profile_name!r} "
        f"for interface {target.interface_name!r} ({topology})? The profile will be saved inactive with "
        f"autoconnect disabled and IPv4/IPv6 disabled. {membership} The complete current profile inventory "
        "and interface identity are re-read after confirmation. This does not activate the profile; activating "
        "a later bridge, bond, or VLAN can change network traffic. Current OS permissions apply; the server "
        "requests no privilege elevation. Repeat the request fields and state-bound phrase in the form. "
        f"Type {target.confirmation_phrase!r} and confirm.",
        NetworkManagerVirtualProfileCreateConfirmation,
    )


async def _confirm_network_route_action(
    action: NetworkRouteAction,
    destination: str,
    gateway: str,
    interface: str,
    table: int,
    metric: int,
) -> Elicit[NetworkRouteActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _route_action_confirmation_details,
        action,
        destination,
        gateway,
        interface,
        table,
        metric,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact route target could not be verified.")
    spec = target.spec
    via = f"via {spec.gateway}" if spec.gateway else "direct"
    effect = (
        " This is a default route and may redirect traffic or disconnect this MCP client."
        if spec.destination in {"0.0.0.0/0", "::/0"}
        else " This changes where matching traffic is routed and may interrupt network access."
    )
    preference = " IPv6 route preference is medium." if spec.family == "ipv6" else ""
    return Elicit(
        f"Confirm {spec.action} {spec.family} static route {spec.destination} {via} on interface "
        f"{spec.interface} (ifindex {spec.interface_snapshot.index}), table {spec.table}, metric {spec.metric}?"
        f"{effect}{preference} The action is revalidated after confirmation, affects only the current network namespace, "
        "is temporary, and uses current OS permissions without privilege elevation. Repeat the displayed "
        "interface index in the confirmation form.",
        NetworkRouteActionConfirmation,
    )


async def _confirm_firewall_rule_action(
    action: FirewallRuleAction,
    family: FirewallFamily,
    protocol: Literal["tcp", "udp"],
    port: int,
    source_cidr: str,
) -> Elicit[FirewallRuleActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _firewall_rule_confirmation_details,
        action,
        family,
        protocol,
        port,
        source_cidr,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact managed firewall rule could not be verified.")
    spec = target.spec
    source = f"from {spec.source_cidr}" if spec.source_cidr else "from any source"
    change = "add an inbound block" if spec.action == "add_block" else "remove an inbound block"
    return Elicit(
        f"Confirm {change} for {spec.family} {spec.protocol.upper()} destination port {spec.port} {source}? "
        "A matching packet is dropped in the dedicated nftables input chain; this can block the MCP connection "
        "or other services using that port. Unmatched traffic in the managed chain follows its accept policy; "
        "other firewall rules continue to apply. The managed table includes a harmless counter-only ownership "
        "marker; if the last block rule is removed, the empty chain and marker may remain until reboot. "
        "Firewall changes are runtime-only, do not persist across reboot, and use current OS permissions "
        "without privilege elevation.",
        FirewallRuleActionConfirmation,
    )


async def _confirm_firewalld_port_action(
    action: FirewalldPortActionName,
    configuration: FirewalldConfigurationName,
    zone: str,
    protocol: Literal["tcp", "udp"],
    port: int,
    port_position: Literal["destination", "source"] = "destination",
) -> Elicit[FirewalldPortActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _firewalld_port_action_confirmation_details,
        action,
        configuration,
        zone,
        protocol,
        port,
        port_position,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact firewalld zone and port rule could not be verified.")
    if action == "add_port":
        effect = f"This adds the exact single-port entry to the zone's {target.port_position}-port list."
    else:
        effect = f"This removes the exact single-port entry from the zone's {target.port_position}-port list."
    if configuration == "runtime":
        zone_state = "The zone is currently bound to an interface or source."
        persistence = "This change takes effect immediately and lasts until firewalld reloads, restarts, or the host reboots."
    else:
        zone_state = "This changes the saved zone configuration."
        persistence = "The change does not alter runtime firewall state until firewalld reloads or restarts."
    return Elicit(
        f"Confirm firewalld {action} for {target.protocol.upper()} {target.port_position} port {target.port} "
        f"in exact zone {json.dumps(target.zone, ensure_ascii=True)} ({target.configuration} configuration)? "
        f"Current port rule present: {target.rule_present}. {zone_state} State token: {target.confirmation_token}. "
        f"{effect} The selected entry matches this port field on traffic in the zone, which may cover several "
        f"interface or source bindings. Other zone services, rich rules, and policies may independently allow "
        f"matching traffic. "
        f"{persistence} The tool changes only this exact port entry; "
        "it does not reload firewalld, change default policy, or request privilege elevation. Current OS and "
        "firewalld authorization determine whether it can proceed.",
        FirewalldPortActionConfirmation,
    )


async def _confirm_firewalld_icmp_block_action(
    action: FirewalldICMPBlockActionName,
    configuration: FirewalldConfigurationName,
    zone: str,
    icmp_type: str,
) -> Elicit[FirewalldICMPBlockActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _firewalld_icmp_block_confirmation_details,
        action,
        configuration,
        zone,
        icmp_type,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact firewalld ICMP block state could not be verified.")
    effect = (
        "This blocks the selected ICMP type for traffic in the zone."
        if action == "add_block"
        else "This removes only this ICMP-specific block; other rules may still block the type."
    )
    persistence = (
        "The runtime change lasts until firewalld reloads, restarts, or the host reboots."
        if configuration == "runtime"
        else "This changes saved configuration only; runtime behavior changes after firewalld reloads or restarts."
    )
    return Elicit(
        f"Confirm firewalld {action} for ICMP type {json.dumps(target.icmp_type, ensure_ascii=True)} "
        f"in exact zone {json.dumps(target.zone, ensure_ascii=True)} ({target.configuration})? "
        f"Current block present: {target.matching_count == 1}. The selected zone is active: {target.zone_active}. "
        f"State token: {target.confirmation_token}. {effect} The zone's ICMP block inversion is disabled; "
        f"inversion-enabled zones are refused because inversion changes the meaning of block entries. "
        f"A zone may cover several interface or source bindings, and other firewall rules or policies also "
        f"affect traffic. {persistence} The tool changes only this exact ICMP block and does not change "
        "default policy, enable inversion, reload firewalld, or use privilege elevation.",
        FirewalldICMPBlockActionConfirmation,
    )


async def _confirm_firewalld_service_action(
    action: FirewalldServiceActionName,
    configuration: FirewalldConfigurationName,
    zone: str,
    service: str,
) -> Elicit[FirewalldServiceActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _firewalld_service_action_confirmation_details,
        action,
        configuration,
        zone,
        service,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact firewalld zone and service state could not be verified.")
    if action == "add_service":
        effect = "This adds the exact named service entry to the zone's service list."
    else:
        effect = "This removes the exact named service entry from the zone's service list."
    if configuration == "runtime":
        zone_state = "The zone is currently bound to an interface or source."
        persistence = "This change takes effect immediately and lasts until firewalld reloads, restarts, or the host reboots."
    else:
        zone_state = "This changes the saved zone configuration."
        persistence = "The change does not alter runtime firewall state until firewalld reloads or restarts."
    return Elicit(
        f"Confirm firewalld {action} for service {json.dumps(target.service, ensure_ascii=True)} "
        f"in exact zone {json.dumps(target.zone, ensure_ascii=True)} ({target.configuration} configuration)? "
        f"Current service entry present: {target.service_present}. {zone_state} State token: {target.confirmation_token}. "
        f"{effect} A firewalld service definition may include multiple ports, protocols, or connection-tracking "
        f"helpers; this tool does not enumerate all traffic effects. A zone may apply to multiple interfaces or "
        f"source networks. Other zone entries, rich rules, or policies may independently allow traffic, so removing "
        f"this service does not guarantee its traffic is blocked. {persistence} The tool changes only this exact "
        "service entry; it does not reload firewalld, change default policy, or request privilege elevation. "
        "Current OS and firewalld authorization determine whether it can proceed.",
        FirewalldServiceActionConfirmation,
    )


async def _confirm_firewalld_rich_rule_action(
    action: FirewalldRichRuleActionName,
    configuration: FirewalldConfigurationName,
    zone: str,
    protocol: Literal["tcp", "udp"],
    port: int,
    source_cidr: str | None = None,
    verdict: FirewalldRichRuleVerdictName = "accept",
    port_end: int | None = None,
    destination_cidr: str | None = None,
    log_enabled: bool = False,
    log_prefix: str | None = None,
    log_level: FirewalldRichRuleLogLevelName | None = None,
    audit_enabled: bool = False,
    priority: int | None = None,
    port_position: Literal["destination", "source"] = "destination",
) -> Elicit[FirewalldRichRuleActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _firewalld_rich_rule_confirmation_details,
        action,
        configuration,
        zone,
        protocol,
        port,
        source_cidr,
        verdict,
        port_end,
        destination_cidr,
        log_enabled,
        log_prefix,
        log_level,
        audit_enabled,
        priority,
        port_position,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact firewalld rich rule could not be verified.")
    operation = "add" if action == "add" else "remove"
    source = f"from source {target.source_cidr}" if target.source_cidr else "from any source"
    destination = (
        f"to destination {target.destination_cidr}"
        if target.destination_cidr
        else "to any destination"
    )
    selected_port = (
        f"{target.port_position} ports {target.port}-{target.port_end}"
        if target.port_end is not None
        else f"{target.port_position} port {target.port}"
    )
    if configuration == "runtime":
        timing = "The zone is currently bound to an interface or source; this takes effect immediately until firewalld reloads, restarts, or the host reboots."
    else:
        timing = "This changes saved configuration only; runtime behavior changes after a firewalld reload or restart."
    if target.priority is None or target.priority == 0:
        ordering = (
            "Priority 0 uses firewalld's log, deny, then allow chain ordering; ordering among rules with the same priority is undefined."
        )
    elif target.priority < 0:
        ordering = (
            f"Priority {target.priority} runs before other firewalld primitives; lower numeric priorities run earlier, "
            "and ordering among equal-priority rules is undefined."
        )
    else:
        ordering = (
            f"Priority {target.priority} runs after other firewalld primitives; lower numeric priorities run earlier, "
            "and ordering among equal-priority rules is undefined."
        )
    modifiers = []
    if target.log_enabled:
        log_description = "logs matching attempts at most once per minute"
        if target.log_prefix:
            log_description += f" with prefix {json.dumps(target.log_prefix, ensure_ascii=True)}; the iptables backend truncates prefixes to 29 characters"
        if target.log_level:
            log_description += f" at level {target.log_level}"
        else:
            log_description += " at the default warning level"
        modifiers.append(log_description)
    if target.audit_enabled:
        modifiers.append("writes matching audit records at most once per minute")
    modifier_text = (
        " The selected rule " + " and ".join(modifiers) + "."
        if modifiers else " No log or audit records are requested."
    )
    return Elicit(
        f"Confirm firewalld {operation} of a {target.verdict} rich rule for {target.protocol.upper()} {selected_port} {source} {destination} "
        f"in exact zone {json.dumps(target.zone, ensure_ascii=True)} ({target.configuration})? "
        f"Exact rule: {json.dumps(target.rich_rule, ensure_ascii=True)}. State token: {target.confirmation_token}. {timing} "
        "The selected zone may apply to several interfaces or source bindings. An accept rule permits matching traffic and a reject/drop rule blocks matching traffic; other firewalld rules, policies, and frontends may also affect the packet decision. "
        f"{ordering}{modifier_text} Only this typed rule, including its source/destination address filters and selected {target.port_position} port, verdict, logging, audit, and priority, is changed; no arbitrary rule text, default policy, reload, or privilege elevation is used. Current OS and firewalld authorization determine whether it can proceed.",
        FirewalldRichRuleActionConfirmation,
    )


async def _confirm_firewalld_rich_icmp_rule_action(
    action: FirewalldRichICMPRuleActionName,
    configuration: FirewalldConfigurationName,
    zone: str,
    icmp_type: str,
    source_cidr: str | None = None,
    destination_cidr: str | None = None,
    verdict: FirewalldRichICMPRuleVerdictName = "accept",
    log_enabled: bool = False,
    log_prefix: str | None = None,
    log_level: FirewalldRichICMPRuleLogLevelName | None = None,
    audit_enabled: bool = False,
    priority: int | None = None,
) -> Elicit[FirewalldRichICMPRuleActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _firewalld_rich_icmp_rule_confirmation_details,
        action,
        configuration,
        zone,
        icmp_type,
        source_cidr,
        destination_cidr,
        verdict,
        log_enabled,
        log_prefix,
        log_level,
        audit_enabled,
        priority,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact firewalld rich ICMP rule could not be verified.")
    source = f"from source {target.source_cidr}" if target.source_cidr else "from any source"
    destination = (
        f"to destination {target.destination_cidr}"
        if target.destination_cidr else "to any destination"
    )
    if target.priority is None or target.priority == 0:
        ordering = "Priority 0 uses firewalld's log, deny, then allow chain ordering."
    elif target.priority < 0:
        ordering = f"Priority {target.priority} runs before other firewalld primitives."
    else:
        ordering = f"Priority {target.priority} runs after other firewalld primitives."
    modifiers = []
    if target.log_enabled:
        text = "logs matching attempts at most once per minute"
        if target.log_prefix:
            text += f" with prefix {json.dumps(target.log_prefix, ensure_ascii=True)}"
        if target.log_level:
            text += f" at level {target.log_level}"
        modifiers.append(text)
    if target.audit_enabled:
        modifiers.append("writes matching audit records at most once per minute")
    modifier_text = " The rule " + " and ".join(modifiers) + "." if modifiers else " No log or audit records are requested."
    timing = (
        "The zone is currently bound to an interface or source; this runtime change takes effect immediately until firewalld reloads, restarts, or the host reboots."
        if configuration == "runtime"
        else "This changes saved configuration only; runtime behavior changes after firewalld reloads or restarts."
    )
    return Elicit(
        f"Confirm firewalld {action} of a {target.verdict} rich rule matching ICMP type "
        f"{json.dumps(target.icmp_type, ensure_ascii=True)} {source} {destination} in exact zone "
        f"{json.dumps(target.zone, ensure_ascii=True)} ({target.configuration})? Exact rule: "
        f"{json.dumps(target.rich_rule, ensure_ascii=True)}. Current rule present: {target.matching_count == 1}. "
        f"The zone is active: {target.zone_active}. State token: {target.confirmation_token}. {timing} "
        "The ICMP definition is rechecked before and after the action. Accept permits matching packets; reject or drop blocks them. "
        "Other firewalld rules, policies, and frontends can affect the final packet decision. "
        f"{ordering}{modifier_text} The tool changes only this generated typed rule; it does not reload firewalld, "
        "change default policy, accept arbitrary rule text, or request privilege elevation.",
        FirewalldRichICMPRuleActionConfirmation,
    )


async def _confirm_firewalld_rich_protocol_rule_action(
    action: FirewalldRichProtocolRuleActionName,
    configuration: FirewalldConfigurationName,
    zone: str,
    protocol_value: str,
    source_cidr: str | None = None,
    destination_cidr: str | None = None,
    verdict: FirewalldRichProtocolRuleVerdictName = "accept",
    log_enabled: bool = False,
    log_prefix: str | None = None,
    log_level: FirewalldRichProtocolRuleLogLevelName | None = None,
    audit_enabled: bool = False,
    priority: int | None = None,
) -> Elicit[FirewalldRichProtocolRuleActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _firewalld_rich_protocol_rule_confirmation_details,
        action,
        configuration,
        zone,
        protocol_value,
        source_cidr,
        destination_cidr,
        verdict,
        log_enabled,
        log_prefix,
        log_level,
        audit_enabled,
        priority,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact firewalld rich protocol rule could not be verified.")
    source = f"from source {target.source_cidr}" if target.source_cidr else "from any source"
    destination = (
        f"to destination {target.destination_cidr}"
        if target.destination_cidr else "to any destination"
    )
    if target.priority is None or target.priority == 0:
        ordering = "Priority 0 uses firewalld's log, deny, then allow chain ordering."
    elif target.priority < 0:
        ordering = f"Priority {target.priority} runs before other firewalld primitives."
    else:
        ordering = f"Priority {target.priority} runs after other firewalld primitives."
    modifiers = []
    if target.log_enabled:
        text = "logs matching packets at most once per minute"
        if target.log_prefix:
            text += f" with prefix {json.dumps(target.log_prefix, ensure_ascii=True)}"
        if target.log_level:
            text += f" at level {target.log_level}"
        modifiers.append(text)
    if target.audit_enabled:
        modifiers.append("writes matching audit records at most once per minute")
    modifier_text = " The rule " + " and ".join(modifiers) + "." if modifiers else " No log or audit records are requested."
    timing = (
        "The zone is currently bound to an interface or source; this runtime change takes effect immediately until firewalld reloads, restarts, or the host reboots."
        if configuration == "runtime"
        else "This changes saved configuration only; runtime behavior changes after firewalld reloads or restarts."
    )
    return Elicit(
        f"Confirm firewalld {action} of a {target.verdict} rich rule for IP protocol "
        f"{json.dumps(target.protocol_value, ensure_ascii=True)} (number {target.protocol_number}) "
        f"{source} {destination} in exact zone {json.dumps(target.zone, ensure_ascii=True)} "
        f"({target.configuration})? Exact rule: {json.dumps(target.rich_rule, ensure_ascii=True)}. "
        f"Current rule present: {target.matching_count == 1}. Zone active: {target.zone_active}. "
        f"State token: {target.confirmation_token}. {timing} Protocol names are resolved using the host's "
        "local IP protocol database and encoded as the shown numeric protocol value. Accept permits matching "
        "packets; reject/drop blocks them. Other rules, policies, and frontends can affect the final packet "
        f"decision. {ordering}{modifier_text} The tool changes only this generated typed rule; it does not "
        "reload firewalld, change default policy, accept arbitrary rule text, or request privilege elevation.",
        FirewalldRichProtocolRuleActionConfirmation,
    )


async def _confirm_ufw_port_rule_action(
    action: UFWPortRuleActionName,
    protocol: Literal["tcp", "udp"],
    port: int,
    direction: Literal["in", "out"] = "in",
    source_address: str = "any",
    destination_address: str = "any",
    port_end: int | None = None,
    additional_ports: list[StrictInt] | None = None,
) -> Elicit[UFWPortRuleActionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _ufw_port_rule_confirmation_details,
        action,
        protocol,
        port,
        direction,
        source_address,
        destination_address,
        port_end,
        additional_ports,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact UFW port rule could not be verified.")
    policy = action.split("_", 1)[1]
    policy_effect = {
        "allow": "permits matching traffic",
        "deny": "drops matching traffic",
        "reject": "rejects matching traffic",
        "limit": "applies UFW connection rate limiting to matching traffic",
    }[policy]
    effect = "add" if action.startswith("add_") else "remove"
    change_effect = (
        f"Adding the entry {policy_effect}."
        if effect == "add"
        else f"Removing this entry stops this exact rule from {policy_effect}."
    )
    other_count = target.other_actions_ipv4_count + target.other_actions_ipv6_count
    numbered_entries = (
        f"IPv4={target.ipv4_rule_number}, IPv6={target.ipv6_rule_number}"
        if effect == "remove"
        else "none yet"
    )
    additional_ports_json = json.dumps(list(target.additional_ports or ()), separators=(",", ":"))
    port_label = (
        ", ".join(str(item) for item in (target.port, *target.additional_ports))
        if target.additional_ports
        else str(target.port) if target.port_end is None
        else f"{target.port}-{target.port_end} (inclusive)"
    )
    return Elicit(
        f"Confirm UFW {effect} {policy} for {target.direction} {target.protocol.upper()} destination port selector {port_label}, "
        f"source {target.source_address}, destination {target.destination_address}, on all UFW-managed interfaces? Existing matching {policy} entries: "
        f"IPv4={target.ipv4_count}, IPv6={target.ipv6_count}; numbered entries to remove: {numbered_entries}. "
        f"Matching entries for other UFW actions: {other_count}. additional_ports_json: {additional_ports_json}. "
        f"State token: {target.confirmation_token}. "
        "A removal re-reads the numbered list between IPv4 and IPv6 entries because UFW renumbers after deletion. "
        f"{change_effect} When both addresses are 'any' and IPv6 is enabled, "
        "the rule may apply to both IPv4 and IPv6. Earlier rules may take "
        "precedence, and raw firewall rules outside UFW's numbered status are not inspected. Other firewall "
        "rules and default policies continue to apply. UFW must remain active; this action does not change "
        "default policy or enable/disable UFW. It uses current OS permissions and does not request elevation.",
        UFWPortRuleActionConfirmation,
    )


async def _confirm_extended_attribute_action(
    path: str,
    name: str,
    action: Literal["set", "remove"],
    value_base64: str = "",
) -> Elicit[PathAdminConfirmation]:
    prepared, phrase, validation_error = await asyncio.to_thread(
        _extended_attribute_confirmation_details,
        path,
        name,
        action,
        value_base64,
    )
    if validation_error or prepared is None or phrase is None:
        raise ValueError(validation_error or "The extended-attribute request could not be verified.")
    value_sha = hashlib.sha256(prepared.value).hexdigest() if prepared.value is not None else None
    operation = f"set {name!r} to {len(prepared.value)} bytes with SHA-256 {value_sha}" if action == "set" else f"remove {name!r}"
    current = prepared.current_sha256 or "absent"
    return Elicit(
        f"Confirm {action} extended attribute {operation} on {str(prepared.path)!r}? Current attribute SHA-256: {current}. "
        "Extended attributes can affect application behavior and security policy; Linux permissions determine whether the write succeeds. "
        f"Type {phrase!r} and confirm.",
        PathAdminConfirmation,
    )


async def _confirm_posix_acl_action(
    path: str,
    action: Literal["set", "remove"],
    acl_kind: Literal["access", "default"],
    entries: list[ACLWriteEntry] | None = None,
) -> Elicit[PathAdminConfirmation]:
    prepared, phrase, validation_error = await asyncio.to_thread(
        _posix_acl_confirmation_details,
        path,
        action,
        acl_kind,
        entries or [],
    )
    if validation_error or prepared is None or phrase is None:
        raise ValueError(validation_error or "The POSIX ACL request could not be verified.")
    current = prepared.current_sha256 or "absent"
    described = [entry.model_dump() for entry in prepared.entries]
    impact = " This changes access permissions for the file/directory." if acl_kind == "access" else " New children may inherit this default ACL."
    return Elicit(
        f"Confirm {action} {acl_kind} POSIX ACL on {str(prepared.path)!r}? Current ACL SHA-256: {current}. "
        f"Requested entries: {json.dumps(described, ensure_ascii=True, sort_keys=True)}.{impact} "
        f"Type {phrase!r} and confirm.",
        PathAdminConfirmation,
    )


async def _confirm_directory_action(
    path: str,
    action: Literal["create_parents", "delete_recursive"],
    mode: str | None = None,
) -> Elicit[PathAdminConfirmation]:
    prepared, phrase, validation_error = await asyncio.to_thread(
        _directory_action_confirmation_details,
        path,
        action,
        mode,
    )
    if validation_error or prepared is None or phrase is None:
        raise ValueError(validation_error or "The directory request could not be verified.")
    if action == "create_parents":
        effect = (
            f"Create {len(prepared.missing_components)} missing directory component(s) "
            f"{list(prepared.missing_components)!r}, each with mode {prepared.mode_octal}."
        )
    else:
        effect = (
            f"Recursively delete this exact directory tree, including {prepared.tree_entries} entries "
            f"with approximately {prepared.tree_bytes} regular-file bytes. Tree SHA-256: {prepared.tree_sha256}. "
            f"The tree scan is capped at 20000 entries."
        )
    return Elicit(
        f"Confirm {action} for {str(prepared.path)!r}? {effect} "
        f"Type {phrase!r} and confirm.",
        PathAdminConfirmation,
    )


async def _confirm_directory_tree_action(
    action: Literal["copy", "move"],
    source_path: str,
    destination_path: str,
) -> Elicit[PathAdminConfirmation]:
    prepared, phrase, validation_error = await asyncio.to_thread(
        _directory_tree_action_confirmation_details,
        action,
        source_path,
        destination_path,
    )
    if validation_error or prepared is None or phrase is None:
        raise ValueError(validation_error or "The directory-tree request could not be verified.")
    if action == "copy":
        effect = (
            f"Copy {prepared.entries} entries and approximately {prepared.bytes_total} regular-file bytes "
            f"from {str(prepared.source)!r} to new path {str(prepared.destination)!r}. "
            "Publication is atomic and never overwrites. Copy preserves regular-file data, symbolic-link targets, rwx modes, "
            "modification times, and hard-link relationships within the copied tree; ownership, ACLs, xattrs, and access times are not copied. "
            "Special files are refused; the limits are "
            "20000 entries, 64 GiB for copy, and 256 directory levels. Copy checks destination free bytes and, when reported, available inodes against up to one inode per entry plus the destination root during confirmation and again before staging."
        )
    else:
        effect = (
            f"Move {prepared.entries} entries and approximately {prepared.bytes_total} regular-file bytes "
            f"from {str(prepared.source)!r} to new path {str(prepared.destination)!r} by same-filesystem rename. "
            "Existing ownership and metadata are preserved. The move never overwrites and refuses mounted trees or filesystem crossings."
        )
    return Elicit(
        f"Confirm recursive directory {action}? {effect} Source-tree SHA-256: {prepared.tree_sha256}. "
        f"Type {phrase!r} and confirm.",
        PathAdminConfirmation,
    )


async def _confirm_symlink_action(
    path: str,
    action: Literal["create", "remove"],
    target: str = "",
) -> Elicit[PathAdminConfirmation]:
    prepared, phrase, validation_error = await asyncio.to_thread(
        _symlink_action_confirmation_details,
        path,
        action,
        target,
    )
    if validation_error or prepared is None or phrase is None:
        raise ValueError(validation_error or "The symlink operation could not be verified.")
    operation = (
        f"create a symbolic link at {str(prepared.path)!r} pointing to {prepared.link_target!r}"
        if action == "create"
        else f"remove the symbolic link at {str(prepared.path)!r} pointing to {prepared.link_target!r}"
    )
    return Elicit(
        f"Confirm {operation}? The target is recorded as link text and is not followed. "
        f"Type {phrase!r} and confirm.",
        PathAdminConfirmation,
    )


async def _confirm_path_owner_change(
    path: str,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
    recursive: bool = False,
) -> Elicit[PathAdminConfirmation]:
    prepared, phrase, validation_error = await asyncio.to_thread(
        _owner_change_confirmation_details,
        path,
        owner_uid,
        owner_gid,
        recursive,
    )
    if validation_error or prepared is None or phrase is None:
        raise ValueError(validation_error or "The ownership operation could not be verified.")
    if prepared.recursive:
        requested_uid = "unchanged" if owner_uid is None else str(owner_uid)
        requested_gid = "unchanged" if owner_gid is None else str(owner_gid)
        outside_note = (
            f" {prepared.external_hardlink_groups} hard-linked file or symlink group(s) have paths outside this tree; those aliases will change too."
            if prepared.external_hardlink_groups
            else ""
        )
        return Elicit(
            f"Recursively change ownership under {str(prepared.path)!r} for {len(prepared.tree_entries)} entries "
            f"and approximately {prepared.tree_bytes} regular-file bytes to UID {requested_uid} and GID {requested_gid}? "
            "The MCP server must already run as root. The scan is limited to 20,000 entries and 256 levels, refuses mounted roots, nested mounts, and special files, and changes symlink ownership without following its target. "
            "A chown may clear setuid/setgid bits. If an action fails partway through, earlier changes remain in place and are not rolled back."
            f"{outside_note} Type {phrase!r} and confirm.",
            PathAdminConfirmation,
        )
    previous_uid, previous_gid = prepared.entry_snapshot[4:6]
    requested_uid = previous_uid if owner_uid is None else owner_uid
    requested_gid = previous_gid if owner_gid is None else owner_gid
    hardlink_note = (
        f" This regular file has {prepared.entry_snapshot[3]} hard links, so the ownership change affects every linked path."
        if prepared.entry_snapshot[3] > 1
        else ""
    )
    return Elicit(
        f"Change ownership of {str(prepared.path)!r} from UID {previous_uid}/GID {previous_gid} "
        f"to UID {requested_uid}/GID {requested_gid}?{hardlink_note} "
        f"The operation uses current OS permissions and will fail if the server identity lacks authority. "
        f"Type {phrase!r} and confirm.",
        PathAdminConfirmation,
    )


async def _confirm_binary_file_write(
    path: str,
    data_base64: str,
    action: Literal["create", "replace", "append"],
) -> Elicit[BinaryFileWriteConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _binary_file_write_confirmation_details,
        path,
        data_base64,
        action,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The binary file operation could not be verified.")
    current_size = target.current_snapshot[6] if target.current_snapshot else None
    change = {
        "create": "create a new file without replacing an existing path",
        "replace": "atomically replace one existing regular file while preserving its mode, owner, ACL, and visible xattrs",
        "append": "append to one existing regular file without changing any hard-linked aliases",
    }[action]
    return Elicit(
        f"Confirm binary operation to {change} at {str(target.path)!r}? "
        f"Payload size: {len(target.payload)} bytes; payload SHA-256: {target.payload_sha256}; "
        f"current file size: {current_size if current_size is not None else 'absent'}; "
        "the base64 payload is not repeated in the prompt. Each call is limited to 4 MiB. "
        "Replace refuses files with visible capability, IMA, or EVM security attributes. "
        "Paths under /proc, /sys, /dev, and /run are excluded. "
        f"Type {phrase!r} and confirm to proceed.",
        BinaryFileWriteConfirmation,
    )


async def _confirm_binary_file_upload(
    path: str,
    action: Literal["create", "replace"],
    expected_size: int,
    expected_sha256: str,
) -> Elicit[BinaryFileUploadConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _binary_file_upload_confirmation_details,
        path,
        action,
        expected_size,
        expected_sha256,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The large binary-file upload could not be verified.")
    if action == "create":
        effect = "The target does not exist; commit will create it with mode 0600."
    else:
        snapshot = target.current_snapshot
        assert snapshot is not None
        effect = (
            f"The existing target is {snapshot[6]} bytes, owned by UID {snapshot[4]}/GID {snapshot[5]}, "
            f"mode {stat.S_IMODE(snapshot[2]):04o}. Commit will atomically replace this path and preserve "
            "its owner, mode, ACL, and visible xattrs; other hard-link names keep the old file."
        )
    return Elicit(
        f"Confirm a chunked binary {action} at {str(target.path)!r}? Expected size: "
        f"{target.expected_size} bytes; SHA-256: {target.expected_sha256}. {effect} "
        "The first step creates a hidden mode-0600 staging file in this directory, so temporary disk use can reach the full upload size; "
        "the target remains unchanged until commit. Chunks are limited to 4 MiB, each must arrive at the reported next offset, "
        "and the upload expires after one hour of inactivity; expired staging files are removed within 30 seconds. "
        "An unexpected server exit can leave its hidden staging file behind. "
        "Replacement refuses files with visible capability, IMA, or EVM security attributes; a concurrent writer can race the final rename after the last path check. Paths under /proc, /sys, /dev, and /run are excluded. "
        f"Type {target.confirmation_phrase!r} and confirm to begin.",
        BinaryFileUploadConfirmation,
    )


async def _confirm_binary_file_delete(path: str) -> Elicit[PathAdminConfirmation]:
    target, phrase, validation_error = await asyncio.to_thread(
        _binary_file_delete_confirmation_details,
        path,
    )
    if validation_error or target is None or phrase is None:
        raise ValueError(validation_error or "The binary file deletion could not be verified.")
    snapshot = target.current_snapshot
    link_note = (
        f" It has {snapshot[3]} hard links; unlinking this path removes only this directory entry."
        if snapshot[3] > 1
        else ""
    )
    return Elicit(
        f"Delete the regular file at {str(target.path)!r}? It currently contains {snapshot[6]} bytes "
        f"(UID {snapshot[4]}, GID {snapshot[5]}, mode {stat.S_IMODE(snapshot[2]):04o}).{link_note} "
        "This unlinks the path and is not secure erasure; backups and storage snapshots may retain data. "
        "The confirmation is bound to the canonical path, parent directory, and current file identity/metadata. "
        f"Type {phrase!r} and confirm.",
        PathAdminConfirmation,
    )


async def _confirm_text_file_creation(
    path: str,
    content: str,
) -> Elicit[TextFileCreationConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _text_file_creation_confirmation_details,
        path,
        content,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The new-file destination could not be verified.")
    preview = repr(content[:160])
    if len(content) > 160:
        preview += " …"
    return Elicit(
        f"Create a new UTF-8 text file at {str(target.path)!r} with {target.byte_count} bytes "
        f"and SHA-256 {target.content_sha256}? Escaped content preview: {preview}. "
        "The destination must remain absent; this action never overwrites an existing file. "
        "The new file receives mode 0600 (owner read/write only). Current OS permissions apply; "
        "the server requests no privilege elevation. Repeat the canonical path and content digest.",
        TextFileCreationConfirmation,
    )


async def _confirm_text_file_replacement(
    path: str,
    content: str,
) -> Elicit[TextFileReplacementConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _text_file_replacement_confirmation_details,
        path,
        content,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact text-file replacement could not be verified.")
    preview = repr(content[:160])
    if len(content) > 160:
        preview += " …"
    executable_note = (
        " This file is executable; replacing it may change program behavior."
        if int(target.mode_octal, 8) & 0o111
        else ""
    )
    return Elicit(
        f"Replace the current UTF-8 text in {str(target.path)!r} ({len(target.original)} bytes, "
        f"mode {target.mode_octal}, SHA-256 {target.current_sha256}) with {len(target.replacement)} bytes "
        f"(SHA-256 {target.replacement_sha256})? Escaped replacement preview: {preview}."
        f"{executable_note} This replaces the full file content in place, preserving its owner, mode, ACL, "
        "and checked xattrs; modification/change times update. Files with visible capability, IMA, or EVM "
        "security attributes are refused; xattr inspection errors fail closed. "
        "The current file and replacement are revalidated; if a write fails, the server attempts to restore "
        "the original content. Current OS permissions apply; no privilege elevation is requested. "
        "Repeat the canonical path and both content digests.",
        TextFileReplacementConfirmation,
    )


async def _confirm_text_file_deletion(
    path: str,
) -> Elicit[TextFileDeletionConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _text_file_deletion_confirmation_details,
        path,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact text-file deletion could not be verified.")
    return Elicit(
        f"Unlink the regular UTF-8 text file at {str(target.path)!r} "
        f"({len(target.original)} bytes, mode {target.mode_octal}, SHA-256 {target.current_sha256})? "
        "This removes the path but is not secure erasure; the tool has no trash or recovery step. "
        "It refuses symlinks, directories, hard-linked files, "
        "setuid/setgid files, files with visible protected security attributes, binary files, and files over 64 KiB. "
        "A concurrent path change in the final unlink window cannot be rolled back. Current OS permissions apply; "
        "no privilege elevation is requested. Repeat the canonical path "
        "and current content digest.",
        TextFileDeletionConfirmation,
    )


async def _confirm_file_mode_change(
    path: str,
    mode: str,
) -> Elicit[FileModeChangeConfirmation]:
    target, validation_error = await asyncio.to_thread(
        _file_mode_change_confirmation_details,
        path,
        mode,
    )
    if validation_error or target is None:
        raise ValueError(validation_error or "The exact file-mode change could not be verified.")
    acl_note = (
        " A visible POSIX access ACL is present; chmod will update its mode-corresponding entries and group-class mask."
        if target.access_acl_present
        else " If a POSIX access ACL is present, chmod will update its mode-corresponding entries and group-class mask."
    )
    new_mode = int(target.new_mode_octal, 8)
    special_effects: list[str] = []
    if new_mode & stat.S_ISUID:
        special_effects.append("setuid can make executions run with the file owner's effective UID")
    if new_mode & stat.S_ISGID:
        special_effects.append(
            "setgid can make executions use the file's group; on a directory, new entries can inherit its group"
            if target.kind == "directory"
            else "setgid can make executions run with the file's effective group"
        )
    if new_mode & stat.S_ISVTX:
        special_effects.append("sticky restricts who may remove or rename entries in this directory")
    effect_note = (
        " Special-bit effect: " + "; ".join(special_effects) + "."
        if special_effects
        else " This request clears any existing setuid, setgid, or sticky bits."
        if int(target.current_mode_octal, 8) & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
        else ""
    )
    return Elicit(
        f"Set the full permission mode of this exact {target.kind} at {str(target.path)!r} "
        f"from {target.current_mode_octal} to {target.new_mode_octal}? This is nonrecursive and does not change "
        "ownership. The new rwx permissions can remove access for users or make future access unavailable to this process."
        f"{effect_note}{acl_note} Current OS permissions apply; no privilege elevation is requested. "
        "Repeat the canonical path and both full modes.",
        FileModeChangeConfirmation,
    )


@asynccontextmanager
async def _server_lifespan(_server):
    async def expire_uploads_periodically() -> None:
        while True:
            await asyncio.sleep(30)
            await asyncio.to_thread(_expire_binary_file_uploads)

    expiry_task = asyncio.create_task(expire_uploads_periodically())
    try:
        yield {}
    finally:
        expiry_task.cancel()
        try:
            await expiry_task
        except asyncio.CancelledError:
            pass
        await asyncio.to_thread(_close_all_binary_file_uploads)
        await asyncio.to_thread(_terminal_sessions.close_all)
        await remote_desktop_portal.close()
        kwin_script_client.close()


def create_server(tool_selection: ToolSelection | None = None) -> MCPServer:
    selection = tool_selection or ToolSelection.from_environment()
    # Tie readiness output to every structured tool it describes so startup
    # selection does not leave statuses for a fully hidden capability.
    selection_sensitive_capability_tools = {
        "linux_system_info": ("get_linux_system_info",),
        "command_execution": ("run_shell_command",),
        "terminal_sessions": (
            "start_terminal_session",
            "read_terminal_session",
            "write_terminal_session",
            "close_terminal_session",
        ),
        "resource_usage": ("get_resource_usage",),
        "pressure_stall_info": ("get_pressure_stall_info",),
        "resource_history": ("sample_resource_history",),
        "process_history": ("sample_process_history",),
        "cgroup_history": ("sample_cgroup_history",),
        "process_execution_context": ("get_process_execution_context",),
        "namespace_inventory": ("list_namespace_inventory",),
        "container_inventory": ("list_containers",),
        "container_control": ("manage_container",),
        "container_create": ("create_container",),
        "container_image_inventory": ("list_container_images",),
        "container_image_control": ("manage_container_image",),
        "container_image_build": ("build_container_image",),
        "container_pod_inventory": ("list_container_pods",),
        "container_pod_control": ("manage_container_pod",),
        "virtual_machine_inventory": ("list_virtual_machines",),
        "virtual_machine_control": ("manage_virtual_machine",),
        "virtual_machine_configuration": ("configure_virtual_machine",),
        "virtual_machine_disk_attachment": ("attach_virtual_machine_disk",),
        "virtual_machine_snapshot_inventory": ("list_virtual_machine_snapshots",),
        "virtual_machine_snapshot_control": ("manage_virtual_machine_snapshot",),
        "virtualization_storage_inventory": ("list_libvirt_storage",),
        "libvirt_volume_creation": ("create_libvirt_storage_volume",),
        "cpu_inventory": ("list_cpu_inventory",),
        "numa_inventory": ("list_numa_nodes",),
        "gpu_inventory": ("list_gpu_devices",),
        "gpu_power_limit_inventory": ("list_gpu_power_limits",),
        "gpu_power_limit_control": ("manage_gpu_power_limit",),
        "powercap_limit_inventory": ("list_powercap_limits",),
        "powercap_limit_control": ("manage_powercap_limit",),
        "gpu_frequency_limit_inventory": ("list_xe_gpu_frequency_limits",),
        "gpu_frequency_limit_control": ("manage_xe_gpu_frequency_limit",),
        "process_list": ("list_processes",),
        "process_detail": ("get_process_detail",),
        "process_tree": ("get_process_tree",),
        "process_control": ("signal_process",),
        "filesystem_access": (
            "inspect_path",
            "list_path_extended_attributes",
            "list_directory",
            "read_text_file",
            "read_binary_file",
        ),
        "filesystem_write": (
            "create_text_file",
            "replace_text_file",
            "delete_text_file",
            "read_binary_file",
            "write_binary_file",
            "delete_binary_file",
            "begin_binary_file_upload",
            "append_binary_file_upload",
            "commit_binary_file_upload",
            "abort_binary_file_upload",
            "manage_directory",
            "manage_directory_tree",
            "manage_symlink",
            "change_path_owner",
            "manage_extended_attribute",
            "manage_posix_acl",
        ),
        "filesystem_permissions": (
            "set_file_mode",
            "change_path_owner",
            "manage_symlink",
            "manage_extended_attribute",
            "manage_posix_acl",
        ),
        "hardware_devices": ("list_hardware_devices",),
        "udev_inventory": ("list_udev_devices",),
        "sensor_readings": ("list_sensor_readings",),
        "fan_control_inventory": ("list_fan_controls",),
        "fan_control": ("manage_fan_control",),
        "display_backlight_inventory": ("list_display_backlights",),
        "display_brightness_control": ("manage_display_brightness",),
        "audio_inventory": ("list_audio_devices",),
        "audio_server_inventory": ("list_audio_server_devices",),
        "audio_server_control": ("manage_audio_endpoint",),
        "power_supply_inventory": ("list_power_supplies",),
        "power_state": ("get_power_state",),
        "power_inhibitor_inventory": ("list_power_inhibitors",),
        "power_control": ("get_power_action_readiness", "manage_power_action"),
        "power_profile_inventory": ("get_power_profile",),
        "power_profile_control": ("manage_power_profile",),
        "printer_inventory": ("list_printers",),
        "printer_control": ("manage_printer",),
        "kernel_modules": ("list_kernel_modules",),
        "kernel_module_control": ("manage_kernel_module",),
        "kernel_module_startup_control": ("manage_kernel_module_startup",),
        "kernel_parameter_inventory": ("list_kernel_parameters",),
        "kernel_parameter_control": ("manage_kernel_parameter",),
        "kernel_parameter_persistence": ("manage_persistent_kernel_parameter",),
        "kernel_command_line_control": ("manage_kernel_command_line",),
        "initramfs_control": ("manage_initramfs_rebuild",),
        "tpm_attestation": ("create_tpm_attestation",),
        "kernel_security_posture": ("get_kernel_security_posture",),
        "linux_audit": (
            "get_linux_audit_status",
            "list_linux_audit_events",
            "summarize_linux_audit",
            "manage_linux_audit_rule",
        ),
        "linux_audit_rule_control": ("manage_linux_audit_rule",),
        "selinux_booleans": ("list_selinux_booleans",),
        "selinux_boolean_control": ("manage_selinux_boolean",),
        "selinux_context_control": ("manage_selinux_context",),
        "selinux_fcontext_rule_control": ("manage_selinux_fcontext_rule",),
        "ima_measurements": ("list_ima_measurements",),
        "ima_policy": ("list_ima_policy",),
        "tpm_inventory": ("list_tpm_devices",),
        "tpm_event_log": ("list_tpm_event_log",),
        "service_inventory": ("list_services", "list_openrc_runlevels"),
        "service_control": ("manage_service",),
        "openrc_service_startup": ("manage_openrc_service_startup",),
        "runit_service_startup": ("manage_runit_service_startup",),
        "s6_service_startup": ("manage_s6_startup_set",),
        "systemd_timers": ("list_systemd_timers",),
        "systemd_timer_control": ("manage_systemd_timer",),
        "systemd_timer_definition_control": ("manage_systemd_timer_definition", "delete_systemd_timer_definition"),
        "systemd_service_definition_control": ("manage_systemd_service_definition",),
        "cron_inventory": ("list_cron_jobs",),
        "cron_control": ("manage_cron_job",),
        "at_control": ("manage_at_job",),
        "crypttab_inventory": ("list_crypttab_entries",),
        "boot_target_inventory": ("list_boot_targets",),
        "boot_target_control": ("set_default_boot_target",),
        "session_inventory": ("list_login_sessions",),
        "journal_inventory": ("list_journal_entries",),
        "system_log_inventory": ("list_system_log_entries",),
        "local_users": ("list_local_users",),
        "local_groups": ("list_local_groups",),
        "nss_identity_lookup": ("lookup_nss_identity",),
        "local_identity_control": ("manage_local_identity",),
        "local_password_control": ("set_local_user_password",),
        "local_ssh_key_control": ("manage_local_ssh_key",),
        "sudo_policy_control": ("manage_sudo_policy", "manage_sudo_group_policy"),
        "sssd_domain_inventory": ("list_sssd_domains",),
        "sssd_domain_control": ("manage_sssd_domain",),
        "pam_profile_inventory": ("list_pam_profiles",),
        "pam_profile_control": ("manage_pam_profile",),
        "package_inventory": ("list_installed_packages",),
        "package_control": ("manage_package",),
        "application_package_inventory": ("list_application_packages",),
        "application_package_control": (
            "manage_flatpak_package",
            "manage_snap_package",
            "manage_nix_profile_entry",
            "manage_nix_profile_history",
        ),
        "nix_profile_history_inventory": ("list_nix_profile_history",),
        "nix_profile_history_control": ("manage_nix_profile_history",),
        "window_list": ("observe_desktop", "list_windows"),
        "window_detail": ("get_window_detail", "get_focused_window"),
        "window_focus": ("focus_window",),
        "window_close": ("close_window",),
        "window_resize": ("resize_window",),
        "window_minimize": ("minimize_window",),
        "window_maximize": ("maximize_window",),
        "workspace_list": ("observe_desktop", "list_workspaces"),
        "output_list": ("list_outputs",),
        "workspace_switch": ("switch_workspace",),
        "window_move_workspace": ("move_window_to_workspace",),
        "screenshot": ("capture_screenshot",),
        "input_pointer": ("observe_desktop", "pointer_action"),
        "input_keyboard": ("observe_desktop", "keyboard_action"),
        "input_touch": ("observe_desktop", "touch_action"),
        "app_discovery": ("list_desktop_apps",),
        "app_launch": ("list_desktop_apps", "launch_app"),
        "clipboard_read": ("observe_desktop", "read_clipboard"),
        "clipboard_write": ("observe_desktop", "write_clipboard"),
        "notifications": ("observe_desktop", "send_notification"),
        "accessibility": ("inspect_accessibility_tree",),
        "apparmor_profile_control": ("manage_apparmor_profile",),
        "apparmor_profiles": ("list_apparmor_profiles",),
        "block_devices": ("list_block_devices",),
        "block_device_stats": ("list_block_device_stats",),
        "block_device_health": ("get_block_device_health",),
        "btrfs_snapshot_inventory": ("list_btrfs_snapshots",),
        "btrfs_snapshot_control": ("manage_btrfs_snapshot",),
        "btrfs_filesystem_control": ("manage_btrfs_filesystem",),
        "ext4_control": ("manage_ext4_filesystem",),
        "filesystem_list": ("list_filesystems",),
        "fstab_inventory": ("list_fstab_entries",),
        "luks_control": ("manage_luks_mapping",),
        "luks_token_inventory": ("list_luks_tokens",),
        "luks_token_control": ("manage_luks_token",),
        "luks_header_control": ("manage_luks_header",),
        "lvm_control": ("manage_lvm_volume",),
        "lvm_group_control": ("manage_lvm_volume_group",),
        "lvm_inventory": ("list_lvm_inventory",),
        "md_raid_control": ("manage_md_raid",),
        "mount_control": ("manage_mount",),
        "python_environment_control": ("manage_python_environment",),
        "python_environment_inventory": ("list_python_environments", "list_python_environment_packages"),
        "native_package_environment_control": ("manage_native_package_environment",),
        "native_package_environment_inventory": ("list_native_package_environments", "list_native_environment_packages"),
        "container_resource_control": ("manage_container_resource", "manage_container_network_attachment"),
        "container_resource_inventory": ("list_container_resources", "list_container_network_attachments"),
        "dns_configuration": ("get_dns_configuration",),
        "firewall_control": ("manage_firewall_rule",),
        "firewall_frontend_inventory": ("list_firewall_frontends",),
        "firewall_rules": ("list_firewall_rules",),
        "firewalld_port_control": ("manage_firewalld_port",),
        "firewalld_icmp_block_control": ("manage_firewalld_icmp_block",),
        "firewalld_service_control": ("manage_firewalld_service",),
        "firewalld_rich_rule_control": ("manage_firewalld_rich_rule", "manage_firewalld_rich_icmp_rule", "manage_firewalld_rich_protocol_rule"),
        "network_addresses": ("list_network_addresses",),
        "network_control": ("manage_network_interface", "manage_network_address"),
        "network_interfaces": ("list_network_interfaces",),
        "network_manager_control": ("manage_network_manager_profile",),
        "network_manager_profile_dns": ("get_network_manager_profile_dns",),
        "network_manager_profile_dns_control": ("configure_network_manager_profile_dns",),
        "network_manager_profile_ip": ("get_network_manager_profile_ip",),
        "network_manager_profile_ip_control": ("configure_network_manager_profile_ip",),
        "network_manager_profile_routes": ("get_network_manager_profile_routes",),
        "network_manager_profile_route_control": ("manage_network_manager_profile_route",),
        "network_manager_profiles": ("list_network_manager_profiles",),
        "network_manager_virtual_profile_control": (
            "create_network_manager_virtual_profile",
            "create_network_manager_port_profile",
            "manage_network_manager_port_membership",
        ),
        "network_manager_vpn_import": ("import_network_manager_vpn_profile",),
        "network_policy": ("list_network_policy",),
        "network_protocol_stats": ("list_network_protocol_stats",),
        "network_route_lookup": ("lookup_network_route",),
        "network_routes": ("list_network_routes",),
        "network_socket_owners": ("list_socket_owners",),
        "network_sockets": ("list_network_sockets",),
        "network_unix_raw_sockets": ("list_unix_raw_sockets",),
        "radio_control": ("manage_radio_device",),
        "radio_inventory": ("list_radio_devices",),
        "bluetooth_device_inventory": ("list_bluetooth_devices",),
        "bluetooth_pairing": ("manage_bluetooth_pairing",),
        "remote_virtual_machine_control": ("manage_remote_virtual_machine",),
        "remote_virtual_machine_inventory": ("list_remote_virtual_machines",),
        "remote_virtual_machine_snapshot_inventory": ("list_remote_virtual_machine_snapshots",),
        "remote_virtual_machine_snapshot_control": ("manage_remote_virtual_machine_snapshot",),
        "remote_virtual_machine_disk_attachment": ("attach_remote_virtual_machine_disk",),
        "remote_virtual_machine_creation": ("create_remote_virtual_machine",),
        "remote_virtual_machine_configuration": ("configure_remote_virtual_machine",),
        "remote_libvirt_network_inventory": ("list_remote_libvirt_networks",),
        "remote_libvirt_storage_inventory": ("list_remote_libvirt_storage",),
        "remote_libvirt_resource_control": ("manage_remote_libvirt_resource",),
        "route_control": ("manage_network_route",),
        "systemd_network_profiles": ("list_systemd_network_profiles",),
        "systemd_network_profile_control": (
            "configure_systemd_network_profile",
            "create_systemd_network_profile",
            "create_systemd_netdev_profile",
            "configure_systemd_netdev_profile",
            "delete_systemd_netdev_profile",
            "delete_systemd_network_profile",
        ),
        "storage_topology": ("list_storage_topology",),
        "time_settings": ("get_time_settings", "list_time_zones"),
        "time_control": ("manage_time_settings",),
        "time_sync_status": ("get_time_sync_status",),
        "ufw_port_control": ("manage_ufw_port_rule",),
        "virtual_network_creation": ("create_libvirt_isolated_network", "create_libvirt_network"),
        "virtual_network_ipv4_control": ("configure_libvirt_network_ipv4",),
        "virtual_network_inventory": ("list_libvirt_networks",),
        "libvirt_resource_control": ("manage_libvirt_resource",),
        "virtual_machine_creation": ("create_virtual_machine",),
        "xfs_control": ("manage_xfs_filesystem",),
    }
    server = MCPServer(
        name="linux-mcp",
        version="0.1.0",
        instructions=(
            "manage_apparmor_profile changes one exact loaded AppArmor profile between enforce and complain modes after client confirmation; it edits the matching standard profile file and reloads it, uses current-account permissions, does not force unconfined profiles, and complain mode weakens confinement. manage_selinux_boolean changes one exact SELinux boolean after confirmation. manage_selinux_context restores the policy-defined type on one exact path without recursion or force-reset options; manage_selinux_fcontext_rule adds or removes one persistent anchored literal path rule and does not relabel the current object. "
            "Linux host and desktop MCP. Host inventory and filesystem-read tools are read-only; list_systemd_timers reports loaded system and user-manager timer schedules, manage_systemd_timer starts/stops/enables/disables one exact timer after confirmation; manage_systemd_timer_definition creates or updates a generated timer file for an already-loaded service without starting or enabling it; delete_systemd_timer_definition removes an inactive, disabled generated timer file after confirmation; manage_systemd_service_definition creates or updates a confirmed generated one-shot service unit from an absolute executable and fixed argv, then reloads the manager without starting or enabling it; manage_kernel_module_startup adds/removes a confirmed exact-module entry in systemd modules-load.d for future boots only; list_kernel_parameters reads four fixed runtime sysctls, manage_kernel_parameter changes one exact allowlisted runtime value after confirmation, and manage_persistent_kernel_parameter writes one generated sysctl.d setting for systemd-sysctl at boot without changing the running value; manage_kernel_command_line adds/removes one simple argument through current grubby entries or a bounded static /etc/default/grub GRUB_CMDLINE_LINUX/GRUB_CMDLINE_LINUX_DEFAULT assignment plus verified grub-mkconfig regeneration when grubby is unavailable, refuses root= and unsupported shell/config layouts, and binds confirmation to boot-entry/config/generator state; grub-mkconfig may execute root-owned /etc/grub.d hooks; future-entry templates on grubby hosts, other GRUB layouts, expanded mkinitcpio presets, and nonstandard initramfs targets are not exposed; list_cron_jobs reports visible cron/Anacron schedules and at-queue metadata while omitting commands, list_fstab_entries reports bounded /etc/fstab metadata while omitting exact sources and arbitrary option values, and list_crypttab_entries reports encrypted-device configuration metadata while omitting device identifiers, key paths, and arbitrary option values; list_storage_topology reports bounded active sysfs block-device layering, selected device-mapper classes, and MD RAID metadata including current sync action, completed/total sectors, and mismatch sectors when exposed, while list_lvm_inventory reports bounded LVM volume-group extents and logical-volume layout using read-only vgs/lvs reports and omitting physical-volume paths/UUIDs and active-use state; manage_lvm_volume can create/grow exact logical volumes, shrink only linear raw or ext4 volumes with a verified offline filesystem, create/remove LVM snapshots, or restore one exact healthy classic COW snapshot below 100% usage into its named origin after confirmation and active-but-closed device checks; restore overwrites origin changes made since the snapshot, requires an already-root server plus lvconvert, dmsetup, and fuser, and verifies LV topology rather than block contents; ext4 resize occurs before LV reduction and other filesystems/layouts are refused. list_btrfs_snapshots inventories local/received snapshots under an explicit mounted Btrfs top-level subvolume (ID 5); manage_btrfs_snapshot confirms read-write/read-only creation, exact snapshot deletion, or constrained restore of a read-only snapshot as a writable clone at an exact unmounted non-default subvolume, preserving the original at a new sibling backup path through an atomic target/staging exchange followed by a no-overwrite backup rename; it does not change /etc/fstab or the default subvolume, refuses nested subvolumes, and reports that snapshots share copy-on-write extents and do not recursively include nested subvolumes. manage_btrfs_filesystem creates a single-device Btrfs filesystem on a verified unused device, grows one mounted single-device filesystem online after backing-device expansion, or shrinks one mounted filesystem to a confirmed sector-aligned byte size above the current minimum; shrink requires an already-root server, may relocate data with heavy I/O, and changes no backing-device layer. manage_mount mounts or unmounts one exact configured fstab target after confirmation, using current-user permissions and no elevation. manage_audio_endpoint changes volume, mute, or default state for one exact current-session sink/source after confirmation, with volume capped at 100%. lookup_network_route reports the kernel-selected route for one literal IPv4/IPv6 destination through a bounded read-only iproute2 lookup without sending packets. create_text_file creates a new exact path, replace_text_file replaces the full content of one exact regular text file, and delete_text_file unlinks one exact regular text-file path without secure erasure or recovery, with explicit client confirmation bound to the path and content digest; read_binary_file pages binary reads, write_binary_file creates/replaces/appends binary data up to 4 MiB per call, begin_binary_file_upload confirms a complete size and SHA-256 before staging up to 64 GiB in sequential chunks with available-space preflight for atomic create/replacement, and the append/commit/abort upload tools require its short-lived secret token, delete_binary_file unlinks one exact regular file, manage_directory creates parents or recursively deletes a bounded directory tree, manage_directory_tree confirms bounded recursive copy to an atomic new path or same-filesystem move, manage_symlink creates/removes a symlink, change_path_owner changes numeric UID/GID on one exact path or a confirmed bounded directory tree (root required, no mounted paths/special files, no symlink following), and manage_extended_attribute/manage_posix_acl change xattrs/ACLs after exact confirmation; set_file_mode changes rwx and supported type-compatible special bits on one exact file or directory; chmod can change effective ACL permissions. Process execution context reports bounded scheduler, cgroup, namespace, and security metadata for one explicit PID. create_text_file, replace_text_file, delete_text_file, read_binary_file, write_binary_file, begin_binary_file_upload, delete_binary_file, manage_directory, manage_symlink, change_path_owner, manage_extended_attribute, manage_posix_acl, set_file_mode, manage_lvm_volume, manage_btrfs_snapshot, manage_mount, manage_audio_endpoint, manage_systemd_timer, manage_systemd_timer_definition, manage_systemd_service_definition, manage_kernel_module_startup, manage_kernel_parameter, manage_persistent_kernel_parameter, manage_initramfs_rebuild, create_tpm_attestation, manage_service, manage_package, manage_python_environment, set_default_boot_target, manage_power_action, signal_process, manage_container, manage_container_network_attachment, manage_virtual_machine, manage_virtual_machine_snapshot, manage_libvirt_resource, manage_radio_device, manage_network_interface, manage_network_address, manage_network_route, manage_network_manager_profile, configure_systemd_network_profile, create_systemd_network_profile, delete_systemd_network_profile, configure_network_manager_profile_dns, configure_network_manager_profile_ip, create_network_manager_virtual_profile, create_network_manager_port_profile, manage_network_manager_port_membership, import_network_manager_vpn_profile, manage_firewall_rule, manage_firewalld_port, manage_firewalld_rich_rule, and manage_ufw_port_rule are host control tools and require explicit client confirmation. manage_package runs one package-manager transaction with current-user permissions, may execute package scripts and alter dependencies, and does not request privilege elevation. manage_power_action requests one immediate system-wide logind transition or firmware-setup reboot; it uses current-user permissions, does not request privilege elevation, and does not bypass inhibitor locks. get_power_action_readiness reports the current logind support and authorization signal but cannot guarantee that firmware or hardware will complete the transition. signal_process, manage_container, manage_virtual_machine, manage_radio_device, manage_network_interface, and manage_network_address require fresh identity tokens from their inventory tools. Container tools use standard local Docker/Podman Unix sockets or the local Podman CLI forced into non-remote mode; a rootful engine may perform host-privileged operations. list_container_network_attachments reports named-network attachments for one exact local container while omitting addresses and endpoint settings; manage_container_network_attachment confirms connect/disconnect for one exact non-default network, refuses forced or last-network disconnection, and verifies the result. Podman network attachment inspection and control are limited to running standalone containers. list_virtual_machines inventories local QEMU domains through fixed qemu:///system and qemu:///session connections. list_remote_virtual_machines accepts only constrained qemu+ssh endpoints ending in /system or /session; manage_remote_virtual_machine requires exact endpoint/domain/state confirmation and disables SSH config, agent forwarding, password prompts, and unknown host-key acceptance. attach_remote_virtual_machine_disk requires the fresh identity_token from list_remote_virtual_machines and confirms one existing raw/qcow2 volume from an active persistent remote directory pool for an unused virtio slot in a shut-off VM; it checks complete bounded remote domain definitions for existing references and updates only persistent configuration. The guest may alter the volume on a later start. list_virtual_machine_snapshots reports bounded snapshot names for one exact local VM token. manage_virtual_machine_snapshot confirms disk snapshot creation only for shut-off guests, reversion to one exact snapshot, or leaf-only snapshot deletion; reversion can discard later guest data and may restore a saved running guest. list_libvirt_networks inventories local virtual-network names and state; list_libvirt_storage inventories local pool state and capacity and can return volume names and sizes for one exact pool in one selected scope, omitting storage paths and XML. Both use read-only virsh calls. manage_libvirt_resource requires exact client confirmation and a short-lived UUID/state-bound token before starting/stopping one local network or pool or changing its autostart setting. manage_remote_libvirt_resource resolves an exact qemu+ssh endpoint and network/storage-pool name, then confirms the endpoint, scope, UUID, action, and current state before revalidation and post-action verification. create_libvirt_isolated_network and create_libvirt_network define persistent inactive local networks from bounded settings; configure_libvirt_network_ipv4 changes only IPv4 address/DHCP settings on supported inactive NAT/routed networks after exact confirmation, preserving UUID, mode, bridge, and autostart. manage_virtual_machine requires exact client confirmation and a fresh UUID-bound identity token; it uses current libvirt authorization without invoking sudo or registering virsh’s terminal polkit agent, and it does not expose force-off or undefine. list_radio_devices reports exact rfkill device indexes, types, names, and soft/hard block state. manage_radio_device requires exact client confirmation, changes only one device’s soft block state, cannot override a hard block, and may disconnect this MCP client. manage_network_interface changes current-namespace link state or MTU; manage_network_address adds or removes one exact current-namespace address; manage_network_route adds or removes one exact transient static route; manage_network_manager_profile activates or deactivates one exact NetworkManager profile or persistently toggles only its autoconnect property; configure_network_manager_profile_dns changes selected saved IPv4/IPv6 DNS values without activation or reapplication; get_network_manager_profile_ip reads saved IPv4/IPv6 method, address/prefix, and gateway values; configure_network_manager_profile_ip confirms and verifies automatic/manual address, prefix, and gateway updates to the saved profile without activation or reapplication; get_network_manager_profile_routes reports saved IPv4/IPv6 routes and their attributes, while manage_network_manager_profile_route confirms and verifies simple saved route additions/removals without activation or reapplication; configure_systemd_network_profile edits selected settings in one exact existing systemd-networkd .network file after literal-interface and precedence checks, validates referenced .netdev devices, and does not reload/reconfigure networkd; create_systemd_network_profile creates one typed profile after collision/precedence checks, requires an already-root server, and does not reload/reconfigure networkd; delete_systemd_network_profile removes one exact root-owned literal-interface profile after full-state confirmation, refuses drop-ins, ambiguous precedence, and same-named fallback profiles, and does not reload/reconfigure networkd; configure_systemd_netdev_profile changes typed bridge STP/VLAN-filtering, bond-mode, or VLAN-ID settings in one exact existing root-owned .netdev file after full-state confirmation; delete_systemd_netdev_profile unlinks one exact inactive supported .netdev only when no detected .network match or membership reference depends on it; both refuse drop-ins and same-named fallbacks and do not reload/reconfigure networkd; manage_firewall_rule adds or removes one exact transient inbound TCP/UDP block rule in its dedicated nftables table. manage_firewalld_port adds or removes one exact TCP/UDP destination-port or source-port entry in a selected firewalld zone, either in runtime state or saved permanent configuration; adding it may expose the service through all zone bindings, and other rules may independently allow that port. manage_firewalld_icmp_block adds or removes one exact supported ICMP type block in a selected firewalld zone; it refuses ICMP block inversion. manage_firewalld_rich_rule adds or removes one typed TCP/UDP source or destination port or port-range rule with optional same-family source/destination CIDRs, accept/reject/drop verdict, kernel logging and audit records rate-limited to one match per minute, and priority from -32768 through 32767; negative priorities run before other firewalld primitives, positive priorities after them, priority 0 follows log/deny/allow chain order, and equal-priority ordering is undefined. It does not accept arbitrary rich-rule text or other rich-rule elements/actions. manage_firewalld_rich_icmp_rule matches one exact supported ICMP type, and manage_firewalld_rich_protocol_rule matches one IP protocol number or a name resolved through the host local protocol database; both use typed source/destination filters, verdict, logging, audit, and priority settings with exact state confirmation. manage_ufw_port_rule adds or removes one TCP/UDP numeric port, contiguous range, or sorted list of 2–15 distinct numeric ports (not combined with a range) for allow, deny, reject, or connection-rate-limit in active UFW with inbound/outbound direction and optional literal source/destination IP or CIDR filters; interfaces, routed rules, and default-policy changes are outside the tool, and other rules may affect effective behavior. NetworkManager virtual-profile tools create inactive bridge, bond, and VLAN profiles; port-profile membership changes update only saved controller/port-type fields on one pinned Ethernet profile, including active profiles, while preserving autoconnect and IPv4/IPv6 methods. They do not activate, deactivate, or reapply a profile; for active profiles, the current applied settings remain until NetworkManager reapplies or reactivates it, and a later apply may change traffic. VPN import supports bounded self-contained OpenVPN and WireGuard configs and leaves the profile inactive. Network and firewall actions may interrupt or expose access. run_shell_command runs arbitrary /bin/sh commands after exact request confirmation with the server identity by default and optional noninteractive sudo/root mode, bounded to 30 minutes and 1 MiB of combined output; start_terminal_session opens a confirmed interactive PTY for up to 30 minutes, and read_terminal_session, write_terminal_session, and close_terminal_session manage its bounded output, individually confirmed input/resizing, and process group. Browser navigation, DOM, and browser-profile tools are intentionally outside this server. "
            "manage_lvm_volume_group creates a new LVM group, adds blank PVs, removes only unused PVs, or atomically migrates allocated extents between exact PVs after confirmation; pvmove migration requires twice the source allocation free on its destination and may take up to 30 minutes. manage_md_raid creates and activates verified Linux MD RAID0/1/4/5/6/10 arrays, manages blank spares, replaces one healthy active member on a non-degraded idle array, marks one exact healthy member faulty, removes one exact already-faulty member, starts a non-repairing consistency check on a healthy idle redundant array, or stops one exact active idle array after confirmation when it is unmounted, unused by swap, writable, and has no block-layer holders; stopping does not erase member data or remove RAID metadata but makes the array unavailable until assembled again. Check reads all members, records mismatches, and may still trigger normal MD recovery writes after read errors. Assembly supports only complete, clean, non-degraded native version-1 arrays from exact active members, read-only by default with a confirmed read-write option; it refuses legacy/external metadata, stale or dirty members, reshape/recovery metadata, spares, and degraded starts. Repair, reshape, and boot-time assembly configuration remain unavailable. "
            "Observe the desktop first and pass its fresh snapshot token to every mutation. Use exact compositor-issued window/workspace IDs. "
            "Pointer and keyboard input use XDG RemoteDesktop consent and require a fresh token. "
            "Startup category and tool selection changes which MCP tools are registered; it does not restrict operating-system permissions or network access through other enabled tools. "
            + selection.status_text()
        ),
        lifespan=_server_lifespan,
    )
    tool = selected_tool_decorator(server, selection)

    @tool(name="get_session_capabilities", description="Report Linux host inspection and desktop-session feature readiness, dependencies, and permissions.")
    async def tool_get_session_capabilities() -> CapabilitiesResponse:
        response = await _get_session_capabilities()
        visible_capabilities = dict(response.capabilities)
        for capability, related_tools in selection_sensitive_capability_tools.items():
            if not any(selection.is_enabled(name) for name in related_tools):
                visible_capabilities.pop(capability, None)
        if len(visible_capabilities) == len(response.capabilities):
            return response
        visible_count = sum(item.available for item in visible_capabilities.values())
        summary_prefix = response.summary.partition("; available capabilities:")[0]
        return CapabilitiesResponse(
            session=response.session,
            capabilities=visible_capabilities,
            summary=(
                f"{summary_prefix}; available capabilities: {visible_count}/{len(visible_capabilities)}. "
                "Capability details are hidden when all related tools are disabled."
            ),
        )

    @tool(name="run_shell_command", description="Run an arbitrary /bin/sh command after explicit MCP client confirmation using a phrase bound to the complete request. Runs as the MCP server's OS identity by default; run_as='root' uses noninteractive sudo when the server is not already root and therefore requires applicable sudo policy. Command and stdin are capped at 64 KiB; environment overrides at 64 entries/64 KiB; timeout at 1-1800 seconds; combined output at 1 KiB-1 MiB. Uses pipes without a TTY, so terminal-only programs need noninteractive modes. The shell can perform any operation permitted to that identity, including destructive system changes. Detached processes may outlive timeout/process-group cleanup.")
    async def tool_run_shell_command(
        command: str,
        confirmation: Annotated[
            ElicitationResult[CommandExecutionConfirmation],
            Resolve(_confirm_shell_command),
        ],
        working_directory: str = "",
        timeout_seconds: int = 60,
        max_output_bytes: int = 65536,
        stdin_text: str = "",
        environment: dict[str, str] | None = None,
        run_as: Literal["server", "root"] = "server",
    ) -> CommandExecutionResponse:
        if confirmation.action != "accept":
            return _failed_command_response(
                command=command,
                working_directory=working_directory,
                run_as=run_as,
                message="Explicit client confirmation is required; no command was run.",
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                stdin_text=stdin_text,
                environment=environment,
            )
        prepared, error = _prepare_command(
            command,
            working_directory,
            timeout_seconds,
            max_output_bytes,
            stdin_text,
            environment,
            run_as,
        )
        if error or prepared is None:
            return _failed_command_response(
                command=command,
                working_directory=working_directory,
                run_as=run_as,
                message=error or "The command request could not be prepared.",
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                stdin_text=stdin_text,
                environment=environment,
                user_confirmed=True,
            )
        data = confirmation.data
        if data.confirm is not True or data.confirmation_phrase != prepared.phrase:
            return _failed_command_response(
                command=command,
                working_directory=prepared.working_directory,
                run_as=run_as,
                message="Confirmation did not match this exact command request; no command was run.",
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                stdin_text=stdin_text,
                environment=environment,
                user_confirmed=False,
            )
        return await asyncio.to_thread(_run_prepared_command, prepared, confirmed=True)

    @tool(name="start_terminal_session", description="Start a persistent interactive /bin/sh session on a PTY after explicit client confirmation bound to the command, working directory, environment, identity, lifetime, and terminal size. Runs as the server identity by default; run_as='root' uses noninteractive sudo or the already-root server. Sessions last at most 1800 seconds; up to 8 can run concurrently; retained output is capped at 1 MiB. Use read_terminal_session, write_terminal_session, and close_terminal_session to interact. Detached processes can outlive the terminal session.")
    async def tool_start_terminal_session(
        command: str,
        confirmation: Annotated[
            ElicitationResult[TerminalSessionConfirmation],
            Resolve(_confirm_terminal_session_start),
        ],
        working_directory: str = "",
        timeout_seconds: int = 1800,
        environment: dict[str, str] | None = None,
        run_as: Literal["server", "root"] = "server",
        rows: int = 24,
        columns: int = 80,
    ) -> TerminalSessionStartResponse:
        if confirmation.action != "accept":
            return TerminalSessionStartResponse(success=False, message="Explicit client confirmation is required; no terminal was started.")
        prepared, digest, error = _terminal_start_request(
            command, working_directory, timeout_seconds, environment, run_as, rows, columns
        )
        if error or prepared is None or digest is None:
            return TerminalSessionStartResponse(success=False, message=error or "The terminal request could not be prepared.")
        data = confirmation.data
        if data.confirm is not True or data.confirmation_phrase != f"RUN {digest[:16]}":
            return TerminalSessionStartResponse(
                success=False,
                request_sha256=digest,
                working_directory=prepared.working_directory,
                run_as=run_as,
                terminal_rows=rows,
                terminal_columns=columns,
                message="Confirmation did not match this exact terminal request; no process was started.",
            )
        return await asyncio.to_thread(
            _terminal_sessions.start,
            prepared,
            request_digest=digest,
            rows=rows,
            columns=columns,
        )

    @tool(name="read_terminal_session", description="Read bounded output from one terminal session. Supports polling for up to 10 seconds and returns merged PTY output, cumulative dropped-byte count, process state, and exit code. Reading does not send input or change terminal state.")
    async def tool_read_terminal_session(
        session_id: str,
        wait_seconds: float = 1.0,
        max_bytes: int = 16384,
    ) -> TerminalSessionOutputResponse:
        return await asyncio.to_thread(
            _terminal_sessions.read,
            session_id,
            wait_seconds=wait_seconds,
            max_bytes=max_bytes,
        )

    @tool(name="write_terminal_session", description="After explicit confirmation bound to the session and exact input, send up to 4 KiB of text to one live PTY session or resize it to 1-500 rows and columns. A newline or control character can execute commands in the session. Every write/resize requires a typed confirmation phrase.")
    async def tool_write_terminal_session(
        session_id: str,
        confirmation: Annotated[
            ElicitationResult[TerminalSessionConfirmation],
            Resolve(_confirm_terminal_session_write),
        ],
        text: str = "",
        rows: int | None = None,
        columns: int | None = None,
    ) -> TerminalSessionWriteResponse:
        if confirmation.action != "accept":
            return TerminalSessionWriteResponse(success=False, session_id=session_id, message="Explicit client confirmation is required; no terminal input was sent.")
        digest = _terminal_write_digest(session_id, text, rows, columns)
        data = confirmation.data
        if data.confirm is not True or data.confirmation_phrase != f"SEND {digest[:16]}":
            return TerminalSessionWriteResponse(success=False, session_id=session_id, message="Confirmation did not match this exact terminal input; nothing was sent.")
        return await asyncio.to_thread(
            _terminal_sessions.write,
            session_id,
            text=text,
            rows=rows,
            columns=columns,
        )

    @tool(name="close_terminal_session", description="After explicit client confirmation, send SIGHUP and terminate the process group attached to one exact terminal session. Detached/new-session processes may outlive it.")
    async def tool_close_terminal_session(
        session_id: str,
        confirmation: Annotated[
            ElicitationResult[TerminalSessionConfirmation],
            Resolve(_confirm_terminal_session_close),
        ],
    ) -> TerminalSessionCloseResponse:
        if confirmation.action != "accept":
            return TerminalSessionCloseResponse(success=False, session_id=session_id, message="Explicit client confirmation is required; no process was terminated.")
        digest = _terminal_close_digest(session_id)
        data = confirmation.data
        if data.confirm is not True or data.confirmation_phrase != f"CLOSE {digest[:16]}":
            return TerminalSessionCloseResponse(success=False, session_id=session_id, message="Confirmation did not match this terminal session; no process was terminated.")
        return await asyncio.to_thread(_terminal_sessions.close, session_id)

    @tool(name="get_linux_system_info", description="Read the Linux distribution, kernel, architecture, init system, hostname, and uptime. Does not read machine IDs or credentials.")
    def tool_get_linux_system_info() -> LinuxSystemInfoResponse:
        return _get_linux_system_info()

    @tool(name="get_resource_usage", description="Read CPU count, load averages, memory, swap, and uptime from Linux procfs.")
    def tool_get_resource_usage() -> ResourceUsageResponse:
        return _get_resource_usage()

    @tool(name="get_pressure_stall_info", description="Read bounded system-wide CPU, memory, and I/O Pressure Stall Information averages and cumulative stall time from fixed /proc/pressure files. Unsupported resource files remain unavailable; no PSI triggers or controls are created.")
    def tool_get_pressure_stall_info() -> PressureStallInfoResponse:
        return _get_pressure_stall_info()

    @tool(name="sample_resource_history", description="Collect 2-20 bounded CPU-utilization, memory, swap, load, and uptime samples over a requested interval. Sampling lasts at most 60 seconds and reads Linux procfs only.")
    async def tool_sample_resource_history(
        sample_count: int = 5,
        interval_seconds: float = 1.0,
    ) -> ResourceHistoryResponse:
        return await _sample_resource_history(
            sample_count=sample_count,
            interval_seconds=interval_seconds,
        )

    @tool(name="sample_process_history", description="Sample CPU time, resident/virtual memory, thread count, and storage-layer read/write counters and rates for up to 32 explicit PIDs over 2-20 intervals. The request lasts at most 60 seconds, checks process start-time identity, and omits command lines, environments, and working directories.")
    async def tool_sample_process_history(
        pids: list[int],
        sample_count: int = 5,
        interval_seconds: float = 1.0,
    ) -> ProcessResourceHistoryResponse:
        return await _sample_process_history(
            pids=pids,
            sample_count=sample_count,
            interval_seconds=interval_seconds,
        )

    @tool(name="sample_cgroup_history", description="Sample cgroup-v2 CPU, memory, swap, and PID resources for up to 32 explicit PIDs over 2-20 intervals. Runs for at most 60 seconds and samples only when the target shares the server's cgroup namespace and the hierarchy root is safely visible at /sys/fs/cgroup.")
    async def tool_sample_cgroup_history(
        pids: list[int],
        sample_count: int = 5,
        interval_seconds: float = 1.0,
    ) -> ProcessCgroupHistoryResponse:
        return await _sample_cgroup_history(
            pids=pids,
            sample_count=sample_count,
            interval_seconds=interval_seconds,
        )

    @tool(name="list_cpu_inventory", description="List bounded logical CPU IDs, online state, topology, model/vendor, and available frequency readings from procfs/sysfs. Frequency fields are snapshots and are not controls.")
    def tool_list_cpu_inventory(limit: int = 128) -> CPUInventoryResponse:
        return _list_cpu_inventory(limit=limit)

    @tool(name="list_numa_nodes", description="List bounded NUMA node online state, CPU membership, per-node memory totals/free memory, and distances to online nodes from fixed Linux sysfs attributes. Optional fields may be unavailable; no NUMA controls are exposed.")
    def tool_list_numa_nodes(limit: int = 128) -> NUMANodeListResponse:
        return _list_numa_nodes(limit=limit)

    @tool(name="list_gpu_devices", description="List bounded Linux DRM GPU card metadata and available driver-specific read-only telemetry: AMDGPU utilization/VRAM, Intel i915/Xe hwmon temperature/energy, Xe actual per-GT frequency, Nouveau temperature, and optional NVIDIA nvidia-smi utilization/memory/temperature/power. Unsupported metrics remain absent; no controls, process lists, UUIDs, or serial-number fields are queried.")
    def tool_list_gpu_devices(limit: int = 32) -> GPUInventoryResponse:
        return _list_gpu_devices(limit=limit)

    @tool(name="list_gpu_power_limits", description="List PCI DRM GPUs whose standard Linux hwmon interface exposes a current power cap and driver-reported minimum/maximum range. Caps are in microWatts; this tool reads only and does not query undocumented controls.")
    def tool_list_gpu_power_limits(query: str = "", limit: int = 64) -> GPUPowerLimitListResponse:
        return _list_gpu_power_limits(query=query, limit=limit)

    @tool(name="manage_gpu_power_limit", description="After exact client confirmation, set one exact PCI GPU's standard hwmon power cap to a driver-supported value in microWatts. The GPU, controller, current cap, and allowed min/max are bound to confirmation and rechecked; the value is verified after writing. A higher limit can increase power draw and heat, while a lower limit can reduce performance. Only GPUs exposing standard powerX_cap/min/max attributes are supported. Uses current OS permissions without sudo or elevation.")
    async def tool_manage_gpu_power_limit(
        drm_card: str,
        controller: str,
        power_index: int,
        target_micro_watts: int,
        confirmation: Annotated[
            ElicitationResult[GPUPowerLimitActionConfirmation],
            Resolve(_confirm_gpu_power_limit),
        ],
    ) -> GPUPowerLimitActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_gpu_power_limit_action,
                drm_card,
                controller,
                power_index,
                target_micro_watts,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_gpu_power_limit_action,
            drm_card,
            controller,
            power_index,
            target_micro_watts,
            confirmed=True,
            confirmation_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="list_powercap_limits", description="List bounded Linux powercap zones and their driver-exposed power constraints, current limits, optional time windows, and supported ranges. This covers CPU/platform power controls and other devices using the standard /sys/class/powercap ABI; entries without a valid reported range are read-only through this tool.")
    def tool_list_powercap_limits(query: str = "", limit: int = 64) -> PowercapLimitListResponse:
        return _list_powercap_limits(query=query, limit=limit)

    @tool(name="manage_powercap_limit", description="After exact client confirmation, set one Linux powercap constraint to an integer microWatt value inside the driver's reported minimum/maximum range. Revalidates the exact zone, constraint, current value, range, and sysfs identities, then verifies the result. A lower limit can reduce performance; a higher limit can increase power use and heat. Uses current OS permissions without elevation.")
    async def tool_manage_powercap_limit(
        zone: str,
        constraint_index: int,
        target_power_limit_uw: int,
        confirmation: Annotated[
            ElicitationResult[PowercapLimitActionConfirmation],
            Resolve(_confirm_powercap_limit),
        ],
    ) -> PowercapLimitActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_powercap_limit_action,
                zone,
                constraint_index,
                target_power_limit_uw,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_powercap_limit_action,
            zone,
            constraint_index,
            target_power_limit_uw,
            confirmed=True,
            confirmation_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="list_xe_gpu_frequency_limits", description="List bounded per-tile/per-GT minimum and maximum frequency requests and driver-reported hardware bounds for Intel Xe DRM GPUs exposing the documented freq0 sysfs interface. Values are in MHz; unsupported drivers and missing attributes are omitted or reported as partial.")
    def tool_list_xe_gpu_frequency_limits(query: str = "", limit: int = 128) -> GPUFrequencyLimitListResponse:
        return _list_gpu_frequency_limits(query=query, limit=limit)

    @tool(name="manage_xe_gpu_frequency_limit", description="After exact client confirmation, set one Intel Xe GT max_freq request in MHz within the driver-reported hardware range and above its current min_freq. The exact GPU, tile, GT, current range, and sysfs identities are rebound to confirmation and verified after writing. Raising the ceiling can increase power and heat; lowering it can reduce performance. Uses current OS permissions without sudo or elevation.")
    async def tool_manage_xe_gpu_frequency_limit(
        drm_card: str,
        tile_id: int,
        gt_id: int,
        target_max_frequency_mhz: int,
        confirmation: Annotated[
            ElicitationResult[GPUFrequencyLimitConfirmation],
            Resolve(_confirm_gpu_frequency_limit),
        ],
    ) -> GPUFrequencyLimitActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_gpu_frequency_limit_action,
                drm_card,
                tile_id,
                gt_id,
                target_max_frequency_mhz,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_gpu_frequency_limit_action,
            drm_card,
            tile_id,
            gt_id,
            target_max_frequency_mhz,
            confirmed=True,
            confirmation_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="list_processes", description="List bounded Linux process metadata, optionally filtered by process name. Command-line arguments, environment, and working directories are excluded.")
    def tool_list_processes(query: str = "", limit: int = 50, sort_by: Literal["pid", "memory"] = "pid") -> ProcessListResponse:
        return _list_processes(query=query, limit=limit, sort_by=sort_by)

    @tool(name="get_process_detail", description="Read bounded metadata for one exact Linux PID and return an opaque process-instance token required by signal_process. Command-line arguments, environment, and working directory are excluded.")
    def tool_get_process_detail(pid: int) -> ProcessDetailResponse:
        return _get_process_detail(pid)

    @tool(name="get_process_execution_context", description="Read bounded scheduler, CPU/memory affinity, cgroup, namespace, seccomp, and effective-capability metadata for one exact Linux PID. When cgroup v2 is safely visible in the same cgroup namespace, also reads CPU, memory, swap, and PID limits/counters for its cgroup and ancestors. Checks process start time before and after collection; command lines, environments, and working directories are excluded.")
    def tool_get_process_execution_context(pid: int) -> ProcessExecutionContextResponse:
        return _get_process_execution_context(pid)

    @tool(name="list_namespace_inventory", description="Group namespace inode references by type across at most 5,000 stable process entries visible through procfs. Returns reference counts and one representative PID, without process names or command lines; the snapshot is non-atomic and may be incomplete under procfs visibility restrictions.")
    def tool_list_namespace_inventory() -> NamespaceInventoryResponse:
        return _list_namespace_inventory()

    @tool(name="get_process_tree", description="Read a bounded subtree rooted at one exact Linux PID, with process names, parent PIDs, depth, UID, state, threads, and memory. Command-line arguments, environments, and working directories are excluded.")
    def tool_get_process_tree(
        root_pid: int = 1,
        max_depth: int = 8,
        limit: int = 200,
    ) -> ProcessTreeResponse:
        return _get_process_tree(root_pid=root_pid, max_depth=max_depth, limit=limit)

    @tool(name="signal_process", description="After explicit confirmation naming the exact PID, process identity, and symbolic signal, send one Linux signal to the process instance identified by a fresh get_process_detail token. Uses current-user permissions and prefers pidfd signaling to avoid PID-reuse races.")
    async def tool_signal_process(
        pid: int,
        identity_token: str,
        signal_name: str,
        confirmation: Annotated[
            ElicitationResult[ProcessSignalConfirmation],
            Resolve(_confirm_process_signal),
        ],
    ) -> ProcessSignalResponse:
        if confirmation.action != "accept":
            return ProcessSignalResponse(
                success=False,
                pid=pid,
                signal_name=signal_name,
                user_confirmed=False,
                message=f"Process signal was {confirmation.action}; no signal was sent.",
            )
        if not confirmation.data.confirm:
            return ProcessSignalResponse(
                success=False,
                pid=pid,
                signal_name=signal_name,
                user_confirmed=False,
                message="Confirmation was not affirmative; no signal was sent.",
            )
        return _perform_process_signal(
            pid=pid,
            identity_token=identity_token,
            signal_name=signal_name,
            confirmed=True,
        )

    @tool(name="list_filesystems", description="List mounted filesystems and bounded capacity information. Device sources and mount options are omitted.")
    def tool_list_filesystems(query: str = "", limit: int = 100) -> FilesystemListResponse:
        return _list_filesystems(query=query, limit=limit)

    @tool(name="manage_mount", description="After explicit client confirmation, mount or unmount one exact existing directory listed as a unique valid /etc/fstab target. Uses the configured source/options and current mount namespace; it does not invoke sudo, polkit, or interactive elevation, while util-linux and fstab rules determine authorization. Helper programs from the configured filesystem type may run. Root, pseudo-filesystem, swap, symlinked, writable-path, and non-fstab targets are refused. Unmount is exact, nonrecursive, nonlazy, and refuses stacked mounts.")
    async def tool_manage_mount(
        action: MountActionName,
        mount_point: str,
        confirmation: Annotated[
            ElicitationResult[MountActionConfirmation],
            Resolve(_confirm_mount_action),
        ],
    ) -> MountActionResponse:
        if confirmation.action != "accept":
            return MountActionResponse(
                success=False,
                action=action,
                mount_point=mount_point,
                user_confirmed=False,
                message=f"Mount action was {confirmation.action}; no command was run.",
            )
        if not confirmation.data.confirm:
            return MountActionResponse(
                success=False,
                action=action,
                mount_point=mount_point,
                user_confirmed=False,
                message="Confirmation was not affirmative; no mount command was run.",
            )
        return await asyncio.to_thread(
            _perform_mount_action,
            action,
            mount_point,
            confirmed=True,
        )

    @tool(name="list_fstab_entries", description="Read bounded metadata from the fixed /etc/fstab file. Returns mount targets, filesystem types, source classifications, allowlisted option flags, and dump/fsck fields; exact source identifiers and arbitrary mount-option values are omitted. This tool is read-only and does not mount or modify filesystems.")
    def tool_list_fstab_entries(query: str = "", limit: int = 100) -> FstabEntryListResponse:
        return _list_fstab_entries(query=query, limit=limit)

    @tool(name="list_crypttab_entries", description="Read bounded metadata from the fixed /etc/crypttab file. Returns mapper names, device/key-source classifications, explicit encryption modes, selected flags, and token/keyscript-presence booleans; device identifiers, key paths, and arbitrary option values are omitted. It flags swap/tmp settings that format the mapped device during activation. This tool is read-only and does not unlock or modify encrypted devices.")
    def tool_list_crypttab_entries(query: str = "", limit: int = 100) -> CrypttabEntryListResponse:
        return _list_crypttab_entries(query=query, limit=limit)

    @tool(name="inspect_path", description="Read metadata for one explicit absolute path. Follows symlinks to the canonical target, omits file contents, and excludes paths under /proc, /sys, /dev, and /run.")
    def tool_inspect_path(path: str) -> PathMetadataResponse:
        return _inspect_path(path=path)

    @tool(name="list_path_extended_attributes", description="List bounded extended-attribute names and values for one explicit absolute path using current OS permissions. Decodes visible POSIX ACL xattrs, base64-encodes binary values, supports paging, and excludes paths under /proc, /sys, /dev, and /run. Values may contain arbitrary application metadata; this is read-only.")
    def tool_list_path_extended_attributes(
        path: str,
        offset: int = 0,
        limit: int = 64,
    ) -> PathExtendedAttributeResponse:
        return _list_path_extended_attributes(path=path, offset=offset, limit=limit)

    @tool(name="list_directory", description="List bounded metadata for entries in one explicit absolute directory. Set recursive=true to include descendants; recursive results use paths relative to the selected directory. Symlinks are reported without following them, and recursive scans stop at 5,000 entries or 128 levels. Paths under /proc, /sys, /dev, and /run are excluded.")
    def tool_list_directory(path: str, query: str = "", limit: int = 100, recursive: bool = False) -> DirectoryListResponse:
        return _list_directory(path=path, query=query, limit=limit, recursive=recursive)

    @tool(name="read_text_file", description="Read up to 64 KiB from one explicit absolute regular text file using current OS permissions. Follows symlinks to the canonical target, refuses binary files and paths under /proc, /sys, /dev, and /run; read-only.")
    def tool_read_text_file(path: str, max_bytes: int = 65536) -> TextFileReadResponse:
        return _read_text_file(path=path, max_bytes=max_bytes)

    @tool(name="read_binary_file", description="Read one bounded byte range from an explicit regular file and return strict base64 data. Pages up to 1 MiB with an offset, so binary and large files can be read in chunks. Reports the total size and SHA-256 of the returned page; refuses paths under /proc, /sys, /dev, and /run.")
    def tool_read_binary_file(path: str, offset: int = 0, max_bytes: int = 262144) -> BinaryFileReadResponse:
        return _read_binary_file(path=path, offset=offset, max_bytes=max_bytes)

    @tool(name="write_binary_file", description="After exact client confirmation, create, atomically replace, or append binary data at one exact regular-file path. Payloads are strict base64 and capped at 4 MiB per call; use append for larger files. Replacement preserves owner, mode, ACL, and visible xattrs, and refuses files with visible capability/IMA/EVM security attributes. Paths under /proc, /sys, /dev, and /run are excluded.")
    async def tool_write_binary_file(
        path: str,
        data_base64: str,
        action: Literal["create", "replace", "append"],
        confirmation: Annotated[
            ElicitationResult[BinaryFileWriteConfirmation],
            Resolve(_confirm_binary_file_write),
        ],
    ) -> BinaryFileWriteResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _write_binary_file,
                path,
                data_base64,
                action,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _write_binary_file,
            path,
            data_base64,
            action,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="begin_binary_file_upload", description="After exact client confirmation, begin one chunked binary create or replacement for files larger than 4 MiB and up to 64 GiB. Confirmation binds the canonical path, target identity, exact total size, and complete SHA-256. Checks currently available destination-filesystem space against active upload reservations, then creates a hidden mode-0600 staging file in the same directory; the destination remains unchanged until commit. The server reserves at most 128 GiB across active uploads. The upload token expires after one hour of inactivity and its staging file is removed within 30 seconds. Unexpected server exit can leave the hidden staging file behind.")
    async def tool_begin_binary_file_upload(
        path: str,
        action: Literal["create", "replace"],
        expected_size: Annotated[int, PydanticField(strict=True, gt=4_194_304, le=MAX_BINARY_UPLOAD_BYTES)],
        expected_sha256: Annotated[str, PydanticField(pattern=r"^[0-9a-f]{64}$")],
        confirmation: Annotated[
            ElicitationResult[BinaryFileUploadConfirmation],
            Resolve(_confirm_binary_file_upload),
        ],
    ) -> BinaryFileUploadResponse:
        if confirmation.action != "accept":
            return BinaryFileUploadResponse(
                success=False,
                state="failed",
                path=path,
                action=action,
                expected_size_bytes=expected_size,
                sha256=expected_sha256,
                user_confirmed=False,
                message=f"Binary-file upload was {confirmation.action}; no staging file was created.",
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _begin_binary_file_upload,
            path,
            action,
            expected_size,
            expected_sha256,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="append_binary_file_upload", description="Append one sequential base64 chunk of up to 4 MiB to a previously confirmed large binary-file upload. Requires its secret short-lived upload_id and the exact next offset. This writes only to the private staging file; it cannot publish the destination. The complete staged size and SHA-256 are rechecked at commit.")
    async def tool_append_binary_file_upload(
        upload_id: Annotated[str, PydanticField(min_length=40, max_length=60)],
        offset: Annotated[int, PydanticField(strict=True, ge=0, le=MAX_BINARY_UPLOAD_BYTES)],
        data_base64: Annotated[str, PydanticField(max_length=5_592_408)],
    ) -> BinaryFileUploadResponse:
        return await asyncio.to_thread(_append_binary_file_upload, upload_id, offset, data_base64)

    @tool(name="commit_binary_file_upload", description="Publish one previously confirmed large binary-file upload after verifying its exact byte count and complete SHA-256. A create uses an atomic no-overwrite link; a replacement uses atomic rename after rechecking the original target and preserving owner, mode, ACL, and visible xattrs. A concurrent external writer can race the final replacement interval. Commit consumes the upload token; the original target remains intact if validation fails before publication.")
    async def tool_commit_binary_file_upload(
        upload_id: Annotated[str, PydanticField(min_length=40, max_length=60)],
    ) -> BinaryFileUploadResponse:
        return await asyncio.to_thread(_commit_binary_file_upload, upload_id)

    @tool(name="abort_binary_file_upload", description="Discard one private staging file for a previously confirmed large binary-file upload. Requires its secret short-lived upload_id; the destination is not changed.")
    async def tool_abort_binary_file_upload(
        upload_id: Annotated[str, PydanticField(min_length=40, max_length=60)],
    ) -> BinaryFileUploadResponse:
        return await asyncio.to_thread(_abort_binary_file_upload, upload_id)

    @tool(name="delete_binary_file", description="After exact confirmation, unlink one regular file, including binary or large files. The prompt is bound to the canonical path, parent-directory identity, and file metadata; symlinks and paths under /proc, /sys, /dev, and /run are refused. This is not secure erasure, and other hard links, backups, or storage snapshots may retain data.")
    async def tool_delete_binary_file(
        path: str,
        confirmation: Annotated[
            ElicitationResult[PathAdminConfirmation],
            Resolve(_confirm_binary_file_delete),
        ],
    ) -> PathAdminResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _delete_binary_file,
                path,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _delete_binary_file,
            path,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_directory", description="After exact confirmation, create all missing directory components (with a selected rwx mode) or recursively delete one exact directory tree. Parent components are opened without following symlinks; deletion fingerprints and rechecks the tree, is capped at 20000 entries, never follows symlinks, and refuses protected system pseudo-filesystem paths.")
    async def tool_manage_directory(
        path: str,
        action: Literal["create_parents", "delete_recursive"],
        confirmation: Annotated[
            ElicitationResult[PathAdminConfirmation],
            Resolve(_confirm_directory_action),
        ],
        mode: str | None = None,
    ) -> PathAdminResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _manage_directory,
                path,
                action,
                mode,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _manage_directory,
            path,
            action,
            mode,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_directory_tree", description="After exact confirmation, recursively copy one directory tree to a new path or move it by same-filesystem rename. Copy is atomic and non-overwriting, capped at 20000 entries, 64 GiB of regular-file data, and 256 levels; it checks currently available destination bytes against logical source bytes and, when reported, free inodes against the entry count plus destination root during confirmation and again before staging; internal hard links reduce inode use, while filesystem allocation and concurrent writes can still cause a no-space failure. It preserves file/directory rwx modes, symbolic-link targets, modification times, and hard-link relationships within the copied tree. It does not preserve ownership, ACLs, xattrs, or access times. Special files and nested mount points are refused. Move preserves metadata, is limited to one filesystem, and refuses mounted trees. Paths under /proc, /sys, /dev, and /run are excluded.")
    async def tool_manage_directory_tree(
        action: Literal["copy", "move"],
        source_path: str,
        destination_path: str,
        confirmation: Annotated[
            ElicitationResult[PathAdminConfirmation],
            Resolve(_confirm_directory_tree_action),
        ],
    ) -> PathAdminResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _manage_directory_tree,
                action,
                source_path,
                destination_path,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _manage_directory_tree,
            action,
            source_path,
            destination_path,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_symlink", description="After exact confirmation, create or remove one symbolic link at an absolute path. Creation never replaces an existing directory entry; removal never follows the link. The link target is shown and bound as uninterpreted link text. Paths under /proc, /sys, /dev, and /run are excluded.")
    async def tool_manage_symlink(
        path: str,
        action: Literal["create", "remove"],
        confirmation: Annotated[
            ElicitationResult[PathAdminConfirmation],
            Resolve(_confirm_symlink_action),
        ],
        target: str = "",
    ) -> PathAdminResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _manage_symlink,
                path,
                action,
                target,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _manage_symlink,
            path,
            action,
            target,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="change_path_owner", description="After exact confirmation, change the numeric UID and/or GID of one regular file or directory, or set recursive=true to change a bounded directory tree. Nonrecursive mode refuses symlinks and special files; recursive mode changes symlink ownership without following links, refuses special files and mounted paths, requires the MCP server to already run as root, and is capped at 20,000 entries and 256 levels. A partial recursive failure leaves earlier changes in place. Chown may clear setuid/setgid bits, and multiply-linked files or symlinks affect aliases outside the tree.")
    async def tool_change_path_owner(
        path: str,
        confirmation: Annotated[
            ElicitationResult[PathAdminConfirmation],
            Resolve(_confirm_path_owner_change),
        ],
        owner_uid: int | None = None,
        owner_gid: int | None = None,
        recursive: bool = False,
    ) -> PathAdminResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _change_path_owner,
                path,
                owner_uid,
                owner_gid,
                recursive=recursive,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _change_path_owner,
            path,
            owner_uid,
            owner_gid,
            recursive=recursive,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_extended_attribute", description="After exact confirmation, set or remove one Linux extended attribute on one regular file or directory. Values are base64 and capped at 64 KiB. Namespaced attributes include user.*, trusted.*, security.*, and system.*; POSIX ACL attributes use manage_posix_acl instead. Security-sensitive attributes can affect access or execution policy. Paths under /proc, /sys, /dev, and /run are excluded.")
    async def tool_manage_extended_attribute(
        path: str,
        name: str,
        action: Literal["set", "remove"],
        confirmation: Annotated[
            ElicitationResult[PathAdminConfirmation],
            Resolve(_confirm_extended_attribute_action),
        ],
        value_base64: str = "",
    ) -> PathAdminResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _manage_extended_attribute,
                path,
                name,
                action,
                value_base64,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _manage_extended_attribute,
            path,
            name,
            action,
            value_base64,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_posix_acl", description="After exact confirmation, set or remove a POSIX access ACL on a regular file/directory or a default ACL on a directory. Entries use numeric UID/GID qualifiers and three-position rwx permissions. Named entries require a mask. ACL changes can grant or remove access for users and groups. Paths under /proc, /sys, /dev, and /run are excluded.")
    async def tool_manage_posix_acl(
        path: str,
        action: Literal["set", "remove"],
        acl_kind: Literal["access", "default"],
        confirmation: Annotated[
            ElicitationResult[PathAdminConfirmation],
            Resolve(_confirm_posix_acl_action),
        ],
        entries: list[ACLWriteEntry] | None = None,
    ) -> PathAdminResponse:
        normalized_entries = entries or []
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _manage_posix_acl,
                path,
                action,
                acl_kind,
                normalized_entries,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _manage_posix_acl,
            path,
            action,
            acl_kind,
            normalized_entries,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="create_text_file", description="After explicit client confirmation, create a new UTF-8 text file at one exact absolute path. Accepts at most 64 KiB, refuses existing targets and paths under /proc, /sys, /dev, or /run, creates with mode 0600, revalidates the destination and exact content digest, and uses current OS permissions without elevation. A partial file may remain if the filesystem fails during writing.")
    async def tool_create_text_file(
        path: str,
        content: str,
        confirmation: Annotated[
            ElicitationResult[TextFileCreationConfirmation],
            Resolve(_confirm_text_file_creation),
        ],
    ) -> TextFileCreationResponse:
        if confirmation.action != "accept":
            return (await asyncio.to_thread(
                _create_text_file,
                path,
                content,
                confirmed=False,
            )).model_copy(update={
                "message": f"File creation was {confirmation.action}; no file was created."
            })
        if not confirmation.data.confirm:
            return (await asyncio.to_thread(
                _create_text_file,
                path,
                content,
                confirmed=False,
            )).model_copy(update={"message": "Confirmation was not affirmative; no file was created."})
        return await asyncio.to_thread(
            _create_text_file,
            path,
            content,
            confirmed=True,
            confirmed_path=confirmation.data.path,
            confirmed_content_sha256=confirmation.data.content_sha256,
        )

    @tool(name="replace_text_file", description="After explicit client confirmation, replace the full UTF-8 content of one exact regular file up to 64 KiB. Refuses multiply linked, setuid/setgid, and files with visible security.capability/security.ima/security.evm attributes; binds confirmation to the canonical path and current/new content digests; writes in place to preserve owner, mode, ACL, and checked xattrs; verifies the result; and attempts to restore original content if writing fails. Modification/change times update. Uses current OS permissions without elevation; paths under /proc, /sys, /dev, and /run are excluded.")
    async def tool_replace_text_file(
        path: str,
        content: str,
        confirmation: Annotated[
            ElicitationResult[TextFileReplacementConfirmation],
            Resolve(_confirm_text_file_replacement),
        ],
    ) -> TextFileReplacementResponse:
        if confirmation.action != "accept":
            return (await asyncio.to_thread(
                _replace_text_file,
                path,
                content,
                confirmed=False,
            )).model_copy(update={
                "message": f"File replacement was {confirmation.action}; no content was changed."
            })
        if not confirmation.data.confirm:
            return (await asyncio.to_thread(
                _replace_text_file,
                path,
                content,
                confirmed=False,
            )).model_copy(update={"message": "Confirmation was not affirmative; no file content was changed."})
        return await asyncio.to_thread(
            _replace_text_file,
            path,
            content,
            confirmed=True,
            confirmed_path=confirmation.data.path,
            confirmed_current_sha256=confirmation.data.current_sha256,
            confirmed_replacement_sha256=confirmation.data.replacement_sha256,
        )

    @tool(name="delete_text_file", description="After explicit client confirmation, unlink one exact regular UTF-8 text-file path up to 64 KiB. This is not secure erasure and has no trash or recovery step. Refuses symlinks, directories, multiply linked files, setuid/setgid files, files with visible protected security attributes, binary files, and paths under /proc, /sys, /dev, or /run. Binds approval to canonical path and current content digest, revalidates identity/content, and uses current OS permissions without elevation. A concurrent path change in the final unlink window cannot be rolled back.")
    async def tool_delete_text_file(
        path: str,
        confirmation: Annotated[
            ElicitationResult[TextFileDeletionConfirmation],
            Resolve(_confirm_text_file_deletion),
        ],
    ) -> TextFileDeletionResponse:
        if confirmation.action != "accept":
            return (await asyncio.to_thread(
                _delete_text_file,
                path,
                confirmed=False,
            )).model_copy(update={
                "message": f"File deletion was {confirmation.action}; no file was deleted."
            })
        if not confirmation.data.confirm:
            return (await asyncio.to_thread(
                _delete_text_file,
                path,
                confirmed=False,
            )).model_copy(update={"message": "Confirmation was not affirmative; no file was deleted."})
        return await asyncio.to_thread(
            _delete_text_file,
            path,
            confirmed=True,
            confirmed_path=confirmation.data.path,
            confirmed_current_sha256=confirmation.data.current_sha256,
        )

    @tool(name="set_file_mode", description="After explicit client confirmation, set owner/group/other rwx bits and optional setuid, setgid, or sticky bits on one exact regular file or directory. Accepts three/four octal digits through 07777; uses four digits when setting special bits. Setuid/setgid files require an execute bit, the setuid bit and sticky bit are refused on directories and regular files respectively. Does not recurse; refuses symlinks, hard-linked regular files, visible protected security attributes, and paths under /proc, /sys, /dev, or /run. Binds approval to canonical path and full current/new modes, follows current OS permissions without elevation, and warns about execution identity, directory group inheritance, sticky-directory removal rules, and ACL effects.")
    async def tool_set_file_mode(
        path: str,
        mode: str,
        confirmation: Annotated[
            ElicitationResult[FileModeChangeConfirmation],
            Resolve(_confirm_file_mode_change),
        ],
    ) -> FileModeChangeResponse:
        if confirmation.action != "accept":
            return (await asyncio.to_thread(
                _set_file_mode,
                path,
                mode,
                confirmed=False,
            )).model_copy(update={
                "message": f"Permission-mode change was {confirmation.action}; no mode was changed."
            })
        if not confirmation.data.confirm:
            return (await asyncio.to_thread(
                _set_file_mode,
                path,
                mode,
                confirmed=False,
            )).model_copy(update={"message": "Confirmation was not affirmative; no permission mode was changed."})
        return await asyncio.to_thread(
            _set_file_mode,
            path,
            mode,
            confirmed=True,
            confirmed_path=confirmation.data.path,
            confirmed_current_mode_octal=confirmation.data.current_mode_octal,
            confirmed_new_mode_octal=confirmation.data.new_mode_octal,
        )

    @tool(name="list_network_interfaces", description="Read Linux interface state, primary IPv4/IPv6 addresses, default gateways, MTU, administrative state, and traffic counters. Returns a short-lived identity token for exact confirmation-gated link state, MTU, or address changes; link-layer hardware addresses are omitted.")
    def tool_list_network_interfaces(query: str = "", limit: int = 64) -> NetworkInterfaceListResponse:
        return _list_network_interfaces(query=query, limit=limit)

    @tool(name="list_radio_devices", description="List bounded Linux rfkill devices such as WLAN, Bluetooth, WWAN, NFC, UWB, GPS, and FM radios. Returns kernel index, driver name, radio type, soft/hard block state, and a short-lived identity token; serials and network addresses are excluded.")
    def tool_list_radio_devices(query: str = "", limit: int = 64) -> RadioDeviceListResponse:
        return _list_radio_devices(query=query, limit=limit)

    @tool(name="list_bluetooth_devices", description="List bounded Bluetooth devices already cached by the local BlueZ daemon, including their device addresses, reported names, and paired state. Does not start a discovery scan or connect to devices. Device names and addresses can identify nearby or previously used devices. Requires bluetoothctl and system D-Bus.")
    def tool_list_bluetooth_devices(query: str = "", limit: int = 64) -> BluetoothDeviceListResponse:
        return _list_bluetooth_devices(query=query, limit=limit)

    @tool(name="list_network_manager_profiles", description="List bounded NetworkManager connection-profile UUIDs, names, types, attached devices, and autoconnect state. Requests only those fields, never asks nmcli to show secrets, and performs no connection changes.")
    def tool_list_network_manager_profiles(query: str = "", limit: int = 100) -> NetworkManagerProfileListResponse:
        return _list_network_manager_profiles(query=query, limit=limit)

    @tool(name="get_network_manager_profile_dns", description="Read allowlisted saved IPv4/IPv6 DNS properties for one exact NetworkManager profile UUID returned by list_network_manager_profiles. Reports method, configured DNS servers, search/routing domains, DNS options, automatic-DNS flags, and priorities. Requests no secret fields and makes no changes; DNS servers and domains may reveal local network configuration.")
    def tool_get_network_manager_profile_dns(profile_uuid: str) -> NetworkManagerProfileDNSResponse:
        return _get_network_manager_profile_dns(profile_uuid=profile_uuid)

    @tool(name="get_network_manager_profile_ip", description="Read the saved IPv4 or IPv6 method, address/prefix list, and gateway for one exact NetworkManager profile UUID. Queries only these allowlisted properties and no secrets; runtime addresses may differ until NetworkManager applies the profile.")
    def tool_get_network_manager_profile_ip(
        profile_uuid: str,
        family: NetworkManagerIPFamily,
    ) -> NetworkManagerProfileIPResponse:
        return _get_network_manager_profile_ip(profile_uuid=profile_uuid, family=family)

    @tool(name="get_network_manager_profile_routes", description="Read saved IPv4 or IPv6 routes for one exact NetworkManager profile UUID. Reports destination, gateway, metric, and route attributes without requesting secrets or changing the profile.")
    def tool_get_network_manager_profile_routes(
        profile_uuid: str,
        family: NetworkManagerRouteFamily,
    ) -> NetworkManagerProfileRoutesResponse:
        return _get_network_manager_profile_routes(profile_uuid=profile_uuid, family=family)

    @tool(name="manage_network_manager_profile_route", description="After explicit client confirmation, add or remove one simple saved IPv4/IPv6 route on an exact NetworkManager profile UUID. Destination requires a prefix; gateway is optional and metric requires a gateway. Replacement, duplicate destinations, multipath changes, and removal of routes with advanced attributes are refused. The full saved route state is bound to confirmation and verified. It edits only the saved profile and does not activate or reapply it; current OS permissions apply without elevation.")
    async def tool_manage_network_manager_profile_route(
        profile_uuid: str,
        family: NetworkManagerRouteFamily,
        action: NetworkManagerRouteAction,
        destination: str,
        confirmation: Annotated[
            ElicitationResult[NetworkManagerProfileRouteActionConfirmation],
            Resolve(_confirm_network_manager_profile_route_action),
        ],
        gateway: str | None = None,
        metric: int | None = None,
    ) -> NetworkManagerProfileRouteActionResponse:
        arguments = (profile_uuid, family, action, destination, gateway, metric)
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_network_manager_profile_route_action,
                *arguments,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_network_manager_profile_route_action,
            *arguments,
            confirmed=True,
            confirmed_profile_uuid=confirmation.data.profile_uuid,
            confirmed_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="configure_network_manager_profile_dns", description="After explicit client confirmation, update selected saved IPv4/IPv6 DNS server lists, search domains, and automatic-DNS flags on one exact NetworkManager profile UUID. Empty lists clear that saved list; omitted fields are preserved. Addresses/domains are strictly validated, the full selected DNS state is bound to confirmation and revalidated, and no secret fields are requested. This updates the saved profile only; it does not activate or reapply it. Uses current OS permissions without elevation and may change name resolution when NetworkManager next applies the profile.")
    async def tool_configure_network_manager_profile_dns(
        profile_uuid: str,
        confirmation: Annotated[
            ElicitationResult[NetworkManagerProfileDNSConfigConfirmation],
            Resolve(_confirm_network_manager_profile_dns_configuration),
        ],
        ipv4_dns_servers: list[str] | None = None,
        ipv4_search_domains: list[str] | None = None,
        ipv4_ignore_auto_dns: bool | None = None,
        ipv6_dns_servers: list[str] | None = None,
        ipv6_search_domains: list[str] | None = None,
        ipv6_ignore_auto_dns: bool | None = None,
    ) -> NetworkManagerProfileDNSConfigResponse:
        arguments = (
            profile_uuid,
            ipv4_dns_servers,
            ipv4_search_domains,
            ipv4_ignore_auto_dns,
            ipv6_dns_servers,
            ipv6_search_domains,
            ipv6_ignore_auto_dns,
        )
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_network_manager_profile_dns_configuration,
                *arguments,
                confirmed=False,
            )
        if not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_network_manager_profile_dns_configuration,
                *arguments,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_network_manager_profile_dns_configuration,
            *arguments,
            confirmed=True,
            confirmed_profile_uuid=confirmation.data.profile_uuid,
            confirmed_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="configure_network_manager_profile_ip", description="After explicit client confirmation, set one saved NetworkManager IPv4/IPv6 family to automatic or manual mode. Manual mode requires literal address/prefix values and accepts an optional same-family gateway; automatic mode clears saved static addresses and gateway. The exact selected profile IP state is bound to confirmation and verified after the update. It changes only the saved profile and does not run activation or reapply; current OS permissions apply without elevation.")
    async def tool_configure_network_manager_profile_ip(
        profile_uuid: str,
        family: NetworkManagerIPFamily,
        method: NetworkManagerIPMethod,
        confirmation: Annotated[
            ElicitationResult[NetworkManagerProfileIPConfigConfirmation],
            Resolve(_confirm_network_manager_profile_ip_configuration),
        ],
        addresses: list[str] | None = None,
        gateway: str | None = None,
    ) -> NetworkManagerProfileIPConfigResponse:
        arguments = (profile_uuid, family, method, addresses, gateway)
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_network_manager_profile_ip_configuration,
                *arguments,
                confirmed=False,
            )
        if not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_network_manager_profile_ip_configuration,
                *arguments,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_network_manager_profile_ip_configuration,
            *arguments,
            confirmed=True,
            confirmed_profile_uuid=confirmation.data.profile_uuid,
            confirmed_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="create_network_manager_virtual_profile", description="After exact client confirmation, create one persistent, inactive NetworkManager bridge, bond, or VLAN profile. Bridge/bond interfaces must be unused; VLANs require an existing parent and ID 1-4094. Bond mode is selected from a fixed allowlist. The saved profile has autoconnect off and IPv4/IPv6 disabled; bridge/bond port profiles are not attached. The complete profile inventory and interface identity are bound to confirmation and revalidated. The tool does not activate the profile or request privilege elevation; later activation can change network traffic.")
    async def tool_create_network_manager_virtual_profile(
        kind: NetworkManagerVirtualProfileKind,
        profile_name: str,
        interface_name: str,
        confirmation: Annotated[
            ElicitationResult[NetworkManagerVirtualProfileCreateConfirmation],
            Resolve(_confirm_network_manager_virtual_profile_creation),
        ],
        parent_interface: str | None = None,
        vlan_id: int | None = None,
        bond_mode: NetworkManagerBondMode | None = None,
    ) -> NetworkManagerVirtualProfileCreateResponse:
        arguments = (kind, profile_name, interface_name, parent_interface, vlan_id, bond_mode)
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_network_manager_virtual_profile_creation,
                *arguments,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_network_manager_virtual_profile_creation,
            *arguments,
            confirmed=True,
            confirmed_kind=confirmation.data.kind,
            confirmed_profile_name=confirmation.data.profile_name,
            confirmed_interface_name=confirmation.data.interface_name,
            confirmed_parent_interface=confirmation.data.parent_interface,
            confirmed_vlan_id=confirmation.data.vlan_id,
            confirmed_bond_mode=confirmation.data.bond_mode,
            confirmed_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="create_network_manager_port_profile", description="After exact client confirmation, create one persistent inactive Ethernet port profile attached to an exact saved NetworkManager bridge or bond UUID. The named interface must be a currently NetworkManager-managed Ethernet device. Autoconnect is disabled and the live interface is not switched. NetworkManager does not store IPv4/IPv6 settings on an attached port profile; the bridge/bond controller supplies IP configuration. Full profile, controller, and device identity are bound to confirmation and revalidated. Later activation can interrupt traffic; the tool uses current OS permissions without elevation.")
    async def tool_create_network_manager_port_profile(
        controller_uuid: str,
        profile_name: str,
        interface_name: str,
        confirmation: Annotated[
            ElicitationResult[NetworkManagerPortProfileCreateConfirmation],
            Resolve(_confirm_network_manager_port_profile_creation),
        ],
    ) -> NetworkManagerPortProfileCreateResponse:
        arguments = (controller_uuid, profile_name, interface_name)
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_network_manager_port_profile_creation,
                *arguments,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_network_manager_port_profile_creation,
            *arguments,
            confirmed=True,
            confirmed_controller_uuid=confirmation.data.controller_uuid,
            confirmed_profile_name=confirmation.data.profile_name,
            confirmed_interface_name=confirmation.data.interface_name,
            confirmed_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="manage_network_manager_port_membership", description="After exact client confirmation, attach or detach one exact pinned NetworkManager Ethernet profile to one saved bridge or bond UUID. Attaching is allowed only when the saved IPv4/IPv6 methods are automatic and there are no saved addresses, gateways, DNS overrides, or static routes. NetworkManager omits per-port IP settings while attached; the bridge/bond controller supplies IP configuration. Detaching leaves automatic IP methods and empty saved address/DNS/route lists. Autoconnect is preserved. Binds the complete profile inventory, IP settings, membership fields, and interface identity to confirmation and revalidates them. It does not activate, deactivate, or reapply either profile; a later activation/reapply may change traffic. Uses current OS permissions without elevation.")
    async def tool_manage_network_manager_port_membership(
        action: Literal["add", "remove"],
        profile_uuid: str,
        controller_uuid: str,
        confirmation: Annotated[
            ElicitationResult[NetworkManagerPortMembershipConfirmation],
            Resolve(_confirm_network_manager_port_membership),
        ],
    ) -> NetworkManagerPortMembershipResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_network_manager_port_membership_action,
                action,
                profile_uuid,
                controller_uuid,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_network_manager_port_membership_action,
            action,
            profile_uuid,
            controller_uuid,
            confirmed=True,
            confirmed_action=confirmation.data.action,
            confirmed_profile_uuid=confirmation.data.profile_uuid,
            confirmed_controller_uuid=confirmation.data.controller_uuid,
            confirmed_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="import_network_manager_vpn_profile", description="After exact confirmation, import one self-contained OpenVPN or WireGuard config into a persistent NetworkManager profile. OpenVPN inline credential blocks are supported while known external file, include, management-socket, and helper-command directives are refused. WireGuard accepts a bounded wg-quick Interface/Peer subset and rejects shell hooks, file-based keys, and unsupported settings; each DNS address family must also have an Interface Address. The source must be a readable regular file no larger than 1 MiB; its complete content and the full profile inventory are bound to confirmation and revalidated. OpenVPN is staged in a private temporary copy; WireGuard is added through one NetworkManager D-Bus call with autoconnect disabled at creation. The tool hides command output, never queries profile secrets, verifies one inactive profile, and does not activate the VPN or request privilege elevation. Inline certificates, private keys, or passwords may be saved by NetworkManager; later activation can change routes or disconnect this MCP client.")
    async def tool_import_network_manager_vpn_profile(
        vpn_type: NetworkManagerVPNType,
        source_path: str,
        profile_name: str,
        confirmation: Annotated[
            ElicitationResult[NetworkManagerVPNImportConfirmation],
            Resolve(_confirm_network_manager_vpn_import),
        ],
    ) -> NetworkManagerVPNImportResponse:
        arguments = (vpn_type, source_path, profile_name)
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_network_manager_vpn_import,
                *arguments,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_network_manager_vpn_import,
            *arguments,
            confirmed=True,
            confirmed_vpn_type=confirmation.data.vpn_type,
            confirmed_source_path=confirmation.data.source_path,
            confirmed_profile_name=confirmation.data.profile_name,
            confirmed_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="manage_network_manager_profile", description="After explicit client confirmation, activate or deactivate one exact NetworkManager connection profile by UUID, or enable/disable only that profile's persistent connection.autoconnect setting. The tool requests no secret fields, revalidates profile identity/state, and uses current OS permissions without elevation. Activation/deactivation can interrupt this MCP client; deactivation blocks that profile from autoconnecting again until reboot or a later user action. Autoconnect changes persist in the profile across reboot; NetworkManager does not implement autoconnect for VPN profiles.")
    async def tool_manage_network_manager_profile(
        action: NetworkManagerProfileAction,
        profile_uuid: str,
        confirmation: Annotated[
            ElicitationResult[NetworkManagerProfileActionConfirmation],
            Resolve(_confirm_network_manager_profile_action),
        ],
    ) -> NetworkManagerProfileActionResponse:
        if confirmation.action != "accept":
            return (await asyncio.to_thread(
                _perform_network_manager_profile_action,
                action,
                profile_uuid,
                confirmed=False,
            )).model_copy(update={
                "message": f"NetworkManager profile action was {confirmation.action}; no change was run."
            })
        if not confirmation.data.confirm:
            return (await asyncio.to_thread(
                _perform_network_manager_profile_action,
                action,
                profile_uuid,
                confirmed=False,
            )).model_copy(update={"message": "Confirmation was not affirmative; no profile change was run."})
        return await asyncio.to_thread(
            _perform_network_manager_profile_action,
            action,
            profile_uuid,
            confirmed=True,
            confirmed_profile_uuid=confirmation.data.profile_uuid,
        )

    @tool(name="list_systemd_network_profiles", description="List bounded systemd .network, .netdev, and .link profile candidates with selected allowlisted metadata from fixed system network directories. .network candidates include configured DNS servers/domains, DNSDefaultRoute, selected UseDNS/UseDNR flags, and UseDomains modes. Secret keys, interface addresses, MAC addresses, comments, raw config text, and config writes are excluded; files/drop-ins remain separate and are not merged into an effective configuration.")
    def tool_list_systemd_network_profiles(query: str = "", limit: int = 100) -> SystemdNetworkProfileListResponse:
        return _list_systemd_network_profiles(query=query, limit=limit)

    @tool(name="configure_systemd_network_profile", description="After explicit client confirmation, update selected settings in one exact existing /etc/systemd/network .network file whose [Match] section names exactly one literal interface; use the separate confirmed create and delete tools for whole-file operations. Supports DHCP, literal static address/prefix values, gateway, DNS servers/domains, DNS default-route behavior, and bridge/bond/VLAN membership. Address and gateway updates edit [Network] directives only and refuse separate [Address]/[Route] sections when the referenced .netdev definition is unambiguous. Empty address/DNS/domain/VLAN lists clear those settings; clear flags remove gateway or bridge/bond membership. Drop-ins, ambiguous precedence, unsupported syntax, and create/delete operations are refused. The full bounded networkd profile state and exact file contents are bound to confirmation and rechecked before replacement. It does not run networkctl reload or reconfigure; saved settings may change routes, DNS, or connectivity when applied later. Current OS permissions apply; no privilege elevation is requested.")
    async def tool_configure_systemd_network_profile(
        filename: str,
        interface: str,
        confirmation: Annotated[
            ElicitationResult[SystemdNetworkProfileConfigConfirmation],
            Resolve(_confirm_systemd_network_profile_configuration),
        ],
        dhcp: Literal["yes", "no", "ipv4", "ipv6"] | None = None,
        addresses: list[str] | None = None,
        gateway: str | None = None,
        clear_gateway: bool = False,
        dns_servers: list[str] | None = None,
        domains: list[str] | None = None,
        dns_default_route: bool | None = None,
        bridge: str | None = None,
        clear_bridge_membership: bool = False,
        bond: str | None = None,
        clear_bond_membership: bool = False,
        vlans: list[str] | None = None,
    ) -> SystemdNetworkProfileConfigResponse:
        arguments = (
            filename,
            interface,
            dhcp,
            addresses,
            gateway,
            clear_gateway,
            dns_servers,
            domains,
            dns_default_route,
            bridge,
            clear_bridge_membership,
            bond,
            clear_bond_membership,
            vlans,
        )
        accepted = confirmation.action == "accept" and confirmation.data.confirm
        return await asyncio.to_thread(
            _configure_systemd_network_profile,
            *arguments,
            confirmed=accepted,
            confirmed_filename=confirmation.data.filename if accepted else None,
            confirmed_interface=confirmation.data.interface if accepted else None,
            state_token=confirmation.data.state_token if accepted else None,
        )

    @tool(name="create_systemd_network_profile", description="After explicit client confirmation, create one exact persistent /etc/systemd/network .network profile with a literal interface match and explicit DHCP mode. Supports typed address/prefix, gateway, DNS/domain, DNS default-route, and existing bridge/bond/VLAN .netdev references. Refuses filename collisions, drop-ins for the target, ambiguous earlier matching files, unsupported settings, and clear-only operations. Creation requires the MCP server to already run as root; content is bound to confirmation and the full bounded networkd state is rechecked before and after the mode-0600 create. It does not run networkctl reload or reconfigure; a later reload or service restart can change routes, DNS, or connectivity. No privilege elevation is requested.")
    async def tool_create_systemd_network_profile(
        filename: str,
        interface: str,
        dhcp: Literal["yes", "no", "ipv4", "ipv6"],
        confirmation: Annotated[
            ElicitationResult[SystemdNetworkProfileCreateConfirmation],
            Resolve(_confirm_systemd_network_profile_creation),
        ],
        addresses: list[str] | None = None,
        gateway: str | None = None,
        dns_servers: list[str] | None = None,
        domains: list[str] | None = None,
        dns_default_route: bool | None = None,
        bridge: str | None = None,
        bond: str | None = None,
        vlans: list[str] | None = None,
    ) -> SystemdNetworkProfileCreateResponse:
        accepted = confirmation.action == "accept" and confirmation.data.confirm
        return await asyncio.to_thread(
            _create_systemd_network_profile,
            filename,
            interface,
            dhcp,
            addresses,
            gateway,
            dns_servers,
            domains,
            dns_default_route,
            bridge,
            bond,
            vlans,
            confirmed=accepted,
            confirmed_filename=confirmation.data.filename if accepted else None,
            confirmed_interface=confirmation.data.interface if accepted else None,
            state_token=confirmation.data.state_token if accepted else None,
        )

    @tool(name="create_systemd_netdev_profile", description="After explicit client confirmation, create one exact persistent /etc/systemd/network .netdev profile for a bridge, bond, or VLAN interface. Supports bridge STP/VLAN filtering, one explicit Linux bond mode, or one VLAN ID from 1 through 4094. Refuses filename/name collisions, existing live interfaces, incompatible settings, and unsafe or ambiguous networkd inventories. Creation requires the MCP server to already run as root; the generated mode-0600 file is bound to confirmation and the full bounded networkd state is rechecked before and after writing. It does not run networkctl reload or reconfigure; a later reload or restart can create the interface and change connectivity. No privilege elevation is requested.")
    async def tool_create_systemd_netdev_profile(
        filename: str,
        name: str,
        kind: SystemdNetDevKind,
        confirmation: Annotated[
            ElicitationResult[SystemdNetDevCreateConfirmation],
            Resolve(_confirm_systemd_netdev_creation),
        ],
        bridge_stp: bool | None = None,
        vlan_filtering: bool | None = None,
        bond_mode: SystemdBondMode | None = None,
        vlan_id: StrictInt | None = None,
    ) -> SystemdNetDevCreateResponse:
        accepted = confirmation.action == "accept" and confirmation.data.confirm
        return await asyncio.to_thread(
            _create_systemd_netdev_profile,
            filename,
            name,
            kind,
            bridge_stp,
            vlan_filtering,
            bond_mode,
            vlan_id,
            confirmed=accepted,
            confirmed_filename=confirmation.data.filename if accepted else None,
            confirmed_name=confirmation.data.name if accepted else None,
            confirmed_kind=confirmation.data.kind if accepted else None,
            state_token=confirmation.data.state_token if accepted else None,
        )

    @tool(name="configure_systemd_netdev_profile", description="After exact client confirmation, update bridge STP/VLAN filtering, a Linux bond mode, or one VLAN ID in one exact existing systemd-networkd .netdev file. Preserves other file content, requires the target to be a unique root-owned regular file with no drop-ins or same-named fallback, and binds confirmation to the full bounded networkd state and exact file identity/content. No networkd reload or reconfigure is requested; a later reload or restart can change interface behavior or connectivity. Uses current OS permissions without elevation.")
    async def tool_configure_systemd_netdev_profile(
        filename: str,
        name: str,
        kind: SystemdNetDevKind,
        confirmation: Annotated[
            ElicitationResult[SystemdNetDevConfigConfirmation],
            Resolve(_confirm_systemd_netdev_configuration),
        ],
        bridge_stp: bool | None = None,
        vlan_filtering: bool | None = None,
        bond_mode: SystemdBondMode | None = None,
        vlan_id: StrictInt | None = None,
    ) -> SystemdNetDevConfigResponse:
        accepted = confirmation.action == "accept" and confirmation.data.confirm
        return await asyncio.to_thread(
            _configure_systemd_netdev_profile,
            filename,
            name,
            kind,
            bridge_stp,
            vlan_filtering,
            bond_mode,
            vlan_id,
            confirmed=accepted,
            confirmed_filename=confirmation.data.filename if accepted else None,
            confirmed_name=confirmation.data.name if accepted else None,
            confirmed_kind=confirmation.data.kind if accepted else None,
            state_token=confirmation.data.state_token if accepted else None,
        )

    @tool(name="delete_systemd_netdev_profile", description="After exact client confirmation, unlink one exact inactive root-owned /etc/systemd/network .netdev definition for a bridge, bond, or VLAN. Refuses live interfaces, detected .network matches/references, drop-ins, same-named fallback definitions, and ambiguous networkd state. The full bounded configuration, exact file identity, and content are rechecked; deletion is not secure erasure and has no recovery step. No reload or reconfigure is requested. Uses current OS permissions without elevation.")
    async def tool_delete_systemd_netdev_profile(
        filename: str,
        name: str,
        kind: SystemdNetDevKind,
        confirmation: Annotated[
            ElicitationResult[SystemdNetDevDeleteConfirmation],
            Resolve(_confirm_systemd_netdev_deletion),
        ],
    ) -> SystemdNetDevDeleteResponse:
        accepted = confirmation.action == "accept" and confirmation.data.confirm
        return await asyncio.to_thread(
            _delete_systemd_netdev_profile,
            filename,
            name,
            kind,
            confirmed=accepted,
            confirmed_filename=confirmation.data.filename if accepted else None,
            confirmed_name=confirmation.data.name if accepted else None,
            confirmed_kind=confirmation.data.kind if accepted else None,
            state_token=confirmation.data.state_token if accepted else None,
        )

    @tool(name="delete_systemd_network_profile", description="After exact client confirmation, unlink one exact existing root-owned /etc/systemd/network .network file matching one literal interface. This is not secure erasure and has no recovery step. Refuses drop-ins, ambiguous precedence, and same-named fallback profiles. Binds confirmation to the complete bounded networkd state, file identity, and content digest, then verifies deletion. It does not reload or reconfigure networkd; a later reload or restart may select another profile or leave the interface unmatched. Uses current OS permissions without elevation.")
    async def tool_delete_systemd_network_profile(
        filename: str,
        interface: str,
        confirmation: Annotated[
            ElicitationResult[SystemdNetworkProfileDeleteConfirmation],
            Resolve(_confirm_systemd_network_profile_deletion),
        ],
    ) -> SystemdNetworkProfileDeleteResponse:
        accepted = confirmation.action == "accept" and confirmation.data.confirm
        return await asyncio.to_thread(
            _delete_systemd_network_profile,
            filename,
            interface,
            confirmed=accepted,
            confirmed_filename=confirmation.data.filename if accepted else None,
            confirmed_interface=confirmation.data.interface if accepted else None,
            state_token=confirmation.data.state_token if accepted else None,
        )

    @tool(name="manage_network_interface", description="After explicit client confirmation, set one listed interface administratively up/down or change its MTU in the current network namespace. Requires the fresh identity_token from list_network_interfaces and revalidates interface name, index, link identity, MTU, and state. Pass mtu as null for set_up/set_down and an integer from 68 through 65535 for set_mtu. Taking a link down may disconnect this MCP client; changes are not persisted across reboot and use current OS permissions without elevation.")
    async def tool_manage_network_interface(
        action: NetworkInterfaceAction,
        identity_token: str,
        mtu: int | None,
        confirmation: Annotated[
            ElicitationResult[NetworkInterfaceActionConfirmation],
            Resolve(_confirm_network_interface_action),
        ],
    ) -> NetworkInterfaceActionResponse:
        if confirmation.action != "accept":
            return _perform_interface_action(
                action=action,
                identity_token=identity_token,
                mtu=mtu,
                confirmed=False,
            ).model_copy(update={"message": f"Network interface action was {confirmation.action}; no change was run."})
        if not confirmation.data.confirm:
            return _perform_interface_action(
                action=action,
                identity_token=identity_token,
                mtu=mtu,
                confirmed=False,
            ).model_copy(update={"message": "Confirmation was not affirmative; no network change was run."})
        return _perform_interface_action(
            action=action,
            identity_token=identity_token,
            mtu=mtu,
            confirmed=True,
        )

    @tool(name="manage_radio_device", description="After explicit client confirmation, soft-block or unblock one exact rfkill device returned by list_radio_devices. Requires a fresh identity token, revalidates device index/name/type and block state, and uses only the local rfkill command. A hard block cannot be overridden; blocking may disconnect wireless services and this MCP client. Uses current OS permissions without elevation.")
    async def tool_manage_radio_device(
        action: RadioDeviceActionName,
        identity_token: str,
        confirmation: Annotated[
            ElicitationResult[RadioDeviceActionConfirmation],
            Resolve(_confirm_radio_device_action),
        ],
    ) -> RadioDeviceActionResponse:
        if confirmation.action != "accept":
            return (await asyncio.to_thread(
                _perform_radio_device_action,
                action,
                identity_token,
                "",
                -1,
                "",
                "",
                confirmed=False,
            )).model_copy(update={
                "message": f"Radio-device action was {confirmation.action}; no radio command was run."
            })
        data = confirmation.data
        if not data.confirm:
            return (await asyncio.to_thread(
                _perform_radio_device_action,
                action,
                identity_token,
                "",
                data.radio_index,
                data.name,
                data.radio_type,
                confirmed=False,
            )).model_copy(update={"message": "Confirmation was not affirmative; no radio command was run."})
        return await asyncio.to_thread(
            _perform_radio_device_action,
            action,
            identity_token,
            data.expected_state_token,
            data.radio_index,
            data.name,
            data.radio_type,
            confirmed=True,
        )

    @tool(name="manage_bluetooth_pairing", description="After explicit client confirmation, pair one exact unpaired device already known to BlueZ. Uses bluetoothctl with a short-lived device token and rechecks its address, name, paired/trusted/connected state before acting and its paired state afterward. BlueZ pairing initiates a Bluetooth connection and may prompt through the system agent; bluetoothctl may mark the device trusted depending on BlueZ version. Does not scan or change controller power. Uses the current account and BlueZ policy without sudo; timeout is bounded to 90 seconds.")
    async def tool_manage_bluetooth_pairing(
        identity_token: str,
        confirmation: Annotated[
            ElicitationResult[BluetoothPairingConfirmation],
            Resolve(_confirm_bluetooth_pairing),
        ],
    ) -> BluetoothPairingResponse:
        if confirmation.action != "accept":
            return (await asyncio.to_thread(
                _perform_bluetooth_pairing,
                identity_token,
                "",
                "",
                "",
                confirmed=False,
            )).model_copy(update={
                "message": f"Bluetooth pairing was {confirmation.action}; no pairing command was run."
            })
        data = confirmation.data
        if not data.confirm:
            return (await asyncio.to_thread(
                _perform_bluetooth_pairing,
                identity_token,
                "",
                data.address,
                data.name,
                confirmed=False,
            )).model_copy(update={"message": "Confirmation was not affirmative; no Bluetooth pairing command was run."})
        return await asyncio.to_thread(
            _perform_bluetooth_pairing,
            identity_token,
            data.state_token,
            data.address,
            data.name,
            confirmed=True,
        )

    @tool(name="manage_network_address", description="After explicit client confirmation, add or remove one exact IPv4/IPv6 CIDR address on a listed interface in the current network namespace. Use list_network_addresses to identify current addresses; requires the fresh identity_token from list_network_interfaces and an explicit CIDR address. Rechecks interface identity and address state, then verifies the result. Address changes are temporary; removing an address can disconnect traffic, and a network manager may restore it. Uses current OS permissions without elevation.")
    async def tool_manage_network_address(
        action: NetworkAddressAction,
        identity_token: str,
        address: str,
        confirmation: Annotated[
            ElicitationResult[NetworkAddressActionConfirmation],
            Resolve(_confirm_network_address_action),
        ],
    ) -> NetworkAddressActionResponse:
        if confirmation.action != "accept":
            return _perform_address_action(
                action=action,
                identity_token=identity_token,
                address=address,
                confirmed=False,
            ).model_copy(update={"message": f"Network address action was {confirmation.action}; no change was run."})
        if not confirmation.data.confirm:
            return _perform_address_action(
                action=action,
                identity_token=identity_token,
                address=address,
                confirmed=False,
            ).model_copy(update={"message": "Confirmation was not affirmative; no address change was run."})
        return _perform_address_action(
            action=action,
            identity_token=identity_token,
            address=address,
            confirmed=True,
        )

    @tool(name="list_network_addresses", description="List bounded IPv4/IPv6 addresses for all interfaces, including secondary addresses, address scopes, labels, flags, and preferred/valid lifetimes. Uses the optional iproute2 command and does not change network state.")
    def tool_list_network_addresses(query: str = "", limit: int = 256) -> NetworkAddressListResponse:
        return _list_network_addresses(query=query, limit=limit)

    @tool(name="get_dns_configuration", description="Read bounded DNS configuration from /etc/resolv.conf and, when installed, resolvectl global and per-link status. The resolver file may point to a local stub; systemd-resolved status reports upstream servers separately. Nameservers and search domains reveal local network configuration. Read-only; no DNS queries are sent.")
    def tool_get_dns_configuration() -> DNSConfigurationResponse:
        return _get_dns_configuration()

    @tool(name="list_network_sockets", description="List bounded TCP/UDP IPv4/IPv6 sockets from the current network namespace, including kernel-visible UID and inode fields where available. Use list_socket_owners with returned inodes to resolve visible processes; UNIX/raw sockets use a separate inventory.")
    def tool_list_network_sockets(query: str = "", limit: int = 100) -> NetworkSocketListResponse:
        return _list_network_sockets(query=query, limit=limit)

    @tool(name="list_unix_raw_sockets", description="List bounded UNIX-domain sockets, including filesystem/abstract paths and type/state, plus IPv4/IPv6 raw sockets and visible UID/inode metadata. Use list_socket_owners with returned inodes to resolve visible processes.")
    def tool_list_unix_raw_sockets(query: str = "", limit: int = 100) -> UnixRawSocketResponse:
        return _list_unix_raw_sockets(query=query, limit=limit)

    @tool(name="list_socket_owners", description="Resolve up to 128 explicitly supplied socket inodes to visible PID/name/UID records by bounded /proc/PID/fd scanning. Results depend on procfs visibility and never read process arguments, environments, or working directories.")
    def tool_list_socket_owners(inodes: list[int], limit: int = 100) -> SocketOwnerListResponse:
        return _list_socket_owners(inodes=inodes, limit=limit)

    @tool(name="list_network_protocol_stats", description="List bounded cumulative protocol counters from current-namespace /proc/net/snmp, netstat, and snmp6 tables. Reports snapshots rather than rates; no packet capture or network configuration is performed.")
    def tool_list_network_protocol_stats(query: str = "", limit: int = 64) -> NetworkProtocolStatsResponse:
        return _list_network_protocol_stats(query=query, limit=limit)

    @tool(name="list_network_routes", description="List bounded IPv4/IPv6 kernel route entries from procfs for the current network namespace. Does not change routes; policy rules and destination-specific route selection are available through separate tools.")
    def tool_list_network_routes(query: str = "", limit: int = 100) -> NetworkRouteListResponse:
        return _list_network_routes(query=query, limit=limit)

    @tool(name="lookup_network_route", description="Look up the kernel-selected route for one literal IPv4 or IPv6 destination in the current network namespace. Uses a bounded read-only iproute2 JSON query, sends no packets, and reports selection for locally originated traffic in iproute2's default lookup context; it does not model an incoming interface, firewall mark, protocol, or port.")
    def tool_lookup_network_route(destination: str) -> NetworkRouteLookupResponse:
        return _lookup_network_route(destination=destination)

    @tool(name="list_network_policy", description="Read bounded IPv4/IPv6 routing-policy rules and routes from all routing tables in the current network namespace using fixed read-only iproute2 JSON queries.")
    def tool_list_network_policy(
        family: Literal["all", "ipv4", "ipv6"] = "all",
        limit: int = 200,
    ) -> NetworkPolicySnapshotResponse:
        return _list_network_policy(family=family, limit=limit)

    @tool(name="manage_network_route", description="After explicit client confirmation, add or remove one exact transient IPv4/IPv6 unicast static route in the current network namespace. Supply a canonical destination CIDR, an IP gateway or an empty string for a direct route, exact interface name, numeric table ID, and metric. IPv6 actions use medium route preference. Add refuses to replace an existing route; remove matches only one exact static (protocol 4) route and does not remove kernel or dynamically installed routes. Default-route changes may redirect traffic or disconnect this MCP client. Uses current OS permissions without elevation, verifies the resulting route, and does not persist configuration.")
    async def tool_manage_network_route(
        action: NetworkRouteAction,
        destination: str,
        gateway: str,
        interface: str,
        table: int,
        metric: int,
        confirmation: Annotated[
            ElicitationResult[NetworkRouteActionConfirmation],
            Resolve(_confirm_network_route_action),
        ],
    ) -> NetworkRouteActionResponse:
        if confirmation.action != "accept":
            return (await asyncio.to_thread(
                _perform_route_action,
                action,
                destination,
                gateway,
                interface,
                table,
                metric,
                confirmed=False,
            )).model_copy(update={
                "message": f"Network route action was {confirmation.action}; no change was run."
            })
        if not confirmation.data.confirm:
            return (await asyncio.to_thread(
                _perform_route_action,
                action,
                destination,
                gateway,
                interface,
                table,
                metric,
                confirmed=False,
            )).model_copy(update={"message": "Confirmation was not affirmative; no route change was run."})
        return await asyncio.to_thread(
            _perform_route_action,
            action,
            destination,
            gateway,
            interface,
            table,
            metric,
            confirmed=True,
            expected_interface_index=confirmation.data.interface_index,
        )

    @tool(name="list_firewall_rules", description="List bounded active nftables and IPv4/IPv6 iptables ruleset entries visible in the current network namespace. Uses optional read-only nft/iptables-save commands; permissions may limit visibility. Does not change firewall state.")
    def tool_list_firewall_rules(query: str = "", limit: int = 100) -> FirewallInventoryResponse:
        return _list_firewall_rules(query=query, limit=limit)

    @tool(name="manage_firewall_rule", description="After explicit client confirmation, add or remove one exact transient inbound TCP/UDP destination-port block rule in a dedicated nftables table. Choose ipv4 or ipv6, a port, and an optional canonical source CIDR (empty for any source). The tool creates only its own filter/input chain with accept policy, a harmless counter-only ownership marker, and exact drop rules; it does not change other tables, default policies, allow rules, or persistent firewall configuration. It verifies its managed table and exact rule, refuses foreign or advanced objects, uses current OS permissions without elevation, and a block may disconnect this MCP client.")
    async def tool_manage_firewall_rule(
        action: FirewallRuleAction,
        family: FirewallFamily,
        protocol: Literal["tcp", "udp"],
        port: int,
        source_cidr: str,
        confirmation: Annotated[
            ElicitationResult[FirewallRuleActionConfirmation],
            Resolve(_confirm_firewall_rule_action),
        ],
    ) -> FirewallRuleActionResponse:
        if confirmation.action != "accept":
            return (await asyncio.to_thread(
                _perform_firewall_rule_action,
                action,
                family,
                protocol,
                port,
                source_cidr,
                confirmed=False,
            )).model_copy(update={
                "message": f"Firewall rule action was {confirmation.action}; no change was run."
            })
        if not confirmation.data.confirm:
            return (await asyncio.to_thread(
                _perform_firewall_rule_action,
                action,
                family,
                protocol,
                port,
                source_cidr,
                confirmed=False,
            )).model_copy(update={"message": "Confirmation was not affirmative; no firewall change was run."})
        return await asyncio.to_thread(
            _perform_firewall_rule_action,
            action,
            family,
            protocol,
            port,
            source_cidr,
            confirmed=True,
        )

    @tool(name="list_firewall_frontends", description="Read bounded runtime firewalld zone bindings/settings and UFW active state, defaults, logging, and displayed rules. Uses fixed read-only commands and does not change firewall state.")
    def tool_list_firewall_frontends(query: str = "", limit: int = 100) -> FirewallFrontendInventoryResponse:
        return _list_firewall_frontends(query=query, limit=limit)

    @tool(name="manage_firewalld_port", description="After exact client confirmation, add or remove one exact TCP/UDP single-port entry in one firewalld zone's destination-port or source-port list, in runtime or saved permanent configuration. port_position defaults to destination; set it to source to use firewalld source-port commands. Requires an existing zone and exact port/protocol; runtime changes require the zone currently bound to an interface or source. Revalidates the selected exact zone port-list state, then verifies the result. Runtime changes are lost on firewalld reload/restart or reboot; permanent changes do not alter runtime state until reload/restart. Adding a destination port may expose a service through every interface/source bound to the zone; other services/rules/policies may independently allow matching traffic. Does not change default policy, reload firewalld, or use sudo.")
    async def tool_manage_firewalld_port(
        action: FirewalldPortActionName,
        configuration: FirewalldConfigurationName,
        zone: str,
        protocol: Literal["tcp", "udp"],
        port: int,
        confirmation: Annotated[
            ElicitationResult[FirewalldPortActionConfirmation],
            Resolve(_confirm_firewalld_port_action),
        ],
        port_position: Literal["destination", "source"] = "destination",
    ) -> FirewalldPortActionResponse:
        if confirmation.action != "accept":
            return FirewalldPortActionResponse(
                success=False,
                action=action,
                configuration=configuration,
                zone=zone,
                protocol=protocol,
                port_position=port_position,
                port=port,
                user_confirmed=False,
                message=f"Firewalld port confirmation was {confirmation.action}; no change was run.",
            )
        data = confirmation.data
        if (
            data.action != action
            or data.configuration != configuration
            or data.zone != zone
            or data.protocol != protocol
            or data.port_position != port_position
            or data.port != port
        ):
            return FirewalldPortActionResponse(
                success=False,
                action=action,
                configuration=configuration,
                zone=zone,
                protocol=protocol,
                port_position=port_position,
                port=port,
                user_confirmed=False,
                message="Confirmation did not repeat the exact action, configuration, zone, protocol, and port; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_firewalld_port_action,
            action,
            configuration,
            zone,
            protocol,
            port,
            data.expected_state_token,
            confirmed=data.confirm is True,
            port_position=port_position,
        )

    @tool(name="manage_firewalld_icmp_block", description="After exact client confirmation, add or remove one exact supported ICMP type block in one firewalld zone's runtime or saved permanent configuration. The type must appear in firewall-cmd --get-icmptypes. Runtime changes require the zone currently bound to an interface or source. Revalidates the type definition, block list, zone binding, and inversion state, then verifies the result. Refuses zones with ICMP block inversion enabled because inversion changes the meaning of block entries. Other firewall rules and policies may affect traffic. Runtime changes are lost on firewalld reload/restart or reboot; permanent changes do not affect runtime until reload/restart. Does not change default policy, enable inversion, reload firewalld, or use sudo.")
    async def tool_manage_firewalld_icmp_block(
        action: FirewalldICMPBlockActionName,
        configuration: FirewalldConfigurationName,
        zone: str,
        icmp_type: str,
        confirmation: Annotated[
            ElicitationResult[FirewalldICMPBlockActionConfirmation],
            Resolve(_confirm_firewalld_icmp_block_action),
        ],
    ) -> FirewalldICMPBlockActionResponse:
        if confirmation.action != "accept":
            return FirewalldICMPBlockActionResponse(
                success=False,
                action=action,
                configuration=configuration,
                zone=zone,
                icmp_type=icmp_type,
                user_confirmed=False,
                message=f"Firewalld ICMP block confirmation was {confirmation.action}; no change was run.",
            )
        data = confirmation.data
        if (
            data.action != action
            or data.configuration != configuration
            or data.zone != zone
            or data.icmp_type != icmp_type
        ):
            return FirewalldICMPBlockActionResponse(
                success=False,
                action=action,
                configuration=configuration,
                zone=zone,
                icmp_type=icmp_type,
                user_confirmed=False,
                message="Confirmation did not repeat the exact action, configuration, zone, and ICMP type; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_firewalld_icmp_block_action,
            action,
            configuration,
            zone,
            icmp_type,
            data.expected_state_token,
            confirmed=data.confirm is True,
        )

    @tool(name="manage_firewalld_service", description="After exact client confirmation, add or remove one exact firewalld service entry in one zone's runtime or saved permanent configuration. The service must appear in firewall-cmd --get-services; runtime changes require the zone currently bound to an interface or source. Revalidates exact zone and service membership, then verifies the result. A service definition may include multiple ports, protocols, or connection-tracking helpers, and the tool does not enumerate all traffic effects. Adding may affect traffic for every zone binding; other entries, rich rules, or policies may independently allow traffic. Runtime changes are lost on firewalld reload/restart or reboot; permanent changes do not alter runtime state until reload/restart. Does not change default policy, reload firewalld, or use sudo.")
    async def tool_manage_firewalld_service(
        action: FirewalldServiceActionName,
        configuration: FirewalldConfigurationName,
        zone: str,
        service: str,
        confirmation: Annotated[
            ElicitationResult[FirewalldServiceActionConfirmation],
            Resolve(_confirm_firewalld_service_action),
        ],
    ) -> FirewalldServiceActionResponse:
        if confirmation.action != "accept":
            return FirewalldServiceActionResponse(
                success=False,
                action=action,
                configuration=configuration,
                zone=zone,
                service=service,
                user_confirmed=False,
                message=f"Firewalld service confirmation was {confirmation.action}; no change was run.",
            )
        data = confirmation.data
        if (
            data.action != action
            or data.configuration != configuration
            or data.zone != zone
            or data.service != service
        ):
            return FirewalldServiceActionResponse(
                success=False,
                action=action,
                configuration=configuration,
                zone=zone,
                service=service,
                user_confirmed=False,
                message="Confirmation did not repeat the exact action, configuration, zone, and service; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_firewalld_service_action,
            action,
            configuration,
            zone,
            service,
            data.expected_state_token,
            confirmed=data.confirm is True,
        )

    @tool(name="manage_firewalld_rich_rule", description="After exact client confirmation, add or remove one typed firewalld rich rule for one TCP/UDP source or destination port or inclusive port range, optional canonical IPv4/IPv6 source and destination CIDRs, and an accept/reject/drop verdict. Optional log and audit records are each rate-limited to one per minute; log prefix and level require log_enabled=true. The iptables backend may truncate log prefixes to 29 characters. Optional priority is -32768 through 32767: negative runs before other firewalld primitives, positive after, and priority 0 follows log/deny/allow ordering; lower values run earlier and equal-priority ordering is undefined. Source and destination addresses must use the same IP family. Uses no arbitrary rule text. The exact zone must exist; runtime changes require it to be currently bound to an interface or source. Revalidates exact rule state and zone binding, then verifies the result. A zone may cover several bindings; accept permits matching traffic and reject/drop blocks matching traffic, while other firewall rules or policies may affect the final packet decision. Runtime changes are lost on firewalld reload/restart or reboot; permanent changes do not affect runtime until reload/restart. Does not change default policy, reload firewalld, or use sudo.")
    async def tool_manage_firewalld_rich_rule(
        action: FirewalldRichRuleActionName,
        configuration: FirewalldConfigurationName,
        zone: str,
        protocol: Literal["tcp", "udp"],
        port: int,
        confirmation: Annotated[
            ElicitationResult[FirewalldRichRuleActionConfirmation],
            Resolve(_confirm_firewalld_rich_rule_action),
        ],
        source_cidr: str | None = None,
        verdict: FirewalldRichRuleVerdictName = "accept",
        port_end: int | None = None,
        destination_cidr: str | None = None,
        log_enabled: bool = False,
        log_prefix: str | None = None,
        log_level: FirewalldRichRuleLogLevelName | None = None,
        audit_enabled: bool = False,
        priority: int | None = None,
        port_position: Literal["destination", "source"] = "destination",
    ) -> FirewalldRichRuleActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_firewalld_rich_rule_action,
                action,
                configuration,
                zone,
                protocol,
                port,
                source_cidr,
                verdict,
                "",
                port_end=port_end,
                destination_cidr=destination_cidr,
                log_enabled=log_enabled,
                log_prefix=log_prefix,
                log_level=log_level,
                audit_enabled=audit_enabled,
                priority=priority,
                port_position=port_position,
                confirmed=False,
            )
        data = confirmation.data
        if (
            data.action != action
            or data.configuration != configuration
            or data.zone != zone
            or data.protocol != protocol
            or data.port != port
            or data.port_end != port_end
            or data.source_cidr != (source_cidr or None)
            or data.destination_cidr != (destination_cidr or None)
            or data.verdict != verdict
            or data.log_enabled != log_enabled
            or data.log_prefix != (log_prefix or None)
            or data.log_level != log_level
            or data.audit_enabled != audit_enabled
            or data.priority != priority
            or data.port_position != port_position
        ):
            return FirewalldRichRuleActionResponse(
                success=False,
                action=action,
                configuration=configuration,
                zone=zone,
                protocol=protocol,
                port=port,
                port_position=port_position,
                port_end=port_end,
                source_cidr=source_cidr,
                destination_cidr=destination_cidr,
                verdict=verdict,
                user_confirmed=False,
                message="Confirmation did not repeat the exact action, configuration, zone, source/destination port, port range, source, destination, verdict, logging, audit, and priority settings; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_firewalld_rich_rule_action,
            action,
            configuration,
            zone,
            protocol,
            port,
            source_cidr,
            verdict,
            data.expected_state_token,
            port_end=port_end,
            destination_cidr=destination_cidr,
            log_enabled=log_enabled,
            log_prefix=log_prefix,
            log_level=log_level,
            audit_enabled=audit_enabled,
            priority=priority,
            port_position=port_position,
            confirmed=data.confirm is True,
        )

    @tool(name="manage_firewalld_rich_icmp_rule", description="After exact client confirmation, add or remove one typed firewalld rich rule matching one supported ICMP type. It accepts optional canonical same-family source/destination CIDRs, accept/reject/drop verdicts, rate-limited kernel logging/audit, and optional priority. Revalidates the exact ICMP definition, zone binding, and rule list before and after the action; arbitrary rule text and firewalld reloads are not accepted.")
    async def tool_manage_firewalld_rich_icmp_rule(
        action: FirewalldRichICMPRuleActionName,
        configuration: FirewalldConfigurationName,
        zone: str,
        icmp_type: str,
        confirmation: Annotated[
            ElicitationResult[FirewalldRichICMPRuleActionConfirmation],
            Resolve(_confirm_firewalld_rich_icmp_rule_action),
        ],
        source_cidr: str | None = None,
        destination_cidr: str | None = None,
        verdict: FirewalldRichICMPRuleVerdictName = "accept",
        log_enabled: bool = False,
        log_prefix: str | None = None,
        log_level: FirewalldRichICMPRuleLogLevelName | None = None,
        audit_enabled: bool = False,
        priority: int | None = None,
    ) -> FirewalldRichICMPRuleActionResponse:
        arguments = (
            action,
            configuration,
            zone,
            icmp_type,
            source_cidr,
            destination_cidr,
            verdict,
            log_enabled,
            log_prefix,
            log_level,
            audit_enabled,
            priority,
        )
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_firewalld_rich_icmp_rule_action,
                *arguments,
                "",
                confirmed=False,
            )
        data = confirmation.data
        if (
            data.action != action
            or data.configuration != configuration
            or data.zone != zone
            or data.icmp_type != icmp_type
            or data.source_cidr != (source_cidr or None)
            or data.destination_cidr != (destination_cidr or None)
            or data.verdict != verdict
            or data.log_enabled != log_enabled
            or data.log_prefix != (log_prefix or None)
            or data.log_level != log_level
            or data.audit_enabled != audit_enabled
            or data.priority != priority
        ):
            return FirewalldRichICMPRuleActionResponse(
                success=False,
                action=action,
                configuration=configuration,
                zone=zone,
                icmp_type=icmp_type,
                source_cidr=source_cidr,
                destination_cidr=destination_cidr,
                verdict=verdict,
                user_confirmed=False,
                message="Confirmation did not repeat the exact action, configuration, zone, ICMP type, address filters, verdict, logging, audit, and priority; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_firewalld_rich_icmp_rule_action,
            *arguments,
            data.expected_state_token,
            confirmed=data.confirm is True,
        )

    @tool(name="manage_firewalld_rich_protocol_rule", description="After exact client confirmation, add or remove one typed firewalld rich rule matching one IP protocol number or protocol name from the host's local protocol database. Optional canonical same-family source/destination CIDRs, accept/reject/drop verdicts, rate-limited kernel logging/audit, and priority are supported. Revalidates the exact zone binding and rich-rule list before and after the action; arbitrary rule text and firewalld reloads are not accepted.")
    async def tool_manage_firewalld_rich_protocol_rule(
        action: FirewalldRichProtocolRuleActionName,
        configuration: FirewalldConfigurationName,
        zone: str,
        protocol_value: str,
        confirmation: Annotated[
            ElicitationResult[FirewalldRichProtocolRuleActionConfirmation],
            Resolve(_confirm_firewalld_rich_protocol_rule_action),
        ],
        source_cidr: str | None = None,
        destination_cidr: str | None = None,
        verdict: FirewalldRichProtocolRuleVerdictName = "accept",
        log_enabled: bool = False,
        log_prefix: str | None = None,
        log_level: FirewalldRichProtocolRuleLogLevelName | None = None,
        audit_enabled: bool = False,
        priority: int | None = None,
    ) -> FirewalldRichProtocolRuleActionResponse:
        arguments = (
            action,
            configuration,
            zone,
            protocol_value,
            source_cidr,
            destination_cidr,
            verdict,
            log_enabled,
            log_prefix,
            log_level,
            audit_enabled,
            priority,
        )
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_firewalld_rich_protocol_rule_action,
                *arguments,
                "",
                confirmed=False,
            )
        data = confirmation.data
        if (
            data.action != action
            or data.configuration != configuration
            or data.zone != zone
            or data.protocol_value != protocol_value
            or data.source_cidr != (source_cidr or None)
            or data.destination_cidr != (destination_cidr or None)
            or data.verdict != verdict
            or data.log_enabled != log_enabled
            or data.log_prefix != (log_prefix or None)
            or data.log_level != log_level
            or data.audit_enabled != audit_enabled
            or data.priority != priority
        ):
            return FirewalldRichProtocolRuleActionResponse(
                success=False,
                action=action,
                configuration=configuration,
                zone=zone,
                protocol_value=protocol_value,
                source_cidr=source_cidr,
                destination_cidr=destination_cidr,
                verdict=verdict,
                user_confirmed=False,
                message="Confirmation did not repeat the exact action, configuration, zone, protocol, address filters, verdict, logging, audit, and priority; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_firewalld_rich_protocol_rule_action,
            *arguments,
            data.expected_state_token,
            confirmed=data.confirm is True,
        )

    @tool(name="manage_ufw_port_rule", description="After exact client confirmation, add or remove one UFW TCP/UDP numeric port, contiguous port range, or sorted comma-separated numeric port list of at most 15 ports, with allow, deny, reject, or limit action, inbound/outbound direction, and optional literal source/destination IPv4 or IPv6 address/CIDR filters. Ranges and lists are mutually exclusive. Hostnames, interfaces, routed rules, and default-policy changes are not accepted. Revalidates exact numbered-rule state; removal deletes each matching IP-family entry by number and re-reads between deletions. A concurrent UFW change can interrupt dual-stack removal. Earlier rules may take precedence; raw non-UFW rules and effective policy are not fully inspected. Does not enable/disable UFW or use sudo.")
    async def tool_manage_ufw_port_rule(
        action: UFWPortRuleActionName,
        protocol: Literal["tcp", "udp"],
        port: int,
        confirmation: Annotated[
            ElicitationResult[UFWPortRuleActionConfirmation],
            Resolve(_confirm_ufw_port_rule_action),
        ],
        direction: Literal["in", "out"] = "in",
        source_address: str = "any",
        destination_address: str = "any",
        port_end: int | None = None,
        additional_ports: list[StrictInt] | None = None,
    ) -> UFWPortRuleActionResponse:
        if confirmation.action != "accept":
            return UFWPortRuleActionResponse(
                success=False,
                action=action,
                protocol=protocol,
                port=port,
                port_end=port_end,
                additional_ports=additional_ports,
                direction=direction,
                source_address=source_address,
                destination_address=destination_address,
                user_confirmed=False,
                message=f"UFW port-rule confirmation was {confirmation.action}; no change was run.",
            )
        data = confirmation.data
        expected_source, source_error = _canonical_ufw_address(source_address, field="source_address")
        expected_destination, destination_error = _canonical_ufw_address(destination_address, field="destination_address")
        expected_additional_ports_json = json.dumps(list(additional_ports or ()), separators=(",", ":"))
        if (
            source_error is not None
            or destination_error is not None
            or data.action != action
            or data.protocol != protocol
            or data.port != port
            or data.port_end != port_end
            or data.additional_ports_json != expected_additional_ports_json
            or data.direction != direction
            or data.source_address != expected_source
            or data.destination_address != expected_destination
        ):
            return UFWPortRuleActionResponse(
                success=False,
                action=action,
                protocol=protocol,
                port=port,
                port_end=port_end,
                additional_ports=additional_ports,
                direction=direction,
                source_address=expected_source,
                destination_address=expected_destination,
                user_confirmed=False,
                message="Confirmation did not repeat the exact action, protocol, port selector, direction, and normalized addresses; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_ufw_port_rule_action,
            action,
            protocol,
            port,
            data.expected_state_token,
            direction,
            source_address,
            destination_address,
            port_end,
            additional_ports,
            confirmed=data.confirm is True,
        )

    @tool(name="list_openrc_runlevels", description="On OpenRC hosts, read bounded existing /etc/runlevels directories and the service-link names assigned to each. This is a read-only configuration snapshot and does not report dynamic runlevels or change service state.")
    def tool_list_openrc_runlevels(query: str = "", limit: int = 64) -> OpenRCRunlevelListResponse:
        return _list_openrc_runlevels(query=query, limit=limit)

    @tool(name="list_services", description="List systemd service units and runtime/startup states in the selected system or user-manager scope; for OpenRC system scope, include bounded rc-status active states and runlevel contexts; for runit system scope, list supervised service directories and bounded sv status runtime/normal-startup states when available; for s6 system scope, list atomic services with type and up/down state from read-only s6-rc status output and report staged startup prescriptions from s6 set status for the offline current working set, including services not in the live database; on other init systems, list conventional init-script names when available. Read-only; no service actions are performed.")
    def tool_list_services(
        query: str = "",
        limit: int = 100,
        scope: Literal["system", "user"] = "system",
    ) -> ServiceListResponse:
        return _list_services(query=query, limit=limit, scope=scope)

    @tool(name="list_systemd_timers", description="Read loaded systemd timer units and their next/last run times in the system or user-manager scope. Uses a bounded, read-only systemctl list-timers query; --all includes loaded inactive timers, but unloaded unit files are not enumerated. This tool does not start, stop, enable, or modify timers.")
    def tool_list_systemd_timers(
        query: str = "",
        limit: int = 100,
        scope: Literal["system", "user"] = "system",
    ) -> SystemdTimerListResponse:
        return _list_systemd_timers(query=query, limit=limit, scope=scope)

    @tool(name="manage_systemd_timer", description="After exact client confirmation, start or stop one loaded .timer unit, or persistently enable or disable one loaded timer whose unit-file state is enabled/disabled. Works in system or user-manager scope, revalidates trigger/schedule state after confirmation, verifies the resulting state, and never changes timer schedule directives or requests elevation. Starting a persistent calendar timer may immediately trigger a missed event. Enable/disable may also affect units in the timer's Also= setting; disable removes all matching enablement links and does not stop an active timer.")
    async def tool_manage_systemd_timer(
        action: SystemdTimerActionName,
        unit: str,
        scope: SystemdTimerScopeName,
        confirmation: Annotated[
            ElicitationResult[SystemdTimerActionConfirmation],
            Resolve(_confirm_systemd_timer_action),
        ],
    ) -> SystemdTimerActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_systemd_timer_action,
                action,
                unit,
                scope,
                "",
                confirmed=False,
            )
        data = confirmation.data
        if not data.confirm:
            return await asyncio.to_thread(
                _perform_systemd_timer_action,
                action,
                unit,
                scope,
                "",
                confirmed=False,
            )
        if data.action != action or data.unit != unit or data.scope != scope:
            return SystemdTimerActionResponse(
                success=False,
                action=action,
                unit=unit,
                scope=scope,
                user_confirmed=False,
                message="Confirmation did not match the requested timer action and exact unit; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_systemd_timer_action,
            action,
            unit,
            scope,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="manage_systemd_timer_definition", description="After exact client confirmation, create or update one generated systemd .timer file in an existing system or current-user unit directory. It can target only an already-loaded exact .service unit and accepts a systemd-analyze-validated calendar expression and/or bounded boot-relative/repeat delays. Updates are limited to inactive, marked timer files without drop-ins. The tool reloads the selected manager but leaves the timer inactive and does not enable it or create/edit service units; a persistent calendar timer may trigger one catch-up run when later started, and system-scope services may run with root privileges. Uses current OS permissions without elevation.")
    async def tool_manage_systemd_timer_definition(
        action: SystemdTimerDefinitionActionName,
        unit: str,
        scope: SystemdTimerScopeName,
        service_unit: str,
        confirmation: Annotated[
            ElicitationResult[SystemdTimerDefinitionConfirmation],
            Resolve(_confirm_systemd_timer_definition),
        ],
        on_calendar: str | None = None,
        on_boot_seconds: int | None = None,
        on_unit_active_seconds: int | None = None,
        persistent: bool = False,
    ) -> SystemdTimerDefinitionResponse:
        perform_args = {
            "action": action,
            "scope": scope,
            "unit": unit,
            "service_unit": service_unit,
            "on_calendar": on_calendar,
            "on_boot_seconds": on_boot_seconds,
            "on_unit_active_seconds": on_unit_active_seconds,
            "persistent": persistent,
        }
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_systemd_timer_definition,
                **perform_args,
                confirmed=False,
            )
        data = confirmation.data
        if not data.confirm:
            return await asyncio.to_thread(
                _perform_systemd_timer_definition,
                **perform_args,
                confirmed=False,
            )
        if (
            data.action != action
            or data.scope != scope
            or data.unit != unit
            or data.service_unit != service_unit
            or data.on_calendar != on_calendar
            or data.on_boot_seconds != on_boot_seconds
            or data.on_unit_active_seconds != on_unit_active_seconds
            or data.persistent != persistent
        ):
            return SystemdTimerDefinitionResponse(
                success=False,
                action=action,
                scope=scope,
                unit=unit,
                service_unit=service_unit,
                user_confirmed=False,
                message="Confirmation did not match the exact timer definition request; no file was written.",
            )
        return await asyncio.to_thread(
            _perform_systemd_timer_definition,
            **perform_args,
            confirmed=True,
            confirmed_action=data.action,
            confirmed_scope=data.scope,
            confirmed_unit=data.unit,
            confirmed_service_unit=data.service_unit,
            confirmed_on_calendar=data.on_calendar,
            confirmed_on_boot_seconds=data.on_boot_seconds,
            confirmed_on_unit_active_seconds=data.on_unit_active_seconds,
            confirmed_persistent=data.persistent,
            confirmed_phrase=data.confirmation_phrase,
            expected_state_token=data.expected_state_token,
        )

    @tool(name="delete_systemd_timer_definition", description="After exact client confirmation, delete one inactive, disabled generated systemd .timer file previously created by linux-mcp. Files with drop-ins, enablement links, a different fragment path, or a missing generation marker are refused. The selected manager is reloaded and the tool verifies that the file is absent and systemd no longer loads the unit. It does not delete or stop the associated service. Uses current OS permissions without elevation.")
    async def tool_delete_systemd_timer_definition(
        unit: str,
        scope: SystemdTimerScopeName,
        confirmation: Annotated[
            ElicitationResult[SystemdTimerDefinitionDeleteConfirmation],
            Resolve(_confirm_systemd_timer_definition_deletion),
        ],
    ) -> SystemdTimerDefinitionDeleteResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_systemd_timer_definition_deletion,
                scope,
                unit,
                confirmed=False,
            )
        data = confirmation.data
        if not data.confirm:
            return await asyncio.to_thread(
                _perform_systemd_timer_definition_deletion,
                scope,
                unit,
                confirmed=False,
            )
        if data.scope != scope or data.unit != unit:
            return SystemdTimerDefinitionDeleteResponse(
                success=False,
                scope=scope,
                unit=unit,
                user_confirmed=False,
                message="Confirmation did not match the exact timer deletion request; no file was deleted.",
            )
        return await asyncio.to_thread(
            _perform_systemd_timer_definition_deletion,
            scope,
            unit,
            confirmed=True,
            confirmed_scope=data.scope,
            confirmed_unit=data.unit,
            confirmed_phrase=data.confirmation_phrase,
            expected_state_token=data.expected_state_token,
        )

    @tool(name="manage_systemd_service_definition", description="After exact client confirmation, create or update one generated systemd Type=oneshot .service file in an existing system or current-user unit directory. The executable must be a canonical absolute executable path; arguments are passed as a fixed argv vector without a shell. Updates are limited to inactive service files previously created by this tool, without drop-ins, and preserve existing enablement. The manager reloads the selected scope but the service remains inactive; creation leaves it disabled. System-scope services use systemd's configured identity (root by default); user-scope services run as the current user. The executable and arguments are stored as readable unit-file text. Uses current OS permissions and does not request elevation.")
    async def tool_manage_systemd_service_definition(
        action: SystemdServiceDefinitionActionName,
        unit: str,
        scope: SystemdTimerScopeName,
        executable: str,
        arguments: list[str],
        confirmation: Annotated[
            ElicitationResult[SystemdServiceDefinitionConfirmation],
            Resolve(_confirm_systemd_service_definition),
        ],
    ) -> SystemdServiceDefinitionResponse:
        perform_args = {
            "action": action,
            "unit": unit,
            "scope": scope,
            "executable": executable,
            "arguments": arguments,
        }
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_systemd_service_definition,
                **perform_args,
                confirmed=False,
            )
        data = confirmation.data
        if not data.confirm:
            return await asyncio.to_thread(
                _perform_systemd_service_definition,
                **perform_args,
                confirmed=False,
            )
        expected_arguments_json = json.dumps(arguments, ensure_ascii=True, separators=(",", ":"))
        if (
            data.action != action
            or data.scope != scope
            or data.unit != unit
            or data.executable != executable
            or data.arguments_json != expected_arguments_json
        ):
            return SystemdServiceDefinitionResponse(
                success=False,
                action=action,
                scope=scope,
                unit=unit,
                executable=executable,
                arguments=arguments,
                user_confirmed=False,
                message="Confirmation did not match the exact service definition request; no file was written.",
            )
        return await asyncio.to_thread(
            _perform_systemd_service_definition,
            **perform_args,
            confirmed=True,
            confirmed_action=data.action,
            confirmed_scope=data.scope,
            confirmed_unit=data.unit,
            confirmed_executable=data.executable,
            confirmed_arguments=arguments,
            confirmed_phrase=data.confirmation_phrase,
            expected_state_token=data.expected_state_token,
        )

    @tool(name="list_cron_jobs", description="Read schedule metadata from standard system crontabs, the current user's crontab, Anacron, and the visible at queue. Returns schedules, source/line or job identity, and reported owner metadata without command bodies or arbitrary environment assignments; only selected non-secret schedule settings are returned. Reads fixed /etc files and uses bounded crontab/atq queries with current-user permissions; a root atq process may see jobs owned by all users.")
    def tool_list_cron_jobs(query: str = "", limit: int = 200) -> CronJobListResponse:
        return _list_cron_jobs(query=query, limit=limit)

    @tool(name="manage_cron_job", description="After exact client confirmation, add, update, or remove one marked cron job. The default scope=user manages one marked job in the current server identity's crontab. For scope=system, provide a safe job_id and an exact local run_as_user; this manages only the generated /etc/cron.d/linux-mcp-<job_id> file, requires the server to already run as root, and writes an owner-root mode-0644 cron file without elevation. Use schedule and command to identify an existing job for update/remove; update also requires new_schedule and new_command. Schedules must contain five numeric fields. Confirmation binds the exact current crontab or marked system file and requested action. The cron command runs later with the selected account's permissions and environment; secret values remain visible in cron configuration, and an external edit in the final read/write interval can race the update.")
    async def tool_manage_cron_job(
        action: CronJobActionName,
        schedule: str,
        command: str,
        confirmation: Annotated[
            ElicitationResult[CronJobActionConfirmation],
            Resolve(_confirm_cron_job_action),
        ],
        new_schedule: str | None = None,
        new_command: str | None = None,
        scope: Annotated[
            Literal["user", "system"],
            PydanticField(description="user manages the server identity's crontab; system manages one generated /etc/cron.d file and requires the server to already run as root"),
        ] = "user",
        run_as_user: Annotated[
            str,
            PydanticField(
                max_length=64,
                pattern=r"^(?:[A-Za-z_][A-Za-z0-9_.-]{0,62}\$?)?$",
                description="For scope=system, exact existing local account that cron will run as; empty for user scope",
            ),
        ] = "",
        job_id: Annotated[
            str,
            PydanticField(
                max_length=48,
                pattern=r"^(?:[A-Za-z0-9][A-Za-z0-9_-]{0,47})?$",
                description="For scope=system, stable ID for /etc/cron.d/linux-mcp-<job_id>; empty for user scope",
            ),
        ] = "",
    ) -> CronJobActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_cron_job_action,
                action,
                schedule,
                command,
                new_schedule=new_schedule,
                new_command=new_command,
                scope=scope,
                run_as_user=run_as_user,
                job_id=job_id,
                confirmed=False,
            )
        data = confirmation.data
        if data.scope != scope or data.run_as_user != run_as_user or data.job_id != job_id:
            return CronJobActionResponse(
                success=False,
                action=action,
                username=run_as_user,
                schedule=new_schedule if action == "update" and new_schedule else schedule,
                scope=scope,
                job_id=job_id or None,
                user_confirmed=False,
                message="The confirmation fields did not match this exact cron target; no cron source was changed.",
            )
        return await asyncio.to_thread(
            _perform_cron_job_action,
            action,
            schedule,
            command,
            new_schedule=new_schedule,
            new_command=new_command,
            scope=scope,
            run_as_user=run_as_user,
            job_id=job_id,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_at_job", description="After exact client confirmation, add or remove one one-shot job in the current server identity's at queue. Adding requires a local host time in YYYY-MM-DDTHH:MM format at least two minutes and at most 365 days ahead plus one exact single-line command; removing requires a job ID shown by the current user's at queue. The confirmation binds the current queue and, for removal, a digest of the hidden job contents. Uses at/atrm with current-user permissions, sends no completion mail, never targets another user's queue, and requests no privilege elevation. Commands run later through /bin/sh with the server identity's permissions and captured environment; command text may be visible to local administrators, execution depends on atd, and an external queue edit in the final read/action interval can race the request.")
    async def tool_manage_at_job(
        action: AtJobActionName,
        confirmation: Annotated[
            ElicitationResult[AtJobActionConfirmation],
            Resolve(_confirm_at_job_action),
        ],
        run_at: str = "",
        command: str = "",
        job_id: str = "",
    ) -> AtJobActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_at_job_action,
                action,
                run_at,
                command,
                job_id,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_at_job_action,
            action,
            run_at,
            command,
            job_id,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_service", description="After explicit client confirmation, manage one exact service at runtime. systemd accepts start, stop, restart, reload, enable, and disable for exact .service units in system or user-manager scope; OpenRC, runit, and s6-rc accept start, stop, restart, and reload in system scope. OpenRC startup membership is managed separately by manage_openrc_service_startup; runit initial startup state is managed separately by manage_runit_service_startup. OpenRC and s6-rc may change related services to satisfy dependencies; runit acts on one supervised service. Commands use current-user permissions, bounded execution, fixed argument vectors, and no elevation; s6-rc never forces an essential service down, and timeouts may leave transition scripts running or state partial.")
    async def tool_manage_service(
        action: ServiceAction,
        unit: str,
        scope: ServiceScope,
        confirmation: Annotated[
            ElicitationResult[ServiceActionConfirmation],
            Resolve(_confirm_service_action),
        ],
    ) -> ServiceActionResponse:
        if confirmation.action != "accept":
            return ServiceActionResponse(
                success=False,
                action=action,
                unit=unit,
                scope=scope,
                manager=_detect_init_system() or "unknown",
                message=f"Service action was {confirmation.action}; no command was run.",
            )
        if not confirmation.data.confirm:
            return ServiceActionResponse(
                success=False,
                action=action,
                unit=unit,
                scope=scope,
                manager=_detect_init_system() or "unknown",
                message="Confirmation was not affirmative; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_service_action,
            action=action,
            unit=unit,
            confirmed=True,
            scope=scope,
        )

    @tool(name="manage_openrc_service_startup", description="After exact client confirmation, add or remove one exact OpenRC service from one existing persistent system runlevel using rc-update. The request revalidates the runlevel directory and exact service symlink after confirmation, does not start or stop the running service, and uses current-user permissions without elevation.")
    async def tool_manage_openrc_service_startup(
        action: Literal["enable", "disable"],
        unit: str,
        runlevel: str,
        confirmation: Annotated[
            ElicitationResult[OpenRCServiceStartupConfirmation],
            Resolve(_confirm_openrc_service_startup),
        ],
    ) -> OpenRCServiceStartupResponse:
        if confirmation.action != "accept":
            return OpenRCServiceStartupResponse(
                success=False,
                action=action,
                unit=unit,
                runlevel=runlevel,
                user_confirmed=False,
                message=f"OpenRC startup action was {confirmation.action}; no change was run.",
            )
        data = confirmation.data
        if not data.confirm:
            return OpenRCServiceStartupResponse(
                success=False,
                action=action,
                unit=unit,
                runlevel=runlevel,
                user_confirmed=False,
                message="Confirmation was not affirmative; no OpenRC startup change was run.",
            )
        if data.action != action or data.unit != unit or data.runlevel != runlevel:
            return OpenRCServiceStartupResponse(
                success=False,
                action=action,
                unit=unit,
                runlevel=runlevel,
                user_confirmed=False,
                message="Confirmation did not match the requested exact service, action, and runlevel; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_openrc_startup_action,
            action,
            unit,
            runlevel,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="manage_runit_service_startup", description="After exact client confirmation, change the persistent initial state of one exact supervised runit service by creating or removing its service-directory down marker. The request revalidates the service directory and marker after confirmation. The change affects a future runsv supervisor start and does not change a currently running service or supervisor; it uses current-user filesystem permissions without elevation.")
    async def tool_manage_runit_service_startup(
        action: Literal["enable", "disable"],
        unit: str,
        confirmation: Annotated[
            ElicitationResult[RunitServiceStartupConfirmation],
            Resolve(_confirm_runit_service_startup),
        ],
    ) -> RunitServiceStartupResponse:
        if confirmation.action != "accept":
            return RunitServiceStartupResponse(
                success=False,
                action=action,
                unit=unit,
                user_confirmed=False,
                message=f"Runit startup action was {confirmation.action}; no marker change was made.",
            )
        data = confirmation.data
        if not data.confirm:
            return RunitServiceStartupResponse(
                success=False,
                action=action,
                unit=unit,
                user_confirmed=False,
                message="Confirmation was not affirmative; no runit startup marker change was made.",
            )
        if data.action != action or data.unit != unit:
            return RunitServiceStartupResponse(
                success=False,
                action=action,
                unit=unit,
                user_confirmed=False,
                message="Confirmation did not match the requested exact service and action; no marker change was made.",
            )
        return await asyncio.to_thread(
            _perform_runit_startup_action,
            action,
            unit,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="manage_s6_startup_set", description="After exact client confirmation, enable or disable one existing s6-frontend atomic service in the current offline working set. Revalidates the exact service prescription before and after the command and refuses dependency-inconsistent changes. This stages startup configuration only: it does not change the live service database or current service state; the set must be committed and installed before boot behavior changes. Uses current-user permissions without elevation.")
    async def tool_manage_s6_startup_set(
        action: Literal["enable", "disable"],
        unit: str,
        confirmation: Annotated[
            ElicitationResult[S6StartupSetConfirmation],
            Resolve(_confirm_s6_startup_set),
        ],
    ) -> S6StartupSetResponse:
        if confirmation.action != "accept":
            return S6StartupSetResponse(
                success=False,
                action=action,
                unit=unit,
                user_confirmed=False,
                message=f"s6 startup-set action was {confirmation.action}; no change was made.",
            )
        data = confirmation.data
        if not data.confirm:
            return S6StartupSetResponse(
                success=False,
                action=action,
                unit=unit,
                user_confirmed=False,
                message="Confirmation was not affirmative; no s6 startup-set change was made.",
            )
        if data.action != action or data.unit != unit:
            return S6StartupSetResponse(
                success=False,
                action=action,
                unit=unit,
                user_confirmed=False,
                message="Confirmation did not match the exact s6 service and action; no change was made.",
            )
        return await asyncio.to_thread(
            _perform_s6_startup_set,
            action,
            unit,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="set_default_boot_target", description="After explicit client confirmation, set one exact installed systemd .target as the default for the next boot. Does not alter the running session. Uses current-user permissions, a fixed systemctl argument vector, and no elevation.")
    async def tool_set_default_boot_target(
        target: str,
        confirmation: Annotated[
            ElicitationResult[BootTargetConfirmation],
            Resolve(_confirm_default_boot_target),
        ],
    ) -> BootTargetActionResponse:
        if confirmation.action != "accept":
            return BootTargetActionResponse(
                success=False,
                target=target,
                message=f"Default-target change was {confirmation.action}; no command was run.",
            )
        if not confirmation.data.confirm:
            return BootTargetActionResponse(
                success=False,
                target=target,
                message="Confirmation was not affirmative; no command was run.",
            )
        return _set_default_boot_target(target=target, confirmed=True)

    @tool(name="manage_container", description="After explicit client confirmation, start, stop, restart, pause, unpause, or remove one exact Docker/Podman container returned by list_containers. Requires its fresh identity token, rechecks the container identity after confirmation, uses only a local API socket or local Podman CLI, and never removes volumes or forces removal. A rootful engine may perform host-privileged operations.")
    async def tool_manage_container(
        action: ContainerAction,
        identity_token: str,
        confirmation: Annotated[
            ElicitationResult[ContainerActionConfirmation],
            Resolve(_confirm_container_action),
        ],
    ) -> ContainerActionResponse:
        if confirmation.action != "accept":
            return _perform_container_action(
                action=action,
                identity_token=identity_token,
                confirmed=False,
            ).model_copy(update={"message": f"Container action was {confirmation.action}; no action was run."})
        if not confirmation.data.confirm:
            return _perform_container_action(
                action=action,
                identity_token=identity_token,
                confirmed=False,
            ).model_copy(update={"message": "Confirmation was not affirmative; no container action was run."})
        return _perform_container_action(
            action=action,
            identity_token=identity_token,
            confirmed=True,
        )

    @tool(name="create_container", description="After exact client confirmation, create one stopped Docker/Podman container from an exact local image. Optional network_name selects one exact existing non-default local network; without it the runtime default applies. The command is an argument array, never a shell string. Optional environment_variables is a name-to-value object; values are hidden in confirmation and output, but stored in the container and may be visible through runtime inspection. Podman values are passed through an anonymous environment file, not its command line, and implicit host proxy variables are disabled. Optional container_user accepts numeric UID or UID:GID (UID 0 is container root); read_only_rootfs, no_new_privileges, and drop_capabilities provide explicit hardening. Optional port mappings accept host_port:container_port[/tcp|udp] (TCP and loopback by default) or host_ipv4:host_port:container_port[/tcp|udp]; explicit 0.0.0.0 binds all IPv4 interfaces. Optional volume_mounts accept existing name:/container/path[:ro|rw] mounts; missing volumes are refused and copy-up is disabled. Optional host_path_mounts accept existing /host/path:/container/path[:ro|rw] regular-file or directory mounts outside /proc, /sys, /dev, and /run; read-only is requested by default, and read-write mounts can modify host files after start. Host source paths containing ':' or ',' are unsupported. Optional memory_limit_bytes and cpu_limit_millicores constrain resources. It does not start the container, pull/build an image, or request privileged mode; image-declared VOLUME may create an anonymous volume. Rechecks endpoint, image ID, name, network identity, command, environment, mounts, user, security settings, and limits, then checks stopped state, identity, selected network, and the requested environment/hardening fields. A rootful engine may create host-privileged resources. Hidden when the containers, filesystem, or networking category is disabled.")
    async def tool_create_container(
        runtime: ContainerRuntimeName,
        scope: Literal["system", "user"],
        name: str,
        image: str,
        confirmation: Annotated[
            ElicitationResult[ContainerCreateConfirmation],
            Resolve(_confirm_container_create),
        ],
        command: list[str] | None = None,
        port_mappings: list[str] | None = None,
        memory_limit_bytes: int | None = None,
        cpu_limit_millicores: int | None = None,
        volume_mounts: list[str] | None = None,
        host_path_mounts: list[str] | None = None,
        environment_variables: dict[str, str] | None = None,
        container_user: str | None = None,
        read_only_rootfs: bool = False,
        no_new_privileges: bool = False,
        drop_capabilities: list[str] | None = None,
        network_name: str | None = None,
    ) -> ContainerCreateResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_container_create,
                runtime,
                scope,
                name,
                image,
                command,
                port_mappings,
                memory_limit_bytes,
                cpu_limit_millicores,
                volume_mounts,
                host_path_mounts,
                environment_variables,
                container_user,
                read_only_rootfs,
                no_new_privileges,
                drop_capabilities,
                network_name,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_container_create,
            runtime,
            scope,
            name,
            image,
            command,
            port_mappings,
            memory_limit_bytes,
            cpu_limit_millicores,
            volume_mounts,
            host_path_mounts,
            environment_variables,
            container_user,
            read_only_rootfs,
            no_new_privileges,
            drop_capabilities,
            network_name,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_virtual_machine", description="After explicit client confirmation, start, gracefully shut down, reboot, suspend, or resume one exact local libvirt QEMU domain returned by list_virtual_machines. Requires its fresh UUID-bound identity token, revalidates state after confirmation, and connects only to fixed qemu:///system or qemu:///session URIs. It never force-powers-off or undefines a domain; start runs the configured guest workload and can access its configured host resources.")
    async def tool_manage_virtual_machine(
        action: VirtualMachineActionName,
        identity_token: str,
        confirmation: Annotated[
            ElicitationResult[VirtualMachineActionConfirmation],
            Resolve(_confirm_virtual_machine_action),
        ],
    ) -> VirtualMachineActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_virtual_machine_action,
                action,
                identity_token,
                "",
                "",
                "",
                "",
                confirmed=False,
            )
        data = confirmation.data
        if not data.confirm:
            return await asyncio.to_thread(
                _perform_virtual_machine_action,
                action,
                identity_token,
                "",
                data.scope,
                data.uuid,
                data.name,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_virtual_machine_action,
            action,
            identity_token,
            data.expected_state_token,
            data.scope,
            data.uuid,
            data.name,
            confirmed=True,
        )

    @tool(name="manage_remote_virtual_machine", description="After explicit client confirmation, start, gracefully shut down, reboot, suspend, or resume one exact remote QEMU/libvirt domain returned by list_remote_virtual_machines. Accepts only a qemu+ssh URI ending in /system or /session, binds confirmation to that exact endpoint/domain/state, and revalidates before and after the action. Uses default SSH keys and an owned SSH_AUTH_SOCK when available; disables SSH config, agent forwarding, password prompts, and unknown host-key acceptance. Remote libvirt authorization applies; no sudo is invoked, and a system-scope guest may use privileged resources on its host.")
    async def tool_manage_remote_virtual_machine(
        action: RemoteVirtualMachineActionName,
        identity_token: str,
        confirmation: Annotated[
            ElicitationResult[RemoteVirtualMachineActionConfirmation],
            Resolve(_confirm_remote_virtual_machine_action),
        ],
    ) -> RemoteVirtualMachineActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_remote_virtual_machine_action,
                action,
                identity_token,
                "",
                "",
                "",
                "",
                "",
                confirmed=False,
            )
        data = confirmation.data
        is_exact_confirmation = data.confirm is True and data.action == action
        return await asyncio.to_thread(
            _perform_remote_virtual_machine_action,
            action,
            identity_token,
            data.expected_state_token if is_exact_confirmation else "",
            data.endpoint,
            data.scope,
            data.uuid,
            data.name,
            confirmed=is_exact_confirmation,
        )

    @tool(name="list_remote_libvirt_networks", description="List bounded virtual-network names, state, persistence, and autostart for one validated qemu+ssh libvirt endpoint ending in /system or /session. Uses read-only remote virsh; network XML, bridge names, addresses, DHCP data, and ports are omitted. Requires virsh and OpenSSH on this server, a trusted host key, and remote libvirt access.")
    def tool_list_remote_libvirt_networks(
        endpoint: str,
        limit: int = 100,
    ) -> RemoteLibvirtNetworkListResponse:
        return _list_remote_libvirt_networks(endpoint=endpoint, limit=limit)

    @tool(name="list_remote_libvirt_storage", description="List bounded storage-pool state and capacity metadata from one validated qemu+ssh libvirt endpoint. Optionally pass one exact returned pool name to list its bounded volume names, types, capacities, and allocations. Filesystem paths, volume keys, and XML are omitted. Requires virsh and OpenSSH on this server, a trusted host key, and remote libvirt access.")
    def tool_list_remote_libvirt_storage(
        endpoint: str,
        pool_name: str = "",
        limit: int = 100,
    ) -> RemoteLibvirtStorageInventoryResponse:
        return _list_remote_libvirt_storage(endpoint=endpoint, pool_name=pool_name, limit=limit)

    @tool(name="manage_remote_libvirt_resource", description="After exact client confirmation, start or stop one remote libvirt virtual network or storage pool, or change its autostart setting. Requires the exact validated qemu+ssh endpoint and resource name; binds confirmation to UUID and current state, revalidates before acting, and verifies the result. Stopping a network immediately disconnects guests; stopping a pool can interrupt guest storage access. Uses trusted SSH host keys and current remote libvirt permissions; no sudo is invoked.")
    async def tool_manage_remote_libvirt_resource(
        action: RemoteLibvirtResourceActionName,
        resource_type: RemoteLibvirtResourceTypeName,
        endpoint: str,
        name: str,
        confirmation: Annotated[
            ElicitationResult[RemoteLibvirtResourceActionConfirmation],
            Resolve(_confirm_remote_libvirt_resource_action),
        ],
    ) -> RemoteLibvirtResourceActionResponse:
        if confirmation.action != "accept":
            return RemoteLibvirtResourceActionResponse(
                success=False,
                action=action,
                resource_type=resource_type,
                endpoint=endpoint,
                user_confirmed=False,
                message="The remote libvirt resource action was not confirmed; no command was run.",
            )
        data = confirmation.data
        parsed_endpoint, _endpoint_error = _parse_remote_libvirt_endpoint(endpoint)
        expected_scope = parsed_endpoint.scope if parsed_endpoint is not None else ""
        exact_request = (
            data.action == action
            and data.resource_type == resource_type
            and parsed_endpoint is not None
            and data.endpoint == parsed_endpoint.canonical
            and data.scope == expected_scope
            and data.name == name
        )
        is_confirmed = data.confirm is True and exact_request
        return await asyncio.to_thread(
            _perform_remote_libvirt_resource_action,
            action,
            resource_type,
            endpoint,
            name,
            data.uuid,
            data.expected_state_token if exact_request else "",
            confirmed=is_confirmed,
        )

    @tool(name="list_remote_virtual_machine_snapshots", description="List bounded snapshot names and parent names for one exact remote QEMU/libvirt VM. Requires a fresh identity_token from list_remote_virtual_machines; the validated qemu+ssh endpoint is bound to that token. Uses read-only remote virsh, the server account's SSH keys, and a pretrusted host key.")
    def tool_list_remote_virtual_machine_snapshots(
        identity_token: str,
        limit: int = 100,
    ) -> VirtualMachineSnapshotListResponse:
        return _list_remote_virtual_machine_snapshots(identity_token=identity_token, limit=limit)

    @tool(name="manage_remote_virtual_machine_snapshot", description="After exact client confirmation, create a disk-only snapshot for one shut-off remote QEMU/libvirt VM, revert to one exact snapshot, or delete one exact leaf snapshot. Requires the short-lived identity_token from list_remote_virtual_machines and revalidates the endpoint, domain state, full bounded snapshot inventory, and selected snapshot metadata. Revert may discard later guest changes and resume saved execution state. Uses validated qemu+ssh with SSH config/agent forwarding disabled and a pretrusted host key; no sudo is invoked.")
    async def tool_manage_remote_virtual_machine_snapshot(
        action: VirtualMachineSnapshotActionName,
        identity_token: str,
        snapshot_name: str,
        confirmation: Annotated[
            ElicitationResult[VirtualMachineSnapshotActionConfirmation],
            Resolve(_confirm_remote_virtual_machine_snapshot_action),
        ],
        description: str = "",
    ) -> VirtualMachineSnapshotActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_remote_virtual_machine_snapshot_action,
                action,
                identity_token,
                snapshot_name,
                description,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_remote_virtual_machine_snapshot_action,
            action,
            identity_token,
            snapshot_name,
            description,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="attach_remote_virtual_machine_disk", description="After exact client confirmation, attach one existing raw/qcow2 volume from an active persistent remote directory pool to an unused virtio slot in one shut-off remote QEMU/libvirt VM. It rechecks the full bounded remote VM inventory, selected VM/pool/volume definitions, and visible disk references; it changes persistent configuration only and never formats or starts the disk or VM. Uses validated qemu+ssh with trusted host keys, no SSH config or agent forwarding, and current remote libvirt permissions without sudo.")
    async def tool_attach_remote_virtual_machine_disk(
        identity_token: str,
        pool_name: str,
        volume_name: str,
        disk_target: str,
        confirmation: Annotated[
            ElicitationResult[RemoteVirtualMachineDiskAttachConfirmation],
            Resolve(_confirm_remote_virtual_machine_disk_attach),
        ],
    ) -> RemoteVirtualMachineDiskAttachResponse:
        if confirmation.action != "accept":
            return RemoteVirtualMachineDiskAttachResponse(
                success=False,
                user_confirmed=False,
                message="The remote disk attachment was not confirmed; no command was run.",
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_remote_virtual_machine_disk_attach,
            identity_token,
            pool_name,
            volume_name,
            disk_target,
            data.expected_state_token,
            data.endpoint,
            data.scope,
            data.uuid,
            data.name,
            data.pool_name,
            data.volume_name,
            data.disk_target,
            confirmed=data.confirm is True,
        )

    @tool(name="create_remote_virtual_machine", description="After exact client confirmation, define one stopped remote QEMU/libvirt VM with bounded memory/vCPU values, a newly created sparse qcow2 disk in an active persistent remote directory pool, and optionally one existing persistent remote network. The generated XML is validated with virsh define --validate and the resulting stopped configuration is rechecked. It does not install an OS or start the VM; a partial failure may leave the new disk for inspection. Uses a validated qemu+ssh endpoint with trusted host keys, no SSH config or agent forwarding, and current remote libvirt permissions without sudo.")
    async def tool_create_remote_virtual_machine(
        endpoint: str,
        name: str,
        memory_mib: int,
        vcpus: int,
        pool_name: str,
        disk_volume_name: str,
        disk_capacity_bytes: int,
        confirmation: Annotated[
            ElicitationResult[RemoteVirtualMachineCreateConfirmation],
            Resolve(_confirm_remote_virtual_machine_create),
        ],
        network_name: str = "",
    ) -> RemoteVirtualMachineCreateResponse:
        if confirmation.action != "accept":
            return RemoteVirtualMachineCreateResponse(
                success=False,
                user_confirmed=False,
                message="The remote VM creation was not confirmed; no remote storage or VM definition was changed.",
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_remote_virtual_machine_create,
            endpoint,
            name,
            memory_mib,
            vcpus,
            pool_name,
            disk_volume_name,
            disk_capacity_bytes,
            network_name,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="configure_remote_virtual_machine", description="After exact client confirmation, change memory/current-memory and vCPU values in the persistent definition of one shut-off remote QEMU/libvirt VM returned by list_remote_virtual_machines. It binds confirmation to the endpoint, domain UUID, full current XML, and requested values; rechecks state after confirmation; validates the updated XML with virsh define --validate; and verifies the saved settings. It does not start the VM. Uses validated qemu+ssh with trusted host keys, no SSH config or agent forwarding, and current remote libvirt permissions without sudo.")
    async def tool_configure_remote_virtual_machine(
        identity_token: str,
        memory_mib: int,
        vcpus: int,
        confirmation: Annotated[
            ElicitationResult[RemoteVirtualMachineConfigConfirmation],
            Resolve(_confirm_remote_virtual_machine_config),
        ],
    ) -> RemoteVirtualMachineConfigResponse:
        if confirmation.action != "accept":
            return RemoteVirtualMachineConfigResponse(
                success=False,
                user_confirmed=False,
                message="The remote VM configuration was not confirmed; no domain definition was changed.",
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_remote_virtual_machine_config,
            identity_token,
            memory_mib,
            vcpus,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="create_virtual_machine", description="After exact client confirmation, define one new stopped local QEMU/libvirt VM with bounded memory/vCPU values, a newly created sparse qcow2 disk in an existing persistent running directory pool, and optionally one existing persistent libvirt network. The tool uses the host-reported QEMU emulator for the local architecture, validates the generated XML with virsh define --validate, rechecks pool/network/name state, and verifies the resulting configuration. It does not install an OS or start the VM; a partial failure may leave the new disk for inspection. Uses fixed qemu:///system or qemu:///session URIs and current-account libvirt permissions without sudo.")
    async def tool_create_virtual_machine(
        scope: Literal["system", "session"],
        name: str,
        memory_mib: int,
        vcpus: int,
        pool_name: str,
        disk_volume_name: str,
        disk_capacity_bytes: int,
        confirmation: Annotated[
            ElicitationResult[VirtualMachineCreateConfirmation],
            Resolve(_confirm_virtual_machine_create),
        ],
        network_name: str = "",
    ) -> VirtualMachineCreateResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_virtual_machine_create,
                scope,
                name,
                memory_mib,
                vcpus,
                pool_name,
                disk_volume_name,
                disk_capacity_bytes,
                network_name,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_virtual_machine_create,
            scope,
            name,
            memory_mib,
            vcpus,
            pool_name,
            disk_volume_name,
            disk_capacity_bytes,
            network_name,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="configure_virtual_machine", description="After exact client confirmation, change memory/current-memory and vCPU values in the persistent definition of one shut-off local QEMU/libvirt VM returned by list_virtual_machines. It binds confirmation to the exact domain UUID, full current XML, and requested values; rechecks state after confirmation; validates the updated XML with virsh define --validate; and verifies the saved settings. It does not start the VM. Uses fixed local QEMU system/session URIs and current-account libvirt permissions without sudo.")
    async def tool_configure_virtual_machine(
        identity_token: str,
        memory_mib: int,
        vcpus: int,
        confirmation: Annotated[
            ElicitationResult[VirtualMachineConfigConfirmation],
            Resolve(_confirm_virtual_machine_config),
        ],
    ) -> VirtualMachineConfigResponse:
        if confirmation.action != "accept":
            return VirtualMachineConfigResponse(
                success=False,
                user_confirmed=False,
                message="The local VM configuration was not confirmed; no domain definition was changed.",
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_virtual_machine_config,
            identity_token,
            memory_mib,
            vcpus,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="attach_virtual_machine_disk", description="After exact client confirmation, attach one existing raw/qcow2 volume from a persistent running local directory pool to an unused virtio disk slot in one shut-off local QEMU/libvirt VM. It revalidates VM, pool, volume and local disk-reference state, updates only persistent configuration, verifies the saved definition, and never formats or starts the disk or VM. Uses fixed local URIs and current-account libvirt permissions without sudo.")
    async def tool_attach_virtual_machine_disk(
        identity_token: str,
        pool_name: str,
        volume_name: str,
        disk_target: str,
        confirmation: Annotated[
            ElicitationResult[VirtualMachineDiskAttachConfirmation],
            Resolve(_confirm_virtual_machine_disk_attach),
        ],
    ) -> VirtualMachineDiskAttachResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_virtual_machine_disk_attach,
                identity_token,
                pool_name,
                volume_name,
                disk_target,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_virtual_machine_disk_attach,
            identity_token,
            pool_name,
            volume_name,
            disk_target,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="list_virtual_machine_snapshots", description="List a bounded snapshot-name inventory for one exact local libvirt VM. Requires the short-lived identity_token from list_virtual_machines, rechecks the VM identity/state, and uses only fixed local QEMU system/session URIs. Snapshot actions require a complete inventory and a fresh VM identity token.")
    def tool_list_virtual_machine_snapshots(
        identity_token: str,
        limit: int = 100,
    ) -> VirtualMachineSnapshotListResponse:
        return _list_virtual_machine_snapshots(identity_token=identity_token, limit=limit)

    @tool(name="manage_virtual_machine_snapshot", description="After explicit client confirmation, create a disk snapshot for one shut-off local libvirt VM, revert to one exact snapshot, or delete one exact leaf snapshot. Requires the short-lived identity_token from list_virtual_machines and revalidates the complete bounded snapshot inventory and selected snapshot metadata. Reversion can discard later guest changes and resume a saved running state; deletion is limited to leaves so child snapshots are never merged. Uses fixed local QEMU system/session URIs and current-account permissions without sudo.")
    async def tool_manage_virtual_machine_snapshot(
        action: VirtualMachineSnapshotActionName,
        identity_token: str,
        snapshot_name: str,
        confirmation: Annotated[
            ElicitationResult[VirtualMachineSnapshotActionConfirmation],
            Resolve(_confirm_virtual_machine_snapshot_action),
        ],
        description: str = "",
    ) -> VirtualMachineSnapshotActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_virtual_machine_snapshot_action,
                action,
                identity_token,
                snapshot_name,
                description,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_virtual_machine_snapshot_action,
            action,
            identity_token,
            snapshot_name,
            description,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="list_journal_entries", description="Read a bounded recent systemd journal snapshot. Supports system or user scope, current/recent boot offsets, exact unit filters, a numeric priority threshold from 0 through 7, and bounded text search. Log visibility depends on host permissions.")
    def tool_list_journal_entries(
        query: str = "",
        limit: int = 50,
        scope: Literal["system", "user"] = "system",
        boot_offset: int = 0,
        unit: str = "",
        priority: int | None = None,
    ) -> JournalEntryListResponse:
        return _list_journal_entries(
            query=query,
            limit=limit,
            scope=scope,
            boot_offset=boot_offset,
            unit=unit,
            priority=priority,
        )

    @tool(name="list_system_log_entries", description="Read a bounded snapshot from one fixed /var/log source: syslog, messages, kern, dmesg, auth, or secure. Supports bounded text search. Source files and permissions vary by distribution; authentication logs may contain usernames, client addresses, and command details. Arbitrary paths and rotated archives are not accepted.")
    def tool_list_system_log_entries(
        source: SystemLogSource,
        query: str = "",
        limit: int = 50,
    ) -> SystemLogListResponse:
        return _list_system_log_entries(source=source, query=query, limit=limit)

    @tool(name="list_boot_targets", description="List installed and loaded systemd target units, their runtime state, and the configured default target. Read-only and systemd-specific.")
    def tool_list_boot_targets(query: str = "", limit: int = 100) -> BootTargetListResponse:
        return _list_boot_targets(query=query, limit=limit)

    @tool(name="get_time_settings", description="Read fixed systemd timedated fields for the system timezone, RTC-local mode, NTP support/enabled/synchronized state, and current system/RTC timestamps. Read-only; requires timedatectl and systemd.")
    def tool_get_time_settings() -> TimeSettingsResponse:
        return _get_time_settings()

    @tool(name="get_time_sync_status", description="Read bounded status details and current source information from available chrony and systemd-timesyncd clients. Uses chronyc tracking/sources and timedatectl show-timesync with fixed arguments; optional providers may be installed but inactive or unreadable under current permissions. Read-only; hostnames, IP addresses, and synchronization metrics may be returned.")
    def tool_get_time_sync_status() -> TimeSyncStatusResponse:
        return _get_time_sync_status()

    @tool(name="list_time_zones", description="List bounded timezone identifiers reported by local systemd timedatectl. Supports substring filtering and offset/limit paging; does not change the active timezone.")
    def tool_list_time_zones(query: str = "", offset: int = 0, limit: int = 100) -> TimeZoneListResponse:
        return _list_time_zones(query=query, offset=offset, limit=limit)

    @tool(name="manage_time_settings", description="After explicit client confirmation, set one exact timezone returned by list_time_zones or enable/disable network time synchronization. For set_timezone pass the timezone and null ntp_enabled; for set_ntp pass null timezone and a boolean ntp_enabled. Confirmation is bound to the requested action and current time state. timedatectl uses --no-ask-password and does not invoke sudo; timedated and local authorization policy determine whether the current account may act. Changing timezone updates /etc/localtime and may update the RTC if it uses local time; NTP changes start/stop available synchronization services and may adjust the clock as synchronization proceeds. Direct system clock setting and RTC-mode changes are not supported.")
    async def tool_manage_time_settings(
        action: TimeActionName,
        timezone: str | None,
        ntp_enabled: bool | None,
        confirmation: Annotated[
            ElicitationResult[TimeSettingsActionConfirmation],
            Resolve(_confirm_time_settings_action),
        ],
    ) -> TimeActionResponse:
        if confirmation.action != "accept":
            return TimeActionResponse(
                success=False,
                action=action,
                timezone=timezone,
                ntp_enabled=ntp_enabled,
                user_confirmed=False,
                message=f"Time configuration action was {confirmation.action}; no command was run.",
            )
        data = confirmation.data
        if not data.confirm:
            return TimeActionResponse(
                success=False,
                action=action,
                timezone=timezone,
                ntp_enabled=ntp_enabled,
                user_confirmed=False,
                message="Confirmation was not affirmative; no command was run.",
            )
        if data.action != action or data.timezone != timezone or data.ntp_enabled != ntp_enabled:
            return TimeActionResponse(
                success=False,
                action=action,
                timezone=timezone,
                ntp_enabled=ntp_enabled,
                user_confirmed=False,
                message="Confirmation did not match the exact time action and target; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_time_action,
            action,
            timezone,
            ntp_enabled,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="list_local_users", description="List bounded local /etc/passwd account names, UIDs, and primary GIDs. Does not expose password fields, home paths, or login shells; NSS and remote identity sources are not queried.")
    def tool_list_local_users(query: str = "", limit: int = 100) -> LocalUserListResponse:
        return _list_local_users(query=query, limit=limit)

    @tool(name="list_local_groups", description="List bounded local /etc/group names, GIDs, and member names. NSS and remote identity sources are not queried.")
    def tool_list_local_groups(query: str = "", limit: int = 100) -> LocalGroupListResponse:
        return _list_local_groups(query=query, limit=limit)

    @tool(name="lookup_nss_identity", description="Resolve one exact user or group name/numeric ID through the configured system NSS stack, which may include remote directory services. Does not enumerate identities; password, GECOS, home-directory, and shell fields are omitted.")
    def tool_lookup_nss_identity(kind: Literal["user", "group"], identity: str) -> NSSIdentityLookupResponse:
        return _lookup_nss_identity(kind=kind, identity=identity)

    @tool(name="manage_local_identity", description="After exact client confirmation, create/delete a local user or group, lock/unlock an existing local user's password, set one shell from /etc/shells, move an existing home directory, or add/remove secondary group membership. For action=move_home, supply the exact new absolute path in home_directory. For action=delete_user, remove_home defaults to false; when true, the existing user-owned home beneath /home or /var/home is removed only after the account is deleted, with a 20,000-entry/256-level tree limit, path/tree revalidation, and mounted-tree refusal. Group membership may grant privileges defined by host policy, including sudo-equivalent access. Unlock requires a currently locked account with a usable local password hash and does not set or reveal a password. New users require an existing primary group, use nologin by default, and start password-locked; create_home optionally creates the exact HOME path reported by useradd defaults from /etc/skel. Home moves require a real existing user-owned home beneath /home or /var/home, a new destination beneath one of those bases, no nested mounts, and no running processes; usermod preserves ACL/xattrs where possible and may need manual adjustment after cross-filesystem moves. User deletion uses no force; host USERGROUPS_ENAB may also remove an empty same-name private group. Configured USERDEL_CMD or shadow-utils lifecycle hooks cause deletion/actions to be refused. Empty-group deletion only. Password and public SSH key changes use separate confirmed tools. `manage_sudo_policy` and `manage_sudo_group_policy` provide constrained exact-command user/group rules; group-rule membership follows the host sudo/NSS configuration. PAM changes are limited to Debian-style `pam-auth-update` profiles, and SSSD control only enables or disables an existing domain. Direct PAM stack editing and broader SSSD provider/domain configuration are not exposed. Uses current OS permissions without sudo.")
    async def tool_manage_local_identity(
        action: LocalIdentityActionName,
        confirmation: Annotated[
            ElicitationResult[LocalIdentityActionConfirmation],
            Resolve(_confirm_local_identity_action),
        ],
        username: str | None = None,
        group_name: str | None = None,
        login_shell: str | None = None,
        create_home: bool = False,
        home_directory: Annotated[
            str | None,
            PydanticField(description="For action=move_home, the exact new absolute home path beneath /home or /var/home; omit for all other actions."),
        ] = None,
        remove_home: Annotated[
            bool,
            PydanticField(description="For action=delete_user, recursively remove the existing user-owned home tree beneath /home or /var/home after deleting the account. Defaults to false."),
        ] = False,
    ) -> LocalIdentityActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_local_identity_action,
                action,
                username,
                group_name,
                login_shell,
                create_home,
                home_directory,
                remove_home,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_local_identity_action,
            action,
            username,
            group_name,
            login_shell,
            create_home,
            home_directory,
            remove_home,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="set_local_user_password", description="After explicit confirmation, set a new password for one exact existing local account, including root. The password is a SecretStr input and is supplied to chpasswd through stdin, never argv or the confirmation prompt. Uses local shadow-utils/PAM policy and current OS permissions without sudo. Password aging may update; a pre-existing password lock is preserved. The response does not expose password or hash values.")
    async def tool_set_local_user_password(
        username: str,
        password: Annotated[
            SecretStr,
            PydanticField(description="New password for the exact local account, including root; kept out of the confirmation prompt and command arguments."),
        ],
        confirmation: Annotated[
            ElicitationResult[LocalPasswordSetConfirmation],
            Resolve(_confirm_local_password_set),
        ],
    ) -> LocalPasswordSetResponse:
        secret = password.get_secret_value()
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_local_password_set,
                username,
                secret,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_local_password_set,
            username,
            secret,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="manage_local_ssh_key", description="After explicit confirmation, add or remove one exact OpenSSH public key in a local account's ~/.ssh/authorized_keys file. Accepts a plain public key line, validates it with ssh-keygen, shows its SHA256 fingerprint in the prompt, and binds confirmation to local account/home/file identity. Existing unrelated keys are preserved; this does not change sshd configuration or guarantee SSH access. Root keys may enable root SSH login when sshd permits it. Uses current OS permissions without sudo.")
    async def tool_manage_local_ssh_key(
        action: SSHKeyActionName,
        username: str,
        public_key: str,
        confirmation: Annotated[
            ElicitationResult[LocalSSHKeyActionConfirmation],
            Resolve(_confirm_local_ssh_key_action),
        ],
    ) -> LocalSSHKeyActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_local_ssh_key_action,
                action,
                username,
                public_key,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_local_ssh_key_action,
            action,
            username,
            public_key,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="manage_sudo_policy", description="After explicit confirmation, grant or revoke one local user's sudoers rule for an exact root-owned executable and exact argument string. The generated rule carries the PASSWD tag, and arguments cannot use sudoers wildcards. Other matching host rules or the exempt_group setting may affect effective authentication. The managed /etc/sudoers.d drop-in is mode 0440 and validated with visudo before and after changes. The server must already run as root; the tool never invokes sudo or writes NOPASSWD. A permitted executable may still provide broad root capability.")
    async def tool_manage_sudo_policy(
        action: SudoPolicyActionName,
        username: str,
        command_path: str,
        confirmation: Annotated[
            ElicitationResult[SudoPolicyActionConfirmation],
            Resolve(_confirm_sudo_policy_action),
        ],
        arguments: str = "",
    ) -> SudoPolicyActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_sudo_policy_action,
                action,
                username,
                command_path,
                arguments,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_sudo_policy_action,
            action,
            username,
            command_path,
            arguments,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="manage_sudo_group_policy", description="After explicit confirmation, grant or revoke one local group's sudoers rule for an exact root-owned executable and exact literal argument string. Any account sudo resolves as a member of the group may receive the PASSWD-tagged rule; host NSS/group configuration determines membership. Arguments cannot use sudoers wildcards. The generated /etc/sudoers.d drop-in is mode 0440 and validated with visudo before and after changes. The server must already run as root and does not invoke sudo or write NOPASSWD. Other matching host rules and Defaults exempt_group can affect effective authentication; the executable may provide broad root capability.")
    async def tool_manage_sudo_group_policy(
        action: SudoPolicyActionName,
        group_name: str,
        command_path: str,
        confirmation: Annotated[
            ElicitationResult[SudoPolicyActionConfirmation],
            Resolve(_confirm_sudo_group_policy_action),
        ],
        arguments: str = "",
    ) -> SudoPolicyActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_sudo_policy_action,
                action,
                None,
                command_path,
                arguments,
                "",
                confirmed=False,
                group_name=group_name,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_sudo_policy_action,
            action,
            None,
            command_path,
            arguments,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
            group_name=group_name,
        )

    @tool(name="list_sssd_domains", description="Read the existing SSSD [domain/NAME] sections and whether each name appears in [sssd] domains. Reports names only, omits all provider settings and credentials, and refuses SSSD conf.d snippets because they can override the main file.")
    def tool_list_sssd_domains() -> SSSDDomainListResponse:
        return _list_sssd_domains()

    @tool(name="manage_sssd_domain", description="After exact client confirmation, enable or disable one already configured SSSD domain by changing only its membership in [sssd] domains. The existing [domain/NAME] settings and PAM stack are untouched; disabling can remove remote identities and prevent remote logins. The candidate is checked with sssctl config-check, requires the MCP server to already run as root, refuses conf.d snippets and disabling the last enabled domain, and does not request a service restart.")
    async def tool_manage_sssd_domain(
        action: SSSDDomainActionName,
        domain: str,
        confirmation: Annotated[
            ElicitationResult[SSSDDomainActionConfirmation],
            Resolve(_confirm_sssd_domain_action),
        ],
    ) -> SSSDDomainActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_sssd_domain_action,
                action,
                domain,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_sssd_domain_action,
            action,
            domain,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="list_pam_profiles", description="List package-supplied PAM profiles from /usr/share/pam-configs with their debconf selection state, default flag, priority, and affected PAM stack types. It omits profile contents and arguments; selection state does not prove local common-* files match the generated stack.")
    def tool_list_pam_profiles() -> PAMProfileListResponse:
        return _list_pam_profiles()

    @tool(name="manage_pam_profile", description="After exact client confirmation, enable or disable one existing package-supplied PAM profile through pam-auth-update. This changes system-wide authentication/session policy and can prevent logins. It requires the MCP server to already run as root, uses no --force and does not edit PAM stack files directly; local edits may be preserved or make pam-auth-update refuse regeneration. Keep the current session open and verify a separate login.")
    async def tool_manage_pam_profile(
        action: PAMProfileActionName,
        profile: str,
        confirmation: Annotated[
            ElicitationResult[PAMProfileActionConfirmation],
            Resolve(_confirm_pam_profile_action),
        ],
    ) -> PAMProfileActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_pam_profile_action,
                action,
                profile,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_pam_profile_action,
            action,
            profile,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="list_login_sessions", description="List bounded logind session IDs, UIDs, usernames, seats, TTYs, states, and idle flags. Omits process IDs and remote host details; availability depends on loginctl and host session visibility.")
    def tool_list_login_sessions(query: str = "", limit: int = 50) -> LoginSessionListResponse:
        return _list_login_sessions(query=query, limit=limit)

    @tool(name="list_block_devices", description="List bounded Linux block-device names, capacity, partition status, removable/read-only flags, rotational status, and logical block size from sysfs. No device serials or storage changes are exposed.")
    def tool_list_block_devices(query: str = "", limit: int = 100) -> BlockDeviceListResponse:
        return _list_block_devices(query=query, limit=limit)

    @tool(name="list_storage_topology", description="Read bounded active block-device component/holder relationships from sysfs, including mapper names and selected MD RAID metadata such as current sync action, completed/total sectors, and mismatch sectors when exposed. The kernel mismatch count is sectors rewritten or that would have been rewritten, not distinct corrupt blocks. Device-mapper UUIDs, serials, and loop backing paths are omitted. This tool is read-only and performs no storage changes.")
    def tool_list_storage_topology(query: str = "", limit: int = 100) -> StorageTopologyResponse:
        return _list_storage_topology(query=query, limit=limit)

    @tool(name="list_lvm_inventory", description="Read bounded LVM2 volume-group and logical-volume reports using fixed vgs/lvs fields and --readonly. Returns byte capacity, free/total extent counts, logical-volume layout, origin/pool relations, and optional data/metadata percentages. Physical-volume device paths and UUIDs are omitted; LVM read-only mode cannot report active/in-use state. No storage is changed.")
    def tool_list_lvm_inventory(query: str = "", limit: int = 100) -> LVMInventoryResponse:
        return _list_lvm_inventory(query=query, limit=limit)

    @tool(name="list_btrfs_snapshots", description="List bounded Btrfs local and received snapshots under one explicit mounted top-level subvolume (ID 5). Returns exact paths, subvolume IDs, UUID lineage, generation, and read-only state. An optional case-insensitive substring query matches relative paths or UUIDs; use offset/limit to page results. Requires btrfs-progs and current OS read permissions; nested snapshots are listed independently, and no storage is changed.")
    def tool_list_btrfs_snapshots(
        filesystem_top_level_path: str,
        query: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> BtrfsSnapshotListResponse:
        return _list_btrfs_snapshots(
            filesystem_top_level_path=filesystem_top_level_path,
            query=query,
            limit=limit,
            offset=offset,
        )

    @tool(name="manage_lvm_volume_group", description="After exact client confirmation, create a new LVM volume group, add blank PVs to an existing group, remove exact unused PVs, or atomically move all allocated extents between two exact PVs in one group (pass `physical_device_paths=[source, destination]` in that order for `move_pv`). PV migration requires destination free extents of at least twice the source allocation, uses pvmove --atomic, and can run for up to 30 minutes; if interrupted, inspect LVM state before retrying. Creation/extension initializes blank devices and writes LVM metadata; removal changes group membership but leaves PV labels in place. New PVs refuse recognized signatures, mounted/swap devices, active holders, whole disks with child partitions, and duplicate identities; active LV holders are allowed for migration. New-group creation limits selection to one PV per physical disk; existing groups may use multiple PVs on one disk. The exact group/PV inventory, allocated extents, and block-device identities are revalidated, then membership or migration results are verified. It does not invoke privilege elevation; current OS permissions determine whether it can proceed.")
    async def tool_manage_lvm_volume_group(
        volume_group: str,
        physical_device_paths: list[str],
        confirmation: Annotated[
            ElicitationResult[LVMVolumeGroupActionConfirmation],
            Resolve(_confirm_lvm_group_action),
        ],
        action: LVMVolumeGroupActionName = "create",
    ) -> LVMVolumeGroupActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_lvm_group_action,
                action,
                volume_group,
                physical_device_paths,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_lvm_group_action,
            action,
            volume_group,
            physical_device_paths,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_lvm_volume", description="After exact client confirmation, create/grow/shrink one logical volume, create/remove one LVM snapshot, or restore one exact classic copy-on-write snapshot into its exact origin. Snapshot restore requires snapshot_origin, an already-root server, lvconvert, dmsetup, and fuser; both LV devices must be active but closed, unmounted, not swap, have zero device-mapper open count, and have no unrelated holders. The classic COW snapshot must be healthy and have a known data percentage below 100. It merges the snapshot into the origin, removes the snapshot LV, and overwrites origin changes made after the snapshot; thin, invalid, partial, merging, full, or unknown-capacity snapshots, physical-volume moves, and state that cannot be checked are refused. A concurrent external open can still defer the merge, which the tool reports if the snapshot remains. Growth changes only the LV. Shrink supports only linear raw LVs without signatures or verified ext4 LVs; ext4 must be unmounted and is resized with lvreduce --resizefs before the LV reduction. Shrink refuses XFS, other signatures, snapshots, thin/striped/RAID layouts, held/mounted/swapped volumes, open block-device users, and non-root requests. Raw LV shrink discards data in the removed tail; any failed filesystem shrink prevents LV reduction. LVM state, snapshot/origin use state, filesystem size, and active-use state are revalidated after confirmation; commands use current OS permissions without sudo.")
    async def tool_manage_lvm_volume(
        action: LVMVolumeActionName,
        volume_group: str,
        logical_volume: str,
        confirmation: Annotated[
            ElicitationResult[LVMVolumeActionConfirmation],
            Resolve(_confirm_lvm_volume_action),
        ],
        size_bytes: int | None = None,
        snapshot_origin: str | None = None,
    ) -> LVMVolumeActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_lvm_volume_action,
                action,
                volume_group,
                logical_volume,
                size_bytes,
                snapshot_origin,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_lvm_volume_action,
            action,
            volume_group,
            logical_volume,
            size_bytes,
            snapshot_origin,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="list_luks_tokens", description="List LUKS2 token IDs, escaped and bounded type labels, active keyslot bindings, and active keyslots for one exact block device. Token JSON payloads and provider-specific fields are never returned. Requires the local cryptsetup command.")
    def tool_list_luks_tokens(device_path: str) -> LUKSTokenListResponse:
        return _list_luks_tokens(device_path=device_path)

    @tool(name="manage_luks_token", description="After exact client confirmation, remove one LUKS2 token, unassign one binding, import a token from a private JSON file into an unused ID, or export one token to a new private mode-0600 file. Import never replaces an existing ID; token JSON is never included in prompts or returned to this client. Revalidates device/header/executable and relevant file identities, then verifies the exact metadata change. Cryptsetup external-token plugin loading is disabled for token actions. Export files may contain sensitive provider metadata. Uses current OS permissions without sudo or interactive elevation.")
    async def tool_manage_luks_token(
        action: LUKSTokenActionName,
        device_path: str,
        token_id: Annotated[int, PydanticField(ge=0, le=31, description="LUKS2 token ID from 0 through 31")],
        confirmation: Annotated[
            ElicitationResult[LUKSTokenActionConfirmation],
            Resolve(_confirm_luks_token_action),
        ],
        key_slot: Annotated[int | None, PydanticField(ge=0, le=31, description="Keyslot to unassign from the selected token; used only for unassign")] = None,
        token_json_file: Annotated[str | None, PydanticField(description="For import, an existing server-owned mode-0600-or-stricter UTF-8 token JSON file no larger than 4 MiB")] = None,
        export_file: Annotated[str | None, PydanticField(description="For export, a new absolute output path; the file is created privately with mode 0600 and is never overwritten")] = None,
    ) -> LUKSTokenActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_luks_token_action,
                action,
                device_path,
                token_id,
                key_slot,
                token_json_file,
                export_file,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_luks_token_action,
            action,
            device_path,
            token_id,
            key_slot,
            token_json_file,
            export_file,
            confirmed=True,
            confirmation_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="manage_luks_mapping", description="After exact client confirmation, format one verified blank block device as LUKS1/LUKS2, open/close/grow one exact mapping, add a key from a separate private file, or remove one exact active keyslot while refusing to remove the last active slot or a LUKS2 slot referenced by a token. Use manage_luks_token to inventory, remove, unassign, import, or export LUKS2 tokens. luks_version defaults to luks2. Formatting refuses signatures, mounted/swap devices, holders, backing layers, and whole devices with child partitions. Key actions require existing private key files owned by the server identity with mode 0600 or stricter; contents are not shown in the prompt or argv. Mapping close is never forced; resize changes only mapped block size. State is revalidated, and no sudo or interactive elevation is used.")
    async def tool_manage_luks_mapping(
        action: LUKSActionName,
        device_path: str,
        confirmation: Annotated[
            ElicitationResult[LUKSActionConfirmation],
            Resolve(_confirm_luks_action),
        ],
        mapping_name: str | None = None,
        key_file: str | None = None,
        luks_version: LUKSVersionName = "luks2",
        new_key_file: str | None = None,
        key_slot: int | None = None,
    ) -> LUKSActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_luks_action,
                action,
                device_path,
                mapping_name,
                key_file,
                luks_version,
                new_key_file,
                key_slot,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_luks_action,
            action,
            device_path,
            mapping_name,
            key_file,
            luks_version,
            new_key_file,
            key_slot,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_luks_header", description="After exact client confirmation, create a private LUKS1/LUKS2 header backup without overwriting an existing path, or restore one exact verified backup to an unmounted, unused block device. Backups contain the header and keyslot area and may make credentials valid at backup time usable later; protect and securely erase them appropriately. Restore replaces all current keyslots and LUKS2 token metadata, so credentials changed after the backup may stop working. Restore requires an explicit expected_luks_uuid when the target has no recognized current LUKS header. The backup file must be a private server-owned regular file; identity, digest, device state, UUID, version, and keyslot/token inventories are revalidated. Cryptsetup compatibility checks remain authoritative. Commands use current OS permissions without sudo or interactive elevation.")
    async def tool_manage_luks_header(
        action: LUKSHeaderActionName,
        device_path: str,
        backup_file: str,
        confirmation: Annotated[
            ElicitationResult[LUKSHeaderActionConfirmation],
            Resolve(_confirm_luks_header_action),
        ],
        expected_luks_uuid: str | None = None,
    ) -> LUKSHeaderActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_luks_header_action,
                action,
                device_path,
                backup_file,
                expected_luks_uuid,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_luks_header_action,
            action,
            device_path,
            backup_file,
            expected_luks_uuid,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_ext4_filesystem", description="After exact client confirmation, create ext4 on one verified blank block device, grow an existing ext4 filesystem, or shrink an unmounted ext4 filesystem to an exact target_size_bytes. Shrinking refuses mounted, swap, or held devices; requires read-only e2fsck checks to report clean before and after; never repairs errors or changes the underlying block device; resize2fs may reject a target that is too small; timeout is one hour. Creation refuses recognized signatures, mounted/swap devices, holders, and whole devices with child partitions. Filesystem and device state are revalidated; commands use current OS permissions without sudo or interactive elevation.")
    async def tool_manage_ext4_filesystem(
        action: Ext4FilesystemActionName,
        device_path: str,
        confirmation: Annotated[
            ElicitationResult[Ext4FilesystemActionConfirmation],
            Resolve(_confirm_ext4_action),
        ],
        target_size_bytes: int | None = None,
    ) -> Ext4FilesystemActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_ext4_action,
                action,
                device_path,
                target_size_bytes=target_size_bytes,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_ext4_action,
            action,
            device_path,
            target_size_bytes=target_size_bytes,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_btrfs_filesystem", description="After exact client confirmation, create a single-device Btrfs filesystem on one verified unused block device, grow one mounted filesystem after backing-device expansion, or shrink one mounted filesystem to an explicit target_size_bytes value. Shrinking requires the server to already run as root, checks Btrfs's minimum size and sector alignment, can relocate data and cause heavy I/O, may fail if an active swapfile overlaps the target region, runs for up to one hour, and changes only the filesystem layer; any later partition/LVM/LUKS/device reduction is separate. Creation refuses recognized signatures, mounted/swap devices, holders, and whole devices with child partitions; it never forces formatting, though arbitrary raw data can still be present. Multi-device filesystems are refused. Device identity, mount state, and filesystem geometry are revalidated. Uses current OS permissions without sudo or interactive elevation.")
    async def tool_manage_btrfs_filesystem(
        action: BtrfsFilesystemActionName,
        target_path: str,
        confirmation: Annotated[
            ElicitationResult[BtrfsFilesystemActionConfirmation],
            Resolve(_confirm_btrfs_filesystem_action),
        ],
        target_size_bytes: int | None = None,
    ) -> BtrfsFilesystemActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_btrfs_filesystem_action,
                action,
                target_path,
                target_size_bytes=target_size_bytes,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_btrfs_filesystem_action,
            action,
            target_path,
            target_size_bytes=target_size_bytes,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_xfs_filesystem", description="After exact client confirmation, create a basic XFS filesystem on one block device with no recognized signatures or grow a mounted XFS filesystem without a real-time section to the block device's available size. Creation refuses recognized signatures, mounted/swap devices, holders, and whole devices with child partitions; raw data may still be present, and mkfs.xfs is not forced over existing signatures. Growth is online-only, requires one writable mountpoint in the current namespace, and XFS cannot be shrunk. Device identity and filesystem geometry are revalidated; uses current OS permissions without sudo or interactive elevation.")
    async def tool_manage_xfs_filesystem(
        action: XFSFilesystemActionName,
        device_path: str,
        confirmation: Annotated[
            ElicitationResult[XFSFilesystemActionConfirmation],
            Resolve(_confirm_xfs_action),
        ],
    ) -> XFSFilesystemActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_xfs_action,
                action,
                device_path,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_xfs_action,
            action,
            device_path,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_md_raid", description="After exact client confirmation, create and activate a Linux MD RAID0, RAID1, RAID4, RAID5, RAID6, or RAID10 array on up to 16 verified block devices; assemble one complete, clean, non-degraded native version-1 array from every exact active component in read-only mode by default (set read_only=false to request read-write assembly); add a blank spare; remove an exact inactive spare; replace one healthy active member; mark one exact healthy active member faulty; remove one exact member already marked faulty; start a non-repairing consistency check on one healthy idle redundant array; or stop one exact idle read-write array when it is unmounted, unused by swap, and has no block-layer holders. For action=check or stop, pass device_paths=[]. Assembly refuses stale or dirty components, duplicate/missing roles, spares, reshape/recovery metadata, and external or legacy metadata; it never scans, forces, or starts a degraded array. Read-only assembly does not start resync/recovery/reshape writes. Read-write assembly can update MD metadata; later filesystem or application writes can modify member data. A stopped array is unavailable until assembled again; member data is not erased and RAID metadata is not removed. The check reads all array blocks and records mismatches without correcting them; read errors can still trigger normal MD recovery writes. It runs in the background and may take hours. RAID4 uses one dedicated parity member. Failure marking requires a healthy, idle, non-degraded redundant array; it can reduce redundancy and trigger recovery onto an existing spare. Faulty-member removal requires an active idle array and never erases member metadata. Replacement adds a blank device on a separate physical disk and starts recovery while the old member remains in service. RAID4 and RAID5 require at least 3 devices and RAID6 at least 4; RAID0, RAID4, RAID5, RAID6, and RAID10 use the confirmed 512 KiB default chunk unless a supported chunk is specified, while RAID1 does not use chunks. Creation refuses recognized signatures, mounted/swap devices, holders, read-only devices, whole disks with partitions, and multiple members on the same physical disk; it does not erase signatures or reshape arrays, and boot-time assembly configuration remains unavailable. Array/member state is revalidated and verified; uses current-user permissions without sudo.")
    async def tool_manage_md_raid(
        action: MDRaidActionName,
        array_path: str,
        device_paths: list[str],
        confirmation: Annotated[
            ElicitationResult[MDRaidActionConfirmation],
            Resolve(_confirm_md_raid_action),
        ],
        raid_level: Literal["raid0", "raid1", "raid4", "raid5", "raid6", "raid10"] | None = None,
        chunk_size_kib: int | None = None,
        read_only: bool = True,
    ) -> MDRaidActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_md_raid_action,
                action,
                array_path,
                device_paths,
                raid_level,
                chunk_size_kib,
                read_only,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_md_raid_action,
            action,
            array_path,
            device_paths,
            raid_level,
            chunk_size_kib,
            read_only,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_btrfs_snapshot", description="After exact client confirmation, create a read-write/read-only Btrfs snapshot, delete one exact local/received snapshot, or restore a read-only snapshot into one exact unmounted subvolume. For action=restore, snapshot_path is the read-only source snapshot; provide target_path and a new sibling backup_path. The target must be non-default, unmounted in the current namespace, and have no nested subvolumes. The tool stages a writable snapshot clone, atomically exchanges it with target_path so the target path stays occupied, then moves the original from staging to backup_path without overwriting; it does not change /etc/fstab or the default subvolume. If interrupted between exchange and backup move, the original can remain at staging while the clone occupies the target. A failed operation attempts to put the original target back and reports retained paths. Snapshot creation requires a source subvolume below the mounted top-level path (ID 5) and a new destination. Deletion refuses ordinary subvolumes, the default, mounted snapshots, and snapshots with nested subvolumes. Snapshots share copy-on-write extents, are not independent backups, and do not recursively capture nested subvolumes. Exact paths, UUID lineage, generation, mount state, and filesystem state are revalidated. Uses current OS permissions without sudo or interactive elevation.")
    async def tool_manage_btrfs_snapshot(
        action: BtrfsSnapshotActionName,
        filesystem_top_level_path: str,
        snapshot_path: str,
        confirmation: Annotated[
            ElicitationResult[BtrfsSnapshotActionConfirmation],
            Resolve(_confirm_btrfs_snapshot_action),
        ],
        source_path: str | None = None,
        read_only: bool = False,
        target_path: str | None = None,
        backup_path: str | None = None,
    ) -> BtrfsSnapshotActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_btrfs_snapshot_action,
                action,
                filesystem_top_level_path,
                snapshot_path,
                source_path,
                read_only,
                target_path,
                backup_path,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_btrfs_snapshot_action,
            action,
            filesystem_top_level_path,
            snapshot_path,
            source_path,
            read_only,
            target_path,
            backup_path,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="get_block_device_health", description="Read SMART health for one exact whole-device name from list_block_devices using optional smartctl. Requires current-user access to /dev; ATA/SCSI devices reported in standby are skipped. Other protocols may leave a low-power state. No serials are returned, no self-test is started, and no device settings are changed.")
    def tool_get_block_device_health(name: str) -> BlockDeviceHealthResponse:
        return _get_block_device_health(name=name)

    @tool(name="list_block_device_stats", description="Read bounded cumulative read/write/discard/flush counters from sysfs for block devices. Sector counters use 512-byte sectors; results are snapshots, not rates, and no storage changes are performed.")
    def tool_list_block_device_stats(query: str = "", limit: int = 100) -> BlockDeviceIOStatsResponse:
        return _list_block_device_stats(query=query, limit=limit)

    @tool(name="list_hardware_devices", description="List bounded PCI and USB identifiers, class codes, and driver names plus selected SMBIOS/DMI system, board, chassis, and BIOS fields when exposed. DMI serials, UUIDs, asset tags, modaliases, and raw tables are never queried.")
    def tool_list_hardware_devices(query: str = "", limit: int = 100) -> HardwareDeviceListResponse:
        return _list_hardware_devices(query=query, limit=limit)

    @tool(name="list_udev_devices", description="List bounded Linux udev device records with sysfs path/name, subsystem, device type, attached driver, numeric vendor/product IDs, and device-node major/minor numbers. Serial properties, human-readable labels, device-node symlinks, and arbitrary udev properties are omitted.")
    def tool_list_udev_devices(query: str = "", subsystem: str = "", limit: int = 100) -> UdevDeviceListResponse:
        return _list_udev_devices(query=query, subsystem=subsystem, limit=limit)

    @tool(name="list_sensor_readings", description="Read bounded temperature, fan, voltage, current, power, energy, and humidity inputs from Linux hwmon and thermal sysfs. Values include raw units and normalized units where standardized; some temperature channels and humidity use driver-defined conventions. Thresholds, alarms, and controls are excluded.")
    def tool_list_sensor_readings(query: str = "", limit: int = 100) -> SensorReadingListResponse:
        return _list_sensor_readings(query=query, limit=limit)

    @tool(name="list_fan_controls", description="List Linux hwmon PWM channels with readable values and mode attributes, chip names, optional fan labels, and tachometer RPM. Only channels using the standard PWM interface are included; no values are changed.")
    def tool_list_fan_controls(query: str = "", limit: int = 100) -> FanControlListResponse:
        return _list_fan_controls(query=query, limit=limit)

    @tool(name="manage_fan_control", description="After exact client confirmation, set one exact Linux hwmon PWM channel to manual maximum (255/100%) or return it to automatic mode (pwm_enable=2). A driver may map one PWM channel to multiple fans. Arbitrary lower speeds, fan stops, custom curves, and vendor-specific controls are not exposed. The controller and attribute identities are rechecked; hardware may not follow the request, and an interrupted transition to manual mode can leave the last value active. Verify RPM and temperatures. Uses current OS permissions without sudo or elevation.")
    async def tool_manage_fan_control(
        controller: str,
        pwm_index: int,
        action: FanControlActionName,
        confirmation: Annotated[
            ElicitationResult[FanControlActionConfirmation],
            Resolve(_confirm_fan_control),
        ],
    ) -> FanControlActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_fan_control,
                controller,
                pwm_index,
                action,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_fan_control,
            controller,
            pwm_index,
            action,
            confirmed=True,
            confirmation_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="list_display_backlights", description="List bounded Linux backlight device names and configured/maximum brightness values from /sys/class/backlight. No device paths or hardware identifiers are returned, and this tool does not change brightness.")
    def tool_list_display_backlights() -> DisplayBacklightListResponse:
        return _list_display_backlights()

    @tool(name="manage_display_brightness", description="After exact client confirmation, set one exact Linux display backlight to a value from zero through its reported maximum. The current sysfs device identity and brightness range are bound to confirmation and rechecked before and after the write. Uses current OS permissions without elevation; zero may turn the display dark, and hardware-reported brightness can differ from the configured value.")
    async def tool_manage_display_brightness(
        device_name: str,
        brightness: int,
        confirmation: Annotated[
            ElicitationResult[DisplayBrightnessConfirmation],
            Resolve(_confirm_display_brightness_change),
        ],
    ) -> DisplayBrightnessResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_display_brightness_change,
                device_name,
                brightness,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_display_brightness_change,
            device_name,
            brightness,
            confirmed=True,
            confirmed_device_name=confirmation.data.device_name,
            confirmed_brightness=confirmation.data.brightness,
            confirmed_phrase=confirmation.data.confirmation_phrase,
        )

    @tool(name="list_audio_devices", description="List bounded ALSA sound cards and playback/capture PCM endpoints from procfs. This reports kernel ALSA hardware inventory, not userspace sound-server sinks, volumes, active streams, or audio content.")
    def tool_list_audio_devices(query: str = "", limit: int = 50) -> AudioInventoryResponse:
        return _list_audio_devices(query=query, limit=limit)

    @tool(name="list_audio_server_devices", description="List bounded current-session userspace audio sinks and sources, defaults, and available mute/volume metadata through pactl or wpctl. Endpoints may include network audio tunnels. Active application streams and audio content are excluded; this tool does not change audio settings.")
    def tool_list_audio_server_devices(query: str = "", limit: int = 50) -> AudioServerInventoryResponse:
        return _list_audio_server_devices(query=query, limit=limit)

    @tool(name="manage_audio_endpoint", description="After explicit client confirmation, set the volume, mute state, or default status of one exact current-session userspace sink/source identified by its numeric ID and exact name from list_audio_server_devices; the endpoint may be a network audio tunnel. Volume accepts only an absolute integer percentage from 0 through 100. Revalidates the endpoint and current state after confirmation, uses pactl or wpctl with current-user permissions, and verifies the result; settings affect all clients using that endpoint, and changing the default may redirect new streams.")
    async def tool_manage_audio_endpoint(
        action: AudioActionName,
        direction: AudioDirectionName,
        endpoint_id: str,
        endpoint_name: str,
        confirmation: Annotated[
            ElicitationResult[AudioEndpointActionConfirmation],
            Resolve(_confirm_audio_endpoint_action),
        ],
        volume_percent: int | None = None,
        muted: bool | None = None,
    ) -> AudioEndpointActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return _perform_audio_endpoint_action(
                action=action,
                direction=direction,
                object_id=endpoint_id,
                endpoint_name=endpoint_name,
                expected_state_token="",
                volume_percent=volume_percent,
                muted=muted,
                confirmed=False,
            )
        data = confirmation.data
        if (
            data.action != action
            or data.direction != direction
            or data.endpoint_id != endpoint_id
            or data.endpoint_name != endpoint_name
            or data.volume_percent != volume_percent
            or data.muted != muted
        ):
            return AudioEndpointActionResponse(
                success=False,
                action=action,
                direction=direction,
                endpoint_id=endpoint_id,
                endpoint_name=endpoint_name,
                volume_percent=volume_percent,
                muted=muted,
                user_confirmed=False,
                message="Confirmation did not match the requested audio action and exact endpoint; no setting was changed.",
            )
        return await asyncio.to_thread(
            _perform_audio_endpoint_action,
            action,
            direction,
            endpoint_id,
            endpoint_name,
            data.expected_state_token,
            volume_percent,
            muted,
            confirmed=True,
        )

    @tool(name="list_power_supplies", description="List bounded read-only power-supply type, status, health, battery capacity, charge/energy, voltage/current/power, temperature, and cycle-count snapshots from sysfs. Manufacturer, model, serial number, and writable charge controls are excluded.")
    def tool_list_power_supplies(query: str = "", limit: int = 100) -> PowerSupplyListResponse:
        return _list_power_supplies(query=query, limit=limit)

    @tool(name="get_power_state", description="Read kernel-exported suspend/hibernate choices and selected memory/hibernation modes from fixed /sys/power attributes. Does not request a power transition; use list_power_inhibitors for current logind locks.")
    def tool_get_power_state() -> PowerStateResponse:
        return _get_power_state()

    @tool(name="list_power_inhibitors", description="List active system logind power inhibitors with owner, UID/PID, affected operations, reason, and mode. Does not return command lines or derived process names; this is read-only and does not initiate power actions.")
    def tool_list_power_inhibitors(limit: int = 50) -> PowerInhibitorListResponse:
        return _list_power_inhibitors(limit=limit)

    @tool(name="get_power_profile", description="Read the active and available power-profiles-daemon profiles from powerprofilesctl. Reports profile names only; hardware effects depend on the installed drivers and firmware.")
    def tool_get_power_profile() -> PowerProfileResponse:
        return _get_power_profile()

    @tool(name="manage_power_profile", description="After exact client confirmation, set the system's active power-profiles-daemon profile to one available power-saver, balanced, or performance profile. Binds the current and available profile state, rechecks before the change, and verifies the result. The daemon may adjust CPU or platform power behavior and stores the selected profile for restoration at startup; current OS permissions apply without elevation.")
    async def tool_manage_power_profile(
        requested_profile: PowerProfileName,
        confirmation: Annotated[
            ElicitationResult[PowerProfileConfirmation],
            Resolve(_confirm_power_profile),
        ],
    ) -> PowerProfileActionResponse:
        accepted = confirmation.action == "accept" and confirmation.data.confirm
        return await asyncio.to_thread(
            _perform_power_profile_change,
            requested_profile,
            confirmed=accepted,
            confirmed_phrase=(confirmation.data.confirmation_phrase if accepted else None),
        )

    @tool(name="get_power_action_readiness", description="Query logind's current CanPowerOff/CanReboot/CanSuspend/CanHibernate readiness result for one exact operation, including firmware-setup reboot where supported. Reports support and caller authorization state, not a guarantee that firmware or hardware will complete a transition.")
    def tool_get_power_action_readiness(action: PowerReadinessAction) -> PowerActionReadinessResponse:
        return _get_power_action_readiness(action=action)

    @tool(name="manage_power_action", description="After explicit MCP client confirmation, immediately request one system-wide poweroff, reboot, halt, suspend, hibernate, hybrid sleep, suspend-then-hibernate, or firmware-setup reboot. Uses fixed logind/systemctl operations, current-user permissions, honors logind inhibitor locks, and does not request privilege elevation or interactive polkit authentication.")
    async def tool_manage_power_action(
        action: PowerAction,
        confirmation: Annotated[
            ElicitationResult[PowerActionConfirmation],
            Resolve(_confirm_power_action),
        ],
    ) -> PowerActionResponse:
        if confirmation.action != "accept":
            return PowerActionResponse(
                success=False,
                action=action,
                message=f"Power action was {confirmation.action}; no request was made.",
            )
        if not confirmation.data.confirm:
            return PowerActionResponse(
                success=False,
                action=action,
                message="Confirmation was not affirmative; no power action was requested.",
            )
        return _perform_power_action(action=action, confirmed=True)

    @tool(name="list_printers", description="List bounded configured CUPS queues, their enabled/printing state, job-acceptance state, and the default destination. Does not inspect queued jobs, users, document titles, printer device URIs, or unconfigured network devices.")
    def tool_list_printers(query: str = "", limit: int = 100) -> PrinterListResponse:
        return _list_printers(query=query, limit=limit)

    @tool(name="manage_printer", description="After exact client confirmation, enable/disable one configured CUPS printer queue or allow/reject new job submissions for it. Revalidates the exact queue state before and after the command. Enabling may resume queued jobs; disabling does not pass CUPS's job-cancellation option; rejecting new jobs does not cancel queued jobs. Uses the configured CUPS server and current-user permissions without supplying credentials or requesting elevation.")
    async def tool_manage_printer(
        action: Literal["enable", "disable", "accept", "reject"],
        printer: str,
        confirmation: Annotated[
            ElicitationResult[PrinterActionConfirmation],
            Resolve(_confirm_printer_action),
        ],
    ) -> PrinterActionResponse:
        if confirmation.action != "accept":
            return PrinterActionResponse(
                success=False,
                action=action,
                printer=printer,
                user_confirmed=False,
                message=f"CUPS printer action was {confirmation.action}; no command was run.",
            )
        data = confirmation.data
        if not data.confirm:
            return PrinterActionResponse(
                success=False,
                action=action,
                printer=printer,
                user_confirmed=False,
                message="Confirmation was not affirmative; no CUPS command was run.",
            )
        if data.action != action or data.printer != printer:
            return PrinterActionResponse(
                success=False,
                action=action,
                printer=printer,
                user_confirmed=False,
                message="Confirmation did not match the exact printer queue and action; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_printer_action,
            action,
            printer,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="list_kernel_modules", description="List bounded loaded Linux kernel-module names, sizes, reference counts, and states from procfs. Module addresses and dependency strings are omitted.")
    def tool_list_kernel_modules(query: str = "", limit: int = 100) -> KernelModuleListResponse:
        return _list_kernel_modules(query=query, limit=limit)

    @tool(name="manage_kernel_module", description="After exact confirmation, load one exact installed kernel module with modprobe --ignore-install or unload one exact live, unreferenced module with rmmod. Built-in modules and modules with active references or dependent holders are refused. Loading can also load dependencies; changes are runtime-only and do not configure startup. Uses current OS permissions without sudo.")
    async def tool_manage_kernel_module(
        action: KernelModuleActionName,
        module: str,
        confirmation: Annotated[
            ElicitationResult[KernelModuleActionConfirmation],
            Resolve(_confirm_kernel_module_action),
        ],
    ) -> KernelModuleActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_kernel_module_action,
                action,
                module,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_kernel_module_action,
            action,
            module,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_kernel_module_startup", description="After exact client confirmation, add or remove one generated system-wide modules-load.d entry for an exact installed kernel module in the current kernel's module tree. It refuses to overwrite a file, shadow a same-named config, or duplicate an exact module entry in the standard modules-load.d directories. This changes future boot configuration only; enabling does not load the module now, and disabling does not unload a module already in use. Uses current OS permissions without privilege elevation.")
    async def tool_manage_kernel_module_startup(
        action: KernelModuleStartupActionName,
        module: str,
        confirmation: Annotated[
            ElicitationResult[KernelModuleStartupConfirmation],
            Resolve(_confirm_kernel_module_startup_action),
        ],
    ) -> KernelModuleStartupResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_kernel_module_startup_action,
                action,
                module,
                confirmed=False,
            )
        data = confirmation.data
        if (
            data.action != action
            or data.module != module
        ):
            return KernelModuleStartupResponse(
                success=False,
                action=action,
                module=module,
                user_confirmed=False,
                message="Confirmation did not match the exact kernel-module startup request; no file was changed.",
            )
        return await asyncio.to_thread(
            _perform_kernel_module_startup_action,
            action,
            module,
            confirmed=data.confirm is True,
            confirmed_action=data.action,
            confirmed_module=data.module,
            confirmation_phrase=data.confirmation_phrase,
            expected_state_token=data.expected_state_token,
        )

    @tool(name="list_kernel_parameters", description="List a fixed allowlist of current integer runtime sysctl values: vm.swappiness, vm.vfs_cache_pressure, fs.inotify.max_user_instances, and fs.inotify.max_user_watches. Returns short-lived identity tokens and allowed change ranges. This reads /proc/sys only; it does not inspect or modify GRUB, kernel command-line, or initramfs configuration.")
    def tool_list_kernel_parameters() -> KernelParameterListResponse:
        return _list_kernel_parameters()

    @tool(name="manage_kernel_parameter", description="After exact client confirmation, change one allowlisted integer sysctl at runtime: vm.swappiness, vm.vfs_cache_pressure, fs.inotify.max_user_instances, or fs.inotify.max_user_watches. Requires a fresh identity token from list_kernel_parameters, enforces the listed value range, rechecks the exact current value and procfs identity before writing, and verifies the result. Changes are runtime-only and do not persist across reboot. Uses current OS permissions without sudo.")
    async def tool_manage_kernel_parameter(
        identity_token: str,
        new_value: int,
        confirmation: Annotated[
            ElicitationResult[KernelParameterChangeConfirmation],
            Resolve(_confirm_kernel_parameter_change),
        ],
    ) -> KernelParameterChangeResponse:
        if confirmation.action != "accept":
            return (await asyncio.to_thread(
                _perform_kernel_parameter_change,
                identity_token,
                "",
                "",
                0,
                0,
                confirmed=False,
            )).model_copy(update={
                "message": f"Kernel parameter change was {confirmation.action}; no sysctl value was changed."
            })
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_kernel_parameter_change,
            identity_token,
            data.state_token,
            data.name,
            data.current_value,
            data.new_value,
            confirmed=data.confirm is True,
        )

    @tool(name="manage_persistent_kernel_parameter", description="After exact client confirmation, create/update or remove one generated /etc/sysctl.d file for an allowlisted kernel parameter. It scans bounded standard sysctl.d files and refuses matching or wildcard assignments and filename collisions when saving. Uses current OS permissions without sudo. This persists a setting for systemd-sysctl at boot, does not change the running value, and does not edit GRUB, the kernel command line, or initramfs.")
    async def tool_manage_persistent_kernel_parameter(
        action: KernelParameterPersistenceActionName,
        name: str,
        value: int | None,
        confirmation: Annotated[
            ElicitationResult[KernelParameterPersistenceConfirmation],
            Resolve(_confirm_persistent_kernel_parameter_change),
        ],
    ) -> KernelParameterPersistenceResponse:
        if confirmation.action != "accept":
            return KernelParameterPersistenceResponse(
                success=False,
                action=action,
                name=name,
                user_confirmed=False,
                message=f"Persistent kernel parameter change was {confirmation.action}; no sysctl.d file was changed.",
            )
        data = confirmation.data
        if data.action != action or data.name != name or data.value != value:
            return KernelParameterPersistenceResponse(
                success=False,
                action=action,
                name=name,
                user_confirmed=False,
                message="Confirmation did not match the exact persistent parameter request; no file was changed.",
            )
        return await asyncio.to_thread(
            _perform_persistent_kernel_parameter_change,
            action,
            name,
            value,
            confirmed=data.confirm is True,
            confirmed_action=data.action,
            confirmed_name=data.name,
            confirmed_value=data.value,
            state_token=data.state_token,
        )

    @tool(name="manage_kernel_command_line", description="After exact client confirmation, add or remove one simple argument across current grubby entries, or update a bounded static GRUB_CMDLINE_LINUX/GRUB_CMDLINE_LINUX_DEFAULT assignment and regenerate the current config when grubby is unavailable. It refuses root= and unsupported shell/config layouts, binds confirmation to the complete entry/config state and generator identities, rechecks state, and verifies that only the requested argument changed. It restores defaults on failure and reports any retained recovery copy if rollback cannot complete. Requires current OS permissions and safe root-owned inputs; grub-mkconfig may execute /etc/grub.d hooks. It does not invoke elevation or rebuild initramfs. Boot argument changes may prevent startup or alter security and device behavior; concurrent external boot-config changes can race the final command.")
    async def tool_manage_kernel_command_line(
        action: KernelCommandLineActionName,
        argument: Annotated[
            str,
            PydanticField(
                min_length=1,
                max_length=256,
                description="One simple kernel argument token such as quiet, loglevel=3, or mitigations=auto; root= is refused",
            ),
        ],
        confirmation: Annotated[
            ElicitationResult[KernelCommandLineConfirmation],
            Resolve(_confirm_kernel_command_line_change),
        ],
    ) -> KernelCommandLineResponse:
        if confirmation.action != "accept":
            return KernelCommandLineResponse(
                success=False,
                action=action,
                argument=argument,
                user_confirmed=False,
                message=f"Kernel command-line change was {confirmation.action}; no boot entry was changed.",
            )
        data = confirmation.data
        if data.action != action or data.argument != argument:
            return KernelCommandLineResponse(
                success=False,
                action=action,
                argument=argument,
                user_confirmed=False,
                message="Confirmation did not match the exact kernel command-line request; no boot entry was changed.",
            )
        return await asyncio.to_thread(
            _perform_kernel_command_line_change,
            action,
            argument,
            confirmed=data.confirm is True,
            confirmed_action=data.action,
            confirmed_argument=data.argument,
            state_token=data.state_token,
        )

    @tool(name="manage_initramfs_rebuild", description="After exact client confirmation, rebuild the existing standard initramfs image for the running kernel using dracut, update-initramfs, or a simple literal mkinitcpio preset. Refuses missing, ambiguous, symlinked, unsupported, or nonstandard targets and verifies the result. Uses current OS permissions without requesting elevation. Generator config scripts, configured modules, and post-update hooks may run; the operation can affect bootability and a failed rebuild may leave the image unusable.")
    async def tool_manage_initramfs_rebuild(
        confirmation: Annotated[
            ElicitationResult[InitramfsRebuildConfirmation],
            Resolve(_confirm_initramfs_rebuild),
        ],
    ) -> InitramfsRebuildResponse:
        if confirmation.action != "accept":
            return InitramfsRebuildResponse(
                success=False,
                user_confirmed=False,
                message=f"Initramfs rebuild was {confirmation.action}; no image was rebuilt.",
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_initramfs_rebuild,
            confirmed=data.confirm is True,
            confirmed_backend=data.backend,
            confirmed_kernel_release=data.kernel_release,
            confirmed_image_path=data.image_path,
            state_token=data.state_token,
        )

    @tool(name="get_kernel_security_posture", description="Read a bounded fixed allowlist of active Linux security-module names, kernel lockdown mode, SELinux enforcement, maximum supported policy version, MLS and unknown-handling state, exposed policy capabilities, UEFI SecureBoot and SetupMode variables, and kernel security sysctls. Returns raw interface values without compliance scoring and performs no writes.")
    def tool_get_kernel_security_posture() -> KernelSecurityPostureResponse:
        return _get_kernel_security_posture()

    @tool(name="get_linux_audit_status", description="Read kernel audit status and bounded active audit rules through fixed auditctl -s and -l queries. Rule output may expose watched paths, syscall filters, and audit keys. Status and rules are reported separately when permissions or kernel support differ. Read-only; no rules or kernel settings are changed.")
    def tool_get_linux_audit_status() -> LinuxAuditStatusResponse:
        return _get_linux_audit_status()

    @tool(name="manage_linux_audit_rule", description="After exact client confirmation, add or remove one runtime auditctl file/directory watch with an exact path, selected r/w/x/a access types, and short audit key. The current complete rule set and path identity are rechecked, duplicate watches on the same path are refused, immutable audit mode is refused, and the result is verified. This narrow legacy watch form is deprecated and may affect system performance; it is not persistent across reboot. Uses current OS permissions and does not invoke sudo.")
    async def tool_manage_linux_audit_rule(
        action: Literal["add", "remove"],
        path: Annotated[str, PydanticField(max_length=4095)],
        permissions: Annotated[str, PydanticField(max_length=4, pattern=r"^[rwxa]{1,4}$")],
        key: Annotated[str, PydanticField(max_length=31, pattern=r"^[A-Za-z0-9_.-]{1,31}$")],
        confirmation: Annotated[
            ElicitationResult[LinuxAuditRuleActionConfirmation],
            Resolve(_confirm_audit_watch_rule_action),
        ],
    ) -> LinuxAuditRuleActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_audit_watch_rule_action,
                action,
                path,
                permissions,
                key,
                confirmed=False,
            )
        data = confirmation.data
        prepared, phrase, validation_error = await asyncio.to_thread(
            _audit_watch_rule_confirmation_details,
            action,
            path,
            permissions,
            key,
        )
        if validation_error or prepared is None or phrase is None:
            return LinuxAuditRuleActionResponse(
                success=False,
                action=action,
                path=path,
                permissions=permissions,
                key=key,
                user_confirmed=False,
                message=validation_error or "The exact audit watch could not be revalidated.",
            )
        if (
            data.action != action
            or data.path != str(prepared.path)
            or data.permissions != prepared.permissions
            or data.key != key
            or data.confirmation_phrase != phrase
        ):
            return LinuxAuditRuleActionResponse(
                success=False,
                action=action,
                path=path,
                permissions=permissions,
                key=key,
                user_confirmed=False,
                message="The confirmation fields did not match this exact audit watch; no rule was changed.",
            )
        return await asyncio.to_thread(
            _perform_audit_watch_rule_action,
            action,
            path,
            permissions,
            key,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="list_linux_audit_events", description="List bounded raw Linux audit events using ausearch with a fixed time-window choice (recent, this-hour, today, yesterday, this-week, this-month, this-year, boot, or all retained logs). Supports validated message-type, event-serial, and process-ID filters. Results are capped by output, event, record, and timeout limits; broader windows can be partial. Records may expose user IDs, paths, command arguments, network addresses, terminal data, and audit keys. Read-only.")
    def tool_list_linux_audit_events(
        message_type: str = "",
        limit: int = 50,
        window: Literal[
            "recent", "this-hour", "today", "yesterday", "this-week",
            "this-month", "this-year", "boot", "all",
        ] = "recent",
        event_serial: int | None = None,
        process_id: int | None = None,
    ) -> LinuxAuditEventListResponse:
        return _list_linux_audit_events(
            message_type=message_type,
            limit=limit,
            window=window,
            event_serial=event_serial,
            process_id=process_id,
        )

    @tool(name="summarize_linux_audit", description="Return a bounded aggregate Linux audit report from aureport using an allowlisted report type (overview, authentication, logins, files, hosts, users, processes, executables, syscalls, or keys) and fixed time-window choices. Output is limited to 120 sanitized lines and 256 KiB of command output; broad windows may be partial. Reports may expose user IDs, file paths, hosts, executable names, and audit keys. Read-only.")
    def tool_summarize_linux_audit(
        report_type: Literal[
            "overview", "authentication", "logins", "files", "hosts", "users",
            "processes", "executables", "syscalls", "keys",
        ] = "overview",
        window: Literal[
            "recent", "this-hour", "today", "yesterday", "this-week",
            "this-month", "this-year", "boot", "all",
        ] = "recent",
        limit: int = 80,
    ) -> LinuxAuditSummaryResponse:
        return _summarize_linux_audit(
            report_type=report_type,
            window=window,
            limit=limit,
        )

    @tool(name="list_apparmor_profiles", description="Read bounded pages of loaded AppArmor profile names and kernel-reported modes from the fixed securityfs profile list. Uses returned byte offsets to continue. Does not return policy rules or change profile state.")
    def tool_list_apparmor_profiles(offset: int = 0, limit: int = 100) -> AppArmorProfileListResponse:
        return _list_apparmor_profiles(offset=offset, limit=limit)

    @tool(name="manage_apparmor_profile", description="After exact client confirmation, set one exact loaded AppArmor profile to enforce or complain mode. Requires aa-enforce/aa-complain with exact --profile support and rechecks the loaded profile mode and helper identity. The utility updates the local profile file and reloads it using current-user permissions; it does not invoke sudo. Complain mode weakens protection, while enforce mode may interrupt the confined application. Unconfined and other profile modes are refused.")
    async def tool_manage_apparmor_profile(
        name: str,
        action: Literal["enforce", "complain"],
        confirmation: Annotated[
            ElicitationResult[AppArmorProfileActionConfirmation],
            Resolve(_confirm_apparmor_profile_action),
        ],
    ) -> AppArmorProfileActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_apparmor_profile_action,
                name,
                action,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_apparmor_profile_action,
            name,
            action,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="list_selinux_booleans", description="List bounded current and pending SELinux boolean values from the fixed selinuxfs boolean directory. Supports a substring filter and index-based paging. This is read-only and does not commit or change boolean values.")
    def tool_list_selinux_booleans(
        query: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> SELinuxBooleanListResponse:
        return _list_selinux_booleans(query=query, offset=offset, limit=limit)

    @tool(name="manage_selinux_boolean", description="After exact client confirmation, enable or disable one exact SELinux boolean returned by list_selinux_booleans, for runtime only or persistently across reboots. Rechecks current and pending values and the setsebool executable before acting, uses current-user permissions without sudo, and verifies the resulting runtime value. A persistent setsebool -P operation can rebuild policy and take several minutes; host policy may deny the change.")
    async def tool_manage_selinux_boolean(
        name: str,
        enabled: bool,
        persistent: bool,
        confirmation: Annotated[
            ElicitationResult[SELinuxBooleanActionConfirmation],
            Resolve(_confirm_selinux_boolean_action),
        ],
    ) -> SELinuxBooleanActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_selinux_boolean_action,
                name,
                enabled,
                persistent,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_selinux_boolean_action,
            name,
            enabled,
            persistent,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_selinux_context", description="After exact client confirmation, restore the policy-defined SELinux type for one existing regular file or directory. Uses matchpathcon to bind the active policy label and runs nonrecursive restorecon without -F or -U, so customizable labels and user/role/range fields are not forcibly reset. Rechecks path, current label, policy label, and helper identities, then verifies the resulting SELinux type. Uses current OS permissions and does not invoke sudo; changing a type can affect access.")
    async def tool_manage_selinux_context(
        path: Annotated[str, PydanticField(max_length=4095)],
        confirmation: Annotated[
            ElicitationResult[SELinuxContextRestoreConfirmation],
            Resolve(_confirm_selinux_context_restore),
        ],
    ) -> SELinuxContextRestoreResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_selinux_context_restore,
                path,
                confirmed=False,
            )
        data = confirmation.data
        prepared, phrase, validation_error = await asyncio.to_thread(
            _selinux_context_restore_confirmation_details,
            path,
        )
        if validation_error or prepared is None or phrase is None:
            return SELinuxContextRestoreResponse(
                success=False,
                path=path,
                user_confirmed=False,
                message=validation_error or "The exact SELinux context restore could not be revalidated.",
            )
        if (
            data.path != str(prepared.path)
            or data.current_context != prepared.current_context
            or data.expected_context != prepared.expected_context
            or data.confirmation_phrase != phrase
        ):
            return SELinuxContextRestoreResponse(
                success=False,
                path=path,
                current_context=prepared.current_context,
                expected_context=prepared.expected_context,
                user_confirmed=False,
                message="The confirmation fields did not match this exact path and policy label; no context was changed.",
            )
        return await asyncio.to_thread(
            _perform_selinux_context_restore,
            path,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="manage_selinux_fcontext_rule", description="After exact client confirmation, add or remove one persistent SELinux file-context rule for one exact existing regular file or directory path. The tool creates an anchored literal path expression and limits it to the path's current file type; it cannot express wildcards or recurse. Requires the MCP server to already run as root and a verified semanage executable. It changes the local labeling policy but does not relabel the current object; use manage_selinux_context separately to apply the policy-defined type to this exact path. Removing a rule also leaves the current label unchanged.")
    async def tool_manage_selinux_fcontext_rule(
        action: Literal["add", "remove"],
        path: Annotated[str, PydanticField(max_length=4095)],
        context_type: Annotated[
            str,
            PydanticField(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,126}_t$", description="Exact SELinux type name ending in _t"),
        ],
        confirmation: Annotated[
            ElicitationResult[SELinuxFContextRuleConfirmation],
            Resolve(_confirm_selinux_fcontext_rule),
        ],
    ) -> SELinuxFContextRuleResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_selinux_fcontext_rule_action,
                action,
                path,
                context_type,
                confirmed=False,
            )
        data = confirmation.data
        prepared, phrase, validation_error = await asyncio.to_thread(
            _selinux_fcontext_rule_confirmation_details,
            action,
            path,
            context_type,
        )
        if validation_error or prepared is None or phrase is None:
            return SELinuxFContextRuleResponse(
                success=False,
                action=action,
                path=path,
                context_type=context_type,
                user_confirmed=False,
                message=validation_error or "The exact local SELinux file-context rule could not be revalidated.",
            )
        if (
            data.action != action
            or data.path != str(prepared.path)
            or data.context_type != prepared.context_type
            or data.confirmation_phrase != phrase
        ):
            return SELinuxFContextRuleResponse(
                success=False,
                action=action,
                path=str(prepared.path),
                context_type=context_type,
                file_type="directory" if prepared.file_type == "d" else "regular file",
                rule_expression=prepared.rule_expression,
                user_confirmed=False,
                message="The confirmation fields did not match this exact path and local SELinux rule request.",
            )
        return await asyncio.to_thread(
            _perform_selinux_fcontext_rule_action,
            action,
            path,
            context_type,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="list_ima_measurements", description="Read bounded pages of the ASCII IMA runtime-measurement log and optional count/violation counters. Pass the returned next_offset to continue. Opens fixed securityfs interfaces read-only; template data may contain file paths or event payloads. Does not modify the measurement list or read/verify TPM PCR values.")
    def tool_list_ima_measurements(offset: int = 0, limit: int = 50) -> IMAMeasurementListResponse:
        return _list_ima_measurements(offset=offset, limit=limit)

    @tool(name="list_ima_policy", description="Read bounded pages of raw active IMA policy rules through the fixed securityfs policy interface when the kernel exposes readback. The kernel may require CONFIG_IMA_READ_POLICY and CAP_SYS_ADMIN. Uses returned byte offsets to continue and performs no policy writes.")
    def tool_list_ima_policy(offset: int = 0, limit: int = 50) -> IMAPolicyListResponse:
        return _list_ima_policy(offset=offset, limit=limit)

    @tool(name="list_tpm_devices", description="List bounded TPM class devices using the kernel-reported specification version and optional bound-driver name. Does not issue TPM commands or read status attributes, PCRs, or keys.")
    def tool_list_tpm_devices() -> TPMInventoryResponse:
        return _list_tpm_devices()

    @tool(name="list_tpm_event_log", description="Read bounded pages from the kernel-exported TPM firmware event log in securityfs. An empty device_name selects the lowest-numbered visible TPM; pass the returned byte offset to continue. Reports digest records and a short event-data hex preview. Does not issue TPM commands, read PCR values, verify the log, or attest boot integrity.")
    def tool_list_tpm_event_log(
        device_name: str = "",
        offset: int = 0,
        limit: int = 50,
    ) -> TPMEventLogResponse:
        return _list_tpm_event_log(device_name=device_name, offset=offset, limit=limit)

    @tool(name="create_tpm_attestation", description="After exact client confirmation, create a TPM 2.0 quote for selected SHA-256 PCRs using an existing persistent 0x81-range signing-key handle and a caller-supplied 32-byte nonce. It returns bounded base64 quote, signature, PCR values, and the public key/name, and locally verifies the signature, nonce, and included PCR values. It does not accept secret key authorization values, provision keys, transmit artifacts to a verifier, establish trust in the signing key, or decide whether measurements are acceptable. Uses current OS permissions without elevation; quote data may disclose measured boot/software state.")
    async def tool_create_tpm_attestation(
        persistent_handle: Annotated[
            str,
            PydanticField(pattern=r"^0x81[0-9a-fA-F]{6}$", description="Existing persistent TPM key handle in the 0x81000000-0x81ffffff range"),
        ],
        pcr_indices: Annotated[
            list[Annotated[int, PydanticField(strict=True, ge=0, le=23)]],
            PydanticField(min_length=1, max_length=24, description="One to 24 unique SHA-256 PCR indexes from 0 through 23"),
        ],
        nonce: Annotated[
            str,
            PydanticField(pattern=r"^[0-9a-f]{64}$", description="Caller-supplied unpredictable 32-byte verifier nonce in lowercase hexadecimal"),
        ],
        confirmation: Annotated[
            ElicitationResult[TPMAttestationConfirmation],
            Resolve(_confirm_tpm_attestation),
        ],
    ) -> TPMAttestationResponse:
        if confirmation.action != "accept":
            return TPMAttestationResponse(
                success=False,
                persistent_handle=persistent_handle.lower(),
                nonce=nonce,
                user_confirmed=False,
                message=f"TPM attestation request was {confirmation.action}; no quote was requested.",
            )
        data = confirmation.data
        expected_pcr_indices_json = json.dumps(pcr_indices, separators=(",", ":"))
        if data.pcr_indices_json != expected_pcr_indices_json:
            return TPMAttestationResponse(
                success=False,
                persistent_handle=persistent_handle.lower(),
                pcr_indices=pcr_indices,
                nonce=nonce,
                user_confirmed=False,
                message="Confirmation did not repeat the exact PCR selection as a JSON array; no quote was requested.",
            )
        return await asyncio.to_thread(
            _perform_tpm_attestation,
            persistent_handle=persistent_handle,
            pcr_indices=pcr_indices,
            nonce=nonce,
            confirmed=data.confirm is True,
            confirmed_handle=data.persistent_handle,
            confirmed_pcr_indices=pcr_indices,
            confirmed_nonce=data.nonce,
            state_token=data.state_token,
        )

    @tool(name="list_installed_packages", description="List bounded installed system packages from dpkg, RPM, pacman, or APK metadata. Does not refresh repositories, install software, or include Flatpak/Snap/language package environments.")
    def tool_list_installed_packages(query: str = "", limit: int = 100) -> InstalledPackageListResponse:
        return _list_installed_packages(query=query, limit=limit)

    @tool(name="manage_package", description="After explicit client confirmation, install, upgrade, or remove one exact system package, or upgrade all eligible installed system packages. Pass an empty package string for upgrade_all. Supports dpkg/apt-get, RPM with DNF/YUM or Zypper, pacman, and APK. Package managers may download software, change dependencies, execute scripts, alter configuration, and affect services; pacman install/upgrade includes a full system upgrade. Uses current OS permissions without elevation, with a 30-minute timeout; command output is withheld.")
    async def tool_manage_package(
        action: PackageAction,
        package: str,
        confirmation: Annotated[
            ElicitationResult[PackageActionConfirmation],
            Resolve(_confirm_package_action),
        ],
    ) -> PackageActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return _perform_package_action(action=action, package=package, confirmed=False)
        return await asyncio.to_thread(
            _perform_package_action,
            action=action,
            package=package,
            confirmed=True,
        )

    @tool(name="manage_flatpak_package", description="After explicit client confirmation, install, update, or remove one exact full Flatpak ref formatted as app|runtime/ID/ARCH/BRANCH; the ID, architecture, and branch come from list_application_packages. Operates in the default system installation, a configured named system installation, or the current-user installation. Set installation to the exact named system installation ID shown in list_application_packages, or leave it empty for the selected default installation. Supply a configured remote name for install; pass an empty remote for update/remove, which use the installed ref's origin. Install may add required dependencies; related extensions are excluded. Update excludes runtime dependencies and related extensions, though Flatpak may remove unused end-of-life runtimes. Remove does not request app-data deletion or force removal. System operations follow Flatpak's host authorization policy and may require polkit authentication; this tool does not invoke sudo. Flatpak output is withheld and transactions have a 30-minute timeout.")
    async def tool_manage_flatpak_package(
        action: Literal["install", "update", "remove"],
        scope: Annotated[
            Literal["system", "user"],
            PydanticField(description="Use system for the default or a named system installation; use user for the current user's default installation"),
        ],
        ref: str,
        remote: str,
        confirmation: Annotated[
            ElicitationResult[ApplicationPackageActionConfirmation],
            Resolve(_confirm_flatpak_package_action),
        ],
        installation: Annotated[
            str,
            PydanticField(
                max_length=128,
                description="Exact ID from a system_installation:<ID> inventory scope; leave empty for the default installation, and use only with scope='system'",
            ),
        ] = "",
    ) -> ApplicationPackageActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return ApplicationPackageActionResponse(
                success=False,
                action=action,
                scope=scope,
                ref=ref,
                installation=installation or None,
                remote=remote or None,
                user_confirmed=False,
                message="Explicit client confirmation is required; no Flatpak command was run.",
            )
        data = confirmation.data
        if (
            data.action != action
            or data.scope != scope
            or data.ref != ref
            or data.remote != remote
            or data.installation != installation
        ):
            return ApplicationPackageActionResponse(
                success=False,
                action=action,
                scope=scope,
                ref=ref,
                installation=installation or None,
                remote=remote or None,
                user_confirmed=False,
                message="The confirmation fields did not match this exact Flatpak action; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_flatpak_package_action,
            action,
            scope,
            ref,
            remote,
            data.expected_state_token,
            installation=installation,
            confirmed=True,
        )

    @tool(name="manage_snap_package", description="After explicit client confirmation, install, refresh, switch-and-refresh, enable, disable, revert to one exact retained numeric revision, hold/unhold refreshes for one exact Snap, hold automatic refreshes for all Snaps, remove all refresh holds, or remove one exact Snap. Leave package_name empty for hold_all or unhold_all. Store installs target latest/stable; set classic=true only for a stable-channel Snap verified as published with classic confinement. Classic confinement grants broad system access and reduces Snap's usual isolation. For a local install, provide the exact snap_file_path and package_name shown by snap info; dangerous=true explicitly bypasses assertion/signature checks for that file. Set devmode=true only for a local Snap whose metadata reports developer mode; developer mode grants full access to system resources, logs policy violations, prevents automatic refreshes, and may proceed when assertion verification fails, similar to dangerous mode. Classic and developer mode cannot be combined. Local files must be bounded current-user-owned regular .snap files. Update preserves the current tracking channel; switch_channel accepts a Snap risk, risk/branch, track/risk, or track/risk/branch and changes both the installed revision and future refresh channel. Revert restores revision-specific configuration data and can discard newer changes. Refresh holds require snapd 2.58 or newer and accept 'forever' or an integer duration up to 90 days. Per-Snap holds also affect general refresh requests; a system-wide hold affects automatic refreshes only. Disable makes snap commands unavailable and prevents its services from starting. Removal covers all installed revisions and does not use --purge; on supported classic systems snapd normally creates a data snapshot, while Ubuntu Core or older snapd may not. The snapd control-plane package cannot be removed. Commands use the server account's current permissions without sudo or elevation; command output is withheld and transactions have a 30-minute timeout.")
    async def tool_manage_snap_package(
        action: Literal["install", "update", "switch_channel", "remove", "enable", "disable", "revert", "hold", "unhold", "hold_all", "unhold_all"],
        package_name: str = "",
        *,
        classic: Annotated[
            bool,
            PydanticField(description="For install only, explicitly request the published classic confinement mode, which grants broad system access"),
        ] = False,
        snap_file_path: Annotated[
            str,
            PydanticField(
                max_length=4096,
                description="For a local install, exact absolute path to one current-user-owned regular .snap file; empty means use the Store",
            ),
        ] = "",
        dangerous: Annotated[
            bool,
            PydanticField(description="For local installs only, explicitly bypass Snap assertion/signature validation"),
        ] = False,
        devmode: Annotated[
            bool,
            PydanticField(description="For local installs only, explicitly request the developer mode reported by the Snap file metadata; grants full system-resource access, disables automatic refresh, and may proceed when assertion verification fails"),
        ] = False,
        target_channel: Annotated[
            str,
            PydanticField(
                max_length=160,
                description="For switch_channel, repeat the exact target_channel input from the request (Snap risk, risk/branch, track/risk, or track/risk/branch); leave empty for other actions",
            ),
        ] = "",
        revision: Annotated[
            int | None,
            PydanticField(ge=1, le=2147483647, description="For revert only, exact retained numeric Snap revision to activate; leave empty otherwise"),
        ] = None,
        hold_duration: Annotated[
            str,
            PydanticField(max_length=16, description="For hold or hold_all on snapd 2.58 or newer, 'forever' or an integer duration such as 30m, 12h, or 1h30m, up to 90 days; leave empty otherwise"),
        ] = "",
        confirmation: Annotated[
            ElicitationResult[SnapPackageActionConfirmation],
            Resolve(_confirm_snap_package_action),
        ],
    ) -> SnapPackageActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return SnapPackageActionResponse(
                success=False,
                action=action,
                package_name="all" if action in {"hold_all", "unhold_all"} and not package_name else package_name,
                classic=classic,
                devmode=devmode,
                local_file=bool(snap_file_path),
                dangerous=dangerous,
                target_channel=target_channel or None,
                revision=str(revision) if revision is not None else None,
                hold_duration=hold_duration or None,
                user_confirmed=False,
                message="Explicit client confirmation is required; no Snap command was run.",
            )
        data = confirmation.data
        if (
            data.action != action
            or data.package_name != package_name
            or data.target_channel != target_channel
            or data.classic != classic
            or data.devmode != devmode
            or data.snap_file_path != snap_file_path
            or data.dangerous != dangerous
            or data.revision != revision
            or data.hold_duration != hold_duration
        ):
            return SnapPackageActionResponse(
                success=False,
                action=action,
                package_name="all" if action in {"hold_all", "unhold_all"} and not package_name else package_name,
                classic=classic,
                devmode=devmode,
                local_file=bool(snap_file_path),
                dangerous=dangerous,
                target_channel=target_channel or None,
                revision=str(revision) if revision is not None else None,
                hold_duration=hold_duration or None,
                user_confirmed=False,
                message="The confirmation fields did not match this exact Snap action; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_snap_package_action,
            action,
            package_name,
            data.expected_state_token,
            target_channel=target_channel,
            classic=classic,
            snap_file_path=snap_file_path,
            dangerous=dangerous,
            devmode=devmode,
            revision=revision,
            hold_duration=hold_duration,
            confirmed=True,
        )

    @tool(name="manage_nix_profile_entry", description="After explicit client confirmation, install one simple nixpkgs flake attribute (for example hello or python3Packages.requests) in the current user's default Nix profile, or upgrade/remove one exact profile entry. Installs use the host's configured nixpkgs flake registry reference and may fetch/evaluate sources, download outputs, and run package builds. Upgrade is limited to an active entry with an unlocked flake source and uses that entry's original source. Remove only drops that profile entry; it does not run garbage collection or delete store data. System profiles, bulk upgrades, and locked-flake upgrades are not exposed; profile-history management is available in a separate tool. Nix profile/flake features must already be available in the host's configuration; this tool does not enable them. Uses current-user permissions without elevation; Nix output is withheld and operations have a 30-minute timeout.")
    async def tool_manage_nix_profile_entry(
        action: Literal["install", "upgrade", "remove"],
        entry_name: Annotated[
            str,
            PydanticField(description="For install, a simple nixpkgs attribute path; for upgrade/remove, an exact name or numeric index from the current user's default Nix profile"),
        ],
        confirmation: Annotated[
            ElicitationResult[NixProfileActionConfirmation],
            Resolve(_confirm_nix_profile_action),
        ],
    ) -> NixProfileActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return NixProfileActionResponse(
                success=False,
                action=action,
                entry_name=entry_name,
                user_confirmed=False,
                message="Explicit client confirmation is required; no Nix command was run.",
            )
        data = confirmation.data
        if data.action != action or data.entry_name != entry_name:
            return NixProfileActionResponse(
                success=False,
                action=action,
                entry_name=entry_name,
                user_confirmed=False,
                message="The confirmation fields did not match this exact Nix profile action; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_nix_profile_action,
            action,
            entry_name,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="list_nix_profile_history", description="List bounded version IDs, dates, parent IDs, change counts, and the active generation from the current user's default Nix profile history. Nix package names and source URLs in history output are withheld. Only the existing current-user default profile is inspected.")
    async def tool_list_nix_profile_history(limit: int = 100) -> NixProfileHistoryListResponse:
        return await asyncio.to_thread(_list_nix_profile_history, limit)

    @tool(name="manage_nix_profile_history", description="After exact client confirmation, roll the current user's default Nix profile back to one existing historical version or delete non-current versions older than a bounded age. History cleanup requires a 30-day minimum and previews the exact versions that will lose their rollback path. The current profile is protected from cleanup. This does not target system profiles or run garbage collection; Nix profile commands are experimental and version-dependent.")
    async def tool_manage_nix_profile_history(
        action: Literal["rollback", "wipe_history"],
        target_version: int,
        older_than_days: int,
        confirmation: Annotated[
            ElicitationResult[NixProfileHistoryActionConfirmation],
            Resolve(_confirm_nix_profile_history_action),
        ],
    ) -> NixProfileHistoryActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return NixProfileHistoryActionResponse(
                success=False,
                action=action,
                target_version=target_version or None,
                older_than_days=older_than_days or None,
                user_confirmed=False,
                message="Explicit client confirmation is required; no Nix profile history action was run.",
            )
        data = confirmation.data
        if (
            data.action != action
            or data.target_version != target_version
            or data.older_than_days != older_than_days
        ):
            return NixProfileHistoryActionResponse(
                success=False,
                action=action,
                target_version=target_version or None,
                older_than_days=older_than_days or None,
                user_confirmed=False,
                message="The confirmation fields did not match the exact Nix profile history action; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_nix_profile_history_action,
            action,
            target_version,
            older_than_days,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="list_python_environments", description="List bounded Python virtual environments managed by this server under the current user's ~/.linux-mcp-python-venvs directory. Other venv paths are not discovered or modified. Unsafe, incomplete, and symlinked entries are skipped.")
    def tool_list_python_environments(limit: int = 100) -> PythonEnvironmentListResponse:
        return _list_python_environments(limit=limit)

    @tool(name="list_python_environment_packages", description="List bounded installed project names and versions from one exact managed Python virtual environment. The environment must have been created under the current user's home directory. Package metadata is read directly without running the environment's Python, pip, or installed package code.")
    async def tool_list_python_environment_packages(
        environment_name: str,
        limit: int = 100,
    ) -> PythonEnvironmentPackageListResponse:
        return await asyncio.to_thread(
            _list_python_environment_packages,
            environment_name,
            limit,
        )

    @tool(name="manage_python_environment", description="After exact client confirmation, create one managed Python venv or install, upgrade, or uninstall one exact pip project in it. Environments live under ~/.linux-mcp-python-venvs for the current user; only simple project names and an optional exact version are accepted, with no URLs, VCS sources, requirement files, or pip options. Install/upgrade may access the public package index, change dependencies, and execute build/install code as the current non-root user. Requires python3 with venv/ensurepip support and matching real/effective non-root user IDs; no sudo is used. Pip config files and PIP_* overrides are disabled, output is withheld, and package transactions are limited to 30 minutes.")
    async def tool_manage_python_environment(
        action: Literal["create", "install", "upgrade", "uninstall"],
        environment_name: str,
        package_name: str,
        version: str,
        confirmation: Annotated[
            ElicitationResult[PythonEnvironmentActionConfirmation],
            Resolve(_confirm_python_environment_action),
        ],
    ) -> PythonEnvironmentActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_python_environment_action,
                action,
                environment_name,
                package_name,
                version,
                "",
                confirmed=False,
            )
        data = confirmation.data
        if (
            data.action != action
            or data.environment_name != environment_name
            or data.package_name != package_name
            or data.version != version
        ):
            return PythonEnvironmentActionResponse(
                success=False,
                action=action,
                environment_name=environment_name,
                package_name=package_name or None,
                version=version or None,
                user_confirmed=False,
                message="The confirmation fields did not match this exact Python environment action; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_python_environment_action,
            action,
            environment_name,
            package_name,
            version,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="list_native_package_environments", description="List bounded current-user managed npm prefixes or Cargo install roots under ~/.linux-mcp-npm-prefixes and ~/.linux-mcp-cargo-roots. Unsafe, symlinked, or incomplete entries are skipped; no package code is executed.")
    def tool_list_native_package_environments(
        ecosystem: Literal["npm", "cargo"],
        limit: int = 100,
    ) -> NativePackageEnvironmentListResponse:
        return _list_native_package_environments(ecosystem, limit)

    @tool(name="list_native_environment_packages", description="List bounded installed top-level npm package or Cargo crate names and versions from one exact managed current-user environment. npm package.json metadata is read without running package code; Cargo's supported install-list command is scoped to the exact managed root.")
    def tool_list_native_environment_packages(
        ecosystem: Literal["npm", "cargo"],
        environment_name: str,
        limit: int = 100,
    ) -> NativeEnvironmentPackageListResponse:
        return _list_native_environment_packages(ecosystem, environment_name, limit)

    @tool(name="manage_native_package_environment", description="After exact client confirmation, create one private managed npm prefix or Cargo install root, or install/upgrade/uninstall one exact npm package or crates.io binary crate in it. Environments are limited to ~/.linux-mcp-npm-prefixes or ~/.linux-mcp-cargo-roots for the current user. Top-level selectors accept simple package/crate names only; install may pin one exact semantic version. npm uses the public registry; Cargo uses its default crates.io source and normal dependency resolution. Installs/upgrades can download dependencies and run npm lifecycle or Cargo build code as the current non-root user. No arbitrary top-level URLs, paths, git selectors, manager options, sudo, or root execution. Output is withheld; package transactions have a 30-minute timeout.")
    async def tool_manage_native_package_environment(
        ecosystem: Literal["npm", "cargo"],
        action: Literal["create", "install", "upgrade", "uninstall"],
        environment_name: str,
        package_name: str,
        version: str,
        confirmation: Annotated[
            ElicitationResult[NativePackageEnvironmentActionConfirmation],
            Resolve(_confirm_native_package_environment_action),
        ],
    ) -> NativePackageEnvironmentActionResponse:
        if confirmation.action != "accept" or not confirmation.data.confirm:
            return await asyncio.to_thread(
                _perform_native_package_environment_action,
                ecosystem,
                action,
                environment_name,
                package_name,
                version,
                "",
                confirmed=False,
            )
        data = confirmation.data
        if (
            data.ecosystem != ecosystem
            or data.action != action
            or data.environment_name != environment_name
            or data.package_name != package_name
            or data.version != version
        ):
            return NativePackageEnvironmentActionResponse(
                success=False,
                ecosystem=ecosystem,
                action=action,
                environment_name=environment_name,
                package_name=package_name or None,
                version=version or None,
                user_confirmed=False,
                message="The confirmation fields did not match this exact npm/Cargo environment action; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_native_package_environment_action,
            ecosystem,
            action,
            environment_name,
            package_name,
            version,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="list_application_packages", description="List installed Flatpak apps/runtimes from the default system, configured named system installations, and the current-user installation, installed system Snaps, and entries in the current user's default Nix profile. Named system installation scopes use system_installation:<ID>; pass that ID to manage_flatpak_package with scope='system'. Optional managers report per-source availability; this is read-only and performs no package changes.")
    def tool_list_application_packages(query: str = "", limit: int = 100) -> ApplicationPackageInventoryResponse:
        return _list_application_packages(query=query, limit=limit)

    @tool(name="list_containers", description="List bounded containers from local Docker/Podman endpoints and read-only containerd/CRI-O endpoints through crictl. The runtime filter accepts auto, docker, podman, containerd, or cri-o. Only Docker/Podman entries receive short-lived lifecycle-action tokens; CRI entries are inventory-only. Command arguments, environment, labels, mounts, logs, and remote endpoints are excluded.")
    def tool_list_containers(
        runtime: Literal["auto", "docker", "podman", "containerd", "cri-o"] = "auto",
        query: str = "",
        limit: int = 100,
    ) -> ContainerListResponse:
        return _list_containers(runtime=runtime, query=query, limit=limit)

    @tool(name="list_container_images", description="List bounded local Docker/Podman image IDs and exact repository tags/digests from fixed local API sockets or a Podman CLI forced into non-remote mode. Does not list layers, inspect Dockerfiles, pull images, or expose remote image locations beyond references.")
    def tool_list_container_images(
        runtime: Literal["auto", "docker", "podman"] = "auto",
        query: str = "",
        limit: int = 100,
    ) -> ContainerImageListResponse:
        return _list_container_images(runtime=runtime, query=query, limit=limit)

    @tool(name="manage_container_image", description="After exact client confirmation, pull one fully qualified tag/digest reference, add a new tag to one exact local image, or remove one exact local tag without force. Podman may use credentials configured for the current identity; this Docker API request does not forward client credentials, so private-registry pulls may fail. Pulls consume network bandwidth/storage. Tag overwrites are refused after state revalidation, though a concurrent external retag in the final read/action interval can race. Removal refuses in-use images and does not prune parent layers. Uses fixed local Docker API sockets or Podman CLI forced into non-remote mode; revalidates image IDs and inventory before and after the action.")
    async def tool_manage_container_image(
        action: ContainerImageActionName,
        runtime: ContainerRuntimeName,
        scope: Literal["system", "user"],
        image: str,
        confirmation: Annotated[
            ElicitationResult[ContainerImageActionConfirmation],
            Resolve(_confirm_container_image_action),
        ],
        target_tag: str | None = None,
    ) -> ContainerImageActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_container_image_action,
                action,
                runtime,
                scope,
                image,
                target_tag,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_container_image_action,
            action,
            runtime,
            scope,
            image,
            target_tag,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="build_container_image", description="After exact client confirmation, build one new local Docker/Podman image tag from a bounded explicit context directory containing a root Dockerfile or Containerfile. The tool refuses an existing destination tag, revalidates the complete local image inventory and captured context digest, applies bounded Docker/Podman ignore rules, and never starts a container. Build instructions execute in the runtime's builder and may access registries/network or consume substantial resources. Contexts are capped at 64 MiB and exclude symlinks, special files, and nested mount points; host ownership, timestamps, and xattrs are omitted. Podman builds use a local CLI forced into non-remote mode; Docker uses a fixed local API socket.")
    async def tool_build_container_image(
        runtime: ContainerImageBuildRuntimeName,
        scope: Literal["system", "user"],
        tag: str,
        context_dir: str,
        confirmation: Annotated[
            ElicitationResult[ContainerImageBuildConfirmation],
            Resolve(_confirm_container_image_build),
        ],
    ) -> ContainerImageBuildResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_container_image_build,
                runtime,
                scope,
                tag,
                context_dir,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_container_image_build,
            runtime,
            scope,
            tag,
            context_dir,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="list_container_resources", description="List bounded names and selected metadata for local Docker/Podman volumes or networks from fixed local API sockets or a Podman CLI forced into non-remote mode. Does not expose mountpoint paths, driver options, labels, network configuration, or attached container names.")
    def tool_list_container_resources(
        runtime: Literal["auto", "docker", "podman"] = "auto",
        kind: ContainerResourceKindName = "volume",
        query: str = "",
        limit: int = 100,
    ) -> ContainerResourceListResponse:
        return _list_container_resources(runtime=runtime, kind=kind, query=query, limit=limit)

    @tool(name="manage_container_resource", description="After exact client confirmation, create a local-driver volume or bridge network, or remove one exact unused volume/network. Bridge creation accepts up to eight canonical network_subnets, with at most four per IP family on Podman and one per family on Docker bridge networks, plus a parallel network_gateways list (use null for runtime-selected gateways); this supports dual-stack and bounded multi-subnet Podman networks while preserving the legacy IPv4 subnet/gateway fields. IPv4 prefixes are limited to /8 through /30, IPv6 to /48 through /120. For Podman, explicit gateway entries must precede automatic entries to preserve the CLI option order. It also accepts internal-network mode, host bridge name, and MTU; requested settings are revalidated in the prompt and checked through runtime inspection. Overlapping subnets are refused by the engine when detected. Internal mode limits connectivity through this network only. Network creation may add host-side bridge, route, or firewall configuration. Removal never forces or removes containers; volume removal can permanently delete stored data. Uses only a local Docker API socket or Podman CLI forced into non-remote mode. A rootful engine may perform host-privileged operations.")
    async def tool_manage_container_resource(
        action: ContainerResourceActionName,
        runtime: ContainerRuntimeName,
        scope: Literal["system", "user"],
        kind: ContainerResourceKindName,
        name: str,
        confirmation: Annotated[
            ElicitationResult[ContainerResourceActionConfirmation],
            Resolve(_confirm_container_resource_action),
        ],
        network_subnet: str | None = None,
        network_gateway: str | None = None,
        network_internal: bool | None = None,
        network_bridge_name: str | None = None,
        network_mtu: int | None = None,
        network_subnets: list[str] | None = None,
        network_gateways: list[str | None] | None = None,
    ) -> ContainerResourceActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_container_resource_action,
                action,
                runtime,
                scope,
                kind,
                name,
                network_subnet,
                network_gateway,
                network_internal,
                network_bridge_name,
                network_mtu,
                network_subnets,
                network_gateways,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_container_resource_action,
            action,
            runtime,
            scope,
            kind,
            name,
            network_subnet,
            network_gateway,
            network_internal,
            network_bridge_name,
            network_mtu,
            network_subnets,
            network_gateways,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="list_container_network_attachments", description="List exact named-network attachments for one selected local Docker/Podman container. Requires one runtime, scope, and exact container name or full ID; Podman attachment inspection is limited to running standalone containers. Network addresses and endpoint settings are omitted. This tool is hidden when either the containers or networking category is disabled.")
    def tool_list_container_network_attachments(
        runtime: ContainerRuntimeName,
        scope: Literal["system", "user"],
        container: str,
    ) -> ContainerNetworkAttachmentResponse:
        return _list_container_network_attachments(runtime=runtime, scope=scope, container=container)

    @tool(name="manage_container_network_attachment", description="After exact client confirmation, connect or disconnect one local Docker/Podman container to/from one exact non-default local network; Podman actions are limited to running standalone containers. Disconnection never forces and refuses to remove the container's last network; changes can immediately alter workload connectivity. Revalidates the container, network, endpoint, and complete bounded inventories, then verifies the resulting attachment. Hidden when either the containers or networking category is disabled.")
    async def tool_manage_container_network_attachment(
        action: ContainerNetworkActionName,
        runtime: ContainerRuntimeName,
        scope: Literal["system", "user"],
        container: str,
        network: str,
        confirmation: Annotated[
            ElicitationResult[ContainerNetworkAttachmentConfirmation],
            Resolve(_confirm_container_network_attachment_action),
        ],
    ) -> ContainerNetworkAttachmentActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_container_network_attachment_action,
                action,
                runtime,
                scope,
                container,
                network,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_container_network_attachment_action,
            action,
            runtime,
            scope,
            container,
            network,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="list_container_pods", description="List bounded Podman pods in the current local Podman scope, including exact pod IDs/names, state, member count, attached container IDs/names, and selected member statuses. Uses the local Podman CLI forced into non-remote mode; no Docker or remote pod endpoint is queried.")
    def tool_list_container_pods(query: str = "", limit: int = 100) -> ContainerPodListResponse:
        return _list_container_pods(query=query, limit=limit)

    @tool(name="manage_container_pod", description="After exact client confirmation, create an empty Podman pod without an infra container, start or stop one exact pod and all its revalidated member containers, or remove one empty non-running pod without force. Start/stop may run or interrupt every workload attached to the pod; member containers are never removed. Uses the local Podman CLI forced into non-remote mode and current-scope permissions.")
    async def tool_manage_container_pod(
        action: ContainerPodActionName,
        name: str,
        confirmation: Annotated[
            ElicitationResult[ContainerPodActionConfirmation],
            Resolve(_confirm_container_pod_action),
        ],
    ) -> ContainerPodActionResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_container_pod_action,
                action,
                name,
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_container_pod_action,
            action,
            name,
            confirmed=data.confirm is True,
            confirmation_phrase=data.confirmation_phrase,
        )

    @tool(name="list_virtual_machines", description="List bounded local QEMU/libvirt domains in the system and/or current user's session connection. Returns exact UUID, domain name, runtime state, numeric ID when active, and a short-lived identity token. The server uses fixed local URIs and excludes remote connections and domain XML/configuration.")
    def tool_list_virtual_machines(
        scope: Literal["system", "session", "both"] = "both",
        query: str = "",
        limit: int = 100,
    ) -> VirtualMachineListResponse:
        return _list_virtual_machines(scope=scope, query=query, limit=limit)

    @tool(name="list_remote_virtual_machines", description="List a bounded QEMU/libvirt VM inventory from one explicitly supplied qemu+ssh URI ending in /system or /session. Remote URIs with passwords, query options, fragments, other drivers, or other transports are rejected. Uses read-only virsh, the server account's default SSH keys, and SSH_AUTH_SOCK only when it is an owned Unix socket; SSH config, agent forwarding, password prompts, and unknown host-key acceptance are disabled. Returns short-lived identity tokens for confirmed lifecycle actions; domain XML is omitted.")
    def tool_list_remote_virtual_machines(
        endpoint: str,
        query: str = "",
        limit: int = 100,
    ) -> RemoteVirtualMachineListResponse:
        return _list_remote_virtual_machines(endpoint=endpoint, query=query, limit=limit)

    @tool(name="list_libvirt_networks", description="List bounded virtual-network names, active state, persistence, and autostart settings from fixed local QEMU/libvirt system and/or session connections. Uses read-only virsh calls and omits network XML, bridges, addresses, DHCP leases, and port details.")
    def tool_list_libvirt_networks(
        scope: Literal["system", "session", "both"] = "both",
        limit: int = 100,
    ) -> LibvirtNetworkListResponse:
        return _list_libvirt_networks(scope=scope, limit=limit)

    @tool(name="create_libvirt_isolated_network", description="After exact client confirmation, define one persistent but inactive isolated local libvirt network. It has a libvirt-assigned bridge name and no forwarding, IP addresses, DHCP, or custom bridge settings. It rechecks the complete local network-name inventory, validates generated XML, and verifies the saved inactive definition. Starting the network is a separate confirmed action. Uses fixed qemu:///system or qemu:///session URIs and current-account libvirt permissions without sudo.")
    async def tool_create_libvirt_isolated_network(
        scope: Literal["system", "session"],
        name: str,
        confirmation: Annotated[
            ElicitationResult[LibvirtNetworkCreateConfirmation],
            Resolve(_confirm_libvirt_network_create),
        ],
    ) -> LibvirtNetworkCreateResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_libvirt_network_create,
                scope,
                name,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_libvirt_network_create,
            scope,
            name,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="create_libvirt_network", description="After exact client confirmation, define one persistent inactive local libvirt network in isolated, NAT, routed, or existing-Linux-bridge mode. NAT and route modes require an IPv4 bridge address/prefix and can include one bounded DHCP range; iproute2 rejects subnets overlapping current host routes and addresses. Bridge mode requires an existing Linux bridge and directly exposes guests to that bridge's LAN, without libvirt-managed firewall, IP, DNS, or DHCP. No arbitrary XML, IPv6, Open vSwitch, or host-bridge creation is supported. Starting the network is a separate confirmed action; uses fixed local QEMU URIs and current-account libvirt permissions without sudo.")
    async def tool_create_libvirt_network(
        scope: Literal["system", "session"],
        name: str,
        forward_mode: Literal["isolated", "nat", "route", "bridge"],
        *,
        bridge_name: Annotated[
            str,
            PydanticField(max_length=15, description="For bridge mode only, the name of an existing Linux bridge; omit otherwise"),
        ] = "",
        ipv4_cidr: Annotated[
            str,
            PydanticField(max_length=64, description="For nat/route, the bridge IPv4 address and prefix, such as 192.168.122.1/24; omit otherwise"),
        ] = "",
        dhcp_start: Annotated[
            str,
            PydanticField(max_length=15, description="Optional first DHCP IPv4 address for nat/route; provide with dhcp_end"),
        ] = "",
        dhcp_end: Annotated[
            str,
            PydanticField(max_length=15, description="Optional last DHCP IPv4 address for nat/route; provide with dhcp_start"),
        ] = "",
        confirmation: Annotated[
            ElicitationResult[LibvirtNetworkDefinitionConfirmation],
            Resolve(_confirm_libvirt_network_definition),
        ],
    ) -> LibvirtNetworkCreateResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_libvirt_network_definition,
                scope,
                name,
                forward_mode,
                bridge_name,
                ipv4_cidr,
                dhcp_start,
                dhcp_end,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_libvirt_network_definition,
            scope,
            name,
            forward_mode,
            bridge_name,
            ipv4_cidr,
            dhcp_start,
            dhcp_end,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="configure_libvirt_network_ipv4", description="After exact client confirmation, update the IPv4 bridge address and optional DHCP range on one existing persistent inactive NAT or routed local libvirt network. It preserves the network UUID, forwarding mode, bridge name, and autostart state, refuses unsupported XML and active/temporary networks, rejects host-subnet overlap, and leaves the network inactive. Isolated and direct-bridge networks, IPv6, arbitrary XML, and changing forwarding modes are not supported. Uses fixed local QEMU URIs and current-account libvirt permissions without sudo.")
    async def tool_configure_libvirt_network_ipv4(
        scope: Literal["system", "session"],
        name: str,
        ipv4_cidr: Annotated[
            str,
            PydanticField(max_length=64, description="New IPv4 bridge address and prefix, such as 192.168.122.1/24"),
        ],
        *,
        dhcp_action: Literal["keep", "set", "disable"] = "keep",
        dhcp_start: Annotated[
            str,
            PydanticField(max_length=15, description="For dhcp_action='set', the first IPv4 address in the new DHCP range"),
        ] = "",
        dhcp_end: Annotated[
            str,
            PydanticField(max_length=15, description="For dhcp_action='set', the last IPv4 address in the new DHCP range"),
        ] = "",
        confirmation: Annotated[
            ElicitationResult[LibvirtNetworkIPv4ConfigurationConfirmation],
            Resolve(_confirm_libvirt_network_ipv4_configuration),
        ],
    ) -> LibvirtNetworkIPv4ConfigurationResponse:
        if confirmation.action != "accept":
            return await asyncio.to_thread(
                _perform_libvirt_network_ipv4_configuration,
                scope,
                name,
                ipv4_cidr,
                dhcp_action,
                dhcp_start,
                dhcp_end,
                "",
                confirmed=False,
            )
        data = confirmation.data
        return await asyncio.to_thread(
            _perform_libvirt_network_ipv4_configuration,
            scope,
            name,
            ipv4_cidr,
            dhcp_action,
            dhcp_start,
            dhcp_end,
            data.confirmation_phrase,
            confirmed=data.confirm is True,
        )

    @tool(name="list_libvirt_storage", description="List bounded local libvirt storage pools and capacity summaries. Optionally set pool_name to list volume names, types, capacities, and allocations for one exact pool; specify system or session scope for that request. Filesystem paths, volume keys, and pool XML are omitted. This is read-only.")
    def tool_list_libvirt_storage(
        scope: Literal["system", "session", "both"] = "both",
        pool_name: str = "",
        limit: int = 100,
    ) -> LibvirtStorageInventoryResponse:
        return _list_libvirt_storage(scope=scope, pool_name=pool_name, limit=limit)

    @tool(name="manage_libvirt_resource", description="After exact client confirmation, start/stop one local libvirt virtual network or storage pool, or change its persistent autostart setting. Requires the exact scope and name from inventory, displays and confirms its UUID/current state, revalidates immediately before acting, and uses only fixed local QEMU URIs. Network stop is immediate; pool stop leaves raw data intact but may disrupt guests using its volumes. Does not define, undefine, edit, build, delete, or modify volumes.")
    async def tool_manage_libvirt_resource(
        action: LibvirtResourceActionName,
        resource_type: LibvirtResourceTypeName,
        scope: Literal["system", "session"],
        name: str,
        confirmation: Annotated[
            ElicitationResult[LibvirtResourceActionConfirmation],
            Resolve(_confirm_libvirt_resource_action),
        ],
    ) -> LibvirtResourceActionResponse:
        if confirmation.action != "accept":
            return LibvirtResourceActionResponse(
                success=False,
                action=action,
                resource_type=resource_type,
                scope=scope,
                name=name,
                user_confirmed=False,
                message=f"Libvirt resource confirmation was {confirmation.action}; no action was run.",
            )
        data = confirmation.data
        if (
            data.action != action
            or data.resource_type != resource_type
            or data.scope != scope
            or data.name != name
        ):
            return LibvirtResourceActionResponse(
                success=False,
                action=action,
                resource_type=resource_type,
                scope=scope,
                name=name,
                user_confirmed=False,
                message="Confirmation did not repeat the exact resource, scope, and action; no command was run.",
            )
        if not data.confirm:
            return await asyncio.to_thread(
                _perform_libvirt_resource_action,
                action,
                resource_type,
                scope,
                name,
                data.uuid,
                data.expected_state_token,
                confirmed=False,
            )
        return await asyncio.to_thread(
            _perform_libvirt_resource_action,
            action,
            resource_type,
            scope,
            name,
            data.uuid,
            data.expected_state_token,
            confirmed=True,
        )

    @tool(name="create_libvirt_storage_volume", description="After exact client confirmation, create a sparse raw or qcow2 volume with a requested 1 MiB to 1 TiB virtual capacity in one persistent, running, directory-backed local libvirt pool. Requires exact scope and pool name, a new constrained volume name, and repeats the pool UUID/current state plus all requested values in confirmation. Revalidates pool identity/state and volume-name availability immediately before creation, then verifies exact volume name/capacity/format. Sparse guest writes can overcommit storage. Does not attach the volume to a VM or modify existing volumes; uses only fixed local QEMU URIs and current-account permissions without sudo.")
    async def tool_create_libvirt_storage_volume(
        scope: Literal["system", "session"],
        pool_name: str,
        volume_name: str,
        capacity_bytes: int,
        volume_format: Literal["raw", "qcow2"],
        confirmation: Annotated[
            ElicitationResult[LibvirtVolumeCreateConfirmation],
            Resolve(_confirm_libvirt_volume_create),
        ],
    ) -> LibvirtVolumeCreateResponse:
        if confirmation.action != "accept":
            return LibvirtVolumeCreateResponse(
                success=False,
                scope=scope,
                pool_name=pool_name,
                volume_name=volume_name,
                capacity_bytes=capacity_bytes,
                volume_format=volume_format,
                user_confirmed=False,
                message=f"Libvirt volume-creation confirmation was {confirmation.action}; no volume was created.",
            )
        data = confirmation.data
        if (
            data.scope != scope
            or data.pool_name != pool_name
            or data.volume_name != volume_name
            or data.capacity_bytes != capacity_bytes
            or data.volume_format != volume_format
        ):
            return LibvirtVolumeCreateResponse(
                success=False,
                scope=scope,
                pool_name=pool_name,
                volume_name=volume_name,
                capacity_bytes=capacity_bytes,
                volume_format=volume_format,
                user_confirmed=False,
                message="Confirmation did not repeat the exact pool, scope, volume name, capacity, and format; no command was run.",
            )
        return await asyncio.to_thread(
            _perform_libvirt_volume_create,
            scope,
            pool_name,
            volume_name,
            capacity_bytes,
            volume_format,
            data.pool_uuid,
            data.expected_state_token,
            confirmed=data.confirm is True,
        )

    @tool(name="observe_desktop", description="Observe visible windows/workspaces and issue a short-lived one-use token for clipboard or notification operations.")
    def tool_observe_desktop() -> DesktopObservationResponse:
        return _observe_desktop()

    @tool(name="list_windows", description="List visible windows and return a fresh one-use token bound to the exact window/workspace IDs for supported actions and input.")
    def tool_list_windows() -> WindowListResponse:
        return _list_windows()

    @tool(name="get_window_detail", description="Get details for an exact compositor window ID and issue a fresh action token for that window.")
    def tool_get_window_detail(target: str) -> WindowDetailResponse:
        return _get_window_detail(target)

    @tool(name="get_focused_window", description="Get the currently focused window and issue a fresh token for its exact ID.")
    def tool_get_focused_window() -> FocusedWindowResponse:
        return _get_focused_window()

    @tool(name="list_workspaces", description="List workspaces and return a fresh token bound to the observed workspace and window IDs.")
    def tool_list_workspaces() -> WorkspaceListResponse:
        return _list_workspaces()

    @tool(name="list_outputs", description="List compositor-reported monitors, current modes, scale, focus, and logical bounds when available.")
    def tool_list_outputs() -> OutputListResponse:
        from wayland_mcp.backends.registry import detect_backend
        return detect_backend().list_outputs()

    @tool(name="focus_window", description="Focus one exact observed window ID. Consumes the observation token.")
    def tool_focus_window(target: str, token_id: str) -> ActionResult:
        return _focus_window(target, token_id)

    @tool(name="close_window", description="Request the compositor to close one exact observed window ID. Consumes the observation token.")
    def tool_close_window(target: str, token_id: str) -> ActionResult:
        return _close_window(target, token_id)

    @tool(name="resize_window", description="Resize one exact observed window ID where supported. Dimensions are bounded by the compositor adapter.")
    def tool_resize_window(target: str, width: int, height: int, token_id: str) -> ActionResult:
        return _resize_window(target, width, height, token_id)

    @tool(name="minimize_window", description="Minimize one exact observed window ID where the compositor supports it.")
    def tool_minimize_window(target: str, token_id: str) -> ActionResult:
        return _minimize_window(target, token_id)

    @tool(name="maximize_window", description="Maximize one exact observed window ID where the compositor has a native per-window operation.")
    def tool_maximize_window(target: str, token_id: str) -> ActionResult:
        return _maximize_window(target, token_id)

    @tool(name="switch_workspace", description="Switch to one exact workspace ID from a fresh workspace observation.")
    def tool_switch_workspace(workspace: str, token_id: str) -> ActionResult:
        return _switch_workspace(workspace, token_id)

    @tool(name="move_window_to_workspace", description="Move one exact observed window to an exact workspace ID from the same observation token.")
    def tool_move_window_to_workspace(target: str, workspace: str, token_id: str) -> ActionResult:
        return _move_window_to_workspace(target, workspace, token_id)

    @tool(name="capture_screenshot", description="Capture a PNG of the desktop or a focused/exact window. Exact targeted captures fail closed when the compositor cannot verify the requested ID; EWMH-compatible X11 uses optional maim for the root window or an exact observed numeric window ID. Returns MCP image content and a fresh observation token where available.", structured_output=False)
    async def tool_capture_screenshot(scope: str = "window", target: str | None = None) -> CallToolResult:
        response, image_data = await _capture_screenshot(scope=scope, target=target)
        content: list[TextContent | ImageContent] = [
            TextContent(text=json.dumps(response.model_dump(mode="json"), ensure_ascii=False))
        ]
        if response.success and image_data:
            content.append(Image(data=image_data, format="png").to_image_content())
        return CallToolResult(content=content, structured_content=response.model_dump(mode="json"))

    @tool(name="inspect_accessibility_tree", description="Inspect a bounded AT-SPI2 accessibility tree for the desktop or one named application. No browser-specific inspection is performed.")
    def tool_inspect_accessibility_tree(application: str | None = None, max_depth: int = 3) -> AccessibilityTreeResponse:
        return _inspect_accessibility_tree(application=application, max_depth=max_depth)

    @tool(name="pointer_action", description="Move, click, double-click, scroll, or drag within the exact observed focused window. Coordinates are relative to its current geometry; drag requires start_x/start_y plus destination x/y. Supports left/middle/right and side/extra/forward/back/task mouse buttons. Wayland requires XDG RemoteDesktop permission. X11 uses optional xdotool XTEST input after rechecking the exact focused window and pointer position; scroll amounts become discrete wheel steps. Niri uses a separate user-selected monitor ScreenCast stream with absolute coordinates and exact output-bound checks.")
    async def tool_pointer_action(
        target_window_id: str,
        token_id: str,
        action: str,
        x: int | None = None,
        y: int | None = None,
        button: str = "left",
        delta_x: int = 0,
        delta_y: int = 0,
        start_x: int | None = None,
        start_y: int | None = None,
    ) -> PointerActionResult:
        return await _pointer_action(target_window_id, token_id, action, x, y, button, delta_x, delta_y, start_x, start_y)

    @tool(name="keyboard_action", description="Type up to 1000 characters or press one bounded key/chord in the exact window bound by the fresh observation token. Wayland requires XDG RemoteDesktop permission. X11 uses optional xdotool XTEST input and rechecks the exact focused window before typing or sending a key.")
    async def tool_keyboard_action(
        target_window_id: str,
        token_id: str,
        action: str,
        text: str | None = None,
        key: str | None = None,
    ) -> KeyboardActionResult:
        return await _keyboard_action(target_window_id, token_id, action, text, key)

    @tool(name="touch_action", description="Send one bounded single-finger tap, double-tap, long-press, or swipe to the exact observed focused window. Requires XDG RemoteDesktop touchscreen permission and a user-selected monitor ScreenCast stream whose logical bounds match one current compositor output. The screen stream is used for coordinate mapping only; this tool does not read its pixels. Newly granted portal permission stops the first attempt so the window can be observed again.")
    async def tool_touch_action(
        target_window_id: str,
        token_id: str,
        action: str,
        x: int,
        y: int,
        end_x: int | None = None,
        end_y: int | None = None,
        duration_ms: int | None = None,
    ) -> TouchActionResult:
        return await _touch_action(target_window_id, token_id, action, x, y, end_x, end_y, duration_ms)

    @tool(name="list_desktop_apps", description="List visible Freedesktop applications, excluding browser automation, and return a token bound to the exact IDs shown.")
    def tool_list_desktop_apps(query: str = "", limit: int = 100) -> AppListResponse:
        return _list_desktop_apps(query=query, limit=limit)

    @tool(name="launch_app", description="Launch one exact application ID returned by list_desktop_apps. No shell or caller-supplied command/arguments are accepted.")
    def tool_launch_app(app_id: str, token_id: str) -> AppLaunchResult:
        return _launch_app(app_id, token_id)

    @tool(name="read_clipboard", description="Read bounded plain text from the Wayland clipboard using a fresh observe_desktop token.")
    def tool_read_clipboard(token_id: str, max_bytes: int = 32768) -> ClipboardContent:
        return _read_clipboard(token_id, max_bytes)

    @tool(name="write_clipboard", description="Replace clipboard contents with up to 64 KiB of text using a fresh observe_desktop token.")
    def tool_write_clipboard(text: str, token_id: str) -> ClipboardWriteResult:
        return _write_clipboard(text, token_id)

    @tool(name="send_notification", description="Send one bounded desktop notification using a fresh observe_desktop token.")
    def tool_send_notification(title: str, body: str, token_id: str) -> NotificationResult:
        return _send_notification(title, body, token_id)

    return server


async def run_server(tool_selection: ToolSelection | None = None) -> None:
    logger.info("Starting linux-mcp stdio server.")
    server = create_server(tool_selection)
    try:
        await server.run_stdio_async()
    except Exception as exc:
        logger.error("Fatal error in linux-mcp server: %s", exc, exc_info=True)
        raise


def _parse_startup_selection(argv: list[str] | None = None) -> ToolSelection:
    parser = argparse.ArgumentParser(
        prog="linux-mcp",
        description="Run the Linux MCP server with optional category and individual-tool selection.",
    )
    parser.add_argument(
        "--disable-category",
        action="append",
        choices=CATEGORIES,
        default=[],
        metavar="CATEGORY",
        help="hide every tool in a category (repeatable)",
    )
    parser.add_argument(
        "--enable-category",
        action="append",
        choices=CATEGORIES,
        default=[],
        metavar="CATEGORY",
        help="re-enable a category disabled in the environment (repeatable)",
    )
    parser.add_argument(
        "--disable-tool",
        action="append",
        metavar="TOOL",
        default=[],
        help="hide one named tool (repeatable)",
    )
    parser.add_argument(
        "--enable-tool",
        action="append",
        metavar="TOOL",
        default=[],
        help="re-enable one named tool disabled by category or environment (repeatable)",
    )
    parser.add_argument(
        "--list-tool-categories",
        action="store_true",
        help="print category names and their tools, then exit",
    )
    args = parser.parse_args(argv)
    if args.list_tool_categories:
        for category in CATEGORIES:
            tools = sorted(
                name
                for name, group in TOOL_CATEGORIES.items()
                if category in TOOL_CATEGORY_MEMBERSHIPS[name]
            )
            print(f"{category}: {', '.join(tools)}")
        raise SystemExit(0)
    try:
        return ToolSelection.from_environment().with_cli_overrides(
            disable_categories=args.disable_category,
            enable_categories=args.enable_category,
            disable_tools=args.disable_tool,
            enable_tools=args.enable_tool,
        )
    except ValueError as exc:
        parser.error(str(exc))


def main(argv: list[str] | None = None) -> None:
    try:
        asyncio.run(run_server(_parse_startup_selection(argv)))
    except KeyboardInterrupt:
        logger.info("linux-mcp server stopped.")


if __name__ == "__main__":
    main()
