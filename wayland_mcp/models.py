from __future__ import annotations

from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field, StrictBool, StrictInt

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
PowerActionAvailability = Literal["yes", "no", "challenge", "na", "unknown"]


class WindowGeometry(BaseModel):
    x: int = 0
    y: int = 0
    width: int = 0
    height: int = 0


class WindowState(BaseModel):
    is_focused: bool = False
    is_minimized: bool = False
    is_maximized: Optional[bool] = Field(
        default=None,
        description="Whether the window is maximized when this compositor reports the state; null means unknown.",
    )
    is_fullscreen: bool = False
    is_floating: bool = False


class WindowInfo(BaseModel):
    id: str = Field(description="Unique window identifier or memory address assigned by compositor")
    app_id: str = Field(description="Application class or Freedesktop app-id")
    title: str = Field(description="Window title text")
    workspace_id: Optional[str] = Field(default=None, description="Identifier of the workspace holding the window")
    workspace_name: Optional[str] = Field(default=None, description="Human-readable name of the workspace")
    is_focused: bool = Field(default=False, description="Whether this window currently has keyboard/input focus")
    geometry: Optional[WindowGeometry] = Field(default=None, description="Window boundary box (x, y, w, h)")
    state: WindowState = Field(default_factory=WindowState, description="Window state flags (minimized, maximized, etc.)")


class WorkspaceInfo(BaseModel):
    id: str = Field(description="Unique workspace identifier")
    name: str = Field(description="Workspace label or name")
    is_active: bool = Field(default=False, description="Whether this workspace is currently active/visible")
    is_focused: bool = Field(default=False, description="Whether this workspace currently has compositor input focus")
    monitor: Optional[str] = Field(default=None, description="Monitor output name hosting this workspace")
    windows_count: int = Field(default=0, description="Number of windows on this workspace")


class OutputInfo(BaseModel):
    id: str = Field(description="Compositor-assigned display output name")
    name: str = Field(description="Display output name")
    make: Optional[str] = Field(default=None, description="Display manufacturer when reported by the compositor")
    model: Optional[str] = Field(default=None, description="Display model when reported by the compositor")
    enabled: bool = Field(default=True, description="Whether this display output is currently enabled")
    is_focused: bool = Field(default=False, description="Whether this output currently has compositor focus")
    width_pixels: Optional[int] = Field(default=None, description="Current mode width in physical pixels")
    height_pixels: Optional[int] = Field(default=None, description="Current mode height in physical pixels")
    refresh_rate_hz: Optional[float] = Field(default=None, description="Current refresh rate in hertz")
    scale: Optional[float] = Field(default=None, description="Logical output scale factor")
    logical_geometry: Optional[WindowGeometry] = Field(default=None, description="Logical compositor-space output bounds when reported")


class OutputListResponse(BaseModel):
    success: bool
    total_outputs: int
    outputs: List[OutputInfo]
    compositor: str
    message: Optional[str] = None


class SessionInfo(BaseModel):
    session_type: str = Field(description="XDG_SESSION_TYPE (e.g. 'wayland', 'x11', 'headless')")
    is_wayland: bool = Field(description="True if running inside an active Wayland display session")
    wayland_display: Optional[str] = Field(default=None, description="WAYLAND_DISPLAY socket name (e.g. 'wayland-1')")
    x11_display: Optional[str] = Field(default=None, description="X11 DISPLAY variable (e.g. ':1')")
    desktop_name: str = Field(description="Reported desktop environment name (XDG_CURRENT_DESKTOP)")
    compositor_backend: str = Field(description="Internal backend driver name matching this compositor")


class PerCapabilityStatus(BaseModel):
    supported: bool = Field(description="Whether the compositor protocol supports this capability conceptually")
    available: bool = Field(description="Whether this capability is currently callable and ready on this system")
    reason: Optional[str] = Field(default=None, description="Explanation if unsupported or unavailable")
    required_dependency: Optional[str] = Field(default=None, description="External binary, portal, or companion needed")
    required_permission: Optional[str] = Field(default=None, description="User permission or portal grant required")
    state: Literal[
        "ready", "partial", "permission_required", "permission_denied",
        "dependency_missing", "session_not_started", "not_supported", "error"
    ] = Field(default="not_supported", description="Current capability state")


class CompositorCapabilities(BaseModel):
    """Compatibility shape used by compositor adapters to publish capabilities."""
    window_list: bool = False
    window_detail: bool = False
    window_focus: bool = False
    window_close: bool = False
    window_resize: bool = False
    window_minimize: bool = False
    window_maximize: bool = False
    workspace_list: bool = False
    output_list: bool = False
    workspace_switch: bool = False
    window_move: bool = False
    screenshot: bool = False
    bounded_input: bool = False
    app_discovery: bool = False
    app_launch: bool = False
    clipboard_read: bool = False
    clipboard_write: bool = False
    notifications: bool = False
    accessibility: bool = False
    unsupported_operations: List[str] = Field(default_factory=list)

    def as_status_map(self) -> Dict[str, PerCapabilityStatus]:
        result: Dict[str, PerCapabilityStatus] = {}
        for name, available in self.model_dump(exclude={"unsupported_operations"}).items():
            result[name] = PerCapabilityStatus(
                supported=bool(available),
                available=bool(available),
                state="ready" if available else "not_supported",
                reason=None if available else "Not implemented for this compositor backend",
            )
        return result


class CapabilitiesResponse(BaseModel):
    session: SessionInfo
    capabilities: Dict[str, PerCapabilityStatus]
    summary: str = Field(description="Human-readable summary of backend status and support")


class FocusedWindowResponse(BaseModel):
    success: bool
    window: Optional[WindowInfo] = None
    token_id: Optional[str] = Field(default=None, description="Fresh one-use observation token for actions on the exact focused window")
    message: Optional[str] = None


class WindowListResponse(BaseModel):
    success: bool
    total_windows: int
    windows: List[WindowInfo]
    focused_window: Optional[WindowInfo] = None
    compositor: str
    token_id: Optional[str] = None
    message: Optional[str] = None


class WindowDetailResponse(BaseModel):
    success: bool
    window: Optional[WindowInfo] = None
    compositor: str
    token_id: Optional[str] = None
    message: Optional[str] = None


class WorkspaceListResponse(BaseModel):
    success: bool
    total_workspaces: int
    workspaces: List[WorkspaceInfo]
    active_workspace: Optional[WorkspaceInfo] = None
    compositor: str
    token_id: Optional[str] = None
    message: Optional[str] = None


class ActionResult(BaseModel):
    success: bool
    action: str = Field(description="Action name performed (e.g. 'focus_window', 'close_window')")
    target: Optional[str] = Field(default=None, description="Target window identifier or workspace")
    message: str = Field(description="Human-readable result or diagnostic explanation")
    requires_reobservation: bool = Field(
        default=True,
        description="Whether this action alters desktop state such that fresh observation is required before further input",
    )


class ScreenshotResponse(BaseModel):
    success: bool
    scope: str = Field(description="'window' or 'desktop'")
    target: Optional[str] = Field(default=None, description="Target window identifier if window-scoped")
    geometry: Optional[WindowGeometry] = Field(default=None, description="Pixel coordinates and dimensions of capture")
    mime_type: str = Field(default="image/png", description="MIME format of captured image")
    image_base64: str = Field(default="", description="Empty for MCP transport; screenshot pixels are returned as an image content block")
    token_id: Optional[str] = Field(default=None, description="Fresh observation snapshot token bound to this screenshot")
    message: Optional[str] = None


class AccessibilityNode(BaseModel):
    name: str = Field(default="", description="Accessible element label or name")
    role: str = Field(default="", description="Accessible role (e.g. push button, text, window, list)")
    description: Optional[str] = Field(default=None, description="Accessibility description if available")
    states: List[str] = Field(default_factory=list, description="Active states (e.g. focused, visible, editable)")
    bounds: Optional[Dict[str, int]] = Field(default=None, description="Bounding rectangle {x, y, width, height}")
    actions: List[str] = Field(default_factory=list, description="Supported accessible actions (e.g. click, press, activate)")
    children_count: int = Field(default=0, description="Total number of child accessible elements")
    children: List["AccessibilityNode"] = Field(default_factory=list, description="Subtree child nodes within budget")


class AccessibilityTreeResponse(BaseModel):
    success: bool
    application: Optional[str] = Field(default=None, description="Application queried")
    root: Optional[AccessibilityNode] = Field(default=None, description="Root accessible node within query budget")
    total_nodes_collected: int = Field(default=0, description="Total accessible nodes retrieved within limits")
    time_elapsed_ms: float = Field(default=0.0, description="Execution duration in milliseconds")
    token_id: Optional[str] = Field(default=None, description="Fresh observation snapshot token bound to this tree")
    message: Optional[str] = None


class PointerAction(BaseModel):
    action: str = Field(description="'click', 'double_click', 'move', 'scroll', or 'drag'")
    x: Optional[int] = Field(default=None, description="X pixel coordinate relative to target window or desktop")
    y: Optional[int] = Field(default=None, description="Y pixel coordinate relative to target window or desktop")
    start_x: Optional[int] = Field(default=None, description="Drag start X coordinate relative to target window")
    start_y: Optional[int] = Field(default=None, description="Drag start Y coordinate relative to target window")
    button: str = Field(default="left", description="Mouse button: left, middle, right, side, extra, forward, back, or task")
    delta_x: int = Field(default=0, description="Horizontal scroll amount")
    delta_y: int = Field(default=0, description="Vertical scroll amount")


class PointerActionResult(BaseModel):
    success: bool
    actions_performed: int
    message: str
    requires_reobservation: bool = True


class KeyboardAction(BaseModel):
    action: str = Field(description="'type_text' or 'press_key'")
    text: Optional[str] = Field(default=None, description="Text string to type (bounded length)")
    key: Optional[str] = Field(default=None, description="Key name to press (e.g. 'Return', 'Escape', 'Tab', 'Ctrl+c')")


class KeyboardActionResult(BaseModel):
    success: bool
    text_length: int = 0
    key_pressed: Optional[str] = None
    message: str
    requires_reobservation: bool = True


class TouchActionResult(BaseModel):
    success: bool
    actions_performed: int = 0
    message: str
    requires_reobservation: bool = True


class DesktopAppInfo(BaseModel):
    id: str = Field(description="Freedesktop desktop entry filename (e.g. 'org.gnome.Calculator.desktop')")
    name: str = Field(description="Human-readable application name")
    generic_name: Optional[str] = Field(default=None, description="Generic category name (e.g. 'Text Editor')")
    comment: Optional[str] = Field(default=None, description="Application description or tooltip")
    categories: List[str] = Field(default_factory=list, description="Freedesktop categories")
    icon: Optional[str] = Field(default=None, description="Icon name or path")
    nodisplay: bool = Field(default=False, description="Whether NoDisplay is set in .desktop file")


class AppListResponse(BaseModel):
    success: bool
    total_apps: int
    applications: List[DesktopAppInfo]
    token_id: Optional[str] = None
    message: Optional[str] = None


class ClipboardContent(BaseModel):
    success: bool
    mime_type: str = "text/plain"
    text: str = ""
    message: Optional[str] = None


class NotificationResult(BaseModel):
    success: bool
    notification_id: Optional[int] = None
    message: str


class AppLaunchResult(BaseModel):
    success: bool
    app_id: str
    message: str


class InputActionResult(BaseModel):
    success: bool
    action: str
    target_window_id: str
    message: str
    requires_reobservation: bool = True


class ClipboardWriteResult(BaseModel):
    success: bool
    bytes_written: int = 0
    message: str


class DesktopObservationResponse(BaseModel):
    """One bounded observation of current windows, workspaces, and display bounds."""
    success: bool
    compositor: str
    windows: List[WindowInfo] = Field(default_factory=list)
    workspaces: List[WorkspaceInfo] = Field(default_factory=list)
    desktop_geometry: Optional[WindowGeometry] = None
    token_id: Optional[str] = None
    message: Optional[str] = None


class LinuxSystemInfoResponse(BaseModel):
    """Basic host identity and operating-system details; excludes machine IDs and credentials."""
    success: bool
    hostname: Optional[str] = None
    distribution: Optional[str] = None
    distribution_id: Optional[str] = None
    distribution_version: Optional[str] = None
    kernel_release: Optional[str] = None
    architecture: Optional[str] = None
    init_system: Optional[str] = None
    uptime_seconds: Optional[float] = None
    message: Optional[str] = None


class ResourceUsageResponse(BaseModel):
    """Memory, swap, load average, and CPU count read from Linux procfs."""
    success: bool
    logical_cpu_count: Optional[int] = None
    load_average_1m: Optional[float] = None
    load_average_5m: Optional[float] = None
    load_average_15m: Optional[float] = None
    memory_total_bytes: Optional[int] = None
    memory_available_bytes: Optional[int] = None
    memory_used_bytes: Optional[int] = None
    swap_total_bytes: Optional[int] = None
    swap_free_bytes: Optional[int] = None
    uptime_seconds: Optional[float] = None
    message: Optional[str] = None


class PressureStallMetric(BaseModel):
    avg10_percent: float = Field(ge=0, le=100)
    avg60_percent: float = Field(ge=0, le=100)
    avg300_percent: float = Field(ge=0, le=100)
    total_microseconds: int = Field(ge=0, le=18_446_744_073_709_551_615)


class PressureStallResource(BaseModel):
    resource: Literal["cpu", "memory", "io"]
    available: bool
    some: Optional[PressureStallMetric] = None
    full: Optional[PressureStallMetric] = None
    partial: bool = False


class PressureStallInfoResponse(BaseModel):
    success: bool
    available_resources: int = 0
    resources: List[PressureStallResource] = Field(default_factory=list)
    partial: bool = False
    message: Optional[str] = None


class CPUUtilization(BaseModel):
    logical_cpu: int = Field(description="Linux logical CPU ID")
    utilization_percent: float = Field(ge=0, le=100)


class ResourceHistorySample(BaseModel):
    timestamp_utc: str
    elapsed_seconds: float
    cpu_utilization_percent: Optional[float] = Field(default=None, ge=0, le=100)
    per_cpu: List[CPUUtilization] = Field(default_factory=list)
    memory_total_bytes: Optional[int] = None
    memory_available_bytes: Optional[int] = None
    memory_used_bytes: Optional[int] = None
    swap_total_bytes: Optional[int] = None
    swap_free_bytes: Optional[int] = None
    load_average_1m: Optional[float] = None
    load_average_5m: Optional[float] = None
    load_average_15m: Optional[float] = None
    uptime_seconds: Optional[float] = None


class ResourceHistoryResponse(BaseModel):
    success: bool
    requested_samples: int
    returned_samples: int = 0
    interval_seconds: float
    samples: List[ResourceHistorySample] = Field(default_factory=list)
    truncated_cpu_list: bool = False
    message: Optional[str] = None


class ProcessResourceSample(BaseModel):
    timestamp_utc: str
    elapsed_seconds: float
    cpu_interval_seconds: Optional[float] = None
    cpu_utilization_percent: Optional[float] = Field(default=None, ge=0)
    resident_memory_bytes: Optional[int] = None
    virtual_memory_bytes: Optional[int] = None
    thread_count: Optional[int] = None
    storage_read_bytes: Optional[int] = None
    storage_write_bytes: Optional[int] = None
    storage_read_bytes_per_second: Optional[float] = Field(default=None, ge=0)
    storage_write_bytes_per_second: Optional[float] = Field(default=None, ge=0)


class ProcessResourceHistory(BaseModel):
    pid: int
    process_name: Optional[str] = None
    state: Literal["ready", "partially_available", "unavailable", "process_changed"]
    samples: List[ProcessResourceSample] = Field(default_factory=list)


class ProcessResourceHistoryResponse(BaseModel):
    success: bool
    requested_pids: List[int] = Field(default_factory=list)
    requested_samples: int
    returned_samples: int = 0
    interval_seconds: float
    processes: List[ProcessResourceHistory] = Field(default_factory=list)
    partial: bool = False
    message: Optional[str] = None


class ProcessCgroupHistorySample(BaseModel):
    timestamp_utc: str
    elapsed_seconds: float
    cpu_interval_seconds: Optional[float] = None
    cpu_utilization_percent: Optional[float] = Field(default=None, ge=0)
    cpu_throttled_usec_per_second: Optional[float] = Field(default=None, ge=0)
    resources: Optional[ProcessCgroupV2Resources] = None


class ProcessCgroupHistory(BaseModel):
    pid: int
    process_name: Optional[str] = None
    cgroup_path: Optional[str] = None
    state: Literal["ready", "partially_available", "unavailable", "process_changed", "cgroup_changed"]
    samples: List[ProcessCgroupHistorySample] = Field(default_factory=list)


class ProcessCgroupHistoryResponse(BaseModel):
    success: bool
    requested_pids: List[int] = Field(default_factory=list)
    requested_samples: int
    returned_samples: int = 0
    interval_seconds: float
    processes: List[ProcessCgroupHistory] = Field(default_factory=list)
    partial: bool = False
    message: Optional[str] = None


class CPUInfo(BaseModel):
    logical_cpu: int = Field(description="Linux logical CPU ID")
    online: Optional[bool] = Field(default=None, description="Whether this logical CPU is online when reported by procfs/sysfs")
    physical_package_id: Optional[int] = Field(default=None, description="Physical package ID from CPU topology sysfs")
    core_id: Optional[int] = Field(default=None, description="Core ID from CPU topology sysfs")
    vendor_id: Optional[str] = Field(default=None, description="CPU vendor identifier from procfs")
    model_name: Optional[str] = Field(default=None, description="CPU model string from procfs")
    scaling_frequency_mhz: Optional[float] = Field(default=None, description="Last frequency requested by the scaling driver, when exposed")
    hardware_frequency_mhz: Optional[float] = Field(default=None, description="Frequency reported from hardware, when exposed")
    minimum_frequency_mhz: Optional[float] = None
    maximum_frequency_mhz: Optional[float] = None


class CPUInventoryResponse(BaseModel):
    success: bool
    architecture: Optional[str] = None
    logical_cpu_count: int = Field(default=0, description="Discovered logical CPU entries, including offline CPUs when listed")
    online_cpu_count: Optional[int] = Field(default=None, description="Online logical CPU count when it can be determined")
    vendor_id: Optional[str] = None
    model_name: Optional[str] = None
    returned_cpus: int = 0
    cpus: List[CPUInfo] = Field(default_factory=list)
    limit: int = 128
    truncated: bool = False
    message: Optional[str] = None


class NUMANodeDistance(BaseModel):
    target_node_id: int = Field(ge=0, le=65_535)
    distance: int = Field(ge=0, le=65_535)


class NUMANodeInfo(BaseModel):
    node_id: int = Field(ge=0, le=65_535)
    online: Optional[bool] = Field(default=None, description="Whether the node is online when reported by sysfs")
    cpu_ids: List[int] = Field(default_factory=list, description="Bounded logical CPU IDs associated with this node")
    cpu_count: Optional[int] = Field(default=None, description="Full CPU membership count when its sysfs list parsed successfully")
    cpu_ids_truncated: bool = Field(default=False, description="Whether the returned CPU ID list was shortened by the response cap")
    memory_total_bytes: Optional[int] = Field(default=None, ge=0)
    memory_free_bytes: Optional[int] = Field(default=None, ge=0)
    distances_to_online_nodes: List[NUMANodeDistance] = Field(default_factory=list)
    distances_truncated: bool = Field(default=False, description="Whether the distance vector was shortened by the response cap")


class NUMANodeListResponse(BaseModel):
    success: bool
    node_count: int = Field(default=0, description="Discovered NUMA node directories before the requested result limit")
    online_node_count: Optional[int] = Field(default=None)
    returned_nodes: int = 0
    nodes: List[NUMANodeInfo] = Field(default_factory=list)
    limit: int = 128
    partial: bool = False
    truncated: bool = False
    message: Optional[str] = None


class GPUFrequencyInfo(BaseModel):
    tile_id: int = Field(ge=0, le=65_535)
    gt_id: int = Field(ge=0, le=65_535)
    actual_frequency_mhz: int = Field(ge=0, le=100_000, description="Actual resolved Xe GT frequency reported by the kernel, in MHz")


class GPUDeviceInfo(BaseModel):
    drm_card: str = Field(description="Kernel DRM card node name")
    pci_address: Optional[str] = None
    vendor_id: Optional[str] = None
    device_id: Optional[str] = None
    subsystem_vendor_id: Optional[str] = None
    subsystem_device_id: Optional[str] = None
    class_code: Optional[str] = None
    driver: Optional[str] = None
    boot_vga: Optional[bool] = None
    amdgpu_busy_percent: Optional[int] = Field(default=None, ge=0, le=100)
    amdgpu_vram_total_bytes: Optional[int] = Field(default=None, ge=0)
    amdgpu_vram_used_bytes: Optional[int] = Field(default=None, ge=0)
    telemetry_source: Optional[Literal["amdgpu_sysfs", "i915_hwmon", "xe_sysfs", "nouveau_hwmon", "nvidia_smi"]] = None
    utilization_percent: Optional[int] = Field(default=None, ge=0, le=100)
    memory_total_bytes: Optional[int] = Field(default=None, ge=0)
    memory_used_bytes: Optional[int] = Field(default=None, ge=0)
    temperature_celsius: Optional[int] = Field(default=None, ge=0, le=255)
    power_draw_watts: Optional[float] = Field(default=None, ge=0, le=100000)
    energy_input_microjoules: Optional[int] = Field(default=None, ge=0, description="Driver-reported cumulative device energy counter; not a power rate")
    package_energy_input_microjoules: Optional[int] = Field(default=None, ge=0, description="Driver-reported cumulative package energy counter; not a power rate")
    xe_gt_frequencies: List[GPUFrequencyInfo] = Field(default_factory=list, description="Available actual frequency snapshots for each Xe tile/GT")


class GPUInventoryResponse(BaseModel):
    success: bool
    total_gpus: int = Field(default=0, description="DRM cards discovered before scan/result caps")
    returned_gpus: int = 0
    gpus: List[GPUDeviceInfo] = Field(default_factory=list)
    limit: int = 32
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class GPUPowerLimitInfo(BaseModel):
    drm_card: str
    pci_address: str
    driver: str
    controller: str
    chip_name: str
    power_index: int
    current_limit_micro_watts: int = Field(description="Current driver-reported hardware power cap in microWatts")
    minimum_limit_micro_watts: int = Field(description="Minimum supported hardware cap in microWatts")
    maximum_limit_micro_watts: int = Field(description="Maximum supported hardware cap in microWatts")
    label: Optional[str] = None


class GPUPowerLimitListResponse(BaseModel):
    success: bool
    total_limits: int = 0
    returned_limits: int = 0
    limits: List[GPUPowerLimitInfo] = Field(default_factory=list)
    limit: int = 64
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class GPUPowerLimitActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact GPU power-cap change")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the exact GPU, cap range, current cap, and requested value")


class GPUPowerLimitActionResponse(BaseModel):
    success: bool
    action: Literal["set_limit"]
    drm_card: str
    controller: str
    power_index: int
    target_micro_watts: int
    resulting_micro_watts: Optional[int] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class PowercapLimitInfo(BaseModel):
    zone: str = Field(description="Relative powercap zone path, including parent zones when present")
    zone_name: str
    constraint_index: int
    constraint_name: Optional[str] = None
    current_power_limit_uw: int = Field(description="Current driver-reported constraint in microWatts")
    minimum_power_limit_uw: Optional[int] = Field(default=None, description="Driver-reported minimum writable limit, when exposed")
    maximum_power_limit_uw: Optional[int] = Field(default=None, description="Driver-reported maximum writable limit, when exposed")
    time_window_us: Optional[int] = Field(default=None, description="Current constraint window in microseconds, when exposed")
    controllable: bool = Field(description="True when a valid driver-reported minimum and maximum range is available")


class PowercapLimitListResponse(BaseModel):
    success: bool
    total_limits: int = 0
    returned_limits: int = 0
    limits: List[PowercapLimitInfo] = Field(default_factory=list)
    limit: int = 64
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class PowercapLimitActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact Linux powercap constraint change")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the exact power zone, constraint, current value, and driver-reported range")


class PowercapLimitActionResponse(BaseModel):
    success: bool
    action: Literal["set_limit"]
    zone: str
    constraint_index: int
    target_power_limit_uw: int
    resulting_power_limit_uw: Optional[int] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class GPUFrequencyLimitInfo(BaseModel):
    drm_card: str
    pci_address: str
    tile_id: int
    gt_id: int
    current_min_frequency_mhz: int
    current_max_frequency_mhz: int
    hardware_min_frequency_mhz: int
    hardware_max_frequency_mhz: int


class GPUFrequencyLimitListResponse(BaseModel):
    success: bool
    total_limits: int = 0
    returned_limits: int = 0
    limits: List[GPUFrequencyLimitInfo] = Field(default_factory=list)
    limit: int = 128
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class GPUFrequencyLimitConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact Xe GT maximum-frequency change")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the GPU, GT range, and requested maximum frequency")


class GPUFrequencyLimitActionResponse(BaseModel):
    success: bool
    drm_card: str
    tile_id: int
    gt_id: int
    target_max_frequency_mhz: int
    resulting_max_frequency_mhz: Optional[int] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class ProcessInfo(BaseModel):
    """Process metadata without command-line arguments, environment, or working directory."""
    pid: int
    parent_pid: Optional[int] = None
    name: str
    state: Optional[str] = None
    uid: Optional[int] = None
    username: Optional[str] = None
    thread_count: Optional[int] = None
    resident_memory_bytes: Optional[int] = None
    virtual_memory_bytes: Optional[int] = None


class ProcessTreeNode(ProcessInfo):
    depth: int = Field(description="Distance from the requested root process; the root has depth zero")


class ProcessListResponse(BaseModel):
    success: bool
    total_matches: int = 0
    returned_processes: int = 0
    processes: List[ProcessInfo] = Field(default_factory=list)
    limit: int = 50
    sort_by: Literal["pid", "memory"] = "pid"
    truncated: bool = False
    skipped_processes: int = 0
    message: Optional[str] = None


class ProcessDetailResponse(BaseModel):
    success: bool
    process: Optional[ProcessInfo] = None
    identity_token: Optional[str] = Field(
        default=None,
        description="Opaque process-instance token for exact signal actions; it becomes stale when the PID is reused.",
    )
    message: Optional[str] = None


class ProcessCgroupMembership(BaseModel):
    hierarchy_id: int
    controllers: List[str] = Field(default_factory=list)
    path: str = Field(description="Kernel-reported cgroup path, truncated to a bounded length")


class ProcessCgroupV2Resources(BaseModel):
    cgroup_path: str = Field(description="Cgroup-v2 path relative to the verified hierarchy root")
    level_from_process: int = Field(description="Zero is the process's leaf cgroup; larger values are ancestors")
    cpu_weight: Optional[int] = Field(default=None, description="Kernel cgroup-v2 CPU weight")
    cpu_quota_usec: Optional[int] = Field(default=None, description="CPU quota in microseconds per configured period")
    cpu_period_usec: Optional[int] = Field(default=None, description="CPU quota period in microseconds")
    cpu_quota_unlimited: Optional[bool] = Field(default=None, description="Whether cpu.max reports an unlimited quota")
    cpu_usage_usec: Optional[int] = Field(default=None, description="Cumulative CPU usage in microseconds, including descendants")
    cpu_user_usec: Optional[int] = Field(default=None, description="Cumulative user CPU time in microseconds")
    cpu_system_usec: Optional[int] = Field(default=None, description="Cumulative system CPU time in microseconds")
    cpu_nr_periods: Optional[int] = None
    cpu_nr_throttled: Optional[int] = None
    cpu_throttled_usec: Optional[int] = None
    memory_current_bytes: Optional[int] = Field(default=None, description="Current memory usage in bytes, including descendants")
    memory_max_bytes: Optional[int] = Field(default=None, description="Hard memory limit in bytes; consult memory_max_unlimited for the max sentinel")
    memory_max_unlimited: Optional[bool] = None
    memory_high_bytes: Optional[int] = Field(default=None, description="Memory high threshold in bytes; consult memory_high_unlimited for the max sentinel")
    memory_high_unlimited: Optional[bool] = None
    memory_swap_current_bytes: Optional[int] = Field(default=None, description="Current swap usage in bytes")
    memory_swap_max_bytes: Optional[int] = Field(default=None, description="Swap limit in bytes; consult memory_swap_max_unlimited for the max sentinel")
    memory_swap_max_unlimited: Optional[bool] = None
    memory_events: Dict[str, int] = Field(default_factory=dict, description="Cumulative hierarchical memory-controller event counters")
    pids_current: Optional[int] = Field(default=None, description="Current cgroup task count, including descendants")
    pids_max: Optional[int] = Field(default=None, description="Task-count limit; consult pids_max_unlimited for the max sentinel")
    pids_max_unlimited: Optional[bool] = None


class NamespaceInstanceInfo(BaseModel):
    namespace_inode: int = Field(gt=0, le=18_446_744_073_709_551_615)
    reference_count: int = Field(
        ge=1,
        description=(
            "Scanned process entries referencing this inode; for *_for_children "
            "types, this counts configured child-namespace targets, not current members."
        ),
    )
    representative_pid: int = Field(gt=0, le=2**31 - 1, description="One observed PID in this namespace; it may exit after the snapshot")


class NamespaceTypeInfo(BaseModel):
    namespace_type: Literal[
        "cgroup", "ipc", "mnt", "net", "pid", "pid_for_children",
        "time", "time_for_children", "user", "uts",
    ]
    supported: bool = True
    available: bool = False
    namespace_count: int = Field(default=0, description="Namespace groups returned; see truncated for the per-type result cap")
    namespaces: List[NamespaceInstanceInfo] = Field(default_factory=list)
    truncated: bool = False
    partial: bool = False


class NamespaceInventoryResponse(BaseModel):
    success: bool
    scanned_processes: int = 0
    skipped_processes: int = 0
    scan_limit: int = 5000
    namespace_types: List[NamespaceTypeInfo] = Field(default_factory=list)
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class ProcessExecutionContextResponse(BaseModel):
    success: bool
    pid: Optional[int] = None
    process_name: Optional[str] = None
    state: Optional[str] = None
    scheduling_policy_id: Optional[int] = None
    scheduling_policy: Optional[str] = None
    priority: Optional[int] = None
    nice_value: Optional[int] = None
    realtime_priority: Optional[int] = None
    last_cpu: Optional[int] = None
    allowed_cpus: Optional[str] = Field(default=None, description="Kernel CPU-list notation; it is not expanded into individual IDs")
    allowed_memory_nodes: Optional[str] = Field(default=None, description="Kernel memory-node list notation; it is not expanded into individual IDs")
    cgroups: List[ProcessCgroupMembership] = Field(default_factory=list)
    cgroup_v2_resources_available: bool = False
    cgroup_v2_resources: List[ProcessCgroupV2Resources] = Field(default_factory=list)
    cgroup_v2_message: Optional[str] = None
    namespace_ids: Dict[str, int] = Field(
        default_factory=dict,
        description=(
            "Visible namespace inode IDs for a fixed set of types; "
            "*_for_children keys refer to future-child namespace targets."
        ),
    )
    no_new_privileges: Optional[bool] = None
    seccomp_mode: Optional[int] = Field(default=None, description="0 disabled, 1 strict, 2 filter")
    seccomp_filter_count: Optional[int] = None
    effective_capabilities_hex: Optional[str] = Field(default=None, description="Raw effective-capability bit mask in hexadecimal")
    partial: bool = False
    message: Optional[str] = None


class ProcessTreeResponse(BaseModel):
    success: bool
    root_pid: Optional[int] = None
    total_processes: int = 0
    returned_processes: int = 0
    nodes: List[ProcessTreeNode] = Field(default_factory=list)
    max_depth: int = 8
    limit: int = 200
    truncated: bool = False
    scan_cap_reached: bool = False
    skipped_processes: int = 0
    message: Optional[str] = None


class ProcessSignalConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm sending this exact signal to the observed process instance")


class ProcessSignalResponse(BaseModel):
    success: bool
    pid: int
    process_name: Optional[str] = None
    uid: Optional[int] = None
    signal_name: str
    signal_number: Optional[int] = None
    user_confirmed: bool = Field(default=False, description="Whether the exact process signal received explicit MCP client confirmation")
    message: str


class CommandExecutionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm running the exact shell request shown in the prompt")
    confirmation_phrase: str = Field(description="Repeat the RUN phrase bound to the complete command request")


class CommandExecutionResponse(BaseModel):
    success: bool
    command_sha256: str = Field(description="SHA-256 digest of the exact command request, without echoing its contents")
    working_directory: Optional[str] = None
    run_as: Literal["server", "root"] = "server"
    exit_code: Optional[int] = None
    duration_seconds: Optional[float] = None
    stdout: str = ""
    stderr: str = ""
    output_truncated: bool = False
    timed_out: bool = False
    user_confirmed: bool = False
    message: Optional[str] = None


class TerminalSessionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact terminal-session operation")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the terminal session and exact input/action")


class TerminalSessionStartResponse(BaseModel):
    success: bool
    session_id: Optional[str] = Field(default=None, description="Opaque process-local terminal session identifier")
    pid: Optional[int] = None
    request_sha256: Optional[str] = None
    working_directory: Optional[str] = None
    run_as: Literal["server", "root"] = "server"
    terminal_rows: int = 24
    terminal_columns: int = 80
    expires_in_seconds: Optional[float] = None
    message: Optional[str] = None


class TerminalSessionOutputResponse(BaseModel):
    success: bool
    session_id: str
    output_text: str = ""
    returned_bytes: int = 0
    dropped_bytes: int = 0
    process_running: bool = False
    exit_code: Optional[int] = None
    timed_out: bool = False
    expires_in_seconds: Optional[float] = None
    message: Optional[str] = None


class TerminalSessionWriteResponse(BaseModel):
    success: bool
    session_id: str
    bytes_written: int = 0
    terminal_rows: Optional[int] = None
    terminal_columns: Optional[int] = None
    process_running: bool = False
    message: Optional[str] = None


class TerminalSessionCloseResponse(BaseModel):
    success: bool
    session_id: str
    was_running: bool = False
    exit_code: Optional[int] = None
    message: Optional[str] = None


class FilesystemInfo(BaseModel):
    mount_point: str
    filesystem_type: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    available_bytes: int
    used_percent: float


class FilesystemListResponse(BaseModel):
    success: bool
    total_filesystems: int = 0
    returned_filesystems: int = 0
    filesystems: List[FilesystemInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class MountActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm mounting or unmounting this exact configured mount point")


class MountActionResponse(BaseModel):
    success: bool
    action: Literal["mount", "unmount"]
    mount_point: str
    filesystem_type: Optional[str] = None
    user_confirmed: bool = Field(default=False, description="Whether this exact mount action received explicit MCP client confirmation")
    state_verified: bool = Field(default=False, description="Whether current mount state was read back after the command")
    message: str


class FilesystemPathInfo(BaseModel):
    path: str
    kind: Literal["file", "directory", "symlink", "socket", "fifo", "device", "other"]
    size_bytes: Optional[int] = None
    mode_octal: str
    owner_uid: int
    owner_gid: int
    modified_at: str


class PathMetadataResponse(BaseModel):
    success: bool
    metadata: Optional[FilesystemPathInfo] = None
    message: Optional[str] = None


class POSIXACLEntry(BaseModel):
    tag: Literal["user_obj", "user", "group_obj", "group", "mask", "other"]
    qualifier_id: Optional[int] = Field(default=None, description="Numeric UID for a named user or GID for a named group")
    permissions: str = Field(description="ACL permission bits rendered as rwx letters or '-'")
    effective_permissions: Optional[str] = Field(default=None, description="Permissions after the ACL mask for group and named entries")


class ExtendedAttributeInfo(BaseModel):
    name: str
    size_bytes: Optional[int] = None
    text_value: Optional[str] = Field(default=None, description="Printable UTF-8 preview when the attribute value is text")
    base64_value: Optional[str] = Field(default=None, description="Base64 preview when the attribute value is binary or non-text")
    null_terminated: bool = False
    value_truncated: bool = False
    acl_entries: List[POSIXACLEntry] = Field(default_factory=list)
    acl_entry_count: Optional[int] = None
    acl_entries_truncated: bool = False
    acl_parse_error: Optional[str] = None
    unavailable_reason: Optional[str] = None


class PathExtendedAttributeResponse(BaseModel):
    success: bool
    path: str = ""
    offset: int = 0
    next_offset: Optional[int] = None
    has_more: Optional[bool] = None
    total_attributes: int = 0
    returned_attributes: int = 0
    attributes: List[ExtendedAttributeInfo] = Field(default_factory=list)
    limit: int = 64
    partial: bool = False
    truncated: bool = False
    message: Optional[str] = None


class DirectoryEntryInfo(BaseModel):
    name: str
    kind: Literal["file", "directory", "symlink", "socket", "fifo", "device", "other"]
    size_bytes: Optional[int] = None
    mode_octal: str
    owner_uid: int
    owner_gid: int
    modified_at: str


class DirectoryListResponse(BaseModel):
    success: bool
    path: str
    scanned_entries: int = 0
    total_entries: int = 0
    returned_entries: int = 0
    entries: List[DirectoryEntryInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class TextFileReadResponse(BaseModel):
    success: bool
    path: Optional[str] = None
    size_bytes: Optional[int] = None
    bytes_returned: int = 0
    content: Optional[str] = None
    truncated: bool = False
    encoding_replacements: bool = False
    message: Optional[str] = None


class BinaryFileReadResponse(BaseModel):
    success: bool
    path: Optional[str] = None
    offset: int = 0
    size_bytes: Optional[int] = None
    bytes_returned: int = 0
    data_base64: str = ""
    next_offset: Optional[int] = None
    truncated: bool = False
    sha256: Optional[str] = None
    message: Optional[str] = None


class BinaryFileWriteConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact binary file write")
    confirmation_phrase: str = Field(description="Repeat the WRITE phrase bound to the path, action, payload, and current file state")


class BinaryFileWriteResponse(BaseModel):
    success: bool
    path: Optional[str] = None
    action: Optional[Literal["create", "replace", "append"]] = None
    bytes_written: int = 0
    file_size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class BinaryFileUploadConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm staging this exact large binary-file create or replacement")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the target path, expected size/digest, and current target state")


class BinaryFileUploadResponse(BaseModel):
    success: bool
    state: Literal["started", "uploading", "committed", "aborted", "failed"] = "failed"
    upload_id: Optional[str] = Field(default=None, description="Secret short-lived token required for appending chunks, committing, or aborting this upload")
    path: Optional[str] = None
    action: Optional[Literal["create", "replace"]] = None
    expected_size_bytes: Optional[int] = None
    uploaded_bytes: int = 0
    file_size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    file_changed: bool = False
    user_confirmed: bool = False
    message: str


class PathAdminConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact path administration action")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the canonical path, requested operation, and current object state")


class ACLWriteEntry(BaseModel):
    tag: Literal["user_obj", "user", "group_obj", "group", "mask", "other"]
    qualifier_id: Optional[int] = Field(default=None, ge=0, le=4_294_967_294, strict=True, description="Numeric UID/GID for named user/group entries")
    permissions: str = Field(description="Exactly three rwx positions, such as 'rwx', 'r-x', or '---'")


class PathAdminResponse(BaseModel):
    success: bool
    path: Optional[str] = None
    action: Optional[str] = None
    symlink_target: Optional[str] = None
    previous_uid: Optional[int] = None
    previous_gid: Optional[int] = None
    owner_uid: Optional[int] = None
    owner_gid: Optional[int] = None
    link_count: Optional[int] = None
    attribute_name: Optional[str] = None
    value_sha256: Optional[str] = None
    acl_kind: Optional[Literal["access", "default"]] = None
    acl_entry_count: Optional[int] = None
    bytes_written: Optional[int] = None
    entries_affected: Optional[int] = None
    bytes_affected: Optional[int] = None
    mode_octal: Optional[str] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class TextFileCreationConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm creation of this exact new text file")
    path: str = Field(description="Repeat the exact canonical destination path shown in the prompt")
    content_sha256: str = Field(description="Repeat the SHA-256 digest of the exact UTF-8 content shown in the prompt")


class TextFileCreationResponse(BaseModel):
    success: bool
    path: Optional[str] = None
    bytes_written: int = 0
    sha256: Optional[str] = None
    mode_octal: Optional[str] = None
    created: bool = False
    user_confirmed: bool = Field(
        default=False,
        description="Whether this exact file creation received explicit MCP client confirmation",
    )
    message: str


class TextFileReplacementConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm replacement of this exact regular text file")
    path: str = Field(description="Repeat the exact canonical path shown in the prompt")
    current_sha256: str = Field(description="Repeat the digest of the current file content shown in the prompt")
    replacement_sha256: str = Field(description="Repeat the digest of the exact replacement text shown in the prompt")


class TextFileReplacementResponse(BaseModel):
    success: bool
    path: Optional[str] = None
    previous_sha256: Optional[str] = None
    sha256: Optional[str] = None
    bytes_written: int = 0
    mode_octal: Optional[str] = None
    restored_on_failure: Optional[bool] = None
    user_confirmed: bool = Field(
        default=False,
        description="Whether this exact text-file replacement received explicit MCP client confirmation",
    )
    message: str


class TextFileDeletionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm deletion of this exact regular text file")
    path: str = Field(description="Repeat the exact canonical path shown in the prompt")
    current_sha256: str = Field(description="Repeat the digest of the current file content shown in the prompt")


class TextFileDeletionResponse(BaseModel):
    success: bool
    path: Optional[str] = None
    sha256: Optional[str] = None
    file_size_bytes: int = 0
    deleted: bool = False
    user_confirmed: bool = Field(
        default=False,
        description="Whether deletion of this exact text file received explicit MCP client confirmation",
    )
    message: str


class FileModeChangeConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact nonrecursive rwx and optional special-bit mode change")
    path: str = Field(description="Repeat the exact canonical file or directory path shown in the prompt")
    current_mode_octal: str = Field(description="Repeat the current full mode, including any special bits, shown in the prompt")
    new_mode_octal: str = Field(description="Repeat the requested full rwx and special-bit mode shown in the prompt")


class FileModeChangeResponse(BaseModel):
    success: bool
    path: Optional[str] = None
    previous_mode_octal: Optional[str] = None
    mode_octal: Optional[str] = None
    kind: Optional[Literal["file", "directory"]] = None
    access_acl_present: Optional[bool] = None
    restored_on_failure: Optional[bool] = None
    user_confirmed: bool = Field(
        default=False,
        description="Whether this exact permission-mode change received explicit MCP client confirmation",
    )
    message: str


class NetworkAddress(BaseModel):
    address: str
    prefix_length: Optional[int] = None
    scope: Optional[str] = None


class NetworkInterfaceInfo(BaseModel):
    name: str
    index: Optional[int] = None
    operational_state: Optional[str] = None
    administrative_up: Optional[bool] = None
    mtu: Optional[int] = None
    is_loopback: bool = False
    identity_token: Optional[str] = Field(
        default=None,
        description="Short-lived token bound to this exact observed interface for confirmation-gated link changes",
    )
    addresses: List[NetworkAddress] = Field(default_factory=list)
    default_gateway_ipv4: Optional[str] = None
    default_gateway_ipv6: Optional[str] = None
    rx_bytes: Optional[int] = None
    tx_bytes: Optional[int] = None
    rx_packets: Optional[int] = None
    tx_packets: Optional[int] = None
    rx_errors: Optional[int] = None
    tx_errors: Optional[int] = None


class NetworkInterfaceListResponse(BaseModel):
    success: bool
    total_interfaces: int = 0
    returned_interfaces: int = 0
    interfaces: List[NetworkInterfaceInfo] = Field(default_factory=list)
    limit: int = 64
    truncated: bool = False
    message: Optional[str] = None


class NetworkManagerProfileInfo(BaseModel):
    uuid: str
    name: str
    connection_type: str
    device: Optional[str] = None
    autoconnect: Optional[bool] = None


class NetworkManagerProfileListResponse(BaseModel):
    success: bool
    total_profiles: int = 0
    returned_profiles: int = 0
    profiles: List[NetworkManagerProfileInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    malformed_rows: int = 0
    message: Optional[str] = None


class NetworkManagerDNSFamilySettings(BaseModel):
    method: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    search_domains: List[str] = Field(default_factory=list)
    dns_options: List[str] = Field(default_factory=list)
    ignore_auto_dns: Optional[bool] = None
    dns_priority: Optional[int] = None


class NetworkManagerProfileDNSResponse(BaseModel):
    success: bool
    profile_uuid: Optional[str] = None
    profile_name: Optional[str] = None
    ipv4: Optional[NetworkManagerDNSFamilySettings] = None
    ipv6: Optional[NetworkManagerDNSFamilySettings] = None
    partial: bool = False
    truncated: bool = False
    message: Optional[str] = None


class NetworkManagerProfileDNSConfigConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm these exact persistent DNS profile changes")
    profile_uuid: str = Field(description="Repeat the exact NetworkManager profile UUID shown in the prompt")
    confirmation_phrase: str = Field(description="Repeat the state-bound phrase shown in the prompt")


class NetworkManagerProfileDNSConfigResponse(BaseModel):
    success: bool
    profile_uuid: Optional[str] = None
    profile_name: Optional[str] = None
    changed_properties: List[str] = Field(default_factory=list)
    user_confirmed: bool = False
    message: str


class NetworkManagerProfileIPResponse(BaseModel):
    success: bool
    profile_uuid: Optional[str] = None
    profile_name: Optional[str] = None
    connection_type: Optional[str] = None
    family: Optional[Literal["ipv4", "ipv6"]] = None
    method: Optional[str] = None
    addresses: List[str] = Field(default_factory=list)
    gateway: Optional[str] = None
    message: str


class NetworkManagerProfileIPConfigConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm these exact persistent NetworkManager IP profile changes")
    profile_uuid: str = Field(description="Repeat the exact NetworkManager profile UUID shown in the prompt")
    confirmation_phrase: str = Field(description="Repeat the state-bound IP configuration phrase shown in the prompt")


class NetworkManagerProfileIPConfigResponse(BaseModel):
    success: bool
    profile_uuid: Optional[str] = None
    profile_name: Optional[str] = None
    connection_type: Optional[str] = None
    family: Optional[Literal["ipv4", "ipv6"]] = None
    method: Optional[Literal["auto", "manual"]] = None
    previous_method: Optional[str] = None
    previous_addresses: List[str] = Field(default_factory=list)
    previous_gateway: Optional[str] = None
    addresses: List[str] = Field(default_factory=list)
    gateway: Optional[str] = None
    user_confirmed: bool = False
    message: str


class NetworkManagerProfileRoute(BaseModel):
    destination: str
    gateway: Optional[str] = None
    metric: Optional[int] = None
    attributes: List[str] = Field(default_factory=list)


class NetworkManagerProfileRoutesResponse(BaseModel):
    success: bool
    profile_uuid: Optional[str] = None
    profile_name: Optional[str] = None
    connection_type: Optional[str] = None
    family: Optional[Literal["ipv4", "ipv6"]] = None
    routes: List[NetworkManagerProfileRoute] = Field(default_factory=list)
    message: str


class NetworkManagerProfileRouteActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact saved NetworkManager route change")
    profile_uuid: str = Field(description="Repeat the exact NetworkManager profile UUID shown in the prompt")
    confirmation_phrase: str = Field(description="Repeat the state-bound saved-route phrase shown in the prompt")


class NetworkManagerProfileRouteActionResponse(BaseModel):
    success: bool
    profile_uuid: Optional[str] = None
    profile_name: Optional[str] = None
    connection_type: Optional[str] = None
    family: Optional[Literal["ipv4", "ipv6"]] = None
    action: Optional[Literal["add", "remove"]] = None
    route: Optional[NetworkManagerProfileRoute] = None
    previous_routes: List[NetworkManagerProfileRoute] = Field(default_factory=list)
    routes: List[NetworkManagerProfileRoute] = Field(default_factory=list)
    user_confirmed: bool = False
    message: str


class NetworkManagerProfileActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact NetworkManager connection-profile action")
    profile_uuid: str = Field(
        description="Repeat the exact profile UUID shown in the confirmation prompt",
    )


class NetworkManagerProfileActionResponse(BaseModel):
    success: bool
    action: Literal["activate", "deactivate", "enable_autoconnect", "disable_autoconnect"]
    profile_uuid: Optional[str] = None
    name: Optional[str] = None
    connection_type: Optional[str] = None
    device: Optional[str] = None
    active_before: Optional[bool] = None
    active_after: Optional[bool] = None
    autoconnect_before: Optional[bool] = None
    autoconnect_after: Optional[bool] = None
    user_confirmed: bool = Field(
        default=False,
        description="Whether this exact NetworkManager profile action received explicit MCP client confirmation",
    )
    message: str


class NetworkManagerVirtualProfileCreateConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact persistent NetworkManager bridge, bond, or VLAN profile creation")
    kind: Literal["bridge", "bond", "vlan"] = Field(description="Repeat the requested NetworkManager profile type")
    profile_name: str = Field(description="Repeat the exact profile name shown in the confirmation prompt")
    interface_name: str = Field(description="Repeat the exact interface name shown in the confirmation prompt")
    parent_interface: Optional[str] = Field(default=None, description="Repeat the VLAN parent interface, or leave blank for bridge/bond")
    vlan_id: Optional[int] = Field(default=None, description="Repeat the VLAN ID, or leave blank for bridge/bond")
    bond_mode: Optional[Literal["active-backup", "balance-rr", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"]] = Field(
        default=None,
        description="Repeat the bond mode, or leave blank for bridge/VLAN",
    )
    confirmation_phrase: str = Field(description="Repeat the state-bound profile creation phrase shown in the prompt")


class NetworkManagerVirtualProfileCreateResponse(BaseModel):
    success: bool
    kind: Optional[Literal["bridge", "bond", "vlan"]] = None
    profile_name: Optional[str] = None
    interface_name: Optional[str] = None
    parent_interface: Optional[str] = None
    vlan_id: Optional[int] = None
    bond_mode: Optional[Literal["active-backup", "balance-rr", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"]] = None
    profile_uuid: Optional[str] = None
    user_confirmed: bool = False
    message: str


class NetworkManagerPortProfileCreateConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact inactive Ethernet port profile creation")
    controller_uuid: str = Field(description="Repeat the exact bridge or bond profile UUID")
    profile_name: str = Field(description="Repeat the exact port-profile name shown in the prompt")
    interface_name: str = Field(description="Repeat the exact Ethernet interface name shown in the prompt")
    confirmation_phrase: str = Field(description="Repeat the state-bound port-profile phrase shown in the prompt")


class NetworkManagerPortProfileCreateResponse(BaseModel):
    success: bool
    controller_uuid: Optional[str] = None
    controller_name: Optional[str] = None
    controller_type: Optional[Literal["bridge", "bond"]] = None
    profile_name: Optional[str] = None
    interface_name: Optional[str] = None
    profile_uuid: Optional[str] = None
    user_confirmed: bool = False
    message: str


class NetworkManagerPortMembershipConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact saved bridge/bond port membership change")
    action: Literal["add", "remove"] = Field(description="Repeat whether to attach or detach the Ethernet profile")
    profile_uuid: str = Field(description="Repeat the exact Ethernet connection profile UUID")
    controller_uuid: str = Field(description="Repeat the exact bridge or bond profile UUID")
    confirmation_phrase: str = Field(description="Repeat the state-bound membership phrase shown in the prompt")


class NetworkManagerPortMembershipResponse(BaseModel):
    success: bool
    action: Optional[Literal["add", "remove"]] = None
    profile_uuid: Optional[str] = None
    profile_name: Optional[str] = None
    interface_name: Optional[str] = None
    controller_uuid: Optional[str] = None
    controller_name: Optional[str] = None
    controller_type: Optional[Literal["bridge", "bond"]] = None
    user_confirmed: bool = False
    message: str


class NetworkManagerVPNImportConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm importing this exact OpenVPN or WireGuard source into NetworkManager")
    vpn_type: Literal["openvpn", "wireguard"] = Field(description="Repeat the exact VPN import type")
    source_path: str = Field(description="Repeat the exact source path shown in the prompt")
    profile_name: str = Field(description="Repeat the exact saved profile name shown in the prompt")
    confirmation_phrase: str = Field(description="Repeat the state-bound import phrase shown in the prompt")


class NetworkManagerVPNImportResponse(BaseModel):
    success: bool
    vpn_type: Optional[Literal["openvpn", "wireguard"]] = None
    profile_name: Optional[str] = None
    profile_uuid: Optional[str] = None
    source_name: Optional[str] = None
    size_bytes: Optional[int] = None
    user_confirmed: bool = False
    message: str


class SystemdNetworkProfileInfo(BaseModel):
    source: Literal["etc", "run", "usr_local_lib", "usr_lib", "lib_compat"]
    filename: str
    profile_filename: Optional[str] = None
    file_type: Literal["network", "netdev", "link"]
    is_drop_in: bool = False
    is_symlink: bool = False
    masked: bool = False
    empty: bool = False
    name: Optional[str] = None
    kind: Optional[str] = None
    match_name_patterns: List[str] = Field(default_factory=list)
    match_driver_patterns: List[str] = Field(default_factory=list)
    dhcp: Optional[str] = None
    configured_dns_servers: List[str] = Field(default_factory=list)
    dns_domains: List[str] = Field(default_factory=list)
    dns_default_route: Optional[bool] = None
    dhcp_dns_settings: Dict[str, bool] = Field(default_factory=dict)
    use_domains_settings: Dict[str, str] = Field(default_factory=dict)


class SystemdNetworkProfileListResponse(BaseModel):
    success: bool
    total_profiles: int = 0
    returned_profiles: int = 0
    profiles: List[SystemdNetworkProfileInfo] = Field(default_factory=list)
    limit: int = 100
    partial: bool = False
    truncated: bool = False
    skipped_files: int = 0
    message: Optional[str] = None


class SystemdNetworkProfileConfigConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact persistent systemd-networkd profile update")
    filename: str = Field(description="Repeat the exact existing .network filename shown in the prompt")
    interface: str = Field(description="Repeat the exact interface name matched by the profile")
    state_token: str = Field(description="Repeat the state-bound token shown in the prompt")


class SystemdNetworkProfileConfigResponse(BaseModel):
    success: bool
    filename: Optional[str] = None
    interface: Optional[str] = None
    changed_settings: List[str] = Field(default_factory=list)
    settings_sha256: Optional[str] = None
    user_confirmed: bool = False
    message: str


class SystemdNetworkProfileCreateConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm creation of this exact systemd-networkd profile")
    filename: str = Field(description="Repeat the exact new .network filename shown in the prompt")
    interface: str = Field(description="Repeat the exact literal interface matched by the profile")
    state_token: str = Field(description="Repeat the state-bound token shown in the prompt")


class SystemdNetworkProfileCreateResponse(BaseModel):
    success: bool
    created: bool = False
    filename: Optional[str] = None
    interface: Optional[str] = None
    configured_settings: List[str] = Field(default_factory=list)
    settings_sha256: Optional[str] = None
    user_confirmed: bool = False
    message: str


class SystemdNetworkProfileDeleteConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm deletion of this exact systemd-networkd profile")
    filename: str = Field(description="Repeat the exact .network filename shown in the prompt")
    interface: str = Field(description="Repeat the literal interface matched by the profile")
    state_token: str = Field(description="Repeat the state-bound token shown in the prompt")


class SystemdNetworkProfileDeleteResponse(BaseModel):
    success: bool
    deleted: bool = False
    filename: Optional[str] = None
    interface: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class SystemdNetDevCreateConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm creation of this exact systemd-networkd virtual-device profile")
    filename: str = Field(description="Repeat the exact new .netdev filename shown in the prompt")
    name: str = Field(description="Repeat the exact virtual interface name shown in the prompt")
    kind: Literal["bridge", "bond", "vlan"] = Field(description="Repeat the exact virtual-device kind shown in the prompt")
    state_token: str = Field(description="Repeat the state-bound token shown in the prompt")


class SystemdNetDevCreateResponse(BaseModel):
    success: bool
    created: bool = False
    filename: Optional[str] = None
    name: Optional[str] = None
    kind: Optional[Literal["bridge", "bond", "vlan"]] = None
    configured_settings: List[str] = Field(default_factory=list)
    settings_sha256: Optional[str] = None
    user_confirmed: bool = False
    message: str


class SystemdNetDevConfigConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm these exact persistent systemd-networkd .netdev settings")
    filename: str = Field(description="Repeat the exact existing .netdev filename shown in the prompt")
    name: str = Field(description="Repeat the exact virtual interface name shown in the prompt")
    kind: Literal["bridge", "bond", "vlan"] = Field(description="Repeat the exact virtual-device kind shown in the prompt")
    state_token: str = Field(description="Repeat the state-bound token shown in the prompt")


class SystemdNetDevConfigResponse(BaseModel):
    success: bool
    filename: Optional[str] = None
    name: Optional[str] = None
    kind: Optional[Literal["bridge", "bond", "vlan"]] = None
    changed_settings: List[str] = Field(default_factory=list)
    settings_sha256: Optional[str] = None
    user_confirmed: bool = False
    message: str


class SystemdNetDevDeleteConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm deletion of this exact systemd-networkd .netdev profile")
    filename: str = Field(description="Repeat the exact .netdev filename shown in the prompt")
    name: str = Field(description="Repeat the exact virtual interface name shown in the prompt")
    kind: Literal["bridge", "bond", "vlan"] = Field(description="Repeat the exact virtual-device kind shown in the prompt")
    state_token: str = Field(description="Repeat the state-bound token shown in the prompt")


class SystemdNetDevDeleteResponse(BaseModel):
    success: bool
    deleted: bool = False
    filename: Optional[str] = None
    name: Optional[str] = None
    kind: Optional[Literal["bridge", "bond", "vlan"]] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class NetworkInterfaceActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact network interface change")


class NetworkInterfaceActionResponse(BaseModel):
    success: bool
    action: Literal["set_up", "set_down", "set_mtu"]
    interface: Optional[str] = None
    interface_index: Optional[int] = None
    mtu: Optional[int] = None
    user_confirmed: bool = Field(default=False, description="Whether this exact interface change received explicit MCP client confirmation")
    message: str


class RadioDeviceInfo(BaseModel):
    radio_index: int
    name: str
    radio_type: str
    soft_blocked: bool
    hard_blocked: bool
    blocked: bool
    identity_token: str = Field(
        description="Short-lived token bound to this exact kernel rfkill device for confirmed soft-block changes",
    )


class RadioDeviceListResponse(BaseModel):
    success: bool
    total_radios: int = 0
    returned_radios: int = 0
    devices: List[RadioDeviceInfo] = Field(default_factory=list)
    limit: int = 64
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class RadioDeviceActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact radio-device soft block or unblock")
    radio_index: int = Field(strict=True, description="Repeat the exact rfkill index shown in the prompt")
    name: str = Field(description="Repeat the exact radio name shown in the prompt")
    radio_type: str = Field(description="Repeat the exact radio type shown in the prompt")
    expected_state_token: str = Field(description="Repeat the short-lived state token shown in the prompt")


class RadioDeviceActionResponse(BaseModel):
    success: bool
    action: Literal["block", "unblock"]
    radio_index: Optional[int] = None
    name: Optional[str] = None
    radio_type: Optional[str] = None
    soft_blocked: Optional[bool] = None
    hard_blocked: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = Field(
        default=False,
        description="Whether this exact radio-device action received explicit MCP client confirmation",
    )
    message: str


class BluetoothDeviceInfo(BaseModel):
    address: str = Field(description="Bluetooth device address; this can identify a nearby or previously known device")
    name: Optional[str] = Field(default=None, description="Bluetooth device name or alias reported by BlueZ")
    paired: Optional[bool] = Field(default=None, description="Whether BlueZ currently reports this device as paired")
    identity_token: str = Field(description="Short-lived token bound to this exact device address and observed name")


class BluetoothDeviceListResponse(BaseModel):
    success: bool
    total_devices: int = 0
    returned_devices: int = 0
    devices: List[BluetoothDeviceInfo] = Field(default_factory=list)
    limit: int = 64
    partial: bool = False
    truncated: bool = False
    message: Optional[str] = None


class BluetoothPairingConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm pairing with this exact BlueZ device")
    address: str = Field(description="Repeat the exact Bluetooth address shown in the prompt")
    name: str = Field(description="Repeat the exact device name or empty string shown in the prompt")
    state_token: str = Field(description="Repeat the token bound to the observed unpaired state")


class BluetoothPairingResponse(BaseModel):
    success: bool
    address: Optional[str] = None
    name: Optional[str] = None
    paired: Optional[bool] = None
    connected: Optional[bool] = None
    user_confirmed: bool = Field(default=False, description="Whether this exact pairing action received explicit client confirmation")
    message: str


class NetworkAddressActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact interface address change")


class NetworkAddressActionResponse(BaseModel):
    success: bool
    action: Literal["add", "remove"]
    interface: Optional[str] = None
    interface_index: Optional[int] = None
    address: Optional[str] = None
    user_confirmed: bool = Field(default=False, description="Whether this exact address change received explicit MCP client confirmation")
    message: str


class NetworkRouteActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact transient route change")
    interface_index: int = Field(
        ge=1,
        description="Repeat the interface index shown in the confirmation prompt",
    )


class NetworkRouteActionResponse(BaseModel):
    success: bool
    action: Literal["add", "remove"]
    family: Optional[Literal["ipv4", "ipv6"]] = None
    destination: Optional[str] = None
    gateway: Optional[str] = None
    interface: Optional[str] = None
    interface_index: Optional[int] = None
    table: Optional[int] = None
    metric: Optional[int] = None
    preferred_source: Optional[str] = None
    user_confirmed: bool = Field(default=False, description="Whether this exact route change received explicit MCP client confirmation")
    message: str


class NetworkAddressDetail(BaseModel):
    interface: str
    interface_index: Optional[int] = None
    family: Literal["ipv4", "ipv6"]
    address: str
    prefix_length: int
    peer_address: Optional[str] = None
    broadcast_address: Optional[str] = None
    anycast_address: Optional[str] = None
    scope: Optional[str] = None
    label: Optional[str] = None
    protocol: Optional[str] = None
    flags: List[str] = Field(default_factory=list)
    preferred_lifetime: Optional[str | int] = None
    valid_lifetime: Optional[str | int] = None


class NetworkAddressListResponse(BaseModel):
    success: bool
    total_addresses: int = 0
    returned_addresses: int = 0
    addresses: List[NetworkAddressDetail] = Field(default_factory=list)
    limit: int = 256
    truncated: bool = False
    message: Optional[str] = None


class ServiceInfo(BaseModel):
    name: str
    manager: str
    scope: Literal["system", "user"] = "system"
    active_state: Optional[str] = None
    sub_state: Optional[str] = None
    startup_state: Optional[str] = Field(
        default=None,
        description="Reported startup state; for s6, this is the staged prescription in the offline current working set, not the live database.",
    )
    preset_state: Optional[str] = None
    description: Optional[str] = None
    runlevel_contexts: List[str] = Field(default_factory=list, description="OpenRC runlevels or dynamic service groups reported for this service")
    manager_details: dict[str, str] = Field(
        default_factory=dict,
        description="Additional bounded manager metadata; s6 may include live_database_membership and startup_prescription.",
    )


class ServiceListResponse(BaseModel):
    success: bool
    manager: str
    scope: Literal["system", "user"] = "system"
    total_services: int = 0
    returned_services: int = 0
    services: List[ServiceInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class OpenRCRunlevelInfo(BaseModel):
    name: str = Field(description="Exact existing OpenRC runlevel name")
    services: List[str] = Field(default_factory=list, description="Service names linked into this runlevel")
    service_count: int = Field(default=0, description="Number of service links returned for this runlevel")
    truncated: bool = False


class OpenRCRunlevelListResponse(BaseModel):
    success: bool
    total_runlevels: int = 0
    returned_runlevels: int = 0
    runlevels: List[OpenRCRunlevelInfo] = Field(default_factory=list)
    limit: int = 64
    truncated: bool = False
    message: Optional[str] = None


class OpenRCServiceStartupConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact service's startup membership change")
    action: Literal["enable", "disable"]
    unit: str = Field(description="Repeat the exact OpenRC service name shown in the confirmation prompt")
    runlevel: str = Field(description="Repeat the exact OpenRC runlevel shown in the confirmation prompt")
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the runlevel and service state token shown in the confirmation prompt",
    )


class OpenRCServiceStartupResponse(BaseModel):
    success: bool
    action: Literal["enable", "disable"]
    unit: str
    runlevel: str
    runlevel_membership: Optional[Literal["present", "absent"]] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether this exact OpenRC startup change received explicit client confirmation")
    message: str


class RunitServiceStartupConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact runit service's persistent initial-state change")
    action: Literal["enable", "disable"]
    unit: str = Field(description="Repeat the exact runit service name shown in the confirmation prompt")
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the service-directory and down-marker state token shown in the confirmation prompt",
    )


class RunitServiceStartupResponse(BaseModel):
    success: bool
    action: Literal["enable", "disable"]
    unit: str
    startup_state: Optional[Literal["enabled", "disabled"]] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether this exact runit startup change received explicit client confirmation")
    message: str


class S6StartupSetConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact service's staged s6 startup-set change")
    action: Literal["enable", "disable"]
    unit: str = Field(description="Repeat the exact s6 atomic-service name shown in the confirmation prompt")
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the offline working-set service state token shown in the confirmation prompt",
    )


class S6StartupSetResponse(BaseModel):
    success: bool
    action: Literal["enable", "disable"]
    unit: str
    startup_state: Optional[Literal["enabled", "disabled", "essential", "masked"]] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether this exact s6 working-set change received explicit client confirmation")
    message: str


class SystemdTimerInfo(BaseModel):
    unit: str = Field(description="Exact timer unit name currently known to the selected systemd manager")
    activates: Optional[str] = Field(default=None, description="Unit activated when this timer elapses, if reported")
    next_run: Optional[str] = Field(default=None, description="Next scheduled run as shown by systemd, or null when no next run is scheduled")
    time_until_next: Optional[str] = Field(default=None, description="Time remaining until the next run, as shown by systemd")
    last_run: Optional[str] = Field(default=None, description="Most recent run time as shown by systemd")
    time_since_last: Optional[str] = Field(default=None, description="Elapsed time since the most recent run, as shown by systemd")


class SystemdTimerListResponse(BaseModel):
    success: bool
    scope: Literal["system", "user"] = "system"
    total_timers: int = 0
    returned_timers: int = 0
    timers: List[SystemdTimerInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class SystemdTimerActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact systemd timer action")
    action: Literal["start", "stop", "enable", "disable"]
    scope: Literal["system", "user"]
    unit: str = Field(description="Repeat the exact timer unit name shown in the confirmation prompt")
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the current state token shown in the confirmation prompt",
    )


class SystemdTimerActionResponse(BaseModel):
    success: bool
    action: Literal["start", "stop", "enable", "disable"]
    unit: str
    scope: Literal["system", "user"]
    active_state: Optional[str] = None
    unit_file_state: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = Field(
        default=False,
        description="Whether the exact timer action received explicit MCP client confirmation",
    )
    message: str


class SystemdTimerDefinitionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact generated systemd timer definition")
    action: Literal["create", "update"]
    scope: Literal["system", "user"]
    unit: str = Field(description="Repeat the exact .timer unit name")
    service_unit: str = Field(description="Repeat the exact loaded .service unit that the timer will activate")
    on_calendar: Optional[str] = Field(default=None, description="Repeat the calendar schedule, if configured")
    on_boot_seconds: Optional[int] = Field(default=None, description="Repeat the boot-relative delay in seconds, if configured")
    on_unit_active_seconds: Optional[int] = Field(default=None, description="Repeat the repeat interval in seconds after the service becomes active, if configured")
    persistent: bool = Field(default=False, description="Repeat whether missed calendar events should be caught up")
    confirmation_phrase: str = Field(description="Repeat the exact confirmation phrase shown in the prompt")
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the timer-file and manager state token shown in the confirmation prompt",
    )


class SystemdTimerDefinitionResponse(BaseModel):
    success: bool
    action: Literal["create", "update"]
    scope: Literal["system", "user"]
    unit: str
    service_unit: Optional[str] = None
    path: Optional[str] = None
    on_calendar: Optional[str] = None
    on_boot_seconds: Optional[int] = None
    on_unit_active_seconds: Optional[int] = None
    persistent: bool = False
    file_written: bool = False
    unit_file_state: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether the exact timer definition received MCP client confirmation")
    message: str


class SystemdTimerDefinitionDeleteConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm deletion of this exact generated timer file")
    scope: Literal["system", "user"]
    unit: str = Field(description="Repeat the exact .timer unit name")
    confirmation_phrase: str = Field(description="Repeat the exact deletion phrase shown in the prompt")
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the timer-file and manager state token shown in the confirmation prompt",
    )


class SystemdTimerDefinitionDeleteResponse(BaseModel):
    success: bool
    scope: Literal["system", "user"]
    unit: str
    path: Optional[str] = None
    unit_file_state: Optional[str] = None
    file_deleted: bool = False
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether the exact timer deletion received MCP client confirmation")
    message: str


class SystemdServiceDefinitionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact generated systemd one-shot service definition")
    action: Literal["create", "update"]
    scope: Literal["system", "user"]
    unit: str = Field(description="Repeat the exact .service unit name")
    executable: str = Field(description="Repeat the exact canonical absolute executable path")
    arguments: List[str] = Field(default_factory=list, description="Repeat the exact argument vector; arguments are passed directly without a shell")
    confirmation_phrase: str = Field(description="Repeat the exact confirmation phrase shown in the prompt")
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the service-file and manager state token shown in the confirmation prompt",
    )


class SystemdServiceDefinitionResponse(BaseModel):
    success: bool
    action: Literal["create", "update"]
    scope: Literal["system", "user"]
    unit: str
    executable: Optional[str] = None
    arguments: List[str] = Field(default_factory=list)
    path: Optional[str] = None
    file_written: bool = False
    unit_file_state: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether the exact service definition received MCP client confirmation")
    message: str


class CronJobInfo(BaseModel):
    scheduler: Literal["cron", "anacron", "at"]
    source: str = Field(description="Fixed system configuration source or current-user scheduler queue")
    schedule: str = Field(description="Cron expression, Anacron period/delay, or queued at-job time")
    user: Optional[str] = Field(default=None, description="Execution user when reported by the scheduler source")
    line_number: Optional[int] = Field(default=None, description="Configuration line containing this job, when applicable")
    job_id: Optional[str] = Field(default=None, description="Anacron identifier or at-queue job number, when applicable")
    queue: Optional[str] = Field(default=None, description="at queue letter, when reported")
    timezone: Optional[str] = Field(default=None, description="CRON_TZ setting in effect for this entry, when present")
    schedule_settings: List[str] = Field(default_factory=list, description="Selected safe scheduling settings; arbitrary environment assignments are omitted")
    command_redacted: bool = Field(default=True, description="Scheduled command text is intentionally omitted")


class CronJobListResponse(BaseModel):
    success: bool
    total_jobs: int = 0
    returned_jobs: int = 0
    jobs: List[CronJobInfo] = Field(default_factory=list)
    sources_checked: List[str] = Field(default_factory=list)
    limit: int = 200
    truncated: bool = False
    message: Optional[str] = None


class CronJobActionConfirmation(BaseModel):
    confirm: bool = Field(description="Whether the client explicitly confirms this exact current-user or marked system cron change")
    scope: Literal["user", "system"] = Field(default="user", description="Repeat whether the target is the server user's crontab or a marked /etc/cron.d entry")
    run_as_user: str = Field(default="", description="For system scope, repeat the exact local account that the cron daemon will use")
    job_id: str = Field(default="", description="For system scope, repeat the exact generated cron-file ID")
    confirmation_phrase: str = Field(description="Exact short-lived phrase bound to the selected crontab or system file and requested action")


class CronJobActionResponse(BaseModel):
    success: bool
    action: Literal["add", "update", "remove"]
    username: str
    schedule: str
    scope: Literal["user", "system"] = "user"
    job_id: Optional[str] = None
    user_confirmed: bool = False
    message: str


class AtJobActionConfirmation(BaseModel):
    confirm: bool = Field(description="Whether the client explicitly confirms this exact current-user at-queue change")
    confirmation_phrase: str = Field(description="Exact short-lived phrase bound to the requested at job and current queue state")


class AtJobActionResponse(BaseModel):
    success: bool
    action: Literal["add", "remove"]
    username: str
    job_id: Optional[str] = None
    run_at: Optional[str] = None
    user_confirmed: bool = False
    message: str


class FstabEntryInfo(BaseModel):
    line_number: int = Field(description="Line number in the fixed /etc/fstab source")
    mount_point: str = Field(description="Decoded mount target; escaped tabs and newlines are represented as backslash-t and backslash-n")
    filesystem_type: str = Field(description="Filesystem type from the configuration entry")
    source_kind: Literal["uuid", "label", "partition_uuid", "partition_label", "device", "network", "pseudo", "other"] = Field(description="Classification of the configured source; its exact value is omitted")
    option_flags: List[str] = Field(default_factory=list, description="Explicit filesystem-independent options from a fixed allowlist; arbitrary options and values are omitted")
    dump_frequency: int = Field(default=0, description="Configured dump frequency, defaulting to zero when omitted")
    fsck_pass_number: int = Field(default=0, description="Configured fsck pass number, defaulting to zero when omitted")


class FstabEntryListResponse(BaseModel):
    success: bool
    total_entries: int = 0
    returned_entries: int = 0
    entries: List[FstabEntryInfo] = Field(default_factory=list)
    malformed_lines: int = 0
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class CrypttabEntryInfo(BaseModel):
    line_number: int = Field(description="Line number in the fixed /etc/crypttab source")
    volume_name: str = Field(description="Configured decrypted mapping name under /dev/mapper")
    device_source_kind: Literal["uuid", "label", "partition_uuid", "partition_label", "path", "other"] = Field(description="Classification of the encrypted-device reference; its exact value is omitted")
    key_source_kind: Literal["implicit", "random_device", "path_or_socket", "other"] = Field(description="Classification of the key-source field; key-file and socket paths are omitted")
    encryption_mode: Optional[Literal["luks", "plain", "tcrypt", "bitlk", "fvault2"]] = Field(default=None, description="Explicitly configured encryption mode, or null when unspecified or ambiguous")
    option_flags: List[str] = Field(default_factory=list, description="Explicit safe options from a fixed allowlist; arbitrary option names and values are omitted")
    formats_on_activation: bool = Field(default=False, description="Whether the swap or tmp option indicates that activation formats the mapped device")
    pkcs11_configured: bool = Field(default=False, description="Whether a PKCS#11 option is present; its URI is omitted")
    fido2_configured: bool = Field(default=False, description="Whether a FIDO2 option is present; its value is omitted")
    tpm2_configured: bool = Field(default=False, description="Whether a TPM2 option is present; its value is omitted")
    custom_keyscript_configured: bool = Field(default=False, description="Whether a keyscript option is present; its value is omitted")


class CrypttabEntryListResponse(BaseModel):
    success: bool
    total_entries: int = 0
    returned_entries: int = 0
    entries: List[CrypttabEntryInfo] = Field(default_factory=list)
    malformed_lines: int = 0
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class ServiceActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact service action")


class ServiceActionResponse(BaseModel):
    success: bool
    action: Literal["start", "stop", "restart", "reload", "enable", "disable"]
    unit: str
    scope: Literal["system", "user"]
    manager: Optional[str] = None
    user_confirmed: bool = Field(default=False, description="Whether the exact service action received explicit MCP client confirmation")
    message: str


class ContainerInfo(BaseModel):
    runtime: Literal["docker", "podman", "containerd", "cri-o"]
    scope: Literal["system", "user"]
    container_id: str
    name: str
    image: str
    state: str
    status: str
    created_at: Optional[str] = None
    identity_token: Optional[str] = Field(default=None, description="Short-lived action token for exact Docker/Podman containers; CRI inventory entries are read-only and have no action token")


class ContainerListResponse(BaseModel):
    success: bool
    total_containers: int = 0
    returned_containers: int = 0
    containers: List[ContainerInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class ContainerImageInfo(BaseModel):
    runtime: Literal["docker", "podman"]
    scope: Literal["system", "user"]
    image_id: str
    tags: List[str] = Field(default_factory=list, description="Exact locally available image references")
    size_bytes: Optional[int] = None
    created_at: Optional[str] = None


class ContainerImageListResponse(BaseModel):
    success: bool
    total_images: int = 0
    returned_images: int = 0
    images: List[ContainerImageInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class ContainerImageActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact local container image action")
    confirmation_phrase: str = Field(description="Repeat the short-lived phrase bound to the selected runtime and image state")


class ContainerImageActionResponse(BaseModel):
    success: bool
    action: Literal["pull", "tag", "remove"]
    runtime: Optional[Literal["docker", "podman"]] = None
    scope: Optional[Literal["system", "user"]] = None
    image: Optional[str] = None
    target_tag: Optional[str] = None
    image_id: Optional[str] = None
    user_confirmed: bool = False
    message: str


class ContainerImageBuildConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact local image build and captured context")
    confirmation_phrase: str = Field(description="Repeat the short-lived phrase bound to the local image inventory and context digest")


class ContainerImageBuildResponse(BaseModel):
    success: bool
    runtime: Optional[Literal["docker", "podman"]] = None
    scope: Optional[Literal["system", "user"]] = None
    tag: Optional[str] = None
    image_id: Optional[str] = None
    context_digest: Optional[str] = None
    context_file_count: int = 0
    context_bytes: int = 0
    user_confirmed: bool = False
    message: str


class ContainerResourceInfo(BaseModel):
    runtime: Literal["docker", "podman"]
    scope: Literal["system", "user"]
    kind: Literal["volume", "network"]
    name: str
    resource_id: Optional[str] = None
    driver: Optional[str] = None
    created_at: Optional[str] = None
    is_default: bool = False


class ContainerResourceListResponse(BaseModel):
    success: bool
    kind: Literal["volume", "network"]
    total_resources: int = 0
    returned_resources: int = 0
    resources: List[ContainerResourceInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class ContainerResourceActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact local container resource action")
    confirmation_phrase: str = Field(description="Repeat the short-lived phrase bound to the selected runtime and resource inventory")


class ContainerResourceActionResponse(BaseModel):
    success: bool
    action: Literal["create", "remove"]
    runtime: Optional[Literal["docker", "podman"]] = None
    scope: Optional[Literal["system", "user"]] = None
    kind: Literal["volume", "network"]
    name: Optional[str] = None
    resource_id: Optional[str] = None
    network_subnet: Optional[str] = Field(default=None, description="Compatibility field for a single requested IPv4 subnet")
    network_gateway: Optional[str] = Field(default=None, description="Compatibility field for a single requested IPv4 gateway")
    network_subnets: List[str] = Field(default_factory=list, description="Requested canonical bridge subnets in subnet order; Podman allows up to four per IP family, Docker bridge allows one per family")
    network_gateways: List[Optional[str]] = Field(default_factory=list, description="Requested gateways in subnet order; null means runtime-selected")
    network_internal: Optional[bool] = Field(default=None, description="Requested internal-network mode; omitted when runtime defaults apply")
    network_bridge_name: Optional[str] = Field(default=None, description="Requested host bridge interface name")
    network_mtu: Optional[int] = Field(default=None, description="Requested bridge MTU in bytes")
    user_confirmed: bool = False
    message: str


class ContainerNetworkAttachmentResponse(BaseModel):
    success: bool
    runtime: Optional[Literal["docker", "podman"]] = None
    scope: Optional[Literal["system", "user"]] = None
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    container_state: Optional[str] = None
    networks: List[str] = Field(default_factory=list)
    user_confirmed: bool = False
    message: str


class ContainerNetworkAttachmentConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact local container network connection change")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the exact container, network, and current attachment state")


class ContainerNetworkAttachmentActionResponse(BaseModel):
    success: bool
    action: Literal["connect", "disconnect"]
    runtime: Optional[Literal["docker", "podman"]] = None
    scope: Optional[Literal["system", "user"]] = None
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    network: Optional[str] = None
    user_confirmed: bool = False
    message: str


class ContainerPodInfo(BaseModel):
    runtime: Literal["podman"] = "podman"
    scope: Literal["system", "user"]
    pod_id: str
    name: str
    state: Literal["created", "running", "stopped", "exited", "paused", "degraded", "dead", "unknown"]
    created_at: Optional[str] = None
    container_count: int = 0
    container_ids: List[str] = Field(default_factory=list)
    container_names: List[str] = Field(default_factory=list)
    container_statuses: List[str] = Field(default_factory=list)


class ContainerPodListResponse(BaseModel):
    success: bool
    total_pods: int = 0
    returned_pods: int = 0
    pods: List[ContainerPodInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class ContainerPodActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact local Podman pod action")
    confirmation_phrase: str = Field(description="Repeat the short-lived phrase bound to the exact pod and member state")


class ContainerPodActionResponse(BaseModel):
    success: bool
    action: Literal["create", "start", "stop", "remove"]
    scope: Optional[Literal["system", "user"]] = None
    name: Optional[str] = None
    pod_id: Optional[str] = None
    user_confirmed: bool = False
    message: str


class ContainerActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact local container action")


class ContainerActionResponse(BaseModel):
    success: bool
    action: Literal["start", "stop", "restart", "pause", "unpause", "remove"]
    runtime: Optional[Literal["docker", "podman"]] = None
    scope: Optional[Literal["system", "user"]] = None
    container_id: Optional[str] = None
    name: Optional[str] = None
    user_confirmed: bool = Field(default=False, description="Whether this exact container action received explicit MCP client confirmation")
    message: str


class ContainerCreateConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm creating this exact stopped local container")
    confirmation_phrase: str = Field(description="Repeat the short-lived phrase bound to the image and container configuration")


class ContainerCreateResponse(BaseModel):
    success: bool
    runtime: Optional[Literal["docker", "podman"]] = None
    scope: Optional[Literal["system", "user"]] = None
    container_id: Optional[str] = None
    name: Optional[str] = None
    image: Optional[str] = None
    network_name: Optional[str] = Field(default=None, description="Exact existing non-default local network selected for the stopped container")
    port_mappings: List[str] = Field(default_factory=list, description="Confirmed IPv4 host-to-container TCP/UDP bindings")
    volume_mounts: List[str] = Field(default_factory=list, description="Confirmed existing named-volume mounts and access modes")
    host_path_mounts: List[str] = Field(default_factory=list, description="Confirmed existing host-path mounts and access modes")
    environment_names: List[str] = Field(default_factory=list, description="Names of explicitly configured environment variables; values are never returned")
    container_user: Optional[str] = Field(default=None, description="Requested numeric container UID or UID:GID; UID 0 is container root")
    read_only_rootfs: bool = Field(default=False, description="Whether creation explicitly requested a read-only root filesystem")
    no_new_privileges: bool = Field(default=False, description="Whether creation explicitly requested no-new-privileges")
    dropped_capabilities: List[str] = Field(default_factory=list, description="Linux capabilities explicitly requested to be dropped")
    memory_limit_bytes: Optional[int] = None
    cpu_limit_millicores: Optional[int] = None
    user_confirmed: bool = False
    message: str


class VirtualMachineInfo(BaseModel):
    scope: Literal["system", "session"]
    uuid: str
    name: str
    state: str
    domain_id: Optional[int] = None
    identity_token: str = Field(description="Short-lived token bound to this exact local libvirt domain instance for confirmed actions")


class VirtualMachineListResponse(BaseModel):
    success: bool
    scope: Literal["system", "session", "both"] = "both"
    total_virtual_machines: int = 0
    returned_virtual_machines: int = 0
    virtual_machines: List[VirtualMachineInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class RemoteVirtualMachineInfo(BaseModel):
    endpoint: str = Field(description="Validated qemu+ssh endpoint without credentials or transport options")
    scope: Literal["system", "session"]
    uuid: str
    name: str
    state: str
    domain_id: Optional[int] = None
    identity_token: str = Field(description="Short-lived token bound to this exact remote endpoint and libvirt domain instance")


class RemoteVirtualMachineListResponse(BaseModel):
    success: bool
    endpoint: Optional[str] = None
    scope: Optional[Literal["system", "session"]] = None
    total_virtual_machines: int = 0
    returned_virtual_machines: int = 0
    virtual_machines: List[RemoteVirtualMachineInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class RemoteVirtualMachineActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact remote libvirt domain action")
    action: Literal["start", "shutdown", "reboot", "suspend", "resume"]
    endpoint: str = Field(description="Repeat the exact validated remote qemu+ssh endpoint")
    scope: Literal["system", "session"]
    uuid: str = Field(description="Repeat the exact remote domain UUID shown in the prompt")
    name: str = Field(description="Repeat the exact current remote domain name shown in the prompt")
    expected_state_token: str = Field(description="Repeat the short-lived state token shown in the prompt")


class RemoteVirtualMachineActionResponse(BaseModel):
    success: bool
    action: Literal["start", "shutdown", "reboot", "suspend", "resume"]
    endpoint: Optional[str] = None
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    name: Optional[str] = None
    state: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether this exact remote libvirt action received explicit MCP client confirmation")
    message: str


class RemoteVirtualMachineDiskAttachConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm attaching this exact existing remote volume to the shut-off VM's persistent configuration")
    endpoint: str = Field(description="Repeat the exact validated remote qemu+ssh endpoint")
    scope: Literal["system", "session"]
    uuid: str = Field(description="Repeat the remote VM UUID shown in the prompt")
    name: str = Field(description="Repeat the exact remote VM name shown in the prompt")
    pool_name: str = Field(description="Repeat the existing remote directory-pool name")
    volume_name: str = Field(description="Repeat the exact existing remote volume name")
    disk_target: str = Field(description="Repeat the requested unused virtio target, from vdb through vdz")
    expected_state_token: str = Field(description="Repeat the short-lived token bound to the VM, pool, volume, target, and current state")


class RemoteVirtualMachineDiskAttachResponse(BaseModel):
    success: bool
    endpoint: Optional[str] = None
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    vm_name: Optional[str] = None
    pool_name: Optional[str] = None
    volume_name: Optional[str] = None
    volume_capacity_bytes: Optional[int] = None
    volume_format: Optional[Literal["raw", "qcow2"]] = None
    disk_target: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether this exact remote disk attachment received explicit client confirmation")
    message: str


class RemoteVirtualMachineCreateConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm creating this exact stopped remote VM and its sparse disk")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to this remote endpoint, requested VM resources, and current libvirt state")


class RemoteVirtualMachineCreateResponse(BaseModel):
    success: bool
    endpoint: Optional[str] = None
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    name: Optional[str] = None
    memory_mib: Optional[int] = None
    vcpus: Optional[int] = None
    pool_name: Optional[str] = None
    disk_volume_name: Optional[str] = None
    disk_capacity_bytes: Optional[int] = None
    network_name: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class RemoteVirtualMachineConfigConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm changing memory and vCPU values in this exact shut-off remote VM's persistent definition")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the remote VM definition, requested resources, and current state")


class RemoteVirtualMachineConfigResponse(BaseModel):
    success: bool
    endpoint: Optional[str] = None
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    name: Optional[str] = None
    previous_max_memory_mib: Optional[int] = None
    previous_current_memory_mib: Optional[int] = None
    previous_vcpus: Optional[int] = None
    memory_mib: Optional[int] = None
    vcpus: Optional[int] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class VirtualMachineConfigConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm changing memory and vCPU values in this exact shut-off local VM's persistent definition")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the local VM definition, requested resources, and current state")


class VirtualMachineConfigResponse(BaseModel):
    success: bool
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    name: Optional[str] = None
    previous_max_memory_mib: Optional[int] = None
    previous_current_memory_mib: Optional[int] = None
    previous_vcpus: Optional[int] = None
    memory_mib: Optional[int] = None
    vcpus: Optional[int] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether this exact local VM resource change received explicit MCP client confirmation")
    message: str


class RemoteLibvirtNetworkInfo(BaseModel):
    endpoint: str = Field(description="Validated qemu+ssh endpoint without credentials or transport options")
    scope: Literal["system", "session"]
    name: str
    state: str
    autostart: Optional[bool] = None
    persistent: Optional[bool] = None


class RemoteLibvirtNetworkListResponse(BaseModel):
    success: bool
    endpoint: Optional[str] = None
    scope: Optional[Literal["system", "session"]] = None
    total_networks: int = 0
    returned_networks: int = 0
    networks: List[RemoteLibvirtNetworkInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class RemoteLibvirtStoragePoolInfo(BaseModel):
    endpoint: str = Field(description="Validated qemu+ssh endpoint without credentials or transport options")
    scope: Literal["system", "session"]
    name: str
    state: str
    autostart: Optional[bool] = None
    persistent: Optional[bool] = None
    capacity: Optional[str] = None
    allocation: Optional[str] = None
    available: Optional[str] = None


class RemoteLibvirtStorageVolumeInfo(BaseModel):
    name: str
    volume_type: Optional[str] = None
    capacity: Optional[str] = None
    allocation: Optional[str] = None


class RemoteLibvirtStorageInventoryResponse(BaseModel):
    success: bool
    endpoint: Optional[str] = None
    scope: Optional[Literal["system", "session"]] = None
    total_pools: int = 0
    returned_pools: int = 0
    pools: List[RemoteLibvirtStoragePoolInfo] = Field(default_factory=list)
    selected_pool_name: Optional[str] = None
    total_volumes: int = 0
    returned_volumes: int = 0
    volumes: List[RemoteLibvirtStorageVolumeInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class RemoteLibvirtResourceActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact remote libvirt network or storage-pool action")
    resource_type: Literal["network", "storage_pool"]
    action: Literal["start", "stop", "enable_autostart", "disable_autostart"]
    endpoint: str = Field(description="Repeat the exact validated remote qemu+ssh endpoint")
    scope: Literal["system", "session"]
    name: str = Field(description="Repeat the exact remote network or storage-pool name")
    uuid: str = Field(description="Repeat the exact remote libvirt resource UUID")
    expected_state_token: str = Field(description="Repeat the short-lived token bound to this endpoint, resource, and state")


class RemoteLibvirtResourceActionResponse(BaseModel):
    success: bool
    resource_type: Literal["network", "storage_pool"]
    action: Literal["start", "stop", "enable_autostart", "disable_autostart"]
    endpoint: Optional[str] = None
    scope: Optional[Literal["system", "session"]] = None
    name: Optional[str] = None
    uuid: Optional[str] = None
    state: Optional[str] = None
    autostart: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class VirtualMachineCreateConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm defining this exact stopped local virtual machine and creating its blank disk")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the requested VM resources and current libvirt state")


class VirtualMachineCreateResponse(BaseModel):
    success: bool
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    name: Optional[str] = None
    memory_mib: Optional[int] = None
    vcpus: Optional[int] = None
    pool_name: Optional[str] = None
    disk_volume_name: Optional[str] = None
    disk_capacity_bytes: Optional[int] = None
    network_name: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class VirtualMachineDiskAttachConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm attaching this exact existing local volume to the shut-off VM's persistent configuration")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the VM, volume, device slot, and current libvirt state")


class VirtualMachineDiskAttachResponse(BaseModel):
    success: bool
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    vm_name: Optional[str] = None
    pool_name: Optional[str] = None
    volume_name: Optional[str] = None
    volume_capacity_bytes: Optional[int] = None
    volume_format: Optional[Literal["raw", "qcow2"]] = None
    disk_target: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class VirtualMachineSnapshotInfo(BaseModel):
    name: str
    parent_name: Optional[str] = None


class VirtualMachineSnapshotListResponse(BaseModel):
    success: bool
    endpoint: Optional[str] = Field(default=None, description="Validated qemu+ssh endpoint for remote snapshot inventory")
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    domain_name: Optional[str] = None
    domain_state: Optional[str] = None
    total_snapshots: int = 0
    returned_snapshots: int = 0
    snapshots: List[VirtualMachineSnapshotInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class VirtualMachineSnapshotActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact local or remote libvirt snapshot action")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the domain, snapshot inventory, and requested operation")


class VirtualMachineSnapshotActionResponse(BaseModel):
    success: bool
    action: Literal["create", "revert", "delete"]
    endpoint: Optional[str] = Field(default=None, description="Validated qemu+ssh endpoint for remote snapshot action")
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    domain_name: Optional[str] = None
    snapshot_name: Optional[str] = None
    snapshot_description: Optional[str] = None
    domain_state_before: Optional[str] = None
    domain_state_after: Optional[str] = None
    user_confirmed: bool = False
    message: str


class LibvirtNetworkInfo(BaseModel):
    scope: Literal["system", "session"]
    name: str
    state: str
    autostart: Optional[bool] = Field(default=None, description="Whether libvirt is configured to start this network automatically")
    persistent: Optional[bool] = Field(default=None, description="Whether the network definition persists across libvirt daemon restarts")


class LibvirtNetworkListResponse(BaseModel):
    success: bool
    scope: Literal["system", "session", "both"] = "both"
    total_networks: int = 0
    returned_networks: int = 0
    networks: List[LibvirtNetworkInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class LibvirtNetworkCreateConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm defining this exact inactive isolated libvirt network")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the requested name and current network inventory")


class LibvirtNetworkDefinitionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm defining this exact inactive libvirt network configuration")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the network mode, settings, and current host/network state")


class LibvirtNetworkIPv4ConfigurationConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm changing the IPv4 and DHCP settings on this exact inactive NAT or routed libvirt network")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the current network definition and requested IPv4/DHCP settings")


class LibvirtNetworkIPv4ConfigurationResponse(BaseModel):
    success: bool
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    name: Optional[str] = None
    forward_mode: Optional[Literal["nat", "route"]] = None
    bridge_name: Optional[str] = None
    previous_ipv4_cidr: Optional[str] = None
    ipv4_cidr: Optional[str] = None
    previous_dhcp_start: Optional[str] = None
    previous_dhcp_end: Optional[str] = None
    dhcp_start: Optional[str] = None
    dhcp_end: Optional[str] = None
    active: Optional[bool] = None
    persistent: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class LibvirtNetworkCreateResponse(BaseModel):
    success: bool
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    name: Optional[str] = None
    active: Optional[bool] = None
    persistent: Optional[bool] = None
    forward_mode: Optional[Literal["isolated", "nat", "route", "bridge"]] = None
    bridge_name: Optional[str] = None
    ipv4_cidr: Optional[str] = None
    dhcp_start: Optional[str] = None
    dhcp_end: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class LibvirtStoragePoolInfo(BaseModel):
    scope: Literal["system", "session"]
    name: str
    state: str
    autostart: Optional[bool] = Field(default=None, description="Whether libvirt is configured to start this pool automatically")
    persistent: Optional[bool] = Field(default=None, description="Whether the pool definition persists across libvirt daemon restarts")
    capacity: Optional[str] = Field(default=None, description="Capacity text reported by virsh; units follow virsh's human-readable format")
    allocation: Optional[str] = Field(default=None, description="Allocated space text reported by virsh")
    available: Optional[str] = Field(default=None, description="Available space text reported by virsh")


class LibvirtStorageVolumeInfo(BaseModel):
    name: str
    volume_type: Optional[str] = None
    capacity: Optional[str] = Field(default=None, description="Capacity text reported by virsh")
    allocation: Optional[str] = Field(default=None, description="Allocated space text reported by virsh")


class LibvirtStorageInventoryResponse(BaseModel):
    success: bool
    scope: Literal["system", "session", "both"] = "both"
    total_pools: int = 0
    returned_pools: int = 0
    pools: List[LibvirtStoragePoolInfo] = Field(default_factory=list)
    selected_pool_name: Optional[str] = None
    total_volumes: int = 0
    returned_volumes: int = 0
    volumes: List[LibvirtStorageVolumeInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class LibvirtResourceActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact local libvirt network or storage-pool action")
    resource_type: Literal["network", "storage_pool"]
    action: Literal["start", "stop", "enable_autostart", "disable_autostart"]
    scope: Literal["system", "session"]
    name: str = Field(description="Repeat the exact virtual-network or storage-pool name shown in the prompt")
    uuid: str = Field(description="Repeat the exact libvirt resource UUID shown in the prompt")
    expected_state_token: str = Field(description="Repeat the short-lived token bound to the exact resource and current state")


class LibvirtResourceActionResponse(BaseModel):
    success: bool
    resource_type: Literal["network", "storage_pool"]
    action: Literal["start", "stop", "enable_autostart", "disable_autostart"]
    scope: Optional[Literal["system", "session"]] = None
    name: Optional[str] = None
    uuid: Optional[str] = None
    state: Optional[str] = None
    autostart: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class LibvirtVolumeCreateConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm creation of this exact sparse libvirt storage volume")
    scope: Literal["system", "session"]
    pool_name: str = Field(description="Repeat the exact storage-pool name shown in the prompt")
    pool_uuid: str = Field(description="Repeat the exact storage-pool UUID shown in the prompt")
    volume_name: str = Field(description="Repeat the exact new volume name shown in the prompt")
    capacity_bytes: int = Field(description="Repeat the exact virtual capacity in bytes shown in the prompt")
    volume_format: Literal["raw", "qcow2"]
    expected_state_token: str = Field(description="Repeat the short-lived token bound to this request and current pool state")


class LibvirtVolumeCreateResponse(BaseModel):
    success: bool
    scope: Optional[Literal["system", "session"]] = None
    pool_name: Optional[str] = None
    pool_uuid: Optional[str] = None
    volume_name: Optional[str] = None
    capacity_bytes: Optional[int] = None
    volume_format: Literal["raw", "qcow2"] = "qcow2"
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class VirtualMachineActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact local libvirt domain action")
    action: Literal["start", "shutdown", "reboot", "suspend", "resume"]
    scope: Literal["system", "session"]
    uuid: str = Field(description="Repeat the exact domain UUID shown in the prompt")
    name: str = Field(description="Repeat the exact current domain name shown in the prompt")
    expected_state_token: str = Field(description="Repeat the short-lived state token shown in the prompt")


class VirtualMachineActionResponse(BaseModel):
    success: bool
    action: Literal["start", "shutdown", "reboot", "suspend", "resume"]
    scope: Optional[Literal["system", "session"]] = None
    uuid: Optional[str] = None
    name: Optional[str] = None
    state: Optional[str] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether this exact libvirt domain action received explicit MCP client confirmation")
    message: str


class BootTargetInfo(BaseModel):
    name: str
    unit_file_state: Optional[str] = None
    preset_state: Optional[str] = None
    active_state: Optional[str] = None
    sub_state: Optional[str] = None
    description: Optional[str] = None
    is_default: bool = False


class BootTargetListResponse(BaseModel):
    success: bool
    default_target: Optional[str] = None
    total_targets: int = 0
    returned_targets: int = 0
    targets: List[BootTargetInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class BootTargetConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this persistent default boot-target change")


class BootTargetActionResponse(BaseModel):
    success: bool
    target: str
    user_confirmed: bool = Field(default=False, description="Whether the exact target change received explicit MCP client confirmation")
    message: str


class TimeSettingsResponse(BaseModel):
    success: bool
    init_system: Optional[str] = None
    timezone: Optional[str] = None
    local_rtc: Optional[bool] = Field(default=None, description="Whether the hardware RTC is configured to use local time; null means unavailable")
    can_ntp: Optional[bool] = Field(default=None, description="Whether systemd timedated reports network time synchronization support")
    ntp_enabled: Optional[bool] = Field(default=None, description="Whether network time synchronization is enabled")
    ntp_synchronized: Optional[bool] = Field(default=None, description="Whether the system clock is currently synchronized")
    system_time: Optional[str] = Field(default=None, description="Current system clock value as emitted by timedatectl")
    rtc_time: Optional[str] = Field(default=None, description="Current hardware RTC value as emitted by timedatectl")
    message: Optional[str] = None


class TimeSyncProviderStatus(BaseModel):
    provider: Literal["chrony", "systemd-timesyncd"]
    available: bool
    success: bool
    partial: bool = False
    properties: Dict[str, str] = Field(default_factory=dict)
    sources: List[str] = Field(default_factory=list)
    malformed_records: int = 0
    truncated: bool = False
    message: Optional[str] = None


class TimeSyncStatusResponse(BaseModel):
    success: bool
    providers: List[TimeSyncProviderStatus] = Field(default_factory=list)
    message: Optional[str] = None


class DNSLinkInfo(BaseModel):
    link: Optional[str] = Field(default=None, description="Interface name for a per-link resolver section; null for global settings")
    link_index: Optional[int] = None
    is_global: bool = False
    current_dns_server: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    fallback_dns_servers: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list, description="Per-device DNS domain values reported separately from the search-domain list")
    search_domains: List[str] = Field(default_factory=list)
    settings: Dict[str, str] = Field(default_factory=dict)


class DNSConfigurationSource(BaseModel):
    source: Literal["resolv.conf", "systemd-resolved", "NetworkManager"]
    available: bool
    success: bool
    partial: bool = False
    source_target: Optional[str] = None
    nameservers: List[str] = Field(default_factory=list)
    search_domains: List[str] = Field(default_factory=list)
    domain: Optional[str] = None
    resolver_options: List[str] = Field(default_factory=list)
    links: List[DNSLinkInfo] = Field(default_factory=list)
    malformed_records: int = 0
    truncated: bool = False
    message: Optional[str] = None


class DNSConfigurationResponse(BaseModel):
    success: bool
    sources: List[DNSConfigurationSource] = Field(default_factory=list)
    message: Optional[str] = None


class TimeZoneInfo(BaseModel):
    name: str


class TimeZoneListResponse(BaseModel):
    success: bool
    total_time_zones: int = 0
    returned_time_zones: int = 0
    time_zones: List[TimeZoneInfo] = Field(default_factory=list)
    offset: int = 0
    limit: int = 100
    next_offset: Optional[int] = None
    truncated: bool = False
    message: Optional[str] = None


class TimeSettingsActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact time configuration change")
    action: Literal["set_timezone", "set_ntp"]
    timezone: Optional[str] = Field(default=None, description="Exact timezone identifier for set_timezone; null for set_ntp")
    ntp_enabled: Optional[bool] = Field(default=None, description="Desired network time synchronization state for set_ntp; null for set_timezone")
    expected_state_token: str = Field(description="Repeat the state token shown with the exact action and current configuration")


class TimeActionResponse(BaseModel):
    success: bool
    action: Literal["set_timezone", "set_ntp"]
    timezone: Optional[str] = None
    ntp_enabled: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether this exact time configuration action received explicit MCP client confirmation")
    message: str


class LocalUserInfo(BaseModel):
    username: str
    uid: int
    primary_gid: int


class LocalUserListResponse(BaseModel):
    success: bool
    total_users: int = 0
    returned_users: int = 0
    users: List[LocalUserInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class LocalGroupInfo(BaseModel):
    name: str
    gid: int
    members: List[str] = Field(default_factory=list, description="Supplementary member names recorded in local /etc/group")
    member_count: int = 0
    members_truncated: bool = False


class LocalGroupListResponse(BaseModel):
    success: bool
    total_groups: int = 0
    returned_groups: int = 0
    groups: List[LocalGroupInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class NSSUserInfo(BaseModel):
    username: str
    uid: int
    primary_gid: int


class NSSGroupInfo(BaseModel):
    name: str
    gid: int
    members: List[str] = Field(default_factory=list)
    member_count: int = 0
    members_truncated: bool = False


class NSSIdentityLookupResponse(BaseModel):
    success: bool
    kind: str
    identity: str
    found: bool = False
    user: Optional[NSSUserInfo] = None
    group: Optional[NSSGroupInfo] = None
    message: Optional[str] = None


class LoginSessionInfo(BaseModel):
    session_id: str
    uid: int
    username: str
    seat: Optional[str] = None
    tty: Optional[str] = None
    state: Optional[str] = None
    idle: Optional[bool] = None


class LoginSessionListResponse(BaseModel):
    success: bool
    total_sessions: int = 0
    returned_sessions: int = 0
    sessions: List[LoginSessionInfo] = Field(default_factory=list)
    limit: int = 50
    truncated: bool = False
    message: Optional[str] = None


class BlockDeviceInfo(BaseModel):
    name: str
    size_bytes: Optional[int] = Field(default=None, description="Capacity derived from the sysfs size attribute in 512-byte sectors")
    is_partition: bool = False
    removable: Optional[bool] = None
    read_only: Optional[bool] = None
    rotational: Optional[bool] = None
    logical_block_size_bytes: Optional[int] = None


class BlockDeviceListResponse(BaseModel):
    success: bool
    total_devices: int = 0
    returned_devices: int = 0
    devices: List[BlockDeviceInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class StorageTopologyNode(BaseModel):
    name: str = Field(description="Kernel block-device name from sysfs")
    size_bytes: Optional[int] = Field(default=None, description="Capacity derived from sysfs sectors in 512-byte units")
    stack_type: Literal["block_device", "partition", "loop", "device_mapper", "dm_crypt", "lvm_logical_volume", "multipath", "md_raid"]
    mapped_name: Optional[str] = Field(default=None, description="Device-mapper name from its read-only sysfs attribute")
    component_devices: List[str] = Field(default_factory=list, description="Block devices directly used as components of this node")
    holder_devices: List[str] = Field(default_factory=list, description="Block devices that directly use this node as a component")
    raid_level: Optional[str] = Field(default=None, description="Kernel MD RAID level when exposed")
    raid_device_count: Optional[int] = Field(default=None, description="Configured MD array device count when exposed")
    raid_degraded_count: Optional[int] = Field(default=None, description="MD array degraded-device count when exposed")
    raid_sync_action: Optional[str] = Field(default=None, description="Current MD background sync action, such as idle, check, recover, or resync")
    raid_sync_completed_sectors: Optional[int] = Field(default=None, description="Completed sectors in the current MD background sync action, when exposed")
    raid_sync_total_sectors: Optional[int] = Field(default=None, description="Total sectors in the current MD background sync action, when exposed")
    raid_mismatch_count: Optional[int] = Field(default=None, description="Mismatch sectors reported by the kernel MD check interface; this is not a count of distinct corrupt blocks")
    relation_data_partial: bool = Field(default=False, description="Whether sysfs relation or metadata reads were incomplete or changed during collection")


class StorageTopologyResponse(BaseModel):
    success: bool
    total_devices: int = 0
    returned_devices: int = 0
    devices: List[StorageTopologyNode] = Field(default_factory=list)
    limit: int = 100
    partial: bool = False
    truncated: bool = False
    message: Optional[str] = None


class LVMVolumeGroupInfo(BaseModel):
    name: str
    size_bytes: Optional[int] = Field(default=None, description="Volume-group size in bytes from the LVM report")
    free_bytes: Optional[int] = Field(default=None, description="Unallocated volume-group capacity in bytes")
    physical_volume_count: Optional[int] = None
    logical_volume_count: Optional[int] = None
    extent_size_bytes: Optional[int] = Field(default=None, description="Physical extent size in bytes")
    extent_count: Optional[int] = Field(default=None, description="Total physical extents in this volume group")
    free_extent_count: Optional[int] = Field(default=None, description="Unallocated physical extents in this volume group")


class LVMLogicalVolumeInfo(BaseModel):
    volume_group: str
    name: str
    size_bytes: Optional[int] = Field(default=None, description="Logical-volume size in bytes from the LVM report")
    layout: Optional[str] = Field(default=None, description="Reported LVM layout, such as linear, striped, or raid")
    pool: Optional[str] = Field(default=None, description="Thin/cache pool name when reported")
    origin: Optional[str] = Field(default=None, description="Origin volume name when reported")
    data_percent: Optional[float] = Field(default=None, description="Pool or snapshot data usage percentage when reported")
    metadata_percent: Optional[float] = Field(default=None, description="Pool metadata usage percentage when reported")


class LVMInventoryResponse(BaseModel):
    success: bool
    total_volume_groups: int = 0
    returned_volume_groups: int = 0
    volume_groups: List[LVMVolumeGroupInfo] = Field(default_factory=list)
    total_logical_volumes: int = 0
    returned_logical_volumes: int = 0
    logical_volumes: List[LVMLogicalVolumeInfo] = Field(default_factory=list)
    limit: int = 100
    partial: bool = False
    truncated: bool = False
    message: Optional[str] = None


class LVMVolumeActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact LVM logical-volume action")
    confirmation_phrase: str = Field(description="Repeat the LVM phrase bound to the exact volume-group state and requested action")


class LVMVolumeActionResponse(BaseModel):
    success: bool
    action: Literal["create", "resize", "shrink", "create_snapshot", "remove_snapshot", "restore_snapshot"]
    volume_group: str
    logical_volume: str
    snapshot_origin: Optional[str] = None
    size_bytes: Optional[int] = None
    current_size_bytes: Optional[int] = None
    actual_size_bytes: Optional[int] = None
    filesystem_type: Optional[str] = None
    filesystem_size_bytes: Optional[int] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class LVMVolumeGroupActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact LVM volume-group or PV membership action")
    confirmation_phrase: str = Field(description="Repeat the LVM phrase bound to the exact action, group, block devices, and current LVM state")


class LVMVolumeGroupActionResponse(BaseModel):
    success: bool
    action: Literal["create", "add_pv", "remove_pv", "move_pv"]
    volume_group: str
    physical_devices: List[str] = Field(default_factory=list)
    physical_volume_count: Optional[int] = None
    source_allocated_extents: Optional[int] = None
    destination_free_extents: Optional[int] = None
    move_bytes: Optional[int] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class BtrfsSnapshotInfo(BaseModel):
    path: str
    relative_path: str
    subvolume_id: int
    generation: int
    parent_id: int
    top_level_id: int
    uuid: str
    parent_uuid: str
    received_uuid: str
    read_only: bool


class BtrfsSnapshotListResponse(BaseModel):
    success: bool
    filesystem_top_level_path: Optional[str] = None
    total_snapshots: int = 0
    returned_snapshots: int = 0
    snapshots: List[BtrfsSnapshotInfo] = Field(default_factory=list)
    limit: int = 100
    offset: int = 0
    partial: bool = False
    truncated: bool = False
    message: Optional[str] = None


class BtrfsSnapshotActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact Btrfs snapshot creation, deletion, or restoration")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the exact Btrfs paths and current subvolume state")


class BtrfsSnapshotActionResponse(BaseModel):
    success: bool
    action: Literal["create", "delete", "restore"]
    filesystem_top_level_path: str
    snapshot_path: str
    source_path: Optional[str] = None
    source_uuid: Optional[str] = None
    snapshot_uuid: Optional[str] = None
    target_path: Optional[str] = None
    backup_path: Optional[str] = None
    restored_subvolume_uuid: Optional[str] = None
    staging_path: Optional[str] = None
    read_only: Optional[bool] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class LUKSActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact LUKS1 or LUKS2 device, mapping, or keyslot action")
    confirmation_phrase: str = Field(description="Repeat the LUKS phrase bound to the selected version, exact device, mapping, key-file identity, keyslot selection, and current storage state")


class LUKSActionResponse(BaseModel):
    success: bool
    action: Literal["format", "open", "close", "resize", "add_key", "remove_key"]
    device_path: str
    mapping_name: Optional[str] = None
    mapped_size_bytes: Optional[int] = None
    key_slot: Optional[int] = None
    active_keyslots: List[int] = Field(default_factory=list)
    user_confirmed: bool = False
    message: Optional[str] = None


class LUKSHeaderActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact LUKS header backup or restore")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the exact block device and backup-file state")


class LUKSHeaderActionResponse(BaseModel):
    success: bool
    action: Literal["backup", "restore"]
    device_path: str
    backup_file: str
    luks_version: Optional[Literal["luks1", "luks2"]] = None
    luks_uuid: Optional[str] = None
    backup_sha256: Optional[str] = None
    backup_size_bytes: Optional[int] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class LUKSTokenInfo(BaseModel):
    token_id: int
    token_type: str = Field(description="ASCII-escaped token type label; long labels are truncated for bounded display")
    keyslots: List[int] = Field(default_factory=list, description="Active keyslot IDs associated with this token")
    bound: bool = Field(description="False means the token currently has no keyslot binding")


class LUKSTokenListResponse(BaseModel):
    success: bool
    device_path: str
    luks_uuid: Optional[str] = None
    active_keyslots: List[int] = Field(default_factory=list)
    total_tokens: int = 0
    returned_tokens: int = 0
    tokens: List[LUKSTokenInfo] = Field(default_factory=list)
    message: Optional[str] = None


class LUKSTokenActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact LUKS2 token removal, keyslot unassignment, import, or export")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the device, full LUKS2 metadata, token data, and file state")


class LUKSTokenActionResponse(BaseModel):
    success: bool
    action: Literal["remove", "unassign", "import", "export"]
    device_path: str
    token_id: int
    token_type: Optional[str] = Field(default=None, description="ASCII-escaped token type label; long labels are truncated for bounded display")
    key_slot: Optional[int] = None
    previous_keyslots: List[int] = Field(default_factory=list)
    resulting_keyslots: List[int] = Field(default_factory=list)
    token_json_file: Optional[str] = None
    export_file: Optional[str] = None
    result_size_bytes: Optional[int] = Field(default=None, ge=0)
    user_confirmed: bool = False
    message: Optional[str] = None


class Ext4FilesystemActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact ext4 format, grow, or shrink action")
    confirmation_phrase: str = Field(description="Repeat the ext4 phrase bound to the block device and current storage state")


class Ext4FilesystemActionResponse(BaseModel):
    success: bool
    action: Literal["create", "grow", "shrink"]
    device_path: str
    target_size_bytes: Optional[int] = None
    filesystem_size_bytes: Optional[int] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class XFSFilesystemActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact XFS format or grow action")
    confirmation_phrase: str = Field(description="Repeat the XFS phrase bound to the block device and current storage state")


class XFSFilesystemActionResponse(BaseModel):
    success: bool
    action: Literal["create", "grow"]
    device_path: str
    filesystem_size_bytes: Optional[int] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class BtrfsFilesystemActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact Btrfs filesystem create, grow, or shrink action")
    confirmation_phrase: str = Field(description="Repeat the Btrfs phrase bound to the exact block device or mountpoint and current filesystem state")


class BtrfsFilesystemActionResponse(BaseModel):
    success: bool
    action: Literal["create", "grow", "shrink"]
    target_path: str
    filesystem_uuid: Optional[str] = None
    filesystem_size_bytes: Optional[int] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class MDRaidActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact MD RAID array or member-device action")
    confirmation_phrase: str = Field(description="Repeat the RAID phrase bound to the exact block devices and current array state")


class MDRaidActionResponse(BaseModel):
    success: bool
    action: Literal["create", "assemble", "add_spare", "remove_spare", "replace_member", "mark_faulty", "remove_faulty", "check", "stop"]
    array_path: str
    raid_level: Optional[str] = None
    device_paths: List[str] = Field(default_factory=list)
    read_only: Optional[bool] = Field(default=None, description="Whether an assembled MD array was started read-only")
    sync_action: Optional[str] = Field(default=None, description="Current MD background sync action after a check request")
    mismatch_count: Optional[int] = Field(default=None, description="Kernel-reported mismatch sectors; not a count of distinct corrupt blocks")
    user_confirmed: bool = False
    message: Optional[str] = None


class KernelModuleActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact kernel module load or unload")
    confirmation_phrase: str = Field(description="Repeat the module phrase bound to the exact module file and current kernel state")


class KernelModuleActionResponse(BaseModel):
    success: bool
    action: Literal["load", "unload"]
    module: str
    user_confirmed: bool = False
    message: Optional[str] = None


class KernelModuleStartupConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact persistent kernel module startup change")
    action: Literal["enable", "disable"]
    module: str = Field(description="Repeat the exact installed kernel module name")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the module, config file, and current module identity")
    expected_state_token: str = Field(pattern=r"^[0-9a-f]{64}$", description="Repeat the exact startup state token")


class KernelModuleStartupResponse(BaseModel):
    success: bool
    action: Literal["enable", "disable"]
    module: str
    path: Optional[str] = None
    file_changed: bool = False
    user_confirmed: bool = False
    message: str


class LocalIdentityActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact local user or group change")
    confirmation_phrase: str = Field(description="Repeat the identity phrase bound to the local account files and requested change")


class LocalIdentityActionResponse(BaseModel):
    success: bool
    action: Literal[
        "create_user", "delete_user", "lock_user", "unlock_user", "set_shell", "move_home",
        "create_group", "delete_group", "add_user_to_group", "remove_user_from_group",
    ]
    username: Optional[str] = None
    group_name: Optional[str] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class LocalPasswordSetConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm setting a new password for this exact local account")
    confirmation_phrase: str = Field(description="Repeat the one-time phrase bound to the pending local account password request")


class LocalPasswordSetResponse(BaseModel):
    success: bool
    username: Optional[str] = None
    user_confirmed: bool = False
    message: str


class LocalSSHKeyActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm adding or removing this exact OpenSSH public key")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the account, key fingerprint, and authorized_keys state")


class LocalSSHKeyActionResponse(BaseModel):
    success: bool
    action: Literal["add", "remove"]
    username: Optional[str] = None
    fingerprint: Optional[str] = None
    user_confirmed: bool = False
    message: str


class SudoPolicyActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm granting or revoking this exact PASSWD-tagged sudo command rule")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the local user/group, executable, exact arguments, and sudoers state")


class SudoPolicyActionResponse(BaseModel):
    success: bool
    action: Literal["grant", "revoke"]
    username: Optional[str] = None
    group_name: Optional[str] = None
    command_path: Optional[str] = None
    user_confirmed: bool = False
    message: str


class SSSDDomainEntry(BaseModel):
    name: str
    enabled: bool


class SSSDDomainListResponse(BaseModel):
    available: bool
    path: Optional[str] = None
    domains: list[SSSDDomainEntry] = Field(default_factory=list)
    message: str


class SSSDDomainActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm enabling or disabling this existing SSSD domain")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the domain and exact current SSSD configuration")


class SSSDDomainActionResponse(BaseModel):
    success: bool
    action: Literal["enable", "disable"]
    domain: Optional[str] = None
    enabled_domains: list[str] = Field(default_factory=list)
    user_confirmed: bool = False
    message: str


class PAMProfileEntry(BaseModel):
    name: str
    title: str
    selected: bool
    default: bool
    priority: int
    stack_types: list[str] = Field(default_factory=list)


class PAMProfileListResponse(BaseModel):
    available: bool
    path: Optional[str] = None
    profiles: list[PAMProfileEntry] = Field(default_factory=list)
    message: str


class PAMProfileActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm changing one packaged PAM profile's selection")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the profile, selected profile set, profile files, and current common PAM configuration")


class PAMProfileActionResponse(BaseModel):
    success: bool
    action: Literal["enable", "disable"]
    profile: Optional[str] = None
    selected_profiles: list[str] = Field(default_factory=list)
    user_confirmed: bool = False
    message: str


class BlockDeviceIOStats(BaseModel):
    name: str
    reads_completed: int
    reads_merged: int
    sectors_read_512: int
    read_time_ms: int
    writes_completed: int
    writes_merged: int
    sectors_written_512: int
    write_time_ms: int
    in_flight: int
    io_time_ms: int
    weighted_io_time_ms: int
    discards_completed: Optional[int] = None
    discards_merged: Optional[int] = None
    sectors_discarded_512: Optional[int] = None
    discard_time_ms: Optional[int] = None
    flushes_completed: Optional[int] = None
    flush_time_ms: Optional[int] = None


class BlockDeviceIOStatsResponse(BaseModel):
    success: bool
    total_devices: int = 0
    returned_devices: int = 0
    devices: List[BlockDeviceIOStats] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class BlockDeviceSmartAttribute(BaseModel):
    attribute_id: int
    name: str
    current: Optional[int] = None
    worst: Optional[int] = None
    threshold: Optional[int] = None
    when_failed: Optional[Literal["now", "past", "-"]] = None
    raw_value: Optional[str] = Field(default=None, description="Device-reported raw attribute value; interpretation varies by vendor")


class BlockDeviceHealthResponse(BaseModel):
    success: bool
    name: str
    health_status: Literal["passed", "failed", "unknown", "unavailable"]
    protocol: Optional[Literal["ATA", "SCSI", "NVMe"]] = None
    smartctl_exit_status: Optional[int] = None
    temperature_celsius: Optional[float] = None
    power_on_hours: Optional[int] = None
    power_cycle_count: Optional[int] = None
    nvme_critical_warning: Optional[int] = None
    nvme_available_spare_percent: Optional[int] = None
    nvme_available_spare_threshold_percent: Optional[int] = None
    nvme_percentage_used: Optional[int] = None
    nvme_data_units_read: Optional[int] = None
    nvme_data_units_written: Optional[int] = None
    nvme_media_errors: Optional[int] = None
    nvme_error_log_entries: Optional[int] = None
    ata_attributes: List[BlockDeviceSmartAttribute] = Field(default_factory=list)
    ata_attributes_truncated: bool = False
    message: Optional[str] = None


class HardwareDeviceInfo(BaseModel):
    bus: Literal["pci", "usb"] = Field(description="Linux hardware bus represented by this sysfs device")
    device_id: str = Field(description="PCI BDF or USB bus/port path; no serial number")
    vendor_id: Optional[str] = Field(default=None, description="Numeric hexadecimal vendor ID")
    product_id: Optional[str] = Field(default=None, description="Numeric hexadecimal product/device ID")
    class_code: Optional[str] = Field(default=None, description="Numeric hexadecimal device class code")
    subclass_code: Optional[str] = Field(default=None, description="Numeric hexadecimal subclass code")
    protocol_code: Optional[str] = Field(default=None, description="Numeric hexadecimal protocol code")
    driver: Optional[str] = Field(default=None, description="Bound kernel driver name when available")


class FirmwareInfo(BaseModel):
    system_vendor: Optional[str] = None
    product_name: Optional[str] = None
    product_version: Optional[str] = None
    board_vendor: Optional[str] = None
    board_name: Optional[str] = None
    board_version: Optional[str] = None
    chassis_vendor: Optional[str] = None
    chassis_type: Optional[str] = None
    chassis_version: Optional[str] = None
    bios_vendor: Optional[str] = None
    bios_version: Optional[str] = None
    bios_date: Optional[str] = None
    bios_release: Optional[str] = None


class HardwareDeviceListResponse(BaseModel):
    success: bool
    total_devices: int = 0
    returned_devices: int = 0
    devices: List[HardwareDeviceInfo] = Field(default_factory=list)
    firmware: Optional[FirmwareInfo] = Field(default=None, description="Selected descriptive system, board, chassis, and BIOS fields; explicit unique identifier fields are omitted")
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class DisplayBacklightInfo(BaseModel):
    name: str = Field(description="Exact kernel backlight device name used by the brightness control tool")
    brightness: int = Field(description="Current configured brightness from the kernel backlight device")
    actual_brightness: Optional[int] = Field(default=None, description="Current hardware-reported brightness when exposed")
    max_brightness: int = Field(description="Maximum configured brightness reported by the kernel device")


class DisplayBacklightListResponse(BaseModel):
    success: bool
    total_devices: int = 0
    devices: List[DisplayBacklightInfo] = Field(default_factory=list)
    truncated: bool = False
    message: Optional[str] = None


class DisplayBrightnessConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact brightness change")
    device_name: str = Field(description="Repeat the exact backlight device name")
    brightness: int = Field(description="Repeat the requested brightness value")
    confirmation_phrase: str = Field(description="Repeat the state-bound brightness phrase shown in the prompt")


class DisplayBrightnessResponse(BaseModel):
    success: bool
    device_name: Optional[str] = None
    brightness: Optional[int] = None
    actual_brightness: Optional[int] = None
    max_brightness: Optional[int] = None
    user_confirmed: bool = False
    message: str


class UdevDeviceInfo(BaseModel):
    sysfs_path: str = Field(description="Kernel device path relative to /sys; symlink aliases are omitted")
    sysname: str = Field(description="Kernel device name")
    subsystem: str
    devtype: Optional[str] = None
    driver: Optional[str] = Field(default=None, description="Attached kernel driver when available")
    vendor_id: Optional[str] = Field(default=None, description="Numeric hexadecimal vendor ID when available")
    product_id: Optional[str] = Field(default=None, description="Numeric hexadecimal product ID when available")
    major: Optional[int] = Field(default=None, description="Device-node major number when available")
    minor: Optional[int] = Field(default=None, description="Device-node minor number when available")


class UdevDeviceListResponse(BaseModel):
    success: bool
    total_devices: int = 0
    returned_devices: int = 0
    devices: List[UdevDeviceInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class SensorReading(BaseModel):
    source: Literal["hwmon", "thermal_zone"] = Field(description="Linux hwmon or thermal-zone sysfs source")
    device: str = Field(description="Sysfs device entry, optionally followed by its hwmon chip name")
    channel: str = Field(description="Sensor channel name, such as temp1 or fan2")
    kind: Literal["temperature", "fan_speed", "voltage", "current", "power", "energy", "humidity"]
    label: Optional[str] = Field(default=None, description="Driver-provided sensor or thermal-zone label")
    raw_value: int = Field(description="Integer value read from the sysfs input attribute")
    raw_unit: str = Field(description="Unit convention of the sysfs input attribute")
    value: float = Field(description="Value converted to the reported unit, or raw numeric value if the unit is driver-defined")
    unit: str = Field(description="Normalized unit, or driver_defined when no standard unit is available")
    normalization_status: Literal["standard", "driver_specific_possible", "driver_defined"] = Field(
        description="Whether the unit follows a standard convention or remains driver-specific"
    )


class SensorReadingListResponse(BaseModel):
    success: bool
    total_readings: int = 0
    returned_readings: int = 0
    readings: List[SensorReading] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class FanControlInfo(BaseModel):
    controller: str = Field(description="Exact Linux hwmon controller name, such as hwmon2")
    controller_path: str = Field(description="Resolved sysfs device path for the hwmon controller")
    chip_name: str
    pwm_index: int
    pwm_value: int = Field(description="Current standard hwmon PWM value from 0 through 255")
    control_mode: int = Field(description="Current pwm_enable mode; values 2 or greater indicate automatic control")
    fan_rpm: Optional[int] = None
    fan_label: Optional[str] = None
    controllable: bool = Field(description="Whether standard readable PWM and mode attributes are available and mode is supported")


class FanControlListResponse(BaseModel):
    success: bool
    total_controls: int = 0
    returned_controls: int = 0
    controls: List[FanControlInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class FanControlActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact fan maximum-speed or automatic-mode change")
    confirmation_phrase: str = Field(description="Repeat the fan control phrase bound to the exact hwmon controller, PWM channel, and current state")


class FanControlActionResponse(BaseModel):
    success: bool
    action: Literal["set_full", "restore_auto"]
    controller: str
    pwm_index: int
    pwm_value: Optional[int] = None
    control_mode: Optional[int] = None
    fan_rpm: Optional[int] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class AudioCardInfo(BaseModel):
    card_index: int
    card_id: str
    driver: Optional[str] = None
    name: str


class AudioPCMDeviceInfo(BaseModel):
    card_index: int
    card_id: Optional[str] = None
    card_name: Optional[str] = None
    device_index: int
    name: str
    direction: Literal["playback", "capture"]
    substreams: int


class AudioInventoryResponse(BaseModel):
    success: bool
    total_cards: int = 0
    returned_cards: int = 0
    cards: List[AudioCardInfo] = Field(default_factory=list)
    total_pcm_devices: int = 0
    returned_pcm_devices: int = 0
    pcm_devices: List[AudioPCMDeviceInfo] = Field(default_factory=list)
    limit: int = 50
    truncated: bool = False
    message: Optional[str] = None


class AudioServerDeviceInfo(BaseModel):
    object_id: Optional[str] = None
    direction: Literal["sink", "source"]
    name: str
    description: Optional[str] = None
    driver: Optional[str] = None
    state: Optional[str] = None
    is_default: Optional[bool] = None
    muted: Optional[bool] = None
    volume_channels: Dict[str, str] = Field(default_factory=dict)


class AudioServerInventoryResponse(BaseModel):
    success: bool
    partial: bool = False
    manager: Optional[Literal["wireplumber", "pulseaudio", "pipewire_pulse"]] = None
    default_sink: Optional[str] = None
    default_source: Optional[str] = None
    total_sinks: int = 0
    returned_sinks: int = 0
    sinks: List[AudioServerDeviceInfo] = Field(default_factory=list)
    total_sources: int = 0
    returned_sources: int = 0
    sources: List[AudioServerDeviceInfo] = Field(default_factory=list)
    limit: int = 50
    truncated: bool = False
    message: Optional[str] = None


class AudioEndpointActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact current-session audio endpoint change")
    action: Literal["set_volume", "set_mute", "set_default"]
    direction: Literal["sink", "source"]
    endpoint_id: str = Field(description="Repeat the exact numeric endpoint ID shown in the prompt")
    endpoint_name: str = Field(description="Repeat the exact endpoint name shown in the prompt")
    volume_percent: Optional[int] = Field(default=None, ge=0, le=100)
    muted: Optional[bool] = None
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the current endpoint state token shown in the confirmation prompt",
    )


class AudioEndpointActionResponse(BaseModel):
    success: bool
    action: Literal["set_volume", "set_mute", "set_default"]
    direction: Literal["sink", "source"]
    endpoint_id: Optional[str] = None
    endpoint_name: Optional[str] = None
    volume_percent: Optional[int] = None
    muted: Optional[bool] = None
    is_default: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = Field(
        default=False,
        description="Whether this exact audio endpoint change received explicit MCP client confirmation",
    )
    message: str


class PowerSupplyInfo(BaseModel):
    name: str
    type: Optional[str] = None
    present: Optional[bool] = None
    online: Optional[bool] = None
    online_value: Optional[int] = None
    status: Optional[str] = None
    health: Optional[str] = None
    capacity_percent: Optional[float] = None
    energy_now_wh: Optional[float] = None
    energy_full_wh: Optional[float] = None
    energy_full_design_wh: Optional[float] = None
    charge_now_ah: Optional[float] = None
    charge_full_ah: Optional[float] = None
    charge_full_design_ah: Optional[float] = None
    voltage_now_v: Optional[float] = None
    current_now_a: Optional[float] = None
    power_now_w: Optional[float] = None
    temperature_c: Optional[float] = None
    cycle_count: Optional[int] = None


class PowerSupplyListResponse(BaseModel):
    success: bool
    total_supplies: int = 0
    returned_supplies: int = 0
    supplies: List[PowerSupplyInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class PowerStateResponse(BaseModel):
    success: bool
    supported_sleep_states: List[str] = Field(default_factory=list, description="Kernel-exported /sys/power/state choices; this is not a guarantee that a transition will succeed")
    suspend_to_idle_supported: bool = False
    suspend_to_ram_supported: bool = False
    hibernation_supported: bool = False
    memory_sleep_modes: List[str] = Field(default_factory=list)
    selected_memory_sleep_mode: Optional[str] = None
    hibernation_modes: List[str] = Field(default_factory=list)
    selected_hibernation_mode: Optional[str] = None
    partial: bool = False
    message: Optional[str] = None


class PowerInhibitorInfo(BaseModel):
    who: str
    operations: List[str]
    why: str
    mode: Literal["block", "block-weak", "delay"]
    uid: int
    pid: int


class PowerInhibitorListResponse(BaseModel):
    success: bool
    partial: bool = False
    total_inhibitors: int = 0
    returned_inhibitors: int = 0
    inhibitors: List[PowerInhibitorInfo] = Field(default_factory=list)
    limit: int = 50
    truncated: bool = False
    message: Optional[str] = None


class PowerActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this immediate system-wide power action")


class PowerActionResponse(BaseModel):
    success: bool
    action: str = Field(description="Requested power operation, or 'unknown' if the input was invalid")
    user_confirmed: bool = Field(default=False, description="Whether this exact system-wide power action received explicit MCP client confirmation")
    message: str


class PowerActionReadinessResponse(BaseModel):
    success: bool
    action: str = Field(description="Queried power operation, or 'unknown' if the input was invalid")
    availability: PowerActionAvailability = "unknown"
    message: str


class PowerProfileResponse(BaseModel):
    success: bool
    active_profile: Optional[Literal["power-saver", "balanced", "performance"]] = None
    available_profiles: List[Literal["power-saver", "balanced", "performance"]] = Field(default_factory=list)
    message: str


class PowerProfileConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact system power-profile change")
    confirmation_phrase: str = Field(description="Repeat the state-bound profile phrase shown in the prompt")


class PowerProfileActionResponse(BaseModel):
    success: bool
    active_profile: Optional[Literal["power-saver", "balanced", "performance"]] = None
    available_profiles: List[Literal["power-saver", "balanced", "performance"]] = Field(default_factory=list)
    requested_profile: Optional[Literal["power-saver", "balanced", "performance"]] = None
    user_confirmed: bool = False
    message: str


class PrinterInfo(BaseModel):
    name: str
    state: Literal["idle", "printing", "disabled", "other", "unknown"] = "unknown"
    enabled: Optional[bool] = None
    accepting_jobs: Optional[bool] = None


class PrinterListResponse(BaseModel):
    success: bool
    total_printers: int = 0
    returned_printers: int = 0
    printers: List[PrinterInfo] = Field(default_factory=list)
    default_destination: Optional[str] = None
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class PrinterActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact CUPS printer queue action")
    action: Literal["enable", "disable", "accept", "reject"]
    printer: str = Field(description="Repeat the exact configured CUPS queue name shown in the confirmation prompt")
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the enabled, job-acceptance, and queue-state token shown in the confirmation prompt",
    )


class PrinterActionResponse(BaseModel):
    success: bool
    action: Literal["enable", "disable", "accept", "reject"]
    printer: str
    enabled: Optional[bool] = None
    accepting_jobs: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = Field(default=False, description="Whether this exact CUPS queue action received explicit client confirmation")
    message: str


class KernelModuleInfo(BaseModel):
    name: str
    size_bytes: int
    reference_count: int
    state: str


class KernelModuleListResponse(BaseModel):
    success: bool
    total_modules: int = 0
    returned_modules: int = 0
    modules: List[KernelModuleInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class KernelParameterInfo(BaseModel):
    name: str
    current_value: int
    minimum_value: int
    maximum_value: int
    description: str
    identity_token: str = Field(description="Short-lived token bound to this exact kernel parameter and observed value")


class KernelParameterListResponse(BaseModel):
    success: bool
    total_parameters: int = 0
    returned_parameters: int = 0
    parameters: List[KernelParameterInfo] = Field(default_factory=list)
    partial: bool = False
    message: Optional[str] = None


class KernelParameterChangeConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact runtime kernel parameter change")
    name: str = Field(description="Repeat the exact kernel parameter name shown in the prompt")
    current_value: int = Field(strict=True, description="Repeat the current value shown in the prompt")
    new_value: int = Field(strict=True, description="Repeat the requested runtime value shown in the prompt")
    state_token: str = Field(description="Repeat the token bound to the observed parameter state and requested value")


class KernelParameterChangeResponse(BaseModel):
    success: bool
    name: Optional[str] = None
    previous_value: Optional[int] = None
    current_value: Optional[int] = None
    user_confirmed: bool = Field(default=False, description="Whether this exact runtime parameter change received explicit client confirmation")
    message: str


class KernelParameterPersistenceConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact persistent sysctl configuration change")
    action: Literal["set", "remove"]
    name: str = Field(description="Repeat the exact allowlisted kernel parameter name")
    value: Optional[int] = Field(strict=True, description="Repeat the requested persistent value, or null when removing the generated setting")
    state_token: str = Field(pattern=r"^[0-9a-f]{64}$", description="Repeat the token bound to the generated config file and sysctl.d state")


class KernelParameterPersistenceResponse(BaseModel):
    success: bool
    action: Literal["set", "remove"]
    name: str
    path: Optional[str] = None
    previous_value: Optional[int] = None
    configured_value: Optional[int] = None
    file_changed: bool = False
    user_confirmed: bool = Field(default=False, description="Whether this exact persistent sysctl change received explicit client confirmation")
    message: str


class KernelCommandLineConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact persistent boot argument change")
    action: Literal["add", "remove"]
    argument: str = Field(max_length=256, description="Repeat the exact single kernel command-line argument")
    state_token: str = Field(pattern=r"^[0-9a-f]{64}$", description="Repeat the phrase bound to the current boot entries or supported GRUB config and generator state")


class KernelCommandLineResponse(BaseModel):
    success: bool
    action: Literal["add", "remove"]
    argument: str
    affected_entries: int = 0
    user_confirmed: bool = False
    message: str


class InitramfsRebuildConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm rebuilding the current kernel's initramfs")
    backend: Literal["dracut", "update-initramfs", "mkinitcpio"]
    kernel_release: str = Field(max_length=128, description="Repeat the exact running kernel release")
    image_path: str = Field(max_length=4096, description="Repeat the exact standard initramfs image path")
    state_token: str = Field(pattern=r"^[0-9a-f]{64}$", description="Repeat the token bound to the current image, generator, kernel image, preset/config/drop-in state, and /boot state")


class InitramfsRebuildResponse(BaseModel):
    success: bool
    backend: Optional[Literal["dracut", "update-initramfs", "mkinitcpio"]] = None
    kernel_release: Optional[str] = None
    image_path: Optional[str] = None
    previous_size_bytes: Optional[int] = None
    image_size_bytes: Optional[int] = None
    user_confirmed: bool = Field(default=False, description="Whether the exact initramfs rebuild received explicit client confirmation")
    message: str


class KernelSecuritySetting(BaseModel):
    name: str
    value: str
    source: str


class KernelSecurityPostureResponse(BaseModel):
    success: bool
    active_security_modules: List[str] = Field(default_factory=list)
    lockdown_mode: Optional[Literal["none", "integrity", "confidentiality"]] = None
    selinux_enforcing: Optional[bool] = None
    selinux_policy_version: Optional[int] = Field(
        default=None,
        description="Compatibility alias for selinux_max_policy_version; this is the kernel maximum supported version, not the loaded policy version.",
    )
    selinux_max_policy_version: Optional[int] = Field(
        default=None,
        description="Maximum SELinux policy format version supported by this kernel; it does not identify the loaded policy's version.",
    )
    selinux_mls_enabled: Optional[bool] = None
    selinux_deny_unknown: Optional[bool] = None
    selinux_reject_unknown: Optional[bool] = None
    selinux_policy_capabilities: List[str] = Field(
        default_factory=list,
        description="Policy capabilities exposed by the active SELinux policy through selinuxfs",
    )
    secure_boot_enabled: Optional[bool] = Field(
        default=None,
        description="UEFI SecureBoot variable: true when firmware signature verification of drivers and boot applications is active during this boot.",
    )
    secure_boot_setup_mode: Optional[bool] = Field(
        default=None,
        description="UEFI SetupMode variable: true when the platform reports setup mode.",
    )
    settings: List[KernelSecuritySetting] = Field(default_factory=list)
    unavailable_sources: List[str] = Field(default_factory=list)
    truncated: bool = False
    message: Optional[str] = None


class LinuxAuditKernelStatus(BaseModel):
    enabled: Optional[int] = Field(default=None, description="Kernel audit enabled mode reported by auditctl: 0 disabled, 1 enabled, 2 enabled and locked")
    failure_mode: Optional[int] = Field(default=None, description="Kernel audit failure mode: 0 silent, 1 printk, 2 panic")
    daemon_pid: Optional[int] = Field(default=None, description="Audit daemon PID reported by the kernel; zero means no daemon PID is registered")
    rate_limit: Optional[int] = None
    backlog_limit: Optional[int] = None
    lost_events: Optional[int] = None
    backlog_events: Optional[int] = None
    backlog_wait_time: Optional[int] = Field(default=None, description="Kernel audit backlog wait-time setting in the units reported by auditctl")
    backlog_wait_time_actual: Optional[int] = Field(default=None, description="Measured kernel audit backlog wait time in the units reported by auditctl")


class LinuxAuditStatusResponse(BaseModel):
    success: bool
    status_readable: bool = Field(default=False, description="Whether the fixed auditctl status query completed successfully")
    rules_readable: bool = Field(default=False, description="Whether the fixed auditctl active-rule query completed successfully")
    kernel_status: LinuxAuditKernelStatus = Field(default_factory=LinuxAuditKernelStatus)
    rules: List[str] = Field(default_factory=list, description="Bounded active audit rule lines; may expose watched paths, syscall filters, or audit keys")
    returned_rule_count: int = 0
    malformed_status_lines: int = 0
    malformed_rule_lines: int = 0
    unavailable_sources: List[str] = Field(default_factory=list)
    status_error: Optional[str] = None
    rules_error: Optional[str] = None
    truncated: bool = False
    message: Optional[str] = None


class LinuxAuditRuleActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact runtime Linux audit-watch rule change")
    action: Literal["add", "remove"] = Field(description="Repeat whether this exact audit watch will be added or removed")
    path: str = Field(description="Repeat the exact canonical watched path")
    permissions: str = Field(description="Repeat the exact selected audit access types")
    key: str = Field(description="Repeat the exact audit rule key")
    confirmation_phrase: str = Field(description="Short-lived phrase bound to the selected rule and current audit rule set")


class LinuxAuditRuleActionResponse(BaseModel):
    success: bool
    action: Literal["add", "remove"]
    path: Optional[str] = None
    permissions: Optional[str] = None
    key: Optional[str] = None
    user_confirmed: bool = False
    message: str


class LinuxAuditEventInfo(BaseModel):
    event_id: str = Field(description="Audit event timestamp and serial identifier")
    timestamp: str = Field(description="Raw numeric audit event timestamp from the kernel record")
    serial: int = Field(description="Audit event serial number")
    records: List[str] = Field(default_factory=list, description="Raw audit records belonging to this event")


class LinuxAuditEventListResponse(BaseModel):
    success: bool
    partial: bool = False
    window: Literal[
        "recent", "this-hour", "today", "yesterday", "this-week",
        "this-month", "this-year", "boot", "all",
    ] = "recent"
    limit: int = 50
    message_type: str = ""
    event_serial: Optional[int] = None
    process_id: Optional[int] = None
    returned_event_count: int = 0
    events: List[LinuxAuditEventInfo] = Field(default_factory=list)
    malformed_records: int = 0
    truncated: bool = False
    query_error: Optional[str] = None
    message: Optional[str] = None


class LinuxAuditSummaryResponse(BaseModel):
    success: bool
    partial: bool = False
    report_type: Literal[
        "overview", "authentication", "logins", "files", "hosts", "users",
        "processes", "executables", "syscalls", "keys",
    ] = "overview"
    window: Literal[
        "recent", "this-hour", "today", "yesterday", "this-week",
        "this-month", "this-year", "boot", "all",
    ] = "recent"
    limit: int = 80
    returned_line_count: int = 0
    report_lines: List[str] = Field(
        default_factory=list,
        description="Bounded sanitized aureport summary lines; may include sensitive local identities, paths, hosts, executable names, or audit keys.",
    )
    truncated: bool = False
    query_error: Optional[str] = None
    message: Optional[str] = None


class AppArmorProfileInfo(BaseModel):
    name: str = Field(description="Loaded AppArmor profile name, including any visible namespace prefix")
    mode: str = Field(description="Kernel-reported profile mode, such as enforce or complain")


class AppArmorProfileListResponse(BaseModel):
    success: bool
    offset: int = Field(default=0, description="Requested byte offset in the AppArmor securityfs profile list")
    start_offset: int = Field(default=0, description="Entry-boundary byte offset where this page actually began")
    next_offset: Optional[int] = Field(default=None, description="Byte offset to pass to the next call when has_more is true")
    has_more: Optional[bool] = Field(default=None, description="Whether more loaded profiles follow this page")
    scanned_bytes: int = 0
    returned_profiles: int = 0
    profiles: List[AppArmorProfileInfo] = Field(default_factory=list)
    limit: int = 100
    unavailable_sources: List[str] = Field(default_factory=list)
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class AppArmorProfileActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact AppArmor profile mode change")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the exact loaded profile, mode, action, and helper identity")


class AppArmorProfileActionResponse(BaseModel):
    success: bool
    name: Optional[str] = None
    action: Optional[Literal["enforce", "complain"]] = None
    mode_before: Optional[str] = None
    mode_after: Optional[str] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class SELinuxBooleanInfo(BaseModel):
    name: str
    current: Optional[bool] = Field(default=None, description="Current kernel value; null when the boolean could not be read")
    pending: Optional[bool] = Field(default=None, description="Pending kernel value; null when the boolean could not be read")
    unavailable_reason: Optional[str] = None


class SELinuxBooleanListResponse(BaseModel):
    success: bool
    query: str = ""
    offset: int = 0
    next_offset: Optional[int] = None
    has_more: Optional[bool] = None
    total_booleans: int = 0
    returned_booleans: int = 0
    booleans: List[SELinuxBooleanInfo] = Field(default_factory=list)
    limit: int = 100
    unavailable_sources: List[str] = Field(default_factory=list)
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class SELinuxBooleanActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact SELinux boolean change")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the boolean, current state, persistence choice, and setsebool executable")


class SELinuxBooleanActionResponse(BaseModel):
    success: bool
    name: Optional[str] = None
    enabled: Optional[bool] = None
    persistent: Optional[bool] = None
    current_before: Optional[bool] = None
    pending_before: Optional[bool] = None
    current_after: Optional[bool] = None
    pending_after: Optional[bool] = None
    user_confirmed: bool = False
    message: Optional[str] = None


class SELinuxContextRestoreConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm restoring the policy-defined SELinux type on this exact path")
    path: str = Field(description="Repeat the exact canonical path")
    current_context: Optional[str] = Field(default=None, description="Repeat the current SELinux context, or null when it is not labeled")
    expected_context: str = Field(description="Repeat the raw policy-defined context from matchpathcon")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the path, labels, policy, and helper identities")


class SELinuxContextRestoreResponse(BaseModel):
    success: bool
    path: Optional[str] = None
    current_context: Optional[str] = None
    expected_context: Optional[str] = None
    resulting_context: Optional[str] = None
    user_confirmed: bool = False
    message: str


class SELinuxFContextRuleConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact persistent SELinux file-context rule change")
    action: Literal["add", "remove"]
    path: str = Field(description="Repeat the exact canonical file or directory path")
    context_type: str = Field(description="Repeat the SELinux type name")
    confirmation_phrase: str = Field(description="Repeat the phrase bound to the path, rule state, and semanage executable")


class SELinuxFContextRuleResponse(BaseModel):
    success: bool
    action: Optional[Literal["add", "remove"]] = None
    path: Optional[str] = None
    context_type: Optional[str] = None
    file_type: Optional[str] = None
    rule_expression: Optional[str] = None
    user_confirmed: bool = False
    message: str


class IMAMeasurementInfo(BaseModel):
    byte_offset: int = Field(description="Byte position of this record in the ASCII IMA runtime-measurement interface")
    pcr_index: int = Field(description="PCR index recorded by IMA; this is not a read of the TPM PCR value")
    template_digest: str = Field(description="Hex digest of the complete IMA template data")
    template_name: str = Field(description="IMA template name or custom template format")
    template_data: str = Field(description="Bounded raw template fields; may include event names, file paths, signatures, or event payloads")
    template_data_truncated: bool = False


class IMAMeasurementListResponse(BaseModel):
    success: bool
    runtime_measurements_count: Optional[int] = None
    violations: Optional[int] = None
    offset: int = Field(default=0, description="Requested byte offset in the ASCII IMA measurement interface")
    start_offset: int = Field(default=0, description="Record-boundary byte offset where this page actually began")
    next_offset: Optional[int] = Field(default=None, description="Byte offset to pass to the next call when has_more is true")
    has_more: Optional[bool] = Field(
        default=None,
        description="Whether unread records follow this page; null means the bounded scan could not determine it.",
    )
    scanned_bytes: int = 0
    returned_measurements: int = 0
    measurements: List[IMAMeasurementInfo] = Field(default_factory=list)
    limit: int = 50
    unavailable_sources: List[str] = Field(default_factory=list)
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class IMAPolicyRuleInfo(BaseModel):
    byte_offset: int = Field(description="Byte position of this rule in the kernel-exported IMA policy interface")
    rule: str = Field(description="Raw active IMA policy rule with control characters escaped")


class IMAPolicyListResponse(BaseModel):
    success: bool
    offset: int = Field(default=0, description="Requested byte offset in the active IMA policy interface")
    start_offset: int = Field(default=0, description="Rule-boundary byte offset where this page actually began")
    next_offset: Optional[int] = Field(default=None, description="Byte offset to pass to the next call when has_more is true")
    has_more: Optional[bool] = Field(default=None, description="Whether unread policy rules follow this page")
    scanned_bytes: int = 0
    returned_rules: int = 0
    rules: List[IMAPolicyRuleInfo] = Field(default_factory=list)
    limit: int = 50
    unavailable_sources: List[str] = Field(default_factory=list)
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class TPMDeviceInfo(BaseModel):
    name: str
    tpm_version_major: Optional[int] = Field(default=None, ge=1, le=255)
    driver: Optional[str] = None
    unavailable_attributes: List[str] = Field(default_factory=list)
    partial: bool = False


class TPMInventoryResponse(BaseModel):
    success: bool
    total_devices: int = Field(default=0, description="TPM class devices discovered within the bounded sysfs scan")
    returned_devices: int = 0
    devices: List[TPMDeviceInfo] = Field(default_factory=list)
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class TPMEventDigestAlgorithm(BaseModel):
    algorithm_id: int = Field(ge=0, le=65535)
    algorithm: str
    digest_size_bytes: int = Field(ge=1, le=128)


class TPMEventDigest(BaseModel):
    algorithm_id: int = Field(ge=0, le=65535)
    algorithm: str
    digest: str = Field(description="Digest bytes in hexadecimal")


class TPMEventInfo(BaseModel):
    byte_offset: int = Field(description="Byte position of this record in the kernel-exported binary event log")
    pcr_index: int = Field(ge=0, le=4_294_967_295)
    event_type: int = Field(ge=0, le=4_294_967_295)
    event_type_name: str
    digests: List[TPMEventDigest] = Field(default_factory=list)
    event_data_size_bytes: int = Field(ge=0)
    event_data_preview_hex: str = Field(
        description="At most 128 leading event-data bytes in hexadecimal; event data may include paths or firmware details"
    )
    event_data_truncated: bool = False


class TPMEventLogResponse(BaseModel):
    success: bool
    device_name: Optional[str] = None
    log_format: Optional[Literal["legacy_sha1", "crypto_agile"]] = None
    spec_version: Optional[str] = None
    algorithms: List[TPMEventDigestAlgorithm] = Field(default_factory=list)
    offset: int = Field(default=0, description="Requested byte offset in the binary event log")
    next_offset: Optional[int] = Field(default=None, description="Byte offset for the next page when has_more is true")
    has_more: Optional[bool] = Field(default=None, description="Whether another event follows this page")
    scanned_bytes: int = 0
    returned_events: int = 0
    events: List[TPMEventInfo] = Field(default_factory=list)
    limit: int = 50
    unavailable_sources: List[str] = Field(default_factory=list)
    truncated: bool = False
    partial: bool = False
    message: Optional[str] = None


class TPMAttestationConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this TPM quote request")
    persistent_handle: str = Field(pattern=r"^0x81[0-9a-fA-F]{6}$", description="Repeat the exact persistent TPM attestation-key handle")
    pcr_indices: List[int] = Field(min_length=1, max_length=24, description="Repeat the selected unique PCR indexes from 0 through 23")
    nonce: str = Field(pattern=r"^[0-9a-f]{64}$", description="Repeat the caller-supplied 32-byte verifier nonce")
    state_token: str = Field(pattern=r"^[0-9a-f]{64}$", description="Repeat the token bound to the public key, TPM device, tools, nonce, and PCR selection")


class TPMAttestationResponse(BaseModel):
    success: bool
    persistent_handle: str
    pcr_bank: Literal["sha256"] = "sha256"
    pcr_indices: List[int] = Field(default_factory=list)
    nonce: str
    ak_public_key_pem: Optional[str] = None
    ak_name_base64: Optional[str] = None
    quote_message_base64: Optional[str] = None
    signature_base64: Optional[str] = None
    pcr_values_base64: Optional[str] = None
    signature_verified: bool = False
    user_confirmed: bool = False
    message: str


class InstalledPackageInfo(BaseModel):
    name: str
    version: Optional[str] = None
    architecture: Optional[str] = None


class InstalledPackageListResponse(BaseModel):
    success: bool
    manager: str
    total_packages: int = 0
    returned_packages: int = 0
    packages: List[InstalledPackageInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


PackageAction = Literal["install", "upgrade", "remove", "upgrade_all"]


class PackageActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm the exact system package-manager operation")


class PackageActionResponse(BaseModel):
    success: bool
    action: PackageAction
    package: str = ""
    manager: Optional[str] = None
    frontend: Optional[str] = None
    return_code: Optional[int] = None
    timed_out: bool = False
    user_confirmed: bool = Field(default=False, description="Whether the exact package-manager action received explicit MCP client confirmation")
    message: str


class ApplicationPackageInfo(BaseModel):
    manager: Literal["flatpak", "snap", "nix"]
    name: str
    package_kind: Literal["app", "runtime", "snap", "profile_entry"]
    version: Optional[str] = None
    architecture: Optional[str] = None
    branch: Optional[str] = None
    revision: Optional[str] = None
    scope: str
    active: Optional[bool] = None


class ApplicationPackageSourceStatus(BaseModel):
    manager: Literal["flatpak", "snap", "nix"]
    scope: str
    available: bool
    success: bool
    package_count: int = 0
    truncated: bool = False
    message: Optional[str] = None


class ApplicationPackageInventoryResponse(BaseModel):
    success: bool
    partial: bool = False
    sources: List[ApplicationPackageSourceStatus] = Field(default_factory=list)
    total_packages: int = 0
    returned_packages: int = 0
    packages: List[ApplicationPackageInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class ApplicationPackageActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact Flatpak app/runtime transaction")
    action: Literal["install", "update", "remove"]
    scope: Literal["system", "user"]
    ref: str = Field(description="Repeat the exact full Flatpak ref shown in the confirmation prompt")
    remote: str = Field(default="", description="Repeat the configured remote name for install; empty for update/remove")
    installation: str = Field(
        default="",
        max_length=128,
        description="Repeat the exact configured named system installation ID, or leave empty for the selected default installation",
    )
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the token binding the exact action, ref, scope, named installation configuration, installed state, remote configuration, and user installation context",
    )


class ApplicationPackageActionResponse(BaseModel):
    success: bool
    action: Literal["install", "update", "remove"]
    scope: Literal["system", "user"]
    ref: str
    installation: Optional[str] = None
    remote: Optional[str] = None
    state_verified: bool = False
    return_code: Optional[int] = None
    timed_out: bool = False
    user_confirmed: bool = Field(default=False, description="Whether the exact Flatpak transaction received explicit MCP client confirmation")
    message: str


class SnapPackageActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact Snap package transaction")
    action: Literal["install", "update", "switch_channel", "remove", "enable", "disable", "revert", "hold", "unhold", "hold_all", "unhold_all"]
    package_name: str = Field(
        default="",
        max_length=40,
        description="Repeat the exact lowercase Snap Store name, or leave empty for a system-wide refresh hold action",
    )
    target_channel: str = Field(
        default="",
        max_length=160,
        description="For switch_channel, repeat the exact target_channel input from the tool request; leave empty for other actions",
    )
    snap_file_path: str = Field(
        default="",
        max_length=4096,
        description="For a local Snap install, repeat the exact absolute .snap file path; otherwise leave empty",
    )
    dangerous: bool = Field(
        default=False,
        description="For a local Snap install only, repeat whether assertion/signature verification is explicitly bypassed",
    )
    classic: bool = Field(
        default=False,
        description="For install only, repeat whether the request explicitly selected classic confinement",
    )
    devmode: bool = Field(
        default=False,
        description="For local install only, repeat whether the request explicitly selected developer mode, which grants full system-resource access and may proceed when assertion verification fails",
    )
    revision: Optional[int] = Field(
        default=None,
        ge=1,
        le=2147483647,
        description="For revert only, repeat the exact retained numeric revision to activate",
    )
    hold_duration: str = Field(
        default="",
        max_length=16,
        description="For hold or hold_all on snapd 2.58 or newer, repeat 'forever' or a bounded duration such as 30m, 12h, or 1h30m; leave empty otherwise",
    )
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the token binding the action, exact Snap or full installed inventory for system-wide holds, channel, requested revision or hold duration, local-file digest, confinement modes, installed revision, and tracking state",
    )


class SnapPackageActionResponse(BaseModel):
    success: bool
    action: Literal["install", "update", "switch_channel", "remove", "enable", "disable", "revert", "hold", "unhold", "hold_all", "unhold_all"]
    package_name: str
    target_channel: Optional[str] = None
    revision: Optional[str] = None
    hold_duration: Optional[str] = None
    enabled: Optional[bool] = None
    held: Optional[bool] = None
    classic: bool = False
    devmode: bool = False
    local_file: bool = False
    dangerous: bool = False
    state_verified: bool = False
    return_code: Optional[int] = None
    timed_out: bool = False
    user_confirmed: bool = Field(default=False, description="Whether the exact Snap transaction received explicit MCP client confirmation")
    message: str


class NixProfileActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact Nix profile install or entry change")
    action: Literal["install", "upgrade", "remove"]
    entry_name: str = Field(
        max_length=512,
        pattern=r"^(?:[A-Za-z0-9][A-Za-z0-9+._@-]{0,255}|[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*){0,15})$",
        description="Repeat the exact nixpkgs attribute path for install, or exact name or numeric index from the current user's default Nix profile for upgrade/remove",
    )
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the token binding the action, selector, current default profile generation, and user context",
    )


class NixProfileActionResponse(BaseModel):
    success: bool
    action: Literal["install", "upgrade", "remove"]
    entry_name: str = Field(description="Profile name/index for upgrade/remove or requested nixpkgs attribute for install")
    state_verified: bool = False
    return_code: Optional[int] = None
    timed_out: bool = False
    user_confirmed: bool = Field(default=False, description="Whether the exact Nix profile action received explicit MCP client confirmation")
    message: str


class NixProfileGenerationInfo(BaseModel):
    version: int
    date: str
    previous_version: Optional[int] = None
    changed_entry_count: int = 0
    is_current: bool = False


class NixProfileHistoryListResponse(BaseModel):
    success: bool
    current_version: Optional[int] = None
    total_versions: int = 0
    returned_versions: int = 0
    generations: List[NixProfileGenerationInfo] = Field(default_factory=list, max_length=500)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class NixProfileHistoryActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact rollback or age-bounded history cleanup for the current user's default Nix profile")
    action: Literal["rollback", "wipe_history"]
    target_version: int = Field(default=0, ge=0, description="Repeat the exact existing profile version for rollback; zero for wipe_history")
    older_than_days: int = Field(default=0, ge=0, le=36500, description="Repeat the age cutoff in days for wipe_history; zero for rollback")
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the token binding current profile contents, history, action parameters, and user context",
    )


class NixProfileHistoryActionResponse(BaseModel):
    success: bool
    action: Literal["rollback", "wipe_history"]
    current_version: Optional[int] = None
    target_version: Optional[int] = None
    older_than_days: Optional[int] = None
    affected_versions: List[int] = Field(default_factory=list, max_length=100)
    state_verified: bool = False
    timed_out: bool = False
    user_confirmed: bool = Field(default=False, description="Whether the exact Nix profile history action received explicit MCP client confirmation")
    message: str


class PythonEnvironmentInfo(BaseModel):
    environment_name: str
    python_available: bool = True


class PythonEnvironmentListResponse(BaseModel):
    success: bool
    total_environments: int = 0
    returned_environments: int = 0
    environments: List[PythonEnvironmentInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    skipped_entries: int = 0
    message: Optional[str] = None


class PythonEnvironmentPackageInfo(BaseModel):
    name: str
    version: str


class PythonEnvironmentPackageListResponse(BaseModel):
    success: bool
    environment_name: str
    total_packages: int = 0
    returned_packages: int = 0
    packages: List[PythonEnvironmentPackageInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class PythonEnvironmentActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact current-user Python virtual-environment or pip action")
    action: Literal["create", "install", "upgrade", "uninstall"]
    environment_name: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        description="Repeat the exact managed environment name under the current user's home directory",
    )
    package_name: str = Field(
        default="",
        pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$",
        description="Repeat one exact Python project name; empty only when creating an environment",
    )
    version: str = Field(
        default="",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}$",
        description="Repeat one exact version for install, or an empty string for other actions",
    )
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the token binding the exact action, environment, interpreter, current identity, and package inventory",
    )


class PythonEnvironmentActionResponse(BaseModel):
    success: bool
    action: Literal["create", "install", "upgrade", "uninstall"]
    environment_name: str
    package_name: Optional[str] = None
    version: Optional[str] = None
    state_verified: bool = False
    return_code: Optional[int] = None
    timed_out: bool = False
    user_confirmed: bool = Field(default=False, description="Whether the exact Python environment action received explicit MCP client confirmation")
    message: str


class NativePackageEnvironmentInfo(BaseModel):
    ecosystem: Literal["npm", "cargo"]
    environment_name: str


class NativePackageEnvironmentListResponse(BaseModel):
    success: bool
    ecosystem: Literal["npm", "cargo"]
    total_environments: int = 0
    returned_environments: int = 0
    environments: List[NativePackageEnvironmentInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    skipped_entries: int = 0
    message: Optional[str] = None


class NativeEnvironmentPackageInfo(BaseModel):
    name: str
    version: str


class NativeEnvironmentPackageListResponse(BaseModel):
    success: bool
    ecosystem: Literal["npm", "cargo"]
    environment_name: str
    total_packages: int = 0
    returned_packages: int = 0
    packages: List[NativeEnvironmentPackageInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class NativePackageEnvironmentActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact npm or Cargo environment action")
    ecosystem: Literal["npm", "cargo"]
    action: Literal["create", "install", "upgrade", "uninstall"]
    environment_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    package_name: str = Field(
        default="",
        max_length=220,
        pattern=r"^(?:[a-z0-9][a-z0-9._-]{0,213}|@[a-z0-9][a-z0-9._-]{0,99}/[a-z0-9][a-z0-9._-]{0,99}|[A-Za-z0-9][A-Za-z0-9_-]{0,63})?$",
        description="Repeat the exact npm package or Cargo crates.io crate name; empty for create",
    )
    version: str = Field(
        default="",
        max_length=128,
        pattern=r"^(?:[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?)?$",
        description="Repeat one exact semantic version for install, or empty for other actions",
    )
    expected_state_token: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="Repeat the token binding the ecosystem, action, environment, package inventory, manager identity, and current user",
    )


class NativePackageEnvironmentActionResponse(BaseModel):
    success: bool
    ecosystem: Literal["npm", "cargo"]
    action: Literal["create", "install", "upgrade", "uninstall"]
    environment_name: str
    package_name: Optional[str] = None
    version: Optional[str] = None
    state_verified: bool = False
    timed_out: bool = False
    user_confirmed: bool = Field(default=False, description="Whether the exact npm/Cargo action received explicit MCP client confirmation")
    message: str


class NetworkSocketInfo(BaseModel):
    protocol: Literal["tcp", "udp"]
    family: Literal["ipv4", "ipv6"]
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    uid: Optional[int] = None
    inode: Optional[int] = None


class NetworkSocketListResponse(BaseModel):
    success: bool
    total_sockets: int = 0
    returned_sockets: int = 0
    sockets: List[NetworkSocketInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class SocketProcessOwner(BaseModel):
    inode: int
    pid: int
    name: str
    uid: Optional[int] = None
    open_descriptor_count: int


class SocketOwnerListResponse(BaseModel):
    success: bool
    requested_inodes: List[int] = Field(default_factory=list)
    matched_inodes: List[int] = Field(default_factory=list)
    unmatched_inodes: List[int] = Field(default_factory=list)
    total_owners: int = 0
    returned_owners: int = 0
    owners: List[SocketProcessOwner] = Field(default_factory=list)
    processes_scanned: int = 0
    descriptors_scanned: int = 0
    inaccessible_processes: int = 0
    unreadable_descriptors: int = 0
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class UnixDomainSocketInfo(BaseModel):
    inode: int
    socket_type: str
    state: str
    flags: int
    reference_count: int
    path: Optional[str] = Field(default=None, description="Bound filesystem or abstract-namespace path, when present")


class RawSocketInfo(BaseModel):
    family: Literal["ipv4", "ipv6"]
    local_address: str
    local_protocol_number: int
    remote_address: Optional[str] = None
    state: str
    uid: Optional[int] = None
    inode: Optional[int] = None


class UnixRawSocketResponse(BaseModel):
    success: bool
    total_unix_sockets: int = 0
    returned_unix_sockets: int = 0
    unix_sockets: List[UnixDomainSocketInfo] = Field(default_factory=list)
    total_raw_sockets: int = 0
    returned_raw_sockets: int = 0
    raw_sockets: List[RawSocketInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class NetworkProtocolCounterGroup(BaseModel):
    source: Literal["snmp", "netstat", "snmp6"]
    protocol: str
    counters: dict[str, int] = Field(default_factory=dict)


class NetworkProtocolStatsResponse(BaseModel):
    success: bool
    total_groups: int = 0
    returned_groups: int = 0
    groups: List[NetworkProtocolCounterGroup] = Field(default_factory=list)
    limit: int = 64
    truncated: bool = False
    message: Optional[str] = None


class NetworkRouteInfo(BaseModel):
    family: Literal["ipv4", "ipv6"]
    destination: str
    prefix_length: int
    gateway: Optional[str] = None
    interface: str
    metric: int
    flags: int = Field(description="Raw route flags from the Linux procfs table")
    source: Optional[str] = None
    source_prefix_length: Optional[int] = None


class NetworkRouteListResponse(BaseModel):
    success: bool
    total_routes: int = 0
    returned_routes: int = 0
    routes: List[NetworkRouteInfo] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class NetworkRouteLookupResponse(BaseModel):
    success: bool
    family: Optional[Literal["ipv4", "ipv6"]] = None
    destination: Optional[str] = None
    source: Optional[str] = None
    preferred_source: Optional[str] = None
    gateway: Optional[str] = None
    device: Optional[str] = None
    table: Optional[str | int] = None
    metric: Optional[int] = None
    protocol: Optional[str | int] = None
    route_type: Optional[str] = None
    scope: Optional[str] = None
    truncated: bool = False
    message: Optional[str] = None


class NetworkPolicyRule(BaseModel):
    family: Literal["ipv4", "ipv6"]
    priority: Optional[int] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    table: Optional[str | int] = None
    action: Optional[str] = None
    firewall_mark: Optional[str | int] = None
    incoming_interface: Optional[str] = None
    outgoing_interface: Optional[str] = None
    uid_range: Optional[str] = None
    ip_protocol: Optional[str | int] = None
    source_port: Optional[str | int] = None
    destination_port: Optional[str | int] = None
    protocol: Optional[str | int] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)


class NetworkPolicyRoute(BaseModel):
    family: Literal["ipv4", "ipv6"]
    destination: str
    gateway: Optional[str] = None
    gateway_family: Optional[str] = None
    interface: Optional[str] = None
    table: Optional[str | int] = None
    route_type: Optional[str] = None
    scope: Optional[str] = None
    metric: Optional[int] = None
    protocol: Optional[str | int] = None
    preferred_source: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)


class NetworkPolicySnapshotResponse(BaseModel):
    success: bool
    family: Literal["all", "ipv4", "ipv6"] = "all"
    total_rules: int = 0
    returned_rules: int = 0
    rules: List[NetworkPolicyRule] = Field(default_factory=list)
    total_routes: int = 0
    returned_routes: int = 0
    routes: List[NetworkPolicyRoute] = Field(default_factory=list)
    limit: int = 200
    truncated: bool = False
    message: Optional[str] = None


class FirewallEntry(BaseModel):
    source: Literal["nftables", "iptables_ipv4", "iptables_ipv6"]
    object_type: str
    family: Optional[str] = None
    table: Optional[str] = None
    chain: Optional[str] = None
    name: Optional[str] = None
    policy: Optional[str] = None
    hook: Optional[str] = None
    priority: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class FirewallSourceStatus(BaseModel):
    source: Literal["nftables", "iptables_ipv4", "iptables_ipv6"]
    available: bool
    success: bool
    entry_count: int = 0
    truncated: bool = False
    message: Optional[str] = None


class FirewallInventoryResponse(BaseModel):
    success: bool
    partial: bool = False
    sources: List[FirewallSourceStatus] = Field(default_factory=list)
    total_entries: int = 0
    returned_entries: int = 0
    entries: List[FirewallEntry] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class FirewallRuleActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact transient inbound firewall block rule")


class FirewallRuleActionResponse(BaseModel):
    success: bool
    action: Literal["add_block", "remove_block"]
    family: Optional[Literal["ipv4", "ipv6"]] = None
    protocol: Optional[Literal["tcp", "udp"]] = None
    port: Optional[int] = None
    source_cidr: Optional[str] = None
    rule_handle: Optional[int] = None
    user_confirmed: bool = Field(default=False, description="Whether this exact firewall rule change received explicit MCP client confirmation")
    message: str


class FirewalldPortActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact firewalld port rule and configuration scope")
    action: Literal["add_port", "remove_port"]
    configuration: Literal["runtime", "permanent"]
    zone: str = Field(description="Repeat the exact firewalld zone name shown in the prompt")
    protocol: Literal["tcp", "udp"]
    port_position: Literal["destination", "source"] = Field(default="destination", description="Repeat whether this is a destination-port or source-port entry")
    port: int = Field(description="Repeat the exact source or destination port shown in the prompt")
    expected_state_token: str = Field(description="Repeat the short-lived token bound to this zone and current rule state")


class FirewalldPortActionResponse(BaseModel):
    success: bool
    action: Literal["add_port", "remove_port"]
    configuration: Literal["runtime", "permanent"]
    zone: Optional[str] = None
    protocol: Optional[Literal["tcp", "udp"]] = None
    port_position: Optional[Literal["destination", "source"]] = None
    port: Optional[int] = None
    zone_active: Optional[bool] = None
    rule_present: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class FirewalldICMPBlockActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact firewalld ICMP block and configuration scope")
    action: Literal["add_block", "remove_block"]
    configuration: Literal["runtime", "permanent"]
    zone: str = Field(description="Repeat the exact firewalld zone name shown in the prompt")
    icmp_type: str = Field(description="Repeat the exact supported ICMP type name shown in the prompt")
    expected_state_token: str = Field(description="Repeat the short-lived token bound to this zone, type definition, and current block state")


class FirewalldICMPBlockActionResponse(BaseModel):
    success: bool
    action: Literal["add_block", "remove_block"]
    configuration: Literal["runtime", "permanent"]
    zone: Optional[str] = None
    icmp_type: Optional[str] = None
    zone_active: Optional[bool] = None
    rule_present: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class FirewalldServiceActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact firewalld service and configuration scope")
    action: Literal["add_service", "remove_service"]
    configuration: Literal["runtime", "permanent"]
    zone: str = Field(description="Repeat the exact firewalld zone name shown in the prompt")
    service: str = Field(description="Repeat the exact firewalld service name shown in the prompt")
    expected_state_token: str = Field(description="Repeat the short-lived token bound to this zone and current service state")


class FirewalldServiceActionResponse(BaseModel):
    success: bool
    action: Literal["add_service", "remove_service"]
    configuration: Literal["runtime", "permanent"]
    zone: Optional[str] = None
    service: Optional[str] = None
    zone_active: Optional[bool] = None
    service_present: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class FirewalldRichRuleActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact firewalld rich rule and configuration scope")
    action: Literal["add", "remove"]
    configuration: Literal["runtime", "permanent"]
    zone: str = Field(description="Repeat the exact firewalld zone name shown in the prompt")
    protocol: Literal["tcp", "udp"]
    port_position: Literal["destination", "source"] = Field(default="destination", description="Repeat whether the selected port is a destination or source port")
    port: int = Field(description="Repeat the first selected source or destination port shown in the prompt")
    port_end: Optional[int] = Field(default=None, description="Repeat the inclusive end of the selected source or destination port range, or null for one port")
    source_cidr: Optional[str] = Field(default=None, description="Repeat the canonical source CIDR, or null for any source")
    destination_cidr: Optional[str] = Field(default=None, description="Repeat the canonical destination CIDR, or null for any destination")
    verdict: Literal["accept", "reject", "drop"]
    log_enabled: StrictBool = Field(default=False, description="Repeat whether the rule logs matching attempts, capped at one event per minute")
    log_prefix: Optional[str] = Field(default=None, description="Repeat the optional safe log prefix, up to 127 characters")
    log_level: Optional[Literal["emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"]] = Field(default=None, description="Repeat the optional kernel log level; requires log_enabled=true")
    audit_enabled: StrictBool = Field(default=False, description="Repeat whether matching attempts create audit records, capped at one event per minute")
    priority: Optional[StrictInt] = Field(default=None, description="Repeat the optional rich-rule priority from -32768 through 32767")
    expected_state_token: str = Field(description="Repeat the short-lived token bound to this zone and current rich-rule state")


class FirewalldRichRuleActionResponse(BaseModel):
    success: bool
    action: Literal["add", "remove"]
    configuration: Literal["runtime", "permanent"]
    zone: Optional[str] = None
    protocol: Optional[Literal["tcp", "udp"]] = None
    port_position: Optional[Literal["destination", "source"]] = None
    port: Optional[int] = None
    port_end: Optional[int] = None
    source_cidr: Optional[str] = None
    destination_cidr: Optional[str] = None
    verdict: Optional[Literal["accept", "reject", "drop"]] = None
    rule_present: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class FirewalldRichICMPRuleActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact firewalld rich ICMP-type rule and configuration scope")
    action: Literal["add", "remove"]
    configuration: Literal["runtime", "permanent"]
    zone: str = Field(description="Repeat the exact firewalld zone name shown in the prompt")
    icmp_type: str = Field(description="Repeat the exact supported firewalld ICMP type name")
    source_cidr: Optional[str] = Field(default=None, description="Repeat the canonical source CIDR, or null for any source")
    destination_cidr: Optional[str] = Field(default=None, description="Repeat the canonical destination CIDR, or null for any destination")
    verdict: Literal["accept", "reject", "drop"]
    log_enabled: StrictBool = Field(default=False, description="Repeat whether matching attempts are logged at most once per minute")
    log_prefix: Optional[str] = Field(default=None, description="Repeat the optional safe log prefix, up to 127 characters")
    log_level: Optional[Literal["emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"]] = Field(default=None, description="Repeat the optional kernel log level; requires log_enabled=true")
    audit_enabled: StrictBool = Field(default=False, description="Repeat whether matching attempts create audit records at most once per minute")
    priority: Optional[StrictInt] = Field(default=None, description="Repeat the optional rich-rule priority from -32768 through 32767")
    expected_state_token: str = Field(description="Repeat the short-lived token bound to this zone, ICMP definition, and rich-rule state")


class FirewalldRichICMPRuleActionResponse(BaseModel):
    success: bool
    action: Literal["add", "remove"]
    configuration: Literal["runtime", "permanent"]
    zone: Optional[str] = None
    icmp_type: Optional[str] = None
    source_cidr: Optional[str] = None
    destination_cidr: Optional[str] = None
    verdict: Optional[Literal["accept", "reject", "drop"]] = None
    rich_rule: Optional[str] = None
    rule_present: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class FirewalldRichProtocolRuleActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact firewalld rich protocol rule and configuration scope")
    action: Literal["add", "remove"]
    configuration: Literal["runtime", "permanent"]
    zone: str = Field(description="Repeat the exact firewalld zone name shown in the prompt")
    protocol_value: str = Field(description="Repeat the protocol name or numeric IP protocol value shown in the prompt")
    source_cidr: Optional[str] = Field(default=None, description="Repeat the canonical source CIDR, or null for any source")
    destination_cidr: Optional[str] = Field(default=None, description="Repeat the canonical destination CIDR, or null for any destination")
    verdict: Literal["accept", "reject", "drop"]
    log_enabled: StrictBool = Field(default=False, description="Repeat whether matching attempts are logged at most once per minute")
    log_prefix: Optional[str] = Field(default=None, description="Repeat the optional safe log prefix, up to 127 characters")
    log_level: Optional[Literal["emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"]] = Field(default=None, description="Repeat the optional kernel log level; requires log_enabled=true")
    audit_enabled: StrictBool = Field(default=False, description="Repeat whether matching attempts create audit records at most once per minute")
    priority: Optional[StrictInt] = Field(default=None, description="Repeat the optional rich-rule priority from -32768 through 32767")
    expected_state_token: str = Field(description="Repeat the short-lived token bound to this zone and exact rich-rule state")


class FirewalldRichProtocolRuleActionResponse(BaseModel):
    success: bool
    action: Literal["add", "remove"]
    configuration: Literal["runtime", "permanent"]
    zone: Optional[str] = None
    protocol_value: Optional[str] = None
    protocol_number: Optional[int] = None
    source_cidr: Optional[str] = None
    destination_cidr: Optional[str] = None
    verdict: Optional[Literal["accept", "reject", "drop"]] = None
    rich_rule: Optional[str] = None
    rule_present: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class UFWPortRuleActionConfirmation(BaseModel):
    confirm: bool = Field(description="Confirm this exact UFW port allow/deny/reject/limit rule")
    action: Literal[
        "add_allow", "add_deny", "add_reject", "add_limit",
        "remove_allow", "remove_deny", "remove_reject", "remove_limit",
    ]
    protocol: Literal["tcp", "udp"]
    port: int = Field(description="Repeat the first destination port shown in the prompt")
    port_end: Optional[int] = Field(default=None, description="Repeat the inclusive last destination port for a range, or null for one port")
    additional_ports: Optional[List[StrictInt]] = Field(default=None, description="Repeat remaining destination ports in strictly increasing order for a numeric list of at most 15 total ports, or null for one port or a range")
    direction: Literal["in", "out"] = Field(description="Repeat inbound or outbound direction")
    source_address: str = Field(description="Repeat the exact source IP or CIDR shown in the prompt")
    destination_address: str = Field(description="Repeat the exact destination IP or CIDR shown in the prompt")
    expected_state_token: str = Field(description="Repeat the short-lived token bound to the UFW rule state")


class UFWPortRuleActionResponse(BaseModel):
    success: bool
    action: Literal[
        "add_allow", "add_deny", "add_reject", "add_limit",
        "remove_allow", "remove_deny", "remove_reject", "remove_limit",
    ]
    protocol: Optional[Literal["tcp", "udp"]] = None
    port: Optional[int] = None
    port_end: Optional[int] = None
    additional_ports: Optional[List[StrictInt]] = None
    direction: Optional[Literal["in", "out"]] = None
    source_address: Optional[str] = None
    destination_address: Optional[str] = None
    rule_present: Optional[bool] = None
    state_verified: bool = False
    user_confirmed: bool = False
    message: str


class FirewalldZoneInfo(BaseModel):
    name: str
    is_default: bool = False
    is_active: bool = False
    properties: Dict[str, List[str]] = Field(default_factory=dict)


class FirewallFrontendSourceStatus(BaseModel):
    frontend: Literal["firewalld", "ufw"]
    available: bool
    success: bool
    partial: bool = False
    active: Optional[bool] = None
    default_zone: Optional[str] = None
    active_zones: List[str] = Field(default_factory=list)
    total_zones: int = 0
    returned_zones: int = 0
    zones: List[FirewalldZoneInfo] = Field(default_factory=list)
    logging: Optional[str] = None
    default_policies: Dict[str, str] = Field(default_factory=dict)
    total_rules: int = 0
    returned_rules: int = 0
    rules: List[str] = Field(default_factory=list)
    malformed_records: int = 0
    truncated: bool = False
    message: Optional[str] = None


class FirewallFrontendInventoryResponse(BaseModel):
    success: bool
    partial: bool = False
    sources: List[FirewallFrontendSourceStatus] = Field(default_factory=list)
    limit: int = 100
    truncated: bool = False
    message: Optional[str] = None


class JournalEntryInfo(BaseModel):
    timestamp: Optional[str] = Field(default=None, description="UTC timestamp from the journal entry")
    priority: Optional[int] = Field(default=None, description="Syslog priority number from 0 (emergency) through 7 (debug)")
    unit: Optional[str] = Field(default=None, description="System or user unit associated with the entry, when present")
    identifier: Optional[str] = Field(default=None, description="Syslog identifier or process name, when present")
    message: Optional[str] = Field(default=None, description="Journal message, shortened at 8192 characters")


class JournalEntryListResponse(BaseModel):
    success: bool
    scope: Literal["system", "user"] = Field(default="system", description="System journal or the current user's journal")
    boot_offset: int = Field(default=0, description="Boot offset: 0 is current; negative values select earlier boots")
    scanned_entries: int = Field(default=0, description="Journal records scanned in this bounded snapshot")
    matching_entries: int = Field(default=0, description="Records matching the text query within the scanned snapshot")
    returned_entries: int = Field(default=0, description="Matching records returned after applying the result limit")
    entries: List[JournalEntryInfo] = Field(default_factory=list)
    limit: int = Field(default=50, description="Maximum number of returned journal entries")
    truncated: bool = Field(default=False, description="Whether the snapshot, scan, message, or returned results were capped")
    message: Optional[str] = None


SystemLogSource = Literal["syslog", "messages", "kern", "dmesg", "auth", "secure"]


class SystemLogEntryInfo(BaseModel):
    source: SystemLogSource
    line: str = Field(description="One sanitized log line, shortened at 8192 characters")


class SystemLogListResponse(BaseModel):
    success: bool
    source: SystemLogSource
    scanned_entries: int = Field(default=0, description="Lines scanned from the bounded tail snapshot")
    matching_entries: int = Field(default=0, description="Lines matching the text query within the scanned snapshot")
    returned_entries: int = Field(default=0, description="Matching lines returned after applying the result limit")
    entries: List[SystemLogEntryInfo] = Field(default_factory=list)
    limit: int = Field(default=50, description="Maximum number of returned log lines")
    truncated: bool = Field(default=False, description="Whether the byte window, scan, line, or result count was capped")
    message: Optional[str] = None
