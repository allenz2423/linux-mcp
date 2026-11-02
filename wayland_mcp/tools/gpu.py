"""Read-only DRM GPU inventory with optional AMDGPU and NVIDIA telemetry."""

from __future__ import annotations

import csv
import math
import os
import re
import sys
from pathlib import Path

from wayland_mcp.models import GPUDeviceInfo, GPUFrequencyInfo, GPUInventoryResponse
from wayland_mcp.session import find_session_binary, get_sanitized_env
from wayland_mcp.tools.commands import run_bounded_command

DRM_ROOT = Path("/sys/class/drm")
CARD_RE = re.compile(r"^card[0-9]{1,5}$")
PCI_ADDRESS_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
DRIVER_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,128}$")
NVIDIA_PCI_ADDRESS_RE = re.compile(r"^([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])$")
HWMON_DIRECTORY_RE = re.compile(r"^hwmon([0-9]{1,5})$")
TILE_DIRECTORY_RE = re.compile(r"^tile([0-9]{1,5})$")
GT_DIRECTORY_RE = re.compile(r"^gt([0-9]{1,5})$")
MAX_DRM_ENTRIES = 256
MAX_DRM_SCAN_ENTRIES = 4096
MAX_GPU_RESULTS = 64
MAX_ATTRIBUTE_BYTES = 256
MAX_ATTRIBUTE_INTEGER = 2**63 - 1
MAX_NVIDIA_SMI_OUTPUT_BYTES = 256 * 1024
MAX_SYSFS_DIRECTORY_SCAN_ENTRIES = 1024
MAX_HWMON_DEVICES = 32
MAX_GPU_TILES = 64
MAX_GPU_GROUPS = 128
MAX_GPU_FREQUENCY_MHZ = 100_000
MAX_SYSFS_DIRECTORY_ID = 65_535


def _read_attribute(path: Path) -> tuple[str | None, bool]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_ATTRIBUTE_BYTES + 1)
    except FileNotFoundError:
        return None, False
    except OSError:
        return None, True
    if len(raw) > MAX_ATTRIBUTE_BYTES:
        return None, True
    try:
        return raw.decode("ascii").strip(), False
    except UnicodeDecodeError:
        return None, True


def _read_hex(path: Path, digits: int) -> tuple[str | None, bool]:
    raw, partial = _read_attribute(path)
    if raw is None:
        return None, partial
    try:
        value = int(raw, 0)
    except ValueError:
        return None, True
    if not 0 <= value < 1 << (digits * 4):
        return None, True
    return f"{value:0{digits}x}", partial


def _read_integer(path: Path, maximum: int = MAX_ATTRIBUTE_INTEGER) -> tuple[int | None, bool]:
    raw, partial = _read_attribute(path)
    if raw is None:
        return None, partial
    try:
        value = int(raw, 10)
    except ValueError:
        return None, True
    if not 0 <= value <= maximum:
        return None, True
    return value, partial


def _numbered_directories(
    root: Path,
    pattern: re.Pattern[str],
    limit: int,
) -> tuple[list[tuple[int, Path]], bool]:
    directories: list[tuple[int, Path]] = []
    partial = False
    try:
        with os.scandir(root) as entries:
            for scanned, entry in enumerate(entries):
                if scanned >= MAX_SYSFS_DIRECTORY_SCAN_ENTRIES:
                    partial = True
                    break
                match = pattern.fullmatch(entry.name)
                if match is None:
                    continue
                directory_id = int(match.group(1))
                if directory_id > MAX_SYSFS_DIRECTORY_ID:
                    partial = True
                    continue
                try:
                    if entry.is_dir(follow_symlinks=True):
                        directories.append((directory_id, root / entry.name))
                except OSError:
                    partial = True
    except FileNotFoundError:
        return [], False
    except OSError:
        return [], True
    directories.sort(key=lambda item: item[0])
    if len({directory_id for directory_id, _ in directories}) != len(directories):
        partial = True
    if len(directories) > limit:
        partial = True
        directories = directories[:limit]
    return directories, partial


def _driver_hwmon_metrics(
    device: Path,
    driver: str,
) -> tuple[int | None, int | None, int | None, bool]:
    """Read only documented, read-only temperature/energy inputs for selected drivers."""
    specifications = {
        "i915": ("i915", "temp1_input", "energy1_input", None),
        "xe": ("xe", "temp2_input", "energy1_input", "energy2_input"),
        "nouveau": ("nouveau", "temp1_input", None, None),
    }
    specification = specifications.get(driver)
    if specification is None:
        return None, None, None, False
    expected_name, temperature_attribute, energy_attribute, package_energy_attribute = specification
    hwmon_devices, partial = _numbered_directories(
        device / "hwmon",
        HWMON_DIRECTORY_RE,
        MAX_HWMON_DEVICES,
    )
    matches: list[Path] = []
    for _, hwmon in hwmon_devices:
        name, field_partial = _read_attribute(hwmon / "name")
        partial |= field_partial
        if name == expected_name:
            matches.append(hwmon)
    if len(matches) > 1:
        partial = True
    if not matches:
        return None, None, None, partial

    hwmon = matches[0]
    temperature_millidegrees, field_partial = _read_integer(
        hwmon / temperature_attribute,
        maximum=255_000,
    )
    partial |= field_partial
    temperature_celsius = (
        temperature_millidegrees // 1000
        if temperature_millidegrees is not None
        else None
    )
    energy_input, field_partial = (
        _read_integer(hwmon / energy_attribute)
        if energy_attribute
        else (None, False)
    )
    partial |= field_partial
    package_energy_input, field_partial = (
        _read_integer(hwmon / package_energy_attribute)
        if package_energy_attribute
        else (None, False)
    )
    partial |= field_partial
    return temperature_celsius, energy_input, package_energy_input, partial


def _xe_gt_frequencies(device: Path) -> tuple[list[GPUFrequencyInfo], bool]:
    frequencies: list[GPUFrequencyInfo] = []
    tiles, partial = _numbered_directories(device, TILE_DIRECTORY_RE, MAX_GPU_TILES)
    for tile_id, tile in tiles:
        groups, groups_partial = _numbered_directories(tile, GT_DIRECTORY_RE, MAX_GPU_GROUPS)
        partial |= groups_partial
        for gt_id, group in groups:
            if len(frequencies) >= MAX_GPU_GROUPS:
                partial = True
                break
            actual_frequency, field_partial = _read_integer(
                group / "freq0" / "act_freq",
                maximum=MAX_GPU_FREQUENCY_MHZ,
            )
            partial |= field_partial
            if actual_frequency is not None:
                frequencies.append(GPUFrequencyInfo(
                    tile_id=tile_id,
                    gt_id=gt_id,
                    actual_frequency_mhz=actual_frequency,
                ))
    frequencies.sort(key=lambda item: (item.tile_id, item.gt_id))
    return frequencies, partial


def _driver_name(device_path: Path) -> tuple[str | None, bool]:
    try:
        name = (device_path / "driver").resolve(strict=True).name
    except FileNotFoundError:
        return None, False
    except (OSError, RuntimeError):
        return None, True
    if not DRIVER_RE.fullmatch(name):
        return None, True
    return name, False


def _pci_address(device_path: Path) -> tuple[str | None, bool]:
    try:
        name = device_path.resolve(strict=True).name
    except FileNotFoundError:
        return None, False
    except (OSError, RuntimeError):
        return None, True
    if PCI_ADDRESS_RE.fullmatch(name):
        return name.lower(), False
    return None, False


def _gpu_info(card: Path) -> tuple[GPUDeviceInfo, bool]:
    device = card / "device"
    partial = False
    pci_address, field_partial = _pci_address(device)
    partial |= field_partial
    driver, field_partial = _driver_name(device)
    partial |= field_partial

    vendor_id, field_partial = _read_hex(device / "vendor", 4)
    partial |= field_partial
    device_id, field_partial = _read_hex(device / "device", 4)
    partial |= field_partial
    subsystem_vendor_id, field_partial = _read_hex(device / "subsystem_vendor", 4)
    partial |= field_partial
    subsystem_device_id, field_partial = _read_hex(device / "subsystem_device", 4)
    partial |= field_partial
    class_code, field_partial = _read_hex(device / "class", 6)
    partial |= field_partial
    boot_vga_raw, field_partial = _read_integer(device / "boot_vga", maximum=1)
    partial |= field_partial

    amdgpu_busy_percent = None
    amdgpu_vram_total_bytes = None
    amdgpu_vram_used_bytes = None
    energy_input_microjoules = None
    package_energy_input_microjoules = None
    xe_gt_frequencies: list[GPUFrequencyInfo] = []
    utilization_percent = None
    memory_total_bytes = None
    memory_used_bytes = None
    temperature_celsius = None
    telemetry_source = None
    if driver == "amdgpu":
        amdgpu_busy_percent, field_partial = _read_integer(device / "gpu_busy_percent", maximum=100)
        partial |= field_partial
        amdgpu_vram_total_bytes, field_partial = _read_integer(device / "mem_info_vram_total")
        partial |= field_partial
        amdgpu_vram_used_bytes, field_partial = _read_integer(device / "mem_info_vram_used")
        partial |= field_partial
        utilization_percent = amdgpu_busy_percent
        memory_total_bytes = amdgpu_vram_total_bytes
        memory_used_bytes = amdgpu_vram_used_bytes
        if any(value is not None for value in (utilization_percent, memory_total_bytes, memory_used_bytes)):
            telemetry_source = "amdgpu_sysfs"
    elif driver in {"i915", "xe", "nouveau"}:
        (
            temperature_celsius,
            energy_input_microjoules,
            package_energy_input_microjoules,
            field_partial,
        ) = _driver_hwmon_metrics(device, driver)
        partial |= field_partial
        if driver == "xe":
            xe_gt_frequencies, field_partial = _xe_gt_frequencies(device)
            partial |= field_partial
        if (
            temperature_celsius is not None
            or energy_input_microjoules is not None
            or package_energy_input_microjoules is not None
            or xe_gt_frequencies
        ):
            telemetry_source = {
                "i915": "i915_hwmon",
                "xe": "xe_sysfs",
                "nouveau": "nouveau_hwmon",
            }[driver]

    return GPUDeviceInfo(
        drm_card=card.name,
        pci_address=pci_address,
        vendor_id=vendor_id,
        device_id=device_id,
        subsystem_vendor_id=subsystem_vendor_id,
        subsystem_device_id=subsystem_device_id,
        class_code=class_code,
        driver=driver,
        boot_vga=bool(boot_vga_raw) if boot_vga_raw is not None else None,
        amdgpu_busy_percent=amdgpu_busy_percent,
        amdgpu_vram_total_bytes=amdgpu_vram_total_bytes,
        amdgpu_vram_used_bytes=amdgpu_vram_used_bytes,
        telemetry_source=telemetry_source,
        utilization_percent=utilization_percent,
        memory_total_bytes=memory_total_bytes,
        memory_used_bytes=memory_used_bytes,
        temperature_celsius=temperature_celsius,
        energy_input_microjoules=energy_input_microjoules,
        package_energy_input_microjoules=package_energy_input_microjoules,
        xe_gt_frequencies=xe_gt_frequencies,
    ), partial


def _normalize_nvidia_pci_address(value: str) -> str | None:
    match = NVIDIA_PCI_ADDRESS_RE.fullmatch(value.strip())
    if not match:
        return None
    domain, bus, device, function = match.groups()
    domain_number = int(domain, 16)
    if domain_number > 0xFFFF:
        return None
    return f"{domain_number:04x}:{bus.lower()}:{device.lower()}.{function}"


def _nvidia_number(value: str, *, integer: bool, maximum: float) -> tuple[int | float | None, bool]:
    value = value.strip()
    if value.casefold() in {"", "n/a", "na", "-"}:
        return None, False
    try:
        number = float(value)
    except ValueError:
        return None, True
    if not math.isfinite(number) or not 0 <= number <= maximum:
        return None, True
    if integer:
        if not number.is_integer():
            return None, True
        return int(number), False
    return number, False


def _parse_nvidia_smi_csv(output: str) -> tuple[dict[str, dict[str, int | float | None]], bool]:
    metrics: dict[str, dict[str, int | float | None]] = {}
    partial = False
    for row in csv.reader(output.splitlines(), skipinitialspace=True):
        if not row or not any(field.strip() for field in row):
            continue
        if len(row) != 6:
            partial = True
            continue
        address = _normalize_nvidia_pci_address(row[0])
        if address is None or address in metrics:
            partial = True
            continue
        utilization, invalid_utilization = _nvidia_number(row[1], integer=True, maximum=100)
        memory_total_mib, invalid_memory_total = _nvidia_number(
            row[2], integer=True, maximum=MAX_ATTRIBUTE_INTEGER // (1024 * 1024)
        )
        memory_used_mib, invalid_memory_used = _nvidia_number(
            row[3], integer=True, maximum=MAX_ATTRIBUTE_INTEGER // (1024 * 1024)
        )
        temperature, invalid_temperature = _nvidia_number(row[4], integer=True, maximum=255)
        power_draw, invalid_power = _nvidia_number(row[5], integer=False, maximum=100_000)
        partial |= any((invalid_utilization, invalid_memory_total, invalid_memory_used, invalid_temperature, invalid_power))
        metrics[address] = {
            "utilization_percent": utilization,
            "memory_total_bytes": int(memory_total_mib) * 1024 * 1024 if memory_total_mib is not None else None,
            "memory_used_bytes": int(memory_used_mib) * 1024 * 1024 if memory_used_mib is not None else None,
            "temperature_celsius": temperature,
            "power_draw_watts": power_draw,
        }
    if not metrics and output.strip():
        partial = True
    return metrics, partial


def _nvidia_smi_metrics(
    gpus: list[GPUDeviceInfo],
) -> tuple[dict[str, dict[str, int | float | None]], bool]:
    if not any(gpu.driver == "nvidia" for gpu in gpus):
        return {}, False
    env = get_sanitized_env()
    nvidia_smi = find_session_binary("nvidia-smi", env)
    if not nvidia_smi:
        return {}, False
    output, _error, output_truncated = run_bounded_command(
        [
            nvidia_smi,
            "--query-gpu=pci.bus_id,utilization.gpu,memory.total,memory.used,temperature.gpu,power.draw",
            "--format=csv,noheader,nounits",
        ],
        env,
        command_label="NVIDIA GPU telemetry",
        timeout_seconds=4.0,
        max_output_bytes=MAX_NVIDIA_SMI_OUTPUT_BYTES,
    )
    if output is None or output_truncated:
        return {}, True
    return _parse_nvidia_smi_csv(output)


def list_gpu_devices(limit: int = 32) -> GPUInventoryResponse:
    """List visible DRM cards and available read-only per-driver telemetry."""
    if not sys.platform.startswith("linux"):
        return GPUInventoryResponse(success=False, message="GPU inventory is available only on Linux.")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return GPUInventoryResponse(success=False, limit=32, message="limit must be a positive integer.")
    limit = min(limit, MAX_GPU_RESULTS)
    cards: list[Path] = []
    total_gpus = 0
    scan_truncated = False
    try:
        with os.scandir(DRM_ROOT) as entries:
            for scanned, entry in enumerate(entries):
                if scanned >= MAX_DRM_SCAN_ENTRIES:
                    scan_truncated = True
                    break
                if CARD_RE.fullmatch(entry.name):
                    total_gpus += 1
                    if len(cards) < MAX_DRM_ENTRIES:
                        cards.append(DRM_ROOT / entry.name)
                    else:
                        scan_truncated = True
    except OSError:
        return GPUInventoryResponse(
            success=False,
            limit=limit,
            message="The Linux DRM sysfs inventory is unavailable or unreadable.",
        )

    cards.sort(key=lambda entry: int(entry.name[4:]))
    truncated = scan_truncated or total_gpus > len(cards)
    visible = cards[:limit]
    truncated |= total_gpus > len(visible)
    gpus: list[GPUDeviceInfo] = []
    partial = False
    for card in visible:
        gpu, field_partial = _gpu_info(card)
        gpus.append(gpu)
        partial |= field_partial
    nvidia_metrics, nvidia_partial = _nvidia_smi_metrics(gpus)
    partial |= nvidia_partial
    if nvidia_metrics:
        gpus = [
            gpu.model_copy(update={**nvidia_metrics[gpu.pci_address], "telemetry_source": "nvidia_smi"})
            if gpu.pci_address in nvidia_metrics and gpu.vendor_id == "10de"
            else gpu
            for gpu in gpus
        ]
    return GPUInventoryResponse(
        success=True,
        total_gpus=total_gpus,
        returned_gpus=len(gpus),
        gpus=gpus,
        limit=limit,
        truncated=truncated,
        partial=partial,
        message=(
            "Some sysfs fields or optional GPU telemetry were unavailable or malformed."
            if partial else None
        ),
    )
