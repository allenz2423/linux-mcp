"""Bounded read-only snapshot of selected Linux kernel security interfaces."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from wayland_mcp.models import KernelSecurityPostureResponse, KernelSecuritySetting

MAX_VALUE_BYTES = 128
MAX_LSM_BYTES = 4096
MAX_LSMS = 64
LSM_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
INTEGER_RE = re.compile(r"^[+-]?\d{1,16}$")

LSM_PATH = Path("/sys/kernel/security/lsm")
LOCKDOWN_PATH = Path("/sys/kernel/security/lockdown")
SELINUX_ENFORCE_PATH = Path("/sys/fs/selinux/enforce")
SELINUX_POLICY_VERSION_PATH = Path("/sys/fs/selinux/policyvers")
SELINUX_MLS_PATH = Path("/sys/fs/selinux/mls")
SELINUX_DENY_UNKNOWN_PATH = Path("/sys/fs/selinux/deny_unknown")
SELINUX_REJECT_UNKNOWN_PATH = Path("/sys/fs/selinux/reject_unknown")
SELINUX_POLICY_CAPABILITIES_ROOT = Path("/sys/fs/selinux/policy_capabilities")
MAX_POLICY_CAPABILITY_ENTRIES = 256
MAX_POLICY_CAPABILITIES = 128
POLICY_CAPABILITY_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
EFI_GLOBAL_VARIABLE_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
EFI_VARIABLES_PATH = Path("/sys/firmware/efi/efivars")
SECURE_BOOT_PATH = EFI_VARIABLES_PATH / f"SecureBoot-{EFI_GLOBAL_VARIABLE_GUID}"
SETUP_MODE_PATH = EFI_VARIABLES_PATH / f"SetupMode-{EFI_GLOBAL_VARIABLE_GUID}"
EFI_BOOLEAN_VARIABLE_SIZE = 5  # 4-byte attributes followed by one data byte.

KERNEL_SECURITY_SETTINGS = (
    ("dmesg_restrict", Path("/proc/sys/kernel/dmesg_restrict")),
    ("kptr_restrict", Path("/proc/sys/kernel/kptr_restrict")),
    ("perf_event_paranoid", Path("/proc/sys/kernel/perf_event_paranoid")),
    ("randomize_va_space", Path("/proc/sys/kernel/randomize_va_space")),
    ("modules_disabled", Path("/proc/sys/kernel/modules_disabled")),
    ("kexec_load_disabled", Path("/proc/sys/kernel/kexec_load_disabled")),
    ("unprivileged_bpf_disabled", Path("/proc/sys/kernel/unprivileged_bpf_disabled")),
    ("io_uring_disabled", Path("/proc/sys/kernel/io_uring_disabled")),
    ("yama_ptrace_scope", Path("/proc/sys/kernel/yama/ptrace_scope")),
    ("mmap_min_addr", Path("/proc/sys/vm/mmap_min_addr")),
)


def _read_bounded(path: Path, limit: int) -> tuple[str | None, bool]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError:
        return None, False
    if len(raw) > limit:
        return None, True
    return raw.decode("ascii", errors="replace").strip(), False


def _read_integer(path: Path) -> int | None:
    value, truncated = _read_bounded(path, MAX_VALUE_BYTES)
    if value is None or truncated or not INTEGER_RE.fullmatch(value):
        return None
    try:
        return int(value, 10)
    except ValueError:
        return None


def _read_efi_boolean(path: Path) -> tuple[bool | None, bool]:
    """Read one standard efivar boolean without exceeding its fixed 5-byte format."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(EFI_BOOLEAN_VARIABLE_SIZE + 1)
    except OSError:
        return None, False
    if len(raw) > EFI_BOOLEAN_VARIABLE_SIZE:
        return None, True
    if len(raw) != EFI_BOOLEAN_VARIABLE_SIZE or raw[4] not in (0, 1):
        return None, False
    return raw[4] == 1, False


def kernel_security_posture_available() -> bool:
    """Return whether any selected Linux kernel security interface is visible."""
    if not sys.platform.startswith("linux"):
        return False
    paths = (
        LSM_PATH,
        LOCKDOWN_PATH,
        SELINUX_ENFORCE_PATH,
        SELINUX_POLICY_VERSION_PATH,
        SELINUX_MLS_PATH,
        SELINUX_DENY_UNKNOWN_PATH,
        SELINUX_REJECT_UNKNOWN_PATH,
        SECURE_BOOT_PATH,
        SETUP_MODE_PATH,
        *(path for _, path in KERNEL_SECURITY_SETTINGS),
    )
    return any(path.is_file() for path in paths) or SELINUX_POLICY_CAPABILITIES_ROOT.is_dir()


def _read_selinux_boolean(path: Path) -> bool | None:
    value = _read_integer(path)
    if value not in (0, 1):
        return None
    return bool(value)


def _read_selinux_policy_capabilities() -> tuple[list[str] | None, bool]:
    names: list[str] = []
    truncated = False
    try:
        with os.scandir(SELINUX_POLICY_CAPABILITIES_ROOT) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_POLICY_CAPABILITY_ENTRIES:
                    truncated = True
                    break
                if POLICY_CAPABILITY_NAME_RE.fullmatch(entry.name):
                    if len(names) >= MAX_POLICY_CAPABILITIES:
                        truncated = True
                        break
                    names.append(entry.name)
    except OSError:
        return None, False
    names.sort()
    return names, truncated


def get_kernel_security_posture() -> KernelSecurityPostureResponse:
    """Read a fixed allowlist of kernel and EFI security status attributes."""
    if not sys.platform.startswith("linux"):
        return KernelSecurityPostureResponse(
            success=False,
            message="Kernel security posture inventory is available only on Linux.",
        )

    active_modules: list[str] = []
    lockdown_mode: str | None = None
    settings: list[KernelSecuritySetting] = []
    unavailable: list[str] = []
    truncated = False

    raw_lsms, lsm_truncated = _read_bounded(LSM_PATH, MAX_LSM_BYTES)
    truncated = truncated or lsm_truncated
    if raw_lsms is None:
        unavailable.append("active_security_modules")
    else:
        for item in raw_lsms.split(",")[:MAX_LSMS]:
            name = item.strip()
            if name and LSM_NAME_RE.fullmatch(name):
                active_modules.append(name)
        if len(raw_lsms.split(",")) > MAX_LSMS:
            truncated = True

    raw_lockdown, lockdown_truncated = _read_bounded(LOCKDOWN_PATH, MAX_VALUE_BYTES)
    truncated = truncated or lockdown_truncated
    active_lockdown = re.findall(r"\[([a-z]+)\]", raw_lockdown or "")
    if not lockdown_truncated and len(active_lockdown) == 1 and active_lockdown[0] in {
        "none", "integrity", "confidentiality",
    }:
        lockdown_mode = active_lockdown[0]
    else:
        unavailable.append("lockdown_mode")

    selinux_enforcing: bool | None = None
    enforce_value = _read_integer(SELINUX_ENFORCE_PATH)
    if enforce_value in (0, 1):
        selinux_enforcing = bool(enforce_value)
    else:
        unavailable.append("selinux_enforce")

    max_policy_version = _read_integer(SELINUX_POLICY_VERSION_PATH)
    if max_policy_version is None or max_policy_version < 0:
        unavailable.append("selinux_max_policy_version")
        max_policy_version = None

    selinux_mls_enabled = _read_selinux_boolean(SELINUX_MLS_PATH)
    if selinux_mls_enabled is None:
        unavailable.append("selinux_mls_enabled")

    selinux_deny_unknown = _read_selinux_boolean(SELINUX_DENY_UNKNOWN_PATH)
    if selinux_deny_unknown is None:
        unavailable.append("selinux_deny_unknown")

    selinux_reject_unknown = _read_selinux_boolean(SELINUX_REJECT_UNKNOWN_PATH)
    if selinux_reject_unknown is None:
        unavailable.append("selinux_reject_unknown")

    selinux_policy_capabilities, capabilities_truncated = _read_selinux_policy_capabilities()
    truncated = truncated or capabilities_truncated
    selinux_policy_capabilities_read = selinux_policy_capabilities is not None
    if selinux_policy_capabilities is None:
        unavailable.append("selinux_policy_capabilities")
        selinux_policy_capabilities = []

    secure_boot_enabled, secure_boot_truncated = _read_efi_boolean(SECURE_BOOT_PATH)
    truncated = truncated or secure_boot_truncated
    if secure_boot_enabled is None:
        unavailable.append("secure_boot_enabled")

    secure_boot_setup_mode, setup_mode_truncated = _read_efi_boolean(SETUP_MODE_PATH)
    truncated = truncated or setup_mode_truncated
    if secure_boot_setup_mode is None:
        unavailable.append("secure_boot_setup_mode")

    for name, path in KERNEL_SECURITY_SETTINGS:
        value, value_truncated = _read_bounded(path, MAX_VALUE_BYTES)
        if value is None or value_truncated or not INTEGER_RE.fullmatch(value):
            unavailable.append(name)
            truncated = truncated or value_truncated
            continue
        settings.append(KernelSecuritySetting(name=name, value=value, source=str(path)))

    has_data = bool(
        active_modules or lockdown_mode is not None or selinux_enforcing is not None
        or max_policy_version is not None or selinux_mls_enabled is not None
        or selinux_deny_unknown is not None or selinux_reject_unknown is not None
        or selinux_policy_capabilities_read or secure_boot_enabled is not None
        or secure_boot_setup_mode is not None or settings
    )
    return KernelSecurityPostureResponse(
        success=has_data,
        active_security_modules=active_modules,
        lockdown_mode=lockdown_mode,
        selinux_enforcing=selinux_enforcing,
        selinux_policy_version=max_policy_version,
        selinux_max_policy_version=max_policy_version,
        selinux_mls_enabled=selinux_mls_enabled,
        selinux_deny_unknown=selinux_deny_unknown,
        selinux_reject_unknown=selinux_reject_unknown,
        selinux_policy_capabilities=selinux_policy_capabilities,
        secure_boot_enabled=secure_boot_enabled,
        secure_boot_setup_mode=secure_boot_setup_mode,
        settings=settings,
        unavailable_sources=unavailable,
        truncated=truncated,
        message=(
            "Raw snapshots of selected kernel and EFI interfaces; this tool does not verify the full boot chain, score compliance, or infer exploitability."
            if has_data else "No selected kernel or EFI security interfaces could be read."
        ),
    )
