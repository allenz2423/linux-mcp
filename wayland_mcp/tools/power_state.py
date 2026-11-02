"""Read-only kernel sleep-state and power-mode inventory."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from wayland_mcp.models import PowerStateResponse

POWER_ROOT = Path("/sys/power")
MAX_POWER_ATTRIBUTE_BYTES = 4096
MODE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _read_attribute(name: str) -> tuple[str | None, bool]:
    try:
        with (POWER_ROOT / name).open("rb") as stream:
            raw = stream.read(MAX_POWER_ATTRIBUTE_BYTES + 1)
    except FileNotFoundError:
        return None, False
    except OSError:
        return None, True
    if len(raw) > MAX_POWER_ATTRIBUTE_BYTES:
        return None, True
    try:
        return raw.decode("ascii").strip(), False
    except UnicodeDecodeError:
        return None, True


def _parse_modes(value: str | None) -> tuple[list[str], str | None, bool]:
    if value is None:
        return [], None, False
    modes: list[str] = []
    selected_modes: list[str] = []
    partial = False
    for token in value.split():
        is_selected = token.startswith("[") and token.endswith("]")
        mode = token[1:-1] if is_selected else token
        if not MODE_RE.fullmatch(mode):
            partial = True
            continue
        if mode not in modes:
            modes.append(mode)
        if is_selected:
            selected_modes.append(mode)
    if len(selected_modes) > 1:
        partial = True
    selected = selected_modes[0] if len(selected_modes) == 1 else None
    if selected is not None and selected not in modes:
        partial = True
        selected = None
    return modes, selected, partial


def get_power_state() -> PowerStateResponse:
    """Report kernel-exposed sleep choices without requesting a transition."""
    if not sys.platform.startswith("linux"):
        return PowerStateResponse(success=False, message="Power-state inventory is available only on Linux.")
    state_text, state_partial = _read_attribute("state")
    if state_text is None:
        return PowerStateResponse(
            success=False,
            message="The Linux kernel sleep-state interface is unavailable or unreadable.",
        )
    states, selected_state, malformed_states = _parse_modes(state_text)
    partial = state_partial or malformed_states or selected_state is not None

    memory_text, memory_partial = _read_attribute("mem_sleep")
    memory_modes, selected_memory_mode, malformed_memory_modes = _parse_modes(memory_text)
    partial |= memory_partial or malformed_memory_modes

    disk_text, disk_partial = _read_attribute("disk")
    hibernation_modes, selected_hibernation_mode, malformed_hibernation_modes = _parse_modes(disk_text)
    partial |= disk_partial or malformed_hibernation_modes

    return PowerStateResponse(
        success=True,
        supported_sleep_states=states,
        suspend_to_idle_supported="freeze" in states,
        suspend_to_ram_supported="mem" in states,
        hibernation_supported="disk" in states,
        memory_sleep_modes=memory_modes,
        selected_memory_sleep_mode=selected_memory_mode,
        hibernation_modes=hibernation_modes,
        selected_hibernation_mode=selected_hibernation_mode,
        partial=partial,
        message=(
            "Some optional power-mode data was unavailable, malformed, or truncated; listed kernel choices do not guarantee an actual sleep transition."
            if partial else "Kernel-exported sleep choices only; use list_power_inhibitors for current logind locks. Firmware readiness and transition success are not inferred."
        ),
    )
