from __future__ import annotations

from collections import deque

import pytest

from wayland_mcp.tools import power_profiles


PROFILE_LIST = """\
  performance:
    CpuDriver: amd_pstate
    Degraded: no
  * balanced:
    CpuDriver: amd_pstate
  power-saver:
    CpuDriver: amd_pstate
"""


def _configure_fake_cli(monkeypatch: pytest.MonkeyPatch, outputs: list[str]) -> list[list[str]]:
    monkeypatch.setattr(power_profiles.sys, "platform", "linux")
    monkeypatch.setattr(power_profiles, "get_sanitized_env", lambda _env=None: {"PATH": "/usr/bin"})
    monkeypatch.setattr(
        power_profiles,
        "find_session_binary",
        lambda name, _env=None: f"/usr/bin/{name}",
    )
    pending = deque(outputs)
    calls: list[list[str]] = []

    def fake_run(argv: list[str], _env: dict[str, str], **_kwargs: object) -> tuple[str, str | None, bool]:
        calls.append(argv)
        if not pending:
            raise AssertionError(f"unexpected command: {argv!r}")
        return pending.popleft(), None, False

    monkeypatch.setattr(power_profiles, "run_bounded_command", fake_run)
    return calls


def test_inventory_parses_available_and_active_profiles(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_fake_cli(monkeypatch, [PROFILE_LIST, "balanced\n"])

    response = power_profiles.get_power_profile()

    assert response.success is True
    assert response.active_profile == "balanced"
    assert response.available_profiles == ["balanced", "performance", "power-saver"]


def test_inventory_fails_closed_on_unknown_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_fake_cli(monkeypatch, ["* turbo:\n  Driver: custom\n  balanced:\n", "balanced\n"])

    response = power_profiles.get_power_profile()

    assert response.success is False
    assert "unsupported" in response.message


def test_confirmed_profile_change_rechecks_and_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _configure_fake_cli(
        monkeypatch,
        [
            PROFILE_LIST,
            "balanced\n",
            PROFILE_LIST,
            "balanced\n",
            PROFILE_LIST,
            "balanced\n",
            "",
            PROFILE_LIST.replace("* balanced:", "balanced:").replace("  performance:", "  * performance:"),
            "performance\n",
        ],
    )

    target, error = power_profiles.power_profile_confirmation_details("performance")
    assert error is None
    assert target is not None

    response = power_profiles.perform_power_profile_change(
        "performance",
        confirmed=True,
        confirmed_phrase=target.confirmation_phrase,
    )

    assert response.success is True
    assert response.active_profile == "performance"
    assert calls[6] == ["/usr/bin/powerprofilesctl", "set", "performance"]


def test_power_profile_tools_are_hidden_by_power_or_hardware_category() -> None:
    from wayland_mcp.server import create_server
    from wayland_mcp.tool_config import ToolSelection

    async def names_for(selection: ToolSelection) -> set[str]:
        return {tool.name for tool in await create_server(selection).list_tools()}

    import asyncio

    assert {"get_power_profile", "manage_power_profile"} <= asyncio.run(names_for(ToolSelection()))
    for category in ("power", "hardware"):
        names = asyncio.run(names_for(ToolSelection(disabled_categories=frozenset({category}))))
        assert "get_power_profile" not in names
        assert "manage_power_profile" not in names
