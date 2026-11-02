from __future__ import annotations

import pytest

from wayland_mcp.tools import timer_control


def _snapshot(active_state: str, unit_file_state: str) -> timer_control.SystemdTimerSnapshot:
    return timer_control.SystemdTimerSnapshot(
        unit="sample.timer",
        scope="system",
        load_state="loaded",
        active_state=active_state,
        unit_file_state=unit_file_state,
        trigger_units=("sample.service",),
        configured_unit="sample.service",
        persistent=None,
        on_calendar=None,
        state_token="a" * 64,
    )


@pytest.mark.parametrize(
    ("action", "before", "after", "message_part"),
    [
        ("start", _snapshot("active", "enabled"), _snapshot("active", "enabled"), "already active"),
        ("stop", _snapshot("inactive", "enabled"), _snapshot("inactive", "enabled"), "already inactive"),
        ("enable", _snapshot("inactive", "enabled"), _snapshot("inactive", "enabled"), "already enabled"),
        ("disable", _snapshot("active", "disabled"), _snapshot("active", "disabled"), "already disabled"),
        ("start", _snapshot("inactive", "enabled"), _snapshot("active", "enabled"), "activation was changed"),
        ("stop", _snapshot("active", "enabled"), _snapshot("inactive", "enabled"), "deactivation was changed"),
        ("enable", _snapshot("inactive", "disabled"), _snapshot("inactive", "enabled"), "enablement was changed"),
        ("disable", _snapshot("active", "enabled"), _snapshot("active", "disabled"), "enablement was removed"),
    ],
)
def test_timer_action_message_distinguishes_noop_from_state_change(monkeypatch, action, before, after, message_part):
    monkeypatch.setattr(timer_control, "timer_action_confirmation_details", lambda *_args: (before, None))
    monkeypatch.setattr(timer_control, "_read_timer_snapshot", lambda *_args: (after, None))
    monkeypatch.setattr(timer_control, "get_sanitized_env", lambda: {})
    monkeypatch.setattr(timer_control, "find_session_binary", lambda *_args: "/usr/bin/systemctl")
    monkeypatch.setattr(timer_control, "run_bounded_command", lambda *_args, **_kwargs: ("", None, False))

    response = timer_control.perform_systemd_timer_action(
        action,
        "sample.timer",
        "system",
        before.state_token,
        confirmed=True,
    )

    assert response.success
    assert response.state_verified
    assert message_part in response.message
