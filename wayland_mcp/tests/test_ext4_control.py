from __future__ import annotations

import pytest

from wayland_mcp.tools import ext4_control


def test_filesystem_state_passes_pinned_descriptor_to_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    descriptor = 19
    path = f"/proc/self/fd/{descriptor}"
    calls: list[tuple[list[str], tuple[int, ...]]] = []

    monkeypatch.setattr(
        ext4_control,
        "find_session_binary",
        lambda name, _env=None: f"/usr/sbin/{name}",
    )

    def fake_run(command: list[str], *, pass_fds: tuple[int, ...] = (), **_kwargs: object) -> tuple[int, str]:
        calls.append((command, pass_fds))
        if command[0].endswith("/blkid") and command[3] == "TYPE":
            return 0, "ext4\n"
        if command[0].endswith("/blkid") and command[3] == "UUID":
            return 0, "12345678-1234-5678-9abc-def012345678\n"
        if command[0].endswith("/dumpe2fs"):
            return 0, "Block count: 16384\nBlock size: 4096\n"
        raise AssertionError(f"unexpected command: {command!r}")

    monkeypatch.setattr(ext4_control, "_run", fake_run)

    assert ext4_control._filesystem_state(path, pass_fds=(descriptor,)) == (
        16384,
        4096,
        "12345678-1234-5678-9abc-def012345678",
    )
    assert len(calls) == 3
    assert all(call_fds == (descriptor,) for _command, call_fds in calls)
    assert all(command[-1] == path for command, _call_fds in calls)
