from __future__ import annotations

from wayland_mcp.tools import remote_virtual_machines


def test_remote_table_query_can_preserve_virsh_headers(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(command, _env, **_kwargs):
        observed["command"] = command
        return "table output\n", None, False

    monkeypatch.setattr(
        remote_virtual_machines,
        "find_session_binary",
        lambda binary, _env: f"/usr/bin/{binary}",
    )
    monkeypatch.setattr(remote_virtual_machines, "run_bounded_command", fake_run)

    output, error, truncated = remote_virtual_machines._run_remote_virsh(
        "qemu+ssh://test.example/system",
        ["net-list", "--all", "--table"],
        readonly=True,
        quiet=False,
        timeout_seconds=10,
        max_output_bytes=4096,
        command_label="test remote table query",
    )

    command = observed["command"]
    assert output == "table output\n"
    assert error is None and truncated is False
    assert "--quiet" not in command
    assert "--readonly" in command
    assert command[-3:] == ["net-list", "--all", "--table"]
