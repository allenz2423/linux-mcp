from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace

from wayland_mcp.tools import native_package_environments


def test_npm_transaction_uses_distinct_private_empty_config_files(monkeypatch, tmp_path):
    observed: dict[str, Path] = {}

    def fake_run(command, env, **kwargs):
        user_config = Path(env["NPM_CONFIG_USERCONFIG"])
        global_config = Path(env["NPM_CONFIG_GLOBALCONFIG"])
        assert user_config != global_config
        assert user_config.is_file() and global_config.is_file()
        assert user_config.read_bytes() == b""
        assert global_config.read_bytes() == b""
        assert stat.S_IMODE(user_config.stat().st_mode) & 0o077 == 0
        assert stat.S_IMODE(global_config.stat().st_mode) & 0o077 == 0
        assert env["NPM_CONFIG_CACHE"] == str(tmp_path / "prefix" / ".npm-cache")
        observed.update(user_config=user_config, global_config=global_config)
        return "ok", None, False

    monkeypatch.setattr(native_package_environments, "run_bounded_command", fake_run)
    snapshot = SimpleNamespace(
        ecosystem="npm",
        home=tmp_path,
        environment_path=tmp_path / "prefix",
        manager_binary="/usr/bin/npm",
        action="install",
        package_name="is-number",
        version="7.0.0",
    )

    result = native_package_environments._run_snapshot_command(
        snapshot,
        ["/usr/bin/npm", "install", "is-number@7.0.0"],
        timeout=30,
        label="test npm install",
    )

    assert result == ("ok", None, False)
    assert not observed["user_config"].exists()
    assert not observed["global_config"].exists()
