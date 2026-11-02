from __future__ import annotations

import os
import stat
import subprocess
from types import SimpleNamespace

from wayland_mcp.tools import luks_control


def test_mutation_runner_forwards_private_umask(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(luks_control, "_environment", lambda: {})
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert luks_control._run_mutation(["cryptsetup", "luksHeaderBackup"], None, device_fd=17, umask=0o077)

    assert observed["umask"] == 0o077
    assert observed["pass_fds"] == (17,)


def test_header_backup_uses_new_private_path_for_cryptsetup(monkeypatch, tmp_path) -> None:
    backup_file = tmp_path / "header.backup"
    parent_info = tmp_path.stat()
    luks_uuid = "12345678-1234-5678-9abc-def012345678"
    target = luks_control.LUKSHeaderTarget(
        action="backup",
        device_path="/dev/test-device",
        device_major=7,
        device_minor=0,
        device_size_bytes=1024 * 1024,
        luks_version="luks2",
        luks_uuid=luks_uuid,
        backup_file=str(backup_file),
        backup_parent_identity=(parent_info.st_dev, parent_info.st_ino),
        backup_file_identity=None,
        backup_file_size_bytes=None,
        backup_file_digest=None,
        header_keyslots=(0,),
        header_tokens=(),
        current_header_present=True,
        current_keyslots=(0,),
        current_tokens=(),
        signatures=None,
        state_digest="test-state",
    )
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        luks_control,
        "luks_header_action_confirmation_details",
        lambda *_args, **_kwargs: (target, "confirmation", None),
    )
    monkeypatch.setattr(
        luks_control,
        "_open_verified_block_device",
        lambda _target: os.open(os.devnull, os.O_RDONLY),
    )
    monkeypatch.setattr(luks_control, "find_session_binary", lambda *_args: "/usr/bin/cryptsetup")
    monkeypatch.setattr(
        luks_control,
        "_safe_header_parent",
        lambda _path: (tmp_path, backup_file.name, (parent_info.st_dev, parent_info.st_ino), None),
    )
    monkeypatch.setattr(
        luks_control,
        "_probe_luks_header",
        lambda *_args, **_kwargs: ("luks2", luks_uuid, None),
    )
    monkeypatch.setattr(
        luks_control,
        "_header_key_state",
        lambda *_args, **_kwargs: ((0,), ()),
    )

    def create_backup(command, _key_data, *, umask=None, extra_fds=(), **_kwargs):
        path = command[command.index("--header-backup-file") + 1]
        observed["path"] = path
        observed["umask"] = umask
        observed["extra_fds"] = extra_fds
        assert os.path.isabs(path)
        assert path.startswith("/proc/self/fd/")
        assert path.rsplit("/", 1)[0] == f"/proc/self/fd/{extra_fds[0]}"
        assert not os.path.lexists(path)
        old_umask = os.umask(umask if umask is not None else 0)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
            try:
                os.write(descriptor, b"verified header backup")
                os.fchmod(descriptor, 0o400)
            finally:
                os.close(descriptor)
        finally:
            os.umask(old_umask)
        return True

    monkeypatch.setattr(luks_control, "_run_mutation", create_backup)

    result = luks_control.perform_luks_header_action(
        "backup",
        target.device_path,
        str(backup_file),
        confirmed=True,
        confirmation_phrase="confirmation",
    )

    assert result.success is True
    assert observed["umask"] == 0o077
    assert len(observed["extra_fds"]) == 1
    assert backup_file.is_file()
    assert stat.S_IMODE(backup_file.stat().st_mode) == 0o400
    assert list(tmp_path.iterdir()) == [backup_file]
