from __future__ import annotations

import os
from pathlib import Path

import pytest

from wayland_mcp.tools import accounts_control


def _home_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, int]:
    base = tmp_path / "homes"
    base.mkdir()
    home = base / "alice"
    home.mkdir()
    (home / "notes.txt").write_text("account data", encoding="utf-8")
    uid = os.getuid() or 12345
    if os.getuid() == 0:
        os.chown(home, uid, uid)
        os.chown(home / "notes.txt", uid, uid)
    monkeypatch.setattr(accounts_control, "HOME_BASE_PATHS", (base,))
    monkeypatch.setattr(
        accounts_control,
        "_safe_home_parent",
        lambda path, _label: (accounts_control._path_identity(path.stat(follow_symlinks=False)), None),
    )
    monkeypatch.setattr(accounts_control, "_home_has_nested_mount", lambda _path: (False, None))
    return base, home, uid


def _planned_target(
    home: Path,
    parent: Path,
    uid: int,
) -> accounts_control.LocalIdentityTarget:
    (
        path,
        home_identity,
        parent_path,
        parent_identity,
        tree_sha,
        entries,
        total_bytes,
        error,
    ) = accounts_control._planned_home_removal(uid, str(home))
    assert error is None
    assert path == home
    assert home_identity is not None
    assert parent_path == parent
    assert parent_identity is not None
    assert tree_sha is not None
    return accounts_control.LocalIdentityTarget(
        action="delete_user",
        username="alice",
        group_name=None,
        login_shell=None,
        current_user=("alice", uid, uid, str(home), "/bin/sh"),
        current_group=None,
        password_state=None,
        side_effect_notes=(),
        files_digest="files",
        state_digest="state",
        source_home_directory=str(home),
        source_home_identity=home_identity,
        home_parent_path=str(parent_path),
        home_parent_identity=parent_identity,
        remove_home=True,
        home_tree_sha256=tree_sha,
        home_tree_entries=entries,
        home_tree_bytes=total_bytes,
    )


def test_home_removal_plan_binds_bounded_owned_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _base, home, uid = _home_tree(tmp_path, monkeypatch)

    target = _planned_target(home, home.parent, uid)

    assert target.home_tree_entries == 1
    assert target.home_tree_bytes == len(b"account data")
    assert len(target.home_tree_sha256 or "") == 64


def test_home_removal_plan_refuses_root_and_mounted_trees(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _base, home, uid = _home_tree(tmp_path, monkeypatch)

    assert "root" in (accounts_control._planned_home_removal(0, str(home))[-1] or "")
    monkeypatch.setattr(accounts_control, "_home_has_nested_mount", lambda _path: (True, None))
    assert "mounted filesystem" in (accounts_control._planned_home_removal(uid, str(home))[-1] or "")


def test_home_removal_is_symlink_resistant_and_leaves_external_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _base, home, uid = _home_tree(tmp_path, monkeypatch)
    external = tmp_path / "outside.txt"
    external.write_text("keep", encoding="utf-8")
    (home / "external-link").symlink_to(external)
    target = _planned_target(home, home.parent, uid)
    monkeypatch.setattr(accounts_control, "_parse_local_state", lambda: ({}, {}, "digest", None))

    removed, error = accounts_control._remove_confirmed_home(target)

    assert removed is True
    assert error is None
    assert not home.exists()
    assert external.read_text(encoding="utf-8") == "keep"


def test_home_removal_refuses_tree_changes_after_confirmation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _base, home, uid = _home_tree(tmp_path, monkeypatch)
    target = _planned_target(home, home.parent, uid)
    (home / "new-file.txt").write_text("changed", encoding="utf-8")
    monkeypatch.setattr(accounts_control, "_parse_local_state", lambda: ({}, {}, "digest", None))

    removed, error = accounts_control._remove_confirmed_home(target)

    assert removed is False
    assert "changed" in (error or "")
    assert home.is_dir()
    assert (home / "new-file.txt").exists()


def test_remove_home_is_only_valid_for_delete_user() -> None:
    _target, _phrase, error = accounts_control.local_identity_action_confirmation_details(
        "lock_user",
        username="alice",
        remove_home=True,
    )

    assert error == "remove_home applies only to delete_user."


def test_delete_user_removes_confirmed_home_only_after_fixed_userdel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _base, home, uid = _home_tree(tmp_path, monkeypatch)
    commands: list[list[str]] = []
    state_reads = 0
    current_user = ("alice", uid, uid, str(home), "/bin/sh")

    def account_state():
        nonlocal state_reads
        state_reads += 1
        if state_reads <= 3:
            return {"alice": current_user}, {}, "before", None
        return {}, {}, "after", None

    monkeypatch.setattr(accounts_control, "local_identity_control_available", lambda: True)
    monkeypatch.setattr(accounts_control, "_side_effect_policy", lambda *_args, **_kwargs: ("side-effects", (), None))
    monkeypatch.setattr(accounts_control, "_parse_local_state", account_state)
    monkeypatch.setattr(accounts_control, "find_session_binary", lambda name, _env=None: f"/usr/sbin/{name}")

    def fake_run(command: list[str], **_kwargs: object) -> tuple[int, str]:
        commands.append(command)
        return 0, ""

    monkeypatch.setattr(accounts_control, "_run", fake_run)
    target, phrase, error = accounts_control.local_identity_action_confirmation_details(
        "delete_user",
        username="alice",
        remove_home=True,
    )
    assert error is None
    assert target is not None
    assert phrase is not None

    response = accounts_control.perform_local_identity_action(
        "delete_user",
        username="alice",
        remove_home=True,
        confirmed=True,
        confirmation_phrase=phrase,
    )

    assert response.success is True
    assert commands == [["/usr/sbin/userdel", "alice"]]
    assert not home.exists()
