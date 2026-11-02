from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from wayland_mcp.tools import btrfs_snapshots


def test_read_only_snapshot_identity_survives_clone_generation_change() -> None:
    snapshot = btrfs_snapshots.BtrfsSubvolume(
        path=Path("/mnt/btrfs/snapshot"),
        relative_path="snapshot",
        subvolume_id=257,
        generation=9,
        parent_id=256,
        top_level_id=5,
        uuid="75119e93-db74-6a42-8bef-40bad88ac6c1",
        parent_uuid="12345678-1234-5678-9abc-def012345678",
        received_uuid="-",
        read_only=True,
        stat_identity=(90, 256, 0o755, 1, 1),
    )
    after_clone = replace(snapshot, generation=10)

    assert btrfs_snapshots._same_subvolume_state(after_clone, snapshot) is False
    assert btrfs_snapshots._same_subvolume_identity(after_clone, snapshot) is True


def test_parse_subvolume_list_accepts_padded_uuid_columns() -> None:
    rows, partial = btrfs_snapshots._parse_subvolume_list(
        "ID 256 gen 9 parent 5 top level 5 parent_uuid -                                    "
        "received_uuid -                                    "
        "uuid 75119e93-db74-6a42-8bef-40bad88ac6c1 path source subvolume\n"
    )

    assert partial is False
    assert rows == [
        {
            "subvolume_id": 256,
            "generation": 9,
            "parent_id": 5,
            "top_level_id": 5,
            "parent_uuid": "-",
            "received_uuid": "-",
            "uuid": "75119e93-db74-6a42-8bef-40bad88ac6c1",
            "relative_path": "source subvolume",
        }
    ]


def test_same_btrfs_mount_accepts_subvolume_paths_with_separate_st_dev(
    monkeypatch,
    tmp_path: Path,
) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "36 25 0:90 / /mnt/btrfs rw,relatime - btrfs /dev/loop0 rw,subvolid=5\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(btrfs_snapshots, "MOUNTINFO", mountinfo)

    assert btrfs_snapshots._same_btrfs_mount(Path("/mnt/btrfs"), Path("/mnt/btrfs/source")) is True


def test_same_btrfs_mount_rejects_a_nested_mount(tmp_path: Path, monkeypatch) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "36 25 0:90 / /mnt/btrfs rw,relatime - btrfs /dev/loop0 rw,subvolid=5\n"
        "37 36 0:91 / /mnt/btrfs/source rw,relatime - btrfs /dev/loop0 rw,subvolid=256\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(btrfs_snapshots, "MOUNTINFO", mountinfo)

    assert btrfs_snapshots._same_btrfs_mount(Path("/mnt/btrfs"), Path("/mnt/btrfs/source")) is False


def test_same_btrfs_mount_rejects_a_nested_different_filesystem(tmp_path: Path, monkeypatch) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "36 25 0:90 / /mnt/btrfs rw,relatime - btrfs /dev/loop0 rw,subvolid=5\n"
        "37 36 8:1 / /mnt/btrfs/source rw,relatime - ext4 /dev/sda1 rw\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(btrfs_snapshots, "MOUNTINFO", mountinfo)

    assert btrfs_snapshots._same_btrfs_mount(Path("/mnt/btrfs"), Path("/mnt/btrfs/source")) is False
