from __future__ import annotations

import errno
import os
import stat
import struct

import pytest

from wayland_mcp.models import ACLWriteEntry
from wayland_mcp.tools.filesystem_path_admin import manage_posix_acl, posix_acl_confirmation_details


def test_manage_trivial_access_acl_verifies_mode_when_kernel_elides_xattr(tmp_path) -> None:
    path = tmp_path / "acl-target"
    path.write_bytes(b"test")
    path.chmod(0o600)
    entries = [
        ACLWriteEntry(tag="user_obj", permissions="rw-"),
        ACLWriteEntry(tag="group_obj", permissions="---"),
        ACLWriteEntry(tag="other", permissions="---"),
    ]

    raw_acl = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, permissions, 0xFFFFFFFF)
        for tag, permissions in ((0x01, 6), (0x04, 0), (0x20, 0))
    )
    try:
        os.setxattr(path, "system.posix_acl_access", raw_acl)
    except OSError as exc:
        if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP, errno.EPERM, errno.EACCES}:
            pytest.skip(f"filesystem does not permit POSIX ACL changes: {exc}")
        raise
    try:
        os.getxattr(path, "system.posix_acl_access")
    except OSError as exc:
        if exc.errno != getattr(errno, "ENODATA", 61):
            raise
    else:
        pytest.skip("filesystem retains trivial ACL xattrs, so the kernel elision path is unavailable")

    prepared, phrase, error = posix_acl_confirmation_details(str(path), "set", "access", entries)
    assert prepared is not None and phrase is not None and error is None
    result = manage_posix_acl(
        str(path), "set", "access", entries, confirmed=True, confirmation_phrase=phrase
    )

    assert result.success, result.message
    assert stat.S_IMODE(path.stat().st_mode) & 0o777 == 0o600
    try:
        os.getxattr(path, "system.posix_acl_access")
    except OSError as exc:
        assert exc.errno == getattr(errno, "ENODATA", 61)
