from __future__ import annotations

import base64
import os
import stat
from pathlib import Path

from wayland_mcp.tools.filesystem_admin import (
    binary_file_write_confirmation_details,
    read_binary_file,
    write_binary_file,
)


def _write(path: str, value: bytes, action: str):
    encoded = base64.b64encode(value).decode("ascii")
    target, phrase, error = binary_file_write_confirmation_details(path, encoded, action)
    assert target is not None and phrase is not None and error is None
    return write_binary_file(
        path,
        encoded,
        action,
        confirmed=True,
        confirmation_phrase=phrase,
    )


def test_binary_file_create_page_append_and_atomic_replace(tmp_path) -> None:
    path = str(tmp_path / "sample.bin")
    first = b"\x00\x01binary\xff"
    assert _write(path, first, "create").success

    page = read_binary_file(path, offset=0, max_bytes=3)
    assert page.success and page.truncated
    assert base64.b64decode(page.data_base64) == first[:3]
    assert page.next_offset == 3
    assert base64.b64decode(read_binary_file(path, offset=3, max_bytes=100).data_base64) == first[3:]

    try:
        os.setxattr(path, "user.linux_mcp_test", b"preserved")
        xattr_supported = True
    except OSError:
        xattr_supported = False
    original_mode = stat.S_IMODE(os.stat(path).st_mode)

    second = b"\x80append"
    assert _write(path, second, "append").success
    assert Path(path).read_bytes() == first + second

    replacement = b"\xfe\x00replacement"
    assert _write(path, replacement, "replace").success
    assert Path(path).read_bytes() == replacement
    assert stat.S_IMODE(os.stat(path).st_mode) == original_mode
    if xattr_supported:
        assert os.getxattr(path, "user.linux_mcp_test") == b"preserved"


def test_binary_file_requires_matching_confirmation_and_create_never_overwrites(tmp_path) -> None:
    path = str(tmp_path / "existing.bin")
    Path(path).write_bytes(b"original")
    encoded = base64.b64encode(b"replacement").decode("ascii")
    result = write_binary_file(path, encoded, "replace", confirmed=True, confirmation_phrase="WRITE wrong")
    assert not result.success
    assert Path(path).read_bytes() == b"original"

    _, phrase, error = binary_file_write_confirmation_details(path, encoded, "create")
    assert phrase is None
    assert "already exists" in (error or "")
