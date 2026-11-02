from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

from wayland_mcp.tools import kernel_command_line as kernel


def _read_at(directory_fd: int, name: str, **_kwargs):
    descriptor = os.open(name, os.O_RDONLY, dir_fd=directory_fd)
    try:
        info = os.fstat(descriptor)
        chunks = []
        while chunk := os.read(descriptor, 64 * 1024):
            chunks.append(chunk)
        return b"".join(chunks), kernel._identity(info), kernel._read_xattrs(descriptor)
    finally:
        os.close(descriptor)


def _read_path(path: Path):
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return (*_read_at(directory_fd, path.name), None)
    finally:
        os.close(directory_fd)


def test_grub_generation_accepts_its_reserved_output_file(tmp_path: Path, monkeypatch):
    output = tmp_path / "grub.cfg"
    original = b"menuentry 'fixture' {\n linux /vmlinuz root=UUID=fixture quiet\n}\n"
    generated = b"menuentry 'fixture' {\n linux /vmlinuz root=UUID=fixture quiet audit=1\n}\n"
    output.write_bytes(original)
    output.chmod(0o640)
    output_identity = kernel._identity(output.stat())
    output_parent_identity = kernel._identity(tmp_path.stat())
    descriptor = os.open(output, os.O_RDONLY)
    try:
        output_xattrs = kernel._read_xattrs(descriptor)
    finally:
        os.close(descriptor)
    assert output_xattrs is not None

    snapshot = SimpleNamespace(
        output_path=output,
        output_bytes=original,
        output_identity=output_identity,
        output_parent_identity=output_parent_identity,
        output_xattrs=output_xattrs,
    )
    monkeypatch.setattr(
        kernel,
        "_safe_rooted_directory",
        lambda path, _label: kernel._identity(Path(path).stat(follow_symlinks=False)),
    )
    monkeypatch.setattr(
        kernel,
        "_read_rooted_file",
        lambda path, _label, _limit: _read_path(Path(path)),
    )
    monkeypatch.setattr(kernel, "_read_at", _read_at)

    temp_name, temp_identity = kernel._create_grub_output_temp(snapshot)

    (tmp_path / temp_name).write_bytes(generated)
    prepared, error = kernel._prepare_generated_output(snapshot, temp_name, temp_identity)
    assert error is None
    assert prepared == generated

    published, warning = kernel._publish_grub_output(snapshot, temp_name, prepared)
    assert published is True
    assert warning is None
    assert output.read_bytes() == generated
    assert sorted(path.name for path in tmp_path.iterdir()) == ["grub.cfg"]
