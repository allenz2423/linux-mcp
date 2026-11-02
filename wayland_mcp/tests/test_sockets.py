from __future__ import annotations

from pathlib import Path

from wayland_mcp.tools import sockets


PROC_SOCKET_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
)
PROC_SOCKET_HEADER_IPV6 = (
    "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
)


def test_tcp_inventory_maps_procfs_uid_and_inode_after_combined_columns(tmp_path: Path, monkeypatch) -> None:
    proc_net = tmp_path / "net"
    proc_net.mkdir()
    (proc_net / "tcp").write_text(
        PROC_SOCKET_HEADER
        + "  0: 0100007F:C001 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 123456789 1 0000000000000000 100 0 0 10 0\n",
        encoding="ascii",
    )
    monkeypatch.setattr(sockets, "PROC_NET", proc_net)
    monkeypatch.setattr(sockets.sys, "platform", "linux")

    response = sockets.list_network_sockets(query="49153")

    assert response.success
    assert len(response.sockets) == 1
    assert response.sockets[0].local_port == 49153
    assert response.sockets[0].uid == 1000
    assert response.sockets[0].inode == 123456789


def test_raw_inventory_uses_positive_inode_and_marks_zero_unavailable(tmp_path: Path, monkeypatch) -> None:
    proc_net = tmp_path / "net"
    proc_net.mkdir()
    (proc_net / "raw").write_text(
        PROC_SOCKET_HEADER
        + "  0: 0100007F:0001 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 987654321 1 0000000000000000 100 0 0 10 0\n"
        + "  1: 0100007F:0002 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 0 1 0000000000000000 100 0 0 10 0\n",
        encoding="ascii",
    )
    monkeypatch.setattr(sockets, "PROC_NET", proc_net)
    monkeypatch.setattr(sockets.sys, "platform", "linux")

    response = sockets.list_unix_raw_sockets()

    assert response.success
    assert len(response.raw_sockets) == 2
    by_protocol = {item.local_protocol_number: item for item in response.raw_sockets}
    assert by_protocol[1].uid == 1000
    assert by_protocol[1].inode == 987654321
    assert by_protocol[2].uid == 1000
    assert by_protocol[2].inode is None


def test_ipv6_tcp_inventory_accepts_remote_address_header(tmp_path: Path, monkeypatch) -> None:
    proc_net = tmp_path / "net"
    proc_net.mkdir()
    (proc_net / "tcp6").write_text(
        PROC_SOCKET_HEADER_IPV6
        + "  0: 00000000000000000000000001000000:D431 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 223456789 1 0000000000000000 100 0 0 10 0\n",
        encoding="ascii",
    )
    monkeypatch.setattr(sockets, "PROC_NET", proc_net)
    monkeypatch.setattr(sockets.sys, "platform", "linux")

    response = sockets.list_network_sockets(query="54321")

    assert response.success
    assert len(response.sockets) == 1
    assert response.sockets[0].family == "ipv6"
    assert response.sockets[0].local_address == "::1"
    assert response.sockets[0].local_port == 54321
    assert response.sockets[0].uid == 1000
    assert response.sockets[0].inode == 223456789


def test_ipv6_raw_inventory_accepts_remote_address_header(tmp_path: Path, monkeypatch) -> None:
    proc_net = tmp_path / "net"
    proc_net.mkdir()
    (proc_net / "raw6").write_text(
        PROC_SOCKET_HEADER_IPV6
        + "  0: 00000000000000000000000001000000:0001 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 323456789 1 0000000000000000 100 0 0 10 0\n",
        encoding="ascii",
    )
    monkeypatch.setattr(sockets, "PROC_NET", proc_net)
    monkeypatch.setattr(sockets.sys, "platform", "linux")

    response = sockets.list_unix_raw_sockets()

    assert response.success
    assert len(response.raw_sockets) == 1
    assert response.raw_sockets[0].family == "ipv6"
    assert response.raw_sockets[0].local_address == "::1"
    assert response.raw_sockets[0].local_protocol_number == 1
    assert response.raw_sockets[0].uid == 1000
    assert response.raw_sockets[0].inode == 323456789
