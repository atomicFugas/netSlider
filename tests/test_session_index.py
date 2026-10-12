"""Session indexing — port reuse creates a new instance."""

from __future__ import annotations

from madrigal.core.pcap.models import (
    ImportedCapture,
    IPv4Endpoints,
    LinkType,
    PacketDiagnosis,
    PacketRecord,
    TCPInfo,
    CaptureDiagnostics,
)
from madrigal.core.tcp.session import build_session_index


def _tcp_pkt(pid: int, flags: int, seq: int = 1) -> PacketRecord:
    return PacketRecord(
        packet_id=pid,
        ts=float(pid),
        link_type=LinkType.ETHERNET,
        raw=b"",
        diagnosis=PacketDiagnosis.OK,
        ipv4=IPv4Endpoints("10.0.0.2", "10.0.0.1"),
        tcp=TCPInfo(
            src_port=50100,
            dst_port=9100,
            seq=seq,
            ack=1,
            flags=flags,
            header_len=20,
            payload=b"",
            checksum=0,
            checksum_ok=True,
        ),
    )


def test_port_reuse_new_instance() -> None:
    # conn1: SYN, data, FIN; conn2: SYN again same ports
    packets = [
        _tcp_pkt(1, 0x02, 1000),  # SYN
        _tcp_pkt(2, 0x18, 1001),  # PSH+ACK
        _tcp_pkt(3, 0x11, 1002),  # FIN+ACK
        _tcp_pkt(4, 0x02, 5000),  # SYN reuse
        _tcp_pkt(5, 0x18, 5001),
    ]
    cap = ImportedCapture(
        capture_id="t",
        path="t.pcap",
        packets=packets,
        diagnostics=CaptureDiagnostics(path="t.pcap"),
    )
    index = build_session_index(cap)
    assert len(index.sessions) == 2
    assert index.sessions[0].key.instance == 1
    assert index.sessions[1].key.instance == 2
    assert index.packet_to_session[1] != index.packet_to_session[4]
