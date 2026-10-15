"""TCP reassembly edge cases."""

from __future__ import annotations

from pathlib import Path

from netslider.core.pcap import import_capture
from netslider.core.pcap.models import IPv4Endpoints, LinkType, PacketDiagnosis, PacketRecord, TCPInfo
from netslider.core.tcp import build_session_index, packets_for_session, reassemble_session
from netslider.core.tcp.reassembly import SpanStatus
from netslider.core.tcp.session import EndpointPair, SessionKey, TcpSession
from netslider.demo.corpus.defects import generate_defect_pcaps

ROOT = Path(__file__).resolve().parents[1]
DEFECTS = ROOT / "netslider" / "demo" / "corpus" / "defects"


def _pkt(
    pid: int,
    seq: int,
    payload: bytes,
    *,
    sport: int = 50100,
    dport: int = 9100,
    flags: int = 0x18,  # PSH+ACK
    src: str = "10.0.0.2",
    dst: str = "10.0.0.1",
) -> PacketRecord:
    return PacketRecord(
        packet_id=pid,
        ts=float(pid),
        link_type=LinkType.ETHERNET,
        raw=b"",
        diagnosis=PacketDiagnosis.OK,
        ipv4=IPv4Endpoints(src, dst),
        tcp=TCPInfo(
            src_port=sport,
            dst_port=dport,
            seq=seq,
            ack=1,
            flags=flags,
            header_len=20,
            payload=payload,
            checksum=0,
            checksum_ok=True,
        ),
    )


def _session() -> TcpSession:
    pair = EndpointPair("10.0.0.1", 9100, "10.0.0.2", 50100)
    # canonical: 10.0.0.1:9100 < 10.0.0.2:50100? compare tuples
    # ("10.0.0.1", 9100) < ("10.0.0.2", 50100) → a=server, b=client
    return TcpSession(key=SessionKey("cap", pair, 1), packet_ids=[])


def test_in_order_reassembly() -> None:
    sess = _session()
    # client → server is B_TO_A if a=server
    pkts = [
        _pkt(1, 1000, b"AAAA", flags=0x02),  # SYN alone — no payload path after +1
        _pkt(2, 1001, b"HELLO"),
        _pkt(3, 1006, b"WORLD"),
    ]
    # Fix: SYN with empty payload
    pkts[0] = _pkt(1, 1000, b"", flags=0x02)
    result = reassemble_session(sess, pkts, capture_id="cap")
    # client 10.0.0.2 → server = B_TO_A
    stream = result.b_to_a
    assert stream.materialize() == b"HELLOWORLD"
    assert stream.bytes_unknown == 0
    assert all(s.status == SpanStatus.OK for s in stream.spans)


def test_gap_marks_unknown() -> None:
    sess = _session()
    pkts = [
        _pkt(1, 1000, b"AAAA"),
        _pkt(2, 1010, b"BBBB"),  # gap of 6 bytes
    ]
    result = reassemble_session(sess, pkts, capture_id="cap")
    stream = result.b_to_a
    assert stream.bytes_unknown == 6
    assert any(s.status == SpanStatus.UNKNOWN for s in stream.spans)
    data = stream.materialize()
    assert data.startswith(b"AAAA")
    assert data.endswith(b"BBBB")
    assert b"?" in data


def test_identical_retransmit_deduped() -> None:
    sess = _session()
    pkts = [
        _pkt(1, 1000, b"ABCD"),
        _pkt(2, 1000, b"ABCD"),  # retransmit
        _pkt(3, 1004, b"EF"),
    ]
    result = reassemble_session(sess, pkts, capture_id="cap")
    stream = result.b_to_a
    assert stream.materialize() == b"ABCDEF"
    assert any("retransmit" in d for d in stream.defects)


def test_overlap_conflict_ambiguous() -> None:
    sess = _session()
    pkts = [
        _pkt(1, 1000, b"AAAA"),
        _pkt(2, 1002, b"XXYY"),  # overlaps last 2 of AAAA with XX, then YY new
    ]
    result = reassemble_session(sess, pkts, capture_id="cap")
    stream = result.b_to_a
    # first_seen keeps original AAAA bytes; new tail YY is appended
    assert stream.materialize() == b"AAAAYY"
    assert any("AMBIGUOUS" in d for d in stream.defects)
    assert stream.bytes_ambiguous > 0
    assert any(s.status == SpanStatus.AMBIGUOUS for s in stream.spans)


def test_provenance_packet_roundtrip() -> None:
    sess = _session()
    pkts = [_pkt(7, 500, b"MD01")]
    result = reassemble_session(sess, pkts, capture_id="cap")
    stream = result.b_to_a
    assert stream.provenance.packet_for_offset(0) == 7
    assert stream.provenance.range_for_packet(7) == (0, 4)


def _client_stream_from_pcap(path: Path):
    cap = import_capture(path, capture_id=path.stem)
    index = build_session_index(cap)
    assert index.sessions
    sess = index.sessions[0]
    return reassemble_session(sess, packets_for_session(cap, sess), capture_id=cap.capture_id)


def test_defect_pcap_gap(tmp_path: Path) -> None:
    paths = generate_defect_pcaps(tmp_path / "defects")
    streams = _client_stream_from_pcap(paths["gap"])
    stream = streams.b_to_a
    assert stream.bytes_unknown == 6
    assert any(s.status == SpanStatus.UNKNOWN for s in stream.spans)


def test_defect_pcap_retransmit(tmp_path: Path) -> None:
    paths = generate_defect_pcaps(tmp_path / "defects")
    streams = _client_stream_from_pcap(paths["retransmit"])
    stream = streams.b_to_a
    assert stream.materialize() == b"ABCDEF"
    assert any("retransmit" in d for d in stream.defects)


def test_defect_pcap_overlap(tmp_path: Path) -> None:
    paths = generate_defect_pcaps(tmp_path / "defects")
    streams = _client_stream_from_pcap(paths["overlap"])
    stream = streams.b_to_a
    assert stream.materialize() == b"AAAAYY"
    assert any("AMBIGUOUS" in d for d in stream.defects)
    assert stream.bytes_ambiguous > 0
    assert any(s.status == SpanStatus.AMBIGUOUS for s in stream.spans)


def test_defect_pcap_reorder(tmp_path: Path) -> None:
    paths = generate_defect_pcaps(tmp_path / "defects")
    streams = _client_stream_from_pcap(paths["reorder"])
    stream = streams.b_to_a
    assert stream.materialize() == b"ABCDEFGH"
    assert stream.bytes_unknown == 0
    assert any("out-of-order" in d for d in stream.defects)


def test_reorder_unit() -> None:
    """Higher SEQ first, then lower — contiguous after drain."""
    sess = _session()
    pkts = [
        _pkt(1, 1000, b"", flags=0x02),  # SYN → expected data seq 1001
        _pkt(2, 1005, b"EFGH"),
        _pkt(3, 1001, b"ABCD"),
    ]
    result = reassemble_session(sess, pkts, capture_id="cap")
    stream = result.b_to_a
    assert stream.materialize() == b"ABCDEFGH"
    assert stream.bytes_unknown == 0
    assert any(s.status == SpanStatus.OK for s in stream.spans)


def test_checked_in_defect_pcaps() -> None:
    """Checked-in corpus defects/ must exist and match unit expectations."""
    assert DEFECTS.is_dir(), f"missing defects dir: {DEFECTS}"
    for name, check in (
        ("gap.pcap", lambda s: s.bytes_unknown == 6),
        ("retransmit.pcap", lambda s: s.materialize() == b"ABCDEF"),
        ("overlap.pcap", lambda s: s.materialize() == b"AAAAYY"),
        ("reorder.pcap", lambda s: s.materialize() == b"ABCDEFGH" and s.bytes_unknown == 0),
    ):
        path = DEFECTS / name
        assert path.is_file(), f"missing defect capture: {path}"
        streams = _client_stream_from_pcap(path)
        assert check(streams.b_to_a), name
