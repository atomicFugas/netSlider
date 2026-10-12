"""PCAP import + session index against demo corpus."""

from __future__ import annotations

from pathlib import Path

from madrigal.core.pcap import import_capture
from madrigal.core.tcp import build_session_index, packets_for_session, reassemble_session

CORPUS = Path(__file__).resolve().parents[1] / "madrigal" / "demo" / "corpus" / "main.pcap"


def test_import_main_corpus() -> None:
    assert CORPUS.is_file()
    cap = import_capture(CORPUS, capture_id="main")
    assert cap.diagnostics.packet_count > 10
    assert cap.diagnostics.tcp_packet_count > 5
    assert cap.diagnostics.backend == "classic"


def test_session_and_reassembly_contains_magic() -> None:
    cap = import_capture(CORPUS, capture_id="main")
    index = build_session_index(cap)
    assert len(index.sessions) >= 1
    sess = index.sessions[0]
    pkts = packets_for_session(cap, sess)
    streams = reassemble_session(sess, pkts, capture_id="main")
    combined = streams.a_to_b.materialize() + streams.b_to_a.materialize()
    assert b"MD01" in combined


def test_provenance_links_bytes_to_packets() -> None:
    cap = import_capture(CORPUS, capture_id="main")
    index = build_session_index(cap)
    sess = index.sessions[0]
    streams = reassemble_session(sess, packets_for_session(cap, sess), capture_id="main")
    for stream in (streams.a_to_b, streams.b_to_a):
        if stream.length == 0:
            continue
        origin = stream.provenance.origin_at(0)
        assert origin is not None
        assert origin.packet_id in sess.packet_ids
        break
    else:
        raise AssertionError("no stream data")
