"""Phase 2: action-log alignment, framing probes, compare."""

from __future__ import annotations

from pathlib import Path

from netslider.core.investigate import (
    align_actions,
    delimiter_histogram,
    diff_ranges,
    find_magic,
    load_action_log,
    parse_magic_string,
    probe_grid,
    probe_length_prefix,
)
from netslider.core.pcap import import_capture
from netslider.core.tcp import build_session_index, packets_for_session, reassemble_session

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "netslider" / "demo" / "corpus"


def test_load_action_log_json() -> None:
    log = load_action_log(CORPUS / "action_log.json")
    assert len(log.events) >= 5
    assert log.events[0].action == "connect"
    assert any(e.action == "set_param" for e in log.events)


def test_parse_magic_variants() -> None:
    assert parse_magic_string("MD01") == b"MD01"
    assert parse_magic_string("4d443031") == b"MD01"
    assert parse_magic_string("4d 44 30 31") == b"MD01"


def test_find_magic_and_length_probe_on_demo() -> None:
    cap = import_capture(CORPUS / "main.pcap", capture_id="main")
    index = build_session_index(cap)
    sess = index.sessions[0]
    streams = reassemble_session(sess, packets_for_session(cap, sess), capture_id="main")
    data = streams.b_to_a.materialize() + streams.a_to_b.materialize()
    # client requests are on B→A in our canonical ordering
    client = streams.b_to_a.materialize()
    hits = find_magic(client, b"MD01")
    assert len(hits) >= 3
    probe = probe_length_prefix(client, len_offset=4, len_size=2, endian="be", magic=b"MD01")
    assert probe.frames_ok >= 3
    assert probe.coverage > 0.5
    ranked = probe_grid(client, magic=b"MD01")
    assert ranked[0].frames_ok >= 1


def test_align_actions_relative() -> None:
    cap = import_capture(CORPUS / "main.pcap", capture_id="main")
    log = load_action_log(CORPUS / "action_log.json")
    index = build_session_index(cap)
    sess = index.sessions[0]
    streams_bundle = reassemble_session(sess, packets_for_session(cap, sess), capture_id="main")
    result = align_actions(
        log,
        cap.packets,
        session=sess,
        streams={"A→B": streams_bundle.a_to_b, "B→A": streams_bundle.b_to_a},
        mode="relative",
        window_s=0.08,
    )
    assert result.mode == "relative"
    # At least some non-connect actions should hit packets (nearest, not whole capture)
    hit = [a for a in result.actions if a.event.action not in {"connect", "disconnect"} and a.packet_ids]
    assert len(hit) >= 1
    assert all(len(a.packet_ids) <= 4 for a in hit)


def test_delimiter_histogram() -> None:
    data = b"MD01\x00\x03\x01\x01\x00" * 5 + b"\n\n"
    stats = delimiter_histogram(data)
    assert stats
    assert stats[0].count >= 1


def test_diff_ranges() -> None:
    diff = diff_ranges(b"AAAA", 0, b"AABA", 10)
    assert not diff.equal
    assert diff.first_diff == 2
    same = diff_ranges(b"xx", 0, b"xx", 5)
    assert same.equal
