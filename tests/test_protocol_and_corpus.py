"""Phase 0: protocol framing + corpus generation."""

from __future__ import annotations

import struct
from pathlib import Path

from netslider.demo import protocol as proto
from netslider.demo.corpus.generate import generate_corpus


def test_frame_roundtrip() -> None:
    raw = proto.set_param(1, 180)
    frame, consumed = proto.try_decode_one(raw)
    assert frame is not None
    assert consumed == len(raw)
    assert frame.opcode == proto.Opcode.SET_PARAM
    pid, val = struct.unpack_from("<HH", frame.payload, 0)
    assert pid == 1 and val == 180


def test_generate_corpus(tmp_path: Path) -> None:
    paths = generate_corpus(tmp_path, extra=True)
    assert paths["main_pcap"].stat().st_size > 100
    assert paths["action_log"].stat().st_size > 100
    assert paths["extra_pcap"].stat().st_size > 100
    # Classic PCAP magic
    magic = paths["main_pcap"].read_bytes()[:4]
    assert magic == b"\xd4\xc3\xb2\xa1"
