"""Phase 3: declarative/Python interpretations + corpus validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from madrigal.core.interp import (
    DEMO_DEVICE_V1_YAML,
    SchemaError,
    apply_declarative,
    apply_interpretation_file,
    apply_interpretation_text,
    load_interpretation,
    parse_interpretation_text,
)
from madrigal.core.interp.hashutil import content_hash
from madrigal.core.interp.models import ValueStatus
from madrigal.core.interp.python_hook import PythonHookError
from madrigal.core.pcap import import_capture
from madrigal.core.project import ProjectStore
from madrigal.core.tcp import build_session_index, packets_for_session, reassemble_session
from madrigal.core.tcp.session import Direction
from madrigal.core.validate import refresh_stale, validate_stream, validate_workspace
from madrigal.core.workspace import CaptureWorkspace
from madrigal.demo.protocol import Opcode, read_param, set_param

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "madrigal" / "demo" / "corpus"
INTERP_YAML = CORPUS / "interpretations" / "device_v1.yaml"
INTERP_PY = CORPUS / "interpretations" / "device_v1_frame.py"


def _workspace(pcap_name: str = "main.pcap") -> CaptureWorkspace:
    path = CORPUS / pcap_name
    cap = import_capture(path, capture_id=path.stem)
    index = build_session_index(cap)
    streams = [
        reassemble_session(sess, packets_for_session(cap, sess), capture_id=cap.capture_id)
        for sess in index.sessions
    ]
    return CaptureWorkspace(capture=cap, sessions=index, streams=streams)


def test_parse_demo_yaml() -> None:
    doc = parse_interpretation_text(DEMO_DEVICE_V1_YAML)
    assert doc.id == "device_v1"
    assert doc.framing.header.magic == b"MD01"
    assert doc.framing.header.len_offset == 4
    assert len(doc.messages) >= 5


def test_load_corpus_yaml() -> None:
    doc = load_interpretation(INTERP_YAML)
    assert doc.id == "device_v1"
    assert doc.source_path == INTERP_YAML.resolve()


def test_apply_declarative_on_synthetic_bytes() -> None:
    doc = parse_interpretation_text(DEMO_DEVICE_V1_YAML)
    blob = read_param(7) + set_param(7, 42)
    # Minimal DirectedStream stub via reassembly on empty — use materialize override
    from madrigal.core.tcp.reassembly import DirectedStream

    stream = DirectedStream(session_id="s1", direction=Direction.A_TO_B)
    result = apply_declarative(doc, stream, capture_id="synth", data=blob)
    assert result.stats.messages_ok == 2
    assert result.stats.coverage == 1.0
    opcodes = [m.opcode for m in result.messages]
    assert opcodes == [Opcode.READ_PARAM, Opcode.SET_PARAM]
    set_msg = result.messages[1]
    values = {f.name: f.value for f in set_msg.fields}
    assert values["param_id"] == 7
    assert values["value"] == 42
    hyp = next(f for f in set_msg.fields if f.name == "value")
    assert hyp.status == ValueStatus.HYPOTHESIS


def test_apply_on_main_pcap() -> None:
    ws = _workspace("main.pcap")
    sess = ws.sessions.sessions[0]
    bundle = ws.stream_for(sess.key.session_id)
    assert bundle is not None
    # Client requests are B→A in demo corpus
    result = apply_interpretation_file(
        INTERP_YAML,
        bundle.b_to_a,
        capture_id=ws.capture.capture_id,
        direction=Direction.B_TO_A,
    )
    assert result.stats.messages_ok >= 3
    assert result.stats.coverage > 0.5
    assert all(m.provenance.capture_id == "main" for m in result.messages)
    assert any(m.matched_rule for m in result.messages)


def test_apply_extra_pcap_generalizes() -> None:
    """Interpretation must work on extra capture (not filename lookup)."""
    ws = _workspace("extra.pcap")
    sess = ws.sessions.sessions[0]
    bundle = ws.stream_for(sess.key.session_id)
    assert bundle is not None
    doc = load_interpretation(INTERP_YAML)
    for stream, direction in (
        (bundle.a_to_b, Direction.A_TO_B),
        (bundle.b_to_a, Direction.B_TO_A),
    ):
        if stream.length == 0:
            continue
        result = apply_declarative(
            doc, stream, capture_id=ws.capture.capture_id, direction=direction
        )
        assert result.stats.messages_ok >= 1


def test_python_hook_on_main() -> None:
    ws = _workspace("main.pcap")
    sess = ws.sessions.sessions[0]
    bundle = ws.stream_for(sess.key.session_id)
    assert bundle is not None
    result = apply_interpretation_file(
        INTERP_PY,
        bundle.b_to_a,
        capture_id="main",
        direction=Direction.B_TO_A,
    )
    assert result.source == "python"
    assert result.stats.messages_ok >= 3
    assert any("opcode" in {f.name for f in m.fields} for m in result.messages)


def test_python_hook_timeout(tmp_path: Path) -> None:
    script = tmp_path / "hang.py"
    script.write_text(
        "def frame(stream):\n"
        "    while True:\n"
        "        pass\n"
        "    return []\n",
        encoding="utf-8",
    )
    from madrigal.core.interp.python_hook import apply_python_script
    from madrigal.core.tcp.reassembly import DirectedStream

    stream = DirectedStream(session_id="s", direction=Direction.A_TO_B)
    with pytest.raises(PythonHookError, match="timed out"):
        apply_python_script(script, stream, capture_id="c", data=b"MD01", timeout_s=0.5)


def test_validate_workspace_counters() -> None:
    ws = _workspace("main.pcap")
    result = validate_workspace(INTERP_YAML, ws)
    assert result.interpretation_id == "device_v1"
    assert result.counters.ok >= 3
    assert result.counters.contradict == 0 or result.counters.ok > result.counters.contradict
    assert not result.stale
    assert any(h.kind == "ok" for h in result.hits)


def test_stale_validation_hash() -> None:
    ws = _workspace("main.pcap")
    result = validate_workspace(INTERP_YAML, ws)
    assert not result.stale
    refresh_stale(result, "deadbeef" * 8)
    assert result.stale
    # Matching hash clears stale
    refresh_stale(result, result.interpretation_hash)
    assert not result.stale


def test_project_save_interpretation_and_validation(tmp_path: Path) -> None:
    store = ProjectStore.create(tmp_path / "proj", name="p3")
    dest = store.save_interpretation("device_v1.yaml", DEMO_DEVICE_V1_YAML)
    assert dest.is_file()
    assert "interpretations/device_v1.yaml" in store.meta.interpretations
    assert dest in store.list_interpretations()

    ws = _workspace("main.pcap")
    result = validate_workspace(dest, ws)
    vpath = store.save_validation("run1", result.to_dict())
    assert vpath.is_file()
    loaded = store.load_validation_json(vpath)
    assert loaded["interpretation_id"] == "device_v1"
    assert loaded["counters"]["ok"] >= 1


def test_schema_rejects_bad() -> None:
    with pytest.raises(SchemaError):
        parse_interpretation_text("id: x\nframing:\n  type: nonsense\n")


def test_content_hash_stable() -> None:
    a = content_hash(DEMO_DEVICE_V1_YAML)
    b = content_hash(DEMO_DEVICE_V1_YAML)
    assert a == b
    assert len(a) == 64


def test_validate_stream_provenance_packets() -> None:
    ws = _workspace("main.pcap")
    sess = ws.sessions.sessions[0]
    bundle = ws.stream_for(sess.key.session_id)
    assert bundle is not None
    result = validate_stream(
        INTERP_YAML, bundle.b_to_a, capture_id="main", direction=Direction.B_TO_A
    )
    ok_hits = [h for h in result.hits if h.kind == "ok"]
    assert ok_hits
    # At least some framed messages should resolve to packet IDs via provenance
    assert any(h.packet_ids for h in ok_hits)
