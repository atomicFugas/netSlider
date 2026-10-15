"""Regenerate golden expected JSON under this directory."""

from __future__ import annotations

import json
from pathlib import Path

from netslider.core.interp import apply_interpretation_file
from netslider.core.pcap import import_capture
from netslider.core.tcp import build_session_index, packets_for_session, reassemble_session
from netslider.core.tcp.session import Direction
from netslider.core.validate import validate_workspace
from netslider.core.workspace import CaptureWorkspace
from netslider.demo.corpus.golden import GOLDEN_DIR

CORPUS = GOLDEN_DIR.parent
INTERP = CORPUS / "interpretations" / "device_v1.yaml"


def _summarize_apply(pcap: Path) -> dict:
    cap = import_capture(pcap, capture_id=pcap.stem)
    index = build_session_index(cap)
    rows = []
    total_ok = 0
    total_err = 0
    opcodes: list[int] = []
    for sess in index.sessions:
        streams = reassemble_session(
            sess, packets_for_session(cap, sess), capture_id=cap.capture_id
        )
        for direction, stream in (
            (Direction.A_TO_B, streams.a_to_b),
            (Direction.B_TO_A, streams.b_to_a),
        ):
            if stream.length == 0:
                continue
            result = apply_interpretation_file(
                INTERP, stream, capture_id=cap.capture_id, direction=direction
            )
            total_ok += result.stats.messages_ok
            total_err += result.stats.messages_error
            opcodes.extend(m.opcode for m in result.messages if m.opcode is not None)
            rows.append(
                {
                    "session_id": sess.key.session_id,
                    "direction": direction.value,
                    "messages_ok": result.stats.messages_ok,
                    "messages_error": result.stats.messages_error,
                    "coverage_min": 0.5,
                }
            )
    return {
        "interpretation": "device_v1",
        "pcap": pcap.name,
        "messages_ok": total_ok,
        "messages_error": total_err,
        "opcodes_present": sorted(set(opcodes)),
        "streams": rows,
    }


def _summarize_validate(pcap: Path) -> dict:
    cap = import_capture(pcap, capture_id=pcap.stem)
    index = build_session_index(cap)
    streams = [
        reassemble_session(sess, packets_for_session(cap, sess), capture_id=cap.capture_id)
        for sess in index.sessions
    ]
    ws = CaptureWorkspace(capture=cap, sessions=index, streams=streams)
    result = validate_workspace(INTERP, ws)
    return {
        "interpretation": result.interpretation_id,
        "pcap": pcap.name,
        "counters": {
            "ok_min": result.counters.ok,
            "contradict_max": result.counters.contradict,
            "uncovered_max": result.counters.uncovered,
        },
        "stale": False,
    }


def main() -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    apply_extra = _summarize_apply(CORPUS / "extra.pcap")
    # Soft thresholds for golden: store mins so minor corpus regen still passes
    apply_extra["messages_ok_min"] = apply_extra["messages_ok"]
    apply_extra["messages_error_max"] = apply_extra["messages_error"]
    (GOLDEN_DIR / "expected_apply_extra.json").write_text(
        json.dumps(apply_extra, indent=2) + "\n", encoding="utf-8"
    )
    validate_main = _summarize_validate(CORPUS / "main.pcap")
    (GOLDEN_DIR / "expected_validate_main.json").write_text(
        json.dumps(validate_main, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {GOLDEN_DIR / 'expected_apply_extra.json'}")
    print(f"wrote {GOLDEN_DIR / 'expected_validate_main.json'}")


if __name__ == "__main__":
    main()
