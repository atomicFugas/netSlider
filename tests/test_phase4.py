"""Phase 4: portable projects, report, CLI --project, golden reuse, limits."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from click.testing import CliRunner

from netslider.cli.main import cli
from netslider.core.limits import check_capture_file, check_packet_count, merge_limits
from netslider.core.project import ProjectStore
from netslider.core.report import ReportDraft, build_markdown_report, write_report
from netslider.core.interp import DEMO_DEVICE_V1_YAML, load_interpretation
from netslider.demo.corpus.golden import GOLDEN_DIR
from netslider.demo.corpus.stress import generate_stress_pcap

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "netslider" / "demo" / "corpus"
INTERP = CORPUS / "interpretations" / "device_v1.yaml"


def test_project_portable_after_move(tmp_path: Path) -> None:
    src = tmp_path / "lab"
    store = ProjectStore.create(src, name="portable")
    store.import_capture(CORPUS / "extra.pcap")
    store.save_interpretation("device_v1.yaml", INTERP.read_text(encoding="utf-8"))
    assert store.assert_portable() == []

    moved = tmp_path / "elsewhere" / "lab"
    moved.parent.mkdir(parents=True)
    shutil.move(str(src), str(moved))
    opened = ProjectStore.open(moved)
    assert opened.meta.name == "portable"
    assert opened.assert_portable() == []
    cap = opened.resolve_rel(opened.meta.captures[0])
    assert cap.is_file()
    interp = opened.primary_interpretation()
    assert interp is not None and interp.is_file()


def test_package_zip_roundtrip(tmp_path: Path) -> None:
    store = ProjectStore.create(tmp_path / "lab", name="z")
    store.save_interpretation("device_v1.yaml", DEMO_DEVICE_V1_YAML)
    zpath = store.package_zip(tmp_path / "lab.zip")
    assert zpath.is_file() and zpath.stat().st_size > 0


def test_report_markdown_and_json(tmp_path: Path) -> None:
    store = ProjectStore.create(tmp_path / "lab", name="report-demo")
    store.save_interpretation("device_v1.yaml", DEMO_DEVICE_V1_YAML)
    doc = load_interpretation(store.primary_interpretation())
    draft = ReportDraft(
        title="Demo",
        rationale="Test rationale",
        scope="demo-device",
        examples=["read_param on main.pcap"],
        counterexamples=["truncated frame"],
        open_questions=["endianness on wire?"],
    )
    md = build_markdown_report(store, draft=draft, interpretation=doc)
    assert "Test rationale" in md
    assert "device_v1" in md
    md_path, json_path = write_report(
        tmp_path / "out", project=store, draft=draft, interpretation=doc
    )
    assert md_path.is_file()
    assert json_path is not None and json_path.is_file()
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["id"] == "device_v1"
    assert payload["netslider_export"]["format"] == "interpretation/v1"


def test_cli_apply_project(tmp_path: Path) -> None:
    store = ProjectStore.create(tmp_path / "lab", name="cli")
    store.import_interpretation(INTERP)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "apply",
            "--project",
            str(store.root),
            "--pcap",
            str(CORPUS / "extra.pcap"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "ok=" in result.output


def test_cli_report(tmp_path: Path) -> None:
    store = ProjectStore.create(tmp_path / "lab", name="rep")
    store.import_interpretation(INTERP)
    out = tmp_path / "reports"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "report",
            "--project",
            str(store.root),
            "--pcap",
            str(CORPUS / "main.pcap"),
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (out / "report.md").is_file()
    assert (out / "report.interpretation.json").is_file()


def test_golden_apply_extra() -> None:
    expected_path = GOLDEN_DIR / "expected_apply_extra.json"
    assert expected_path.is_file(), f"missing golden fixture: {expected_path}"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["apply", str(INTERP), str(CORPUS / "extra.pcap"), "--json-out"],
    )
    assert result.exit_code == 0, result.output
    payloads = json.loads(result.output)
    ok = sum(p["stats"]["messages_ok"] for p in payloads)
    err = sum(p["stats"]["messages_error"] for p in payloads)
    assert ok >= expected.get("messages_ok_min", expected["messages_ok"])
    assert err <= expected.get("messages_error_max", expected["messages_error"])
    opcodes = sorted(
        {
            m["opcode"]
            for p in payloads
            for m in p.get("messages", [])
            if m.get("opcode") is not None
        }
    )
    for op in expected.get("opcodes_present", []):
        assert op in opcodes


def test_golden_validate_main() -> None:
    expected_path = GOLDEN_DIR / "expected_validate_main.json"
    assert expected_path.is_file(), f"missing golden fixture: {expected_path}"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["validate", str(INTERP), str(CORPUS / "main.pcap"), "--json-out"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    counters = payload["counters"]
    assert counters["ok"] >= expected["counters"]["ok_min"]
    assert counters["contradict"] <= expected["counters"]["contradict_max"]
    assert counters["uncovered"] <= expected["counters"]["uncovered_max"]
    assert payload["stale"] is False


def test_limits_warn_and_block(tmp_path: Path) -> None:
    tiny = tmp_path / "t.pcap"
    tiny.write_bytes(b"\x00" * 100)
    settings = {
        "limits": {
            "warn_capture_bytes": 50,
            "max_capture_bytes": 10_000,
            "warn_packets": 10,
            "max_packets": 100,
        }
    }
    check = check_capture_file(tiny, settings)
    assert check.ok
    assert check.warnings
    big = tmp_path / "big.pcap"
    big.write_bytes(b"\x00" * 20_000)
    blocked = check_capture_file(big, settings)
    assert blocked.blocked
    pkt = check_packet_count(50, settings)
    assert pkt.warnings
    assert check_packet_count(200, settings).blocked
    assert merge_limits(settings)["max_packets"] == 100


def test_stress_smoke_generates(tmp_path: Path) -> None:
    out = tmp_path / "stress.pcap"
    metrics = generate_stress_pcap(out, profile="smoke", exchanges=20, payload_size=16)
    assert out.is_file()
    assert metrics["packets"] > 20
    assert metrics["bytes"] > 0


def test_observations_api(tmp_path: Path) -> None:
    store = ProjectStore.create(tmp_path / "lab", name="obs")
    path = store.save_observation("note1", {"text": "hypothesis: len at offset 4"})
    assert path in store.list_observations()
