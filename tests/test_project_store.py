"""Phase 0: portable project open/save."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from madrigal.core.project import ProjectError, ProjectStore


def test_create_open_roundtrip(tmp_path: Path) -> None:
    root = tmp_path / "lab"
    store = ProjectStore.create(root, name="demo", description="phase0")
    assert (root / "project.madrigal.json").is_file()
    assert (root / "settings.json").is_file()
    for sub in ("captures", "action_logs", "interpretations", "observations", "validations"):
        assert (root / sub).is_dir()

    opened = ProjectStore.open(root)
    assert opened.meta.name == "demo"
    assert opened.meta.description == "phase0"
    assert opened.settings["tcp"]["overlap_policy"] == "first_seen"


def test_create_rejects_nonempty(tmp_path: Path) -> None:
    root = tmp_path / "busy"
    root.mkdir()
    (root / "noise.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ProjectError):
        ProjectStore.create(root, name="x")


def test_import_capture_copies(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    store = ProjectStore.create(root, name="p")
    src = tmp_path / "sample.pcap"
    src.write_bytes(b"\x00" * 24)
    dest = store.import_capture(src)
    assert dest.is_file()
    assert dest != src
    assert "captures/sample.pcap" in store.meta.captures
    data = json.loads((root / "project.madrigal.json").read_text(encoding="utf-8"))
    assert "captures/sample.pcap" in data["captures"]


def test_open_missing_manifest(tmp_path: Path) -> None:
    with pytest.raises(ProjectError):
        ProjectStore.open(tmp_path)


def test_save_interpretation_and_validation(tmp_path: Path) -> None:
    store = ProjectStore.create(tmp_path / "proj", name="p")
    dest = store.save_interpretation(
        "demo.yaml",
        "id: demo\nframing:\n  type: length_prefixed\n  header: {magic: MD01, len_offset: 4, len_size: 2}\nmessages: []\n",
    )
    assert dest.name == "demo.yaml"
    assert store.list_interpretations()
    v = store.save_validation("run.json", {"ok": 1, "stale": False})
    assert v.is_file()
    assert store.load_validation_json(v)["ok"] == 1
