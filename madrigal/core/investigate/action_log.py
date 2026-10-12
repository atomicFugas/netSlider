"""Action log loaders (JSON v1 + simple CSV)."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ActionEvent:
    seq: int
    ts_epoch: float
    ts_raw: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    note: str = ""

    def summary(self) -> str:
        bits = [self.action]
        if self.params:
            bits.append(str(self.params))
        if self.note:
            bits.append(f"({self.note})")
        return " ".join(bits)


@dataclass
class ActionLog:
    path: str
    format: str
    device: str = ""
    events: list[ActionEvent] = field(default_factory=list)


def _parse_ts(value: str | float | int) -> tuple[float, str]:
    if isinstance(value, (int, float)):
        return float(value), str(value)
    text = str(value).strip()
    if not text:
        raise ValueError("empty timestamp")
    # numeric string
    try:
        return float(text), text
    except ValueError:
        pass
    # ISO-8601
    normalized = text.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    return dt.timestamp(), text


def load_action_log(path: Path | str) -> ActionLog:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _load_json(path)
    if suffix == ".csv":
        return _load_csv(path)
    # sniff
    head = path.read_text(encoding="utf-8")[:64].lstrip()
    if head.startswith("{") or head.startswith("["):
        return _load_json(path)
    return _load_csv(path)


def _load_json(path: Path) -> ActionLog:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        raw_events = data
        fmt = "list"
        device = ""
    else:
        raw_events = data.get("events", [])
        fmt = str(data.get("format", "json"))
        device = str(data.get("device", ""))
    events: list[ActionEvent] = []
    for i, row in enumerate(raw_events, start=1):
        ts_epoch, ts_raw = _parse_ts(row.get("ts") or row.get("timestamp") or row.get("time"))
        events.append(
            ActionEvent(
                seq=int(row.get("seq", i)),
                ts_epoch=ts_epoch,
                ts_raw=ts_raw,
                action=str(row.get("action", row.get("name", "unknown"))),
                params=dict(row.get("params") or {}),
                result=dict(row.get("result") or {}),
                note=str(row.get("note", "")),
            )
        )
    events.sort(key=lambda e: (e.ts_epoch, e.seq))
    return ActionLog(path=str(path), format=fmt, device=device, events=events)


def _load_csv(path: Path) -> ActionLog:
    events: list[ActionEvent] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for i, row in enumerate(reader, start=1):
            ts_key = next((k for k in ("ts", "timestamp", "time") if k in row and row[k]), None)
            if ts_key is None:
                continue
            ts_epoch, ts_raw = _parse_ts(row[ts_key])
            action = row.get("action") or row.get("name") or "unknown"
            params = {k: v for k, v in row.items() if k not in {ts_key, "action", "name", "note", "seq"} and v}
            events.append(
                ActionEvent(
                    seq=int(row["seq"]) if row.get("seq") else i,
                    ts_epoch=ts_epoch,
                    ts_raw=ts_raw,
                    action=str(action),
                    params=params,
                    result={},
                    note=str(row.get("note", "")),
                )
            )
    events.sort(key=lambda e: (e.ts_epoch, e.seq))
    return ActionLog(path=str(path), format="csv", events=events)
