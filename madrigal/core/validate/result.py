"""Corpus validation result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class ValidationCounters:
    ok: int = 0
    contradict: int = 0
    uncovered: int = 0
    unknown: int = 0
    ambiguous: int = 0
    inapplicable: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationCounters:
        return cls(
            ok=int(data.get("ok", 0)),
            contradict=int(data.get("contradict", 0)),
            uncovered=int(data.get("uncovered", 0)),
            unknown=int(data.get("unknown", 0)),
            ambiguous=int(data.get("ambiguous", 0)),
            inapplicable=int(data.get("inapplicable", 0)),
        )


@dataclass
class ValidationHit:
    """One drill-down row (message or stream region)."""

    kind: str  # ok | contradict | uncovered | unknown | ambiguous | inapplicable
    capture_id: str
    session_id: str
    direction: str
    stream_offset: int
    length: int
    note: str = ""
    matched_rule: str | None = None
    opcode: int | None = None
    packet_ids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "capture_id": self.capture_id,
            "session_id": self.session_id,
            "direction": self.direction,
            "stream_offset": self.stream_offset,
            "length": self.length,
            "note": self.note or None,
            "matched_rule": self.matched_rule,
            "opcode": self.opcode,
            "packet_ids": list(self.packet_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationHit:
        return cls(
            kind=str(data.get("kind", "ok")),
            capture_id=str(data.get("capture_id", "")),
            session_id=str(data.get("session_id", "")),
            direction=str(data.get("direction", "")),
            stream_offset=int(data.get("stream_offset", 0)),
            length=int(data.get("length", 0)),
            note=str(data.get("note") or ""),
            matched_rule=data.get("matched_rule"),
            opcode=data.get("opcode"),
            packet_ids=list(data.get("packet_ids") or []),
        )


@dataclass
class ValidationResult:
    interpretation_id: str
    interpretation_hash: str
    created_at: str = field(default_factory=_utc_now_iso)
    filters: dict[str, Any] = field(default_factory=dict)
    counters: ValidationCounters = field(default_factory=ValidationCounters)
    hits: list[ValidationHit] = field(default_factory=list)
    stale: bool = False
    notes: list[str] = field(default_factory=list)

    def mark_stale_if_needed(self, current_hash: str) -> bool:
        self.stale = self.interpretation_hash != current_hash
        return self.stale

    def to_dict(self) -> dict[str, Any]:
        return {
            "interpretation_id": self.interpretation_id,
            "interpretation_hash": self.interpretation_hash,
            "created_at": self.created_at,
            "filters": dict(self.filters),
            "counters": self.counters.to_dict(),
            "hits": [h.to_dict() for h in self.hits],
            "stale": self.stale,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationResult:
        return cls(
            interpretation_id=str(data.get("interpretation_id", "")),
            interpretation_hash=str(data.get("interpretation_hash", "")),
            created_at=str(data.get("created_at", "")),
            filters=dict(data.get("filters") or {}),
            counters=ValidationCounters.from_dict(data.get("counters") or {}),
            hits=[ValidationHit.from_dict(h) for h in (data.get("hits") or [])],
            stale=bool(data.get("stale", False)),
            notes=list(data.get("notes") or []),
        )
