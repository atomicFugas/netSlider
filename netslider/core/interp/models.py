"""Shared interpretation result models (provenance-linked)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ValueStatus(str, Enum):
    OBSERVATION = "observation"
    RULE = "rule"
    HYPOTHESIS = "hypothesis"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class ProvenanceRef:
    """Byte-range provenance for a derived message / field."""

    capture_id: str
    session_id: str
    direction: str
    stream_offset: int
    length: int
    packet_ids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FieldValue:
    name: str
    value: Any
    status: ValueStatus
    offset: int  # relative to message body start
    length: int
    type_name: str
    hypothesis: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": _jsonable(self.value),
            "status": self.status.value,
            "offset": self.offset,
            "length": self.length,
            "type": self.type_name,
            "hypothesis": self.hypothesis,
            "note": self.note or None,
        }


@dataclass
class MessageSpan:
    start: int
    end: int
    status: str = "ok"  # ok | incomplete | bad_magic | error
    note: str = ""

    @property
    def length(self) -> int:
        return max(0, self.end - self.start)


@dataclass
class ParsedMessage:
    span: MessageSpan
    fields: list[FieldValue]
    provenance: ProvenanceRef
    matched_rule: str | None = None
    opcode: int | None = None
    raw: bytes = b""
    body_offset: int = 0  # absolute stream offset where body (fields) begin

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.span.start,
            "end": self.span.end,
            "status": self.span.status,
            "note": self.span.note or None,
            "opcode": self.opcode,
            "matched_rule": self.matched_rule,
            "body_offset": self.body_offset,
            "fields": [f.to_dict() for f in self.fields],
            "provenance": self.provenance.to_dict(),
        }


@dataclass
class ApplyStats:
    messages_ok: int = 0
    messages_error: int = 0
    bytes_covered: int = 0
    bytes_total: int = 0
    uncovered_ranges: list[tuple[int, int]] = field(default_factory=list)

    @property
    def coverage(self) -> float:
        if self.bytes_total <= 0:
            return 0.0
        return self.bytes_covered / self.bytes_total

    def to_dict(self) -> dict[str, Any]:
        return {
            "messages_ok": self.messages_ok,
            "messages_error": self.messages_error,
            "bytes_covered": self.bytes_covered,
            "bytes_total": self.bytes_total,
            "coverage": round(self.coverage, 4),
            "uncovered_ranges": [list(r) for r in self.uncovered_ranges],
        }


@dataclass
class ApplyResult:
    interpretation_id: str
    interpretation_hash: str
    capture_id: str
    session_id: str
    direction: str
    messages: list[ParsedMessage] = field(default_factory=list)
    stats: ApplyStats = field(default_factory=ApplyStats)
    source: str = "declarative"  # declarative | python
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "interpretation_id": self.interpretation_id,
            "interpretation_hash": self.interpretation_hash,
            "capture_id": self.capture_id,
            "session_id": self.session_id,
            "direction": self.direction,
            "source": self.source,
            "stats": self.stats.to_dict(),
            "notes": list(self.notes),
            "messages": [m.to_dict() for m in self.messages],
        }


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, (str, float, bool)) or value is None:
        return value
    return str(value)
