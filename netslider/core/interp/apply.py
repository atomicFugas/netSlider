"""Apply declarative (or Python) interpretations to directed streams."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from netslider.core.interp.fields import FieldDecodeError, decode_field, decode_value
from netslider.core.interp.framing import frame_stream
from netslider.core.interp.hashutil import content_hash, file_content_hash
from netslider.core.interp.models import (
    ApplyResult,
    ApplyStats,
    FieldValue,
    ParsedMessage,
    ValueStatus,
)
from netslider.core.interp.schema import (
    InterpretationDoc,
    MessageRule,
    WhenClause,
    load_interpretation,
    parse_interpretation_text,
)
from netslider.core.interp.util import (
    direction_str,
    provenance_for_range,
    uncovered_ranges,
)
from netslider.core.tcp.reassembly import DirectedStream
from netslider.core.tcp.session import Direction


def _when_matches(clause: WhenClause | None, body: bytes, fields_so_far: dict[str, Any]) -> bool:
    if clause is None:
        return True
    value: Any
    if clause.field in fields_so_far:
        value = fields_so_far[clause.field]
    elif clause.field == "opcode" and body:
        value = body[0]
    else:
        # Try decoding a u8 at offset 0 as last resort for opcode-style guards
        try:
            value, _ = decode_value(body, 0, "u8")
        except FieldDecodeError:
            return False
    if clause.eq is not None and value != clause.eq:
        return False
    if clause.ne is not None and value == clause.ne:
        return False
    return True


def _match_rule(body: bytes, rules: list[MessageRule]) -> MessageRule | None:
    for rule in rules:
        probe: dict[str, Any] = {}
        if rule.when and rule.when.field == "opcode" and body:
            probe["opcode"] = body[0]
        if _when_matches(rule.when, body, probe):
            return rule
    return None


def _parse_fields(body: bytes, rule: MessageRule | None) -> tuple[list[FieldValue], list[str]]:
    if rule is None:
        fields: list[FieldValue] = []
        notes: list[str] = []
        if body:
            fields.append(
                FieldValue(
                    name="opcode",
                    value=body[0],
                    status=ValueStatus.UNVERIFIED,
                    offset=0,
                    length=1,
                    type_name="u8",
                    note="no matching message rule",
                )
            )
            if len(body) > 1:
                fields.append(
                    FieldValue(
                        name="payload",
                        value=body[1:],
                        status=ValueStatus.UNVERIFIED,
                        offset=1,
                        length=len(body) - 1,
                        type_name="bytes",
                    )
                )
        return fields, notes

    fields = []
    notes = []
    for spec in rule.fields:
        try:
            fields.append(decode_field(body, spec))
        except FieldDecodeError as exc:
            notes.append(str(exc))
            fields.append(
                FieldValue(
                    name=spec.name,
                    value=None,
                    status=ValueStatus.UNVERIFIED,
                    offset=spec.offset,
                    length=0,
                    type_name=spec.type,
                    hypothesis=spec.hypothesis,
                    note=str(exc),
                )
            )
    return fields, notes


def apply_declarative(
    doc: InterpretationDoc,
    stream: DirectedStream,
    *,
    capture_id: str,
    direction: Direction | str | None = None,
    data: bytes | None = None,
) -> ApplyResult:
    """Frame + parse a directed stream with a declarative interpretation."""
    direction_s = direction_str(direction if direction is not None else stream.direction)
    buf = data if data is not None else stream.materialize()
    interp_hash = content_hash(doc.content_for_hash)
    frames = frame_stream(buf, doc.framing)
    messages: list[ParsedMessage] = []
    covered: list[tuple[int, int]] = []
    notes: list[str] = []
    ok = 0
    err = 0

    for fr in frames:
        if fr.span.status == "ok":
            covered.append((fr.span.start, fr.span.end))
            ok += 1
        else:
            err += 1
            notes.append(f"[{fr.span.start}:{fr.span.end}) {fr.span.status}: {fr.span.note}")

        rule = _match_rule(fr.body, doc.messages) if fr.span.status == "ok" else None
        fields, field_notes = _parse_fields(fr.body, rule) if fr.span.status == "ok" else ([], [])
        notes.extend(field_notes)
        opcode = fr.body[0] if fr.body else None
        body_abs = fr.span.start + fr.header_size
        messages.append(
            ParsedMessage(
                span=fr.span,
                fields=fields,
                provenance=provenance_for_range(
                    stream, capture_id, fr.span.start, fr.span.length, direction_s
                ),
                matched_rule=rule.name if rule else None,
                opcode=opcode,
                raw=fr.raw,
                body_offset=body_abs,
            )
        )

    uncovered = uncovered_ranges(len(buf), covered)
    stats = ApplyStats(
        messages_ok=ok,
        messages_error=err,
        bytes_covered=sum(e - s for s, e in covered),
        bytes_total=len(buf),
        uncovered_ranges=uncovered,
    )
    return ApplyResult(
        interpretation_id=doc.id,
        interpretation_hash=interp_hash,
        capture_id=capture_id,
        session_id=stream.session_id,
        direction=direction_s,
        messages=messages,
        stats=stats,
        source="declarative",
        notes=notes,
    )


def apply_interpretation_file(
    path: Path,
    stream: DirectedStream,
    *,
    capture_id: str,
    direction: Direction | str | None = None,
) -> ApplyResult:
    path = path.resolve()
    if path.suffix.lower() == ".py":
        from netslider.core.interp.python_hook import apply_python_script

        return apply_python_script(
            path, stream, capture_id=capture_id, direction=direction
        )
    doc = load_interpretation(path)
    return apply_declarative(doc, stream, capture_id=capture_id, direction=direction)


def apply_interpretation_text(
    text: str,
    stream: DirectedStream,
    *,
    capture_id: str,
    direction: Direction | str | None = None,
) -> ApplyResult:
    doc = parse_interpretation_text(text)
    return apply_declarative(doc, stream, capture_id=capture_id, direction=direction)


def interpretation_hash_for_path(path: Path) -> str:
    return file_content_hash(path)
