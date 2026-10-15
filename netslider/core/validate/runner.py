"""Corpus validation: apply an interpretation across selected sessions."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable

from netslider.core.interp.apply import apply_declarative, apply_interpretation_file
from netslider.core.interp.hashutil import content_hash
from netslider.core.interp.models import ApplyResult, ValueStatus
from netslider.core.interp.schema import InterpretationDoc, load_interpretation
from netslider.core.tcp.reassembly import DirectedStream, SpanStatus
from netslider.core.tcp.session import Direction
from netslider.core.validate.result import ValidationCounters, ValidationHit, ValidationResult
from netslider.core.workspace import CaptureWorkspace, build_workspace_from_path


def _stream_pair(workspace: CaptureWorkspace, session_id: str) -> tuple[DirectedStream, DirectedStream] | None:
    bundle = workspace.stream_for(session_id)
    if bundle is None:
        return None
    return bundle.a_to_b, bundle.b_to_a


def _reassembly_hits(
    stream: DirectedStream,
    capture_id: str,
    direction: str,
) -> tuple[list[ValidationHit], int, int]:
    """Count UNKNOWN / AMBIGUOUS reassembly bytes as validation hits."""
    hits: list[ValidationHit] = []
    unknown = 0
    ambiguous = 0
    for span in stream.spans:
        if span.status == SpanStatus.UNKNOWN:
            unknown += span.length
            hits.append(
                ValidationHit(
                    kind="unknown",
                    capture_id=capture_id,
                    session_id=stream.session_id,
                    direction=direction,
                    stream_offset=span.stream_offset,
                    length=span.length,
                    note=span.note or "UNKNOWN reassembly span",
                    packet_ids=list(span.packet_ids),
                )
            )
        elif span.status == SpanStatus.AMBIGUOUS:
            ambiguous += span.length
            hits.append(
                ValidationHit(
                    kind="ambiguous",
                    capture_id=capture_id,
                    session_id=stream.session_id,
                    direction=direction,
                    stream_offset=span.stream_offset,
                    length=span.length,
                    note=span.note or "AMBIGUOUS reassembly span",
                    packet_ids=list(span.packet_ids),
                )
            )
    return hits, unknown, ambiguous


def _classify_apply(result: ApplyResult) -> tuple[list[ValidationHit], ValidationCounters]:
    hits: list[ValidationHit] = []
    counters = ValidationCounters()

    for msg in result.messages:
        kind = "ok"
        note = msg.span.note
        if msg.span.status != "ok":
            kind = "contradict"
            note = note or msg.span.status
        elif any(f.value is None or f.status == ValueStatus.UNVERIFIED and f.note for f in msg.fields):
            # Field decode failure → contradict
            bad = [f for f in msg.fields if f.value is None or f.note]
            if any(f.value is None for f in msg.fields):
                kind = "contradict"
                note = "; ".join(f.note for f in bad if f.note) or "field decode failed"
        if kind == "ok":
            counters.ok += 1
        else:
            counters.contradict += 1
        hits.append(
            ValidationHit(
                kind=kind,
                capture_id=result.capture_id,
                session_id=result.session_id,
                direction=result.direction,
                stream_offset=msg.span.start,
                length=msg.span.length,
                note=note,
                matched_rule=msg.matched_rule,
                opcode=msg.opcode,
                packet_ids=list(msg.provenance.packet_ids),
            )
        )

    for start, end in result.stats.uncovered_ranges:
        length = end - start
        if length <= 0:
            continue
        counters.uncovered += length
        hits.append(
            ValidationHit(
                kind="uncovered",
                capture_id=result.capture_id,
                session_id=result.session_id,
                direction=result.direction,
                stream_offset=start,
                length=length,
                note="bytes not covered by framed messages",
            )
        )

    return hits, counters


def validate_stream(
    doc: InterpretationDoc | Path,
    stream: DirectedStream,
    *,
    capture_id: str,
    direction: Direction | str | None = None,
) -> ValidationResult:
    """Validate a single directed stream."""
    if isinstance(doc, Path):
        path = doc
        if path.suffix.lower() == ".py":
            apply_result = apply_interpretation_file(
                path, stream, capture_id=capture_id, direction=direction
            )
            interp_id = path.stem
            interp_hash = apply_result.interpretation_hash
        else:
            loaded = load_interpretation(path)
            apply_result = apply_declarative(
                loaded, stream, capture_id=capture_id, direction=direction
            )
            interp_id = loaded.id
            interp_hash = apply_result.interpretation_hash
    else:
        apply_result = apply_declarative(
            doc, stream, capture_id=capture_id, direction=direction
        )
        interp_id = doc.id
        interp_hash = apply_result.interpretation_hash

    hits, counters = _classify_apply(apply_result)
    dir_s = apply_result.direction
    re_hits, unk, amb = _reassembly_hits(stream, capture_id, dir_s)
    hits.extend(re_hits)
    counters.unknown += unk
    counters.ambiguous += amb

    return ValidationResult(
        interpretation_id=interp_id,
        interpretation_hash=interp_hash,
        filters={"capture_id": capture_id, "session_id": stream.session_id, "direction": dir_s},
        counters=counters,
        hits=hits,
    )


def validate_workspace(
    doc: InterpretationDoc | Path,
    workspace: CaptureWorkspace,
    *,
    session_ids: Iterable[str] | None = None,
    directions: Iterable[Direction] | None = None,
) -> ValidationResult:
    """Apply interpretation to selected sessions/directions in a workspace."""
    dirs = list(directions) if directions is not None else [Direction.A_TO_B, Direction.B_TO_A]
    selected = (
        list(session_ids)
        if session_ids is not None
        else [s.key.session_id for s in workspace.sessions.sessions]
    )

    if isinstance(doc, Path):
        path = doc
        if path.suffix.lower() == ".py":
            interp_id = path.stem
            # Hash filled from first apply
            interp_hash = ""
            doc_obj: InterpretationDoc | None = None
            py_path: Path | None = path
        else:
            doc_obj = load_interpretation(path)
            interp_id = doc_obj.id
            interp_hash = content_hash(doc_obj.content_for_hash)
            py_path = None
    else:
        doc_obj = doc
        interp_id = doc.id
        interp_hash = content_hash(doc.content_for_hash)
        py_path = None

    merged = ValidationCounters()
    hits: list[ValidationHit] = []
    notes: list[str] = []
    capture_id = workspace.capture.capture_id

    for sid in selected:
        pair = _stream_pair(workspace, sid)
        if pair is None:
            merged.inapplicable += 1
            hits.append(
                ValidationHit(
                    kind="inapplicable",
                    capture_id=capture_id,
                    session_id=sid,
                    direction="",
                    stream_offset=0,
                    length=0,
                    note="session not found in workspace",
                )
            )
            continue
        bundle = workspace.stream_for(sid)
        if bundle and bundle.error:
            notes.append(f"{sid}: {bundle.error}")
            merged.inapplicable += 1
            hits.append(
                ValidationHit(
                    kind="inapplicable",
                    capture_id=capture_id,
                    session_id=sid,
                    direction="",
                    stream_offset=0,
                    length=0,
                    note=bundle.error,
                )
            )
            continue

        a_to_b, b_to_a = pair
        for direction in dirs:
            stream = a_to_b if direction == Direction.A_TO_B else b_to_a
            if stream.length == 0:
                continue
            if py_path is not None:
                one = validate_stream(py_path, stream, capture_id=capture_id, direction=direction)
            else:
                assert doc_obj is not None
                one = validate_stream(doc_obj, stream, capture_id=capture_id, direction=direction)
            if not interp_hash:
                interp_hash = one.interpretation_hash
            c = one.counters
            merged.ok += c.ok
            merged.contradict += c.contradict
            merged.uncovered += c.uncovered
            merged.unknown += c.unknown
            merged.ambiguous += c.ambiguous
            merged.inapplicable += c.inapplicable
            hits.extend(one.hits)

    return ValidationResult(
        interpretation_id=interp_id,
        interpretation_hash=interp_hash,
        filters={
            "capture_id": capture_id,
            "session_ids": selected,
            "directions": [d.value for d in dirs],
        },
        counters=merged,
        hits=hits,
        notes=notes,
    )


def validate_project_captures(
    doc: InterpretationDoc | Path,
    capture_paths: Iterable[Path],
    *,
    settings: dict[str, Any] | None = None,
    session_ids: Iterable[str] | None = None,
    directions: Iterable[Direction] | None = None,
    progress: Callable[[str], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> ValidationResult:
    """Validate an interpretation across multiple capture files and merge results."""
    paths = [Path(p) for p in capture_paths]
    if not paths:
        raise ValueError("No capture paths provided for corpus validation")

    if isinstance(doc, Path):
        path = doc
        if path.suffix.lower() == ".py":
            interp_id = path.stem
            interp_hash = ""
        else:
            loaded = load_interpretation(path)
            interp_id = loaded.id
            interp_hash = content_hash(loaded.content_for_hash)
    else:
        interp_id = doc.id
        interp_hash = content_hash(doc.content_for_hash)

    merged = ValidationCounters()
    hits: list[ValidationHit] = []
    notes: list[str] = []
    capture_ids: list[str] = []

    for i, cap_path in enumerate(paths):
        if cancel_check and cancel_check():
            raise InterruptedError("cancelled")
        if progress:
            progress(f"Validating capture {i + 1}/{len(paths)}: {cap_path.name}…")
        try:
            workspace = build_workspace_from_path(
                cap_path,
                settings=settings,
                cancel_check=cancel_check,
            )
        except InterruptedError:
            raise
        except Exception as exc:
            notes.append(f"{cap_path.name}: {exc}")
            merged.inapplicable += 1
            hits.append(
                ValidationHit(
                    kind="inapplicable",
                    capture_id=cap_path.stem,
                    session_id="",
                    direction="",
                    stream_offset=0,
                    length=0,
                    note=str(exc),
                )
            )
            continue

        capture_ids.append(workspace.capture.capture_id)
        one = validate_workspace(
            doc,
            workspace,
            session_ids=session_ids,
            directions=directions,
        )
        if not interp_hash:
            interp_hash = one.interpretation_hash
        c = one.counters
        merged.ok += c.ok
        merged.contradict += c.contradict
        merged.uncovered += c.uncovered
        merged.unknown += c.unknown
        merged.ambiguous += c.ambiguous
        merged.inapplicable += c.inapplicable
        hits.extend(one.hits)
        notes.extend(one.notes)

    dirs = list(directions) if directions is not None else [Direction.A_TO_B, Direction.B_TO_A]
    return ValidationResult(
        interpretation_id=interp_id,
        interpretation_hash=interp_hash,
        filters={
            "capture_ids": capture_ids,
            "capture_paths": [p.name for p in paths],
            "session_ids": list(session_ids) if session_ids is not None else None,
            "directions": [d.value for d in dirs],
        },
        counters=merged,
        hits=hits,
        notes=notes,
    )


def refresh_stale(result: ValidationResult, current_hash: str) -> ValidationResult:
    """Return a copy-ish update marking stale when hashes diverge."""
    result.mark_stale_if_needed(current_hash)
    return result
