"""Small helpers shared by declarative and Python apply paths."""

from __future__ import annotations

from netslider.core.interp.models import ProvenanceRef
from netslider.core.tcp.reassembly import DirectedStream
from netslider.core.tcp.session import Direction


def direction_str(direction: Direction | str) -> str:
    if isinstance(direction, Direction):
        return direction.value
    return str(direction)


def packet_ids_for_range(stream: DirectedStream, start: int, length: int) -> list[int]:
    ids: list[int] = []
    seen: set[int] = set()
    for off in range(start, start + max(0, length)):
        origin = stream.provenance.origin_at(off)
        if origin is None:
            continue
        if origin.packet_id not in seen:
            seen.add(origin.packet_id)
            ids.append(origin.packet_id)
    return ids


def provenance_for_range(
    stream: DirectedStream,
    capture_id: str,
    start: int,
    length: int,
    direction: str,
) -> ProvenanceRef:
    return ProvenanceRef(
        capture_id=capture_id,
        session_id=stream.session_id,
        direction=direction,
        stream_offset=start,
        length=length,
        packet_ids=packet_ids_for_range(stream, start, length),
    )


def uncovered_ranges(total: int, covered: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if total <= 0:
        return []
    marks = [False] * total
    for start, end in covered:
        for i in range(max(0, start), min(total, end)):
            marks[i] = True
    ranges: list[tuple[int, int]] = []
    i = 0
    while i < total:
        if marks[i]:
            i += 1
            continue
        j = i + 1
        while j < total and not marks[j]:
            j += 1
        ranges.append((i, j))
        i = j
    return ranges
