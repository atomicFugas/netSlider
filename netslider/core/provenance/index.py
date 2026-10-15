"""Byte-range ↔ packet provenance index.

Every derived stream byte stores
``(capture_id, session_id, direction, stream_offset, packet_id)``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StreamByteOrigin:
    stream_offset: int
    capture_id: str
    session_id: str
    direction: str
    packet_id: int
    status: str = "ok"  # ok | unknown | ambiguous


@dataclass(frozen=True)
class ProvenanceHit:
    stream_offset: int
    capture_id: str
    session_id: str
    direction: str
    packet_id: int
    note: str = ""


@dataclass
class ProvenanceIndex:
    """Maps stream offsets to originating packets (and secondary hits)."""

    primary: dict[int, StreamByteOrigin] = field(default_factory=dict)
    hits: list[ProvenanceHit] = field(default_factory=list)
    # stream_offset → packet_id for reverse (packet → offsets) built lazily
    _packet_offsets: dict[int, list[int]] = field(default_factory=dict)

    def add(self, origin: StreamByteOrigin) -> None:
        self.primary[origin.stream_offset] = origin
        self._packet_offsets.setdefault(origin.packet_id, []).append(origin.stream_offset)

    def add_hit(self, hit: ProvenanceHit) -> None:
        self.hits.append(hit)

    def mark_ambiguous(self, stream_offset: int, length: int = 1) -> None:
        for off in range(stream_offset, stream_offset + length):
            prev = self.primary.get(off)
            if prev is None:
                continue
            self.primary[off] = StreamByteOrigin(
                stream_offset=prev.stream_offset,
                capture_id=prev.capture_id,
                session_id=prev.session_id,
                direction=prev.direction,
                packet_id=prev.packet_id,
                status="ambiguous",
            )

    def origin_at(self, stream_offset: int) -> StreamByteOrigin | None:
        return self.primary.get(stream_offset)

    def packet_for_offset(self, stream_offset: int) -> int | None:
        origin = self.primary.get(stream_offset)
        return origin.packet_id if origin else None

    def offsets_for_packet(self, packet_id: int) -> list[int]:
        return list(self._packet_offsets.get(packet_id, []))

    def range_for_packet(self, packet_id: int) -> tuple[int, int] | None:
        offs = self.offsets_for_packet(packet_id)
        if not offs:
            return None
        return min(offs), max(offs) + 1
