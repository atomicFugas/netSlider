"""Directed TCP stream reassembly (RFC 9293-inspired).

Policies
--------
- Order by sequence number; consume contiguous payload into the stream.
- Identical retransmits are deduplicated (dropped, noted).
- Gaps / truncation → ``UNKNOWN`` spans (never zero-filled).
- Overlapping different data → ``AMBIGUOUS``; default overlap policy
  ``first_seen`` keeps earlier bytes and flags the conflict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from netslider.core.pcap.models import PacketRecord
from netslider.core.provenance.index import ProvenanceHit, ProvenanceIndex, StreamByteOrigin
from netslider.core.tcp.session import Direction, TcpSession


class SpanStatus(Enum):
    OK = "ok"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"


@dataclass
class StreamSpan:
    stream_offset: int
    length: int
    status: SpanStatus
    data: bytes | None  # None for UNKNOWN
    packet_ids: list[int] = field(default_factory=list)
    note: str = ""


@dataclass
class DirectedStream:
    session_id: str
    direction: Direction
    spans: list[StreamSpan] = field(default_factory=list)
    provenance: ProvenanceIndex = field(default_factory=ProvenanceIndex)
    next_seq: int | None = None
    isn: int | None = None
    defects: list[str] = field(default_factory=list)
    bytes_ok: int = 0
    bytes_unknown: int = 0
    bytes_ambiguous: int = 0

    @property
    def length(self) -> int:
        if not self.spans:
            return 0
        last = self.spans[-1]
        return last.stream_offset + last.length

    def materialize(self) -> bytes:
        """Joined view: OK/AMBIGUOUS chosen bytes; UNKNOWN filled with 0x3F ('?').

        Raw captures are never modified; this is a display/analysis buffer only.
        """
        out = bytearray()
        for span in self.spans:
            if span.status == SpanStatus.UNKNOWN or span.data is None:
                out.extend(b"?" * span.length)
            else:
                out.extend(span.data)
        return bytes(out)


@dataclass
class SessionStreams:
    session: TcpSession
    a_to_b: DirectedStream
    b_to_a: DirectedStream
    error: str | None = None


def _seq_lt(a: int, b: int) -> bool:
    """Sequence comparison with wrap (RFC 1982 style for 32-bit)."""
    return ((a - b) & 0xFFFFFFFF) > 0x80000000


def _seq_le(a: int, b: int) -> bool:
    return a == b or _seq_lt(a, b)


def _seq_add(seq: int, n: int) -> int:
    return (seq + n) & 0xFFFFFFFF


class DirectedReassembler:
    def __init__(
        self,
        session_id: str,
        direction: Direction,
        capture_id: str,
        overlap_policy: str = "first_seen",
    ) -> None:
        self.stream = DirectedStream(session_id=session_id, direction=direction)
        self.capture_id = capture_id
        self.overlap_policy = overlap_policy
        # Map absolute TCP seq → (stream_offset, byte) for overlap checks on buffered data
        self._stream_bytes: dict[int, tuple[int, int, int]] = {}  # seq -> (soff, byte, pkt_id)
        self._cursor = 0  # next stream offset
        self._expected_seq: int | None = None
        # Out-of-order segments: (payload_seq, payload, packet)
        self._ooo: list[tuple[int, bytes, PacketRecord]] = []

    def _emit_unknown(self, length: int, note: str) -> None:
        if length <= 0:
            return
        self.stream.spans.append(
            StreamSpan(
                stream_offset=self._cursor,
                length=length,
                status=SpanStatus.UNKNOWN,
                data=None,
                note=note,
            )
        )
        self.stream.bytes_unknown += length
        self.stream.defects.append(f"UNKNOWN gap {length}B @ stream {self._cursor}: {note}")
        self._cursor += length

    def _emit_data(
        self,
        data: bytes,
        packet_id: int,
        seq_start: int,
        status: SpanStatus = SpanStatus.OK,
        note: str = "",
    ) -> None:
        if not data:
            return
        soff = self._cursor
        self.stream.spans.append(
            StreamSpan(
                stream_offset=soff,
                length=len(data),
                status=status,
                data=data,
                packet_ids=[packet_id],
                note=note,
            )
        )
        if status == SpanStatus.OK:
            self.stream.bytes_ok += len(data)
        elif status == SpanStatus.AMBIGUOUS:
            self.stream.bytes_ambiguous += len(data)

        for i, b in enumerate(data):
            seq = _seq_add(seq_start, i)
            stream_off = soff + i
            self._stream_bytes[seq] = (stream_off, b, packet_id)
            self.stream.provenance.add(
                StreamByteOrigin(
                    stream_offset=stream_off,
                    capture_id=self.capture_id,
                    session_id=self.stream.session_id,
                    direction=self.stream.direction.value,
                    packet_id=packet_id,
                    status=status.value,
                )
            )
        self._cursor += len(data)

    def _note_expected(self, payload_seq: int) -> None:
        if self._expected_seq is None:
            self._expected_seq = payload_seq
            self.stream.isn = payload_seq
            self.stream.next_seq = payload_seq

    def _advance_after_data(self, payload_seq: int, payload: bytes) -> None:
        self._expected_seq = _seq_add(payload_seq, len(payload))
        self.stream.next_seq = self._expected_seq

    def _drain_ooo(self, *, commit_gaps: bool) -> None:
        """Emit buffered segments that are now contiguous; optionally commit holes."""
        if self._expected_seq is None or not self._ooo:
            return
        self._ooo.sort(key=lambda item: item[0])
        progressed = True
        while progressed and self._ooo:
            progressed = False
            expected = self._expected_seq
            assert expected is not None
            nxt_seq, nxt_payload, nxt_pkt = self._ooo[0]
            end_seq = _seq_add(nxt_seq, len(nxt_payload))

            if _seq_le(end_seq, expected):
                self._ooo.pop(0)
                self._handle_retransmit_or_overlap(nxt_pkt, nxt_seq, nxt_payload, expected)
                progressed = True
                continue

            if _seq_lt(nxt_seq, expected):
                self._ooo.pop(0)
                skip = (expected - nxt_seq) & 0xFFFFFFFF
                if skip < len(nxt_payload):
                    self._handle_retransmit_or_overlap(
                        nxt_pkt, nxt_seq, nxt_payload[:skip], expected
                    )
                    tail = nxt_payload[skip:]
                    self._emit_data(tail, nxt_pkt.packet_id, expected, SpanStatus.OK)
                    self._advance_after_data(expected, tail)
                else:
                    self._handle_retransmit_or_overlap(
                        nxt_pkt, nxt_seq, nxt_payload, expected
                    )
                progressed = True
                continue

            if nxt_seq == expected:
                self._ooo.pop(0)
                self._emit_data(nxt_payload, nxt_pkt.packet_id, nxt_seq, SpanStatus.OK)
                self._advance_after_data(nxt_seq, nxt_payload)
                progressed = True
                continue

            # Future segment — wait unless finishing the capture
            if not commit_gaps:
                break
            gap = (nxt_seq - expected) & 0xFFFFFFFF
            if gap > 16 * 1024 * 1024:
                self.stream.defects.append(
                    f"implausible gap {gap} from pkt {nxt_pkt.packet_id}; dropping buffered"
                )
                self._ooo.pop(0)
                progressed = True
                continue
            self._emit_unknown(gap, f"seq gap before pkt {nxt_pkt.packet_id}")
            self._expected_seq = nxt_seq
            self._ooo.pop(0)
            self._emit_data(nxt_payload, nxt_pkt.packet_id, nxt_seq, SpanStatus.OK)
            self._advance_after_data(nxt_seq, nxt_payload)
            progressed = True

    def finish(self) -> None:
        """Commit remaining out-of-order buffer; unfilled holes become UNKNOWN."""
        self._drain_ooo(commit_gaps=True)

    def feed(self, pkt: PacketRecord, payload_seq: int) -> None:
        """Feed one segment. *payload_seq* is the SEQ of the first payload byte
        (already advanced past SYN if applicable)."""
        assert pkt.tcp is not None
        payload = pkt.tcp.payload
        if not payload:
            # SYN (no payload) establishes the first expected data sequence.
            if pkt.syn:
                self._note_expected(payload_seq)
            return

        if self._expected_seq is None:
            self._note_expected(payload_seq)

        expected = self._expected_seq
        assert expected is not None
        end_seq = _seq_add(payload_seq, len(payload))

        # Fully at-or-before expected end → retransmit / overlap only
        if _seq_le(end_seq, expected):
            self._handle_retransmit_or_overlap(pkt, payload_seq, payload, expected)
            return

        # Starts before expected but extends past → check overlap, then append tail
        if _seq_lt(payload_seq, expected):
            skip = (expected - payload_seq) & 0xFFFFFFFF
            if skip >= len(payload):
                self._handle_retransmit_or_overlap(pkt, payload_seq, payload, expected)
                return
            self._handle_retransmit_or_overlap(pkt, payload_seq, payload[:skip], expected)
            payload = payload[skip:]
            payload_seq = expected

        # Future data — buffer for reorder; gaps committed in finish()
        if payload_seq != expected:
            gap = (payload_seq - expected) & 0xFFFFFFFF
            if gap > 16 * 1024 * 1024:
                self.stream.defects.append(
                    f"implausible gap {gap} from pkt {pkt.packet_id}; skipping segment"
                )
                return
            self._ooo.append((payload_seq, payload, pkt))
            self.stream.defects.append(
                f"out-of-order buffered pkt {pkt.packet_id} seq={payload_seq}"
            )
            return

        self._emit_data(payload, pkt.packet_id, payload_seq, SpanStatus.OK)
        self._advance_after_data(payload_seq, payload)
        self._drain_ooo(commit_gaps=False)

    def _upgrade_spans_ambiguous(self, offsets: set[int]) -> None:
        """Upgrade OK spans that cover conflicted offsets to AMBIGUOUS (keep bytes)."""
        if not offsets:
            return
        for span in self.stream.spans:
            if span.status != SpanStatus.OK:
                continue
            end = span.stream_offset + span.length
            if any(span.stream_offset <= off < end for off in offsets):
                span.status = SpanStatus.AMBIGUOUS
                if span.note:
                    span.note = f"{span.note}; overlap conflict"
                else:
                    span.note = "overlap conflict"
                # Counters: move covered OK bytes that conflicted into ambiguous already
                # counted per-byte above; adjust bytes_ok for whole span once.
                self.stream.bytes_ok = max(0, self.stream.bytes_ok - span.length)

    def _handle_retransmit_or_overlap(
        self,
        pkt: PacketRecord,
        payload_seq: int,
        payload: bytes,
        expected: int,
    ) -> None:
        conflicts = 0
        identical = 0
        conflict_offsets: set[int] = set()
        for i, b in enumerate(payload):
            seq = _seq_add(payload_seq, i)
            if _seq_le(expected, seq) and seq != expected and not _seq_lt(seq, expected):
                # past expected — shouldn't happen in this helper
                continue
            prev = self._stream_bytes.get(seq)
            if prev is None:
                continue
            soff, old_b, old_pkt = prev
            if old_b == b:
                identical += 1
                self.stream.provenance.add_hit(
                    ProvenanceHit(
                        stream_offset=soff,
                        capture_id=self.capture_id,
                        session_id=self.stream.session_id,
                        direction=self.stream.direction.value,
                        packet_id=pkt.packet_id,
                        note="retransmit identical",
                    )
                )
            else:
                conflicts += 1
                if self.overlap_policy == "first_seen":
                    # keep old byte; mark span region ambiguous in provenance
                    self.stream.provenance.mark_ambiguous(soff, 1)
                    conflict_offsets.add(soff)
                    self.stream.defects.append(
                        f"AMBIGUOUS seq={seq} pkt {old_pkt} vs {pkt.packet_id} "
                        f"(kept first-seen 0x{old_b:02x}, saw 0x{b:02x})"
                    )
                    self.stream.bytes_ambiguous += 1
                else:
                    # last_seen — rewrite materialization is complex; flag only for now
                    self.stream.defects.append(
                        f"AMBIGUOUS seq={seq} last_seen not fully applied"
                    )
                    conflict_offsets.add(soff)

        if conflicts == 0 and identical:
            self.stream.defects.append(
                f"retransmit deduped pkt {pkt.packet_id} ({identical}B identical)"
            )
        elif conflicts:
            self._upgrade_spans_ambiguous(conflict_offsets)


def payload_seq_for(pkt: PacketRecord, isn_syn: bool) -> int:
    """SEQ of first payload byte. SYN consumes one sequence number."""
    assert pkt.tcp is not None
    seq = pkt.tcp.seq
    if pkt.syn:
        return _seq_add(seq, 1)
    return seq


def reassemble_session(
    session: TcpSession,
    packets: list[PacketRecord],
    *,
    capture_id: str,
    overlap_policy: str = "first_seen",
) -> SessionStreams:
    """Reassemble both directions. Isolates errors per session."""
    endpoints = session.key.endpoints
    a_to_b = DirectedReassembler(
        session.key.session_id, Direction.A_TO_B, capture_id, overlap_policy
    )
    b_to_a = DirectedReassembler(
        session.key.session_id, Direction.B_TO_A, capture_id, overlap_policy
    )

    error: str | None = None
    try:
        for pkt in packets:
            if pkt.tcp is None or pkt.ipv4 is None:
                continue
            direction = endpoints.direction_of(
                pkt.ipv4.src, pkt.tcp.src_port, pkt.ipv4.dst, pkt.tcp.dst_port
            )
            if direction is None:
                continue
            pseq = payload_seq_for(pkt, isn_syn=pkt.syn)
            if direction == Direction.A_TO_B:
                a_to_b.feed(pkt, pseq)
            else:
                b_to_a.feed(pkt, pseq)
        a_to_b.finish()
        b_to_a.finish()
    except Exception as exc:  # isolate session failure
        error = f"reassembly failed: {exc}"

    return SessionStreams(
        session=session,
        a_to_b=a_to_b.stream,
        b_to_a=b_to_a.stream,
        error=error,
    )


def reassemble_all(
    sessions: list[TcpSession],
    packets_by_session: dict[str, list[PacketRecord]],
    *,
    capture_id: str,
    overlap_policy: str = "first_seen",
) -> list[SessionStreams]:
    results: list[SessionStreams] = []
    for sess in sessions:
        pkts = packets_by_session.get(sess.key.session_id, [])
        try:
            results.append(
                reassemble_session(
                    sess, pkts, capture_id=capture_id, overlap_policy=overlap_policy
                )
            )
        except Exception as exc:
            results.append(
                SessionStreams(
                    session=sess,
                    a_to_b=DirectedStream(sess.key.session_id, Direction.A_TO_B),
                    b_to_a=DirectedStream(sess.key.session_id, Direction.B_TO_A),
                    error=str(exc),
                )
            )
    return results
