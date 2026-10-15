"""Time-align action log events to capture packets / stream ranges."""

from __future__ import annotations

from dataclasses import dataclass, field

from netslider.core.investigate.action_log import ActionEvent, ActionLog
from netslider.core.pcap.models import PacketRecord
from netslider.core.tcp.reassembly import DirectedStream
from netslider.core.tcp.session import TcpSession


@dataclass
class AlignedAction:
    event: ActionEvent
    aligned_ts: float
    packet_ids: list[int] = field(default_factory=list)
    stream_ranges: list[tuple[str, int, int]] = field(default_factory=list)
    # (direction_label, start, end)
    note: str = ""


@dataclass
class AlignmentResult:
    mode: str
    offset: float  # added to action ts_epoch → capture time domain
    window_s: float
    actions: list[AlignedAction] = field(default_factory=list)


def _capture_span(packets: list[PacketRecord]) -> tuple[float, float] | None:
    ts = [p.ts for p in packets]
    if not ts:
        return None
    return min(ts), max(ts)


def compute_offset(
    events: list[ActionEvent],
    packets: list[PacketRecord],
    mode: str = "relative",
) -> float:
    """Return offset such that ``action.ts_epoch + offset`` ≈ capture time."""
    if not events or not packets:
        return 0.0
    if mode == "absolute":
        return 0.0
    # Relative: pin first meaningful action to first payload-bearing packet.
    # Handshake-only packets at capture start would otherwise skew the window.
    payload_pkts = [p for p in packets if p.tcp and p.tcp.payload]
    anchor_pkt = payload_pkts[0] if payload_pkts else packets[0]
    skip = {"connect", "disconnect"}
    anchor_ev = next((e for e in events if e.action not in skip), events[0])
    return anchor_pkt.ts - anchor_ev.ts_epoch


def packets_in_window(
    packets: list[PacketRecord],
    center_ts: float,
    window_s: float,
) -> list[PacketRecord]:
    lo = center_ts - window_s
    hi = center_ts + window_s
    return [p for p in packets if lo <= p.ts <= hi]


def stream_ranges_for_packets(
    stream: DirectedStream,
    direction_label: str,
    packet_ids: set[int],
) -> list[tuple[str, int, int]]:
    ranges: list[tuple[str, int, int]] = []
    for pid in sorted(packet_ids):
        rng = stream.provenance.range_for_packet(pid)
        if rng is not None:
            ranges.append((direction_label, rng[0], rng[1]))
    return ranges


def _nearest_packets(
    packets: list[PacketRecord],
    center_ts: float,
    window_s: float,
    *,
    prefer_payload: bool,
    limit: int = 4,
) -> list[PacketRecord]:
    nearby = packets_in_window(packets, center_ts, window_s)
    if prefer_payload:
        payload = [p for p in nearby if p.tcp and p.tcp.payload]
        if payload:
            nearby = payload
    nearby.sort(key=lambda p: abs(p.ts - center_ts))
    return nearby[:limit]


def align_actions(
    action_log: ActionLog,
    packets: list[PacketRecord],
    *,
    session: TcpSession | None = None,
    streams: dict[str, DirectedStream] | None = None,
    mode: str = "relative",
    window_s: float = 0.08,
    offset: float | None = None,
    max_packets: int = 4,
) -> AlignmentResult:
    """Align each action to nearby packets (optionally scoped to one session)."""
    if session is not None:
        allowed = set(session.packet_ids)
        packets = [p for p in packets if p.packet_id in allowed]

    off = compute_offset(action_log.events, packets, mode=mode) if offset is None else offset
    aligned: list[AlignedAction] = []
    for ev in action_log.events:
        center = ev.ts_epoch + off
        prefer_payload = ev.action not in {"connect", "disconnect"}
        nearby = _nearest_packets(
            packets,
            center,
            window_s,
            prefer_payload=prefer_payload,
            limit=max_packets,
        )
        pids = [p.packet_id for p in nearby]
        ranges: list[tuple[str, int, int]] = []
        if streams:
            pid_set = set(pids)
            for label, stream in streams.items():
                ranges.extend(stream_ranges_for_packets(stream, label, pid_set))
        note = ""
        if not pids:
            note = "no packets in window"
        aligned.append(
            AlignedAction(
                event=ev,
                aligned_ts=center,
                packet_ids=pids,
                stream_ranges=ranges,
                note=note,
            )
        )
    return AlignmentResult(mode=mode, offset=off, window_s=window_s, actions=aligned)
