"""TCP session indexing — 5-tuple + connection instance (no port-reuse merge)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from madrigal.core.pcap.models import ImportedCapture, PacketRecord


class Direction(Enum):
    A_TO_B = "a_to_b"
    B_TO_A = "b_to_a"


@dataclass(frozen=True)
class EndpointPair:
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int

    def label(self) -> str:
        return f"{self.a_ip}:{self.a_port} ↔ {self.b_ip}:{self.b_port}"

    def direction_of(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Direction | None:
        if (
            src_ip == self.a_ip
            and src_port == self.a_port
            and dst_ip == self.b_ip
            and dst_port == self.b_port
        ):
            return Direction.A_TO_B
        if (
            src_ip == self.b_ip
            and src_port == self.b_port
            and dst_ip == self.a_ip
            and dst_port == self.a_port
        ):
            return Direction.B_TO_A
        return None


@dataclass(frozen=True)
class SessionKey:
    capture_id: str
    endpoints: EndpointPair
    instance: int

    @property
    def session_id(self) -> str:
        e = self.endpoints
        return f"{self.capture_id}:{e.a_ip}:{e.a_port}-{e.b_ip}:{e.b_port}#{self.instance}"


@dataclass
class TcpSession:
    key: SessionKey
    packet_ids: list[int] = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    closed: bool = False
    error: str | None = None

    @property
    def display_name(self) -> str:
        flags = []
        if self.syn_seen:
            flags.append("SYN")
        if self.fin_seen:
            flags.append("FIN")
        if self.rst_seen:
            flags.append("RST")
        flag_s = ",".join(flags) if flags else "—"
        return f"{self.key.endpoints.label()}  [{flag_s}]  pkts={len(self.packet_ids)}"


def _canonical_pair(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> EndpointPair:
    left = (src_ip, src_port)
    right = (dst_ip, dst_port)
    if left <= right:
        return EndpointPair(src_ip, src_port, dst_ip, dst_port)
    return EndpointPair(dst_ip, dst_port, src_ip, src_port)


@dataclass
class SessionIndex:
    capture_id: str
    sessions: list[TcpSession] = field(default_factory=list)
    packet_to_session: dict[int, str] = field(default_factory=dict)

    def by_id(self, session_id: str) -> TcpSession | None:
        for s in self.sessions:
            if s.key.session_id == session_id:
                return s
        return None


def build_session_index(capture: ImportedCapture) -> SessionIndex:
    """Group TCP packets into sessions.

    A new connection instance starts when:
    - first packet for the 5-tuple, or
    - a SYN (optionally SYN-only) arrives after the previous instance was closed
      (FIN/RST), or
    - a SYN arrives while a previous instance is still open (port reuse) —
      previous is marked closed and a new instance begins.
    """
    index = SessionIndex(capture_id=capture.capture_id)
    current: dict[EndpointPair, TcpSession] = {}
    next_instance: dict[EndpointPair, int] = {}

    def start_session(pair: EndpointPair, pkt: PacketRecord) -> TcpSession:
        inst = next_instance.get(pair, 0) + 1
        next_instance[pair] = inst
        sess = TcpSession(
            key=SessionKey(capture.capture_id, pair, inst),
            first_ts=pkt.ts,
            last_ts=pkt.ts,
            syn_seen=bool(pkt.syn),
        )
        current[pair] = sess
        index.sessions.append(sess)
        return sess

    for pkt in capture.packets:
        if not pkt.is_tcp_data or pkt.tcp is None or pkt.ipv4 is None:
            continue
        tcp = pkt.tcp
        pair = _canonical_pair(pkt.ipv4.src, tcp.src_port, pkt.ipv4.dst, tcp.dst_port)
        sess = current.get(pair)
        # Active open only (SYN without ACK). SYN+ACK must not start a new instance.
        syn_new = pkt.syn and not pkt.ack_flag

        if sess is None:
            sess = start_session(pair, pkt)
        elif sess.closed and syn_new:
            sess = start_session(pair, pkt)
        elif (not sess.closed) and syn_new and sess.syn_seen and len(sess.packet_ids) > 0:
            # Port reuse: active SYN while previous still open
            sess.closed = True
            sess = start_session(pair, pkt)

        sess.packet_ids.append(pkt.packet_id)
        sess.last_ts = pkt.ts
        if pkt.syn:
            sess.syn_seen = True
        if pkt.fin:
            sess.fin_seen = True
            sess.closed = True
        if pkt.rst:
            sess.rst_seen = True
            sess.closed = True
        index.packet_to_session[pkt.packet_id] = sess.key.session_id

    return index


def packets_for_session(capture: ImportedCapture, session: TcpSession) -> list[PacketRecord]:
    by_id = {p.packet_id: p for p in capture.packets}
    return [by_id[i] for i in session.packet_ids if i in by_id]
