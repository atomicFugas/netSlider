"""In-memory analysis workspace for an opened capture."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from netslider.core.pcap.models import ImportedCapture, PacketRecord
from netslider.core.tcp.reassembly import DirectedStream, SessionStreams
from netslider.core.tcp.session import SessionIndex, TcpSession


@dataclass
class CaptureWorkspace:
    capture: ImportedCapture
    sessions: SessionIndex
    streams: list[SessionStreams] = field(default_factory=list)

    def stream_for(self, session_id: str) -> SessionStreams | None:
        for s in self.streams:
            if s.session.key.session_id == session_id:
                return s
        return None

    def packet(self, packet_id: int) -> PacketRecord | None:
        for p in self.capture.packets:
            if p.packet_id == packet_id:
                return p
        return None

    def session(self, session_id: str) -> TcpSession | None:
        return self.sessions.by_id(session_id)


def build_workspace_from_path(
    path: Path,
    *,
    capture_id: str | None = None,
    checksum_policy: str = "warn",
    overlap_policy: str = "first_seen",
    settings: dict[str, Any] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> CaptureWorkspace:
    """Import a capture and reassemble all sessions into a workspace."""
    from netslider.core.limits import check_capture_file, check_packet_count
    from netslider.core.pcap import import_capture
    from netslider.core.tcp import build_session_index, packets_for_session, reassemble_session
    from netslider.core.tcp.reassembly import DirectedStream as DS
    from netslider.core.tcp.session import Direction

    path = Path(path)
    if settings is not None:
        tcp_cfg = settings.get("tcp", {})
        checksum_policy = tcp_cfg.get("checksum_policy", checksum_policy)
        overlap_policy = tcp_cfg.get("overlap_policy", overlap_policy)

    limit = check_capture_file(path, settings)
    if limit.blocked:
        raise ValueError("; ".join(limit.errors) or "capture blocked by limits")

    if cancel_check and cancel_check():
        raise InterruptedError("cancelled")

    cap = import_capture(
        path,
        capture_id=capture_id or path.stem,
        checksum_policy=checksum_policy,
    )
    pkt_limit = check_packet_count(cap.diagnostics.packet_count, settings)
    if pkt_limit.blocked:
        raise ValueError("; ".join(pkt_limit.errors) or "packet count blocked by limits")

    if cancel_check and cancel_check():
        raise InterruptedError("cancelled")

    sessions = build_session_index(cap)
    streams: list[SessionStreams] = []
    for sess in sessions.sessions:
        if cancel_check and cancel_check():
            raise InterruptedError("cancelled")
        pkts = packets_for_session(cap, sess)
        try:
            streams.append(
                reassemble_session(
                    sess,
                    pkts,
                    capture_id=cap.capture_id,
                    overlap_policy=overlap_policy,
                )
            )
        except Exception as exc:
            streams.append(
                SessionStreams(
                    session=sess,
                    a_to_b=DS(sess.key.session_id, Direction.A_TO_B),
                    b_to_a=DS(sess.key.session_id, Direction.B_TO_A),
                    error=str(exc),
                )
            )
    return CaptureWorkspace(capture=cap, sessions=sessions, streams=streams)
