"""In-memory analysis workspace for an opened capture."""

from __future__ import annotations

from dataclasses import dataclass, field

from madrigal.core.pcap.models import ImportedCapture, PacketRecord
from madrigal.core.tcp.reassembly import DirectedStream, SessionStreams
from madrigal.core.tcp.session import SessionIndex, TcpSession


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
