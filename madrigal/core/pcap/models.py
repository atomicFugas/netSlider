"""Capture / packet models shared by importers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LinkType(Enum):
    ETHERNET = 1
    UNKNOWN = -1


class PacketDiagnosis(Enum):
    OK = "ok"
    NON_ETHERNET = "non_ethernet"
    NON_IPV4 = "non_ipv4"
    IPV6 = "ipv6"
    NON_TCP = "non_tcp"
    MALFORMED = "malformed"
    CHECKSUM_BAD = "checksum_bad"


@dataclass(frozen=True)
class IPv4Endpoints:
    src: str
    dst: str


@dataclass(frozen=True)
class TCPInfo:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    header_len: int
    payload: bytes
    checksum: int
    checksum_ok: bool | None  # None = not verified


@dataclass
class PacketRecord:
    packet_id: int  # 1-based index in capture
    ts: float
    link_type: LinkType
    raw: bytes
    diagnosis: PacketDiagnosis = PacketDiagnosis.OK
    diagnosis_detail: str = ""
    eth_type: int | None = None
    ipv4: IPv4Endpoints | None = None
    ip_header_len: int = 0
    ip_checksum_ok: bool | None = None
    tcp: TCPInfo | None = None
    # Offset of TCP payload within `raw` (Ethernet frame bytes)
    payload_file_offset: int | None = None

    @property
    def is_tcp_data(self) -> bool:
        return (
            self.diagnosis in (PacketDiagnosis.OK, PacketDiagnosis.CHECKSUM_BAD)
            and self.tcp is not None
            and self.ipv4 is not None
        )

    @property
    def syn(self) -> bool:
        return bool(self.tcp and self.tcp.flags & 0x02)

    @property
    def fin(self) -> bool:
        return bool(self.tcp and self.tcp.flags & 0x01)

    @property
    def rst(self) -> bool:
        return bool(self.tcp and self.tcp.flags & 0x04)

    @property
    def ack_flag(self) -> bool:
        return bool(self.tcp and self.tcp.flags & 0x10)


@dataclass
class CaptureDiagnostics:
    path: str
    packet_count: int = 0
    tcp_packet_count: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    backend: str = "classic"
    link_type: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def note_skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


@dataclass
class ImportedCapture:
    capture_id: str
    path: str
    packets: list[PacketRecord]
    diagnostics: CaptureDiagnostics
