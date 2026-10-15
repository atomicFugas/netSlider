"""Synthesize a classic PCAP from a TCP byte exchange (no root/tcpdump needed)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ipv4_header(src: str, dst: str, payload_len: int, proto: int = 6, ident: int = 1) -> bytes:
    total_len = 20 + payload_len
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # ver/ihl
        0,  # tos
        total_len,
        ident,
        0x4000,  # don't fragment
        64,  # ttl
        proto,
        0,  # checksum placeholder
        src_b,
        dst_b,
    )
    csum = _checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:]


def _tcp_header(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    src_ip: str,
    dst_ip: str,
) -> bytes:
    data_offset = 5 << 4
    window = 65535
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        data_offset,
        flags,
        window,
        0,  # checksum
        0,  # urgent
    )
    src_b = bytes(int(x) for x in src_ip.split("."))
    dst_b = bytes(int(x) for x in dst_ip.split("."))
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    csum = _checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", csum) + header[18:]


ETH_TYPE_IPV4 = b"\x08\x00"
TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10
TCP_FLAG_PSH = 0x08
TCP_FLAG_FIN = 0x01


@dataclass
class Endpoint:
    ip: str
    port: int
    mac: bytes


@dataclass
class RecordedSegment:
    """One TCP payload segment with direction and timing."""

    t_sec: float
    client_to_server: bool
    payload: bytes


class PcapWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh = path.open("wb")
        # Global header: magic, v2.4, timezone, sigfigs, snaplen, LINKTYPE_ETHERNET
        self._fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def write_frame(self, t_sec: float, frame: bytes) -> None:
        ts_sec = int(t_sec)
        ts_usec = int((t_sec - ts_sec) * 1_000_000)
        self._fh.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
        self._fh.write(frame)

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def build_tcp_session_pcap(
    path: Path,
    segments: list[RecordedSegment],
    client: Endpoint,
    server: Endpoint,
    t0: float,
) -> None:
    """Write a full TCP handshake + data + teardown for one session."""
    c_seq = 1000
    s_seq = 2000
    ident = 1

    def eth(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
        return dst_mac + src_mac + ETH_TYPE_IPV4 + payload

    def send_tcp(
        t: float,
        src: Endpoint,
        dst: Endpoint,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes,
    ) -> None:
        nonlocal ident
        tcp = _tcp_header(src.port, dst.port, seq, ack, flags, payload, src.ip, dst.ip)
        ip = _ipv4_header(src.ip, dst.ip, len(tcp) + len(payload), ident=ident)
        ident += 1
        frame = eth(src.mac, dst.mac, ip + tcp + payload)
        writer.write_frame(t, frame)

    with PcapWriter(path) as writer:
        # Handshake
        send_tcp(t0, client, server, c_seq, 0, TCP_FLAG_SYN, b"")
        c_seq += 1
        send_tcp(t0 + 0.001, server, client, s_seq, c_seq, TCP_FLAG_SYN | TCP_FLAG_ACK, b"")
        s_seq += 1
        send_tcp(t0 + 0.002, client, server, c_seq, s_seq, TCP_FLAG_ACK, b"")

        for seg in segments:
            flags = TCP_FLAG_PSH | TCP_FLAG_ACK
            if seg.client_to_server:
                send_tcp(seg.t_sec, client, server, c_seq, s_seq, flags, seg.payload)
                c_seq += len(seg.payload)
                send_tcp(seg.t_sec + 0.0005, server, client, s_seq, c_seq, TCP_FLAG_ACK, b"")
            else:
                send_tcp(seg.t_sec, server, client, s_seq, c_seq, flags, seg.payload)
                s_seq += len(seg.payload)
                send_tcp(seg.t_sec + 0.0005, client, server, c_seq, s_seq, TCP_FLAG_ACK, b"")

        fin_t = (segments[-1].t_sec + 0.01) if segments else t0 + 0.1
        send_tcp(fin_t, client, server, c_seq, s_seq, TCP_FLAG_FIN | TCP_FLAG_ACK, b"")
        c_seq += 1
        send_tcp(fin_t + 0.001, server, client, s_seq, c_seq, TCP_FLAG_FIN | TCP_FLAG_ACK, b"")
        s_seq += 1
        send_tcp(fin_t + 0.002, client, server, c_seq, s_seq, TCP_FLAG_ACK, b"")


def build_client_data_pcap(
    path: Path,
    data_packets: list[tuple[int, bytes]],
    client: Endpoint,
    server: Endpoint,
    t0: float,
    *,
    client_isn: int = 1000,
    server_isn: int = 2000,
) -> None:
    """Write handshake + client→server data packets with explicit TCP sequence numbers.

    ``data_packets`` is a list of ``(seq, payload)`` using absolute post-handshake
    sequence numbers (ISN+1 for the first contiguous byte after SYN).
    Used to synthesize defect captures (gap / retransmit / overlap).
    """
    c_seq = client_isn
    s_seq = server_isn
    ident = 1

    def eth(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
        return dst_mac + src_mac + ETH_TYPE_IPV4 + payload

    def send_tcp(
        t: float,
        src: Endpoint,
        dst: Endpoint,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes,
    ) -> None:
        nonlocal ident
        tcp = _tcp_header(src.port, dst.port, seq, ack, flags, payload, src.ip, dst.ip)
        ip = _ipv4_header(src.ip, dst.ip, len(tcp) + len(payload), ident=ident)
        ident += 1
        frame = eth(src.mac, dst.mac, ip + tcp + payload)
        writer.write_frame(t, frame)

    with PcapWriter(path) as writer:
        send_tcp(t0, client, server, c_seq, 0, TCP_FLAG_SYN, b"")
        c_seq += 1
        send_tcp(t0 + 0.001, server, client, s_seq, c_seq, TCP_FLAG_SYN | TCP_FLAG_ACK, b"")
        s_seq += 1
        send_tcp(t0 + 0.002, client, server, c_seq, s_seq, TCP_FLAG_ACK, b"")

        t = t0 + 0.01
        ack_point = c_seq
        for seq, payload in data_packets:
            send_tcp(
                t,
                client,
                server,
                seq,
                s_seq,
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                payload,
            )
            end = seq + len(payload)
            if end > ack_point:
                ack_point = end
            send_tcp(t + 0.0005, server, client, s_seq, ack_point, TCP_FLAG_ACK, b"")
            t += 0.01

        send_tcp(t, client, server, ack_point, s_seq, TCP_FLAG_FIN | TCP_FLAG_ACK, b"")
        ack_point += 1
        send_tcp(t + 0.001, server, client, s_seq, ack_point, TCP_FLAG_FIN | TCP_FLAG_ACK, b"")
        s_seq += 1
        send_tcp(t + 0.002, client, server, ack_point, s_seq, TCP_FLAG_ACK, b"")
