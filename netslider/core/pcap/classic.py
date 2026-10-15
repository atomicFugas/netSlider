"""Classic PCAP (libpcap) reader — Ethernet / IPv4 / TCP.

Primary importer for Phase 1 when TShark is unavailable. PCAPNG is diagnosed
and deferred to the optional PyShark backend.
"""

from __future__ import annotations

import struct
from pathlib import Path

from netslider.core.pcap.checksums import verify_ipv4_header_checksum, verify_tcp_checksum
from netslider.core.pcap.models import (
    CaptureDiagnostics,
    ImportedCapture,
    IPv4Endpoints,
    LinkType,
    PacketDiagnosis,
    PacketRecord,
    TCPInfo,
)

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NSEC_LE = 0xA1B23C4D
PCAPNG_MAGIC = 0x0A0D0D0A

ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_VLAN = 0x8100
IP_PROTO_TCP = 6


class PcapImportError(Exception):
    """Raised when a capture cannot be opened or is unsupported."""


def _ip_str(addr: bytes) -> str:
    return ".".join(str(b) for b in addr)


def parse_ethernet_tcp(
    frame: bytes,
    *,
    verify_checksums: bool,
    checksum_policy: str,
) -> tuple[
    PacketDiagnosis,
    str,
    int | None,
    IPv4Endpoints | None,
    int,
    bool | None,
    TCPInfo | None,
    int | None,
]:
    """Parse one Ethernet frame. Returns diagnosis + fields."""
    if len(frame) < 14:
        return PacketDiagnosis.MALFORMED, "frame too short", None, None, 0, None, None, None

    eth_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    if eth_type == ETH_TYPE_VLAN:
        if len(frame) < 18:
            return PacketDiagnosis.MALFORMED, "truncated VLAN", eth_type, None, 0, None, None, None
        eth_type = struct.unpack_from("!H", frame, 16)[0]
        offset = 18

    if eth_type == ETH_TYPE_IPV6:
        return PacketDiagnosis.IPV6, "IPv6 not supported in Phase 1", eth_type, None, 0, None, None, None
    if eth_type != ETH_TYPE_IPV4:
        return (
            PacketDiagnosis.NON_IPV4,
            f"ethertype 0x{eth_type:04x}",
            eth_type,
            None,
            0,
            None,
            None,
            None,
        )

    if len(frame) < offset + 20:
        return PacketDiagnosis.MALFORMED, "truncated IPv4", eth_type, None, 0, None, None, None

    ver_ihl = frame[offset]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return PacketDiagnosis.MALFORMED, "bad IPv4 header", eth_type, None, 0, None, None, None
    if len(frame) < offset + ihl:
        return PacketDiagnosis.MALFORMED, "truncated IPv4 header", eth_type, None, 0, None, None, None

    total_len = struct.unpack_from("!H", frame, offset + 2)[0]
    proto = frame[offset + 9]
    src = frame[offset + 12 : offset + 16]
    dst = frame[offset + 16 : offset + 20]
    ipv4 = IPv4Endpoints(src=_ip_str(src), dst=_ip_str(dst))

    ip_checksum_ok: bool | None = None
    if verify_checksums:
        ip_checksum_ok = verify_ipv4_header_checksum(frame[offset : offset + ihl])

    if proto != IP_PROTO_TCP:
        return (
            PacketDiagnosis.NON_TCP,
            f"ip proto {proto}",
            eth_type,
            ipv4,
            ihl,
            ip_checksum_ok,
            None,
            None,
        )

    tcp_off = offset + ihl
    # Prefer IP total length when sane
    ip_end = offset + total_len if total_len >= ihl else len(frame)
    ip_end = min(ip_end, len(frame))
    if ip_end < tcp_off + 20:
        return PacketDiagnosis.MALFORMED, "truncated TCP", eth_type, ipv4, ihl, ip_checksum_ok, None, None

    src_port, dst_port, seq, ack, off_flags, _window, tcp_csum, _urg = struct.unpack_from(
        "!HHIIHHHH", frame, tcp_off
    )
    data_offset = (off_flags >> 12) * 4
    flags = off_flags & 0x1FF
    if data_offset < 20 or tcp_off + data_offset > ip_end:
        return PacketDiagnosis.MALFORMED, "bad TCP header len", eth_type, ipv4, ihl, ip_checksum_ok, None, None

    payload = frame[tcp_off + data_offset : ip_end]
    payload_file_offset = tcp_off + data_offset

    tcp_checksum_ok: bool | None = None
    if verify_checksums:
        tcp_segment = frame[tcp_off:ip_end]
        tcp_checksum_ok = verify_tcp_checksum(src, dst, tcp_segment)

    diagnosis = PacketDiagnosis.OK
    detail = ""
    if verify_checksums and (ip_checksum_ok is False or tcp_checksum_ok is False):
        parts = []
        if ip_checksum_ok is False:
            parts.append("IPv4 checksum")
        if tcp_checksum_ok is False:
            parts.append("TCP checksum")
        detail = "bad " + " + ".join(parts)
        if checksum_policy == "warn":
            diagnosis = PacketDiagnosis.CHECKSUM_BAD
        # checksum_policy == "ignore": keep OK, still record detail empty for UI noise
        elif checksum_policy == "ignore":
            detail = ""


    tcp = TCPInfo(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        flags=flags,
        header_len=data_offset,
        payload=payload,
        checksum=tcp_csum,
        checksum_ok=tcp_checksum_ok,
    )
    return diagnosis, detail, eth_type, ipv4, ihl, ip_checksum_ok, tcp, payload_file_offset


def read_classic_pcap(
    path: Path,
    *,
    capture_id: str | None = None,
    checksum_policy: str = "warn",
) -> ImportedCapture:
    path = path.resolve()
    data = path.read_bytes()
    if len(data) < 24:
        raise PcapImportError(f"File too short for PCAP header: {path}")

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == PCAPNG_MAGIC or struct.unpack_from(">I", data, 0)[0] == PCAPNG_MAGIC:
        raise PcapImportError(
            "PCAPNG detected — install TShark and use the pyshark backend, "
            "or convert with: editcap -F pcap in.pcapng out.pcap"
        )

    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NSEC_LE):
        endian = "<"
        nsec = magic == PCAP_MAGIC_NSEC_LE
    else:
        magic_be = struct.unpack_from(">I", data, 0)[0]
        if magic_be in (PCAP_MAGIC_BE, 0x4D3CB2A1):
            endian = ">"
            nsec = magic_be == 0x4D3CB2A1
        else:
            raise PcapImportError(f"Unrecognized capture magic 0x{magic:08x}: {path}")

    _ver_maj, _ver_min, _thiszone, _sigfigs, _snaplen, network = struct.unpack_from(
        f"{endian}HHIIII", data, 4
    )
    diag = CaptureDiagnostics(path=str(path), backend="classic", link_type=network)
    verify = checksum_policy != "ignore"

    if network != LinkType.ETHERNET.value:
        diag.warnings.append(
            f"Unsupported link type {network} (need Ethernet=1). Packets will be diagnosed."
        )

    packets: list[PacketRecord] = []
    offset = 24
    pkt_id = 0
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += 16
        if offset + incl_len > len(data):
            diag.warnings.append(f"Truncated packet record at packet {pkt_id + 1}")
            break
        frame = data[offset : offset + incl_len]
        offset += incl_len
        pkt_id += 1
        ts = float(ts_sec) + (ts_frac / 1_000_000_000.0 if nsec else ts_frac / 1_000_000.0)

        if network != LinkType.ETHERNET.value:
            packets.append(
                PacketRecord(
                    packet_id=pkt_id,
                    ts=ts,
                    link_type=LinkType.UNKNOWN,
                    raw=frame,
                    diagnosis=PacketDiagnosis.NON_ETHERNET,
                    diagnosis_detail=f"linktype={network}",
                )
            )
            diag.note_skip("non_ethernet")
            continue

        (
            diagnosis,
            detail,
            eth_type,
            ipv4,
            ihl,
            ip_csum_ok,
            tcp,
            payload_off,
        ) = parse_ethernet_tcp(frame, verify_checksums=verify, checksum_policy=checksum_policy)

        if diagnosis == PacketDiagnosis.CHECKSUM_BAD and checksum_policy == "warn":
            diag.warnings.append(f"packet {pkt_id}: {detail}")
        if diagnosis not in (PacketDiagnosis.OK, PacketDiagnosis.CHECKSUM_BAD):
            diag.note_skip(diagnosis.value)
        else:
            diag.tcp_packet_count += 1

        packets.append(
            PacketRecord(
                packet_id=pkt_id,
                ts=ts,
                link_type=LinkType.ETHERNET,
                raw=frame,
                diagnosis=diagnosis,
                diagnosis_detail=detail,
                eth_type=eth_type,
                ipv4=ipv4,
                ip_header_len=ihl,
                ip_checksum_ok=ip_csum_ok,
                tcp=tcp,
                payload_file_offset=payload_off,
            )
        )

    diag.packet_count = len(packets)
    cid = capture_id or path.stem
    return ImportedCapture(capture_id=cid, path=str(path), packets=packets, diagnostics=diag)
