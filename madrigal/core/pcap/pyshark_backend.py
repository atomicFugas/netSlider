"""Optional PyShark/TShark importer for PCAPNG and exotic captures."""

from __future__ import annotations

import shutil
from pathlib import Path

from madrigal.core.pcap.models import (
    CaptureDiagnostics,
    ImportedCapture,
    IPv4Endpoints,
    LinkType,
    PacketDiagnosis,
    PacketRecord,
    TCPInfo,
)


class TSharkUnavailable(Exception):
    pass


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def read_with_pyshark(
    path: Path,
    *,
    capture_id: str | None = None,
    checksum_policy: str = "warn",
) -> ImportedCapture:
    if not tshark_available():
        raise TSharkUnavailable(
            "TShark not found on PATH. Install Wireshark/tshark, or convert PCAPNG to classic PCAP."
        )

    import pyshark  # lazy

    path = path.resolve()
    diag = CaptureDiagnostics(path=str(path), backend="pyshark")
    packets: list[PacketRecord] = []

    cap = pyshark.FileCapture(
        str(path),
        keep_packets=False,
        use_json=True,
        include_raw=True,
    )
    try:
        for idx, pkt in enumerate(cap, start=1):
            ts = float(pkt.sniff_timestamp)
            raw = b""
            if hasattr(pkt, "get_raw_packet"):
                try:
                    raw = pkt.get_raw_packet()
                except Exception:
                    raw = b""

            diagnosis = PacketDiagnosis.OK
            detail = ""
            eth_type = None
            ipv4 = None
            tcp_info = None

            layers = {l.layer_name for l in pkt.layers}
            if "ipv6" in layers and "ip" not in layers:
                diagnosis = PacketDiagnosis.IPV6
                detail = "IPv6"
                diag.note_skip("ipv6")
            elif "ip" not in layers:
                diagnosis = PacketDiagnosis.NON_IPV4
                detail = "no IPv4"
                diag.note_skip("non_ipv4")
            elif "tcp" not in layers:
                diagnosis = PacketDiagnosis.NON_TCP
                detail = "no TCP"
                diag.note_skip("non_tcp")
                ipv4 = IPv4Endpoints(src=pkt.ip.src, dst=pkt.ip.dst)
            else:
                ipv4 = IPv4Endpoints(src=pkt.ip.src, dst=pkt.ip.dst)
                payload = b""
                if hasattr(pkt.tcp, "payload"):
                    try:
                        payload = bytes.fromhex(pkt.tcp.payload.replace(":", ""))
                    except Exception:
                        payload = b""
                flags = int(getattr(pkt.tcp, "flags", "0"), 0)
                tcp_info = TCPInfo(
                    src_port=int(pkt.tcp.srcport),
                    dst_port=int(pkt.tcp.dstport),
                    seq=int(pkt.tcp.seq),
                    ack=int(getattr(pkt.tcp, "ack", "0")),
                    flags=flags,
                    header_len=int(getattr(pkt.tcp, "hdr_len", "20")),
                    payload=payload,
                    checksum=int(getattr(pkt.tcp, "checksum", "0"), 0),
                    checksum_ok=None,
                )
                diag.tcp_packet_count += 1

            packets.append(
                PacketRecord(
                    packet_id=idx,
                    ts=ts,
                    link_type=LinkType.ETHERNET,
                    raw=raw if isinstance(raw, (bytes, bytearray)) else b"",
                    diagnosis=diagnosis,
                    diagnosis_detail=detail,
                    eth_type=eth_type,
                    ipv4=ipv4,
                    tcp=tcp_info,
                )
            )
    finally:
        cap.close()

    diag.packet_count = len(packets)
    if checksum_policy:
        diag.extra["checksum_policy"] = checksum_policy
    return ImportedCapture(
        capture_id=capture_id or path.stem,
        path=str(path),
        packets=packets,
        diagnostics=diag,
    )
