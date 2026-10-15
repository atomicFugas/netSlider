"""Synthetic stress capture generator (NFR profile ~100 MiB / 250k packets).

Generates a classic PCAP of repeated MD01 frames without Docker. Default
``profile=smoke`` is small for CI; ``profile=nfr`` targets the plan thresholds.
"""

from __future__ import annotations

import argparse
import struct
import time
from pathlib import Path

from netslider.demo.pcap_synth import (
    ETH_TYPE_IPV4,
    TCP_FLAG_ACK,
    TCP_FLAG_PSH,
    TCP_FLAG_SYN,
    Endpoint,
    PcapWriter,
    _ipv4_header,
    _tcp_header,
)
from netslider.demo.protocol import Opcode, encode_frame

PROFILES = {
    # Fast CI / unit smoke (~few thousand packets, <2 MiB)
    "smoke": {"exchanges": 500, "payload": 32},
    # Approx NFR: aim ≥250k packets and ≥100 MiB when possible
    "nfr": {"exchanges": 80_000, "payload": 1200},
}


def _md01_exchange(i: int, payload_size: int) -> tuple[bytes, bytes]:
    from netslider.demo.protocol import measurement_data

    req = encode_frame(Opcode.READ_PARAM, struct.pack("<H", i % 16))
    data = bytes([(i + j) & 0xFF for j in range(min(payload_size, 65000))])
    resp = measurement_data(i & 0xFF, data)
    return req, resp


def generate_stress_pcap(
    out_path: Path,
    *,
    profile: str = "smoke",
    exchanges: int | None = None,
    payload_size: int | None = None,
) -> dict[str, float | int | str]:
    """Write a stress PCAP; returns size/packet metrics."""
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile {profile!r}; choose from {sorted(PROFILES)}")
    cfg = PROFILES[profile]
    n = exchanges if exchanges is not None else int(cfg["exchanges"])
    psz = payload_size if payload_size is not None else int(cfg["payload"])

    client = Endpoint(ip="10.0.0.2", port=50100, mac=bytes.fromhex("020000000001"))
    server = Endpoint(ip="10.0.0.1", port=9100, mac=bytes.fromhex("020000000002"))
    t0 = time.time()
    c_seq = 1000
    s_seq = 2000
    ident = 1
    packets = 0

    def eth(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
        return dst_mac + src_mac + ETH_TYPE_IPV4 + payload

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with PcapWriter(out_path) as writer:

        def send_tcp(
            t: float,
            src: Endpoint,
            dst: Endpoint,
            seq: int,
            ack: int,
            flags: int,
            payload: bytes,
        ) -> None:
            nonlocal ident, packets
            tcp = _tcp_header(src.port, dst.port, seq, ack, flags, payload, src.ip, dst.ip)
            ip = _ipv4_header(src.ip, dst.ip, len(tcp) + len(payload), ident=ident)
            ident += 1
            writer.write_frame(t, eth(src.mac, dst.mac, ip + tcp + payload))
            packets += 1

        send_tcp(t0, client, server, c_seq, 0, TCP_FLAG_SYN, b"")
        c_seq += 1
        send_tcp(t0 + 0.001, server, client, s_seq, c_seq, TCP_FLAG_SYN | TCP_FLAG_ACK, b"")
        s_seq += 1
        send_tcp(t0 + 0.002, client, server, c_seq, s_seq, TCP_FLAG_ACK, b"")

        t = t0 + 0.01
        for i in range(n):
            req, resp = _md01_exchange(i, psz)
            send_tcp(t, client, server, c_seq, s_seq, TCP_FLAG_PSH | TCP_FLAG_ACK, req)
            c_seq += len(req)
            t += 0.0002
            send_tcp(t, server, client, s_seq, c_seq, TCP_FLAG_ACK, b"")
            t += 0.0001
            send_tcp(t, server, client, s_seq, c_seq, TCP_FLAG_PSH | TCP_FLAG_ACK, resp)
            s_seq += len(resp)
            t += 0.0002
            send_tcp(t, client, server, c_seq, s_seq, TCP_FLAG_ACK, b"")
            t += 0.0001

    size = out_path.stat().st_size
    return {
        "path": str(out_path),
        "profile": profile,
        "exchanges": n,
        "payload_size": psz,
        "packets": packets,
        "bytes": size,
        "mib": round(size / (1024 * 1024), 3),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Generate netSlider stress PCAP")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "stress_smoke.pcap",
    )
    parser.add_argument("--profile", choices=sorted(PROFILES), default="smoke")
    parser.add_argument("--exchanges", type=int, default=None)
    parser.add_argument("--payload", type=int, default=None)
    args = parser.parse_args(argv)
    metrics = generate_stress_pcap(
        args.out,
        profile=args.profile,
        exchanges=args.exchanges,
        payload_size=args.payload,
    )
    print(
        f"wrote {metrics['path']}  packets={metrics['packets']}  "
        f"size={metrics['bytes']} ({metrics['mib']} MiB)"
    )


if __name__ == "__main__":
    main()
