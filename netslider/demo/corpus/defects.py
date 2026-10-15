"""Generate defect PCAPs: gap, retransmit, overlap conflict, reorder."""

from __future__ import annotations

from pathlib import Path

from netslider.demo.pcap_synth import Endpoint, build_client_data_pcap

DEFAULT_OUT = Path(__file__).resolve().parent / "defects"


def generate_defect_pcaps(out_dir: Path | None = None) -> dict[str, Path]:
    """Write gap / retransmit / overlap / reorder classic PCAPs under ``out_dir``."""
    out = out_dir or DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)

    client = Endpoint(ip="10.0.0.2", port=50100, mac=bytes.fromhex("020000000001"))
    server = Endpoint(ip="10.0.0.1", port=9100, mac=bytes.fromhex("020000000002"))
    t0 = 1_700_000_000.0
    # Post-handshake first data seq = ISN + 1 = 1001
    base = 1001

    gap = out / "gap.pcap"
    build_client_data_pcap(
        gap,
        [(base, b"AAAA"), (base + 10, b"BBBB")],  # 6-byte gap
        client,
        server,
        t0,
    )

    retransmit = out / "retransmit.pcap"
    build_client_data_pcap(
        retransmit,
        [(base, b"ABCD"), (base, b"ABCD"), (base + 4, b"EF")],
        client,
        server,
        t0 + 10,
    )

    overlap = out / "overlap.pcap"
    build_client_data_pcap(
        overlap,
        [(base, b"AAAA"), (base + 2, b"XXYY")],
        client,
        server,
        t0 + 20,
    )

    # Higher SEQ first, then lower SEQ — reassembly still yields contiguous payload.
    reorder = out / "reorder.pcap"
    build_client_data_pcap(
        reorder,
        [(base + 4, b"EFGH"), (base, b"ABCD")],
        client,
        server,
        t0 + 30,
    )

    return {
        "gap": gap,
        "retransmit": retransmit,
        "overlap": overlap,
        "reorder": reorder,
    }
