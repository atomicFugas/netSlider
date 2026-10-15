"""Unified capture import entry point."""

from __future__ import annotations

import struct
from pathlib import Path

from netslider.core.pcap.classic import PcapImportError, read_classic_pcap
from netslider.core.pcap.models import ImportedCapture

PCAPNG_MAGIC = 0x0A0D0D0A


def detect_format(path: Path) -> str:
    path = path.resolve()
    head = path.read_bytes()[:4]
    if len(head) < 4:
        return "unknown"
    le = struct.unpack("<I", head)[0]
    be = struct.unpack(">I", head)[0]
    if le == PCAPNG_MAGIC or be == PCAPNG_MAGIC:
        return "pcapng"
    if le in (0xA1B2C3D4, 0xA1B23C4D) or be in (0xD4C3B2A1, 0x4D3CB2A1):
        return "pcap"
    return "unknown"


def import_capture(
    path: Path | str,
    *,
    capture_id: str | None = None,
    checksum_policy: str = "warn",
    prefer_pyshark: bool = False,
) -> ImportedCapture:
    """Import PCAP/PCAPNG.

    Classic PCAP uses the built-in Ethernet/IPv4/TCP parser.
    PCAPNG (or prefer_pyshark=True) uses PyShark when TShark is available.
    """
    path = Path(path)
    if not path.is_file():
        raise PcapImportError(f"Capture not found: {path}")

    fmt = detect_format(path)
    if fmt == "pcap" and not prefer_pyshark:
        return read_classic_pcap(path, capture_id=capture_id, checksum_policy=checksum_policy)

    # PCAPNG or forced pyshark
    from netslider.core.pcap.pyshark_backend import TSharkUnavailable, read_with_pyshark

    try:
        return read_with_pyshark(path, capture_id=capture_id, checksum_policy=checksum_policy)
    except TSharkUnavailable:
        if fmt == "pcapng":
            raise PcapImportError(
                f"PCAPNG requires TShark ({path}). "
                "Install Wireshark or convert: editcap -F pcap in.pcapng out.pcap"
            ) from None
        # fallback classic
        return read_classic_pcap(path, capture_id=capture_id, checksum_policy=checksum_policy)
