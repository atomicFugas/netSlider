"""IP/TCP checksum helpers."""

from __future__ import annotations

import struct


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data = data + b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def verify_ipv4_header_checksum(header: bytes) -> bool:
    if len(header) < 20:
        return False
    return internet_checksum(header) == 0


def verify_tcp_checksum(
    src_ip: bytes,
    dst_ip: bytes,
    tcp_segment: bytes,
) -> bool:
    """Verify TCP checksum including IPv4 pseudo-header."""
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp_segment))
    return internet_checksum(pseudo + tcp_segment) == 0
