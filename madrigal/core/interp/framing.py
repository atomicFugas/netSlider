"""Framing engine: turn a directed stream into message spans."""

from __future__ import annotations

from dataclasses import dataclass

from madrigal.core.interp.models import MessageSpan
from madrigal.core.interp.schema import FramingHeader, FramingSpec


@dataclass
class FrameSlice:
    span: MessageSpan
    header_size: int
    body: bytes
    raw: bytes


def _read_len(data: bytes, offset: int, size: int, endian: str) -> int:
    chunk = data[offset : offset + size]
    if endian == "le":
        return int.from_bytes(chunk, "little")
    return int.from_bytes(chunk, "big")


def header_size(header: FramingHeader) -> int:
    return max(
        header.len_offset + header.len_size,
        (header.magic_offset + len(header.magic)) if header.magic else 0,
    )


def frame_length_prefixed(
    data: bytes,
    header: FramingHeader,
    *,
    max_frames: int = 10_000,
) -> list[FrameSlice]:
    """Walk *data* using length-prefix framing; resync on bad magic."""
    frames: list[FrameSlice] = []
    hsz = header_size(header)
    if hsz <= 0 or not data:
        return frames

    offset = 0
    while offset + hsz <= len(data) and len(frames) < max_frames:
        if header.magic is not None:
            m_off = offset + header.magic_offset
            m_end = m_off + len(header.magic)
            if m_end > len(data) or data[m_off:m_end] != header.magic:
                # Resync: find next magic occurrence
                nxt = data.find(header.magic, offset + 1) if header.magic else -1
                if nxt < 0:
                    break
                offset = nxt - header.magic_offset
                if offset < 0:
                    offset = nxt
                continue

        length_val = _read_len(
            data, offset + header.len_offset, header.len_size, header.endian
        )
        if header.len_includes_header:
            total = length_val
            body_len = max(0, total - hsz)
        else:
            body_len = length_val
            total = hsz + body_len

        if total < hsz or body_len > 1_000_000:
            frames.append(
                FrameSlice(
                    span=MessageSpan(
                        start=offset,
                        end=min(offset + hsz, len(data)),
                        status="error",
                        note=f"implausible length={length_val}",
                    ),
                    header_size=hsz,
                    body=b"",
                    raw=data[offset : offset + hsz],
                )
            )
            offset += 1
            continue

        if offset + total > len(data):
            frames.append(
                FrameSlice(
                    span=MessageSpan(
                        start=offset,
                        end=len(data),
                        status="incomplete",
                        note="truncated frame",
                    ),
                    header_size=hsz,
                    body=data[offset + hsz :],
                    raw=data[offset:],
                )
            )
            break

        raw = data[offset : offset + total]
        body = raw[hsz:]
        frames.append(
            FrameSlice(
                span=MessageSpan(start=offset, end=offset + total, status="ok"),
                header_size=hsz,
                body=body,
                raw=raw,
            )
        )
        offset += total

    return frames


def frame_stream(data: bytes, framing: FramingSpec, *, max_frames: int = 10_000) -> list[FrameSlice]:
    if framing.type != "length_prefixed":
        raise ValueError(f"Unsupported framing type: {framing.type}")
    return frame_length_prefixed(data, framing.header, max_frames=max_frames)
