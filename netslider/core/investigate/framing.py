"""Framing aids: magic search, length-prefix probes, delimiter histograms."""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd


@dataclass(frozen=True)
class MagicHit:
    offset: int
    length: int


@dataclass
class LengthPrefixProbe:
    len_offset: int
    len_size: int
    endian: str  # "be" | "le"
    len_includes_header: bool
    magic: bytes | None
    magic_offset: int
    frames_ok: int
    frames_bad: int
    coverage: float  # fraction of stream covered by successful frames
    sample_offsets: list[int] = field(default_factory=list)
    note: str = ""


@dataclass
class DelimiterStats:
    byte_value: int
    count: int
    frequency: float
    positions_sample: list[int] = field(default_factory=list)


def find_magic(data: bytes, magic: bytes, *, max_hits: int = 500) -> list[MagicHit]:
    if not magic or not data:
        return []
    hits: list[MagicHit] = []
    start = 0
    while len(hits) < max_hits:
        idx = data.find(magic, start)
        if idx < 0:
            break
        hits.append(MagicHit(offset=idx, length=len(magic)))
        start = idx + 1
    return hits


def parse_magic_string(text: str) -> bytes:
    """Accept ``MD01``, ``0xMD01``, ``4d440031``, ``4d 44 01``, etc."""
    s = text.strip()
    if not s:
        return b""
    if s.lower().startswith("0x"):
        s = s[2:]
    # hex with spaces / colons
    cleaned = s.replace(" ", "").replace(":", "").replace("-", "")
    if all(c in "0123456789abcdefABCDEF" for c in cleaned) and len(cleaned) % 2 == 0 and cleaned:
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            pass
    # ASCII / latin-1 literal (e.g. MD01)
    return s.encode("latin-1", errors="replace")


def probe_length_prefix(
    data: bytes,
    *,
    len_offset: int = 4,
    len_size: int = 2,
    endian: str = "be",
    len_includes_header: bool = False,
    magic: bytes | None = b"MD01",
    magic_offset: int = 0,
    max_frames: int = 200,
) -> LengthPrefixProbe:
    """Walk the stream using a candidate length-prefix framing rule."""
    if len_size not in (1, 2, 4) or not data:
        return LengthPrefixProbe(
            len_offset, len_size, endian, len_includes_header, magic, magic_offset,
            0, 0, 0.0, note="invalid params or empty stream",
        )

    header_min = max(len_offset + len_size, (magic_offset + len(magic)) if magic else 0)

    ok = 0
    bad = 0
    covered = 0
    samples: list[int] = []
    offset = 0
    while offset + header_min <= len(data) and ok + bad < max_frames:
        if magic is not None:
            if data[offset + magic_offset : offset + magic_offset + len(magic)] != magic:
                # resync: find next magic
                if magic:
                    nxt = data.find(magic, offset + 1)
                    if nxt < 0:
                        break
                    offset = nxt - magic_offset
                    if offset < 0:
                        offset = nxt
                    continue
                bad += 1
                offset += 1
                continue
        length_bytes = data[offset + len_offset : offset + len_offset + len_size]
        if len(length_bytes) < len_size:
            break
        body_len = int.from_bytes(length_bytes, "big" if endian == "be" else "little")
        if len_includes_header:
            frame_len = body_len
        else:
            frame_len = (len_offset + len_size) + body_len
        if frame_len <= 0 or offset + frame_len > len(data) or frame_len > 70_000:
            bad += 1
            offset += 1
            continue
        ok += 1
        covered += frame_len
        if len(samples) < 40:
            samples.append(offset)
        offset += frame_len

    coverage = covered / len(data) if data else 0.0
    note = f"ok={ok} bad={bad} coverage={coverage:.1%}"
    return LengthPrefixProbe(
        len_offset=len_offset,
        len_size=len_size,
        endian=endian,
        len_includes_header=len_includes_header,
        magic=magic,
        magic_offset=magic_offset,
        frames_ok=ok,
        frames_bad=bad,
        coverage=coverage,
        sample_offsets=samples,
        note=note,
    )


def delimiter_histogram(
    data: bytes,
    *,
    candidates: list[int] | None = None,
    top_n: int = 16,
) -> list[DelimiterStats]:
    """Byte-frequency histogram (pandas), highlighting delimiter candidates."""
    if not data:
        return []
    series = pd.Series(list(data), dtype="uint8")
    counts = series.value_counts().sort_values(ascending=False)
    total = len(data)
    stats: list[DelimiterStats] = []

    if candidates is None:
        candidates = [0x0A, 0x0D, 0x00, 0x20, 0x3B, 0x2C, 0x7C, 0xFF]

    # Always include top bytes + explicit candidates
    seen: set[int] = set()
    ordered_bytes: list[int] = []
    for b in candidates:
        ordered_bytes.append(int(b))
        seen.add(int(b))
    for b, _cnt in counts.items():
        bi = int(b)
        if bi not in seen:
            ordered_bytes.append(bi)
            seen.add(bi)
        if len(ordered_bytes) >= top_n + len(candidates):
            break

    for b in ordered_bytes[: top_n + len(candidates)]:
        cnt = int(counts.get(b, 0))
        if cnt == 0 and b not in candidates:
            continue
        positions = [i for i, x in enumerate(data) if x == b][:12]
        stats.append(
            DelimiterStats(
                byte_value=b,
                count=cnt,
                frequency=cnt / total if total else 0.0,
                positions_sample=positions,
            )
        )
    stats.sort(key=lambda s: s.count, reverse=True)
    return stats[:top_n]


def probe_grid(
    data: bytes,
    *,
    magic: bytes | None = b"MD01",
) -> list[LengthPrefixProbe]:
    """Try a small grid of length-prefix hypotheses; return ranked by coverage."""
    results: list[LengthPrefixProbe] = []
    for endian in ("be", "le"):
        for len_size in (1, 2, 4):
            for len_offset in (0, 2, 4):
                for includes in (False, True):
                    if magic and len_offset < len(magic):
                        # still allow; magic check uses magic_offset=0
                        pass
                    probe = probe_length_prefix(
                        data,
                        len_offset=len_offset,
                        len_size=len_size,
                        endian=endian,
                        len_includes_header=includes,
                        magic=magic,
                    )
                    results.append(probe)
    results.sort(key=lambda p: (p.coverage, p.frames_ok, -p.frames_bad), reverse=True)
    # de-dupe near-identical top results
    return results[:12]
