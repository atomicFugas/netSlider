"""Compare / diff two stream byte ranges."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RangeDiff:
    a_start: int
    a_data: bytes
    b_start: int
    b_data: bytes
    equal: bool
    first_diff: int | None  # index into min-length prefix, or None if equal prefix
    length_delta: int
    summary: str
    unified: str


def diff_ranges(a_data: bytes, a_start: int, b_data: bytes, b_start: int) -> RangeDiff:
    n = min(len(a_data), len(b_data))
    first = None
    for i in range(n):
        if a_data[i] != b_data[i]:
            first = i
            break
    equal = first is None and len(a_data) == len(b_data)
    length_delta = len(a_data) - len(b_data)
    if equal:
        summary = f"identical ({len(a_data)} B)"
    elif first is None:
        summary = f"common prefix {n} B; length Δ={length_delta}"
    else:
        summary = (
            f"first diff at +{first} "
            f"(A[{a_start + first}]=0x{a_data[first]:02x} "
            f"B[{b_start + first}]=0x{b_data[first]:02x}); "
            f"len A={len(a_data)} B={len(b_data)}"
        )
    unified = _unified_hex(a_data, b_data, a_start, b_start, context=8)
    return RangeDiff(
        a_start=a_start,
        a_data=a_data,
        b_start=b_start,
        b_data=b_data,
        equal=equal,
        first_diff=first,
        length_delta=length_delta,
        summary=summary,
        unified=unified,
    )


def _unified_hex(a: bytes, b: bytes, a_start: int, b_start: int, context: int = 8) -> str:
    lines = ["--- A", "+++ B"]
    n = max(len(a), len(b))
    # show around first difference if any
    first = 0
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            first = i
            break
    lo = max(0, first - context)
    hi = min(n, first + context + 1)
    for i in range(lo, hi):
        av = f"{a[i]:02x}" if i < len(a) else "  "
        bv = f"{b[i]:02x}" if i < len(b) else "  "
        mark = " " if av == bv else "!"
        lines.append(f"{mark} @{a_start + i:04x}/{b_start + i:04x}  {av} | {bv}")
    return "\n".join(lines)
