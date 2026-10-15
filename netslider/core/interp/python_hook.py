"""Restricted-subprocess Python interpretation hooks.

Scripts may define::

    def frame(stream: bytes) -> list[tuple[int, int]]:
        ...

    def parse(message: bytes) -> dict:
        ...

Only a small helper surface is injected; the runner uses a subprocess with a
timeout so a hostile script cannot hang the UI process.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from netslider.core.interp.hashutil import file_content_hash
from netslider.core.interp.models import (
    ApplyResult,
    ApplyStats,
    FieldValue,
    MessageSpan,
    ParsedMessage,
    ValueStatus,
)
from netslider.core.interp.util import direction_str, provenance_for_range, uncovered_ranges
from netslider.core.tcp.reassembly import DirectedStream
from netslider.core.tcp.session import Direction

DEFAULT_TIMEOUT_S = 5.0

_RUNNER = r'''
import json, struct, sys

ALLOWED_IMPORTS = {"struct": struct}

def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name in ALLOWED_IMPORTS:
        return ALLOWED_IMPORTS[name]
    raise ImportError(f"import of {name!r} is not allowed in interpretation scripts")

HELPERS = {
    "__import__": _safe_import,
    "struct": struct,
    "len": len,
    "range": range,
    "enumerate": enumerate,
    "min": min,
    "max": max,
    "sum": sum,
    "abs": abs,
    "bytes": bytes,
    "bytearray": bytearray,
    "int": int,
    "list": list,
    "tuple": tuple,
    "dict": dict,
    "str": str,
    "isinstance": isinstance,
    "True": True,
    "False": False,
    "None": None,
}

def main():
    meta_path = sys.argv[1]
    script_path = sys.argv[2]
    out_path = sys.argv[3]
    meta = json.loads(open(meta_path, "r", encoding="utf-8").read())
    stream = bytes.fromhex(meta["stream_hex"])
    src = open(script_path, "r", encoding="utf-8").read()
    ns = {"__builtins__": HELPERS, "struct": struct}
    exec(compile(src, script_path, "exec"), ns, ns)
    frame_fn = ns.get("frame")
    parse_fn = ns.get("parse")
    spans = []
    if callable(frame_fn):
        raw_spans = frame_fn(stream)
        for item in raw_spans or []:
            if isinstance(item, dict):
                start, end = int(item["start"]), int(item["end"])
            else:
                start, end = int(item[0]), int(item[1])
            spans.append([start, end])
    else:
        spans = [[0, len(stream)]] if stream else []
    messages = []
    for start, end in spans:
        raw = stream[start:end]
        fields = {}
        if callable(parse_fn):
            parsed = parse_fn(raw) or {}
            if isinstance(parsed, dict):
                fields = {str(k): _jsonable(parsed[k]) for k in parsed}
        messages.append({"start": start, "end": end, "fields": fields})
    open(out_path, "w", encoding="utf-8").write(json.dumps({"messages": messages}))

def _jsonable(v):
    if isinstance(v, (bytes, bytearray)):
        return {"__bytes__": bytes(v).hex()}
    if isinstance(v, (int, float, str, bool)) or v is None:
        return v
    return str(v)

if __name__ == "__main__":
    main()
'''


class PythonHookError(Exception):
    """Raised when a Python interpretation fails or times out."""


def _decode_field_payload(value: Any) -> Any:
    if isinstance(value, dict) and "__bytes__" in value:
        return bytes.fromhex(str(value["__bytes__"]))
    return value


def _json_field_value(name: str, value: Any, offset: int = 0) -> FieldValue:
    value = _decode_field_payload(value)
    if isinstance(value, (bytes, bytearray)):
        length = len(value)
        stored: Any = bytes(value)
    elif isinstance(value, int) and not isinstance(value, bool):
        length = 0
        stored = value
    else:
        length = 0
        stored = value
    return FieldValue(
        name=name,
        value=stored,
        status=ValueStatus.RULE,
        offset=offset,
        length=length,
        type_name="python",
    )


def apply_python_script(
    path: Path,
    stream: DirectedStream,
    *,
    capture_id: str,
    direction: Direction | str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    data: bytes | None = None,
) -> ApplyResult:
    path = path.resolve()
    if not path.is_file():
        raise PythonHookError(f"Script not found: {path}")
    direction_s = direction_str(direction if direction is not None else stream.direction)
    buf = data if data is not None else stream.materialize()
    interp_hash = file_content_hash(path)

    with tempfile.TemporaryDirectory(prefix="netslider_py_") as tmp:
        tmp_path = Path(tmp)
        meta_path = tmp_path / "meta.json"
        out_path = tmp_path / "out.json"
        runner_path = tmp_path / "runner.py"
        meta_path.write_text(
            json.dumps({"stream_hex": buf.hex()}),
            encoding="utf-8",
        )
        runner_path.write_text(_RUNNER, encoding="utf-8")
        try:
            proc = subprocess.run(
                [sys.executable, str(runner_path), str(meta_path), str(path), str(out_path)],
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PythonHookError(f"Python interpretation timed out after {timeout_s}s") from exc

        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise PythonHookError(f"Python interpretation failed: {err}")
        if not out_path.is_file():
            raise PythonHookError("Python interpretation produced no output")
        try:
            payload = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PythonHookError(f"Invalid script output JSON: {exc}") from exc

    messages: list[ParsedMessage] = []
    covered: list[tuple[int, int]] = []
    ok = 0
    for item in payload.get("messages") or []:
        start = int(item.get("start", 0))
        end = int(item.get("end", start))
        if end < start:
            start, end = end, start
        start = max(0, min(start, len(buf)))
        end = max(0, min(end, len(buf)))
        raw = buf[start:end]
        fields_raw = item.get("fields") or {}
        fields = [_json_field_value(str(k), fields_raw[k]) for k in fields_raw]
        opcode = None
        if "opcode" in fields_raw and isinstance(fields_raw["opcode"], int):
            opcode = fields_raw["opcode"]
        elif raw:
            opcode = raw[0]
        covered.append((start, end))
        ok += 1
        messages.append(
            ParsedMessage(
                span=MessageSpan(start=start, end=end, status="ok"),
                fields=fields,
                provenance=provenance_for_range(
                    stream, capture_id, start, end - start, direction_s
                ),
                matched_rule="python",
                opcode=opcode,
                raw=raw,
                body_offset=start,
            )
        )

    uncovered = uncovered_ranges(len(buf), covered)
    stats = ApplyStats(
        messages_ok=ok,
        messages_error=0,
        bytes_covered=sum(e - s for s, e in covered),
        bytes_total=len(buf),
        uncovered_ranges=uncovered,
    )
    return ApplyResult(
        interpretation_id=path.stem,
        interpretation_hash=interp_hash,
        capture_id=capture_id,
        session_id=stream.session_id,
        direction=direction_s,
        messages=messages,
        stats=stats,
        source="python",
    )
