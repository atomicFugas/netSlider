"""Field type codecs for declarative interpretations."""

from __future__ import annotations

import struct
from typing import Any

from madrigal.core.interp.models import FieldValue, ValueStatus
from madrigal.core.interp.schema import FieldSpec


class FieldDecodeError(Exception):
    """Raised when a field cannot be decoded from a message body."""


_TYPE_SIZES = {
    "u8": 1,
    "i8": 1,
    "u16le": 2,
    "u16be": 2,
    "i16le": 2,
    "i16be": 2,
    "u32le": 4,
    "u32be": 4,
    "i32le": 4,
    "i32be": 4,
}


def type_size(type_name: str, body_len: int, offset: int) -> int | None:
    """Return fixed size, or remaining bytes for ``bytes`` / ``rest``."""
    key = type_name.strip().lower()
    if key in _TYPE_SIZES:
        return _TYPE_SIZES[key]
    if key in ("bytes", "rest", "raw"):
        if offset > body_len:
            return None
        return body_len - offset
    if key.startswith("bytes:"):
        try:
            return int(key.split(":", 1)[1], 0)
        except ValueError:
            return None
    return None


def decode_value(body: bytes, offset: int, type_name: str) -> tuple[Any, int]:
    """Decode one value; returns (value, length_consumed)."""
    key = type_name.strip().lower()
    size = type_size(key, len(body), offset)
    if size is None:
        raise FieldDecodeError(f"Unknown type {type_name!r}")
    if offset < 0 or offset + size > len(body):
        raise FieldDecodeError(
            f"Field {type_name} at {offset} needs {size} B, body has {len(body)}"
        )
    chunk = body[offset : offset + size]
    if key == "u8":
        return chunk[0], 1
    if key == "i8":
        return struct.unpack_from("b", chunk, 0)[0], 1
    if key == "u16le":
        return struct.unpack_from("<H", chunk, 0)[0], 2
    if key == "u16be":
        return struct.unpack_from(">H", chunk, 0)[0], 2
    if key == "i16le":
        return struct.unpack_from("<h", chunk, 0)[0], 2
    if key == "i16be":
        return struct.unpack_from(">h", chunk, 0)[0], 2
    if key == "u32le":
        return struct.unpack_from("<I", chunk, 0)[0], 4
    if key == "u32be":
        return struct.unpack_from(">I", chunk, 0)[0], 4
    if key == "i32le":
        return struct.unpack_from("<i", chunk, 0)[0], 4
    if key == "i32be":
        return struct.unpack_from(">i", chunk, 0)[0], 4
    if key in ("bytes", "rest", "raw") or key.startswith("bytes:"):
        return bytes(chunk), size
    raise FieldDecodeError(f"Unsupported type {type_name!r}")


def status_for_field(spec: FieldSpec) -> ValueStatus:
    if spec.status:
        try:
            return ValueStatus(spec.status.lower())
        except ValueError:
            pass
    if spec.hypothesis:
        return ValueStatus.HYPOTHESIS
    return ValueStatus.RULE


def decode_field(body: bytes, spec: FieldSpec) -> FieldValue:
    value, length = decode_value(body, spec.offset, spec.type)
    return FieldValue(
        name=spec.name,
        value=value,
        status=status_for_field(spec),
        offset=spec.offset,
        length=length,
        type_name=spec.type,
        hypothesis=spec.hypothesis,
    )
