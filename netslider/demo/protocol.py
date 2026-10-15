"""Demo device binary protocol (unencrypted over TCP).

Frame layout (big-endian length)::

    magic[4] = b"MD01"
    length[u16be]  — bytes after header (opcode + payload), not including magic/len
    opcode[u8]
    payload[...]

Opcodes
-------
0x01 READ_PARAM        payload: param_id u16le
0x02 SET_PARAM         payload: param_id u16le, value u16le
0x03 PARAM_VALUE       payload: param_id u16le, value u16le
0x10 READ_MEASUREMENT  payload: sensor_id u8
0x11 MEASUREMENT_DATA  payload: sensor_id u8, n_bytes u16le, data[n]
0x7F ERROR             payload: code u8
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterator

MAGIC = b"MD01"
HEADER_SIZE = 6  # magic + length


class Opcode(IntEnum):
    READ_PARAM = 0x01
    SET_PARAM = 0x02
    PARAM_VALUE = 0x03
    READ_MEASUREMENT = 0x10
    MEASUREMENT_DATA = 0x11
    ERROR = 0x7F


@dataclass(frozen=True)
class Frame:
    opcode: int
    payload: bytes

    def encode(self) -> bytes:
        body = bytes([self.opcode & 0xFF]) + self.payload
        return MAGIC + struct.pack(">H", len(body)) + body


def encode_frame(opcode: int, payload: bytes = b"") -> bytes:
    return Frame(opcode=opcode, payload=payload).encode()


def try_decode_one(buf: bytes) -> tuple[Frame | None, int]:
    """Try to decode one frame from *buf*. Returns (frame|None, bytes_consumed)."""
    if len(buf) < HEADER_SIZE:
        return None, 0
    if buf[:4] != MAGIC:
        # Skip one byte to resync (device/client treat as hard error in practice)
        return None, 1
    (body_len,) = struct.unpack_from(">H", buf, 4)
    total = HEADER_SIZE + body_len
    if len(buf) < total:
        return None, 0
    if body_len < 1:
        return None, total
    body = buf[HEADER_SIZE:total]
    return Frame(opcode=body[0], payload=body[1:]), total


def iter_frames(buf: bytes) -> Iterator[tuple[Frame, int, int]]:
    """Yield (frame, start, end) for complete frames in *buf*."""
    offset = 0
    while offset < len(buf):
        frame, consumed = try_decode_one(buf[offset:])
        if consumed == 0:
            break
        if frame is None:
            offset += consumed
            continue
        start = offset
        end = offset + consumed
        yield frame, start, end
        offset = end


def read_param(param_id: int) -> bytes:
    return encode_frame(Opcode.READ_PARAM, struct.pack("<H", param_id))


def set_param(param_id: int, value: int) -> bytes:
    return encode_frame(Opcode.SET_PARAM, struct.pack("<HH", param_id, value))


def param_value(param_id: int, value: int) -> bytes:
    return encode_frame(Opcode.PARAM_VALUE, struct.pack("<HH", param_id, value))


def read_measurement(sensor_id: int) -> bytes:
    return encode_frame(Opcode.READ_MEASUREMENT, bytes([sensor_id & 0xFF]))


def measurement_data(sensor_id: int, data: bytes) -> bytes:
    payload = bytes([sensor_id & 0xFF]) + struct.pack("<H", len(data)) + data
    return encode_frame(Opcode.MEASUREMENT_DATA, payload)


def error_frame(code: int) -> bytes:
    return encode_frame(Opcode.ERROR, bytes([code & 0xFF]))
