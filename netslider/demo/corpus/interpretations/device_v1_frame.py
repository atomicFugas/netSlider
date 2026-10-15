"""Python framing/parse hook for the demo MD01 protocol."""

import struct

MAGIC = b"MD01"


def frame(stream: bytes):
    spans = []
    offset = 0
    while offset + 6 <= len(stream):
        if stream[offset : offset + 4] != MAGIC:
            nxt = stream.find(MAGIC, offset + 1)
            if nxt < 0:
                break
            offset = nxt
            continue
        (body_len,) = struct.unpack_from(">H", stream, offset + 4)
        total = 6 + body_len
        if offset + total > len(stream):
            break
        spans.append((offset, offset + total))
        offset += total
    return spans


def parse(message: bytes):
    if len(message) < 7 or message[:4] != MAGIC:
        return {}
    (body_len,) = struct.unpack_from(">H", message, 4)
    body = message[6 : 6 + body_len]
    if not body:
        return {}
    opcode = body[0]
    out = {"opcode": opcode}
    if opcode in (0x01, 0x03) and len(body) >= 3:
        out["param_id"] = struct.unpack_from("<H", body, 1)[0]
        if opcode == 0x03 and len(body) >= 5:
            out["value"] = struct.unpack_from("<H", body, 3)[0]
    elif opcode == 0x02 and len(body) >= 5:
        out["param_id"] = struct.unpack_from("<H", body, 1)[0]
        out["value"] = struct.unpack_from("<H", body, 3)[0]
    elif opcode == 0x10 and len(body) >= 2:
        out["sensor_id"] = body[1]
    elif opcode == 0x11 and len(body) >= 4:
        out["sensor_id"] = body[1]
        out["n_bytes"] = struct.unpack_from("<H", body, 2)[0]
    elif opcode == 0x7F and len(body) >= 2:
        out["code"] = body[1]
    return out
