"""TCP mock device implementing the demo binary protocol."""

from __future__ import annotations

import argparse
import logging
import socket
import socketserver
import struct
import threading
from typing import Callable

from netslider.demo import protocol as proto

log = logging.getLogger("netslider.demo.device")

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9100


class DeviceState:
    def __init__(self) -> None:
        self.params: dict[int, int] = {
            1: 100,  # setpoint
            2: 25,  # threshold
            3: 1,  # mode
        }
        self._lock = threading.Lock()

    def get(self, param_id: int) -> int | None:
        with self._lock:
            return self.params.get(param_id)

    def set(self, param_id: int, value: int) -> int | None:
        with self._lock:
            if param_id not in self.params:
                return None
            self.params[param_id] = value & 0xFFFF
            return self.params[param_id]

    def measurement(self, sensor_id: int) -> bytes:
        # Deterministic pseudo-measurement; size grows with sensor_id for corpus variety.
        n = min(64 * 1024, 16 + sensor_id * 64)
        return bytes((i + sensor_id) & 0xFF for i in range(n))


def handle_frame(state: DeviceState, frame: proto.Frame) -> bytes:
    op = frame.opcode
    if op == proto.Opcode.READ_PARAM:
        if len(frame.payload) < 2:
            return proto.error_frame(1)
        (param_id,) = struct.unpack_from("<H", frame.payload, 0)
        value = state.get(param_id)
        if value is None:
            return proto.error_frame(2)
        return proto.param_value(param_id, value)

    if op == proto.Opcode.SET_PARAM:
        if len(frame.payload) < 4:
            return proto.error_frame(1)
        param_id, value = struct.unpack_from("<HH", frame.payload, 0)
        new_val = state.set(param_id, value)
        if new_val is None:
            return proto.error_frame(2)
        return proto.param_value(param_id, new_val)

    if op == proto.Opcode.READ_MEASUREMENT:
        if len(frame.payload) < 1:
            return proto.error_frame(1)
        sensor_id = frame.payload[0]
        data = state.measurement(sensor_id)
        return proto.measurement_data(sensor_id, data)

    return proto.error_frame(3)


class DeviceHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: ThreadedTCPServer = self.server  # type: ignore[assignment]
        state = server.device_state
        on_exchange = server.on_exchange
        sock: socket.socket = self.request
        sock.settimeout(30.0)
        buf = b""
        log.info("client connected %s", self.client_address)
        try:
            while True:
                chunk = sock.recv(65535)
                if not chunk:
                    break
                buf += chunk
                while True:
                    frame, consumed = proto.try_decode_one(buf)
                    if consumed == 0:
                        break
                    if frame is None:
                        buf = buf[consumed:]
                        continue
                    request = buf[:consumed]
                    buf = buf[consumed:]
                    reply = handle_frame(state, frame)
                    sock.sendall(reply)
                    if on_exchange is not None:
                        on_exchange(request, reply)
        except (BrokenPipeError, ConnectionResetError, TimeoutError) as exc:
            log.info("connection closed: %s", exc)
        finally:
            log.info("client disconnected %s", self.client_address)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    device_state: DeviceState
    on_exchange: Callable[[bytes, bytes], None] | None


def serve(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    on_exchange: Callable[[bytes, bytes], None] | None = None,
) -> ThreadedTCPServer:
    server = ThreadedTCPServer((host, port), DeviceHandler)
    server.device_state = DeviceState()
    server.on_exchange = on_exchange
    return server


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="netSlider demo mock device")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)
    server = serve(args.host, args.port)
    host, port = server.server_address
    log.info("listening on %s:%s", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
