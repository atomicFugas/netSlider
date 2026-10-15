"""Scripted client that drives the mock device and emits an action log."""

from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netslider.demo import protocol as proto

log = logging.getLogger("netslider.demo.client")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9100


@dataclass
class ActionEvent:
    seq: int
    ts: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    note: str = ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeviceClient:
    def __init__(self, host: str, port: int, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.buf = b""

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        self.buf = b""

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.sock = None

    def _transact(self, request: bytes) -> proto.Frame:
        assert self.sock is not None
        self.sock.sendall(request)
        deadline = time.monotonic() + self.timeout
        while True:
            frame, consumed = proto.try_decode_one(self.buf)
            if frame is not None and consumed:
                self.buf = self.buf[consumed:]
                return frame
            if consumed and frame is None:
                self.buf = self.buf[consumed:]
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for device response")
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(65535)
            if not chunk:
                raise ConnectionError("device closed connection")
            self.buf += chunk

    def read_param(self, param_id: int) -> tuple[int, int]:
        frame = self._transact(proto.read_param(param_id))
        if frame.opcode != proto.Opcode.PARAM_VALUE or len(frame.payload) < 4:
            raise RuntimeError(f"unexpected reply opcode={frame.opcode:#x}")
        pid, value = struct.unpack_from("<HH", frame.payload, 0)
        return pid, value

    def set_param(self, param_id: int, value: int) -> tuple[int, int]:
        frame = self._transact(proto.set_param(param_id, value))
        if frame.opcode != proto.Opcode.PARAM_VALUE or len(frame.payload) < 4:
            raise RuntimeError(f"unexpected reply opcode={frame.opcode:#x}")
        pid, new_val = struct.unpack_from("<HH", frame.payload, 0)
        return pid, new_val

    def read_measurement(self, sensor_id: int) -> tuple[int, bytes]:
        frame = self._transact(proto.read_measurement(sensor_id))
        if frame.opcode != proto.Opcode.MEASUREMENT_DATA or len(frame.payload) < 3:
            raise RuntimeError(f"unexpected reply opcode={frame.opcode:#x}")
        sensor = frame.payload[0]
        (n,) = struct.unpack_from("<H", frame.payload, 1)
        data = frame.payload[3 : 3 + n]
        return sensor, data


def run_script(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    pause_s: float = 0.05,
) -> list[ActionEvent]:
    """Execute a fixed research scenario and return action events."""
    events: list[ActionEvent] = []
    client = DeviceClient(host, port)
    seq = 0

    def log_action(action: str, params: dict, result: dict, note: str = "") -> None:
        nonlocal seq
        seq += 1
        events.append(
            ActionEvent(
                seq=seq,
                ts=_utc_now(),
                action=action,
                params=params,
                result=result,
                note=note,
            )
        )

    client.connect()
    try:
        log_action("connect", {"host": host, "port": port}, {"ok": True})

        for param_id in (1, 2, 3):
            time.sleep(pause_s)
            pid, value = client.read_param(param_id)
            log_action(
                "read_param",
                {"param_id": param_id},
                {"param_id": pid, "value": value},
            )

        time.sleep(pause_s)
        pid, value = client.set_param(1, 180)
        log_action(
            "set_param",
            {"param_id": 1, "value": 180},
            {"param_id": pid, "value": value},
            note="raise setpoint",
        )

        time.sleep(pause_s)
        pid, value = client.read_param(1)
        log_action(
            "read_param",
            {"param_id": 1},
            {"param_id": pid, "value": value},
            note="verify setpoint",
        )

        for sensor_id in (1, 4, 8):
            time.sleep(pause_s)
            sid, data = client.read_measurement(sensor_id)
            log_action(
                "read_measurement",
                {"sensor_id": sensor_id},
                {"sensor_id": sid, "nbytes": len(data), "sha1_prefix": data[:8].hex()},
            )

        time.sleep(pause_s)
        pid, value = client.set_param(2, 40)
        log_action(
            "set_param",
            {"param_id": 2, "value": 40},
            {"param_id": pid, "value": value},
            note="raise threshold",
        )
    finally:
        client.close()
        log_action("disconnect", {}, {"ok": True})

    return events


def write_action_log(events: list[ActionEvent], path: Path) -> None:
    payload = {
        "format": "netslider.action_log.v1",
        "device": "demo-device",
        "events": [asdict(e) for e in events],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="netSlider demo scripted client")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--out", type=Path, default=Path("action_log.json"))
    parser.add_argument("--pause", type=float, default=0.05)
    args = parser.parse_args(argv)
    events = run_script(args.host, args.port, pause_s=args.pause)
    write_action_log(events, args.out)
    log.info("wrote %s (%d events)", args.out, len(events))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
