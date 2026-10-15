"""Generate demo corpus: main PCAP + action log (+ optional extra capture).

Runs the mock device and scripted client locally, records request/response
bytes, and synthesizes a PCAP so no Docker/tcpdump/root is required for Phase 0.
Docker Compose under ``madrigal/demo/`` remains the preferred capture path when available.
"""

from __future__ import annotations

import argparse
import logging
import socket
import threading
import time
from pathlib import Path

from madrigal.demo.client.scripted import run_script, write_action_log
from madrigal.demo.corpus.defects import generate_defect_pcaps
from madrigal.demo.device.server import serve
from madrigal.demo.pcap_synth import Endpoint, RecordedSegment, build_tcp_session_pcap

log = logging.getLogger("madrigal.demo.corpus")

DEFAULT_OUT = Path(__file__).resolve().parent


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def generate_corpus(out_dir: Path, extra: bool = True) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    segments: list[RecordedSegment] = []
    t0 = time.time()
    lock = threading.Lock()

    def on_exchange(request: bytes, reply: bytes) -> None:
        now = time.time()
        with lock:
            segments.append(RecordedSegment(now, True, request))
            segments.append(RecordedSegment(now + 0.001, False, reply))

    server = serve("127.0.0.1", port, on_exchange=on_exchange)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)

    try:
        events = run_script("127.0.0.1", port, pause_s=0.03)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    action_path = out_dir / "action_log.json"
    write_action_log(events, action_path)

    client_ep = Endpoint(ip="10.0.0.2", port=50100, mac=bytes.fromhex("020000000001"))
    server_ep = Endpoint(ip="10.0.0.1", port=9100, mac=bytes.fromhex("020000000002"))
    main_pcap = out_dir / "main.pcap"
    build_tcp_session_pcap(main_pcap, segments, client_ep, server_ep, t0=t0)

    paths: dict[str, Path] = {
        "action_log": action_path,
        "main_pcap": main_pcap,
    }

    if extra:
        # Second capture with different client port / timing for generalization tests.
        port2 = _free_port()
        segments2: list[RecordedSegment] = []

        def on_exchange2(request: bytes, reply: bytes) -> None:
            now = time.time()
            with lock:
                segments2.append(RecordedSegment(now, True, request))
                segments2.append(RecordedSegment(now + 0.001, False, reply))

        server2 = serve("127.0.0.1", port2, on_exchange=on_exchange2)
        t2 = threading.Thread(target=server2.serve_forever, daemon=True)
        t2.start()
        time.sleep(0.05)
        try:
            from datetime import datetime, timezone

            from madrigal.demo.client.scripted import ActionEvent, DeviceClient

            def _now() -> str:
                return datetime.now(timezone.utc).isoformat()

            client = DeviceClient("127.0.0.1", port2)
            client.connect()
            extra_events: list[ActionEvent] = []
            try:
                pid, val = client.set_param(1, 220)
                extra_events.append(
                    ActionEvent(
                        1,
                        _now(),
                        "set_param",
                        {"param_id": 1, "value": 220},
                        {"param_id": pid, "value": val},
                    )
                )
                pid, val = client.read_param(1)
                extra_events.append(
                    ActionEvent(2, _now(), "read_param", {"param_id": 1}, {"param_id": pid, "value": val})
                )
                sid, data = client.read_measurement(2)
                extra_events.append(
                    ActionEvent(
                        3,
                        _now(),
                        "read_measurement",
                        {"sensor_id": 2},
                        {"sensor_id": sid, "nbytes": len(data)},
                    )
                )
            finally:
                client.close()
            write_action_log(extra_events, out_dir / "action_log_extra.json")
        finally:
            server2.shutdown()
            server2.server_close()
            t2.join(timeout=2.0)

        extra_pcap = out_dir / "extra.pcap"
        client2 = Endpoint(ip="10.0.0.3", port=50200, mac=bytes.fromhex("020000000003"))
        build_tcp_session_pcap(extra_pcap, segments2, client2, server_ep, t0=time.time())
        paths["extra_pcap"] = extra_pcap
        paths["action_log_extra"] = out_dir / "action_log_extra.json"

    defect_paths = generate_defect_pcaps(out_dir / "defects")
    for key, path in defect_paths.items():
        paths[f"defect_{key}"] = path

    # Tiny README for humans browsing the corpus folder
    (out_dir / "README.md").write_text(
        "# Demo corpus\n\n"
        "Generated by `madrigal-demo-corpus` / `python -m madrigal.demo.corpus.generate`.\n\n"
        "- `main.pcap` — primary research capture\n"
        "- `action_log.json` — scripted client actions aligned to the same run\n"
        "- `extra.pcap` — second capture with different parameters\n"
        "- `defects/gap.pcap` — sequence gap → UNKNOWN spans\n"
        "- `defects/retransmit.pcap` — identical retransmit dedupe\n"
        "- `defects/overlap.pcap` — overlapping conflict → AMBIGUOUS\n",
        encoding="utf-8",
    )
    return paths


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Generate Madrigal demo corpus")
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output directory (default: madrigal/demo/corpus)",
    )
    parser.add_argument("--no-extra", action="store_true", help="Skip extra capture")
    args = parser.parse_args(argv)
    paths = generate_corpus(args.out, extra=not args.no_extra)
    for key, path in paths.items():
        size = path.stat().st_size if path.exists() else 0
        log.info("%s -> %s (%d bytes)", key, path, size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
