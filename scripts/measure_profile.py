#!/usr/bin/env python3
"""Measure import / reassembly / apply against the NFR stress profile.

Example::

    python scripts/measure_profile.py --profile smoke
    python scripts/measure_profile.py --profile nfr --keep
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "nfr"), default="smoke")
    parser.add_argument("--keep", action="store_true", help="Keep generated PCAP")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="PCAP output path (default: temp or demo/corpus/stress_<profile>.pcap)",
    )
    parser.add_argument("--json", dest="json_out", action="store_true")
    args = parser.parse_args(argv)

    from netslider.core.interp import apply_interpretation_file
    from netslider.core.limits import check_capture_file, check_packet_count
    from netslider.core.pcap import import_capture
    from netslider.core.tcp import build_session_index, packets_for_session, reassemble_session
    from netslider.core.tcp.session import Direction
    from netslider.demo.corpus.stress import generate_stress_pcap

    interp = ROOT / "netslider" / "demo" / "corpus" / "interpretations" / "device_v1.yaml"
    if args.out is not None:
        pcap_path = args.out
    elif args.keep:
        pcap_path = ROOT / "netslider" / "demo" / "corpus" / f"stress_{args.profile}.pcap"
    else:
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp.close()
        pcap_path = Path(tmp.name)

    t_gen0 = time.perf_counter()
    gen = generate_stress_pcap(pcap_path, profile=args.profile)
    t_gen = time.perf_counter() - t_gen0

    limit_file = check_capture_file(pcap_path)
    t_imp0 = time.perf_counter()
    cap = import_capture(pcap_path, capture_id=pcap_path.stem)
    t_imp = time.perf_counter() - t_imp0
    limit_pkts = check_packet_count(cap.diagnostics.packet_count)

    t_idx0 = time.perf_counter()
    index = build_session_index(cap)
    t_idx = time.perf_counter() - t_idx0

    t_re0 = time.perf_counter()
    streams = []
    for sess in index.sessions:
        streams.append(
            reassemble_session(sess, packets_for_session(cap, sess), capture_id=cap.capture_id)
        )
    t_re = time.perf_counter() - t_re0

    t_ap0 = time.perf_counter()
    apply_ok = 0
    for bundle in streams:
        for stream, direction in (
            (bundle.a_to_b, Direction.A_TO_B),
            (bundle.b_to_a, Direction.B_TO_A),
        ):
            if stream.length == 0:
                continue
            result = apply_interpretation_file(
                interp, stream, capture_id=cap.capture_id, direction=direction
            )
            apply_ok += result.stats.messages_ok
    t_ap = time.perf_counter() - t_ap0

    report = {
        "profile": args.profile,
        "generate_s": round(t_gen, 4),
        "import_s": round(t_imp, 4),
        "index_s": round(t_idx, 4),
        "reassemble_s": round(t_re, 4),
        "apply_s": round(t_ap, 4),
        "total_s": round(t_gen + t_imp + t_idx + t_re + t_ap, 4),
        "pcap_bytes": gen["bytes"],
        "pcap_mib": gen["mib"],
        "packets": cap.diagnostics.packet_count,
        "sessions": len(index.sessions),
        "messages_ok": apply_ok,
        "limit_warnings": limit_file.warnings + limit_pkts.warnings,
        "limit_errors": limit_file.errors + limit_pkts.errors,
        "pcap": str(pcap_path),
    }

    if not args.keep and args.out is None:
        try:
            pcap_path.unlink(missing_ok=True)
        except OSError:
            pass

    if args.json_out:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"profile={report['profile']} packets={report['packets']} "
            f"size={report['pcap_mib']}MiB messages_ok={report['messages_ok']}"
        )
        print(
            f"  generate={report['generate_s']}s import={report['import_s']}s "
            f"index={report['index_s']}s reassemble={report['reassemble_s']}s "
            f"apply={report['apply_s']}s total={report['total_s']}s"
        )
        for w in report["limit_warnings"]:
            print(f"  WARN: {w}")
        for e in report["limit_errors"]:
            print(f"  ERR: {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
