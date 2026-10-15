# Madrigal — Approach

## Problem

Recover structure and meaning from an **undocumented binary TCP protocol** using
only captures (and optional action logs), without mutating sources, and with
results that remain auditable and reusable on new captures.

## Method

1. **Import with diagnosis** — Ethernet/IPv4/TCP only; unsupported L2/IPv6 is
   reported, not silently mis-parsed.
2. **Session-aware reassembly** — 5-tuple + connection instance; directed
   streams; UNKNOWN/AMBIGUOUS spans instead of invented bytes.
3. **Investigate before committing** — action-log time windows, magic /
   length-prefix probes, range compare to form framing hypotheses.
4. **Author interpretations** — start declarative (YAML); escalate to Python
   hooks only when needed; separate **rule** values from **hypotheses**.
5. **Validate on a corpus** — counts for ok / contradict / uncovered / unknown /
   ambiguous / inapplicable; mark runs **stale** when the interpretation hash
   changes.
6. **Export for reuse** — Markdown rationale + machine interpretation JSON;
   `madrigal apply --project … --pcap extra.pcap` proves generalization
   (not filename lookup).

## Demo stand

A fake MD01 length-prefixed device (read/set param, measurement) produces the
checked-in corpus (`main.pcap`, `extra.pcap`, action logs) so evaluation does
not require hardware. Defect captures under `demo/corpus/defects/` exercise
UNKNOWN / retransmit / AMBIGUOUS reassembly. Stress profiles under
`demo/corpus/stress.py` exercise the ~100 MiB / 250k packet NFR with
`scripts/measure_profile.py`.

## What we deliberately skip

Live capture UI, TLS decryption, compression codecs, full state-machine
recovery, and non-Ethernet/IPv6 parsing (diagnose only) — per the brief.
