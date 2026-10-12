# Madrigal — Architecture

## Layers

```
PySide6 UI (app/)
    │  project browser · sessions · hex · investigate · interpret/validate
    ▼
Core library (core/)
    pcap/          import (classic PCAP + PyShark/PCAPNG)
    tcp/           session index + directed reassembly + SpanStatus
    provenance/    stream byte ↔ packet maps
    investigate/   action-log align, framing probes, compare
    interp/        declarative YAML + sandboxed Python apply
    validate/      corpus counters + stale hash
    project/       portable directory store (relative paths only)
    report/        Markdown + machine interpretation JSON
    limits.py      soft/hard NFR thresholds
    ▼
Demo stand (demo/)
    mock device + scripted client + synthetic PCAP corpus + golden/
```

## Provenance (non-negotiable)

Every derived message / validation hit stores
`(capture_id, session_id, direction, stream_offset, length)` plus optional
packet IDs. Source captures are never rewritten; project imports **copy** into
`captures/`.

## TCP reassembly

Directed streams follow RFC 9293-inspired rules:

| Situation | Result |
|-----------|--------|
| Contiguous payload | `OK` span |
| Gap / truncation | `UNKNOWN` (never zero-filled) |
| Overlap conflict | `AMBIGUOUS` + policy (`first_seen` default) |
| Identical retransmit | Deduplicated |

## Interpretations

1. **Declarative** (default): YAML/JSON with `framing.length_prefixed` + message
   `when` rules and typed fields (`u8`, `u16le`, `bytes`, …).
2. **Python** (advanced): `frame(stream) -> spans`, `parse(message) -> dict` in a
   restricted subprocess with timeout.

Both paths share `ApplyResult` and feed `validate_workspace`.

## Portable project (R5)

```
project.madrigal.json   # relative paths only
settings.json           # tcp + limits
captures/
action_logs/
interpretations/
observations/
validations/
```

Open after directory move: resolve via `ProjectStore.resolve_rel` /
`assert_portable`. Zip via `project-package` / UI **Package Project as Zip**.

## Long operations

`CaptureLoadWorker` (and optional `ValidateWorker`) run on `QThread` with
progress strings and cooperative cancel between sessions. UI **Cancel load**
wires `worker.cancel()`.

## Headless reuse (R6)

```
madrigal apply --project ./lab --pcap extra.pcap
madrigal validate device_v1.yaml main.pcap
madrigal report --project ./lab --pcap main.pcap --out ./out
```

Golden summaries live under `madrigal/demo/corpus/golden/`.
