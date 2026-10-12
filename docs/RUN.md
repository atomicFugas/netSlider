# Madrigal — Run

## Setup

```bash
cd /path/to/NetSliders
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
# optional pinned set:
# pip install -r requirements.lock
```

**System dependency:** PCAPNG import needs **TShark** (`brew install wireshark`).
Classic PCAP (demo corpus) uses the built-in parser and does not require TShark.

## GUI

```bash
madrigal
# or
python -m madrigal.app.main
```

| Area | Use |
|------|-----|
| File → New/Open/Save project | Portable project directory |
| Import Capture / Action Log / Interpretation | Copies into project (relative paths) |
| Load selected capture | Background import + reassembly (**Cancel load** on toolbar) |
| Investigate tabs | Actions, Framing, Compare |
| Interpret / Validate | YAML/Python editor, apply, corpus validation |
| Export Report / Package Zip | Markdown+JSON report; zippable project |

## CLI

Entry points: `madrigal-cli` (or `python -m madrigal.cli.main`).

```bash
# Create a portable project (or use the checked-in samples/lab)
madrigal-cli project-new ./samples/lab --name demo
madrigal-cli project-info ./samples/lab

# Seed it from the demo corpus (once)
madrigal-cli demo-corpus
# then in the GUI: Import Capture / Action Log / Interpretation
# or copy files into samples/lab/{captures,action_logs,interpretations}/

madrigal-cli inspect madrigal/demo/corpus/main.pcap
madrigal-cli align madrigal/demo/corpus/main.pcap madrigal/demo/corpus/action_log.json

# Apply / validate — positional paths (no project needed)
madrigal-cli apply madrigal/demo/corpus/interpretations/device_v1.yaml \
  madrigal/demo/corpus/extra.pcap

# Or project-scoped (requires ./samples/lab to exist with an interpretation)
madrigal-cli apply --project ./samples/lab --pcap madrigal/demo/corpus/extra.pcap
madrigal-cli validate madrigal/demo/corpus/interpretations/device_v1.yaml \
  madrigal/demo/corpus/main.pcap --json-out

madrigal-cli report --project ./samples/lab \
  --pcap madrigal/demo/corpus/main.pcap --out ./out
madrigal-cli project-package ./samples/lab --out ./lab.zip
```

If `madrigal-cli` is not on `PATH`, use `python -m madrigal.cli.main …` after `pip install -e .`.

## Demo corpus & golden fixtures

```bash
madrigal-demo-corpus
# or: python -m madrigal.demo.corpus

# Regenerate expected apply/validate summaries:
python -m madrigal.demo.corpus.golden
```

Golden files: `madrigal/demo/corpus/golden/expected_*.json`.

## NFR measurement

```bash
# Fast smoke (~thousands of packets)
python scripts/measure_profile.py --profile smoke --json

# Full plan profile (~100 MiB / ≥250k packets) — slow, large disk
python scripts/measure_profile.py --profile nfr --keep
```

Generate stress PCAPs directly:

```bash
python -m madrigal.demo.corpus.stress --profile smoke --out /tmp/stress.pcap
```

Project `settings.json` → `limits` controls soft warn / hard max for capture
size and packet count (defaults: warn 100 MiB / 250k; max 200 MiB / 500k).

## Tests

```bash
pytest -q
```

## Project layout (portable)

```
project.madrigal.json
settings.json
captures/
action_logs/
interpretations/
observations/
validations/
```

All manifest paths are **relative**. After moving or unzipping the project
directory, `project-info` / `assert_portable` should report no absolute-path
warnings.
