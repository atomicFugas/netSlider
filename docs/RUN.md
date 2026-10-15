# netSlider — Run

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

**System dependency:** PCAPNG import needs **TShark** (`brew install wireshark` on macOS, or install [Wireshark](https://www.wireshark.org/) on Windows and ensure `tshark` is on `PATH`).
Classic PCAP (demo corpus) uses the built-in parser and does not require TShark.

## GUI

```bash
netslider
# or
python -m netslider.app.main
```

## Windows distributable (other PC, no Python)

Build on a Windows machine that already has the project venv:

```powershell
.\scripts\build_windows.ps1
```

This produces:

- `dist\NetSlider\NetSlider.exe` — double-click to launch the GUI
- `dist\NetSlider\netslider-cli.exe` — headless CLI
- `dist\NetSlider-windows.zip` — copy this to another PC
- `NetSlider.bat` at the repo root — one-click launch of the dist build

**Run only** `dist\NetSlider\NetSlider.exe` or `NetSlider.bat`. Do **not** run anything under `build\netslider\` (PyInstaller staging EXEs look for a missing `_internal\python*.dll` and fail with "Failed to load Python DLL").

On the other PC: unzip, double-click `NetSlider.exe`. Classic `.pcap` works with no extra installs. For `.pcapng`, install Wireshark so `tshark` is on `PATH`. First launch may be slow while Windows Defender scans the folder. An unsigned build may show a SmartScreen warning once.

| Area | Use |
|------|-----|
| File → New/Open/Save project | Portable project directory |
| Import Capture / Action Log / Interpretation | Copies into project (relative paths) |
| Load selected capture | Background import + reassembly (**Cancel load** on toolbar) |
| Investigate tabs | Actions, Framing, Compare |
| Interpret / Validate | YAML/Python editor, apply, multi-capture corpus validate (async + Cancel) |
| Observations | Notes linked to hex selection (offset/length + provenance) |
| Report | Markdown preview + export (also File → Export Report) |
| Package Zip | Zippable portable project |

## CLI

Entry points: `netslider-cli` (or `python -m netslider.cli.main`).

```bash
# Create a portable project (or use the checked-in samples/lab)
netslider-cli project-new ./samples/lab --name demo
netslider-cli project-info ./samples/lab

# Seed it from the demo corpus (once)
netslider-cli demo-corpus
# then in the GUI: Import Capture / Action Log / Interpretation
# or copy files into samples/lab/{captures,action_logs,interpretations}/

netslider-cli inspect netslider/demo/corpus/main.pcap
netslider-cli align netslider/demo/corpus/main.pcap netslider/demo/corpus/action_log.json

# Apply / validate — positional paths (no project needed)
netslider-cli apply netslider/demo/corpus/interpretations/device_v1.yaml \
  netslider/demo/corpus/extra.pcap

# Or project-scoped (requires ./samples/lab to exist with an interpretation)
netslider-cli apply --project ./samples/lab --pcap netslider/demo/corpus/extra.pcap
netslider-cli validate netslider/demo/corpus/interpretations/device_v1.yaml \
  netslider/demo/corpus/main.pcap --json-out

# Validate all captures listed in a portable project
netslider-cli validate --project ./samples/lab

netslider-cli report --project ./samples/lab \
  --pcap netslider/demo/corpus/main.pcap --out ./out
netslider-cli project-package ./samples/lab --out ./lab.zip
```

If `netslider-cli` is not on `PATH`, use `python -m netslider.cli.main …` after `pip install -e .`.

## Demo corpus & golden fixtures

```bash
netslider-demo-corpus
# or: python -m netslider.demo.corpus

# Regenerate expected apply/validate summaries:
python -m netslider.demo.corpus.golden
```

Golden files: `netslider/demo/corpus/golden/expected_*.json`.

Defect captures (gap / retransmit / overlap / reorder) are written under
`netslider/demo/corpus/defects/` by the same generator.

## Docker demo stand (optional)

Local synth (`netslider-demo-corpus`) is enough for development and CI.
When Docker is available, the mock device + client + tcpdump path is:

```bash
cd netslider/demo
docker compose up --build
```

This writes a live capture as `netslider/demo/corpus/main_live.pcapng`
(gitignored). Requires a Docker engine that can run `nicolaka/netshoot`
with `NET_RAW` / `NET_ADMIN` for tcpdump.

## NFR measurement

```bash
# Fast smoke (~thousands of packets)
python scripts/measure_profile.py --profile smoke --json

# Full plan profile (~100 MiB / ≥250k packets) — slow, large disk
python scripts/measure_profile.py --profile nfr --keep
```

Generate stress PCAPs directly:

```bash
python -m netslider.demo.corpus.stress --profile smoke --out /tmp/stress.pcap
```

Project `settings.json` → `limits` controls soft warn / hard max for capture
size and packet count (defaults: warn 100 MiB / 250k; max 200 MiB / 500k).

## Tests

```bash
pytest -q
```

## Project layout (portable)

```
project.netslider.json
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
