# netSlider
### Protocol Laboratory

> Research undocumented binary exchange over TCP — keep every conclusion
> tied to packets and bytes, and hand the project to another engineer without
> losing the trail.

netSlider is a local desktop lab for reverse-engineering device protocols when
you have PCAP/PCAPNG and an action log, but no usable protocol spec. Open a
capture, align it with what the client did, frame messages, write an
interpretation, validate it on a corpus, and export a reproducible project.

Built for the course case (historically **МАДРИГАЛ**): offline,
provenance-first, transferable research.

---

## The problem

TCP delivers a **byte stream**, not messages. A single application frame can
span packets; one packet can hold several frames. Retransmits and reordering
must not change the reconstructed payload. A value that appears after
“set 21” is only a **hypothesis** until it survives other parameters and
counterexamples.

netSlider keeps those distinctions visible:

| Concept | Meaning |
|---------|---------|
| Observation | What appears in bytes / logs |
| Rule result | What the interpretation extracts |
| Hypothesis | Claimed meaning — still under test |
| Counterexample | Concrete data where a rule fails |

---

## What you can do

1. **Import** PCAP / PCAPNG (Ethernet + TCP/IPv4), pick a session and direction
2. **Reassemble** directed streams with sequence order, retransmit dedupe, and explicit `UNKNOWN` / `AMBIGUOUS` spans
3. **Navigate** from any derived result back to source packets and stream offsets
4. **Align** traffic with an action log (read / set / measure)
5. **Probe** framing — magic bytes, length prefixes, histograms
6. **Author** interpretations — declarative YAML by default, optional Python for hard cases
7. **Validate** on a corpus — contradictions, gaps, stale runs after edits
8. **Ship** a portable project + human report + machine-readable apply path

---

## Stack

| Layer | Choice |
|-------|--------|
| UI | PySide6 + hex stream viewer |
| Captures | TShark / PyShark (+ classic PCAP parser for demo files) |
| Analysis | pandas |
| Interpretations | YAML schema + optional Python hooks |
| Demo stand | Docker mock device + scripted client |
| Reuse | `netslider-cli` headless apply / validate / report |

No Tkinter. No cloud. Main scenario is **offline**.

---

## Quick start

**User guide:** [English](docs/USER_GUIDE.md) · [Русский](docs/USER_GUIDE.ru.md)
(what it is, why, GUI/CLI walkthrough with `samples/lab`).

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"

# optional: TShark for PCAPNG
# macOS: brew install wireshark

netslider-demo-corpus          # synthetic PCAPs + action logs
netslider                      # GUI
netslider-cli --help           # headless tools
pytest -q
```

Generate a research corpus without hardware:

```bash
netslider-demo-corpus
# → netslider/demo/corpus/main.pcap, action_log.json, extra.pcap, …
```

Or bring up the mock device stand:

```bash
cd netslider/demo && docker compose up --build
```

Detailed steps: [docs/RUN.md](docs/RUN.md)

### Windows zip (run on another PC)

On a Windows build machine with the project venv:

```powershell
.\scripts\build_windows.ps1
```

Copy `dist\NetSlider-windows.zip` to the other PC, unzip, double-click `NetSlider.exe`. Locally after a build, use `NetSlider.bat` or `dist\NetSlider\NetSlider.exe` (never `build\netslider\`). No Python install required on the other PC. Classic PCAP works out of the box; PCAPNG needs Wireshark (`tshark` on `PATH`). See [docs/RUN.md](docs/RUN.md).

---

## Research loop

```text
  PCAP + action log
        │
        ▼
  session / directed stream ──► hex + packets (provenance)
        │
        ▼
  framing hypotheses ──► YAML / Python interpretation
        │
        ▼
  corpus validate ──► refine on counterexamples
        │
        ▼
  portable project + report + `netslider-cli apply`
```

Hand the project folder (or zip) to another machine: relative paths only,
sources immutable, stale validation marked when rules change.

---

## Project layout

```text
netslider/
  app/           PySide6 UI
  core/          PCAP, TCP, provenance, interp, validate, project, report
  cli/           Headless apply / validate / report
  demo/          Mock device, client, corpus generators
docs/            Case brief, runbook, plan
tests/
```

Portable research project (example):

```text
project.netslider.json
captures/
action_logs/
interpretations/
observations/
validations/
settings.json
```

---

## Requirements coverage (case R1–R6)

| ID | Capability |
|----|------------|
| R1 | Source exchange, TCP reassembly, provenance navigation |
| R2 | Action alignment, compare, framing aids |
| R3 | Declarative + Python interpretations, programmable apply |
| R4 | Corpus validation, contradictions, stale results |
| R5 | Portable project, no absolute paths |
| R6 | Markdown report, machine-readable interp, CLI reuse |

Out of scope (per brief): live capture UI, TLS decryption, compression
codecs, full state-machine recovery.

---

## License / case

Course / lab case: **Лаборатория протоколов МАДРИГАЛ** — research and
description of unknown network protocols. See
[docs/Мадригал. Лаборатория протоколов.pdf](docs/Мадригал.%20Лаборатория%20протоколов.pdf).
