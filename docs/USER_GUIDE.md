# netSlider — User Guide

[Русская версия](USER_GUIDE.ru.md)

This guide is for people who want to **research an undocumented binary TCP protocol** with netSlider: open a capture, form framing and field hypotheses, validate them, and hand off a portable project.

For install details, Docker demo stand, Windows zip build, and developer recipes, see [RUN.md](RUN.md). For architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 1. What it is

netSlider is a **local desktop protocol laboratory**. You bring:

- a PCAP or PCAPNG capture of Ethernet + TCP/IPv4 traffic, and optionally
- an **action log** (what the client did: read / set / measure),

and the tool helps you reassemble directed TCP streams, explore bytes with provenance back to packets, write an **interpretation** (YAML, optional Python), validate it on a corpus, and export a report plus a reusable project.

It is offline by design. There is no cloud, no live-capture UI, and no TLS decryption.

Built for research transfer: another engineer should open your project folder and follow the same trail from conclusions back to bytes.

---

## 2. Why use it

TCP delivers a **byte stream**, not application messages. One frame can span packets; one packet can hold several frames. Retransmits and reordering must not invent bytes.

A value that appears after “set 21” is only a **hypothesis** until it survives other parameters and counterexamples.

netSlider keeps those distinctions visible:

| Concept | Meaning |
|---------|---------|
| Observation | What appears in bytes or logs |
| Rule result | What the interpretation extracts |
| Hypothesis | Claimed meaning — still under test |
| Counterexample | Concrete data where a rule fails |

Use it when you need to:

1. Reconstruct streams honestly (`UNKNOWN` / `AMBIGUOUS` spans instead of guessing bytes).
2. Align traffic with what the operator did.
3. Author and re-check framing and field rules on several captures.
4. Ship a portable project + Markdown report + machine-readable interpretation for CLI reuse.

**Out of scope:** live capture UI, TLS decryption, compression codecs, full state-machine recovery, non-Ethernet / IPv6 parsing (those are diagnosed, not parsed as app payload).

---

## 3. Install and launch

### From source (Python 3.11+)

```bash
python3.11 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .

netslider                  # GUI
netslider-cli --help       # headless tools
```

### Windows zip (no Python on the target PC)

Build with `.\scripts\build_windows.ps1`, then run `NetSlider.exe` from the zip (or `NetSlider.bat` after a local build). Do **not** run EXEs under `build\netslider\`. Details: [RUN.md](RUN.md).

### Captures

| Format | Requirement |
|--------|-------------|
| Classic `.pcap` (demo / `samples/lab`) | Built-in parser — no TShark needed |
| `.pcapng` | Wireshark / **TShark** on `PATH` |

Full setup, demo corpus generation, and Docker stand: [RUN.md](RUN.md).

---

## 4. Five-minute tour (`samples/lab`)

The repo includes a ready portable project. No Docker required.

1. Start the GUI: `netslider`.
2. **File → Open Project…** and choose `samples/lab`.
3. In the Captures list, select `captures/main.pcap`.
4. Toolbar: **Load selected capture** (or double-click). Wait until sessions appear.
5. Select a session. Set **Direction** (`A → B` or `B → A`). Hex and packets fill in.
6. Click a hex byte or a packet row — the provenance label shows stream offset ↔ packet.
7. Bottom tab **Interpret / Validate**:
   - Open the project interpretation from the file combo, or click **Load demo YAML**.
   - **Apply to stream** — parsed messages appear with field detail.
   - Check corpus captures → **Validate corpus**.
8. Bottom tab **Report**: fill rationale → **Refresh preview** → **Export…**  
   (interpretation must be **saved on disk** in the project — editor buffer alone is not enough).
9. Optional: **File → Package Project as Zip…** to hand off the folder.

You have completed one research loop: load → inspect → apply → validate → export.

---

## 5. Workbench anatomy

```text
+------------------+---------------------------+--------------------+
| Project / path   | Direction A→B / B→A       | Packets table      |
| Captures list    | Hex dump                  | Provenance label   |
| Sessions list    | Defects (UNKNOWN/…)       |                    |
+------------------+---------------------------+--------------------+
| Investigate | Interpret / Validate | Observations | Report        |
+-------------------------------------------------------------------+
```

| Area | Role |
|------|------|
| Captures | Files in the portable project (`captures/`) |
| Sessions | TCP connections (5-tuple + instance) found in the loaded capture |
| Direction | One directed half of the connection; hex shows that stream only |
| Hex dump | Reassembled payload for the selected direction |
| Defects | Gaps / conflicts surfaced as `UNKNOWN` or `AMBIGUOUS` |
| Packets | Source frames; click to relate to stream bytes |
| Provenance | Link from a derived range back to packets and offsets |

**Menus (File):** New / Open / Save Project → Import Capture / Action Log / Interpretation → Open Capture in Workspace → Export Report → Package Project as Zip → Quit.

**Toolbar:** Load selected capture · Open action log… · Cancel load.

---

## 6. Investigate

Bottom tab **Investigate** has three tools. Use them **before** locking an interpretation.

### Actions

Align an action log (read / set / measure timestamps) with the capture.

- If the project already has an action log, it can load automatically.
- Or use toolbar **Open action log…**.
- Pick an action to jump toward related packets / stream ranges (time window modes in the panel).

### Framing

Form hypotheses about message boundaries:

- **Find magic** (demo default `MD01`).
- **Probe / Auto grid** for length-prefix layouts.
- Byte **histogram** for delimiter clues.

### Compare

Select a hex range → **Mark as A** / **Mark as B** → unified diff of the two ranges. Useful when two messages should differ only in a setpoint field.

---

## 7. Interpretations

Bottom tab **Interpret / Validate**.

An **interpretation** describes how to split the stream into messages and decode fields. Prefer declarative **YAML**. Use optional **Python** hooks only when YAML is not enough.

### Load and apply

1. Choose a file from the combo (project `interpretations/`), or **Load demo YAML**.
2. Edit in the buffer if needed.
3. **Apply to stream** — runs against the current session + direction.
4. **Save to project** when you want validation history and report export to see this version.

Colors / status on fields reflect whether a value is treated as observation, rule, hypothesis, or unverified (see the panel legend).

### Minimal YAML shape

```yaml
id: my_proto_v1
description: optional
framing:
  type: length_prefixed
  header:
    magic: MD01
    magic_offset: 0
    len_offset: 4
    len_size: 2          # 1, 2, or 4
    endian: be           # be | le
    len_includes_header: false
messages:
  - name: example
    when: { field: opcode, eq: 0x01 }
    fields:
      - { name: opcode, offset: 0, type: u8 }
      - { name: param_id, offset: 1, type: u16le, hypothesis: "optional claim" }
unknown_policy: leave_unparsed
```

Checked-in example: [`samples/lab/interpretations/device_v1.yaml`](../samples/lab/interpretations/device_v1.yaml).

### Field types

`u8` / `i8`, `u16le` / `u16be`, `i16*`, `u32*` / `i32*`, `bytes` / `rest` / `raw`, `bytes:N`.

Optional per field: `hypothesis` text and/or `status`: `observation` | `rule` | `hypothesis` | `unverified`.

### Python hooks (advanced)

A `.py` next to the YAML can expose:

- `frame(stream) -> [(start, end), ...]`
- `parse(message) -> dict`

Runs in a restricted subprocess with a timeout. Example: `samples/lab/interpretations/device_v1_frame.py`.

---

## 8. Validate on a corpus

Still on **Interpret / Validate**:

1. Check which project captures to include.
2. Optionally both directions / all sessions.
3. **Validate corpus** (async; use **Cancel** if needed).

### Hit kinds

| Kind | Meaning |
|------|---------|
| `ok` | Rule applied cleanly |
| `contradict` | Rule disagrees with span status or decode expectations |
| `uncovered` | Bytes / regions the interpretation did not cover as expected |
| `unknown` | Stream span is `UNKNOWN` (gap / missing data) |
| `ambiguous` | Stream span is `AMBIGUOUS` (overlap conflict) |
| `inapplicable` | Capture / session not suitable for this check |

Filter hits in the panel; click a hit to jump into hex (may reload another capture).

### Stale results

If you edit the interpretation after a validation run, saved results are marked **stale** (hash of the interpretation changed). Re-run validate before trusting the numbers.

---

## 9. Observations

Bottom tab **Observations**.

Human notes tied to the current selection:

- capture, session, direction, stream offset, length

**Save observation** writes JSON under `observations/`. Browse saved notes and jump back to the linked range. Requires an open project.

Use observations for “looks like a length field” style notes that are not yet formal YAML rules.

---

## 10. Export report and package zip

### Report

Tab **Report** (or **File → Export Report**):

1. Title, rationale, scope, open questions.
2. **Refresh preview**.
3. **Export…** to a folder — Markdown plus machine-readable interpretation JSON (basename `netslider_report`).

Needs an open project **and** an interpretation file on disk in the project (import or **Save to project**).

### Package zip

**File → Package Project as Zip…** builds a zip of the portable project directory (relative paths only). Unzip elsewhere and **Open Project** — sources stay immutable copies under `captures/`, etc.

---

## 11. Bring your own capture

| Action | Effect |
|--------|--------|
| **File → Import Capture…** | Copies into `captures/` with a relative path in the manifest (portable) |
| **File → Import Action Log…** | Copies into `action_logs/` |
| **File → Import Interpretation…** | Copies into `interpretations/` |
| **File → Open Capture in Workspace…** | Loads for inspection without importing into a project |

Prefer **Import** when you want validation, observations, report, and zip handoff. Workspace-only is fine for a quick look.

Typical flow:

1. **File → New Project…** (empty folder) or open an existing one.
2. Import capture (+ action log if you have one).
3. Load capture → pick session / direction → Investigate → author YAML → Validate on `extra` captures → Report → Zip.

---

## 12. CLI cheat sheet

Same research loop without the GUI. Entry point: `netslider-cli` (or `python -m netslider.cli.main`).

```bash
netslider-cli project-info ./samples/lab

netslider-cli apply ./samples/lab/interpretations/device_v1.yaml \
  ./samples/lab/captures/extra.pcap

netslider-cli validate --project ./samples/lab

netslider-cli report --project ./samples/lab \
  --pcap ./samples/lab/captures/main.pcap --out ./out

netslider-cli project-package ./samples/lab --out ./lab.zip
```

More recipes (inspect, align, demo-corpus): [RUN.md](RUN.md).

---

## 13. Glossary

| Term | In the UI |
|------|-----------|
| Session | One TCP connection instance in the Sessions list |
| Direction | `A → B` or `B → A` half-stream shown in hex |
| Provenance | Mapping from stream bytes back to packets |
| `UNKNOWN` | Missing / gapped payload — never zero-filled |
| `AMBIGUOUS` | Overlapping conflicting payload |
| Interpretation | YAML (and optional Python) that frames and parses messages |
| Apply | Run interpretation on the current directed stream |
| Validate | Run on one or more project captures; produce hit counts |
| Stale | Validation no longer matches current interpretation hash |
| Portable project | Folder with `project.netslider.json` and relative paths only |
| Observation (note) | Human annotation under Observations tab |
| Hypothesis | Field claim still under test (`hypothesis:` in YAML / status) |

---

## 14. Troubleshooting

| Symptom | What to try |
|---------|-------------|
| Empty hex after load | Select a session and a direction; some directions have little or no payload |
| PCAPNG fails to import | Install Wireshark so `tshark` is on `PATH` |
| Load stuck / wrong file | **Cancel load**, then load again |
| Report export refuses | Save or import an interpretation into the project (disk file, not only editor) |
| Validate looks wrong after edit | Re-run Validate; previous run may be **stale** |
| Absolute-path warnings after move | Keep relative imports; re-open the project folder; see `project-info` / portability checks in [RUN.md](RUN.md) |
| Windows SmartScreen / slow first run | Expected for unsigned zip; Defender may scan `dist` once |
| Wrong EXE path | Use `dist\NetSlider\NetSlider.exe` or `NetSlider.bat`, never `build\netslider\` |

---

## 15. Appendix — YAML reference and examples

**Required:** `id`, `framing` (`type: length_prefixed` today), `messages`.

**Framing header fields:** `magic`, `magic_offset`, `len_offset`, `len_size` (1/2/4), `endian` (`be`|`le`), `len_includes_header`.

**Message `when`:** `{ field: <name>, eq: <value> }` (and related clauses supported by the schema).

**`unknown_policy`:** default `leave_unparsed`.

**Examples:**

- [`samples/lab/interpretations/device_v1.yaml`](../samples/lab/interpretations/device_v1.yaml)
- [`samples/lab/interpretations/device_v1_frame.py`](../samples/lab/interpretations/device_v1_frame.py)
- Demo corpus copy: `netslider/demo/corpus/interpretations/`

**Research loop (reminder):**

```text
PCAP + action log
      → session / directed stream (hex + provenance)
      → framing hypotheses
      → YAML / Python interpretation
      → corpus validate → refine on counterexamples
      → portable project + report + netslider-cli apply
```
