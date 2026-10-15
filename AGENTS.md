# netSlider: rules for AI assistants

Protocol laboratory for reverse-engineering undocumented binary TCP protocols from PCAP/PCAPNG and action logs. Stack: Python 3.11+, PySide6 UI, PyShark/TShark (+ classic PCAP parser), pandas, declarative YAML interpretations with optional sandboxed Python hooks, Click CLI, Docker demo stand.

## Workflow

- Read `docs/ARCHITECTURE.md` and `docs/APPROACH.md` first. Use `docs/RUN.md` for local run and corpus setup. The phased plan lives in `docs/netslider_protocol_lab_e90cf7a2.plan.md`.
- Prefer extending `netslider/core/` over one-off UI logic. Keep provenance links for every derived result.
- If something is unclear or hard to undo, ask before acting.

## Rules

1. Write all comments, docstrings, commit messages and branch names in English. Chat replies are in English too, unless the `ask-ru` rule is attached to the conversation.
2. Write like a human developer. No em dashes or en dashes (use `-` or a comma), no emojis, no filler phrasing.
3. Work only inside this project. Never modify system files, global configs, `.env` files or secrets. Install dependencies locally, not globally.
4. Never delete anything without asking first.
5. Ask and warn before any irreversible action (deleting data, dropping a database, `git reset --hard`, force push, deploy).
6. Do not add yourself or the tool to contributors, authors or credits. No `Co-authored-by` trailers, no "Generated with" lines.
7. Inside the project you may freely edit files, install needed plugins and dependencies, and run tests and local scripts, as long as rules 3 to 6 are respected.
8. Never rewrite source captures or invent bytes for gaps. Preserve `UNKNOWN` / `AMBIGUOUS` spans, portable relative paths, and provenance. Do not weaken the Python interpretation sandbox or timeouts, and do not edit golden expected outputs just to make tests pass.
