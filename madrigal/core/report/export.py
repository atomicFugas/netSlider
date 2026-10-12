"""Markdown + machine-readable report export (R6)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from madrigal.core.interp.schema import InterpretationDoc, load_interpretation
from madrigal.core.project.store import ProjectStore
from madrigal.core.validate.result import ValidationResult


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class ReportDraft:
    """Authorable report sections for Markdown export."""

    title: str = "Madrigal Protocol Report"
    rationale: str = ""
    scope: str = ""
    examples: list[str] = field(default_factory=list)
    counterexamples: list[str] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def interpretation_to_machine_json(doc: InterpretationDoc | Path) -> dict[str, Any]:
    """Export a portable machine-readable interpretation document."""
    if isinstance(doc, Path):
        loaded = load_interpretation(doc)
    else:
        loaded = doc
    payload = loaded.to_dict()
    payload["madrigal_export"] = {
        "format": "interpretation/v1",
        "exported_at": _utc_now_iso(),
        "source_path": (
            loaded.source_path.name if loaded.source_path is not None else None
        ),
    }
    return payload


def build_markdown_report(
    project: ProjectStore | None = None,
    *,
    draft: ReportDraft | None = None,
    interpretation: InterpretationDoc | Path | None = None,
    validation: ValidationResult | dict[str, Any] | None = None,
    apply_summaries: list[dict[str, Any]] | None = None,
) -> str:
    """Compose a Markdown report (rationale, scope, examples, counters, open Qs)."""
    draft = draft or ReportDraft()
    lines: list[str] = [
        f"# {draft.title}",
        "",
        f"_Generated {_utc_now_iso()}_",
        "",
    ]

    if project is not None:
        lines.extend(
            [
                "## Project",
                "",
                f"- **Name:** {project.meta.name}",
                f"- **Format version:** {project.meta.format_version}",
                f"- **Created:** {project.meta.created_at}",
                f"- **Captures:** {len(project.meta.captures)}",
                f"- **Interpretations:** {len(project.list_interpretations())}",
                "",
            ]
        )
        if project.meta.description:
            lines.extend([project.meta.description, ""])

    lines.extend(["## Rationale", "", draft.rationale or "_Not provided._", ""])
    lines.extend(["## Scope", "", draft.scope or "_Not provided._", ""])

    if interpretation is not None:
        if isinstance(interpretation, Path):
            doc = load_interpretation(interpretation)
        else:
            doc = interpretation
        lines.extend(
            [
                "## Interpretation",
                "",
                f"- **Id:** `{doc.id}`",
                f"- **Protocol:** {doc.scope.protocol or '—'}",
                f"- **Versions:** {', '.join(doc.scope.versions) or '—'}",
                f"- **Framing:** `{doc.framing.type}` "
                f"(len_offset={doc.framing.header.len_offset}, "
                f"len_size={doc.framing.header.len_size}, "
                f"endian={doc.framing.header.endian})",
                f"- **Message rules:** {len(doc.messages)}",
                "",
            ]
        )
        if doc.description:
            lines.extend([doc.description, ""])

    lines.append("## Examples")
    lines.append("")
    if draft.examples:
        for ex in draft.examples:
            lines.append(f"- {ex}")
    else:
        lines.append("_None recorded._")
    lines.append("")

    lines.append("## Counterexamples")
    lines.append("")
    if draft.counterexamples:
        for ex in draft.counterexamples:
            lines.append(f"- {ex}")
    else:
        lines.append("_None recorded._")
    lines.append("")

    if validation is not None:
        if isinstance(validation, ValidationResult):
            v = validation.to_dict()
        else:
            v = validation
        counters = v.get("counters") or {}
        lines.extend(
            [
                "## Corpus validation",
                "",
                f"- **Interpretation:** `{v.get('interpretation_id', '—')}`",
                f"- **Hash:** `{str(v.get('interpretation_hash', ''))[:16]}…`",
                f"- **Stale:** {v.get('stale', False)}",
                f"- **ok:** {counters.get('ok', 0)}",
                f"- **contradict:** {counters.get('contradict', 0)}",
                f"- **uncovered (bytes):** {counters.get('uncovered', 0)}",
                f"- **unknown (bytes):** {counters.get('unknown', 0)}",
                f"- **ambiguous (bytes):** {counters.get('ambiguous', 0)}",
                f"- **inapplicable:** {counters.get('inapplicable', 0)}",
                "",
            ]
        )

    if apply_summaries:
        lines.extend(["## Apply summaries", ""])
        for item in apply_summaries:
            stats = item.get("stats") or {}
            lines.append(
                f"- `{item.get('capture_id', '?')}` / `{item.get('session_id', '?')}` "
                f"{item.get('direction', '')}: "
                f"ok={stats.get('messages_ok', 0)} "
                f"err={stats.get('messages_error', 0)} "
                f"coverage={stats.get('coverage', 0)}"
            )
        lines.append("")

    lines.extend(["## Open questions", ""])
    if draft.open_questions:
        for q in draft.open_questions:
            lines.append(f"- {q}")
    else:
        lines.append("_None recorded._")
    lines.append("")

    if draft.notes:
        lines.extend(["## Notes", ""])
        for n in draft.notes:
            lines.append(f"- {n}")
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "_Exported by Madrigal Protocol Laboratory._",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(
    out_dir: Path,
    *,
    project: ProjectStore | None = None,
    draft: ReportDraft | None = None,
    interpretation: InterpretationDoc | Path | None = None,
    validation: ValidationResult | dict[str, Any] | None = None,
    apply_summaries: list[dict[str, Any]] | None = None,
    basename: str = "report",
) -> tuple[Path, Path | None]:
    """Write ``{basename}.md`` and optionally ``{basename}.interpretation.json``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"{basename}.md"
    md_path.write_text(
        build_markdown_report(
            project,
            draft=draft,
            interpretation=interpretation,
            validation=validation,
            apply_summaries=apply_summaries,
        ),
        encoding="utf-8",
    )
    json_path: Path | None = None
    if interpretation is not None:
        json_path = out_dir / f"{basename}.interpretation.json"
        json_path.write_text(
            json.dumps(
                interpretation_to_machine_json(interpretation),
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
    return md_path, json_path
