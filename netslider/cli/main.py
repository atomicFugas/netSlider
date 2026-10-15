"""netSlider CLI — project, corpus, apply/validate, report."""

from __future__ import annotations

import json
from pathlib import Path

import click

from netslider import __version__
from netslider.core.project import ProjectError, ProjectStore


@click.group()
@click.version_option(__version__, prog_name="netslider")
def cli() -> None:
    """netSlider Protocol Laboratory CLI."""


@cli.command("project-new")
@click.argument("path", type=click.Path())
@click.option("--name", default=None, help="Project display name")
def project_new(path: str, name: str | None) -> None:
    """Create an empty portable project directory."""
    root = Path(path)
    display = name or root.name or "untitled"
    try:
        store = ProjectStore.create(root, name=display)
    except ProjectError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Created project at {store.root}")


@cli.command("project-info")
@click.argument("path", type=click.Path(exists=True, file_okay=False))
def project_info(path: str) -> None:
    """Print project manifest summary."""
    try:
        store = ProjectStore.open(Path(path))
    except ProjectError as exc:
        raise click.ClickException(str(exc)) from exc
    data = store.meta.to_dict()
    data["portability_warnings"] = store.assert_portable()
    data["interpretations_on_disk"] = [store.relative(p) for p in store.list_interpretations()]
    click.echo(json.dumps(data, indent=2))


@cli.command("project-package")
@click.argument("path", type=click.Path(exists=True, file_okay=False))
@click.option("--out", type=click.Path(), default=None, help="Zip output path")
def project_package(path: str, out: str | None) -> None:
    """Zip a project directory for portable transfer."""
    try:
        store = ProjectStore.open(Path(path))
        dest = store.package_zip(Path(out) if out else None)
    except ProjectError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Wrote {dest}")


@cli.command("demo-corpus")
@click.option(
    "--out",
    type=click.Path(),
    default=None,
    help="Output directory (default: netslider/demo/corpus)",
)
@click.option("--no-extra", is_flag=True, help="Skip extra capture")
def demo_corpus(out: str | None, no_extra: bool) -> None:
    """Generate synthetic demo PCAP + action log."""
    from netslider.demo.corpus.generate import DEFAULT_OUT, generate_corpus

    out_dir = Path(out) if out else DEFAULT_OUT
    paths = generate_corpus(out_dir, extra=not no_extra)
    for key, p in paths.items():
        click.echo(f"{key}: {p}")


@cli.command("align")
@click.argument("pcap", type=click.Path(exists=True, dir_okay=False))
@click.argument("action_log", type=click.Path(exists=True, dir_okay=False))
@click.option("--window", default=0.2, show_default=True, help="± seconds around each action")
@click.option("--mode", default="relative", type=click.Choice(["relative", "absolute"]))
def align_cmd(pcap: str, action_log: str, window: float, mode: str) -> None:
    """Time-align an action log to a capture and print matched packets."""
    from netslider.core.investigate import align_actions, load_action_log
    from netslider.core.pcap import import_capture
    from netslider.core.tcp import build_session_index

    cap = import_capture(Path(pcap), capture_id=Path(pcap).stem)
    log = load_action_log(Path(action_log))
    index = build_session_index(cap)
    sess = index.sessions[0] if index.sessions else None
    result = align_actions(log, cap.packets, session=sess, mode=mode, window_s=window)
    click.echo(f"mode={result.mode} offset={result.offset:.6f} window=±{result.window_s}s")
    for a in result.actions:
        click.echo(
            f"  #{a.event.seq} {a.event.action:16s} pkts={a.packet_ids or '—'} {a.note}"
        )


def _resolve_interpretation(
    interpretation: str | None,
    project: str | None,
    interp_name: str | None,
) -> Path:
    if project:
        try:
            store = ProjectStore.open(Path(project))
        except ProjectError as exc:
            raise click.ClickException(str(exc)) from exc
        if interpretation:
            cand = Path(interpretation)
            if not cand.is_file():
                cand = store.resolve_rel(interpretation)
            return cand
        if interp_name:
            return store.resolve_rel(f"interpretations/{interp_name}")
        primary = store.primary_interpretation()
        if primary is None:
            raise click.ClickException("Project has no interpretations")
        return primary
    if not interpretation:
        raise click.ClickException("Provide INTERPRETATION or --project")
    return Path(interpretation)


def _load_workspace(pcap: Path, settings: dict | None = None):
    from netslider.core.limits import check_capture_file, check_packet_count
    from netslider.core.pcap import import_capture
    from netslider.core.tcp import build_session_index, packets_for_session, reassemble_session
    from netslider.core.workspace import CaptureWorkspace

    limit = check_capture_file(pcap, settings)
    for w in limit.warnings:
        click.echo(f"WARN: {w}", err=True)
    if limit.blocked:
        raise click.ClickException("; ".join(limit.errors))

    cap = import_capture(pcap, capture_id=pcap.stem)
    pkt_limit = check_packet_count(cap.diagnostics.packet_count, settings)
    for w in pkt_limit.warnings:
        click.echo(f"WARN: {w}", err=True)
    if pkt_limit.blocked:
        raise click.ClickException("; ".join(pkt_limit.errors))

    index = build_session_index(cap)
    streams = [
        reassemble_session(sess, packets_for_session(cap, sess), capture_id=cap.capture_id)
        for sess in index.sessions
    ]
    return CaptureWorkspace(capture=cap, sessions=index, streams=streams)


@cli.command("apply")
@click.argument("legacy_interp", required=False, type=click.Path())
@click.argument("legacy_pcap", required=False, type=click.Path())
@click.option("--project", type=click.Path(exists=True, file_okay=False), help="Portable project dir")
@click.option("--pcap", "pcap_opt", type=click.Path(exists=True, dir_okay=False), help="Capture to apply")
@click.option("--interpretation", "interp_opt", type=click.Path(), help="Interpretation file")
@click.option("--interp-name", default=None, help="interpretations/<name> inside --project")
@click.option("--direction", default="both", type=click.Choice(["a2b", "b2a", "both"]))
@click.option("--json-out", "json_out", is_flag=True, help="Emit machine-readable JSON")
def apply_cmd(
    legacy_interp: str | None,
    legacy_pcap: str | None,
    project: str | None,
    pcap_opt: str | None,
    interp_opt: str | None,
    interp_name: str | None,
    direction: str,
    json_out: bool,
) -> None:
    """Apply an interpretation to a capture.

    Forms::

        netslider-cli apply device_v1.yaml capture.pcap
        netslider-cli apply --project ./lab --pcap extra.pcapng
    """
    from netslider.core.interp import apply_interpretation_file
    from netslider.core.tcp.session import Direction

    interp_arg = interp_opt or legacy_interp
    pcap_arg = pcap_opt or legacy_pcap
    if not pcap_arg:
        raise click.ClickException("Provide a PCAP path (positional or --pcap)")

    settings = None
    if project:
        try:
            settings = ProjectStore.open(Path(project)).settings
        except ProjectError as exc:
            raise click.ClickException(str(exc)) from exc

    interp_path = _resolve_interpretation(interp_arg, project, interp_name)
    if not interp_path.is_file():
        raise click.ClickException(f"Interpretation not found: {interp_path}")

    path = Path(pcap_arg)
    if not path.is_file():
        raise click.ClickException(f"Capture not found: {path}")

    ws = _load_workspace(path, settings)
    dirs = {
        "a2b": [Direction.A_TO_B],
        "b2a": [Direction.B_TO_A],
        "both": [Direction.A_TO_B, Direction.B_TO_A],
    }[direction]
    payloads = []
    for sess in ws.sessions.sessions:
        bundle = ws.stream_for(sess.key.session_id)
        if bundle is None:
            continue
        for d in dirs:
            stream = bundle.a_to_b if d == Direction.A_TO_B else bundle.b_to_a
            if stream.length == 0:
                continue
            result = apply_interpretation_file(
                interp_path, stream, capture_id=ws.capture.capture_id, direction=d
            )
            payloads.append(result.to_dict())
            if not json_out:
                click.echo(
                    f"{sess.key.session_id} {d.value}: "
                    f"ok={result.stats.messages_ok} err={result.stats.messages_error} "
                    f"coverage={result.stats.coverage:.1%}"
                )
    if json_out:
        click.echo(json.dumps(payloads, indent=2))


@cli.command("validate")
@click.argument("legacy_interp", required=False, type=click.Path())
@click.argument("legacy_pcap", required=False, type=click.Path())
@click.option("--project", type=click.Path(exists=True, file_okay=False))
@click.option("--pcap", "pcap_opt", type=click.Path(exists=True, dir_okay=False))
@click.option("--interpretation", "interp_opt", type=click.Path())
@click.option("--interp-name", default=None)
@click.option(
    "--all-captures",
    is_flag=True,
    help="With --project and no --pcap: validate all project captures",
)
@click.option("--json-out", "json_out", is_flag=True, help="Emit machine-readable JSON")
def validate_cmd(
    legacy_interp: str | None,
    legacy_pcap: str | None,
    project: str | None,
    pcap_opt: str | None,
    interp_opt: str | None,
    interp_name: str | None,
    all_captures: bool,
    json_out: bool,
) -> None:
    """Run corpus validation of an interpretation against one or more captures."""
    from netslider.core.validate import validate_project_captures, validate_workspace

    interp_arg = interp_opt or legacy_interp
    pcap_arg = pcap_opt or legacy_pcap

    store = None
    settings = None
    if project:
        try:
            store = ProjectStore.open(Path(project))
            settings = store.settings
        except ProjectError as exc:
            raise click.ClickException(str(exc)) from exc

    interp_path = _resolve_interpretation(interp_arg, project, interp_name)
    if not interp_path.is_file():
        raise click.ClickException(f"Interpretation not found: {interp_path}")

    # Project corpus mode: --project with --all-captures, or --project alone (no pcap)
    if store is not None and (all_captures or not pcap_arg):
        paths = [
            store.resolve_rel(rel)
            for rel in store.meta.captures
            if (store.root / rel).is_file()
        ]
        if not paths:
            raise click.ClickException("Project has no capture files to validate")
        result = validate_project_captures(interp_path, paths, settings=settings)
        if json_out:
            click.echo(json.dumps(result.to_dict(), indent=2))
        else:
            c = result.counters
            click.echo(
                f"{result.interpretation_id} hash={result.interpretation_hash[:12]}… "
                f"captures={len(paths)} stale={result.stale}\n"
                f"  ok={c.ok} contradict={c.contradict} uncovered={c.uncovered} "
                f"unknown={c.unknown} ambiguous={c.ambiguous} inapplicable={c.inapplicable}"
            )
        return

    if not pcap_arg:
        raise click.ClickException(
            "Provide a PCAP path (positional or --pcap), or --project for all captures"
        )

    path = Path(pcap_arg)
    ws = _load_workspace(path, settings)
    result = validate_workspace(interp_path, ws)
    if json_out:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        c = result.counters
        click.echo(
            f"{result.interpretation_id} hash={result.interpretation_hash[:12]}… "
            f"stale={result.stale}\n"
            f"  ok={c.ok} contradict={c.contradict} uncovered={c.uncovered} "
            f"unknown={c.unknown} ambiguous={c.ambiguous} inapplicable={c.inapplicable}"
        )


@cli.command("report")
@click.option("--project", type=click.Path(exists=True, file_okay=False), required=True)
@click.option("--out", type=click.Path(), default=".", help="Output directory")
@click.option("--interpretation", default=None, help="Interp path or project-relative")
@click.option("--pcap", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--basename", default="report")
def report_cmd(
    project: str,
    out: str,
    interpretation: str | None,
    pcap: str | None,
    basename: str,
) -> None:
    """Export Markdown report + machine interpretation JSON from a project."""
    from netslider.core.report import ReportDraft, write_report
    from netslider.core.validate import validate_workspace

    try:
        store = ProjectStore.open(Path(project))
    except ProjectError as exc:
        raise click.ClickException(str(exc)) from exc

    interp_path = _resolve_interpretation(interpretation, project, None)
    validation = None
    apply_summaries = None
    if pcap:
        ws = _load_workspace(Path(pcap), store.settings)
        validation = validate_workspace(interp_path, ws)
        apply_summaries = [
            {
                "capture_id": validation.filters.get("capture_id"),
                "session_id": "*",
                "direction": "both",
                "stats": {
                    "messages_ok": validation.counters.ok,
                    "messages_error": validation.counters.contradict,
                    "coverage": None,
                },
            }
        ]

    draft = ReportDraft(
        title=f"{store.meta.name} — protocol report",
        rationale="Exported from netSlider project for reuse and review.",
        scope=(
            f"Captures: {', '.join(store.meta.captures) or '—'}. "
            f"Interpretation: {interp_path.name}."
        ),
        open_questions=["Confirm framing on additional field captures."],
    )
    md_path, json_path = write_report(
        Path(out),
        project=store,
        draft=draft,
        interpretation=interp_path,
        validation=validation,
        apply_summaries=apply_summaries,
        basename=basename,
    )
    click.echo(f"Markdown: {md_path}")
    if json_path:
        click.echo(f"Interpretation JSON: {json_path}")


@cli.command("inspect")
@click.argument("pcap", type=click.Path(exists=True, dir_okay=False))
@click.option("--checksum-policy", default="warn", type=click.Choice(["warn", "ignore"]))
@click.option("--overlap-policy", default="first_seen", type=click.Choice(["first_seen", "last_seen"]))
def inspect_pcap(pcap: str, checksum_policy: str, overlap_policy: str) -> None:
    """Import a capture, list sessions, and summarize reassembly."""
    from netslider.core.pcap import import_capture
    from netslider.core.tcp import build_session_index, packets_for_session, reassemble_session

    path = Path(pcap)
    cap = import_capture(path, capture_id=path.stem, checksum_policy=checksum_policy)
    click.echo(
        f"backend={cap.diagnostics.backend} packets={cap.diagnostics.packet_count} "
        f"tcp={cap.diagnostics.tcp_packet_count} skips={cap.diagnostics.skipped}"
    )
    index = build_session_index(cap)
    click.echo(f"sessions={len(index.sessions)}")
    for sess in index.sessions:
        streams = reassemble_session(
            sess,
            packets_for_session(cap, sess),
            capture_id=cap.capture_id,
            overlap_policy=overlap_policy,
        )
        click.echo(
            f"  {sess.key.session_id}\n"
            f"    {sess.display_name}\n"
            f"    A→B len={streams.a_to_b.length} unk={streams.a_to_b.bytes_unknown} "
            f"defects={len(streams.a_to_b.defects)}\n"
            f"    B→A len={streams.b_to_a.length} unk={streams.b_to_a.bytes_unknown} "
            f"defects={len(streams.b_to_a.defects)}"
        )
        if streams.error:
            click.echo(f"    ERROR: {streams.error}")


if __name__ == "__main__":
    cli()
