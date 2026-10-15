"""Background workers for long capture / apply / validate operations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Signal, Slot

from netslider.core.limits import check_capture_file, check_packet_count
from netslider.core.pcap import PcapImportError, import_capture
from netslider.core.tcp import build_session_index, packets_for_session, reassemble_session
from netslider.core.tcp.reassembly import SessionStreams
from netslider.core.workspace import CaptureWorkspace


class CaptureLoadWorker(QObject):
    progress = Signal(str)
    finished = Signal(object)  # CaptureWorkspace
    failed = Signal(str)
    cancelled = Signal()

    def __init__(
        self,
        path: Path,
        capture_id: str,
        checksum_policy: str = "warn",
        overlap_policy: str = "first_seen",
        settings: dict | None = None,
    ) -> None:
        super().__init__()
        self.path = path
        self.capture_id = capture_id
        self.checksum_policy = checksum_policy
        self.overlap_policy = overlap_policy
        self.settings = settings
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    @Slot()
    def run(self) -> None:
        try:
            limit = check_capture_file(self.path, self.settings)
            for w in limit.warnings:
                self.progress.emit(f"WARN: {w}")
            if limit.blocked:
                self.failed.emit("; ".join(limit.errors))
                return

            self.progress.emit(f"Importing {self.path.name}…")
            capture = import_capture(
                self.path,
                capture_id=self.capture_id,
                checksum_policy=self.checksum_policy,
            )
            if self._cancel:
                self.cancelled.emit()
                return

            pkt_limit = check_packet_count(capture.diagnostics.packet_count, self.settings)
            for w in pkt_limit.warnings:
                self.progress.emit(f"WARN: {w}")
            if pkt_limit.blocked:
                self.failed.emit("; ".join(pkt_limit.errors))
                return

            self.progress.emit("Building session index…")
            sessions = build_session_index(capture)
            streams: list[SessionStreams] = []
            for i, sess in enumerate(sessions.sessions):
                if self._cancel:
                    self.cancelled.emit()
                    return
                self.progress.emit(f"Reassembling session {i + 1}/{len(sessions.sessions)}…")
                pkts = packets_for_session(capture, sess)
                try:
                    streams.append(
                        reassemble_session(
                            sess,
                            pkts,
                            capture_id=capture.capture_id,
                            overlap_policy=self.overlap_policy,
                        )
                    )
                except Exception as exc:
                    from netslider.core.tcp.reassembly import DirectedStream
                    from netslider.core.tcp.session import Direction

                    streams.append(
                        SessionStreams(
                            session=sess,
                            a_to_b=DirectedStream(sess.key.session_id, Direction.A_TO_B),
                            b_to_a=DirectedStream(sess.key.session_id, Direction.B_TO_A),
                            error=str(exc),
                        )
                    )

            ws = CaptureWorkspace(capture=capture, sessions=sessions, streams=streams)
            self.finished.emit(ws)
        except PcapImportError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"Unexpected error: {exc}")


class ValidateWorker(QObject):
    """Apply corpus validation on a background thread (single or multi-capture)."""

    progress = Signal(str)
    finished = Signal(object)  # ValidationResult
    failed = Signal(str)
    cancelled = Signal()

    def __init__(
        self,
        interpretation: Any,
        *,
        workspace: CaptureWorkspace | None = None,
        capture_paths: list[Path] | None = None,
        settings: dict | None = None,
        session_ids=None,
        directions=None,
        current_hash: str | None = None,
    ) -> None:
        super().__init__()
        self.interpretation = interpretation
        self.workspace = workspace
        self.capture_paths = list(capture_paths) if capture_paths else None
        self.settings = settings
        self.session_ids = session_ids
        self.directions = directions
        self.current_hash = current_hash
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def _cancelled(self) -> bool:
        return self._cancel

    @Slot()
    def run(self) -> None:
        try:
            if self._cancel:
                self.cancelled.emit()
                return

            from netslider.core.validate import (
                refresh_stale,
                validate_project_captures,
                validate_workspace,
            )

            if self.capture_paths:
                self.progress.emit("Validating corpus…")
                result = validate_project_captures(
                    self.interpretation,
                    self.capture_paths,
                    settings=self.settings,
                    session_ids=self.session_ids,
                    directions=self.directions,
                    progress=lambda msg: self.progress.emit(msg),
                    cancel_check=self._cancelled,
                )
            elif self.workspace is not None:
                self.progress.emit("Validating corpus…")
                result = validate_workspace(
                    self.interpretation,
                    self.workspace,
                    session_ids=self.session_ids,
                    directions=self.directions,
                )
            else:
                self.failed.emit("No workspace or capture paths for validation")
                return

            if self._cancel:
                self.cancelled.emit()
                return

            if self.current_hash:
                refresh_stale(result, self.current_hash)
            self.finished.emit(result)
        except InterruptedError:
            self.cancelled.emit()
        except Exception as exc:
            self.failed.emit(str(exc))
