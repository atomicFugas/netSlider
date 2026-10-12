"""Background workers for long capture / apply / validate operations."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot

from madrigal.core.limits import check_capture_file, check_packet_count
from madrigal.core.pcap import PcapImportError, import_capture
from madrigal.core.tcp import build_session_index, packets_for_session, reassemble_session
from madrigal.core.tcp.reassembly import SessionStreams


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
                    from madrigal.core.tcp.reassembly import DirectedStream
                    from madrigal.core.tcp.session import Direction

                    streams.append(
                        SessionStreams(
                            session=sess,
                            a_to_b=DirectedStream(sess.key.session_id, Direction.A_TO_B),
                            b_to_a=DirectedStream(sess.key.session_id, Direction.B_TO_A),
                            error=str(exc),
                        )
                    )
            from madrigal.core.workspace import CaptureWorkspace

            ws = CaptureWorkspace(capture=capture, sessions=sessions, streams=streams)
            self.finished.emit(ws)
        except PcapImportError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"Unexpected error: {exc}")


class ValidateWorker(QObject):
    """Apply corpus validation on a background thread."""

    progress = Signal(str)
    finished = Signal(object)  # ValidationResult
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, interpretation: Path, workspace, session_ids=None, directions=None) -> None:
        super().__init__()
        self.interpretation = interpretation
        self.workspace = workspace
        self.session_ids = session_ids
        self.directions = directions
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    @Slot()
    def run(self) -> None:
        try:
            if self._cancel:
                self.cancelled.emit()
                return
            self.progress.emit("Validating corpus…")
            from madrigal.core.validate import validate_workspace

            result = validate_workspace(
                self.interpretation,
                self.workspace,
                session_ids=self.session_ids,
                directions=self.directions,
            )
            if self._cancel:
                self.cancelled.emit()
                return
            self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))
