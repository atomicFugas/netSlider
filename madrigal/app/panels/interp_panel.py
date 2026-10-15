"""Interpretation editor + corpus validation panel (Phase 3 / R3–R4)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from madrigal.app.workers import ValidateWorker
from madrigal.core.interp import (
    DEMO_DEVICE_V1_YAML,
    SchemaError,
    apply_interpretation_file,
    apply_interpretation_text,
    parse_interpretation_text,
)
from madrigal.core.interp.hashutil import content_hash, file_content_hash
from madrigal.core.interp.python_hook import PythonHookError
from madrigal.core.project import ProjectStore
from madrigal.core.tcp.reassembly import DirectedStream
from madrigal.core.tcp.session import Direction
from madrigal.core.validate import ValidationResult
from madrigal.core.workspace import CaptureWorkspace

_STATUS_COLORS = {
    "observation": QColor("#1b5e20"),
    "rule": QColor("#0d47a1"),
    "hypothesis": QColor("#e65100"),
    "unverified": QColor("#6a1b9a"),
}


def _scroll_wrap(inner: QWidget) -> QScrollArea:
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QScrollArea.Shape.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    scroll.setMinimumHeight(0)
    inner.setMinimumWidth(0)
    scroll.setWidget(inner)
    return scroll


class InterpPanel(QWidget):
    """Editor + apply + corpus validation with stale-result marking."""

    jumpToStreamRange = Signal(object, int, int)
    statusMessage = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.project: ProjectStore | None = None
        self.workspace: CaptureWorkspace | None = None
        self.session_id: str | None = None
        self._direction = Direction.A_TO_B
        self._stream: DirectedStream | None = None
        self._last_validation: ValidationResult | None = None
        self._loaded_path: Path | None = None
        self._validate_thread: QThread | None = None
        self._validate_worker: ValidateWorker | None = None

        self.setMinimumHeight(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(splitter)

        splitter.addWidget(_scroll_wrap(self._build_editor()))
        splitter.addWidget(_scroll_wrap(self._build_results()))
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([520, 360])

    def set_project(self, project: ProjectStore | None) -> None:
        self.project = project
        self._refresh_file_list()
        self._refresh_capture_list()

    def set_workspace(self, workspace: CaptureWorkspace | None) -> None:
        self.workspace = workspace
        self._refresh_capture_list()

    def set_session(
        self,
        session_id: str | None,
        direction: Direction,
        stream: DirectedStream | None,
    ) -> None:
        self.session_id = session_id
        self._direction = direction
        self._stream = stream

    def _build_editor(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 4, 4, 4)

        row = QHBoxLayout()
        self.file_combo = QComboBox()
        self.file_combo.setMinimumWidth(120)
        self.file_combo.currentIndexChanged.connect(self._on_file_chosen)
        row.addWidget(self.file_combo, stretch=1)
        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self._refresh_file_list)
        row.addWidget(btn_refresh)
        btn_demo = QPushButton("Load demo YAML")
        btn_demo.clicked.connect(self._load_demo_yaml)
        row.addWidget(btn_demo)
        v.addLayout(row)

        self.editor = QTextEdit()
        self.editor.setAcceptRichText(False)
        font = QFont("Menlo")
        if not font.exactMatch():
            font = QFont("Courier New")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(11)
        self.editor.setFont(font)
        self.editor.setPlainText(DEMO_DEVICE_V1_YAML)
        self.editor.setMinimumHeight(140)
        v.addWidget(self.editor, stretch=2)

        legend = QLabel(
            "Field status colors: "
            "<span style='color:#0d47a1'>rule</span> · "
            "<span style='color:#e65100'>hypothesis</span> · "
            "<span style='color:#1b5e20'>observation</span> · "
            "<span style='color:#6a1b9a'>unverified</span>"
        )
        legend.setWordWrap(True)
        v.addWidget(legend)

        actions = QHBoxLayout()
        btn_apply = QPushButton("Apply to stream")
        btn_apply.clicked.connect(self._apply_current)
        actions.addWidget(btn_apply)
        btn_save = QPushButton("Save to project")
        btn_save.clicked.connect(self._save_to_project)
        actions.addWidget(btn_save)
        self.btn_validate = QPushButton("Validate corpus")
        self.btn_validate.clicked.connect(self._validate_corpus)
        actions.addWidget(self.btn_validate)
        self.btn_cancel_validate = QPushButton("Cancel")
        self.btn_cancel_validate.setEnabled(False)
        self.btn_cancel_validate.clicked.connect(self._cancel_validate)
        actions.addWidget(self.btn_cancel_validate)
        actions.addStretch(1)
        v.addLayout(actions)

        form = QFormLayout()
        self.both_dirs = QCheckBox("Both directions")
        self.both_dirs.setChecked(True)
        form.addRow("Validate", self.both_dirs)
        self.all_sessions = QCheckBox("All sessions (per capture)")
        self.all_sessions.setChecked(True)
        form.addRow("", self.all_sessions)
        v.addLayout(form)

        v.addWidget(QLabel("Corpus captures (checked = include; none = current workspace)"))
        self.capture_list = QListWidget()
        self.capture_list.setMaximumHeight(90)
        self.capture_list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        v.addWidget(self.capture_list)

        self.summary = QLabel("Apply an interpretation to parse the current stream.")
        self.summary.setWordWrap(True)
        v.addWidget(self.summary)
        return w

    def _build_results(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 4, 4, 4)

        v.addWidget(QLabel("Parsed messages / validation hits"))
        self.result_table = QTableWidget(0, 6)
        self.result_table.setHorizontalHeaderLabels(
            ["Kind", "Off", "Len", "Opcode/Rule", "Status/Fields", "Note"]
        )
        self.result_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.result_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.result_table.itemSelectionChanged.connect(self._on_result_selected)
        self.result_table.horizontalHeader().setStretchLastSection(True)
        self.result_table.setMinimumHeight(100)
        v.addWidget(self.result_table, stretch=2)

        v.addWidget(QLabel("Field detail (selected message)"))
        self.field_table = QTableWidget(0, 5)
        self.field_table.setHorizontalHeaderLabels(
            ["Name", "Value", "Type", "Status", "Hypothesis"]
        )
        self.field_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.field_table.horizontalHeader().setStretchLastSection(True)
        self.field_table.setMinimumHeight(80)
        v.addWidget(self.field_table, stretch=1)

        self.stale_label = QLabel("")
        self.stale_label.setWordWrap(True)
        v.addWidget(self.stale_label)
        return w

    def _refresh_file_list(self) -> None:
        self.file_combo.blockSignals(True)
        self.file_combo.clear()
        self.file_combo.addItem("(editor buffer)", None)
        paths: list[Path] = []
        if self.project is not None:
            paths.extend(self.project.list_interpretations())
        demo = (
            Path(__file__).resolve().parents[2]
            / "demo"
            / "corpus"
            / "interpretations"
        )
        if demo.is_dir():
            for p in sorted(demo.iterdir()):
                if p.suffix.lower() in {".yaml", ".yml", ".json", ".py"}:
                    paths.append(p)
        seen: set[str] = set()
        for path in paths:
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            label = path.name
            if self.project and path.is_relative_to(self.project.root):
                label = self.project.relative(path)
            self.file_combo.addItem(label, path)
        self.file_combo.blockSignals(False)

    def _on_file_chosen(self, _index: int) -> None:
        path = self.file_combo.currentData()
        if path is None:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Load failed", str(exc))
            return
        self.editor.setPlainText(text)
        self._loaded_path = Path(path)
        self.statusMessage.emit(f"Loaded interpretation {Path(path).name}")

    def _load_demo_yaml(self) -> None:
        self.file_combo.setCurrentIndex(0)
        self.editor.setPlainText(DEMO_DEVICE_V1_YAML)
        self._loaded_path = None
        self.statusMessage.emit("Loaded demo device_v1 YAML into editor")

    def _current_text(self) -> str:
        return self.editor.toPlainText()

    def _apply_current(self) -> None:
        if self._stream is None or self.workspace is None:
            QMessageBox.information(self, "Apply", "Load a capture and select a session first.")
            return
        capture_id = self.workspace.capture.capture_id
        path = self.file_combo.currentData()
        try:
            if path is not None and Path(path).suffix.lower() == ".py":
                result = apply_interpretation_file(
                    Path(path),
                    self._stream,
                    capture_id=capture_id,
                    direction=self._direction,
                )
            else:
                text = self._current_text()
                # Prefer file on disk when combo points at YAML and editor matches? Always use buffer.
                result = apply_interpretation_text(
                    text,
                    self._stream,
                    capture_id=capture_id,
                    direction=self._direction,
                )
        except (SchemaError, PythonHookError, OSError, ValueError) as exc:
            QMessageBox.critical(self, "Apply failed", str(exc))
            return

        self._populate_apply_results(result)
        self.summary.setText(
            f"{result.interpretation_id} ({result.source}): "
            f"{result.stats.messages_ok} ok / {result.stats.messages_error} err · "
            f"coverage={result.stats.coverage:.1%} · "
            f"hash={result.interpretation_hash[:12]}…"
        )
        self.stale_label.setText("")
        self.statusMessage.emit(
            f"Applied {result.interpretation_id}: {result.stats.messages_ok} messages"
        )

    def _populate_apply_results(self, result) -> None:
        self.result_table.setRowCount(0)
        self._apply_rows = []  # type: ignore[attr-defined]
        for msg in result.messages:
            row = self.result_table.rowCount()
            self.result_table.insertRow(row)
            kind = msg.span.status
            rule = msg.matched_rule or "—"
            opcode = f"0x{msg.opcode:02X}" if msg.opcode is not None else "—"
            field_summary = ", ".join(
                f"{f.name}={_short(f.value)}" for f in msg.fields[:4]
            )
            vals = [
                kind,
                str(msg.span.start),
                str(msg.span.length),
                f"{opcode} / {rule}",
                field_summary,
                msg.span.note or "",
            ]
            for col, text in enumerate(vals):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, row)
                self.result_table.setItem(row, col, item)
            self._apply_rows.append(msg)  # type: ignore[attr-defined]
        self.field_table.setRowCount(0)

    def _on_result_selected(self) -> None:
        rows = self.result_table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        # Validation hits path
        if self._last_validation is not None and hasattr(self, "_val_rows"):
            if row < len(self._val_rows):
                hit = self._val_rows[row]
                self.jumpToStreamRange.emit(self._direction, hit.stream_offset, hit.length)
                self.field_table.setRowCount(0)
                return
        # Apply messages path
        if hasattr(self, "_apply_rows") and row < len(self._apply_rows):
            msg = self._apply_rows[row]
            self.jumpToStreamRange.emit(self._direction, msg.span.start, msg.span.length)
            self.field_table.setRowCount(0)
            for f in msg.fields:
                r = self.field_table.rowCount()
                self.field_table.insertRow(r)
                vals = [
                    f.name,
                    _short(f.value),
                    f.type_name,
                    f.status.value,
                    f.hypothesis or "",
                ]
                for col, text in enumerate(vals):
                    item = QTableWidgetItem(text)
                    color = _STATUS_COLORS.get(f.status.value)
                    if color is not None and col == 3:
                        item.setForeground(color)
                    self.field_table.setItem(r, col, item)

    def _save_to_project(self) -> None:
        if self.project is None:
            QMessageBox.information(self, "Save", "Open a project first.")
            return
        text = self._current_text()
        name = "device_v1.yaml"
        if self._loaded_path is not None:
            name = self._loaded_path.name
        try:
            # Validate YAML/JSON before save (skip raw .py buffer)
            if not name.endswith(".py"):
                parse_interpretation_text(text)
            dest = self.project.save_interpretation(name, text)
        except (SchemaError, OSError) as exc:
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self._refresh_file_list()
        # Select saved file
        for i in range(self.file_combo.count()):
            p = self.file_combo.itemData(i)
            if p is not None and Path(p).resolve() == dest.resolve():
                self.file_combo.setCurrentIndex(i)
                break
        self.statusMessage.emit(f"Saved {dest.name}")

    def _refresh_capture_list(self) -> None:
        self.capture_list.clear()
        if self.project is None:
            return
        current_id = (
            self.workspace.capture.capture_id if self.workspace is not None else None
        )
        for rel in self.project.meta.captures:
            path = self.project.root / rel
            if not path.is_file():
                continue
            item = QListWidgetItem(rel)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            item.setData(Qt.ItemDataRole.UserRole, path)
            if current_id and path.stem == current_id:
                item.setText(f"{rel} (loaded)")
            self.capture_list.addItem(item)

    def _selected_capture_paths(self) -> list[Path]:
        paths: list[Path] = []
        for i in range(self.capture_list.count()):
            item = self.capture_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                path = item.data(Qt.ItemDataRole.UserRole)
                if path is not None:
                    paths.append(Path(path))
        return paths

    def _validate_corpus(self) -> None:
        if self._validate_thread is not None:
            QMessageBox.information(self, "Busy", "Validation is already running.")
            return

        paths = self._selected_capture_paths()
        if not paths and self.workspace is None:
            QMessageBox.information(
                self,
                "Validate",
                "Load a capture or check at least one project capture.",
            )
            return

        text = self._current_text()
        path = self.file_combo.currentData()
        dirs = (
            [Direction.A_TO_B, Direction.B_TO_A]
            if self.both_dirs.isChecked()
            else [self._direction]
        )
        session_ids = None
        if not self.all_sessions.isChecked():
            if self.session_id is None:
                QMessageBox.information(
                    self, "Validate", "Select a session or enable all sessions."
                )
                return
            session_ids = [self.session_id]

        try:
            if path is not None and Path(path).suffix.lower() == ".py":
                interpretation: object = Path(path)
                current_hash = file_content_hash(Path(path))
            else:
                interpretation = parse_interpretation_text(text)
                current_hash = content_hash(interpretation.content_for_hash)
        except (SchemaError, OSError, ValueError) as exc:
            QMessageBox.critical(self, "Validate failed", str(exc))
            return

        settings = self.project.settings if self.project is not None else None
        worker = ValidateWorker(
            interpretation,
            workspace=None if paths else self.workspace,
            capture_paths=paths or None,
            settings=settings,
            session_ids=session_ids,
            directions=dirs,
            current_hash=current_hash,
        )
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self.statusMessage.emit)
        worker.finished.connect(self._on_validate_finished)
        worker.failed.connect(self._on_validate_failed)
        worker.cancelled.connect(self._on_validate_cancelled)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.cancelled.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._clear_validate_thread)
        self._validate_thread = thread
        self._validate_worker = worker
        self.btn_validate.setEnabled(False)
        self.btn_cancel_validate.setEnabled(True)
        self.statusMessage.emit("Validating corpus…")
        thread.start()

    def _cancel_validate(self) -> None:
        if self._validate_worker is not None:
            self._validate_worker.cancel()
            self.statusMessage.emit("Cancelling validation…")

    def _clear_validate_thread(self) -> None:
        self._validate_thread = None
        self._validate_worker = None
        self.btn_validate.setEnabled(True)
        self.btn_cancel_validate.setEnabled(False)

    def _on_validate_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Validate failed", message)
        self.statusMessage.emit("Validation failed")

    def _on_validate_cancelled(self) -> None:
        self.statusMessage.emit("Validation cancelled")

    def _on_validate_finished(self, result: object) -> None:
        assert isinstance(result, ValidationResult)
        self._last_validation = result
        self._populate_validation(result)

        if self.project is not None:
            try:
                caps = result.filters.get("capture_ids") or result.filters.get("capture_id")
                suffix = (
                    "corpus"
                    if isinstance(caps, list)
                    else (caps or "workspace")
                )
                self.project.save_validation(
                    f"{result.interpretation_id}_{suffix}",
                    result.to_dict(),
                )
            except Exception as exc:
                self.statusMessage.emit(f"Validation OK but save failed: {exc}")

        stale = "  STALE" if result.stale else ""
        c = result.counters
        self.summary.setText(
            f"Validation {result.interpretation_id}: "
            f"ok={c.ok} contradict={c.contradict} uncovered={c.uncovered} "
            f"unknown={c.unknown} ambiguous={c.ambiguous} inapplicable={c.inapplicable}"
            f"{stale}"
        )
        self.stale_label.setText(
            "Results are STALE — interpretation content hash changed."
            if result.stale
            else f"Fresh run · hash={result.interpretation_hash[:16]}… · {result.created_at}"
        )
        self.statusMessage.emit(
            f"Validated: ok={c.ok} contradict={c.contradict} uncovered={c.uncovered}"
        )

    def _populate_validation(self, result: ValidationResult) -> None:
        self.result_table.setRowCount(0)
        self._val_rows = []  # type: ignore[attr-defined]
        self._apply_rows = []  # type: ignore[attr-defined]
        for hit in result.hits:
            row = self.result_table.rowCount()
            self.result_table.insertRow(row)
            opcode = f"0x{hit.opcode:02X}" if hit.opcode is not None else "—"
            vals = [
                hit.kind,
                str(hit.stream_offset),
                str(hit.length),
                f"{opcode} / {hit.matched_rule or '—'}",
                f"{hit.capture_id}:{hit.direction}" if hit.capture_id else hit.direction,
                hit.note or "",
            ]
            for col, text in enumerate(vals):
                item = QTableWidgetItem(text)
                if hit.kind == "contradict":
                    item.setForeground(QColor("#b71c1c"))
                elif hit.kind == "uncovered":
                    item.setForeground(QColor("#e65100"))
                elif hit.kind in ("unknown", "ambiguous"):
                    item.setForeground(QColor("#6a1b9a"))
                self.result_table.setItem(row, col, item)
            self._val_rows.append(hit)  # type: ignore[attr-defined]
        self.field_table.setRowCount(0)

    def check_saved_validations_stale(self) -> None:
        """Mark on-disk validations stale relative to current editor/file hash."""
        if self.project is None:
            return
        text = self._current_text()
        path = self.file_combo.currentData()
        try:
            if path is not None and Path(path).suffix.lower() == ".py":
                current = file_content_hash(Path(path))
                interp_id = Path(path).stem
            else:
                doc = parse_interpretation_text(text)
                current = content_hash(doc.content_for_hash)
                interp_id = doc.id
        except SchemaError:
            return
        for vpath in self.project.list_validations():
            try:
                data = self.project.load_validation_json(vpath)
            except Exception:
                continue
            if data.get("interpretation_id") != interp_id:
                continue
            result = ValidationResult.from_dict(data)
            if result.mark_stale_if_needed(current) and data.get("stale") is not True:
                data["stale"] = True
                try:
                    self.project.save_validation(vpath.name, data)
                except Exception:
                    pass


def _short(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        hx = bytes(value).hex()
        return hx if len(hx) <= 24 else hx[:24] + "…"
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value} (0x{value:X})"
    s = str(value)
    return s if len(s) <= 40 else s[:40] + "…"
