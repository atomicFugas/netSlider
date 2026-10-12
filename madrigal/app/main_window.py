"""Main window — Phase 1+2: reassembly, action-log align, framing, compare."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThread
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from madrigal import __version__
from madrigal.app.panels.interp_panel import InterpPanel
from madrigal.app.panels.investigate_panel import InvestigatePanel
from madrigal.app.widgets.hex_view import HexView
from madrigal.app.workers import CaptureLoadWorker
from madrigal.core.project import ProjectError, ProjectStore
from madrigal.core.tcp.reassembly import SpanStatus
from madrigal.core.tcp.session import Direction
from madrigal.core.workspace import CaptureWorkspace


def _fit_to_screen(window: QMainWindow, pref_w: int = 1280, pref_h: int = 780) -> None:
    screen = QGuiApplication.primaryScreen()
    if screen is None:
        window.resize(pref_w, pref_h)
        return
    avail = screen.availableGeometry()
    w = min(pref_w, max(900, avail.width() - 40))
    h = min(pref_h, max(600, avail.height() - 60))
    window.resize(w, h)
    window.setMinimumSize(800, 520)
    frame = window.frameGeometry()
    frame.moveCenter(avail.center())
    window.move(frame.topLeft())


def _shrinkable(widget: QWidget) -> None:
    """Allow splitter panes to shrink below their sizeHint."""
    widget.setMinimumSize(0, 0)
    widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.project: ProjectStore | None = None
        self.workspace: CaptureWorkspace | None = None
        self._current_session_id: str | None = None
        self._current_direction = Direction.A_TO_B
        self._load_thread: QThread | None = None
        self._load_worker: CaptureLoadWorker | None = None
        self._hex_sel_start = 0
        self._hex_sel_len = 0

        self.setWindowTitle(f"Madrigal Protocol Laboratory {__version__}")
        self._build_ui()
        self._build_menus()
        self._build_toolbar()
        _fit_to_screen(self)
        self._set_status("No project open")

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)

        # Outer vertical split: workbench (top) / investigate (bottom)
        self.main_split = QSplitter(Qt.Orientation.Vertical)
        root.addWidget(self.main_split, stretch=1)

        workbench = QSplitter(Qt.Orientation.Horizontal)
        _shrinkable(workbench)
        self.main_split.addWidget(workbench)

        # ── Left: project + sessions ─────────────────────────────────
        left = QWidget()
        _shrinkable(left)
        left_l = QVBoxLayout(left)
        left_l.setContentsMargins(0, 0, 0, 0)
        left_l.setSpacing(2)
        left_l.addWidget(QLabel("Project"))
        self.project_info = QLabel("—")
        self.project_info.setWordWrap(True)
        left_l.addWidget(self.project_info)
        left_l.addWidget(QLabel("Captures"))
        self.capture_list = QListWidget()
        self.capture_list.setMinimumHeight(40)
        self.capture_list.itemDoubleClicked.connect(self._on_capture_activated)
        left_l.addWidget(self.capture_list, stretch=1)
        left_l.addWidget(QLabel("Sessions"))
        self.session_list = QListWidget()
        self.session_list.setMinimumHeight(40)
        self.session_list.currentItemChanged.connect(self._on_session_selected)
        left_l.addWidget(self.session_list, stretch=2)
        workbench.addWidget(left)

        # ── Center: direction + hex + defects ─────────────────────────
        center = QWidget()
        _shrinkable(center)
        center_l = QVBoxLayout(center)
        center_l.setContentsMargins(0, 0, 0, 0)
        center_l.setSpacing(2)

        dir_row = QHBoxLayout()
        dir_row.addWidget(QLabel("Direction"))
        self.direction_combo = QComboBox()
        self.direction_combo.addItem("A → B", Direction.A_TO_B)
        self.direction_combo.addItem("B → A", Direction.B_TO_A)
        self.direction_combo.currentIndexChanged.connect(self._on_direction_changed)
        dir_row.addWidget(self.direction_combo, stretch=1)
        self.stream_meta = QLabel("")
        self.stream_meta.setMinimumWidth(0)
        dir_row.addWidget(self.stream_meta)
        center_l.addLayout(dir_row)

        self.hex_view = HexView()
        self.hex_view.setMinimumHeight(80)
        self.hex_view.offsetActivated.connect(self._on_hex_offset)
        self.hex_view.selectionChanged.connect(self._on_hex_selection)
        center_l.addWidget(self.hex_view, stretch=1)

        center_l.addWidget(QLabel("Defects"))
        self.defect_view = QTextEdit()
        self.defect_view.setReadOnly(True)
        self.defect_view.setMinimumHeight(36)
        self.defect_view.setMaximumHeight(72)
        self.defect_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        center_l.addWidget(self.defect_view)
        workbench.addWidget(center)

        # ── Right: packets + provenance ──────────────────────────────
        right = QWidget()
        _shrinkable(right)
        right_l = QVBoxLayout(right)
        right_l.setContentsMargins(0, 0, 0, 0)
        right_l.setSpacing(2)
        right_l.addWidget(QLabel("Packets (session)"))
        self.packet_table = QTableWidget(0, 6)
        self.packet_table.setHorizontalHeaderLabels(
            ["#", "Time", "Src", "Dst", "Flags", "Len"]
        )
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.packet_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.packet_table.itemSelectionChanged.connect(self._on_packet_selected)
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setMinimumHeight(60)
        right_l.addWidget(self.packet_table, stretch=1)

        right_l.addWidget(QLabel("Provenance"))
        self.prov_label = QLabel("Click a hex byte or packet row.")
        self.prov_label.setWordWrap(True)
        self.prov_label.setMinimumHeight(0)
        self.prov_label.setMaximumHeight(56)
        right_l.addWidget(self.prov_label)
        workbench.addWidget(right)

        workbench.setStretchFactor(0, 2)
        workbench.setStretchFactor(1, 5)
        workbench.setStretchFactor(2, 3)
        workbench.setSizes([220, 640, 360])

        # ── Bottom: Investigate + Interpret tabs ─────────────────────
        self.bottom_tabs = QTabWidget()
        _shrinkable(self.bottom_tabs)
        self.bottom_tabs.setMinimumHeight(120)

        self.investigate = InvestigatePanel()
        _shrinkable(self.investigate)
        self.investigate.jumpToPackets.connect(self._jump_to_packets)
        self.investigate.jumpToStreamRange.connect(self._jump_to_stream_range)
        self.investigate.statusMessage.connect(self._set_status)
        self.investigate.requestSelectionAsA.connect(self._mark_selection_a)
        self.investigate.requestSelectionAsB.connect(self._mark_selection_b)
        self.bottom_tabs.addTab(self.investigate, "Investigate")

        self.interp = InterpPanel()
        _shrinkable(self.interp)
        self.interp.jumpToStreamRange.connect(self._jump_to_stream_range)
        self.interp.statusMessage.connect(self._set_status)
        self.bottom_tabs.addTab(self.interp, "Interpret / Validate")

        self.main_split.addWidget(self.bottom_tabs)

        self.main_split.setStretchFactor(0, 3)
        self.main_split.setStretchFactor(1, 2)
        self.main_split.setSizes([480, 260])
        self.main_split.setChildrenCollapsible(False)

        self.setStatusBar(QStatusBar())

    def _build_menus(self) -> None:
        file_menu = self.menuBar().addMenu("&File")

        for text, shortcut, slot in (
            ("&New Project…", QKeySequence.StandardKey.New, self.new_project),
            ("&Open Project…", QKeySequence.StandardKey.Open, self.open_project),
            ("&Save Project", QKeySequence.StandardKey.Save, self.save_project),
        ):
            act = QAction(text, self)
            act.setShortcut(shortcut)
            act.triggered.connect(slot)
            file_menu.addAction(act)

        file_menu.addSeparator()
        act_import_cap = QAction("Import &Capture…", self)
        act_import_cap.triggered.connect(self.import_capture)
        file_menu.addAction(act_import_cap)
        act_import_log = QAction("Import Action &Log…", self)
        act_import_log.triggered.connect(self.import_action_log)
        file_menu.addAction(act_import_log)
        act_import_interp = QAction("Import &Interpretation…", self)
        act_import_interp.triggered.connect(self.import_interpretation)
        file_menu.addAction(act_import_interp)
        act_open_cap = QAction("Open Capture in &Workspace…", self)
        act_open_cap.triggered.connect(self.open_capture_dialog)
        file_menu.addAction(act_open_cap)

        file_menu.addSeparator()
        act_report = QAction("Export &Report…", self)
        act_report.triggered.connect(self.export_report)
        file_menu.addAction(act_report)
        act_zip = QAction("Package Project as &Zip…", self)
        act_zip.triggered.connect(self.package_project)
        file_menu.addAction(act_zip)

        file_menu.addSeparator()
        act_quit = QAction("&Quit", self)
        act_quit.setShortcut(QKeySequence.StandardKey.Quit)
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        help_menu = self.menuBar().addMenu("&Help")
        act_about = QAction("&About", self)
        act_about.triggered.connect(self.show_about)
        help_menu.addAction(act_about)

    def _build_toolbar(self) -> None:
        tb = QToolBar("Main")
        self.addToolBar(tb)
        act = QAction("Load selected capture", self)
        act.triggered.connect(self.load_selected_capture)
        tb.addAction(act)
        act_log = QAction("Open action log…", self)
        act_log.triggered.connect(self.open_action_log_dialog)
        tb.addAction(act_log)
        self.act_cancel_load = QAction("Cancel load", self)
        self.act_cancel_load.setEnabled(False)
        self.act_cancel_load.triggered.connect(self.cancel_capture_load)
        tb.addAction(self.act_cancel_load)

    def open_action_log_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open action log", "", "Action logs (*.json *.csv);;All files (*)"
        )
        if not path:
            return
        try:
            self.investigate.load_action_log_path(Path(path))
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "Action log failed", str(exc))

    def _set_status(self, text: str) -> None:
        self.statusBar().showMessage(text)

    def _refresh_project_view(self) -> None:
        self.capture_list.clear()
        if self.project is None:
            self.project_info.setText("—")
            self.interp.set_project(None)
            return
        p = self.project
        self.project_info.setText(
            f"<b>{p.meta.name}</b><br/><small>{p.root}</small><br/>created {p.meta.created_at}"
        )
        for rel in p.meta.captures:
            self.capture_list.addItem(rel)
        if p.meta.action_logs:
            log_path = p.root / p.meta.action_logs[0]
            if log_path.is_file():
                try:
                    self.investigate.load_action_log_path(log_path)
                except Exception as exc:
                    self._set_status(f"Action log load failed: {exc}")
        self.interp.set_project(p)
        self._set_status(f"Project open: {p.root}")

    def new_project(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Create project in directory")
        if not path:
            return
        root = Path(path)
        name, ok = QInputDialog.getText(
            self, "New project", "Project name:", text=root.name or "untitled"
        )
        if not ok:
            return
        name = name.strip() or "untitled"
        try:
            if root.exists() and any(root.iterdir()):
                root = root / name
            self.project = ProjectStore.create(root, name=name)
        except ProjectError as exc:
            QMessageBox.critical(self, "New project failed", str(exc))
            return
        self._refresh_project_view()

    def open_project(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Open Madrigal project")
        if not path:
            return
        try:
            self.project = ProjectStore.open(Path(path))
        except ProjectError as exc:
            QMessageBox.critical(self, "Open project failed", str(exc))
            return
        self._refresh_project_view()

    def save_project(self) -> None:
        if self.project is None:
            QMessageBox.information(self, "Save", "No project open.")
            return
        self.project.save()
        self._set_status(f"Saved {self.project.root}")

    def import_capture(self) -> None:
        if not self._require_project():
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Import capture", "", "Captures (*.pcap *.pcapng *.cap);;All files (*)"
        )
        if not path:
            return
        try:
            dest = self.project.import_capture(Path(path))
        except ProjectError as exc:
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        self._refresh_project_view()
        self._start_load(dest, capture_id=dest.stem)

    def import_action_log(self) -> None:
        if not self._require_project():
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Import action log", "", "Action logs (*.json *.csv);;All files (*)"
        )
        if not path:
            return
        try:
            dest = self.project.import_action_log(Path(path))
            self.investigate.load_action_log_path(dest)
        except (ProjectError, OSError, ValueError) as exc:
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        self._refresh_project_view()

    def import_interpretation(self) -> None:
        if not self._require_project():
            return
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import interpretation",
            "",
            "Interpretations (*.yaml *.yml *.json *.py);;All files (*)",
        )
        if not path:
            return
        try:
            dest = self.project.import_interpretation(Path(path))
        except ProjectError as exc:
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        self._refresh_project_view()
        self._set_status(f"Imported interpretation {dest.name}")

    def open_capture_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open capture", "", "Captures (*.pcap *.pcapng *.cap);;All files (*)"
        )
        if not path:
            return
        self._start_load(Path(path), capture_id=Path(path).stem)

    def load_selected_capture(self) -> None:
        item = self.capture_list.currentItem()
        if item is None:
            QMessageBox.information(self, "Capture", "Select a capture in the project list.")
            return
        if self.project is None:
            return
        path = self.project.root / item.text()
        self._start_load(path, capture_id=path.stem)

    def _on_capture_activated(self, item: QListWidgetItem) -> None:
        if self.project is None:
            return
        path = self.project.root / item.text()
        self._start_load(path, capture_id=path.stem)

    def _require_project(self) -> bool:
        if self.project is None:
            QMessageBox.information(self, "Project", "Open or create a project first.")
            return False
        return True

    def _start_load(self, path: Path, capture_id: str) -> None:
        if self._load_thread is not None:
            QMessageBox.information(self, "Busy", "A capture is still loading.")
            return
        checksum = "warn"
        overlap = "first_seen"
        settings = None
        if self.project is not None:
            tcp_cfg = self.project.settings.get("tcp", {})
            checksum = tcp_cfg.get("checksum_policy", checksum)
            overlap = tcp_cfg.get("overlap_policy", overlap)
            settings = self.project.settings

        thread = QThread(self)
        worker = CaptureLoadWorker(
            path, capture_id, checksum, overlap, settings=settings
        )
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._set_status)
        worker.finished.connect(self._on_capture_loaded)
        worker.failed.connect(self._on_capture_failed)
        worker.cancelled.connect(self._on_capture_cancelled)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.cancelled.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._clear_load_thread)
        self._load_thread = thread
        self._load_worker = worker
        self.act_cancel_load.setEnabled(True)
        thread.start()

    def cancel_capture_load(self) -> None:
        if self._load_worker is not None:
            self._load_worker.cancel()
            self._set_status("Cancelling capture load…")

    def _clear_load_thread(self) -> None:
        self._load_thread = None
        self._load_worker = None
        self.act_cancel_load.setEnabled(False)

    def _on_capture_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Capture load failed", message)
        self._set_status("Load failed")

    def _on_capture_cancelled(self) -> None:
        self._set_status("Capture load cancelled")

    def _on_capture_loaded(self, workspace: object) -> None:
        assert isinstance(workspace, CaptureWorkspace)
        self.workspace = workspace
        self.investigate.set_workspace(workspace)
        self.interp.set_workspace(workspace)
        self.session_list.clear()
        for sess in workspace.sessions.sessions:
            item = QListWidgetItem(sess.display_name)
            item.setData(Qt.ItemDataRole.UserRole, sess.key.session_id)
            streams = workspace.stream_for(sess.key.session_id)
            if streams and streams.error:
                item.setToolTip(streams.error)
                item.setForeground(Qt.GlobalColor.red)
            self.session_list.addItem(item)

        diag = workspace.capture.diagnostics
        warn = "; ".join(diag.warnings[:3])
        self._set_status(
            f"Loaded {diag.path} — {diag.packet_count} pkts, "
            f"{diag.tcp_packet_count} TCP, sessions={len(workspace.sessions.sessions)}"
            + (f" | {warn}" if warn else "")
        )
        if self.session_list.count():
            self.session_list.setCurrentRow(0)

    def _on_session_selected(
        self, current: QListWidgetItem | None, _prev: QListWidgetItem | None
    ) -> None:
        if current is None or self.workspace is None:
            return
        self._current_session_id = current.data(Qt.ItemDataRole.UserRole)
        self._populate_packets()
        self._refresh_stream_view()
        self._sync_investigate_session()

    def _on_direction_changed(self, _index: int) -> None:
        self._current_direction = self.direction_combo.currentData()
        self._refresh_stream_view()
        self._sync_investigate_session()

    def _sync_investigate_session(self) -> None:
        stream = self._current_stream()
        self.investigate.set_session(
            self._current_session_id,
            self._current_direction,
            stream,
        )
        self.interp.set_session(
            self._current_session_id,
            self._current_direction,
            stream,
        )

    def _current_stream(self):
        if self.workspace is None or self._current_session_id is None:
            return None
        bundle = self.workspace.stream_for(self._current_session_id)
        if bundle is None:
            return None
        return bundle.a_to_b if self._current_direction == Direction.A_TO_B else bundle.b_to_a

    def _refresh_stream_view(self) -> None:
        stream = self._current_stream()
        if stream is None:
            self.hex_view.set_data(b"")
            self.stream_meta.setText("")
            self.defect_view.clear()
            return
        data = stream.materialize()
        self.hex_view.set_data(data)
        unknown: set[int] = set()
        ambiguous: set[int] = set()
        for span in stream.spans:
            rng = range(span.stream_offset, span.stream_offset + span.length)
            if span.status == SpanStatus.UNKNOWN:
                unknown.update(rng)
            elif span.status == SpanStatus.AMBIGUOUS:
                ambiguous.update(rng)
        for off, origin in stream.provenance.primary.items():
            if origin.status == "ambiguous":
                ambiguous.add(off)
        self.hex_view.set_markers(ambiguous=ambiguous, unknown=unknown)
        self.stream_meta.setText(
            f"len={stream.length}  ok={stream.bytes_ok}  "
            f"unknown={stream.bytes_unknown}  ambig≈{stream.bytes_ambiguous}"
        )
        lines = list(stream.defects)
        bundle = self.workspace.stream_for(self._current_session_id) if self.workspace else None
        if bundle and bundle.error:
            lines.insert(0, f"SESSION ERROR: {bundle.error}")
        if self.workspace:
            d = self.workspace.capture.diagnostics
            if d.skipped:
                lines.append(f"import skips: {d.skipped}")
            lines.extend(d.warnings[:20])
        self.defect_view.setPlainText("\n".join(lines) if lines else "No defects marked.")

    def _populate_packets(self) -> None:
        self.packet_table.setRowCount(0)
        if self.workspace is None or self._current_session_id is None:
            return
        sess = self.workspace.session(self._current_session_id)
        if sess is None:
            return
        t0 = sess.first_ts
        for pid in sess.packet_ids:
            pkt = self.workspace.packet(pid)
            if pkt is None or pkt.tcp is None or pkt.ipv4 is None:
                continue
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            flags = []
            if pkt.syn:
                flags.append("SYN")
            if pkt.ack_flag:
                flags.append("ACK")
            if pkt.fin:
                flags.append("FIN")
            if pkt.rst:
                flags.append("RST")
            if pkt.tcp.flags & 0x08:
                flags.append("PSH")
            vals = [
                str(pkt.packet_id),
                f"{pkt.ts - t0:.4f}",
                f"{pkt.ipv4.src}:{pkt.tcp.src_port}",
                f"{pkt.ipv4.dst}:{pkt.tcp.dst_port}",
                "/".join(flags) or "—",
                str(len(pkt.tcp.payload)),
            ]
            for col, text in enumerate(vals):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, pkt.packet_id)
                self.packet_table.setItem(row, col, item)

    def _on_packet_selected(self) -> None:
        rows = self.packet_table.selectionModel().selectedRows()
        if not rows or self.workspace is None:
            return
        item = self.packet_table.item(rows[0].row(), 0)
        if item is None:
            return
        packet_id = int(item.data(Qt.ItemDataRole.UserRole))
        stream = self._current_stream()
        if stream is None:
            return
        rng = stream.provenance.range_for_packet(packet_id)
        if rng is None:
            self.prov_label.setText(f"Packet {packet_id}: no payload in this direction.")
            self.hex_view.set_markers(highlight=set())
            return
        start, end = rng
        self.hex_view.select_range(start, end - start)
        self.hex_view.set_markers(highlight=set(range(start, end)))
        self.prov_label.setText(
            f"Packet {packet_id} → stream [{start}:{end}) "
            f"({end - start} B)  capture={self.workspace.capture.capture_id}"
        )

    def _on_hex_offset(self, offset: int) -> None:
        stream = self._current_stream()
        if stream is None or self.workspace is None:
            return
        origin = stream.provenance.origin_at(offset)
        if origin is None:
            for span in stream.spans:
                if span.stream_offset <= offset < span.stream_offset + span.length:
                    self.prov_label.setText(
                        f"offset {offset}: status={span.status.value}  note={span.note or '—'}"
                    )
                    return
            self.prov_label.setText(f"offset {offset}: no provenance")
            return
        self.prov_label.setText(
            f"offset {offset}: pkt #{origin.packet_id}  "
            f"dir={origin.direction}  status={origin.status}\n"
            f"capture={origin.capture_id}  session={origin.session_id}"
        )
        for row in range(self.packet_table.rowCount()):
            item = self.packet_table.item(row, 0)
            if item and int(item.data(Qt.ItemDataRole.UserRole)) == origin.packet_id:
                self.packet_table.selectRow(row)
                break
        self.hex_view.set_markers(highlight={offset})

    def _on_hex_selection(self, start: int, length: int) -> None:
        self._hex_sel_start = start
        self._hex_sel_len = length

    def _mark_selection_a(self) -> None:
        if self._hex_sel_len <= 0:
            QMessageBox.information(self, "Compare", "Select a hex range first.")
            return
        self.investigate.mark_range_a(self._hex_sel_start, self._hex_sel_len)

    def _mark_selection_b(self) -> None:
        if self._hex_sel_len <= 0:
            QMessageBox.information(self, "Compare", "Select a hex range first.")
            return
        self.investigate.mark_range_b(self._hex_sel_start, self._hex_sel_len)

    def _jump_to_packets(self, packet_ids: list) -> None:
        if not packet_ids:
            return
        target = int(packet_ids[0])
        for row in range(self.packet_table.rowCount()):
            item = self.packet_table.item(row, 0)
            if item and int(item.data(Qt.ItemDataRole.UserRole)) == target:
                self.packet_table.selectRow(row)
                self.packet_table.scrollToItem(item)
                break

    def _jump_to_stream_range(self, direction: object, start: int, length: int) -> None:
        if isinstance(direction, Direction) and direction != self._current_direction:
            idx = self.direction_combo.findData(direction)
            if idx >= 0:
                self.direction_combo.setCurrentIndex(idx)
        if length > 0:
            self.hex_view.select_range(start, length)
            self.hex_view.set_markers(highlight=set(range(start, start + length)))

    def export_report(self) -> None:
        if not self._require_project():
            return
        assert self.project is not None
        out_dir = QFileDialog.getExistingDirectory(self, "Export report to directory")
        if not out_dir:
            return
        from madrigal.core.report import ReportDraft, write_report

        interps = self.project.list_interpretations()
        if not interps:
            QMessageBox.information(
                self, "Report", "Import or save an interpretation first."
            )
            return
        interp = interps[0]
        validation = None
        if self.workspace is not None:
            from madrigal.core.validate import validate_workspace

            try:
                validation = validate_workspace(interp, self.workspace)
            except Exception as exc:
                QMessageBox.warning(self, "Report", f"Validation skipped: {exc}")
        draft = ReportDraft(
            title=f"{self.project.meta.name} — protocol report",
            rationale="Lab notes exported from the Madrigal workbench.",
            scope=f"Interpretation `{interp.name}`; "
            f"captures={len(self.project.meta.captures)}.",
            open_questions=["Review uncovered / contradict hits in validation."],
        )
        try:
            md_path, json_path = write_report(
                Path(out_dir),
                project=self.project,
                draft=draft,
                interpretation=interp,
                validation=validation,
                basename="madrigal_report",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Report failed", str(exc))
            return
        msg = f"Wrote {md_path}"
        if json_path:
            msg += f"\nand {json_path}"
        QMessageBox.information(self, "Report", msg)
        self._set_status(f"Exported report to {out_dir}")

    def package_project(self) -> None:
        if not self._require_project():
            return
        assert self.project is not None
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Package project zip",
            f"{self.project.meta.name}.madrigal.zip",
            "Zip (*.zip)",
        )
        if not path:
            return
        try:
            dest = self.project.package_zip(Path(path))
        except Exception as exc:
            QMessageBox.critical(self, "Package failed", str(exc))
            return
        warns = self.project.assert_portable()
        note = ""
        if warns:
            note = "\n\nPortability warnings:\n- " + "\n- ".join(warns)
        QMessageBox.information(self, "Package", f"Wrote {dest}{note}")
        self._set_status(f"Packaged {dest}")

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            "About Madrigal",
            f"<h3>Madrigal Protocol Laboratory {__version__}</h3>"
            "<p>Phase 4: portable projects, Markdown/JSON reports, CLI reuse, "
            "resource limits, and golden corpus tests — plus Phases 1–3 tooling.</p>",
        )
