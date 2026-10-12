"""Investigation tab: action log, framing probes, range compare."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from madrigal.core.investigate import (
    ActionLog,
    align_actions,
    delimiter_histogram,
    diff_ranges,
    find_magic,
    load_action_log,
    parse_magic_string,
    probe_grid,
    probe_length_prefix,
)
from madrigal.core.tcp.reassembly import DirectedStream
from madrigal.core.tcp.session import Direction
from madrigal.core.workspace import CaptureWorkspace


def _scroll_wrap(inner: QWidget) -> QScrollArea:
    """Put dense tab content in a scroll area that respects the panel height."""
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


class InvestigatePanel(QWidget):
    """Emits navigation requests into the main hex/packet views."""

    jumpToPackets = Signal(list)
    jumpToStreamRange = Signal(object, int, int)
    statusMessage = Signal(str)
    requestSelectionAsA = Signal()
    requestSelectionAsB = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.workspace: CaptureWorkspace | None = None
        self.session_id: str | None = None
        self.action_log: ActionLog | None = None
        self.alignment = None
        self._stream_data = b""
        self._direction = Direction.A_TO_B
        self._mark_a: tuple[int, int] | None = None
        self._mark_b: tuple[int, int] | None = None

        self.setMinimumHeight(0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setMinimumHeight(0)
        self.tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(self.tabs)

        self.tabs.addTab(_scroll_wrap(self._build_actions_tab()), "Actions")
        self.tabs.addTab(_scroll_wrap(self._build_framing_tab()), "Framing")
        self.tabs.addTab(_scroll_wrap(self._build_compare_tab()), "Compare")

    def set_workspace(self, workspace: CaptureWorkspace | None) -> None:
        self.workspace = workspace
        self._realign()

    def set_session(
        self,
        session_id: str | None,
        direction: Direction,
        stream: DirectedStream | None,
    ) -> None:
        self.session_id = session_id
        self._direction = direction
        self._stream_data = stream.materialize() if stream else b""
        self._realign()

    def load_action_log_path(self, path: Path) -> None:
        self.action_log = load_action_log(path)
        self._populate_actions()
        self._realign()
        self.statusMessage.emit(f"Loaded action log ({len(self.action_log.events)} events)")

    def mark_range_a(self, start: int, length: int) -> None:
        self._mark_a = (start, length)
        self.mark_a_label.setText(f"A: [{start}:{start + length}) ({length} B)")
        self._run_compare()

    def mark_range_b(self, start: int, length: int) -> None:
        self._mark_b = (start, length)
        self.mark_b_label.setText(f"B: [{start}:{start + length}) ({length} B)")
        self._run_compare()

    def _build_actions_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 4, 4, 4)
        form = QFormLayout()
        self.align_mode = QComboBox()
        self.align_mode.addItem("Relative (pin first action)", "relative")
        self.align_mode.addItem("Absolute timestamps", "absolute")
        self.align_mode.currentIndexChanged.connect(self._realign)
        form.addRow("Align", self.align_mode)
        self.window_spin = QDoubleSpinBox()
        self.window_spin.setRange(0.01, 5.0)
        self.window_spin.setSingleStep(0.02)
        self.window_spin.setValue(0.08)
        self.window_spin.setSuffix(" s")
        self.window_spin.valueChanged.connect(self._realign)
        form.addRow("Window ±", self.window_spin)
        v.addLayout(form)

        self.action_table = QTableWidget(0, 5)
        self.action_table.setHorizontalHeaderLabels(["#", "Action", "Δt", "Pkts", "Note"])
        self.action_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.action_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.action_table.itemSelectionChanged.connect(self._on_action_selected)
        self.action_table.horizontalHeader().setStretchLastSection(True)
        self.action_table.setMinimumHeight(100)
        v.addWidget(self.action_table, stretch=1)

        self.action_detail = QLabel("Select an action to highlight related packets/stream bytes.")
        self.action_detail.setWordWrap(True)
        v.addWidget(self.action_detail)
        return w

    def _populate_actions(self) -> None:
        self.action_table.setRowCount(0)
        if not self.action_log:
            return
        t0 = self.action_log.events[0].ts_epoch if self.action_log.events else 0.0
        for ev in self.action_log.events:
            row = self.action_table.rowCount()
            self.action_table.insertRow(row)
            vals = [str(ev.seq), ev.action, f"{ev.ts_epoch - t0:.3f}", "", ev.note or ""]
            for col, text in enumerate(vals):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, ev.seq)
                self.action_table.setItem(row, col, item)

    def _realign(self) -> None:
        if self.action_log is None or self.workspace is None:
            return
        sess = self.workspace.session(self.session_id) if self.session_id else None
        streams: dict[str, DirectedStream] = {}
        if sess is not None:
            bundle = self.workspace.stream_for(sess.key.session_id)
            if bundle:
                streams["A→B"] = bundle.a_to_b
                streams["B→A"] = bundle.b_to_a
        self.alignment = align_actions(
            self.action_log,
            self.workspace.capture.packets,
            session=sess,
            streams=streams,
            mode=self.align_mode.currentData(),
            window_s=self.window_spin.value(),
        )
        by_seq = {a.event.seq: a for a in self.alignment.actions}
        for row in range(self.action_table.rowCount()):
            item = self.action_table.item(row, 0)
            if not item:
                continue
            aligned = by_seq.get(int(item.data(Qt.ItemDataRole.UserRole)))
            if not aligned:
                continue
            pkt_item = self.action_table.item(row, 3)
            if pkt_item:
                pkt_item.setText(str(len(aligned.packet_ids)))
            note_item = self.action_table.item(row, 4)
            if note_item and aligned.note:
                note_item.setText(aligned.note)

    def _on_action_selected(self) -> None:
        rows = self.action_table.selectionModel().selectedRows()
        if not rows or self.alignment is None:
            return
        seq_item = self.action_table.item(rows[0].row(), 0)
        if seq_item is None:
            return
        seq = int(seq_item.data(Qt.ItemDataRole.UserRole))
        aligned = next((a for a in self.alignment.actions if a.event.seq == seq), None)
        if aligned is None:
            return
        ev = aligned.event
        self.action_detail.setText(
            f"#{ev.seq} {ev.summary()}\n"
            f"result={ev.result}  aligned_ts={aligned.aligned_ts:.6f}  "
            f"offset={self.alignment.offset:.6f}\n"
            f"packets={aligned.packet_ids}  ranges={aligned.stream_ranges}"
        )
        if aligned.packet_ids:
            self.jumpToPackets.emit(list(aligned.packet_ids))
        dir_label = "A→B" if self._direction == Direction.A_TO_B else "B→A"
        for label, start, end in aligned.stream_ranges:
            if label == dir_label and end > start:
                self.jumpToStreamRange.emit(self._direction, start, end - start)
                return
        if aligned.stream_ranges:
            label, start, end = aligned.stream_ranges[0]
            direction = Direction.A_TO_B if label == "A→B" else Direction.B_TO_A
            self.jumpToStreamRange.emit(direction, start, end - start)

    def _build_framing_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 4, 4, 4)
        v.setSpacing(6)

        magic_box = QGroupBox("Magic search")
        magic_l = QHBoxLayout(magic_box)
        self.magic_edit = QLineEdit("MD01")
        self.magic_edit.setPlaceholderText("MD01 / 4d443031 / 0x…")
        magic_l.addWidget(self.magic_edit, stretch=1)
        btn_magic = QPushButton("Find")
        btn_magic.clicked.connect(self._run_magic_search)
        magic_l.addWidget(btn_magic)
        v.addWidget(magic_box)

        self.magic_results = QTableWidget(0, 2)
        self.magic_results.setHorizontalHeaderLabels(["Offset", "Len"])
        self.magic_results.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.magic_results.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.magic_results.itemSelectionChanged.connect(self._on_magic_selected)
        self.magic_results.horizontalHeader().setStretchLastSection(True)
        self.magic_results.setMaximumHeight(110)
        v.addWidget(self.magic_results)

        probe_box = QGroupBox("Length-prefix probe")
        probe_form = QFormLayout(probe_box)
        self.len_offset = QSpinBox()
        self.len_offset.setRange(0, 64)
        self.len_offset.setValue(4)
        probe_form.addRow("Len offset", self.len_offset)
        self.len_size = QComboBox()
        self.len_size.addItem("u16", 2)
        self.len_size.addItem("u8", 1)
        self.len_size.addItem("u32", 4)
        probe_form.addRow("Len size", self.len_size)
        self.len_endian = QComboBox()
        self.len_endian.addItem("big-endian", "be")
        self.len_endian.addItem("little-endian", "le")
        probe_form.addRow("Endian", self.len_endian)
        self.len_includes = QComboBox()
        self.len_includes.addItem("length = body only", False)
        self.len_includes.addItem("length includes header", True)
        probe_form.addRow("Length means", self.len_includes)
        btn_row = QHBoxLayout()
        btn_probe = QPushButton("Probe")
        btn_probe.clicked.connect(self._run_probe)
        btn_grid = QPushButton("Auto grid")
        btn_grid.clicked.connect(self._run_probe_grid)
        btn_row.addWidget(btn_probe)
        btn_row.addWidget(btn_grid)
        probe_form.addRow(btn_row)
        v.addWidget(probe_box)

        self.probe_out = QTextEdit()
        self.probe_out.setReadOnly(True)
        self.probe_out.setMaximumHeight(90)
        v.addWidget(self.probe_out)

        hist_row = QHBoxLayout()
        hist_row.addWidget(QLabel("Delimiter / byte histogram"))
        btn_hist = QPushButton("Compute")
        btn_hist.clicked.connect(self._run_histogram)
        hist_row.addWidget(btn_hist)
        hist_row.addStretch(1)
        v.addLayout(hist_row)

        self.hist_table = QTableWidget(0, 4)
        self.hist_table.setHorizontalHeaderLabels(["Byte", "ASCII", "Count", "Freq"])
        self.hist_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.hist_table.horizontalHeader().setStretchLastSection(True)
        self.hist_table.setMinimumHeight(80)
        v.addWidget(self.hist_table)
        v.addStretch(1)
        return w

    def _run_magic_search(self) -> None:
        magic = parse_magic_string(self.magic_edit.text())
        self.magic_results.setRowCount(0)
        if not magic or not self._stream_data:
            self.statusMessage.emit("No magic / empty stream")
            return
        hits = find_magic(self._stream_data, magic)
        for hit in hits:
            row = self.magic_results.rowCount()
            self.magic_results.insertRow(row)
            for col, text in enumerate([str(hit.offset), str(hit.length)]):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, hit.offset)
                item.setData(Qt.ItemDataRole.UserRole + 1, hit.length)
                self.magic_results.setItem(row, col, item)
        self.statusMessage.emit(f"Magic {magic!r}: {len(hits)} hits")

    def _on_magic_selected(self) -> None:
        rows = self.magic_results.selectionModel().selectedRows()
        if not rows:
            return
        item = self.magic_results.item(rows[0].row(), 0)
        if not item:
            return
        start = int(item.data(Qt.ItemDataRole.UserRole))
        length = int(item.data(Qt.ItemDataRole.UserRole + 1))
        self.jumpToStreamRange.emit(None, start, length)

    def _run_probe(self) -> None:
        magic = parse_magic_string(self.magic_edit.text()) or None
        probe = probe_length_prefix(
            self._stream_data,
            len_offset=self.len_offset.value(),
            len_size=self.len_size.currentData(),
            endian=self.len_endian.currentData(),
            len_includes_header=self.len_includes.currentData(),
            magic=magic,
        )
        self.probe_out.setPlainText(f"{probe.note}\nsamples: {probe.sample_offsets[:20]}")
        if probe.sample_offsets:
            self.jumpToStreamRange.emit(None, probe.sample_offsets[0], 6)

    def _run_probe_grid(self) -> None:
        magic = parse_magic_string(self.magic_edit.text()) or None
        results = probe_grid(self._stream_data, magic=magic)
        lines = ["Top length-prefix hypotheses:"]
        for i, p in enumerate(results[:8], start=1):
            lines.append(
                f"{i}. off={p.len_offset} size={p.len_size} {p.endian} "
                f"incl_hdr={p.len_includes_header} → {p.note}"
            )
        self.probe_out.setPlainText("\n".join(lines))
        if results and results[0].frames_ok:
            best = results[0]
            self.len_offset.setValue(best.len_offset)
            idx = self.len_size.findData(best.len_size)
            if idx >= 0:
                self.len_size.setCurrentIndex(idx)
            idx = self.len_endian.findData(best.endian)
            if idx >= 0:
                self.len_endian.setCurrentIndex(idx)
            idx = self.len_includes.findData(best.len_includes_header)
            if idx >= 0:
                self.len_includes.setCurrentIndex(idx)

    def _run_histogram(self) -> None:
        stats = delimiter_histogram(self._stream_data)
        self.hist_table.setRowCount(0)
        for s in stats:
            row = self.hist_table.rowCount()
            self.hist_table.insertRow(row)
            ascii_s = chr(s.byte_value) if 32 <= s.byte_value < 127 else "."
            vals = [f"0x{s.byte_value:02x}", ascii_s, str(s.count), f"{s.frequency:.2%}"]
            for col, text in enumerate(vals):
                self.hist_table.setItem(row, col, QTableWidgetItem(text))

    def _build_compare_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(4, 4, 4, 4)
        v.addWidget(QLabel("Mark two ranges from the hex selection, then diff."))
        row = QHBoxLayout()
        self.btn_mark_a = QPushButton("Mark selection as A")
        self.btn_mark_b = QPushButton("Mark selection as B")
        self.btn_mark_a.clicked.connect(self.requestSelectionAsA.emit)
        self.btn_mark_b.clicked.connect(self.requestSelectionAsB.emit)
        row.addWidget(self.btn_mark_a)
        row.addWidget(self.btn_mark_b)
        v.addLayout(row)
        self.mark_a_label = QLabel("A: —")
        self.mark_b_label = QLabel("B: —")
        v.addWidget(self.mark_a_label)
        v.addWidget(self.mark_b_label)
        self.compare_out = QTextEdit()
        self.compare_out.setReadOnly(True)
        self.compare_out.setFontFamily("Menlo")
        self.compare_out.setMinimumHeight(80)
        v.addWidget(self.compare_out, stretch=1)
        return w

    def _run_compare(self) -> None:
        if not self._mark_a or not self._mark_b or not self._stream_data:
            return
        a0, al = self._mark_a
        b0, bl = self._mark_b
        diff = diff_ranges(
            self._stream_data[a0 : a0 + al],
            a0,
            self._stream_data[b0 : b0 + bl],
            b0,
        )
        self.compare_out.setPlainText(diff.summary + "\n\n" + diff.unified)
