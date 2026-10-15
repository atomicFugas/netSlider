"""Author and browse project observations linked to stream ranges."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from madrigal.core.project import ProjectStore
from madrigal.core.tcp.session import Direction
from madrigal.core.workspace import CaptureWorkspace


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ObservationsPanel(QWidget):
    """Save notes tied to capture/session/direction/offset/length."""

    jumpToStreamRange = Signal(object, int, int)
    statusMessage = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.project: ProjectStore | None = None
        self.workspace: CaptureWorkspace | None = None
        self.session_id: str | None = None
        self._direction = Direction.A_TO_B
        self._sel_start = 0
        self._sel_len = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)

        self.link_label = QLabel("No selection linked.")
        self.link_label.setWordWrap(True)
        root.addWidget(self.link_label)

        self.note_edit = QTextEdit()
        self.note_edit.setPlaceholderText("Observation note…")
        self.note_edit.setMinimumHeight(80)
        root.addWidget(self.note_edit, stretch=1)

        form = QFormLayout()
        self.name_hint = QLabel("(auto name from timestamp)")
        form.addRow("File", self.name_hint)
        root.addLayout(form)

        row = QHBoxLayout()
        btn_save = QPushButton("Save observation")
        btn_save.clicked.connect(self._save)
        row.addWidget(btn_save)
        btn_refresh = QPushButton("Refresh list")
        btn_refresh.clicked.connect(self._refresh_list)
        row.addWidget(btn_refresh)
        row.addStretch(1)
        root.addLayout(row)

        root.addWidget(QLabel("Saved observations"))
        self.list = QListWidget()
        self.list.itemSelectionChanged.connect(self._on_selected)
        root.addWidget(self.list, stretch=2)

        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(120)
        root.addWidget(self.detail)

    def set_project(self, project: ProjectStore | None) -> None:
        self.project = project
        self._refresh_list()

    def set_workspace(self, workspace: CaptureWorkspace | None) -> None:
        self.workspace = workspace
        self._update_link_label()

    def set_session(self, session_id: str | None, direction: Direction) -> None:
        self.session_id = session_id
        self._direction = direction
        self._update_link_label()

    def set_selection(self, start: int, length: int) -> None:
        self._sel_start = max(0, start)
        self._sel_len = max(0, length)
        self._update_link_label()

    def _update_link_label(self) -> None:
        cap = self.workspace.capture.capture_id if self.workspace else "—"
        sess = self.session_id or "—"
        self.link_label.setText(
            f"Link: capture={cap} session={sess} "
            f"dir={self._direction.value} offset={self._sel_start} len={self._sel_len}"
        )

    def _payload(self) -> dict:
        return {
            "created_at": _utc_now_iso(),
            "note": self.note_edit.toPlainText().strip(),
            "capture_id": (
                self.workspace.capture.capture_id if self.workspace is not None else None
            ),
            "session_id": self.session_id,
            "direction": self._direction.value,
            "stream_offset": self._sel_start,
            "length": self._sel_len,
        }

    def _save(self) -> None:
        if self.project is None:
            QMessageBox.information(self, "Observations", "Open a project first.")
            return
        note = self.note_edit.toPlainText().strip()
        if not note:
            QMessageBox.information(self, "Observations", "Write a note before saving.")
            return
        payload = self._payload()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = f"obs_{stamp}.json"
        try:
            dest = self.project.save_observation(name, payload)
        except Exception as exc:
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self.note_edit.clear()
        self._refresh_list()
        self.statusMessage.emit(f"Saved observation {dest.name}")

    def _refresh_list(self) -> None:
        self.list.clear()
        self.detail.clear()
        if self.project is None:
            return
        for path in self.project.list_observations():
            item = QListWidgetItem(path.name)
            item.setData(Qt.ItemDataRole.UserRole, path)
            self.list.addItem(item)

    def _on_selected(self) -> None:
        items = self.list.selectedItems()
        if not items:
            return
        path: Path = items[0].data(Qt.ItemDataRole.UserRole)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.detail.setPlainText(str(exc))
            return
        self.detail.setPlainText(json.dumps(data, indent=2, ensure_ascii=False))
        note = data.get("note") or ""
        if note:
            self.note_edit.setPlainText(note)
        direction = data.get("direction")
        start = int(data.get("stream_offset") or 0)
        length = int(data.get("length") or 0)
        if length > 0:
            dir_enum = Direction.A_TO_B
            if direction == Direction.B_TO_A.value:
                dir_enum = Direction.B_TO_A
            self.jumpToStreamRange.emit(dir_enum, start, length)
