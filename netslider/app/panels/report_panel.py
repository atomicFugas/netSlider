"""Report preview tab using core/report Markdown export."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from netslider.core.project import ProjectStore
from netslider.core.report import ReportDraft, build_markdown_report, write_report
from netslider.core.workspace import CaptureWorkspace


class ReportPanel(QWidget):
    """Preview Markdown report and export Markdown + machine JSON."""

    statusMessage = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.project: ProjectStore | None = None
        self.workspace: CaptureWorkspace | None = None
        self._last_validation = None

        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)

        form = QFormLayout()
        self.title_edit = QLineEdit("Protocol report")
        form.addRow("Title", self.title_edit)
        self.rationale_edit = QLineEdit("Lab notes from the netSlider workbench.")
        form.addRow("Rationale", self.rationale_edit)
        self.scope_edit = QLineEdit()
        form.addRow("Scope", self.scope_edit)
        self.questions_edit = QLineEdit("Review uncovered / contradict hits.")
        form.addRow("Open questions", self.questions_edit)
        root.addLayout(form)

        row = QHBoxLayout()
        btn_preview = QPushButton("Refresh preview")
        btn_preview.clicked.connect(self.refresh_preview)
        row.addWidget(btn_preview)
        btn_export = QPushButton("Export…")
        btn_export.clicked.connect(self.export_report)
        row.addWidget(btn_export)
        row.addStretch(1)
        root.addLayout(row)

        root.addWidget(QLabel("Markdown preview"))
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        root.addWidget(self.preview, stretch=1)

    def set_project(self, project: ProjectStore | None) -> None:
        self.project = project
        if project is not None:
            self.title_edit.setText(f"{project.meta.name} — protocol report")
            self.scope_edit.setText(
                f"Captures: {len(project.meta.captures)}; "
                f"interpretations: {len(project.list_interpretations())}."
            )
        self.refresh_preview()

    def set_workspace(self, workspace: CaptureWorkspace | None) -> None:
        self.workspace = workspace

    def set_validation(self, validation) -> None:
        self._last_validation = validation

    def _draft(self) -> ReportDraft:
        questions = [q.strip() for q in self.questions_edit.text().split(";") if q.strip()]
        return ReportDraft(
            title=self.title_edit.text().strip() or "Protocol report",
            rationale=self.rationale_edit.text().strip(),
            scope=self.scope_edit.text().strip(),
            open_questions=questions,
        )

    def _interpretation_path(self) -> Path | None:
        if self.project is None:
            return None
        return self.project.primary_interpretation()

    def refresh_preview(self) -> None:
        if self.project is None:
            self.preview.setPlainText("Open a project to preview a report.")
            return
        interp = self._interpretation_path()
        validation = self._last_validation
        if validation is None and self.workspace is not None and interp is not None:
            try:
                from netslider.core.validate import validate_workspace

                validation = validate_workspace(interp, self.workspace)
            except Exception:
                validation = None
        try:
            md = build_markdown_report(
                self.project,
                draft=self._draft(),
                interpretation=interp,
                validation=validation,
            )
        except Exception as exc:
            self.preview.setPlainText(f"Preview failed: {exc}")
            return
        self.preview.setPlainText(md)

    def export_report(self) -> None:
        if self.project is None:
            QMessageBox.information(self, "Report", "Open a project first.")
            return
        interp = self._interpretation_path()
        if interp is None:
            QMessageBox.information(
                self, "Report", "Import or save an interpretation first."
            )
            return
        out_dir = QFileDialog.getExistingDirectory(self, "Export report to directory")
        if not out_dir:
            return
        validation = self._last_validation
        if validation is None and self.workspace is not None:
            try:
                from netslider.core.validate import validate_workspace

                validation = validate_workspace(interp, self.workspace)
            except Exception as exc:
                QMessageBox.warning(self, "Report", f"Validation skipped: {exc}")
        try:
            md_path, json_path = write_report(
                Path(out_dir),
                project=self.project,
                draft=self._draft(),
                interpretation=interp,
                validation=validation,
                basename="netslider_report",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Report failed", str(exc))
            return
        self.refresh_preview()
        msg = f"Wrote {md_path}"
        if json_path:
            msg += f"\nand {json_path}"
        QMessageBox.information(self, "Report", msg)
        self.statusMessage.emit(f"Exported report to {out_dir}")
