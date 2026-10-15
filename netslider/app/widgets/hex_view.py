"""Simple hex viewer with selection and stream-offset reporting."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QAbstractScrollArea, QSizePolicy


class HexView(QAbstractScrollArea):
    """Fixed-width hex dump. Emits ``offsetActivated(int)`` on click."""

    offsetActivated = Signal(int)
    selectionChanged = Signal(int, int)  # start, length

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._data = b""
        self._bytes_per_row = 16
        self._row_height = 18
        self._selection_start = -1
        self._selection_len = 0
        self._highlight: set[int] = set()
        self._ambiguous: set[int] = set()
        self._unknown: set[int] = set()
        font = QFont("Menlo")
        if not font.exactMatch():
            font = QFont("Courier New")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(12)
        self.setFont(font)
        self.setMinimumSize(0, 0)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.viewport().setCursor(Qt.CursorShape.IBeamCursor)
        self.setMouseTracking(True)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(480, 200)

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        return QSize(120, 60)

    def set_data(self, data: bytes) -> None:
        self._data = data
        self._selection_start = -1
        self._selection_len = 0
        self._update_scroll()
        self.viewport().update()

    def set_markers(self, *, highlight: set[int] | None = None, ambiguous: set[int] | None = None, unknown: set[int] | None = None) -> None:
        if highlight is not None:
            self._highlight = highlight
        if ambiguous is not None:
            self._ambiguous = ambiguous
        if unknown is not None:
            self._unknown = unknown
        self.viewport().update()

    def select_range(self, start: int, length: int, *, scroll: bool = True) -> None:
        self._selection_start = max(0, start)
        self._selection_len = max(0, length)
        if scroll and self._bytes_per_row:
            row = self._selection_start // self._bytes_per_row
            self.verticalScrollBar().setValue(row)
        self.viewport().update()
        self.selectionChanged.emit(self._selection_start, self._selection_len)

    def _update_scroll(self) -> None:
        rows = (len(self._data) + self._bytes_per_row - 1) // self._bytes_per_row
        self.verticalScrollBar().setRange(0, max(0, rows - 1))
        self.verticalScrollBar().setPageStep(max(1, self.viewport().height() // self._row_height))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._update_scroll()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self.viewport())
        painter.fillRect(self.viewport().rect(), QColor("#1e1e1e"))
        painter.setFont(self.font())
        fm = painter.fontMetrics()
        char_w = fm.horizontalAdvance("0")
        first_row = self.verticalScrollBar().value()
        rows_visible = self.viewport().height() // self._row_height + 2
        sel_lo = self._selection_start
        sel_hi = self._selection_start + self._selection_len

        for row_i in range(rows_visible):
            row = first_row + row_i
            offset = row * self._bytes_per_row
            if offset >= len(self._data):
                break
            y = row_i * self._row_height + fm.ascent() + 2
            # address
            painter.setPen(QColor("#858585"))
            painter.drawText(6, y, f"{offset:08x}")

            x_hex = 6 + char_w * 10
            x_ascii = x_hex + char_w * (self._bytes_per_row * 3 + 2)
            chunk = self._data[offset : offset + self._bytes_per_row]
            ascii_chars: list[str] = []
            for i, b in enumerate(chunk):
                abs_off = offset + i
                bx = x_hex + i * char_w * 3
                bg = None
                if sel_lo <= abs_off < sel_hi:
                    bg = QColor("#264f78")
                elif abs_off in self._highlight:
                    bg = QColor("#3a5f3a")
                elif abs_off in self._ambiguous:
                    bg = QColor("#6b4c1e")
                elif abs_off in self._unknown:
                    bg = QColor("#5a1e1e")
                if bg is not None:
                    painter.fillRect(bx - 1, y - fm.ascent(), char_w * 2 + 2, self._row_height - 2, bg)
                painter.setPen(QColor("#d4d4d4"))
                painter.drawText(bx, y, f"{b:02x}")
                ascii_chars.append(chr(b) if 32 <= b < 127 else ".")

            painter.setPen(QColor("#ce9178"))
            painter.drawText(x_ascii, y, "".join(ascii_chars))

        # separator
        painter.setPen(QPen(QColor("#333333")))
        painter.drawLine(0, 0, 0, self.viewport().height())

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() != Qt.MouseButton.LeftButton:
            return
        off = self._offset_at(event.position().toPoint())
        if off is not None:
            self.select_range(off, 1, scroll=False)
            self.offsetActivated.emit(off)

    def _offset_at(self, pos) -> int | None:
        fm = self.fontMetrics()
        char_w = fm.horizontalAdvance("0")
        row = self.verticalScrollBar().value() + pos.y() // self._row_height
        x_hex = 6 + char_w * 10
        col = (pos.x() - x_hex) // (char_w * 3)
        if col < 0 or col >= self._bytes_per_row:
            return None
        off = row * self._bytes_per_row + int(col)
        if off < 0 or off >= len(self._data):
            return None
        return off

    def scrollContentsBy(self, dx: int, dy: int) -> None:  # noqa: N802
        self.viewport().update()
