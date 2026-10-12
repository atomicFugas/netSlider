"""Application entry point."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from madrigal.app.main_window import MainWindow


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    app = QApplication(argv)
    app.setApplicationName("Madrigal")
    app.setOrganizationName("Madrigal")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
