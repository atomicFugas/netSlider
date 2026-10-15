"""Resolve package-relative paths for source and frozen (PyInstaller) runs."""

from __future__ import annotations

import sys
from pathlib import Path


def package_root() -> Path:
    """Return the on-disk root of the ``netslider`` package.

    Under PyInstaller onedir this is typically ``_internal/netslider``.
    In a normal install it is the package directory next to this module.
    """
    here = Path(__file__).resolve().parent
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass is not None:
            bundled = Path(meipass) / "netslider"
            if bundled.is_dir():
                return bundled
    return here


def demo_corpus_dir() -> Path:
    """Path to ``netslider/demo/corpus`` (interpretations, sample PCAPs)."""
    return package_root() / "demo" / "corpus"


def demo_interpretations_dir() -> Path:
    """Path to bundled demo interpretation YAML/JSON/Python files."""
    return demo_corpus_dir() / "interpretations"
