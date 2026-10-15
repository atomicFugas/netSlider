# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller onedir build: NetSlider.exe + netslider-cli.exe."""

from __future__ import annotations

from PyInstaller.building.api import COLLECT, EXE, PYZ
from PyInstaller.building.build_main import Analysis
from PyInstaller.utils.hooks import collect_all, collect_data_files

block_cipher = None

pyside6_datas, pyside6_binaries, pyside6_hidden = collect_all("PySide6")
netslider_datas = collect_data_files("netslider")
# collect_data_files skips .py; keep demo interpretation hooks next to YAML
netslider_datas += [
    (
        "netslider/demo/corpus/interpretations/device_v1_frame.py",
        "netslider/demo/corpus/interpretations",
    ),
]

hiddenimports = list(
    {
        *pyside6_hidden,
        "PySide6",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "pyshark",
        "yaml",
        "pandas",
        "click",
        "netslider",
        "netslider.app.main",
        "netslider.cli.main",
    }
)

gui_a = Analysis(
    ["netslider/app/main.py"],
    pathex=[],
    binaries=pyside6_binaries,
    datas=pyside6_datas + netslider_datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

cli_a = Analysis(
    ["netslider/cli/main.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

gui_pyz = PYZ(gui_a.pure, gui_a.zipped_data, cipher=block_cipher)
cli_pyz = PYZ(cli_a.pure, cli_a.zipped_data, cipher=block_cipher)

gui_exe = EXE(
    gui_pyz,
    gui_a.scripts,
    [],
    exclude_binaries=True,
    name="NetSlider",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

cli_exe = EXE(
    cli_pyz,
    cli_a.scripts,
    [],
    exclude_binaries=True,
    name="netslider-cli",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    gui_exe,
    gui_a.binaries,
    gui_a.zipfiles,
    gui_a.datas,
    cli_exe,
    cli_a.binaries,
    cli_a.zipfiles,
    cli_a.datas,
    name="NetSlider",
)
