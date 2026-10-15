@echo off
REM Launch the portable onedir build (not build\netslider staging).
set "EXE=%~dp0dist\NetSlider\NetSlider.exe"
if not exist "%EXE%" (
  echo NetSlider.exe not found at:
  echo   %EXE%
  echo Run:  .\scripts\build_windows.ps1
  pause
  exit /b 1
)
start "" "%EXE%"
