# Build a portable Windows onedir bundle (NetSlider.exe + netslider-cli.exe).
# Run from the repo root with PowerShell:
#   .\scripts\build_windows.ps1
#
# Output:
#   dist\NetSlider\NetSlider.exe
#   dist\NetSlider-windows.zip

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Error "Missing .venv. Create it first: python -m venv .venv && .\.venv\Scripts\pip install -e `".[build]`""
}

Write-Host "Installing package + build extras..."
& $VenvPython -m pip install -e ".[build]"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$PyInstaller = Join-Path $Root ".venv\Scripts\pyinstaller.exe"
if (-not (Test-Path $PyInstaller)) {
    Write-Error "pyinstaller not found after install"
}

Write-Host "Running PyInstaller (netslider.spec)..."
& $PyInstaller netslider.spec --noconfirm
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$DistDir = Join-Path $Root "dist\NetSlider"
$Exe = Join-Path $DistDir "NetSlider.exe"
if (-not (Test-Path $Exe)) {
    Write-Error "Build finished but NetSlider.exe was not found at $Exe"
}

# PyInstaller leaves incomplete EXEs under build\netslider\ (no _internal).
# Remove them so double-clicking the wrong NetSlider.exe cannot happen.
$WorkDir = Join-Path $Root "build\netslider"
foreach ($name in @("NetSlider.exe", "netslider-cli.exe")) {
    $stale = Join-Path $WorkDir $name
    if (Test-Path $stale) {
        Remove-Item $stale -Force
        Write-Host "Removed incomplete staging exe: $stale"
    }
}

$ZipPath = Join-Path $Root "dist\NetSlider-windows.zip"
if (Test-Path $ZipPath) {
    Remove-Item $ZipPath -Force
}

Write-Host "Zipping $DistDir -> $ZipPath ..."
Compress-Archive -Path $DistDir -DestinationPath $ZipPath -Force

$Launcher = Join-Path $Root "NetSlider.bat"
@"
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
"@ | Set-Content -Path $Launcher -Encoding ASCII

Write-Host ""
Write-Host "Done."
Write-Host "  App:       $Exe"
Write-Host "  Launcher:  $Launcher"
Write-Host "  Zip:       $ZipPath"
Write-Host "Use dist\NetSlider\NetSlider.exe (or NetSlider.bat). Never run build\netslider\*."
Write-Host "Classic PCAP works without extras; PCAPNG needs Wireshark (tshark on PATH)."
