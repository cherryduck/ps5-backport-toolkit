# Build the standalone Windows bundle: dist\ps5bp\{ps5bp.exe,ps5bp-gui.exe}
# Usage (PowerShell, repo root or anywhere):  scripts\build-bundle.ps1
# Needs Python 3.11+ on PATH (python.org installer or `winget install Python.Python.3.12`).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$Venv = if ($env:VENV) { $env:VENV } else { ".venv-bundle" }
$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
if (-not (Test-Path $Venv)) { & $Python -m venv $Venv; if ($LASTEXITCODE) { exit $LASTEXITCODE } }
$Py = Join-Path $Venv "Scripts\python.exe"
& $Py -m pip install -q --upgrade pip
& $Py -m pip install -q ".[gui]" pyinstaller
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& $Py -m PyInstaller --clean --noconfirm --distpath dist --workpath build packaging\ps5bp.spec
if ($LASTEXITCODE) { exit $LASTEXITCODE }
Write-Host ""
Write-Host "built: $(Get-Location)\dist\ps5bp\ps5bp.exe and ps5bp-gui.exe"
