#!/usr/bin/env bash
# Build the standalone bundle: dist/ps5bp/{ps5bp,ps5bp-gui}
set -euo pipefail
cd "$(dirname "$0")/.."
VENV=${VENV:-.venv-bundle}
PYTHON=${PYTHON:-/usr/bin/python3}     # system Python: hermes/uv builds ship an unstripped libpython
[ -d "$VENV" ] || "$PYTHON" -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q '.[gui]' pyinstaller
"$VENV/bin/pyinstaller" --clean --noconfirm --distpath dist --workpath build packaging/ps5bp.spec
echo
echo "built: $(pwd)/dist/ps5bp/ps5bp and ps5bp-gui"
echo "desktop entry: scripts/install-desktop.sh $(pwd)/dist/ps5bp/ps5bp-gui"
