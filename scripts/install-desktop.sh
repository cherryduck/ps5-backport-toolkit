#!/usr/bin/env bash
# Install a desktop entry + icon for the GUI (per user, no root).
#   scripts/install-desktop.sh [path/to/ps5bp-gui]     default: dist bundle, else ps5bp-gui on PATH
#   scripts/install-desktop.sh --uninstall
# Also shipped at the top of the Linux release tarball: there it uses the ps5bp-gui next to it.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
if [ -x "$HERE/ps5bp-gui" ]; then              # release tarball layout
    cd "$HERE"; DEFAULT_EXE=$HERE/ps5bp-gui; SVG=$HERE/_internal/ps5bp/data/ps5bp.svg
else                                            # source tree: scripts/
    cd "$HERE/.."; DEFAULT_EXE=""; SVG=ps5bp/data/ps5bp.svg
fi
APPS=${XDG_DATA_HOME:-$HOME/.local/share}/applications
ICONS=${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor
if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$APPS/ps5bp.desktop" "$ICONS/scalable/apps/ps5bp.svg" "$ICONS/256x256/apps/ps5bp.png"
    echo "removed"; exit 0
fi
EXE=${1:-$DEFAULT_EXE}
if [ -z "$EXE" ]; then
    if [ -x dist/ps5bp/ps5bp-gui ]; then EXE=$(pwd)/dist/ps5bp/ps5bp-gui
    else EXE=$(command -v ps5bp-gui || true); fi
fi
[ -n "$EXE" ] && [ -x "$EXE" ] || { echo "ps5bp-gui not found — build the bundle or pipx install first" >&2; exit 1; }
EXE=$(readlink -f "$EXE")
mkdir -p "$APPS" "$ICONS/scalable/apps" "$ICONS/256x256/apps"
cp "$SVG" "$ICONS/scalable/apps/ps5bp.svg"
if command -v rsvg-convert >/dev/null; then rsvg-convert -w 256 -h 256 "$SVG" > "$ICONS/256x256/apps/ps5bp.png"; fi
cat > "$APPS/ps5bp.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=PS5 Backport Toolkit
GenericName=PS5 game backport tool
Comment=Analyze PS5 game dumps and build firmware backports
Exec="$EXE"
Icon=ps5bp
Terminal=false
Categories=Utility;
Keywords=PS5;backport;fakelib;SELF;
StartupWMClass=ps5bp-gui
EOF
command -v update-desktop-database >/dev/null && update-desktop-database -q "$APPS" || true
echo "installed $APPS/ps5bp.desktop -> $EXE"
