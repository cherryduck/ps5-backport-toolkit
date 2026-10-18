# PyInstaller spec: one onedir bundle with two executables sharing the same libs.
#   dist/ps5bp/ps5bp[.exe]       command line
#   dist/ps5bp/ps5bp-gui[.exe]   GUI (no console)
# Build with scripts/build-bundle.sh (Linux) or scripts/build-bundle.ps1 (Windows).
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

ROOT = Path(SPECPATH).parent
datas = collect_data_files("ps5bp") + collect_data_files("capstone")
binaries = collect_dynamic_libs("capstone")
# every ps5bp module: rules and helpers are imported lazily (rules.registry(), GUI tabs), so a
# hand-kept list silently drops new ones from the bundle
common = dict(pathex=[str(ROOT)], binaries=binaries, datas=datas,
              hiddenimports=collect_submodules("ps5bp"),
              excludes=["tkinter", "pytest"])

cli = Analysis([str(ROOT / "packaging/entry_cli.py")], **common)
gui = Analysis([str(ROOT / "packaging/entry_gui.py")], **common)

WINDOWS = sys.platform == "win32"

# Trim the bundle (Linux only; the patterns are Linux shared objects): the GTK3 platform theme drags in GTK/cairo/atk/a second ICU (~70 MB);
# PDF + embedded-display platforms and Qt translations are unused. Wayland, xcb,
# offscreen and the xdg-desktop-portal theme stay.
import re
DROP = re.compile(r"(libqgtk3|/translations/|libQt6Pdf|libqpdf|egldeviceintegrations|libqeglfs|libqvnc"
                  r"|libqlinuxfb|libqminimalegl|libqvkkhrdisplay|libQt6EglFSDeviceIntegration"
                  r"|^libgtk-3|^libgdk-3|^libatk|^libatspi|^libcairo|^libgdk_pixbuf|^libcloudproviders"
                  r"|^libepoxy|^libglycin|^libicu\w+\.so\.78|^libpango|^librsvg|^libtinysparql|^libcolord"
                  r"|^libxkbcommon-x11|^liblcms2)")


def trim(toc):
    return [e for e in toc if not DROP.search(e[0].split("_internal/")[-1])]


if not WINDOWS:
    for a in (cli, gui):
        a.binaries = trim(a.binaries)
        a.datas = trim(a.datas)

STRIP = not WINDOWS                     # no `strip` tool on Windows
ICON = str(ROOT / "packaging/ps5bp.ico") if WINDOWS else None
cli_exe = EXE(PYZ(cli.pure), cli.scripts, [], exclude_binaries=True, name="ps5bp", console=True,
              strip=STRIP, icon=ICON)
gui_exe = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True, name="ps5bp-gui", console=False,
              strip=STRIP, icon=ICON)

COLLECT(cli_exe, cli.binaries, cli.datas, gui_exe, gui.binaries, gui.datas, name="ps5bp", strip=STRIP)
