"""PyQt6 front end (optional: pip install 'ps5bp[gui]')."""
import sys


def main() -> int:
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print("The GUI needs PyQt6: pip install 'ps5bp[gui]'", file=sys.stderr)
        return 1
    from .. import __version__
    from .window import MainWindow
    app = QApplication(sys.argv)
    app.setApplicationName("PS5 Backport Toolkit")
    app.setApplicationVersion(__version__)
    app.setDesktopFileName("ps5bp")                 # Wayland app_id -> matches ps5bp.desktop
    from importlib import resources
    from PyQt6.QtGui import QIcon
    icon = resources.files("ps5bp").joinpath("data/ps5bp.svg")
    if icon.is_file():
        app.setWindowIcon(QIcon(str(icon)))
    w = MainWindow()
    w.show()
    return app.exec()
