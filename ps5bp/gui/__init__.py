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
    app.setApplicationName("PS5 Backporter")
    app.setApplicationVersion(__version__)
    w = MainWindow()
    w.show()
    return app.exec()
