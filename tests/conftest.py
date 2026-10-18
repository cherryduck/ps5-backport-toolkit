import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


import pytest


@pytest.fixture(autouse=True)
def _isolated_ps5bp_home(tmp_path, monkeypatch):
    """Never touch the real kit store / applied.json ledger."""
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))


@pytest.fixture(autouse=True)
def _isolated_qsettings(tmp_path):
    """Never touch the user's saved GUI settings (~/.config/ps5bp, %APPDATA%\\ps5bp)."""
    try:
        from PyQt6.QtCore import QSettings
    except ImportError:
        return
    for fmt in (QSettings.Format.NativeFormat, QSettings.Format.IniFormat):
        QSettings.setPath(fmt, QSettings.Scope.UserScope, str(tmp_path / "qtcfg"))
