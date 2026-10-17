"""Phase 10g: the AMPR index combo on the Dump's fakelibs row."""
import os

import pytest

pytest.importorskip("PyQt6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from test_gui import wait                                    # noqa: E402,F401
from test_gui_10f import win, db, game                       # noqa: E402,F401
from test_phase10g import make_game                          # noqa: E402


def test_ampr_index_combo(win, tmp_path):
    items = [(win.ampr_index.itemText(i), win.ampr_index.itemData(i)) for i in range(win.ampr_index.count())]
    assert items == [("auto", "auto"), ("regenerate", "regen"), ("keep", "keep")]
    win.out_edit.setText(str(tmp_path / "o"))
    assert win.build_options().ampr_index == "auto"
    win.ampr_index.setCurrentIndex(win.ampr_index.findData("keep"))
    assert win.build_options().ampr_index == "keep"
    assert win.settings.value("ampr_index") == "keep"                 # remembered


def test_ampr_combo_restored(tmp_path, monkeypatch, db):
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    from PyQt6.QtWidgets import QApplication
    from ps5bp.gui.window import MainWindow
    app = QApplication.instance() or QApplication([])
    w = MainWindow()
    w.ampr_index.setCurrentIndex(w.ampr_index.findData("regen"))
    w.close()
    w2 = MainWindow()
    assert w2.ampr_index.currentData() == "regen"
    w2.close()
    app.processEvents()


def test_gui_build_reports_index_and_analyze_shows_ampr(win, tmp_path):
    g = make_game(tmp_path)
    win.game_edit.setText(str(g))
    win.target.setCurrentIndex(win.target.findData(4))
    win._analyze()
    wait(win)
    shown = [win.warn_list.item(i).text() for i in range(win.warn_list.count())]
    assert any("Ampr emulator: version 0.3.6.6" in s for s in shown)
    win.out_edit.setText(str(tmp_path / "out"))
    win._build()
    wait(win)
    rep = win.last_report
    assert rep.ok and rep.ampr["index"]["action"] == "created"
    assert "AMPR index: created" in win.built_text(rep)
    assert (tmp_path / "out/ampr_emu.index").is_file()
