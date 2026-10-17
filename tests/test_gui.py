"""Drive the real MainWindow headless: analyze -> tick rule -> build -> cancel path."""
import os
import time

import pytest

pytest.importorskip("PyQt6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication   # noqa: E402

from ps5bp.core import sdk                 # noqa: E402
from ps5bp.core.binary import Binary       # noqa: E402
from test_rules import PRO, TEXT_VA, db as _db, game as _game   # noqa: E402,F401  (fixtures)

game = _game
db = _db


@pytest.fixture
def win(tmp_path, monkeypatch, db):
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))          # same store the db fixture filled
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    app = QApplication.instance() or QApplication([])
    from ps5bp.gui.window import MainWindow
    w = MainWindow()
    w._headless = True
    yield w
    w.close()
    app.processEvents()


def wait(w, timeout=20):
    app = QApplication.instance()
    t = time.time()
    while w.worker is not None and time.time() - t < timeout:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()
    assert w.worker is None, "worker did not finish"


def test_kits_listed(win):
    assert win.kit_table.rowCount() == 1 and win.kit_table.item(0, 0).text() == "kit"


def test_analyze_and_build(win, game, tmp_path):
    win.game_edit.setText(str(game))
    win.target.setCurrentIndex(win.target.findData(4))
    assert not win.build_btn.isEnabled()
    win._analyze()
    wait(win)
    assert win.plan is not None and win.build_btn.isEnabled()
    assert win.bin_table.rowCount() == 1
    assert "absent" in [win.cov_table.item(r, 1).text() for r in range(win.cov_table.rowCount())]
    pro = win.rule_boxes["pro-disable"]
    assert pro.isEnabled() and not pro.isChecked()                       # never recommended (10j), not pre-ticked
    assert not win.rule_boxes["pssr-memory"].isEnabled()                 # nothing detected
    pro.setChecked(True)
    win.out_edit.setText(str(tmp_path / "out"))
    win._build()
    wait(win)
    rep = win.last_report
    assert rep.ok and any(f["applied"] for f in rep.findings if f["rule"] == "pro-disable")
    b = Binary.load(tmp_path / "out/eboot.bin")
    assert b.read(TEXT_VA, 7) == bytes.fromhex("31c089078906c3")
    assert sdk.find(b).ps5 == sdk.SDK_PAIRS[4][0]
    # second build into the same folder replaces the earlier build
    (tmp_path / "out/stale.txt").write_text("x")
    win._build()
    wait(win)
    assert win.last_report.ok and not (tmp_path / "out/stale.txt").exists()
    # a non-empty folder that isn't a ps5bp build is refused, untouched
    (tmp_path / "other").mkdir()
    (tmp_path / "other/mine.txt").write_text("keep")
    win.out_edit.setText(str(tmp_path / "other"))
    win._build()
    assert "not empty" in win.last_error and (tmp_path / "other/mine.txt").read_text() == "keep"
    assert win.build_btn.isEnabled()


def test_invalidate_on_target_change(win, game):
    win.game_edit.setText(str(game))
    win._analyze()
    wait(win)
    assert win.build_btn.isEnabled()
    win.target.setCurrentIndex(win.target.findData(6))
    assert win.plan is None and not win.build_btn.isEnabled()


def test_cancel(win, game, tmp_path):
    from ps5bp.gui.workers import BuildWorker
    from ps5bp.core.pipeline import BuildOptions
    win.game_edit.setText(str(game))
    win._analyze()
    wait(win)
    w = BuildWorker(game, BuildOptions(target=4, out=tmp_path / "c"))
    got = []
    w.cancelled.connect(lambda: got.append("cancelled"))
    w.stop()                    # cancel before the first progress point
    w.run()                     # synchronous
    assert got == ["cancelled"] and not (tmp_path / "c").exists()


def wait_attr(w, attr, timeout=60):
    app = QApplication.instance()
    t = time.time()
    while getattr(w, attr) is not None and time.time() - t < timeout:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()
    assert getattr(w, attr) is None, f"{attr} did not finish"


def test_memfix_tab_trial(win, tmp_path):
    from test_memfix import make
    g = make(tmp_path / "PPSA99999/eboot.bin").parent
    win.game_edit.setText(str(g))
    win._mf_scan()
    wait_attr(win, "mf_worker")
    assert win.mf_table.rowCount() == 1
    win.mf_table.selectRow(0)
    assert [win.mf_variant.itemText(k) for k in range(win.mf_variant.count())] == ["shrink", "retry-align"]
    win.mf_amount.setCurrentText("256M")
    win._mf_add()
    assert win.memfix_choices() == [f"{win.mf_sites[0].id}:shrink:256M"]
    win.target.setCurrentIndex(win.target.findData(4))
    win._analyze()
    wait(win)
    win.out_edit.setText(str(tmp_path / "out"))
    win._build()
    wait(win)
    rep = win.last_report
    assert rep.ok and rep.memfix_trial == 1 and (tmp_path / "out/memfix-recipe.json").is_file()
    assert win.mf_trials.count() == 1
    win._mf_result(True)
    assert "works" in win.mf_out.toPlainText()
    win.game_edit.setText(str(tmp_path))                     # another game: site list forgotten
    assert win.mf_table.rowCount() == 0 and not win.memfix_choices()


def test_output_follows_game(win, tmp_path):
    a, b = tmp_path / "PPSA00001", tmp_path / "PPSA00002"
    win.game_edit.setText(str(a))
    assert win.out_edit.text() == str(tmp_path / "PPSA00001-backport")
    win.out_edit.setText(str(tmp_path / "custom"))            # user's choice for this game stays
    win._invalidate()
    assert win.out_edit.text() == str(tmp_path / "custom")
    win.game_edit.setText(str(b))                              # another game: never reuse it
    assert win.out_edit.text() == str(tmp_path / "PPSA00002-backport")


def test_gui_target_list_console_fw_and_also(win, game, tmp_path):
    assert [win.target.itemData(i) for i in range(win.target.count())] == list(range(4, 14))
    win.target.setCurrentIndex(win.target.findData(4))
    win.console_fw.setText("11.60")
    assert not win.fw_warn.isHidden() and "black-screen" in win.fw_warn.text()
    win.console_fw.setText("5.00")
    assert win.fw_warn.isHidden()
    win.console_fw.setText("11.60")
    win.also_edit.setText("5,11")
    win.out_edit.setText(str(tmp_path / "gout"))
    o = win.build_options()
    assert o.console_fw == "11.60" and o.also_targets == [(5, 0), (11, 0)]
    win.also_edit.setText("zz")
    with pytest.raises(ValueError):
        win.build_options()
    win.also_edit.setText("5")
    win.mode.setCurrentIndex(win.mode.findData("inplace"))
    assert not win.also_edit.isEnabled() and win.build_options().also_targets == []


def test_console_tab_constructs(win):
    from PyQt6.QtWidgets import QApplication
    names = [win.tabs.tabText(i) for i in range(win.tabs.count())]
    assert "Console" in names
    win.con_ip.setText("10.0.0.5")
    win.con_ip.editingFinished.emit()
    assert win.settings.value("console/ip") == "10.0.0.5"
    assert win.con_stop_btn.isEnabled() is False and win.con_bridge is None
    win._con_crash("diag", "", "blk")                    # triage panel + handoff to the Crash log tab
    assert win.con_triage.toPlainText().startswith("diag") and win.klog_in.toPlainText() == "blk"
    for k in range(6000):
        win._con_line(f"l{k}")
    win._con_flush()
    QApplication.instance().processEvents()
    assert win.con_log.blockCount() <= win.LOG_LINES + 1


def test_console_diagnose_now_button(win):
    assert win.con_diag_btn.text() == "Diagnose now"
    KH = [ln for ln in open(os.path.join(os.path.dirname(__file__), "data/kh_savedata_loop.log")).read().splitlines()]
    for ln in KH * 2:
        win._con_line(ln)
    win.con_diag_btn.click()
    t = time.time()
    while win.con_diag_worker.isRunning() and time.time() - t < 20:
        QApplication.instance().processEvents()
        time.sleep(0.01)
    QApplication.instance().processEvents()
    txt = win.con_triage.toPlainText()
    assert "0x809f8032" in txt and "repeated 2x" in txt and win.con_diag_btn.isEnabled()
    win._con_loop("game looks stuck in a loop: x", "/tmp/loop-1.txt")
    assert "stuck" in win.con_triage.toPlainText()
