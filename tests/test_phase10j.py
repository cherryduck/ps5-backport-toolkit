"""Phase 10j: pro-disable never recommended, savedata-prepare recommended for FW4, 'Tick all
recommended' (GUI) / --recommended (CLI), Console tab control row below the dump row."""
import os

import pytest

from ps5bp.core.rules import Finding, pick_recommended, registry
from test_phase10cb import H, mkspec, prep, prep_game, statuses
from test_rules import PRO, game as _game, db as _db      # noqa: F401  (fixtures)

game = _game
db = _db

MODE2 = prep(H("55 4889e5 c745e4 02000000 488d75e0"))
MODE6 = prep(H("55 4889e5 c745e4 06000000 488d75e0"))


# ---- items 1, 2: recommendations ----------------------------------------------------------------------
def test_pro_disable_never_recommended(game, db):
    from ps5bp.core.pipeline import plan
    for target in (4, 5, 11):
        fs = [f for f in plan(game, target, db).findings if f.rule == "pro-disable"]
        assert fs and not any(f.recommended for f in fs)
    fs = [f for f in plan(game, 4, db).findings if f.rule == "pro-disable"]    # kits prove PRO absent on 4.xx
    assert any("Pro hardware query is absent on 4.xx; only matters on a console whose own firmware lacks it"
               in f.reason for f in fs)


@pytest.mark.parametrize("code,mode", [(MODE2, 2), (MODE6, 6)])
def test_savedata_prepare_recommended_by_declared_sdk(tmp_path, code, mode):
    g = prep_game(tmp_path / "g", code)
    for target in (4, 3):
        ((st, f),) = statuses(g, "savedata-prepare", target)
        assert st == "PATCH" and f.recommended and "KH HD 2.8" in f.reason and "community FW4" in f.reason
    for target in (5, 8, 11):
        ((st, f),) = statuses(g, "savedata-prepare", target)
        assert st == "PATCH" and not f.recommended


def test_savedata_prepare_unknown_and_done_not_recommended(tmp_path):
    g = prep_game(tmp_path / "u", prep(H("55 4889e5 c745e4 05000000 488d75e0")))
    ((st, f),) = statuses(g, "savedata-prepare")
    assert st == "UNKNOWN" and not f.recommended
    g = prep_game(tmp_path / "d", prep(H("55 4889e5 c745e4 00000000 488d75e0")))
    ((st, f),) = statuses(g, "savedata-prepare")
    assert st == "DONE" and not f.recommended


# ---- shared conflict policy -----------------------------------------------------------------------------
def test_pick_recommended_conflicts_first_in_registry_order():
    reg = list(registry())
    a, b = ("pssr-memory", "pro-disable") if reg.index("pssr-memory") < reg.index("pro-disable") else ("pro-disable", "pssr-memory")
    chosen, skipped = pick_recommended({a, b, "wwise-71"})
    assert a in chosen and b not in chosen and "wwise-71" in chosen and skipped == [(b, a)]
    assert pick_recommended({b}, taken={a}) == ([], [(b, a)])          # a hand-ticked rule counts as taken
    assert pick_recommended({"wwise-71"}, blocked={"wwise-71"}) == ([], [])
    assert "user-patch" not in pick_recommended({"user-patch"})[0]


# ---- item 3: CLI ------------------------------------------------------------------------------------------
def test_cli_recommended_dry_run(tmp_path, monkeypatch, capsys):
    from ps5bp.cli import main
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))
    g = prep_game(tmp_path / "g", MODE6)
    assert main(["build", str(g), "--target", "4", "--out", str(tmp_path / "o"), "--dry-run", "--force"]) == 0
    txt = capsys.readouterr().out
    assert "recommended: --rule savedata-prepare" in txt and "APPLIED" not in txt
    assert main(["build", str(g), "--target", "4", "--out", str(tmp_path / "o"), "--dry-run", "--force",
                 "--recommended"]) == 0
    txt = capsys.readouterr().out
    assert "--recommended: enabled savedata-prepare" in txt
    assert "APPLIED" in txt and "recommended: --rule savedata-prepare" not in txt
    assert not (tmp_path / "o").exists()
    # --no-rule wins over --recommended; target 8 has nothing recommended
    assert main(["build", str(g), "--target", "4", "--out", str(tmp_path / "o"), "--dry-run", "--force",
                 "--recommended", "--no-rule", "savedata-prepare"]) == 0
    assert "APPLIED" not in capsys.readouterr().out


def test_cli_recommended_builds_and_patches(tmp_path, monkeypatch, capsys):
    from ps5bp.cli import main
    from ps5bp.core.binary import Binary
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))
    g = prep_game(tmp_path / "g", MODE6)
    assert main(["build", str(g), "--target", "4", "--out", str(tmp_path / "o"), "--force", "--recommended"]) == 0
    assert Binary.load(tmp_path / "o/eboot.bin").read(0x100 + 4, 7) == H("c745e4 00000000")


def test_recommended_option_conflict_skipped(tmp_path, monkeypatch):
    from ps5bp.core import pipeline
    from ps5bp.core.evidence import EvidenceDB
    from ps5bp.core.rules.pro import ProDisable
    from ps5bp.core.rules.pssr_memory import PssrMemory
    import ps5bp.core.rules as R
    g = prep_game(tmp_path / "g", MODE6)
    orig = R.detect_all
    # pretend both conflicting rules are recommended; the first in registry order must win
    monkeypatch.setattr(R, "detect_all", lambda ctx: orig(ctx) + [Finding("pro-disable", "eboot.bin", "x", recommended=True),
                                                                  Finding("pssr-memory", "eboot.bin", "y", recommended=True)])
    monkeypatch.setattr(ProDisable, "apply", lambda self, ctx, f: None)
    monkeypatch.setattr(PssrMemory, "apply", lambda self, ctx, f: None)
    rep = pipeline.build(g, pipeline.BuildOptions(target=4, out=tmp_path / "o", dry_run=True, force=True,
                                                  recommended=True), EvidenceDB(tmp_path / "home"), log=lambda m: None)
    w = " | ".join(rep.warnings)
    assert "--recommended: enabled" in w and "not enabled: conflicts with" in w
    assert sum(1 for f in rep.findings if f["rule"] in ("pro-disable", "pssr-memory") and f["applied"]) == 1


# ---- items 3, 5: GUI ----------------------------------------------------------------------------------------
pytest.importorskip("PyQt6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PyQt6.QtWidgets import QApplication   # noqa: E402
from test_gui import wait                  # noqa: E402


@pytest.fixture
def win(tmp_path, monkeypatch, db):
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    app = QApplication.instance() or QApplication([])
    from ps5bp.gui.window import MainWindow
    w = MainWindow()
    w._headless = True
    yield w
    w.close()
    app.processEvents()


def F(rule, rec=True, ok=True):
    return Finding(rule, "eboot.bin", f"{rule} finding", applicable=ok, recommended=rec)


def ticked(win):
    return {n for n, b in win.rule_boxes.items() if b.isChecked()}


def test_tick_all_recommended_on_off(win):
    assert not win.rec_all.isChecked()
    win._fill_rules([F("wwise-71"), F("savedata-prepare"), F("set3-nonfatal", rec=False), F("tls-atexit", ok=False)])
    assert ticked(win) == set()
    win.rule_boxes["set3-nonfatal"].setChecked(True)               # manual tick on a non-★ row
    win.rec_all.setChecked(True)
    assert ticked(win) == {"wwise-71", "savedata-prepare", "set3-nonfatal"}
    assert not win.rule_boxes["tls-atexit"].isEnabled() and not win.rule_boxes["tls-atexit"].isChecked()
    win.rec_all.setChecked(False)
    assert ticked(win) == {"set3-nonfatal"}                         # only the ★ rows were unticked
    assert win.selected_rules() == {"set3-nonfatal"}


def test_tick_all_recommended_remembered_and_after_analyze(win, tmp_path):
    win.rec_all.setChecked(True)
    assert win.settings.value("rules/auto_recommended") in (True, "true")
    win._fill_rules([F("wwise-71")])
    assert ticked(win) == {"wwise-71"}                              # new analyze ticks the ★ rows
    win._fill_rules([F("wwise-71", rec=False), F("savedata-prepare")])
    assert ticked(win) == {"wwise-71", "savedata-prepare"}          # earlier ticks survive a re-analyze (as before)
    win.rec_all.setChecked(False)
    assert win.settings.value("rules/auto_recommended") in (False, "false")
    # a fresh window reads the remembered state
    from ps5bp.gui.window import MainWindow
    w2 = MainWindow()
    assert not w2.rec_all.isChecked()
    win.rec_all.setChecked(True)
    w3 = MainWindow()
    assert w3.rec_all.isChecked()
    w2.close(); w3.close()


def test_manual_untick_keeps_master_on(win):
    win.rec_all.setChecked(True)
    win._fill_rules([F("wwise-71"), F("savedata-prepare")])
    win.rule_boxes["wwise-71"].setChecked(False)
    assert win.rec_all.isChecked() and ticked(win) == {"savedata-prepare"}      # not fought
    win.rec_all.setChecked(False)
    win.rec_all.setChecked(True)                                                   # toggling re-ticks
    assert ticked(win) == {"wwise-71", "savedata-prepare"}


def test_tick_all_conflict_first_wins_and_says(win):
    reg = list(registry())
    a, b = ("pssr-memory", "pro-disable") if reg.index("pssr-memory") < reg.index("pro-disable") else ("pro-disable", "pssr-memory")
    msgs = []
    win.say = msgs.append
    win.rec_all.setChecked(True)
    win._fill_rules([F(a), F(b), F("wwise-71")])
    assert ticked(win) == {a, "wwise-71"}
    assert any(b in m and a in m and "conflict" in m for m in msgs)


def test_tick_all_after_real_analyze(win, tmp_path):
    g = prep_game(tmp_path / "g", MODE6)
    win.rec_all.setChecked(True)
    win.game_edit.setText(str(g))
    win.target.setCurrentIndex(win.target.findData(4))
    win._analyze()
    wait(win)
    assert win.rule_boxes["savedata-prepare"].isChecked()
    assert "savedata-prepare" in win.selected_rules()
    assert "★ savedata-prepare" in win.rule_table.item(list(win.rule_boxes).index("savedata-prepare"), 1).text()


def test_console_start_row_after_dump_row(win):
    lay = win.con_start_btn.parentWidget().layout()
    def index_of(widget):
        for i in range(lay.count()):
            it = lay.itemAt(i)
            sub = it.layout()
            if sub is not None and any(sub.itemAt(j).widget() is widget for j in range(sub.count())):
                return i
        raise AssertionError(f"{widget} not in a row")
    ip, dump, start = index_of(win.con_ip), index_of(win.con_dump_on), index_of(win.con_start_btn)
    assert ip == 0 and ip < dump < start
    assert index_of(win.con_stop_btn) == index_of(win.con_status) == start
    assert start > index_of(win.con_game)
    assert start < lay.count() - 1                                   # the log view follows
    assert win.con_start_btn.isEnabled() and not win.con_stop_btn.isEnabled() and win.con_status.text() == "idle"
