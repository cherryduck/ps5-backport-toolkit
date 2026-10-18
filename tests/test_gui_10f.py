"""Phase 10f: GUI parity (seeds, replace-dump pickers, undo, learn/reindex, kit columns, build-done text)."""
import os
import shutil
import time

import pytest

pytest.importorskip("PyQt6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QInputDialog   # noqa: E402

from ps5bp.core.evidence import EvidenceDB               # noqa: E402
from ps5bp.core.pipeline import BuildOptions, build      # noqa: E402
from ps5bp.core.rules.contracts import load as load_contracts   # noqa: E402
from synth import Spec, build_elf, build_self            # noqa: E402
from test_gui import wait                                # noqa: E402,F401
from test_rules import db as _db, game as _game          # noqa: E402,F401

db = _db
game = _game
MARK = b"/app0/k9.psp"


def put(path, spec):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_self(build_elf(spec)[0]))


def lib(mod, nids, strings=b""):
    return Spec(kind="module", module=mod, export_libs=[mod], exports=[(n, 0) for n in nids],
                import_libs=["libkernel"], imports=[], strings=strings)


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


def spin(cond, timeout=20):
    app = QApplication.instance()
    t = time.time()
    while not cond() and time.time() - t < timeout:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()
    assert cond(), "timed out"


def add_kit(tmp_path, name, files, fw=4, extra=None):
    k = tmp_path / ("src-" + name)
    put(k / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("KKKKKKKKKK1", 0)]))
    for rel, spec in files.items():
        put(k / rel, spec)
    for rel, data in (extra or {}).items():
        (k / rel).parent.mkdir(parents=True, exist_ok=True)
        (k / rel).write_bytes(data)
    d = EvidenceDB(tmp_path / "home")
    try:
        d.add_kit(k, fw, name)
    finally:
        d.close()


# ---- 1. seeds ------------------------------------------------------------------------------
def test_seeds_and_plt_fallback(win, tmp_path):
    manual = [c for c in load_contracts().values() if c.gate == "manual"]
    assert manual and all(c.nid in win.seeds_edit.toolTip() for c in manual)
    win.out_edit.setText(str(tmp_path / "o"))
    o = win.build_options()
    assert o.seeds == [] and o.seed_plt_fallback is False
    nid = manual[0].nid
    win.seeds_edit.setText(f"{nid}, {nid} ")
    win.seed_plt.setChecked(True)
    o = win.build_options()
    assert o.seeds == [nid] and o.seed_plt_fallback is True
    win.seeds_edit.setText(f"{nid},BOGUS")
    assert "BOGUS" in win.seeds_edit.toolTip() and "#fdd" in win.seeds_edit.styleSheet()
    with pytest.raises(ValueError, match="BOGUS"):
        win.build_options()


def test_seeds_reach_the_build(win, game, tmp_path):
    nid = next(c.nid for c in load_contracts().values() if c.gate == "manual")
    win.game_edit.setText(str(game))
    win.target.setCurrentIndex(win.target.findData(4))
    win._analyze()
    wait(win)
    win.out_edit.setText(str(tmp_path / "out"))
    win.seeds_edit.setText(nid)
    win._build()
    wait(win)
    rep = win.last_report
    assert rep.ok and any("--seed " + nid in w for w in rep.warnings)      # compat-stubs ran: game doesn't import it


# ---- 2. replace-dump pickers -------------------------------------------------------------------
def test_replace_pickers(win, game, tmp_path, monkeypatch):
    items = lambda cb: [cb.itemText(i) for i in range(cb.count())]          # noqa: E731
    assert items(win.replace_ampr) == ["keep dump's", "auto (best kit)"] and win.replace_dump() == {}
    add_kit(tmp_path, "ap1", {"fakelib/libSceAmpr.sprx": lib("libSceAmpr", ["AAAAAAAAAA1"]),
                              "fakelib/libScePlayGo.sprx": lib("libScePlayGo", ["PPPPPPPPPP1"])})
    add_kit(tmp_path, "ap2", {"fakelib/libSceAmpr.sprx": lib("libSceAmpr", ["AAAAAAAAAA1"])})
    win._refresh_kits()
    assert items(win.replace_ampr) == ["keep dump's", "auto (best kit)", "ap1", "ap2"]
    assert items(win.replace_playgo) == ["keep dump's", "auto (best kit)", "ap1"]
    win.replace_ampr.setCurrentIndex(1)
    win.replace_playgo.setCurrentIndex(win.replace_playgo.findText("ap1"))
    assert win.replace_dump() == {"libSceAmpr": None, "libScePlayGo": "ap1"}
    win.replace_ampr.setCurrentIndex(win.replace_ampr.findText("ap2"))
    assert win.replace_dump() == {"libSceAmpr": "ap2", "libScePlayGo": "ap1"}
    win.out_edit.setText(str(tmp_path / "o"))
    assert win.build_options().replace_dump == win.replace_dump()
    # selection survives a refresh; removing the chosen kit falls back to keep and drops the plan
    win._refresh_kits()
    assert win.replace_dump() == {"libSceAmpr": "ap2", "libScePlayGo": "ap1"}
    d = EvidenceDB(tmp_path / "home")
    d.remove_kit("ap2")
    d.close()
    win._refresh_kits()
    assert win.replace_dump() == {"libScePlayGo": "ap1"}
    # Analyze receives it too
    seen = {}
    import ps5bp.gui.workers as W
    real = W.plan
    monkeypatch.setattr(W, "plan", lambda *a, **k: (seen.update(k), real(*a, **k))[1])
    win.game_edit.setText(str(game))
    win._analyze()
    wait(win)
    assert seen["replace_dump"] == {"libScePlayGo": "ap1"}
    # changing a picker invalidates the plan
    assert win.plan is not None
    win.replace_playgo.setCurrentIndex(0)
    assert win.plan is None


# ---- 3. undo -----------------------------------------------------------------------------------
def applied_backport(win, game, tmp_path):
    win.game_edit.setText(str(game))
    before = {p.relative_to(game).as_posix(): p.read_bytes() for p in game.rglob("*") if p.is_file()}
    out = tmp_path / "out"
    build(game, BuildOptions(target=4, out=out), EvidenceDB(tmp_path / "home"), log=lambda m: None)
    shutil.copytree(out, game, dirs_exist_ok=True, ignore=shutil.ignore_patterns("backport-report.*"))
    return out, before


def test_undo_dialog_flow(win, game, tmp_path):
    out, before = applied_backport(win, game, tmp_path)
    d = win._undo()
    assert d.game_edit.text() == str(game) and not d.apply_btn.isEnabled()
    d._preview()                                              # no outputs yet
    assert "at least one" in d.last_error
    d.out_list.addItem(str(out))
    d._preview()
    spin(lambda: d.worker is None)
    assert d.plan is not None and "edit(s) to reverse" in d.out.toPlainText() and d.apply_btn.isEnabled()
    assert d.last_error == ""
    d.force.setChecked(True)                                  # changing inputs invalidates the preview
    assert d.plan is None and not d.apply_btn.isEnabled() and not d.force_warn.isHidden()
    d.force.setChecked(False)
    d._preview()
    spin(lambda: d.worker is None)
    d._apply()
    assert d.worker is not None                               # off the GUI thread
    spin(lambda: d.worker is None)
    assert d.result == "done" and d.applied
    assert {p.relative_to(game).as_posix(): p.read_bytes() for p in game.rglob("*") if p.is_file()
            if p.relative_to(game).as_posix() in before} == before


def test_undo_dialog_refusal_and_force(win, game, tmp_path):
    out, _ = applied_backport(win, game, tmp_path)
    eb = game / "eboot.bin"
    raw = bytearray(eb.read_bytes())
    raw[-1] ^= 0xFF
    eb.write_bytes(raw)                                       # modified after the overlay
    d = win._undo()
    d.out_list.addItem(str(out))
    d._preview()
    spin(lambda: d.worker is None)
    assert d.plan is None and "eboot.bin" in d.last_error and not d.apply_btn.isEnabled()
    d.force.setChecked(True)
    d._preview()
    spin(lambda: d.worker is None)
    assert d.plan is not None and d.last_error == "" and "--force" in d.out.toPlainText()


# ---- 4. kits tab ---------------------------------------------------------------------------------
def test_kit_columns_and_reindex(win, tmp_path):
    psml = lib("libScePsml", ["PSMLNID0001"], strings=b"\0" + MARK + b"\0")
    libc = Spec(kind="module", module="libc", export_libs=["libc"], exports=[("CCCCCCCCCC1", 0)],
                import_libs=["libkernel"], imports=[])
    add_kit(tmp_path, "ovl", {"fakelib/libScePsml.sprx": psml}, extra={"k9.psp": b"MODEL" * 10})
    add_kit(tmp_path, "withlibc", {"sce_module/libc.prx": libc, "fakelib/libSceFoo.sprx": lib("libSceFoo", ["FFFFFFFFFF1"])})
    win._refresh_kits()
    hdr = [win.kit_table.horizontalHeaderItem(c).text() for c in range(win.kit_table.columnCount())]
    assert "PSML overlay" in hdr and "libc" in hdr
    row = {win.kit_table.item(r, 0).text(): r for r in range(win.kit_table.rowCount())}
    po, lc = hdr.index("PSML overlay"), hdr.index("libc")
    assert win.kit_table.item(row["ovl"], po).text() == "yes" and win.kit_table.item(row["kit"], po).text() == "—"
    ident = win.kit_table.item(row["withlibc"], lc).text()
    assert ident != "—" and len(ident) == 12 and win.kit_table.item(row["kit"], lc).text() == "—"
    # wipe the records, Reindex libc brings them back (worker thread)
    d = EvidenceDB(tmp_path / "home")
    d.db.execute("DELETE FROM libcs")
    d.db.commit()
    d.close()
    win._refresh_kits()
    assert win.kit_table.item(row["withlibc"], lc).text() == "—"
    win._reindex_kits()
    assert win.kit_worker is not None
    spin(lambda: win.kit_worker is None)
    assert win.kit_table.item(row["withlibc"], lc).text() == ident
    assert "libc reindex" in win.log.toPlainText()


def test_add_kit_passes_tested_fw(win, tmp_path, monkeypatch):
    k = tmp_path / "src-new"
    put(k / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("KKKKKKKKKK1", 0)]))
    put(k / "fakelib/libSceFoo.sprx", lib("libSceFoo", ["FFFFFFFFFF1"]))
    from PyQt6.QtWidgets import QFileDialog
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k_: str(k))
    ints = iter([(5, True), (4, True)])                        # kit FW 5, tested on 4
    monkeypatch.setattr(QInputDialog, "getInt", lambda *a, **k_: next(ints))
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k_: ("newkit", True))
    win._add_kit(False)
    spin(lambda: win.kit_worker is None)
    d = EvidenceDB(tmp_path / "home")
    try:
        kit = d.kit("newkit")
    finally:
        d.close()
    assert kit is not None and kit.fw == 5 and kit.tested_fw == 4


def test_learn_dialog(win, game, db, tmp_path):
    out = tmp_path / "out"
    build(game, BuildOptions(target=4, out=out), db, log=lambda m: None)
    d = win._learn_dialog()
    d._run()
    assert "Choose" in d.last_error
    d.orig_edit.setText(str(game))
    d.kit_edit.setText(str(out))
    d._run()
    assert d.worker is not None
    spin(lambda: d.worker is None)
    assert d.last_error == "" and "changed bytes by kind" in d.report.toPlainText()
    from ps5bp.core.learn import learn_report
    assert d.report.toPlainText() == "\n".join(learn_report(game, out))
    # recipes: same switch as --recipe
    d.recipe.setChecked(True)
    d.out_edit.setText(str(tmp_path / "recipes"))
    d._run()
    spin(lambda: d.worker is None)
    assert d.last_error == ""


# ---- 5. build-done text ---------------------------------------------------------------------------
def test_built_text_siblings_libc_console(win, game, tmp_path):
    win.game_edit.setText(str(game))
    win.target.setCurrentIndex(win.target.findData(4))
    win.console_fw.setText("11.60")
    win.also_edit.setText("5")
    win._analyze()
    wait(win)
    win.out_edit.setText(str(tmp_path / "out"))
    win._build()
    wait(win)
    rep = win.last_report
    txt = win.last_box.text()
    assert rep.siblings and rep.siblings[0]["out"] in txt and "Sibling outputs" in txt
    assert rep.console_warning and "⚠ " + rep.console_warning in txt
    assert "libc cross-check" not in txt                       # synthetic game has no libc


def test_libc_line_variants(win):
    f = win.libc_line
    assert f({}) == ""
    assert "no kit has a recorded libc" in f({"kits_with_libc": 0})
    assert "no kit libc of this build" in f({"kits_with_libc": 3, "same_identity": 0, "identical": 0})
    assert "matches 2 kit libc" in f({"kits_with_libc": 3, "same_identity": 2, "identical": 2})
    assert "matches 1 of 2" in f({"kits_with_libc": 3, "same_identity": 2, "identical": 1})
    assert "differs from 2" in f({"kits_with_libc": 3, "same_identity": 2, "identical": 0})
