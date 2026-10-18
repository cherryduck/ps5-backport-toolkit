"""Main window: game -> analyze -> choose rules -> build."""
from __future__ import annotations

import os
import subprocess
import sys
from collections import deque
from pathlib import Path

from PyQt6.QtCore import QSettings, QTimer, Qt, QUrl, pyqtSlot
from PyQt6.QtGui import QBrush, QColor, QDesktopServices, QFont
from PyQt6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QHBoxLayout,
                             QHeaderView, QInputDialog, QLabel, QLineEdit, QListWidget, QMainWindow,
                             QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSplitter,
                             QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from .. import __version__
from ..core import sdk
from ..core.evidence import EvidenceDB, home
from ..core.pipeline import MODES, BuildOptions
from ..core.rules import pick_recommended, registry
from ..core.rules.contracts import load as load_contracts
from .dialogs import LearnDialog, UndoDialog
from .workers import AnalyzeWorker, BuildWorker, ConsoleBridge, FuncWorker, KitWorker

STATUS_COLOR = {"game": "#5a9", "system": "#5a9", "fakelib": "#49c", "partial": "#c93",
                "unverified": "#888", "absent": "#d55", "missing": "#d55", "stubbed": "#c93", "dump": "#49c"}
REPLACEABLE = ("libSceAmpr", "libScePlayGo")
STAGES = {"scan": "Scanning", "binaries": "Patching", "copy": "Copying game", "write": "Writing"}


def table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setAlternatingRowColors(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    t.horizontalHeader().setStretchLastSection(True)
    return t


def fill(t: QTableWidget, rows: list[list], colors: dict[int, str] | None = None) -> None:
    t.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, v in enumerate(row):
            it = QTableWidgetItem("" if v is None else str(v))
            if colors and r in colors:
                it.setForeground(QBrush(QColor(colors[r])))
            t.setItem(r, c, it)


def host_env() -> dict[str, str]:
    """The environment for launching the user's own programs from the bundled app.

    A PyInstaller bundle puts its _internal folder first in LD_LIBRARY_PATH (keeping the user's
    value as LD_LIBRARY_PATH_ORIG). Programs started from it (xdg-open -> Dolphin, Nautilus, ...)
    would then load the bundle's older Qt and die at once, so restore the original value."""
    env = dict(os.environ)
    if getattr(sys, "frozen", False):
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)
    return env


def open_folder(path: str | Path) -> bool:
    """Show `path` in the system file manager. Returns False if nothing could be started."""
    path = str(path)
    if sys.platform.startswith("linux"):
        try:
            subprocess.Popen(["xdg-open", path], env=host_env(), start_new_session=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except OSError:
            pass                                    # no xdg-open: let Qt try
    return QDesktopServices.openUrl(QUrl.fromLocalFile(path))


def settings_store() -> QSettings:
    """Saved GUI state. Linux: ~/.config/ps5bp/ps5bp.conf (native). Windows: an INI file in
    %APPDATA%\\ps5bp rather than the registry, so it is a plain file (and tests can redirect it)."""
    if os.name == "nt":
        return QSettings(QSettings.Format.IniFormat, QSettings.Scope.UserScope, "ps5bp", "ps5bp")
    return QSettings("ps5bp", "ps5bp")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"PS5 Backport Toolkit {__version__}")
        self.resize(1100, 760)
        self.settings = settings_store()
        self.plan = None
        self.worker = None                     # current AnalyzeWorker / BuildWorker
        self.kit_worker = None
        self.patches: list[Path] = []
        self.rule_boxes: dict[str, QCheckBox] = {}
        self.mf_sites: list = []
        self.mf_worker = None

        root = QWidget()
        v = QVBoxLayout(root)

        # --- game + target ---------------------------------------------------------------
        row = QHBoxLayout()
        row.addWidget(QLabel("Game folder:"))
        self.game_edit = QLineEdit(self.settings.value("game", ""))
        self.game_edit.setPlaceholderText("decrypted game dump (contains eboot.bin, sce_sys/, sce_module/)")
        self._out_game = self.game_edit.text().strip()     # game the output folder was chosen for
        self.game_edit.textChanged.connect(self._game_changed)
        self.game_edit.textChanged.connect(self._invalidate)
        self.game_edit.textChanged.connect(self._mf_clear)
        row.addWidget(self.game_edit, 1)
        b = QPushButton("Browse…")
        b.clicked.connect(self._browse_game)
        row.addWidget(b)
        row.addWidget(QLabel("Target FW:"))
        self.target = QComboBox()
        for t in sdk.SUPPORTED_TARGETS:
            self.target.addItem(f"{t}.xx", t)
        self.target.setCurrentIndex(max(0, self.target.findData(int(self.settings.value("target", 4)))))
        self.target.currentIndexChanged.connect(self._invalidate)
        row.addWidget(self.target)
        row.addWidget(QLabel("Console FW:"))
        self.console_fw = QLineEdit(str(self.settings.value("console_fw", "")))
        self.console_fw.setPlaceholderText("e.g. 11.60")
        self.console_fw.setMaximumWidth(80)
        self.console_fw.setToolTip("Firmware of the console you run on (--console-fw). Advice only: warns when "
                                   "the target SDK is 2+ majors below it.")
        self.console_fw.textChanged.connect(self._fw_changed)
        self.target.currentIndexChanged.connect(self._fw_changed)
        row.addWidget(self.console_fw)
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self._analyze)
        row.addWidget(self.analyze_btn)
        v.addLayout(row)

        self.info = QLabel("Pick a game folder and press Analyze.")
        self.info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        f = self.info.font()
        f.setBold(True)
        self.info.setFont(f)
        v.addWidget(self.info)
        self.fw_warn = QLabel()
        self.fw_warn.setWordWrap(True)
        self.fw_warn.setStyleSheet("color: #b36b00")
        self.fw_warn.hide()
        v.addWidget(self.fw_warn)

        # --- tabs --------------------------------------------------------------------------
        self.tabs = QTabWidget()
        # overview
        ov = QSplitter(Qt.Orientation.Vertical)
        self.bin_table = table(["File", "Role", "SDK", "Imports", "Exports", "Flags", "Problem"])
        ov.addWidget(self.bin_table)
        self.warn_list = QListWidget()
        ov.addWidget(self.warn_list)
        ov.setSizes([400, 160])
        self.tabs.addTab(ov, "Overview")
        # imports
        self.cov_table = table(["Module", "Status", "Needed", "Proven", "Fakelib", "Notes"])
        self.tabs.addTab(self.cov_table, "Imports")
        # rules
        rw = QWidget()
        rv = QVBoxLayout(rw)
        rv.addWidget(QLabel("Fix rules are off unless ticked. Rows marked ★ are recommended for this game."))
        self.rec_all = QCheckBox("Tick all recommended (★)")
        self.rec_all.setToolTip("Ticks every ★ row (the first one wins if two conflict) and keeps doing so after each\n"
                                "Analyze. Unticking it unticks the ★ rows only; rows you ticked yourself stay.")
        self.rec_all.setChecked(self.settings.value("rules/auto_recommended", "false") in (True, "true"))
        self.rec_all.toggled.connect(self._rec_all_toggled)
        rv.addWidget(self.rec_all)
        self.rec_rules: list[str] = []                     # ★ rows (usable + recommended) of the last analyze
        self.rule_table = table(["", "Rule", "Findings", "What it does"])
        self.rule_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        rv.addWidget(self.rule_table, 1)
        pr = QHBoxLayout()
        pr.addWidget(QLabel("Patch files:"))
        self.patch_list = QListWidget()
        self.patch_list.setMaximumHeight(70)
        pr.addWidget(self.patch_list, 1)
        pb = QVBoxLayout()
        b = QPushButton("Add…")
        b.clicked.connect(self._add_patch)
        pb.addWidget(b)
        b = QPushButton("Remove")
        b.clicked.connect(self._remove_patch)
        pb.addWidget(b)
        pr.addLayout(pb)
        rv.addLayout(pr)
        sr = QHBoxLayout()
        sr.addWidget(QLabel("Seeds:"))
        self.seeds_edit = QLineEdit()
        self.seeds_edit.setPlaceholderText("contract NIDs, comma-separated (compat-stubs is switched on for you)")
        manual = [f"  {c.nid}  {c.label()}" for c in load_contracts().values() if c.gate == "manual"]
        self._seeds_tip = (
            "--seed: force a GOT stub contract for these NIDs even where the game's firmware has them or the "
            "gate would refuse. Only NIDs in the contract table are accepted.\n"
            "Manual-only contracts (applied only when seeded here):\n" + ("\n".join(manual) or "  (none)"))
        self.seeds_edit.setToolTip(self._seeds_tip)
        self.seeds_edit.textChanged.connect(self._seeds_changed)
        sr.addWidget(self.seeds_edit, 1)
        self.seed_plt = QCheckBox("PLT fallback")
        self.seed_plt.setToolTip("--seed-plt-fallback: where a GOT seed is refused, overwrite the PLT entry "
                                 "instead (never silent)")
        sr.addWidget(self.seed_plt)
        rv.addLayout(sr)
        self.tabs.addTab(rw, "Fix rules")
        self._fill_rules()
        # kits
        kw = QWidget()
        kv = QVBoxLayout(kw)
        self.kit_label = QLabel()
        kv.addWidget(self.kit_label)
        self.kit_table = table(["Name", "FW", "Title", "Files", "PSML overlay", "libc", "Source", "Added"])
        kv.addWidget(self.kit_table, 1)
        kr = QHBoxLayout()
        for text, slot in (("Add kit folder…", lambda: self._add_kit(False)),
                           ("Add kit zip…", lambda: self._add_kit(True)), ("Remove", self._remove_kit),
                           ("Learn from kit…", self._learn_dialog), ("Reindex libc", self._reindex_kits)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            kr.addWidget(b)
        kr.addStretch(1)
        kv.addLayout(kr)
        self.tabs.addTab(kw, "Kits")
        # crash log
        cw = QWidget()
        cv = QVBoxLayout(cw)
        cr = QHBoxLayout()
        cr.addWidget(QLabel("Paste a klog captured while the game crashed, or load a file. "
                            "The game folder above is used to resolve the backtrace."))
        cr.addStretch(1)
        b = QPushButton("Load file…")
        b.clicked.connect(self._load_klog)
        cr.addWidget(b)
        b = QPushButton("Triage")
        b.clicked.connect(self._triage)
        cr.addWidget(b)
        cv.addLayout(cr)
        cs = QSplitter(Qt.Orientation.Vertical)
        self.klog_in = QPlainTextEdit()
        self.klog_in.setPlaceholderText("klog text…")
        self.klog_in.setFont(QFont("monospace"))
        cs.addWidget(self.klog_in)
        self.klog_out = QPlainTextEdit()
        self.klog_out.setReadOnly(True)
        self.klog_out.setFont(QFont("monospace"))
        cs.addWidget(self.klog_out)
        cs.setSizes([200, 400])
        cv.addWidget(cs, 1)
        self.tabs.addTab(cw, "Crash log")
        # memory fix
        mw = QWidget()
        mv = QVBoxLayout(mw)
        mr = QHBoxLayout()
        mr.addWidget(QLabel("For games that exit on a failed startup allocation. A crash log in the "
                            "Crash log tab ranks the failing site first."))
        mr.addStretch(1)
        self.mf_scan_btn = QPushButton("Find allocation sites")
        self.mf_scan_btn.clicked.connect(self._mf_scan)
        mr.addWidget(self.mf_scan_btn)
        mv.addLayout(mr)
        self.mf_table = table(["#", "site", "API", "function", "flags", "length", "shrink", "fixes"])
        self.mf_table.itemSelectionChanged.connect(self._mf_selected)
        mv.addWidget(self.mf_table, 1)
        ar = QHBoxLayout()
        ar.addWidget(QLabel("Fix:"))
        self.mf_variant = QComboBox()
        ar.addWidget(self.mf_variant)
        self.mf_amount = QComboBox()
        for a in ("128M", "256M", "512M"):
            self.mf_amount.addItem(a)
        ar.addWidget(QLabel("cut:"))
        ar.addWidget(self.mf_amount)
        b = QPushButton("Add to build")
        b.clicked.connect(self._mf_add)
        ar.addWidget(b)
        b = QPushButton("Remove")
        b.clicked.connect(self._mf_remove)
        ar.addWidget(b)
        ar.addStretch(1)
        mv.addLayout(ar)
        self.mf_list = QListWidget()
        self.mf_list.setMaximumHeight(80)
        mv.addWidget(QLabel("Applied by the next Build backport and recorded as a trial:"))
        mv.addWidget(self.mf_list)
        tr = QHBoxLayout()
        tr.addWidget(QLabel("Trials:"))
        self.mf_trials = QComboBox()
        tr.addWidget(self.mf_trials, 1)
        b = QPushButton("It boots")
        b.clicked.connect(lambda: self._mf_result(True))
        tr.addWidget(b)
        b = QPushButton("It crashed (uses the Crash log text)")
        b.clicked.connect(lambda: self._mf_result(False))
        tr.addWidget(b)
        mv.addLayout(tr)
        self.mf_out = QPlainTextEdit()
        self.mf_out.setReadOnly(True)
        self.mf_out.setFont(QFont("monospace"))
        self.mf_out.setMaximumHeight(150)
        mv.addWidget(self.mf_out)
        self.tabs.addTab(mw, "Memory fix")
        self._build_console_tab()
        # log
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("monospace"))
        self.tabs.addTab(self.log, "Log")
        v.addWidget(self.tabs, 1)

        # --- output + build --------------------------------------------------------------
        row = QHBoxLayout()
        row.addWidget(QLabel("Output:"))
        self.mode = QComboBox()
        for m, label in zip(MODES, ("overlay (changed files + fakelib/)", "full copy (reflink)",
                                    "in place (keeps .orig)")):
            self.mode.addItem(label, m)
        self.mode.setCurrentIndex(max(0, self.mode.findData(self.settings.value("mode", "overlay"))))
        self.mode.currentIndexChanged.connect(self._mode_changed)
        row.addWidget(self.mode)
        self.out_edit = QLineEdit(self.settings.value("out", ""))
        self.out_edit.setPlaceholderText("empty or new folder")
        row.addWidget(self.out_edit, 1)
        self.out_btn = QPushButton("Browse…")
        self.out_btn.clicked.connect(self._browse_out)
        row.addWidget(self.out_btn)
        self.force = QCheckBox("Rebuild existing backport")
        self.force.setToolTip("Accept a game folder whose eboot is already at/below the target SDK, or that already contains files an earlier ps5bp build wrote (--force)")
        row.addWidget(self.force)
        v.addLayout(row)
        row = QHBoxLayout()
        row.addWidget(QLabel("Also build for:"))
        self.also_edit = QLineEdit(str(self.settings.value("also_target", "")))
        self.also_edit.setPlaceholderText("e.g. 5,11 — SDK-only siblings <out>-fwN (higher than the target)")
        self.also_edit.setToolTip("--also-target: after the main build, write copies that differ only in the "
                                  "SDK fields and param.json versions. Not available for in-place builds.")
        self.also_edit.setEnabled(self.mode.currentData() != "inplace")
        row.addWidget(self.also_edit, 1)
        v.addLayout(row)
        row = QHBoxLayout()
        row.addWidget(QLabel("Dump's fakelibs:"))
        self.replace_boxes: dict[str, QComboBox] = {}
        for mod in REPLACEABLE:
            row.addWidget(QLabel(f"{mod}:"))
            cb = QComboBox()
            cb.setToolTip(f"What to do with the {mod} the dump ships (--replace-dump-fakelib): keep it, let "
                          "the build pick the best kit's, or use one named kit's. ampr_emu.index is never "
                          "deleted; see the AMPR index box. Every launch starts on keep.")
            cb.currentIndexChanged.connect(self._invalidate)
            self.replace_boxes[mod] = cb
            row.addWidget(cb, 1)
        self.replace_ampr, self.replace_playgo = self.replace_boxes["libSceAmpr"], self.replace_boxes["libScePlayGo"]
        row.addWidget(QLabel("AMPR index:"))
        self.ampr_index = QComboBox()
        for label, key in (("auto", "auto"), ("regenerate", "regen"), ("keep", "keep")):
            self.ampr_index.addItem(label, key)
        self.ampr_index.setCurrentIndex(max(0, self.ampr_index.findData(str(self.settings.value("ampr_index", "auto")))))
        self.ampr_index.setToolTip("ampr_emu.index of a game that carries the Ampr emulator (--ampr-index). auto: write "
                                   "one if the game has none, refresh a stale one (unless asset packs depend on it); "
                                   "regenerate: always rewrite it; keep: never touch it, only report staleness. The "
                                   "game's own index is saved with the other originals, so Undo restores it.")
        self.ampr_index.currentIndexChanged.connect(
            lambda _=0: self.settings.setValue("ampr_index", self.ampr_index.currentData()))
        row.addWidget(self.ampr_index)
        v.addLayout(row)
        row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setFormat("")
        row.addWidget(self.progress, 1)
        self.build_btn = QPushButton("Build backport")
        self.build_btn.setEnabled(False)
        self.build_btn.clicked.connect(self._build)
        row.addWidget(self.build_btn)
        self.undo_btn = QPushButton("Undo applied backport…")
        self.undo_btn.setToolTip("Put a game folder back after a backport was copied over it (ps5bp undo)")
        self.undo_btn.clicked.connect(self._undo)
        row.addWidget(self.undo_btn)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel)
        row.addWidget(self.cancel_btn)
        v.addLayout(row)

        self.setCentralWidget(root)
        self._mode_changed()
        self._refresh_kits()

    # ---- helpers ------------------------------------------------------------------------
    def say(self, msg: str) -> None:
        self.log.appendPlainText(msg)
        self.statusBar().showMessage(msg.splitlines()[0] if msg else "", 8000)

    def busy(self, on: bool) -> None:
        self.analyze_btn.setEnabled(not on)
        self.build_btn.setEnabled(not on and self.plan is not None)
        self.cancel_btn.setEnabled(on)
        if not on:
            self.progress.setRange(0, 100)
            self.progress.setValue(0)
            self.progress.setFormat("")

    @pyqtSlot(str, int, int)
    def _progress(self, stage: str, i: int, n: int) -> None:
        self.progress.setRange(0, max(n, 1))
        self.progress.setValue(i)
        self.progress.setFormat(f"{STAGES.get(stage, stage)} {i}/{n}")

    def _release(self, attr: str = "worker") -> None:
        w = getattr(self, attr)
        setattr(self, attr, None)
        if w is not None:
            w.deleteLater()

    def _fw_changed(self, *_) -> None:
        w = sdk.console_warning(self.target.currentData(), 0, self.console_fw.text()) \
            if self._console_fw_ok() else None
        self.fw_warn.setText("⚠ " + w if w else "")
        self.fw_warn.setVisible(bool(w))

    def _console_fw_ok(self) -> bool:
        t = self.console_fw.text().strip()
        try:
            return bool(t) and sdk.fw_major_of_str(t) >= 0
        except ValueError:
            return False

    def _invalidate(self, *_) -> None:
        self.plan = None
        self.build_btn.setEnabled(False)

    def _mode_changed(self, *_) -> None:
        inplace = self.mode.currentData() == "inplace"
        self.out_edit.setEnabled(not inplace)
        self.out_btn.setEnabled(not inplace)
        if hasattr(self, "also_edit"):
            self.also_edit.setEnabled(not inplace)          # siblings are separate outputs

    def _browse_game(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Game folder", self.game_edit.text())
        if d:
            self.game_edit.setText(d)

    @staticmethod
    def default_out(game: str) -> str:
        g = Path(game.strip()).expanduser()
        return str(g.parent / f"{g.name}-backport") if game.strip() else ""

    def _game_changed(self, text: str) -> None:
        # the output folder belongs to one game: a different game gets its own default,
        # so one game's backport can never be built over another's
        if text.strip() != self._out_game:
            self._out_game = text.strip()
            self.out_edit.setText(self.default_out(text))

    def _browse_out(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Output folder", self.out_edit.text())
        if d:
            self.out_edit.setText(d)

    # ---- rules ----------------------------------------------------------------------------
    def _fill_rules(self, findings=None) -> None:
        by: dict[str, list] = {}
        for f in findings or []:
            by.setdefault(f.rule, []).append(f)
        reg = registry()
        checked = {n for n, b in self.rule_boxes.items() if b.isChecked()}
        self.rule_boxes = {}
        self.rec_rules = []
        self.rule_table.setRowCount(len(reg))
        for r, rule in enumerate(reg.values()):
            fs = by.get(rule.name, [])
            usable = [f for f in fs if f.applicable]
            rec = any(f.recommended for f in usable)
            if rec:
                self.rec_rules.append(rule.name)
            box = QCheckBox()
            box.setChecked(rule.name in checked and bool(usable))
            box.setEnabled(bool(usable))
            box.toggled.connect(lambda on, n=rule.name: self._rule_toggled(n, on))
            self.rule_boxes[rule.name] = box
            cell = QWidget()
            lay = QHBoxLayout(cell)
            lay.setContentsMargins(6, 0, 0, 0)
            lay.addWidget(box)
            self.rule_table.setCellWidget(r, 0, cell)
            lines = [("" if f.applicable else "n/a: ") + f.title + (f" — {f.reason}" if f.reason else "")
                     for f in fs] or ["nothing detected"]
            shown = lines if len(lines) <= 6 else lines[:5] + [f"… and {len(lines) - 5} more (hover for all)"]
            items = [("★ " if rec else "") + rule.name, "\n".join(shown), rule.summary
                     + (f" (conflicts: {', '.join(rule.conflicts)})" if rule.conflicts else "")]
            for c, text in enumerate(items, 1):
                it = QTableWidgetItem(text)
                it.setToolTip("\n".join(lines))
                if not usable:
                    it.setForeground(QBrush(QColor("#888")))
                self.rule_table.setItem(r, c, it)
        self.rule_table.resizeRowsToContents()
        if self.rec_all.isChecked():
            self._tick_recommended()

    def _tick_recommended(self) -> None:
        """Tick every enabled ★ row. Conflicts: the first rule in registry order wins; rows the user
        ticked by hand count as taken. The user is told about each rule that had to stay off."""
        manual = {n for n, b in self.rule_boxes.items() if b.isChecked() and n not in self.rec_rules}
        want = [n for n in self.rec_rules if self.rule_boxes[n].isEnabled()]
        chosen, skipped = pick_recommended(want, taken=manual)
        for n in chosen:
            self.rule_boxes[n].setChecked(True)
        for n, other in skipped:
            self.say(f"{n} not ticked: conflicts with {other}")

    def _rec_all_toggled(self, on: bool) -> None:
        self.settings.setValue("rules/auto_recommended", on)
        if on:
            self._tick_recommended()
        else:
            for n in self.rec_rules:
                if n in self.rule_boxes:
                    self.rule_boxes[n].setChecked(False)

    def _rule_toggled(self, name: str, on: bool) -> None:
        if not on:
            return
        for other in registry()[name].conflicts:
            b = self.rule_boxes.get(other)
            if b and b.isChecked():
                b.setChecked(False)
                self.say(f"{other} switched off: conflicts with {name}")

    def selected_rules(self) -> set[str]:
        return {n for n, b in self.rule_boxes.items() if b.isChecked() and n != "user-patch"}

    def _add_patch(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Patch recipes", "", "Patch recipe (*.json);;All files (*)")
        for f in files:
            if Path(f) not in self.patches:
                self.patches.append(Path(f))
                self.patch_list.addItem(f)
        if files:
            self._invalidate()
            self.say("patch files changed — press Analyze")

    def _remove_patch(self) -> None:
        for it in self.patch_list.selectedItems():
            self.patches.remove(Path(it.text()))
            self.patch_list.takeItem(self.patch_list.row(it))
        self._invalidate()

    # ---- analyze ------------------------------------------------------------------------
    def _analyze(self) -> None:
        game = Path(self.game_edit.text()).expanduser()
        if not (game / "eboot.bin").is_file():
            QMessageBox.warning(self, "Not a game folder", f"No eboot.bin in\n{game}")
            return
        self.settings.setValue("game", str(game))
        self.settings.setValue("target", self.target.currentData())
        self.settings.setValue("console_fw", self.console_fw.text().strip())
        self.say(f"analyzing {game} for FW {self.target.currentData()}.xx")
        self.busy(True)
        self.worker = AnalyzeWorker(game, self.target.currentData(), list(self.patches), self.replace_dump())
        self.worker.progress.connect(self._progress)
        self.worker.plan_ready.connect(self._on_plan)
        self.worker.error.connect(self._on_analyze_error)
        self.worker.start()

    @pyqtSlot(object)
    def _on_plan(self, p) -> None:
        self._release()
        self.plan = p
        self.busy(False)
        gs, cov = p.scan, p.coverage
        sdks = sorted({b.sdk_str() for b in gs.binaries if b.role != "fakelib" and b.sdk_ps5})
        ident = (f"{gs.title or gs.title_id}  [{gs.title_id}]  v{gs.content_version or '?'}" if gs.title_id
                 else f"{Path(gs.root).name}  (no param.json)")
        self.info.setText(f"{ident}   SDK {', '.join(sdks) or '?'}   flags: {', '.join(gs.flags) or 'none'}")
        fill(self.bin_table, [[b.path, b.role, b.sdk_str(), b.n_imports, b.n_exports, ", ".join(b.flags),
                               b.error] for b in gs.binaries],
             {i: "#d55" for i, b in enumerate(gs.binaries) if b.error})
        warns = list(gs.warnings)
        if cov is None:
            warns.append("No kits in the library — add some on the Kits tab to get fakelib selection.")
            self.cov_table.setRowCount(0)
        else:
            rows, colors = [], {}
            for i, m in enumerate(cov.modules):
                fl = f"{Path(m.choice.relpath).name}  ({m.choice.kit}, FW{m.choice.kit_fw})" if m.choice else ""
                notes = []
                if m.absent:
                    pre = "not on this FW, fakelib provides" if m.choice else "ABSENT on this FW"
                    notes.append(f"{pre}: {', '.join(m.absent[:4])}" + (" …" if len(m.absent) > 4 else ""))
                if m.choice and m.choice.missing:
                    notes.append(f"fakelib lacks {len(m.choice.missing)}")
                if m.unproven and m.status == "unverified":
                    notes.append(f"{len(m.unproven)} without evidence")
                if m.stubbed:
                    kits = sorted({k for n in m.stubbed for k, *_ in m.stub_src.get(n, [])})
                    notes.append(f"{len(m.stubbed)} PLT-stubbed by {', '.join(kits)} (rule kit-stubs)")
                if m.conflict:
                    notes.append(f"{len(m.conflict)} with conflicting evidence")
                if m.note:
                    notes.append(m.note)
                rows.append([m.module, m.status, len(m.needed), m.proven, fl, "; ".join(notes)])
                colors[i] = STATUS_COLOR.get(m.status, "#888")
                if m.status == "stubbed":
                    warns.append(f"{m.module}: {len(m.stubbed)} import(s) stubbed by kits for this FW — "
                                 "consider the kit-stubs rule")
                if m.status in ("absent", "missing", "partial"):
                    warns.append(f"{m.module}: {m.status}" + (f" ({', '.join(m.absent[:4])})" if m.absent else ""))
            fill(self.cov_table, rows, colors)
            warns += cov.deps
            from ..core.advice import ampr_advice
            warns += ["advice: " + x for x in ampr_advice(gs, cov)]
        from ..core.pipeline import ampr_describe_lines, describe_ampr
        warns += ["ampr: " + x for x in ampr_describe_lines(describe_ampr(Path(gs.root)))]
        self.warn_list.clear()
        self.warn_list.addItems(warns or ["no warnings"])
        self._fill_rules(p.findings)
        rec = [f.rule for f in p.findings if f.recommended and f.applicable]
        self.say(f"analysis done: {len(gs.binaries)} binaries, "
                 f"{len(cov.fakelibs()) if cov else 0} fakelib(s) selected"
                 + (f"; recommended rules: {', '.join(sorted(set(rec)))}" if rec else ""))
        self.build_btn.setEnabled(not any(b.error for b in gs.binaries if b.role != "fakelib"))

    @pyqtSlot(str)
    def _on_analyze_error(self, msg: str) -> None:
        self._release()
        self.busy(False)
        self.say(f"analysis failed: {msg}")
        QMessageBox.critical(self, "Analysis failed", msg.split("\n\n")[0])

    # ---- build --------------------------------------------------------------------------
    def build_options(self) -> BuildOptions:
        mode = self.mode.currentData()
        also = [sdk.parse_target(x) for x in self.also_edit.text().split(",") if x.strip()] \
            if mode != "inplace" else []                      # ValueError -> shown by _build
        cfw = self.console_fw.text().strip()
        if cfw:
            sdk.fw_major_of_str(cfw)
        seeds = self._seed_list()
        bad = [n for n in seeds if n not in load_contracts()]
        if bad:
            raise ValueError(f"seeds: no stub contract for {', '.join(bad)}")
        return BuildOptions(also_targets=also, seeds=seeds, seed_plt_fallback=self.seed_plt.isChecked(), console_fw=cfw or None, target=self.target.currentData(), mode=mode,
                            out=None if mode == "inplace" else Path(self.out_edit.text()).expanduser(),
                            force=self.force.isChecked(), rules=self.selected_rules(),
                            replace_dump=self.replace_dump(), ampr_index=self.ampr_index.currentData() or "auto",
                            patches=list(self.patches) if self.rule_boxes["user-patch"].isChecked() else [],
                            memfix=self.memfix_choices(),
                            klog_text=self.klog_in.toPlainText() or None)

    def _build(self, confirm: bool = True) -> None:
        if self.plan is None:
            return
        try:
            opts = self.build_options()
        except ValueError as e:
            self.last_error = str(e)
            self.say(self.last_error)
            if not getattr(self, "_headless", False):
                QMessageBox.warning(self, "Build options", self.last_error)
            return
        if opts.mode != "inplace" and not self.out_edit.text().strip():
            QMessageBox.warning(self, "Output folder", "Choose an output folder.")
            return
        if opts.mode != "inplace":
            from ..core.pipeline import is_previous_build, previous_build_title
            o = Path(self.out_edit.text().strip()).expanduser()
            if o.is_dir() and any(o.iterdir()):
                prev = previous_build_title(o)
                tid = self.plan.scan.title_id if self.plan else ""
                if prev and tid and prev != tid:
                    self.last_error = f"{o} holds the backport of another game ({prev}). Choose another folder."
                    self.say(self.last_error)
                    if not getattr(self, "_headless", False):
                        QMessageBox.warning(self, "Output folder", self.last_error)
                    return
                if not is_previous_build(o):
                    self.last_error = (f"{o} is not empty and isn't an earlier ps5bp build. "
                                       "Choose an empty or new folder.")
                    self.say(self.last_error)
                    if not getattr(self, "_headless", False):
                        QMessageBox.warning(self, "Output folder", self.last_error)
                    return
                if confirm and not getattr(self, "_headless", False) and QMessageBox.question(
                        self, "Replace previous build", f"Replace the earlier backport in\n{o}?") \
                        != QMessageBox.StandardButton.Yes:
                    return
        if confirm and opts.mode == "inplace" and QMessageBox.question(
                self, "Build in place", "Modify the game folder itself? Originals are kept as *.orig.") \
                != QMessageBox.StandardButton.Yes:
            return
        self.settings.setValue("mode", opts.mode)
        self.settings.setValue("console_fw", self.console_fw.text().strip())
        self.settings.setValue("also_target", self.also_edit.text().strip())
        self.settings.setValue("out", self.out_edit.text())
        game = Path(self.plan.scan.root)
        self.say(f"building {game} -> FW {opts.target}.xx, {opts.mode}"
                 + (f", rules: {', '.join(sorted(opts.rules))}" if opts.rules else "")
                 + (f", {len(opts.patches)} patch file(s)" if opts.patches else "")
                 + (f", memfix: {' '.join(opts.memfix)}" if opts.memfix else ""))
        self.busy(True)
        self.worker = BuildWorker(game, opts)
        self.worker.log.connect(self.say)
        self.worker.progress.connect(self._progress)
        self.worker.build_finished.connect(self._on_built)
        self.worker.cancelled.connect(self._on_cancelled)
        self.worker.error.connect(self._on_build_error)
        self.worker.start()

    def _cancel(self) -> None:
        if isinstance(self.worker, BuildWorker) and self.worker.isRunning():
            self.say("cancelling…")
            self.worker.stop()

    @pyqtSlot(object)
    def _on_built(self, rep) -> None:
        self._release()
        self.busy(False)
        self.last_report = rep
        if rep.memfix_trial is not None:
            self._mf_refresh_trials()
        self.say(rep.to_text())
        self.tabs.setCurrentWidget(self.log)
        box = QMessageBox(self)
        box.setWindowTitle("Backport built")
        box.setText(self.built_text(rep))
        self.last_box = box
        if rep.warnings:
            box.setDetailedText("\n".join(rep.warnings))
        openb = box.addButton("Open folder", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Close)
        if not getattr(self, "_headless", False):
            box.exec()
            if box.clickedButton() is openb:
                if not open_folder(rep.out):
                    QMessageBox.warning(self, "Open folder", f"Could not open a file manager for:\n{rep.out}")

    @staticmethod
    def libc_line(cc: dict) -> str:
        """One-line summary of BuildReport.libc_check (empty when the build had no libc / no kit store)."""
        if not cc:
            return ""
        n, same, ident = cc.get("kits_with_libc", 0), cc.get("same_identity", 0), cc.get("identical", 0)
        if not n:
            return "libc cross-check: no kit has a recorded libc (Kits tab → Reindex libc)."
        if not same:
            return f"libc cross-check: no kit libc of this build ({n} kit libc(s) recorded, none the same build)."
        if ident == same:
            return f"libc cross-check: matches {ident} kit libc(s) byte for byte (decoded)."
        if ident:
            return f"libc cross-check: matches {ident} of {same} same-build kit libc(s), differs from the rest (see Log)."
        return f"libc cross-check: differs from {same} same-build kit libc(s) (see Log for the ranges)."

    def built_text(self, rep) -> str:
        t = (f"{len(rep.edits)} edit(s), {len(rep.fakelibs)} fakelib(s), "
             f"{len(rep.verified)} binaries verified.\n\n{rep.out}")
        if rep.siblings:
            t += "\n\nSibling outputs (SDK fields only):\n" + "\n".join(
                f"  FW {sb['target_str']}: {sb['out']}" for sb in rep.siblings)
        lc = self.libc_line(rep.libc_check)
        if lc:
            t += "\n\n" + lc
        ax = (rep.ampr or {}).get("index") or {}
        if ax.get("action") and ax["action"] != "none":
            t += f"\n\nAMPR index: {ax['action']}" + (f" ({ax['entries']} entries)" if ax.get("entries") else "")
        if rep.console_warning:
            t += "\n\n⚠ " + rep.console_warning
        if rep.originals:
            t += (f"\n\nCopying this over the game replaces its files. The originals are saved in\n"
                  f"{rep.originals}\nand `ps5bp undo GAME {rep.out}` (or Undo applied backport…) puts them back.")
        return t

    @pyqtSlot()
    def _on_cancelled(self) -> None:
        self._release()
        self.busy(False)
        self.say("build cancelled (a partial output folder may remain)")

    @pyqtSlot(str)
    def _on_build_error(self, msg: str) -> None:
        self._release()
        self.busy(False)
        self.last_error = msg
        self.say(f"build failed: {msg}")
        self.tabs.setCurrentWidget(self.log)
        if not getattr(self, "_headless", False):
            QMessageBox.critical(self, "Build failed", msg.split("\n\n")[0])

    # ---- memory fix ------------------------------------------------------------------------
    def replace_dump(self) -> dict[str, str | None]:
        """module -> None (auto, best kit) | kit name; modules left on "keep dump's" are absent."""
        out: dict[str, str | None] = {}
        for mod, cb in self.replace_boxes.items():
            d = cb.currentData()
            if d == "auto":
                out[mod] = None
            elif isinstance(d, str) and d.startswith("kit:"):
                out[mod] = d[4:]
        return out

    def _fill_replace_boxes(self, files) -> None:
        for mod, cb in self.replace_boxes.items():
            cur = cb.currentData()
            cb.blockSignals(True)
            cb.clear()
            cb.addItem("keep dump's", "keep")
            cb.addItem("auto (best kit)", "auto")
            for name in sorted({f.kit for f in files if f.role == "fakelib" and f.module == mod}):
                cb.addItem(name, f"kit:{name}")
            cb.setCurrentIndex(max(0, cb.findData(cur)))
            cb.blockSignals(False)
            if cb.currentData() != cur and cur is not None:
                self._invalidate()                        # the chosen kit went away

    def _seed_list(self) -> list[str]:
        out: list[str] = []
        for x in self.seeds_edit.text().replace(",", " ").split():
            if x not in out:
                out.append(x)
        return out

    def _seeds_changed(self, *_) -> None:
        bad = [n for n in self._seed_list() if n not in load_contracts()]
        self.seeds_edit.setStyleSheet("background: #fdd" if bad else "")
        self.seeds_edit.setToolTip(self._seeds_tip + (f"\n\nNo contract for: {', '.join(bad)}" if bad else ""))

    def _mf_clear(self, *_) -> None:
        """Site ids belong to one eboot: forget them when the game folder changes."""
        if hasattr(self, "mf_list"):
            self.mf_sites = []
            self.mf_table.setRowCount(0)
            self.mf_list.clear()
            self.mf_trials.clear()

    def memfix_choices(self) -> list[str]:
        return [self.mf_list.item(k).text() for k in range(self.mf_list.count())]

    def _mf_title(self) -> str:
        return self.plan.scan.title_id if self.plan else ""

    def _mf_scan(self) -> None:
        from ..core import memfix
        game = Path(self.game_edit.text()).expanduser()
        if not (game / "eboot.bin").is_file():
            QMessageBox.warning(self, "Memory fix", "Choose a game folder with an eboot.bin first.")
            return
        self.mf_scan_btn.setEnabled(False)
        self.say(f"memfix: scanning allocation sites in {game / 'eboot.bin'}")
        self.mf_worker = FuncWorker(lambda g, k: memfix.scan(g, "eboot.bin", k)[1], game,
                                    self.klog_in.toPlainText() or None)
        self.mf_worker.done.connect(self._mf_scanned)
        self.mf_worker.error.connect(self._mf_error)
        self.mf_worker.start()

    @pyqtSlot(object)
    def _mf_scanned(self, sites) -> None:
        self._release("mf_worker")
        self.mf_scan_btn.setEnabled(True)
        self.mf_sites = sites
        rows, colors = [], {}
        for n, s in enumerate(sites):
            flags = ", ".join(x for x, on in (("CRASH PATH", s.on_crash_path), ("fatal", s.fatal)) if on)
            shrink = ("safe" if s.shrink_safe else "unsafe") if s.hook is not None else "n/a"
            rows.append([n + 1, s.id, s.api, f"{s.fn:#x}", flags, " ; ".join(s.len_desc[-2:]), shrink,
                         ", ".join(s.variants())])
            if s.on_crash_path:
                colors[n] = "#d55"
        fill(self.mf_table, rows, colors)
        self.say(f"memfix: {len(sites)} allocation site(s)")
        if sites:
            self.mf_table.selectRow(0)
        self._mf_refresh_trials()

    @pyqtSlot(str)
    def _mf_error(self, msg: str) -> None:
        self._release("mf_worker")
        self.mf_scan_btn.setEnabled(True)
        self.say(f"memfix scan failed: {msg}")

    def _mf_selected(self) -> None:
        r = self.mf_table.currentRow()
        self.mf_variant.clear()
        if 0 <= r < len(self.mf_sites):
            s = self.mf_sites[r]
            for v in s.variants():
                self.mf_variant.addItem(v)
            self.mf_out.setPlainText("\n".join([f"site {s.id}  {s.api}  in fn {s.fn:#x}",
                                                f"length ({s.len_reg}):"] + [f"   {d}" for d in s.len_desc]
                                               + [f"on failure: {s.fail_desc}",
                                                  f"shrink: {s.shrink_why}" + (f" (hook {s.hook:#x})" if s.hook else "")]
                                               + ([f"crash-path callers: {', '.join(f'{c:#x}' for c in s.crash_callers)}"]
                                                  if s.crash_callers else [])))

    def _mf_add(self) -> None:
        r = self.mf_table.currentRow()
        if not 0 <= r < len(self.mf_sites) or not self.mf_variant.currentText():
            return
        v = self.mf_variant.currentText()
        c = f"{self.mf_sites[r].id}:{v}" + (f":{self.mf_amount.currentText()}" if v == "shrink" else "")
        if c not in self.memfix_choices():
            self.mf_list.addItem(c)

    def _mf_remove(self) -> None:
        for it in self.mf_list.selectedItems():
            self.mf_list.takeItem(self.mf_list.row(it))

    def _mf_refresh_trials(self) -> None:
        from ..core import memfix
        self.mf_trials.clear()
        for t in reversed(memfix.list_trials(self._mf_title())):
            self.mf_trials.addItem(f"#{t['id']}  {t['time']}  FW{t['target']}  {t.get('result') or 'untested'}  "
                                   f"{' '.join(t['choices'])}", t["id"])

    def _mf_result(self, works: bool) -> None:
        from ..core import memfix
        n = self.mf_trials.currentData()
        if n is None:
            return
        game = Path(self.game_edit.text()).expanduser()
        try:
            msgs = memfix.record_result(game, self._mf_title(), n, works,
                                        None if works else (self.klog_in.toPlainText() or None))
        except Exception as e:                           # noqa: BLE001
            msgs = [f"failed: {e}"]
        self.mf_out.setPlainText("\n".join(msgs))
        self.say("memfix: " + " / ".join(msgs))
        self._mf_refresh_trials()

    # ---- console ---------------------------------------------------------------------------
    LOG_LINES = 5000

    def _build_console_tab(self) -> None:
        self.con_bridge = None
        self.con_send_worker = None
        self._con_pending: list[str] = []
        self._con_recent: deque[str] = deque(maxlen=2000)
        self.con_diag_worker = None
        self.con_timer = QTimer(self)
        self.con_timer.setInterval(100)
        self.con_timer.timeout.connect(self._con_flush)
        w = QWidget()
        v = QVBoxLayout(w)
        r = QHBoxLayout()
        r.addWidget(QLabel("Console IP:"))
        self.con_ip = QLineEdit(self.settings.value("console/ip", ""))
        self.con_ip.setPlaceholderText("192.168.x.y")
        self.con_ip.editingFinished.connect(lambda: self.settings.setValue("console/ip", self.con_ip.text().strip()))
        r.addWidget(self.con_ip, 1)
        v.addLayout(r)
        self.con_payloads: dict[str, QLineEdit] = {}
        for key, label in (("klogsrv", "klogsrv"), ("ftpsrv", "ftpsrv"), ("other", "other payload")):
            pr = QHBoxLayout()
            pr.addWidget(QLabel(f"{label}:"))
            ed = QLineEdit(self.settings.value(f"console/payload_{key}", ""))
            ed.setPlaceholderText("path to your own .elf (not bundled)")
            ed.editingFinished.connect(lambda k=key, e=ed: self.settings.setValue(f"console/payload_{k}", e.text().strip()))
            self.con_payloads[key] = ed
            pr.addWidget(ed, 1)
            b = QPushButton("Browse…")
            b.clicked.connect(lambda _=False, e=ed: self._con_pick(e))
            pr.addWidget(b)
            b = QPushButton("Send")
            b.clicked.connect(lambda _=False, e=ed: self._con_send(e))
            pr.addWidget(b)
            v.addLayout(pr)
        gr = QHBoxLayout()
        gr.addWidget(QLabel("Game folder (to resolve crash backtraces; optional):"))
        self.con_game = QLineEdit(self.settings.value("console/game", ""))
        self.con_game.setPlaceholderText("your backport output (overlay or full), or a game folder; empty = the game folder at the top")
        self.con_game.setToolTip("A folder on this PC with the same files the console is running.\n"
                                 "Best: the backport's output folder. For an overlay build, files the overlay\n"
                                 "doesn't contain are read from the game folder it was built from\n"
                                 "(named in its backport-report.json).")
        self.con_game.editingFinished.connect(lambda: self.settings.setValue("console/game", self.con_game.text().strip()))
        gr.addWidget(self.con_game, 1)
        b = QPushButton("Browse…")
        b.clicked.connect(lambda: self._con_pick(self.con_game, folder=True))
        gr.addWidget(b)
        v.addLayout(gr)
        dr = QHBoxLayout()
        self.con_dump_on = QCheckBox("Capture crash dumps (FTP :2121) into:")
        self.con_dump_on.setChecked(self.settings.value("console/dumps_on", "false") in (True, "true"))
        self.con_dump_on.toggled.connect(lambda on: self.settings.setValue("console/dumps_on", on))
        dr.addWidget(self.con_dump_on)
        self.con_dump_dir = QLineEdit(self.settings.value("console/dumps_dir", str(home() / "dumps")))
        self.con_dump_dir.editingFinished.connect(lambda: self.settings.setValue("console/dumps_dir", self.con_dump_dir.text().strip()))
        dr.addWidget(self.con_dump_dir, 1)
        b = QPushButton("Browse…")
        b.clicked.connect(lambda: self._con_pick(self.con_dump_dir, folder=True))
        dr.addWidget(b)
        v.addLayout(dr)
        cr = QHBoxLayout()                       # last of the fill-in rows, right above the log
        self.con_start_btn = QPushButton("Start live log")
        self.con_start_btn.clicked.connect(self._con_start)
        cr.addWidget(self.con_start_btn)
        self.con_stop_btn = QPushButton("Stop")
        self.con_stop_btn.setEnabled(False)
        self.con_stop_btn.clicked.connect(self._con_stop)
        cr.addWidget(self.con_stop_btn)
        self.con_status = QLabel("idle")
        cr.addWidget(self.con_status, 1)
        v.addLayout(cr)
        sp = QSplitter(Qt.Orientation.Vertical)
        self.con_log = QPlainTextEdit()
        self.con_log.setReadOnly(True)
        self.con_log.setFont(QFont("monospace"))
        self.con_log.setMaximumBlockCount(self.LOG_LINES)
        sp.addWidget(self.con_log)
        bot = QSplitter(Qt.Orientation.Horizontal)
        self.con_triage = QPlainTextEdit()
        self.con_triage.setReadOnly(True)
        self.con_triage.setFont(QFont("monospace"))
        self.con_triage.setPlaceholderText("latest crash / hang diagnosis appears here")
        tv = QWidget()
        tl = QVBoxLayout(tv)
        tl.setContentsMargins(0, 0, 0, 0)
        self.con_diag_btn = QPushButton("Diagnose now")
        self.con_diag_btn.setToolTip("Explain the recent console log (last 2000 lines) right now: crash triage if a "
                                     "crash is in it, otherwise the problems the log lines show (e.g. a save data "
                                     "mount failing in a loop on a black screen).")
        self.con_diag_btn.clicked.connect(self._con_diagnose)
        tl.addWidget(self.con_diag_btn)
        tl.addWidget(self.con_triage)
        bot.addWidget(tv)
        self.con_dumps = QListWidget()
        bot.addWidget(self.con_dumps)
        sp.addWidget(bot)
        sp.setSizes([350, 250])
        v.addWidget(sp, 1)
        self.last_console_crash = ""
        self.tabs.addTab(w, "Console")

    def _con_pick(self, edit: QLineEdit, folder: bool = False) -> None:
        if folder:
            f = QFileDialog.getExistingDirectory(self, "Folder", edit.text())
        else:
            f, _ = QFileDialog.getOpenFileName(self, "Payload (.elf)", edit.text(), "ELF (*.elf);;All files (*)")
        if f:
            edit.setText(f)
            edit.editingFinished.emit()

    def _con_host(self) -> str | None:
        ip = self.con_ip.text().strip()
        if not ip:
            self.say("console: enter the console IP first")
            return None
        self.settings.setValue("console/ip", ip)
        return ip

    def _con_send(self, edit: QLineEdit) -> None:
        from ..core import console
        ip, path = self._con_host(), edit.text().strip()
        if not ip:
            return
        if not Path(path).is_file():
            self.say(f"console: payload not found: {path}")
            return
        self.con_status.setText(f"sending {Path(path).name}…")
        wk = FuncWorker(console.send_payload, ip, path)
        self.con_send_worker = wk
        wk.done.connect(lambda n, p=path: (self.con_status.setText("sent"), self.say(f"console: sent {n} bytes of {Path(p).name} to {ip}")))
        wk.error.connect(lambda m: (self.con_status.setText("send failed"), self.say(f"console: send failed: {m.splitlines()[0]}")))
        wk.start()

    def _con_start(self) -> None:
        ip = self._con_host()
        if not ip or self.con_bridge is not None:
            return
        from ..core.klog import has_game
        top = self.game_edit.text().strip()
        game = self.con_game.text().strip() or (top if top and has_game(Path(top).expanduser()) else "")
        flags = self.plan.scan.flags if self.plan else []
        dumps = Path(self.con_dump_dir.text().strip()).expanduser() if self.con_dump_on.isChecked() else None
        crash_dir = dumps if dumps else home() / "console"
        b = ConsoleBridge(ip, 3232, 2121, game, flags, crash_dir, dumps)
        b.line.connect(self._con_line)
        b.status.connect(self.con_status.setText)
        b.crash.connect(self._con_crash)
        b.loop.connect(self._con_loop)
        b.dump_event.connect(lambda m: self.con_status.setText(m))
        b.captured.connect(self._con_captured)
        self.con_bridge = b
        self.con_timer.start()
        self.con_start_btn.setEnabled(False)
        self.con_stop_btn.setEnabled(True)
        b.start()

    def _con_stop(self) -> None:
        b, self.con_bridge = self.con_bridge, None
        if b is not None:
            for sig in (b.line, b.status, b.crash, b.loop, b.dump_event, b.captured):
                try:
                    sig.disconnect()
                except TypeError:
                    pass
            b.stop()
        self.con_timer.stop()
        self._con_flush()
        self.con_start_btn.setEnabled(True)
        self.con_stop_btn.setEnabled(False)
        self.con_status.setText("stopped")

    def _con_line(self, ln: str) -> None:
        self._con_pending.append(ln)
        self._con_recent.append(ln)

    def _con_loop(self, text: str, saved: str) -> None:
        self.con_triage.setPlainText(text + (f"\nloop saved to {saved}\n" if saved else ""))
        self.say("console: game looks stuck in a loop" + (f" — saved {saved}" if saved else ""))

    def _con_diagnose(self) -> None:
        from ..core import console
        from ..core.klog import has_game
        top = self.game_edit.text().strip()
        game = self.con_game.text().strip() or (top if top and has_game(Path(top).expanduser()) else "")
        flags = self.plan.scan.flags if self.plan else []
        lines = list(self._con_recent)
        self.con_diag_btn.setEnabled(False)
        wk = FuncWorker(console.diagnose_recent, lines, game or None, flags)
        self.con_diag_worker = wk

        def done(text):
            self.con_triage.setPlainText(text)
            self.con_diag_btn.setEnabled(True)

        def err(m):
            self.con_triage.setPlainText(f"diagnosis failed: {m.splitlines()[0]}")
            self.con_diag_btn.setEnabled(True)
        wk.done.connect(done)
        wk.error.connect(err)
        wk.start()

    def _con_flush(self) -> None:
        if self._con_pending:
            chunk, self._con_pending = self._con_pending[-self.LOG_LINES:], []
            self.con_log.appendPlainText("\n".join(chunk))

    def _con_crash(self, text: str, saved: str, block: str) -> None:
        self.con_triage.setPlainText(text + (f"\ncrash block saved to {saved}\n" if saved else ""))
        self.last_console_crash = block
        self.klog_in.setPlainText(block)           # ready for the Crash log / Memory fix tabs
        self.say("console: crash detected" + (f" — saved {saved}" if saved else ""))

    def _con_captured(self, cap) -> None:
        state = "complete" if cap.complete else ("vanished" if cap.vanished else "partial")
        self.con_dumps.addItem(f"{cap.folder}  [{state}]  {len(cap.files)} file(s)  {cap.out_dir}")

    # ---- crash log -------------------------------------------------------------------------
    def _load_klog(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, "Crash log", "", "Logs (*.txt *.log);;All files (*)")
        if f:
            self.klog_in.setPlainText(Path(f).read_text(errors="replace", encoding="utf-8"))

    def _triage(self) -> None:
        from ..core import klog
        t = klog.parse(self.klog_in.toPlainText())
        game = Path(self.game_edit.text()).expanduser()
        flags = self.plan.scan.flags if self.plan else []
        if klog.has_game(game):
            try:
                klog.symbolize(t, game)
            except Exception as e:                       # noqa: BLE001
                self.say(f"could not resolve backtrace against {game}: {e}")
        klog.diagnose(t, flags)
        self.klog_out.setPlainText(t.to_text())

    # ---- kits -----------------------------------------------------------------------------
    def _refresh_kits(self) -> None:
        db = EvidenceDB()
        try:
            kits = db.kits()
            files = db.kit_files()
            counts = {k.name: sum(1 for f in files if f.kit == k.name) for k in kits}
            overlay = {k.name for k, *_ in db.psml_overlays()}
            libc = {r.kit: r.identity[:12] for r in db.libc_records()}
        finally:
            db.close()
        self.kit_label.setText(f"Kit library: {home()} — {len(kits)} kit(s). A kit is an existing backport's "
                               f"files; it supplies fakelibs and evidence of which functions each FW has.")
        fill(self.kit_table, [[k.name, f"{k.fw}.xx" + (f" (tested {k.tested_fw})" if k.tested_fw else ""),
                               k.title_id, counts[k.name], "yes" if k.name in overlay else "—",
                               libc.get(k.name, "—"), k.source, k.added]
                              for k in kits])
        self._fill_replace_boxes(files)

    def _add_kit(self, is_zip: bool) -> None:
        if is_zip:
            src, _ = QFileDialog.getOpenFileName(self, "Kit zip", "", "Zip (*.zip)")
        else:
            src = QFileDialog.getExistingDirectory(self, "Kit folder")
        if not src:
            return
        fw, ok = QInputDialog.getInt(self, "Kit firmware", "Firmware the kit's author targeted (e.g. 4):",
                                     4, 1, 10)
        if not ok:
            return
        tested, ok = QInputDialog.getInt(self, "Tested on", "Firmware the kit was actually run on, per its "
                                         "author's notes (e.g. 10 if only tested on 10.01):", fw, 1, 13)
        if not ok:
            return
        name, ok = QInputDialog.getText(self, "Kit name", "Name (blank = automatic):")
        if not ok:
            return
        self._run_kit(KitWorker("add", src=Path(src), fw=fw, name=name.strip(),
                                tested_fw=None if tested == fw else tested))

    def _remove_kit(self) -> None:
        rows = {i.row() for i in self.kit_table.selectedItems()}
        for r in rows:
            name = self.kit_table.item(r, 0).text()
            if QMessageBox.question(self, "Remove kit", f"Remove {name}?") == QMessageBox.StandardButton.Yes:
                self._run_kit(KitWorker("remove", name=name))
                return

    def _run_kit(self, w: KitWorker) -> None:
        if self.kit_worker is not None:
            return
        self.kit_worker = w
        w.done.connect(self._on_kit_done)
        w.error.connect(self._on_kit_error)
        self.say("updating kit library…")
        w.start()

    @pyqtSlot(str)
    def _on_kit_done(self, msg: str) -> None:
        self._release("kit_worker")
        self.say(msg)
        self._refresh_kits()
        self._invalidate()

    @pyqtSlot(str)
    def _on_kit_error(self, msg: str) -> None:
        self._release("kit_worker")
        self.last_error = msg
        self.say(f"kit operation failed: {msg}")
        if not getattr(self, "_headless", False):
            QMessageBox.critical(self, "Kit", msg)

    def _learn_dialog(self) -> LearnDialog:
        d = LearnDialog(self, self.game_edit.text().strip(), getattr(self, "_headless", False))
        self.learn_dlg = d
        if not getattr(self, "_headless", False):
            d.exec()
        return d

    def _reindex_kits(self) -> None:
        self._run_kit(KitWorker("reindex"))

    def _undo(self) -> UndoDialog:
        d = UndoDialog(self, self.game_edit.text().strip(), getattr(self, "_headless", False))
        self.undo_dlg = d
        d.applied = False
        if not getattr(self, "_headless", False):
            d.exec()
            if d.applied:
                self.say("undo applied to " + d.game_edit.text().strip())
        return d

    def closeEvent(self, e) -> None:                             # noqa: N802
        self._con_stop()
        for w in (self.worker, self.kit_worker):
            if w is not None and w.isRunning():
                if isinstance(w, BuildWorker):
                    w.stop()
                w.wait(10000)
        super().closeEvent(e)
