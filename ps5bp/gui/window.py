"""Main window: game -> analyze -> choose rules -> build."""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QUrl, pyqtSlot
from PyQt6.QtGui import QBrush, QColor, QDesktopServices, QFont
from PyQt6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QHBoxLayout,
                             QHeaderView, QInputDialog, QLabel, QLineEdit, QListWidget, QMainWindow,
                             QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSplitter,
                             QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from .. import __version__
from ..core import sdk
from ..core.evidence import EvidenceDB, home
from ..core.pipeline import MODES, BuildOptions
from ..core.rules import registry
from .workers import AnalyzeWorker, BuildWorker, FuncWorker, KitWorker

STATUS_COLOR = {"game": "#5a9", "system": "#5a9", "fakelib": "#49c", "partial": "#c93",
                "unverified": "#888", "absent": "#d55", "missing": "#d55"}
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


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"PS5 Backporter {__version__}")
        self.resize(1100, 760)
        self.settings = QSettings("ps5bp", "ps5bp")
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
        self.tabs.addTab(rw, "Fix rules")
        self._fill_rules()
        # kits
        kw = QWidget()
        kv = QVBoxLayout(kw)
        self.kit_label = QLabel()
        kv.addWidget(self.kit_label)
        self.kit_table = table(["Name", "FW", "Source", "Title", "Files", "Added"])
        kv.addWidget(self.kit_table, 1)
        kr = QHBoxLayout()
        for text, slot in (("Add kit folder…", lambda: self._add_kit(False)),
                           ("Add kit zip…", lambda: self._add_kit(True)), ("Remove", self._remove_kit)):
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
        self.force.setToolTip("Accept a game folder that already contains fakelib/ (--force)")
        row.addWidget(self.force)
        v.addLayout(row)
        row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setFormat("")
        row.addWidget(self.progress, 1)
        self.build_btn = QPushButton("Build backport")
        self.build_btn.setEnabled(False)
        self.build_btn.clicked.connect(self._build)
        row.addWidget(self.build_btn)
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

    def _invalidate(self, *_) -> None:
        self.plan = None
        self.build_btn.setEnabled(False)

    def _mode_changed(self, *_) -> None:
        inplace = self.mode.currentData() == "inplace"
        self.out_edit.setEnabled(not inplace)
        self.out_btn.setEnabled(not inplace)

    def _browse_game(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Game folder", self.game_edit.text())
        if d:
            self.game_edit.setText(d)
            if not self.out_edit.text():
                self.out_edit.setText(str(Path(d).parent / f"{Path(d).name}-backport"))

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
        self.rule_table.setRowCount(len(reg))
        for r, rule in enumerate(reg.values()):
            fs = by.get(rule.name, [])
            usable = [f for f in fs if f.applicable]
            rec = any(f.recommended for f in usable)
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
            items = [("★ " if rec else "") + rule.name, "\n".join(lines), rule.summary
                     + (f" (conflicts: {', '.join(rule.conflicts)})" if rule.conflicts else "")]
            for c, text in enumerate(items, 1):
                it = QTableWidgetItem(text)
                it.setToolTip("\n".join(lines))
                if not usable:
                    it.setForeground(QBrush(QColor("#888")))
                self.rule_table.setItem(r, c, it)
        self.rule_table.resizeRowsToContents()

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
        self.say(f"analyzing {game} for FW {self.target.currentData()}.xx")
        self.busy(True)
        self.worker = AnalyzeWorker(game, self.target.currentData(), list(self.patches))
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
                rows.append([m.module, m.status, len(m.needed), m.proven, fl, "; ".join(notes)])
                colors[i] = STATUS_COLOR.get(m.status, "#888")
                if m.status in ("absent", "missing", "partial"):
                    warns.append(f"{m.module}: {m.status}" + (f" ({', '.join(m.absent[:4])})" if m.absent else ""))
            fill(self.cov_table, rows, colors)
            warns += cov.deps
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
        return BuildOptions(target=self.target.currentData(), mode=mode,
                            out=None if mode == "inplace" else Path(self.out_edit.text()).expanduser(),
                            force=self.force.isChecked(), rules=self.selected_rules(),
                            patches=list(self.patches) if self.rule_boxes["user-patch"].isChecked() else [],
                            memfix=self.memfix_choices(),
                            klog_text=self.klog_in.toPlainText() or None)

    def _build(self, confirm: bool = True) -> None:
        if self.plan is None:
            return
        opts = self.build_options()
        if opts.mode != "inplace" and not self.out_edit.text().strip():
            QMessageBox.warning(self, "Output folder", "Choose an output folder.")
            return
        if confirm and opts.mode == "inplace" and QMessageBox.question(
                self, "Build in place", "Modify the game folder itself? Originals are kept as *.orig.") \
                != QMessageBox.StandardButton.Yes:
            return
        self.settings.setValue("mode", opts.mode)
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
        box.setText(f"{len(rep.edits)} edit(s), {len(rep.fakelibs)} fakelib(s), "
                    f"{len(rep.verified)} binaries verified.\n\n{rep.out}")
        if rep.warnings:
            box.setDetailedText("\n".join(rep.warnings))
        openb = box.addButton("Open folder", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Close)
        if not getattr(self, "_headless", False):
            box.exec()
            if box.clickedButton() is openb:
                QDesktopServices.openUrl(QUrl.fromLocalFile(rep.out))

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

    # ---- crash log -------------------------------------------------------------------------
    def _load_klog(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, "Crash log", "", "Logs (*.txt *.log);;All files (*)")
        if f:
            self.klog_in.setPlainText(Path(f).read_text(errors="replace"))

    def _triage(self) -> None:
        from ..core import klog
        t = klog.parse(self.klog_in.toPlainText())
        game = Path(self.game_edit.text()).expanduser()
        flags = self.plan.scan.flags if self.plan else []
        if (game / "eboot.bin").is_file():
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
            counts = {k.name: len(db.kit_files(k.name)) for k in kits}
        finally:
            db.close()
        self.kit_label.setText(f"Kit library: {home()} — {len(kits)} kit(s). A kit is an existing backport's "
                               f"files; it supplies fakelibs and evidence of which functions each FW has.")
        fill(self.kit_table, [[k.name, f"{k.fw}.xx", k.source, k.title_id, counts[k.name], k.added]
                              for k in kits])

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
        name, ok = QInputDialog.getText(self, "Kit name", "Name (blank = automatic):")
        if not ok:
            return
        self._run_kit(KitWorker("add", src=Path(src), fw=fw, name=name.strip()))

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
        self.say(f"kit operation failed: {msg}")
        QMessageBox.critical(self, "Kit", msg)

    def closeEvent(self, e) -> None:                             # noqa: N802
        for w in (self.worker, self.kit_worker):
            if w is not None and w.isRunning():
                if isinstance(w, BuildWorker):
                    w.stop()
                w.wait(10000)
        super().closeEvent(e)
