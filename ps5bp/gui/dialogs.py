"""Dialogs: undo an applied backport, learn from a kit. Long work runs on a FuncWorker (never the GUI thread).
`headless` (set by the tests) skips every modal question/message box; the outcome lands in `last_error`/`result`."""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import pyqtSlot
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (QCheckBox, QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                             QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout)

from .workers import FuncWorker


def _plan(game: Path, outs: list[Path], force: bool):
    from ..core.undo import plan_undo
    return plan_undo(game, outs, force=force)


def _apply(game: Path, up) -> str:
    from ..core.undo import apply_undo
    apply_undo(game, up)
    return "done"


def undo_summary(up) -> str:
    L = [f"{up.count} edit(s) to reverse: {len(up.writes)} file(s) rewritten, {len(up.deletes)} removed, "
         f"{len(up.restores)} restored from .orig"]
    L += [f"  restore {rel}" for rel in sorted(up.writes)]
    L += [f"  delete  {rel}" for rel in up.deletes]
    L += [f"  note: {n}" for n in up.notes]
    return "\n".join(L)


class UndoDialog(QDialog):
    """Pick the game folder + output folder(s) (newest first), preview plan_undo, confirm, apply."""

    def __init__(self, parent, game: str = "", headless: bool = False) -> None:
        super().__init__(parent)
        self.setWindowTitle("Undo applied backport")
        self.resize(760, 560)
        self.headless = headless
        self.worker: FuncWorker | None = None
        self.plan = None
        self.last_error = ""
        self.result = ""
        self.applied = False
        v = QVBoxLayout(self)
        v.addWidget(QLabel("Reverses a backport that was copied over the game: the game folder is put back "
                           "to what it was before. List the output folder of every build you applied, "
                           "newest first."))
        r = QHBoxLayout()
        r.addWidget(QLabel("Game folder:"))
        self.game_edit = QLineEdit(game)
        self.game_edit.textChanged.connect(self._invalidate)
        r.addWidget(self.game_edit, 1)
        b = QPushButton("Browse…")
        b.clicked.connect(self._browse_game)
        r.addWidget(b)
        v.addLayout(r)
        v.addWidget(QLabel("Output folders (newest first):"))
        r = QHBoxLayout()
        self.out_list = QListWidget()
        self.out_list.setMaximumHeight(110)
        r.addWidget(self.out_list, 1)
        col = QVBoxLayout()
        for text, slot in (("Add…", self._add_out), ("Remove", self._remove_out),
                           ("Up", lambda: self._move(-1)), ("Down", lambda: self._move(1))):
            b = QPushButton(text)
            b.clicked.connect(slot)
            col.addWidget(b)
        col.addStretch(1)
        r.addLayout(col)
        v.addLayout(r)
        self.force = QCheckBox("Force: undo even when files no longer match what the backport wrote")
        self.force.toggled.connect(self._invalidate)
        v.addWidget(self.force)
        self.force_warn = QLabel("⚠ Force skips the check that the files still match what the backport wrote: "
                                 "changes made to them since (patches, other tools) can be lost. Read the "
                                 "notes in the preview.")
        self.force_warn.setWordWrap(True)
        self.force_warn.setStyleSheet("color: #c00; font-weight: bold")
        self.force_warn.hide()
        self.force.toggled.connect(self.force_warn.setVisible)
        v.addWidget(self.force_warn)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setFont(QFont("monospace"))
        self.out.setPlaceholderText("press Preview to see what would change")
        v.addWidget(self.out, 1)
        r = QHBoxLayout()
        self.status = QLabel()
        r.addWidget(self.status, 1)
        self.preview_btn = QPushButton("Preview")
        self.preview_btn.clicked.connect(self._preview)
        r.addWidget(self.preview_btn)
        self.apply_btn = QPushButton("Undo backport")
        self.apply_btn.setEnabled(False)
        self.apply_btn.clicked.connect(self._apply)
        r.addWidget(self.apply_btn)
        b = QPushButton("Close")
        b.clicked.connect(self.reject)
        r.addWidget(b)
        v.addLayout(r)

    # ---- inputs -----------------------------------------------------------------------
    def outputs(self) -> list[Path]:
        return [Path(self.out_list.item(i).text()).expanduser() for i in range(self.out_list.count())]

    def _browse_game(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Game folder", self.game_edit.text())
        if d:
            self.game_edit.setText(d)

    def _add_out(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Backport output folder")
        if d:
            self.out_list.addItem(d)
            self._invalidate()

    def _remove_out(self) -> None:
        for it in self.out_list.selectedItems():
            self.out_list.takeItem(self.out_list.row(it))
        self._invalidate()

    def _move(self, d: int) -> None:
        r = self.out_list.currentRow()
        if 0 <= r + d < self.out_list.count() and r >= 0:
            it = self.out_list.takeItem(r)
            self.out_list.insertItem(r + d, it)
            self.out_list.setCurrentRow(r + d)
            self._invalidate()

    def _invalidate(self, *_) -> None:
        self.plan = None
        self.apply_btn.setEnabled(False)

    def _busy(self, on: bool) -> None:
        self.preview_btn.setEnabled(not on)
        self.apply_btn.setEnabled(not on and self.plan is not None)

    # ---- plan / apply -----------------------------------------------------------------
    def _fail(self, msg: str) -> None:
        self.last_error = msg
        self.status.setText("refused")
        self.out.setPlainText(msg)
        if not self.headless:
            QMessageBox.critical(self, "Undo", msg)

    def _preview(self) -> None:
        if self.worker is not None:
            return
        game = Path(self.game_edit.text().strip()).expanduser()
        outs = self.outputs()
        self.last_error = ""
        if not (self.game_edit.text().strip() and game.is_dir() and outs):
            self._fail("Choose the game folder and at least one backport output folder.")
            return
        self.plan = None
        self.status.setText("planning…")
        self._busy(True)
        self._start(FuncWorker(_plan, game, outs, self.force.isChecked()), self._planned)

    def _start(self, w: FuncWorker, done) -> None:
        self.worker = w
        w.done.connect(done)
        w.error.connect(self._errored)
        w.start()

    def _release(self) -> None:
        w, self.worker = self.worker, None
        if w is not None:
            w.deleteLater()

    @pyqtSlot(object)
    def _planned(self, up) -> None:
        self._release()
        self.plan = up
        self.out.setPlainText(undo_summary(up))
        self.status.setText("ready — nothing written yet")
        self._busy(False)

    @pyqtSlot(str)
    def _errored(self, msg: str) -> None:
        self._release()
        self._busy(False)
        self._fail(msg.split("\n\n")[0])

    def _apply(self) -> None:
        if self.worker is not None or self.plan is None:
            return
        if not self.headless and QMessageBox.question(
                self, "Undo backport",
                f"{self.plan.count} edit(s) will be reversed in\n{self.game_edit.text().strip()}\n\nContinue?"
                + ("\n\nFORCE is on: files that no longer match are overwritten." if self.force.isChecked() else "")
        ) != QMessageBox.StandardButton.Yes:
            return
        self.status.setText("undoing…")
        self._busy(True)
        up, self.plan = self.plan, None
        self._start(FuncWorker(_apply, Path(self.game_edit.text().strip()).expanduser(), up), self._applied)

    @pyqtSlot(object)
    def _applied(self, res) -> None:
        self._release()
        self.result = str(res)
        self.out.appendPlainText("\ndone — the game folder is back to its state before the backport")
        self.status.setText("done")
        self._busy(False)
        self.applied = True

    def reject(self) -> None:                                # noqa: D102 — never close under a running worker
        if self.worker is not None and self.worker.isRunning():
            self.worker.wait(30000)
        super().reject()


def _learn(orig: Path, kit: Path, recipe: bool, out: Path) -> str:
    from ..core.learn import learn_report
    return "\n".join(learn_report(orig, kit, recipe, out))


class LearnDialog(QDialog):
    """`ps5bp kit learn`: explain a kit's edits against the original dump; optionally write recipes."""

    def __init__(self, parent, original: str = "", headless: bool = False) -> None:
        super().__init__(parent)
        self.setWindowTitle("Learn from kit")
        self.resize(820, 600)
        self.headless = headless
        self.worker: FuncWorker | None = None
        self.last_error = ""
        v = QVBoxLayout(self)
        self.orig_edit = self._row(v, "Original dump:", original)
        self.kit_edit = self._row(v, "Backport kit folder:", "")
        self.recipe = QCheckBox("Write the unexplained edits as per-game recipe file(s) (--recipe) into:")
        self.out_edit = QLineEdit(str(Path.home()))
        self.out_edit.setEnabled(False)
        self.recipe.toggled.connect(self.out_edit.setEnabled)
        r = QHBoxLayout()
        r.addWidget(self.recipe)
        r.addWidget(self.out_edit, 1)
        b = QPushButton("Browse…")
        b.clicked.connect(lambda: self._pick(self.out_edit))
        r.addWidget(b)
        v.addLayout(r)
        self.report = QPlainTextEdit()
        self.report.setReadOnly(True)
        self.report.setFont(QFont("monospace"))
        v.addWidget(self.report, 1)
        r = QHBoxLayout()
        self.status = QLabel()
        r.addWidget(self.status, 1)
        self.run_btn = QPushButton("Learn")
        self.run_btn.clicked.connect(self._run)
        r.addWidget(self.run_btn)
        b = QPushButton("Close")
        b.clicked.connect(self.reject)
        r.addWidget(b)
        v.addLayout(r)

    def _row(self, v: QVBoxLayout, label: str, text: str) -> QLineEdit:
        r = QHBoxLayout()
        r.addWidget(QLabel(label))
        e = QLineEdit(text)
        r.addWidget(e, 1)
        b = QPushButton("Browse…")
        b.clicked.connect(lambda: self._pick(e))
        r.addWidget(b)
        v.addLayout(r)
        return e

    def _pick(self, e: QLineEdit) -> None:
        d = QFileDialog.getExistingDirectory(self, "Folder", e.text())
        if d:
            e.setText(d)

    def _run(self) -> None:
        if self.worker is not None:
            return
        orig, kit = Path(self.orig_edit.text().strip()).expanduser(), Path(self.kit_edit.text().strip()).expanduser()
        self.last_error = ""
        if not (self.orig_edit.text().strip() and self.kit_edit.text().strip() and orig.is_dir() and kit.is_dir()):
            self.last_error = "Choose the original dump folder and the backport kit folder."
            self.status.setText(self.last_error)
            if not self.headless:
                QMessageBox.warning(self, "Learn from kit", self.last_error)
            return
        out = Path(self.out_edit.text().strip() or ".").expanduser()
        self.run_btn.setEnabled(False)
        self.status.setText("comparing…")
        w = self.worker = FuncWorker(_learn, orig, kit, self.recipe.isChecked(), out)
        w.done.connect(self._done)
        w.error.connect(self._failed)
        w.start()

    def _release(self) -> None:
        w, self.worker = self.worker, None
        self.run_btn.setEnabled(True)
        if w is not None:
            w.deleteLater()

    @pyqtSlot(object)
    def _done(self, text) -> None:
        self._release()
        self.report.setPlainText(text)
        self.status.setText("done")

    @pyqtSlot(str)
    def _failed(self, msg: str) -> None:
        self._release()
        self.last_error = msg.split("\n\n")[0]
        self.report.setPlainText(msg)
        self.status.setText("failed")
        if not self.headless:
            QMessageBox.critical(self, "Learn from kit", self.last_error)

    def reject(self) -> None:                                # noqa: D102
        if self.worker is not None and self.worker.isRunning():
            self.worker.wait(60000)
        super().reject()
