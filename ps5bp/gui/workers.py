"""Background workers. Each opens its own EvidenceDB: sqlite connections are per-thread."""
from __future__ import annotations

import threading
import traceback
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal

from ..core.evidence import EvidenceDB
from ..core.pipeline import BuildCancelled, BuildError, BuildOptions, build, plan


class AnalyzeWorker(QThread):
    plan_ready = pyqtSignal(object)          # Plan
    progress = pyqtSignal(str, int, int)
    error = pyqtSignal(str)

    def __init__(self, game: Path, target: int, patches: list[Path], replace_dump: dict | None = None):
        super().__init__()
        self.game, self.target, self.patches = game, target, patches
        self.replace_dump = replace_dump or {}

    def run(self) -> None:
        db = None
        try:
            db = EvidenceDB()
            self.plan_ready.emit(plan(self.game, self.target, db, self.patches, progress=self.progress.emit,
                                      replace_dump=self.replace_dump))
        except Exception as e:                                   # noqa: BLE001
            self.error.emit(f"{e}\n\n{traceback.format_exc()}")
        finally:
            if db:
                db.close()


class BuildWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(str, int, int)
    build_finished = pyqtSignal(object)      # BuildReport (not `finished`: that shadows QThread.finished)
    cancelled = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, game: Path, opts: BuildOptions):
        super().__init__()
        self.game, self.opts = game, opts
        self._cancel = threading.Event()

    def stop(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        db = None
        try:
            db = EvidenceDB() if self.opts.fakelibs else None
            rep = build(self.game, self.opts, db, log=self.log.emit, cancel=self._cancel,
                        progress=self.progress.emit)
            self.build_finished.emit(rep)
        except BuildCancelled:
            self.cancelled.emit()
        except BuildError as e:
            self.error.emit(str(e))
        except Exception as e:                                   # noqa: BLE001
            self.error.emit(f"{e}\n\n{traceback.format_exc()}")
        finally:
            if db:
                db.close()


class KitWorker(QThread):
    """add (src, fw, name, source) or remove (name) a kit."""
    done = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, action: str, **kw):
        super().__init__()
        self.action, self.kw = action, kw

    def run(self) -> None:
        db = None
        try:
            db = EvidenceDB()
            if self.action == "add":
                r = db.add_kit(self.kw["src"], self.kw["fw"], self.kw.get("name") or None,
                               self.kw.get("source", ""), tested_fw=self.kw.get("tested_fw"))
                self.done.emit(f"kit added: {r}")
            else:
                ok = db.remove_kit(self.kw["name"])
                self.done.emit(f"kit {self.kw['name']} {'removed' if ok else 'not found'}")
        except Exception as e:                                   # noqa: BLE001
            self.error.emit(str(e))
        finally:
            if db:
                db.close()


class FuncWorker(QThread):
    """Run fn(*args) off the UI thread (memfix site scan)."""
    done = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, fn, *args):
        super().__init__()
        self.fn, self.args = fn, args

    def run(self) -> None:
        try:
            self.done.emit(self.fn(*self.args))
        except Exception as e:                                   # noqa: BLE001
            self.error.emit(f"{e}\n\n{traceback.format_exc()}")
