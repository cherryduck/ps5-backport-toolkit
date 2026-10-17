"""Background workers. Each opens its own EvidenceDB: sqlite connections are per-thread."""
from __future__ import annotations

import threading
import traceback
from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal

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
    """add (src, fw, name, source, tested_fw), remove (name) or reindex (names) kits."""
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
            elif self.action == "reindex":
                res = db.reindex(self.kw.get("names") or None)
                self.done.emit("libc reindex:\n" + "\n".join(f"{n:32} {m}" for n, m in res.items())
                               if res else "libc reindex: no kits")
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


class ConsoleBridge(QObject):
    """Runs the klog stream (+ optional crash-dump watcher) on their own threads and relays
    everything to the GUI thread as signals. Crash triage (which may disassemble) also runs
    off the GUI thread."""
    line = pyqtSignal(str)
    status = pyqtSignal(str)
    crash = pyqtSignal(str, str, str)        # triage text, saved crash file, raw block
    dump_event = pyqtSignal(str)
    captured = pyqtSignal(object)            # console.Captured
    loop = pyqtSignal(str, str)              # loop diagnosis text, saved loop file

    def __init__(self, host: str, klog_port: int, ftp_port: int, game: str, flags: list[str],
                 crash_dir: Path, dumps_dir: Path | None):
        super().__init__()
        from ..core import console
        self._c = console
        self.game, self.flags, self.crash_dir = game, flags, crash_dir
        self.detector = console.CrashDetector()
        self.loops = console.LoopDetector()
        self.watcher = None
        if dumps_dir is not None:
            self.watcher = console.CoreDumpWatcher(host, dumps_dir, port=ftp_port,
                                                   on_event=self.dump_event.emit,
                                                   on_captured=self.captured.emit)
        self.stream = console.KlogStream(host, klog_port, on_line=self._on_line, on_status=self.status.emit)

    def _on_line(self, ln: str) -> None:
        self.line.emit(ln)
        if self.watcher and self._c.DUMP_ANNOUNCE.search(ln):
            self.watcher.wake()
        ev = self.loops.feed(ln)
        if ev:
            try:
                text = self._c.loop_text(ev, self.game or None, self.flags)
                saved = self._c.save_loop(text, self.crash_dir)
            except Exception as e:                               # noqa: BLE001
                text, saved = f"loop diagnosis failed: {e}", ""
            self.loop.emit(text, str(saved))
        block = self.detector.feed(ln)
        if block:
            try:
                text = self._c.triage_text(block, self.game or None, self.flags)
                saved = self._c.save_crash(block, self.crash_dir)
            except Exception as e:                               # noqa: BLE001
                text, saved = f"triage failed: {e}", ""
            self.crash.emit(text, str(saved), block)

    def start(self) -> None:
        if self.watcher:
            self.watcher.start()
        self.stream.start()

    def stop(self) -> None:
        self.stream.stop()
        if self.watcher:
            self.watcher.stop()
        for t in (self.stream, self.watcher):
            if t is not None and t.is_alive():
                t.join(3)
