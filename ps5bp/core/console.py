"""Talk to a console running user-supplied payloads (pure stdlib).

* ELF loader (elfldr and compatible)  TCP 9021: connect, send the raw ELF, close.
* klogsrv                             TCP 3232: plain-text kernel log, one line per '\\n'.
* ftpsrv                              FTP 2121, anonymous: used to fetch the crash dump folder
  ``/user/devlog/system/sce_coredumps.0/<TITLEID>_<n>/`` (``report.log`` first, a
  ``.prosperodmp`` later). The console deletes that folder when the crash screen closes,
  so :class:`CoreDumpWatcher` copies it as soon as it appears.

Payloads are never bundled; the caller supplies the file.
"""
from __future__ import annotations

import ftplib
import re
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ELF_PORT = 9021
KLOG_PORT = 3232
FTP_PORT = 2121
COREDUMP_ROOT = "/user/devlog/system/sce_coredumps.0"

# a klog line announcing a dump: wakes the watcher immediately
DUMP_ANNOUNCE = re.compile(r"\[CRS\]\[coredump_seq\] prepare\(\).*?path=(\S+?\.prosperodmp)")


# ---- payload sender --------------------------------------------------------------------------
def send_payload(host: str, path: str | Path, port: int = ELF_PORT, timeout: float = 10.0) -> int:
    """Send the file's raw bytes to the ELF loader. Returns the number of bytes sent."""
    data = Path(path).read_bytes()
    if not data:
        raise ValueError(f"{path} is empty")
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(data)
        try:
            s.shutdown(socket.SHUT_WR)         # tell the loader the ELF is complete
        except OSError:
            pass
    return len(data)


# ---- klog stream -----------------------------------------------------------------------------
class KlogStream(threading.Thread):
    """Connect to klogsrv and call on_line(str) per line; reconnect after `retry` seconds."""

    def __init__(self, host: str, port: int = KLOG_PORT,
                 on_line: Callable[[str], None] | None = None,
                 on_status: Callable[[str], None] | None = None,
                 retry: float = 2.0, connect_timeout: float = 5.0):
        super().__init__(daemon=True, name="klog-stream")
        self.host, self.port, self.retry, self.connect_timeout = host, port, retry, connect_timeout
        self.on_line = on_line or (lambda s: None)
        self.on_status = on_status or (lambda s: None)
        self._stop_ev = threading.Event()
        self._sock: socket.socket | None = None
        self.connections = 0

    def stop(self) -> None:
        self._stop_ev.set()
        s = self._sock
        if s is not None:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    @property
    def stopped(self) -> bool:
        return self._stop_ev.is_set()

    def run(self) -> None:
        while not self._stop_ev.is_set():
            try:
                self.on_status(f"connecting to {self.host}:{self.port}")
                s = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
            except OSError as e:
                self.on_status(f"connect failed: {e}")
                self._stop_ev.wait(self.retry)
                continue
            self._sock = s
            self.connections += 1
            s.settimeout(1.0)
            self.on_status("connected")
            buf = b""
            try:
                while not self._stop_ev.is_set():
                    try:
                        chunk = s.recv(65536)
                    except socket.timeout:
                        continue
                    if not chunk:
                        break
                    buf += chunk
                    *lines, buf = buf.split(b"\n")
                    for ln in lines:
                        self.on_line(ln.decode("utf-8", errors="replace").rstrip("\r"))
                if buf and not self._stop_ev.is_set():
                    self.on_line(buf.decode("utf-8", errors="replace").rstrip("\r"))
            except OSError as e:
                if not self._stop_ev.is_set():
                    self.on_status(f"connection error: {e}")
            finally:
                self._sock = None
                try:
                    s.close()
                except OSError:
                    pass
            if not self._stop_ev.is_set():
                self.on_status("disconnected; retrying")
                self._stop_ev.wait(self.retry)
        self.on_status("stopped")


# ---- crash detector --------------------------------------------------------------------------
class CrashDetector:
    """Accumulates klog lines; feed() returns the text of a completed /app0/ fatal-signal block.

    The block starts at "A user thread receives a fatal signal" (or a '# reason:' header) and
    ends at the "mDBG: Sending signal" / "App Crash" line, exactly as klog.parse reads it.
    The returned text also carries recent launch lines so the title id resolves. Whether the
    block is a game crash is decided by klog.parse itself (a loaded module or the process
    under /app0/).
    """

    MAX_BLOCK = 600

    def __init__(self, context: int = 400):
        self._block: list[str] | None = None
        self._ctx: deque[str] = deque(maxlen=context)

    @staticmethod
    def _starts(line: str) -> bool:
        return "A user thread receives a fatal signal" in line or bool(re.match(r"#\s*reason:", line))

    @staticmethod
    def _ends(line: str) -> bool:
        return line.startswith("mDBG: Sending signal") or "App Crash" in line

    def feed(self, line: str) -> str | None:
        out = None
        if self._block is None:
            if self._starts(line):
                self._block = [line]
            elif re.search(r"launchApp\(|notifyAppCrash\(\)|EXEC /app0/eboot\.bin", line):
                self._ctx.append(line)
        else:
            if self._starts(line) and line.lstrip("# ").startswith("A user thread") and len(self._block) > 1:
                out = self._finish()            # a new block began without a terminator
                self._block = [line]
                return out
            self._block.append(line)
            if self._ends(line) or len(self._block) > self.MAX_BLOCK:
                out = self._finish()
        return out

    def flush(self) -> str | None:
        return self._finish() if self._block else None

    def _finish(self) -> str | None:
        block, self._block = self._block or [], None
        text = "\n".join(list(self._ctx) + block) + "\n"
        from . import klog
        t = klog.parse(text)
        if not t.crashes:
            return None
        c = t.crashes[-1]
        if not any(m.in_app for m in c.modules):      # not a game (/app0/) process
            return None
        return text


# ---- loop / hang detector --------------------------------------------------------------------
_PFX = re.compile(r"^\s*<\d+>\s*")
_ERRISH = re.compile(r"\b(error|errors|fail|failed|failure|unresolved|not found|invalid|cannot|can't|abort|"
                     r"assert\w*|exception|fatal|timeout|timed out|rejected)\b|\b0x8[0-9a-f]{7}\b", re.I)


def normalise(line: str) -> str:
    """A line with the <NNN> priority prefix, numbers and number lists replaced, so the same message
    compares equal from one pass to the next (timestamps, counters, rotating id histories)."""
    s = _PFX.sub("", line).strip()
    s = re.sub(r"\d+", "#", s)
    return re.sub(r"#(?:\s*,\s*#)+", "#", s)


def looks_stuck(lines: list[str]) -> bool:
    """A repeating group of lines only counts as a hang when the klog itself explains something in it
    (a libSceSaveData failure, an Ampr index problem) or it contains a warning/error-looking line.
    A periodic benign line (heartbeat, stats) never triggers."""
    from . import klog
    text = "\n".join(lines)
    t = klog.parse(text)
    return bool(t.issues or t.ampr_findings or _ERRISH.search(text))


@dataclass
class LoopEvent:
    window: list[str]          # one pass through the loop (raw lines)
    repeats: int               # passes seen when it was reported
    recent: list[str]          # the repeated passes (raw lines)

    def text(self) -> str:
        return "\n".join(self.recent) + "\n"


class LoopDetector:
    """feed(line) -> LoopEvent when the stream is cycling: the last K (1..max_window) normalised lines
    repeat `min_repeats` times in a row (6 for K=1: one line alone must repeat more) and the loop is
    not benign (looks_stuck). Reported once per loop; re-armed after `rearm` consecutive lines that do
    not belong to the loop (the stream moved on). Keeps the last `buffer` raw lines for Diagnose-now."""

    def __init__(self, min_repeats: int = 3, max_window: int = 30, buffer: int = 2000, rearm: int = 5):
        self.min_repeats, self.max_window, self.rearm = min_repeats, max_window, rearm
        self.raw: deque[str] = deque(maxlen=buffer)
        self._norm: deque[str] = deque(maxlen=max(buffer, 6 * max_window + 8))
        self._active: frozenset | None = None
        self._miss = 0

    def recent(self) -> list[str]:
        return list(self.raw)

    def feed(self, line: str) -> LoopEvent | None:
        n = normalise(line)
        self.raw.append(line)
        self._norm.append(n)
        if self._active is not None:
            self._miss = 0 if n in self._active else self._miss + 1
            if self._miss < self.rearm:
                return None
            self._active, self._miss = None, 0
        if not n:
            return None
        seq = self._norm
        L = len(seq)
        for k in range(1, self.max_window + 1):
            reps = 6 if k == 1 else self.min_repeats
            if L < reps * k or seq[-1] != seq[-1 - k]:
                continue
            tail = [seq[i] for i in range(L - reps * k, L)]
            w = tail[-k:]
            if tail != w * reps:
                continue
            if k > 1 and any(w[i:] + w[:i] == w for i in range(1, k) if k % i == 0):
                continue                                   # a shorter period exists: found at a smaller k
            raw = list(self.raw)[-reps * k:]
            if not looks_stuck(raw):
                continue
            self._active, self._miss = frozenset(w), 0
            return LoopEvent(raw[-k:], reps, raw)
        return None


def loop_text(ev: LoopEvent, game: str | Path | None = None, flags: list[str] | None = None) -> str:
    head = (f"game looks stuck in a loop: {len(ev.window)} line(s) repeated {ev.repeats}x and counting\n"
            "one pass:\n" + "".join(f"   {x}\n" for x in ev.window) + "\n")
    return head + triage_text(ev.text(), game, flags)


def diagnose_recent(lines: list[str], game: str | Path | None = None, flags: list[str] | None = None) -> str:
    """The `Diagnose now` button: explain the buffered recent log (crash triage if a crash block is in it,
    log-line problems otherwise)."""
    if not lines:
        return "nothing to diagnose yet: no console log lines received\n"
    return f"diagnosis of the last {len(lines)} log line(s)\n\n" + triage_text("\n".join(lines) + "\n", game, flags)


def save_loop(text: str, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = time.strftime("loop-%Y%m%d-%H%M%S")
    p = out / f"{base}.txt"
    n = 1
    while p.exists():
        p = out / f"{base}-{n}.txt"
        n += 1
    p.write_text(text)
    return p


def triage_text(block: str, game: str | Path | None = None, flags: list[str] | None = None) -> str:
    """Parse + (optionally symbolize) + diagnose a crash block with the existing klog code."""
    from . import klog
    t = klog.parse(block)
    if game:
        try:
            klog.symbolize(t, Path(game))
        except Exception as e:                           # noqa: BLE001
            t.suggestions.append(f"could not resolve the backtrace against {game}: {e}")
    klog.diagnose(t, flags)
    return t.to_text()


def save_crash(block: str, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = out / time.strftime("crash-%Y%m%d-%H%M%S")
    p = base.with_suffix(".txt")
    n = 1
    while p.exists():
        p = out / f"{base.name}-{n}.txt"
        n += 1
    p.write_text(block)
    return p


def latest_crash(path: str | Path) -> Path | None:
    """A crash file, or the newest crash-*.txt in a folder."""
    p = Path(path)
    if p.is_file():
        return p
    files = sorted(p.glob("crash-*.txt"), key=lambda f: (f.stat().st_mtime, f.name)) if p.is_dir() else []
    return files[-1] if files else None


# ---- FTP helpers + core dump watcher ---------------------------------------------------------
@dataclass
class Entry:
    name: str
    is_dir: bool
    size: int


def parse_list(lines: list[str]) -> list[Entry]:
    """Parse unix-style LIST lines (ftpsrv has no NLST): perms links owner group size date... name."""
    out = []
    for ln in lines:
        parts = ln.rstrip("\r\n").split(None, 8)
        if len(parts) < 9 or not re.match(r"^[\-dlbcps][rwxsStT\-]{9}", parts[0]):
            continue
        # date is 3 tokens ("Jan 1 12:00"); the name is everything after, spaces included
        m = re.match(r"^\S+\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+\S+\s(.*)$", ln.rstrip("\r\n"))
        if not m:
            continue
        name = m.group(2)
        if name in (".", ".."):
            continue
        out.append(Entry(name, parts[0][0] == "d", int(m.group(1))))
    return out


def ftp_connect(host: str, port: int = FTP_PORT, timeout: float = 15.0) -> ftplib.FTP:
    f = ftplib.FTP()
    f.connect(host, port, timeout=timeout)
    f.login("anonymous", "anonymous@")
    f.set_pasv(True)
    return f


def ftp_list(f: ftplib.FTP, path: str) -> list[Entry] | None:
    """Entries of a remote dir; None when it does not exist (550)."""
    lines: list[str] = []
    try:
        f.retrlines("LIST " + path, lines.append)
    except ftplib.error_perm as e:
        if str(e).startswith("550"):
            return None
        raise
    return parse_list(lines)


@dataclass
class Captured:
    folder: str
    out_dir: Path
    files: list[Path] = field(default_factory=list)
    complete: bool = False          # .prosperodmp saved
    vanished: bool = False
    notes: list[str] = field(default_factory=list)


class CoreDumpWatcher(threading.Thread):
    """Poll the coredump root over FTP; copy every NEW crash folder into out_dir/<folder>/.

    Folders present when the watcher starts are left alone. on_event(str) reports progress,
    on_captured(Captured) fires once per folder when done (complete, vanished or timed out).
    wake() (e.g. on a klog line matching DUMP_ANNOUNCE) triggers an immediate poll.
    """

    def __init__(self, host: str, out_dir: str | Path, port: int = FTP_PORT,
                 on_event: Callable[[str], None] | None = None,
                 on_captured: Callable[[Captured], None] | None = None,
                 root: str = COREDUMP_ROOT, poll: float = 2.0, dump_timeout: float = 120.0,
                 retries: int = 3, timeout: float = 15.0):
        super().__init__(daemon=True, name="coredump-watcher")
        self.host, self.port, self.root = host, port, root.rstrip("/")
        self.out_dir = Path(out_dir)
        self.on_event = on_event or (lambda s: None)
        self.on_captured = on_captured or (lambda c: None)
        self.poll, self.dump_timeout, self.retries, self.timeout = poll, dump_timeout, retries, timeout
        self._stop_ev = threading.Event()
        self._wake = threading.Event()
        self.ready = threading.Event()          # baseline taken
        self._seen: set[str] = set()
        self._baselined = False
        self._f: ftplib.FTP | None = None

    def stop(self) -> None:
        self._stop_ev.set()
        self._wake.set()

    def wake(self) -> None:
        self._wake.set()

    def _sleep(self) -> None:
        self._wake.wait(self.poll)
        self._wake.clear()

    def _close(self) -> None:
        if self._f is not None:
            try:
                self._f.close()
            except Exception:                            # noqa: BLE001
                pass
        self._f = None

    def _conn(self) -> ftplib.FTP:
        if self._f is None:
            self._f = ftp_connect(self.host, self.port, self.timeout)
        return self._f

    def run(self) -> None:
        last_err = ""
        while not self._stop_ev.is_set():
            try:
                ents = ftp_list(self._conn(), self.root)
                names = {e.name for e in ents or [] if e.is_dir}
                if not self._baselined:
                    self._seen = set(names)
                    self._baselined = True
                    self.ready.set()
                    self.on_event(f"watching {self.root} ({len(names)} existing folder(s) ignored)")
                for n in sorted(names - self._seen):
                    if self._stop_ev.is_set():
                        break
                    self._seen.add(n)
                    self.on_event(f"new crash folder {n}")
                    self._capture(n)
                last_err = ""
            except (OSError, ftplib.Error, EOFError) as e:
                if str(e) != last_err:
                    self.on_event(f"ftp: {e}")
                    last_err = str(e)
                self._close()
            if not self._stop_ev.is_set():
                self._sleep()
        self._close()

    # ---- one folder
    def _capture(self, name: str) -> None:
        cap = Captured(name, self.out_dir / name)
        cap.out_dir.mkdir(parents=True, exist_ok=True)
        remote = f"{self.root}/{name}"
        saved: dict[str, int] = {}               # file -> bytes saved
        last_size: dict[str, int] = {}
        t0 = time.monotonic()
        t_report: float | None = None
        fails = 0
        while not self._stop_ev.is_set():
            try:
                ents = ftp_list(self._conn(), remote)
                if ents is None:
                    cap.vanished = True
                    cap.notes.append("folder disappeared (crash screen closed?)")
                    break
                files = {e.name: e.size for e in ents if not e.is_dir}
                if "report.log" in files and t_report is None:
                    t_report = time.monotonic()
                for fname, size in sorted(files.items()):
                    if saved.get(fname) == size:
                        continue
                    stable = last_size.get(fname) == size
                    last_size[fname] = size
                    if fname.endswith(".prosperodmp") and not stable:
                        continue                 # still being written: wait for two equal sizes
                    got = self._download(remote, fname, cap)
                    if got is not None:
                        saved[fname] = got
                fails = 0
                if any(n.endswith(".prosperodmp") and saved[n] == files.get(n) for n in saved):
                    cap.complete = True
                    break
            except (OSError, ftplib.Error, EOFError) as e:
                fails += 1
                self._close()
                self.on_event(f"{name}: ftp error: {e}")
                if fails >= self.retries:
                    cap.notes.append(f"ftp error: {e}")
                    break
            if time.monotonic() - (t_report if t_report is not None else t0) > self.dump_timeout:
                cap.notes.append(f"no .prosperodmp within {self.dump_timeout:g}s")
                break
            self._sleep()
        cap.files = sorted(p for p in cap.out_dir.iterdir() if p.suffix != ".partial")
        self.on_event(f"{name}: saved {len(cap.files)} file(s)" + ("" if cap.complete else " (no core dump)")
                      + ("; " + "; ".join(cap.notes) if cap.notes else ""))
        self.on_captured(cap)

    def _download(self, remote: str, fname: str, cap: Captured) -> int | None:
        dest = cap.out_dir / fname
        part = cap.out_dir / (fname + ".partial")
        for attempt in range(1, self.retries + 1):
            try:
                with open(part, "wb") as fh:
                    self._conn().retrbinary(f"RETR {remote}/{fname}", fh.write)
                part.replace(dest)
                size = dest.stat().st_size
                self.on_event(f"saved {fname} ({size} bytes)")
                return size
            except ftplib.error_perm as e:
                part.unlink(missing_ok=True)
                cap.notes.append(f"{fname} vanished before it could be read" if str(e).startswith("550")
                                 else f"{fname}: {e}")
                return None
            except (OSError, ftplib.Error, EOFError) as e:
                part.unlink(missing_ok=True)
                self._close()
                self.on_event(f"{fname}: attempt {attempt} failed: {e}")
                if attempt == self.retries:
                    cap.notes.append(f"{fname}: gave up after {attempt} attempts")
                    return None
                time.sleep(0.1)
        return None
