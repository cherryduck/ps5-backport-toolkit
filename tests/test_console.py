"""Console tooling against local fake servers (no console needed): klog stream, payload send,
crash detection/triage, and the FTP crash-dump watcher."""
import queue
import socket
import socketserver
import threading
from pathlib import Path

import pytest

from ps5bp import cli
from ps5bp.core import console
from test_klog import LOG

WAIT = 10


# ---- fake servers ----------------------------------------------------------------------------
class TcpServer:
    """Accepts connections; handler(conn, n) runs per connection (n = 1, 2, ...)."""

    def __init__(self, handler):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self.count = 0
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.count += 1
            try:
                self.handler(c, self.count)
            finally:
                c.close()

    def close(self):
        self.sock.close()


@pytest.fixture
def servers():
    made = []

    def mk(h):
        s = TcpServer(h)
        made.append(s)
        return s
    yield mk
    for s in made:
        s.close()


class FakeFS:
    """dirs: {path: {name: bytes | dict-marker}}. Files are bytes; dirs are paths in .dirs."""

    def __init__(self):
        self.lock = threading.Lock()
        self.dirs: dict[str, dict[str, bytes]] = {}

    def listing(self, path):
        with self.lock:
            path = path.rstrip("/")
            if path not in self.dirs:
                return None
            lines = [f"-rw-r--r-- 1 root root {len(b)} Jan  1 00:00 {n}" for n, b in sorted(self.dirs[path].items())]
            sub = {d.rsplit("/", 1)[1] for d in self.dirs if d.rsplit("/", 1)[0] == path and d != path}
            lines += [f"drwxr-xr-x 2 root root 4096 Jan  1 00:00 {n}" for n in sorted(sub)]
            return "\r\n".join(lines) + ("\r\n" if lines else "")

    def read(self, path):
        d, n = path.rsplit("/", 1)
        with self.lock:
            return self.dirs.get(d, {}).get(n)


def make_ftp(fs: FakeFS):
    class H(socketserver.StreamRequestHandler):
        def send(self, s):
            self.wfile.write((s + "\r\n").encode())
            self.wfile.flush()

        def handle(self):
            self.send("220 fake")
            pasv = None
            cwd = "/"
            while True:
                raw = self.rfile.readline()
                if not raw:
                    return
                cmd, _, arg = raw.decode().strip().partition(" ")
                cmd = cmd.upper()
                if cmd == "USER":
                    self.send("331 pw")
                elif cmd == "PASS":
                    self.send("230 ok")
                elif cmd == "TYPE":
                    self.send("200 ok")
                elif cmd == "CWD":
                    if fs.listing(arg) is None:
                        self.send("550 no")
                    else:
                        cwd = arg
                        self.send("250 ok")
                elif cmd == "PASV":
                    pasv = socket.socket()
                    pasv.bind(("127.0.0.1", 0))
                    pasv.listen(1)
                    p = pasv.getsockname()[1]
                    self.send(f"227 Entering Passive Mode (127,0,0,1,{p >> 8},{p & 255})")
                elif cmd in ("LIST", "RETR"):
                    data = fs.listing(arg or cwd) if cmd == "LIST" else fs.read(arg)
                    if data is None:
                        if pasv:
                            pasv.close()
                            pasv = None
                        self.send("550 not found")
                        continue
                    if isinstance(data, str):
                        data = data.encode()
                    self.send("150 go")
                    c, _ = pasv.accept()
                    c.sendall(data)
                    c.close()
                    pasv.close()
                    pasv = None
                    self.send("226 done")
                elif cmd == "QUIT":
                    self.send("221 bye")
                    return
                else:
                    self.send("502 no")

    class S(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    srv = S(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def ftp():
    fs = FakeFS()
    srv = make_ftp(fs)
    root = console.COREDUMP_ROOT
    fs.dirs[root] = {}
    yield fs, srv.server_address[1]
    srv.shutdown()
    srv.server_close()


# ---- payload ---------------------------------------------------------------------------------
def test_send_payload_exact_bytes(tmp_path, servers):
    got = queue.Queue()

    def h(c, n):
        buf = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
        got.put(buf)
    srv = servers(h)
    blob = bytes(range(256)) * 2000
    p = tmp_path / "x.elf"
    p.write_bytes(blob)
    assert console.send_payload("127.0.0.1", p, srv.port) == len(blob)
    assert got.get(timeout=WAIT) == blob


def test_send_payload_errors(tmp_path):
    p = tmp_path / "e.elf"
    p.write_bytes(b"")
    with pytest.raises(ValueError):
        console.send_payload("127.0.0.1", p, 1)
    p.write_bytes(b"x")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(OSError):
        console.send_payload("127.0.0.1", p, port, timeout=1)
    assert cli.main(["console", "send", "127.0.0.1", str(p), "--port", str(port)]) == 1


# ---- klog + crash detection ------------------------------------------------------------------
def test_klog_stream_detects_and_triages_crash(servers):
    lines = ["<118>boot"] + LOG.splitlines() + ["<118>after"]
    srv = servers(lambda c, n: c.sendall(("\n".join(lines) + "\n").encode()))
    det = console.CrashDetector()
    blocks, got, done = [], [], threading.Event()

    def on_line(ln):
        got.append(ln)
        b = det.feed(ln)
        if b:
            blocks.append(b)
        if ln == "<118>after":
            done.set()
    ks = console.KlogStream("127.0.0.1", srv.port, on_line=on_line, retry=0.05)
    ks.start()
    assert done.wait(WAIT)
    ks.stop()
    ks.join(WAIT)
    assert got[0] == "<118>boot" and len(blocks) == 1
    text = console.triage_text(blocks[0])
    assert "exit is called with non-zero" in text and "PPSA99999" in text
    assert "libSceFoo.sprx" in text


def test_save_and_latest_crash(tmp_path):
    a = console.save_crash("one\n", tmp_path)
    b = console.save_crash("two\n", tmp_path)
    assert a != b and a.name.startswith("crash-")
    assert console.latest_crash(tmp_path) in (a, b)
    assert console.latest_crash(a) == a
    assert console.latest_crash(tmp_path / "none") is None


def test_detector_ignores_non_game_crash_and_no_terminator():
    det = console.CrashDetector()
    sys_block = LOG.replace("/app0/", "/system/")
    assert [b for b in map(det.feed, sys_block.splitlines()) if b] == []
    det = console.CrashDetector()
    cut = LOG[:LOG.index("mDBG")].splitlines()
    assert [b for b in map(det.feed, cut) if b] == []
    assert det.flush() is not None            # stream ended mid-block: flushed on demand


def test_klog_reconnects_after_drop(servers):
    def h(c, n):
        c.sendall(f"line{n}\n".encode())
        if n >= 2:
            threading.Event().wait(5)          # hold the second connection open
    srv = servers(h)
    seen = queue.Queue()
    status = []
    ks = console.KlogStream("127.0.0.1", srv.port, on_line=seen.put, on_status=status.append, retry=0.05)
    ks.start()
    assert seen.get(timeout=WAIT) == "line1"
    assert seen.get(timeout=WAIT) == "line2"
    ks.stop()
    ks.join(WAIT)
    assert not ks.is_alive() and ks.connections == 2
    assert any("disconnected" in s for s in status)


def test_cli_klog_exit_after_crash(tmp_path, servers, capsys):
    srv = servers(lambda c, n: c.sendall(LOG.encode()) or threading.Event().wait(5))
    out = tmp_path / "log.txt"
    rc = cli.main(["console", "klog", "127.0.0.1", "--port", str(srv.port), "--out", str(out),
                   "--exit-after-crash"])
    assert rc == 0
    assert "fatal signal" in out.read_text()
    crashes = list(tmp_path.glob("crash-*.txt"))
    assert len(crashes) == 1
    assert "crash detected" in capsys.readouterr().out
    # memfix --from-console resolves the newest crash file
    assert console.latest_crash(tmp_path) == crashes[0]


def test_parse_list():
    ents = console.parse_list([
        "drwxr-xr-x 2 root root 4096 Jan  1 00:00 .",
        "drwxr-xr-x 2 root root 4096 Jan  1 00:00 PPSA01234_5",
        "-rw-r--r-- 1 root root 120 Oct 17 12:30 my report.log",
        "total 3",
    ])
    assert [(e.name, e.is_dir, e.size) for e in ents] == [("PPSA01234_5", True, 4096), ("my report.log", False, 120)]


# ---- coredump watcher ------------------------------------------------------------------------
class Rec:
    def __init__(self):
        self.q = queue.Queue()
        self.events = []

    def on_event(self, m):
        self.events.append(m)

    def on_captured(self, c):
        self.q.put(c)


def start_watcher(fs, port, out, **kw):
    rec = Rec()
    w = console.CoreDumpWatcher("127.0.0.1", out, port=port, on_event=rec.on_event,
                                on_captured=rec.on_captured, poll=0.05, **kw)
    w.start()
    assert w.ready.wait(WAIT)
    return w, rec


def test_watcher_ignores_existing_and_captures_new(tmp_path, ftp):
    fs, port = ftp
    root = console.COREDUMP_ROOT
    fs.dirs[root + "/PPSA00001_1"] = {"report.log": b"old"}
    w, rec = start_watcher(fs, port, tmp_path / "out", dump_timeout=5)
    try:
        core = bytes(range(251)) * 400
        new = root + "/PPSA99999_2"
        fs.dirs[new] = {"report.log": b"report"}
        w.wake()
        fs.dirs[new]["game.prosperodmp"] = core
        w.wake()
        cap = rec.q.get(timeout=WAIT)
    finally:
        w.stop()
        w.join(WAIT)
    assert cap.folder == "PPSA99999_2" and cap.complete and not cap.vanished
    d = tmp_path / "out" / "PPSA99999_2"
    assert (d / "report.log").read_bytes() == b"report"
    assert (d / "game.prosperodmp").read_bytes() == core
    assert not list(d.glob("*.partial"))
    assert not (tmp_path / "out" / "PPSA00001_1").exists()
    assert rec.q.empty()


def test_watcher_handles_vanishing_folder(tmp_path, ftp):
    fs, port = ftp
    root = console.COREDUMP_ROOT
    w, rec = start_watcher(fs, port, tmp_path / "out", dump_timeout=30)
    try:
        new = root + "/PPSA99999_3"
        fs.dirs[new] = {"report.log": b"only the report"}
        w.wake()
        for _ in range(400):                   # wait until report.log has been saved
            if any("saved report.log" in e for e in rec.events):
                break
            threading.Event().wait(0.01)
        with fs.lock:
            del fs.dirs[new]                   # crash screen closed
        cap = rec.q.get(timeout=WAIT)
    finally:
        w.stop()
        w.join(WAIT)
    assert cap.vanished and not cap.complete
    assert [p.name for p in cap.files] == ["report.log"]
    assert (tmp_path / "out" / "PPSA99999_3" / "report.log").read_bytes() == b"only the report"


def test_watcher_timeout_without_dump(tmp_path, ftp):
    fs, port = ftp
    w, rec = start_watcher(fs, port, tmp_path / "out", dump_timeout=0.3)
    try:
        fs.dirs[console.COREDUMP_ROOT + "/PPSA99999_4"] = {"report.log": b"r"}
        w.wake()
        cap = rec.q.get(timeout=WAIT)
    finally:
        w.stop()
        w.join(WAIT)
    assert not cap.complete and any("no .prosperodmp" in n for n in cap.notes)
    assert [p.name for p in cap.files] == ["report.log"]


def test_watcher_tolerates_missing_root(tmp_path, ftp):
    fs, port = ftp
    del fs.dirs[console.COREDUMP_ROOT]
    w, rec = start_watcher(fs, port, tmp_path / "out")
    w.stop()
    w.join(WAIT)
    assert not w.is_alive()


def test_dump_announce_regex():
    m = console.DUMP_ANNOUNCE.search(
        "<118>[CRS][coredump_seq] prepare() ok, path=/user/devlog/system/sce_coredumps.0/PPSA1_1/x.prosperodmp")
    assert m and m.group(1).endswith("x.prosperodmp")


def test_memfix_from_console_uses_newest_crash(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace
    from ps5bp.core import memfix
    seen = {}
    monkeypatch.setattr(cli, "scan_game", lambda g: SimpleNamespace(title_id="PPSA99999", flags=[]))

    def fake_scan(game, f, kt):
        seen["kt"] = kt
        return None, []
    monkeypatch.setattr(memfix, "scan", fake_scan)
    monkeypatch.setattr(memfix, "crash_frames", lambda kt, f: [1])
    old = tmp_path / "crash-20200101-000000.txt"
    new = tmp_path / "crash-20300101-000000.txt"
    old.write_text("old")
    new.write_text("new")
    import os
    os.utime(old, (1, 1))
    assert cli.main(["memfix", str(tmp_path), "--from-console", str(tmp_path)]) == 0
    assert seen["kt"] == "new" and str(new) in capsys.readouterr().out
    assert cli.main(["memfix", str(tmp_path), "--from-console", str(tmp_path / "empty")]) == 2
