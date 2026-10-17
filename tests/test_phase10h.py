"""Phase 10h: savedata-mount leaves read-only mounts alone; klog explains ordinary lines; loop detector."""
import os
import time
from pathlib import Path

import pytest

from ps5bp import cli
from ps5bp.core import console, klog
from ps5bp.core.binary import Binary
from test_phase9 import MODE_RO, MODE_VAR, mount_game
from test_console import servers  # noqa: F401
from test_phase10cb import game, run, statuses
from synth import TEXT_VA

KH = (Path(__file__).parent / "data/kh_savedata_loop.log").read_text().splitlines()
B = 0x400000


# ---- item 1 ---------------------------------------------------------------------------------
def test_readonly_mount_reported_not_patched(tmp_path):
    from ps5bp.core.rules.savedata_mount import SavedataMount, sites
    g, store = mount_game(tmp_path / "ro", MODE_RO)
    (s,) = sites(Binary.load(g / "eboot.bin"), B)
    assert s["state"] == "unfixed" and s["mode"] == 1          # still detected...
    ((st, f),) = statuses(g, "savedata-mount")
    assert st is None and not f.applicable and "read-only" in f.reason and "0x809f8032" in f.reason
    rep, frs = run(g, tmp_path / "ro", "savedata-mount")
    assert not [e for e in rep.edits if e.kind == "rule:savedata-mount"]    # ...but never written
    assert Binary.load(tmp_path / "ro/out/eboot.bin").read(TEXT_VA + store + 4, 4) == b"\xff\xff\xff\xff"


def test_create_and_unknown_mode_still_patched(tmp_path):
    for n, mode in (("var", MODE_VAR), ("w", bytes.fromhex("c745a020000000"))):      # unknown / constant 0x20
        g, _ = mount_game(tmp_path / n, mode)
        ((st, f),) = statuses(g, "savedata-mount")
        assert st is None and f.applicable and f.data["len"] == 8, n
        rep, _ = run(g, tmp_path / n, "savedata-mount")
        assert [e.new for e in rep.edits if e.kind == "rule:savedata-mount"] == ["00000000"], n


def test_learn_readonly_kit_zero_still_explained(tmp_path):
    from ps5bp.core.learn import learn
    g, store = mount_game(tmp_path / "o", MODE_RO)
    k, _ = mount_game(tmp_path / "k", MODE_RO, b"\0\0\0\0")
    reps, recipes = learn(g, k, "PPSA99999")
    (r,) = [r for r in reps if r.file == "eboot.bin"]
    assert r.classes.get("savedata") == 4 and not r.edits and not recipes
    assert any("read-only site, ps5bp leaves it" in n for n in r.notes)


KH_GAME = Path("/home/cherryduck/Downloads/[DLPSGAME.COM]-PPSA35909-DUPLEX/[DLPSGAME.COM]-PPSA35909-DUPLEX/"
               "PPSA35909-app0_KINGDOM_HEARTS_HD_2.8_FINAL_CHAPTER")


@pytest.mark.skipif(not KH_GAME.is_dir(), reason="real KH folder not present")
def test_real_kh_readonly_sites_not_patched():
    from ps5bp.core.rules.savedata_mount import sites
    ro = {"eboot.bin": 0x4b9dd3, "kh3d.elf": 0x5ba1b3}
    for rel, call in ro.items():
        p = KH_GAME / rel
        if not p.is_file():
            continue
        ss = sites(Binary.load(p), B if rel == "eboot.bin" else 0)
        assert [s["mode"] for s in ss if s["call"] == call] == [1]


# ---- item 2 ---------------------------------------------------------------------------------
def test_klog_explains_kh_lines_without_crash():
    t = klog.parse("\n".join(KH * 3))
    klog.diagnose(t)
    txt = t.to_text()
    assert any("CUSA05795-Launcher28US" in i and "0x809f8032" in i and "rejected by this firmware" in i
               and "read-only" in i and "systemBlocks=0" in i and "[repeated 3x]" in i for i in t.issues)
    assert klog.SAVEDATA_RO_FIX in t.suggestions
    assert "no fatal-signal block found" in txt and "problems found in the log lines" in txt


def test_klog_rw_mount_no_ro_advice_and_known_noise():
    rw = [x.replace("mountMode=0x00000001", "mountMode=0x00000006") for x in KH]
    t = klog.parse("\n".join(rw))
    assert t.issues and not t.suggestions
    t = klog.parse("<118>[libSceSaveData] Failed to mount X(0x809f8022)\n")
    assert not t.issues and t.noise                       # not created yet stays noise
    t = klog.parse("<118>[libSceSaveData] Failed to mount X(0x809f0008)\n"
                   "<118>[libSceSaveData] GetResult : ExecResult : 0x809f1234(api_id=77)\n")
    assert any("not found" in i for i in t.issues)
    assert any("0x809f1234" in i and "api_id=77" in i for i in t.issues)


def test_cli_klog_crashless_log_prints_issues(tmp_path, capsys):
    f = tmp_path / "k.log"
    f.write_text("\n".join(KH) + "\n")
    assert cli.main(["klog", str(f)]) == 0
    out = capsys.readouterr().out
    assert "no fatal-signal block" in out and "0x809f8032" in out and "systemBlocks=0" in out


# ---- item 3 ---------------------------------------------------------------------------------
def feed_all(det, lines):
    return [e for e in map(det.feed, lines) if e]


def test_loop_true_positive_once_and_rearms():
    det = console.LoopDetector()
    evs = feed_all(det, KH * 10)
    assert len(evs) == 1 and len(evs[0].window) == 5 and evs[0].repeats == 3
    txt = console.loop_text(evs[0])
    assert "stuck in a loop" in txt and "0x809f8032" in txt and "systemBlocks=0" in txt
    # the stream moves on, then a different loop starts -> a second report
    other = [f"<118>[Foo] load failed code {n % 2}" for n in range(30)]
    evs2 = feed_all(det, [f"<118>normal line {i}" for i in range(8)] + other)
    assert len(evs2) == 1


def test_loop_rotating_id_history_still_matches():
    lines = []
    for i in range(12):
        lines.append(KH[0])
        lines.append(f"<118>[libSceSaveData] GetResult : ExecResult : 0x809f8032(api_id=90) {i} [90,88,{i}]")
        lines += KH[2:]
    assert len(feed_all(console.LoopDetector(), lines)) == 1


def test_benign_periodic_lines_do_not_trigger():
    det = console.LoopDetector()
    assert not feed_all(det, ["<118>[SceShellCore] heartbeat"] * 50)
    assert not feed_all(det, ["<118>[SceShellCore] heartbeat tick 1", "<118>[SceShellCore] stats ok 5"] * 40)
    assert not feed_all(console.LoopDetector(), [f"<118>line {i}" for i in range(200)])


def test_cli_console_klog_reports_loop(tmp_path, servers, capsys):
    import threading
    srv = servers(lambda c, n: c.sendall(("\n".join(KH * 6) + "\n").encode()) or threading.Event().wait(1.5))
    out = tmp_path / "log.txt"
    import threading as th
    t = th.Timer(1.0, lambda: os.kill(os.getpid(), 2))        # Ctrl-C ends the klog command
    t.start()
    try:
        cli.main(["console", "klog", "127.0.0.1", "--port", str(srv.port), "--out", str(out)])
    finally:
        t.cancel()
    o = capsys.readouterr().out
    assert "game looks stuck in a loop" in o and "0x809f8032" in o
    assert len(list(tmp_path.glob("loop-*.txt"))) == 1


def test_save_loop_files(tmp_path):
    a = console.save_loop("x", tmp_path)
    b = console.save_loop("y", tmp_path)
    assert a != b and a.name.startswith("loop-") and sorted(tmp_path.glob("loop-*.txt")) == sorted([a, b])
