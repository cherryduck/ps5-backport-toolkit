"""Phase 10g: ampr_emu.index (AMPRIDX3) reader/writer and its handling in builds, undo, klog, GUI."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ps5bp.core import amprindex as A, klog
from ps5bp.core.pipeline import BuildError, BuildOptions, build
from ps5bp.core.undo import apply_undo, plan_undo
from synth import Spec, build_elf, build_self

REF = Path("/home/cherryduck/ps5-analysis/ampr_emu-ref/tools/build_ampr_index.py")
EMU = Spec(kind="module", module="libSceAmpr", export_libs=["libSceAmpr"], exports=[("AMPRAMPRAM1", 0)],
           import_libs=["libkernel"], imports=[], strings=b"\0" + b"0.3.6.6 (public beta) (c) Drakmor\0")


def put(path: Path, spec: Spec) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_self(build_elf(spec)[0]))


def quiet(m):
    pass


def make_game(tmp_path, emulator=True, name="g") -> Path:
    g = tmp_path / name
    put(g / "eboot.bin", Spec())
    if emulator:
        put(g / "fakelib/libSceAmpr.sprx", EMU)
    for rel, n in (("data/a.pak", 100), ("Media/B.bin", 7), ("données/é.txt", 3)):
        (g / rel).parent.mkdir(parents=True, exist_ok=True)
        (g / rel).write_bytes(b"x" * n)
    (g / "sce_sys").mkdir(exist_ok=True)
    (g / "sce_sys/param.json").write_text('{"sdkVersion": "0x0700000000000000"}')
    return g


def own_index(g: Path) -> bytes:
    return A.build(A.rows_for_tree(A.scan_tree(g)))


def snapshot(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and not p.name.endswith(".orig") and not p.name.startswith("backport-report")}


# ---- format -----------------------------------------------------------------------------------
def test_round_trip_and_layout():
    rows = [("/app0/Zed.bin", 5, 10), ("/app0/a/B.txt", 0, 0), ("/app0/données/é.txt", 9, 1700000000)]
    data = A.build(rows)
    idx = A.parse(data)
    assert [e.path for e in idx.entries] == ["/app0/a/B.txt", "/app0/données/é.txt", "/app0/Zed.bin"]   # key order
    assert {(e.path, e.size, e.mtime) for e in idx.entries} == set(rows)
    magic, ver, rsz, n, blen, hoff, ssz, nslots = A.HEADER.unpack_from(data)
    assert (magic, ver, rsz, n, ssz, nslots) == (b"AMPRIDX3", 3, 24, 3, 16, 8) and hoff % 16 == 0
    assert len(data) == hoff + nslots * 16
    slots = [A.SLOT.unpack_from(data, hoff + i * 16) for i in range(nslots)]
    for i, e in enumerate(idx.entries):
        assert any(s[0] == A.path_hash(e.path) and s[1] == i + 1 for s in slots)


def test_key_ascii_only_and_slot_counts():
    assert A.key_for("/app0/ÄB\\C") == "/app0/Äb/c".encode()        # non-ASCII untouched, '\' -> '/'
    assert A.slot_count(1) == 2 and A.slot_count(5) == 16 and A.slot_count(8) == 16
    assert A.path_hash("/app0/x") != 0


def test_forced_hash_collision_flags(monkeypatch):
    monkeypatch.setattr(A, "path_hash", lambda p: 5)
    slots = A.build_hash_slots(["/app0/a", "/app0/b", "/app0/c"])      # 3 entries -> 8 slots
    mask = len(slots) - 1
    assert [slots[(5 + k) & mask] for k in range(3)] == [(5, 1, 1), (5, 2, 1), (5, 3, 1)]
    assert A.build_hash_slots(["/app0/a"])[5 & 1] == (5, 1, 0)         # no duplicate: no flag


def test_collision_and_skips():
    with pytest.raises(A.AmprIndexError, match="collision"):
        A.build([("/app0/A", 1, 1), ("/app0/a", 2, 2)])
    idx = A.parse(A.build([("/app0/b", 1, 1), ("/app0/B", 2, 2), ("/app0/a\tb", 3, 3)], allow_collisions=True))
    assert len(idx.entries) == 1                                       # tab path skipped, duplicate dropped


def test_parse_rejects_corruption():
    data = A.build([("/app0/a", 1, 1)])
    for bad in (data[:20], b"XXXXXXXX" + data[8:], data[:-16]):
        with pytest.raises(A.AmprIndexError):
            A.parse(bad)


def test_emulator_version(tmp_path):
    put(tmp_path / "a.sprx", EMU)
    assert A.emulator_version(tmp_path / "a.sprx") == "0.3.6.6 (public beta)"
    (tmp_path / "b.sprx").write_bytes(b"\0" + b"0.4.2.1 (c) Drakmor\0")
    assert A.emulator_version(tmp_path / "b.sprx") == "0.4.2.1"
    (tmp_path / "c.sprx").write_bytes(b"nothing")
    assert A.emulator_version(tmp_path / "c.sprx") == "unknown"
    assert A.emulator_version(tmp_path / "none") is None


@pytest.mark.skipif(not REF.is_file(), reason="reference builder not present")
def test_byte_equal_with_reference_builder(tmp_path):
    root = tmp_path / "app0"
    names = ["eboot.bin", "Media/Zed.PAK", "media/sub/dir/File.Dat", "données/é.txt", "ÄÖ/üß.bin", "a b/c.txt",
             "ampr_commands.bin", "APR_EMU.LOG", "UPPER.TXT", "lower.txt", "x/_y", "x/Y"]
    for i, n in enumerate(names):
        p = root / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"d" * (i * 13))
        os.utime(p, (1700000000 + i, 1700000000 + i * 7))
    mine = A.build(A.rows_for_tree(A.scan_tree(root)))
    r = subprocess.run([sys.executable, str(REF), str(root)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (root / "ampr_emu.index").read_bytes() == mine
    assert len(A.parse(mine).entries) == len(names) - 2                # commands + log skipped


# ---- builds ------------------------------------------------------------------------------------
def opts(tmp_path, mode="overlay", **kw) -> BuildOptions:
    return BuildOptions(target=4, mode=mode, out=None if mode == "inplace" else tmp_path / "out", **kw)


def disk_matches(index_file: Path, tree_root: Path):
    d = A.compare(A.read(index_file), A.rows_for_tree(A.scan_tree(tree_root, inplace_backups=True)))
    assert not d, d.summary()


@pytest.mark.parametrize("mode", ["overlay", "full", "inplace"])
def test_no_index_is_created(tmp_path, mode):
    g = make_game(tmp_path)
    rep = build(g, opts(tmp_path, mode), None, log=quiet)
    assert rep.ok and rep.ampr["index"]["action"] == "created"
    assert rep.ampr["emulator"] == {"dump": "0.3.6.6 (public beta)", "chosen": None, "final": "0.3.6.6 (public beta)"}
    root = g if mode == "inplace" else tmp_path / "out"
    assert (root / "ampr_emu.index").is_file()
    if mode == "overlay":                      # the overlay carries the changed files + the index
        assert not (tmp_path / "out.originals/ampr_emu.index").exists()
        merged = tmp_path / "merged"
        shutil.copytree(g, merged)
        shutil.copytree(root, merged, dirs_exist_ok=True)
        disk_matches(root / "ampr_emu.index", merged)
    else:
        disk_matches(root / "ampr_emu.index", root)
    e = [x for x in rep.edits if x.kind == "generated"]
    assert len(e) == 1 and e[0].file == "ampr_emu.index" and e[0].old == ""
    assert rep.outputs["ampr_emu.index"] == e[0].new
    assert "Ampr emulator:" in rep.to_text() and json.loads(rep.to_json())["ampr"]["packs"] is False
    assert not any("ampr" in w.lower() for w in rep.warnings)


def test_no_emulator_no_index(tmp_path):
    g = make_game(tmp_path, emulator=False)
    rep = build(g, opts(tmp_path, "full"), None, log=quiet)
    assert rep.ampr["index"]["action"] == "none" and not (tmp_path / "out/ampr_emu.index").exists()
    assert rep.ampr["emulator"]["final"] is None


@pytest.mark.parametrize("mode", ["overlay", "full", "inplace"])
def test_matching_index_untouched(tmp_path, mode):
    g = make_game(tmp_path)
    orig = own_index(g)
    (g / "ampr_emu.index").write_bytes(orig)
    rep = build(g, opts(tmp_path, mode), None, log=quiet)
    assert rep.ampr["index"]["action"] == "kept"
    assert (g / "ampr_emu.index").read_bytes() == orig and not (g / "ampr_emu.index.orig").exists()
    if mode == "full":
        assert (tmp_path / "out/ampr_emu.index").read_bytes() == orig
    if mode == "overlay":
        assert not (tmp_path / "out/ampr_emu.index").exists()
    assert not [e for e in rep.edits if e.kind == "generated"]


@pytest.mark.parametrize("mode", ["overlay", "full", "inplace"])
def test_stale_index_regenerated_and_undone(tmp_path, mode):
    g = make_game(tmp_path)
    old = own_index(g)
    (g / "ampr_emu.index").write_bytes(old)
    (g / "data/new.pak").write_bytes(b"n" * 50)               # added after the index was made
    start = snapshot(g)
    rep = build(g, opts(tmp_path, mode), None, log=quiet)
    assert rep.ok and rep.ampr["index"]["action"] == "regenerated" and "added" in rep.ampr["index"]["note"]
    root = g if mode == "inplace" else tmp_path / "out"
    new = (root / "ampr_emu.index").read_bytes()
    assert new != old and any(e.path == "/app0/data/new.pak" for e in A.parse(new).entries)
    gen = next(e for e in rep.edits if e.kind == "generated")
    assert gen.old and gen.new and rep.outputs["ampr_emu.index"] == gen.new
    if mode == "overlay":
        assert (tmp_path / "out.originals/ampr_emu.index").read_bytes() == old
        assert (g / "ampr_emu.index").read_bytes() == old     # the game itself is untouched
        shutil.copytree(root, g, dirs_exist_ok=True)           # user copies the overlay over the game
        apply_undo(g, plan_undo(g, [tmp_path / "out"]))
        assert snapshot(g) == start
    elif mode == "inplace":
        assert (g / "ampr_emu.index.orig").read_bytes() == old
        apply_undo(g, plan_undo(g, [g / "backport-report.json"]))
        assert snapshot(g) == start
    else:
        assert (g / "ampr_emu.index").read_bytes() == old


@pytest.mark.parametrize("mode", ["overlay", "inplace"])
def test_undo_deletes_created_index(tmp_path, mode):
    g = make_game(tmp_path)
    start = snapshot(g)
    build(g, opts(tmp_path, mode), None, log=quiet)
    if mode == "overlay":
        shutil.copytree(tmp_path / "out", g, dirs_exist_ok=True)
        rp = tmp_path / "out"
    else:
        rp = g / "backport-report.json"
    assert (g / "ampr_emu.index").is_file()
    apply_undo(g, plan_undo(g, [rp]))
    assert not (g / "ampr_emu.index").exists()
    assert snapshot(g) == start


def test_packs_keep_index_and_warn(tmp_path):
    g = make_game(tmp_path)
    (g / "ampr_assets.index").write_bytes(b"AMPRPAK4")
    old = own_index(g)
    (g / "ampr_emu.index").write_bytes(old)
    (g / "data/new.pak").write_bytes(b"n")
    rep = build(g, opts(tmp_path, "full"), None, log=quiet)
    assert rep.ampr["index"]["action"] == "kept-stale-packs" and rep.ampr["packs"]
    assert (tmp_path / "out/ampr_emu.index").read_bytes() == old
    assert any("PATH SET" in w for w in rep.warnings) and rep.ok
    # sizes-only difference with packs: still kept, still warned
    g2 = make_game(tmp_path, name="g2")
    (g2 / "ampr_assets.index").write_bytes(b"AMPRPAK4")
    (g2 / "ampr_emu.index").write_bytes(own_index(g2))
    (g2 / "data/a.pak").write_bytes(b"y" * 5)
    rep = build(g2, BuildOptions(target=4, out=tmp_path / "out2"), None, log=quiet)
    assert rep.ampr["index"]["action"] == "kept-stale-packs" and any("does NOT match" in w for w in rep.warnings)
    assert not (tmp_path / "out2/ampr_emu.index").exists()


def test_regen_with_packs_refused_unless_force(tmp_path):
    g = make_game(tmp_path)
    (g / "ampr_assets.index").write_bytes(b"AMPRPAK4")
    (g / "ampr_emu.index").write_bytes(own_index(g))
    (g / "data/new.pak").write_bytes(b"n")
    with pytest.raises(BuildError, match="regen refused"):
        build(g, opts(tmp_path, "overlay", ampr_index="regen"), None, log=quiet)
    assert not (tmp_path / "out").exists()                      # refused before writing anything
    rep = build(g, opts(tmp_path, "overlay", ampr_index="regen", force=True), None, log=quiet)
    assert rep.ampr["index"]["action"] == "regenerated"
    # same path set + packs: regen is allowed (file ids unchanged)
    g2 = make_game(tmp_path, name="g2")
    (g2 / "ampr_assets.index").write_bytes(b"AMPRPAK4")
    (g2 / "ampr_emu.index").write_bytes(own_index(g2))
    rep = build(g2, BuildOptions(target=4, out=tmp_path / "o2", ampr_index="regen"), None, log=quiet)
    assert rep.ampr["index"]["action"] == "regenerated"


def test_regen_rewrites_matching_index(tmp_path):
    g = make_game(tmp_path)
    (g / "ampr_emu.index").write_bytes(own_index(g))
    rep = build(g, opts(tmp_path, ampr_index="regen"), None, log=quiet)
    assert rep.ampr["index"]["action"] == "regenerated" and (tmp_path / "out/ampr_emu.index").is_file()


def test_keep_mode(tmp_path):
    g = make_game(tmp_path)
    (g / "ampr_emu.index").write_bytes(own_index(g))
    (g / "data/new.pak").write_bytes(b"n")
    rep = build(g, opts(tmp_path, "full", ampr_index="keep"), None, log=quiet)
    assert rep.ampr["index"]["action"] == "kept-by-option" and any("stale" in w for w in rep.warnings)
    assert (tmp_path / "out/ampr_emu.index").read_bytes() == (g / "ampr_emu.index").read_bytes()
    g2 = make_game(tmp_path, name="g2")
    rep = build(g2, BuildOptions(target=4, out=tmp_path / "o2", ampr_index="keep"), None, log=quiet)
    assert rep.ampr["index"]["action"] == "missing-by-option" and not (tmp_path / "o2/ampr_emu.index").exists()
    with pytest.raises(BuildError):
        build(g2, BuildOptions(target=4, out=tmp_path / "o3", ampr_index="bogus"), None, log=quiet)


def test_unreadable_index_regenerated(tmp_path):
    g = make_game(tmp_path)
    (g / "ampr_emu.index").write_bytes(b"idx")
    rep = build(g, opts(tmp_path), None, log=quiet)
    assert rep.ampr["index"]["action"] == "regenerated" and "unreadable" in rep.ampr["index"]["note"]


def test_sibling_copies_index(tmp_path):
    g = make_game(tmp_path)
    old = own_index(g)
    (g / "ampr_emu.index").write_bytes(old)
    (g / "data/new.pak").write_bytes(b"n")
    rep = build(g, opts(tmp_path, also_targets=[(5, 0)]), None, log=quiet)
    sd = tmp_path / "out-fw5"
    assert rep.ok and (sd / "ampr_emu.index").read_bytes() == (tmp_path / "out/ampr_emu.index").read_bytes()
    assert (tmp_path / "out-fw5.originals/ampr_emu.index").read_bytes() == old
    srep = json.loads((sd / "backport-report.json").read_text())
    assert "ampr_emu.index" in srep["outputs"] and any(e["kind"] == "generated" for e in srep["edits"])
    shutil.copytree(sd, g, dirs_exist_ok=True)                           # the sibling is undoable too
    apply_undo(g, plan_undo(g, [sd]))
    assert (g / "ampr_emu.index").read_bytes() == old


def test_final_tree_helpers():
    assert A.has_emulator(["Fakelib/LIBSCEAMPR.SPRX"]) and not A.has_emulator(["fakelib/other.sprx"])
    assert A.has_packs(["AMPR_ASSETS.INDEX"]) and not A.has_packs(["ampr_assets.index.crc"])


def test_final_tree_overlay_overrides_and_removes(tmp_path):
    g, o = tmp_path / "g", tmp_path / "o"
    for root, rel, n in ((g, "a.bin", 1), (g, "Fakelib/Old.sprx", 2), (g, "keep.txt", 3), (o, "a.bin", 9),
                         (o, "fakelib/new.sprx", 4), (o, "backport-report.json", 1)):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(b"x" * n)
    t = A.final_tree("overlay", g, o, removed=["Fakelib/Old.sprx"])
    assert {k: v.stat().st_size for k, v in t.items()} == {"a.bin": 9, "keep.txt": 3, "fakelib/new.sprx": 4}


def test_describe_ampr(tmp_path):
    from ps5bp.core.pipeline import ampr_describe_lines, describe_ampr
    g = make_game(tmp_path)
    L = ampr_describe_lines(describe_ampr(g))
    assert any("0.3.6.6" in x for x in L) and any("missing" in x for x in L)
    (g / "ampr_emu.index").write_bytes(own_index(g))
    (g / "ampr_assets.index").write_bytes(b"x")
    L = ampr_describe_lines(describe_ampr(g))
    assert any("entries" in x for x in L) and any("ampr_assets.index" in x for x in L)


def test_cli_analyze_prints_ampr(tmp_path, capsys):
    from ps5bp.cli import main
    g = make_game(tmp_path)
    main(["analyze", str(g)])
    assert "Ampr emulator: version 0.3.6.6" in capsys.readouterr().out


def test_cli_build_option(tmp_path):
    from ps5bp.cli import main
    g = make_game(tmp_path)
    assert main(["build", str(g), "--target", "4", "--out", str(tmp_path / "o"), "--no-fakelibs",
                 "--ampr-index", "keep"]) == 0
    assert not (tmp_path / "o/ampr_emu.index").exists()
    assert main(["build", str(g), "--target", "4", "--out", str(tmp_path / "o"), "--no-fakelibs"]) == 0
    assert (tmp_path / "o/ampr_emu.index").is_file()


# ---- klog --------------------------------------------------------------------------------------
KLOG = """\
<118>[AMPR_EMU] name=libSceAmpr version=0.3.6.6 (public beta) build=abc Jun 1 2025
<118>[AMPR_EMU] apr.index unavailable path=/app0/ampr_emu.index building runtime index
<118>[AMPR_EMU] apr.index build fail reason=read-only
<118>[AMPR_EMU] indexed-path-missing /app0/data/gone.pak
<118>[AMPR_EMU] apr.index invalid-counts n=0
"""


def test_klog_ampr_triage():
    t = klog.parse(KLOG)
    klog.diagnose(t)
    assert t.ampr_versions and "0.3.6.6" in t.ampr_versions[0]
    d = "\n".join(t.diagnosis)
    assert "missing and the emulator did not build" in d and "could not write" in d
    assert "STALE" in d and "corrupt" in d and "--ampr-index regen" in d
    assert "Ampr emulator log lines" in t.to_text()
    t2 = klog.parse("<118>[AMPR_EMU] apr.index defer runtime build\n")
    klog.diagnose(t2)
    assert any("missing" in x for x in t2.diagnosis)
    t3 = klog.parse("<118>nothing\n")
    klog.diagnose(t3)
    assert not t3.ampr_findings
