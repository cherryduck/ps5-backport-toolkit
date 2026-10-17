"""Phase 10d: libc identity (normalised ps5bp-rule edits), kit records, `kit reindex`, build report section."""
import json
import struct
import zipfile
from pathlib import Path

import pytest

import test_phase10cb as t
from ps5bp.core import libcid, sdk
from ps5bp.core.binary import Binary
from ps5bp.core.evidence import EvidenceDB
from ps5bp.core.pipeline import BuildOptions, build

H = t.H
MF = "IWIBBdTHit4"
MF_CALL = 0x180


def libc_spec():
    """Synthetic libc: __cxa_thread_atexit wrapper (-> missing import) + a call of the flexible-memory import."""
    wrapper = H("55 4889e5") + t.call(0x104, 0x10) + H("5d c3")
    mapf = H("55 4889e5 ba03000000 b900800000") + t.call(MF_CALL + 4 + 5 + 5, 0x20) + H("5d c3")
    return t.mkspec([t.IMPL, MF], {0x100: wrapper, 0x140: H("c3"), MF_CALL: mapf}, kind="module", module="libc",
                    export_libs=["libc"], exports=[(t.WRAP, 0), (t.LOCAL, 0)], export_values=[0x100, 0x140])


def libc_bytes(tmp: Path, edit=None, sdk_pair=(0x07000038, 0x10590001)) -> bytes:
    p = t.put(tmp / "libc.prx", libc_spec(), sdk_pair)
    b = Binary.load(p)
    if edit:
        edit(b)
    return bytes(b.data)


def ident(data: bytes) -> str:
    return libcid.identity(data)[0]


def test_identity_ignores_ps5bp_rule_edits(tmp_path):
    base = libc_bytes(tmp_path)
    want = ident(base)

    def tls(b):
        b.patch(0x105, b.read(0x105, 4), struct.pack("<i", 0x140 - 0x109))
    variants = {
        "tls": tls,
        "mapflex-zero": lambda b: b.patch(MF_CALL + 9, H("b900800000"), H("b900000000")),
        "mapflex-xor": lambda b: b.patch(MF_CALL + 9, H("b900800000"), H("31c9909090")),
    }
    seen = {base}
    for name, fn in variants.items():
        d = libc_bytes(tmp_path, fn)
        assert d not in seen
        seen.add(d)
        assert ident(d) == want, name
    # SDK pair
    d = libc_bytes(tmp_path, sdk_pair=(0x04000031, 0x09040001))
    assert d not in seen and ident(d) == want
    # everything at once
    def all_(b):
        tls(b)
        variants["mapflex-xor"](b)
    d = libc_bytes(tmp_path, all_, (0x04000031, 0x09040001))
    assert ident(d) == want
    # any other byte changes the identity
    d = libc_bytes(tmp_path, lambda b: b.patch(0x1F0, b.read(0x1F0, 1), b"\x90"))
    assert ident(d) != want
    # ... including an edit at the mapflex site that is none of the three forms
    d = libc_bytes(tmp_path, lambda b: b.patch(MF_CALL + 9, H("b900800000"), H("b901000000")))
    assert ident(d) != want


def test_identity_notes_say_what_was_normalised(tmp_path):
    d = libc_bytes(tmp_path, lambda b: b.patch(MF_CALL + 9, H("b900800000"), H("31c9909090")),
                   (0x04000031, 0x09040001))
    _, notes = libcid.identity(d)
    assert any("flexible-memory" in n for n in notes) and any(n.startswith("sdk") for n in notes)


def test_identity_sync_umtx_and_got_seeds(tmp_path):
    from test_sync_umtx import WAIT, WAKE, sync_self
    from ps5bp.core.rules import sync_umtx as su
    raw = sync_self([WAKE, WAIT, "KKKKKKKKKK1"])
    b = Binary(raw)
    pl = su.plan_module(b, 4)
    for rva, old, new, _ in su.build_edits(b, pl):
        b.patch(rva, old, new)
    assert bytes(b.data) != raw
    assert ident(bytes(b.data)) == ident(raw)
    # a different cave content is not hidden: an unrelated code change keeps its own identity
    b.patch(0x3F0, b.read(0x3F0, 1), b"\x90")
    assert ident(bytes(b.data)) != ident(raw)
    # GOT seed (compat-stubs) reverted
    import test_compat_stubs as tc
    g, lay = tc.make(tmp_path, [tc.TB59], tc.prog(tc.PRO, ("call", 0), tc.EPI), name="sce_module/libc.prx")
    t.put(g / "eboot.bin", t.spec_with(["rTXw65xmLIA"]))
    orig = (g / "sce_module/libc.prx").read_bytes()
    rep = build(g, BuildOptions(target=4, out=tmp_path / "o", rules={"compat-stubs"}), None, log=lambda m: None)
    out = (tmp_path / "o/sce_module/libc.prx").read_bytes()
    assert out != orig and ident(out) == ident(orig)


def make_kit(tmp: Path, name: str, libc: bytes | None) -> Path:
    k = tmp / name
    t.put(k / "fakelib/libSceFoo.sprx", t.spec_with(["rTXw65xmLIA"], kind="module", module="libSceFoo"))
    if libc is not None:
        (k / "sce_module").mkdir()
        (k / "sce_module/libc.prx").write_bytes(libc)
    return k


def test_kit_add_stores_and_records_libc_and_reindex(tmp_path):
    db = EvidenceDB(tmp_path / "home")
    libc = libc_bytes(tmp_path)
    r = db.add_kit(make_kit(tmp_path, "k1", libc), 4, "k1")
    assert r["libc"]["identity"] == ident(libc)
    (rec,) = db.libc_records()
    assert rec.kit == "k1" and rec.file_sha == libcid.sha(libc) and rec.size == len(Binary(libc).to_elf())
    assert rec.elf_sha == libcid.sha(Binary(libc).to_elf()) and rec.identity == ident(libc)
    assert db.kit("k1").path("sce_module/libc.prx").read_bytes() == libc            # stored
    # no libc: no record, reindex says so
    db.add_kit(make_kit(tmp_path, "k2", None), 4, "k2")
    assert [x.kit for x in db.libc_records()] == ["k1"]
    res = db.reindex()
    assert res["k1"].startswith("ok") and "no libc stored" in res["k2"]
    # a kit that predates 10d (record lost): reindex recomputes it from the stored libc
    db.db.execute("DELETE FROM libcs")
    db.db.commit()
    assert db.libc_records() == []
    assert db.reindex(["k1"])["k1"].startswith("ok") and len(db.libc_records()) == 1
    db.remove_kit("k1")
    assert db.libc_records() == []


def test_reindex_cli(tmp_path, monkeypatch, capsys):
    from ps5bp.cli import main
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))
    db = EvidenceDB()
    db.add_kit(make_kit(tmp_path, "k1", libc_bytes(tmp_path)), 4, "k1")
    db.db.execute("DELETE FROM libcs")
    db.db.commit()
    assert main(["kit", "reindex"]) == 0
    assert "k1" in capsys.readouterr().out and len(EvidenceDB().libc_records()) == 1


def test_build_report_cross_check(tmp_path):
    g = t.game(tmp_path / "g", libc_spec(), "sce_module/libc.prx")
    plain = EvidenceDB(tmp_path / "h0")
    ref = build(g, BuildOptions(target=4, out=tmp_path / "ref", rules={"tls-atexit"}, force=True), plain,
                log=lambda m: None)
    mine = (tmp_path / "ref/sce_module/libc.prx").read_bytes()
    assert ref.libc_check["kits_with_libc"] == 0
    assert "no kit has a recorded libc" in (tmp_path / "ref/backport-report.txt").read_text()

    db = EvidenceDB(tmp_path / "h1")
    db.add_kit(make_kit(tmp_path, "same", mine), 4, "same")                        # identical to our output
    unpatched = libc_bytes(tmp_path / "x", sdk_pair=(0x04000031, 0x09040001))
    db.add_kit(make_kit(tmp_path, "plain", unpatched), 4, "plain")                 # same build, no tls edit
    ob = Binary(libc_bytes(tmp_path / "y"))
    ob.patch(0x1F0, ob.read(0x1F0, 1), b"\x90")                                    # a different build
    db.add_kit(make_kit(tmp_path, "other", bytes(ob.data)), 4, "other")
    db.add_kit(make_kit(tmp_path, "nolibc", None), 4, "nolibc")
    rep = build(g, BuildOptions(target=4, out=tmp_path / "out", rules={"tls-atexit"}, force=True), db,
                log=lambda m: None)
    assert rep.ok
    cc = json.loads((tmp_path / "out/backport-report.json").read_text())["libc_check"]
    assert cc["kits_with_libc"] == 3 and cc["same_identity"] == 2 and cc["identical"] == 1
    rows = {k["kit"]: k for k in cc["kits"]}
    assert rows["same"]["match"] and not rows["plain"]["match"] and "other" not in rows
    (rng,) = rows["plain"]["ranges"]
    assert rng["explained_by"] == ["tls-atexit"] and rng["len"] == 4 and rows["plain"]["n_ranges"] == 1
    txt = (tmp_path / "out/backport-report.txt").read_text()
    assert "libc cross-check" in txt and "2 of 3 kit libc(s) are the same build" in txt
    assert "same: identical" in txt and "plain: differs in 1 range(s)" in txt and "tls-atexit" in txt
    # report only: the output libc is the same with and without kits
    assert (tmp_path / "out/sce_module/libc.prx").read_bytes() == mine
    assert cc["identity"] == ident(mine)


def test_cross_check_labels_unexplained_ranges(tmp_path):
    """Same identity, but the kit's flags edit is its own (mapflex-flags was off) while the SDK fields differ
    because ps5bp declared FW4: one range is labelled sdk, the other is 'not explained by a ps5bp edit'."""
    g = t.game(tmp_path / "g", libc_spec(), "sce_module/libc.prx")
    kb = Binary(libc_bytes(tmp_path / "x"))
    kb.patch(MF_CALL + 9, H("b900800000"), H("31c9909090"))
    db = EvidenceDB(tmp_path / "h")
    db.add_kit(make_kit(tmp_path, "mf", bytes(kb.data)), 4, "mf")
    rep = build(g, BuildOptions(target=4, out=tmp_path / "out", force=True), db, log=lambda m: None)
    row = rep.libc_check["kits"][0]
    assert not row["match"] and row["n_ranges"] == 2
    labels = sorted(r["explained_by"] for r in row["ranges"])
    assert labels == [[], ["sdk"]]
    assert "not explained by a ps5bp edit" in rep.to_text()
    # with the rule on, the flags edit is ps5bp's: no unexplained range is left
    rep = build(g, BuildOptions(target=4, out=tmp_path / "out2", force=True, rules={"mapflex-flags"}), db,
                log=lambda m: None)
    labels = sorted(r["explained_by"] for r in rep.libc_check["kits"][0]["ranges"])
    assert labels == [["mapflex-flags"], ["sdk"]]
