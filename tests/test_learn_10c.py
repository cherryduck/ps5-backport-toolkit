"""`kit learn` explains edits made by the phase-10c rules (round trips on synthetic binaries; real community
pairs when PS5BP_DECKERR_TREE is set)."""
import glob
import os
import struct
import zipfile
from pathlib import Path

import pytest

import test_phase10cb as t
from ps5bp.core import dynamic
from ps5bp.core.binary import Binary
from ps5bp.core.evidence import EvidenceDB
from ps5bp.core.learn import learn
from ps5bp.core.pipeline import BuildOptions, build

TREE = os.environ.get("PS5BP_DECKERR_TREE")
H = t.H


def roundtrip(g: Path, tmp: Path, rules, target: int = 4, db=None):
    out = tmp / "out"
    rep = build(g, BuildOptions(target=target, out=out, rules=set(rules), force=True), db, log=lambda m: None)
    assert rep.ok
    reps, _ = learn(g, out)
    return rep, reps


def classes(reps) -> dict:
    tot: dict = {}
    for r in reps:
        for k, v in r.classes.items():
            tot[k] = tot.get(k, 0) + v
    return tot


def assert_explained(reps, cls):
    tot = classes(reps)
    assert tot.get(cls, 0) > 0, tot
    assert "game" not in tot, [(r.file, r.edits) for r in reps]


# ---- byte-edit rules (shadow-run on the original) ----------------------------------------------------------
def test_gamepresets_explained_and_other_value_is_not(tmp_path):
    g = t.game(tmp_path, t.mkspec([t.GP], {0x100: t.GP_PATCH}))
    rep, reps = roundtrip(g, tmp_path, {"gamepresets-28"})
    assert_explained(reps, "gamepresets-28")
    # the same site edited to a different value stays unexplained, with a note naming the rule
    p = tmp_path / "out/eboot.bin"
    b = Binary.load(p)
    b.patch(0x100 + 4 + 4, H("28000000"), H("20000000"))
    b.save(p)
    reps, _ = learn(g, tmp_path / "out")
    tot = classes(reps)
    assert tot.get("game") == 1 and "gamepresets-28" not in tot
    assert "gamepresets-28 would write 28000000" in reps[0].edits[0]["note"]


def test_gamepresets_init_helper(tmp_path):
    g = t.helper_game(tmp_path)
    _, reps = roundtrip(g, tmp_path, {"gamepresets-28"})
    assert_explained(reps, "gamepresets-28")


def test_tls_atexit_explained(tmp_path):
    g = t.tls_game(tmp_path)
    _, reps = roundtrip(g, tmp_path, {"tls-atexit"})
    assert_explained(reps, "tls-atexit")
    assert classes(reps)["tls-atexit"] == 4


def test_savedata_mount_forms_explained(tmp_path):
    for i, g in enumerate((t.game(tmp_path / "a", t.mkspec([t.MOUNT3], {0x100: t.M3_ALIAS})),
                           t.wrapper_game(tmp_path / "b"),
                           t.unity_game(tmp_path / "c", t.unity_code(t.UNITY_R14)))):
        tp = tmp_path / f"o{i}"
        tp.mkdir()
        _, reps = roundtrip(g, tp, {"savedata-mount"})
        assert_explained(reps, "savedata")


def test_savedata_prepare_dirsearch_explained(tmp_path):
    g = t.prep_game(tmp_path / "p", t.prep(H("55 4889e5 c745e4 02000000 488d75e0")))
    _, reps = roundtrip(g, tmp_path / "p", {"savedata-prepare"})
    assert_explained(reps, "savedata-prepare")
    g = t.game(tmp_path / "d", t.mkspec([t.SEARCH2], {}))
    _, reps = roundtrip(g, tmp_path / "d", {"savedata-dirsearch"})
    assert_explained(reps, "savedata-dirsearch")           # rename: dynstr bytes attributed to the rule, not "imports"
    assert "imports" not in classes(reps)
    spec = t.mkspec([t.SEARCH2, t.SEARCH], {})
    g = t.game(tmp_path / "f", spec)
    t.set_got(g / "eboot.bin", spec, 0, 0x16)
    t.set_got(g / "eboot.bin", spec, 1, 0x26)
    _, reps = roundtrip(g, tmp_path / "f", {"savedata-dirsearch"})
    assert_explained(reps, "savedata-dirsearch")


@pytest.mark.parametrize("name", t.NAMES)
def test_frostbite_explained(tmp_path, name):
    g = t.fb_game(tmp_path, t.fb_text(name))
    _, reps = roundtrip(g, tmp_path, {"frostbite-8ch"})
    assert_explained(reps, "frostbite-8ch")


def test_set3_nonfatal_explained(tmp_path):
    from ps5bp.core.rules import set3_nonfatal as s3
    code = H("55 4889e5") + t.call(0x100 + 4, t.PLT0) + H("85c0 7405 5d c3")
    g = t.game(tmp_path, t.mkspec([s3.SET3], {0x100: code}))
    _, reps = roundtrip(g, tmp_path, {"set3-nonfatal"}, target=6)
    assert_explained(reps, "set3-nonfatal")
    assert classes(reps)["set3-nonfatal"] == 1


# ---- cave-placing rules (matched structurally) --------------------------------------------------------------
def test_compat_stub_got_seed_explained_with_the_cave_bytes(tmp_path):
    import test_compat_stubs as tc
    g, lay = tc.make(tmp_path, [tc.PEG], tc.prog(tc.PRO, ("call", 0), tc.EPI))
    out = tmp_path / "out"
    rep = build(g, BuildOptions(target=4, out=out, rules={"compat-stubs"}), None, log=lambda m: None)
    assert rep.ok and [f for f in rep.findings if f["applied"]]
    reps, _ = learn(g, out)
    tot = classes(reps)
    assert tot.get("compat-stubs", 0) >= 3 and "game" not in tot
    # a cave holding something that is not the contract stub is not explained
    p = out / "eboot.bin"
    b = Binary.load(p)
    got = b.u64(lay["got"][0])
    b.data[b.foff(got)] ^= 0xFF
    b.save(p)
    reps, _ = learn(g, out)
    r = reps[0]
    assert classes(reps).get("game") and "GOT slot repointed" in r.edits[0]["note"] + "".join(e["note"] for e in r.edits)


def test_sync_umtx_explained(tmp_path):
    from test_sync_umtx import sync_self, WAKE, WAIT
    g = tmp_path / "G"
    (g / "sce_module").mkdir(parents=True)
    t.put(g / "eboot.bin", t.spec_with(["rTXw65xmLIA"]))
    (g / "sce_module/libtest.prx").write_bytes(sync_self([WAKE, WAIT, "KKKKKKKKKK1"]))
    (g / "sce_sys").mkdir()
    rep, reps = roundtrip(g, tmp_path, {"sync-umtx"})
    tot = classes(reps)
    assert tot.get("sync-umtx", 0) > 60 and "game" not in tot and "imports" not in tot, tot


def test_trinity_gate_explained_pristine_and_forced(tmp_path):
    import test_trinity_gate as tg
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    g = tg._game(tmp_path / "a", False, False)
    _, reps = roundtrip(g, tmp_path / "a", {"trinity-hw-gate"})
    assert_explained(reps, "trinity-hw-gate")
    assert "imports" not in classes(reps)
    g = tg._game(tmp_path / "b", True, True)
    _, reps = roundtrip(g, tmp_path / "b", {"trinity-hw-gate"})
    assert_explained(reps, "trinity-hw-gate")


def test_trinity_gate_kit_over_a_pristine_dump_derived_bodies(tmp_path):
    """A kit that derived GetOperationMode/AGC bodies over canonical PLT entries (community form)."""
    import test_trinity_gate as tg
    from ps5bp.core.rules import trinity_hw_gate as th
    from ps5bp.core.rules.common import jump_slots
    (tmp_path / "a").mkdir()
    g = tg._game(tmp_path / "a", False, False)
    kit = tmp_path / "kit"
    kit.mkdir()
    b = Binary.load(g / "eboot.bin")
    d = dynamic.parse(b)
    slots = jump_slots(b, d)
    is_s = next(s for s in slots if s.nid == th.IS_TRINITY)
    op = next(s for s in slots if s.nid == th.OPMODE)
    agc = next(s for s in slots if s.nid == th.AGC_IS_TRINITY)
    pl = th.plan_module(b, 4)
    assert pl.status == "PATCH"
    for rva, old, new, note in th.build_edits(b, pl):
        b.patch(rva, old, new)
    cave = 0x300                                          # int3 padding in the synthetic text
    code = th.opmode_cave(cave, is_s.va)
    assert b.read(cave, len(code)) == b"\xcc" * len(code)
    b.patch(cave, b"\xcc" * len(code), code)
    b.patch(op.va, op.entry[:5], b"\xe9" + struct.pack("<i", cave - (op.va + 5)))
    body = th.agc_body(agc.va, is_s.va)
    b.patch(agc.va, agc.entry[:len(body)], body)
    (kit / "eboot.bin").write_bytes(bytes(b.data))
    (kit / "sce_sys").mkdir()
    reps, _ = learn(g, kit)
    tot = classes(reps)
    assert tot.get("trinity-hw-gate", 0) > 20 and "game" not in tot, (tot, [r.edits for r in reps])


def test_psml_overlay_files_explained(tmp_path):
    g = tmp_path / "G"
    t.put(g / "eboot.bin", t.spec_with(["rTXw65xmLIA"]))
    kit = tmp_path / "K"
    t.put(kit / "eboot.bin", t.spec_with(["rTXw65xmLIA"]))
    (kit / "fakelib").mkdir()
    (kit / "fakelib/libScePsml.sprx").write_bytes(b"\x7fELFxxxx/app0/k9.psp\0")
    (kit / "k9.psp").write_bytes(b"model")
    reps, _ = learn(g, kit)
    got = {r.file: r.classes for r in reps if "psml-overlay" in r.classes}
    assert set(got) == {"fakelib/libScePsml.sprx", "k9.psp"}
    (kit / "fakelib/libScePsml.sprx").write_bytes(b"\x7fELFxxxx/system/k9\0")        # plain PSML: not an overlay
    assert not [r for r in learn(g, kit)[0] if "psml-overlay" in r.classes]


# ---- per-rule kit observations ------------------------------------------------------------------------------
def test_kit_add_records_10c_observations(tmp_path):
    g = t.game(tmp_path / "x", t.mkspec([t.GP], {0x100: t.GP_PATCH}))
    k = tmp_path / "kit"
    t.put(k / "fakelib/libSceFoo.sprx", t.spec_with(["rTXw65xmLIA"], kind="module", module="libSceFoo"))
    k.joinpath("eboot.bin").write_bytes((g / "eboot.bin").read_bytes())
    db = EvidenceDB(tmp_path / "home")
    db.add_kit(k, 4, "unfixed")
    done = Binary.load(k / "eboot.bin")
    done.patch(0x100 + 4 + 4, H("30000000"), H("28000000"))
    k2 = tmp_path / "kit2"
    t.put(k2 / "fakelib/libSceFoo.sprx", t.spec_with(["rTXw65xmLIA"], kind="module", module="libSceFoo"))
    done.save(k2 / "eboot.bin")
    db.add_kit(k2, 4, "fixed")
    obs = {o["kit"]: (o["unfixed"], o["fixed"]) for o in db.rule_observations("gamepresets-28")}
    assert obs == {"unfixed": (1, 0), "fixed": (0, 1)}


# ---- real community binaries (local only) -------------------------------------------------------------------
def _zip(pat):
    hits = sorted(glob.glob(f"{TREE}/D/**/{pat}", recursive=True))
    if not hits:
        pytest.skip(f"no {pat}")
    return hits[0]


def _extract(tmp, base_pat, work_pat, member="sce_module/libc.prx"):
    d = {}
    for tag, pat in (("orig", base_pat), ("kit", work_pat)):
        with zipfile.ZipFile(_zip(pat)) as z:
            z.extract(member, tmp / tag)
        d[tag] = tmp / tag
    return d


REAL = {
    "SMB3D": ("baselines/*PPSA31162*", "BACKPORT/backports/*PPSA31162*", {"tls-atexit": 4}),
    "GalacticRacer": ("baselines/*PPSA28416*", "BACKPORT/backports/*PPSA28416*", {"tls-atexit": 4, "mapflex": 10}),
    "Resonance": ("baselines/*PPSA30601*", "BACKPORT/backports/*PPSA30601*", {"tls-atexit": 4, "mapflex": 10}),
    "ASTRO": ("baselines/*PPSA21567*", "BACKPORT/backports/*PPSA21567*", {"sync-umtx": 80, "mapflex": 15}),
    "Elliot": ("baselines/*PPSA31162*", "test_builds/*ELLIOT*", {"tls-atexit": 4}),
}


@pytest.mark.skipif(not TREE, reason="PS5BP_DECKERR_TREE not set")
@pytest.mark.parametrize("title", REAL)
def test_real_libc_pairs_fully_explained(tmp_path, title):
    base, work, want = REAL[title]
    d = _extract(tmp_path, base, work)
    reps, _ = learn(d["orig"], d["kit"])
    assert len(reps) == 1 and not reps[0].problem
    assert reps[0].classes == want, reps[0].classes
    assert reps[0].edits == []                                # 0 unexplained regions (was 1-4 before 10d)


@pytest.mark.skipif(not TREE, reason="PS5BP_DECKERR_TREE not set")
def test_real_libc_pairs_have_equal_identity(tmp_path):
    from ps5bp.core import libcid
    for title, (base, work, _) in REAL.items():
        d = _extract(tmp_path / title, base, work)
        a = libcid.record_for("a", d["orig"] / "sce_module/libc.prx")
        b = libcid.record_for("b", d["kit"] / "sce_module/libc.prx")
        assert a.identity == b.identity, title
        assert a.elf_sha != b.elf_sha


@pytest.mark.skipif(not TREE, reason="PS5BP_DECKERR_TREE not set")
def test_real_gow_v8_shapes_round_trip(tmp_path):
    """No GoW baseline exists in the tree: take V8's eboot + Unity SaveData.prx, undo the edits ps5bp itself knows
    (GOT seed, GamePresets 0x28, the Unity 8-byte copy) to get a stand-in original, and check learn explains
    exactly those on the real binaries. (Shape check only — the stand-in is derived from the kit.)"""
    from ps5bp.core.libcid import _put
    from ps5bp.core.rules import contracts, gamepresets, got_seed
    with zipfile.ZipFile(_zip("**/PPSA28997*V8.zip")) as z:
        for m in ("eboot.bin", "Media/Plugins/SaveData.prx"):
            z.extract(m, tmp_path / "kit")
    b = Binary.load(tmp_path / "kit/eboot.bin")
    for nid_, c in contracts.load().items():
        try:
            pl = got_seed.plan(b, nid_, c.stub)
        except Exception:                                          # noqa: BLE001
            continue
        if pl.status == "DONE":
            _put(b, pl.cur, b"\xcc" * len(c.stub))
            _put(b, pl.got, struct.pack("<Q", pl.plt + 6))
    for r in gamepresets.sites(b, 0x400000):
        if r["status"] == "DONE":
            _put(b, r["va"] + r["len"] - 4 - 0x400000, (0x30).to_bytes(4, "little"))
    (tmp_path / "orig").mkdir()
    b.save(tmp_path / "orig/eboot.bin")
    import re
    sd = Binary.load(tmp_path / "kit/Media/Plugins/SaveData.prx")
    seg = next(p for p in sd.loads() if p.is_exec)
    for m in re.finditer(rb"\x49\x8b\x46\x30\x48\x89\x85(....)\x90\x90\x90", sd.segment_bytes(seg), re.S):
        _put(sd, seg.vaddr + m.start(), b"\xc4\xc1\x78\x10\x46\x30\xc5\xf8\x11\x85" + m.group(1))
    (tmp_path / "orig/Media/Plugins").mkdir(parents=True)
    sd.save(tmp_path / "orig/Media/Plugins/SaveData.prx")
    reps, _ = learn(tmp_path / "orig", tmp_path / "kit")
    by = {r.file: r for r in reps}
    assert by["eboot.bin"].classes == {"compat-stubs": 18, "gamepresets-28": 1} and not by["eboot.bin"].edits
    assert by["Media/Plugins/SaveData.prx"].classes == {"savedata": 14} and not by["Media/Plugins/SaveData.prx"].edits
