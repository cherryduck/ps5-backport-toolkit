"""Phase 10c-A: GOT-seed delivery, stub contracts, compat-stubs and set3-nonfatal."""
import json
import os
import struct
from pathlib import Path

import capstone
import pytest

from ps5bp.core import dynamic
from ps5bp.core.asm import Asm
from ps5bp.core.binary import Binary
from ps5bp.core.evidence import EvidenceDB
from ps5bp.core.nid import name_of, nid
from ps5bp.core.pipeline import BuildError, BuildOptions, build
from ps5bp.core.rules import contracts, got_seed, gates
from synth import DATA_OFF, DATA_VA, TEXT_OFF, TEXT_VA, Spec, build_elf, build_self

B = 0x400000
PEG, VRRI, GETVRR, SET3, TOURN, NETCTL, YFC3, TB59, OPMODE, PADREM = (
    "5tRaBjtdTzY", "kP2L8t3j-aM", "gWT7X8H0bYs", "TViD1EZXkNI", "gELp9ue2ccQ", "obuxdTiwkF8", "YFC3dBBipj8",
    "tB59hFLH3SA", "NH6xARDOVv8", "fCWdlnmB1Ks")
QUIET = dict(log=lambda m: None)


def make(tmp, imports, code=None, tail=0x40, fill=b"\xcc", sdk=0x07000038, lazy=True, bind_now=False, name="eboot.bin",
         branch_into_run=False, spec_kw=None):
    """Game with one import PLT entry per NID (entry k at k*16), caller code at 0x80 and `tail`
    bytes of int3 after it. `code`: bytes, or callable(Asm) -> None to assemble with PLT targets."""
    spec = Spec(import_libs=["libkernel"], imports=[(n, 0) for n in imports], ps5_sdk=sdk, **(spec_kw or {}))
    _, lay = build_elf(spec)
    text = bytearray(fill * 0x80)
    for k, got in enumerate(lay["got"]):
        text[k * 16:k * 16 + 16] = (b"\xff\x25" + struct.pack("<i", got - (TEXT_VA + k * 16 + 6)) + b"\x68"
                                    + struct.pack("<I", k) + b"\xe9" + struct.pack("<i", -(k * 16 + 16)))
    a = Asm(TEXT_VA + 0x80)
    if callable(code):
        code(a)
    elif code:
        a.raw(code)
    body = a.assemble()
    text += body + fill * tail
    text = text.ljust(0x100, fill)
    if branch_into_run:                       # a call into the int3 run after the PLT entries
        text[0x80 + 1:0x80 + 6] = b"\xe8" + struct.pack("<i", 0x10 - (0x80 + 6))
    spec.text = bytes(text)
    elf, lay = build_elf(spec)
    elf = bytearray(elf)
    for k, g in enumerate(lay["got"]):
        v = k * 16 + 6 if lazy else 0x1234
        elf[DATA_OFF + g - DATA_VA:DATA_OFF + g - DATA_VA + 8] = struct.pack("<Q", v)
    if bind_now:                                           # DT_PLTREL (0x14) -> DT_BIND_NOW (0x18)
        o = DATA_OFF + lay["dyn"] - DATA_VA
        for i in range(0, 0x100, 16):
            t = struct.unpack_from("<q", elf, o + i)[0]
            if t == 0x14:
                struct.pack_into("<q", elf, o + i, 0x18)
            if t == 0:
                break
    g = tmp / "PPSA99999"
    (g / name).parent.mkdir(parents=True, exist_ok=True)
    (g / name).write_bytes(build_self(bytes(elf)))
    return g, lay


def call(k):
    return lambda a: a.rel32("e8", k * 16)


def prog(*parts):
    """Assemble parts: bytes (hex string) or ('call', k)."""
    def f(a):
        for p in parts:
            if isinstance(p, tuple):
                a.rel32("e8", p[1] * 16)
            else:
                a.hex(p)
    return f


PRO = "55 4889e5"
EPI = "5d c3"
RET0 = "31c0"


def run(game, tmp, target=4, rules=("compat-stubs",), db=None, **kw):
    out = tmp / "out"
    rep = build(game, BuildOptions(target=target, out=out, rules=set(rules), **kw), db, **QUIET)
    return rep, out


def got_of(b, lay, k=0):
    return b.u64(lay["got"][k])


def test_contract_table():
    t = contracts.load()
    assert len(t) >= 20 and set(c.gate for c in t.values()) <= set(contracts.GATES)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for c in t.values():
        assert 0 < len(c.stub) <= 15 and len(c.padded) == 16
        ins = list(md.disasm(c.stub, 0))
        assert sum(i.size for i in ins) == len(c.stub), c.nid          # fully decodes
        assert ins[-1].mnemonic == "ret", c.nid
        if c.name_verified:
            assert nid(c.name) == c.nid, c.name
    assert t[NETCTL].gate == "manual" and t["1hdjgLpYoY0"].gate == "manual"
    assert t[OPMODE].stub.hex() == "c70702000000c7060000000031c0c3"
    assert t[PADREM].stub.hex() == "31c08806c3"
    assert t[GETVRR].stub.hex() == "4889f7b90800000031c0f348abc3"
    assert t[PEG].absent_on(4) and t[PEG].absent_on(5) and not t[PEG].absent_on(6)
    assert t[TOURN].absent_on(4) is None


def test_seed_plan_states(tmp_path):
    g, lay = make(tmp_path, [PEG])
    b = Binary.load(g / "eboot.bin")
    p = got_seed.plan(b, PEG, contracts.load()[PEG].stub)
    assert (p.status, p.plt, p.got) == ("PATCH", TEXT_VA, lay["got"][0])
    g2, _ = make(tmp_path / "n", [PEG], lazy=False)
    assert got_seed.plan(Binary.load(g2 / "eboot.bin"), PEG, b"\x31\xc0\xc3").status == "UNKNOWN"
    g3, _ = make(tmp_path / "bn", [PEG], bind_now=True)
    p3 = got_seed.plan(Binary.load(g3 / "eboot.bin"), PEG, b"\x31\xc0\xc3")
    assert p3.status == "UNKNOWN" and "BIND_NOW" in p3.reason


def test_seed_patch_done_and_verification(tmp_path):
    g, lay = make(tmp_path, [PEG, TOURN], prog(PRO, RET0, EPI))
    b0 = Binary.load(g / "eboot.bin")
    c = contracts.load()[PEG]
    rep, out = run(g, tmp_path, seeds=[PEG])
    assert rep.ok
    b = Binary.load(out / "eboot.bin")
    cave = got_of(b, lay)
    assert cave != 6 and b.read(cave, 16) == c.padded
    assert cave < b0.phdrs[0].filesz                          # inside the int3 run (no segment growth)
    assert b.phdrs[0].filesz == b0.phdrs[0].filesz
    assert b.read(0, 16) == b0.read(0, 16)                          # PLT entry untouched
    d = dynamic.parse(b)
    assert all(not s.defined for s in d.symbols if s.nid == PEG)    # import kept
    assert got_of(b, lay, 1) == 16 + 6                              # TOURN: no lead, no evidence, not seeded
    edits = [e for e in rep.edits if e.kind == "rule:compat-stubs"]
    assert len(edits) == 2 and {e.file for e in edits} == {"eboot.bin"}
    assert [f["applied"] for f in rep.findings if f["rule"] == "compat-stubs"] == [True]
    # second build over the output: DONE, nothing to apply, no warning
    out2 = tmp_path / "out2"
    rep2 = build(out, BuildOptions(target=4, out=out2, rules={"compat-stubs"}, force=True), None, **QUIET)
    f = [x for x in rep2.findings if x["rule"] == "compat-stubs"][0]
    assert not f["applied"] and f["reason"].startswith("DONE")
    assert not any("compat-stubs" in w for w in rep2.warnings)
    assert not [e for e in rep2.edits if e.kind.startswith("rule:")]


def test_lead_and_target(tmp_path):
    g, lay = make(tmp_path, [PEG], prog(PRO, RET0, EPI))
    rep, out = run(g, tmp_path, target=4)                 # compat-stubs on, 5.02 lead > 4
    assert got_of(Binary.load(out / "eboot.bin"), lay) != 6
    g6, lay6 = make(tmp_path / "six", [PEG], prog(PRO, RET0, EPI), sdk=0x08000038)
    rep, out = run(g6, tmp_path / "six", target=6)         # target 6 >= 5.02: not needed
    assert got_of(Binary.load(out / "eboot.bin"), lay6) == 6
    assert not [f for f in rep.findings if f["rule"] == "compat-stubs"]
    # off by default: only a recommendation-free silence
    rep, out = run(g, tmp_path / "off", rules=())
    assert got_of(Binary.load(out / "eboot.bin"), lay) == 6


def test_manual_and_forced(tmp_path):
    g, lay = make(tmp_path, [NETCTL, PEG], prog(PRO, RET0, EPI))
    rep, out = run(g, tmp_path)
    b = Binary.load(out / "eboot.bin")
    assert got_of(b, lay, 0) == 6                          # manual contract: never automatic
    rep, out = run(g, tmp_path / "m", seeds=[NETCTL])
    b = Binary.load(out / "eboot.bin")
    cv = got_of(b, lay, 0)
    assert cv != 6 and b.read(cv, 16) == contracts.load()[NETCTL].padded
    with pytest.raises(BuildError, match="no stub contract"):
        run(g, tmp_path / "x", seeds=["ZZZZZZZZZZZ"])
    # forced NID the game doesn't import: warning
    rep, _ = run(g, tmp_path / "y", seeds=[YFC3])
    assert any("--seed YFC3dBBipj8" in w for w in rep.warnings)


def test_evidence_beats_lead(tmp_path):
    k = tmp_path / "kit"
    from test_rules import put
    put(k / "eboot.bin", Spec(import_libs=["libkernel"], imports=[(PEG, 0)]))          # PEG proven present on FW4
    put(k / "fakelib/libSceFoo.sprx", Spec(kind="module", module="libSceFoo", export_libs=["libSceFoo"],
                                           exports=[("FFFFFFFFFF1", 0)], import_libs=["libkernel"], imports=[],
                                           stubbed=[(TOURN, 0)]))                          # TOURN absent on FW4
    db = EvidenceDB(tmp_path / "home")
    db.add_kit(k, 4, "kit")
    g, lay = make(tmp_path / "g", [PEG, TOURN], prog(PRO, RET0, EPI))
    rep, out = run(g, tmp_path / "g", db=db)
    db.close()
    b = Binary.load(out / "eboot.bin")
    assert got_of(b, lay, 0) == 6                          # present on target: lead (5.02) ignored
    cv = got_of(b, lay, 1)
    assert cv != 16 + 6 and b.read(cv, 16) == contracts.load()[TOURN].padded     # evidence-only NID seeded
    assert "proven absent" in [f for f in rep.findings if f["rule"] == "compat-stubs"][0]["reason"]


def test_owned_by_pro_disable(tmp_path):
    g, lay = make(tmp_path, [OPMODE], prog(PRO, RET0, EPI))
    rep, out = run(g, tmp_path, rules=("compat-stubs", "pro-disable"))
    assert got_of(Binary.load(out / "eboot.bin"), lay) == 6       # pro-disable owns it (PLT mode)
    assert Binary.load(out / "eboot.bin").read(0, 7) == bytes.fromhex("31c089078906c3")
    rep, out = run(g, tmp_path / "solo")
    b = Binary.load(out / "eboot.bin")
    assert b.read(got_of(b, lay), 15) == bytes.fromhex("c70702000000c7060000000031c0c3")


@pytest.mark.parametrize("code,ok", [
    ((PRO, ("call", 0), RET0, EPI), True),                                   # result ignored
    ((PRO, ("call", 0), "85c0 7502 90 90", RET0, EPI), True),                # error check only
    ((PRO, ("call", 0), "8945fc", RET0, EPI), False),                        # stored
    ((PRO, ("call", 0), EPI), False),                                        # returned
    ((PRO, ("call", 0), "89c7", RET0, EPI), False),                          # passed on
])
def test_gate_result_unused(tmp_path, code, ok):
    g, lay = make(tmp_path, [VRRI], prog(*code))
    rep, out = run(g, tmp_path)
    changed = got_of(Binary.load(out / "eboot.bin"), lay) != 6
    assert changed == ok
    if not ok:
        f = [x for x in rep.findings if x["rule"] == "compat-stubs"][0]
        assert not f["applicable"] and "gate" in f["reason"]


def test_gate_result_tail_and_pointer(tmp_path):
    g, lay = make(tmp_path, [VRRI], prog(PRO, "5d", ("jmpplt",)) if False else
                  (lambda a: a.hex("55 4889e5 5d").rel32("e9", 0).hex("cc")))
    rep, out = run(g, tmp_path)
    assert got_of(Binary.load(out / "eboot.bin"), lay) == 6          # tail jump to the import: refused


def test_gate_output_buffer(tmp_path):
    full = "".join(f"48c745{(0x100 - 0x50 + 8 * i) & 0xFF:02x}00000000" for i in range(8))   # 8 x mov qword [rbp-0x50+8i],0
    lea = "488d75b0"
    g, lay = make(tmp_path, [GETVRR], prog(PRO, "4883ec60", full, lea, ("call", 0), RET0, "c9c3"))
    rep, out = run(g, tmp_path)
    b = Binary.load(out / "eboot.bin")
    cv = got_of(b, lay)
    assert cv != 6 and b.read(cv, 14) == contracts.load()[GETVRR].stub
    half = "".join(f"48c745{(0x100 - 0x50 + 8 * i) & 0xFF:02x}00000000" for i in range(4))
    g2, lay2 = make(tmp_path / "h", [GETVRR], prog(PRO, "4883ec60", half, lea, ("call", 0), RET0, "c9c3"))
    rep, out = run(g2, tmp_path / "h")
    assert got_of(Binary.load(out / "eboot.bin"), lay2) == 6
    assert "initialised" in [f for f in rep.findings if f["rule"] == "compat-stubs"][0]["reason"]
    g3, lay3 = make(tmp_path / "p", [GETVRR], prog(PRO, "4889fe", ("call", 0), RET0, EPI))   # rsi is an argument
    rep, out = run(g3, tmp_path / "p")
    assert got_of(Binary.load(out / "eboot.bin"), lay3) == 6


def test_gate_compares_error(tmp_path):
    g, lay = make(tmp_path, [YFC3], prog(PRO, ("call", 0), "3d03000280", "7402 90 90", RET0, EPI))
    rep, out = run(g, tmp_path)
    b = Binary.load(out / "eboot.bin")
    assert got_of(b, lay) != 6 and b.read(got_of(b, lay), 6) == bytes.fromhex("b803000280c3")
    g2, lay2 = make(tmp_path / "n", [YFC3], prog(PRO, ("call", 0), "85c0 7402 90 90", RET0, EPI))
    rep, out = run(g2, tmp_path / "n")
    assert got_of(Binary.load(out / "eboot.bin"), lay2) == 6


def test_libc_only_contract(tmp_path):
    g, lay = make(tmp_path, [TB59], prog(PRO, ("call", 0), RET0, EPI))
    rep, out = run(g, tmp_path)
    assert got_of(Binary.load(out / "eboot.bin"), lay) == 6          # not libc.prx
    g2, lay2 = make(tmp_path / "l", [TB59], prog(PRO, ("call", 0), RET0, EPI), name="sce_module/libc.prx",
                    spec_kw=dict(kind="module", module="libc"))
    make(tmp_path / "l", [PEG], prog(PRO, RET0, EPI))               # plus an eboot beside it
    rep, out = run(g2, tmp_path / "l")
    b = Binary.load(out / "sce_module/libc.prx")
    assert got_of(b, lay2) != 6


def test_cave_grow_and_branch_target(tmp_path):
    # no int3 run at all -> the executable segment grows
    g, lay = make(tmp_path, [PEG], prog(PRO, RET0, EPI), tail=0x40, fill=b"\x90")
    b0 = Binary.load(g / "eboot.bin")
    rep, out = run(g, tmp_path)
    assert rep.ok
    b = Binary.load(out / "eboot.bin")
    cv = got_of(b, lay)
    assert cv == b0.phdrs[0].filesz and b.phdrs[0].filesz == b0.phdrs[0].filesz + 16
    assert b.read(cv, 16) == contracts.load()[PEG].padded
    # an int3 run that is a call target is not used
    g2, lay2 = make(tmp_path / "t", [PEG], prog(PRO, RET0, EPI), branch_into_run=True)
    rep, out = run(g2, tmp_path / "t")
    b2 = Binary.load(out / "eboot.bin")
    assert got_of(b2, lay2) >= 0x80 + 8                                # skipped the run after the PLT (call target)


def test_two_seeds_distinct_caves(tmp_path):
    g, lay = make(tmp_path, [PEG, "T4ucGB8CsnM"], prog(PRO, RET0, EPI), tail=0x80)
    rep, out = run(g, tmp_path)
    b = Binary.load(out / "eboot.bin")
    a, c = got_of(b, lay, 0), got_of(b, lay, 1)
    assert a != c and abs(a - c) >= 16 and rep.ok


def test_plt_fallback_only_when_asked(tmp_path):
    g, lay = make(tmp_path, [PEG], prog(PRO, RET0, EPI), lazy=False)
    rep, out = run(g, tmp_path)
    b = Binary.load(out / "eboot.bin")
    assert b.read(0, 2) == b"\xff\x25"                              # refused, nothing silently patched
    rep, out = run(g, tmp_path / "f", seed_plt_fallback=True)
    b = Binary.load(out / "eboot.bin")
    assert b.read(0, 3) == bytes.fromhex("31c0c3")
    assert "requested fallback" in " ".join(e.note for e in rep.edits)


def test_stub_absent_leaves_contract_nids(tmp_path):
    k = tmp_path / "kit"
    from test_rules import put
    put(k / "eboot.bin", Spec(import_libs=["libkernel"], imports=[]))
    put(k / "fakelib/libSceFoo.sprx", Spec(kind="module", module="libSceFoo", export_libs=["libSceFoo"],
                                           exports=[("FFFFFFFFFF1", 0)], import_libs=["libkernel"], imports=[],
                                           stubbed=[(TOURN, 0)]))
    db = EvidenceDB(tmp_path / "home")
    db.add_kit(k, 4, "kit")
    g, lay = make(tmp_path / "g", [TOURN], prog(PRO, RET0, EPI))
    rep, out = run(g, tmp_path / "g", rules=("compat-stubs", "stub-absent"), db=db)
    db.close()
    b = Binary.load(out / "eboot.bin")
    assert b.read(0, 2) == b"\xff\x25" and got_of(b, lay) != 6


# ---- set3-nonfatal ------------------------------------------------------------------------

def set3_game(tmp, shapes, sdk=0x10000038):
    """One caller function per shape; each calls Set3DLatency (PLT 0) then the shape's bytes."""
    def code(a):
        for s in shapes:
            a.hex(PRO).rel32("e8", 0).hex(s).hex("5d c3 cc cc")
    return make(tmp, [SET3], code, sdk=sdk)


def test_set3_nonfatal_patch_and_done(tmp_path):
    g, lay = set3_game(tmp_path, ["85c0 7405 b8 01000000", "85c0 7402 90 90"])
    rep, out = run(g, tmp_path, target=7, rules=("set3-nonfatal",))
    assert rep.ok
    b0, b = Binary.load(g / "eboot.bin"), Binary.load(out / "eboot.bin")
    diff = [i for i in range(0x100) if b0.read(i, 1) != b.read(i, 1)]
    assert len(diff) == 2 and all(b.read(i, 1) == b"\xeb" and b0.read(i, 1) == b"\x74" for i in diff)
    assert [e.kind for e in rep.edits if e.kind.startswith("rule")] == ["rule:set3-nonfatal"] * 2
    rep2 = build(out, BuildOptions(target=7, out=tmp_path / "o2", rules={"set3-nonfatal"}, force=True), None, **QUIET)
    f = [x for x in rep2.findings if x["rule"] == "set3-nonfatal"][0]
    assert f["reason"].startswith("DONE") and not any("set3" in w for w in rep2.warnings)


def test_set3_nonfatal_refuses_unknown_shape_and_other_targets(tmp_path):
    g, lay = set3_game(tmp_path, ["85c0 7405 b8 01000000", "89c3 90 90"])      # second caller: shape unknown
    rep, out = run(g, tmp_path, target=8, rules=("set3-nonfatal",))
    b0, b = Binary.load(g / "eboot.bin"), Binary.load(out / "eboot.bin")
    assert b0.read(0, 0x100) == b.read(0, 0x100)                              # none patched
    f = [x for x in rep.findings if x["rule"] == "set3-nonfatal"][0]
    assert not f["applicable"] and f["reason"].startswith("UNKNOWN")
    g2, _ = set3_game(tmp_path / "t", ["85c0 7405 b8 01000000"], sdk=0x10000038)
    for target in (10, 5):                                                    # outside 6..9: no finding
        rep, _ = run(g2, tmp_path / f"t{target}", target=target, rules=("set3-nonfatal",), force=True)
        assert not [x for x in rep.findings if x["rule"] == "set3-nonfatal"]


def test_set3_seed_below_6_via_compat_stubs(tmp_path):
    g, lay = set3_game(tmp_path, ["85c0 7405 b8 01000000"])
    rep, out = run(g, tmp_path, target=5)
    b = Binary.load(out / "eboot.bin")
    assert b.read(got_of(b, lay), 3) == bytes.fromhex("31c0c3")


# ---- real community backports (local only) ---------------------------------------------------

TREE = os.environ.get("PS5BP_DECKERR_TREE")
GOW = (Path(TREE) / "D/fixing input/unity_input_gui/experimental_outputs/PPSA28997_GOD_OF_WAR_SONS_OF_SPARTA_01008001_V8/test_builds"
       if TREE else None)


@pytest.mark.skipif(not (GOW and GOW.is_dir()), reason="PS5BP_DECKERR_TREE not set / absent")
def test_real_working_build_is_done_and_reseeds(tmp_path):
    import zipfile
    zf = next(GOW.glob("*.zip"))
    with zipfile.ZipFile(zf) as z:
        z.extract("eboot.bin", tmp_path)
    b = Binary.load(tmp_path / "eboot.bin")
    c = contracts.load()[OPMODE]
    p = got_seed.plan(b, OPMODE, c.stub)
    assert p.status == "DONE" and p.cur == 0x105DD10 and p.got == 0x1E18218
    # revert the GOT slot only (the community cave stays): a fresh seed takes one of the many
    # 15-byte int3 runs after a ret/jmp instead
    b2 = Binary(bytes(b.data), tmp_path / "eboot.bin")
    b2.patch(p.got, struct.pack("<Q", p.cur), struct.pack("<Q", p.plt + 6))
    b2.writes.clear()
    p2 = got_seed.plan(b2, OPMODE, c.stub)
    assert p2.status == "PATCH"
    slots = got_seed.free_slots(b2, len(c.stub))
    assert len(slots) > 1000 and 0x105DD10 not in slots
    got_seed.apply(b2, p2, c.stub)
    new = b2.u64(p.got)
    assert new == slots[0] and b2.read(new, 15) == c.stub and b2.read(new + 15, 1) == b.read(new + 15, 1)
    assert len(b2.writes) == 2                                       # the stub and the GOT slot, nothing else
