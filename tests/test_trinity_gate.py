"""trinity-hw-gate on synthetic modules + unicorn check of the derived OperationMode / AGC bodies."""
import struct

import pytest

from ps5bp.core import dynamic
from ps5bp.core.binary import Binary
from ps5bp.core.rules import registry, resolve
from ps5bp.core.rules import trinity_hw_gate as tg
from test_sync_umtx import sync_elf
from synth import build_self

IS, HAS, OP, AGC = tg.IS_TRINITY, tg.HAS_TRINITY, tg.OPMODE, tg.AGC_IS_TRINITY


def make(imports, forced=(), got_bad=False, target_plt=None):
    raw, lay = sync_elf(imports)
    b = Binary(build_self(raw))
    for nid_, body in forced:
        k = imports.index(nid_)
        va = 16 * (k + 1)
        b.patch(va, b.read(va, len(body)), body)
    return b


def test_registered_off_by_default_not_recommended():
    r = registry()["trinity-hw-gate"]
    assert not r.default and "pro-disable" in r.conflicts
    with pytest.raises(ValueError, match="conflicts"):
        resolve({"trinity-hw-gate", "pro-disable"}, set())


def test_plain_import_renamed_and_seeded_below_7():
    b = make([IS, "KKKKKKKKKK1"])
    pl = tg.plan_module(b, 4)
    assert pl.status == "PATCH" and pl.seed and not pl.forced_is and pl.op is None
    for rva, old, new, note in tg.build_edits(b, pl):
        b.patch(rva, old, new)
    d = dynamic.parse(b)
    assert {s.nid for s in d.imports()} == {HAS, "KKKKKKKKKK1"}
    s = pl.is_slot
    got = b.u64(s.got)
    assert got != s.va + 6 and b.read(got, 3) == bytes.fromhex("31c0c3")
    assert b.read(s.va, 2) == b"\xff\x25"                       # PLT untouched
    assert tg.plan_module(b, 4).status == "DONE"


def test_no_seed_from_7():
    b = make([IS, "KKKKKKKKKK1"])
    pl = tg.plan_module(b, 7)
    assert pl.status == "PATCH" and not pl.seed
    edits = tg.build_edits(b, pl)
    assert len(edits) == 1                                      # just the rename
    for e in edits:
        b.patch(e[0], e[1], e[2])
    assert tg.plan_module(b, 7) is None                         # imports Has, nothing derived: not our marker


FORCED = [(IS, tg.FORCED_IS), (OP, tg.FORCED_OPMODE), (AGC, tg.FORCED_AGC)]


def test_forced_stubs_restored_and_derived():
    b = make([IS, OP, AGC, "KKKKKKKKKK1"], forced=FORCED)
    pl = tg.plan_module(b, 4)
    assert pl.status == "PATCH" and pl.forced_is and pl.op and pl.agc and pl.forced_pro
    for rva, old, new, note in tg.build_edits(b, pl):
        b.patch(rva, old, new)
    is_va, op_va, agc_va = 16, 32, 48
    canon = b.read(is_va, 16)
    assert canon[:2] == b"\xff\x25" and canon[6] == 0x68 and canon[11] == 0xE9
    assert b.read(op_va, 1) == b"\xe9"                           # jmp cave
    assert b.read(agc_va, 12)[:1] == b"\x57" and b.read(agc_va + 6, 1) == b"\x5f"
    # the forced entries are not forced any more: second plan sees only the gate
    assert tg.plan_module(b, 4).status == "DONE"


def test_forced_stub_tail_may_be_cc_padded():
    b = make([IS, "KKKKKKKKKK1"], forced=[(IS, tg.FORCED_IS + b"\xcc" * 10)])
    pl = tg.plan_module(b, 4)
    assert pl.status == "PATCH" and pl.forced_is
    for rva, old, new, note in tg.build_edits(b, pl):
        b.patch(rva, old, new)
    e = b.read(16, 16)
    assert e[6] == 0x68 and struct.unpack_from("<I", e, 7)[0] == 0     # idx of slot 0 rebuilt


def test_refusals():
    # both imported
    assert "both" in tg.plan_module(make([IS, HAS, "KKKKKKKKKK1"]), 4).why
    # forced Pro stub without a TrinityMode import
    p = tg.plan_module(make([OP, "KKKKKKKKKK1"], forced=[(OP, tg.FORCED_OPMODE)]), 4)
    assert p.status == "UNKNOWN" and "without a TrinityMode import" in p.why
    # Has imported while forced stubs remain
    p = tg.plan_module(make([HAS, OP, "KKKKKKKKKK1"], forced=[(OP, tg.FORCED_OPMODE)]), 4)
    assert p.status == "UNKNOWN" and "forced-Pro stubs remain" in p.why
    # PLT neither lazy nor forced-1 (a return-0 stub)
    p = tg.plan_module(make([IS, "KKKKKKKKKK1"], forced=[(IS, bytes.fromhex("31c0c3"))]), 4)
    assert p.status == "UNKNOWN" and "neither lazy nor the forced-1" in p.why
    # GOT neither lazy nor a return-0 seed
    b = make([IS, "KKKKKKKKKK1"])
    d = dynamic.parse(b)
    got = [s for s in tg.jump_slots(b, d) if s.nid == IS][0].got
    b.patch(got, b.read(got, 8), struct.pack("<Q", 0x2A0))
    p = tg.plan_module(b, 4)
    assert p.status == "UNKNOWN" and "not a return-0 seed" in p.why
    # no int3 padding for the cave
    b = make([IS, OP, "KKKKKKKKKK1"], forced=[(IS, tg.FORCED_IS), (OP, tg.FORCED_OPMODE)])
    off = b.foff(0)
    for i in range(0x40, 0x400):
        if b.data[off + i] == 0xCC:
            b.data[off + i] = 0x90
    p = tg.plan_module(b, 4)
    assert p.status == "UNKNOWN" and "int3 padding" in p.why


def test_target_7_plus_untouched_without_import():
    assert tg.plan_module(make(["KKKKKKKKKK1"]), 4) is None


# ---------------------------------------------------------------- emulation of the derived bodies
unicorn = pytest.importorskip("unicorn")
import unicorn.x86_const as X  # noqa: E402

CODE, DATA, STACK = 0x100000, 0x200000, 0x300000
HAS_PLT, HALT = CODE + 0x800, CODE + 0x900


def emu(code: bytes, at: int, has_result: int, rdi: int, rsi: int):
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for base in (CODE, DATA, STACK):
        uc.mem_map(base, 0x10000, unicorn.UC_PROT_ALL)
    uc.mem_write(at, code)
    uc.mem_write(HAS_PLT, b"\xb8" + struct.pack("<I", has_result) + b"\xc3")      # mov eax, N; ret
    uc.mem_write(HALT, b"\xf4")
    top = STACK + 0x8000
    uc.mem_write(top - 8, struct.pack("<Q", HALT))
    uc.reg_write(X.UC_X86_REG_RSP, top - 8)
    uc.mem_write(DATA, b"\xaa" * 16)
    uc.reg_write(X.UC_X86_REG_RDI, rdi)
    uc.reg_write(X.UC_X86_REG_RSI, rsi)
    # a hook on the Has stub checks the call alignment
    seen = []
    uc.hook_add(unicorn.UC_HOOK_CODE, lambda u, a, s, _: seen.append(u.reg_read(X.UC_X86_REG_RSP) % 16),
                begin=HAS_PLT, end=HAS_PLT)
    uc.emu_start(at, HALT)
    assert uc.reg_read(X.UC_X86_REG_RSP) == top and seen == [8]
    return uc, uc.reg_read(X.UC_X86_REG_RAX)


@pytest.mark.parametrize("has,want", [(0, 2), (1, 3), (0xFFFFFF01, 3), (0x100, 2)])
def test_operation_mode_cave(has, want):
    code = tg.opmode_cave(CODE + 0x100, HAS_PLT)
    uc, rax = emu(code, CODE + 0x100, has, DATA, DATA + 8)
    mode, _ = struct.unpack("<II", bytes(uc.mem_read(DATA, 8)))
    low, = struct.unpack("<I", bytes(uc.mem_read(DATA + 8, 4)))
    assert (mode, low, rax) == (want, 0, 0)
    assert bytes(uc.mem_read(DATA + 4, 4)) == b"\xaa" * 4          # nothing else clobbered


@pytest.mark.parametrize("has", [0, 1])
def test_agc_body(has):
    body = tg.agc_body(CODE + 0x200, HAS_PLT)
    uc, rax = emu(body, CODE + 0x200, has, DATA, 0)
    assert uc.mem_read(DATA, 2) == bytes([has, 0xAA]) and rax == 0


# ---------------------------------------------------------------- through the pipeline
def _game(tmp_path, with_stack: bool, forced: bool):
    from ps5bp.core.pipeline import BuildOptions  # noqa: F401
    from test_sync_umtx import sync_self
    g = tmp_path / ("G" + str(with_stack) + str(forced))
    g.mkdir(exist_ok=True)
    imports = [IS, OP, AGC, "KKKKKKKKKK1"]
    raw = sync_self(imports, strings=b"\0/app0/k9.psp\0" if with_stack else b"")
    b = Binary(raw)
    if forced:
        for nid_, body in FORCED:
            va = 16 * (imports.index(nid_) + 1)
            b.patch(va, b.read(va, len(body)), body)
    (g / "eboot.bin").write_bytes(bytes(b.data))
    if with_stack:
        (g / "k9.psp").write_bytes(b"m")
    return g


def test_build_forced_pro_needs_the_pro_stack(tmp_path):
    from ps5bp.core.pipeline import BuildOptions, BuildError, build
    rep = build(_game(tmp_path, False, True), BuildOptions(target=4, out=tmp_path / "a", rules={"trinity-hw-gate"}),
                None, log=lambda m: None)
    f = [x for x in rep.findings if x["rule"] == "trinity-hw-gate"]
    assert f and not f[0]["applied"] and "Pro stack" in f[0]["reason"]
    rep = build(_game(tmp_path, True, True), BuildOptions(target=4, out=tmp_path / "b", rules={"trinity-hw-gate"}),
                None, log=lambda m: None)
    f = [x for x in rep.findings if x["rule"] == "trinity-hw-gate"]
    assert rep.ok and f and f[0]["applied"] and not f[0]["recommended"]
    nb = Binary.load(tmp_path / "b/eboot.bin")
    assert tg.plan_module(nb, 4).status == "DONE"
    with pytest.raises(BuildError, match="conflicts"):
        build(_game(tmp_path, True, True), BuildOptions(target=4, out=tmp_path / "c",
                                                        rules={"trinity-hw-gate", "pro-disable"}), None,
              log=lambda m: None)


def test_build_unforced_needs_no_stack_and_is_not_recommended(tmp_path):
    from ps5bp.core.pipeline import BuildOptions, build
    g = _game(tmp_path, False, False)
    rep = build(g, BuildOptions(target=4, out=tmp_path / "a"), None, log=lambda m: None)
    assert not any("trinity-hw-gate" in w for w in rep.warnings)          # off + never recommended
    rep = build(g, BuildOptions(target=4, out=tmp_path / "b", rules={"trinity-hw-gate"}), None, log=lambda m: None)
    assert rep.ok and [x for x in rep.findings if x["rule"] == "trinity-hw-gate" and x["applied"]]
