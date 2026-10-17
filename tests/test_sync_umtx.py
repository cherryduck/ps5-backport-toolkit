"""sync-umtx: synthetic modules (PATCH / DONE / refusals / existing _umtx_op) and unicorn emulation
of the generated shims + helpers against a fake `_umtx_op`."""
import struct

import pytest

from ps5bp.core import dynamic
from ps5bp.core.binary import Binary
from ps5bp.core.pipeline import BuildOptions, build
from ps5bp.core.rules import sync_umtx as su
from synth import DATA_OFF, DATA_VA, Spec, build_elf, build_self

W32, W64, WAKE, WAIT, UMTX = su.WAIT32, su.WAIT64, su.WAKE, su.WAIT, su.UMTX


def sync_elf(imports, bind_now=False, lazy=True, strings=b"", text_extra=b""):
    """Module with a real PLT0 at 0, entry k at 16*(k+1), lazy GOT, a caller, and int3 padding."""
    spec = Spec(import_libs=["libkernel"], imports=[(n, 0) for n in imports], kind="module", module="libtest",
                needed=["libkernel.prx"], strings=strings)
    _, lay = build_elf(spec)
    text = bytearray(b"\xcc" * 0x400)
    text[0:16] = b"\xff\x35" + b"\0" * 4 + b"\xff\x25" + b"\0" * 4 + b"\xcc" * 4          # PLT0 (dummy)
    for k, got in enumerate(lay["got"]):
        va = 16 * (k + 1)
        text[va:va + 16] = (b"\xff\x25" + struct.pack("<i", got - (va + 6)) + b"\x68" + struct.pack("<I", k)
                            + b"\xe9" + struct.pack("<i", -(va + 16)))
    call_at = 16 * (len(imports) + 1) + 16
    code = b"".join(b"\xe8" + struct.pack("<i", 16 * (k + 1) - (call_at + 5 * k + 5)) for k in range(len(imports)))
    text[call_at:call_at + len(code)] = code + b"\xc3"
    spec.text = bytes(text)
    elf, lay2 = build_elf(spec)
    assert lay2["got"] == lay["got"]
    elf = bytearray(elf)
    if lazy:
        for k, got in enumerate(lay["got"]):
            struct.pack_into("<Q", elf, DATA_OFF + got - DATA_VA, 16 * (k + 1) + 6)
    if bind_now:                                      # DT_PLTREL (0x14) -> DT_FLAGS = DF_BIND_NOW
        dyn = lay["dyn"]
        for i in range(0, 0x400, 16):
            tg, = struct.unpack_from("<q", elf, DATA_OFF + dyn - DATA_VA + i)
            if tg == 0x14:
                struct.pack_into("<qQ", elf, DATA_OFF + dyn - DATA_VA + i, 0x1E, 8)
                break
    return bytes(elf), lay


def sync_self(*a, **k):
    return build_self(sync_elf(*a, **k)[0])


def load(imports, **k):
    return Binary(sync_self(imports, **k))


# ---------------------------------------------------------------- planning
def test_patch_plan_and_sites():
    b = load([W32, W64, WAKE, WAIT])
    pl = su.plan_module(b, 4)
    assert pl.status == "PATCH" and [s.nid for s in pl.convert] == [W32, W64, WAKE, WAIT]
    assert pl.anchor_slot.nid == W32 and pl.umtx_plt is None and set(pl.placement) == {"plain", "ta", "ta2", "tb", "tail"}
    assert len(pl.renames) == 4 and all(new[:11] == UMTX.encode() for _, _, new in pl.renames)


def test_target_gates():
    b = load([W32, W64, WAKE, WAIT])
    assert su.plan_module(b, 9) is None                      # everything exported on 9.xx
    pl = su.plan_module(b, 7)                                # Wake/Wait exist (6.00), Wait32/64 don't (9.00)
    assert [s.nid for s in pl.convert] == [W32, W64]
    assert su.plan_module(load([WAKE, WAIT]), 6) is None
    assert su.plan_module(load(["KKKKKKKKKK1"]), 4) is None


def test_apply_edits_and_done():
    b = load([W32, W64, WAKE, WAIT, "KKKKKKKKKK1"])      # a real module keeps other imports: PLT0 is found from one
    pl = su.plan_module(b, 4)
    raw = bytes(b.data)
    for rva, old, new, note in su.build_edits(b, pl):
        b.patch(rva, old, new)
    d = dynamic.parse(b)
    assert {s.nid for s in d.imports()} == {UMTX, "KKKKKKKKKK1"}
    assert len([s for s in d.imports() if s.nid == UMTX]) == 4
    again = su.plan_module(b, 4)
    assert again.status == "DONE"
    # only the PLT entries, caves, GOT slot and strings changed
    changed = [i for i in range(len(raw)) if raw[i] != b.data[i]]
    assert changed
    # 16-byte PLT shims
    for k, nid_ in enumerate([W32, W64, WAKE, WAIT]):
        e = b.read(16 * (k + 1), 16)
        assert e.startswith(su.SHIM_PREFIX[nid_]) and len(e) == 16
    # WAIT generic shim == Wait64 shim body
    assert b.read(16 * 2, 10) == b.read(16 * 4, 10)


def test_existing_umtx_import_is_the_anchor():
    b = load([WAKE, WAIT, UMTX])
    pl = su.plan_module(b, 4)
    assert pl.status == "PATCH" and pl.umtx_plt == 16 * 3 and pl.anchor_slot is None
    assert set(pl.placement) == {"plain", "ta", "ta2", "tb"}
    edits = su.build_edits(b, pl)
    assert not any("GOT" in n for *_, n in edits)            # nothing to relocate
    for rva, old, new, note in edits:
        b.patch(rva, old, new)
    assert su.plan_module(b, 4) is None or su.plan_module(b, 4).status == "DONE"
    assert b.read(16 * 3, 2) == b"\xff\x25"                  # the real _umtx_op PLT entry is intact


def test_refusals():
    assert su.plan_module(load([WAKE, WAIT], bind_now=True), 4).status == "UNKNOWN"
    assert "BIND_NOW" in su.plan_module(load([WAKE, WAIT], bind_now=True), 4).why
    p = su.plan_module(load([WAKE, WAIT], lazy=False), 4)
    assert p.status == "UNKNOWN" and "not lazy" in p.why
    b = load([WAKE, WAIT])
    b.patch(16, b.read(16, 2), b"\x90\x90")                  # PLT entry not canonical
    p = su.plan_module(b, 4)
    assert p.status == "UNKNOWN" and "canonical" in p.why
    # GOT slot referenced from code outside the PLT: mov rax,[rip+got]
    raw, lay = sync_elf([WAKE, WAIT])
    b = Binary(build_self(raw))
    at = 0x200
    disp = lay["got"][0] - (at + 7)
    b.patch(at, b.read(at, 7), b"\x48\x8b\x05" + struct.pack("<i", disp))
    p = su.plan_module(b, 4)
    assert p.status == "UNKNOWN" and "GOT" in p.why
    # the same import string twice in the table: not unique
    b = Binary(sync_self([WAKE, WAKE, WAIT]))
    p = su.plan_module(b, 4)
    assert p.status == "UNKNOWN" and "unique" in p.why


def test_no_cave_refused():
    raw, lay = sync_elf([WAKE, WAIT])
    b = Binary(build_self(raw, slack=0))
    t = b.segment_bytes(b.phdrs[0])
    # fill all int3 padding with nops
    off = b.foff(0)
    for i in range(0x40, 0x400):
        if b.data[off + i] == 0xCC:
            b.data[off + i] = 0x90
    p = su.plan_module(b, 4)
    assert p.status == "UNKNOWN" and "no code cave" in p.why


# ---------------------------------------------------------------- pipeline
def test_build_with_rule(tmp_path):
    g = tmp_path / "PPSA99999"
    (g / "sce_module").mkdir(parents=True)
    spec = Spec(import_libs=["libkernel"], imports=[("rTXw65xmLIA", 0)])
    (g / "eboot.bin").write_bytes(build_self(build_elf(spec)[0]))
    (g / "sce_module/libtest.prx").write_bytes(sync_self([WAKE, WAIT, "KKKKKKKKKK1"]))
    rep = build(g, BuildOptions(target=4, out=tmp_path / "o", rules={"sync-umtx"}), None, log=lambda m: None)
    assert rep.ok
    f = [x for x in rep.findings if x["rule"] == "sync-umtx"]
    assert len(f) == 1 and f[0]["applied"] and not f[0]["recommended"]
    kinds = {e.kind for e in rep.edits if e.file == "sce_module/libtest.prx"}
    assert "rule:sync-umtx" in kinds
    nb = Binary.load(tmp_path / "o/sce_module/libtest.prx")
    assert su.plan_module(nb, 4).status == "DONE"
    # off by default and never recommended
    rep2 = build(g, BuildOptions(target=4, out=tmp_path / "o2"), None, log=lambda m: None)
    assert not any("sync-umtx" in w and "recommended" in w for w in rep2.warnings)
    assert su.plan_module(Binary.load(tmp_path / "o2/sce_module/libtest.prx"), 4).status == "PATCH"


# ---------------------------------------------------------------- unicorn emulation
unicorn = pytest.importorskip("unicorn")
from unicorn import UC_HOOK_CODE, UC_PROT_ALL, Uc  # noqa: E402
import unicorn.x86_const as X  # noqa: E402

CODE, DATA, STACK = 0x100000, 0x200000, 0x300000
FAKE, HALT, GOT = CODE + 0xF000, CODE + 0xF100, DATA + 0x100
SHIMS = CODE + 0x100                      # 4 shims, 16 bytes each
PIECES = {"plain": CODE + 0x1000, "ta": CODE + 0x1100, "ta2": CODE + 0x1180, "tb": CODE + 0x1200, "tail": CODE + 0x1300}
PLT_ANCHOR = CODE + 0x1400                # case B: `jmp [GOT]`
PLT0 = CODE + 0x1500
CALLEE_SAVED = {X.UC_X86_REG_RBX: 0xB1, X.UC_X86_REG_RBP: 0xB2, X.UC_X86_REG_R12: 0xB3, X.UC_X86_REG_R13: 0xB4,
                X.UC_X86_REG_R14: 0xB5, X.UC_X86_REG_R15: 0xB6}


class Harness:
    def __init__(self, anchor_kind: str, kinds=(W32, W64, WAKE, WAIT), umtx_ret=0):
        self.calls = []
        self.umtx_ret = umtx_ret
        self.uc = uc = Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc.mem_map(CODE, 0x20000, UC_PROT_ALL)
        uc.mem_map(DATA, 0x10000, UC_PROT_ALL)
        uc.mem_map(STACK, 0x10000, UC_PROT_ALL)
        kinds = set(kinds)
        if anchor_kind == "plt":
            anchor, tail = ("plt", PLT_ANCHOR), None
            uc.mem_write(GOT, struct.pack("<Q", FAKE))
            uc.mem_write(PLT_ANCHOR, b"\xff\x25" + struct.pack("<i", GOT - (PLT_ANCHOR + 6)))
        else:
            # first call goes through the relocated lazy tail -> "resolver" (PLT0) which binds the GOT slot
            anchor = ("got", GOT)
            a = su.Asm(PIECES["tail"])
            a.hex("68 07000000")
            a.rel32("e9", PLT0)
            tail = a.assemble()
            uc.mem_write(GOT, struct.pack("<Q", PIECES["tail"]))
            # PLT0 stand-in: pop the pushed index, bind GOT := FAKE, jump to FAKE (args untouched)
            res = bytearray()
            res += bytes.fromhex("41 5b")                                                    # pop r11 (index)
            res += bytes.fromhex("49bb") + struct.pack("<Q", FAKE)                           # mov r11, FAKE
            res += bytes.fromhex("4c891c25") + struct.pack("<I", GOT)                        # mov [GOT], r11
            res += bytes.fromhex("41ffe3")                                                   # jmp r11
            uc.mem_write(PLT0, bytes(res))
        at = dict(PIECES)
        self.pieces = su.pieces_for(kinds, anchor, tail, at)
        for k, v in self.pieces.items():
            uc.mem_write(PIECES[k], v)
        assert "ta2" in self.pieces
        self.shim_at = {}
        for i, n in enumerate((W32, W64, WAKE, WAIT)):
            self.shim_at[n] = SHIMS + 16 * i
            helper = PIECES["plain"] if n == WAKE else PIECES["ta"]
            uc.mem_write(self.shim_at[n], su.shim(n, self.shim_at[n], helper))
        uc.mem_write(FAKE, b"\xc3")
        uc.mem_write(HALT, b"\xf4")
        uc.hook_add(UC_HOOK_CODE, self._hook, begin=FAKE, end=FAKE)

    def _hook(self, uc, addr, size, _):
        rd = lambda r: uc.reg_read(r)                              # noqa: E731
        rsp = rd(X.UC_X86_REG_RSP)
        r8 = rd(X.UC_X86_REG_R8)
        ts = struct.unpack("<qq", bytes(uc.mem_read(r8, 16))) if r8 else None
        self.calls.append({"obj": rd(X.UC_X86_REG_RDI), "op": rd(X.UC_X86_REG_RSI) & 0xFFFFFFFF,
                           "val": rd(X.UC_X86_REG_RDX), "uaddr": rd(X.UC_X86_REG_RCX), "uaddr2": r8,
                           "r9": rd(X.UC_X86_REG_R9), "ts": ts, "rsp_mod16": rsp % 16})
        uc.reg_write(X.UC_X86_REG_RAX, self.umtx_ret)

    def run(self, nid_, rdi, rsi, rdx, rcx=0x7777):
        uc = self.uc
        top = STACK + 0x8000
        uc.reg_write(X.UC_X86_REG_RSP, top - 8)                    # as after a `call`: rsp % 16 == 8
        uc.mem_write(top - 8, struct.pack("<Q", HALT))
        for r, v in CALLEE_SAVED.items():
            uc.reg_write(r, v)
        for r, v in ((X.UC_X86_REG_RDI, rdi), (X.UC_X86_REG_RSI, rsi), (X.UC_X86_REG_RDX, rdx),
                     (X.UC_X86_REG_RCX, rcx)):
            uc.reg_write(r, v)
        self.calls.clear()
        uc.emu_start(self.shim_at[nid_], HALT)
        assert uc.reg_read(X.UC_X86_REG_RSP) == top, "stack not restored"
        for r, v in CALLEE_SAVED.items():
            assert uc.reg_read(r) == v
        return uc.reg_read(X.UC_X86_REG_RAX)

    def timeout(self, us: int) -> int:
        self.uc.mem_write(DATA, struct.pack("<I", us))
        return DATA


@pytest.fixture(params=["plt", "got"])
def h(request):
    return Harness(request.param)


def only(h):
    assert len(h.calls) == 1
    c = h.calls[0]
    assert c["rsp_mod16"] == 8, "misaligned at the _umtx_op call"
    assert c["r9"] == 0xFFFFFFFF and c["uaddr"] == 0
    return c


def test_wait32_timed(h):
    h.run(W32, 0xAAAA0000, 0x11223344, h.timeout(2_500_123))
    c = only(h)
    assert (c["obj"], c["op"], c["val"]) == (0xAAAA0000, 11, 0x11223344)
    assert c["ts"] == (2, 500_123_000)


def test_wait32_val_is_32bit(h):
    h.run(W32, 0x1000, 0xFFFFFFFF_FFFFFFFF, 0)
    assert only(h)["val"] == 0xFFFFFFFF                          # mov edx, esi: zero-extended u32 compare value


def test_wait64_timed_and_untimed(h):
    h.run(W64, 0x2000, 0x1_0000_0001, h.timeout(1_000_000))
    c = only(h)
    assert (c["obj"], c["op"], c["val"], c["ts"]) == (0x2000, 2, 0x1_0000_0001, (1, 0))
    h.run(W64, 0x2000, 7, 0)                                     # NULL timeout: wait forever
    c = only(h)
    assert (c["op"], c["val"], c["uaddr2"], c["ts"]) == (2, 7, 0, None)


def test_generic_wait_untimed_ignores_name_arg(h):
    h.run(WAIT, 0x3000, 1, 0, rcx=0xDEAD0000)                    # libc init-once: (addr, 1, NULL, "SceLibcIV2Once")
    c = only(h)
    assert (c["obj"], c["op"], c["val"], c["uaddr"], c["uaddr2"]) == (0x3000, 2, 1, 0, 0)


def test_zero_timeout_is_a_zero_timespec_not_null(h):
    h.run(W32, 0x4000, 5, h.timeout(0))
    c = only(h)
    assert c["uaddr2"] != 0 and c["ts"] == (0, 0)


def test_timeout_saturated_value(h):
    h.run(W32, 0x4000, 5, h.timeout(0xFFFFFFFF))
    assert only(h)["ts"] == (4294, 967_295_000)


def test_timeout_edges(h):
    for us, want in ((1, (0, 1000)), (999_999, (0, 999_999_000)), (1_000_000, (1, 0)), (1_000_001, (1, 1000))):
        h.run(W64, 0x5000, 0, h.timeout(us))
        assert only(h)["ts"] == want, us


def test_wake_one_and_all(h):
    h.run(WAKE, 0x6000, 1, 0)
    c = only(h)
    assert (c["obj"], c["op"], c["val"], c["uaddr2"]) == (0x6000, 3, 1, 0)
    h.run(WAKE, 0x6000, 0x7FFFFFFF, 0, rcx=0x1234)
    c = only(h)
    assert (c["op"], c["val"], c["uaddr"], c["uaddr2"]) == (3, 0x7FFFFFFF, 0, 0)


def test_wake_negative_count_is_sign_extended(h):
    h.run(WAKE, 0x6000, 0xFFFFFFFF, 0)                           # int -1
    assert only(h)["val"] == 0xFFFFFFFF_FFFFFFFF


def test_result_passthrough():
    for kind in ("plt", "got"):
        hh = Harness(kind, umtx_ret=0xFFFFFFFFFFFFFFFF)
        assert hh.run(W32, 0x1000, 1, hh.timeout(5)) == 0xFFFFFFFFFFFFFFFF
        assert hh.run(WAKE, 0x1000, 1, 0) == 0xFFFFFFFFFFFFFFFF
