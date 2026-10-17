"""Local-only validation against community backport binaries (skipped unless PS5BP_DECKERR_TREE points at them)."""
import glob
import io
import os
import struct
import zipfile
from pathlib import Path

import pytest

from ps5bp.core.binary import Binary
from ps5bp.core.rules import sync_umtx as su

TREE = os.environ.get("PS5BP_DECKERR_TREE")
pytestmark = pytest.mark.skipif(not TREE or not Path(TREE).is_dir(), reason="PS5BP_DECKERR_TREE not set")


def _member(pattern: str, member: str) -> bytes:
    hits = sorted(glob.glob(f"{TREE}/D/**/{pattern}", recursive=True))
    if not hits:
        pytest.skip(f"no {pattern} under the tree")
    with zipfile.ZipFile(hits[0]) as z:
        return z.read(member)


def astro():
    base = _member("baselines/*PPSA21567 ASTRO BOT*.zip", "sce_module/libc.prx")
    work = _member("BACKPORT/backports/*PPSA21567 ASTRO BOT*.zip", "sce_module/libc.prx")
    return base, work


def test_astro_libc_sites_match_working_build():
    base, work = astro()
    bb, wb = Binary(base), Binary(work)
    pl = su.plan_module(bb, 4)
    assert pl.status == "PATCH"
    assert [s.va for s in pl.convert] == [0x115B50, 0x115B60]                       # Wait, Wake PLT entries
    edits = su.build_edits(bb, pl)
    for rva, old, new, _ in edits:
        bb.patch(rva, old, new)
    # sites shared with the working (community) variant: PLT entries, GOT slot, import strings
    assert bb.read(0x115B50, 10) == wb.read(0x115B50, 10)                          # Wait64 shim prefix
    assert bb.read(0x115B60, 10) == wb.read(0x115B60, 10)                          # Wake shim prefix
    assert bb.read(0x1A8DC1, 32) == wb.read(0x1A8DC1, 32)                          # renamed strings
    assert Binary(base).u64(0x192600) == 0x115B56 and bb.u64(0x192600) != 0x115B56   # GOT slot -> relocated lazy tail
    assert wb.u64(0x192600) != 0x115B56                                             # (theirs: 0x1150d1)
    assert su.plan_module(wb, 4).status == "DONE"
    assert su.plan_module(bb, 4).status == "DONE"


def test_astro_libc_patched_shims_run_in_emulation():
    unicorn = pytest.importorskip("unicorn")
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_HOOK_CODE
    import unicorn.x86_const as X
    base, _ = astro()
    b = Binary(base)
    pl = su.plan_module(b, 4)
    for rva, old, new, _ in su.build_edits(b, pl):
        b.patch(rva, old, new)
    img = b.to_elf()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    BASE = 0x10000000
    for p in b.loads():
        data = b.segment_bytes(p)
        lo = BASE + p.vaddr // 0x1000 * 0x1000
        hi = BASE + (p.vaddr + max(p.memsz, len(data)) + 0xFFF) // 0x1000 * 0x1000
        try:
            uc.mem_map(lo, hi - lo, UC_PROT_ALL)
        except Exception:                                                           # noqa: BLE001 overlapping page
            pass
        uc.mem_write(BASE + p.vaddr, data)
    got = 0x192600
    FAKE, HALT, STK = 0x30000000, 0x30001000, 0x40000000
    uc.mem_map(0x30000000, 0x2000, UC_PROT_ALL)
    uc.mem_map(STK, 0x10000, UC_PROT_ALL)
    uc.mem_write(FAKE, b"\xc3")
    uc.mem_write(HALT, b"\xf4")
    uc.mem_write(BASE + got, struct.pack("<Q", FAKE))          # slot already bound
    calls = []

    def hook(u, a, s, _):
        calls.append((u.reg_read(X.UC_X86_REG_RDI), u.reg_read(X.UC_X86_REG_RSI) & 0xFFFFFFFF,
                      u.reg_read(X.UC_X86_REG_RDX), u.reg_read(X.UC_X86_REG_R8),
                      u.reg_read(X.UC_X86_REG_RSP) % 16))
        u.reg_write(X.UC_X86_REG_RAX, 0)
    uc.hook_add(UC_HOOK_CODE, hook, begin=FAKE, end=FAKE)

    def run(rip, rdi, rsi, rdx):
        top = STK + 0x8000
        uc.reg_write(X.UC_X86_REG_RSP, top - 8)
        uc.mem_write(top - 8, struct.pack("<Q", HALT))
        for r, v in ((X.UC_X86_REG_RDI, rdi), (X.UC_X86_REG_RSI, rsi), (X.UC_X86_REG_RDX, rdx)):
            uc.reg_write(r, v)
        calls.clear()
        uc.emu_start(BASE + rip, HALT)
        assert uc.reg_read(X.UC_X86_REG_RSP) == top
    run(0x115B50, 0xAAAA, 1, 0)                                # libc __std_init_once: Wait(addr, 1, NULL)
    assert calls == [(0xAAAA, 2, 1, 0, 8)]
    run(0x115B60, 0xBBBB, 0x7FFFFFFF, 0)                       # Wake(addr, all)
    assert calls == [(0xBBBB, 3, 0x7FFFFFFF, 0, 8)]


def _all_zip_members(suffix: str):
    for p in sorted(glob.glob(f"{TREE}/D/**/*.zip", recursive=True)):
        with zipfile.ZipFile(p) as z:
            for i in z.infolist():
                if i.filename.endswith(suffix) and i.file_size < 400_000_000:
                    yield Path(p).name[:40], i.filename, z.read(i)


def test_every_community_libc_gets_a_coherent_sync_patch_or_a_reasoned_refusal():
    n_patch = n_done = 0
    for zname, member, raw in _all_zip_members("libc.prx"):
        b = Binary(raw)
        pl = su.plan_module(b, 4)
        if pl is None:
            continue
        if pl.status == "DONE":
            n_done += 1
            continue
        assert pl.status == "PATCH", (zname, pl.why)
        for rva, old, new, _ in su.build_edits(b, pl):
            b.patch(rva, old, new)
        again = su.plan_module(b, 4)
        assert again is not None and again.status == "DONE", zname
        n_patch += 1
    assert n_patch >= 5 and n_done >= 1


def test_ps5util_donor_has_no_sync_imports_left():
    for zname, member, raw in _all_zip_members("Media/Modules/PS5Util.prx"):
        assert su.plan_module(Binary(raw), 4) is None


def test_trinity_gate_on_gow_eboot():
    from ps5bp.core import dynamic
    from ps5bp.core.rules import trinity_hw_gate as tg
    for zname, member, raw in _all_zip_members("eboot.bin"):
        if "GOD_OF_WAR" not in zname and "GOD" not in zname:
            continue
        b = Binary(raw)
        pl = tg.plan_module(b, 4)
        assert pl is not None and pl.status == "PATCH" and pl.seed and pl.op is None   # OperationMode is only GOT-seeded
        for rva, old, new, _ in tg.build_edits(b, pl):
            b.patch(rva, old, new)
        d = dynamic.parse(b)
        assert tg.HAS_TRINITY in d.imported_nids() and tg.IS_TRINITY not in d.imported_nids()
        assert tg.plan_module(b, 4).status == "DONE"
        return
    pytest.skip("GoW V8 eboot not in the tree")


def test_astro_libc_through_the_build_pipeline(tmp_path):
    """Build verification (any byte outside a recorded edit fails) on the real ASTRO libc."""
    from ps5bp.core.pipeline import BuildOptions, build
    from synth import Spec, build_elf, build_self
    base, _ = astro()
    g = tmp_path / "PPSA21567"
    (g / "sce_module").mkdir(parents=True)
    (g / "eboot.bin").write_bytes(build_self(build_elf(Spec(import_libs=["libkernel"], imports=[("rTXw65xmLIA", 0)]))[0]))
    (g / "sce_module/libc.prx").write_bytes(base)
    rep = build(g, BuildOptions(target=4, out=tmp_path / "o", rules={"sync-umtx"}, force=True), None, log=lambda m: None)
    assert rep.ok
    es = [e for e in rep.edits if e.kind == "rule:sync-umtx"]
    assert len(es) == 10                                   # 5 cave pieces, 2 PLT shims, GOT slot, 2 strings
    nb = Binary.load(tmp_path / "o/sce_module/libc.prx")
    assert su.plan_module(nb, 4).status == "DONE"
