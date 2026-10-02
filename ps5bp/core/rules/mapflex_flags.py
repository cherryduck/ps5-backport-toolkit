"""mapflex-flags: clear flag 0x8000 where libc calls the retargeted flexible-memory import.

The libc retarget (nid_retarget.txt: 4h6F1LLbTiw -> IWIBBdTHit4,
sceKernelMapNamedFlexibleMemoryInternal -> sceKernelMapFlexibleMemory) keeps the call
sites as they were, including `mov ecx, 0x8000` — a flag of the internal variant. DLPS's
ACE COMBAT 8 build also clears it (`mov ecx, 0`); their earlier PPSA11386 build did not.
Off by default; recommended when such a call site exists.
"""
from __future__ import annotations

from ..asm import plt_stubs, stub_for
from .. import dynamic
from .. import x86flow as xf
from . import Finding, Rule, RuleContext

NIDS = ("IWIBBdTHit4", "4h6F1LLbTiw")
OLD, NEW = bytes.fromhex("b900800000"), bytes.fromhex("b900000000")


def sites(b, base: int) -> list[int]:
    """VAs of `mov ecx, 0x8000` that set the flags argument of a call to the import."""
    d = dynamic.parse(b)
    if not d:
        return []
    st = plt_stubs(b, d, base)
    tgts = {va for n in NIDS if (va := stub_for(st, n)) is not None}
    if not tgts:
        return []
    from ..memsite import Scanner
    sc = Scanner(b, base)
    out = []
    for t in tgts:
        for call in sc.calls_to(t):
            fn = xf.function_at(sc.read, call, 0x2000)
            try:
                k = fn.index(call)
            except KeyError:
                continue
            j = xf.last_write(fn, "rcx", k, max(-1, k - 12))
            if j is not None and fn.insns[j].bytes == OLD:
                out.append(fn.insns[j].address)
    return sorted(out)


class MapflexFlags(Rule):
    name = "mapflex-flags"
    summary = "Clear flag 0x8000 at libc's calls of the retargeted MapFlexibleMemory"

    def detect(self, ctx: RuleContext) -> list[Finding]:
        out = []
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error or not any(n in nids for nids in bi.imports_by_module.values()
                                                           for n in NIDS):
                continue
            for va in sites(ctx.load(bi.path), ctx.base_for(bi.path)):
                out.append(Finding(self.name, bi.path, f"{va:#x}: mov ecx, 0x8000 -> 0 (flags of the "
                                   "retargeted flexible-memory call)", recommended=True, data={"va": va}))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        off = b.patch(f.data["va"] - ctx.base_for(f.file), OLD, NEW)
        ctx.edit(f.file, f"rule:{self.name}", off, OLD.hex(), NEW.hex(), f"{f.data['va']:#x} flags 0x8000 -> 0")
