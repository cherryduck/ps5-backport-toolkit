"""pro-disable: run a PS5 Pro build like a base PS5 (no Pro code path, no PSSR).

Generic replacement for per-game branch flips (e.g. Wolverine's jne->jmp at the
Pro-flag store):
  * NH6xARDOVv8 (hardware query, writes *rdi and *rsi) is replaced by
        xor eax, eax ; mov [rdi], eax ; mov [rsi], eax ; ret
    Both outputs 0, the values DLPS's FW4 libScePsml stub writes for the same NID.
    In Wolverine *rdi==3 selects the Pro path and *rsi==1 selects 8 CPU threads
    (else 13), so 0/0 = base PS5 with the normal 13 threads.
  * sceKernelIsTrinityMode is replaced by  xor eax, eax ; ret   (as both PPSA11386 kits do)
The PLT entry itself becomes the stub.  When coverage proves the NID absent on the
target FW, the import symbol is also bound locally so the loader doesn't need it.
"""
from __future__ import annotations

from ..nid import nid
from . import Finding, Rule, RuleContext
from .common import imports_nid, localize, proven_absent, stub_plt

PRO_QUERY = "NH6xARDOVv8"
TRINITY = nid("sceKernelIsTrinityMode")

BODIES = {
    PRO_QUERY: bytes.fromhex("31c0 8907 8906 c3".replace(" ", "")),
    TRINITY: bytes.fromhex("31c0c3"),
}
LABEL = {PRO_QUERY: "Pro hardware query", TRINITY: "sceKernelIsTrinityMode"}


class ProDisable(Rule):
    name = "pro-disable"
    summary = "Disable the PS5 Pro code path (Pro query -> base PS5, Trinity -> 0)"
    conflicts = ("pssr-memory",)

    def detect(self, ctx: RuleContext) -> list[Finding]:
        out = []
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error:
                continue
            for n in (PRO_QUERY, TRINITY):
                if not imports_nid(ctx.load(bi.path), n):
                    continue
                absent = proven_absent(ctx, "libkernel", n)
                out.append(Finding(self.name, bi.path, f"{LABEL[n]} imported by {bi.path}",
                                   recommended=absent,
                                   reason=f"{n} is proven absent on {ctx.target}.xx" if absent else "",
                                   data={"nid": n, "localize": absent}))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        base = ctx.base_for(f.file)
        n = f.data["nid"]
        r = stub_plt(b, n, base, BODIES[n])
        if r is None:
            raise ValueError(f"{f.file}: {n} has no standard PLT stub — cannot apply {self.name}")
        off, old, new, stub_rva = r
        ctx.edit(f.file, f"rule:{self.name}", off, old.hex(), new.hex(), f"{LABEL[n]} stub -> base PS5")
        if f.data.get("localize"):
            for o, old, new in localize(b, n, stub_rva):
                ctx.edit(f.file, f"rule:{self.name}", o, old.hex(), new.hex(),
                         f"bind {n} locally (absent on target)")
