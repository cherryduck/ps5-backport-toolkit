"""stub-absent: neutralise imports that are proven absent on the target firmware.

For every import of a game binary that coverage proves absent on the target (and no
fakelib supplies), the PLT entry becomes `xor eax, eax ; ret` and the symbol is bound
locally — the technique kit authors use inside fakelibs. A blunt instrument: the
function now does nothing and returns 0. Off by default; NIDs owned by a more
specific rule (pro-disable) are skipped.
"""
from __future__ import annotations

from . import Finding, Rule, RuleContext
from .common import localize, stub_plt
from .pro import BODIES as PRO_BODIES

BODY = bytes.fromhex("31c0c3")


class StubAbsent(Rule):
    name = "stub-absent"
    summary = "Stub (return 0) every import proven absent on the target FW"

    def detect(self, ctx: RuleContext) -> list[Finding]:
        if not ctx.cov:
            return []
        absent = {m.module: set(m.absent) for m in ctx.cov.modules if m.status == "absent"}
        out = []
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error:
                continue
            for mod, nids in bi.imports_by_module.items():
                for n in sorted(set(nids) & absent.get(mod, set())):
                    if n in PRO_BODIES:
                        continue
                    out.append(Finding(self.name, bi.path, f"{mod}:{n} absent on {ctx.target}.xx",
                                       recommended=True, data={"nid": n, "module": mod}))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        r = stub_plt(b, f.data["nid"], ctx.base_for(f.file), BODY)
        if r is None:
            raise ValueError(f"{f.file}: {f.data['nid']} has no standard PLT stub")
        off, old, new, stub_rva = r
        ctx.edit(f.file, f"rule:{self.name}", off, old.hex(), new.hex(), f"{f.data['nid']} -> return 0")
        for o, old, new in localize(b, f.data["nid"], stub_rva):
            ctx.edit(f.file, f"rule:{self.name}", o, old.hex(), new.hex(), "bind locally")
