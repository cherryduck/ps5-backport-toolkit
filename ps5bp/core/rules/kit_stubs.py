"""kit-stubs: reuse the PLT stubs other backports wrote for the same imports.

Kits ingested with `ps5bp kit add` record every import whose PLT entry the backporter
overwrote in place (e.g. DLPS's ACE COMBAT 8: `xor eax,eax; ret` for VRR / libc-internal
calls, `ud2` for _Xbad_function_call, the Pro query as *a=2,*b=0). For every game binary
(eboot, prx, sprx) importing such a NID from a module no fakelib replaces, this rule
writes the same stub body into the entry's first bytes, exactly as the kit did — the
rest of the entry and the import symbol are left alone.

When kits disagree, the body most kits used wins (then the kit closest to the target FW).
`--stubs-from KIT` limits the sources to the named kit(s) (reproduce exactly what one
group did). The Pro-path NIDs are skipped while pro-disable or pssr-memory is active (they decide
the Pro path). Off by default: a stub encodes what another group chose, not a proof.
"""
from __future__ import annotations

from collections import Counter

from ..asm import canonical_plt, plt_entries
from .. import dynamic
from . import Finding, Rule, RuleContext
from .pro import BODIES as PRO_BODIES


def pick(sources: list[tuple[str, str, int, str]], target: int) -> tuple[str, list[str]]:
    """(body hex, kits that used it) from [(kit, body, fw, relpath)]."""
    count = Counter(b for _, b, _, _ in sources)
    best = sorted(count, key=lambda b: (-count[b], min(fw for _, x, fw, _ in sources if x == b) - target))[0]
    return best, sorted({k for k, b, _, _ in sources if b == best})


def describe(body: bytes) -> str:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in md.disasm(body, 0))


class KitStubs(Rule):
    name = "kit-stubs"
    summary = "Reuse the PLT stubs kits wrote for the same imports (all game binaries)"

    def detect(self, ctx: RuleContext) -> list[Finding]:
        if not ctx.cov:
            return []
        enabled = set(ctx.options.get("enabled", ()))
        skip = set(PRO_BODIES) if enabled & {"pro-disable", "pssr-memory"} else set()
        only = set(ctx.options.get("stubs_from") or ())
        by_mod = {m.module: m for m in ctx.cov.modules if m.stub_src and not m.choice}
        out = []
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error:
                continue
            for mod, nids in bi.imports_by_module.items():
                m = by_mod.get(mod)
                if not m:
                    continue
                for n in sorted(set(nids) & set(m.stub_src)):
                    if n in skip:
                        continue
                    src = [x for x in m.stub_src[n] if not only or x[0] in only]
                    if not src:
                        continue
                    body, kits = pick(src, ctx.target)
                    alt = len({b for _, b, _, _ in src}) - 1
                    conflict = n in m.conflict
                    out.append(Finding(
                        self.name, bi.path, f"{mod}:{n} -> {describe(bytes.fromhex(body))}",
                        recommended=True,
                        reason=f"stubbed by {', '.join(kits)}" + (f"; {alt} other variant(s)" if alt else "")
                               + ("; other kits import it unpatched (conflicting evidence)" if conflict else ""),
                        data={"nid": n, "module": mod, "body": body}))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        base = ctx.base_for(f.file)
        d = dynamic.parse(b)
        assert d
        n, body = f.data["nid"], bytes.fromhex(f.data["body"])
        for name, va, e in plt_entries(b, d, base):
            if name.split("#")[0] != n:
                continue
            if not canonical_plt(e):
                raise ValueError(f"{f.file}: PLT entry of {n} is already patched")
            off = b.patch(va - base, e[:len(body)], body)
            ctx.edit(f.file, f"rule:{self.name}", off, e[:len(body)].hex(), body.hex(),
                     f"{n} PLT stub ({f.reason.split(';')[0]})")
            return
        raise ValueError(f"{f.file}: no PLT entry for {n}")
