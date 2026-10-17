"""psml-overlay: a kit-supplied libScePsml that loads its PSSR model from /app0, plus that model.

Observed in community FW4 backports of Pro/PSSR titles: the title's own fakelib/libScePsml.sprx is
a build whose model path was retargeted from the system's KPN9 file to the string `/app0/k9.psp`,
and the matching k9.psp sits next to eboot.bin.  Together they let the PSSR/MFSR2 path run on
firmware that has no KPN9 model.  No names are baked in: a kit counts as an *overlay provider*
when its libScePsml fakelib contains `/app0/k9.psp` and the kit root has a k9.psp (`kit add`
keeps both).  The rule applies when

  * the game imports libScePsml (the MFSR2 contract lives there),
  * a provider's fakelib exports a superset of the NIDs the game imports from libScePsml,

and then installs that libScePsml in place of the coverage's choice and copies k9.psp to the game
root.  DONE when the game already carries a libScePsml naming /app0/k9.psp and a k9.psp.

Composition: the per-title `pssr-memory` recipes (e.g. the Wolverine one) only shrink startup
allocations on the Pro/PSSR path; the DLPS Wolverine kit's libScePsml + k9.psp are an overlay
provider in this sense, so with that kit added the two rules are independent and combine.
`trinity-hw-gate` over forced-Pro stubs needs this Pro stack.  Off by default; never recommended
(proved on titles built for new firmware; unproven for a low declared SDK on a Pro).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from ..coverage import Choice
from . import Finding, Rule, RuleContext

MARK = b"/app0/k9.psp"


def needed_nids(ctx: RuleContext) -> set[str]:
    out: set[str] = set()
    for bi in ctx.gs.binaries:
        if bi.role == "fakelib" or bi.error:
            continue
        for mod, nids in bi.imports_by_module.items():
            if mod.startswith("libScePsml"):
                out |= set(nids)
    return out


def dump_has_overlay(ctx: RuleContext) -> bool:
    root = Path(ctx.gs.root)
    if not (root / "k9.psp").is_file():
        return False
    for bi in ctx.gs.binaries:
        if bi.role == "fakelib" and bi.module.startswith("libScePsml"):
            try:
                if MARK in (root / bi.path).read_bytes():
                    return True
            except OSError:
                pass
    return False


class PsmlOverlay(Rule):
    name = "psml-overlay"
    summary = "Kit libScePsml that loads /app0/k9.psp + its k9.psp at the game root (PSSR/MFSR2 titles)"

    def detect(self, ctx: RuleContext) -> list[Finding]:
        needed = needed_nids(ctx)
        if not needed:
            return []
        if dump_has_overlay(ctx):
            return [Finding(self.name, "k9.psp", "DONE: the game already carries a /app0/k9.psp libScePsml and k9.psp",
                            applicable=False, reason="already in place", data={"status": "DONE"})]
        db = ctx.options.get("db")
        provs = db.psml_overlays() if db is not None else []
        if not provs:
            return [Finding(self.name, "k9.psp", "UNKNOWN: no overlay provider in the kit library", applicable=False,
                            reason="a kit whose libScePsml names /app0/k9.psp, with its k9.psp at the kit root "
                                   "(`ps5bp kit add` keeps both)", data={"status": "UNKNOWN"})]
        ok = [p for p in provs if needed <= p[3]]
        if not ok:
            best = max(provs, key=lambda p: len(needed & p[3]))
            miss = sorted(needed - best[3])
            return [Finding(self.name, "k9.psp",
                            f"UNKNOWN: no provider exports all {len(needed)} libScePsml imports "
                            f"(best: {best[0].name}, missing {len(miss)})", applicable=False,
                            reason="missing: " + ", ".join(miss[:5]), data={"status": "UNKNOWN"})]
        ok.sort(key=lambda p: (bool(ctx.gs.title_id) and p[0].title_id == ctx.gs.title_id,
                               p[0].fw <= ctx.target, p[0].fw if p[0].fw <= ctx.target else -p[0].fw), reverse=True)
        kit, kf, k9, exports = ok[0]
        root_k9 = Path(ctx.gs.root) / "k9.psp"
        if root_k9.is_file() and root_k9.read_bytes() != k9.read_bytes():
            return [Finding(self.name, "k9.psp", "UNKNOWN: the game root already has a different k9.psp",
                            applicable=False, reason=str(root_k9), data={"status": "UNKNOWN"})]
        note = []
        assert db is not None
        for dmod, dn in db.fakelib_imports(kit.name, kf.relpath).items():
            if dmod.startswith("libScePsml"):
                continue
            gone = dn & db.absent(dmod, ctx.target)
            if gone:
                note.append(f"imports {len(gone)} NID(s) from {dmod} proven absent on {ctx.target}.xx")
        return [Finding(self.name, "k9.psp",
                        f"PATCH: libScePsml from kit {kit.name} (FW{kit.fw}, exports {len(exports)} of which the "
                        f"game imports {len(needed)}) + k9.psp ({k9.stat().st_size} B) at the game root",
                        applicable=True, recommended=False,
                        reason="never recommended: no console result for a low declared SDK" +
                               ("; " + "; ".join(note) if note else ""),
                        data={"status": "PATCH", "kit": kit.name, "kit_fw": kit.fw, "relpath": kf.relpath,
                              "sha256": kf.sha256, "k9": str(k9), "exports": len(exports),
                              "needed": sorted(needed)})]

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        d = f.data
        if ctx.cov is None or ctx.add_file is None:
            raise ValueError("psml-overlay needs the kit library (coverage) and a build context")
        m = next((m for m in ctx.cov.modules if m.module.startswith("libScePsml")), None)
        if m is None:
            raise ValueError("coverage has no libScePsml entry")
        kit = ctx.options["db"].kit(d["kit"])
        if hashlib.sha256(kit.path(d["relpath"]).read_bytes()).hexdigest() != d["sha256"]:
            raise ValueError("kit libScePsml changed since detection")
        m.choice = Choice(d["kit"], d["kit_fw"], d["relpath"], d["sha256"], len(d["needed"]), [], d["exports"])
        m.status = "fakelib"
        m.note = "psml-overlay: loads /app0/k9.psp"
        ctx.add_file("k9.psp", Path(d["k9"]), f"PSML overlay model (kit {d['kit']}); loaded by libScePsml as /app0/k9.psp")
