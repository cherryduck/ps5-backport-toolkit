"""pssr-memory: keep the Pro/PSSR path but make its startup allocations fit on old FW.

Game-specific: the patch sites differ per title/version, so this rule offers the
built-in recipes in ps5bp/data/recipes whose title and byte signatures match.
Also offers recipes confirmed with `ps5bp memfix --result N works`
(<data folder>/recipes/, see evidence.home()); the first applicable recipe per file wins (user recipes before built-ins).
Off by default (changes game code, not just imports); conflicts with pro-disable.
"""
from __future__ import annotations

from ..recipe import Recipe, builtin
from . import Finding, Rule, RuleContext


class PssrMemory(Rule):
    name = "pssr-memory"
    summary = "Keep PSSR on Pro, shrink/split its startup allocations (per-game recipes)"
    conflicts = ("pro-disable",)

    def detect(self, ctx: RuleContext) -> list[Finding]:
        from ..memfix import user_recipes_dir
        out = []
        user = []
        d = user_recipes_dir()
        if d.is_dir():
            for f in sorted(d.glob("*.json")):
                try:
                    r = Recipe.load(f)
                except Exception:                    # noqa: BLE001 — skip a broken user file
                    continue
                if r.rule == self.name:
                    user.append(r)
        taken: set[str] = set()                  # files already covered by an applicable recipe
        for r in user + builtin(self.name):
            if r.file in taken:
                continue
            if r.title_id and ctx.gs.title_id and r.title_id != ctx.gs.title_id:
                continue
            if not any(b.path == r.file and not b.error for b in ctx.gs.binaries):
                continue
            why = r.check(ctx.load(r.file), ctx.gs.title_id)
            if why and not (r.title_id and r.title_id == ctx.gs.title_id):
                continue                 # unknown title and no signature match: not this game
            if not why:
                taken.add(r.file)
            out.append(Finding(self.name, r.file, f"recipe {r.name}", applicable=not why,
                               recommended=not why, reason=why or r.note, data={"recipe": r}))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        r = f.data["recipe"]
        b = ctx.load(r.file)
        for off, old, new, note in r.apply(b):
            ctx.edit(r.file, f"rule:{self.name}", off, old.hex(), new.hex(), note)
