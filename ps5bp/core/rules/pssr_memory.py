"""pssr-memory: keep the Pro/PSSR path but make its startup allocations fit on old FW.

Game-specific: the patch sites differ per title/version, so this rule offers the
built-in recipes in ps5bp/data/recipes whose title and byte signatures match.
Off by default (changes game code, not just imports); conflicts with pro-disable.
"""
from __future__ import annotations

from ..recipe import builtin
from . import Finding, Rule, RuleContext


class PssrMemory(Rule):
    name = "pssr-memory"
    summary = "Keep PSSR on Pro, shrink/split its startup allocations (per-game recipes)"
    conflicts = ("pro-disable",)

    def detect(self, ctx: RuleContext) -> list[Finding]:
        out = []
        for r in builtin(self.name):
            if r.title_id and ctx.gs.title_id and r.title_id != ctx.gs.title_id:
                continue
            if not any(b.path == r.file and not b.error for b in ctx.gs.binaries):
                continue
            why = r.check(ctx.load(r.file), ctx.gs.title_id)
            if why and not (r.title_id and r.title_id == ctx.gs.title_id):
                continue                 # unknown title and no signature match: not this game
            out.append(Finding(self.name, r.file, f"recipe {r.name}", applicable=not why,
                               recommended=not why, reason=why or r.note, data={"recipe": r}))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        r = f.data["recipe"]
        b = ctx.load(r.file)
        for off, old, new, note in r.apply(b):
            ctx.edit(r.file, f"rule:{self.name}", off, old.hex(), new.hex(), note)
