"""user-patch: apply recipe files given with `--patch FILE` (see ps5bp/core/recipe.py)."""
from __future__ import annotations

from ..recipe import Recipe
from . import Finding, Rule, RuleContext


class UserPatch(Rule):
    name = "user-patch"
    summary = "Apply patch recipe files given with --patch"

    def detect(self, ctx: RuleContext) -> list[Finding]:
        out = []
        for p in ctx.options.get("patches", []):
            r = Recipe.load(p)
            why = r.check(ctx.load(r.file), ctx.gs.title_id)
            out.append(Finding(self.name, r.file, f"patch {r.name} ({p})", applicable=not why,
                               recommended=not why, reason=why or r.note, data={"recipe": r}))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        r = f.data["recipe"]
        b = ctx.load(r.file)
        for off, old, new, note in r.apply(b):
            ctx.edit(r.file, f"rule:{self.name}", off, old.hex(), new.hex(), note)
