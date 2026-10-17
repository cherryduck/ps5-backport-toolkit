"""Shared plumbing for rules that rewrite a few proven bytes at detected sites.

Every such rule's detector classifies each site as
  PATCH    the pre-image matches the known broken form -> `data["edits"]` lists the writes
  DONE     the site already has the fixed form (nothing to do, never touched)
  UNKNOWN  something else / ambiguous -> refused, reported, never edited
and `apply` writes the edits through Binary.patch (pre-image verified) and records each in
the build report, so the pipeline's "no byte changed outside a recorded edit" check covers it.
"""
from __future__ import annotations

from . import Finding, Rule, RuleContext

PATCH, DONE, UNKNOWN = "PATCH", "DONE", "UNKNOWN"


def finding(rule: str, file: str, title: str, status: str, *, recommended: bool = False, reason: str = "",
            edits: list[tuple[int, str, str, str]] | None = None, **data) -> Finding:
    """edits: [(runtime VA, old hex, new hex, note)] — empty unless status == PATCH."""
    ok = status == PATCH
    return Finding(rule, file, f"[{status}] {title}", applicable=ok, recommended=recommended and ok,
                   reason=reason, data={"status": status, "edits": edits or [], **data})


class EditRule(Rule):
    """apply() = every edit of the finding, pre-image checked."""

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        base = ctx.base_for(f.file)
        for va, old, new, note in f.data["edits"]:
            off = b.patch(va - base, bytes.fromhex(old), bytes.fromhex(new))
            ctx.edit(f.file, f"rule:{self.name}", off, old, new, f"{va:#x} {note}")


def code_binaries(ctx: RuleContext, *nids: str):
    """Game binaries (not fakelibs, parseable) that import at least one of `nids`."""
    want = set(nids)
    for bi in ctx.gs.binaries:
        if bi.role == "fakelib" or bi.error:
            continue
        if want & {n for v in bi.imports_by_module.values() for n in v}:
            yield bi
