"""compat-stubs: seed contract stubs for imports the target firmware does not provide.

For every import of a game binary that has an entry in the stub-contract table
(ps5bp/data/stub_contracts.json) and is not proven present on the declared target, the contract's
stub body is delivered through the GOT (see got_seed.py): the PLT entry, import symbol and
relocation stay, so a firmware that exports the NID binds natively and the same build works on
old and new firmware.

Decision per NID: coverage evidence first (proven absent / stubbed by a kit for this FW => seed;
proven present => leave), otherwise the table's first-exported lead (seed when the declared SDK
major is below it). Some contracts are only safe under a caller contract (result ignored, owned
0x40-byte output buffer, error code compared); the gate is proved with data-flow over every caller
or the NID is skipped with the reason. Manual contracts are seeded only by `--seed NID`, which
also overrides the evidence/lead decision (never a gate). Status per site: PATCH / DONE (GOT
already points at the stub) / UNKNOWN (refused: reason given). Off by default; nothing is
recommended without a recorded console result (`hw_proved` in the table).

Skipped: NIDs owned by an enabled pro-disable / pssr-memory (Pro query, Trinity) or kit-stubs.
`--seed-plt-fallback` allows the PLT-overwrite stub for sites where a GOT seed is refused.
"""
from __future__ import annotations

from pathlib import PurePosixPath

from . import Finding, Rule, RuleContext
from . import contracts, gates, got_seed
from .common import proven_absent, stub_plt, localize

PRO_OWNED = {"NH6xARDOVv8", "tU5e3f9gSiU"}


class CompatStubs(Rule):
    name = "compat-stubs"
    summary = "Seed per-NID stub contracts via the GOT for imports the target FW lacks (native binding kept)"

    def detect(self, ctx: RuleContext) -> list[Finding]:
        table = contracts.load()
        enabled = set(ctx.options.get("enabled", ()))
        seeds = set(ctx.options.get("seeds") or ())
        pro_on = bool(enabled & {"pro-disable", "pssr-memory"})
        kit_owned = {}
        if "kit-stubs" in enabled and ctx.cov:
            kit_owned = {m.module: set(m.stub_src) for m in ctx.cov.modules if not m.choice}
        mods = {m.module: m for m in ctx.cov.modules} if ctx.cov else {}
        out: list[Finding] = []
        used: dict[str, int] = {}
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error:
                continue
            for mod, nids in sorted(bi.imports_by_module.items()):
                for n in sorted(set(nids) & set(table)):
                    c = table[n]
                    forced = n in seeds
                    if c.gate == "manual" and not forced:
                        continue
                    if n in PRO_OWNED and pro_on:
                        continue
                    if n in kit_owned.get(mod, ()):
                        continue
                    f = self._site(ctx, bi, mod, c, forced, mods.get(mod), used)
                    if f:
                        out.append(f)
        return out

    def _site(self, ctx, bi, mod, c, forced, m, used) -> Finding | None:
        title = f"{mod}:{c.label()} -> {c.semantics}"
        why = self._need(ctx, c, m, forced)
        if why is None:
            return None
        need, reason = why
        if not need:
            return None
        b = ctx.load(bi.path)
        base = ctx.base_for(bi.path)
        base_data = {"nid": c.nid, "module": mod}

        def fail(msg, status="UNKNOWN"):
            return Finding(self.name, bi.path, title, applicable=False, reason=f"{status}: {msg}",
                           data={**base_data, "status": status})
        if c.gate == "libc-only" and PurePosixPath(bi.path).name != "libc.prx":
            return None                                   # only libc's own consumer
        p = got_seed.plan(b, c.nid, c.stub)
        if p.status == "DONE":
            return fail(p.reason + f" ({reason})", "DONE")
        if p.status == "UNKNOWN":
            if ctx.options.get("seed_plt_fallback"):
                return Finding(self.name, bi.path, title + " [PLT fallback]", recommended=False,
                               reason=f"{reason}; GOT seed refused ({p.reason}); PLT overwrite as requested",
                               data={**base_data, "status": "PLT", "refused": p.reason})
            return fail(p.reason)
        if c.gate in ("result-unused-or-error-check", "output-buffer-owned-0x40", "caller-compares-0x80020003"):
            ok, proof = gates.check(c.gate, b, base, p.plt, p.got)
            if not ok:
                return fail(f"gate {c.gate} not proved: {proof}")
            reason += f"; gate {c.gate}: {proof}"
        used[bi.path] = used.get(bi.path, 0) + 1
        if used[bi.path] > got_seed.cave_capacity(b):
            return fail("no executable cave left for another 16-byte stub")
        return Finding(self.name, bi.path, title, recommended=c.hw_proved and not forced,
                       reason=reason, data={**base_data, "status": "PATCH"})

    @staticmethod
    def _need(ctx, c, m, forced) -> tuple[bool, str] | None:
        """(seed it?, why). None = nothing to report (provided elsewhere)."""
        if m is not None:
            if m.status == "game":
                return None                               # the game ships that module itself
            if m.choice and c.nid not in m.choice.missing:
                return None                               # a chosen fakelib exports it
        if forced:
            return True, "forced by --seed"
        if m is not None:
            if c.nid in m.absent:
                return True, f"proven absent on {ctx.declared_sdk}.xx"
            if c.nid in m.stubbed:
                return True, f"stubbed by a kit for FW >= {ctx.declared_sdk}"
            if c.nid not in m.unproven and c.nid not in m.conflict:
                return None                               # proven present on the target
        gone = c.absent_on(ctx.declared_sdk)
        if gone:
            return True, f"first exported on {c.first_exported_fw} (lead, no evidence); target {ctx.declared_sdk}.xx"
        return False, ""

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        c = contracts.load()[f.data["nid"]]
        b = ctx.load(f.file)
        kind = f"rule:{self.name}"
        if f.data["status"] == "PLT":
            r = stub_plt(b, c.nid, ctx.base_for(f.file), c.stub)
            if r is None:
                raise ValueError(f"{f.file}: {c.nid} has no standard PLT stub — cannot seed or overwrite")
            off, old, new, rva = r
            ctx.edit(f.file, kind, off, old.hex(), new.hex(), f"{c.nid} PLT stub (requested fallback; {f.data['refused']})")
            if proven_absent(ctx, f.data["module"], c.nid):
                for o, ob, nb in localize(b, c.nid, rva):
                    ctx.edit(f.file, kind, o, ob.hex(), nb.hex(), f"bind {c.nid} locally (absent on target)")
            return
        p = got_seed.plan(b, c.nid, c.stub)
        for off, old, new, note in got_seed.apply(b, p, c.stub):
            ctx.edit(f.file, kind, off, old, new, note)
