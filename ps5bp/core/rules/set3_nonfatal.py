"""set3-nonfatal: make a rejected sceAudioOut2Set3DLatency non-fatal on 6.00-9.xx.

Firmware 6.00-9.xx exports sceAudioOut2Set3DLatency (TViD1EZXkNI) but rejects modes above 1 with
0x80268001; engines whose sink init treats a nonzero result as fatal (Wwise) then play no sound.
Below 6.00 the NID is absent and the compat-stubs seed covers it; from 10.xx it works. For targets
6-9 the failure branch is removed at the call: `call <Set3DLatency>; test eax,eax; je X` becomes
`...; jmp X` (je -> jmp, same displacement, so the success path is always taken).

Every direct call in a binary must have exactly that shape (or already be flipped) - otherwise
nothing in that binary is patched and the reason is reported. Tail jumps, address-taken or
GOT-indirect uses also refuse. Off by default; untested on 6-9 hardware, so never recommended.
"""
from __future__ import annotations

from .. import dynamic
from ..asm import is_plt_entry
from . import Finding, Rule, RuleContext
from . import gates, got_seed

SET3 = "TViD1EZXkNI"
TEST = b"\x85\xc0"


class Set3Nonfatal(Rule):
    name = "set3-nonfatal"
    summary = "Audio: ignore a failing sceAudioOut2Set3DLatency (test eax,eax; je -> jmp) for targets 6-9"

    def detect(self, ctx: RuleContext) -> list[Finding]:
        if not 6 <= ctx.declared_sdk <= 9:
            return []
        out = []
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error or SET3 not in {n for v in bi.imports_by_module.values() for n in v}:
                continue
            b = ctx.load(bi.path)
            base = ctx.base_for(bi.path)
            title = f"sceAudioOut2Set3DLatency in {bi.path}"

            def fail(msg):
                return Finding(self.name, bi.path, title, applicable=False, reason=f"UNKNOWN: {msg}",
                               data={"status": "UNKNOWN"})
            p = self._locate(b)
            if p is None:
                out.append(fail("no unique canonical PLT entry / single jump slot for the import"))
                continue
            plt, got = p
            calls, other = gates.refs(b, plt, got, base)
            if other or not calls:
                out.append(fail("; ".join(other[:3]) if other else "no direct call site"))
                continue
            todo, done, bad = [], [], []
            for c in calls:
                nxt = b.read(c + 5, 3)
                if nxt[:2] == TEST and nxt[2] == 0x74:
                    todo.append(c + 7)
                elif nxt[:2] == TEST and nxt[2] == 0xEB:
                    done.append(c + 7)
                else:
                    bad.append(f"{base + c:#x}: `{b.read(c + 5, 4).hex()}`")
            if bad:
                out.append(fail("call site(s) not followed by `test eax,eax; je rel8`: " + ", ".join(bad[:4])))
            elif not todo:
                out.append(Finding(self.name, bi.path, title, applicable=False,
                                   reason=f"DONE: all {len(done)} call(s) already jump unconditionally",
                                   data={"status": "DONE"}))
            else:
                out.append(Finding(self.name, bi.path, title + f": {len(todo)} call(s)",
                                   reason=f"{len(todo)} je -> jmp" + (f", {len(done)} already done" if done else ""),
                                   data={"status": "PATCH", "sites": todo}))
        return out

    @staticmethod
    def _locate(b):
        """(plt rva, got rva) of the import's single canonical PLT entry, or None."""
        d = dynamic.parse(b)
        si = next((i for i, s in enumerate(d.symbols) if s.nid == SET3 and not s.defined), None) if d else None
        if si is None:
            return None
        r = [x for x in got_seed._relocs(b, d, dynamic.DT_JMPREL, dynamic.DT_PLTRELSZ) if x[1] >> 32 == si]
        if len(r) != 1:
            return None
        users = [va for va, g in got_seed.ff25_entries(b) if g == r[0][0]]
        return (users[0], r[0][0]) if len(users) == 1 and is_plt_entry(b, users[0], 0) else None

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        for rva in f.data["sites"]:
            off = b.patch(rva, b"\x74", b"\xeb")
            ctx.edit(f.file, f"rule:{self.name}", off, "74", "eb",
                     f"{ctx.base_for(f.file) + rva:#x}: Set3DLatency failure branch je -> jmp")
