"""savedata-mount: sceSaveDataMount3 parameter qword +0x18 = -1 -> 0 on low firmware.

Evidence (no game-specific knowledge needed):
  * ACE COMBAT 8 (DLPS FW 4.03) and PPSA11386 (DLPS FW4) both change the -1 stored there
    to 0; with -1 an ACE COMBAT 8 4.xx backport boots but fails to save (CE-107098-5),
    with 0 it saves (console-confirmed).
  * PSVIETHOA's FW6 PPSA11386 keeps -1 -> accepted on 6.xx.
Detector: for every call to sceSaveDataMount3 (PLT stub or jmp thunk) the parameter
struct is located from rdi (`lea rdi,[base+off]` directly or via one register copy) and
the last store to struct+0x18 before the call is checked; `mov qword [..], -1` is
rewritten in place to 0 (same instruction, imm32 ffffffff -> 00000000).
When rdi comes from elsewhere (struct built by a caller) the site is reported but can't
be patched here.
"""
from __future__ import annotations

import re

from .. import dynamic
from .. import x86flow as xf
from ..asm import plt_stubs, stub_for
from . import Finding, Rule, RuleContext
from .evidence_rules import recommendation

MOUNT3 = "ZP4e7rlzOUk"           # sceSaveDataMount3
FIELD = 0x18
MODE = 0x20          # mount mode; a constant 1 (read-only) never creates, so +0x18 is unused there
_MEM = re.compile(r"\[(\w+)(?: ([+-]) (0x[0-9a-f]+|\d+))?\]")


def calls_to_import(sc, nid_: str) -> list[int]:
    """Direct calls to an import's PLT stub or to a `jmp stub` thunk."""
    d = dynamic.parse(sc.b)
    if not d:
        return []
    stub = stub_for(plt_stubs(sc.b, d, sc.base), nid_)
    if stub is None:
        return []
    out = list(sc.calls_to(stub))
    import numpy as np
    for t in np.unique(sc.call_tgt):
        t = int(t)
        if t != stub and sc.cva <= t < sc.cva + len(sc.code) - 5 and sc.code[t - sc.cva] == 0xE9:
            if t + 5 + int.from_bytes(sc.code[t - sc.cva + 1:t - sc.cva + 5], "little", signed=True) == stub:
                out += sc.calls_to(t)
    return sorted(out)


def _slot(op_str: str):
    m = _MEM.search(op_str)
    if not m:
        return None
    off = int(m[3], 0) if m[3] else 0
    return m[1], -off if m[2] == "-" else off


def sites(b, base: int) -> list[dict]:
    """[{call, store, state}] state: 'unfixed' (-1), 'zero', 'other', 'unknown'."""
    from ..memsite import Scanner
    try:
        sc = Scanner(b, base)
    except IndexError:
        return []
    out = []
    for call in calls_to_import(sc, MOUNT3):
        fn = xf.function_at(sc.read, call)
        try:
            k = fn.index(call)
        except KeyError:
            continue
        j = xf.last_write(fn, "rdi", k)
        src = fn.insns[j] if j is not None else None
        aliases: list[tuple[str, int]] = [("rdi", 0)]
        if src is not None and src.mnemonic == "mov" and len(src.reads) == 1:      # mov rdi, rX
            r = next(iter(src.reads))
            aliases.append((r, 0))
            j2 = xf.last_write(fn, r, j)
            src = fn.insns[j2] if j2 is not None else None
        if src is None or src.mnemonic != "lea":
            out.append({"call": call, "store": None, "state": "unknown"})
            continue
        s = _slot(src.op_str)
        if s:
            aliases.append(s)
        want = {(r, o + FIELD) for r, o in aliases}
        want_mode = {(r, o + MODE) for r, o in aliases}
        hit = mode = None
        for i in fn.insns[:k]:
            if i.mem_store and i.mnemonic == "mov" and _slot(i.op_str) in want:
                hit = i
            if i.mem_store and i.mnemonic == "mov" and _slot(i.op_str) in want_mode:
                o = i.raw.operands
                mode = o[1].imm if len(o) == 2 and o[1].type == 2 else None
        if hit is None:
            out.append({"call": call, "store": None, "state": "unknown"})
            continue
        ops = hit.raw.operands
        imm = ops[1].imm if len(ops) == 2 and ops[1].type == 2 else None       # X86_OP_IMM
        state = "unfixed" if imm == -1 and hit.bytes[-4:] == b"\xff\xff\xff\xff" else \
            ("zero" if imm == 0 else "other")
        out.append({"call": call, "store": hit.address, "len": hit.size, "state": state, "mode": mode})
    return out


class SavedataMount(Rule):
    name = "savedata-mount"
    summary = "sceSaveDataMount3 param +0x18 = -1 -> 0 (save error CE-107098-5 on low FW)"
    PRIOR = {"needed_max": 4, "ok_min": 6, "confirmed": "console-tested: ACE COMBAT 8 built for 4.xx fails to save without it, on a PS5 Pro 11.60"}

    def detect(self, ctx: RuleContext) -> list[Finding]:
        rec, why = recommendation(self.name, ctx, self.PRIOR)
        out = []
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error or MOUNT3 not in {n for v in bi.imports_by_module.values() for n in v}:
                continue
            for s in sites(ctx.load(bi.path), ctx.base_for(bi.path)):
                if s["state"] == "unfixed":
                    out.append(Finding(self.name, bi.path, f"{s['store']:#x}: Mount3 param +0x18 -1 -> 0 "
                                       f"(call {s['call']:#x})", recommended=rec, reason=why,
                                       data={"va": s["store"], "len": s["len"]}))
                elif s["state"] == "unknown":
                    out.append(Finding(self.name, bi.path, f"call {s['call']:#x}: Mount3 param struct built "
                                       "outside this function", applicable=False,
                                       reason="check +0x18 by hand if saving fails"))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        va = f.data["va"] + f.data["len"] - 4
        off = b.patch(va - ctx.base_for(f.file), b"\xff\xff\xff\xff", b"\0\0\0\0")
        ctx.edit(f.file, f"rule:{self.name}", off, "ffffffff", "00000000",
                 f"{f.data['va']:#x} SaveDataMount3 param +0x18 -1 -> 0")

    @staticmethod
    def probe(b, base: int) -> tuple[int, int]:
        st = [s["state"] for s in sites(b, base) if s.get("mode") != 1]     # read-only sites prove nothing
        return st.count("unfixed"), st.count("zero")
