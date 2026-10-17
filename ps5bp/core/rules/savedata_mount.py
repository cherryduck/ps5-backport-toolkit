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
Phase 10h: a site whose mount mode (+0x20) is the constant 1 (read-only) is reported but NOT
patched: a read-only mount never creates, FW4 kits leave -1 there, and ps5bp's 0 on such a site
was once suspected of a KH HD 2.8 0x809f8032 loop (disproved: that was a half-created save).
Console-tested: KH HD 2.8 (PPSA35909) boots on a PS5 Pro 11.60 with read-only left at -1 and the create site at 0.
When rdi comes from elsewhere the site is reported as unknown unless the extended
(flow-based) detector below can prove it:
  * register alias chains (`mov rax,rsi` / `lea rdi,[rax+8]` / `add`), stores in any basic
    block before the call (regflow);
  * local wrappers: when the request pointer is the function's own argument, every direct
    caller of the function is analysed instead (two levels), a store made through the
    argument inside the wrapper itself counts first;
  * guards: exactly one qword store of -1 to +0x18, a non-zero store covering the blocks
    field (+0x10) must exist, the instruction must end ff ff ff ff; an explicit qword 0 store
    with the blocks store present is DONE; anything else is refused (UNKNOWN).
Unity `SaveData.prx` plugins copy blocks+systemBlocks (+0x30 of the managed request) with one
16-byte vector move, which carries the new SDK's systemBlocks sentinel across. Observed in
community FW4 backports: the move is replaced by an 8-byte copy of `blocks` only, so
systemBlocks keeps the zero the request was initialised with:
    c5 f8 10 43 30 | c5 f8 11 84 24 d32      (rbx -> [rsp+d32])   14 bytes
 -> 48 8b 43 30 | 48 89 84 24 d32 | 90 90
    c4 c1 78 10 46 30 | c5 f8 11 85 d32      (r14 -> [rbp+d32]; r15: ...47 30)
 -> 49 8b 46 30 | 48 89 85 d32 | 90 90 90
Guards: exactly one such copy in the file, it stores to request+0x10 of a later Mount3 call,
and the bytes at +0x18 were zeroed by an earlier store with nothing non-zero written between.
"""
from __future__ import annotations

import re

from .. import x86flow as xf
from . import Finding, Rule, RuleContext
from .bytefix import DONE, PATCH, UNKNOWN, finding
from .common import calls_to_import  # noqa: F401  (re-export)
from .evidence_rules import recommendation

MOUNT3 = "ZP4e7rlzOUk"           # sceSaveDataMount3
FIELD = 0x18
MODE = 0x20          # mount mode; a constant 1 (read-only) never creates, so +0x18 is unused there
READONLY_WHY = ("read-only mount: systemBlocks left at -1 (a read-only mount never creates; FW4 kits leave it; "
                "matches DLPS's FW4 builds; console-tested: KH HD 2.8 boots with it left at -1)")
_MEM = re.compile(r"\[(\w+)(?: ([+-]) (0x[0-9a-f]+|\d+))?\]")


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


# ---- extended detector: aliases, local wrappers, Unity vector copy ---------------------------
BLOCKS = 0x10
ARGREGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


def _state_here(flow, tok, roff: int) -> dict:
    """PATCH / DONE / NONE / UNKNOWN for the request at (tok, roff) given the stores in `flow`."""
    sb_lo, sb_hi = roff + FIELD, roff + FIELD + 8
    ov = [s for s in flow.stores if s.base == tok and s.off < sb_hi and s.off + s.size > sb_lo]
    blk = [s for s in flow.stores if s.base == tok and not s.zero and s.off <= roff + BLOCKS
           and s.off + s.size >= roff + BLOCKS + 8]
    exact = [s for s in ov if s.size == 8 and s.off == sb_lo]
    m1 = [s for s in exact if s.imm == -1]
    z0 = [s for s in exact if s.imm == 0]
    if not m1 and not z0:
        return {"status": "NONE"}
    if len(m1) + len(z0) != 1 or len(exact) != 1:
        return {"status": UNKNOWN, "why": "several stores to +0x18"}
    if any(s is not exact[0] and not (s.zero and s.idx < exact[0].idx) for s in ov):
        return {"status": UNKNOWN, "why": "another non-zero store overlaps +0x18"}
    if not blk:
        return {"status": UNKNOWN, "why": "no store to the blocks field (+0x10) before the call"}
    st = exact[0]
    if m1:
        if st.insn.bytes[-4:] != b"\xff\xff\xff\xff":
            return {"status": UNKNOWN, "why": "-1 store encoding does not end ff ff ff ff"}
        return {"status": PATCH, "va": st.insn.address, "len": st.insn.size}
    return {"status": DONE, "va": st.insn.address, "len": st.insn.size}


def _request_states(sc, fn, k: int, reg: str, delta: int, depth: int, seen: set) -> list[dict]:
    from ..regflow import scan
    flow = scan(fn, k)
    tok, roff = flow.resolve(reg)
    roff += delta
    r = _state_here(flow, tok, roff)
    if r["status"] != "NONE":
        return [r]
    if tok[1] != 0 or tok[0] not in ARGREGS:
        return [r]                                        # a local object nobody stores +0x18 of: nothing to fix
    if depth >= 2 or fn.start in seen:
        return [{"status": UNKNOWN, "why": "request is a wrapper argument nested more than two levels deep"}]
    callers = sc.calls_to(fn.start)
    if not callers:
        return [{"status": UNKNOWN, "why": f"request is the argument of {fn.start:#x}, which has no direct callers"}]
    out = []
    for c in callers:
        try:
            cfn = xf.function_at(sc.read, c)
            ci = cfn.index(c)
        except KeyError:
            out.append({"status": UNKNOWN, "why": f"cannot resync to the caller at {c:#x}"})
            continue
        for r2 in _request_states(sc, cfn, ci, tok[0], roff, depth + 1, seen | {fn.start}):
            out.append({**r2, "wrapper": fn.start, "via": c})
    return out


def flow_sites(b, base: int, only: set[int] | None = None) -> list[dict]:
    """Per Mount3 call (restricted to `only`): [{call, status, va?, len?, why?, wrapper?}]."""
    from ..memsite import Scanner
    from .common import calls_to_import
    try:
        sc = Scanner(b, base)
    except IndexError:
        return []
    out = []
    for call in calls_to_import(sc, MOUNT3):
        if only is not None and call not in only:
            continue
        try:
            fn = xf.function_at(sc.read, call)
            k = fn.index(call)
        except KeyError:
            out.append({"call": call, "status": UNKNOWN, "why": "cannot resync to the containing function"})
            continue
        for r in _request_states(sc, fn, k, "rdi", 0, 0, set()):
            out.append({"call": call, **r})
    return out


_UNITY = {   # name -> (orig regex, replacement builder)
    "rbx": (re.compile(rb"\xc5\xf8\x10\x43\x30\xc5\xf8\x11\x84\x24(....)", re.S),
            lambda d: bytes.fromhex("488b4330 48 89 84 24".replace(" ", "")) + d + b"\x90\x90"),
    "r14": (re.compile(rb"\xc4\xc1\x78\x10\x46\x30\xc5\xf8\x11\x85(....)", re.S),
            lambda d: bytes.fromhex("498b4630 488985".replace(" ", "")) + d + b"\x90\x90\x90"),
    "r15": (re.compile(rb"\xc4\xc1\x78\x10\x47\x30\xc5\xf8\x11\x85(....)", re.S),
            lambda d: bytes.fromhex("498b4730 488985".replace(" ", "")) + d + b"\x90\x90\x90"),
}
_UNITY_DONE = {
    "rbx": re.compile(rb"\x48\x8b\x43\x30\x48\x89\x84\x24....\x90\x90", re.S),
    "r14": re.compile(rb"\x49\x8b\x46\x30\x48\x89\x85....\x90\x90\x90", re.S),
    "r15": re.compile(rb"\x49\x8b\x47\x30\x48\x89\x85....\x90\x90\x90", re.S),
}


def is_unity_savedata(path: str) -> bool:
    return path.replace("\\", "/").lower().endswith("savedata.prx")


def _unity_proof(sc, va: int, store_off: int) -> str | None:
    """None when the copy at va is proved to write blocks+systemBlocks of a Mount3 request whose
    systemBlocks was zeroed beforehand; else the reason it is not."""
    from ..regflow import scan
    from .common import calls_to_import
    try:
        fn = xf.function_at(sc.read, va)
        k = fn.index(va)
    except KeyError:
        return "cannot resync to the containing function"
    store = fn.insns[k + 1]
    if store.address != va + store_off:
        return "unexpected instruction boundaries"
    if any(i.target is not None and va < i.target < store.end for i in fn.insns):
        return "a branch targets the middle of the copy"
    flow = scan(fn, k + 1)
    loc = flow.mem_loc(store.raw.operands[0])
    if loc is None:
        return "destination is not a plain base+disp operand"
    calls = [c for c in calls_to_import(sc, MOUNT3) if fn.contains(c) and c > va]
    if not calls:
        return "no Mount3 call after the copy in this function"
    call = min(calls)
    cf = scan(fn, fn.index(call))
    if cf.resolve("rdi") != (loc[0], loc[1] - BLOCKS):
        return "destination is not request+0x10 of the following Mount3 call"
    lo, hi = loc[1] + 8, loc[1] + 16
    ov = [s for s in flow.stores if s.base == loc[0] and s.off < hi and s.off + s.size > lo]
    if not ov or not ov[-1].zero or not all(s.zero for s in ov):
        return "systemBlocks is not proved zero-initialised before the copy"
    return None


def unity_sites(b, base: int) -> list[dict]:
    """[{status, va?, old?, new?, form?, why?}] for the Unity SaveData.prx vector copy."""
    from ..memsite import Scanner
    try:
        sc = Scanner(b, base)
    except IndexError:
        return []
    seg = sc.code
    hits = []                                    # (form, offset, kind)
    for form, (rx, build) in _UNITY.items():
        for m in rx.finditer(seg):
            hits.append((form, m.start(), "PATCH", m.group(0), build(m.group(1))))
    for form, rx in _UNITY_DONE.items():
        for m in rx.finditer(seg):
            hits.append((form, m.start(), "DONE", m.group(0), m.group(0)))
    if not hits:
        return []
    if len(hits) > 1:
        return [{"status": UNKNOWN, "why": f"{len(hits)} candidate vector copies (expected exactly one)"}]
    form, off, kind, old, new = hits[0]
    va = sc.cva + off
    store_off = 5 if form == "rbx" else 6
    why = _unity_proof(sc, va, store_off) if kind == "PATCH" else None
    if why:
        return [{"status": UNKNOWN, "va": va, "why": why}]
    return [{"status": kind, "va": va, "old": old.hex(), "new": new.hex(), "form": form}]


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
            b, base = ctx.load(bi.path), ctx.base_for(bi.path)
            old = sites(b, base)
            have: set[int] = set()
            for s in old:
                if s["state"] == "unfixed" and s.get("mode") == 1:
                    have.add(s["store"])
                    out.append(Finding(self.name, bi.path, f"{s['store']:#x}: Mount3 param +0x18 -1 (read-only mount, "
                                       f"call {s['call']:#x})", applicable=False, reason=READONLY_WHY,
                                       data={"va": s["store"], "len": s["len"], "readonly": True}))
                elif s["state"] == "unfixed":
                    have.add(s["store"])
                    out.append(Finding(self.name, bi.path, f"{s['store']:#x}: Mount3 param +0x18 -1 -> 0 "
                                       f"(call {s['call']:#x})", recommended=rec, reason=why,
                                       data={"va": s["store"], "len": s["len"]}))
            pending = [s for s in old if s["state"] == "unknown"]
            ext = {}
            for r in flow_sites(b, base, {s["call"] for s in pending}):
                ext.setdefault(r["call"], []).append(r)
            for s in pending:
                rows = [r for r in ext.get(s["call"], []) if r["status"] != "NONE"]
                shown = False
                for r in rows:
                    where = f"call {s['call']:#x}" + (f" via wrapper {r['wrapper']:#x} (caller {r['via']:#x})"
                                                       if "wrapper" in r else "")
                    if r["status"] == PATCH and r["va"] not in have:
                        have.add(r["va"])
                        out.append(finding(self.name, bi.path, f"{r['va']:#x}: Mount3 param +0x18 -1 -> 0 ({where})",
                                           PATCH, recommended=rec, reason=why,
                                           edits=[(r["va"] + r["len"] - 4, "ffffffff", "00000000",
                                                   "SaveDataMount3 param +0x18 -1 -> 0")]))
                        shown = True
                    elif r["status"] == DONE and r["va"] not in have:
                        have.add(r["va"])
                        out.append(finding(self.name, bi.path, f"{r['va']:#x}: Mount3 param +0x18 already 0 ({where})",
                                           DONE, reason="already patched"))
                        shown = True
                    elif r["status"] == UNKNOWN:
                        out.append(finding(self.name, bi.path, f"{where}: Mount3 request not proved", UNKNOWN,
                                           reason=r["why"] + " — check +0x18 by hand if saving fails"))
                        shown = True
                if not shown and not rows:
                    out.append(Finding(self.name, bi.path, f"call {s['call']:#x}: Mount3 param struct built "
                                       "outside this function", applicable=False,
                                       reason="check +0x18 by hand if saving fails"))
            if is_unity_savedata(bi.path):
                seen_unity = False
                for r in unity_sites(b, base):
                    seen_unity = True
                    if r["status"] == PATCH:
                        out.append(finding(self.name, bi.path, f"{r['va']:#x}: Unity SaveData blocks+systemBlocks "
                                           f"16-byte vector copy ({r['form']}) -> 8-byte copy", PATCH,
                                           recommended=rec, reason=why,
                                           edits=[(r["va"], r["old"], r["new"], "Mount3 request vector copy -> "
                                                                               "8-byte copy (systemBlocks stays 0)")]))
                    elif r["status"] == DONE:
                        out.append(finding(self.name, bi.path, f"{r['va']:#x}: Unity SaveData copy already 8 bytes",
                                           DONE, reason="already patched"))
                    else:
                        out.append(finding(self.name, bi.path, "Unity SaveData vector copy not proved", UNKNOWN,
                                           reason=r["why"]))
                if not seen_unity and not any(f.file == bi.path for f in out):
                    out.append(finding(self.name, bi.path, "Unity SaveData Mount3 request form not recognised",
                                       UNKNOWN, reason="no known blocks/systemBlocks copy and no -1 store found"))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        base = ctx.base_for(f.file)
        if f.data.get("edits"):
            for va, old, new, note in f.data["edits"]:
                off = b.patch(va - base, bytes.fromhex(old), bytes.fromhex(new))
                ctx.edit(f.file, f"rule:{self.name}", off, old, new, f"{va:#x} {note}")
            return
        va = f.data["va"] + f.data["len"] - 4
        off = b.patch(va - base, b"\xff\xff\xff\xff", b"\0\0\0\0")
        ctx.edit(f.file, f"rule:{self.name}", off, "ffffffff", "00000000",
                 f"{f.data['va']:#x} SaveDataMount3 param +0x18 -1 -> 0")

    @staticmethod
    def probe(b, base: int) -> tuple[int, int]:
        st = [s["state"] for s in sites(b, base) if s.get("mode") != 1]     # read-only sites prove nothing
        return st.count("unfixed"), st.count("zero")
