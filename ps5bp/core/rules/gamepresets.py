"""gamepresets-28: sceUserServiceGetGamePresets request size 0x30 -> 0x28.

The call takes (userId, request*) and the request's first qword is its own size. Builds
made with a newer SDK store 0x30; a 4.xx system rejects that size (0x80960005). Observed in
community FW4 backports (hardware-proved): the same call with the size stored as 0x28 works,
nothing else changes - the omitted tail stays zero-initialised.

Detector, per direct call of the import (PLT stub or jmp thunk):
  * the request is whatever `rsi` holds at the call, followed through lea / mov-reg / add
    aliases (regflow); stores of an immediate qword to its first field are counted
      exactly one 0x30 (encoding ends 30 00 00 00) and no 0x28 -> PATCH (imm32 -> 0x28)
      exactly one 0x28 and no 0x30                          -> DONE
  * no such store at all: the request may be initialised by a helper called just before the
    call (memset 0x30 + size store). Accepted only when the helper contains exactly one
    `mov edx, 0x30` (the memset length, left alone) and exactly one `mov qword [rax|rdi],
    0x30|0x28` and every caller of the helper is followed by a call of this import.
  * anything else -> UNKNOWN: refused for that call.
"""
from __future__ import annotations

import re

from .. import x86flow as xf
from ..regflow import scan
from . import Finding, RuleContext
from .bytefix import DONE, PATCH, UNKNOWN, EditRule, code_binaries, finding
from .common import calls_to_import

NID = "-sD02mFDBh4"             # sceUserServiceGetGamePresets
OLD, NEW = 0x30, 0x28
_STORE_HELPER = re.compile(r"qword ptr \[(rax|rdi)\], 0x(30|28)$")


def _size_stores(fn, flow, req) -> list:
    return [s for s in flow.stores if (s.base, s.off) == req and s.size == 8 and s.imm in (OLD, NEW)]


def _is_ret_end(ins) -> bool:
    return ins.mnemonic in ("ret", "ud2")


def _helper_sites(sc, fn, k, gp_calls: set[int]) -> dict | None:
    """The init-helper form. Returns {'va','len','state'} for the single size store, or None."""
    # nearest preceding direct call that is not an import call; no other call in between
    h = None
    for j in range(k - 1, -1, -1):
        i = fn.insns[j]
        if i.mnemonic == "call":
            h = i
            break
    if h is None or h.target is None or h.target in sc.stubs:
        return None
    # rsi/rdi at the GP call come straight from [rbp-X] slots, untouched since the helper call
    slots = []
    for reg in ("rdi", "rsi"):
        j = xf.last_write(fn, reg, k)
        if j is None or j <= fn.index(h.address):
            return None
        ins = fn.insns[j]
        m = re.search(r"\[rbp - 0x[0-9a-f]+\]$", ins.op_str)
        if ins.mnemonic not in ("mov", "lea") or not m:
            return None
        slots.append(m.group(0))
    hi = fn.index(h.address)
    if any(i.mem_store and any(s in i.op_str for s in slots) for i in fn.insns[hi + 1:k]):
        return None
    body = []
    hf = xf.decode(sc.read(h.target, 0x400), h.target)
    for i in hf:
        body.append(i)
        if _is_ret_end(i):
            break
    else:
        return None
    n_len = sum(1 for i in body if i.mnemonic == "mov" and i.op_str == "edx, 0x30")
    stores = [i for i in body if i.mnemonic == "mov" and _STORE_HELPER.search(i.op_str)]
    if n_len != 1 or len(stores) != 1:
        return None
    # every caller of the helper is followed by this import's call
    callers = sc.calls_to(h.target)
    if not callers:
        return None
    for c in callers:
        cf = xf.function_at(sc.read, c)
        try:
            ci = cf.index(c)
        except KeyError:
            return None
        ok = False
        for i in cf.insns[ci + 1:ci + 24]:
            if i.address in gp_calls:
                ok = True
                break
            if _is_ret_end(i):
                break
        if not ok:
            return None
    st = stores[0]
    imm = st.raw.operands[1].imm
    return {"va": st.address, "len": st.size, "imm": imm, "enc": st.bytes}


def sites(b, base: int) -> list[dict]:
    """[{call, status, va?, len?, how, why?}] — one row per call of the import."""
    from ..memsite import Scanner
    try:
        sc = Scanner(b, base)
    except IndexError:
        return []
    calls = calls_to_import(sc, NID)
    out = []
    for call in calls:
        try:
            fn = xf.function_at(sc.read, call)
            k = fn.index(call)
        except KeyError:
            out.append({"call": call, "status": UNKNOWN, "why": "cannot resync to the containing function"})
            continue
        flow = scan(fn, k)
        req = flow.resolve("rsi")
        st = _size_stores(fn, flow, req)
        n30 = [s for s in st if s.imm == OLD]
        n28 = [s for s in st if s.imm == NEW]
        if len(n30) == 1 and not n28:
            s = n30[0]
            if s.insn.bytes[-4:] == (OLD).to_bytes(4, "little"):
                out.append({"call": call, "status": PATCH, "va": s.insn.address, "len": s.insn.size,
                            "how": "direct"})
            else:
                out.append({"call": call, "status": UNKNOWN, "why": "0x30 store encoding does not end 30 00 00 00"})
        elif len(n28) == 1 and not n30:
            out.append({"call": call, "status": DONE, "va": n28[0].insn.address, "len": n28[0].insn.size,
                        "how": "direct"})
        elif not st:
            h = _helper_sites(sc, fn, k, set(calls))
            if h and h["imm"] == OLD and h["enc"][-4:] == (OLD).to_bytes(4, "little"):
                out.append({"call": call, "status": PATCH, "va": h["va"], "len": h["len"], "how": "init-helper"})
            elif h and h["imm"] == NEW:
                out.append({"call": call, "status": DONE, "va": h["va"], "len": h["len"], "how": "init-helper"})
            else:
                out.append({"call": call, "status": UNKNOWN, "why": "no size store found / unproved initialiser"})
        else:
            out.append({"call": call, "status": UNKNOWN,
                        "why": f"size stores 0x30={len(n30)} 0x28={len(n28)}: ambiguous"})
    return out


class GamePresets28(EditRule):
    name = "gamepresets-28"
    summary = "sceUserServiceGetGamePresets request size 0x30 -> 0x28 (rejected with 0x80960005 on 4.xx)"
    NEEDED_MAX = 4          # hardware-proved on FW4 (observed in community FW4 backports)

    def detect(self, ctx: RuleContext) -> list[Finding]:
        out = []
        rec = ctx.declared_sdk <= self.NEEDED_MAX
        why = (f"4.xx rejects the 0x30 request size (0x80960005); the 0x28 form is hardware-proved there"
               if rec else "")
        for bi in code_binaries(ctx, NID):
            seen: set[int] = set()
            rows = sites(ctx.load(bi.path), ctx.base_for(bi.path))
            for r in rows:
                key = r.get("va")
                if key is not None and key in seen:
                    continue
                seen.add(key) if key is not None else None
                if r["status"] == PATCH:
                    va, ln = r["va"], r["len"]
                    out.append(finding(self.name, bi.path, f"{va:#x}: GetGamePresets request size 0x30 -> 0x28 "
                                       f"({r['how']}, call {r['call']:#x})", PATCH, recommended=rec, reason=why,
                                       edits=[(va + ln - 4, "30000000", "28000000", "GetGamePresets size 0x30 -> 0x28")]))
                elif r["status"] == DONE:
                    out.append(finding(self.name, bi.path, f"{r['va']:#x}: request size already 0x28 "
                                       f"(call {r['call']:#x})", DONE, reason="already patched"))
                else:
                    out.append(finding(self.name, bi.path, f"call {r['call']:#x}: GetGamePresets request not "
                                       "proved", UNKNOWN, reason=r["why"] + " — check by hand if the call fails"))
        return out
