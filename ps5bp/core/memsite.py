"""Locate direct-memory allocation sites in a game binary (for `ps5bp memfix`).

A *site* is one call that allocates/maps memory. For each the scan works out:
  * the length argument and how it was computed (def chain inside the function),
  * whether a failed call is fatal (reaches exit/abort/ud2 shortly after),
  * a hook point for `shrink`: the first direct call after the length was last written
    into a callee-saved register — patching that call to go through a cave lets the
    cave lower the register before the game copies it into the argument,
  * whether shrinking is safe: no other copy of the length's inputs is still used after
    the hook (else the game would later assume the original size),
  * the page-array shape for `page-split`: len = count * page_size, and the function
    stores one address per page into an output array after the call.

Detection: calls to known memory APIs (by NID name), plus calls whose search-end argument
(rsi) is the return value of sceKernelGetDirectMemorySize — this catches wrappers that
library code (e.g. libSceAmpr) exposes under an unnamed NID.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from . import dynamic
from . import x86flow as xf
from .asm import plt_stubs
from .binary import Binary
from .nid import name_of

# NID name -> argument register carrying the length
LEN_ARG = {
    "sceKernelAllocateDirectMemory": "rdx",
    "sceKernelAllocateMainDirectMemory": "rdi",
    "sceKernelMapDirectMemory": "rsi",
    "sceKernelMapNamedDirectMemory": "rsi",
    "sceKernelMapFlexibleMemory": "rsi",
    "sceKernelMapNamedFlexibleMemory": "rsi",
    "sceKernelReserveVirtualRange": "rsi",
}
GDMS = "sceKernelGetDirectMemorySize"
FATAL = {"exit", "_exit", "abort", "sceKernelDebugRaiseException", "sceKernelDebugRaiseExceptionOnReleaseMode"}
PAGE = 0x200000


@dataclass
class Site:
    call: int                        # VA of the allocating call
    api: str                         # import name, or "alloc-like <nid>" for structural hits
    target: int                      # call target VA
    fn: int                          # containing function start
    fn_end: int = 0
    len_reg: str = ""
    len_desc: list[str] = field(default_factory=list)   # def chain, disassembled
    len_const: int | None = None
    fatal: bool = False
    fail_desc: str = ""
    hook: int | None = None          # shrink hook call VA
    hook_target: int | None = None
    hook_reg: str = ""               # register shrunk at the hook
    shrink_safe: bool = False
    shrink_why: str = ""
    page_split: dict | None = None   # parameters for the page-split template
    callers: list[int] = field(default_factory=list)    # direct calls to fn
    crash_callers: list[int] = field(default_factory=list)
    on_crash_path: bool = False
    score: int = 0

    @property
    def id(self) -> str:
        return f"{self.call:x}"

    def variants(self) -> list[str]:
        v = []
        if self.page_split:
            v.append("page-split")
        if self.hook is not None and self.shrink_safe:
            v.append("shrink")
        v.append("retry-align")
        return v


class Scanner:
    def __init__(self, b: Binary, base: int = 0x400000):
        self.b, self.base = b, base
        self.dyn = dynamic.parse(b)
        self.stubs = {va: n for n, va in plt_stubs(b, self.dyn, base).items()} if self.dyn else {}
        ex = [p for p in b.loads() if p.is_exec]
        self.seg = ex[0]
        self.code = b.segment_bytes(self.seg)
        self.cva = base + self.seg.vaddr
        a = np.frombuffer(self.code, np.uint8)
        idx = np.nonzero(a == 0xE8)[0]
        idx = idx[idx + 5 <= len(self.code)]
        disp = np.lib.stride_tricks.sliding_window_view(a, 4)[idx + 1].copy().view(np.int32).ravel()
        self.call_va = self.cva + idx.astype(np.int64)
        self.call_tgt = self.call_va + 5 + disp.astype(np.int64)
        self._names: dict[int, str] = {}

    def read(self, va: int, n: int) -> bytes:
        """Code bytes; ranges reaching outside the executable segment are zero-padded
        (Binary.read returns all zeros when a range merely *starts* unmapped)."""
        lo, hi = self.cva, self.cva + len(self.code)
        if lo <= va and va + n <= hi:
            return self.code[va - lo:va - lo + n]
        out = bytearray(n)
        a, z = max(va, lo), min(va + n, hi)
        if a < z:
            out[a - va:z - va] = self.code[a - lo:z - lo]
        return bytes(out)

    def name(self, va: int) -> str:
        """Import name for a call target (PLT stub or a jmp thunk to one), '' otherwise."""
        if va in self._names:
            return self._names[va]
        n = ""
        t = va
        for _ in range(3):
            if t in self.stubs:
                nid = self.stubs[t].split("#")[0]
                n = name_of(nid) or nid
                break
            b = self.read(t, 5)
            if b[0] != 0xE9:
                break
            t = t + 5 + int.from_bytes(b[1:], "little", signed=True)
        self._names[va] = n
        return n

    def calls_to(self, tgt: int) -> list[int]:
        return [int(x) for x in self.call_va[self.call_tgt == tgt]]

    # ---- discovery -------------------------------------------------------------------------
    def sites(self) -> list[Site]:
        cands: dict[int, tuple[int, str, str]] = {}
        named = {va: n for va, n in ((va, self.name(va)) for va in self.stubs)}
        for va, n in named.items():
            if n in LEN_ARG:
                for c in self.calls_to(va):
                    cands[c] = (va, n, LEN_ARG[n])
            if n == GDMS:
                for c in self.calls_to(va):
                    s = self._after_gdms(c)
                    if s and s[0] not in cands:
                        cands[s[0]] = s[1:]
        # thunks (jmp rel32 -> stub) of named APIs
        for tgt in np.unique(self.call_tgt):
            tgt = int(tgt)
            if tgt in self.stubs or not (self.cva <= tgt < self.cva + len(self.code)):
                continue
            if self.code[tgt - self.cva] != 0xE9:
                continue
            n = self.name(tgt)
            if n in LEN_ARG:
                for c in self.calls_to(tgt):
                    cands.setdefault(c, (tgt, n, LEN_ARG[n]))
        out = []
        for c, (tgt, api, reg) in sorted(cands.items()):
            try:
                out.append(self.analyse(c, tgt, api, reg))
            except Exception:                    # noqa: BLE001 — undecodable site: skip
                continue
        return out

    def _after_gdms(self, gcall: int):
        """The call that consumes GetDirectMemorySize's result as rsi (search end)."""
        fn = xf.function_at(self.read, gcall, 0x800)
        try:
            k = fn.index(gcall)
        except KeyError:
            return None
        for j in range(k + 1, min(k + 24, len(fn.insns))):
            ins = fn.insns[j]
            if ins.mnemonic == "call":
                if ins.target is None:
                    return None
                _, roots = xf.def_chain(fn, "rsi", j, 3)
                k2 = xf.last_write(fn, "rsi", j)
                if k2 is not None and k2 > k and fn.insns[k2].mnemonic == "mov" and "rax" in fn.insns[k2].reads \
                        and xf.last_write(fn, "rax", k2) == k:
                    n = self.name(ins.target)
                    if n not in LEN_ARG:
                        n = f"{n or self._nid(ins.target)} (alloc-like)"
                    return ins.address, ins.target, n, "rdx"
                return None
        return None

    def _nid(self, va: int) -> str:
        t = va
        for _ in range(3):
            if t in self.stubs:
                return self.stubs[t].split("#")[0]
            b = self.read(t, 5)
            if b[0] != 0xE9:
                break
            t = t + 5 + int.from_bytes(b[1:], "little", signed=True)
        return f"{va:#x}"

    # ---- per-site analysis -----------------------------------------------------------------
    def analyse(self, call: int, tgt: int, api: str, reg: str) -> Site:
        fn = xf.function_at(self.read, call)
        k = fn.index(call)
        s = Site(call, api, tgt, fn.start, fn.end, reg)
        defs, roots = xf.def_chain(fn, reg, k)
        s.len_desc = [f"{fn.insns[d].address:x}: {fn.insns[d].mnemonic} {fn.insns[d].op_str}" for d in defs]
        s.len_desc += [f"<- {r} ({kind})" for r, kind in sorted(roots)]
        s.len_const = xf.imm_written(fn, reg, k)
        s.fatal, s.fail_desc = self._fatal(fn, k)
        s.callers = self.calls_to(fn.start)
        self._hook(fn, k, s, defs, roots)
        s.page_split = self._page_split(fn, k, s, defs, roots)
        return s

    def _fatal(self, fn: xf.Function, k: int) -> tuple[bool, str]:
        """test eax,eax ; jcc after the call: does the failure branch reach exit/ud2?"""
        ins = fn.insns
        if k + 2 >= len(ins) or ins[k + 1].mnemonic != "test" or not ins[k + 2].mnemonic.startswith("j"):
            return False, "result not checked directly"
        j = ins[k + 2]
        fail = j.target if j.mnemonic in ("jne", "js", "jnz") else ins[k + 3].address
        try:
            p = fn.index(fail)
        except KeyError:
            return False, f"failure branch {fail:#x} outside function"
        for q in range(p, min(p + 12, len(ins))):
            i = ins[q]
            if i.mnemonic == "call" and i.target is not None and self.name(i.target) in FATAL:
                return True, f"failure -> {self.name(i.target)}() at {i.address:#x}"
            if i.mnemonic == "ud2":
                return True, f"failure -> ud2 at {i.address:#x}"
            if i.mnemonic in ("ret", "jmp"):
                break
        return False, f"failure returns to caller (branch {fail:#x})"

    def _hook(self, fn, k, s: Site, defs, roots) -> None:
        # register holding the final length, callee-saved
        reg = s.len_reg
        kk = xf.last_write(fn, reg, k)
        while kk is not None and fn.insns[kk].mnemonic == "mov" and len(fn.insns[kk].reads) == 1 \
                and next(iter(fn.insns[kk].reads)) not in xf.CALLEE_SAVED:
            src = next(iter(fn.insns[kk].reads))
            reg, kk = src, xf.last_write(fn, src, kk)
        if kk is not None and fn.insns[kk].mnemonic == "mov" and len(fn.insns[kk].reads) == 1:
            src = next(iter(fn.insns[kk].reads))
            if src in xf.CALLEE_SAVED:
                reg, kk = src, xf.last_write(fn, src, kk)
        if reg not in xf.CALLEE_SAVED or kk is None:
            s.shrink_why = "length is not kept in a callee-saved register"
            return
        hook = next((j for j in range(kk + 1, k) if fn.insns[j].mnemonic == "call"
                     and fn.insns[j].bytes[0] == 0xE8), None)
        if hook is None:
            s.shrink_why = "no call between length computation and allocation to hook"
            return
        if any(reg in fn.insns[j].writes for j in range(hook + 1, k)):
            s.shrink_why = f"{reg} rewritten after the hook"
            return
        s.hook, s.hook_target, s.hook_reg = fn.insns[hook].address, fn.insns[hook].target, reg
        # safety: the length's inputs (and plain copies of them) must be dead after the hook
        srcs = {r for r, kind in roots if kind == "entry"}
        for d in defs:
            if d < hook:
                srcs |= fn.insns[d].writes
        for j in range(hook):
            i = fn.insns[j]
            if i.mnemonic == "mov" and len(i.reads) == 1 and i.reads <= srcs and not i.mem_store:
                srcs |= i.writes
            if i.mem_store and i.store_src in srcs:
                s.shrink_why = f"length input spilled to memory at {i.address:#x}"
                return
        srcs.discard(reg)
        for r in sorted(srcs & xf.CALLEE_SAVED):       # caller-saved ones die at the call
            u = xf.read_before_write(fn, r, k + 1)
            if u is not None:
                s.shrink_why = f"{r} (length input) still used at {fn.insns[u].address:#x}"
                return
        s.shrink_safe = True
        s.shrink_why = f"{reg} is the only live copy of the length"

    def _page_split(self, fn, k, s: Site, defs, roots) -> dict | None:
        """len = roundup(count * page) with count/page entry args and an out-array fill."""
        if s.len_reg != "rdx" or self.name(s.target) != "sceKernelAllocateDirectMemory":
            return None
        ins = fn.insns
        im = [d for d in defs if ins[d].mnemonic == "imul"]
        if not im:
            return None
        ent = sorted(r for r, kind in roots if kind == "entry")
        if len(ent) != 2 or not set(ent) <= set(xf.ARGS):
            return None
        out_arg = next((a for a in xf.ARGS[:3] if a not in ent), None)
        if out_arg is None:
            return None
        # the page-size arg is compared against 2 MB before the call
        page_arg = None
        for d in range(k):
            i = ins[d]
            if i.mnemonic == "cmp" and i.reads & set(ent) and f"{PAGE:#x}" in i.op_str:
                page_arg = next(iter(i.reads & set(ent)))
        if page_arg is None:
            return None
        count_arg = next(a for a in ent if a != page_arg)
        # out array: copy of out_arg used as a store base after the call
        out_regs = {out_arg} | {next(iter(ins[j].writes)) for j in range(k)
                                if ins[j].mnemonic == "mov" and ins[j].reads == {out_arg} and len(ins[j].writes) == 1}
        stores = [i for i in ins[k + 1:] if i.mem_store and any(f"[{r} +" in i.op_str for r in out_regs)]
        if not stores:
            return None
        memtype = xf.imm_written(fn, "r8", k)
        acct = None
        for i in ins[k + 1:k + 6]:
            if i.bytes[:1] == b"\xf0" and i.mnemonic.endswith("add") and i.rip_target is not None:
                acct = i.rip_target
        ret = b"\xb0\x01"
        for q, i in enumerate(ins):
            if i.mnemonic == "ret":
                p = q
                while p > 0 and ins[p - 1].mnemonic in ("pop",):
                    p -= 1
                if p > 1 and ins[p - 1].mnemonic == "add" and ins[p - 1].op_str.startswith("rsp"):
                    v = ins[p - 2]
                    if v.mnemonic in ("mov", "xor") and v.writes & {"rax"}:
                        ret = v.bytes
                break
        fail_exit = None
        j = ins[k + 2]
        fail_va = j.target if j.mnemonic in ("jne", "js", "jnz") else ins[k + 3].address
        if s.fatal and fail_va is not None:
            p = fn.index(fail_va)
            if ins[p].mnemonic == "mov" and ins[p].op_str.startswith("edi"):
                fail_exit = ins[p].bytes
        return {"out": out_arg, "page": page_arg, "count": count_arg, "memtype": memtype or 0,
                "account": acct, "ret": ret.hex(), "fail_edi": fail_exit.hex() if fail_exit else None,
                "page_size": PAGE}


def rank(sites: list[Site], crash_frames: list[int] | None = None, base: int = 0x400000) -> list[Site]:
    """Score sites; crash_frames = backtrace return addresses (game VAs) from a klog."""
    fr = list(crash_frames or [])
    for s in sites:
        s.score = 0
        s.crash_callers = [c for c in s.callers if c + 5 in fr]
        s.on_crash_path = bool(s.crash_callers) or any(s.fn <= f < s.fn_end for f in fr)
        if s.on_crash_path:
            s.score += 100
        if s.fatal:
            s.score += 30
        if any("entry" in d for d in s.len_desc):
            s.score += 10
        if s.len_const and s.len_const >= 0x10000000:
            s.score += 10
        if s.page_split:
            s.score += 5
    return sorted(sites, key=lambda s: (-s.score, s.call))
