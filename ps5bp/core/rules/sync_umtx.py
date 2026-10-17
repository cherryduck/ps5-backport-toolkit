"""sync-umtx: SyncOnAddress Wait/Wake -> `_umtx_op` shims, for targets below their first firmware.

EXPERIMENTAL, never recommended: it replaces a kernel-facing primitive, so a console must
prove it per title.

ABIs (established from the callers in libc builds and from FreeBSD's umtx interface):

  Sony SyncOnAddress (libkernel; imported lazily by libc / Unity PS5Util):
    Wait32  B2n8aDorSH4  first FW 9.00  (u32 *addr, u32 expect,  const u32 *timeout_us, const char *name)
    Wait64  PZQhiiLXRFs  first FW 9.00  (u64 *addr, u64 expect,  const u32 *timeout_us, const char *name)
    Wait    Hc4CaR6JBL0  first FW 6.00  same as Wait64 (libc's init-once state is a qword)
    Wake    q2y-wDIVWZA  first FW 6.00  (void *addr, int count)           (1 = one, 0x7fffffff = all)
  `timeout_us` is a pointer to a uint32 microsecond count, NULL = wait forever; libc builds
  it as `imul eax, ms, 1000` (saturating to 0xffffffff).  The name string is a debug label.
  Observed callers ignore the result.

  FreeBSD (PS4/PS5 kernel)  _umtx_op(obj=rdi, op=esi, val=rdx, uaddr=rcx, uaddr2=r8)
    op  2 UMTX_OP_WAIT        sleep while *(u_long*)obj == val
    op  3 UMTX_OP_WAKE        wake `val` waiters
    op 11 UMTX_OP_WAIT_UINT   sleep while *(u_int*)obj == val
    uaddr2 = timeout (NULL = forever); with uaddr (the size argument of newer kernels) = 0 it is a
    plain relative `struct timespec`.  Op numbers 2/3/11 are the shared-key forms, so waiters
    and wakers meet on the same key whatever the process mapping.  Result 0, or -1 + errno
    (the shims pass it through; the community Unity adapter converts to errno, libc ignores it).
    r9 = -1 is set as well (bitset-style "match any"; harmless for a 5-argument call, kept
    because working community builds do it).

Mapping (PLT entry -> 16-byte shim in place, all end in a `jmp` into a small helper):
    Wait32  r8=rdx, edx=esi, esi=11  -> timed helper
    Wait64/Wait  r8=rdx, rdx=rsi, esi=2 -> timed helper
    Wake    rdx=(int64)esi, esi=3, r8=0 -> plain helper
  timed helper: r8==NULL -> plain; else read uint32 us, sec=us/1e6, nsec=(us%1e6)*1000, build a
  timespec on the stack (3 pushes: keeps the 16-byte call alignment), rdx restored, call
  `_umtx_op`, drop the stack, return.  plain helper: ecx=0, r9d=-1, tail-jump to `_umtx_op`.

`_umtx_op` itself comes from (a) the module's own `_umtx_op` import when it has one, else
(b) the first converted import, whose symbol string is renamed to `_umtx_op`: its lazy tail
(`push idx; jmp PLT0`) is relocated into a cave and the GOT slot's initial value points to it,
the helpers go through that GOT slot.  Every converted import's string is renamed (same
length, unique), so the loader never needs the missing NID.

Guards (anything else is refused, status UNKNOWN): no BIND_NOW; every converted import has a
canonical `ff 25` PLT entry and a lazy GOT slot; its symbol is from libkernel and its string is
unique; the GOT slots are not referenced from code outside the PLT; cave space (int3 padding
runs first, so the edits stay undoable; segment growth only as a fallback).  Already-shimmed
modules report DONE.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

import numpy as np

from .. import dynamic
from .. import x86flow as xf
from ..asm import Asm, canonical_plt
from ..binary import Binary
from . import Finding, Rule, RuleContext
from .common import Slot, allocate_runs as _allocate, int3_runs, jump_slots

UMTX = "04AjkP0jO9U"                       # _umtx_op
WAIT32, WAIT64, WAKE, WAIT = "B2n8aDorSH4", "PZQhiiLXRFs", "q2y-wDIVWZA", "Hc4CaR6JBL0"
FIRST_FW = {WAIT32: 9, WAIT64: 9, WAKE: 6, WAIT: 6}      # first firmware exporting each NID
LABEL = {WAIT32: "Wait32", WAIT64: "Wait64", WAKE: "Wake", WAIT: "Wait"}
OP = {WAIT32: 11, WAIT64: 2, WAIT: 2, WAKE: 3}
# in-place shim prefixes (first 10 bytes before the jmp): ours; also recognises the community form
SHIM_PREFIX = {
    WAIT32: bytes.fromhex("4989d0 89f2 6a0b 5e e9".replace(" ", "")),
    WAIT64: bytes.fromhex("4989d0 4889f2 6a02 5e e9".replace(" ", "")),
    WAKE: bytes.fromhex("4863d6 6a03 5e 4531c0 e9".replace(" ", "")),
}
SHIM_PREFIX[WAIT] = SHIM_PREFIX[WAIT64]
DF_BIND_NOW, DF_1_NOW = 0x8, 0x1


# ------------------------------------------------------------------ code generation
def timed_a(a: Asm, plain: int, ta2: int) -> None:
    """r8 = uint32 microsecond pointer or NULL: NULL -> plain; else load it, keep `val` in r10."""
    a.hex("4d85c0")                        # test r8, r8
    a.rel32("0f84", plain)                 # je   plain  (no timeout)
    a.hex("418b00")                        # mov  eax, [r8]
    a.hex("4989d2")                        # mov  r10, rdx           (keep `val`)
    a.hex("31d2")                          # xor  edx, edx
    a.rel32("e9", ta2)


def timed_a2(a: Asm, tb: int) -> None:
    """us -> sec/ns, timespec on the stack (3 pushes keep the 16-byte call alignment)."""
    a.hex("41bb40420f00")                  # mov  r11d, 1000000
    a.hex("41f7f3")                        # div  r11d               eax = sec, edx = us
    a.hex("69d2e8030000")                  # imul edx, edx, 1000     ns
    a.hex("50 52 50")                      # push rax (alignment pad); push rdx (ns); push rax (sec)
    a.rel32("e9", tb)


def timed_b(a: Asm, call: tuple[str, int]) -> None:
    a.hex("4989e0")                        # mov  r8, rsp            &timespec
    a.hex("4c89d2")                        # mov  rdx, r10
    a.hex("31c9")                          # xor  ecx, ecx
    a.hex("4183c9ff")                      # or   r9d, -1
    kind, target = call
    if kind == "got":
        a.rip32("ff15", target)            # call [GOT]
    else:
        a.rel32("e8", target)              # call PLT
    a.hex("4883c418")                      # add  rsp, 24
    a.hex("c3")


def plain(a: Asm, jump: tuple[str, int]) -> None:
    a.hex("31c9")                          # xor  ecx, ecx
    a.hex("4183c9ff")                      # or   r9d, -1
    kind, target = jump
    if kind == "got":
        a.rip32("ff25", target)            # jmp [GOT]
    else:
        a.rel32("e9", target)              # jmp PLT


def shim(nid_: str, at: int, helper: int) -> bytes:
    """16-byte PLT replacement for one converted import."""
    a = Asm(at)
    if nid_ == WAIT32:
        a.hex("4989d0 89f2 6a0b 5e")
    elif nid_ in (WAIT64, WAIT):
        a.hex("4989d0 4889f2 6a02 5e")
    elif nid_ == WAKE:
        a.hex("4863d6 6a03 5e 4531c0")
    else:
        raise ValueError(nid_)
    a.rel32("e9", helper)
    return a.assemble().ljust(16, b"\xcc")


def pieces_for(kinds: set[str], anchor: tuple[str, int | None], tail: bytes | None, at: dict[str, int]) -> dict[str, bytes]:
    """Assemble the helper pieces at the addresses in `at` (names: plain, ta, tb, tail)."""
    out: dict[str, bytes] = {}
    a = Asm(at["plain"])
    plain(a, anchor)
    out["plain"] = a.assemble()
    if kinds - {WAKE}:
        a = Asm(at["ta"])
        timed_a(a, at["plain"], at["ta2"])
        out["ta"] = a.assemble()
        a = Asm(at["ta2"])
        timed_a2(a, at["tb"])
        out["ta2"] = a.assemble()
        a = Asm(at["tb"])
        timed_b(a, anchor)
        out["tb"] = a.assemble()
    if tail is not None:
        out["tail"] = tail
    return out


def _sizes(kinds: set[str], tail: bool) -> dict[str, int]:
    """Piece sizes; `tail` means the anchor is a GOT slot (rip-relative jump/call, one byte longer)."""
    probe = {"plain": 0x1000, "ta": 0x2000, "ta2": 0x2800, "tb": 0x3000}
    anchor = ("got", 0x4000) if tail else ("plt", 0x4000)
    sz = {}
    for k, v in pieces_for(kinds, anchor, b"\0" * 10 if tail else None, {**probe, "tail": 0x5000}).items():
        sz[k] = len(v)
    return sz


# ------------------------------------------------------------------ analysis
@dataclass
class Plan:
    status: str                              # PATCH | DONE | UNKNOWN
    why: str = ""
    convert: list[Slot] = field(default_factory=list)
    anchor_slot: Slot | None = None           # case A: the slot whose GOT the helpers use
    umtx_plt: int | None = None               # case B: existing _umtx_op PLT entry
    renames: list[tuple[int, bytes, bytes]] = field(default_factory=list)   # (rva, old, new)
    callers: dict[str, int] = field(default_factory=dict)
    result_used: int = 0
    placement: dict[str, int] = field(default_factory=dict)
    grow: tuple[int, int] | None = None      # (segment idx, bytes) when no int3 run fits


def _refs_outside_plt(b: Binary, gots: list[int], plt_ranges: list[tuple[int, int]]) -> int:
    """Code positions with a [rip+disp32] operand landing on one of the GOT slots, other than the PLT entries."""
    n = 0
    for p in b.loads():
        if not p.is_exec:
            continue
        seg = np.frombuffer(b.segment_bytes(p), np.uint8)
        if len(seg) < 8:
            continue
        w = np.lib.stride_tricks.sliding_window_view(seg, 4)
        disp = w.copy().view(np.int32).ravel()
        pos = np.arange(len(disp), dtype=np.int64)
        for g in gots:
            for tail in (0, 1, 4):
                hit = np.nonzero(disp == (g - (p.vaddr + pos + 4 + tail)))[0]
                for i in hit:
                    i = int(i)
                    if i >= 1 and (seg[i - 1] & 0xC7) == 0x05:
                        va = p.vaddr + i - 2
                        if not any(a <= va < e for a, e in plt_ranges):
                            n += 1
    return n


def _callers(b: Binary, stub: int) -> tuple[int, int, int]:
    """(calls, tail jumps, call sites reading the result) for a PLT entry."""
    calls = jmps = used = 0
    for p in b.loads():
        if not p.is_exec:
            continue
        seg = b.segment_bytes(p)
        a = np.frombuffer(seg, np.uint8)
        for op in (0xE8, 0xE9):
            idx = np.nonzero(a[:-4] == op)[0] if len(a) > 4 else []
            if not len(idx):
                continue
            w = np.lib.stride_tricks.sliding_window_view(a, 4)[idx + 1].copy().view(np.int32).ravel()
            tgt = p.vaddr + idx.astype(np.int64) + 5 + w
            for i in idx[tgt == stub]:
                if op == 0xE9:
                    jmps += 1
                    continue
                calls += 1
                va = p.vaddr + int(i)
                try:
                    fn = xf.function_at(lambda v, n: b.read(v, n), va)
                    k = fn.index(va)
                    if xf.read_before_write(fn, "rax", k + 1) is not None:
                        used += 1
                except Exception:                                   # noqa: BLE001
                    used += 1
    return calls, jmps, used


def plan_module(b: Binary, target: int) -> Plan | None:
    """None: module has nothing to do. Plan.status PATCH / DONE / UNKNOWN."""
    d = dynamic.parse(b)
    if not d or dynamic.DT_JMPREL not in d.tags or dynamic.DT_PLTRELSZ not in d.tags:
        return None
    imp = d.imported_nids()
    if not imp & (set(FIRST_FW) | {UMTX}):
        return None
    slots = jump_slots(b, d)
    sync = [s for s in slots if s.nid in FIRST_FW]
    umtx = [s for s in slots if s.nid == UMTX]
    # DONE: renamed to _umtx_op and the PLT entry is one of our shims
    done = [s for s in umtx if not canonical_plt(s.entry) and any(s.entry.startswith(p) for p in SHIM_PREFIX.values())]
    if done and not sync:
        return Plan("DONE", f"{len(done)} PLT entr{'y' if len(done) == 1 else 'ies'} already shimmed to _umtx_op")
    need = [s for s in sync if FIRST_FW[s.nid] > target]
    if not need:
        return None
    if done:
        return Plan("UNKNOWN", "partly converted already (shims and sync imports both present)")
    pl = Plan("PATCH", convert=need)
    t = d.tags
    if (t.get(0x1E, [0])[0] & DF_BIND_NOW) or 24 in t or (t.get(0x6FFFFFFB, [0])[0] & DF_1_NOW):
        return Plan("UNKNOWN", "BIND_NOW: lazy PLT stubs are required", convert=need)
    for s in need:
        if not canonical_plt(s.entry):
            return Plan("UNKNOWN", f"{LABEL[s.nid]} PLT entry at {s.va:#x} is not a canonical ff25 stub", convert=need)
        if b.u64(s.got) != s.va + 6:
            return Plan("UNKNOWN", f"{LABEL[s.nid]} GOT slot {s.got:#x} is not lazy", convert=need)
        sym = d.symbols[s.sym]
        if sym.defined or not d.lib_name(sym).startswith("libkernel"):
            return Plan("UNKNOWN", f"{LABEL[s.nid]} is not an undefined libkernel import", convert=need)
    # symbol strings: rename in place, each string must be unique and used only by converted symbols
    strtab, strsz = t[dynamic.DT_STRTAB][0], t[dynamic.DT_STRSZ][0]
    blob = b.read(strtab, strsz)
    symtab = t[dynamic.DT_SYMTAB][0]
    done_str: set[int] = set()
    for s in need:
        off = b.u32(symtab + 24 * s.sym)
        if off in done_str:
            continue
        old = d.symbols[s.sym].name.encode()
        if len(re.findall(rb"(?<=\0)" + re.escape(old) + rb"(?=\0)", blob)) != 1 or blob[off:off + len(old) + 1] != old + b"\0":
            return Plan("UNKNOWN", f"string of {LABEL[s.nid]} is not unique in the string table", convert=need)
        users = [x for x in range(len(d.symbols)) if b.u32(symtab + 24 * x) == off]
        if any(x not in {y.sym for y in need} for x in users):
            return Plan("UNKNOWN", f"string of {LABEL[s.nid]} is shared with another symbol", convert=need)
        done_str.add(off)
        new = UMTX.encode() + old[len(UMTX):]
        pl.renames.append((strtab + off, old, new))
    plt_ranges = [(s.va, s.va + 16) for s in slots]
    stray = _refs_outside_plt(b, [s.got for s in need], plt_ranges)
    if stray:
        return Plan("UNKNOWN", f"{stray} code reference(s) to the import GOT slots outside the PLT", convert=need)
    for s in need:
        c, j, u = _callers(b, s.va)
        pl.callers[LABEL[s.nid]] = c + j
        pl.result_used += u
    # _umtx_op: the module's own import, else the first converted slot
    own = next((s for s in umtx if canonical_plt(s.entry)), None)
    if own:
        pl.umtx_plt = own.va
    else:
        pl.anchor_slot = need[0]
    kinds = {s.nid for s in need}
    sizes = _sizes(kinds, pl.anchor_slot is not None)
    avoid = [(s.va, s.va + 16) for s in slots]
    at = _allocate(int3_runs(b, avoid), sizes)
    if at is None:
        ex = next((i for i, p in enumerate(b.phdrs) if p.type == 1 and p.is_exec), None)
        need_b = sum(sizes.values())
        if ex is None or b.slack(ex) < need_b + 16:
            return Plan("UNKNOWN", f"no code cave: needs {need_b} bytes (int3 padding too small, no segment slack)",
                        convert=need)
        pl.grow = (ex, need_b)
        base = b.cave_rva(ex, 1)
        at, off = {}, 0
        for k in sizes:
            at[k] = base + off
            off += sizes[k]
    pl.placement = at
    return pl


# ------------------------------------------------------------------ apply
def build_edits(b: Binary, pl: Plan) -> list[tuple[int, bytes, bytes, str]]:
    """(rva, old, new, note) for a PATCH plan; caves in segment growth are returned with old == b''."""
    kinds = {s.nid for s in pl.convert}
    at = dict(pl.placement)
    if pl.anchor_slot is not None:
        anchor = ("got", pl.anchor_slot.got)
        e = pl.anchor_slot.entry
        plt0 = pl.anchor_slot.va + 16 + struct.unpack_from("<i", e, 12)[0]
        a = Asm(at["tail"])
        a.hex("68" + e[7:11].hex())
        a.rel32("e9", plt0)
        tail = a.assemble()
    else:
        anchor, tail = ("plt", pl.umtx_plt), None
    pieces = pieces_for(kinds, anchor, tail, at)
    edits: list[tuple[int, bytes, bytes, str]] = []
    for name, code in pieces.items():
        old = b"" if pl.grow else b.read(at[name], len(code))
        if not pl.grow and old != b"\xcc" * len(code):
            raise ValueError(f"cave {name} at {at[name]:#x} is no longer int3 padding")
        what = {"plain": "plain helper (ecx=0, r9=-1, tail-jump _umtx_op)",
                "ta": "timed helper: load the uint32 us", "ta2": "timed helper: us -> timespec on the stack", "tb": "timed helper: call _umtx_op",
                "tail": "relocated lazy PLT tail"}[name]
        edits.append((at[name], old, code, what))
    for s in pl.convert:
        helper = at["plain"] if s.nid == WAKE else at["ta"]
        new = shim(s.nid, s.va, helper)
        edits.append((s.va, s.entry, new, f"{LABEL[s.nid]} PLT entry -> _umtx_op op {OP[s.nid]} shim"))
    if pl.anchor_slot is not None:
        g = pl.anchor_slot.got
        edits.append((g, struct.pack("<Q", pl.anchor_slot.va + 6), struct.pack("<Q", at["tail"]),
                      "GOT slot -> relocated lazy tail"))
    for rva, old, new in pl.renames:
        edits.append((rva, old, new, f"import string {old[:11].decode()} -> _umtx_op"))
    return edits


class SyncUmtx(Rule):
    name = "sync-umtx"
    summary = ("EXPERIMENTAL: SyncOnAddress Wait/Wake imports -> _umtx_op shims on targets below their first "
               "FW (libc, Unity PS5Util)")

    def detect(self, ctx: RuleContext) -> list[Finding]:
        out = []
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error:
                continue
            nids = {n for v in bi.imports_by_module.values() for n in v}
            if not nids & (set(FIRST_FW) | {UMTX}):
                continue
            try:
                pl = plan_module(ctx.load(bi.path), ctx.declared_sdk)
            except Exception as e:                                   # noqa: BLE001
                out.append(Finding(self.name, bi.path, f"UNKNOWN: {e}", applicable=False, reason=str(e),
                                   data={"status": "UNKNOWN"}))
                continue
            if pl is None:
                continue
            labels = ", ".join(LABEL[s.nid] for s in pl.convert)
            if pl.status == "PATCH":
                where = (f"via {bi.path}'s own _umtx_op import" if pl.umtx_plt is not None
                         else "renaming the first converted import to _umtx_op")
                warn = ""
                if pl.result_used:
                    warn = (f"; {pl.result_used} call site(s) read the result (raw _umtx_op: -1/errno on "
                            "failure, not an error code)")
                callers = ", ".join(f"{k} x{v}" for k, v in pl.callers.items())
                out.append(Finding(self.name, bi.path, f"PATCH: {labels} -> _umtx_op shims ({callers}), {where}",
                                   applicable=True, recommended=False,
                                   reason="experimental: never recommended, console test needed" + warn,
                                   data={"status": "PATCH", "nids": [s.nid for s in pl.convert]}))
            else:
                out.append(Finding(self.name, bi.path, f"{pl.status}: {pl.why}", applicable=False,
                                   reason=pl.why, data={"status": pl.status}))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        pl = plan_module(b, ctx.declared_sdk)
        if pl is None or pl.status != "PATCH":
            raise ValueError(f"{f.file}: sync-umtx plan changed ({pl.status if pl else 'nothing to do'})")
        edits = build_edits(b, pl)
        if pl.grow:
            ex, n = pl.grow
            caves = [e for e in edits if not e[1]]
            blob = bytearray(sum(len(e[2]) for e in caves))
            pos = pl.placement
            lo = min(pos.values())
            for rva, _, code, _n in caves:
                blob[rva - lo:rva - lo + len(code)] = code
            got = b.add_cave(ex, bytes(blob), 1)
            if got != lo:
                raise ValueError("cave placement mismatch")
            for rva, _, code, note in caves:
                ctx.edit(f.file, f"rule:{self.name}", b.foff(rva), "", code.hex(), note + " (segment grown)")
        for rva, old, new, note in edits:
            if not old and pl.grow:
                continue
            off = b.patch(rva, old, new)
            ctx.edit(f.file, f"rule:{self.name}", off, old.hex(), new.hex(), note)
