"""Call-site proofs for stub contracts that are only safe under a caller contract.

Everything here is read-only analysis over direct calls to an import's PLT entry. Anything that
cannot be followed (tail jumps, address-taken imports, indirect calls through the GOT, odd shapes)
fails the gate: a gate that cannot be proved means the NID is not seeded.
"""
from __future__ import annotations

import re
import struct

import numpy as np

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, x86

from .. import x86flow as xf

MAX_STEPS = 400


def refs(b, plt: int, got: int, base: int = 0) -> tuple[list[int], list[str]]:
    """(rvas of `call rel32` to the PLT entry, descriptions of every other reference).
    Scans executable segments for call/jmp rel32 to `plt`, rip-relative lea/mov of the entry or of
    the GOT slot and `call/jmp [rip+got]`."""
    calls: list[int] = []
    other: list[str] = []
    for p in b.loads():
        if not p.is_exec:
            continue
        seg = b.segment_bytes(p)
        arr = np.frombuffer(seg, np.uint8)
        idx = np.nonzero((arr == 0xE8) | (arr == 0xE9))[0]
        idx = idx[idx + 5 <= len(seg)]
        disp = np.lib.stride_tricks.sliding_window_view(arr, 4)[idx + 1].copy().view(np.int32).ravel()
        for i in idx[(p.vaddr + idx + 5 + disp.astype(np.int64)) == plt]:
            i = int(i)
            if seg[i] == 0xE9 and i >= 11 and seg[i - 11:i - 9] == b"\xff\x25" and seg[i - 5] == 0x68:
                continue                                   # the `jmp PLT0` inside a PLT entry
            if seg[i] == 0xE8:
                calls.append(p.vaddr + i)
            else:
                other.append(f"jmp to the PLT entry at {p.vaddr + i:#x} (tail call)")
        for m in re.finditer(rb"(?:[\x48\x4c]\x8b|[\x48\x4c]\x8d|\xff)[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", seg):
            i = m.start()
            n = 3 if seg[i] != 0xFF else 2
            if i + n + 4 > len(seg):
                continue
            t = p.vaddr + i + n + 4 + struct.unpack_from("<i", seg, i + n)[0]
            if t in (plt, got) and p.vaddr + i != plt:
                other.append(f"address/GOT reference at {p.vaddr + i:#x}")
    return sorted(calls), other


def _fn(b, base: int, rva: int):
    from ..memsite import Scanner                      # clips reads to the code segment
    sc = b.__dict__.get("_scanner")
    if sc is None or sc.base != base:
        sc = b.__dict__["_scanner"] = Scanner(b, base)
    return xf.function_at(sc.read, base + rva)


_CS = Cs(CS_ARCH_X86, CS_MODE_64)


def result_use(fn: xf.Function, k: int) -> str:
    """How the return value of the call at insns[k] is used: 'unused' | 'error-check' | 'used'.
    'error-check' = only `test eax,eax` / `cmp eax,imm` followed by a conditional jump. Any other
    read, a return with rax live, tail jumps or unfollowable flow count as 'used'."""
    insns = fn.insns
    by_addr = {i.address: n for n, i in enumerate(insns)}
    todo, seen, steps = [k + 1], set(), 0
    checked = False
    while todo:
        j = todo.pop()
        while True:
            steps += 1
            if j in seen:
                break
            if j >= len(insns) or steps > MAX_STEPS:
                return "used"
            seen.add(j)
            ins = insns[j]
            mn = ins.mnemonic
            ops = ins.raw.operands
            if mn in ("ret", "retf", "ud2", "hlt"):
                return "used" if mn == "ret" else "unused"
            if mn == "jmp":
                if ins.target is None or ins.target not in by_addr:
                    return "used"
                j = by_addr[ins.target]
                continue
            if mn.startswith("j"):                         # jcc (flags consumer; rax untouched)
                if ins.target is None or ins.target not in by_addr:
                    return "used"
                todo.append(by_addr[ins.target])
                j += 1
                continue
            zero = mn in ("xor", "sub") and len(ops) == 2 and ops[0].type == ops[1].type == x86.X86_OP_REG \
                and ops[0].reg == ops[1].reg and xf.canon(_CS.reg_name(ops[0].reg)) == "rax"
            if "rax" in ins.reads and not zero:
                shape = (mn == "test" and len(ops) == 2 and ops[0].type == ops[1].type == x86.X86_OP_REG
                         and ops[0].reg == ops[1].reg and _CS.reg_name(ops[0].reg) == "eax") or \
                        (mn == "cmp" and len(ops) == 2 and ops[0].type == x86.X86_OP_REG
                         and _CS.reg_name(ops[0].reg) == "eax" and ops[1].type == x86.X86_OP_IMM)
                nxt = insns[j + 1] if j + 1 < len(insns) else None
                if shape and nxt is not None and nxt.mnemonic.startswith("j") and nxt.mnemonic != "jmp":
                    checked = True
                    j += 1
                    continue
                return "used"
            if "rax" in ins.writes:
                if ops and ops[0].type == x86.X86_OP_REG and _CS.reg_name(ops[0].reg) in ("al", "ah", "ax"):
                    return "used"                           # partial write keeps part of the result
                break                                        # overwritten: this path no longer sees it
            j += 1
    return "error-check" if checked else "unused"


def frame_slot(fn: xf.Function, k: int) -> tuple[str, int] | None:
    """(base reg, disp) when rsi at the call insns[k] is `lea rsi,[rbp-X]` / `[rsp+X]` with no
    branch target between the lea and the call."""
    w = xf.last_write(fn, "rsi", k)
    if w is None:
        return None
    ins = fn.insns[w]
    if ins.mnemonic != "lea" or len(ins.raw.operands) != 2:
        return None
    m = ins.raw.operands[1].mem
    base = _CS.reg_name(m.base) if m.base else ""
    if base not in ("rbp", "rsp") or m.index:
        return None
    if _branch_target_between(fn, ins.address, fn.insns[k].address):
        return None
    return base, m.disp


def _branch_target_between(fn: xf.Function, lo: int, hi: int) -> bool:
    """A jump/call-less control-flow merge point in (lo, hi]: any branch target landing there, or a
    ret/unconditional jump between."""
    for i in fn.insns:
        if i.target is not None and not i.mnemonic == "call" and lo < i.target <= hi:
            return True
    for i in fn.insns:
        if lo < i.address < hi and i.mnemonic in ("ret", "jmp"):
            return True
    return False


def owned_zero_fill(fn: xf.Function, k: int, size: int = 0x40) -> tuple[bool, str]:
    """Output-buffer ownership proof for `out = rsi` of the call at insns[k]: the pointer is a frame
    address and the caller itself stores to every byte of [out, out+size) earlier in the same
    straight-line region (so the object is at least that big and initialised by this function)."""
    fs = frame_slot(fn, k)
    if fs is None:
        return False, "rsi is not a plain frame address (lea rsi,[rbp/rsp±x]) in the calling function"
    base, disp = fs
    if base == "rbp" and disp + size > 0:
        return False, f"frame object at rbp{disp:+#x} extends above the saved frame pointer"
    if base == "rsp" and disp < 0:
        return False, "negative rsp offset"
    covered: dict[int, int] = {}                           # byte offset -> store insn address
    for i in fn.insns[:k]:
        if not i.mem_store:
            continue
        for op in i.raw.operands:
            if op.type != x86.X86_OP_MEM or op.access & 2 == 0:
                continue
            m = op.mem
            if (_CS.reg_name(m.base) if m.base else "") != base or m.index:
                continue
            lo = m.disp - disp
            if i.mnemonic.startswith("stos") or op.size <= 0:
                continue
            for x in range(max(lo, 0), min(lo + op.size, size)):
                covered[x] = i.address
    if len(covered) != size:
        return False, f"only {len(covered)}/{size:#x} bytes of the object are initialised by the caller before the call"
    first = min(covered.values())
    if _branch_target_between(fn, first, fn.insns[k].address):
        return False, "the initialising stores are not on the straight-line path to the call"
    return True, f"{base}{disp:+#x}: {size:#x} bytes initialised by the caller before the call"


def compares_error(fn: xf.Function, k: int, code: int) -> tuple[bool, str]:
    """The first reader of eax after the call is `cmp eax, code`."""
    for j in range(k + 1, min(k + 5, len(fn.insns))):
        ins = fn.insns[j]
        if "rax" in ins.reads:
            ops = ins.raw.operands
            ok = (ins.mnemonic == "cmp" and len(ops) == 2 and ops[0].type == x86.X86_OP_REG
                  and _CS.reg_name(ops[0].reg) == "eax" and ops[1].type == x86.X86_OP_IMM
                  and ops[1].imm & 0xFFFFFFFF == code)
            return ok, "" if ok else f"first use of eax at {ins.address:#x} is `{ins.mnemonic} {ins.op_str}`"
        if "rax" in ins.writes or ins.mnemonic in ("jmp", "ret") or ins.mnemonic.startswith("j"):
            break
    return False, "no `cmp eax, imm` right after the call"


def check(gate: str, b, base: int, plt: int, got: int) -> tuple[bool, str]:
    """Evaluate a contract gate over every caller of the import. (ok, reason / proof summary)."""
    calls, other = refs(b, plt, got, base)
    if other:
        return False, "; ".join(other[:3])
    if not calls:
        return False, "no direct call site found to prove the caller contract on"
    notes = []
    for c in calls:
        try:
            fn = _fn(b, base, c)
            k = fn.index(base + c)
        except (KeyError, ValueError, IndexError):
            return False, f"call at {c:#x} could not be decoded"
        if gate == "result-unused-or-error-check":
            u = result_use(fn, k)
            if u == "used":
                return False, f"caller at {base + c:#x} uses the result"
            notes.append(f"{base + c:#x} result {u}")
        elif gate == "output-buffer-owned-0x40":
            ok, why = owned_zero_fill(fn, k)
            if not ok:
                return False, f"caller at {base + c:#x}: {why}"
            notes.append(f"{base + c:#x} {why}")
        elif gate == "caller-compares-0x80020003":
            ok, why = compares_error(fn, k, 0x80020003)
            if not ok:
                return False, f"caller at {base + c:#x}: {why}"
            notes.append(f"{base + c:#x} compares eax with 0x80020003")
        else:
            return False, f"unknown gate {gate}"
    return True, f"{len(calls)} caller(s): " + "; ".join(notes[:4])
