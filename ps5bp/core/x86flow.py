"""Small x86-64 data-flow helpers over one function (capstone detail mode).

Deliberately simple: linear decoding from the function start, register read/write
sets from capstone, sub-registers folded to their 64-bit parent. Good enough to follow
how a call argument was computed inside straight-line compiler output; callers must
treat anything they can't follow as unknown.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

import capstone
from capstone import x86

_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
_md.detail = True

ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
CALLEE_SAVED = {"rbx", "rbp", "r12", "r13", "r14", "r15"}
CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
_LEGACY = {"a": "rax", "b": "rbx", "c": "rcx", "d": "rdx", "si": "rsi", "di": "rdi", "bp": "rbp", "sp": "rsp"}


def canon(name: str) -> str:
    """eax/ax/al/r14d/r14w/r14b -> 64-bit parent; others unchanged."""
    if name.startswith("r") and name[1:3].rstrip("dwb").isdigit():
        return "r" + "".join(c for c in name[1:] if c.isdigit())
    n = name
    for pre in ("r", "e"):
        if n.startswith(pre) and n[1:] in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
            n = n[1:]
    if n in ("ax", "bx", "cx", "dx"):
        return _LEGACY[n[0]]
    if n in ("al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"):
        return _LEGACY[n[0]]
    if n in ("si", "sil", "di", "dil", "bp", "bpl", "sp", "spl"):
        return _LEGACY[n[:2]]
    return name


IGNORE = {"rsp", "rip", "rflags", "flags", "eflags", "fpsw"}


@dataclass
class Insn:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    reads: set[str]
    writes: set[str]
    target: int | None = None          # rel32/rel8 branch or call target
    rip_target: int | None = None      # [rip+disp] effective address
    disp_offset: int = 0               # offset of the rip disp32 inside the instruction
    imm_offset: int = 0                # offset of the branch displacement
    mem_store: bool = False
    store_src: str = ""                # register stored to memory (mov [..], reg)
    raw: object = field(default=None, repr=False)

    @property
    def end(self) -> int:
        return self.address + self.size


def _mk(i) -> Insn:
    try:
        r, w = i.regs_access()
    except capstone.CsError:
        r, w = [], []
    reads = {canon(i.reg_name(x)) for x in r} - IGNORE
    writes = {canon(i.reg_name(x)) for x in w} - IGNORE
    if i.group(capstone.CS_GRP_CALL):
        writes |= CALLER_SAVED                     # SysV: a call clobbers every caller-saved reg
    tgt = rip = None
    store = False
    store_src = ""
    for op in i.operands:
        if op.type == x86.X86_OP_MEM:
            if op.mem.base == x86.X86_REG_RIP:
                rip = i.address + i.size + op.mem.disp
            if op.access & capstone.CS_AC_WRITE:
                store = True
    if store and len(i.operands) == 2 and i.operands[1].type == x86.X86_OP_REG:
        store_src = canon(i.reg_name(i.operands[1].reg))
    if i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL):
        if i.operands and i.operands[0].type == x86.X86_OP_IMM:
            tgt = i.operands[0].imm
    d = i.disp_offset if rip is not None else 0
    return Insn(i.address, i.size, i.mnemonic, i.op_str, bytes(i.bytes), reads, writes, tgt, rip, d,
                i.imm_offset if tgt is not None else 0, store, store_src, i)


def decode(code: bytes, va: int) -> list[Insn]:
    return [_mk(i) for i in _md.disasm(code, va)]


def func_start(read, va: int, limit: int = 0x8000) -> int:
    """Start of the function containing va: just after int3 / 8x zero padding."""
    lo = max(0, va - limit)
    blob = read(lo, va - lo + 1)
    for k in range(len(blob) - 1, 1, -1):
        c = blob[k]
        if c != 0xCC and blob[k - 1] == 0xCC and blob[k - 2] == 0xCC:
            return lo + k
        if c != 0 and k >= 8 and blob[k - 8:k] == b"\0" * 8:
            return lo + k
    return lo


@dataclass
class Function:
    start: int
    insns: list[Insn]

    @property
    def end(self) -> int:
        return self.insns[-1].end if self.insns else self.start

    def index(self, va: int) -> int:
        for k, i in enumerate(self.insns):
            if i.address == va:
                return k
        raise KeyError(hex(va))

    def contains(self, va: int) -> bool:
        return self.start <= va < self.end


def function_at(read, va: int, max_size: int = 0x6000) -> Function:
    """Decode the function containing va: from its start to the int3 padding after it."""
    st = func_start(read, va)
    code = read(st, max(max_size, va - st + 0x400))
    out: list[Insn] = []
    for ins in decode(code, st):
        if ins.mnemonic == "int3" and ins.address > va:
            break
        out.append(ins)
    if not any(i.address == va for i in out) and not any(i.address < va < i.end for i in out):
        # decoding desynchronised (data in code?) — restart near va
        out = decode(read(va, 0x400), va)
        return Function(va, out)
    # functions packed back to back without padding: split at an aligned `push rbp`
    # that follows an unconditional ret/jmp/ud2
    starts = [st]
    for k in range(1, len(out)):
        i, prev = out[k], out[k - 1]
        if i.mnemonic == "push" and i.op_str == "rbp" and i.address % 16 == 0 and \
                prev.mnemonic in ("ret", "jmp", "ud2", "int3"):
            starts.append(i.address)
    s = max(a for a in starts if a <= va)
    nxt = min((a for a in starts if a > va), default=None)
    out = [i for i in out if i.address >= s and (nxt is None or i.address < nxt)]
    return Function(s, out)


def last_write(fn: Function, reg: str, before: int, after: int = -1) -> int | None:
    """Index of the last instruction in (after, before) writing reg."""
    for k in range(before - 1, after, -1):
        if reg in fn.insns[k].writes:
            return k
    return None


def def_chain(fn: Function, reg: str, at: int, depth: int = 8):
    """Follow how `reg` got its value at instruction index `at`.

    Returns (defs, roots): defs = indices of defining instructions (in order),
    roots = set of (reg, kind) where kind is 'entry' (value live at function entry —
    an argument or callee-saved), 'call' (return value of a call), 'mem' (loaded)."""
    defs: list[int] = []
    roots: set[tuple[str, str]] = set()
    todo = [(reg, at, 0)]
    seen = set()
    while todo:
        r, pos, dep = todo.pop()
        if (r, pos) in seen or dep > depth:
            continue
        seen.add((r, pos))
        k = last_write(fn, r, pos)
        if k is None:
            roots.add((r, "entry"))
            continue
        ins = fn.insns[k]
        if ins.mnemonic == "call":
            roots.add((r, "call"))
            continue
        defs.append(k)
        srcs = ins.reads - {r} if ins.mnemonic in ("mov", "movzx", "movsxd", "lea") else ins.reads
        if ins.mnemonic in ("xor", "sub") and len(ins.raw.operands) == 2 and \
                ins.raw.operands[0].type == ins.raw.operands[1].type == x86.X86_OP_REG and \
                ins.raw.operands[0].reg == ins.raw.operands[1].reg:
            srcs = set()                                  # zeroing idiom
        if any(op.type == x86.X86_OP_MEM for op in ins.raw.operands) and ins.mnemonic != "lea":
            roots.add((r, "mem"))
        for s in srcs:
            todo.append((s, k, dep + 1))
    defs = sorted(set(defs))
    return defs, roots


def imm_written(fn: Function, reg: str, before: int) -> int | None:
    """Immediate loaded into reg by the last write before index `before` (mov reg, imm)."""
    k = last_write(fn, reg, before)
    if k is None:
        return None
    ops = fn.insns[k].raw.operands
    if fn.insns[k].mnemonic == "mov" and len(ops) == 2 and ops[1].type == x86.X86_OP_IMM:
        return ops[1].imm & 0xFFFFFFFFFFFFFFFF
    return None


def read_before_write(fn: Function, reg: str, start: int) -> int | None:
    """First index >= start that reads reg before any write to it (liveness), else None."""
    for k in range(start, len(fn.insns)):
        ins = fn.insns[k]
        if reg in ins.reads and not (ins.mnemonic in ("xor", "sub") and reg in ins.writes and
                                     ins.op_str.split(",")[0].strip() == ins.op_str.split(",")[-1].strip()):
            return k
        if reg in ins.writes:
            return None
        if ins.mnemonic == "call" and reg in CALLER_SAVED:
            return None
        if ins.mnemonic == "ret":
            return None
    return None


def rel32_target(read, va: int) -> int | None:
    b = read(va, 6)
    if b[0] in (0xE8, 0xE9):
        return va + 5 + struct.unpack_from("<i", b, 1)[0]
    if b[0] == 0x0F and 0x80 <= b[1] <= 0x8F:
        return va + 6 + struct.unpack_from("<i", b, 2)[0]
    return None
