"""Register alias tracking and memory-store collection over one decoded function.

Used by the request-struct rules (gamepresets-28, savedata-mount, savedata-prepare): a
call argument such as `lea rsi,[rbp-0x50]` names a stack object; stores to that object are
written through other registers (`mov rax,rsi; mov qword [rax+0x18], -1`) or through the
frame register directly. The scan keeps, per register, a *versioned* base token plus a
constant offset, so two accesses are the same object exactly when their (token, offset)
match, and a register that was overwritten in between can never alias the old object.

Linear, not path-sensitive: stores in any basic block before the call are collected, the
caller decides what to do with duplicates / conflicts (the rules require exactly one match
and refuse otherwise).
"""
from __future__ import annotations

from dataclasses import dataclass

from capstone import x86

from . import x86flow as xf

Tok = tuple[str, int]          # (register, version)

_STORE_MN = {"mov", "movabs", "movups", "movaps", "movdqu", "movdqa", "vmovups", "vmovaps", "vmovdqu", "vmovdqa",
             "movq", "vmovq"}
_ZERO_MN = {"xor", "sub", "vxorps", "vxorpd", "vpxor", "xorps", "xorpd", "pxor"}


def vcanon(name: str) -> str:
    """xmmN / ymmN / zmmN -> 'vN' (one name per vector register); others as x86flow.canon."""
    if name[1:3] == "mm" and name[0] in "xyz" and name[3:].isdigit():
        return "v" + name[3:]
    return xf.canon(name)


@dataclass
class Store:
    idx: int
    insn: xf.Insn
    base: Tok
    off: int
    size: int                  # operand size in bytes
    imm: int | None            # sign-extended immediate, None when a register/other is stored
    src: str                   # canonical source register for reg stores ('' otherwise; vector regs 'v<N>')
    zero: bool = False         # stores a value known to be zero (imm 0, or a register zeroed by xor/vxorps)


class Flow:
    def __init__(self) -> None:
        self.ver: dict[str, int] = {}
        self.alias: dict[str, tuple[Tok, int]] = {}
        self.stores: list[Store] = []
        self.zero: set[str] = set()                # registers currently known to hold zero

    def tok(self, reg: str) -> Tok:
        return (reg, self.ver.get(reg, 0))

    def resolve(self, reg: str) -> tuple[Tok, int]:
        """(base token, offset) such that `reg` currently equals base+offset."""
        return self.alias.get(reg) or (self.tok(reg), 0)

    def _bump(self, reg: str) -> None:
        self.ver[reg] = self.ver.get(reg, 0) + 1
        self.alias.pop(reg, None)

    def mem_loc(self, op) -> tuple[Tok, int] | None:
        """Resolved location of a memory operand (None for rip-relative / indexed)."""
        m = op.mem
        if m.base == 0 or m.index != 0 or m.base == x86.X86_REG_RIP:
            return None
        return self._loc(xf.canon(_rn(op, m.base)), m.disp)

    def _loc(self, base: str, disp: int) -> tuple[Tok, int]:
        t, o = self.resolve(base)
        return t, o + disp

    def step(self, k: int, i: xf.Insn) -> None:
        ops = i.raw.operands
        # 1. store?
        # (capstone mislabels the memory operand of vmovups/vmovaps stores as read: key on the mnemonic)
        if ops and ops[0].type == x86.X86_OP_MEM and len(ops) == 2 and i.mnemonic in _STORE_MN:
            loc = self.mem_loc(ops[0])
            if loc:
                src = ops[1]
                imm = src.imm if src.type == x86.X86_OP_IMM else None
                reg = vcanon(_rn(src, src.reg)) if src.type == x86.X86_OP_REG else ""
                self.stores.append(Store(k, i, loc[0], loc[1], ops[0].size, imm, reg,
                                         zero=(imm == 0) or (reg != "" and reg in self.zero)))
        # 2. alias / version update
        mn = i.mnemonic
        new_alias = None
        if len(ops) == 2 and ops[0].type == x86.X86_OP_REG and ops[0].size == 8:
            dst = xf.canon(_rn(ops[0], ops[0].reg))
            if mn == "lea" and ops[1].type == x86.X86_OP_MEM:
                loc = self.mem_loc(ops[1])
                if loc:
                    new_alias = (dst, loc)
            elif mn == "mov" and ops[1].type == x86.X86_OP_REG and ops[1].size == 8:
                new_alias = (dst, self.resolve(xf.canon(_rn(ops[1], ops[1].reg))))
            elif mn in ("add", "sub") and ops[1].type == x86.X86_OP_IMM and dst != "rsp":
                t, o = self.resolve(dst)
                new_alias = (dst, (t, o + (ops[1].imm if mn == "add" else -ops[1].imm)))
        zeroing = None
        if i.mnemonic in _ZERO_MN and len(ops) >= 2 and all(o.type == x86.X86_OP_REG for o in ops) \
                and ops[-1].reg == ops[-2].reg:
            zeroing = vcanon(_rn(ops[0], ops[0].reg))
        elif mn == "mov" and len(ops) == 2 and ops[0].type == x86.X86_OP_REG and ops[1].type == x86.X86_OP_IMM \
                and ops[1].imm == 0:
            zeroing = vcanon(_rn(ops[0], ops[0].reg))
        for w in i.writes:
            self.zero.discard(vcanon(w))
            if w == "rsp":
                continue
            self._bump(w)
        if zeroing:
            self.zero.add(zeroing)
        if mn in ("push", "pop", "leave") or (len(ops) >= 1 and ops[0].type == x86.X86_OP_REG
                                               and xf.canon(_rn(ops[0], ops[0].reg)) == "rsp"
                                               and mn in ("add", "sub", "and", "mov", "lea")):
            self._bump("rsp")
        if new_alias:
            self.alias[new_alias[0]] = new_alias[1]

    def run(self, insns: list[xf.Insn], upto: int) -> "Flow":
        for k in range(upto):
            self.step(k, insns[k])
        return self


def _rn(op, reg: int) -> str:
    # capstone register names need the owning instruction; resolve through the shared engine
    return xf._md.reg_name(reg)


def scan(fn: xf.Function, upto: int) -> Flow:
    """Flow state just before instruction index `upto`, with every store before it."""
    return Flow().run(fn.insns, upto)


def reg_state_at(fn: xf.Function, upto: int, reg: str) -> tuple[Flow, tuple[Tok, int]]:
    f = scan(fn, upto)
    return f, f.resolve(reg)
