"""x86-64 disassembly helpers (capstone) with import / string annotation."""
from __future__ import annotations

import re
import struct

import capstone

from .binary import Binary
from .dynamic import Dynamic
from . import nid as nidmod

_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
_RIP = re.compile(r"\[rip ([+-]) (0x[0-9a-f]+)\]")


class Disasm:
    """Disassemble a Binary at runtime addresses (rva + base)."""

    def __init__(self, b: Binary, base: int = 0x400000, dyn: Dynamic | None = None):
        self.b, self.base, self.dyn = b, base, dyn

    def read(self, va: int, n: int) -> bytes:
        return self.b.read(va - self.base, n)

    def insns(self, va: int, n: int):
        return _md.disasm(self.read(va, n), va)

    def func_start(self, va: int, limit: int = 0x20000) -> int:
        """Scan back to int3 padding (compiled funcs) or 8+ zero bytes (hand-written caves)."""
        for p in range(va, va - limit, -1):
            if self.read(p - 2, 2) == b"\xcc\xcc" and self.read(p, 1) != b"\xcc":
                return p
            if self.read(p - 8, 8) == b"\0" * 8 and self.read(p, 1) != b"\0":
                return p
        return va

    def import_at(self, va: int, depth: int = 0) -> str | None:
        """Full symbol name if va is a PLT stub (follows jmp/call thunks)."""
        if not self.dyn:
            return None
        for i in self.insns(va, 16):
            m = _RIP.search(i.op_str)
            if i.mnemonic == "jmp" and m and m[1] == "+":
                got = i.address + i.size + int(m[2], 16) - self.base
                return self.dyn.plt.get(got)
            if i.mnemonic in ("jmp", "call") and i.op_str.startswith("0x") and depth < 4:
                return self.import_at(int(i.op_str, 16), depth + 1)
            return None
        return None

    def annotate(self, i) -> str:
        m = _RIP.search(i.op_str)
        if m:
            t = i.address + i.size + int(m[2], 16) * (1 if m[1] == "+" else -1)
            s = self.read(t, 64).split(b"\0")[0]
            if len(s) >= 4 and all(32 <= c < 127 for c in s):
                return f'; {t:#x} "{s.decode()}"'
            return f"; {t:#x}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            sym = self.import_at(int(i.op_str, 16))
            if sym:
                n = nidmod.split(sym)[0]
                return f"; {sym} {nidmod.name_of(n)}".rstrip()
        return ""

    def window(self, va: int, before: int = 0x40, after: int = 0x60) -> list[str]:
        st = self.func_start(va)
        if va - st > 0x4000:
            st = va - before
        out = []
        for i in self.insns(st, va + after - st):
            if i.address >= va - before:
                mark = ">>" if i.address == va else "  "
                out.append(f"{mark}{i.address:10x}: {i.mnemonic:8} {i.op_str:40} {self.annotate(i)}".rstrip())
        return out


def rel32(frm: int, to: int, op: str = "call") -> bytes:
    return (b"\xe8" if op == "call" else b"\xe9") + struct.pack("<i", to - (frm + 5))
