"""Tiny x86-64 code-cave assembler + PLT helpers.

Caves are written as hex templates with fixups, not general assembly: every byte
of a rule's cave is visible in the source and can be compared with a known-good
backport.  Addresses are runtime VAs (rva + load base, eboot base 0x400000).
"""
from __future__ import annotations

import re
import struct

from .binary import Binary
from .dynamic import Dynamic

REG64 = {n: i for i, n in enumerate(
    "rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15".split())}


class Asm:
    def __init__(self, base_va: int):
        self.base = base_va
        self.buf = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, int | str, int]] = []   # (pos of disp32, target, bytes after disp)
        self.fixups8: list[tuple[int, int | str]] = []

    @property
    def here(self) -> int:
        return self.base + len(self.buf)

    def hex(self, h: str) -> "Asm":
        self.buf += bytes.fromhex(h.replace(" ", ""))
        return self

    def raw(self, b: bytes) -> "Asm":
        self.buf += b
        return self

    def imm32(self, v: int) -> "Asm":
        self.buf += struct.pack("<i" if v < 0 else "<I", v)
        return self

    def label(self, name: str) -> "Asm":
        self.labels[name] = self.here
        return self

    def rel32(self, opcode: str, target: int | str) -> "Asm":
        """call (e8) / jmp (e9) / jcc (0f 8x) with a 32-bit displacement."""
        self.hex(opcode)
        self.fixups.append((len(self.buf), target, 0))
        self.buf += b"\0\0\0\0"
        return self

    def rel8(self, opcode: str, target: int | str) -> "Asm":
        """short jmp (eb) / jcc (7x) with an 8-bit displacement."""
        self.hex(opcode)
        self.fixups8.append((len(self.buf), target))
        self.buf += b"\0"
        return self

    def rip32(self, prefix: str, target: int | str, tail: str = "") -> "Asm":
        """Instruction with a [rip+disp32] operand: prefix bytes, disp32, then `tail` bytes."""
        self.hex(prefix)
        t = bytes.fromhex(tail.replace(" ", ""))
        self.fixups.append((len(self.buf), target, len(t)))
        self.buf += b"\0\0\0\0" + t
        return self

    def assemble(self) -> bytes:
        for pos, target, tail in self.fixups:
            t = self.labels[target] if isinstance(target, str) else target
            disp = t - (self.base + pos + 4 + tail)
            struct.pack_into("<i", self.buf, pos, disp)
        for pos, target in self.fixups8:
            t = self.labels[target] if isinstance(target, str) else target
            disp = t - (self.base + pos + 1)
            if not -128 <= disp < 128:
                raise ValueError(f"rel8 to {target} out of range ({disp})")
            self.buf[pos] = disp & 0xFF
        return bytes(self.buf)


def rex_rm(reg: str, ext: int) -> bytes:
    """REX.W + 81 /ext ModRM for an `op reg64, imm32` instruction."""
    r = REG64[reg]
    return bytes([0x48 | (r >> 3), 0x81, 0xC0 | (ext << 3) | (r & 7)])


def plt_stubs(b: Binary, dyn: Dynamic, base: int) -> dict[str, int]:
    """Full import name -> runtime VA of its PLT stub (`ff 25 disp32` through the GOT slot)."""
    out: dict[str, int] = {}
    for p in b.loads():
        if not p.is_exec:
            continue
        seg = b.segment_bytes(p)
        for m in re.finditer(rb"\xff\x25", seg):
            i = m.start()
            if i + 6 > len(seg):
                continue
            got = p.vaddr + i + 6 + struct.unpack_from("<i", seg, i + 2)[0]
            name = dyn.plt.get(got)
            if name and name not in out:
                out[name] = base + p.vaddr + i
    return out


def stub_for(stubs: dict[str, int], nid: str) -> int | None:
    return next((va for name, va in stubs.items() if name.split("#")[0] == nid), None)


def is_plt_entry(b: Binary, va: int, base: int) -> bool:
    """16-byte PS5 PLT entry: ff 25 d32 | 68 imm32 | e9 rel32."""
    e = b.read(va - base, 16)
    return e[:2] == b"\xff\x25" and e[6] == 0x68 and e[11] == 0xE9
