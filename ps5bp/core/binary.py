"""Unified access to PS5 executables: fake-signed SELF or plain ELF.

All addressing is by *rva* — the 0-relative vaddr used inside the ELF (program
headers, dynamic tags).  Runtime address = rva + load base (eboot: 0x400000).

SELF layout (fake-signed, as shipped in backports and ps5-app-dumper output):
    0x00  magic 4F 15 3D 1D, version/mode/endian/attrs
    0x18  u16 entry count N
    0x20  N x {u64 props, u64 offset, u64 filesz, u64 memsz}
    0x20+N*0x20  ELF header + program headers (copy)
  Both magics (4F153D1D, 5414F5EE) use this layout; whether a file is usable
  depends only on the per-entry props, not on the magic.
  An entry with props bit 0x800 carries the bytes of phdr (props >> 20) & 0xFFF.
  props 0x4 = signed (fine), 0x2 = encrypted, 0x8 = compressed (unsupported).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
SELF_MAGIC = bytes.fromhex("4f153d1d")       # PS4-style SELF header
SELF5_MAGIC = bytes.fromhex("5414f5ee")      # PS5-style SELF header (same entry layout)
SELF_MAGICS = (SELF_MAGIC, SELF5_MAGIC)

PT_LOAD = 1
PT_DYNAMIC = 2
PT_SCE_PROCPARAM = 0x61000001
PT_SCE_MODULE_PARAM = 0x61000002

PROPS_ENCRYPTED = 0x2
PROPS_COMPRESSED = 0x8
PROPS_HAS_BLOCKS = 0x800

PHDR_FMT = "<IIQQQQQQ"
ENTRY_FMT = "<QQQQ"


class FormatError(Exception):
    """Not a usable PS5 executable."""


class EncryptedError(FormatError):
    """Retail (encrypted/compressed) SELF: must be decrypted by a dumper first."""


@dataclass
class Phdr:
    index: int
    type: int
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int

    @property
    def is_exec(self) -> bool:
        return bool(self.flags & 1)


def sniff(path: Path) -> str | None:
    """'self', 'elf' or None, from the first 4 bytes."""
    try:
        with open(path, "rb") as f:
            m = f.read(4)
    except OSError:
        return None
    if m == ELF_MAGIC:
        return "elf"
    return "self" if m in SELF_MAGICS else None


class Binary:
    def __init__(self, data: bytes | bytearray, path: Path | str | None = None):
        self.data = bytearray(data)
        self.path = Path(path) if path else None
        self.writes: list[tuple[int, int]] = []     # (file offset, length) of every modification
        magic = bytes(self.data[:4])
        if magic == ELF_MAGIC:
            self.kind = "elf"
            self.elf_off = 0
            self.entries: list[list[int]] = []
        elif magic in SELF_MAGICS:
            self.kind = "self"
            n, = struct.unpack_from("<H", self.data, 0x18)
            self.entries = [list(struct.unpack_from(ENTRY_FMT, self.data, 0x20 + i * 0x20)) for i in range(n)]
            self.elf_off = 0x20 + n * 0x20
            if bytes(self.data[self.elf_off:self.elf_off + 4]) != ELF_MAGIC:
                raise FormatError(f"{self.name}: SELF without an ELF header after its entry table")
        else:
            raise FormatError(f"{self.name}: not an ELF or fake-signed SELF")
        self.phoff, = struct.unpack_from("<Q", self.data, self.elf_off + 0x20)
        phnum, = struct.unpack_from("<H", self.data, self.elf_off + 0x38)
        self.e_type, = struct.unpack_from("<H", self.data, self.elf_off + 0x10)
        self.phdrs = [Phdr(i, *struct.unpack_from(PHDR_FMT, self.data, self._phdr_pos(i))) for i in range(phnum)]
        # phdr index -> (file offset of its bytes in *this* file, available size)
        self._seg: dict[int, tuple[int, int]] = {}
        if self.kind == "elf":
            for p in self.phdrs:
                if p.filesz:
                    self._seg[p.index] = (p.offset, p.filesz)
        else:
            for k, (props, off, fs, ms) in enumerate(self.entries):
                if not props & PROPS_HAS_BLOCKS:
                    continue
                idx = (props >> 20) & 0xFFF
                if props & (PROPS_ENCRYPTED | PROPS_COMPRESSED):
                    raise EncryptedError(f"{self.name}: segment {idx} is encrypted/compressed "
                                         f"(props {props:#x}) — decrypt the dump first")
                if idx < len(self.phdrs):
                    self._seg[idx] = (off, min(fs, self.phdrs[idx].filesz))

    # ---- construction -------------------------------------------------
    @classmethod
    def load(cls, path: Path | str) -> "Binary":
        return cls(Path(path).read_bytes(), path)

    @property
    def name(self) -> str:
        return self.path.name if self.path else "<memory>"

    def _phdr_pos(self, i: int) -> int:
        return self.elf_off + self.phoff + i * 56

    # ---- address mapping ----------------------------------------------
    def loads(self) -> list[Phdr]:
        return [p for p in self.phdrs if p.type == PT_LOAD]

    def foff(self, rva: int) -> int | None:
        """File offset (in this file) of the byte at rva, or None if not file-backed."""
        for p in self.loads():
            if p.vaddr <= rva < p.vaddr + p.filesz and p.index in self._seg:
                off, size = self._seg[p.index]
                if rva - p.vaddr < size:
                    return off + rva - p.vaddr
        return None

    def read(self, rva: int, n: int) -> bytes:
        o = self.foff(rva)
        if o is None:
            return b"\0" * n
        return bytes(self.data[o:o + n])

    def u32(self, rva: int) -> int:
        return struct.unpack("<I", self.read(rva, 4))[0]

    def u64(self, rva: int) -> int:
        return struct.unpack("<Q", self.read(rva, 8))[0]

    def segment_bytes(self, p: Phdr) -> bytes:
        if p.index not in self._seg:
            return b""
        off, size = self._seg[p.index]
        return bytes(self.data[off:off + size])

    def find(self, needle: bytes) -> bool:
        return self.data.find(needle) >= 0

    # ---- patching -----------------------------------------------------
    def patch(self, rva: int, old: bytes, new: bytes) -> int:
        """Replace old with new at rva after verifying old. Returns the file offset."""
        if len(old) != len(new):
            raise ValueError("old/new length differ")
        o = self.foff(rva)
        if o is None or self.foff(rva + len(old) - 1) != o + len(old) - 1:
            raise ValueError(f"rva {rva:#x}: not file-backed / crosses a segment end")
        have = bytes(self.data[o:o + len(old)])
        if have != old:
            raise ValueError(f"rva {rva:#x}: expected {old.hex()} found {have.hex()}")
        self.data[o:o + len(new)] = new
        self.writes.append((o, len(new)))
        return o

    def write_rva(self, rva: int, new: bytes) -> int:
        """Overwrite bytes at rva without checking the old content (caller verified it)."""
        return self.patch(rva, self.read(rva, len(new)), new)

    def write_phdr(self, p: Phdr) -> None:
        struct.pack_into(PHDR_FMT, self.data, self._phdr_pos(p.index),
                         p.type, p.flags, p.offset, p.vaddr, p.paddr, p.filesz, p.memsz, p.align)
        self.writes.append((self._phdr_pos(p.index), 56))

    def cave_rva(self, idx: int, align: int = 16) -> int:
        """Where the next cave appended to segment idx would start (aligned)."""
        p = self.phdrs[idx]
        end = p.vaddr + p.filesz
        return end + (-end) % align

    def add_cave(self, idx: int, code: bytes, align: int = 16) -> int:
        """Append code to segment idx at cave_rva(idx, align), zero-padding the gap."""
        p = self.phdrs[idx]
        pad = self.cave_rva(idx, align) - (p.vaddr + p.filesz)
        return self.grow(idx, b"\0" * pad + code) + pad

    def slack(self, idx: int) -> int:
        """Zero bytes that can be appended to LOAD segment idx without overlapping anything."""
        p = self.phdrs[idx]
        if p.type != PT_LOAD or idx not in self._seg or p.memsz > p.filesz:
            return 0
        off, size = self._seg[idx]
        end = off + size
        others = [q for q in self.phdrs if q is not p and q.filesz]
        if self.kind == "self":
            file_limit = min([e[1] for e in self.entries if e[1] >= end] + [len(self.data)])
        else:
            file_limit = min([q.offset for q in others if q.offset >= end] + [len(self.data)])
        elf_room = min([q.offset for q in others if q.offset >= p.offset + p.filesz] + [1 << 62]) - (p.offset + p.filesz)
        va_room = min([q.vaddr for q in self.loads() if q is not p and q.vaddr >= p.vaddr + p.memsz] + [1 << 62]) - (p.vaddr + p.memsz)
        room = min(file_limit - end, elf_room, va_room)
        tail = self.data[end:end + max(room, 0)]
        nz = next((i for i, b in enumerate(tail) if b), len(tail))
        return max(min(room, nz), 0)

    def grow(self, idx: int, code: bytes) -> int:
        """Append code to the end of LOAD segment idx (code cave). Returns the cave rva."""
        if len(code) > self.slack(idx):
            raise ValueError(f"segment {idx}: needs {len(code):#x} bytes, only {self.slack(idx):#x} free")
        p = self.phdrs[idx]
        off, size = self._seg[idx]
        cave = p.vaddr + p.filesz
        self.data[off + size:off + size + len(code)] = code
        self.writes.append((off + size, len(code)))
        if self.kind == "self":
            for k, e in enumerate(self.entries):
                if e[0] & PROPS_HAS_BLOCKS and (e[0] >> 20) & 0xFFF == idx:
                    e[2] += len(code)
                    e[3] = max(e[3], e[2])
                    struct.pack_into(ENTRY_FMT, self.data, 0x20 + k * 0x20, *e)
                    self.writes.append((0x20 + k * 0x20, 0x20))
        p.filesz += len(code)
        p.memsz = max(p.memsz, p.filesz)
        self.write_phdr(p)
        self._seg[idx] = (off, size + len(code))
        return cave

    # ---- conversion ---------------------------------------------------
    def to_elf(self) -> bytes:
        """Plain ELF image (segments at their p_offset)."""
        if self.kind == "elf":
            return bytes(self.data)
        hdr_end = self.phoff + len(self.phdrs) * 56
        size = max([hdr_end] + [p.offset + p.filesz for p in self.phdrs if p.index in self._seg])
        out = bytearray(size)
        out[:hdr_end] = self.data[self.elf_off:self.elf_off + hdr_end]
        for idx, (off, n) in self._seg.items():
            p = self.phdrs[idx]
            out[p.offset:p.offset + n] = self.data[off:off + n]
        return bytes(out)

    def save(self, path: Path | str) -> None:
        Path(path).write_bytes(self.data)
