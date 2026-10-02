"""Dynamic linking info of a PS5 executable: needed libs, modules, imports, exports.

PS5 keeps the standard dynamic tags (vaddrs, read through LOAD segments) plus
Sony tags:
    0x61000043  this module           name | ver<<32 | id<<48
    0x61000045  needed module (x N)   name | ver<<32 | id<<48
    0x61000047  exported library      name | ver<<32 | id<<48
    0x61000049  imported library      name | ver<<32 | id<<48
Symbols are named 'NID#lib#module'.  Undefined symbols (shndx 0) are imports.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .binary import PT_DYNAMIC, Binary
from . import nid as nidmod

DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_HASH, DT_STRTAB, DT_SYMTAB = 0, 1, 2, 4, 5, 6
DT_RELA, DT_RELASZ, DT_STRSZ, DT_JMPREL = 7, 8, 0xA, 0x17
DT_SCE_MODULE_INFO = 0x61000043
DT_SCE_NEEDED_MODULE = 0x61000045
DT_SCE_EXPORT_LIB = 0x61000047
DT_SCE_IMPORT_LIB = 0x61000049

R_X86_64_JUMP_SLOT = 7


@dataclass
class LibRef:
    name: str
    version: int
    id: int

    @property
    def ver_str(self) -> str:
        v = self.version
        return f"{v >> 8}.{v & 0xFF}" if v > 0xFF else str(v)


@dataclass
class Symbol:
    name: str          # full 'NID#L#M'
    value: int
    info: int
    shndx: int

    @property
    def nid(self) -> str:
        return nidmod.split(self.name)[0]

    @property
    def lib_id(self) -> int | None:
        return nidmod.split(self.name)[1]

    @property
    def defined(self) -> bool:
        return self.shndx != 0


@dataclass
class Dynamic:
    tags: dict[int, list[int]] = field(default_factory=dict)
    module: LibRef | None = None
    needed: list[str] = field(default_factory=list)                 # DT_NEEDED file names
    modules: dict[int, LibRef] = field(default_factory=dict)        # needed modules by id
    import_libs: dict[int, LibRef] = field(default_factory=dict)
    export_libs: dict[int, LibRef] = field(default_factory=dict)
    symbols: list[Symbol] = field(default_factory=list)
    plt: dict[int, str] = field(default_factory=dict)               # GOT rva -> full sym name

    # ---- derived views --------------------------------------------------
    def imports(self) -> list[Symbol]:
        return [s for s in self.symbols if not s.defined and s.lib_id is not None]

    def exports(self) -> list[Symbol]:
        return [s for s in self.symbols if s.defined and s.lib_id is not None and (s.info >> 4) in (1, 2)]

    def lib_name(self, sym: Symbol) -> str:
        table = self.export_libs if sym.defined else self.import_libs
        lib = table.get(sym.lib_id) if sym.lib_id is not None else None
        return lib.name if lib else "?"

    def imports_by_lib(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for s in self.imports():
            out.setdefault(self.lib_name(s), set()).add(s.nid)
        return out

    def imported_nids(self) -> set[str]:
        return {s.nid for s in self.imports()}


def _ref(strtab: bytes, v: int) -> LibRef:
    return LibRef(_str(strtab, v & 0xFFFFFFFF), (v >> 32) & 0xFFFF, v >> 48)


def _str(strtab: bytes, off: int) -> str:
    end = strtab.find(b"\0", off)
    return strtab[off:end if end >= 0 else None].decode("utf-8", "replace")


def parse(b: Binary) -> Dynamic | None:
    dynp = next((p for p in b.phdrs if p.type == PT_DYNAMIC), None)
    if dynp is None:
        return None
    raw = b.read(dynp.vaddr, dynp.filesz)
    if not any(raw):           # PT_DYNAMIC not inside a LOAD: fall back to its file bytes (ELF only)
        raw = bytes(b.data[dynp.offset:dynp.offset + dynp.filesz]) if b.kind == "elf" else raw
    d = Dynamic()
    for tg, v in struct.iter_unpack("<qQ", raw[: len(raw) // 16 * 16]):
        if tg == DT_NULL:
            break
        d.tags.setdefault(tg & 0xFFFFFFFFFFFFFFFF, []).append(v)
    t = d.tags
    if DT_STRTAB not in t or DT_SYMTAB not in t:
        return d
    strtab = b.read(t[DT_STRTAB][0], t.get(DT_STRSZ, [0])[0])
    d.needed = [_str(strtab, v) for v in t.get(DT_NEEDED, [])]
    if DT_SCE_MODULE_INFO in t:
        d.module = _ref(strtab, t[DT_SCE_MODULE_INFO][0])
    for tag, table in ((DT_SCE_NEEDED_MODULE, d.modules), (DT_SCE_IMPORT_LIB, d.import_libs),
                       (DT_SCE_EXPORT_LIB, d.export_libs)):
        for v in t.get(tag, []):
            r = _ref(strtab, v)
            table[r.id] = r
    # symbol count from DT_HASH (nchain); fall back to the gap up to STRTAB
    symtab = t[DT_SYMTAB][0]
    if DT_HASH in t:
        nsym = b.u32(t[DT_HASH][0] + 4)
    else:
        nsym = max(0, (t[DT_STRTAB][0] - symtab) // 24)
    raw_syms = b.read(symtab, nsym * 24)
    for st_name, info, other, shndx, value, size in struct.iter_unpack("<IBBHQQ", raw_syms):
        d.symbols.append(Symbol(_str(strtab, st_name), value, info, shndx))
    if DT_JMPREL in t and DT_PLTRELSZ in t:
        rel = b.read(t[DT_JMPREL][0], t[DT_PLTRELSZ][0])
        for r_off, r_info, _ in struct.iter_unpack("<QQq", rel[: len(rel) // 24 * 24]):
            si = r_info >> 32
            if (r_info & 0xFFFFFFFF) == R_X86_64_JUMP_SLOT and si < len(d.symbols):
                d.plt[r_off] = d.symbols[si].name
    return d
