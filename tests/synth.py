"""Build tiny synthetic PS5-style ELFs / fake-signed SELFs for tests (no Sony data)."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ps5bp.core.nid import B64

PHDR = "<IIQQQQQQ"


def b64id(n: int) -> str:
    s = ""
    while True:
        s = B64[n % 64] + s
        n //= 64
        if not n:
            return s


@dataclass
class Spec:
    ps5_sdk: int = 0x07000038
    ps4_sdk: int = 0x10590001
    kind: str = "process"                       # process | module
    module: str = "eboot"
    needed: list[str] = field(default_factory=lambda: ["libkernel.prx", "libc.prx"])
    import_libs: list[str] = field(default_factory=lambda: ["libkernel", "libc"])
    imports: list[tuple[str, int]] = field(default_factory=lambda: [("rTXw65xmLIA", 0), ("uMei1W9uyNo", 1)])
    export_libs: list[str] = field(default_factory=list)
    exports: list[tuple[str, int]] = field(default_factory=list)     # (nid, export-lib index)
    stubbed: list[tuple[str, int]] = field(default_factory=list)     # (nid, import-lib index): bound to a local stub
    text: bytes = b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3" + b"\xcc" * 8
    strings: bytes = b""


TEXT_VA, DATA_VA = 0x0, 0x4000
TEXT_OFF, DATA_OFF = 0x1000, 0x5000


def build_elf(s: Spec) -> tuple[bytes, dict]:
    """Returns (elf bytes, layout info: got rvas, procparam rva, text size...)."""
    strtab = bytearray(b"\0")

    def add(x: str) -> int:
        o = len(strtab)
        strtab.extend(x.encode() + b"\0")
        return o

    needed = [add(n) for n in s.needed]
    imp_libs = [add(n) for n in s.import_libs]
    exp_libs = [add(n) for n in s.export_libs]
    mod = add(s.module)
    # ids as in real files: import lib i -> lib id i, module id i+1; export lib j -> id len(imports)+j, module 0
    syms = [(0, 0, 0, 0)]                                    # name, info, shndx, value
    for nid_, lib in s.imports:
        syms.append((add(f"{nid_}#{b64id(lib)}#{b64id(lib + 1)}"), 0x12, 0, 0))
    nimp = len(s.import_libs)
    for i, (nid_, lib) in enumerate(s.exports):
        syms.append((add(f"{nid_}#{b64id(nimp + lib)}#{b64id(0)}"), 0x12, 1, 0x10 + i))
    for nid_, lib in s.stubbed:
        syms.append((add(f"{nid_}#{b64id(lib)}#{b64id(lib + 1)}"), 0x12, 1, 0x80))
    # data segment layout
    data = bytearray()

    def place(blob: bytes, align: int = 16) -> int:
        while len(data) % align:
            data.append(0)
        o = len(data)
        data.extend(blob)
        return DATA_VA + o

    magic = 0x4942524F if s.kind == "process" else 0x3C13F4BF
    param = struct.pack("<QIIII", 0x40, magic, 1, s.ps4_sdk, s.ps5_sdk).ljust(0x40, b"\0")
    param_rva = place(param)
    str_rva = place(bytes(strtab) + s.strings)
    sym_rva = place(b"".join(struct.pack("<IBBHQQ", n, info, 0, sh, v, 0) for n, info, sh, v in syms))
    nsym = len(syms)
    hash_rva = place(struct.pack("<II", 1, nsym) + struct.pack("<I", 0) + b"\0" * 4 * nsym)
    got_rvas = []
    got_rva0 = place(b"\0" * 8 * max(1, len(s.imports)))
    rela = b""
    for i in range(len(s.imports)):
        g = got_rva0 + 8 * i
        got_rvas.append(g)
        rela += struct.pack("<QQq", g, ((1 + i) << 32) | 7, 0)
    jmprel_rva = place(rela or b"\0" * 24)
    tags = [(1, o) for o in needed]
    tags += [(5, str_rva), (0xA, len(strtab)), (6, sym_rva), (0xB, 24), (4, hash_rva),
             (0x17, jmprel_rva), (2, len(rela)), (0x14, 7)]
    tags += [(0x61000043, mod | (0x101 << 32))]
    tags += [(0x61000049, o | (1 << 32) | (i << 48)) for i, o in enumerate(imp_libs)]
    tags += [(0x61000045, o | (0x101 << 32) | ((i + 1) << 48)) for i, o in enumerate(imp_libs)]
    tags += [(0x61000047, o | (1 << 32) | ((nimp + i) << 48)) for i, o in enumerate(exp_libs)]
    tags += [(0, 0)]
    dyn = b"".join(struct.pack("<qQ", t, v) for t, v in tags)
    dyn_rva = place(dyn)
    text = s.text.ljust(0x100, b"\xcc")
    phdrs = [
        (1, 5, TEXT_OFF, TEXT_VA, TEXT_VA, len(text), len(text), 0x4000),
        (1, 6, DATA_OFF, DATA_VA, DATA_VA, len(data), len(data), 0x4000),
        (2, 6, DATA_OFF + dyn_rva - DATA_VA, dyn_rva, dyn_rva, len(dyn), len(dyn), 8),
        (0x61000001 if s.kind == "process" else 0x61000002, 4,
         DATA_OFF + param_rva - DATA_VA, param_rva, param_rva, 0x40, 0x40, 8),
    ]
    eh = bytearray(0x40)
    eh[:4] = b"\x7fELF"
    eh[4:8] = bytes([2, 1, 1, 9])
    struct.pack_into("<HHIQQQIHHHHHH", eh, 0x10, 0xFE10 if s.kind == "process" else 0xFE18, 0x3E, 1,
                     0, 0x40, 0, 0, 0x40, 56, len(phdrs), 0, 0, 0)
    out = bytearray(DATA_OFF + len(data))
    out[:0x40] = eh
    for i, p in enumerate(phdrs):
        struct.pack_into(PHDR, out, 0x40 + i * 56, *p)
    out[TEXT_OFF:TEXT_OFF + len(text)] = text
    out[DATA_OFF:DATA_OFF + len(data)] = data
    return bytes(out), {"got": got_rvas, "param": param_rva, "text_size": len(text), "dyn": dyn_rva}


def build_self(elf: bytes, magic: bytes = bytes.fromhex("4f153d1d"), props_extra: int = 0,
               slack: int = 0x40) -> bytes:
    """Wrap an ELF as a fake-signed SELF: one data entry per PT_LOAD, segments packed in order."""
    phoff, = struct.unpack_from("<Q", elf, 0x20)
    phnum, = struct.unpack_from("<H", elf, 0x38)
    phs = [struct.unpack_from(PHDR, elf, phoff + i * 56) for i in range(phnum)]
    loads = [i for i, p in enumerate(phs) if p[0] == 1]
    n = len(loads)
    hdr_len = 0x20 + n * 0x20 + phoff + phnum * 56
    entries, blobs = [], []
    pos = (hdr_len + 0xF) & ~0xF
    for i in loads:
        t, f, off, va, pa, fs, ms, al = phs[i]
        entries.append(((i << 20) | 0x800 | 0x4 | props_extra, pos, fs, fs))
        blobs.append((pos, elf[off:off + fs]))
        pos = (pos + fs + slack + 0xF) & ~0xF
    out = bytearray(pos)
    out[:4] = magic
    out[4:8] = bytes([0, 1, 1, 0x12])
    struct.pack_into("<IHHQHH", out, 0x08, 0x101, hdr_len, 0, pos, n, 0x22)
    for k, e in enumerate(entries):
        struct.pack_into("<QQQQ", out, 0x20 + k * 0x20, *e)
    eo = 0x20 + n * 0x20
    out[eo:eo + phoff + phnum * 56] = elf[:phoff + phnum * 56]
    for p, blob in blobs:
        out[p:p + len(blob)] = blob
    return bytes(out)
