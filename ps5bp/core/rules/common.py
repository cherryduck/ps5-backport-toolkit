"""Shared helpers for rules: import stubs, symbol localisation."""
from __future__ import annotations

import struct

from ..asm import is_plt_entry, plt_stubs, stub_for
from ..binary import Binary
from .. import dynamic


def imports_nid(b: Binary, nid: str) -> bool:
    d = dynamic.parse(b)
    return bool(d) and nid in d.imported_nids()


def find_stub(b: Binary, nid: str, base: int) -> int | None:
    d = dynamic.parse(b)
    if not d:
        return None
    return stub_for(plt_stubs(b, d, base), nid)


def stub_plt(b: Binary, nid: str, base: int, body: bytes) -> tuple[int, bytes, bytes, int] | None:
    """Overwrite the 16-byte PLT entry of an import with `body` (padded with int3).
    Returns (file offset, old, new, stub rva) or None if the stub isn't a standard PLT entry."""
    va = find_stub(b, nid, base)
    if va is None or not is_plt_entry(b, va, base):
        return None
    assert len(body) <= 16
    new = body + b"\xcc" * (16 - len(body))
    old = b.read(va - base, 16)
    off = b.patch(va - base, old, new)
    return off, old, new, va - base


def localize(b: Binary, nid: str, rva: int) -> list[tuple[int, bytes, bytes]]:
    """Turn an undefined import into a symbol defined at `rva` (what kit fakelibs do for
    NIDs missing on their target FW): st_shndx=1, st_value=rva. The loader then binds the
    import locally and never needs the firmware to provide the NID."""
    d = dynamic.parse(b)
    assert d
    symtab = d.tags[6][0]
    out = []
    for i, s in enumerate(d.symbols):
        if not s.defined and s.nid == nid:
            ent = symtab + i * 24
            old = b.read(ent + 6, 10)
            new = struct.pack("<HQ", 1, rva)
            out.append((b.patch(ent + 6, old, new), old, new))
    return out


def proven_absent(ctx, module: str, nid: str) -> bool:
    if not ctx.cov:
        return False
    m = next((m for m in ctx.cov.modules if m.module == module), None)
    return bool(m) and nid in m.absent


def calls_to_import(sc, nid_: str) -> list[int]:
    """Direct calls to an import's PLT stub or to a `jmp stub` thunk (sc: memsite.Scanner)."""
    d = dynamic.parse(sc.b)
    if not d:
        return []
    stub = stub_for(plt_stubs(sc.b, d, sc.base), nid_)
    if stub is None:
        return []
    out = list(sc.calls_to(stub))
    import numpy as np
    for t in np.unique(sc.call_tgt):
        t = int(t)
        if t != stub and sc.cva <= t < sc.cva + len(sc.code) - 5 and sc.code[t - sc.cva] == 0xE9:
            if t + 5 + int.from_bytes(sc.code[t - sc.cva + 1:t - sc.cva + 5], "little", signed=True) == stub:
                out += sc.calls_to(t)
    return sorted(out)
