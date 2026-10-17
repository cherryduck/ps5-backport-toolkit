"""Shared helpers for rules: import stubs, symbol localisation."""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from ..asm import is_plt_entry, plt_entries, plt_stubs, stub_for
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


@dataclass
class Slot:
    idx: int
    got: int
    sym: int
    name: str
    nid: str
    va: int
    entry: bytes


def jump_slots(b: Binary, d: dynamic.Dynamic) -> list[Slot]:
    ents = plt_entries(b, d, 0)
    t = d.tags
    rel = b.read(t[dynamic.DT_JMPREL][0], t[dynamic.DT_PLTRELSZ][0])
    out = []
    for i, ((r_off, r_info, _), (name, va, e)) in enumerate(zip(struct.iter_unpack("<QQq", rel[:len(rel) // 24 * 24]), ents)):
        out.append(Slot(i, r_off, r_info >> 32, name, name.split("#")[0], va, e))
    return out


def int3_runs(b: Binary, avoid: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """(rva, length) of usable int3 padding in executable segments (first byte of a run left alone)."""
    runs = []
    for p in b.loads():
        if not p.is_exec:
            continue
        seg = b.segment_bytes(p)
        for m in re.finditer(rb"\xcc{9,}", seg):
            lo, hi = p.vaddr + m.start() + 1, p.vaddr + m.end()
            if any(a < hi and lo < e for a, e in avoid):
                continue
            runs.append((lo, hi - lo))
    return runs


def allocate_runs(runs: list[tuple[int, int]], sizes: dict[str, int]) -> dict[str, int] | None:
    free = [[a, n] for a, n in runs]
    at: dict[str, int] = {}
    for name in sorted(sizes, key=lambda k: -sizes[k]):
        fit = [r for r in free if r[1] >= sizes[name]]
        if not fit:
            return None
        r = min(fit, key=lambda r: r[1])               # best fit
        at[name] = r[0]
        r[0] += sizes[name]
        r[1] -= sizes[name]
    return at


