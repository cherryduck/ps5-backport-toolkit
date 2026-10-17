"""GOT seed: deliver a stub through the lazy GOT slot of an import, leaving PLT / import / reloc alone.

Where kit-stubs / pro-disable overwrite the PLT entry (the import is then dead on any firmware),
a seed puts a 16-byte stub in an executable cave and rewrites the import's 8-byte GOT slot from
`PLT+6` (the lazy-binding push) to the cave. A firmware that exports the NID binds it natively and
overwrites the seed; one that doesn't runs the stub instead of failing with
PRX_NOT_RESOLVED_FUNCTION. One build therefore covers old and new firmware.

Hard preconditions (anything else is UNKNOWN and refused): exactly one import symbol for the NID,
exactly one canonical PLT entry using its slot, exactly one plain R_X86_64_JUMP_SLOT (addend 0) at
that slot and no other relocation against the symbol, GOT pre-image == PLT entry + 6, no BIND_NOW.
Caves: a run of >=15 int3 (every contract stub is <=15 bytes; the rest of the run stays int3) after a terminator (not a rel32 branch target, not inside an exported
symbol), else the end of an executable segment (Binary.slack / add_cave).
"""
from __future__ import annotations

import bisect
import re
import struct
from dataclasses import dataclass

from .. import dynamic
from ..asm import is_plt_entry
from ..binary import Binary

DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1 = 0x18, 0x1E, 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW = 0x8, 0x1
R_X86_64_JUMP_SLOT = 7


@dataclass
class SeedPlan:
    nid: str
    status: str                  # PATCH | DONE | UNKNOWN
    reason: str = ""
    got: int = 0                 # rva of the GOT slot
    plt: int = 0                 # rva of the PLT entry
    cur: int = 0                 # current GOT value


def bind_now(d: dynamic.Dynamic) -> bool:
    t = d.tags
    return (DT_BIND_NOW in t or any(v & DF_BIND_NOW for v in t.get(DT_FLAGS, []))
            or any(v & DF_1_NOW for v in t.get(DT_FLAGS_1, [])))


def _relocs(b: Binary, d: dynamic.Dynamic, tag: int, size_tag: int) -> list[tuple[int, int, int]]:
    if tag not in d.tags or size_tag not in d.tags:
        return []
    raw = b.read(d.tags[tag][0], d.tags[size_tag][0])
    return list(struct.iter_unpack("<QQq", raw[: len(raw) // 24 * 24]))


def ff25_entries(b: Binary) -> list[tuple[int, int]]:
    """(rva, got rva) of every `ff 25 disp32` in executable segments (cached per write count)."""
    key = (id(b.data), len(b.writes))
    c = b.__dict__.get("_ff25")
    if c and c[0] == key:
        return c[1]
    out = []
    for p in b.loads():
        if not p.is_exec:
            continue
        seg = b.segment_bytes(p)
        for m in re.finditer(rb"\xff\x25", seg):
            i = m.start()
            if i + 6 <= len(seg):
                out.append((p.vaddr + i, p.vaddr + i + 6 + struct.unpack_from("<i", seg, i + 2)[0]))
    b.__dict__["_ff25"] = (key, out)
    return out


def _exec_contains(b: Binary, rva: int, n: int = 1) -> bool:
    return any(p.is_exec and p.vaddr <= rva and rva + n <= p.vaddr + p.filesz for p in b.loads())


def plan(b: Binary, nid: str, stub: bytes) -> SeedPlan:
    """Classify the import of `nid` in `b` (rva addressing; GOT values are rvas)."""
    d = dynamic.parse(b)
    if not d or not d.symbols:
        return SeedPlan(nid, "UNKNOWN", "no dynamic symbol table")
    same = [(i, s) for i, s in enumerate(d.symbols) if s.nid == nid and s.lib_id is not None]
    imports = [i for i, s in same if not s.defined]
    if not same:
        return SeedPlan(nid, "UNKNOWN", "NID not imported")
    if len(imports) != 1 or len(same) != 1:
        return SeedPlan(nid, "UNKNOWN", f"{len(same)} symbol(s) for the NID ({len(imports)} undefined): "
                                        "expected exactly one import (already bound locally?)")
    si = imports[0]
    jmp = [r for r in _relocs(b, d, dynamic.DT_JMPREL, dynamic.DT_PLTRELSZ) if r[1] >> 32 == si]
    other = [r for r in _relocs(b, d, dynamic.DT_RELA, dynamic.DT_RELASZ) if r[1] >> 32 == si]
    if len(jmp) != 1 or other:
        return SeedPlan(nid, "UNKNOWN", f"{len(jmp)} jump-slot and {len(other)} other relocation(s) against "
                                        "the import (a seed only reaches a single lazy jump slot)")
    got, info, addend = jmp[0]
    if info & 0xFFFFFFFF != R_X86_64_JUMP_SLOT or addend != 0:
        return SeedPlan(nid, "UNKNOWN", f"reloc at {got:#x} is not a plain JUMP_SLOT (type {info & 0xFFFFFFFF}, "
                                        f"addend {addend})", got)
    users = [va for va, g in ff25_entries(b) if g == got]
    cur = b.u64(got)
    if len(users) != 1 or not is_plt_entry(b, users[0], 0):
        # patched PLT entry: a finished seed has an intact PLT, so look for the finished state first
        if cur and _exec_contains(b, cur, len(stub)) and b.read(cur, len(stub)) == stub:
            return SeedPlan(nid, "DONE", f"GOT slot already points at the stub ({cur:#x})", got, 0, cur)
        return SeedPlan(nid, "UNKNOWN", f"{len(users)} PLT entr(ies) use the slot or the entry is not a "
                                        "canonical `jmp [got]; push; jmp` (already patched / trapped?)", got)
    plt = users[0]
    if cur == plt + 6:
        if bind_now(d):
            return SeedPlan(nid, "UNKNOWN", "DT_BIND_NOW / DF_BIND_NOW: the loader resolves the slot at load", got, plt, cur)
        return SeedPlan(nid, "PATCH", "lazy GOT slot", got, plt, cur)
    if _exec_contains(b, cur, len(stub)) and b.read(cur, len(stub)) == stub:
        return SeedPlan(nid, "DONE", f"GOT slot already points at the stub ({cur:#x})", got, plt, cur)
    return SeedPlan(nid, "UNKNOWN", f"GOT pre-image {cur:#x} is not PLT+6 ({plt + 6:#x}): not lazy / already "
                                    "seeded with something else", got, plt, cur)


# ---- caves ---------------------------------------------------------------------------------

def _sym_ranges(b: Binary, d: dynamic.Dynamic | None) -> list[tuple[int, int]]:
    if not d or dynamic.DT_SYMTAB not in d.tags:
        return []
    raw = b.read(d.tags[dynamic.DT_SYMTAB][0], len(d.symbols) * 24)
    out = []
    for _, _, _, shndx, value, size in struct.iter_unpack("<IBBHQQ", raw):
        if shndx and size:
            out.append((value, value + size))
    return sorted(out)


def int3_slots(b: Binary) -> list[int]:
    """rvas of candidate 16-byte slots inside int3 runs (see module doc). Cached per Binary."""
    c = b.__dict__.get("_int3_slots")
    if c is not None:
        return c
    d = dynamic.parse(b)
    ranges = _sym_ranges(b, d)
    slots: list[int] = []
    for p in b.loads():
        if not p.is_exec:
            continue
        seg = b.segment_bytes(p)
        runs = []
        for m in re.finditer(rb"\xcc{15,}", seg):
            s, e = m.start(), m.end()
            if s < 5 or not _terminator(seg, s):
                continue
            runs.append((s, e))
        if not runs:
            continue
        starts_r = [r[0] for r in runs]
        hit: set[int] = set()
        for m in re.finditer(rb"[\xe8\xe9]|\x0f[\x80-\x8f]", seg):
            i = m.start()
            n = 1 if seg[i] != 0x0F else 2
            if i + n + 4 > len(seg):
                continue
            t = i + n + 4 + struct.unpack_from("<i", seg, i + n)[0]
            k = bisect.bisect_right(starts_r, t) - 1
            if k >= 0 and t < runs[k][1]:
                hit.add(k)
        for k, (s, e) in enumerate(runs):
            if k in hit:
                continue
            for a in range(s, e - 14, 16):
                lo = p.vaddr + a
                if any(rs < lo + 16 and lo < rend for rs, rend in ranges):
                    continue
                slots.append(lo)
    b.__dict__["_int3_slots"] = slots
    return slots


_MD = None


def _terminator(seg: bytes, s: int) -> bool:
    """An instruction that never falls through ends exactly at s (decoded from the bytes before s only,
    so a run that begins on a branch displacement byte - `eb cc` - is not mistaken for padding)."""
    global _MD
    if _MD is None:
        import capstone
        _MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for n in range(1, 9):
        if s - n < 0:
            break
        ins = list(_MD.disasm(seg[s - n:s], 0))
        if len(ins) == 1 and ins[0].size == n and ins[0].mnemonic in ("ret", "jmp", "ud2", "hlt", "retf"):
            return True
    return False


def free_slots(b: Binary, n: int = 15) -> list[int]:
    """Slots whose first n bytes are still int3."""
    return [s for s in int3_slots(b) if b.read(s, n) == b"\xcc" * n]


def cave_capacity(b: Binary, n: int = 15) -> int:
    """How many stubs can still be placed (int3 slots + segment slack)."""
    grow = 0
    for p in b.loads():
        if p.is_exec:
            grow = max(grow, (b.slack(p.index) - 15) // 16)
    return len(free_slots(b, n)) + max(grow, 0)


def place(b: Binary, stub: bytes) -> tuple[int, int, bytes, str]:
    """Write the stub (<=16 bytes) into a cave: an int3 run (the rest of the run stays int3), else the
    grown end of an executable segment (padded to 16 with int3). (rva, file offset, old bytes, how)."""
    assert 0 < len(stub) <= 16
    slots = free_slots(b, len(stub))
    if slots:
        rva = slots[0]
        old = b.read(rva, len(stub))
        off = b.patch(rva, old, stub)
        return rva, off, old, "int3 run"
    padded = stub + b"\xcc" * (16 - len(stub))
    for p in b.loads():
        if p.is_exec and b.slack(p.index) >= 16 + (-(p.vaddr + p.filesz)) % 16:
            rva = b.cave_rva(p.index, 16)
            b.add_cave(p.index, padded, 16)
            b.__dict__.pop("_ff25", None)
            return rva, b.foff(rva), b"", f"segment {p.index} grown to {b.phdrs[p.index].filesz:#x}"
    raise ValueError("no executable cave: no int3 run and no slack at the end of an executable segment")


def apply(b: Binary, p: SeedPlan, stub: bytes) -> list[tuple[int, str, str, str]]:
    """Place the stub and point the GOT slot at it. [(file offset, old hex, new hex, note)]."""
    if p.status != "PATCH":
        raise ValueError(f"{p.nid}: {p.status}: {p.reason}")
    rva, off, old, how = place(b, stub)
    new_got = struct.pack("<Q", rva)
    old_got = struct.pack("<Q", p.cur)
    goff = b.patch(p.got, old_got, new_got)
    return [(off, old.hex(), (stub if old else stub + b"\xcc" * (16 - len(stub))).hex(), f"{p.nid} seed stub at {rva:#x} ({how})"),
            (goff, old_got.hex(), new_got.hex(), f"{p.nid} GOT {p.got:#x}: PLT+6 -> {rva:#x} (import/PLT/reloc kept)")]
