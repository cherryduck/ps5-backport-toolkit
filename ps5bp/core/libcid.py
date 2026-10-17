"""libc cross-check (Phase 10d): identify a libc build independent of ps5bp's own edits, and compare.

Community backports of the same title ship libc.prx files that are one build of Sony's libc plus a
small set of edits. `kit add` records, for the kit's `sce_module/libc.prx`:

  file sha256      the file as shipped (SELF container included)
  elf sha256       the decoded ELF image (what the loader maps; container/re-signing artefacts gone)
  identity         sha256 of the decoded ELF after the edits ps5bp's own rules would make are
                   normalised back to one canonical form (below), so libcs of the same build
                   compare equal whether the edits were made by ps5bp, a community tool or not at all

What `identity()` normalises (everything else is compared byte for byte):

  sdk          PS4/PS5 SDK fields of the PT_SCE_MODULE_PARAM -> 0
  retarget     imports renamed by data/nid_retarget.txt (same-length dynstr rename) -> the new NID
  mapflex      the flags argument of calls to the flexible-memory import: `mov ecx,0x8000`
               (b900800000), `mov ecx,0` (b900000000) and `xor ecx,ecx; nop x3` (31c9909090)
               -> b900800000
  tls-atexit   __cxa_thread_atexit's call retargeted to the local __cxa_atexit -> the PLT stub of
               the missing import (the unpatched form)
  got-seed     contract seeds (data/stub_contracts.json): GOT slot back to PLT+6 and the stub bytes in
               the cave back to int3
  sync-umtx    for every SyncOnAddress / _umtx_op jump slot: the 16-byte PLT entry, the GOT slot and the
               11-byte NID part of the import string are zeroed, and the int3 cave code reachable from
               a shimmed PLT entry or a repointed GOT slot is set back to int3. This does not require
               the edit to have been made by ps5bp (community shims are recognised the same way).

Not normalised (a libc carrying them gets its own identity): any other community edit, segment
growth by an edit rule, SELF/ex-info differences (the decoded ELF never contains them).
It is a cross-check only: nothing here ever substitutes a libc or changes a build.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import dynamic, sdk
from . import x86flow as xf
from .asm import canonical_plt, is_plt_entry, plt_stubs, stub_for
from .binary import Binary

LIBC_REL = "sce_module/libc.prx"
MAPFLEX_NIDS = ("IWIBBdTHit4", "4h6F1LLbTiw")
MF_FORMS = (bytes.fromhex("b900800000"), bytes.fromhex("b900000000"), bytes.fromhex("31c9909090"))
MF_CANON = MF_FORMS[0]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_libc(rel: str) -> bool:
    return rel.replace("\\", "/").endswith("sce_module/libc.prx")


@dataclass
class LibcRecord:
    kit: str
    relpath: str
    file_sha: str
    elf_sha: str
    size: int                      # decoded ELF size
    identity: str
    notes: list[str] = field(default_factory=list)      # what identity() normalised in this file


def mapflex_sites_any(b: Binary, base: int = 0) -> list[tuple[int, bytes]]:
    """[(va, current form)] of the flags setup (any of MF_FORMS) at each call of the flexible-memory import."""
    d = dynamic.parse(b)
    if not d:
        return []
    st = plt_stubs(b, d, base)
    tgts = {va for n in MAPFLEX_NIDS if (va := stub_for(st, n)) is not None}
    if not tgts:
        return []
    from .memsite import Scanner
    try:
        sc = Scanner(b, base)
    except IndexError:
        return []
    out: dict[int, bytes] = {}
    for t in tgts:
        for call in sc.calls_to(t):
            try:
                fn = xf.function_at(sc.read, call, 0x2000)
                k = fn.index(call)
            except KeyError:
                continue
            j = xf.last_write(fn, "rcx", k, max(-1, k - 12))
            if j is None:
                continue
            ins = fn.insns[j]
            raw = sc.read(ins.address, 5)
            if ins.bytes in MF_FORMS[:2]:
                out[ins.address] = ins.bytes
            elif ins.bytes == MF_FORMS[2][:2] and raw == MF_FORMS[2]:
                out[ins.address] = raw
    return sorted(out.items())


def reach_caves(b: Binary, seeds: list[int], avoid: list[tuple[int, int]], limit: int = 400,
                pad_ok=None, trusted: list[int] | None = None) -> list[tuple[int, int]]:
    """Code ranges (rva, rva+n) in executable segments reached from `seeds` by following direct
    jumps/calls, limited to targets that look like padding caves (preceded by int3 or a ret, not a PLT
    entry, not in `avoid`). Used to undo / attribute cave code written by edits over int3 padding.
    `pad_ok(t)` may replace the default test (e.g. 'was int3 in the original')."""
    exe = [(p.vaddr, p.vaddr + p.filesz) for p in b.loads() if p.is_exec]

    def inexec(a: int) -> bool:
        return any(lo <= a < hi for lo, hi in exe)

    def default_ok(t: int) -> bool:
        if not inexec(t) or not inexec(t - 1) or any(lo <= t < hi for lo, hi in avoid):
            return False
        if canonical_plt(b.read(t, 16)):
            return False
        return b.read(t - 1, 1) in (b"\xcc", b"\xc3") or b.read(t - 2, 2) == b"\x0f\x0b"   # int3 / ret / ud2

    ok = pad_ok or default_ok
    seen: dict[int, int] = {}
    todo = [s for s in seeds if ok(s)]
    todo += [s for s in (trusted or []) if inexec(s) and not any(lo <= s < hi for lo, hi in avoid)
             and not canonical_plt(b.read(s, 16))]            # e.g. a GOT slot repointed by an edit
    n = 0
    while todo and n < limit:
        a = todo.pop()
        if a in seen:
            continue
        n += 1
        pos, end = a, a
        for _ in range(96):
            ins = xf.decode(b.read(pos, 15), pos)
            if not ins:
                break
            i = ins[0]
            end = i.end
            if i.target is not None and i.target not in seen and (ok(i.target) or (
                    inexec(i.target) and not any(lo <= i.target < hi for lo, hi in avoid)
                    and (i.target == i.end or any(i.target == z for z in seen.values())))):   # pieces written back to back
                todo.append(i.target)
            pos = i.end
            if i.mnemonic in ("ret", "jmp", "ud2", "int3", "hlt"):
                break
        seen[a] = end
    merged: list[list[int]] = []
    for a, e in sorted(seen.items()):
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([a, e])
    return [(a, e) for a, e in merged]


def _put(b: Binary, rva: int, data: bytes) -> bool:
    o = b.foff(rva)
    if o is None or b.foff(rva + len(data) - 1) != o + len(data) - 1:
        return False
    if bytes(b.data[o:o + len(data)]) == data:
        return False
    b.data[o:o + len(data)] = data
    return True


def normalise(b: Binary) -> list[str]:
    """Apply the normalisations in place on `b`; returns a note per kind that changed something."""
    from .pipeline import load_retargets, retarget_imports
    from .rules import contracts, got_seed, tls_atexit
    from .rules import sync_umtx as su
    from .rules.common import jump_slots
    notes: list[str] = []
    p = sdk.find(b)
    if p is not None and (p.ps4 or p.ps5):
        _put(b, p.rva + sdk.OFF_PS4, b"\0" * 8)
        notes.append(f"sdk fields {sdk.fw_str(p.ps5)} zeroed")
    n = len(retarget_imports(b, 99, load_retargets()))
    if n:
        notes.append(f"{n} retargeted import string(s)")
    n = 0
    for va, cur in mapflex_sites_any(b, 0):
        if cur != MF_CANON:
            n += _put(b, va, MF_CANON)
    if n:
        notes.append(f"{n} flexible-memory flags site(s) -> mov ecx,0x8000")
    try:
        s = tls_atexit.site(b, 0)
    except Exception:                                           # noqa: BLE001
        s = None
    if s and s["status"] == tls_atexit.DONE:
        d = dynamic.parse(b)
        stub = stub_for(plt_stubs(b, d, 0), tls_atexit.IMPL) if d else None
        if stub is not None and _put(b, s["va"], struct.pack("<i", stub - (s["va"] + 4))):
            notes.append("__cxa_thread_atexit call -> import PLT stub")
    d = dynamic.parse(b)
    n = 0
    if d and d.symbols and dynamic.DT_JMPREL in d.tags:
        for nid_, c in contracts.load().items():
            try:
                pl = got_seed.plan(b, nid_, c.stub)
            except Exception:                                   # noqa: BLE001
                continue
            if pl.status != "DONE" or not pl.cur:
                continue
            users = [va for va, g in got_seed.ff25_entries(b) if g == pl.got]
            if len(users) == 1 and is_plt_entry(b, users[0], 0):           # an intact PLT entry: lazy value = PLT+6
                _put(b, pl.cur, b"\xcc" * len(c.stub))
                _put(b, pl.got, struct.pack("<Q", users[0] + 6))
                n += 1
    if n:
        notes.append(f"{n} GOT seed(s) reverted")
    if d and d.symbols and dynamic.DT_JMPREL in d.tags and 5 in d.tags:
        try:
            slots = jump_slots(b, d)
        except Exception:                                       # noqa: BLE001
            slots = []
        want = set(su.FIRST_FW) | {su.UMTX}
        mine = [s for s in slots if s.nid in want]
        if mine:
            strtab, symtab = d.tags[5][0], d.tags[6][0]
            seeds, got_seeds, avoid = [], [], [(min(s.va for s in slots) - 16, max(s.va for s in slots) + 16)]    # PLT0 + entries
            changed = False
            for s in mine:
                if not canonical_plt(s.entry):
                    ins = xf.decode(s.entry, s.va)
                    j = next((i for i in ins if i.mnemonic == "jmp" and i.target is not None), None)
                    if j is not None:
                        seeds.append(j.target)
                cur = b.u64(s.got)
                if cur and cur != s.va + 6:
                    got_seeds.append(cur)
            for a, e in reach_caves(b, seeds, avoid, trusted=got_seeds):
                changed |= _put(b, a, b"\xcc" * (e - a))
            for s in mine:
                changed |= _put(b, s.va, b"\0" * 16)
                changed |= _put(b, s.got, b"\0" * 8)
                off = b.u32(symtab + 24 * s.sym)
                changed |= _put(b, strtab + off, b"\0" * 11)
            if changed:
                notes.append(f"{len(mine)} SyncOnAddress/_umtx_op slot(s) masked")
    return notes


def identity(data: bytes) -> tuple[str, list[str]]:
    """(identity hash, notes) of a libc image (SELF or ELF bytes)."""
    b = Binary(data)
    notes = normalise(b)
    return sha(b.to_elf()), notes


def record_for(kit: str, path: Path, relpath: str = LIBC_REL) -> LibcRecord:
    data = Path(path).read_bytes()
    elf = Binary(data).to_elf()
    ident, notes = identity(data)
    return LibcRecord(kit, relpath, sha(data), sha(elf), len(elf), ident, notes)


# ---------------------------------------------------------------- build cross-check
def _offset_to_rva(b: Binary, off: int) -> int | None:
    for idx, (o, n) in b._seg.items():
        if o <= off < o + n:
            return b.phdrs[idx].vaddr + off - o
    return None


def _elf_off_to_rva(b: Binary, off: int) -> int | None:
    for p in b.loads():
        if p.offset <= off < p.offset + p.filesz:
            return p.vaddr + off - p.offset
    return None


def label_ranges(out_bin: Binary, ranges: list[tuple[int, int]], edits: list) -> list[dict]:
    """Label ELF-offset ranges by the ps5bp edits (sdk / retarget / rule:*) that touch them."""
    spans = []                                         # (rva lo, rva hi, kind)
    for e in edits:
        if e.offset < 0:
            continue
        n = len(e.new) if e.kind == "retarget" else len(e.new) // 2       # retarget edits carry the NID text
        rva = _offset_to_rva(out_bin, e.offset)
        if rva is not None and n:
            spans.append((rva, rva + n, e.kind.replace("rule:", "")))
    out = []
    for s, e in ranges:
        lo, hi = _elf_off_to_rva(out_bin, s), _elf_off_to_rva(out_bin, e - 1)
        top = hi if hi is not None else lo
        kinds = sorted({k for a, z, k in spans if lo is not None and a <= top and lo < z})
        out.append({"elf_offset": s, "len": e - s, "rva": lo, "explained_by": kinds})
    return out


def crosscheck(db, rel: str, out_bin: Binary, edits: list, first: int = 8) -> dict | None:
    """Compare the build's output libc with every kit libc of the same identity. Report only."""
    if db is None:
        return None
    from .learn import _regions
    recs = db.libc_records()
    elf = out_bin.to_elf()
    ident, notes = identity(bytes(out_bin.data))
    res = {"file": rel, "elf_sha256": sha(elf), "file_sha256": sha(bytes(out_bin.data)), "size": len(elf),
           "identity": ident, "normalised": notes, "kits_with_libc": len(recs), "same_identity": 0,
           "identical": 0, "kits": []}
    mine = [e for e in edits if e.file == rel]
    for r in recs:
        if r.identity != ident:
            continue
        res["same_identity"] += 1
        row = {"kit": r.kit, "elf_sha256": r.elf_sha, "match": r.elf_sha == res["elf_sha256"]}
        if row["match"]:
            res["identical"] += 1
        else:
            path = db.libc_path(r.kit)
            try:
                kb = Binary(path.read_bytes()).to_elf() if path else None
            except Exception:                              # noqa: BLE001
                kb = None
            if kb is None:
                row["why"] = "kit libc not stored (run `ps5bp kit add --replace` for it)"
            elif len(kb) != len(elf):
                row["why"] = f"decoded size differs ({len(kb)} vs {len(elf)})"
            else:
                rs = _regions(elf, kb)
                row["n_ranges"] = len(rs)
                row["bytes"] = sum(e - s for s, e in rs)
                row["ranges"] = label_ranges(out_bin, rs[:first], mine)
        res["kits"].append(row)
    return res


def format_text(cc: dict) -> list[str]:
    L = ["", "libc cross-check (report only: ps5bp never substitutes a libc):"]
    L.append(f"   {cc['file']}: decoded sha256 {cc['elf_sha256'][:16]}…, identity {cc['identity'][:16]}…"
             + (f" (normalised: {'; '.join(cc['normalised'])})" if cc["normalised"] else ""))
    if not cc["kits_with_libc"]:
        L.append("   no kit has a recorded libc (`ps5bp kit add` again, or `ps5bp kit reindex`)")
        return L
    L.append(f"   {cc['same_identity']} of {cc['kits_with_libc']} kit libc(s) are the same build; "
             f"yours is byte-identical (decoded) to {cc['identical']}")
    for k in cc["kits"]:
        if k["match"]:
            L.append(f"   {k['kit']}: identical")
            continue
        if "why" in k:
            L.append(f"   {k['kit']}: differs — {k['why']}")
            continue
        L.append(f"   {k['kit']}: differs in {k['n_ranges']} range(s), {k['bytes']} byte(s)"
                 + (f" (first {len(k['ranges'])})" if len(k["ranges"]) < k["n_ranges"] else ""))
        for r in k["ranges"]:
            lab = ", ".join(r["explained_by"]) or "not explained by a ps5bp edit (kit-only / other)"
            at = f"rva {r['rva']:#x}" if r["rva"] is not None else f"elf +{r['elf_offset']:#x}"
            L.append(f"      {at} +{r['len']:#x}: {lab}")
    return L
