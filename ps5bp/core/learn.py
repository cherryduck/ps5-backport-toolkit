"""Learn a backport's game-specific code edits as recipes (`ps5bp kit learn ORIGINAL KIT`).

Every kit binary with a counterpart in the original dump is compared segment by segment.
Changes the toolkit already makes on its own are classified and left out:
  sdk       PT_SCE_PROCPARAM / MODULE_PARAM SDK fields          (build)
  plt-stub  overwritten PLT entries                              (rule kit-stubs, via kit add)
  imports   dynamic string table (NID renames)                    (nid_retarget.txt)
  mapflex   `mov ecx,0x8000` at the retargeted libc call          (rule mapflex-flags)
Everything else is game logic. Edits inside executable segments get byte-signature
anchors (so the recipe can follow the code into another build); data edits keep their VA.
One recipe per binary, bound to the title, applied with `build --patch FILE`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from . import dynamic, sdk
from .asm import canonical_plt, plt_entries
from .binary import PT_LOAD, Binary
from .scan import iter_binaries


@dataclass
class FileReport:
    file: str
    classes: dict[str, int] = field(default_factory=dict)     # class -> bytes changed
    edits: list[dict] = field(default_factory=list)           # learned ops (with notes)
    problem: str = ""
    header_only: list[str] = field(default_factory=list)


def _regions(a: bytes, b: bytes, gap: int = 4) -> list[tuple[int, int]]:
    n = min(len(a), len(b))
    idx = np.nonzero(np.frombuffer(a[:n], np.uint8) != np.frombuffer(b[:n], np.uint8))[0]
    out: list[list[int]] = []
    for i in idx:
        i = int(i)
        if out and i - out[-1][1] <= gap:
            out[-1][1] = i + 1
        else:
            out.append([i, i + 1])
    return [(s, e) for s, e in out]


def _explained(ob: Binary, nb: Binary, base: int) -> list[tuple[int, int, str]]:
    """(start va, end va, class) ranges whose changes the toolkit reproduces itself."""
    out = []
    p = sdk.find(ob)
    if p:
        out.append((base + p.rva + sdk.OFF_PS4, base + p.rva + sdk.OFF_PS5 + 4, "sdk"))
    d, dn = dynamic.parse(ob), dynamic.parse(nb)
    if d and dn:
        new = {name: e for name, va, e in plt_entries(nb, dn, base)}
        for name, va, e in plt_entries(ob, d, base):
            ne = new.get(name)
            if ne is not None and canonical_plt(e) and not canonical_plt(ne):
                out.append((va, va + 16, "plt-stub"))
        if 5 in d.tags:
            s = d.tags[5][0]
            out.append((base + s, base + s + d.tags[0xA][0], "imports"))
    from .rules.mapflex_flags import sites
    try:
        for va in sites(ob, base):
            out.append((va, va + 5, "mapflex"))
    except Exception:                                   # noqa: BLE001 — no exec segment etc.
        pass
    return out


def learn_file(orig: Path, kit: Path, rel: str, title_id: str, scanner_cache: dict) -> tuple[FileReport, dict | None]:
    rep = FileReport(rel)
    ob, nb = Binary.load(orig), Binary.load(kit)
    base = 0x400000 if rel == "eboot.bin" else 0
    lo, ln = [p for p in ob.phdrs if p.type == PT_LOAD], [p for p in nb.phdrs if p.type == PT_LOAD]
    if [(p.vaddr, p.filesz) for p in lo] != [(p.vaddr, p.filesz) for p in ln]:
        rep.problem = "segment layout differs (code caves / grown segments) — not learned"
        return rep, None
    ea, eb = ob.to_elf()[:0x40], nb.to_elf()[:0x40]
    if ea != eb:
        rep.header_only = [f"ELF header +{s:#x}: {ea[s:e].hex()} -> {eb[s:e].hex()}" for s, e in _regions(ea, eb, 0)]
    expl = _explained(ob, nb, base)
    ops: list[dict] = []
    anchors: list[dict] = []
    for po, pn in zip(lo, ln):
        sa, sb = ob.segment_bytes(po), nb.segment_bytes(pn)
        for s, e in _regions(sa, sb):
            va0, va1 = base + po.vaddr + s, base + po.vaddr + e
            cls = next((c for a, z, c in expl if a <= va0 and va1 <= z), None)
            if cls:
                rep.classes[cls] = rep.classes.get(cls, 0) + (e - s)
                continue
            rep.classes["game"] = rep.classes.get("game", 0) + (e - s)
            op = {"va": f"{va0:#x}", "old": sa[s:e].hex(), "new": sb[s:e].hex()}
            if po.is_exec:
                op, anc = _anchored(ob, base, va0, op, len(anchors), scanner_cache)
                if anc:
                    anchors.append(anc)
            op["note"] = _describe(ob, nb, base, va0, va1, po.is_exec, scanner_cache)
            ops.append(op)
    rep.edits = ops
    if not ops:
        return rep, None
    recipe = {"name": f"{title_id or 'game'}-{Path(rel).name}-learned", "rule": "user-patch",
              "title_id": title_id, "file": rel,
              "note": f"Learned with `ps5bp kit learn` from {kit.parent.name if rel == 'eboot.bin' else kit}: "
                      f"{len(ops)} game-logic edit(s) not covered by SDK/stub/retarget handling.",
              "anchors": anchors, "ops": ops}
    return rep, recipe


def _anchored(b: Binary, base: int, va: int, op: dict, n: int, cache: dict) -> tuple[dict, dict | None]:
    from .memfix import MemfixError, make_anchor
    from .memsite import Scanner
    from . import x86flow as xf
    key = id(b)
    sc = cache.get(key) or cache.setdefault(key, Scanner(b, base))
    fn = xf.function_at(sc.read, va)
    ins = next((i for i in fn.insns if i.address <= va < i.end), None)
    if ins is None:
        return op, None
    try:
        a = make_anchor(sc, f"g{n}", ins.address)
    except MemfixError:
        return op, None
    op = dict(op, va=f"$g{n}+{va - ins.address:#x}" if va != ins.address else f"$g{n}")
    return op, a


def _describe(ob: Binary, nb: Binary, base: int, va0: int, va1: int, code: bool, cache: dict) -> str:
    if not code:
        return f"data {va0:#x}"
    from . import x86flow as xf
    from .memsite import Scanner
    sc = cache.get(id(ob)) or cache.setdefault(id(ob), Scanner(ob, base))
    fn = xf.function_at(sc.read, va0)
    ins = [i for i in fn.insns if i.end > va0 and i.address < va1]
    if not ins:
        return f"code {va0:#x}"
    a, z = ins[0].address, ins[-1].end
    new = xf.decode(nb.read(a - base, z - a), a)
    return " ; ".join(f"{i.mnemonic} {i.op_str}" for i in ins) + "  ->  " + \
        " ; ".join(f"{i.mnemonic} {i.op_str}" for i in new)


def learn(original: Path, kit: Path, title_id: str = "") -> tuple[list[FileReport], list[dict]]:
    """Compare every kit binary (outside fakelib/) with the original dump's copy."""
    from .evidence import find_kit_root
    try:
        root = find_kit_root(kit)
    except ValueError:
        root = kit
    reps, recipes = [], []
    cache: dict = {}
    for p in iter_binaries(root):
        rel = p.relative_to(root).as_posix()
        if rel.startswith("fakelib/"):
            continue
        o = original / rel
        if not o.is_file():
            reps.append(FileReport(rel, problem="not in the original dump (added by the kit)"))
            continue
        r, rec = learn_file(o, p, rel, title_id, cache)
        reps.append(r)
        if rec:
            recipes.append(rec)
    return reps, recipes
