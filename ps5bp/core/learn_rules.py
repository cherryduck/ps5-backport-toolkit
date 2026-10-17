"""Explain a kit's edits with ps5bp's own fix rules (used by `kit learn`).

For one original binary and the kit's counterpart, work out which changed byte ranges are exactly what
a generic rule would write, so they are classified as that rule instead of "unexplained".

Rules that rewrite bytes at fixed, detectable places (set3-nonfatal, gamepresets-28, savedata-mount
incl. the Unity vector form, savedata-prepare, savedata-dirsearch, frostbite-8ch, tls-atexit) are run
on a throw-away copy of the ORIGINAL in a shadow rule context; each edit they would make is an
expected (range, new bytes). A kit range counts as that rule only when the kit's bytes equal the
rule's bytes (a different value at the same site stays unexplained, with a note saying so).

Rules that place code in int3 caves, where a kit's cave choice legitimately differs from ps5bp's, are
matched structurally against the kit's bytes:
  compat-stubs     a lazy GOT slot (PLT+6) repointed to an int3 cave whose bytes are the contract stub
  sync-umtx        import strings renamed to _umtx_op (exact), PLT entries replaced by the
                   Wait/Wake shims (shim prefix), the anchor GOT slot, and the cave code reachable from
                   them (originally int3)
  trinity-hw-gate  IsTrinityMode -> HasTrinityMode rename + return-0 seed, and the derived
                   GetOperationMode / AGC GetIsTrinityMode bodies (exact bytes)
The psml-overlay is file-level (a libScePsml fakelib that loads /app0/k9.psp + a root k9.psp) and is
handled by `learn()` itself.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import dynamic
from . import x86flow as xf
from .binary import Binary
from .libcid import reach_caves

SHADOW_RULES = ("savedata-mount", "gamepresets-28", "tls-atexit", "savedata-prepare", "savedata-dirsearch",
                "frostbite-8ch")
CLASS = {"savedata-mount": "savedata"}            # the pre-existing class names are kept


@dataclass
class Expect:
    cls: str
    lo: int                  # va
    hi: int
    new: bytes = b""
    ok: bool = True          # kit bytes equal `new` (or structurally matched)
    note: str = ""


@dataclass
class Shadow:
    entries: list[Expect] = field(default_factory=list)

    def explained(self) -> list[tuple[int, int, str]]:
        return [(e.lo, e.hi, e.cls) for e in self.entries if e.ok]

    def near_miss(self, lo: int, hi: int) -> str:
        for e in self.entries:
            if not e.ok and e.lo < hi and lo < e.hi:
                return e.note
        return ""


def _rva_of_offset(b: Binary, off: int) -> int | None:
    for idx, (o, n) in b._seg.items():
        if o <= off < o + n:
            return b.phdrs[idx].vaddr + off - o
    return None


def _shadow_ctx(orig: Path, root: Path, rel: str, target: int, enabled: set[str]):
    from .rules import RuleContext
    from .scan import GameScan, scan_binary
    bi = scan_binary(orig, root, "eboot" if rel == "eboot.bin" else "module")
    gs = GameScan(root=str(root), binaries=[bi])
    work = Binary.load(orig)
    recorded: list[tuple[str, int, str, str]] = []

    def edit(file, kind, off, old, new, note=""):
        recorded.append((kind.replace("rule:", ""), off, old, new))
    ctx = RuleContext(gs, None, target, load=lambda r: work, edit=edit,
                      options={"enabled": set(enabled), "db": None, "seeds": [], "patches": []})
    return ctx, work, recorded


def _run_shadow(orig: Path, root: Path, rel: str, base: int, target: int, names, kit: Binary) -> list[Expect]:
    from .rules import registry
    reg = registry()
    ctx, work, recorded = _shadow_ctx(orig, root, rel, target, set(names))
    found = []
    for n in names:
        try:
            found += [(reg[n], f) for f in reg[n].detect(ctx) if f.applicable]
        except Exception:                                     # noqa: BLE001 — a detector never breaks learn
            continue
    for rule, f in found:
        try:
            rule.apply(ctx, f)
        except Exception:                                     # noqa: BLE001
            continue
    out = []
    for kind, off, old, new in recorded:
        rva = _rva_of_offset(work, off)
        nb = bytes.fromhex(new) if all(c in "0123456789abcdef" for c in new) and len(new) % 2 == 0 else b""
        if rva is None or not nb:
            continue
        have = kit.read(rva, len(nb))
        out.append(Expect(CLASS.get(kind, kind), base + rva, base + rva + len(nb), nb, have == nb,
                          f"{kind} would write {new}, kit has {have.hex()}"))
    return out


def _seeds(ob: Binary, kit: Binary, base: int) -> list[Expect]:
    """GOT seeds from the contract table (and the HasTrinityMode return-0 seed)."""
    from .rules import contracts, got_seed
    d = dynamic.parse(ob)
    if not d or not d.symbols or dynamic.DT_JMPREL not in d.tags:
        return []
    have = d.imported_nids()
    out = []
    for nid_, c in contracts.load().items():
        if nid_ not in have:
            continue
        try:
            pl = got_seed.plan(ob, nid_, c.stub)
        except Exception:                                     # noqa: BLE001
            continue
        if pl.status != "PATCH":
            continue
        cur = kit.u64(pl.got)
        if cur == pl.cur:
            continue
        cave_new = kit.read(cur, len(c.stub))
        was_pad = ob.read(cur, len(c.stub)) == b"\xcc" * len(c.stub) and kit.foff(cur) is not None
        ok = was_pad and cave_new == c.stub
        note = (f"{nid_}: GOT slot repointed to {cur:#x}, but the bytes there are {cave_new.hex()} "
                f"(contract {c.stub.hex()})" if not ok else "")
        out.append(Expect("compat-stubs", base + pl.got, base + pl.got + 8, ok=ok, note=note))
        if was_pad:
            out.append(Expect("compat-stubs", base + cur, base + cur + len(c.stub), c.stub, ok, note))
    return out


def _sync(ob: Binary, kit: Binary, base: int) -> list[Expect]:
    from .rules import sync_umtx as su
    try:
        pl = su.plan_module(ob, 4)
    except Exception:                                         # noqa: BLE001
        return []
    if pl is None or pl.status != "PATCH" or pl.grow:
        return []
    try:
        edits = su.build_edits(ob, pl)
    except Exception:                                         # noqa: BLE001
        return []
    out: list[Expect] = []
    plt_va = {s.va for s in pl.convert}
    seeds: list[int] = []
    anchor = None
    for rva, old, new, note in edits:
        if rva in plt_va:                                     # PLT entry -> shim: prefix up to the jmp opcode
            ok = kit.read(rva, 10) == new[:10]
            out.append(Expect("sync-umtx", base + rva, base + rva + 16, new, ok,
                              f"sync shim: PLT {rva:#x} is {kit.read(rva, 10).hex()}, expected prefix {new[:10].hex()}"))
            if ok:
                ins = [i for i in xf.decode(kit.read(rva, 16), rva) if i.mnemonic == "jmp" and i.target is not None]
                if ins:
                    seeds.append(ins[0].target)
        elif len(old) == 8 and len(new) == 8 and note.startswith("GOT"):
            anchor = (rva, struct.unpack("<Q", old)[0])
        elif note.startswith("import string"):
            out.append(Expect("sync-umtx", base + rva, base + rva + len(new), new, kit.read(rva, len(new)) == new,
                              "sync rename"))
    if anchor is not None:
        g, lazy = anchor
        cur = kit.u64(g)
        if cur != lazy and kit.foff(cur) is not None:
            out.append(Expect("sync-umtx", base + g, base + g + 8, struct.pack("<Q", cur), True))
            seeds.append(cur)

    def was_pad(t: int) -> bool:
        return ob.read(t, 1) == b"\xcc" and ob.read(t - 1, 1) in (b"\xcc", b"\xc3") or \
            (ob.read(t, 1) == b"\xcc" and ob.read(t - 2, 2) == b"\x0f\x0b")
    avoid = [(min(s.va for s in pl.convert) - 16, max(s.va for s in pl.convert) + 16)]
    for a, e in reach_caves(kit, seeds, avoid, pad_ok=was_pad):
        out.append(Expect("sync-umtx", base + a, base + e, kit.read(a, e - a), True))
    return out


def _trinity(ob: Binary, kit: Binary, base: int) -> list[Expect]:
    from .rules import trinity_hw_gate as th
    from .rules.common import jump_slots
    try:
        pl = th.plan_module(ob, 4)
    except Exception:                                         # noqa: BLE001
        return []
    if pl is None or pl.status != "PATCH" or pl.is_slot is None:
        return []
    s = pl.is_slot
    out: list[Expect] = []
    if pl.forced_is or pl.op or pl.agc:                      # the dump already carries forced stubs: exact edits
        for rva, old, new, note in th.build_edits(ob, pl):
            out.append(Expect("trinity-hw-gate", base + rva, base + rva + len(new), new, kit.read(rva, len(new)) == new,
                              f"trinity: {note}"))
        return out
    for rva, old, new in pl.renames:
        out.append(Expect("trinity-hw-gate", base + rva, base + rva + len(new), new, kit.read(rva, len(new)) == new,
                          "trinity rename"))
    d = dynamic.parse(ob)
    assert d is not None
    slots = jump_slots(ob, d)
    # return-0 seed for the (renamed) HasTrinityMode slot
    cur = kit.u64(s.got)
    if cur != s.va + 6 and kit.foff(cur) is not None and ob.read(cur, 3) == b"\xcc" * 3:
        ok = kit.read(cur, 3) == th.SEED
        out.append(Expect("trinity-hw-gate", base + s.got, base + s.got + 8, ok=ok, note="HasTrinityMode seed"))
        out.append(Expect("trinity-hw-gate", base + cur, base + cur + 3, th.SEED, ok, "HasTrinityMode seed bytes"))
    # derived bodies of a kit that applied the gate over canonical (non-forced) PLT entries
    for sl in slots:
        if sl.nid == th.OPMODE and sl.entry != kit.read(sl.va, 16) and kit.read(sl.va, 1) == b"\xe9":
            tgt = sl.va + 5 + struct.unpack("<i", kit.read(sl.va + 1, 4))[0]
            code = th.opmode_cave(tgt, s.va)
            if ob.read(tgt, len(code)) == b"\xcc" * len(code) and kit.read(tgt, len(code)) == code:
                out.append(Expect("trinity-hw-gate", base + sl.va, base + sl.va + 5, kit.read(sl.va, 5), True))
                out.append(Expect("trinity-hw-gate", base + tgt, base + tgt + len(code), code, True))
        if sl.nid == th.AGC_IS_TRINITY and sl.entry != kit.read(sl.va, 16):
            body = th.agc_body(sl.va, s.va)
            if kit.read(sl.va, len(body)) == body:
                out.append(Expect("trinity-hw-gate", base + sl.va, base + sl.va + len(body), body, True))
    return out


def explain(orig: Path, root: Path, rel: str, ob: Binary, kit: Binary, base: int) -> Shadow:
    sh = Shadow()
    try:
        sh.entries += _run_shadow(orig, root, rel, base, 4, SHADOW_RULES, kit)
        sh.entries += _run_shadow(orig, root, rel, base, 6, ("set3-nonfatal",), kit)
    except Exception:                                         # noqa: BLE001
        pass
    for fn in (_seeds, _sync, _trinity):
        try:
            sh.entries += fn(ob, kit, base)
        except Exception:                                     # noqa: BLE001
            pass
    return sh
