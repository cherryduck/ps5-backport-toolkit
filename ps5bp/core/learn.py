"""Learn a backport's game-specific code edits as recipes (`ps5bp kit learn ORIGINAL KIT`).

Every kit binary with a counterpart in the original dump is compared segment by segment.
Changes the toolkit already makes on its own are classified and left out:
  sdk       PT_SCE_PROCPARAM / MODULE_PARAM SDK fields          (build)
  plt-stub  overwritten PLT entries                              (rule kit-stubs, via kit add)
  imports   dynamic string table (NID renames)                    (nid_retarget.txt)
  mapflex   `mov ecx,0x8000` at the retargeted libc call          (rule mapflex-flags)
  savedata  sceSaveDataMount3 param +0x18 -1 -> 0                 (rule savedata-mount)
  wwise     AkChannelConfig 7.1.4 -> 7.1                          (rule wwise-71)
and, from the phase-10c rules (see learn_rules.py; classified only when the kit's bytes equal what
the rule writes, or for cave code, structurally):
  compat-stubs     GOT seeds: lazy slot -> int3 cave holding the contract stub
  set3-nonfatal    `test eax,eax; je` -> `jmp` after sceAudioOut2Set3DLatency
  gamepresets-28   GetGamePresets request size 0x30 -> 0x28 (direct and init-helper form)
  savedata         savedata-mount incl. local wrappers and the Unity SaveData vector copy
  savedata-prepare / savedata-dirsearch   prepare mode -> 0; Search2 rename / GOT forward
  frostbite-8ch    EA AudioOut2 12 -> 8 channel set-up
  tls-atexit       libc __cxa_thread_atexit -> local __cxa_atexit
  sync-umtx        SyncOnAddress -> _umtx_op renames, PLT shims, anchor GOT and caves
  trinity-hw-gate  IsTrinityMode -> HasTrinityMode, return-0 seed, derived OperationMode / AGC bodies
  psml-overlay     (file level) a fakelib libScePsml naming /app0/k9.psp plus the kit's root k9.psp
Everything else is unexplained: reported as a candidate for a new generic rule (with what
the bytes feed: an import's argument, a constant, data). A per-game recipe is written only
when asked for (`--recipe`): it helps that one game, a generic rule helps every game. Edits inside executable segments get byte-signature
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
    notes: list[str] = field(default_factory=list)


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
    from .rules.savedata_mount import sites as sd_sites
    from .rules.wwise71 import sites as ww_sites
    try:
        for s in sd_sites(ob, base):
            if s["state"] == "unfixed":
                out.append((s["store"], s["store"] + s["len"], "savedata"))
        for ins, imm, n in ww_sites(ob, base):
            out.append((imm, imm + 4 * n, "wwise"))
    except Exception:                                   # noqa: BLE001
        pass
    return out


def _class_at(expl: list[tuple[int, int, str]], va0: int, va1: int) -> str | None:
    return next((c for a, z, c in expl if a <= va0 and va1 <= z), None)


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
    from .learn_rules import explain
    try:
        root = orig.parents[len(Path(rel).parts) - 1]
        shadow = explain(orig, root, rel, ob, nb, base)
    except Exception:                                   # noqa: BLE001 — rule matching never breaks learn
        from .learn_rules import Shadow
        shadow = Shadow()
    expl = shadow.explained() + _explained(ob, nb, base)      # rule-exact ranges first, generic classes after
    ops: list[dict] = []
    anchors: list[dict] = []
    for po, pn in zip(lo, ln):
        sa, sb = ob.segment_bytes(po), nb.segment_bytes(pn)
        for s, e in _regions(sa, sb):
            va0, va1 = base + po.vaddr + s, base + po.vaddr + e
            cls = _class_at(expl, va0, va1)
            if cls:
                rep.classes[cls] = rep.classes.get(cls, 0) + (e - s)
                continue
            # a region can straddle two explained ranges (or an explained one and a real game edit):
            # classify byte by byte, keep the rest as the unexplained region(s)
            rest = []
            for i in range(s, e):
                if sa[i] == sb[i]:
                    continue
                c = _class_at(expl, base + po.vaddr + i, base + po.vaddr + i + 1)
                if c:
                    rep.classes[c] = rep.classes.get(c, 0) + 1
                else:
                    rest.append(i)
            groups: list[list[int]] = []
            for i in rest:
                if groups and i - groups[-1][1] <= 4:
                    groups[-1][1] = i + 1
                else:
                    groups.append([i, i + 1])
            for gs_, ge in groups:
                va0, va1 = base + po.vaddr + gs_, base + po.vaddr + ge
                rep.classes["game"] = rep.classes.get("game", 0) + (ge - gs_)
                op = {"va": f"{va0:#x}", "old": sa[gs_:ge].hex(), "new": sb[gs_:ge].hex()}
                if po.is_exec:
                    op, anc = _anchored(ob, base, va0, op, len(anchors), scanner_cache)
                    if anc:
                        anchors.append(anc)
                op["note"] = _describe(ob, nb, base, va0, va1, po.is_exec, scanner_cache)
                miss = shadow.near_miss(va0, va1)
                if miss:
                    op["note"] += f"   [{miss}]"
                ops.append(op)
    try:
        from .rules.savedata_mount import sites as sd_sites
        for s_ in sd_sites(ob, base):                 # read-only mounts: ps5bp leaves them (Phase 10h)
            if s_["state"] == "unfixed" and s_.get("mode") == 1:
                a, z = s_["store"], s_["store"] + s_["len"]
                if ob.read(a - base, z - a) != nb.read(a - base, z - a):
                    rep.notes.append(f"{s_['store']:#x}: savedata-mount at a read-only mount (mode 1) — the kit "
                                     "changed it, ps5bp leaves it (read-only site, ps5bp leaves it)")
    except Exception:                                   # noqa: BLE001
        pass
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
    reps += _psml_overlay(original, root)
    return reps, recipes


def _psml_overlay(original: Path, root: Path) -> list[FileReport]:
    """File-level psml-overlay: the kit's libScePsml fakelib names /app0/k9.psp and the kit root has the k9.psp."""
    from .rules.psml_overlay import MARK
    k9 = root / "k9.psp"
    if not k9.is_file():
        return []
    out = []
    for p in sorted((root / "fakelib").glob("libScePsml*")) if (root / "fakelib").is_dir() else []:
        try:
            if MARK in p.read_bytes():
                rel = p.relative_to(root).as_posix()
                out.append(FileReport(rel, classes={"psml-overlay": p.stat().st_size}))
        except OSError:
            continue
    if out and not ((original / "k9.psp").is_file() and (original / "k9.psp").read_bytes() == k9.read_bytes()):
        out.append(FileReport("k9.psp", classes={"psml-overlay": k9.stat().st_size}))
    return out


def learn_report(original: Path, kit: Path, recipe: bool = False, out: Path = Path(".")) -> list[str]:
    """The text `ps5bp kit learn` prints (shared with the GUI); with `recipe`, also writes the
    unexplained edits as per-game recipe JSON files into `out`."""
    import json as _json
    tid = ""
    pj = original / "sce_sys/param.json"
    if pj.is_file():
        from .paramjson import ParamJson
        try:
            tid = ParamJson.load(pj).title_id
        except ValueError:
            pass
    L: list[str] = []
    reps, recipes = learn(original, kit, tid)
    totals: dict[str, int] = {}
    for r in reps:
        for k, v in r.classes.items():
            totals[k] = totals.get(k, 0) + v
        if r.problem:
            L.append(f"{r.file}: {r.problem}")
        for n in r.notes:
            L.append(f"{r.file}: {n}")
        for e in r.edits:
            L.append(f"{r.file}: {e['va']}  {e['old']} -> {e['new']}   {e['note']}")
    L.append("\nchanged bytes by kind: " + ", ".join(f"{k} {v}" for k, v in sorted(totals.items())))
    L.append("  sdk / imports: done by every build;  plt-stub: --rule kit-stubs (after `kit add`);  "
             "mapflex: --rule mapflex-flags;  savedata: --rule savedata-mount;  wwise: --rule wwise-71")
    named = sorted(k for k in totals if k not in ("sdk", "plt-stub", "imports", "mapflex", "savedata", "wwise",
                                                  "game"))
    if named:
        L.append("  also explained by their rules (--rule NAME): " + ", ".join(f"{k} ({totals[k]} B)" for k in named))
    if totals.get("game"):
        L.append("  game: edits no generic rule explains (listed above) — each is a candidate for a new "
                 "rule; --recipe writes them as a recipe for this game only")
    hdr = sorted({h for r in reps for h in r.header_only})
    if hdr:
        L.append(f"  not reproduced: ELF header edits ({', '.join(hdr)[:120]}) — re-signing artefacts")
    if not recipe:
        if not recipes:
            L.append("nothing left unexplained: every change is reproduced by generic handling")
        return L
    out.mkdir(parents=True, exist_ok=True)
    for rec in recipes:
        f = out / f"{rec['name']}.json"
        f.write_text(_json.dumps(rec, indent=1), encoding="utf-8")
        L.append(f"wrote {f}  ({len(rec['ops'])} edit(s)) — apply with: ps5bp build ... --patch {f}")
    if not recipes:
        L.append("no game-specific edits to learn")
    return L
