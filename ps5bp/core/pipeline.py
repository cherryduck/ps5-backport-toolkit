"""`ps5bp build`: produce a backport from an original game dump.

Steps
  1. scan the game, refuse encrypted/unreadable binaries
  2. import coverage + fakelib selection (if kits are available)
  3. per binary (game + chosen fakelibs): SDK downgrade, known NID retargets
  4. sce_sys/param.json: sdkVersion / requiredSystemSoftwareVersion lowered to target
  5. write output (overlay | full | inplace), then VERIFY: every output binary re-parses,
     carries the target SDK, and differs from its input only inside recorded edits
  6. backport-report.json / .txt

Every byte change goes through `Edit` records, so verification can prove nothing
else moved.
"""
from __future__ import annotations

import datetime
import fcntl
import json
import os
import re
import shutil
import threading
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path
from typing import Callable

from . import dynamic, sdk
from .binary import Binary
from .coverage import Coverage, analyze as coverage_analyze
from .evidence import EvidenceDB
from .nid import split as nid_split
from .scan import is_loading_layer, GameScan, scan_game

MODES = ("overlay", "full", "inplace")
FICLONE = 0x40049409


class BuildError(Exception):
    pass


class BuildCancelled(BuildError):
    pass


@dataclass
class Edit:
    file: str            # output-relative path
    kind: str            # sdk | retarget | param.json | fakelib | rule:<name>
    offset: int          # file offset (-1 for whole-file actions)
    old: str             # hex (or text for param.json)
    new: str
    note: str = ""


@dataclass
class BuildOptions:
    target: int
    target_minor: int = 0        # BCD minor: 4.03 -> 0x03 (SDK 0x04030031, param 0x0403...)
    mode: str = "overlay"
    out: Path | None = None
    fakelibs: bool = True
    retarget: bool = True
    force: bool = False          # allow input that is already backported (has fakelib/)
    strict: bool = False         # fail when coverage reports absent/missing modules
    dry_run: bool = False
    rules: set[str] = field(default_factory=set)       # opt-in rules (--rule)
    no_rules: set[str] = field(default_factory=set)    # disabled rules (--no-rule)
    patches: list[Path] = field(default_factory=list)  # user recipe files (--patch)
    memfix: list[str] = field(default_factory=list)    # generated memory fixes (SITE:VARIANT[:AMOUNT])
    klog: Path | None = None                           # crash log steering memfix caller choice
    klog_text: str | None = None                       # same, as text (GUI)
    replace_dump: dict[str, str | None] = field(default_factory=dict)  # loading layer -> kit (None = best)
    stubs_from: list[str] = field(default_factory=list)                # kit-stubs: only these kits


@dataclass
class BuildReport:
    game: str
    title_id: str
    title: str
    target: int
    mode: str
    out: str
    started: str
    edits: list[Edit] = field(default_factory=list)
    fakelibs: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    verified: list[str] = field(default_factory=list)
    originals: str = ""                         # overlay: where the replaced input files were saved
    coverage: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    memfix_trial: int | None = None
    target_str: str = ""
    ok: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=1, default=str)

    def to_text(self) -> str:
        L = [f"ps5bp backport report — {self.title or '?'} [{self.title_id or '?'}] -> FW "
             f"{self.target_str or str(self.target) + '.xx'}",
             f"mode {self.mode}, output {self.out}, {'OK' if self.ok else 'FAILED'}", ""]
        by: dict[str, list[Edit]] = {}
        for e in self.edits:
            by.setdefault(e.file, []).append(e)
        for f, es in by.items():
            L.append(f"{f}")
            for e in es:
                where = f"@{e.offset:#x} " if e.offset >= 0 else ""
                L.append(f"   {e.kind:10} {where}{e.old} -> {e.new}  {e.note}".rstrip())
        if self.findings:
            L += ["", "fix rules:"]
            for f in self.findings:
                state = "APPLIED" if f["applied"] else ("recommended" if f["recommended"] else
                                                       ("n/a" if not f["applicable"] else "available"))
                L.append(f"   [{state:11}] {f['rule']:12} {f['title']}" + (f" — {f['reason']}" if f["reason"] else ""))
        if self.fakelibs:
            L += ["", "fakelibs:"] + [f"   {x['file']}  from {x['kit']} (FW{x['kit_fw']})" for x in self.fakelibs]
        if self.warnings:
            L += ["", "warnings:"] + [f"   {w}" for w in self.warnings]
        if self.memfix_trial is not None:
            L += ["", f"memfix trial {self.memfix_trial}: test on the console, then "
                  f"`ps5bp memfix GAME --result {self.memfix_trial} works|crash [--klog new.txt]`"]
        if self.originals:
            L += ["", f"originals of every replaced file: {self.originals}", "   if this overlay is copied over "
                  "the game, restore with: ps5bp undo GAME " + self.out + "  (or copy that folder back)"]
        L += ["", f"verified {len(self.verified)} binaries"]
        return "\n".join(L) + "\n"


def load_retargets() -> list[tuple[str, str, int, str]]:
    """(old NID, new NID, max target FW, note) rows from data/nid_retarget.txt."""
    text = resources.files("ps5bp").joinpath("data/nid_retarget.txt").read_text()
    out = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        old, new, max_fw, *note = line.split(None, 3)
        out.append((old, new, int(max_fw), note[0] if note else ""))
    return out


# ---- binary edits --------------------------------------------------------------
def downgrade_sdk(b: Binary, target: int, minor: int = 0) -> list[tuple[int, str, str, str]]:
    ps5, ps4 = sdk.target_pair(target, minor)
    p = sdk.find(b)
    if p is None or p.ps5 <= ps5:
        return []
    import struct
    old, new = struct.pack("<II", p.ps4, p.ps5), struct.pack("<II", ps4, ps5)
    off = b.patch(p.rva + sdk.OFF_PS4, old, new)
    return [(off, old.hex(), new.hex(), f"{p.kind} param SDK {sdk.fw_str(p.ps5)} -> {sdk.fw_str(ps5)}")]


def retarget_imports(b: Binary, target: int, table) -> list[tuple[int, str, str, str]]:
    d = dynamic.parse(b)
    if not d or 5 not in d.tags:
        return []
    imported = {s.name for s in d.imports()}
    strva, strsz = d.tags[5][0], d.tags[0xA][0]
    strtab = b.read(strva, strsz)
    out = []
    for old, new, max_fw, note in table:
        if target > max_fw:
            continue
        for full in sorted(n for n in imported if nid_split(n)[0] == old):
            i = strtab.find(b"\0" + full.encode() + b"\0")
            while i >= 0:
                off = b.patch(strva + i + 1, old.encode(), new.encode())
                out.append((off, old, new, f"import {full} -> {new}  ({note})"))
                i = strtab.find(b"\0" + full.encode() + b"\0", i + 1)
    return out


# ---- param.json ------------------------------------------------------------------
_PJ_KEYS = ("sdkVersion", "requiredSystemSoftwareVersion")


def patch_param_json(text: str, target: int, minor: int = 0) -> tuple[str, list[tuple[str, str, str]]]:
    """Lower version fields to the target, editing the text in place (keeps formatting)."""
    want = int(f"{target:02d}", 16) << 56 | (minor & 0xFF) << 48   # 4.03 -> 0x0403000000000000
    changes: list[tuple[str, str, str]] = []
    pat = re.compile(r'"(' + "|".join(_PJ_KEYS) + r')"(\s*:\s*)"(0x[0-9a-fA-F]+)"')

    def sub(m: re.Match) -> str:
        key, sep, val = m.groups()
        if int(val, 16) >> 56 <= want >> 56:          # same or lower major: leave it alone
            return m.group(0)
        new = f"0x{want:016x}"
        changes.append((key, val, new))
        return f'"{key}"{sep}"{new}"'

    return pat.sub(sub, text), changes


# ---- output helpers --------------------------------------------------------------
def clone_file(src: Path, dst: Path) -> str:
    """Reflink if the filesystem supports it, else copy. Returns 'reflink' | 'copy'."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(src, "rb") as s, open(dst, "wb") as d:
            fcntl.ioctl(d.fileno(), FICLONE, s.fileno())
        shutil.copystat(src, dst)
        return "reflink"
    except OSError:
        shutil.copy2(src, dst)
        return "copy"


def changed_ranges_ok(orig: bytes, new: bytes, allowed: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Return byte ranges where orig/new differ outside the allowed (start, len) ranges."""
    import numpy as np
    n = min(len(orig), len(new))
    a = np.frombuffer(orig, np.uint8, n)
    b = np.frombuffer(new, np.uint8, n)
    mask = a != b
    for s, ln in allowed:
        mask[s:s + ln] = False
    bad = np.nonzero(mask)[0]
    out = []
    for i in bad[:64]:
        i = int(i)
        if out and i - out[-1][1] <= 16:
            out[-1] = (out[-1][0], i + 1)
        else:
            out.append((i, i + 1))
    if len(orig) != len(new):
        out.append((n, abs(len(orig) - len(new))))
    return out


# ---- pipeline ----------------------------------------------------------------------
def build(game: Path | str, opts: BuildOptions, db: EvidenceDB | None = None,
          log: Callable[[str], None] = print, cancel: "threading.Event | None" = None,
          progress: Callable[[str, int, int], None] | None = None) -> BuildReport:
    """progress(stage, done, total) is called during scan / binaries / copy / write."""
    game = Path(game).resolve()

    def check() -> None:
        if cancel is not None and cancel.is_set():
            raise BuildCancelled("cancelled")

    def prog(stage: str, i: int, n: int) -> None:
        check()
        if progress:
            progress(stage, i, n)
    if opts.target not in sdk.SUPPORTED_TARGETS:
        raise BuildError(f"unsupported target {opts.target} (supported: {sdk.SUPPORTED_TARGETS})")
    if opts.mode not in MODES:
        raise BuildError(f"mode must be one of {MODES}")
    if opts.mode == "inplace":
        out = game
    else:
        if not opts.out:
            raise BuildError("--out is required unless --mode inplace")
        out = Path(opts.out).resolve()
        if out == game or game in out.parents:
            raise BuildError("output must be outside the game folder")
        if out.exists() and any(out.iterdir()) and not opts.dry_run:
            raise BuildError(f"output folder {out} is not empty")

    log(f"scanning {game}")
    gs = scan_game(game, progress=lambda i, n, name: prog("scan", i + 1, n))
    rep = BuildReport(str(game), gs.title_id, gs.title, opts.target, opts.mode, str(out),
                      datetime.datetime.now().isoformat(timespec="seconds"))
    rep.target_str = sdk.target_str(opts.target, opts.target_minor)
    rep.warnings += gs.warnings
    bad = [b for b in gs.binaries if b.error and b.role != "fakelib"]
    if bad:
        raise BuildError("cannot process: " + "; ".join(f"{b.path}: {b.error}" for b in bad))
    if not gs.eboot:
        raise BuildError("no eboot.bin in the game folder")
    ps5_want, _ = sdk.target_pair(opts.target, opts.target_minor)
    if gs.eboot.sdk_ps5 is not None and gs.eboot.sdk_ps5 <= ps5_want and not opts.force:
        raise BuildError(f"eboot.bin is already SDK {gs.eboot.sdk_str()} (already backported?) — "
                         "use --force to rebuild it")

    # 2. coverage / fakelibs
    cov: Coverage | None = None
    if db is not None and db.kits():
        cov = coverage_analyze(gs, db, opts.target, opts.replace_dump)
        rep.coverage = {m.module: m.status for m in cov.modules}
        for m in cov.modules:
            if m.status in ("absent", "missing", "partial"):
                detail = m.absent or (m.choice.missing if m.choice else [])
                rep.warnings.append(f"{m.module}: {m.status}" + (f" ({', '.join(detail[:5])})" if detail else ""))
        rep.warnings += cov.deps
        if opts.strict and any(m.status in ("absent", "missing", "partial") for m in cov.modules):
            raise BuildError("coverage problems and --strict given:\n  " + "\n  ".join(rep.warnings))
    elif opts.fakelibs:
        rep.warnings.append("no kits in the library — fakelibs not selected (ps5bp kit add ...)")

    retargets = load_retargets() if opts.retarget else []
    working: dict[str, tuple[Binary, bytes]] = {}        # rel -> (working copy, input bytes)
    forced: set[str] = set()                                 # written even without edits (fakelibs)

    def get(rel: str, src: Path) -> Binary:
        if rel not in working:
            raw = src.read_bytes()
            working[rel] = (Binary(raw, src), raw)
        return working[rel][0]

    def process(rel: str, src: Path, kind_note: str = "") -> None:
        b = get(rel, src)
        for off, old, new, note in downgrade_sdk(b, opts.target, opts.target_minor):
            rep.edits.append(Edit(rel, "sdk", off, old, new, note))
        for off, old, new, note in retarget_imports(b, opts.target, retargets):
            rep.edits.append(Edit(rel, "retarget", off, old, new, note))
        if kind_note:
            forced.add(rel)

    # 3. game binaries
    todo = [bi for bi in gs.binaries if bi.role != "fakelib"]
    for k, bi in enumerate(todo):
        prog("binaries", k, len(todo))
        process(bi.path, game / bi.path)

    # 3a. generated memory fix -> a recipe file applied like --patch, recorded as a trial
    patches = [Path(x) for x in opts.patches]
    trial = None
    if opts.memfix:
        from . import memfix
        kt = opts.klog_text or (Path(opts.klog).read_text(errors="replace") if opts.klog else None)
        log(f"memfix: analysing allocation sites for {', '.join(opts.memfix)}")
        try:
            rec = memfix.generate(game, opts.memfix, gs.title_id, kt)
        except memfix.MemfixError as e:
            raise BuildError(f"memfix: {e}") from None
        if opts.dry_run:
            import tempfile
            tp = Path(tempfile.mkdtemp(prefix="ps5bp-memfix-")) / "memfix-recipe.json"
            tp.write_text(json.dumps(rec, indent=1))
            patches.append(tp)
        else:
            trial, tpath = memfix.new_trial(gs.title_id, rec, game, opts.target)
            patches.append(memfix.recipe_file(tpath))
            rep.memfix_trial = trial

    # 3b. fix rules
    from .rules import RuleContext, detect_all, resolve
    enabled = set(opts.rules) | ({"user-patch"} if patches else set())
    try:
        active = {r.name: r for r in resolve(enabled, set(opts.no_rules))}
    except ValueError as e:
        raise BuildError(str(e)) from None
    ctx = RuleContext(gs, cov, opts.target, load=lambda rel: get(rel, game / rel),
                      edit=lambda file, kind, off, old, new, note="": rep.edits.append(
                          Edit(file, kind, off, old, new, note)),
                      options={"patches": patches, "enabled": set(active), "stubs_from": opts.stubs_from,
                               "db": db})
    for f in detect_all(ctx):
        applied = False
        if f.rule in active:
            if f.applicable:
                try:
                    active[f.rule].apply(ctx, f)
                except Exception as e:                       # noqa: BLE001
                    raise BuildError(f"rule {f.rule} failed on {f.file}: {e}") from None
                applied = True
            else:
                rep.warnings.append(f"rule {f.rule}: {f.title} not applicable: {f.reason}")
        elif f.recommended and f.applicable:
            rep.warnings.append(f"recommended: --rule {f.rule}  ({f.title}{'; ' + f.reason if f.reason else ''})")
        rep.findings.append({"rule": f.rule, "file": f.file, "title": f.title, "applicable": f.applicable,
                             "recommended": f.recommended, "reason": f.reason, "applied": applied})

    # chosen fakelibs (copied from the kit store, then downgraded like everything else)
    if cov and opts.fakelibs:
        for m in cov.fakelibs():
            c = m.choice
            assert c and db
            kit = db.kit(c.kit)
            assert kit
            rel = f"fakelib/{Path(c.relpath).name}"
            process(rel, kit.path(c.relpath), kind_note="fakelib")
            rep.fakelibs.append({"file": rel, "module": m.module, "kit": c.kit, "kit_fw": c.kit_fw,
                                 "sha256": c.sha256})
            what = (f"replaces the dump's {m.module}" if m.current else
                    (f"{m.module} emulation layer" if is_loading_layer(m.module) else f"replaces system {m.module}"))
            rep.edits.append(Edit(rel, "fakelib", -1, "", c.kit, what))
    # fakelibs shipped by the input (dump layers / earlier backport)
    chosen_files = {f["file"] for f in rep.fakelibs}
    chosen_mods = {f["module"] for f in rep.fakelibs}
    superseded: list[str] = []                  # input fakelib files replaced under another name
    for bi in gs.binaries:
        if bi.role != "fakelib" or bi.path in chosen_files:
            continue
        if bi.module in chosen_mods:
            superseded.append(bi.path)
        elif is_loading_layer(bi.module):
            log(f"keeping the dump's {bi.module} ({bi.path}): emulation layer")
        elif opts.fakelibs and cov:
            rep.warnings.append(f"{bi.path}: the input's own fakelib kept — no kit build of {bi.module or '?'}")
    stale_index = []
    if any(f["module"].startswith("libSceAmpr") for f in rep.fakelibs) and \
            any(bi.role == "fakelib" and bi.module.startswith("libSceAmpr") for bi in gs.binaries):
        stale_index = [n for n in ("ampr_emu.index", "ampr_emu.index.tmp") if (game / n).exists()]
    remove = superseded + stale_index
    if remove and opts.mode == "overlay":
        rep.warnings.append("delete from the installed game (overlay mode cannot remove files): "
                            + ", ".join(remove) + ("  — the Ampr emulator was replaced, its index must be rebuilt"
                                                   if stale_index else ""))

    outputs = {rel: (b, raw, b.writes) for rel, (b, raw) in working.items() if b.writes or rel in forced}

    # 4. param.json
    pj_rel = "sce_sys/param.json"
    pj_new: bytes | None = None
    if (game / pj_rel).is_file():
        raw_pj = (game / pj_rel).read_bytes()             # bytes: keep CRLF / BOM exactly
        bom = raw_pj.startswith(b"\xef\xbb\xbf")
        new_text, changes = patch_param_json(raw_pj.decode("utf-8-sig"), opts.target, opts.target_minor)
        for key, old, new in changes:
            rep.edits.append(Edit(pj_rel, "param.json", -1, f"{key}={old}", new))
        if changes:
            pj_new = (b"\xef\xbb\xbf" if bom else b"") + new_text.encode("utf-8")

    if opts.dry_run:
        rep.ok = True
        log("dry run — nothing written")
        return rep

    # 5. write
    log(f"writing {opts.mode} output to {out}")
    out.mkdir(parents=True, exist_ok=True)
    if opts.mode == "overlay":
        # an overlay is meant to be copied over the game: keep what it would overwrite / what
        # must be deleted, beside it (not inside: it would end up in the game folder)
        odir = out.parent / (out.name + ".originals")
        keep = list(outputs) + ([pj_rel] if pj_new is not None else []) + remove
        saved = 0
        for rel in keep:
            if (game / rel).is_file() and not (odir / rel).exists():
                clone_file(game / rel, odir / rel)
                saved += 1
        if saved or odir.exists():
            rep.originals = str(odir)
            log(f"saved {saved} original file(s) to {odir}")
    if opts.mode == "full":
        stats = {"reflink": 0, "copy": 0}
        files = [Path(dp) / f for dp, dn, fn in os.walk(game, followlinks=True) for f in fn]
        for k, src in enumerate(files):
            prog("copy", k, len(files))
            rel = str(src.relative_to(game))
            if rel in outputs or (rel == pj_rel and pj_new is not None) or rel in remove:
                continue
            stats[clone_file(src, out / rel)] += 1
        log(f"cloned {stats['reflink']} file(s) by reflink, copied {stats['copy']}")
    for k, (rel, (b, raw, allowed)) in enumerate(outputs.items()):
        if progress:                      # not cancellable: never stop half-way through writing
            progress("write", k, len(outputs))
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if opts.mode == "inplace" and dst.exists():
            bak = dst.with_name(dst.name + ".orig")
            if not bak.exists():
                os.replace(dst, bak)
        b.save(dst)
    if opts.mode == "inplace":
        for rel in remove:
            src = game / rel
            bak = src.with_name(src.name + ".orig")
            if src.exists() and not bak.exists():
                os.replace(src, bak)
                log(f"moved aside {rel} -> {bak.name}")
    if remove and opts.mode != "overlay":
        rep.edits += [Edit(rel, "removed", -1, "", "", "superseded / stale after Ampr replacement") for rel in remove]
    if pj_new is not None:
        dst = out / pj_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if opts.mode == "inplace":
            bak = dst.with_name(dst.name + ".orig")
            if not bak.exists():
                shutil.copy2(dst, bak)
        dst.write_bytes(pj_new)

    # 6. verify
    ps5_target, _ = sdk.target_pair(opts.target, opts.target_minor)
    problems = []
    for rel, (_, raw, allowed) in outputs.items():
        data = (out / rel).read_bytes()
        try:
            nb = Binary(data, out / rel)
            p = sdk.find(nb)
            dynamic.parse(nb)
        except Exception as e:                          # noqa: BLE001 — report any parse failure
            problems.append(f"{rel}: does not re-parse: {e}")
            continue
        if p and p.ps5 > ps5_target:
            problems.append(f"{rel}: SDK still {sdk.fw_str(p.ps5)}")
        stray = changed_ranges_ok(raw, data, allowed)
        if stray:
            problems.append(f"{rel}: unexpected changes at " + ", ".join(f"{s:#x}+{n:#x}" for s, n in stray[:5]))
        rep.verified.append(rel)
    if pj_new is not None:
        try:
            json.loads((out / pj_rel).read_bytes().decode("utf-8-sig"))
        except ValueError as e:
            problems.append(f"{pj_rel}: invalid JSON after edit: {e}")
    rep.warnings += problems
    rep.ok = not problems
    if trial is not None:
        from . import memfix
        (out / "memfix-recipe.json").write_text(json.dumps(rec, indent=1))
        memfix.update_trial(gs.title_id, trial, out=str(out), ok=not problems)
    (out / "backport-report.json").write_text(rep.to_json())
    (out / "backport-report.txt").write_text(rep.to_text())
    if problems:
        raise BuildError("verification failed:\n  " + "\n  ".join(problems))
    log(f"done: {len(rep.edits)} edit(s), {len(rep.fakelibs)} fakelib(s), {len(rep.verified)} binaries verified")
    return rep


@dataclass
class Plan:
    """Read-only analysis for UIs: scan, import coverage and fix-rule findings."""
    scan: GameScan
    coverage: Coverage | None
    findings: list            # rules.Finding


def plan(game: Path | str, target: int, db: EvidenceDB | None = None, patches: list[Path] | None = None,
         progress: Callable[[str, int, int], None] | None = None,
         replace_dump: dict[str, str | None] | None = None) -> Plan:
    from .rules import RuleContext, detect_all, file_loader
    game = Path(game).resolve()
    gs = scan_game(game, progress=(lambda i, n, name: progress("scan", i + 1, n)) if progress else None)
    cov = coverage_analyze(gs, db, target, replace_dump) if db is not None and db.kits() else None
    findings = []
    if gs.eboot and not any(b.error for b in gs.binaries if b.role != "fakelib"):
        ctx = RuleContext(gs, cov, target, load=file_loader(game), edit=lambda *a, **k: None,
                          options={"patches": list(patches or []), "db": db})
        findings = detect_all(ctx)
    return Plan(gs, cov, findings)
