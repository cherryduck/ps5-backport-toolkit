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
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path
from typing import Callable

from . import dynamic, sdk
from .binary import Binary
from .coverage import Coverage, analyze as coverage_analyze
from .evidence import EvidenceDB
from .nid import split as nid_split
from .scan import GameScan, scan_game

MODES = ("overlay", "full", "inplace")
FICLONE = 0x40049409


class BuildError(Exception):
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
    coverage: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    ok: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=1, default=str)

    def to_text(self) -> str:
        L = [f"ps5bp backport report — {self.title or '?'} [{self.title_id or '?'}] -> FW {self.target}.xx",
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
def downgrade_sdk(b: Binary, target: int) -> list[tuple[int, str, str, str]]:
    ps5, ps4 = sdk.SDK_PAIRS[target]
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


def patch_param_json(text: str, target: int) -> tuple[str, list[tuple[str, str, str]]]:
    """Lower version fields to the target, editing the text in place (keeps formatting)."""
    want = int(f"{target:02d}", 16) << 56        # BCD major in the top byte: 4 -> 0x0400000000000000
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
          log: Callable[[str], None] = print) -> BuildReport:
    game = Path(game).resolve()
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
    gs = scan_game(game)
    rep = BuildReport(str(game), gs.title_id, gs.title, opts.target, opts.mode, str(out),
                      datetime.datetime.now().isoformat(timespec="seconds"))
    rep.warnings += gs.warnings
    bad = [b for b in gs.binaries if b.error and b.role != "fakelib"]
    if bad:
        raise BuildError("cannot process: " + "; ".join(f"{b.path}: {b.error}" for b in bad))
    if not gs.eboot:
        raise BuildError("no eboot.bin in the game folder")
    if gs.has_fakelib and not opts.force:
        raise BuildError("game already contains fakelib/ (already backported?) — use --force to rebuild it")

    # 2. coverage / fakelibs
    cov: Coverage | None = None
    if db is not None and db.kits():
        cov = coverage_analyze(gs, db, opts.target)
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
        for off, old, new, note in downgrade_sdk(b, opts.target):
            rep.edits.append(Edit(rel, "sdk", off, old, new, note))
        for off, old, new, note in retarget_imports(b, opts.target, retargets):
            rep.edits.append(Edit(rel, "retarget", off, old, new, note))
        if kind_note:
            forced.add(rel)

    # 3. game binaries
    for bi in gs.binaries:
        if bi.role == "fakelib":
            continue
        process(bi.path, game / bi.path)

    # 3b. fix rules
    from .rules import RuleContext, detect_all, resolve
    enabled = set(opts.rules) | ({"user-patch"} if opts.patches else set())
    try:
        active = {r.name: r for r in resolve(enabled, set(opts.no_rules))}
    except ValueError as e:
        raise BuildError(str(e)) from None
    ctx = RuleContext(gs, cov, opts.target, load=lambda rel: get(rel, game / rel),
                      edit=lambda file, kind, off, old, new, note="": rep.edits.append(
                          Edit(file, kind, off, old, new, note)),
                      options={"patches": [Path(x) for x in opts.patches]})
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
            rep.edits.append(Edit(rel, "fakelib", -1, "", c.kit, f"replaces system {m.module}"))
    # stale fakelibs in a --force rebuild
    if gs.has_fakelib and opts.mode == "inplace":
        chosen = {f["file"] for f in rep.fakelibs}
        for bi in gs.binaries:
            if bi.role == "fakelib" and bi.path not in chosen and opts.fakelibs and cov:
                rep.warnings.append(f"{bi.path}: left in place (not selected by coverage)")

    outputs = {rel: (b, raw, b.writes) for rel, (b, raw) in working.items() if b.writes or rel in forced}

    # 4. param.json
    pj_rel = "sce_sys/param.json"
    pj_new: bytes | None = None
    if (game / pj_rel).is_file():
        raw_pj = (game / pj_rel).read_bytes()             # bytes: keep CRLF / BOM exactly
        bom = raw_pj.startswith(b"\xef\xbb\xbf")
        new_text, changes = patch_param_json(raw_pj.decode("utf-8-sig"), opts.target)
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
    if opts.mode == "full":
        stats = {"reflink": 0, "copy": 0}
        for dp, dn, fn in os.walk(game, followlinks=True):
            for f in fn:
                src = Path(dp) / f
                rel = str(src.relative_to(game))
                if rel in outputs or (rel == pj_rel and pj_new is not None) or rel.startswith("fakelib/"):
                    continue
                stats[clone_file(src, out / rel)] += 1
        log(f"cloned {stats['reflink']} file(s) by reflink, copied {stats['copy']}")
    for rel, (b, raw, allowed) in outputs.items():
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if opts.mode == "inplace" and dst.exists():
            bak = dst.with_name(dst.name + ".orig")
            if not bak.exists():
                os.replace(dst, bak)
        b.save(dst)
    if pj_new is not None:
        dst = out / pj_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if opts.mode == "inplace":
            bak = dst.with_name(dst.name + ".orig")
            if not bak.exists():
                shutil.copy2(dst, bak)
        dst.write_bytes(pj_new)

    # 6. verify
    ps5_target, _ = sdk.SDK_PAIRS[opts.target]
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
    (out / "backport-report.json").write_text(rep.to_json())
    (out / "backport-report.txt").write_text(rep.to_text())
    if problems:
        raise BuildError("verification failed:\n  " + "\n  ".join(problems))
    log(f"done: {len(rep.edits)} edit(s), {len(rep.fakelibs)} fakelib(s), {len(rep.verified)} binaries verified")
    return rep
