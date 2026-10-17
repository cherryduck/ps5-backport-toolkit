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
import struct
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
    seeds: list[str] = field(default_factory=list)                     # compat-stubs: NIDs forced / manual (--seed)
    seed_plt_fallback: bool = False                                    # compat-stubs: PLT overwrite where a GOT seed is refused
    console_fw: str | None = None                      # '11.60': advice only (warns when SDK trails it)
    also_targets: list[tuple[int, int]] = field(default_factory=list)  # (major, minor): SDK-only siblings


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
    target_minor: int = 0
    ok: bool = False
    console_fw: str = ""
    console_warning: str = ""
    siblings: list[dict] = field(default_factory=list)   # SDK-only siblings written from this build
    sibling_of: str = ""                                 # sibling reports: the parent output folder
    sibling_edits: list[dict] = field(default_factory=list)   # sibling reports: changes vs the parent

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
        if self.console_fw:
            L += ["", f"console firmware (declared by you): {self.console_fw}"]
            if self.console_warning:
                L.append(f"   WARNING: {self.console_warning}")
        if self.sibling_of:
            L += ["", f"SIBLING of {self.sibling_of}: only SDK fields / param.json versions differ from it"]
            for e in self.sibling_edits:
                L.append(f"   {e['file']}  {e['what']}  {e['old']} -> {e['new']}")
        if self.siblings:
            L += ["", "siblings (same build, higher SDK pair only):"]
            for sb in self.siblings:
                L.append(f"   FW {sb['target_str']}: {sb['out']}  ({sb['edits']} field edit(s))")
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
def is_previous_build(out: Path) -> bool:
    """A folder ps5bp wrote (overlay/full output): safe to replace with a new build."""
    return (out / "backport-report.json").is_file()


def previous_build_title(out: Path) -> str | None:
    """Title id of the earlier ps5bp build in `out` ('' if unknown), None if there is none."""
    try:
        return json.loads((out / "backport-report.json").read_text()).get("title_id") or ""
    except (OSError, ValueError):
        return None


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


# ---- siblings: the verified build re-declared at a higher SDK pair ----------------------
_SIB_SKIP = ("backport-report.json", "backport-report.txt")


def sibling_dir(out: Path, major: int, minor: int = 0) -> Path:
    return out.parent / (f"{out.name}-fw{major}" + (f".{minor:02x}" if minor else ""))


def _pj_span_edit(raw: bytes, old_want: int, new_want: int) -> tuple[bytes, list[tuple[str, int, str, str]]]:
    """param.json: sdkVersion / requiredSystemSoftwareVersion values equal to the main build's
    declared value become the sibling's (same width: only the hex digits move). -> (bytes, [(key, offset, old, new)])"""
    bom = raw.startswith(b"\xef\xbb\xbf")
    text = raw[3:] if bom else raw
    pat = re.compile(rb'"(' + b"|".join(k.encode() for k in _PJ_KEYS) + rb')"(\s*:\s*)"(0x[0-9a-fA-F]+)"')
    out = bytearray(text)
    ch = []
    want_old = f"0x{old_want:016x}".encode().lower()
    new = f"0x{new_want:016x}".encode()
    for m in pat.finditer(text):
        if m.group(3).lower() != want_old or len(m.group(3)) != len(new):
            continue
        out[m.start(3):m.end(3)] = new
        ch.append((m.group(1).decode(), m.start(3) + (3 if bom else 0), m.group(3).decode(), new.decode()))
    return (b"\xef\xbb\xbf" if bom else b"") + bytes(out), ch


def _is_binary_file(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            return f.read(4) in (bytes.fromhex("4f153d1d"), b"\x7fELF")
    except OSError:
        return False


def make_sibling(game: Path, out: Path, rep: BuildReport, gs: GameScan, major: int, minor: int,
                 log: Callable[[str], None] = print) -> dict:
    """Write `<out>-fw<N>`: a copy of the verified main output where ONLY the SDK u32 pair of each
    binary and the param.json versions are re-declared at the sibling target.

    A field is raised only where it equals the main build's declared value (binaries / values the
    game already had at a lower SDK stay). overlay: files the sibling changes that the main overlay
    does not contain (input binaries already at the main pair) are added from the game. Every file is
    then diffed against its main-output counterpart (or the game's) and anything outside the
    recorded fields deletes the sibling and fails.

    Undo: the sibling's report is the main report with sdk / param.json edits re-stated game->sibling
    (so `ps5bp undo GAME <sibling>` works like for the main build). In overlay mode the sibling gets
    its own `<sibling>.originals` = the parent's originals plus the game's copy of every extra file.
    """
    sd = sibling_dir(out, major, minor)
    odir_sd = sd.parent / (sd.name + ".originals")
    main_ps5, _ = sdk.target_pair(rep.target, rep.target_minor)
    new_ps5, new_ps4 = sdk.target_pair(major, minor)
    old_want = int(f"{rep.target:02d}", 16) << 56 | (rep.target_minor & 0xFF) << 48
    new_want = int(f"{major:02d}", 16) << 56 | (minor & 0xFF) << 48
    if sd.exists():
        shutil.rmtree(sd)
    if odir_sd.exists():
        shutil.rmtree(odir_sd)
    log(f"sibling FW {sdk.target_str(major, minor)}: writing {sd}")

    # which relative files does the sibling consist of, and where does each come from
    src_of: dict[str, Path] = {}
    for dp, _, fns in os.walk(out):
        for f in fns:
            rel = str((Path(dp) / f).relative_to(out))
            if rel not in _SIB_SKIP:
                src_of[rel] = out / rel
    extras: list[str] = []
    # the game's own binaries at the main pair are part of the sibling too
    cand = [bi.path for bi in gs.binaries if bi.role != "fakelib"] + ["sce_sys/param.json"]
    for rel in cand:
        if rel not in src_of and (game / rel).is_file():
            if rel == "sce_sys/param.json" or _is_binary_file(game / rel):
                src_of[rel] = game / rel
                extras.append(rel)

    allowed: dict[str, list[tuple[int, int]]] = {}
    changes: list[dict] = []
    data: dict[str, bytes] = {}
    for rel, src in sorted(src_of.items()):
        raw = src.read_bytes()
        if rel == "sce_sys/param.json":
            new, ch = _pj_span_edit(raw, old_want, new_want)
            if not ch:
                if rel in extras:
                    extras.remove(rel)
                continue
            for key, off, o, n in ch:
                allowed.setdefault(rel, []).append((off, len(n)))
                changes.append({"file": rel, "what": key, "offset": off, "old": o, "new": n, "param": True})
            data[rel] = new
        elif _is_binary_file(src):
            try:
                b = Binary(raw, src)
                p = sdk.find(b)
            except Exception:                                             # noqa: BLE001
                continue
            if p is None or p.ps5 != main_ps5:
                if rel in extras:
                    extras.remove(rel)
                continue
            old, new_b = struct.pack("<II", p.ps4, p.ps5), struct.pack("<II", new_ps4, new_ps5)
            off = b.patch(p.rva + sdk.OFF_PS4, old, new_b)
            allowed[rel] = [(off, 8)]
            changes.append({"file": rel, "what": f"{p.kind} param SDK", "offset": off, "old": old.hex(),
                            "new": new_b.hex()})
            data[rel] = bytes(b.data)
    src_of = {r: q for r, q in src_of.items() if r in data or q.is_relative_to(out)}   # unchanged game files stay out
    extras = [e for e in extras if e in data]
    try:
        if not changes:
            raise BuildError(f"sibling FW {sdk.target_str(major, minor)}: no SDK field to change — nothing equals "
                             f"the main build's declared {sdk.target_str(rep.target)}")
        sd.mkdir(parents=True)
        for rel, src in src_of.items():
            clone_file(src, sd / rel)
        for rel, blob in data.items():
            tgt = sd / rel
            tgt.parent.mkdir(parents=True, exist_ok=True)
            if tgt.exists() and tgt.is_symlink():
                tgt.unlink()
            tgt.write_bytes(blob)
        # ---- post-check: nothing but the recorded fields moved ----
        problems = []
        want_files = set(src_of)
        have_files = {str((Path(dp) / f).relative_to(sd)) for dp, _, fns in os.walk(sd) for f in fns}
        if have_files != want_files:
            problems.append(f"file set differs: {sorted(have_files ^ want_files)[:5]}")
        verified = []
        for rel in sorted(have_files & want_files):
            a, bb = src_of[rel].read_bytes(), (sd / rel).read_bytes()
            stray = changed_ranges_ok(a, bb, allowed.get(rel, []))
            if stray:
                problems.append(f"{rel}: changes outside the SDK fields at " +
                                ", ".join(f"{x:#x}+{n:#x}" for x, n in stray[:5]))
                continue
            if rel in allowed and rel != "sce_sys/param.json":
                try:
                    p = sdk.find(Binary(bb, sd / rel))
                    Binary(bb, sd / rel)
                except Exception as e:                                    # noqa: BLE001
                    problems.append(f"{rel}: does not re-parse: {e}")
                    continue
                if not p or p.ps5 != new_ps5 or p.ps4 != new_ps4:
                    problems.append(f"{rel}: SDK is not the sibling pair")
                    continue
                verified.append(rel)
            elif rel == "sce_sys/param.json":
                try:
                    json.loads(bb.decode("utf-8-sig"))
                except ValueError as e:
                    problems.append(f"{rel}: invalid JSON: {e}")
        if problems:
            raise BuildError(f"sibling FW {sdk.target_str(major, minor)} failed its diff check, removed:\n  "
                             + "\n  ".join(problems))
    except BaseException:
        shutil.rmtree(sd, ignore_errors=True)
        raise

    # overlay: originals for the sibling = parent's originals + game copies of the extras
    sib_originals = ""
    if rep.mode == "overlay":
        parent_o = Path(rep.originals) if rep.originals else None
        n = 0
        if parent_o and parent_o.is_dir():
            for dp, _, fns in os.walk(parent_o):
                for f in fns:
                    rel = str((Path(dp) / f).relative_to(parent_o))
                    clone_file(parent_o / rel, odir_sd / rel)
                    n += 1
        for rel in extras:
            if not (odir_sd / rel).exists() and (game / rel).is_file():
                clone_file(game / rel, odir_sd / rel)
                n += 1
        if n:
            sib_originals = str(odir_sd)

    # sibling report: main edits with game->sibling values for the re-declared fields
    import copy
    edits = [copy.copy(e) for e in rep.edits]
    sib_edits = []
    by_loc = {(c["file"], c["offset"]): c for c in changes if not c.get("param")}
    for e in edits:
        c = by_loc.pop((e.file, e.offset), None) if e.kind == "sdk" else None
        if c:
            e.new, e.note = c["new"], e.note + f"; sibling: SDK {sdk.fw_str(new_ps5)}"
        elif e.kind == "param.json":
            key = e.old.partition("=")[0]
            c = next((x for x in changes if x["file"] == e.file and x.get("param") and x["what"] == key), None)
            if c:
                e.new = c["new"]
    for c in changes:
        if c.get("param"):
            if not any(e.kind == "param.json" and e.old.startswith(c["what"] + "=") for e in edits):
                edits.append(Edit(c["file"], "param.json", -1, f"{c['what']}={c['old']}", c["new"], "sibling"))
        elif (c["file"], c["offset"]) in by_loc:
            edits.append(Edit(c["file"], "sdk", c["offset"], c["old"], c["new"], c["what"] + " (sibling)"))
        sib_edits.append({"file": c["file"], "what": c["what"], "old": c["old"], "new": c["new"]})
    import dataclasses
    srep = dataclasses.replace(rep, target=major, out=str(sd), edits=edits, verified=verified, siblings=[],
                               originals=sib_originals, sibling_of=str(out), sibling_edits=sib_edits,
                               target_str=sdk.target_str(major, minor), warnings=list(rep.warnings), ok=True)
    (sd / "backport-report.json").write_text(srep.to_json())
    (sd / "backport-report.txt").write_text(srep.to_text())
    log(f"sibling FW {sdk.target_str(major, minor)}: {len(changes)} SDK field edit(s), diff check passed")
    return {"out": str(sd), "edits": len(changes)}


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
    also: list[tuple[int, int]] = []
    if opts.also_targets:
        if opts.mode == "inplace":
            raise BuildError("--also-target cannot be used with --mode inplace (siblings are separate outputs)")
        main_ps5 = sdk.target_pair(opts.target, opts.target_minor)[0]
        for mj, mn in opts.also_targets:
            if mj not in sdk.SUPPORTED_TARGETS:
                raise BuildError(f"--also-target {mj}: unsupported (supported: {sdk.SUPPORTED_TARGETS})")
            if sdk.target_pair(mj, mn)[0] <= main_ps5:
                raise BuildError(f"--also-target {sdk.target_str(mj, mn)} is not higher than the main target "
                                 f"{sdk.target_str(opts.target, opts.target_minor)}: siblings only go up "
                                 "(a lower SDK is what --target is for)")
            if (mj, mn) not in also:
                also.append((mj, mn))
    if opts.mode == "inplace":
        out = game
    else:
        if not opts.out:
            raise BuildError("--out is required unless --mode inplace")
        out = Path(opts.out).resolve()
        if out == game or game in out.parents:
            raise BuildError("output must be outside the game folder")
        if out in game.parents:
            raise BuildError("output must not contain the game folder")
        if out.exists() and any(out.iterdir()) and not opts.dry_run and not is_previous_build(out):
            raise BuildError(f"output folder {out} is not empty (and not an earlier ps5bp build)")
        for mj, mn in also:
            sd = sibling_dir(out, mj, mn)
            if sd == game or game in sd.parents or sd in game.parents:
                raise BuildError(f"sibling output {sd} overlaps the game folder")
            if sd.exists() and any(sd.iterdir()) and not opts.dry_run and not is_previous_build(sd):
                raise BuildError(f"sibling output folder {sd} is not empty (and not an earlier ps5bp build)")

    log(f"scanning {game}")
    gs = scan_game(game, progress=lambda i, n, name: prog("scan", i + 1, n))
    if opts.mode != "inplace" and not opts.dry_run:
        prev = previous_build_title(out)
        if prev and gs.title_id and prev != gs.title_id:
            raise BuildError(f"{out} holds the backport of another game ({prev}) — choose another output folder")
    rep = BuildReport(str(game), gs.title_id, gs.title, opts.target, opts.mode, str(out),
                      datetime.datetime.now().isoformat(timespec="seconds"))
    rep.target_str = sdk.target_str(opts.target, opts.target_minor)
    rep.target_minor = opts.target_minor
    rep.warnings += gs.warnings
    if opts.console_fw:
        try:
            sdk.fw_major_of_str(opts.console_fw)
        except ValueError as e:
            raise BuildError(str(e)) from None
        rep.console_fw = opts.console_fw.strip()
        cw = sdk.console_warning(opts.target, opts.target_minor, opts.console_fw)
        if cw:
            rep.console_warning = cw
            rep.warnings.append(cw)
            log("WARNING: " + cw)
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
    if opts.seeds:
        from .rules.contracts import load as load_contracts
        bad = [n for n in opts.seeds if n not in load_contracts()]
        if bad:
            raise BuildError(f"--seed: no stub contract for {', '.join(bad)} (see ps5bp/data/stub_contracts.json)")
        enabled.add("compat-stubs")                      # --seed NID implies the rule
    try:
        active = {r.name: r for r in resolve(enabled, set(opts.no_rules))}
    except ValueError as e:
        raise BuildError(str(e)) from None
    ctx = RuleContext(gs, cov, opts.target, load=lambda rel: get(rel, game / rel),
                      edit=lambda file, kind, off, old, new, note="": rep.edits.append(
                          Edit(file, kind, off, old, new, note)),
                      options={"patches": patches, "enabled": set(active), "stubs_from": opts.stubs_from,
                               "db": db, "seeds": list(opts.seeds), "seed_plt_fallback": opts.seed_plt_fallback})
    found = detect_all(ctx)
    for n in opts.seeds:
        if not any(f.rule == "compat-stubs" and f.data.get("nid") == n for f in found):
            rep.warnings.append(f"--seed {n}: no game binary imports it (or a chosen fakelib / game module provides it)")
    for f in found:
        applied = False
        if f.rule in active:
            if f.applicable:
                try:
                    active[f.rule].apply(ctx, f)
                except Exception as e:                       # noqa: BLE001
                    raise BuildError(f"rule {f.rule} failed on {f.file}: {e}") from None
                applied = True
            elif f.data.get("status") != "DONE":             # DONE = already in the wanted state: not a warning
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
        if also:
            log("dry run — would also write siblings: " + ", ".join(
                str(sibling_dir(out, mj, mn)) for mj, mn in also))
        log("dry run — nothing written")
        return rep

    # 5. write
    if opts.mode != "inplace" and out.exists() and any(out.iterdir()):
        # an earlier ps5bp build (checked above): replace it. Its <out>.originals is kept —
        # if that overlay was copied over the game, those are the only true originals left.
        log(f"replacing the previous build in {out}")
        shutil.rmtree(out)
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
    if also:
        for mj, mn in also:
            check()
            sib = make_sibling(game, out, rep, gs, mj, mn, log)
            rep.siblings.append({"target": mj, "target_minor": mn, "target_str": sdk.target_str(mj, mn),
                                 "out": sib["out"], "edits": sib["edits"]})
        (out / "backport-report.json").write_text(rep.to_json())      # now lists the siblings
        (out / "backport-report.txt").write_text(rep.to_text())
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
