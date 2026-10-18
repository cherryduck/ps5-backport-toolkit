"""Reverse a build from its backport-report.json (`ps5bp undo GAME REPORT [REPORT ...]`).

Every byte edit in a report records file offset, old and new bytes, so applying them
backwards restores the input exactly. Give several reports newest first when builds were
stacked (an overlay copied over the game, then another).

  sdk / rule:* / retarget   bytes at offset must equal `new` -> written back to `old`
  param.json                "key": "new" -> "key": "old" (text, formatting kept)
  extra                     a file a rule shipped (k9.psp) -> deleted (an overwritten one: <out>.originals/)
  fakelib                   installed by the build -> deleted (if the build replaced a
                            fakelib the game shipped itself, that file can't be restored
                            from the report: use <out>.originals/ if present)
  generated                 a file ps5bp wrote whole (ampr_emu.index): restored from <name>.orig
                            (in-place) or <out>.originals/ (overlay) when there was one, else deleted
  removed                   restored from <name>.orig if present, else reported
Verification (reports with `inputs`/`outputs` hashes): before a report's files are touched each must
still equal the build's OUTPUT hash (still the backported file, not edited since), and after
reversal each must equal the recorded INPUT hash. Mismatch -> refused, unless force. Older
reports without the hashes undo as before (a note says verification was skipped). Game paths are
matched case-insensitively when the exact path is absent (unambiguous only).
Overlay builds save the input's copy of every file they replace in <out>.originals/
(recorded in the report); when present those are restored as-is, which also covers caves
and replaced dump fakelibs. Without it, code caves (edits with no old bytes) are refused: they also grew a
segment, which the report doesn't record. Nothing is written unless every edit checks out.
"""
from __future__ import annotations

import json
import os
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .ledger import AmbiguousMember, resolve_member


class UndoError(Exception):
    pass


@dataclass
class UndoPlan:
    writes: dict[str, bytearray] = field(default_factory=dict)       # rel -> new content
    deletes: list[str] = field(default_factory=list)
    restores: list[tuple[str, str]] = field(default_factory=list)    # (.orig, rel)
    notes: list[str] = field(default_factory=list)
    count: int = 0


def _bytes(kind: str, s: str) -> bytes:
    return s.encode() if kind == "retarget" else bytes.fromhex(s)


def plan_undo(game: Path, reports: list[Path], force: bool = False) -> UndoPlan:
    up = UndoPlan()
    cur: dict[str, bytearray] = {}

    def R(rel: str) -> str:
        """the report's path as spelled in the game folder"""
        try:
            return resolve_member(game, rel)
        except AmbiguousMember as e:
            raise UndoError(str(e)) from None

    def content(rel: str) -> bytearray:
        if rel not in cur:
            p = game / rel
            if not p.is_file():
                raise UndoError(f"{rel}: not in {game}")
            cur[rel] = bytearray(p.read_bytes())
        return cur[rel]

    def sha_now(rel: str) -> str | None:
        if rel in cur:
            return hashlib.sha256(cur[rel]).hexdigest()
        p = game / rel
        return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None

    def verify(rep: dict, rels: list[str], key: str, what: str) -> None:
        """rels (game spelling) must hash to rep[key][report spelling]"""
        want = rep.get(key)
        if not want:
            return
        bad = []
        for rel in rels:
            exp = want.get(rel) or next((v for k, v in want.items() if k.casefold() == rel.casefold()), None)
            if exp is None:
                continue
            got = sha_now(rel)
            if got is not None and got != exp:
                bad.append(rel)
        if bad:
            msg = f"{what}: " + ", ".join(sorted(bad))
            if not force:
                raise UndoError(msg + " (use --force to override)")
            up.notes.append("--force: " + msg)

    gone: set[str] = set()
    reps = [json.loads((rp / "backport-report.json" if rp.is_dir() else rp).read_text(encoding="utf-8")) for rp in reports]
    for n, rep in enumerate(reps):
        if not rep.get("inputs") or not rep.get("outputs"):
            up.notes.append(f"report {n + 1} ({rep.get('out', '?')}) has no input/output hashes — "
                            "hash verification skipped")
        odir = Path(rep["originals"]) if rep.get("originals") else None
        touched: list[str] = []                       # game files this report rewrites (for the post-check)
        if odir is not None and odir.is_dir():
            # exact copies of the input: restore those files wholesale, delete the rest it added
            have = {R(Path(dp, f).relative_to(odir).as_posix()): Path(dp, f).relative_to(odir).as_posix()
                    for dp, _, fs in os.walk(odir) for f in fs}
            verify(rep, sorted(have), "outputs", "these game files are not the backported files this build wrote "
                   "(changed since it was applied, or another build is on top)")
            for rel in sorted(have):
                cur[rel] = bytearray((odir / have[rel]).read_bytes())
                touched.append(rel)
                gone.discard(rel)
                if rel in up.deletes:
                    up.deletes.remove(rel)
            for e in rep["edits"]:
                f = R(e["file"])
                if e["kind"] in ("fakelib", "extra", "generated") and f not in have and (game / f).exists() and f not in gone:
                    verify(rep, [f], "outputs", "this file is not the one the build installed")
                    up.deletes.append(f)
                    gone.add(f)
                    cur.pop(f, None)
            up.count += len(rep["edits"])
            verify(rep, [t for t in touched if t not in gone], "inputs", "restored files do not match the build's "
                   "recorded inputs")
            continue
        installed = {R(e["file"]) for e in rep["edits"] if e["kind"] in ("fakelib", "extra", "generated")}
        older = {R(e["file"]) for r in reps[n + 1:] for e in r["edits"] if e["kind"] in ("fakelib", "extra", "generated")}
        pre = sorted({R(e["file"]) for e in rep["edits"] if e["kind"] not in ("fakelib", "extra", "generated", "removed")} - installed)
        verify(rep, pre + sorted(x for x in installed if (game / x).exists() and x not in gone), "outputs",
               "these game files are not the backported files this build wrote (changed since it was applied, "
               "or another build is on top)")
        for e in reversed(rep["edits"]):
            rel, kind = R(e["file"]), e["kind"]
            if rel in installed and kind not in ("fakelib", "extra", "generated"):
                continue                                    # whole file goes away anyway
            if kind == "extra":                             # a file a rule added (k9.psp ...): deleted again
                if (game / rel).exists() and rel not in gone:
                    up.deletes.append(rel)
                    gone.add(rel)
                cur.pop(rel, None)
                up.count += 1
                continue
            if kind == "generated":                         # ampr_emu.index: the game's own comes back
                bak_rel = R(rel + ".orig")
                if e["old"] and (game / bak_rel).exists():
                    up.restores.append((bak_rel, rel))
                elif (game / rel).exists() and rel not in gone:
                    if e["old"]:
                        up.notes.append(f"{rel}: replaced by the build and no .orig backup found — deleted")
                    up.deletes.append(rel)
                gone.add(rel)
                cur.pop(rel, None)
                up.count += 1
                continue
            if kind == "fakelib":
                if "replaces the dump's" in e.get("note", "") and rel not in gone and rel not in older:
                    up.notes.append(f"{rel}: replaced a fakelib the game shipped — the original "
                                    "is not in the report (check <out>.originals/)")
                if (game / rel).exists() and rel not in gone:
                    up.deletes.append(rel)
                    gone.add(rel)
                cur.pop(rel, None)
                up.count += 1
                continue
            if kind == "removed":
                bak_rel = R(rel + ".orig")
                if (game / bak_rel).exists():
                    up.restores.append((bak_rel, rel))
                else:
                    up.notes.append(f"{rel}: was removed by the build and has no .orig — restore it from the dump source")
                up.count += 1
                continue
            if kind == "param.json":
                key, _, old_val = e["old"].partition("=")
                text = content(rel).decode("utf-8-sig")
                bom = bytes(content(rel)).startswith(b"\xef\xbb\xbf")
                pat = re.compile(r'("' + re.escape(key) + r'"\s*:\s*")' + re.escape(e["new"]) + '"')
                if not pat.search(text):
                    raise UndoError(f"{rel}: {key} is not {e['new']} (edited since?)")
                text = pat.sub(lambda m: m.group(1) + old_val + '"', text, count=1)
                cur[rel] = bytearray((b"\xef\xbb\xbf" if bom else b"") + text.encode())
                up.count += 1
                continue
            if e["offset"] < 0:
                continue
            old, new = _bytes(kind, e["old"]), _bytes(kind, e["new"])
            if not old and new:
                raise UndoError(f"{rel}: {e.get('note', 'code cave')} — cave edits can't be undone from a report")
            data = content(rel)
            o = e["offset"]
            if bytes(data[o:o + len(new)]) != new:
                raise UndoError(f"{rel} @{o:#x}: expected {new.hex()[:32]}, found "
                                f"{bytes(data[o:o + len(new)]).hex()[:32]} — wrong report order or file changed")
            data[o:o + len(new)] = old
            up.count += 1
        verify(rep, [r for r in pre if r in cur and r not in gone], "inputs",
               "restored files do not match the build's recorded inputs")
    up.writes = {k: v for k, v in cur.items() if k not in gone}
    return up


def apply_undo(game: Path, up: UndoPlan) -> None:
    for rel, data in up.writes.items():
        p = game / rel
        tmp = p.with_name(p.name + ".ps5bp-undo")
        tmp.write_bytes(data)
        os.replace(tmp, p)
    for rel in up.deletes:
        (game / rel).unlink()
    for bak, rel in up.restores:
        os.replace(game / bak, game / rel)
