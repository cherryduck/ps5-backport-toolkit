"""Reverse a build from its backport-report.json (`ps5bp undo GAME REPORT [REPORT ...]`).

Every byte edit in a report records file offset, old and new bytes, so applying them
backwards restores the input exactly. Give several reports newest first when builds were
stacked (an overlay copied over the game, then another).

  sdk / rule:* / retarget   bytes at offset must equal `new` -> written back to `old`
  param.json                "key": "new" -> "key": "old" (text, formatting kept)
  fakelib                   installed by the build -> deleted (if the build replaced a
                            fakelib the game shipped itself, that file can't be restored
                            from the report: use <out>.originals/ if present)
  removed                   restored from <name>.orig if present, else reported
Overlay builds save the input's copy of every file they replace in <out>.originals/
(recorded in the report); when present those are restored as-is, which also covers caves
and replaced dump fakelibs. Without it, code caves (edits with no old bytes) are refused: they also grew a
segment, which the report doesn't record. Nothing is written unless every edit checks out.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


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


def plan_undo(game: Path, reports: list[Path]) -> UndoPlan:
    up = UndoPlan()
    cur: dict[str, bytearray] = {}

    def content(rel: str) -> bytearray:
        if rel not in cur:
            p = game / rel
            if not p.is_file():
                raise UndoError(f"{rel}: not in {game}")
            cur[rel] = bytearray(p.read_bytes())
        return cur[rel]

    gone: set[str] = set()
    reps = [json.loads((rp / "backport-report.json" if rp.is_dir() else rp).read_text()) for rp in reports]
    for n, rep in enumerate(reps):
        odir = Path(rep["originals"]) if rep.get("originals") else None
        if odir is not None and odir.is_dir():
            # exact copies of the input: restore those files wholesale, delete the rest it added
            have = {str(Path(dp, f).relative_to(odir)) for dp, _, fs in os.walk(odir) for f in fs}
            for rel in sorted(have):
                cur[rel] = bytearray((odir / rel).read_bytes())
                gone.discard(rel)
                if rel in up.deletes:
                    up.deletes.remove(rel)
            for e in rep["edits"]:
                if e["kind"] == "fakelib" and e["file"] not in have and (game / e["file"]).exists() \
                        and e["file"] not in gone:
                    up.deletes.append(e["file"])
                    gone.add(e["file"])
                    cur.pop(e["file"], None)
            up.count += len(rep["edits"])
            continue
        installed = {e["file"] for e in rep["edits"] if e["kind"] == "fakelib"}
        older = {e["file"] for r in reps[n + 1:] for e in r["edits"] if e["kind"] == "fakelib"}
        for e in reversed(rep["edits"]):
            rel, kind = e["file"], e["kind"]
            if rel in installed and kind != "fakelib":
                continue                                    # whole file goes away anyway
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
                bak = game / (rel + ".orig")
                if bak.exists():
                    up.restores.append((rel + ".orig", rel))
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
