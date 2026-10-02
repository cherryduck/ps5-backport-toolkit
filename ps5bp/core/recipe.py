"""Patch recipes: shareable, verifiable per-game patches (JSON).

{
  "name": "wolverine-pssr-memory",
  "rule": "pssr-memory",                    # built-in recipes only: which rule offers it
  "title_id": "PPSA03671",                  # optional; recipe skipped for other titles
  "file": "eboot.bin",
  "base": "0x400000",                       # optional; default 0x400000 for eboot, else 0
  "note": "...",
  "match": [{"va": "0x4171867", "bytes": "e8b4e928fc"}],     # all must hold, else not applicable
  "caves": [{"label": "pool", "segment": 0, "align": 16, "code": ["4981fe00000010", ...]}],
  "ops":   [{"call": "0x4171867", "to": "@pool", "old_to": "0x400220"},
            {"va": "0x3ddc5d3", "old": "75", "new": "eb"}]
}

Anchors (optional) locate code by signature instead of fixed VA, so a recipe survives
code moving between builds:
  "anchors": [{"name": "h", "find": "4c 8d ?? ?? e8 ?? ?? ?? ??", "offset": 4, "va": "0x4171867"}]
  `find` is hex with ?? wildcards and must match exactly once in the executable segments
  (the `va` hint is tried first); the anchor is the match + offset. Anywhere a VA is
  accepted: "$h" = anchor, "orig:$h" = original rel32 target of the call/jmp at the anchor,
  "riptgt:$h" = [rip+disp] address used by the instruction at the anchor.

Cave code lines (runtime VAs; `@x` = cave/label, `nid:XXXX` = that import's PLT stub):
  "<hex>"                         raw bytes
  "label NAME"                    define a label
  "rel32 <ophex> <target>"        call e8 / jmp e9 / jcc 0f8x with disp32
  "rel8 <ophex> <target>"         short jmp eb / jcc 7x
  "rip <prefixhex> <target> [tailhex]"   [rip+disp32] operand
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from . import dynamic
from .asm import Asm, plt_stubs, stub_for
from .binary import Binary


class RecipeError(Exception):
    pass


def _int(v) -> int:
    return v if isinstance(v, int) else int(str(v), 0)


@dataclass
class Recipe:
    name: str
    file: str
    raw: dict
    rule: str = "user-patch"
    title_id: str = ""
    base: int | None = None
    note: str = ""
    source: str = ""
    match: list = field(default_factory=list)
    caves: list = field(default_factory=list)
    ops: list = field(default_factory=list)
    anchors: list = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | str, text: str | None = None) -> "Recipe":
        d = json.loads(text if text is not None else Path(path).read_text())
        for k in ("name", "file"):
            if k not in d:
                raise RecipeError(f"{path}: missing '{k}'")
        return cls(d["name"], d["file"], d, d.get("rule", "user-patch"), d.get("title_id", ""),
                   _int(d["base"]) if "base" in d else None, d.get("note", ""), str(path),
                   d.get("match", []), d.get("caves", []), d.get("ops", []), d.get("anchors", []))

    def base_for(self) -> int:
        return self.base if self.base is not None else (0x400000 if self.file == "eboot.bin" else 0)

    # ---- anchors ---------------------------------------------------------------------
    def resolve(self, b: Binary) -> dict[str, dict]:
        """name -> {va, orig, rip} for every anchor; raises RecipeError if one doesn't match once."""
        from .memfix import _regex, find_all
        base = self.base_for()
        out: dict[str, dict] = {}
        for a in self.anchors:
            off = int(a.get("offset", 0))
            va = None
            if "va" in a:
                hint = _int(a["va"]) - off
                n = len(a["find"].split())
                try:
                    blob = b.read(hint - base, n)
                except Exception:                    # noqa: BLE001
                    blob = b""
                if _regex(a["find"]).fullmatch(blob):
                    va = hint + off
            if va is None:
                hits = find_all(b, a["find"], base, 2)
                if len(hits) != 1:
                    raise RecipeError(f"anchor {a['name']}: signature found {len(hits)}x" +
                                      (" (ambiguous)" if hits else " (code not present: other version?)"))
                va = hits[0] + off
            ins = b.read(va - base, 16)
            orig = None
            if ins[0] in (0xE8, 0xE9):
                orig = va + 5 + struct.unpack_from("<i", ins, 1)[0]
            rip = None
            from .x86flow import decode
            dec = decode(ins, va)
            if dec and dec[0].rip_target is not None:
                rip = dec[0].rip_target
            out[a["name"]] = {"va": va, "orig": orig, "rip": rip}
        return out

    # ---- check -----------------------------------------------------------------------
    def check(self, b: Binary, title_id: str = "") -> str:
        """'' if applicable, else the reason it isn't."""
        if self.title_id and title_id and self.title_id != title_id:
            return f"title {title_id} != {self.title_id}"
        try:
            anc = self.resolve(b)
        except RecipeError as e:
            return str(e)
        for op in self.ops:
            if "call" in op and str(op["call"]).startswith("$"):
                a = anc.get(op["call"][1:])
                if a is None:
                    return f"unknown anchor {op['call']}"
                if a["orig"] is None:
                    return f"anchor {op['call']} at {a['va']:#x} is not a call/jmp"
        base = self.base_for()
        for m in self.match:
            va, want = _int(m["va"]), bytes.fromhex(m["bytes"])
            try:
                got = b.read(va - base, len(want))
            except Exception:                    # noqa: BLE001
                return f"{va:#x} not mapped"
            if got != want:
                return f"bytes at {va:#x} are {got.hex()}, expected {want.hex()}"
        for op in self.ops:
            if "old" in op:
                va, old = _int(op["va"]), bytes.fromhex(op["old"])
                if b.read(va - base, len(old)) != old:
                    return f"bytes at {va:#x} differ from 'old'"
            elif "call" in op and "old_to" in op and not str(op["call"]).startswith("$"):
                va = _int(op["call"])
                ins = b.read(va - base, 5)
                if ins[0] not in (0xE8, 0xE9) or va + 5 + struct.unpack("<i", ins[1:])[0] != _int(op["old_to"]):
                    return f"{va:#x} is not a call/jmp to {op['old_to']}"
        return ""

    # ---- apply -----------------------------------------------------------------------
    def apply(self, b: Binary) -> list[tuple[int, bytes, bytes, str]]:
        """Apply to b. Returns (file offset, old, new, note) per change."""
        base = self.base_for()
        out: list[tuple[int, bytes, bytes, str]] = []
        d = dynamic.parse(b)
        stubs = plt_stubs(b, d, base) if d else {}
        labels: dict[str, int] = {}
        anc = self.resolve(b)

        def anchor(t: str, key: str) -> int:
            name = t.split("$", 1)[1]
            if name not in anc or anc[name][key] is None:
                raise RecipeError(f"{self.name}: {t} unresolved")
            return anc[name][key]

        def target(t: str, a: Asm | None = None) -> int | str:
            if t.startswith("$"):
                return anchor(t, "va")
            if t.startswith("orig:"):
                return anchor(t, "orig")
            if t.startswith("riptgt:"):
                return anchor(t, "rip")
            if t.startswith("@"):
                name = t[1:]
                if a is not None and name not in labels:
                    return name                  # local label, resolved by Asm
                return labels[name]
            if t.startswith("nid:"):
                va = stub_for(stubs, t[4:])
                if va is None:
                    raise RecipeError(f"{self.name}: {t[4:]} is not imported")
                return va
            return _int(t)

        # caves: lay out sequentially, each aligned, so labels of earlier caves resolve
        for cave in self.caves:
            seg, align = cave.get("segment", 0), cave.get("align", 16)
            va0 = b.cave_rva(seg, align) + base
            labels[cave["label"]] = va0
            a = Asm(va0)
            for line in cave["code"]:
                tok = line.split()
                if tok[0] == "label":
                    a.label(tok[1])
                elif tok[0] == "rel32":
                    a.rel32(tok[1], target(tok[2], a))
                elif tok[0] == "rel8":
                    a.rel8(tok[1], target(tok[2], a))
                elif tok[0] == "rip":
                    a.rip32(tok[1], target(tok[2], a), tok[3] if len(tok) > 3 else "")
                else:
                    a.hex(line)
            code = a.assemble()
            for k, v in a.labels.items():
                labels.setdefault(k, v)
            seg_before = b.phdrs[seg].filesz
            off = b.add_cave(seg, code, align)
            if b.cave_rva(seg, 1) + base != va0 + len(code):
                raise RecipeError(f"{self.name}: cave placement mismatch")
            out.append((off, b"", bytes(code), f"cave @{cave['label']} at {va0:#x} "
                         f"(segment {seg} filesz {seg_before:#x} -> {b.phdrs[seg].filesz:#x})"))

        for op in self.ops:
            if "call" in op:
                va = int(target(op["call"])) if str(op["call"]).startswith("$") else _int(op["call"])
                ins = b.read(va - base, 5)
                t = int(target(op["to"]))
                new = ins[:1] + struct.pack("<i", t - (va + 5))
                off = b.patch(va - base, ins, new)
                out.append((off, ins, new, f"{va:#x}: retarget -> {op['to']} ({t:#x})"))
            else:
                va, old, new = _int(op["va"]), bytes.fromhex(op["old"]), bytes.fromhex(op["new"])
                off = b.patch(va - base, old, new)
                out.append((off, old, new, op.get("note", f"{va:#x}")))
        return out


def builtin(rule: str | None = None) -> list[Recipe]:
    d = resources.files("ps5bp").joinpath("data/recipes")
    out = []
    for f in sorted(d.iterdir(), key=lambda p: p.name):
        if f.name.endswith(".json"):
            r = Recipe.load(f"builtin:{f.name}", f.read_text())
            if rule is None or r.rule == rule:
                out.append(r)
    return out
