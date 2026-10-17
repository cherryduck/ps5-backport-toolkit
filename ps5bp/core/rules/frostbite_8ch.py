"""frostbite-8ch: EA / Frostbite AudioOut2 12-channel set-up -> 8 channels.

A 4.xx system's AudioOut2 ports accept 1, 2 or 8 channels, not 12 (7.1.4). Frostbite titles pick
the layout with a small format dispatch: `mov r9d, 0x30c` (12 ch format id) / `0x208` (8 ch),
a format word store of 0xC00 into a stack slot (8 ch = 0x800) and a channel count (12 -> 8)
in ebx or eax. Observed in community FW4 backports (hardware-proved on a base 4.50 console
for three layouts of the same code, from NHL 26 / EA SPORTS FC 26, Madden NFL 27, NHL 27): the
12 ch branch is rewritten to the 8 ch constants at four (three for the last two layouts) places.

Detector: every `mov r9d, 0x30c` that follows a `mov dword [rbp-disp], 0xc00` is an anchor.
It must match one of the three known layouts completely - the guard bytes (the already-8ch
twin of the dispatch, both `cmp r9d,...`), the branch targets and the pre-image of every edit.
Every anchor of a binary must match, otherwise the binary is refused as a whole (UNKNOWN) and
nothing is edited. An anchor whose edits already carry the 8 ch values is DONE.
"""
from __future__ import annotations

import re

from .. import x86flow as xf
from . import Finding, RuleContext
from .bytefix import DONE, PATCH, UNKNOWN, EditRule, finding

ANCHOR12 = bytes.fromhex("41b90c030000")          # mov r9d, 0x30c
ANCHOR8 = bytes.fromhex("41b908020000")           # mov r9d, 0x208
_LIKE = re.compile(rb"\xc7\x85.\xff\xff\xff\x00\x0c\x00\x00\x41\xb9\x0c\x03\x00\x00", re.S)
MAX_DECLARED = 4

# guards {offset from the anchor: bytes}, branches {offset of a jump: offset of its target},
# edits ((offset, old, new), ...) — see the module docstring
_STORE_EC = ("c78514ffffff000c0000", "c78514ffffff00080000")
_STORE_F0 = ("c78510ffffff000c0000", "c78510ffffff00080000")
_CMP12, _CMP8 = "4181f90c030000", "4181f908020000"
VARIANTS = (
    {"name": "EA_FORMAT_SLOT_RBP_M0xEC",
     "guards": {-227: _STORE_EC[1], -203: ANCHOR8.hex(), -23: _CMP12, 1883: _CMP8, 1896: _CMP12, 2049: "bb08000000"},
     "branches": {1890: 2049, 1903: 2059},
     "edits": ((-10, *_STORE_EC), (0, ANCHOR12.hex(), ANCHOR8.hex()), (2059, *_STORE_EC),
               (2069, "bb0c000000", "bb08000000"))},
    {"name": "EA_FORMAT_SLOT_RBP_M0xF0",
     "guards": {-194: ANCHOR8.hex(), -188: _STORE_F0[1], -34: _CMP12, 2231: _CMP8, 2249: _CMP12},
     "branches": {2256: -10},
     "edits": ((-10, *_STORE_F0), (0, ANCHOR12.hex(), ANCHOR8.hex()), (2244, "b80c000000", "b808000000"))},
    {"name": "EA_FORMAT_SLOT_RBP_M0xF0_STACKCHECK",
     "guards": {-218: ANCHOR8.hex(), -212: _STORE_F0[1], -34: _CMP12, 2227: _CMP8, 2245: _CMP12},
     "branches": {2252: -10},
     "edits": ((-10, *_STORE_F0), (0, ANCHOR12.hex(), ANCHOR8.hex()), (2240, "b80c000000", "b808000000"))},
)


def _at(seg: bytes, i: int, n: int) -> bytes | None:
    return seg[i:i + n] if 0 <= i and i + n <= len(seg) else None


def _match(seg: bytes, va0: int, i: int, v: dict, post: bool) -> bool:
    """Does variant v match with the anchor at seg offset i (pre-edit bytes, or post-edit if `post`)."""
    for rel, hx in v["guards"].items():
        if _at(seg, i + rel, len(hx) // 2) != bytes.fromhex(hx):
            return False
    for rel, old, new in v["edits"]:
        want = bytes.fromhex(new if post else old)
        if _at(seg, i + rel, len(want)) != want:
            return False
    for rel, tgt in v["branches"].items():
        raw = _at(seg, i + rel, 6)
        ins = xf.decode(raw, va0 + i + rel) if raw else []
        if not ins or not ins[0].mnemonic.startswith("j") or ins[0].target != va0 + i + tgt:
            return False
    return True


def scan(b, base: int) -> dict:
    """{'sites': [{va, variant, status, edits}], 'unknown': [(va, why)]}"""
    sites, unknown = [], []
    for p in b.loads():
        if not p.is_exec:
            continue
        seg = b.segment_bytes(p)
        va0 = base + p.vaddr
        anchors = [(m.start() + 10, False) for m in _LIKE.finditer(seg)]
        anchors += [(m.start(), True) for m in re.finditer(re.escape(ANCHOR8), seg)]
        for i, post in anchors:
            hits = [v for v in VARIANTS if _match(seg, va0, i, v, post)]
            if post and not hits:
                continue                              # an ordinary 8 ch constant, not a patched anchor
            va = va0 + i
            if len(hits) != 1:
                unknown.append((va, f"{len(hits)} layouts match" if hits else "layout not covered by a working build"))
                continue
            v = hits[0]
            edits = [(va + rel, old, new, f"Frostbite AudioOut2 12->8 ({v['name']})") for rel, old, new in v["edits"]]
            sites.append({"va": va, "variant": v["name"], "status": DONE if post else PATCH, "edits": edits})
    return {"sites": sites, "unknown": unknown}


class Frostbite8ch(EditRule):
    name = "frostbite-8ch"
    summary = "EA/Frostbite AudioOut2 12-channel set-up -> 8 channels (4.xx ports accept 1/2/8)"

    def detect(self, ctx: RuleContext) -> list[Finding]:
        rec = ctx.declared_sdk <= MAX_DECLARED
        why = "4.xx AudioOut2 ports take 1/2/8 channels; the 8 ch layouts are hardware-proved on 4.50" if rec else ""
        out = []
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error:
                continue
            r = scan(ctx.load(bi.path), ctx.base_for(bi.path))
            if r["unknown"]:
                for va, w in r["unknown"]:
                    out.append(finding(self.name, bi.path, f"{va:#x}: Frostbite 12 ch set-up not proved", UNKNOWN,
                                       reason=w + " — the whole binary is refused"))
                continue
            for s in r["sites"]:
                if s["status"] == PATCH:
                    out.append(finding(self.name, bi.path, f"{s['va']:#x}: Frostbite AudioOut2 12 -> 8 channels "
                                       f"({s['variant']})", PATCH, recommended=rec, reason=why, edits=s["edits"]))
                else:
                    out.append(finding(self.name, bi.path, f"{s['va']:#x}: Frostbite AudioOut2 already 8 channels "
                                       f"({s['variant']})", DONE, reason="already patched"))
        return out
