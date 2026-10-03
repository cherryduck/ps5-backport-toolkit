"""wwise-71: Wwise 7.1.4 (12-channel) speaker configs -> 7.1 on low firmware.

Wwise's AkChannelConfig packs uNumChannels:8 | eConfigType:4 | uChannelMask:20 into
32 bits. 7.1.4 = 0x2d63f10c (12 ch, standard, mask 0x2d63f), 7.1 = 0x0063f108 (8 ch,
mask 0x63f). Low firmware refuses 12-channel output (DLPS ACE COMBAT 8 4.03 notes), so
the game's requested config is rewritten wherever it appears as an immediate operand in
code: `mov r32, imm32`, `mov m32, imm32`, `movabs r64, imm64` (two packed configs).
Only for games that contain Wwise (ak*.prx modules or Wwise/AkSoundEngine strings).
"""
from __future__ import annotations

import re

from .. import x86flow as xf
from . import Finding, Rule, RuleContext
from .evidence_rules import recommendation

CFG_714 = 0x2D63F10C
CFG_71 = 0x0063F108
_N = CFG_714.to_bytes(4, "little")
_NEW = CFG_71.to_bytes(4, "little")


def is_wwise_game(gs) -> bool:
    return any(re.search(r"(^|/)ak\w+\.prx$", b.path) for b in gs.binaries)


def sites(b, base: int) -> list[tuple[int, int, int]]:
    """(instruction va, imm offset va, count) for immediates holding 7.1.4 (1 or 2 packed)."""
    out = []
    for p in b.loads():
        if not p.is_exec:
            continue
        seg = b.segment_bytes(p)
        seen = set()
        for m in re.finditer(re.escape(_N), seg):
            i = m.start()
            if i in seen:
                continue
            for back in range(1, 12):
                st = i - back
                if st < 0:
                    break
                ins = xf.decode(seg[st:st + 16], base + p.vaddr + st)
                if not ins:
                    continue
                x = ins[0]
                if x.mnemonic not in ("mov", "movabs") or x.size < back + 4:
                    continue
                imm = seg[st + x.size - (8 if x.mnemonic == "movabs" else 4):st + x.size]
                if x.mnemonic == "movabs" and imm == _N * 2:
                    out.append((x.address, x.address + x.size - 8, 2))
                    seen |= {i, i + 4}
                    break
                if x.mnemonic == "mov" and imm == _N and st + x.size == i + 4:
                    out.append((x.address, x.address + x.size - 4, 1))
                    seen.add(i)
                    break
    # a 4-byte match inside a movabs found first (first copy) is not its own instruction
    big = [(a, a + 8) for _, a, n in out if n == 2]
    out = [o for o in out if o[2] == 2 or not any(lo <= o[1] < hi for lo, hi in big)]
    return [o for o in out if not _table_arm(b, base, o[0])]


def _table_arm(b, base: int, va: int) -> bool:
    """`mov reg, imm ; jmp` between other jmp-terminated arms: a config->value lookup
    table (DLPS left these alone), not the config the game asks for."""
    data = b.read(va - base - 8, 24)
    ins = xf.decode(data[8:], va)
    if len(ins) < 2 or ins[1].mnemonic != "jmp":
        return False
    for back in (2, 5):                                   # previous arm ends in jmp rel8/rel32
        prev = xf.decode(data[8 - back:8], va - back)
        if prev and prev[0].mnemonic == "jmp" and prev[0].size == back:
            return True
    return False


class Wwise71(Rule):
    name = "wwise-71"
    summary = "Wwise 7.1.4 (12-channel) speaker config -> 7.1 (low FW refuses 12 channels)"
    # Unproven: DLPS's FW4 PPSA11386 kept 7.1.4 and the game ran; the AC8 selection is
    # conditional (cmovne on an output capability flag), so 4.xx likely never takes it.
    PRIOR = {"needed_max": 0, "ok_min": 99}

    def detect(self, ctx: RuleContext) -> list[Finding]:
        if not is_wwise_game(ctx.gs):
            return []
        rec, why = recommendation(self.name, ctx, self.PRIOR)
        out = []
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error:
                continue
            for ins, imm, n in sites(ctx.load(bi.path), ctx.base_for(bi.path)):
                out.append(Finding(self.name, bi.path, f"{ins:#x}: AkChannelConfig 7.1.4 -> 7.1"
                                   + (" (x2 packed)" if n == 2 else ""), recommended=rec, reason=why,
                                   data={"imm": imm, "n": n}))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        n = f.data["n"]
        off = b.patch(f.data["imm"] - ctx.base_for(f.file), _N * n, _NEW * n)
        ctx.edit(f.file, f"rule:{self.name}", off, (_N * n).hex(), (_NEW * n).hex(),
                 f"{f.data['imm']:#x} Wwise 7.1.4 -> 7.1")

    @staticmethod
    def probe(b, base: int) -> tuple[int, int]:
        unfixed = sum(n for _, _, n in sites(b, base))
        fixed = 0
        for p in b.loads():
            if p.is_exec:
                fixed += b.segment_bytes(p).count(_NEW)
        return unfixed, fixed
