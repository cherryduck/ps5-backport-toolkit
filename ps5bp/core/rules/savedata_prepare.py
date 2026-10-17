"""savedata-prepare: sceSaveDataPrepare request mode 2 / 3 / 6 -> 0.

Newer SDKs request a prepare mode (dword at request+4) that a 4.xx system does not know; the
community FW4 backports set it back to 0. Detected per call of sceSaveDataPrepare
(sDCBrmc61XU; the request is `rsi`):
  * exactly one dword store of the immediate 2 to request+4, nothing else non-zero written
    there                                                              -> PATCH (imm32 -> 0)
  * exactly one dword store of 3 after the request was zeroed by a vector store (the
    `vxorps; vmovups [req], ymm; ... mov [req+4], 3` form)             -> PATCH (imm32 -> 0)
  * exactly one dword store of 6 (single-store guards like mode 2; seen in KH HD 2.8; console-tested
    there: FW4 overlay on a PS5 Pro 11.60 works)                       -> PATCH (imm32 -> 0)
  * any other non-zero immediate store                                 -> UNKNOWN (value shown)
  * a dword store of 0 (and no 2/3/6)                                    -> DONE
  * several candidates / other non-zero writers overlap the field      -> UNKNOWN (refused)
  * mode copied from elsewhere (not an immediate)                      -> nothing to patch, not reported

PATCH findings are recommended when the declared SDK is <= 4 (modes 2/3 from community FW4 builds,
mode 6 console-tested on KH HD 2.8 / PPSA35909).
"""
from __future__ import annotations

from .. import x86flow as xf
from ..regflow import scan
from . import Finding, RuleContext
from .bytefix import DONE, PATCH, UNKNOWN, EditRule, code_binaries, finding
from .common import calls_to_import

MAX_DECLARED = 4               # recommended up to this declared SDK major
NID = "sDCBrmc61XU"            # sceSaveDataPrepare
MODE = 4                       # request offset of the dword prepare mode


def sites(b, base: int) -> list[dict]:
    from ..memsite import Scanner
    try:
        sc = Scanner(b, base)
    except IndexError:
        return []
    out = []
    for call in calls_to_import(sc, NID):
        try:
            fn = xf.function_at(sc.read, call)
            k = fn.index(call)
        except KeyError:
            out.append({"call": call, "status": UNKNOWN, "why": "cannot resync to the containing function"})
            continue
        flow = scan(fn, k)
        tok, roff = flow.resolve("rsi")
        lo, hi = roff + MODE, roff + MODE + 4
        ov = [s for s in flow.stores if s.base == tok and s.off < hi and s.off + s.size > lo]
        nz = [s for s in ov if not s.zero]
        exact = [s for s in ov if s.size == 4 and s.off == lo and s.imm is not None]
        cand = [s for s in exact if s.imm in (2, 3, 6)]
        other = [s for s in exact if s.imm not in (0, 2, 3, 6)]
        if len(cand) > 1:
            out.append({"call": call, "status": UNKNOWN, "why": f"{len(cand)} mode stores for one call"})
        elif len(cand) == 1:
            s = cand[0]
            if len(nz) != 1:
                out.append({"call": call, "status": UNKNOWN, "why": "another non-zero store overlaps the mode field"})
            elif s.insn.bytes[-4:] != s.imm.to_bytes(4, "little"):
                out.append({"call": call, "status": UNKNOWN, "why": "mode immediate is not the last 4 bytes"})
            elif s.imm == 3 and not any(z.zero and z.size >= 16 and z.idx < s.idx and z.off <= lo and z.off + z.size >= hi
                                        and z.base == tok for z in ov):
                out.append({"call": call, "status": UNKNOWN, "why": "mode 3 but the request was not vector-zeroed first"})
            else:
                out.append({"call": call, "status": PATCH, "va": s.insn.address, "len": s.insn.size, "imm": s.imm})
        elif other:
            out.append({"call": call, "status": UNKNOWN, "why": f"unexpected mode value {other[0].imm} at {other[0].insn.address:#x}"})
        elif [s for s in exact if s.imm == 0] and len(nz) == 0:
            s = [s for s in exact if s.imm == 0][0]
            out.append({"call": call, "status": DONE, "va": s.insn.address, "len": s.insn.size, "imm": 0})
    return out


class SavedataPrepare(EditRule):
    name = "savedata-prepare"
    summary = "sceSaveDataPrepare request mode 2/3/6 -> 0 (mode unknown to 4.xx)"

    def detect(self, ctx: RuleContext) -> list[Finding]:
        out = []
        rec = ctx.declared_sdk <= MAX_DECLARED
        why = ("console-tested: KH HD 2.8 (PPSA35909) FW4 overlay on a PS5 Pro 11.60 (mode 6); modes 2/3 from "
               "community FW4 builds") if rec else ""
        for bi in code_binaries(ctx, NID):
            seen: set[int] = set()
            for r in sites(ctx.load(bi.path), ctx.base_for(bi.path)):
                va = r.get("va")
                if va is not None and va in seen:
                    continue
                if va is not None:
                    seen.add(va)
                if r["status"] == PATCH:
                    out.append(finding(self.name, bi.path, f"{va:#x}: SaveDataPrepare mode {r['imm']} -> 0 "
                                       f"(call {r['call']:#x})", PATCH,
                                       recommended=rec, reason=why,
                                       edits=[(va + r["len"] - 4, f"{r['imm']:08x}"[6:] + "000000", "00000000",
                                               f"SaveDataPrepare mode {r['imm']} -> 0")]))
                elif r["status"] == DONE:
                    out.append(finding(self.name, bi.path, f"{va:#x}: SaveDataPrepare mode already 0 "
                                       f"(call {r['call']:#x})", DONE, reason="already patched"))
                else:
                    out.append(finding(self.name, bi.path, f"call {r['call']:#x}: SaveDataPrepare mode not proved",
                                       UNKNOWN, reason=r["why"]))
        return out
