"""savedata-dirsearch: sceSaveDataDirNameSearch2 on firmware that lacks it (exported from 5.02).

Observed in community FW4 backports, two shapes (both only below 5.02, i.e. declared SDK 4.xx):
  * the binary imports DirNameSearch2 (PHnuI4LhuRk) but not DirNameSearch (dyIhnXq-0SM):
    the import's name in the dynamic string table is renamed to the older call (same-length
    NID swap, `#lib#module` suffix kept; PLT, GOT and relocation untouched);
  * it imports both: the lazy GOT slot of DirNameSearch2 (pre-image PLT+6) is pointed at the
    PLT stub of the DirNameSearch import, so calls of the newer API reach the older one.
The two APIs take differently sized requests; this is a lead from those backports, not
hardware-proved here, so the rule is never recommended automatically.

Statuses: PATCH / DONE (slot already forwarded; after a rename the binary no longer imports
Search2 and is simply not listed) / UNKNOWN (BIND_NOW, non-lazy slot, no standard PLT stub,
target above 4.xx).
"""
from __future__ import annotations

import struct

from .. import dynamic
from ..asm import plt_stubs
from . import Finding, RuleContext
from .bytefix import DONE, PATCH, UNKNOWN, EditRule, code_binaries, finding

SEARCH2 = "PHnuI4LhuRk"          # sceSaveDataDirNameSearch2 (first exported 5.02)
SEARCH = "dyIhnXq-0SM"           # sceSaveDataDirNameSearch
MAX_DECLARED = 4                 # 4.xx only: 5.00/5.01 are not covered by the evidence


def _bind_now(d) -> bool:
    return bool(d.tags.get(0x18) or any(v & 8 for v in d.tags.get(0x1E, [])) or
                any(v & 1 for v in d.tags.get(0x6FFFFFFB, [])))


def site(b, base: int) -> dict | None:
    d = dynamic.parse(b)
    if not d or SEARCH2 not in d.imported_nids():
        return None
    syms2 = [s for s in d.imports() if s.nid == SEARCH2]
    syms1 = [s for s in d.imports() if s.nid == SEARCH]
    if not syms1:
        if 5 not in d.tags or 0xA not in d.tags:
            return {"status": UNKNOWN, "why": "no string table"}
        strva = d.tags[5][0]
        strtab = b.read(strva, d.tags[0xA][0])
        edits = []
        for s in {x.name: x for x in syms2}.values():
            pat = b"\0" + s.name.encode() + b"\0"
            i = strtab.find(pat)
            if i < 0:
                return {"status": UNKNOWN, "why": f"{s.name} not found in the string table"}
            edits.append((base + strva + i + 1, SEARCH2.encode().hex(), SEARCH.encode().hex()))
        return {"status": PATCH, "mode": "rename", "edits": edits}
    # both imported: forward the lazy slot
    if _bind_now(d):
        return {"status": UNKNOWN, "why": "BIND_NOW: slots are resolved at load, a forward would be ignored"}
    by_nid = {n.split("#")[0]: va for n, va in plt_stubs(b, d, base).items()}
    s1, s2 = by_nid.get(SEARCH), by_nid.get(SEARCH2)
    if s1 is None or s2 is None:
        return {"status": UNKNOWN, "why": "no standard PLT stub for one of the two imports"}
    slot = next((g for g, n in d.plt.items() if n.split("#")[0] == SEARCH2), None)
    if slot is None:
        return {"status": UNKNOWN, "why": "no jump-slot relocation for DirNameSearch2"}
    cur = b.u64(slot)
    lazy, want = (s2 - base) + 6, s1 - base
    if cur == want:
        return {"status": DONE}
    if cur != lazy:
        return {"status": UNKNOWN, "why": f"GOT slot holds {cur:#x}, not the lazy PLT+6 ({lazy:#x})"}
    return {"status": PATCH, "mode": "forward",
            "edits": [(base + slot, struct.pack("<Q", lazy).hex(), struct.pack("<Q", want).hex())]}


class SavedataDirSearch(EditRule):
    name = "savedata-dirsearch"
    summary = "sceSaveDataDirNameSearch2 (5.02+) -> DirNameSearch: import rename, or GOT forward when both are imported"

    def detect(self, ctx: RuleContext) -> list[Finding]:
        out = []
        for bi in code_binaries(ctx, SEARCH2):
            s = site(ctx.load(bi.path), ctx.base_for(bi.path))
            if s is None:
                continue
            if ctx.declared_sdk > MAX_DECLARED:
                out.append(finding(self.name, bi.path, "DirNameSearch2 imported", UNKNOWN,
                                   reason=f"only evidenced for 4.xx builds; target is {ctx.declared_sdk}.xx"))
                continue
            if s["status"] == PATCH:
                what = ("import renamed to DirNameSearch" if s["mode"] == "rename"
                        else "DirNameSearch2 GOT slot forwarded to the DirNameSearch PLT stub")
                out.append(finding(self.name, bi.path, f"DirNameSearch2: {what}", PATCH,
                                   edits=[(va, o, n, what) for va, o, n in s["edits"]]))
            elif s["status"] == DONE:
                out.append(finding(self.name, bi.path, "DirNameSearch2 slot already forwarded", DONE,
                                   reason="already patched"))
            else:
                out.append(finding(self.name, bi.path, "DirNameSearch2 not handled", UNKNOWN, reason=s["why"]))
        return out
