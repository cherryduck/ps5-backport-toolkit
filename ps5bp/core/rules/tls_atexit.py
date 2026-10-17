"""tls-atexit: libc `__cxa_thread_atexit` -> local `__cxa_atexit` on firmware before 11.00.

Newer libc builds implement `__cxa_thread_atexit` (BKSCW2bCACA) as a thin wrapper that calls
an import, qBS714-Jr3g, which the system only exports from 11.00 on:

    push rbp ; mov rbp, rsp ; call PLT(qBS714-Jr3g) ; pop rbp ; ret

Earlier firmware leaves the import unresolved (crash the first time a C++ thread_local with a
destructor is created). Observed in community FW4 backports (three libc builds, 1.87-1.92 MB):
the call is redirected to libc's own `__cxa_atexit` (tsvEmnenz48), which has the same
(dtor, obj, dso) signature - destructors then run at process exit instead of thread exit.

Detector: the binary imports qBS714-Jr3g, exports both functions, and the export's body is
exactly the five-instruction wrapper above. Call -> PLT stub: PATCH (rel32 -> the local
export); call -> local __cxa_atexit already: DONE; any other body: UNKNOWN.
"""
from __future__ import annotations

import struct

from .. import dynamic
from ..asm import plt_stubs, stub_for
from . import Finding, RuleContext
from .bytefix import DONE, PATCH, UNKNOWN, EditRule, code_binaries, finding

IMPL = "qBS714-Jr3g"             # imported thread-exit registration (exported by the system from 11.00)
WRAPPER = "BKSCW2bCACA"          # __cxa_thread_atexit
LOCAL = "tsvEmnenz48"            # __cxa_atexit
HEAD, TAIL = bytes.fromhex("554889e5e8"), bytes.fromhex("5dc3")


def site(b, base: int) -> dict | None:
    d = dynamic.parse(b)
    if not d or IMPL not in d.imported_nids():
        return None
    ex = {s.nid: s.value for s in d.exports()}
    if WRAPPER not in ex or LOCAL not in ex:
        return {"status": UNKNOWN, "why": "imports the thread-exit call but does not export both "
                "__cxa_thread_atexit and __cxa_atexit"}
    w = base + ex[WRAPPER]
    body = b.read(w - base, 11)
    if body[:5] != HEAD or body[9:11] != TAIL:
        return {"status": UNKNOWN, "why": f"__cxa_thread_atexit body is not the expected wrapper ({body.hex()})"}
    tgt = w + 9 + struct.unpack_from("<i", body, 5)[0]
    local = base + ex[LOCAL]
    stub = stub_for(plt_stubs(b, d, base), IMPL)
    new = struct.pack("<i", local - (w + 9))
    row = {"va": w + 5, "old": body[5:9].hex(), "new": new.hex(), "local": local}
    if tgt == local:
        return {**row, "status": DONE}
    if stub is not None and tgt == stub:
        return {**row, "status": PATCH}
    return {**row, "status": UNKNOWN, "why": f"call target {tgt:#x} is neither the import's PLT stub nor __cxa_atexit"}


class TlsAtexit(EditRule):
    name = "tls-atexit"
    summary = "libc __cxa_thread_atexit -> local __cxa_atexit (the wrapped import exists only from 11.00)"
    EXPORTED_FROM = 11

    def detect(self, ctx: RuleContext) -> list[Finding]:
        rec = ctx.declared_sdk < self.EXPORTED_FROM
        why = f"the wrapped import is first exported by the system in {self.EXPORTED_FROM}.00" if rec else ""
        out = []
        for bi in code_binaries(ctx, IMPL):
            s = site(ctx.load(bi.path), ctx.base_for(bi.path))
            if s is None:
                continue
            if s["status"] == PATCH:
                out.append(finding(self.name, bi.path, f"{s['va'] - 5:#x}: __cxa_thread_atexit calls the missing "
                                   f"import -> local __cxa_atexit ({s['local']:#x})", PATCH, recommended=rec,
                                   reason=why, edits=[(s["va"], s["old"], s["new"],
                                                       "__cxa_thread_atexit -> local __cxa_atexit")]))
            elif s["status"] == DONE:
                out.append(finding(self.name, bi.path, f"{s['va'] - 5:#x}: __cxa_thread_atexit already calls the "
                                   "local __cxa_atexit", DONE, reason="already patched"))
            else:
                out.append(finding(self.name, bi.path, "__cxa_thread_atexit wrapper not recognised", UNKNOWN,
                                   reason=s["why"]))
        return out
