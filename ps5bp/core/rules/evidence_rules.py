"""Firmware boundaries for generic rules, learned from kits (no original dumps needed).

On `kit add`, each probing rule counts in the kit's binaries how often its pattern
appears unfixed (e.g. Mount3 +0x18 = -1) and in the fixed form (0). Stored per kit with
the call-site addresses, so two kits of the same game build can be paired even without a
title id (signature = file name + executable segment layout).
  * unfixed in a kit for FW X           -> the unfixed form works on X (and above)
  * fixed in a kit for FW Y while a kit of the same build is unfixed
                                         -> the fix was needed on Y (and below)
These widen the rule's built-in prior (needed_max / ok_min).
"""
from __future__ import annotations

from pathlib import Path


def recommendation(rule: str, ctx, prior: dict) -> tuple[bool, str]:
    needed, ok = prior["needed_max"], prior["ok_min"]
    src_n, src_o = "built-in evidence", "built-in evidence"
    db = (ctx.options or {}).get("db")
    if db is not None:
        rows = db.rule_observations(rule)
        for r in rows:
            fw_ok = r["tested_fw"] or r["fw"]
            if r["unfixed"] and fw_ok < ok:
                ok, src_o = fw_ok, f"kit {r['kit']}"
        for r in rows:
            if r["fixed"] and not r["unfixed"] and any(o["unfixed"] and o["sig"] == r["sig"] and o is not r
                                                       for o in rows) and r["fw"] >= needed:
                needed, src_n = r["fw"], f"kit {r['kit']} fixed it"
    t = ctx.target
    if t <= needed and t < ok:
        return True, f"needed on {needed}.xx and below ({src_n})"
    if t >= ok:
        return False, (f"left unfixed by {src_o} for {ok}.xx" if src_o.startswith("kit")
                       else f"not needed on {ok}.xx and above ({src_o})")
    return False, f"unknown on {t}.xx: needed on <= {needed}.xx, fine on >= {ok}.xx"


PROBING = ("savedata-mount", "wwise-71")


def probe_kit(path, role: str) -> list[tuple[str, int, int, str]]:
    """(rule, unfixed, fixed, signature) for one kit binary."""
    from ..binary import Binary
    from .savedata_mount import SavedataMount, sites as sd_sites
    from .wwise71 import Wwise71
    out = []
    try:
        b = Binary.load(path)
    except Exception:                                    # noqa: BLE001
        return out
    base = 0x400000 if role == "eboot" else 0
    ex = [p for p in b.loads() if p.is_exec]
    sig = f"{Path(path).name}:{ex[0].vaddr:x}:{ex[0].filesz:x}" if ex else Path(path).name
    try:
        if sd_sites(b, base):
            out.append(("savedata-mount", *SavedataMount.probe(b, base), sig))
        u, f = Wwise71.probe(b, base)
        if u or f:
            out.append(("wwise-71", u, f, sig))
    except Exception:                                    # noqa: BLE001 — a probe never breaks ingest
        pass
    return out
