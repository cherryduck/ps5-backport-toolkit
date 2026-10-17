"""Firmware boundaries for generic rules, learned from kits (no original dumps needed).

On `kit add`, each probing rule counts in the kit's binaries how often its pattern
appears unfixed (e.g. Mount3 +0x18 = -1) and in the fixed form (0). Stored per kit with
the call-site addresses, so two kits of the same game build can be paired even without a
title id (signature = file name + executable segment layout).
  * unfixed in a kit for FW X           -> the unfixed form works on X (and above)
  * fixed in a kit for FW Y while a kit of the same build is unfixed
                                         -> the fix was needed on Y (and below)
These widen the rule's built-in prior (needed_max / ok_min). A prior marked `confirmed`
(tested on a console) wins over kit observations.
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
    t = getattr(ctx, "declared_sdk", ctx.target)      # declared SDK major, not the console FW (Phase 9b)
    conf = prior.get("confirmed")            # console-tested: beats what kits merely suggest
    if conf and t <= prior["needed_max"]:
        why = f"needed on {prior['needed_max']}.xx and below ({conf})"
        if ok <= t:
            why += f"; {src_o} left it unfixed — contradicted by that test"
        return True, why
    if t <= needed and t < ok:
        return True, f"needed on {needed}.xx and below ({src_n})"
    if t >= ok:
        return False, (f"left unfixed by {src_o} for {ok}.xx" if src_o.startswith("kit")
                       else f"not needed on {ok}.xx and above ({src_o})")
    return False, f"unknown on {t}.xx: needed on <= {needed}.xx, fine on >= {ok}.xx"


PROBING = ("savedata-mount", "wwise-71", "gamepresets-28", "savedata-prepare", "savedata-dirsearch",
           "tls-atexit", "set3-nonfatal", "frostbite-8ch")
# The phase-10c rules have no recommendation prior: their observations are recorded (kit, FW, signature)
# so a rule can later get one the way savedata-mount did, but nothing is recommended from them yet.


def _count(rows, key="status") -> tuple[int, int]:
    st = [r[key] for r in rows]
    return st.count("PATCH"), st.count("DONE")


def probe_10c(b, base: int, d) -> list[tuple[str, int, int]]:
    """(rule, unfixed, fixed) for the phase-10c rules whose import the binary has (d: dynamic.Dynamic)."""
    from . import frostbite_8ch, gamepresets, gates, savedata_dirsearch, savedata_prepare, set3_nonfatal, tls_atexit
    imports = d.imported_nids()
    probes = []
    if gamepresets.NID in imports:
        probes.append(("gamepresets-28", lambda: _count(gamepresets.sites(b, base))))
    if savedata_prepare.NID in imports:
        probes.append(("savedata-prepare", lambda: _count(savedata_prepare.sites(b, base))))
    if savedata_dirsearch.SEARCH2 in imports:
        probes.append(("savedata-dirsearch", lambda: _count([savedata_dirsearch.site(b, base) or {"status": ""}])))
    if tls_atexit.IMPL in imports:
        probes.append(("tls-atexit", lambda: _count([tls_atexit.site(b, base) or {"status": ""}])))
    if set3_nonfatal.SET3 in imports:
        def set3():
            loc = set3_nonfatal.Set3Nonfatal._locate(b)
            if not loc:
                return 0, 0
            calls, _ = gates.refs(b, loc[0], loc[1], base)
            nxt = [b.read(c + 5, 3) for c in calls]
            return (sum(1 for x in nxt if x[:2] == set3_nonfatal.TEST and x[2] == 0x74),
                    sum(1 for x in nxt if x[:2] == set3_nonfatal.TEST and x[2] == 0xEB))
        probes.append(("set3-nonfatal", set3))
    if any(m.startswith("libSceAudioOut2") for m in d.imports_by_module()):
        def fb():
            sc = frostbite_8ch.scan(b, base)
            return (0, 0) if sc["unknown"] else _count(sc["sites"])
        probes.append(("frostbite-8ch", fb))
    out = []
    for rule, fn in probes:
        try:
            u, f = fn()
        except Exception:                                # noqa: BLE001 — a probe never breaks ingest
            continue
        if u or f:
            out.append((rule, u, f))
    return out


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
        from .. import dynamic
        d = dynamic.parse(b)
        if d:
            for rule, u, f in probe_10c(b, base, d):
                out.append((rule, u, f, sig))
    except Exception:                                    # noqa: BLE001 — a probe never breaks ingest
        pass
    return out
