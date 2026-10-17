"""Advice shown by `analyze` (and the GUI): text only, nothing is changed.

Ampr: the Ampr emulation layer a dump ships is kept by default (it is a loading layer, not a
firmware fakelib).  In community FW4 backports of Unity titles, and of titles importing exactly
101 libSceAmpr NIDs, the native Ampr path broke content loading (`apr_resolve_vnode` errors /
no audio) and a kit's Ampr emulation fixed it — so for those two profiles analyze recommends
replacing the dump's Ampr with a kit's through --replace-dump-fakelib.  Not a rule: which Ampr
build works is title-specific, and ps5bp never swaps it on its own.
"""
from __future__ import annotations

from .coverage import Coverage
from .scan import GameScan

AMPR_IMPORT_PROFILES = (101,)
UNITY_MARKERS = ("unityplayer", "libunity", "libil2cpp", "gameassembly")


def is_unity(gs: GameScan) -> bool:
    for b in gs.binaries:
        low = b.path.lower().replace("\\", "/")
        if "media/plugins/" in low or any(m in low.rsplit("/", 1)[-1] for m in UNITY_MARKERS):
            return True
        if any(m in (b.module or "").lower() for m in UNITY_MARKERS):
            return True
    return False


def ampr_import_count(gs: GameScan) -> int:
    nids: set[str] = set()
    for b in gs.binaries:
        if b.role == "fakelib" or b.error:
            continue
        for mod, ns in b.imports_by_module.items():
            if mod.startswith("libSceAmpr"):
                nids |= set(ns)
    return len(nids)


def ampr_advice(gs: GameScan, cov: Coverage | None) -> list[str]:
    """Advice lines when the dump's Ampr is kept for a Unity title or a known-import profile."""
    if cov is None:
        return []
    out = []
    for m in cov.modules:
        if not m.module.startswith("libSceAmpr") or m.status != "dump":
            continue
        why = []
        if is_unity(gs):
            why.append("a Unity engine title (Media/Plugins or UnityPlayer modules)")
        n = ampr_import_count(gs)
        if n in AMPR_IMPORT_PROFILES:
            why.append(f"imports exactly {n} libSceAmpr NIDs")
        if not why:
            continue
        have = sorted({c.kit for c in m.candidates})
        out.append(f"{m.module}: the dump's Ampr is kept, but this is {' and '.join(why)} — community FW4 "
                   "backports of such titles needed a kit's Ampr emulation (content-loading errors / no audio "
                   f"otherwise). Consider --replace-dump-fakelib {m.module}"
                   + (f"[=KIT]  (kits with a {m.module}: {', '.join(have)})" if have else
                      "=KIT after `ps5bp kit add` of a kit that ships one"))
    return out
