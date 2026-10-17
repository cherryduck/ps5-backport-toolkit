"""Fix rules: detect a known backport problem in a game and (optionally) patch it.

Each rule's detect() is read-only and returns Findings; apply() edits working copies
obtained from ctx.load() and records every change with ctx.edit().  All writes go
through Binary.patch/add_cave, so the pipeline's verification step covers them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..binary import Binary
from ..coverage import Coverage
from ..scan import GameScan

EBOOT_BASE = 0x400000


@dataclass
class Finding:
    rule: str
    file: str
    title: str
    applicable: bool = True
    recommended: bool = False
    reason: str = ""                 # why not applicable / why recommended
    data: dict = field(default_factory=dict)


@dataclass
class RuleContext:
    gs: GameScan
    cov: Coverage | None
    target: int          # the build's DECLARED SDK major (BuildOptions.target), never the console FW
    load: Callable[[str], Binary]                 # working copy of a game-relative file
    edit: Callable[..., None]                     # edit(file, kind, offset, old, new, note)
    options: dict = field(default_factory=dict)   # rule-specific (e.g. user-patch paths)

    @property
    def declared_sdk(self) -> int:
        """Declared SDK major of the build. Fix recommendations key on this, not on the console
        firmware: the game's runtime behaviour follows the SDK it declares (Phase 9b: savedata-mount
        and wwise-71 on a Pro 11.60 with SDK-4 builds). Same value as `target` for a normal build."""
        return self.target

    def base_for(self, rel: str) -> int:
        return EBOOT_BASE if rel == "eboot.bin" else 0


class Rule:
    name = ""
    summary = ""
    default = False
    conflicts: tuple[str, ...] = ()

    def detect(self, ctx: RuleContext) -> list[Finding]:
        raise NotImplementedError

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        raise NotImplementedError


def registry() -> dict[str, Rule]:
    from .pro import ProDisable
    from .stub_absent import StubAbsent
    from .pssr_memory import PssrMemory
    from .user_patch import UserPatch
    from .kit_stubs import KitStubs
    from .mapflex_flags import MapflexFlags
    from .savedata_mount import SavedataMount
    from .wwise71 import Wwise71
    from .compat_stubs import CompatStubs
    from .set3_nonfatal import Set3Nonfatal
    from .gamepresets import GamePresets28
    from .tls_atexit import TlsAtexit
    from .savedata_prepare import SavedataPrepare
    from .savedata_dirsearch import SavedataDirSearch
    from .frostbite_8ch import Frostbite8ch
    rules = [ProDisable(), PssrMemory(), SavedataMount(), Wwise71(), Set3Nonfatal(), GamePresets28(), TlsAtexit(),
             SavedataPrepare(), SavedataDirSearch(), Frostbite8ch(), KitStubs(), CompatStubs(), MapflexFlags(),
             StubAbsent(), UserPatch()]
    return {r.name: r for r in rules}


def resolve(enabled: set[str], disabled: set[str]) -> list[Rule]:
    reg = registry()
    unknown = (enabled | disabled) - set(reg)
    if unknown:
        raise ValueError(f"unknown rule(s): {', '.join(sorted(unknown))} (have: {', '.join(reg)})")
    active = [r for r in reg.values() if (r.default or r.name in enabled) and r.name not in disabled]
    names = {r.name for r in active}
    for r in active:
        clash = names & set(r.conflicts)
        if clash:
            raise ValueError(f"rule {r.name} conflicts with {', '.join(sorted(clash))}")
    return active


def detect_all(ctx: RuleContext) -> list[Finding]:
    out: list[Finding] = []
    for r in registry().values():
        if r.name == "user-patch" and not ctx.options.get("patches"):
            continue
        out += r.detect(ctx)
    return out


def file_loader(game: Path) -> Callable[[str], Binary]:
    cache: dict[str, Binary] = {}

    def load(rel: str) -> Binary:
        if rel not in cache:
            cache[rel] = Binary.load(game / rel)
        return cache[rel]
    return load
