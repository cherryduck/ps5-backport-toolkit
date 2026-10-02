"""Import coverage: decide, per system module a game needs, whether the target
firmware provides it or a fakelib from the kit library must replace it.

Per module M the game imports from:
  game     — the game ships M itself (sce_module/*.prx ...)
  system   — every needed NID is proven present on the target FW, none proven absent
  fakelib  — a kit fakelib for M exports every needed NID (it replaces the system M)
  partial  — best fakelib still misses some NIDs (listed)
  absent   — no fakelib known and some needed NIDs are proven ABSENT on the target
             (e.g. libkernel's Pro query on 4.xx): the game will fail unless patched
  unverified — no fakelib known, some NIDs lack evidence (usually fine; more kits help)
  missing  — not a system module and not shipped by the game
Fakelib choice: most needed NIDs covered; ties prefer kits targeting <= target FW,
then the highest such kit FW (closest to target), then most exports overall.
Fakelibs import from each other (libSceAgc -> libSceAgcDriver) and kits' builds are
matched pairs, so cross-fakelib imports are checked and repaired by switching one
side to the other's kit.  Remaining problems go to Coverage.deps.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import EvidenceDB, is_system_module
from .scan import GameScan


@dataclass
class Choice:
    kit: str
    kit_fw: int
    relpath: str
    sha256: str
    covered: int
    missing: list[str]
    exports: int


@dataclass
class ModuleResult:
    module: str
    status: str
    needed: list[str]
    users: list[str]
    proven: int = 0
    absent: list[str] = field(default_factory=list)       # needed NIDs proven absent on target
    unproven: list[str] = field(default_factory=list)     # needed NIDs with no evidence
    choice: Choice | None = None
    candidates: list[Choice] = field(default_factory=list)
    current: str = ""                                     # fakelib already in the game folder (sha256)


@dataclass
class Coverage:
    target: int
    modules: list[ModuleResult]
    deps: list[str] = field(default_factory=list)          # problems in chosen fakelibs' own imports
    nonsystem_missing: list[str] = field(default_factory=list)

    def fakelibs(self) -> list[ModuleResult]:
        return [m for m in self.modules if m.choice]

    def by_status(self, status: str) -> list[ModuleResult]:
        return [m for m in self.modules if m.status == status]


def _rank(c: Choice, target: int):
    return (c.covered, c.kit_fw <= target, c.kit_fw if c.kit_fw <= target else -c.kit_fw, c.exports)


def _choose(db: EvidenceDB, module: str, needed: set[str], target: int) -> list[Choice]:
    out = []
    for kit, f, exports in db.fakelib_candidates(module):
        out.append(Choice(kit.name, kit.fw, f.relpath, f.sha256, len(needed & exports),
                          sorted(needed - exports), len(exports)))
    return sorted(out, key=lambda c: _rank(c, target), reverse=True)


def _pair_fakelibs(cov: Coverage, db: EvidenceDB) -> None:
    """Make chosen fakelibs satisfy each other's imports, switching kits where needed."""
    chosen = {m.module: m for m in cov.modules if m.choice}
    for _ in range(4):
        changed = False
        for m in chosen.values():
            assert m.choice
            for dmod, dnids in db.fakelib_imports(m.choice.kit, m.choice.relpath).items():
                other = chosen.get(dmod)
                if not other or not other.choice:
                    continue
                if not dnids - db.exports_of(other.choice.kit, other.choice.relpath):
                    continue
                alt = next((c for c in other.candidates if c.kit == m.choice.kit and not c.missing), None)
                alt2 = next((c for c in m.candidates if c.kit == other.choice.kit and not c.missing), None)
                if alt:
                    other.choice, changed = alt, True
                elif alt2:
                    m.choice, changed = alt2, True
                break
        if not changed:
            break
    for m in chosen.values():
        assert m.choice
        for dmod, dnids in db.fakelib_imports(m.choice.kit, m.choice.relpath).items():
            other = chosen.get(dmod)
            if other and other.choice:
                lack = dnids - db.exports_of(other.choice.kit, other.choice.relpath)
                if lack:
                    cov.deps.append(f"CONFLICT: {m.module} ({m.choice.kit}) needs {len(lack)} NID(s) that "
                                    f"{dmod} ({other.choice.kit}) doesn't export: {', '.join(sorted(lack)[:5])}")


def analyze(gs: GameScan, db: EvidenceDB, target: int) -> Coverage:
    game_bins = [b for b in gs.binaries if b.role != "fakelib" and not b.error]
    shipped = {b.module for b in game_bins if b.role == "module"}
    current = {b.module: b.sha256 for b in gs.binaries if b.role == "fakelib"}
    need: dict[str, set[str]] = {}
    users: dict[str, set[str]] = {}
    for b in game_bins:
        for mod, nids in b.imports_by_module.items():
            need.setdefault(mod, set()).update(nids)
            users.setdefault(mod, set()).add(b.path)
    cov = Coverage(target, [])
    for mod in sorted(need):
        nids = need[mod]
        r = ModuleResult(mod, "", sorted(nids), sorted(users[mod]), current=current.get(mod, ""))
        if mod in shipped:
            r.status = "game"
            cov.modules.append(r)
            continue
        if not is_system_module(mod):
            r.status = "missing"
            cov.nonsystem_missing.append(mod)
            cov.modules.append(r)
            continue
        present, absent = db.present(mod, target), db.absent(mod, target)
        r.proven = len(nids & present)
        r.absent = sorted(nids & absent)
        r.unproven = sorted(nids - present - absent)
        r.candidates = _choose(db, mod, nids, target)
        system_ok = not r.absent and not r.unproven
        if system_ok:
            r.status = "system"
        elif r.candidates:
            r.choice = r.candidates[0]
            r.status = "fakelib" if not r.choice.missing else "partial"
        else:
            r.status = "absent" if r.absent else "unverified"
        cov.modules.append(r)
    _pair_fakelibs(cov, db)
    # dependencies of chosen fakelibs on the system
    provided = {m.module for m in cov.modules if m.choice} | shipped
    for m in cov.fakelibs():
        assert m.choice
        for dmod, dnids in db.fakelib_imports(m.choice.kit, m.choice.relpath).items():
            if dmod in provided or not is_system_module(dmod):
                continue
            missing = dnids - db.present(dmod, target)
            gone = dnids & db.absent(dmod, target)
            if gone:
                cov.deps.append(f"{m.module} ({m.choice.kit}) imports {len(gone)} NID(s) from {dmod} "
                                f"proven ABSENT on {target}.xx: {', '.join(sorted(gone)[:5])}")
            elif missing:
                cov.deps.append(f"{m.module} ({m.choice.kit}) imports {len(missing)} unproven NID(s) from {dmod}")
    return cov
