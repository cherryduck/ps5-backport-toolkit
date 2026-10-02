"""Kit library + firmware evidence database.

A *kit* is the file set of an existing backport (fakelib/, patched game binaries,
extras like k9.psp) labelled with the firmware its author targeted. Ingesting a kit:

  * copies fakelib/*.sprx|prx and extras into the kit store (small; eboot is NOT kept)
  * records each fakelib's module name and exported NIDs  -> what a fakelib can supply
  * records "present" evidence: every import (module, NID) made by any binary in the
    kit to a system module the kit does NOT replace was resolved by the firmware
  * records "absent" evidence: imports a backporter bound to a local stub
  * records PLT stubs: imports whose PLT entry a backporter overwrote in place
    (`xor eax,eax; ret`, `ud2`, out-param writes ...), with the exact stub body, so the
    same stub can be reused for other games (rule kit-stubs). Such NIDs are NOT counted
    as present, even though the binary still imports them.
  * `tested_fw`: the firmware a kit was actually run on, if not the one it targets.
    "Present" evidence is weak (a backporter may leave an import in place that never
    resolves or is never called), so it is recorded at the tested FW, not the target.
  * Ampr / PlayGo emulation fakelibs are stored (used when a dump has none) but are not
    firmware evidence.

Evidence is only recorded for system-named modules (libkernel, libSce*), so that
middleware shipped inside games (libcohtml, libRenoirCore ...) can't masquerade as
firmware libraries.

Firmware ordering: present on FW X => present on every FW >= X;
absent on FW X  => absent on every FW <= X.
"""
from __future__ import annotations

import datetime
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .scan import BinaryInfo, is_loading_layer, iter_binaries, scan_binary

SYSTEM_MODULE = re.compile(r"^(libkernel|libSce\w*)$")
EXTRA_EXTS = {".psp"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS kits (name TEXT PRIMARY KEY, fw INTEGER NOT NULL, source TEXT,
    title_id TEXT, added TEXT, store TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS stubs (kit TEXT, relpath TEXT, module TEXT, nid TEXT, body TEXT,
    fw INTEGER);
CREATE TABLE IF NOT EXISTS files (kit TEXT, relpath TEXT, role TEXT, module TEXT, sha256 TEXT,
    sdk_ps5 INTEGER, PRIMARY KEY (kit, relpath));
CREATE TABLE IF NOT EXISTS exports (kit TEXT, relpath TEXT, module TEXT, nid TEXT);
CREATE TABLE IF NOT EXISTS evidence (fw INTEGER, module TEXT, nid TEXT, present INTEGER,
    kit TEXT, via TEXT);
CREATE INDEX IF NOT EXISTS ev_idx ON evidence (module, nid);
CREATE INDEX IF NOT EXISTS ex_idx ON exports (module, nid);
"""


def is_system_module(name: str) -> bool:
    return bool(SYSTEM_MODULE.match(name))


def home() -> Path:
    if os.environ.get("PS5BP_HOME"):
        return Path(os.environ["PS5BP_HOME"])
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "ps5bp"


@dataclass
class Kit:
    name: str
    fw: int
    source: str
    title_id: str
    added: str
    store: Path
    tested_fw: int | None = None

    def path(self, relpath: str) -> Path:
        return self.store / relpath


@dataclass
class KitFile:
    kit: str
    relpath: str
    role: str
    module: str
    sha256: str
    sdk_ps5: int | None


def find_kit_root(d: Path) -> Path:
    """The directory holding fakelib/ (kits are often nested one or two levels)."""
    if (d / "fakelib").is_dir():
        return d
    for p in sorted(d.rglob("fakelib")):
        if p.is_dir() and len(p.relative_to(d).parts) <= 4:
            return p.parent
    raise ValueError(f"{d}: no fakelib/ directory found — not a backport kit")


class EvidenceDB:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root else home()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.root / "evidence.db")
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(kits)")}
        if "tested_fw" not in cols:                       # migrate older databases
            self.db.execute("ALTER TABLE kits ADD COLUMN tested_fw INTEGER")
            self.db.commit()

    def close(self) -> None:
        self.db.close()

    # ---- kits -----------------------------------------------------------
    def kits(self) -> list[Kit]:
        rows = self.db.execute("SELECT name, fw, source, title_id, added, store, tested_fw FROM kits ORDER BY name")
        return [Kit(n, fw, s or "", t or "", a, Path(st), tf) for n, fw, s, t, a, st, tf in rows]

    def kit(self, name: str) -> Kit | None:
        return next((k for k in self.kits() if k.name == name), None)

    def kit_files(self, kit: str | None = None) -> list[KitFile]:
        q = "SELECT kit, relpath, role, module, sha256, sdk_ps5 FROM files"
        rows = self.db.execute(q + (" WHERE kit=?" if kit else ""), (kit,) if kit else ())
        return [KitFile(*r) for r in rows]

    def remove_kit(self, name: str) -> bool:
        k = self.kit(name)
        if not k:
            return False
        for t in ("kits", "files", "exports", "evidence", "stubs"):
            col = "name" if t == "kits" else "kit"
            self.db.execute(f"DELETE FROM {t} WHERE {col}=?", (name,))
        self.db.commit()
        if k.store.is_dir() and k.store.is_relative_to(self.root):
            shutil.rmtree(k.store)
        return True

    def add_kit(self, src: Path | str, fw: int, name: str | None = None, source: str = "",
                replace: bool = False, tested_fw: int | None = None) -> dict:
        src = Path(src)
        with tempfile.TemporaryDirectory(prefix="ps5bp-kit-") as tmp:
            if src.is_file() and zipfile.is_zipfile(src):
                with zipfile.ZipFile(src) as z:
                    z.extractall(tmp)
                base = Path(tmp)
            elif src.is_dir():
                base = src
            else:
                raise ValueError(f"{src}: not a directory or zip")
            root = find_kit_root(base)
            name = name or re.sub(r"[^\w.+-]+", "_", src.stem if src.is_file() else src.name).strip("_")
            if self.kit(name):
                if not replace:
                    raise ValueError(f"kit '{name}' already exists (use --replace)")
                self.remove_kit(name)
            return self._ingest(root, fw, name, source, tested_fw)

    def _ingest(self, root: Path, fw: int, name: str, source: str, tested_fw: int | None = None) -> dict:
        infos: list[BinaryInfo] = []
        for p in iter_binaries(root):
            rel = p.relative_to(root)
            role = "fakelib" if rel.parts[0] == "fakelib" else ("eboot" if str(rel) == "eboot.bin" else "module")
            infos.append(scan_binary(p, root, role))
        bad = [i for i in infos if i.error]
        if bad:
            raise ValueError("unreadable kit binaries: " + "; ".join(f"{i.path}: {i.error}" for i in bad))
        title_id = ""
        pj = root / "sce_sys" / "param.json"
        if pj.is_file():
            from .paramjson import ParamJson
            try:
                title_id = ParamJson.load(pj).title_id
            except ValueError:
                pass
        store = self.root / "kits" / name
        if store.exists():
            shutil.rmtree(store)
        store.mkdir(parents=True)
        for i in infos:
            if i.role == "fakelib":
                (store / i.path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(root / i.path, store / i.path)
        extras = [p for p in root.iterdir() if p.is_file() and p.suffix.lower() in EXTRA_EXTS]
        for p in extras:
            shutil.copy2(p, store / p.name)
        replaced = {i.module for i in infos if i.role == "fakelib"}
        game_mods = {i.module for i in infos if i.role != "fakelib"}
        c = self.db.cursor()
        c.execute("INSERT INTO kits (name, fw, source, title_id, added, store, tested_fw) VALUES (?,?,?,?,?,?,?)",
                  (name, fw, source, title_id, datetime.datetime.now().isoformat(timespec="seconds"), str(store),
                   tested_fw))
        present_fw = max(fw, tested_fw) if tested_fw is not None else fw
        n_present = n_absent = n_stubs = 0
        for i in infos:
            c.execute("INSERT INTO files VALUES (?,?,?,?,?,?)",
                      (name, i.path, i.role, i.module, i.sha256, i.sdk_ps5))
            if i.role == "fakelib":
                c.executemany("INSERT INTO exports VALUES (?,?,?,?)",
                              [(name, i.path, i.module, n) for n in i.exports])
            for mod, stubs in i.plt_patched.items():
                if not is_system_module(mod):
                    continue
                c.executemany("INSERT INTO stubs VALUES (?,?,?,?,?,?)",
                              [(name, i.path, mod, n, body, fw) for n, body in stubs.items()])
                n_stubs += len(stubs)
            if i.role == "fakelib" and is_loading_layer(i.module):
                continue                                   # emulation layer: not FW evidence
            for mod, nids in i.imports_by_module.items():
                if mod in replaced or mod in game_mods or not is_system_module(mod):
                    continue
                keep = [n for n in nids if n not in i.plt_patched.get(mod, {})]
                c.executemany("INSERT INTO evidence VALUES (?,?,?,1,?,?)",
                              [(present_fw, mod, n, name, i.path) for n in keep])
                n_present += len(keep)
            for mod, nids in i.stubbed_by_module.items():
                if not is_system_module(mod):
                    continue
                c.executemany("INSERT INTO evidence VALUES (?,?,?,0,?,?)",
                              [(fw, mod, n, name, i.path) for n in nids])
                n_absent += len(nids)
        self.db.commit()
        return {"name": name, "fw": fw, "root": str(root), "title_id": title_id,
                "fakelibs": sorted(i.path for i in infos if i.role == "fakelib"),
                "extras": [p.name for p in extras], "present": n_present, "absent": n_absent,
                "plt_stubs": n_stubs, "present_fw": present_fw}

    # ---- queries --------------------------------------------------------
    def present(self, module: str, target: int) -> set[str]:
        """NIDs proven present in system `module` on firmware `target`."""
        rows = self.db.execute("SELECT DISTINCT nid FROM evidence WHERE module=? AND present=1 AND fw<=?",
                               (module, target))
        return {r[0] for r in rows}

    def absent(self, module: str, target: int) -> set[str]:
        rows = self.db.execute("SELECT DISTINCT nid FROM evidence WHERE module=? AND present=0 AND fw>=?",
                               (module, target))
        return {r[0] for r in rows}

    def stubbed(self, module: str, target: int) -> dict[str, list[tuple[str, str, int, str]]]:
        """NIDs of `module` some kit replaced with a PLT stub for a FW >= target:
        nid -> [(kit, body hex, kit fw, relpath)]."""
        out: dict[str, list[tuple[str, str, int, str]]] = {}
        for kit, rel, nid, body, fw in self.db.execute(
                "SELECT kit, relpath, nid, body, fw FROM stubs WHERE module=? AND fw>=?", (module, target)):
            out.setdefault(nid, []).append((kit, body, fw, rel))
        return out

    def fakelib_candidates(self, module: str) -> list[tuple[Kit, KitFile, set[str]]]:
        out = []
        kits = {k.name: k for k in self.kits()}
        for f in self.kit_files():
            if f.role == "fakelib" and f.module == module and f.kit in kits:
                rows = self.db.execute("SELECT nid FROM exports WHERE kit=? AND relpath=?", (f.kit, f.relpath))
                out.append((kits[f.kit], f, {r[0] for r in rows}))
        return out

    def exports_of(self, kit: str, relpath: str) -> set[str]:
        rows = self.db.execute("SELECT nid FROM exports WHERE kit=? AND relpath=?", (kit, relpath))
        return {r[0] for r in rows}

    def fakelib_imports(self, kit: str, relpath: str) -> dict[str, set[str]]:
        """Imports of a stored fakelib, by module (re-scanned from the kit store, cached)."""
        key = (kit, relpath)
        cache = self.__dict__.setdefault("_imp_cache", {})
        if key not in cache:
            k = self.kit(kit)
            info = scan_binary(k.path(relpath), k.store, "fakelib") if k else None
            cache[key] = {m: set(v) for m, v in info.imports_by_module.items()} if info else {}
        return cache[key]
