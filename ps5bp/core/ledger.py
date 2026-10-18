"""Apply safety: a per-user ledger of every file ps5bp wrote, plus helpers shared by build/undo.

`$PS5BP_HOME/applied.json` (same home as the kits) maps sha256 -> where ps5bp produced that
file. `build` hashes the input files it reads or would replace; one that is a known ps5bp
output means an earlier overlay was copied over the game, and backing it up as an "original"
would preserve patched files. Reports also carry input/output hashes so `undo` can verify.

Also here: case-insensitive member lookup (dumps copied through FAT/exFAT/Windows change case).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable

from .evidence import home

VERSION = 1


def ledger_path() -> Path:
    return home() / "applied.json"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def hash_files(root: Path, rels: list[str]) -> dict[str, str]:
    """rel -> sha256 for the files that exist (sorted by path)."""
    return {r: sha256_file(root / r) for r in sorted(set(rels)) if (root / r).is_file()}


def _warn_default(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def load(warn: Callable[[str], None] = _warn_default) -> list[dict]:
    """The ledger's entries. A corrupt file is kept as applied.json.bak and replaced by an empty ledger."""
    p = ledger_path()
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as e:
        warn(f"cannot read the ps5bp ledger {p}: {e} — treating it as empty")
        return []
    try:
        data = json.loads(raw)
        entries = data["entries"]
        if not isinstance(entries, list) or not all(isinstance(e, dict) and "sha256" in e for e in entries):
            raise ValueError("unexpected structure")
    except (ValueError, KeyError, TypeError) as e:
        bak = p.with_name(p.name + ".bak")
        try:
            os.replace(p, bak)
            kept = f"kept as {bak}"
        except OSError:
            kept = "could not be moved aside"
        warn(f"the ps5bp ledger {p} is corrupt ({e}); {kept}, starting a fresh ledger")
        return []
    return entries


def _save(entries: list[dict]) -> None:
    p = ledger_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=p.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": VERSION, "entries": entries}, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def record(files: dict[str, str], *, title_id: str, out: str, built: str, tool: str, target: str,
           warn: Callable[[str], None] = _warn_default) -> None:
    """Add `files` (rel -> sha256) as outputs of one build. Failure to write only warns."""
    if not files:
        return
    try:
        entries = load(warn)
        new = [{"sha256": h, "path": rel, "title_id": title_id, "out": out, "built": built,
                "tool": tool, "target": target} for rel, h in sorted(files.items())]
        keys = {(e["sha256"], e["path"], e["out"]) for e in new}
        entries = [e for e in entries if (e.get("sha256"), e.get("path"), e.get("out")) not in keys] + new
        _save(entries)
    except OSError as e:
        warn(f"could not update the ps5bp ledger {ledger_path()}: {e}")


def known_outputs(inputs: dict[str, str], warn: Callable[[str], None] = _warn_default) -> dict[str, dict]:
    """rel -> the (latest) ledger entry whose sha256 equals that input file's."""
    entries = load(warn)
    by_sha: dict[str, dict] = {}
    for e in entries:
        by_sha[e["sha256"]] = e
    return {rel: by_sha[h] for rel, h in inputs.items() if h in by_sha}


# ---- case-insensitive member lookup ----------------------------------------------------
CASE_INSENSITIVE_FS = sys.platform in ("win32", "darwin")


class AmbiguousMember(Exception):
    pass


def resolve_member(root: Path, rel: str) -> str:
    """The game-relative path `rel` as it is actually spelled under `root`.

    The exact path wins. Otherwise each component is matched case-insensitively against the
    directory listing; exactly one candidate is required (several -> AmbiguousMember). A
    component that matches nothing, and everything after it, is kept as given (the file may
    legitimately not exist).

    On a case-insensitive filesystem (Windows, macOS) `exists()` says yes for any spelling, so
    every component is checked against the real directory listing instead."""
    if not CASE_INSENSITIVE_FS and (root / rel).exists():
        return rel
    cur = root
    parts = Path(rel).parts
    out: list[str] = []
    for i, part in enumerate(parts):
        if not CASE_INSENSITIVE_FS and (cur / part).exists():
            out.append(part)
            cur = cur / part
            continue
        try:
            names = os.listdir(cur) if cur.is_dir() else []
        except OSError:
            names = []
        if part in names:
            out.append(part)
            cur = cur / part
            continue
        hits = [n for n in names if n.casefold() == part.casefold()]
        if len(hits) > 1:
            raise AmbiguousMember(f"{rel}: '{part}' matches {len(hits)} entries that differ only in case "
                                  f"({', '.join(sorted(hits))}) in {cur}")
        if not hits:
            return Path(*out, *parts[i:]).as_posix() if out or parts[i:] else rel
        out.append(hits[0])
        cur = cur / hits[0]
    return Path(*out).as_posix()
