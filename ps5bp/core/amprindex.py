"""The Ampr emulator's `ampr_emu.index` (AMPRIDX3): reader, writer, tree walker, version sniffing.

The index lists every file under /app0 (path, size, mtime) so the emulator can answer stat()
and assign APR file ids without touching a (possibly read-only) image. It is trusted at run
time: a stale index serves wrong sizes, and adding/removing a path renumbers the file ids
(record number + 1) that AMPRPAK4 asset packs (`ampr_assets.index`) are bound to.

File layout (little endian):
  header  '<8sIIQQQII'  b'AMPRIDX3', version 3, record size (24), entries, path-blob length,
                        hash offset, hash slot size (16), slot count
  records '<IIQq'       path offset into the blob, path length (no NUL), size, mtime (seconds)
  blob                  each path as UTF-8 + NUL, in record order
  padding               zeros up to a 16-byte aligned hash offset
  slots   '<QII'        FNV-1a-64 of the key, record number + 1 (0 = empty), flags (1 = another
                        path shares this 64-bit hash)
Paths are '/app0/' + the relative POSIX path; records are sorted by the key (the path with
ASCII A-Z folded to lower case, nothing else). Slot count = smallest power of two >= 2 * entries
(minimum 2), open addressing with linear probing.

This is an independent implementation of that published format.
"""
from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

MAGIC = b"AMPRIDX3"
INDEX_NAME = "ampr_emu.index"
HEADER = struct.Struct("<8sIIQQQII")
RECORD = struct.Struct("<IIQq")
SLOT = struct.Struct("<QII")
FNV_OFFSET, FNV_PRIME, MASK64 = 1469598103934665603, 1099511628211, 0xFFFFFFFFFFFFFFFF
EMU_LIB = "fakelib/libsceampr.sprx"                      # lower-cased key of the emulator file
PACK_NAMES = ("ampr_assets.index", "ampr_assets.index.crc", "ampr_assets.index.runtime")
# never listed: the index itself and its temp/backup files, the emulator's own command/log files
_SKIP_ROOT = {INDEX_NAME, INDEX_NAME + ".tmp", INDEX_NAME + ".bak", "ampr_commands.bin", "apr_emu.log"}
# files ps5bp itself puts into an output folder; not part of the game
_TOOL_FILES = {"backport-report.json", "backport-report.txt", "memfix-recipe.json"}


class AmprIndexError(Exception):
    pass


@dataclass
class Entry:
    path: str          # '/app0/...'
    size: int
    mtime: int


@dataclass
class Index:
    entries: list[Entry] = field(default_factory=list)       # record order

    def keys(self) -> dict[bytes, Entry]:
        return {key_for(e.path): e for e in self.entries}


# ---- keys / hashing -----------------------------------------------------------------------
def key_for(path: str) -> bytes:
    """Backslashes -> '/', UTF-8, then fold only ASCII A-Z (matches the runtime, unlike str.lower())."""
    raw = path.replace("\\", "/").encode("utf-8")
    return bytes((b + 0x20) if 0x41 <= b <= 0x5A else b for b in raw)


def path_hash(path: str) -> int:
    h = FNV_OFFSET
    for byte in key_for(path):
        h ^= byte
        h = (h * FNV_PRIME) & MASK64
    return h or 1


def slot_count(entries: int) -> int:
    if entries <= 0 or entries > 0xFFFFFFFE:
        raise AmprIndexError("invalid index entry count")
    n = 2
    while n < entries * 2:
        n <<= 1
    return n


def build_hash_slots(paths: list[str]) -> list[tuple[int, int, int]]:
    """(hash, record+1, flags) per slot for records in the given order."""
    slots = [(0, 0, 0)] * slot_count(len(paths))
    mask = len(slots) - 1
    for i, p in enumerate(paths):
        h = path_hash(p)
        pos = h & mask
        dup = False
        while slots[pos][1] != 0:
            if slots[pos][0] == h:
                oh, oi, of = slots[pos]
                slots[pos] = (oh, oi, of | 1)
                dup = True
            pos = (pos + 1) & mask
        slots[pos] = (h, i + 1, 1 if dup else 0)
    return slots


# ---- writer -------------------------------------------------------------------------------
def build(rows: Iterable[tuple[str, int, int]], allow_collisions: bool = False) -> bytes:
    """AMPRIDX3 bytes for (path '/app0/...', size, mtime) rows, in any order.

    Paths with tab / CR / LF are skipped. Two paths with the same key (differ only in ASCII case)
    raise AmprIndexError, or with allow_collisions keep the first in sorted order."""
    seen: dict[bytes, str] = {}
    keep: list[tuple[bytes, str, int, int]] = []
    for path, size, mtime in sorted(rows, key=lambda r: (key_for(r[0]), r[0])):
        if any(c in path for c in "\t\n\r"):
            continue
        k = key_for(path)
        if k in seen:
            if not allow_collisions:
                raise AmprIndexError(f"case-insensitive path collision: {seen[k]} <-> {path}")
            continue
        seen[k] = path
        keep.append((k, path, int(size), int(mtime)))
    if not keep:
        raise AmprIndexError("no files to index")
    blob, recs = bytearray(), bytearray()
    for _, path, size, mtime in keep:
        enc = path.encode("utf-8")
        recs += RECORD.pack(len(blob), len(enc), size, mtime)
        blob += enc + b"\0"
    slots = build_hash_slots([p for _, p, _, _ in keep])
    end = HEADER.size + len(recs) + len(blob)
    hash_off = (end + SLOT.size - 1) & ~(SLOT.size - 1)
    out = bytearray(HEADER.pack(MAGIC, 3, RECORD.size, len(keep), len(blob), hash_off, SLOT.size, len(slots)))
    out += recs + blob + b"\0" * (hash_off - end)
    for h, i, f in slots:
        out += SLOT.pack(h, i, f)
    return bytes(out)


# ---- reader -------------------------------------------------------------------------------
def parse(data: bytes) -> Index:
    """Parse and validate an AMPRIDX3 image; AmprIndexError on anything inconsistent."""
    if len(data) < HEADER.size:
        raise AmprIndexError("too short for an AMPRIDX3 header")
    magic, ver, rsz, n, blen, hoff, ssz, nslots = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise AmprIndexError(f"not an AMPRIDX3 file (magic {magic!r})")
    if ver != 3 or rsz != RECORD.size or ssz != SLOT.size:
        raise AmprIndexError(f"unsupported layout (version {ver}, record size {rsz}, slot size {ssz})")
    if n == 0 or n > 0xFFFFFFFE or nslots != slot_count(n):
        raise AmprIndexError(f"invalid counts (entries {n}, slots {nslots})")
    rec_end = HEADER.size + n * rsz
    blob_end = rec_end + blen
    if blob_end > len(data) or hoff < blob_end or hoff % 16 or hoff + nslots * ssz > len(data):
        raise AmprIndexError("sections do not fit the file")
    entries = []
    for i in range(n):
        off, ln, size, mtime = RECORD.unpack_from(data, HEADER.size + i * rsz)
        if off + ln + 1 > blen or data[rec_end + off + ln] != 0:
            raise AmprIndexError(f"record {i}: bad path range")
        try:
            path = data[rec_end + off:rec_end + off + ln].decode("utf-8")
        except UnicodeDecodeError:
            raise AmprIndexError(f"record {i}: path is not UTF-8") from None
        entries.append(Entry(path, size, mtime))
    return Index(entries)


def read(path: Path | str) -> Index:
    try:
        return parse(Path(path).read_bytes())
    except OSError as e:
        raise AmprIndexError(f"cannot read {path}: {e}") from None


# ---- trees --------------------------------------------------------------------------------
def scan_tree(root: Path, inplace_backups: bool = False) -> dict[str, Path]:
    """rel POSIX path -> file for every regular file under root (symlinked files included).

    ps5bp's own report files are left out; with inplace_backups, `X.orig` files whose X exists
    (the backups an in-place build leaves) are left out too."""
    out: dict[str, Path] = {}
    for dp, dn, fns in os.walk(root):
        dn.sort(key=key_for)
        for f in sorted(fns, key=key_for):
            p = Path(dp) / f
            rel = p.relative_to(root).as_posix()
            if rel in _TOOL_FILES:
                continue
            if inplace_backups and f.endswith(".orig") and (p.with_name(f[:-5])).exists():
                continue
            if p.is_file():
                out[rel] = p
    return out


def final_tree(mode: str, game: Path, out: Path, removed: Iterable[str] = ()) -> dict[str, Path]:
    """The game files as they will be on the console, rel path -> file whose stat to index.

    overlay: the game's files overridden / extended by the overlay's, minus `removed` (files the
    build tells the user to delete); full: the output; inplace: the game folder after the edits."""
    if mode == "full":
        return scan_tree(out)
    if mode == "inplace":
        return scan_tree(game, inplace_backups=True)
    tree = {k: v for k, v in scan_tree(game).items()}
    by_key = {key_for(k): k for k in tree}
    for rel, p in scan_tree(out).items():
        old = by_key.get(key_for(rel))
        if old is not None:
            del tree[old]
        tree[rel] = p
        by_key[key_for(rel)] = rel
    gone = {key_for(r) for r in removed}
    return {k: v for k, v in tree.items() if key_for(k) not in gone}


def is_skipped(rel: str) -> bool:
    return rel.replace("\\", "/").lower() in _SKIP_ROOT


def rows_for_tree(files: dict[str, Path]) -> list[tuple[str, int, int]]:
    """(app0 path, size, mtime) for the files an index lists (skip rules of the reference builder)."""
    rows = []
    for rel, p in files.items():
        if is_skipped(rel):
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        rows.append(("/app0/" + rel.replace("\\", "/"), st.st_size, int(st.st_mtime)))
    return rows


def has_emulator(files: Iterable[str]) -> bool:
    return any(f.replace("\\", "/").lower() == EMU_LIB for f in files)


def has_packs(files: Iterable[str]) -> bool:
    return any(f.replace("\\", "/").lower() == "ampr_assets.index" for f in files)


def find_member(root: Path, name: str) -> Path | None:
    """`name` (root level or a/b) as spelled under root, matched case-insensitively."""
    cur = root
    for part in name.split("/"):
        try:
            hit = next((n for n in os.listdir(cur) if n.casefold() == part.casefold()), None)
        except OSError:
            return None
        if hit is None:
            return None
        cur = cur / hit
    return cur if cur.is_file() else None


@dataclass
class Diff:
    added: list[str] = field(default_factory=list)       # paths in the tree, not in the index
    removed: list[str] = field(default_factory=list)     # in the index, not in the tree
    resized: list[str] = field(default_factory=list)     # same path, different size

    @property
    def paths_differ(self) -> bool:
        return bool(self.added or self.removed)

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.resized)

    def summary(self) -> str:
        parts = []
        for label, xs in (("added", self.added), ("removed", self.removed), ("resized", self.resized)):
            if xs:
                parts.append(f"{len(xs)} {label} ({', '.join(xs[:3])}{' …' if len(xs) > 3 else ''})")
        return "; ".join(parts) or "identical"


def compare(idx: Index, rows: Iterable[tuple[str, int, int]]) -> Diff:
    """Path set (by key) and sizes; mtimes are ignored."""
    have = idx.keys()
    d = Diff()
    seen = set()
    for path, size, _ in sorted(rows, key=lambda r: key_for(r[0])):
        k = key_for(path)
        if k in seen:
            continue
        seen.add(k)
        e = have.get(k)
        if e is None:
            d.added.append(path)
        elif e.size != size:
            d.resized.append(path)
    d.removed = [e.path for k, e in have.items() if k not in seen]
    return d


# ---- emulator version -----------------------------------------------------------------------
_VER = re.compile(rb"(\d+\.\d+\.\d+(?:\.\d+)?)[ \t]*(?:\([^)\x00]*\)[ \t]*)*\(c\)[ \t]*Drakmor")


def emulator_version(path: Path | str | None) -> str | None:
    """Version string baked into a libSceAmpr.sprx ('0.3.6.6 (public beta)'), 'unknown' if the
    build has none, None if there is no file."""
    if path is None:
        return None
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    m = _VER.search(data)
    if not m:
        return "unknown"
    whole = m.group(0).decode("latin-1")
    ver = whole.split("(c)")[0].strip()
    return ver or m.group(1).decode()
