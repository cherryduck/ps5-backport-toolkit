"""PS5/PS4 NIDs: 11-char ids that replace symbol names in the dynamic symbol table.

NID = base64 (alphabet A-Za-z0-9+-) of the byte-reversed first 8 bytes of
SHA1(name + SUFFIX), truncated to 11 chars.
Dynamic symbol names look like  NID#<lib id>#<module id>  where the ids are
base64-digit numbers indexing the import/export library and module tables.
"""
from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from importlib import resources

SUFFIX = bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"

# Behaviour-named NIDs whose real symbol names aren't public.
UNNAMED = {
    "NH6xARDOVv8": "<hw/Pro query: *a==3 => Pro>",
}


def nid(name: str) -> str:
    h = hashlib.sha1(name.encode() + SUFFIX).digest()[:8][::-1]
    return base64.b64encode(h, b"+-").decode()[:11]


def b64num(s: str) -> int:
    v = 0
    for c in s:
        v = v * 64 + B64.index(c)
    return v


def split(sym: str) -> tuple[str, int | None, int | None]:
    """'NID#L#M' -> (NID, lib id, module id). Plain names return (name, None, None)."""
    parts = sym.split("#")
    if len(parts) == 3 and all(c in B64 for c in parts[1] + parts[2]) and parts[1] and parts[2]:
        return parts[0], b64num(parts[1]), b64num(parts[2])
    return sym, None, None


@lru_cache(maxsize=1)
def names() -> dict[str, str]:
    """NID -> symbol name, from data/nid_names.txt (one name per line), the verified names in stub_contracts.json, plus UNNAMED."""
    table = dict(UNNAMED)
    try:
        text = resources.files("ps5bp").joinpath("data/nid_names.txt").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        text = ""
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            table[nid(line)] = line
    try:                                   # contract names whose hash matches their NID are verified
        import json
        data = json.loads(resources.files("ps5bp").joinpath("data/stub_contracts.json").read_text(encoding="utf-8"))
        for c in data.get("contracts", []):
            if c.get("name_verified") and nid(c["name"]) == c["nid"]:
                table.setdefault(c["nid"], c["name"])
    except (FileNotFoundError, ModuleNotFoundError, ValueError, KeyError):
        pass
    return table


def name_of(n: str) -> str:
    return names().get(n, "")
