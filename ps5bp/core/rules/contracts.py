"""Stub contracts: per-NID replacement bodies for imports a target firmware may not export.

Data lives in ps5bp/data/stub_contracts.json (authored here; every NID with a public name is
checked against ps5bp.core.nid in the tests). `first_exported_fw` is only a lead taken from
community firmware-dump observations: coverage evidence (kits) always beats it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

GATES = ("none", "result-unused-or-error-check", "output-buffer-owned-0x40",
         "caller-compares-0x80020003", "libc-only", "manual")


@dataclass(frozen=True)
class Contract:
    nid: str
    name: str
    name_verified: bool
    library: str
    stub: bytes
    semantics: str
    first_exported_fw: str | None      # "6.00"; None = no lead
    gate: str
    family: str = ""
    hw_proved: bool = False            # a recorded console result exists (drives `recommended`)
    note: str = ""

    @property
    def padded(self) -> bytes:
        return self.stub + b"\xcc" * (16 - len(self.stub))

    @property
    def first_exported(self) -> tuple[int, int] | None:
        """(major, minor) of the lead; minor is the 2-digit firmware minor (5.02 -> (5, 2))."""
        if not self.first_exported_fw:
            return None
        major, _, minor = self.first_exported_fw.partition(".")
        return int(major), int(minor or 0)

    def absent_on(self, target_major: int) -> bool | None:
        """Lead only: is the NID missing on firmware `target_major`.xx? None without a lead.
        A NID first exported at N.mm (mm>0) may or may not be there on N.00, so N counts as absent."""
        fe = self.first_exported
        if fe is None:
            return None
        return target_major < fe[0] or (target_major == fe[0] and fe[1] > 0)

    def label(self) -> str:
        return self.name if self.name_verified else f"{self.nid} {self.name}"


@lru_cache(maxsize=1)
def load() -> dict[str, Contract]:
    raw = json.loads(resources.files("ps5bp").joinpath("data/stub_contracts.json").read_text())
    out = {}
    for c in raw["contracts"]:
        stub = bytes.fromhex(c["stub"])
        if not 0 < len(stub) <= 15 or c["gate"] not in GATES:
            raise ValueError(f"bad stub contract {c['nid']}")
        out[c["nid"]] = Contract(c["nid"], c["name"], c["name_verified"], c["library"], stub, c["semantics"],
                                 c["first_exported_fw"], c["gate"], c.get("family", ""),
                                 c.get("hw_proved", False), c.get("note", ""))
    return out
