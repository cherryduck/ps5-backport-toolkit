"""SDK version fields (PT_SCE_PROCPARAM / PT_SCE_MODULE_PARAM) and target firmware table.

Param struct (both kinds):  +0x00 u32 size, +0x08 u32 magic, +0x10 u32 PS4 SDK, +0x14 u32 PS5 SDK.
The firmware refuses to launch binaries whose SDK is newer than itself, so a
backport rewrites both fields to a pair the target firmware accepts.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .binary import PT_SCE_MODULE_PARAM, PT_SCE_PROCPARAM, Binary

PROC_MAGIC = 0x4942524F      # 'ORBI'
MODULE_MAGIC = 0x3C13F4BF
OFF_MAGIC, OFF_PS4, OFF_PS5 = 0x8, 0x10, 0x14

# target major firmware -> (PS5 SDK, PS4 SDK) pairs as used by community backports
SDK_PAIRS: dict[int, tuple[int, int]] = {
    1: (0x01000050, 0x07590001),
    2: (0x02000009, 0x08050001),
    3: (0x03000027, 0x08540001),
    4: (0x04000031, 0x09040001),
    5: (0x05000033, 0x09590001),
    6: (0x06000038, 0x10090001),
    7: (0x07000038, 0x10590001),
    8: (0x08000041, 0x11090001),
    9: (0x09000040, 0x11590001),
    10: (0x10000040, 0x12090001),
}
SUPPORTED_TARGETS = (4, 5, 6, 7)


def fw_str(ps5_sdk: int) -> str:
    """0x04000031 -> '4.00' (BCD major.minor)."""
    return f"{(ps5_sdk >> 24) & 0xFF:x}.{(ps5_sdk >> 16) & 0xFF:02x}"


def fw_major(ps5_sdk: int) -> int:
    return int(f"{(ps5_sdk >> 24) & 0xFF:x}")


@dataclass
class SdkParam:
    kind: str          # 'process' | 'module'
    rva: int
    size: int
    ps4: int
    ps5: int


def find(b: Binary) -> SdkParam | None:
    for p in b.phdrs:
        if p.type not in (PT_SCE_PROCPARAM, PT_SCE_MODULE_PARAM):
            continue
        kind = "process" if p.type == PT_SCE_PROCPARAM else "module"
        raw = b.read(p.vaddr, 0x18)
        if b.foff(p.vaddr) is None and b.kind == "elf":
            raw = bytes(b.data[p.offset:p.offset + 0x18])
        size, = struct.unpack_from("<I", raw, 0)
        if size == 0 and kind == "module":
            return None                          # module without a param struct
        magic, = struct.unpack_from("<I", raw, OFF_MAGIC)
        if magic != (PROC_MAGIC if kind == "process" else MODULE_MAGIC) or size < 0x18:
            raise ValueError(f"{b.name}: bad {kind} param (size {size:#x}, magic {magic:#x})")
        ps4, ps5 = struct.unpack_from("<II", raw, OFF_PS4)
        return SdkParam(kind, p.vaddr, size, ps4, ps5)
    return None


def set_sdk(b: Binary, ps5: int, ps4: int) -> tuple[SdkParam, SdkParam] | None:
    """Rewrite the SDK pair. Returns (before, after) or None if the binary has no param."""
    before = find(b)
    if before is None:
        return None
    old = struct.pack("<II", before.ps4, before.ps5)
    b.patch(before.rva + OFF_PS4, old, struct.pack("<II", ps4, ps5))
    after = find(b)
    assert after is not None
    return before, after
