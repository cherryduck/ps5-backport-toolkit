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
    # 11-13: PS4 side continues the +0x50 BCD per major (12.59 / 13.09 / 13.59); PS5 side is a
    # LEAD from another tool's table (11 -> 0x11000040, 12 -> 0x12000038, 13 -> 0x13000035), NOT
    # confirmed. Cross-check (Phase 10a): scanned ~/.local/share/ps5bp/kits, ~/Games, /mnt/sda1,
    # ~/Downloads, ~/Documents and the PS5 homebrew projects under ~/Documents/GitHub with
    # ps5bp's own sdk.find: the only SDK pairs declared anywhere are 2.00/8.05 and 4.00/9.04
    # (kit fakelibs / homebrew builds). No binary declares SDK 8-13, so pairs 8-10 (existing)
    # and 11-13 (new) are unverified against real binaries; nothing contradicts them either.
    # Verify when a game dump / kit built with the 11/12/13 SDK turns up.
    11: (0x11000040, 0x12590001),
    12: (0x12000038, 0x13090001),
    13: (0x13000035, 0x13590001),
}
SUPPORTED_TARGETS = tuple(range(4, 14))


def target_pair(major: int, minor: int = 0) -> tuple[int, int]:
    """(PS5 SDK, PS4 SDK) for target major.minor; minor is the BCD byte (4.03 -> 0x03).
    Backporters targeting e.g. 4.03 keep the major's build suffix: 0x04000031 -> 0x04030031."""
    ps5, ps4 = SDK_PAIRS[major]
    return (ps5 & 0xFF00FFFF) | ((minor & 0xFF) << 16), ps4


def parse_target(s: str) -> tuple[int, int]:
    """'4' -> (4, 0); '4.03' -> (4, 0x03); '4.50' -> (4, 0x50)."""
    m = __import__("re").fullmatch(r"(\d+)(?:\.(\d{1,2}))?", str(s).strip())
    if not m or int(m[1]) not in SUPPORTED_TARGETS:
        raise ValueError(f"target must be one of {', '.join(map(str, SUPPORTED_TARGETS))}, optionally "
                         f"with a minor version (e.g. 4.03)")
    return int(m[1]), int((m[2] or "0").rjust(2, "0"), 16)


def fw_major_of_str(s: str) -> int:
    """Console firmware text ('11.60', '9', '11.2') -> major (decimal). ValueError if malformed."""
    m = __import__("re").fullmatch(r"\s*(\d{1,2})(?:\.(\d{1,2}))?\s*", str(s))
    if not m:
        raise ValueError(f"console firmware must look like 11.60 (got {s!r})")
    return int(m[1])


def declared_gap(target_major: int, console_fw: str | None) -> int:
    """Majors by which the declared SDK trails the console firmware (0 if unknown/not below)."""
    if not console_fw:
        return 0
    return max(0, fw_major_of_str(console_fw) - target_major)


GAP_WARN = 2        # warn at >= this many majors below the console


def console_warning(target_major: int, target_minor: int, console_fw: str | None) -> str | None:
    """Advice (never a behaviour change) when the declared SDK is far below the console FW."""
    if not console_fw or declared_gap(target_major, console_fw) < GAP_WARN:
        return None
    return (f"declared SDK {target_str(target_major, target_minor)} is {declared_gap(target_major, console_fw)} "
            f"majors below console FW {console_fw.strip()}: known black-screen / GPU-hang risk at FW5+ with "
            "SDK-4 builds (reported: Mortal Shell II and Minecraft Dungeons II on base FW 9.00, STAR WARS "
            "Galactic Racer on Pro FW 11.20 — fixed by SDK pair 5 builds). Consider "
            f"--also-target 5,{min(max(target_major + 1, int(console_fw.strip().split('.')[0])), 13)} "
            "to get siblings with a higher SDK pair.")


def target_str(major: int, minor: int = 0) -> str:
    return f"{major}.{minor:02x}" if minor else f"{major}.xx"


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
