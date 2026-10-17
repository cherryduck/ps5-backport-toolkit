"""trinity-hw-gate: one build that is right on both a base PS5 and a PS5 Pro.

The title asks the kernel "am I on a Pro?" through sceKernelIsTrinityMode (tU5e3f9gSiU), the
hardware query sceKernelGetOperationMode (NH6xARDOVv8: *mode, *lowEnergy) and AGC's
sceAgcGetIsTrinityMode (BfBDZGbti7A).  Backports commonly freeze these to "base" or "Pro" in
the PLT.  A constant is wrong on the other console, so this rule replaces the constants by the
real SoC check, sceKernelHasTrinityMode (yu17wG8L5FI, bool(void), same library; Pro SoC test
only — IsTrinityMode additionally needs a per-process sysctl, so the two are not identical):

  1. the IsTrinityMode import string is renamed in place to HasTrinityMode (same length; refused
     when both are imported or the string is not unique);
  2. an IsTrinityMode PLT entry that was forced to `mov eax,1; ret` is restored to the
     canonical lazy entry (`jmp [GOT]; push idx; jmp PLT0`); its GOT slot must be lazy or a
     return-0 seed;
  3. HasTrinityMode does not exist below firmware 7.00: a GOT seed `xor eax,eax; ret` is
     installed there (the loader binds the real export where one exists, the seed only serves
     when the import cannot be resolved);
  4. a GetOperationMode PLT forced to "mode 3" (`*rdi=3; *rsi=0`) jumps to a cave doing
     `*lowEnergy = 0; *mode = 2 | HasTrinityMode()`;
  5. an AGC GetIsTrinityMode PLT forced to 1 becomes `*out = HasTrinityMode()` (in place).
An unforced GetOperationMode is left to its own seed / native binding.

Forced "Pro" stubs make a base console enter the PSSR path, which needs the Pro stack (a PSML
that loads /app0/k9.psp plus the k9.psp itself): without psml-overlay enabled or a dump that
already carries it, the finding is refused.  Experimental: observed in one community FW4
backport working on base 4.50 and Pro 13.60, never recommended (console test needed).
Conflicts with pro-disable (which does the opposite: runs as base).

Seed mechanism: `got_seed()` below is the minimal local version of the GOT-seed delivery
(stub in an int3 cave, lazy GOT slot -> cave, PLT/import/relocation untouched); to be unified
with the shared GOT-seed mechanism.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from .. import dynamic
from ..asm import Asm, canonical_plt
from ..binary import Binary
from ..nid import nid
from . import Finding, Rule, RuleContext
from .common import Slot, allocate_runs, int3_runs, jump_slots

IS_TRINITY = nid("sceKernelIsTrinityMode")             # tU5e3f9gSiU
HAS_TRINITY = nid("sceKernelHasTrinityMode")           # yu17wG8L5FI
OPMODE = "NH6xARDOVv8"
AGC_IS_TRINITY = nid("sceAgcGetIsTrinityMode")         # BfBDZGbti7A
HAS_FIRST_FW = 7
FORCED_IS = bytes.fromhex("b801000000c3")
FORCED_OPMODE = bytes.fromhex("c70703000000" "c70600000000" "31c0c3")
FORCED_AGC = bytes.fromhex("c60701" "31c0c3")
RET0 = (bytes.fromhex("31c0c3"), bytes.fromhex("4831c0c3"))
SEED = bytes.fromhex("31c0c3")


def opmode_cave(at: int, has_plt: int) -> bytes:
    """*lowEnergy(rsi) = 0; *mode(rdi) = 2 | HasTrinityMode(); return 0."""
    a = Asm(at)
    a.hex("832600")                        # and  dword [rsi], 0
    a.hex("57")                            # push rdi            (also aligns the stack for the call)
    a.rel32("e8", has_plt)                 # call HasTrinityMode
    a.hex("5f")                            # pop  rdi
    a.hex("83e001")                        # and  eax, 1
    a.hex("83c802")                        # or   eax, 2
    a.hex("8907")                          # mov  [rdi], eax
    a.hex("31c0")                          # xor  eax, eax
    a.hex("c3")
    return a.assemble()


def agc_body(at: int, has_plt: int) -> bytes:
    """*out(rdi) = HasTrinityMode(); return 0 (16-byte PLT entry body)."""
    a = Asm(at)
    a.hex("57")                            # push rdi
    a.rel32("e8", has_plt)                 # call HasTrinityMode
    a.hex("5f")                            # pop  rdi
    a.hex("8807")                          # mov  [rdi], al
    a.hex("31c0 c3")
    return a.assemble().ljust(16, b"\xcc")


def got_seed(b: Binary, slot: Slot, at: int, code: bytes) -> list[tuple[int, bytes, bytes, str]]:
    """Minimal GOT-seed delivery: `code` into the int3 cave at `at`, the slot's lazy GOT value
    (PLT+6) pointed at it.  Returns [(rva, old, new, note)]."""
    old = b.read(at, len(code))
    if old != b"\xcc" * len(code):
        raise ValueError(f"seed cave at {at:#x} is not int3 padding")
    return [(at, old, code, "GOT seed stub"),
            (slot.got, struct.pack("<Q", slot.va + 6), struct.pack("<Q", at), "GOT slot -> seed stub")]


def canonical_entry(slot: Slot, plt0: int) -> bytes:
    return (b"\xff\x25" + struct.pack("<i", slot.got - (slot.va + 6)) + b"\x68" + struct.pack("<I", slot.idx)
            + b"\xe9" + struct.pack("<i", plt0 - (slot.va + 16)))


@dataclass
class Plan:
    status: str
    why: str = ""
    is_slot: Slot | None = None
    forced_is: bool = False
    seed: bool = False
    op: Slot | None = None
    agc: Slot | None = None
    renames: list[tuple[int, bytes, bytes]] = field(default_factory=list)
    placement: dict[str, int] = field(default_factory=dict)
    plt0: int = 0
    forced_pro: bool = False                 # forced-Pro stubs present: needs the Pro stack


def _entry_ok(e: bytes, forced: bytes) -> bool:
    return e.startswith(forced)


def plan_module(b: Binary, target: int) -> Plan | None:
    d = dynamic.parse(b)
    if not d or dynamic.DT_JMPREL not in d.tags or dynamic.DT_PLTRELSZ not in d.tags:
        return None
    imp = d.imported_nids()
    if not imp & {IS_TRINITY, HAS_TRINITY, OPMODE, AGC_IS_TRINITY}:
        return None
    slots = jump_slots(b, d)
    is_s = [s for s in slots if s.nid == IS_TRINITY]
    has_s = [s for s in slots if s.nid == HAS_TRINITY]
    op = next((s for s in slots if s.nid == OPMODE and _entry_ok(s.entry, FORCED_OPMODE)), None)
    agc = next((s for s in slots if s.nid == AGC_IS_TRINITY and _entry_ok(s.entry, FORCED_AGC)), None)
    forced_pro = bool(op or agc)
    if is_s and has_s:
        return Plan("UNKNOWN", "both IsTrinityMode and HasTrinityMode are imported")
    if not is_s and not has_s:
        if forced_pro:
            return Plan("UNKNOWN", "forced-Pro stub without a TrinityMode import")
        return None
    if has_s and not is_s:
        if forced_pro:
            return Plan("UNKNOWN", "HasTrinityMode imported but forced-Pro stubs remain")
        s = has_s[0]
        got = b.u64(s.got)
        seeded = got != s.va + 6 and b.foff(got) is not None and b.read(got, 3) == SEED
        if seeded or _gated_evidence(b, slots):
            return Plan("DONE", "HasTrinityMode imported" + (" with a return-0 GOT seed" if seeded else "")
                        + ("; forced stubs derived from it" if _gated_evidence(b, slots) else ""))
        return None
    if len(is_s) != 1:
        return Plan("UNKNOWN", "IsTrinityMode imported more than once")
    s = is_s[0]
    pl = Plan("PATCH", is_slot=s, op=op, agc=agc, forced_pro=forced_pro)
    sym = d.symbols[s.sym]
    if sym.defined or not d.lib_name(sym).startswith("libkernel"):
        return Plan("UNKNOWN", "IsTrinityMode is not an undefined libkernel import")
    intact = next((x for x in slots if canonical_plt(x.entry)), None)
    if intact is None:
        return Plan("UNKNOWN", "no intact PLT entry to locate PLT0")
    pl.plt0 = intact.va + 16 + struct.unpack_from("<i", intact.entry, 12)[0]
    if canonical_plt(s.entry):
        pass
    elif s.entry.startswith(FORCED_IS) and (s.entry[6:] == b"\xcc" * 10 or
                                            (s.entry[6] == 0x68 and s.entry[11] == 0xE9)):
        pl.forced_is = True
    else:
        return Plan("UNKNOWN", f"IsTrinityMode PLT {s.va:#x} is neither lazy nor the forced-1 form: "
                               f"{s.entry.hex()}")
    got = b.u64(s.got)
    if got == s.va + 6:
        pl.seed = target < HAS_FIRST_FW
    elif b.foff(got) is not None and any(b.read(got, len(r)) == r for r in RET0):
        pl.seed = False                                           # already a return-0 seed
    else:
        return Plan("UNKNOWN", f"IsTrinityMode GOT {s.got:#x} -> {got:#x} is not a return-0 seed")
    # import string rename
    t = d.tags
    strtab, strsz = t[dynamic.DT_STRTAB][0], t[dynamic.DT_STRSZ][0]
    blob = b.read(strtab, strsz)
    off = b.u32(t[dynamic.DT_SYMTAB][0] + 24 * s.sym)
    old = sym.name.encode()
    if len(re.findall(rb"(?<=\0)" + re.escape(old) + rb"(?=\0)", blob)) != 1 or blob[off:off + len(old)] != old:
        return Plan("UNKNOWN", "IsTrinityMode import string is not unique in the string table")
    users = [x for x in range(len(d.symbols)) if b.u32(t[dynamic.DT_SYMTAB][0] + 24 * x) == off]
    if users != [s.sym]:
        return Plan("UNKNOWN", "IsTrinityMode import string is shared with another symbol")
    pl.renames.append((strtab + off, old, HAS_TRINITY.encode() + old[len(HAS_TRINITY):]))
    # caves
    sizes = {}
    if op is not None:
        sizes["opmode"] = len(opmode_cave(0, 0))
    if pl.seed:
        sizes["seed"] = len(SEED)
    if sizes:
        at = allocate_runs(int3_runs(b, [(x.va, x.va + 16) for x in slots]), sizes)
        if at is None:
            return Plan("UNKNOWN", "no int3 padding for the caves")
        pl.placement = at
    return pl


def _gated_evidence(b: Binary, slots: list[Slot]) -> bool:
    """A HasTrinityMode-only module shows our gate when an OperationMode/AGC entry jumps to a derived body."""
    for s in slots:
        if s.nid == OPMODE and s.entry[0] == 0xE9:
            tgt = s.va + 5 + struct.unpack_from("<i", s.entry, 1)[0]
            code = b.read(tgt, 3)
            if code == bytes.fromhex("832600"):
                return True
        if s.nid == AGC_IS_TRINITY and s.entry[:1] == b"\x57" and s.entry[6:7] == b"\x5f":
            return True
    return False


def build_edits(b: Binary, pl: Plan) -> list[tuple[int, bytes, bytes, str]]:
    assert pl.is_slot is not None
    s = pl.is_slot
    out: list[tuple[int, bytes, bytes, str]] = []
    for rva, old, new in pl.renames:
        out.append((rva, old, new, "import sceKernelIsTrinityMode -> sceKernelHasTrinityMode"))
    if pl.forced_is:
        out.append((s.va, s.entry, canonical_entry(s, pl.plt0), "IsTrinityMode PLT: forced 1 -> original jmp [GOT]"))
    if pl.seed:
        out += got_seed(b, s, pl.placement["seed"], SEED)
    if pl.op is not None:
        at = pl.placement["opmode"]
        code = opmode_cave(at, s.va)
        old = b.read(at, len(code))
        if old != b"\xcc" * len(code):
            raise ValueError("opmode cave is not int3 padding")
        out.append((at, old, code, "GetOperationMode cave: *lowEnergy = 0; *mode = 2 | HasTrinityMode()"))
        jmp = b"\xe9" + struct.pack("<i", at - (pl.op.va + 5))
        out.append((pl.op.va, pl.op.entry[:5], jmp, "GetOperationMode PLT: forced 3 -> jmp derived cave"))
    if pl.agc is not None:
        out.append((pl.agc.va, pl.agc.entry, agc_body(pl.agc.va, s.va),
                    "AGC GetIsTrinityMode PLT: *out = 1 -> *out = HasTrinityMode()"))
    return out


class TrinityHwGate(Rule):
    name = "trinity-hw-gate"
    summary = ("EXPERIMENTAL: IsTrinityMode -> HasTrinityMode (real Pro SoC check), forced OperationMode/AGC "
               "stubs derived from it; one build for base + Pro")
    conflicts = ("pro-disable",)

    def _pro_stack(self, ctx: RuleContext) -> bool:
        if "psml-overlay" in set(ctx.options.get("enabled", ())):
            return True
        return "pssr2-app0" in ctx.gs.flags and "k9.psp" in ctx.gs.extra_files

    def detect(self, ctx: RuleContext) -> list[Finding]:
        out = []
        for bi in ctx.gs.binaries:
            if bi.role == "fakelib" or bi.error:
                continue
            nids = {n for v in bi.imports_by_module.values() for n in v}
            if not nids & {IS_TRINITY, HAS_TRINITY, OPMODE, AGC_IS_TRINITY}:
                continue
            try:
                pl = plan_module(ctx.load(bi.path), ctx.declared_sdk)
            except Exception as e:                                   # noqa: BLE001
                out.append(Finding(self.name, bi.path, f"UNKNOWN: {e}", applicable=False, reason=str(e),
                                   data={"status": "UNKNOWN"}))
                continue
            if pl is None:
                continue
            if pl.status != "PATCH":
                out.append(Finding(self.name, bi.path, f"{pl.status}: {pl.why}", applicable=False, reason=pl.why,
                                   data={"status": pl.status}))
                continue
            if pl.forced_pro and not self._pro_stack(ctx):
                why = ("forced-Pro stubs, but no coherent Pro stack: enable psml-overlay (a PSML loading "
                       "/app0/k9.psp + its k9.psp) or ship a dump that already has it")
                out.append(Finding(self.name, bi.path, f"UNKNOWN: {why}", applicable=False, reason=why,
                                   data={"status": "UNKNOWN"}))
                continue
            parts = ["IsTrinityMode -> HasTrinityMode"]
            if pl.forced_is:
                parts.append("restore forced-1 PLT")
            if pl.seed:
                parts.append(f"HasTrinityMode GOT seed (absent below {HAS_FIRST_FW}.00)")
            if pl.op:
                parts.append("OperationMode = 2 | HasTrinityMode()")
            if pl.agc:
                parts.append("AGC GetIsTrinityMode = HasTrinityMode()")
            out.append(Finding(self.name, bi.path, "PATCH: " + "; ".join(parts), applicable=True, recommended=False,
                               reason="experimental: never recommended, console test needed (proved on one title)",
                               data={"status": "PATCH"}))
        return out

    def apply(self, ctx: RuleContext, f: Finding) -> None:
        b = ctx.load(f.file)
        pl = plan_module(b, ctx.declared_sdk)
        if pl is None or pl.status != "PATCH":
            raise ValueError(f"{f.file}: trinity-hw-gate plan changed")
        for rva, old, new, note in build_edits(b, pl):
            off = b.patch(rva, old, new)
            ctx.edit(f.file, f"rule:{self.name}", off, old.hex(), new.hex(), note)
