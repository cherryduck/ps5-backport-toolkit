"""Crash-log (klog) triage.

Parses the kernel log's fatal-signal block (reason, registers, backtrace, loaded
modules), maps every backtrace frame to its module, and — when the game folder is
given — resolves the call made at each /app0/ frame (the return address minus the call
length) to its target: an import name, or a game function plus the imports it calls.
The heuristics turn that into a short diagnosis with the matching ps5bp rule.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

NOISE = [
    (r"NOT SIGNED MODE", "fake-signed package (expected)"),
    (r"0x809f8022", "save data not created yet (expected on first boot)"),
    (r"0x80020002", "entitlement check failed (offline / no license; expected)"),
    (r"0x8041013d", "PFAuth / update check failed (offline; expected)"),
    (r"patch_shellui failed", "kstuff shellui patch message (unrelated)"),
    (r"0x80020013", "no M.2 drive (unrelated)"),
]
MEMORY_APIS = {"sceKernelAllocateDirectMemory", "sceKernelAllocateMainDirectMemory", "sceKernelMapDirectMemory",
               "sceKernelMapNamedDirectMemory", "sceKernelReserveVirtualRange", "sceKernelMapFlexibleMemory",
               "sceKernelMapNamedFlexibleMemory", "sceKernelAvailableDirectMemorySize",
               "sceKernelGetDirectMemorySize", "sceKernelAllocateDirectMemoryForMiniApp"}
EXIT_APIS = {"exit", "_exit", "abort", "sceKernelDebugRaiseException", "sceKernelDebugRaiseExceptionOnReleaseMode"}


@dataclass
class Module:
    path: str
    start: int
    end: int

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @property
    def in_app(self) -> bool:
        return self.path.startswith("/app0/")

    @property
    def rel(self) -> str:
        return self.path[len("/app0/"):] if self.in_app else self.path


@dataclass
class Frame:
    addr: int
    module: Module | None = None
    call: str = ""                    # resolved call at this return address
    calls_in_fn: list[str] = field(default_factory=list)   # imports the calling function uses

    def where(self) -> str:
        if not self.module:
            return f"{self.addr:#x} (unknown module)"
        return f"{self.module.name}+{self.addr - self.module.start:#x}"


@dataclass
class Crash:
    reason: str = ""
    thread: str = ""
    proc: str = ""
    regs: dict[str, int] = field(default_factory=dict)
    frames: list[Frame] = field(default_factory=list)
    modules: list[Module] = field(default_factory=list)
    signal: str = ""
    line: int = 0

    @property
    def rip(self) -> int | None:
        return self.regs.get("rip")

    def module_at(self, addr: int) -> Module | None:
        return next((m for m in self.modules if m.start <= addr < m.end), None)


@dataclass
class Triage:
    title_id: str = ""
    launches: list[str] = field(default_factory=list)
    crashes: list[Crash] = field(default_factory=list)
    noise: list[str] = field(default_factory=list)
    other_errors: list[str] = field(default_factory=list)
    diagnosis: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    ampr_versions: list[str] = field(default_factory=list)    # '[AMPR_EMU] name=libSceAmpr version=...' lines
    ampr_lines: list[str] = field(default_factory=list)       # other [AMPR_EMU] / apr.index lines (first few)
    ampr_findings: list[str] = field(default_factory=list)    # explanations of the index lines

    def to_text(self) -> str:
        L = [f"title: {self.title_id or '?'}   launches: {len(self.launches)}   crashes: {len(self.crashes)}"]
        for k, c in enumerate(self.crashes):
            L += ["", f"crash {k + 1} (log line {c.line}): {c.reason or '?'}"
                  + (f"   signal {c.signal}" if c.signal else ""),
                  f"   thread {c.thread or '?'} in {c.proc or '?'}"]
            if c.rip is not None:
                m = c.module_at(c.rip)
                L.append(f"   rip {c.rip:#x}  ({m.name}+{c.rip - m.start:#x})" if m else f"   rip {c.rip:#x}")
            L.append("   backtrace:")
            for f in c.frames:
                s = f"     {f.addr:#014x}  {f.where():40}"
                if f.call:
                    s += f"  <- {f.call}"
                L.append(s.rstrip())
                if f.calls_in_fn:
                    L.append(f"{'':63}function also calls: {', '.join(f.calls_in_fn[:8])}")
        if self.ampr_versions or self.ampr_lines:
            L += ["", "Ampr emulator log lines:"] + [f"   {x}" for x in self.ampr_versions[:2] + self.ampr_lines[:10]]
        if self.diagnosis:
            L += ["", "diagnosis:"] + [f"   * {d}" for d in self.diagnosis]
        if self.suggestions:
            L += ["", "try:"] + [f"   - {s}" for s in self.suggestions]
        if self.other_errors:
            L += ["", "other errors mentioning the game / its modules:"] + [f"   {e}" for e in self.other_errors[:15]]
        if self.noise:
            L += ["", "ignored (normal on backports):"] + [f"   {n}" for n in self.noise]
        return "\n".join(L) + "\n"


_HEX = r"([0-9a-fA-F]+)"


AMPR_ADVICE = ("regenerate it with ps5bp (`ps5bp build ... --ampr-index regen`, or Undo + rebuild with the GUI's "
               "AMPR index = regenerate), or run the game once from a writable location so the emulator builds it")
_AMPR_PATTERNS = (
    (r"apr\.index unavailable|defer runtime build|runtime autobuild disabled",
     "ampr_emu.index is missing and the emulator did not build one (/app0 is read-only or autobuild is off): "
     "ship one — " + AMPR_ADVICE),
    (r"apr\.index (build|save) fail|save rename fail",
     "the emulator could not write ampr_emu.index (/app0 is read-only or the disk is full): " + AMPR_ADVICE),
    (r"indexed-path-missing",
     "ampr_emu.index lists a file that no longer exists: the index is STALE (files were removed or replaced "
     "after it was built): " + AMPR_ADVICE),
    (r"apr\.index invalid-counts|invalid-hash-header",
     "ampr_emu.index is corrupt or truncated: " + AMPR_ADVICE),
)


def ampr_scan(lines: list[str]) -> tuple[list[str], list[str], list[str]]:
    """(version lines, other [AMPR_EMU]/apr.index lines, explanations) from a klog."""
    versions, other, findings = [], [], []
    for ln in lines:
        if "[AMPR_EMU]" not in ln and "apr.index" not in ln and "indexed-path-missing" not in ln:
            continue
        txt = ln.strip()[:240]
        if re.search(r"\[AMPR_EMU\]\s+name=libSceAmpr\s+version=", ln):
            if txt not in versions:
                versions.append(txt)
            continue
        if txt not in other:
            other.append(txt)
        for pat, why in _AMPR_PATTERNS:
            if re.search(pat, ln) and why not in findings:
                findings.append(why)
    return versions, other, findings


def parse(text: str) -> Triage:
    t = Triage()
    lines = text.splitlines()
    game_id = r"((?!NPXS)[A-Z]{4}\d{5})"
    crashed = re.findall(r"notifyAppCrash\(\) titleId=\{" + game_id, text)
    launched = re.findall(r"launchApp\(" + game_id + r"\)", text)
    t.title_id = (crashed or launched or [""])[-1]
    t.launches = [ln.strip() for ln in lines if re.search(r"EXEC /app0/eboot\.bin .*category=native_game", ln)]
    for pat, why in NOISE:
        n = sum(1 for ln in lines if re.search(pat, ln))
        if n:
            t.noise.append(f"{why}  [{n}x '{pat}']")

    t.ampr_versions, t.ampr_lines, t.ampr_findings = ampr_scan(lines)
    i = 0
    while i < len(lines):
        if "A user thread receives a fatal signal" not in lines[i] and not re.match(r"#\s*reason:", lines[i]):
            i += 1
            continue
        c = Crash(line=i + 1)
        section = ""
        cur_mod: str | None = None
        j = i + 1
        while j < len(lines):
            ln = lines[j]
            if ln.startswith("mDBG: Sending signal") or "App Crash" in ln:
                mm = re.search(r"signo: (0x[0-9a-fA-F]+)", ln)
                if mm:
                    c.signal = mm.group(1)
                break
            if not ln.startswith("#"):
                j += 1                                     # interleaved log noise
                continue
            body = ln[1:].strip()
            if body.startswith("A user thread receives a fatal signal") and j > i + 1:
                break
            if re.match(r"reason:", body):
                c.reason = body.split(":", 1)[1].strip()
            elif body.startswith("thread name:"):
                c.thread = body.split(":", 1)[1].strip()
            elif body.startswith("proc name:"):
                c.proc = body.split(":", 1)[1].strip()
            elif body.startswith("registers:"):
                section = "regs"
            elif body.startswith("backtrace:"):
                section = "bt"
            elif body.startswith("dynamic libraries:"):
                section = "libs"
            elif section == "regs":
                for r, v in re.findall(r"(\w+)\s*:\s*" + _HEX, body):
                    c.regs[r] = int(v, 16)
            elif section == "bt" and re.fullmatch(_HEX, body):
                a = int(body, 16)
                if a:
                    c.frames.append(Frame(a))
            elif section == "libs":
                mm = re.match(r"xotext:\s*" + _HEX + ":" + _HEX, body)
                if body.startswith("/"):
                    cur_mod = body
                elif mm and cur_mod:
                    c.modules.append(Module(cur_mod, int(mm.group(1), 16), int(mm.group(2), 16)))
                    cur_mod = None
            j += 1
        for f in c.frames:
            f.module = c.module_at(f.addr)
        t.crashes.append(c)
        i = j + 1

    tid = t.title_id
    for ln in lines:
        if re.search(r"\b(error|fail|failed|unresolved|not found)\b", ln, re.I) and \
                ((tid and tid in ln) or "/app0/" in ln) and not any(re.search(p, ln) for p, _ in NOISE):
            t.other_errors.append(ln.strip()[:200])
    return t


# ---- symbolisation with the game folder ----------------------------------------------------
def _fn_start(read, addr: int, limit: int = 0x4000) -> int:
    """Walk back to the int3 / zero padding before the function containing addr."""
    lo = max(0, addr - limit)
    blob = read(lo, addr - lo)
    k = len(blob) - 1
    while k > 0:
        if blob[k] == 0xCC and blob[k - 1] == 0xCC:
            return lo + k + 1
        if blob[k - 7:k + 1] == b"\0" * 8:
            return lo + k + 1
        k -= 1
    return lo


def symbolize(t: Triage, game: Path) -> None:
    """Fill Frame.call / calls_in_fn for frames inside /app0/ binaries of `game`."""
    from . import dynamic
    from .asm import plt_stubs
    from .binary import Binary
    from .nid import name_of

    cache: dict[str, tuple | None] = {}

    def load(rel: str):
        if rel not in cache:
            p = game / rel
            if not p.is_file():
                cache[rel] = None
            else:
                b = Binary.load(p)
                d = dynamic.parse(b)
                stubs = {va: n for n, va in plt_stubs(b, d, 0).items()} if d else {}
                cache[rel] = (b, stubs)
        return cache[rel]

    def label(stubs, rva) -> str:
        if rva in stubs:
            nid = stubs[rva].split("#")[0]
            return name_of(nid) or nid
        return ""

    for c in t.crashes:
        for f in c.frames:
            if not f.module or not f.module.in_app:
                continue
            got = load(f.module.rel)
            if not got:
                continue
            b, stubs = got
            base = f.module.start
            rva = f.addr - base

            def read(r: int, n: int) -> bytes:
                return bytes(b.read(r, n))
            try:
                ins = read(rva - 5, 5)
            except Exception:                              # noqa: BLE001
                continue
            if ins[0] == 0xE8:
                tgt = rva + struct.unpack("<i", ins[1:])[0]
                f.call = label(stubs, tgt) or f"function {base + tgt:#x}"
                if not label(stubs, tgt):
                    f.calls_in_fn = _fn_imports(read, stubs, tgt, label)
            else:
                try:
                    i6 = read(rva - 6, 6)
                except Exception:                          # noqa: BLE001
                    i6 = b""
                if i6[:2] == b"\xff\x15":
                    f.call = "indirect call through GOT/table"
                elif read(rva - 2, 2)[0] == 0xFF or read(rva - 3, 3)[0] == 0xFF:
                    f.call = "indirect call (register / vtable)"


def _fn_imports(read, stubs, start: int, label, size: int = 0x1800) -> list[str]:
    """Imports called directly from the function at `start` (scan until padding)."""
    try:
        blob = read(start, size)
    except Exception:                                      # noqa: BLE001
        return []
    end = len(blob)
    m = re.search(rb"\xcc\xcc", blob)
    if m:
        end = m.start()
    out = []
    for k in range(end - 4):
        if blob[k] == 0xE8:
            tgt = start + k + 5 + struct.unpack_from("<i", blob, k + 1)[0]
            n = label(stubs, tgt)
            if n and n not in out:
                out.append(n)
    return out


# ---- diagnosis --------------------------------------------------------------------------------
def diagnose(t: Triage, game_flags: list[str] | None = None) -> None:
    flags = set(game_flags or [])
    t.diagnosis += [f"Ampr emulator: {x}" for x in t.ampr_findings]
    if not t.crashes:
        t.diagnosis.append("no fatal-signal block found — the game may have hung, or the log does not "
                           "cover the launch (capture klog before starting the game)")
        return
    c = t.crashes[-1]
    app_frames = [f for f in c.frames if f.module is not None and f.module.in_app]
    called = {f.call for f in c.frames if f.call} | {n for f in c.frames for n in f.calls_in_fn}
    if "non-zero" in c.reason or "exit" in c.reason.lower():
        t.diagnosis.append("the game called exit() itself with an error code — a startup check failed; "
                           "this is not a CPU fault, so look at what the calling game code was doing")
        if called & MEMORY_APIS:
            t.diagnosis.append("the failing path allocates memory (" + ", ".join(sorted(called & MEMORY_APIS))
                               + ") — the target FW / console gives the game less direct memory than it asks for")
            if {"pro-query", "pssr"} & flags:
                t.suggestions.append("this is a Pro/PSSR title: build with --rule pssr-memory if a recipe exists, "
                                     "otherwise --rule pro-disable (base-PS5 path, no PSSR)")
            else:
                t.suggestions.append("reduce the startup allocation (patch recipe) — compare with a working kit")
    else:
        rip = c.rip or 0
        m = c.module_at(rip) if c.rip is not None else None
        if m and m.in_app:
            t.diagnosis.append(f"CPU fault inside game code at {m.name}+{rip - m.start:#x} ({c.reason})")
        elif m:
            t.diagnosis.append(f"fault inside system module {m.name} ({c.reason}) — usually a bad argument from "
                               "the game, or a fakelib/system version mismatch")
    fk = sorted({f.module.name for f in app_frames if f.module is not None and f.module.rel.startswith("fakelib/")})
    if fk:
        names = fk
        t.diagnosis.append(f"fakelib code is on the stack: {', '.join(names)} — try the same module from "
                           "another kit (ps5bp analyze shows the candidates)")
    sysmods = {m.name for m in c.modules if not m.in_app}
    app_fakelibs = {m.name for m in c.modules if m.in_app and "/fakelib/" in m.path}
    shadow = sorted(n for n in app_fakelibs if n in sysmods)
    if shadow:
        t.diagnosis.append("both the system and the fakelib copy of " + ", ".join(shadow) + " are loaded")
    if not app_fakelibs:
        t.diagnosis.append("(note) no /app0/fakelib/ modules were loaded — expected on a high FW; on FW <= 7 "
                           "it means the fakelib loader (BackPork) is not active")
