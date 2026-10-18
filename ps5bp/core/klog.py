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


# Imports whose failure a game may turn into an assert/abort -> the ps5bp rule that fixes the matching
# request (NIDs are those the rules themselves match on).
IMPORT_RULES = {
    "sDCBrmc61XU": ("savedata-prepare", "the save 'prepare' request carries a mode 4.xx does not know"),
    "ZP4e7rlzOUk": ("savedata-mount", "the save mount request carries a systemBlocks value 4.xx rejects"),
    "PHnuI4LhuRk": ("savedata-dirsearch", "sceSaveDataDirNameSearch2 does not exist before 5.02"),
    "dyIhnXq-0SM": ("savedata-dirsearch", "the older save-search call failed"),
    "-sD02mFDBh4": ("gamepresets-28", "the game-presets request is bigger than 4.xx accepts"),
    "TViD1EZXkNI": ("set3-nonfatal", "the audio 3D-latency call fails on FW 6-9"),
    "BKSCW2bCACA": ("tls-atexit", "thread-exit registration only exists from 11.00"),
    "qBS714-Jr3g": ("tls-atexit", "thread-exit registration only exists from 11.00"),
}


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
    call_target: int | None = None    # runtime VA the call at this return address goes to

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
    abort: dict = field(default_factory=dict)     # deliberate abort found by symbolize(): see _abort_info

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
    issues: list[str] = field(default_factory=list)           # ordinary log lines explained (libSceSaveData ...)
    layers: list[Path] = field(default_factory=list)          # game folders symbolize() read from

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
        if self.issues:
            L += ["", "problems found in the log lines:"] + [f"   ! {x}" for x in self.issues]
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


# ---- ordinary log lines (no crash block needed) ----------------------------------------------
# libSceSaveData error codes: code -> (meaning, harmless).  0x809f8022 stays noise (see NOISE).
SAVEDATA_CODES = {
    0x809f8022: ("save data not created yet", True),
    0x809f8032: ("the save exists but can't be opened — often a save left half-created by an earlier crash; "
                 "delete it in Settings → Saved Data and retry", False),
    0x809f0008: ("save data not found", False),
}
# api_id as printed by libSceSaveData; only the ones verified on a console are named
SAVEDATA_APIS = {90: "sceSaveDataMount (Mount3)"}
_PFX = re.compile(r"^\s*<\d+>")
_SD_FAIL = re.compile(r"\[libSceSaveData\]\s+Failed to mount\s+(\S+?)\((0x[0-9a-fA-F]+)\)")
_SD_RESULT = re.compile(r"\[libSceSaveData\]\s+GetResult\s*:\s*ExecResult\s*:\s*(0x[0-9a-fA-F]+)\(api_id=(\d+)\)")
_SD_MOUNT = re.compile(r"\[libSceSaveData\]\s+api_id:\s*90\b.*?dirName=(\S+?),.*?blocks=(\d+),\s*systemBlocks=(-?\d+)"
                       r".*?mountMode=(0x[0-9a-fA-F]+)")


def savedata_scan(lines: list[str]) -> tuple[list[str], list[str]]:
    """(issues, suggestions) for libSceSaveData lines: failed mounts and failing API calls, with the mount
    parameters (read-only / systemBlocks) matched to the failure by directory name. Repeats are counted."""
    params: dict[str, tuple[int, int, int]] = {}          # dirName -> (blocks, systemBlocks, mountMode), last seen
    fails: dict[tuple[str, int], int] = {}                # (dir, code) -> count
    results: dict[tuple[int, int], int] = {}              # (code, api) -> count
    order: list = []
    for ln in lines:
        if "[libSceSaveData]" not in ln:
            continue
        m = _SD_MOUNT.search(ln)
        if m:
            params[m[1]] = (int(m[2]), int(m[3]), int(m[4], 16))
            continue
        m = _SD_FAIL.search(ln)
        if m:
            k = ("mount", m[1], int(m[2], 16))
            fails[k[1:]] = fails.get(k[1:], 0) + 1
            if k not in order:
                order.append(k)
            continue
        m = _SD_RESULT.search(ln)
        if m:
            k = ("result", int(m[1], 16), int(m[2]))
            results[k[1:]] = results.get(k[1:], 0) + 1
            if k not in order:
                order.append(k)
    issues: list[str] = []
    sugg: list[str] = []
    mounted_codes = {c for (_, c) in fails}
    for k in order:
        if k[0] == "mount":
            _, d, code = k
            meaning, harmless = SAVEDATA_CODES.get(code, (f"unknown libSceSaveData error {code:#x}", False))
            if harmless:
                continue
            n = fails[(d, code)]
            txt = f"save data mount of {d} failed with {code:#x} ({meaning})"
            p = params.get(d)
            if p:
                blocks, sysb, mode = p
                ro = (mode & 7) == 1
                txt += f"; mount parameters: {'read-only' if ro else 'read-write'} (mountMode {mode:#x}), " \
                       f"blocks={blocks}, systemBlocks={sysb}"
            if n > 1:
                txt += f"   [repeated {n}x]"
            issues.append(txt)
        else:
            _, code, api = k
            if code in mounted_codes or code == 0 or SAVEDATA_CODES.get(code, ("", False))[1]:
                continue                                   # same failure already reported above / harmless
            meaning = SAVEDATA_CODES.get(code, (f"unknown libSceSaveData error {code:#x}", False))[0]
            n = results[(code, api)]
            issues.append(f"libSceSaveData call api_id={api} ({SAVEDATA_APIS.get(api, 'API not identified')}) "
                          f"returned {code:#x} ({meaning})" + (f"   [repeated {n}x]" if n > 1 else ""))
    return issues, sugg


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
    iss, sug = savedata_scan(lines)
    t.issues += iss
    t.suggestions += [x for x in sug if x not in t.suggestions]
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


def game_layers(game: Path) -> list[Path]:
    """Folders to read the running game's files from, first match wins.

    A ps5bp overlay output holds only the files the backport changed (plus fakelib/); its
    backport-report.json names the game folder it was built from, which supplies every
    other file. So pointing at an overlay resolves each frame against exactly what the
    console runs: changed files from the overlay, the rest from the original dump.
    A full build or a plain game folder is used as it is."""
    import json
    layers = [game]
    rp = game / "backport-report.json"
    if rp.is_file():
        try:
            rep = json.loads(rp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            rep = {}
        base = rep.get("game")
        if rep.get("mode") == "overlay" and base and Path(base) != game:
            layers.append(Path(base))
    return layers


def has_game(game: Path) -> bool:
    """True when the folder (or the game behind an overlay) has an eboot.bin."""
    return any((d / "eboot.bin").is_file() for d in game_layers(game))


def symbolize(t: Triage, game: Path) -> None:
    """Fill Frame.call / calls_in_fn for frames inside /app0/ binaries of `game`
    (a game folder, a full build, or an overlay build - see game_layers)."""
    from . import dynamic
    from .asm import plt_stubs
    from .binary import Binary
    from .nid import name_of

    cache: dict[str, tuple | None] = {}
    layers = game_layers(Path(game))
    t.layers = list(layers)
    if len(layers) > 1 and not layers[1].is_dir():
        t.suggestions.append(f"overlay build: the game folder it was built from ({layers[1]}) is missing; "
                             "only files inside the overlay can be resolved")

    def find(rel: str) -> Path | None:
        for d in layers:
            p = d / rel
            if p.is_file():
                return p
            try:                                       # dumps copied via exFAT/Windows can change case
                from .ledger import resolve_member
                q = d / resolve_member(d, rel)
                if q.is_file():
                    return q
            except Exception:                          # noqa: BLE001 - ambiguous/missing: try next layer
                pass
        return None

    def load(rel: str):
        if rel not in cache:
            p = find(rel)
            if p is None:
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

    def nid_of(stubs, read, rva) -> tuple[str, str]:
        """(NID, name) of the import a call target is (PLT stub, or a jmp thunk to one)."""
        for _ in range(3):
            if rva in stubs:
                n = stubs[rva].split("#")[0]
                return n, name_of(n)
            b = read(rva, 5)
            if b[0] != 0xE9:
                break
            rva = rva + 5 + int.from_bytes(b[1:], "little", signed=True)
        return "", ""

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
                f.call_target = base + tgt
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
        _abort_check(t, c, load, nid_of)


_TRAPS = ((b"\xcd\x41", "int 0x41"), (b"\xcd\x44", "int 0x44"), (b"\xcd\x03", "int 3"), (b"\xcc", "int3"),
          (b"\x0f\x0b", "ud2"), (b"\x0f\xff", "ud0"), (b"\x0f\xb9", "ud1"), (b"\xf4", "hlt"))
_JCC = {"je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "js", "jns"}


def _cstr(read, rva: int, n: int = 160) -> str:
    try:
        raw = bytes(read(rva, n)).split(b"\0", 1)[0]
        txt = raw.decode("utf-8")
    except Exception:                                      # noqa: BLE001
        return ""
    return txt if txt and txt.isprintable() and len(raw) < n else ""


def _abort_info(read, stubs, base: int, c: "Crash", f: "Frame", label_nid) -> dict:
    """Is the crash a deliberate abort (int 0x41 / int3 / ud2 ... at rip) and, when the faulting
    function was called from the first frame, which assert did it come from and which call decided it?

    Works on module-relative addresses (`read(rva, n)`). Returns {} when rip is not a trap
    instruction or the bytes cannot be read; the optional keys (file, line, checked, ...) are only
    set for what the caller's code actually shows."""
    from . import x86flow as xf
    rip = c.rip - base
    try:
        head = bytes(read(rip, 2))
    except Exception:                                      # noqa: BLE001
        return {}
    kind = next((n for pat, n in _TRAPS if head.startswith(pat)), "")
    if not kind:
        return {}
    info: dict = {"kind": kind}
    tgt = getattr(f, "call_target", None)
    if tgt is None or not f.call.startswith("function "):
        return info
    tgt -= base
    try:
        if not (tgt <= rip < tgt + 0x400 and _fn_start(read, rip) == tgt):
            return info                                    # the trap is not inside the called function
    except Exception:                                      # noqa: BLE001
        return info
    info["helper"] = base + tgt
    ret = f.addr - base
    try:
        fn = xf.function_at(read, ret - 5)
        k = fn.index(ret - 5)
    except Exception:                                      # noqa: BLE001
        return info
    ins = fn.insns
    # argument set-up right before the call: lea rdi,[rip+str] / mov esi,imm
    j = k - 1
    while j >= 0 and k - j <= 8 and ins[j].mnemonic not in _JCC and ins[j].mnemonic != "call":
        a = ins[j]
        if a.mnemonic == "lea" and a.op_str.startswith(("rdi,", "rsi,", "rdx,")) and a.rip_target is not None:
            s = _cstr(read, a.rip_target)
            if s and "file" not in info and ("\\" in s or "/" in s or "." in s):
                info["file"] = s
        elif a.mnemonic == "mov" and a.op_str.split(",")[0] in ("esi", "edx", "ecx") and a.raw is not None \
                and a.raw.operands[1].type == xf.x86.X86_OP_IMM and "line" not in info:
            info["line"] = a.raw.operands[1].imm
        j -= 1
    if j < 0 or ins[j].mnemonic not in _JCC or ins[j].target is None or not ret <= ins[j].target < ret + 0x40:
        return info
    # the branch that jumps over the assert: look back for the test/cmp and the call it checks
    m = j - 1
    while m >= 0 and j - m <= 4 and ins[m].mnemonic not in ("test", "cmp"):
        m -= 1
    if m < 1 or ins[m].mnemonic not in ("test", "cmp"):
        return info
    p = m - 1
    while p >= 0 and m - p <= 4 and ins[p].mnemonic != "call":
        p -= 1
    if p < 0 or ins[p].mnemonic != "call" or ins[p].target is None:
        return info
    t2 = ins[p].target
    info["checked_call"] = base + ins[p].address
    nid, name = label_nid(t2)
    if nid:
        info["checked_nid"], info["checked"] = nid, name or nid
    else:
        info["checked"] = f"function {base + t2:#x}"
    return info


def _abort_check(t: Triage, c: Crash, load, nid_of) -> None:
    """Fill c.abort when rip is a trap instruction in an /app0/ binary (see _abort_info)."""
    if c.rip is None:
        return
    m = c.module_at(c.rip)
    if not m or not m.in_app:
        return
    got = load(m.rel)
    if not got:
        return
    b, stubs = got

    def read(r: int, n: int) -> bytes:
        return bytes(b.read(r, n))
    first = next((f for f in c.frames if f.module is m), None)
    try:
        dummy = first or Frame(0)
        c.abort = _abort_info(read, stubs, m.start, c, dummy, lambda tg: nid_of(stubs, read, tg))
    except Exception:                                      # noqa: BLE001 - triage never breaks on odd code
        c.abort = {}
    if c.abort.get("helper") and first is not None:
        first.call += " (assert/abort helper)"


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
    elif c.abort:
        _diagnose_abort(t, c)
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
        t.diagnosis.append(_fakelib_note(t, c))


_FAKELIB_TAIL = ("This is normal on a high firmware (the system libraries are new enough); on FW <= 7 it "
                 "would mean the fakelib loader (BackPork) is not active")


def _fakelib_note(t: Triage, c: Crash) -> str:
    """Why no /app0/fakelib/ module is loaded: name the ones the build folder has and what ran instead."""
    sys_paths = {m.name: m.path for m in c.modules if "/common/lib/" in m.path}
    present: list[str] = []
    for d in t.layers:
        try:
            present += sorted(p.name for p in (d / "fakelib").glob("*.sprx") if p.name not in present)
        except OSError:
            pass
    if not present:
        return "(note) no /app0/fakelib/ modules were loaded — the system libraries were used. " + _FAKELIB_TAIL
    used = [n for n in present if n in sys_paths]
    other = [n for n in present if n not in sys_paths]
    txt = f"(note) none of the {len(present)} fakelib/ module(s) in the build folder were loaded ({', '.join(present)})"
    if used:
        txt += f"; the console's own system copies of {', '.join(used)} (/common/lib/) were used instead"
    if other:
        txt += f"; {', '.join(other)} not loaded at all (not needed by this game, or not reached before the crash)"
    return txt + ". " + _FAKELIB_TAIL


def _diagnose_abort(t: Triage, c: Crash) -> None:
    a = c.abort
    t.diagnosis.append(f"deliberate abort ({a['kind']} at rip) — the game stopped itself; this is not a CPU "
                       f"fault, even though the log says '{c.reason or 'fault'}'")
    where = ""
    if a.get("file"):
        where = a["file"] + (f":{a['line']}" if "line" in a else "")
    if a.get("helper") and where:
        msg = f"game assertion failed at {where}"
    elif a.get("helper"):
        msg = f"the game's assert/abort helper at {a['helper']:#x} was called"
    else:
        return
    chk = a.get("checked")
    if chk:
        msg += f" — {chk} returned an error" if a.get("checked_nid") else f" — after the result of {chk} was checked"
    t.diagnosis.append(msg)
    hit = IMPORT_RULES.get(a.get("checked_nid", ""))
    if hit:
        rule, why = hit
        t.suggestions.append(f"build with --rule {rule}: {why}; the failing check is the call at "
                             f"{a['checked_call']:#x}")
    elif a.get("checked_nid"):
        t.suggestions.append(f"no ps5bp rule covers {chk} yet — look at what the game passes to it "
                             f"(call at {a['checked_call']:#x}) and compare with a working kit")
