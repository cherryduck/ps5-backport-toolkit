"""Generate memory-fix recipes from scanned allocation sites, and track console trials.

Choice syntax: SITE:VARIANT[:AMOUNT]   e.g.  3d77bbc:page-split   4171888:shrink:128M
  SITE     the allocating call's VA (hex, as listed by `ps5bp memfix`) or #N (rank)
  VARIANT  shrink | page-split | retry-align
  AMOUNT   shrink only: cut size (default 128M; threshold = 2 x cut)

Generated recipes locate their patch points with byte signatures ("anchors", rel32 and
rip displacements wildcarded) and refer to original call targets symbolically, so the same
recipe can apply to a different build of the game where the code moved.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from . import x86flow as xf
from .binary import Binary
from .evidence import home
from .memsite import PAGE, Scanner, Site, rank
from .nid import nid

AMOUNTS = (128 << 20, 256 << 20, 512 << 20)
REG = {r: k for k, r in enumerate(("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"))}


class MemfixError(Exception):
    pass


def parse_amount(s: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([KMG]?)B?", s.strip().upper())
    if not m:
        return int(s, 0)
    return int(m[1]) << {"": 0, "K": 10, "M": 20, "G": 30}[m[2]]


def fmt_amount(n: int) -> str:
    return f"{n >> 20}M" if n % (1 << 20) == 0 else f"{n:#x}"


# ---- tiny encoders -------------------------------------------------------------------------
def _rex(w: int, r: int = 0, b: int = 0) -> str:
    return f"{0x40 | w << 3 | (r >= 8) << 2 | (b >= 8):02x}"


def mov_rr(dst: str, src: str) -> str:
    d, s = REG[dst], REG[src]
    return _rex(1, s, d) + "89" + f"{0xC0 | (s & 7) << 3 | (d & 7):02x}"


def alu_ri(op: str, reg: str, imm: int) -> str:
    ext = {"cmp": 7, "sub": 5, "add": 0}[op]
    if not 0 <= imm < 1 << 31:
        raise MemfixError(f"immediate {imm:#x} does not fit a sign-extended imm32")
    r = REG[reg]
    return _rex(1, 0, r) + "81" + f"{0xC0 | ext << 3 | (r & 7):02x}" + imm.to_bytes(4, "little").hex()


# ---- anchors ---------------------------------------------------------------------------------
def _wild(ins: xf.Insn) -> str:
    b = bytearray(ins.bytes)
    mask = [False] * len(b)
    if ins.target is not None and ins.imm_offset and b[0] in (0xE8, 0xE9, 0x0F):
        for k in range(ins.imm_offset, min(ins.imm_offset + 4, len(b))):
            mask[k] = True
    if ins.rip_target is not None and ins.disp_offset:
        for k in range(ins.disp_offset, ins.disp_offset + 4):
            mask[k] = True
    return " ".join("??" if m else f"{c:02x}" for c, m in zip(b, mask))


def _regex(pat: str) -> re.Pattern:
    out = b""
    for t in pat.split():
        out += b"." if t == "??" else re.escape(bytes.fromhex(t))
    return re.compile(out, re.S)


def find_all(b: Binary, pat: str, base: int, limit: int = 3) -> list[int]:
    rx = _regex(pat)
    hits = []
    for p in b.loads():
        if not p.is_exec:
            continue
        for m in rx.finditer(b.segment_bytes(p)):
            hits.append(base + p.vaddr + m.start())
            if len(hits) >= limit:
                return hits
    return hits


def make_anchor(sc: Scanner, name: str, va: int) -> dict:
    """Shortest unique signature containing the instruction at va (grows back, then forward)."""
    fn = xf.function_at(sc.read, va)
    k = fn.index(va)
    for span in range(0, 28):
        for fwd in range(0, span + 1):
            j, e = k - (span - fwd), k + fwd
            if j < 0 or e >= len(fn.insns):
                continue
            pat = " ".join(_wild(i) for i in fn.insns[j:e + 1])
            if sum(t != "??" for t in pat.split()) < 8:
                continue
            if len(find_all(sc.b, pat, sc.base, 2)) == 1:
                return {"name": name, "find": pat, "offset": va - fn.insns[j].address, "va": f"{va:#x}"}
    raise MemfixError(f"no unique signature for {va:#x}")


# ---- templates -------------------------------------------------------------------------------
def cave_shrink(label: str, s: Site, cut: int, threshold: int | None = None) -> tuple[list, list, list]:
    if s.hook is None:
        raise MemfixError(f"{s.id}: no hook point for shrink ({s.shrink_why})")
    thr = threshold if threshold is not None else 2 * cut
    code = [alu_ri("cmp", s.hook_reg, thr), f"rel8 72 @{label}_go", alu_ri("sub", s.hook_reg, cut),
            f"label {label}_go", f"rel32 e9 orig:${label}_h"]
    return ([(f"{label}_h", s.hook)], [{"label": label, "segment": 0, "align": 16, "code": code}],
            [{"call": f"${label}_h", "to": f"@{label}"}])


def cave_page_split(label: str, s: Site, callers: list[int], exit_nid: str) -> tuple[list, list, list]:
    ps = s.page_split
    if not ps:
        raise MemfixError(f"{s.id}: not a page-array allocation, page-split does not apply")
    if not callers:
        raise MemfixError(f"{s.id}: function {s.fn:#x} has no direct callers")
    L = label
    epi = "4883c418 5b 415c 415d 415e 415f 5d c3"
    code = [alu_ri("cmp", ps["page"], PAGE), f"rel32 0f85 @{L}_fallback",
            "55 4889e5 4157 4156 4155 4154 53 4883ec18",
            " ".join((mov_rr("r15", ps["out"]), mov_rr("r14", ps["page"]), mov_rr("r13", ps["count"]))),
            "4531e4 31db 4d85ed", f"rel32 0f84 @{L}_done",
            f"label {L}_loop", f"rel32 e8 nid:{nid('sceKernelGetDirectMemorySize')}",
            "48c745c800000000 4c8d4dc8 4889c6 4c89f2 4c89f1 41b8" + int(ps["memtype"]).to_bytes(4, "little").hex()
            + " 31ff",
            f"rel32 e8 orig:${L}_a", "85c0", f"rel32 0f85 @{L}_fail",
            "488b45c8 498904df 4d01f4 48ffc3 4c39eb", f"rel32 0f85 @{L}_loop",
            f"label {L}_done"]
    anchors = [(f"{L}_a", s.call)]
    if ps.get("account"):
        code.append(f"rip f04c0125 riptgt:${L}_acct")
        anchors.append((f"{L}_acct", ps["account_va"]))
    code += [ps["ret"] + " " + epi, f"label {L}_fail"]
    if ps.get("fail_edi"):
        code += [ps["fail_edi"], f"rel32 e8 nid:{exit_nid}", "0f0b"]
    else:
        code += ["31c0 " + epi]
    code += [f"label {L}_fallback", f"rel32 e9 orig:${L}_c0"]
    ops = []
    for n, c in enumerate(callers):
        anchors.append((f"{L}_c{n}", c))
        ops.append({"call": f"${L}_c{n}", "to": f"@{L}"})
    return anchors, [{"label": L, "segment": 0, "align": 16, "code": code}], ops


def cave_retry_align(label: str, s: Site, floor: int = 0x10000) -> tuple[list, list, list]:
    """Call the allocator; if it fails and the alignment (rcx) is above `floor`, tail-call it
    again with alignment = floor. 56 bytes; stack stays 16-byte aligned at both calls."""
    if s.len_reg != "rdx":
        raise MemfixError(f"{s.id}: retry-align supports AllocateDirectMemory-style calls only")
    L = label
    f4 = floor.to_bytes(4, "little").hex()
    code = ["57 56 52 51 4150 4151 50",                 # save args (+ pad slot for alignment)
            f"rel32 e8 orig:${L}_a", "85c0", f"rel8 74 @{L}_ok",
            "48817c2418" + f4, f"rel8 76 @{L}_ok",        # cmp qword [rsp+0x18] (saved rcx), floor
            "4883c408 4159 4158 59 5a 5e 5f",            # restore the arguments
            "b9" + f4, f"rel32 e9 orig:${L}_a",          # retry as a tail call
            f"label {L}_ok", "4883c438 c3"]
    return [(f"{L}_a", s.call)], [{"label": L, "segment": 0, "align": 16, "code": code}], \
        [{"call": f"${L}_a", "to": f"@{L}"}]


# ---- generation -----------------------------------------------------------------------------
def crash_frames(klog_text: str, file: str = "eboot.bin", base: int = 0x400000) -> list[int]:
    from . import klog
    t = klog.parse(klog_text)
    if not t.crashes:
        return []
    return [f.addr - f.module.start + base for f in t.crashes[-1].frames
            if f.module is not None and f.module.in_app and f.module.rel == file]


def scan(game: Path, file: str = "eboot.bin", klog_text: str | None = None):
    b = Binary.load(game / file)
    sc = Scanner(b)
    sites = rank(sc.sites(), crash_frames(klog_text) if klog_text else [])
    return sc, sites


def generate(game: Path, choices: list[str], title_id: str = "", klog_text: str | None = None,
             file: str = "eboot.bin") -> dict:
    sc, sites = scan(game, file, klog_text)
    by_id = {s.id: s for s in sites}
    anchors, caves, ops, notes = [], [], [], []
    for n, ch in enumerate(choices):
        parts = ch.split(":")
        if len(parts) < 2:
            raise MemfixError(f"bad choice '{ch}' (want SITE:VARIANT[:AMOUNT])")
        sid, var = parts[0].lower().removeprefix("0x"), parts[1]
        if sid.startswith("#"):
            k = int(sid[1:]) - 1
            if not 0 <= k < len(sites):
                raise MemfixError(f"no site {sid}")
            s = sites[k]
        elif sid in by_id:
            s = by_id[sid]
        else:
            raise MemfixError(f"no allocation site {sid} in {file} (run `ps5bp memfix` to list them)")
        L = f"mf{n}"
        if var == "shrink":
            cut = parse_amount(parts[2]) if len(parts) > 2 else AMOUNTS[0]
            a, c, o = cave_shrink(L, s, cut)
            notes.append(f"{s.id} shrink: requests >= {fmt_amount(2 * cut)} at hook {s.hook:#x} lose "
                         f"{fmt_amount(cut)} ({s.hook_reg}; {s.shrink_why})")
            if not s.shrink_safe:
                notes.append(f"  WARNING {s.id}: shrink marked unsafe: {s.shrink_why}")
        elif var == "page-split":
            if s.page_split and s.page_split.get("account"):
                s.page_split["account_va"] = _account_va(sc, s)
            callers = s.crash_callers or s.callers
            exit_nid = _exit_nid(sc, s)
            a, c, o = cave_page_split(L, s, callers, exit_nid)
            notes.append(f"{s.id} page-split: {fmt_amount(PAGE)} pages allocated one by one, hooked at "
                         + ", ".join(f"{x:#x}" for x in callers)
                         + (" (callers on the crash path)" if s.crash_callers else " (all callers)"))
        elif var == "retry-align":
            a, c, o = cave_retry_align(L, s)
            notes.append(f"{s.id} retry-align: on failure retry with 64K alignment")
        else:
            raise MemfixError(f"unknown variant '{var}' (shrink | page-split | retry-align)")
        anchors += [make_anchor(sc, name, va) for name, va in a]
        caves += c
        ops += o
    return {"name": f"{title_id or game.name}-memfix-" + "-".join(c.replace(":", "_") for c in choices),
            "rule": "memfix", "title_id": title_id, "file": file,
            "note": "Generated by ps5bp memfix: " + "; ".join(notes),
            "choices": list(choices), "anchors": anchors, "caves": caves, "ops": ops}


def _account_va(sc: Scanner, s: Site) -> int:
    fn = xf.function_at(sc.read, s.call)
    k = fn.index(s.call)
    for i in fn.insns[k + 1:k + 6]:
        if i.bytes[:1] == b"\xf0" and i.rip_target is not None:
            return i.address
    raise MemfixError("accounting instruction vanished")


def _exit_nid(sc: Scanner, s: Site) -> str:
    fn = xf.function_at(sc.read, s.call)
    for i in fn.insns:
        if i.mnemonic == "call" and i.target is not None and sc.name(i.target) == "exit":
            return sc._nid(i.target)
    return nid("exit")


# ---- trials ----------------------------------------------------------------------------------
def trials_dir(title: str) -> Path:
    return home() / "trials" / (title or "unknown")


def user_recipes_dir() -> Path:
    return home() / "recipes"


def new_trial(title: str, recipe: dict, game: Path, target: int) -> tuple[int, Path]:
    d = trials_dir(title)
    d.mkdir(parents=True, exist_ok=True)
    n = 1 + max((int(p.stem) for p in d.glob("*.json") if p.stem.isdigit()), default=0)
    p = d / f"{n}.json"
    p.write_text(json.dumps({"id": n, "title_id": title, "game": str(game), "target": target,
                             "time": time.strftime("%Y-%m-%d %H:%M:%S"), "choices": recipe["choices"],
                             "out": None, "result": None, "recipe": recipe}, indent=1), encoding="utf-8")
    return n, p


def recipe_file(trial_path: Path) -> Path:
    """The trial's recipe as a standalone file (what the build applies)."""
    t = json.loads(trial_path.read_text(encoding="utf-8"))
    p = trial_path.with_suffix(".recipe.json")
    p.write_text(json.dumps(t["recipe"], indent=1), encoding="utf-8")
    return p


def list_trials(title: str) -> list[dict]:
    d = trials_dir(title)
    out = [json.loads(p.read_text(encoding="utf-8")) for p in d.glob("*.json") if p.stem.isdigit()] if d.is_dir() else []
    return sorted(out, key=lambda t: t["id"])


def update_trial(title: str, n: int, **kw) -> dict:
    p = trials_dir(title) / f"{n}.json"
    if not p.is_file():
        raise MemfixError(f"no trial {n} for {title}")
    t = json.loads(p.read_text(encoding="utf-8"))
    t.update(kw)
    p.write_text(json.dumps(t, indent=1), encoding="utf-8")
    return t


def record_result(game: Path, title: str, n: int, works: bool, klog_text: str | None = None) -> list[str]:
    """Mark a trial; promote on success, explain what moved on failure. Returns message lines."""
    t = update_trial(title, n, result="works" if works else "crash")
    if works:
        r = dict(t["recipe"], rule="pssr-memory")
        r["name"] = r["name"].replace("-memfix-", "-memfix-ok-")
        r["note"] = r["note"] + f"  [confirmed on console: trial {n}, FW {t['target']}]"
        d = user_recipes_dir()
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{r['name']}.json"
        p.write_text(json.dumps(r, indent=1), encoding="utf-8")
        return [f"trial {n} works — saved as {p}", "the pssr-memory rule now offers it for this title"]
    msgs = [f"trial {n} marked as crashing"]
    if not klog_text:
        return msgs + ["give the new crash log (--klog) to see whether the failure moved"]
    _, sites = scan(game, t["recipe"].get("file", "eboot.bin"), klog_text)
    hit = [s for s in sites if s.on_crash_path]
    tried = {c.split(":")[0] for c in t["choices"]}
    if not crash_frames(klog_text, t["recipe"].get("file", "eboot.bin")):
        return msgs + ["the new log has no crash inside the game binary: look at `ps5bp klog` — the "
                       "patch may have moved the failure into a system module or another check"]
    if not hit:
        return msgs + ["the crash is no longer on an allocation path: the memory fix probably worked and "
                       "the next problem is something else (run `ps5bp klog`)"]
    s = hit[0]
    if s.id in tried:
        msgs.append(f"the same allocation ({s.id}) still fails")
        for c in t["choices"]:
            p = c.split(":")
            if p[0] == s.id and p[1] == "shrink":
                cur = parse_amount(p[2]) if len(p) > 2 else AMOUNTS[0]
                nxt = next((a for a in AMOUNTS if a > cur), None)
                msgs.append(f"next: {s.id}:shrink:{fmt_amount(nxt)}" if nxt else
                            "already at the largest cut: try another variant or another site")
            elif p[0] == s.id:
                others = [v for v in s.variants() if v != p[1]]
                msgs.append("next: try " + ", ".join(f"{s.id}:{v}" for v in others))
    else:
        msgs.append(f"progress: the failure moved to another allocation, {s.id} ({s.api}) in fn {s.fn:#x}")
        msgs.append("next: keep the current choices and add " + ", ".join(f"{s.id}:{v}" for v in s.variants()))
    return msgs
