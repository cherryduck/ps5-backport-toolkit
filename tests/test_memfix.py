"""memfix: allocation-site analysis, recipe generation, anchors, trials."""
import json
import os
import struct
from pathlib import Path

import capstone
import pytest

from ps5bp.core import memfix
from ps5bp.core.binary import Binary
from ps5bp.core.memsite import Scanner
from ps5bp.core.nid import nid
from ps5bp.core.recipe import Recipe
from synth import TEXT_VA, Spec, build_elf, build_self

B = 0x400000
GDMS, ADM, EXIT = nid("sceKernelGetDirectMemorySize"), nid("sceKernelAllocateDirectMemory"), nid("exit")
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def alloc_fn(at: int, plt: list[int], keep_copy: bool = False) -> bytes:
    """Pool-style function at text offset `at`: len = roundup(rdi, 2M) in r14, then
    GetDirectMemorySize, AllocateDirectMemory(0, end, r14, 2M, 1, &out), exit(-1) on failure."""
    gdms, adm, ex = plt
    c = bytearray()

    def call(t):
        c.extend(b"\xe8" + struct.pack("<i", t - (at + len(c) + 5)))
    c += bytes.fromhex("55 4889e5 4156 53 4883ec10 4989fe")
    if keep_copy:
        c += bytes.fromhex("4889fb")                          # mov rbx, rdi (second copy of the input)
    c += bytes.fromhex("4981c6ffff1f00 4981e60000e0ff")     # add r14, 0x1fffff ; and r14, -2M
    call(gdms)                                                # hook point (first call after the length)
    c += bytes.fromhex("4c8d4de8 b900002000 4889c6 4c89f2 41b801000000 31ff")
    call(adm)
    c += bytes.fromhex("85c0")
    tail = bytes.fromhex(("4889d8 " if keep_copy else "") + "4883c410 5b 415e 5d c3")
    c += bytes([0x75, len(tail)]) + tail
    c += bytes.fromhex("bfffffffff")
    call(ex)
    c += bytes.fromhex("0f0b")
    return bytes(c)


def make(path: Path, shift: int = 0, keep_copy: bool = False) -> Path:
    spec = Spec(import_libs=["libkernel"], imports=[(GDMS, 0), (ADM, 0), (EXIT, 0)])
    _, lay = build_elf(spec)
    text = bytearray(b"\xcc" * 0x200)
    for k, got in enumerate(lay["got"]):
        i = k * 16
        text[i:i + 16] = (b"\xff\x25" + struct.pack("<i", got - (TEXT_VA + i + 6)) + b"\x68"
                          + struct.pack("<I", k) + b"\xe9" + struct.pack("<i", -(i + 16)))
    at = 0x80 + shift
    plt = [TEXT_VA + 16 * k for k in range(3)]
    fn = alloc_fn(TEXT_VA + at, plt, keep_copy)
    text[at:at + len(fn)] = fn
    spec.text = bytes(text)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_self(build_elf(spec)[0]))
    return path


def test_encoders_roundtrip():
    regs = list(memfix.REG)
    for d in regs:
        for s in regs:
            i = next(md.disasm(bytes.fromhex(memfix.mov_rr(d, s)), 0))
            assert (i.mnemonic, i.op_str) == ("mov", f"{d}, {s}")
        for op in ("cmp", "sub"):
            i = next(md.disasm(bytes.fromhex(memfix.alu_ri(op, d, 0x10000000)), 0))
            assert (i.mnemonic, i.op_str) == (op, f"{d}, 0x10000000")
    with pytest.raises(memfix.MemfixError):
        memfix.alu_ri("sub", "r14", 0x80000000)
    assert memfix.parse_amount("128M") == 128 << 20 and memfix.fmt_amount(256 << 20) == "256M"


def test_site_analysis(tmp_path):
    b = Binary.load(make(tmp_path / "g/eboot.bin"))
    (s,) = Scanner(b).sites()
    assert s.api == "sceKernelAllocateDirectMemory" and s.len_reg == "rdx"
    assert s.fatal and "exit" in s.fail_desc
    assert s.hook_reg == "r14" and s.shrink_safe and s.hook == s.fn + 0x1c
    assert s.variants() == ["shrink", "retry-align"]


def test_shrink_unsafe_when_input_kept(tmp_path):
    b = Binary.load(make(tmp_path / "g/eboot.bin", keep_copy=True))
    (s,) = Scanner(b).sites()
    assert not s.shrink_safe and "rbx" in s.shrink_why
    assert "shrink" not in s.variants()


def _apply(rec: dict, path: Path) -> Binary:
    r = Recipe.load("gen", json.dumps(rec))
    b = Binary.load(path)
    assert r.check(b) == ""
    r.apply(b)
    return b


def test_shrink_generates_cave_and_ports_to_moved_code(tmp_path):
    g = make(tmp_path / "g/eboot.bin").parent
    s = Scanner(Binary.load(g / "eboot.bin")).sites()[0]
    rec = memfix.generate(g, [f"{s.id}:shrink:128M"])
    assert rec["anchors"][0]["va"] == f"{s.hook:#x}"
    b = _apply(rec, g / "eboot.bin")
    hook = b.read(s.hook - B, 5)
    cave = s.hook + 5 + struct.unpack("<i", hook[1:])[0]
    ins = [(i.mnemonic, i.op_str) for i in md.disasm(b.read(cave - B, 32), cave)][:4]
    assert ins[0] == ("cmp", "r14, 0x10000000") and ins[1][0] == "jb" and ins[2] == ("sub", "r14, 0x8000000")
    assert ins[3] == ("jmp", f"{B + TEXT_VA:#x}")                 # original hook target (GDMS stub)
    # same recipe on a build where the function moved by 0x30: anchors find it by signature
    g2 = make(tmp_path / "g2/eboot.bin", shift=0x30).parent
    b2 = _apply(rec, g2 / "eboot.bin")
    h2 = s.hook + 0x30
    assert b2.read(h2 - B, 1) == b"\xe8"
    cave2 = h2 + 5 + struct.unpack("<i", b2.read(h2 - B + 1, 4))[0]
    assert b2.read(cave2 - B, 7) == bytes.fromhex(memfix.alu_ri("cmp", "r14", 0x10000000))


def test_retry_align_cave(tmp_path):
    g = make(tmp_path / "g/eboot.bin").parent
    s = Scanner(Binary.load(g / "eboot.bin")).sites()[0]
    b = _apply(memfix.generate(g, [f"{s.id}:retry-align"]), g / "eboot.bin")
    cave = s.call + 5 + struct.unpack("<i", b.read(s.call - B + 1, 4))[0]
    ins = [(i.mnemonic, i.op_str) for i in md.disasm(b.read(cave - B, 56), cave)]
    adm = f"{B + TEXT_VA + 16:#x}"
    assert ("call", adm) in ins and ("jmp", adm) in ins       # first attempt, then tail-call retry
    assert ("cmp", "qword ptr [rsp + 0x18], 0x10000") in ins and ("mov", "ecx, 0x10000") in ins
    assert ins[-2:] == [("add", "rsp, 0x38"), ("ret", "")]


def test_bad_choices(tmp_path):
    g = make(tmp_path / "g/eboot.bin").parent
    for ch in ("nope", "123:shrink", "#9:shrink"):
        with pytest.raises(memfix.MemfixError):
            memfix.generate(g, [ch])
    s = Scanner(Binary.load(g / "eboot.bin")).sites()[0]
    with pytest.raises(memfix.MemfixError):
        memfix.generate(g, [f"{s.id}:page-split"])            # not a page-array allocator


def test_trial_promotion(tmp_path, monkeypatch):
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))
    g = make(tmp_path / "PPSA99999/eboot.bin").parent
    s = Scanner(Binary.load(g / "eboot.bin")).sites()[0]
    rec = memfix.generate(g, [f"{s.id}:shrink:256M"], "PPSA99999")
    n, p = memfix.new_trial("PPSA99999", rec, g, 4)
    assert n == 1 and memfix.list_trials("PPSA99999")[0]["result"] is None
    msgs = memfix.record_result(g, "PPSA99999", 1, True)
    saved = list((tmp_path / "home/recipes").glob("*.json"))
    assert len(saved) == 1 and json.loads(saved[0].read_text())["rule"] == "pssr-memory"
    assert "works" in msgs[0] and memfix.list_trials("PPSA99999")[0]["result"] == "works"


ROOT = Path(os.environ.get("PS5BP_FIXTURES", "/nonexistent"))
SYN = ROOT / "wolverine-orig-synth"
KLOG = ROOT / "klog-wolverine-1160.txt"
need = pytest.mark.skipif(not (SYN.is_dir() and KLOG.is_file() and (ROOT / "wolverine-dlps").is_dir()),
                          reason="needs PS5BP_FIXTURES wolverine fixtures")


@need
def test_wolverine_sites_from_klog():
    _, sites = memfix.scan(SYN, klog_text=KLOG.read_text())
    top = sites[0]
    assert top.id == "3d77bbc" and top.on_crash_path and top.crash_callers == [0x42C445B]
    assert top.page_split and top.page_split["memtype"] == 12 and not top.shrink_safe
    pool = next(s for s in sites if s.id == "4171888")
    assert (pool.hook, pool.hook_reg, pool.shrink_safe) == (0x4171867, "r14", True)


@need
def test_wolverine_generated_fix_equals_dlps(tmp_path, monkeypatch):
    """The DLPS fix re-derived from analysis + klog, not replayed from the built-in recipe."""
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))
    from ps5bp.core.pipeline import BuildOptions, build
    out = tmp_path / "out"
    rep = build(SYN, BuildOptions(target=4, out=out, fakelibs=False, force=True,
                                  memfix=["4171888:shrink:128M", "3d77bbc:page-split"], klog=KLOG),
                log=lambda *_: None)
    assert rep.ok and rep.memfix_trial == 1 and (out / "memfix-recipe.json").is_file()
    assert (out / "eboot.bin").read_bytes() == (ROOT / "wolverine-dlps" / "eboot.bin").read_bytes()


@need
def test_promoted_recipe_supersedes_builtin(tmp_path, monkeypatch):
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))
    from ps5bp.core.pipeline import BuildOptions, build
    rec = memfix.generate(SYN, ["4171888:shrink:128M", "3d77bbc:page-split"], "", KLOG.read_text())
    n, _ = memfix.new_trial("", rec, SYN, 4)
    memfix.record_result(SYN, "", n, True)
    out = tmp_path / "out"
    rep = build(SYN, BuildOptions(target=4, out=out, fakelibs=False, force=True, rules={"pssr-memory"}), log=lambda *_: None)
    applied = [f["title"] for f in rep.findings if f["applied"]]
    assert len(applied) == 1 and "memfix-ok" in applied[0]           # user recipe only, built-in skipped
    assert (out / "eboot.bin").read_bytes() == (ROOT / "wolverine-dlps" / "eboot.bin").read_bytes()
