"""Fix rules and patch recipes on synthetic binaries with real PLT entries."""
import json
import struct

import pytest

from ps5bp.core import dynamic, sdk
from ps5bp.core.asm import Asm, plt_stubs
from ps5bp.core.binary import Binary
from ps5bp.core.evidence import EvidenceDB
from ps5bp.core.nid import nid
from ps5bp.core.pipeline import BuildError, BuildOptions, build
from ps5bp.core.recipe import Recipe
from synth import TEXT_VA, Spec, build_elf, build_self

B = 0x400000
PRO, TRIN = "NH6xARDOVv8", nid("sceKernelIsTrinityMode")


def plt_spec(**kw) -> tuple[Spec, dict]:
    """Spec whose text = PLT entry per import, then `call <plt0>` at TEXT_VA+0x80."""
    spec = Spec(**kw)
    _, lay = build_elf(spec)
    text = bytearray(b"\xcc" * 0x100)
    for k, got in enumerate(lay["got"]):
        i = k * 16
        text[i:i + 16] = (b"\xff\x25" + struct.pack("<i", got - (TEXT_VA + i + 6)) + b"\x68"
                          + struct.pack("<I", k) + b"\xe9" + struct.pack("<i", -(i + 16)))
    text[0x80:0x85] = b"\xe8" + struct.pack("<i", 0 - (0x80 + 5))      # call plt[0]
    spec.text = bytes(text)
    elf, lay2 = build_elf(spec)
    assert lay2["got"] == lay["got"]
    return spec, lay


def put(path, spec):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_self(build_elf(spec)[0]))


@pytest.fixture
def game(tmp_path):
    g = tmp_path / "PPSA99999"
    spec, _ = plt_spec(import_libs=["libkernel"], imports=[(PRO, 0), (TRIN, 0), ("KKKKKKKKKK1", 0)])
    put(g / "eboot.bin", spec)
    return g


@pytest.fixture
def db(tmp_path):
    """Kit that stubs PRO (=> absent on FW4) and imports KKKKKKKKKK1 from the system (=> present)."""
    k = tmp_path / "kit"
    put(k / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("KKKKKKKKKK1", 0)]))
    put(k / "fakelib/libSceFoo.sprx", Spec(kind="module", module="libSceFoo", export_libs=["libSceFoo"],
                                           exports=[("FFFFFFFFFF1", 0)], import_libs=["libkernel"],
                                           imports=[], stubbed=[(PRO, 0)]))
    d = EvidenceDB(tmp_path / "home")
    d.add_kit(k, 4, "kit")
    yield d
    d.close()


def test_plt_map(game):
    b = Binary.load(game / "eboot.bin")
    st = plt_stubs(b, dynamic.parse(b), B)
    assert sorted(n.split("#")[0] for n in st) == sorted([PRO, TRIN, "KKKKKKKKKK1"])
    assert st[next(n for n in st if n.startswith(PRO))] == B + TEXT_VA


def test_asm_fixups():
    a = Asm(0x1000)
    a.label("top").rel8("eb", "end").rel32("e8", 0x2000).rip32("488b05", 0x3000).rel32("0f85", "top").label("end")
    code = a.assemble()
    assert code[:2] == b"\xeb" + bytes([len(code) - 2])
    assert struct.unpack_from("<i", code, 3)[0] == 0x2000 - (0x1000 + 7)
    assert struct.unpack_from("<i", code, 10)[0] == 0x3000 - (0x1000 + 14)
    assert struct.unpack_from("<i", code, 16)[0] == -20


def test_pro_disable(game, db, tmp_path):
    out = tmp_path / "out"
    rep = build(game, BuildOptions(target=4, out=out, rules={"pro-disable"}), db, log=lambda m: None)
    assert rep.ok
    b = Binary.load(out / "eboot.bin")
    assert b.read(TEXT_VA, 16) == bytes.fromhex("31c089078906c3") + b"\xcc" * 9
    assert b.read(TEXT_VA + 16, 3) == bytes.fromhex("31c0c3")
    d = dynamic.parse(b)
    pro = [s for s in d.symbols if s.nid == PRO]
    trin = [s for s in d.symbols if s.nid == TRIN]
    assert all(s.defined and s.value == TEXT_VA for s in pro)       # absent on FW4 => bound locally
    assert all(not s.defined for s in trin)                         # not proven absent => import kept
    assert {f["rule"]: f["applied"] for f in rep.findings} == {"pro-disable": True}


def test_rules_off_by_default_but_recommended(game, db, tmp_path):
    rep = build(game, BuildOptions(target=4, out=tmp_path / "o"), db, log=lambda m: None)
    assert Binary.load(tmp_path / "o/eboot.bin").read(TEXT_VA, 2) == b"\xff\x25"
    assert any("recommended: --rule pro-disable" in w for w in rep.warnings)


def test_stub_absent_and_conflicts(game, db, tmp_path):
    rep = build(game, BuildOptions(target=4, out=tmp_path / "o", rules={"stub-absent"}), db, log=lambda m: None)
    assert not any(f["applied"] for f in rep.findings if f["rule"] == "stub-absent")   # PRO owned by pro-disable
    with pytest.raises(BuildError, match="conflicts"):
        build(game, BuildOptions(target=4, out=tmp_path / "p", rules={"pro-disable", "pssr-memory"}), db,
              log=lambda m: None)
    with pytest.raises(BuildError, match="unknown rule"):
        build(game, BuildOptions(target=4, out=tmp_path / "q", rules={"nope"}), db, log=lambda m: None)


def test_user_patch_recipe(game, db, tmp_path):
    b0 = Binary.load(game / "eboot.bin")
    seg = b0.phdrs[0]
    cave_va = B + b0.cave_rva(0, 16)
    recipe = {
        "name": "t", "file": "eboot.bin",
        "match": [{"va": hex(B + TEXT_VA + 0x80), "bytes": (b0.read(TEXT_VA + 0x80, 5)).hex()}],
        "caves": [{"label": "c", "segment": 0, "code": [
            "label c0", "4881ff00001000", "rel8 72 @skip", "4831ff", "label skip",
            "rel32 e9 nid:KKKKKKKKKK1"]}],
        "ops": [{"call": hex(B + TEXT_VA + 0x80), "to": "@c", "old_to": hex(B + TEXT_VA)},
                {"va": hex(B + TEXT_VA + 0x90), "old": "cccc", "new": "9090"}],
    }
    pf = tmp_path / "t.json"
    pf.write_text(json.dumps(recipe))
    out = tmp_path / "o"
    rep = build(game, BuildOptions(target=4, out=out, patches=[pf]), db, log=lambda m: None)
    assert rep.ok
    b = Binary.load(out / "eboot.bin")
    ins = b.read(TEXT_VA + 0x80, 5)
    assert B + TEXT_VA + 0x85 + struct.unpack("<i", ins[1:])[0] == cave_va
    code = b.read(cave_va - B, 17)
    assert code[:7] == bytes.fromhex("4881ff00001000") and code[7:9] == b"\x72\x03"
    assert cave_va + 17 + struct.unpack("<i", code[13:17])[0] == B + TEXT_VA + 32    # KKKK's PLT entry
    assert b.phdrs[0].filesz > seg.filesz and b.read(TEXT_VA + 0x90, 2) == b"\x90\x90"
    # applying the same recipe to its own output is refused by the match check
    rep2 = build(out, BuildOptions(target=4, out=tmp_path / "o2", patches=[pf], force=True), db, log=lambda m: None)
    assert any("not applicable" in w for w in rep2.warnings)
