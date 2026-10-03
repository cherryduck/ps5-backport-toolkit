"""Phase 9: generic rules learned from kits (savedata-mount, wwise-71), FW boundaries from
kit probes, `kit learn` as candidate finder, overlay originals + `undo`."""
import hashlib
import json
import os
import shutil
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from ps5bp.core.binary import Binary
from ps5bp.core.evidence import EvidenceDB
from ps5bp.core.pipeline import BuildOptions, build
from synth import TEXT_VA, Spec, build_elf, build_self
from test_phase8 import put, spec_with

MOUNT3 = "ZP4e7rlzOUk"


def mount_fn(mode: bytes, field: bytes = b"\xff\xff\xff\xff", at: int = 0x80) -> tuple[bytes, int]:
    """push rbp; mov rbp,rsp; lea rdi,[rbp-0x80]; mov qword [rbp-0x68],imm; <mode store>;
    call PLT entry 0 (text+16); pop rbp; ret  -> (code, offset of the -1 store)"""
    pre = bytes.fromhex("55 4889e5 488d7d80") + bytes.fromhex("48c74598") + field + mode
    call = b"\xe8" + struct.pack("<i", 16 - (at + len(pre) + 5))
    return pre + call + bytes.fromhex("5d c3"), at + 8


def mount_game(tmp: Path, mode: bytes, field: bytes = b"\xff\xff\xff\xff") -> tuple[Path, int]:
    code, store = mount_fn(mode, field)
    g = tmp / "PPSA99999"
    put(g / "eboot.bin", spec_with([MOUNT3], code_at={0x80: code}), (0x07000038, 0x10590001))
    (g / "sce_sys").mkdir(parents=True)
    (g / "sce_sys/param.json").write_text('{"titleId": "PPSA99999", "sdkVersion": "0x0700003800000000", '
                                          '"requiredSystemSoftwareVersion": "0x0700000000000000"}')
    return g, store


MODE_VAR = bytes.fromhex("8975a0")             # mov [rbp-0x60], esi   (mode unknown: may create)
MODE_RO = bytes.fromhex("c745a001000000")      # mov dword [rbp-0x60], 1


def test_savedata_sites_and_probe(tmp_path):
    from ps5bp.core.rules.savedata_mount import SavedataMount, sites
    g, store = mount_game(tmp_path / "a", MODE_VAR)
    b = Binary.load(g / "eboot.bin")
    (s,) = sites(b, 0x400000)
    assert s["state"] == "unfixed" and s["store"] == 0x400000 + TEXT_VA + store and s["mode"] is None
    assert SavedataMount.probe(b, 0x400000) == (1, 0)
    g2, _ = mount_game(tmp_path / "b", MODE_RO)
    assert SavedataMount.probe(Binary.load(g2 / "eboot.bin"), 0x400000) == (0, 0)   # read-only proves nothing
    g3, _ = mount_game(tmp_path / "c", MODE_VAR, b"\0\0\0\0")
    assert SavedataMount.probe(Binary.load(g3 / "eboot.bin"), 0x400000) == (0, 1)


def test_savedata_rule_builds(tmp_path):
    g, store = mount_game(tmp_path, MODE_VAR)
    db = EvidenceDB(tmp_path / "home")
    rep = build(g, BuildOptions(target=4, out=tmp_path / "out", rules={"savedata-mount"}), db, log=lambda m: None)
    (f,) = [x for x in rep.findings if x["rule"] == "savedata-mount"]
    assert f["applied"] and f["recommended"]
    b = Binary.load(tmp_path / "out/eboot.bin")
    assert b.read(TEXT_VA + store, 8) == bytes.fromhex("48c7459800000000")


def test_recommendation_from_kit_evidence(tmp_path):
    """A FW4 kit fixed + a FW6 kit of the same build unfixed -> needed <= 4, fine >= 6."""
    from ps5bp.core.rules.evidence_rules import recommendation
    fixed, _ = mount_game(tmp_path / "k4", MODE_VAR, b"\0\0\0\0")
    unfixed, _ = mount_game(tmp_path / "k6", MODE_VAR)
    db = EvidenceDB(tmp_path / "home")
    (fixed / "fakelib").mkdir(); (unfixed / "fakelib").mkdir()
    db.add_kit(fixed, 4, "k4")
    db.add_kit(unfixed, 6, "k6")
    obs = db.rule_observations("savedata-mount")
    assert {(o["kit"], o["unfixed"], o["fixed"]) for o in obs} == {("k4", 0, 1), ("k6", 1, 0)}
    prior = {"needed_max": 0, "ok_min": 99}                 # no built-in knowledge at all
    ctx = lambda t: SimpleNamespace(target=t, options={"db": db})     # noqa: E731
    assert recommendation("savedata-mount", ctx(4), prior)[0] is True
    assert "k4" in recommendation("savedata-mount", ctx(4), prior)[1]
    assert recommendation("savedata-mount", ctx(5), prior)[0] is False          # unknown
    r6 = recommendation("savedata-mount", ctx(6), prior)
    assert r6[0] is False and "k6" in r6[1]


def test_confirmed_prior_beats_kit_observation(tmp_path):
    from ps5bp.core.rules.evidence_rules import recommendation
    db = SimpleNamespace(rule_observations=lambda r: [{"kit": "k4", "relpath": "eboot.bin", "fw": 4, "tested_fw": None,
                                                        "unfixed": 3, "fixed": 0, "sig": "x"}])
    ctx = SimpleNamespace(target=4, options={"db": db})
    assert recommendation("wwise-71", ctx, {"needed_max": 4, "ok_min": 99})[0] is False
    ok, why = recommendation("wwise-71", ctx, {"needed_max": 4, "ok_min": 99, "confirmed": "console"})
    assert ok and "contradicted" in why


def test_wwise_sites_skip_tables():
    from ps5bp.core.rules.wwise71 import CFG_714, sites
    c = CFG_714.to_bytes(4, "little")
    code = (bytes.fromhex("48ba") + c + c + bytes.fromhex("4889500c")      # movabs rdx; mov [rax+0xc],rdx
            + bytes.fromhex("ba") + c + bytes.fromhex("b808f16300")         # mov edx, 7.1.4; mov eax, 7.1
            + bytes.fromhex("eb0c") + bytes.fromhex("b9") + c + bytes.fromhex("eb05")   # table arm
            + b"\xcc" * 16)
    spec = spec_with([MOUNT3], code_at={0x80: code})
    elf, _ = build_elf(spec)
    b = Binary(build_self(elf))
    got = [(ins - TEXT_VA, n) for ins, _, n in sites(b, 0)]
    assert got == [(0x80, 2), (0x80 + 14, 1)]


def test_learn_explains_rule_edits(tmp_path):
    from ps5bp.core.learn import learn
    code, _ = mount_fn(MODE_VAR)
    fixed, _ = mount_fn(MODE_VAR, b"\0\0\0\0")
    put(tmp_path / "orig/eboot.bin", spec_with([MOUNT3], code_at={0x80: code}), (0x12000038, 0x13090001))
    put(tmp_path / "kit/eboot.bin", spec_with([MOUNT3], code_at={0x80: fixed}), (0x04000031, 0x09040001))
    (r,), recipes = learn(tmp_path / "orig", tmp_path / "kit", "PPSA99999")
    assert set(r.classes) == {"sdk", "savedata"} and recipes == []


def sha_tree(d: Path) -> dict:
    return {str(p.relative_to(d)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(d.rglob("*")) if p.is_file()}


@pytest.mark.parametrize("keep_originals", [True, False])
def test_overlay_copied_over_game_then_undo(tmp_path, keep_originals):
    from ps5bp.core.undo import apply_undo, plan_undo
    g, _ = mount_game(tmp_path / "src", MODE_VAR)
    put(g / "sce_module/libc.prx", Spec(kind="module", module="libc", ps5_sdk=0x07000038,
                                        import_libs=["libkernel"], imports=[("4h6F1LLbTiw", 0)]))
    before = sha_tree(g)
    db = EvidenceDB(tmp_path / "home")
    out = tmp_path / "out"
    rep = build(g, BuildOptions(target=4, out=out, rules={"savedata-mount"}), db, log=lambda m: None)
    odir = Path(rep.originals)
    assert odir.name == "out.originals" and sha_tree(odir) == {k: before[k] for k in sha_tree(odir)}
    if not keep_originals:
        shutil.rmtree(odir)
    shutil.copytree(out, g, dirs_exist_ok=True)              # what the user did
    for f in ("backport-report.json", "backport-report.txt"):
        (g / f).unlink()
    assert sha_tree(g) != before
    up = plan_undo(g, [out])
    apply_undo(g, up)
    assert sha_tree(g) == before


AC8 = Path(os.environ.get("PS5BP_FIXTURES", "/nonexistent"))


@pytest.mark.skipif(not ((AC8 / "ac8-dump/eboot.bin").is_file() and (AC8 / "ac8-dlps/eboot.bin").is_file()
                         and (AC8 / "viet-11386").is_dir()),
                    reason="needs PS5BP_FIXTURES/ac8-dump, ac8-dlps, dlps-11386, viet-11386")
def test_ac8_generic_rules_no_recipe(tmp_path):
    """The console-confirmed AC8 build comes from generic rules alone: learn finds nothing
    game-specific; savedata-mount is recommended at 4 from the PPSA11386 kits (other game)."""
    from ps5bp.core.learn import learn
    from ps5bp.core.pipeline import plan
    dump, kit = AC8 / "ac8-dump", AC8 / "ac8-dlps"
    _, recipes = learn(dump, kit, "PPSA24913")
    assert recipes == []
    db = EvidenceDB(tmp_path / "home")
    db.add_kit(AC8 / "dlps-11386", 4, "dlps-11386")
    db.add_kit(AC8 / "viet-11386", 6, "viet-11386")
    p = plan(dump, 4, db)
    rec = {f.rule for f in p.findings if f.recommended}
    assert {"savedata-mount", "wwise-71"} <= rec          # both console-confirmed on AC8
    db.add_kit(kit, 4, "dlps-ac8", tested_fw=10)
    out = tmp_path / "out"
    rep = build(dump, BuildOptions(target=4, target_minor=0x03, out=out,
                                   rules={"kit-stubs", "mapflex-flags", "savedata-mount", "wwise-71"},
                                   stubs_from=["dlps-ac8"], replace_dump={"libSceAmpr": "dlps-ac8"}),
                db, log=lambda m: None)
    assert rep.ok
    for rel in ("eboot.bin", "sce_module/libc.prx"):
        a, b = bytearray(Binary.load(kit / rel).to_elf()), bytearray(Binary.load(out / rel).to_elf())
        a[0x3C:0x3E] = b[0x3C:0x3E] = b"\0\0"
        assert a == b, rel
