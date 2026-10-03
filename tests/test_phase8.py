"""Phase 8: PLT-stub learning from kits, evidence weights, dump loading layers, kit-stubs,
mapflex-flags, minor-version targets, kit learn."""
import json
import os
import struct
from pathlib import Path

import pytest

from ps5bp.core import dynamic, sdk
from ps5bp.core.asm import canonical_plt, plt_entries
from ps5bp.core.binary import Binary
from ps5bp.core.coverage import analyze
from ps5bp.core.evidence import EvidenceDB
from ps5bp.core.pipeline import BuildError, BuildOptions, build, downgrade_sdk, patch_param_json
from ps5bp.core.scan import scan_game
from synth import TEXT_VA, Spec, build_elf, build_self

B = 0x400000
N1, N2, N3 = "AAAAAAAAAA1", "AAAAAAAAAA2", "AAAAAAAAAA3"     # three libkernel imports
MAPFLEX = "IWIBBdTHit4"


def spec_with(imports, code_at: dict[int, bytes] | None = None, stub: dict[int, bytes] | None = None,
              **kw) -> Spec:
    """PLT entry per import at TEXT_VA+16k; extra code at text offsets; PLT entries
    overwritten with `stub` bodies (a backporter's in-place stub)."""
    spec = Spec(import_libs=["libkernel"], imports=[(n, 0) for n in imports], **kw)
    _, lay = build_elf(spec)
    text = bytearray(b"\xcc" * 0x200)
    for k, got in enumerate(lay["got"]):           # PLT0 at text+0, entry k at 16(k+1)
        i = 16 * (k + 1)
        text[i:i + 16] = (b"\xff\x25" + struct.pack("<i", got - (TEXT_VA + i + 6)) + b"\x68"
                          + struct.pack("<I", k) + b"\xe9" + struct.pack("<i", 0 - (i + 16)))
    for k, body in (stub or {}).items():
        i = 16 * (k + 1)
        text[i:i + len(body)] = body
    for off, code in (code_at or {}).items():
        text[off:off + len(code)] = code
    spec.text = bytes(text)
    return spec


def put(path: Path, spec: Spec, sdk_pair=None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = build_self(build_elf(spec)[0])
    path.write_bytes(data)
    if sdk_pair:
        b = Binary.load(path)
        sdk.set_sdk(b, *sdk_pair)
        b.save(path)
    return path


def test_plt_entries_include_overwritten(tmp_path):
    spec = Spec(import_libs=["libkernel"], imports=[(N1, 0), (N2, 0), (N3, 0)])
    _, lay = build_elf(spec)
    text = bytearray(b"\xcc" * 0x100)
    for k, got in enumerate(lay["got"]):
        i = 16 * (k + 1)                           # PLT0 at 0, entries at 16, 32, 48
        text[i:i + 16] = (b"\xff\x25" + struct.pack("<i", got - (TEXT_VA + i + 6)) + b"\x68"
                          + struct.pack("<I", k) + b"\xe9" + struct.pack("<i", 0 - (i + 16)))
    text[32:35] = bytes.fromhex("31c0c3")         # N2 overwritten in place
    spec.text = bytes(text)
    b = Binary.load(put(tmp_path / "e/eboot.bin", spec))
    es = plt_entries(b, dynamic.parse(b), B)
    assert [(n.split("#")[0], va - B) for n, va, _ in es] == [(N1, 16), (N2, 32), (N3, 48)]
    assert [canonical_plt(e) for _, _, e in es] == [True, False, True]


def kit_spec(stub_n2: bool = True, ampr: bool = False) -> Spec:
    libs, imps = ["libkernel"], [(N1, 0), (N2, 0), (N3, 0)]
    if ampr:
        libs, imps = libs + ["libSceAmpr"], imps + [("AMPRAMPRAM1", 1)]
    spec = Spec(import_libs=libs, imports=imps)
    _, lay = build_elf(spec)
    text = bytearray(b"\xcc" * 0x100)
    for k, got in enumerate(lay["got"]):
        i = 16 * (k + 1)
        text[i:i + 16] = (b"\xff\x25" + struct.pack("<i", got - (TEXT_VA + i + 6)) + b"\x68"
                          + struct.pack("<I", k) + b"\xe9" + struct.pack("<i", 0 - (i + 16)))
    if stub_n2:
        text[32:34] = bytes.fromhex("0f0b")        # ud2
    spec.text = bytes(text)
    return spec


@pytest.fixture
def kits(tmp_path):
    k = tmp_path / "kitA"
    put(k / "eboot.bin", kit_spec())
    put(k / "fakelib/libSceAmpr.sprx", Spec(kind="module", module="libSceAmpr", export_libs=["libSceAmpr"],
                                             exports=[("AMPRAMPRAM1", 0)], import_libs=["libkernel"],
                                             imports=[("KKKKKKKKKK9", 0)]))
    d = EvidenceDB(tmp_path / "home")
    r = d.add_kit(k, 4, "kitA", tested_fw=10)
    yield d, r
    d.close()


def test_ingest_records_plt_stubs_and_weak_presence(kits):
    db, r = kits
    assert r["plt_stubs"] == 1 and r["present_fw"] == 10
    assert set(db.stubbed("libkernel", 4)) == {N2}
    assert db.stubbed("libkernel", 4)[N2][0][1] == "0f0b"
    assert N2 not in db.present("libkernel", 10)            # stubbed import is not "present"
    assert db.present("libkernel", 4) == set()              # tested on 10 only: proves nothing for 4
    assert N1 in db.present("libkernel", 10)
    assert "KKKKKKKKKK9" not in db.present("libkernel", 10)  # Ampr emulator: no FW evidence
    assert db.kit("kitA").tested_fw == 10


def game_with(tmp_path, fakelib_ampr: bool = True, other_fakelib: bool = False, imports_ampr: bool = False) -> Path:
    g = tmp_path / "PPSA99999"
    put(g / "eboot.bin", kit_spec(stub_n2=False, ampr=imports_ampr))
    if fakelib_ampr:
        put(g / "fakelib/libSceAmpr.sprx", Spec(kind="module", module="libSceAmpr", export_libs=["libSceAmpr"],
                                                 exports=[("AMPRAMPRAM1", 0), ("AMPRAMPRAM2", 0)]))
        (g / "ampr_emu.index").write_bytes(b"idx")
    if other_fakelib:
        put(g / "fakelib/libSceFoo.prx", Spec(kind="module", module="libSceFoo", export_libs=["libSceFoo"],
                                               exports=[("FFFFFFFFFF1", 0)]))
    return g


def test_coverage_stubbed_and_dump_layer(kits, tmp_path):
    db, _ = kits
    gs = scan_game(game_with(tmp_path))
    cov = analyze(gs, db, 4)
    k = next(m for m in cov.modules if m.module == "libkernel")
    assert k.status == "stubbed" and k.stubbed == [N2] and k.stub_src[N2][0][0] == "kitA"
    assert not [m for m in cov.modules if m.module == "libSceAmpr"]       # game doesn't import it
    # dump layer (module present in fakelib/) stays even though a kit has one
    gs.binaries[0].imports_by_module["libSceAmpr"] = ["AMPRAMPRAM1"]
    cov = analyze(gs, db, 4)
    a = next(m for m in cov.modules if m.module == "libSceAmpr")
    assert a.status == "dump" and a.choice is None
    cov = analyze(gs, db, 4, {"libSceAmpr": "kitA"})
    a = next(m for m in cov.modules if m.module == "libSceAmpr")
    assert a.status == "fakelib" and a.choice.kit == "kitA" and "replaces the dump" in a.note


def test_kit_stubs_rule_writes_exact_body(kits, tmp_path):
    db, _ = kits
    g = game_with(tmp_path)
    rep = build(g, BuildOptions(target=4, out=tmp_path / "o", rules={"kit-stubs"}), db, log=lambda m: None)
    assert rep.ok
    b = Binary.load(tmp_path / "o/eboot.bin")
    e = {n.split("#")[0]: e for n, _, e in plt_entries(b, dynamic.parse(b), B)}
    assert e[N2][:2] == bytes.fromhex("0f0b") and e[N2][2:6] == kit_spec().text[34:38]   # rest untouched
    assert canonical_plt(e[N1]) and canonical_plt(e[N3])
    # dump's Ampr kept: not rewritten, and the overlay doesn't touch the index
    assert not (tmp_path / "o/fakelib/libSceAmpr.sprx").exists()
    # --stubs-from a kit that doesn't exist -> nothing applied
    rep = build(g, BuildOptions(target=4, out=tmp_path / "o2", rules={"kit-stubs"}, stubs_from=["nope"]),
                db, log=lambda m: None)
    assert not [f for f in rep.findings if f["rule"] == "kit-stubs"]


def test_replace_dump_ampr_handles_index(kits, tmp_path):
    db, _ = kits
    g = game_with(tmp_path, imports_ampr=True)
    kept = build(g, BuildOptions(target=4, out=tmp_path / "keep", mode="full"), db, log=lambda m: None)
    assert (tmp_path / "keep/ampr_emu.index").is_file()                        # dump layer + its index kept
    assert (tmp_path / "keep/fakelib/libSceAmpr.sprx").read_bytes() == (g / "fakelib/libSceAmpr.sprx").read_bytes()
    assert not kept.fakelibs
    rep = build(g, BuildOptions(target=4, out=tmp_path / "o", replace_dump={"libSceAmpr": "kitA"}), db,
                log=lambda m: None)
    assert [f["module"] for f in rep.fakelibs] == ["libSceAmpr"]
    assert any("ampr_emu.index" in w for w in rep.warnings)                   # overlay: tell the user
    rep = build(g, BuildOptions(target=4, out=tmp_path / "f", mode="full", replace_dump={"libSceAmpr": None}),
                db, log=lambda m: None)
    assert not (tmp_path / "f/ampr_emu.index").exists()                       # full: stale index dropped
    assert (tmp_path / "f/fakelib/libSceAmpr.sprx").read_bytes() != (g / "fakelib/libSceAmpr.sprx").read_bytes()


def test_already_backported_decided_by_sdk(kits, tmp_path):
    db, _ = kits
    g = game_with(tmp_path)                       # has fakelib/ but SDK 7.00 > 4: a dump, accepted
    build(g, BuildOptions(target=4, out=tmp_path / "o"), db, log=lambda m: None)
    b = Binary.load(g / "eboot.bin")
    downgrade_sdk(b, 4)
    b.save(g / "eboot.bin")
    with pytest.raises(BuildError, match="already SDK 4.00"):
        build(g, BuildOptions(target=4, out=tmp_path / "o2"), db, log=lambda m: None)


def test_other_dump_fakelib_kept_with_warning(kits, tmp_path):
    db, _ = kits
    g = game_with(tmp_path, other_fakelib=True)
    rep = build(g, BuildOptions(target=4, out=tmp_path / "o"), db, log=lambda m: None)
    assert any("libSceFoo" in w and "kept" in w for w in rep.warnings)


def test_minor_targets():
    assert sdk.parse_target("4.03") == (4, 0x03) and sdk.parse_target("5") == (5, 0)
    assert sdk.target_pair(4, 0x03) == (0x04030031, 0x09040001)
    assert sdk.target_str(4, 3) == "4.03" and sdk.target_str(4) == "4.xx"
    with pytest.raises(ValueError):
        sdk.parse_target("12")
    t, ch = patch_param_json('{"sdkVersion": "0x1200000000000000"}', 4, 0x03)
    assert t == '{"sdkVersion": "0x0403000000000000"}' and ch


def test_mapflex_flags(tmp_path):
    from ps5bp.core.rules.mapflex_flags import sites
    spec = Spec(import_libs=["libkernel"], imports=[(MAPFLEX, 0)])
    _, lay = build_elf(spec)
    text = bytearray(b"\xcc" * 0x100)
    got = lay["got"][0]
    text[16:32] = (b"\xff\x25" + struct.pack("<i", got - (TEXT_VA + 22)) + b"\x68" + struct.pack("<I", 0)
                   + b"\xe9" + struct.pack("<i", -32))
    pre = bytes.fromhex("55 4889e5 ba03000000 b900800000 4c89f7")      # ... mov ecx, 0x8000 ...
    fn = pre + b"\xe8" + struct.pack("<i", 16 - (0x80 + len(pre) + 5)) + bytes.fromhex("5d c3")
    text[0x80:0x80 + len(fn)] = fn
    spec.text = bytes(text)
    b = Binary.load(put(tmp_path / "m/sce_module/libc.prx", spec))
    assert sites(b, 0) == [0x80 + 9]


def test_kit_learn_isolates_game_edits(tmp_path):
    from ps5bp.core.learn import learn
    from ps5bp.core.recipe import Recipe
    fn = bytes.fromhex("55 4889e5 b801000000 5d c3")
    orig = put(tmp_path / "orig/eboot.bin", spec_with([N1, N2], code_at={0xA0: fn}), (0x12000038, 0x13090001))
    kit_fn = fn.replace(bytes.fromhex("b801000000"), bytes.fromhex("b802000000"))
    put(tmp_path / "kit/eboot.bin", spec_with([N1, N2], code_at={0xA0: kit_fn}, stub={1: bytes.fromhex("31c0c3")}),
        (0x04030031, 0x09040001))
    (tmp_path / "kit/fakelib").mkdir()
    reps, recipes = learn(tmp_path / "orig", tmp_path / "kit", "PPSA99999")
    (r,) = reps
    assert set(r.classes) == {"sdk", "plt-stub", "game"} and r.classes["game"] == 1
    (rec,) = recipes
    assert len(rec["ops"]) == 1 and rec["ops"][0]["va"].startswith("$g0")
    rc = Recipe.load("learned", json.dumps(rec))
    b = Binary.load(orig)
    assert rc.check(b, "PPSA99999") == ""
    rc.apply(b)
    assert b.read(0xA0 + 4, 5) == bytes.fromhex("b802000000")


AC8 = Path(os.environ.get("PS5BP_FIXTURES", "/nonexistent"))


@pytest.mark.skipif(not ((AC8 / "ac8-dump/eboot.bin").is_file() and (AC8 / "ac8-dlps/eboot.bin").is_file()),
                    reason="needs PS5BP_FIXTURES/ac8-dump + ac8-dlps")
def test_ac8_reproduces_dlps(tmp_path):
    """DUPLEX dump + DLPS kit as evidence -> every DLPS binary byte-identical (ELF payload, e_shnum aside)."""
    from ps5bp.core.learn import learn
    dump, kit = AC8 / "ac8-dump", AC8 / "ac8-dlps"
    db = EvidenceDB(tmp_path / "home")
    db.add_kit(AC8 / "dlps-11386", 4, "dlps-11386")
    db.add_kit(kit, 4, "dlps-ac8", tested_fw=10)
    _, recipes = learn(dump, kit, "PPSA24913")
    assert recipes == []                                  # phase 9: all explained by generic rules
    out = tmp_path / "out"
    rep = build(dump, BuildOptions(target=4, target_minor=0x03, out=out,
                                   rules={"kit-stubs", "mapflex-flags", "savedata-mount", "wwise-71"},
                                   stubs_from=["dlps-ac8"], replace_dump={"libSceAmpr": "dlps-ac8"}),
                db, log=lambda m: None)
    assert rep.ok and any("ampr_emu.index" in w for w in rep.warnings)
    for f in sorted(kit.rglob("*")):
        rel = f.relative_to(kit).as_posix()
        if not f.is_file() or rel in ("README.txt", "SHA256SUMS") or rel == "fakelib/libScePsml.sprx":
            continue
        mine = out / rel if (out / rel).is_file() else dump / rel
        if rel.endswith(".json"):
            assert mine.read_bytes() == f.read_bytes(), rel
            continue
        a, b = bytearray(Binary.load(f).to_elf()), bytearray(Binary.load(mine).to_elf())
        a[0x3C:0x3E] = b[0x3C:0x3E] = b"\0\0"
        assert a == b, rel
    db.close()
