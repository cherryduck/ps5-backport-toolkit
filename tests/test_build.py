"""End-to-end build on synthetic games and kits."""
import json

import pytest

from ps5bp.core import sdk
from ps5bp.core.binary import Binary
from ps5bp.core.evidence import EvidenceDB
from ps5bp.core.pipeline import BuildError, BuildOptions, build, patch_param_json
from synth import Spec, build_elf, build_self

PJ = ('{\r\n  "titleId": "PPSA99999",\r\n  "sdkVersion": "0x0700003800000000",\r\n'
      '  "requiredSystemSoftwareVersion": "0x0700000000000000",\r\n  "contentVersion": "01.000.000"\r\n}\r\n')


def put(path, spec):
    path.parent.mkdir(parents=True, exist_ok=True)
    elf, _ = build_elf(spec)
    path.write_bytes(build_self(elf))


@pytest.fixture
def game(tmp_path):
    g = tmp_path / "PPSA99999"
    put(g / "eboot.bin", Spec(import_libs=["libkernel", "libSceFoo"],
                              imports=[("KKKKKKKKKK1", 0), ("FFFFFFFFFF1", 1)]))
    put(g / "sce_module/libc.prx", Spec(kind="module", module="libc", ps5_sdk=0x07000038,
                                        import_libs=["libkernel"], imports=[("4h6F1LLbTiw", 0)]))
    put(g / "sce_module/old.prx", Spec(kind="module", module="libold", ps5_sdk=0x03000027, ps4_sdk=0x08540001))
    (g / "sce_sys").mkdir()
    (g / "sce_sys/param.json").write_bytes(b"\xef\xbb\xbf" + PJ.encode())
    (g / "data").mkdir()
    (g / "data/big.pak").write_bytes(b"x" * 4096)
    return g


@pytest.fixture
def db(tmp_path):
    k = tmp_path / "kit"
    put(k / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("KKKKKKKKKK1", 0)]))
    put(k / "fakelib/libSceFoo.sprx", Spec(kind="module", module="libSceFoo", export_libs=["libSceFoo"],
                                           exports=[("FFFFFFFFFF1", 0)], ps5_sdk=0x06000038,
                                           import_libs=[], imports=[], needed=[]))
    d = EvidenceDB(tmp_path / "home")
    d.add_kit(k, 4, "kit")
    yield d
    d.close()


def test_param_json_keeps_formatting():
    new, ch = patch_param_json(PJ, 4)
    assert new == PJ.replace("0x0700003800000000", "0x0400000000000000").replace(
        "0x0700000000000000", "0x0400000000000000")
    assert patch_param_json(PJ, 7)[1] == []


def test_overlay_build(game, db, tmp_path):
    out = tmp_path / "out"
    rep = build(game, BuildOptions(target=4, out=out), db, log=lambda m: None)
    assert rep.ok
    files = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())
    assert files == ["backport-report.json", "backport-report.txt", "eboot.bin", "fakelib/libSceFoo.sprx",
                     "sce_module/libc.prx", "sce_sys/param.json"]          # old.prx (SDK 3) untouched
    for f in ("eboot.bin", "sce_module/libc.prx", "fakelib/libSceFoo.sprx"):
        p = sdk.find(Binary.load(out / f))
        assert (p.ps5, p.ps4) == sdk.SDK_PAIRS[4]
    libc = (out / "sce_module/libc.prx").read_bytes()
    assert b"IWIBBdTHit4#" in libc and b"4h6F1LLbTiw#" not in libc
    pj = (out / "sce_sys/param.json").read_bytes()
    assert pj.startswith(b"\xef\xbb\xbf") and b"\r\n" in pj and pj.count(b"0x0400000000000000") == 2
    assert (game / "eboot.bin").read_bytes() != (out / "eboot.bin").read_bytes()   # input untouched...
    assert sdk.find(Binary.load(game / "eboot.bin")).ps5 == 0x07000038              # ...really
    kinds = sorted({e.kind for e in rep.edits})
    assert kinds == ["fakelib", "param.json", "retarget", "sdk"]
    assert json.loads((out / "backport-report.json").read_text())["ok"] is True


def test_full_and_inplace(game, db, tmp_path):
    out = tmp_path / "full"
    build(game, BuildOptions(target=4, out=out, mode="full"), db, log=lambda m: None)
    assert (out / "data/big.pak").read_bytes() == b"x" * 4096
    assert (out / "sce_module/old.prx").is_file()
    build(game, BuildOptions(target=4, mode="inplace"), db, log=lambda m: None)
    assert (game / "eboot.bin.orig").is_file() and (game / "sce_sys/param.json.orig").is_file()
    assert sdk.find(Binary.load(game / "eboot.bin")).ps5 == 0x04000031
    assert sdk.find(Binary.load(game / "eboot.bin.orig")).ps5 == 0x07000038
    assert (game / "fakelib/libSceFoo.sprx").is_file()
    # rebuilding in place needs --force now (fakelib/ present); originals must survive
    with pytest.raises(BuildError):
        build(game, BuildOptions(target=4, mode="inplace"), db, log=lambda m: None)
    build(game, BuildOptions(target=4, mode="inplace", force=True), db, log=lambda m: None)
    assert sdk.find(Binary.load(game / "eboot.bin.orig")).ps5 == 0x07000038


def test_dry_run_and_refusals(game, db, tmp_path):
    rep = build(game, BuildOptions(target=4, out=tmp_path / "dry", dry_run=True), db, log=lambda m: None)
    assert rep.edits and not (tmp_path / "dry").exists()
    with pytest.raises(BuildError):
        build(game, BuildOptions(target=4, out=game / "x"), db, log=lambda m: None)
    (tmp_path / "busy").mkdir()
    (tmp_path / "busy/f").write_text("x")
    with pytest.raises(BuildError):
        build(game, BuildOptions(target=4, out=tmp_path / "busy"), db, log=lambda m: None)
    elf, _ = build_elf(Spec())
    (game / "eboot.bin").write_bytes(build_self(elf, props_extra=0x2))     # encrypted
    with pytest.raises(BuildError, match="encrypted"):
        build(game, BuildOptions(target=4, out=tmp_path / "enc"), db, log=lambda m: None)


def test_verification_catches_stray_edits(game, db, tmp_path, monkeypatch):
    import ps5bp.core.pipeline as pl
    real = pl.downgrade_sdk

    def sneaky(b, target, minor=0):
        r = real(b, target)
        b.data[0x100] ^= 0xFF                 # unrecorded change
        return r
    monkeypatch.setattr(pl, "downgrade_sdk", sneaky)
    with pytest.raises(BuildError, match="unexpected changes"):
        build(game, BuildOptions(target=4, out=tmp_path / "o"), db, log=lambda m: None)
