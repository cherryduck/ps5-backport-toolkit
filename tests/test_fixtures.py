"""Tests against real backport folders. Skipped unless PS5BP_FIXTURES is set.

Expected layout:  $PS5BP_FIXTURES/wolverine-dlps/   (DLPS 'FW_4xx PPSA03671 ... backport_files')
"""
import os
from pathlib import Path

import pytest

from ps5bp.core import dynamic, sdk
from ps5bp.core.binary import Binary
from ps5bp.core.scan import scan_game

ROOT = Path(os.environ.get("PS5BP_FIXTURES", "/nonexistent"))
WOLV = ROOT / "wolverine-dlps"
pytestmark = pytest.mark.skipif(not WOLV.is_dir(), reason="PS5BP_FIXTURES/wolverine-dlps not present")


def test_wolverine_eboot():
    b = Binary.load(WOLV / "eboot.bin")
    p = sdk.find(b)
    assert (p.ps5, p.ps4) == (0x04000031, 0x09040001)
    d = dynamic.parse(b)
    assert len(d.needed) == 45
    assert "NH6xARDOVv8" in d.imported_nids()
    assert b.slack(0) == 0xB                       # DLPS cave used all but 0xb bytes
    assert b.phdrs[0].filesz == 0x5F22645
    assert b.read(0x6322580 - 0x400000, 7) == bytes.fromhex("4981fe00000010")   # cmp r14, 256MB


def test_wolverine_scan():
    gs = scan_game(WOLV)
    assert {"pro-query", "pssr", "pssr2-app0"} <= set(gs.flags)
    assert gs.extra_files == ["k9.psp"]
    fl = {b.path for b in gs.binaries if b.role == "fakelib"}
    assert {"fakelib/libSceAgc.sprx", "fakelib/libScePsml.sprx"} <= fl
    assert all(not b.error for b in gs.binaries)
    assert gs.needs_downgrade(4) == []


KITS = {"dlps-11386": 4, "viet-11386": 6}


@pytest.fixture(scope="module")
def kitdb(tmp_path_factory):
    from ps5bp.core.evidence import EvidenceDB
    if not all((ROOT / k).is_dir() for k in KITS):
        pytest.skip("PPSA11386 kits not extracted under PS5BP_FIXTURES")
    db = EvidenceDB(tmp_path_factory.mktemp("home"))
    for k, fw in KITS.items():
        db.add_kit(ROOT / k, fw, k)
    return db


def test_wolverine_fakelib_selection(kitdb):
    """Selection reproduces DLPS's Wolverine module set; FW6 picks the exact AGC pair DLPS shipped."""
    from ps5bp.core.coverage import analyze
    gs = scan_game(WOLV)
    shipped = {b.module: b.sha256 for b in gs.binaries if b.role == "fakelib"}
    c4 = analyze(gs, kitdb, 4)
    # Ampr / PlayGo already in the folder are loading layers: kept, not re-selected
    assert {m.module for m in c4.modules if m.status == "dump"} == {"libSceAmpr", "libScePlayGo"}
    assert {m.module for m in c4.fakelibs()} == set(shipped) - {"libSceAmpr", "libScePlayGo"}
    assert all(not m.choice.missing for m in c4.fakelibs())
    assert {m.module for m in c4.fakelibs() if m.choice.sha256 == shipped[m.module]} == {"libScePsml"}
    # ... unless replacing them is asked for: then the kits' builds match DLPS's byte for byte
    c4r = analyze(gs, kitdb, 4, {"libSceAmpr": None, "libScePlayGo": None})
    assert {m.module for m in c4r.fakelibs() if m.choice.sha256 == shipped[m.module]} == \
        {"libScePsml", "libSceAmpr", "libScePlayGo"}
    assert [m.absent for m in c4.modules if m.module == "libkernel"] == [["NH6xARDOVv8"]]
    assert not [d for d in c4.deps if d.startswith("CONFLICT")]
    c6 = analyze(gs, kitdb, 6)
    agc = {m.module: m.choice.sha256 for m in c6.fakelibs() if m.module.startswith("libSceAgc")}
    assert agc == {k: shipped[k] for k in ("libSceAgc", "libSceAgcDriver")}


def test_build_psviethoa_fw6_to_fw4(kitdb, tmp_path):
    """Real 6.xx -> 4.xx build: only SDK fields + 2 param.json bytes change; DLPS FW4 fakelibs installed."""
    from ps5bp.core.pipeline import BuildOptions, build
    src = ROOT / "viet-11386" / "PPSA11386-app0"
    out = tmp_path / "out"
    rep = build(src, BuildOptions(target=4, out=out, force=True), kitdb, log=lambda m: None)
    assert rep.ok
    assert sorted(e.file for e in rep.edits if e.kind == "sdk") == ["eboot.bin", "sce_module/libc.prx"]
    for f in ("eboot.bin", "sce_module/libc.prx"):
        assert sdk.find(Binary.load(out / f)).ps5 == 0x04000031
    a, b = (src / "sce_sys/param.json").read_bytes(), (out / "sce_sys/param.json").read_bytes()
    assert len(a) == len(b) and sum(x != y for x, y in zip(a, b)) == 2
    assert {f["kit"] for f in rep.fakelibs} == {"dlps-11386"}


def test_wolverine_pssr_recipe_reproduces_dlps(kitdb, tmp_path):
    """Reconstructed pre-DLPS Wolverine eboot + pssr-memory rule == DLPS FW4 eboot, byte for byte."""
    from ps5bp.core.pipeline import BuildOptions, build
    src = ROOT / "wolverine-orig-synth"
    if not (src / "eboot.bin").is_file():
        pytest.skip("wolverine-orig-synth not present")
    out = tmp_path / "out"
    # force: the reconstruction is derived from DLPS's file and is already at SDK 4.00
    rep = build(src, BuildOptions(target=4, out=out, rules={"pssr-memory"}, force=True), kitdb, log=lambda m: None)
    assert rep.ok and any(f["applied"] for f in rep.findings if f["rule"] == "pssr-memory")
    assert (out / "eboot.bin").read_bytes() == (ROOT / "wolverine-dlps" / "eboot.bin").read_bytes()
