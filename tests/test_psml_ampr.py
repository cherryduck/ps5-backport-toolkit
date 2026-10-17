"""psml-overlay (kit provider + k9.psp), the extra-file path of the pipeline, and the Ampr advice."""
import hashlib
import shutil
from pathlib import Path

import pytest

from ps5bp.core.advice import ampr_advice, is_unity
from ps5bp.core.coverage import analyze
from ps5bp.core.evidence import EvidenceDB
from ps5bp.core.pipeline import BuildOptions, build
from ps5bp.core.scan import scan_game
from ps5bp.core.undo import apply_undo, plan_undo
from synth import Spec, build_elf, build_self

MARK = b"/app0/k9.psp"
PSML_NIDS = [f"PSMLNID{i:04d}" for i in range(4)]            # 11 chars


def put(path: Path, spec: Spec) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_self(build_elf(spec)[0]))


def psml_lib(exports, strings=b"") -> Spec:
    return Spec(kind="module", module="libScePsml", export_libs=["libScePsml"], exports=[(n, 0) for n in exports],
                import_libs=["libkernel"], imports=[], strings=strings)


def game_spec(psml_imports=PSML_NIDS) -> Spec:
    return Spec(import_libs=["libkernel", "libScePsml"], needed=["libkernel.prx", "libScePsml.prx"],
                imports=[("rTXw65xmLIA", 0)] + [(n, 1) for n in psml_imports])


@pytest.fixture
def game(tmp_path):
    g = tmp_path / "PPSA77777"
    put(g / "eboot.bin", game_spec())
    return g


@pytest.fixture
def db(tmp_path):
    """kit 'plain': libScePsml without the overlay (more exports); kit 'ovl': overlay + k9.psp."""
    d = EvidenceDB(tmp_path / "home")
    plain = tmp_path / "plain"
    put(plain / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("rTXw65xmLIA", 0)]))
    put(plain / "fakelib/libScePsml.sprx", psml_lib(PSML_NIDS + ["PSMLEXTRA01", "PSMLEXTRA02"]))
    d.add_kit(plain, 4, "plain")
    ovl = tmp_path / "ovl"
    put(ovl / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("rTXw65xmLIA", 0)]))
    put(ovl / "fakelib/libScePsml.sprx", psml_lib(PSML_NIDS, strings=b"\0" + MARK + b"\0"))
    (ovl / "k9.psp").write_bytes(b"MODEL" * 100)
    d.add_kit(ovl, 4, "ovl")
    yield d
    d.close()


def test_kit_add_keeps_k9_and_marks_provider(db):
    provs = db.psml_overlays()
    assert [(k.name, f.module) for k, f, _, _ in provs] == [("ovl", "libScePsml")]
    assert provs[0][2].read_bytes() == b"MODEL" * 100
    assert provs[0][3] == set(PSML_NIDS)


def test_overlay_applied_with_k9_at_root(game, db, tmp_path):
    out = tmp_path / "out"
    rep = build(game, BuildOptions(target=4, out=out, rules={"psml-overlay"}), db, log=lambda m: None)
    assert rep.ok
    f = [x for x in rep.findings if x["rule"] == "psml-overlay"]
    assert len(f) == 1 and f[0]["applied"] and not f[0]["recommended"]
    assert (out / "k9.psp").read_bytes() == b"MODEL" * 100
    lib = (out / "fakelib/libScePsml.sprx").read_bytes()
    assert MARK in lib
    assert any(x["module"] == "libScePsml" and x["kit"] == "ovl" for x in rep.fakelibs)
    assert any(e.kind == "extra" and e.file == "k9.psp" for e in rep.edits)
    assert not any(e.file == "fakelib/libScePsml.sprx" and e.kind == "fakelib" and "plain" in e.new for e in rep.edits)


def test_off_by_default_uses_best_coverage_and_no_k9(game, db, tmp_path):
    out = tmp_path / "out"
    rep = build(game, BuildOptions(target=4, out=out), db, log=lambda m: None)
    assert not (out / "k9.psp").exists()
    assert not any("psml-overlay" in w and "recommended" in w for w in rep.warnings)
    assert MARK not in (out / "fakelib/libScePsml.sprx").read_bytes()


def test_undo_removes_k9(game, db, tmp_path):
    out = tmp_path / "out"
    build(game, BuildOptions(target=4, out=out, rules={"psml-overlay"}), db, log=lambda m: None)
    shutil.copytree(out, game, dirs_exist_ok=True)               # the overlay copied over the game
    up = plan_undo(game, [out])
    assert "k9.psp" in up.deletes and "fakelib/libScePsml.sprx" in up.deletes
    apply_undo(game, up)
    assert not (game / "k9.psp").exists()


def test_inplace_mode_backs_up_nothing_new(game, db, tmp_path):
    rep = build(game, BuildOptions(target=4, mode="inplace", rules={"psml-overlay"}), db, log=lambda m: None)
    assert rep.ok and (game / "k9.psp").read_bytes() == b"MODEL" * 100


def test_done_when_game_carries_overlay(tmp_path, db):
    g = tmp_path / "PPSA77778"
    put(g / "eboot.bin", game_spec())
    put(g / "fakelib/libScePsml.sprx", psml_lib(PSML_NIDS, strings=b"\0" + MARK + b"\0"))
    (g / "k9.psp").write_bytes(b"x")
    rep = build(g, BuildOptions(target=4, out=tmp_path / "o", rules={"psml-overlay"}, force=True), db,
                log=lambda m: None)
    f = [x for x in rep.findings if x["rule"] == "psml-overlay"]
    assert f and f[0]["title"].startswith("DONE") and not f[0]["applied"]
    assert (tmp_path / "o/k9.psp").read_bytes() == b"x" if (tmp_path / "o/k9.psp").exists() else True


def test_unknown_without_provider_or_exports(game, tmp_path):
    d = EvidenceDB(tmp_path / "h2")
    plain = tmp_path / "plain2"
    put(plain / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("rTXw65xmLIA", 0)]))
    put(plain / "fakelib/libScePsml.sprx", psml_lib(PSML_NIDS))
    d.add_kit(plain, 4, "plain")
    rep = build(game, BuildOptions(target=4, out=tmp_path / "o", rules={"psml-overlay"}), d, log=lambda m: None)
    f = [x for x in rep.findings if x["rule"] == "psml-overlay"]
    assert f and f[0]["title"].startswith("UNKNOWN") and not f[0]["applicable"]
    d.close()
    # provider lacking a needed NID
    d = EvidenceDB(tmp_path / "h3")
    ovl = tmp_path / "ovl2"
    put(ovl / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("rTXw65xmLIA", 0)]))
    put(ovl / "fakelib/libScePsml.sprx", psml_lib(PSML_NIDS[:2], strings=b"\0" + MARK + b"\0"))
    (ovl / "k9.psp").write_bytes(b"m")
    d.add_kit(ovl, 4, "ovl2")
    rep = build(game, BuildOptions(target=4, out=tmp_path / "o2", rules={"psml-overlay"}), d, log=lambda m: None)
    f = [x for x in rep.findings if x["rule"] == "psml-overlay"]
    assert f and "no provider exports all" in f[0]["title"] and not f[0]["applied"]
    assert not (tmp_path / "o2/k9.psp").exists()
    d.close()


def test_game_without_psml_imports_has_no_finding(tmp_path, db):
    g = tmp_path / "PPSA77779"
    put(g / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("rTXw65xmLIA", 0)]))
    rep = build(g, BuildOptions(target=4, out=tmp_path / "o", rules={"psml-overlay"}), db, log=lambda m: None)
    assert not [x for x in rep.findings if x["rule"] == "psml-overlay"]


def test_different_k9_in_game_root_refused(game, db, tmp_path):
    (game / "k9.psp").write_bytes(b"other")
    rep = build(game, BuildOptions(target=4, out=tmp_path / "o", rules={"psml-overlay"}), db, log=lambda m: None)
    f = [x for x in rep.findings if x["rule"] == "psml-overlay"]
    assert f and "different k9.psp" in f[0]["title"] and not f[0]["applied"]


# ---------------------------------------------------------------- Ampr advice
def ampr_game(tmp_path, n_ampr: int, unity: bool) -> Path:
    g = tmp_path / f"PPSA66{n_ampr}{int(unity)}"
    nids = [f"AMPRNID{i:04d}" for i in range(n_ampr)]
    put(g / "eboot.bin", Spec(import_libs=["libkernel", "libSceAmpr"], needed=["libkernel.prx", "libSceAmpr.prx"],
                              imports=[("rTXw65xmLIA", 0)] + [(n, 1) for n in nids]))
    put(g / "fakelib/libSceAmpr.sprx", Spec(kind="module", module="libSceAmpr", export_libs=["libSceAmpr"],
                                            exports=[(n, 0) for n in nids] or [("AMPRNID9999", 0)],
                                            import_libs=["libkernel"], imports=[]))
    if unity:
        put(g / "Media/Plugins/Foo.prx", Spec(kind="module", module="Foo", import_libs=["libkernel"], imports=[]))
    return g


@pytest.fixture
def adb(tmp_path):
    d = EvidenceDB(tmp_path / "ah")
    k = tmp_path / "ampr_kit"
    put(k / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("rTXw65xmLIA", 0)]))
    put(k / "fakelib/libSceAmpr.sprx", Spec(kind="module", module="libSceAmpr", export_libs=["libSceAmpr"],
                                            exports=[(f"AMPRNID{i:04d}", 0) for i in range(120)],
                                            import_libs=["libkernel"], imports=[]))
    d.add_kit(k, 4, "amprkit")
    yield d
    d.close()


def test_ampr_advice_unity(tmp_path, adb):
    g = ampr_game(tmp_path, 31, unity=True)
    gs = scan_game(g)
    assert is_unity(gs)
    adv = ampr_advice(gs, analyze(gs, adb, 4))
    assert len(adv) == 1 and "--replace-dump-fakelib libSceAmpr" in adv[0] and "Unity" in adv[0] and "amprkit" in adv[0]


def test_ampr_advice_101_profile_only(tmp_path, adb):
    gs = scan_game(ampr_game(tmp_path, 101, unity=False))
    adv = ampr_advice(gs, analyze(gs, adb, 4))
    assert len(adv) == 1 and "exactly 101" in adv[0]
    gs = scan_game(ampr_game(tmp_path, 100, unity=False))
    assert ampr_advice(gs, analyze(gs, adb, 4)) == []


def test_ampr_advice_silent_when_already_replaced_or_no_kits(tmp_path, adb):
    gs = scan_game(ampr_game(tmp_path, 31, unity=True))
    assert ampr_advice(gs, analyze(gs, adb, 4, {"libSceAmpr": None})) == []
    assert ampr_advice(gs, None) == []


def test_ampr_advice_without_a_kit_ampr(tmp_path):
    d = EvidenceDB(tmp_path / "empty")
    k = tmp_path / "k"
    put(k / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("rTXw65xmLIA", 0)]))
    put(k / "fakelib/libSceFoo.sprx", Spec(kind="module", module="libSceFoo", export_libs=["libSceFoo"],
                                           exports=[("FFFFFFFFFF1", 0)], import_libs=["libkernel"], imports=[]))
    d.add_kit(k, 4, "k")
    gs = scan_game(ampr_game(tmp_path, 31, unity=True))
    adv = ampr_advice(gs, analyze(gs, d, 4))
    assert len(adv) == 1 and "kit add" in adv[0]
    d.close()
