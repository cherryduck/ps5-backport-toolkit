"""Evidence DB + coverage engine on synthetic kits."""
import pytest

from ps5bp.core import coverage
from ps5bp.core.binary import Binary
from ps5bp.core import dynamic
from ps5bp.core.evidence import EvidenceDB
from ps5bp.core.scan import scan_game
from synth import Spec, build_elf, build_self


def put(path, spec):
    path.parent.mkdir(parents=True, exist_ok=True)
    elf, _ = build_elf(spec)
    path.write_bytes(build_self(elf))


def fakelib(path, module, exports, imports=(), import_libs=(), stubbed=()):
    put(path, Spec(kind="module", module=module, export_libs=[module], exports=[(n, 0) for n in exports],
                   import_libs=list(import_libs), imports=list(imports), stubbed=list(stubbed),
                   needed=[f"{m}.prx" for m in import_libs]))


def test_stubbed_symbols_are_absent_evidence():
    elf, _ = build_elf(Spec(kind="module", module="libSceFoo", export_libs=["libSceFoo"],
                            exports=[("FFFFFFFFFF1", 0)], import_libs=["libkernel"],
                            imports=[("KKKKKKKKKK1", 0)], stubbed=[("KKKKKKKKKK9", 0)]))
    d = dynamic.parse(Binary(elf))
    assert d.exported_nids() == {"FFFFFFFFFF1"}
    assert d.imports_by_module() == {"libkernel": {"KKKKKKKKKK1"}}
    assert d.stubbed_by_module() == {"libkernel": {"KKKKKKKKKK9"}}


@pytest.fixture
def db(tmp_path):
    k = tmp_path / "kit4"
    # kit game: proves K1,K2 present in libkernel on FW4; its fakelib stubs K9 => absent on FW4
    put(k / "eboot.bin", Spec(import_libs=["libkernel", "libSceFoo"],
                              imports=[("KKKKKKKKKK1", 0), ("KKKKKKKKKK2", 0), ("FFFFFFFFFF1", 1)]))
    fakelib(k / "fakelib/libSceFoo.sprx", "libSceFoo", ["FFFFFFFFFF1", "FFFFFFFFFF2"],
            imports=[("KKKKKKKKKK2", 0)], import_libs=["libkernel"], stubbed=[("KKKKKKKKKK9", 0)])
    (k / "k9.psp").write_bytes(b"model")
    d = EvidenceDB(tmp_path / "home")
    r = d.add_kit(k, fw=4, name="kit4")
    assert r["fakelibs"] == ["fakelib/libSceFoo.sprx"] and r["extras"] == ["k9.psp"]
    assert r["present"] == 3 and r["absent"] == 1
    yield d
    d.close()


def test_evidence_fw_ordering(db):
    assert db.present("libkernel", 4) == {"KKKKKKKKKK1", "KKKKKKKKKK2"}
    assert db.present("libkernel", 6) == {"KKKKKKKKKK1", "KKKKKKKKKK2"}    # present on 4 => on 6
    assert db.present("libkernel", 3) == set()
    assert db.absent("libkernel", 4) == {"KKKKKKKKKK9"}
    assert db.absent("libkernel", 3) == {"KKKKKKKKKK9"}                    # absent on 4 => on 3
    assert db.absent("libkernel", 6) == set()
    assert db.present("libSceFoo", 4) == set()       # replaced by the kit: no system evidence
    assert (db.kit("kit4").store / "fakelib/libSceFoo.sprx").is_file()
    assert (db.kit("kit4").store / "k9.psp").is_file()
    with pytest.raises(ValueError):
        db.add_kit(db.kit("kit4").store, fw=4, name="kit4")


def test_coverage_statuses(db, tmp_path):
    g = tmp_path / "game"
    put(g / "eboot.bin", Spec(import_libs=["libkernel", "libSceFoo", "libSceNet", "libmiddleware"],
                              imports=[("KKKKKKKKKK1", 0), ("FFFFFFFFFF2", 1), ("NNNNNNNNNN1", 2), ("MMMMMMMMMM1", 3)]))
    put(g / "sce_module/libmiddleware.prx", Spec(kind="module", module="libmiddleware",
                                                 imports=[], import_libs=[], needed=[]))
    cov = coverage.analyze(scan_game(g), db, 4)
    st = {m.module: m.status for m in cov.modules}
    assert st == {"libkernel": "system", "libSceFoo": "fakelib", "libSceNet": "unverified", "libmiddleware": "game"}
    foo = next(m for m in cov.modules if m.module == "libSceFoo")
    assert foo.choice.kit == "kit4" and not foo.choice.missing
    # NID proven absent on 4 and nothing can supply libkernel
    put(g / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("KKKKKKKKKK9", 0)]))
    cov = coverage.analyze(scan_game(g), db, 4)
    assert [(m.module, m.status, m.absent) for m in cov.modules if m.module == "libkernel"] == \
        [("libkernel", "absent", ["KKKKKKKKKK9"])]
    assert coverage.analyze(scan_game(g), db, 6).modules[0].status == "unverified"


def test_pairs_repaired_across_kits(tmp_path):
    """Kit A (FW4) Foo needs B1 from Bar; only kit B (FW6) Bar covers the game's Bar needs.
    For target 4 Foo initially picks kit A — the repair must move Foo to kit B."""
    a, b = tmp_path / "A", tmp_path / "B"
    for k in (a, b):
        put(k / "eboot.bin", Spec(import_libs=["libkernel"], imports=[("KKKKKKKKKK1", 0)]))
    fakelib(a / "fakelib/libSceFoo.sprx", "libSceFoo", ["FFFFFFFFFF1"], [("BBBBBBBBBB1", 0)], ["libSceBar"])
    fakelib(a / "fakelib/libSceBar.sprx", "libSceBar", ["BBBBBBBBBB1"])
    fakelib(b / "fakelib/libSceFoo.sprx", "libSceFoo", ["FFFFFFFFFF1"], [("BBBBBBBBBB2", 0)], ["libSceBar"])
    fakelib(b / "fakelib/libSceBar.sprx", "libSceBar", ["BBBBBBBBBB2", "BBBBBBBBBBX"])
    d = EvidenceDB(tmp_path / "home")
    d.add_kit(a, 4, "A")
    d.add_kit(b, 6, "B")
    g = tmp_path / "game"
    put(g / "eboot.bin", Spec(import_libs=["libSceFoo", "libSceBar"],
                              imports=[("FFFFFFFFFF1", 0), ("BBBBBBBBBBX", 1)]))
    cov = coverage.analyze(scan_game(g), d, 4)
    ch = {m.module: m.choice.kit for m in cov.fakelibs()}
    assert ch == {"libSceFoo": "B", "libSceBar": "B"}
    assert not [x for x in cov.deps if x.startswith("CONFLICT")]
