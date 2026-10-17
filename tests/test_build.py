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


# ---- Phase 10a: console FW advice, SDK pairs 4..13, siblings -------------------------------
import os                                                   # noqa: E402
from pathlib import Path                                    # noqa: E402


def _tree(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in Path(root).rglob("*")
            if p.is_file() and not p.name.startswith("backport-report")}


def test_pairs_and_parse_4_to_13():
    assert sdk.SUPPORTED_TARGETS == tuple(range(4, 14))
    for m in range(4, 14):
        ps5, ps4 = sdk.target_pair(m)
        assert sdk.fw_major(ps5) == m and sdk.parse_target(str(m)) == (m, 0)
        assert sdk.target_pair(m, 3)[0] == (ps5 & 0xFF00FFFF) | 0x30000
    assert sdk.target_pair(11) == (0x11000040, 0x12590001)
    assert sdk.target_pair(12) == (0x12000038, 0x13090001)
    assert sdk.target_pair(13) == (0x13000035, 0x13590001)
    assert sdk.parse_target("11.60") == (11, 0x60)
    for bad in ("3", "14", "x", "4.123"):
        with pytest.raises(ValueError):
            sdk.parse_target(bad)


def test_console_warning_trigger():
    assert sdk.console_warning(4, 0, "11.60") and "--also-target" in sdk.console_warning(4, 0, "11.60")
    assert sdk.console_warning(4, 0, "6.00")                 # exactly 2 majors
    assert sdk.console_warning(4, 0, "5.50") is None         # 1 major
    assert sdk.console_warning(11, 0, "11.60") is None
    assert sdk.console_warning(4, 0, None) is None
    with pytest.raises(ValueError):
        sdk.fw_major_of_str("abc")


def test_console_fw_in_report(game, db, tmp_path):
    out = tmp_path / "out"
    rep = build(game, BuildOptions(target=4, out=out, console_fw="11.60"), db, log=lambda m: None)
    assert rep.console_fw == "11.60" and "black-screen" in rep.console_warning
    j = json.loads((out / "backport-report.json").read_text())
    assert j["console_fw"] == "11.60" and "black-screen" in j["console_warning"]
    assert "console firmware" in (out / "backport-report.txt").read_text()
    rep = build(game, BuildOptions(target=4, out=out, console_fw="5.00"), db, log=lambda m: None)
    assert rep.console_warning == ""
    with pytest.raises(BuildError, match="console firmware"):
        build(game, BuildOptions(target=4, out=out, console_fw="abc"), db, log=lambda m: None)


@pytest.mark.parametrize("mode", ["overlay", "full"])
def test_sibling_differs_only_in_sdk_fields(game, db, tmp_path, mode):
    out = tmp_path / "out"
    rep = build(game, BuildOptions(target=4, out=out, mode=mode, also_targets=[(5, 0), (11, 0x60)]), db,
                log=lambda m: None)
    assert [s["target_str"] for s in rep.siblings] == ["5.xx", "11.60"]
    main = _tree(out)
    for suffix, tgt, minor in (("-fw5", 5, 0), ("-fw11.60", 11, 0x60)):
        sib = tmp_path / ("out" + suffix)
        st = _tree(sib)
        assert set(st) == set(main)
        ps5, ps4 = sdk.target_pair(tgt, minor)
        changed = [r for r in main if main[r] != st[r]]
        assert "eboot.bin" in changed and "sce_sys/param.json" in changed
        for r in changed:
            assert len(main[r]) == len(st[r])
            diff = [i for i in range(len(main[r])) if main[r][i] != st[r][i]]
            assert len(diff) <= (8 if r != "sce_sys/param.json" else 36)
            if r != "sce_sys/param.json":
                p = sdk.find(Binary(st[r], r))
                assert (p.ps5, p.ps4) == (ps5, ps4)
        pj = json.loads(st["sce_sys/param.json"].decode("utf-8-sig"))
        want = f"0x{int(f'{tgt:02d}', 16) << 56 | minor << 48:016x}"
        assert pj["sdkVersion"] == want and pj["requiredSystemSoftwareVersion"] == want
        r = json.loads((sib / "backport-report.json").read_text())
        assert r["sibling_of"] == str(out) and r["sibling_edits"]
        assert "SIBLING" in (sib / "backport-report.txt").read_text()
    # old.prx was already below the main target: not raised
    assert sdk.find(Binary(_tree(tmp_path / "out-fw5")["sce_module/old.prx"], "x")).ps5 == 0x03000027 \
        if "sce_module/old.prx" in main else True
    assert json.loads((out / "backport-report.json").read_text())["siblings"]


def test_sibling_fails_on_stray_change_and_is_removed(game, db, tmp_path, monkeypatch):
    import ps5bp.core.pipeline as pl
    real = pl.clone_file

    def evil(src, dst):
        r = real(src, dst)
        if dst.name == "big.pak" and "-fw5" in str(dst):
            b = bytearray(dst.read_bytes())
            b[0x200] ^= 0xFF
            dst.write_bytes(b)
        return r
    monkeypatch.setattr(pl, "clone_file", evil)
    with pytest.raises(BuildError, match="outside the SDK fields"):
        build(game, BuildOptions(target=4, out=tmp_path / "out", mode="full", also_targets=[(5, 0)]), db,
              log=lambda m: None)
    assert not (tmp_path / "out-fw5").exists()
    assert (tmp_path / "out/eboot.bin").exists()             # the verified main build stays


def test_sibling_refuses_lower_equal_and_inplace(game, db, tmp_path):
    for bad in ([(4, 0)], [(7, 0), (4, 0)], [(3 + 1, 0)]):
        with pytest.raises(BuildError, match="not higher"):
            build(game, BuildOptions(target=5, out=tmp_path / "o", also_targets=bad, force=True), db,
                  log=lambda m: None)
    with pytest.raises(BuildError, match="not higher"):
        build(game, BuildOptions(target=4, target_minor=0x50, out=tmp_path / "o", also_targets=[(4, 0x03)]), db,
              log=lambda m: None)
    assert not (tmp_path / "o").exists()
    before = _tree(game)
    with pytest.raises(BuildError, match="inplace"):
        build(game, BuildOptions(target=4, mode="inplace", also_targets=[(5, 0)]), db, log=lambda m: None)
    assert _tree(game) == before


def test_overlay_sibling_undo(game, db, tmp_path):
    import shutil
    from ps5bp.core.undo import apply_undo, plan_undo
    out = tmp_path / "out"
    build(game, BuildOptions(target=4, out=out, also_targets=[(5, 0)]), db, log=lambda m: None)
    sib = tmp_path / "out-fw5"
    assert (tmp_path / "out-fw5.originals").is_dir()
    before = _tree(game)
    shutil.copytree(sib, game, dirs_exist_ok=True)
    assert _tree(game) != before
    apply_undo(game, plan_undo(game, [sib]))
    after = {k: v for k, v in _tree(game).items() if not k.startswith("fakelib/") or k in before}
    assert after == before
    # ps5bp's own sdk fields survive only if the sibling kept them: sanity on a fakelib sibling file
    assert not (game / "fakelib/libSceFoo.sprx").exists()


def test_cli_console_fw_and_also_target(game, db, tmp_path, monkeypatch, capsys):
    from ps5bp.cli import main
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))
    out = tmp_path / "cli"
    assert main(["build", str(game), "--target", "4", "--out", str(out), "--console-fw", "11.60",
                 "--also-target", "5,11"]) == 0
    txt = capsys.readouterr().out
    assert "black-screen" in txt and (tmp_path / "cli-fw5").is_dir() and (tmp_path / "cli-fw11").is_dir()
    assert main(["build", str(game), "--target", "5", "--out", str(tmp_path / "x"), "--also-target", "4",
                 "--force"]) == 1
    with pytest.raises(SystemExit):
        main(["build", str(game), "--target", "4", "--out", str(tmp_path / "y"), "--also-target", "14"])
    assert main(["analyze", str(game), "--target", "4", "--console-fw", "9.00"]) == 0
    assert "black-screen" in capsys.readouterr().out


def test_rule_recommendation_keys_on_declared_sdk():
    from types import SimpleNamespace
    from ps5bp.core.rules.evidence_rules import recommendation
    from ps5bp.core.rules.savedata_mount import SavedataMount
    prior = SavedataMount.PRIOR
    mk = lambda t: SimpleNamespace(target=t, declared_sdk=t, options={})          # noqa: E731
    assert recommendation("savedata-mount", mk(4), prior) == recommendation("savedata-mount", SimpleNamespace(
        target=4, options={}), prior)                       # default case unchanged
    # a console at 11.xx does not change it: only the declared SDK does
    from ps5bp.core.rules import RuleContext
    assert RuleContext.declared_sdk.fget(SimpleNamespace(target=4)) == 4


# ---- Phase 10e: apply safety --------------------------------------------------------------
def _overlay_over(out, game):
    import shutil
    shutil.copytree(out, game, dirs_exist_ok=True, ignore=shutil.ignore_patterns("backport-report.*"))


def test_ledger_records_outputs_and_dry_run_does_not(game, db, tmp_path):
    from ps5bp.core import ledger
    build(game, BuildOptions(target=4, out=tmp_path / "d", dry_run=True), db, log=lambda m: None)
    assert not ledger.ledger_path().exists()
    out = tmp_path / "out"
    rep = build(game, BuildOptions(target=4, out=out, also_targets=[(5, 0)]), db, log=lambda m: None)
    ents = json.loads(ledger.ledger_path().read_text())["entries"]
    assert {e["path"] for e in ents if e["out"] == str(out)} == set(rep.outputs) and rep.outputs
    assert any(e["out"] == str(tmp_path / "out-fw5") for e in ents)
    e = ents[0]
    assert {"sha256", "path", "title_id", "out", "built", "tool", "target"} <= set(e) and e["title_id"] == "PPSA99999"
    assert set(rep.inputs) >= {"eboot.bin", "sce_sys/param.json", "sce_module/libc.prx"}
    assert json.loads((out / "backport-report.json").read_text())["inputs"] == rep.inputs


def test_rebuild_over_applied_overlay_refused(game, db, tmp_path):
    out = tmp_path / "out"
    build(game, BuildOptions(target=4, out=out), db, log=lambda m: None)
    _overlay_over(out, game)
    with pytest.raises(BuildError, match="already"):          # SDK check and/or ledger: either refuses
        build(game, BuildOptions(target=4, out=tmp_path / "o2"), db, log=lambda m: None)
    assert not (tmp_path / "o2").exists()
    build(game, BuildOptions(target=4, out=tmp_path / "o2", force=True), db, log=lambda m: None)


def test_fakelib_only_overlay_caught_without_sdk_check(game, db, tmp_path):
    # an overlay that only changed fakelib/libc: the eboot SDK check can't see it, the ledger does
    out = tmp_path / "out"
    build(game, BuildOptions(target=4, out=out), db, log=lambda m: None)
    (game / "fakelib").mkdir(exist_ok=True)
    import shutil
    shutil.copy2(out / "fakelib/libSceFoo.sprx", game / "fakelib/libSceFoo.sprx")
    with pytest.raises(BuildError, match="ps5bp itself wrote") as ei:
        build(game, BuildOptions(target=4, out=tmp_path / "o2"), db, log=lambda m: None)
    assert "fakelib/libSceFoo.sprx" in str(ei.value) and str(out) in str(ei.value)
    build(game, BuildOptions(target=4, out=tmp_path / "o2", force=True), db, log=lambda m: None)


def test_corrupt_ledger_is_kept_and_restarted(game, db, tmp_path):
    from ps5bp.core import ledger
    lp = ledger.ledger_path()
    lp.parent.mkdir(parents=True, exist_ok=True)
    lp.write_text("{not json")
    msgs = []
    rep = build(game, BuildOptions(target=4, out=tmp_path / "out"), db, log=msgs.append)
    assert (lp.parent / "applied.json.bak").read_text() == "{not json"
    assert any("corrupt" in m for m in rep.warnings)
    assert len(json.loads(lp.read_text())["entries"]) == len(rep.outputs)
    lp.write_text(json.dumps({"entries": "nope"}))
    assert ledger.load(lambda m: msgs.append(m)) == [] and any("corrupt" in m for m in msgs)
    assert not list(lp.parent.glob("applied.json.*.tmp"))


def test_undo_verifies_clean_flow_and_modified_file(game, db, tmp_path):
    from ps5bp.core.undo import UndoError, apply_undo, plan_undo
    out = tmp_path / "out"
    build(game, BuildOptions(target=4, out=out), db, log=lambda m: None)
    before = _tree(game)
    _overlay_over(out, game)
    # game file modified after the overlay -> refused, then forced
    eb = game / "eboot.bin"
    raw = bytearray(eb.read_bytes())
    raw[-1] ^= 0xFF
    eb.write_bytes(raw)
    with pytest.raises(UndoError, match="eboot.bin"):
        plan_undo(game, [out])
    assert any("--force" in n for n in plan_undo(game, [out], force=True).notes)
    raw[-1] ^= 0xFF
    eb.write_bytes(raw)
    up = plan_undo(game, [out])
    assert not any("skipped" in n for n in up.notes)
    apply_undo(game, up)
    assert {k: v for k, v in _tree(game).items() if k in before} == before


def test_undo_reversal_path_verifies_and_post_check(game, db, tmp_path):
    import shutil
    from ps5bp.core.undo import UndoError, plan_undo
    out = tmp_path / "out"
    build(game, BuildOptions(target=4, out=out), db, log=lambda m: None)
    shutil.rmtree(tmp_path / "out.originals")
    rp = out / "backport-report.json"
    _overlay_over(out, game)
    plan_undo(game, [out])                                  # clean: passes
    rep = json.loads(rp.read_text())
    rep["inputs"]["eboot.bin"] = "0" * 64                   # wrong input hash: post-restore check fails
    rp.write_text(json.dumps(rep))
    with pytest.raises(UndoError, match="recorded inputs"):
        plan_undo(game, [out])
    plan_undo(game, [out], force=True)


def test_undo_old_report_without_inputs(game, db, tmp_path):
    from ps5bp.core.undo import apply_undo, plan_undo
    out = tmp_path / "out"
    build(game, BuildOptions(target=4, out=out), db, log=lambda m: None)
    before = _tree(game)
    _overlay_over(out, game)
    rp = out / "backport-report.json"
    rep = json.loads(rp.read_text())
    rep.pop("inputs"), rep.pop("outputs")
    rp.write_text(json.dumps(rep))
    up = plan_undo(game, [out])
    assert any("verification skipped" in n for n in up.notes)
    apply_undo(game, up)
    assert {k: v for k, v in _tree(game).items() if k in before} == before


def test_case_insensitive_member_lookup(tmp_path):
    from ps5bp.core.ledger import AmbiguousMember, resolve_member
    (tmp_path / "Sce_Module").mkdir()
    (tmp_path / "Sce_Module/LIBC.PRX").write_bytes(b"x")
    assert resolve_member(tmp_path, "sce_module/libc.prx") == "Sce_Module/LIBC.PRX"
    assert resolve_member(tmp_path, "sce_module/new.prx") == "Sce_Module/new.prx"
    assert resolve_member(tmp_path, "nothere/a/b") == "nothere/a/b"
    (tmp_path / "Sce_Module/libc.prx").write_bytes(b"y")
    assert resolve_member(tmp_path, "Sce_Module/libc.prx") == "Sce_Module/libc.prx"      # exact wins
    with pytest.raises(AmbiguousMember):
        resolve_member(tmp_path, "sce_module/LibC.prx")


def test_undo_case_insensitive_game(game, db, tmp_path):
    from ps5bp.core.undo import UndoError, apply_undo, plan_undo
    out = tmp_path / "out"
    build(game, BuildOptions(target=4, out=out), db, log=lambda m: None)
    before = {k.lower(): v for k, v in _tree(game).items()}
    _overlay_over(out, game)
    (game / "sce_module").rename(game / "SCE_MODULE")
    (game / "eboot.bin").rename(game / "EBOOT.BIN")
    apply_undo(game, plan_undo(game, [out]))
    after = {k.lower(): v for k, v in _tree(game).items()}
    assert {k: v for k, v in after.items() if k in before} == before
    assert not (game / "eboot.bin").exists() or (game / "EBOOT.BIN").exists()
    # ambiguity -> refused
    import shutil
    shutil.rmtree(game / "sce_module", ignore_errors=True)
    (game / "SCE_MODULE/LIBC.PRX").write_bytes(b"z")
    (game / "SCE_MODULE/Libc.prx").write_bytes(b"z")
    (game / "SCE_MODULE/libc.prx").unlink(missing_ok=True)
    with pytest.raises(UndoError, match="differ only in case"):
        plan_undo(game, [out])
