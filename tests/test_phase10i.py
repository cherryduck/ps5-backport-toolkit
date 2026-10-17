"""Phase 10i: savedata-prepare mode 6, assert-aware crash triage, NID names, 0x809f8032 wording, fakelib note."""
import struct
from pathlib import Path

import pytest

import test_learn_10c as lc
import test_phase10cb as t
from ps5bp.core import klog
from ps5bp.core.binary import Binary
from ps5bp.core.nid import name_of, nid

H = t.H
DATA = Path(__file__).parent / "data"
G = Path("/home/cherryduck/Downloads/[DLPSGAME.COM]-PPSA35909-DUPLEX/[DLPSGAME.COM]-PPSA35909-DUPLEX/"
         "PPSA35909-app0_KINGDOM_HEARTS_HD_2.8_FINAL_CHAPTER")
needs_game = pytest.mark.skipif(not (G / "eboot.bin").is_file(), reason="real KH folder not present")


# ---- item 1: savedata-prepare mode 6 ------------------------------------------------------------------
def test_prepare_mode6_patch_and_note(tmp_path):
    g = t.prep_game(tmp_path / "6", t.prep(H("55 4889e5 c745e4 06000000 488d75e0")))
    ((st, f),) = t.statuses(g, "savedata-prepare")
    assert st == "PATCH" and not f.recommended
    assert "mode 6" in f.title and "not yet seen in community FW4 builds" in f.title and "console-test" in f.title
    rep, _ = t.run(g, tmp_path / "6", "savedata-prepare")
    b = Binary.load(tmp_path / "6/out/eboot.bin")
    assert rep.ok and b.read(0x100 + 4, 7) == H("c745e4 00000000")


def test_prepare_other_nonzero_mode_is_unknown_with_value(tmp_path):
    g = t.prep_game(tmp_path / "5", t.prep(H("55 4889e5 c745e4 05000000 488d75e0")))
    ((st, f),) = t.statuses(g, "savedata-prepare")
    assert st == "UNKNOWN" and "5" in f.reason
    # mode 6 next to another writer is still refused
    g = t.prep_game(tmp_path / "x", t.prep(H("55 4889e5 c745e4 06000000 8945e4 488d75e0")))
    assert t.statuses(g, "savedata-prepare")[0][0] == "UNKNOWN"


def test_prepare_mode6_learn_explained(tmp_path):
    g = t.prep_game(tmp_path / "p", t.prep(H("55 4889e5 c745e4 06000000 488d75e0")))
    _, reps = lc.roundtrip(g, tmp_path / "p", {"savedata-prepare"})
    lc.assert_explained(reps, "savedata-prepare")


@needs_game
def test_real_kh_prepare_sites():
    from ps5bp.core.rules.savedata_prepare import sites
    want = {"eboot.bin": (0x400000, [0x4b9b2b, 0x4b9e26, 0x4bc55c]), "kh3d.elf": (0, [0x5b9f0b, 0x5ba206, 0x5bc93c])}
    for rel, (base, calls) in want.items():
        ss = sites(Binary.load(G / rel), base)
        assert [(s["call"], s["status"]) for s in ss] == [(c, "PATCH") for c in calls], rel
        assert all(s["imm"] == 6 for s in ss)
    p = G / "kh02.elf"
    if p.is_file():
        assert not [s for s in sites(Binary.load(p), 0) if s["status"] == "PATCH"]


# ---- item 3: NID names ----------------------------------------------------------------------------------
SAVEDATA = {"ZP4e7rlzOUk": "sceSaveDataMount3", "85zul--eGXs": "sceSaveDataSetParam",
            "TywrFKCoLGY": "sceSaveDataInitialize3", "c88Yy54Mx0w": "sceSaveDataSaveIcon",
            "sDCBrmc61XU": "sceSaveDataPrepare", "PHnuI4LhuRk": "sceSaveDataDirNameSearch2",
            "dyIhnXq-0SM": "sceSaveDataDirNameSearch"}


def test_savedata_nid_names():
    for n, name in SAVEDATA.items():
        assert nid(name) == n and name_of(n) == name
    for name in ("sceSaveDataTerminate", "sceSaveDataMount2", "sceSaveDataUmount", "sceSaveDataCommit",
                 "sceSaveDataGetParam", "sceSaveDataLoadIcon", "sceSaveDataDelete", "sceSaveDataBackup",
                 "sceSaveDataGetMountInfo", "sceSaveDataSetupSaveDataMemory2", "sceSaveDataSyncSaveDataMemory",
                 "sceSaveDataGetEventResult", "sceSaveDataRegisterEventCallback",
                 "sceSaveDataCreateTransactionResource", "sceSaveDataDeleteTransactionResource"):
        assert name_of(nid(name)) == name


def test_rule_and_contract_nids_have_names():
    import json
    from importlib import resources
    for n, name in (("-sD02mFDBh4", "sceUserServiceGetGamePresets"), ("04AjkP0jO9U", "_umtx_op"),
                    ("BKSCW2bCACA", "__cxa_thread_atexit"), ("tsvEmnenz48", "__cxa_atexit"),
                    ("yu17wG8L5FI", "sceKernelHasTrinityMode"), ("BfBDZGbti7A", "sceAgcGetIsTrinityMode")):
        assert name_of(n) == name
    data = json.loads(resources.files("ps5bp").joinpath("data/stub_contracts.json").read_text())
    for c in data["contracts"]:
        if c["name_verified"]:
            assert name_of(c["nid"]) == c["name"], c


# ---- item 4: 0x809f8032 wording ---------------------------------------------------------------------------
def test_809f8032_wording_and_no_systemblocks_advice():
    t_ = klog.parse((DATA / "kh_savedata_loop.log").read_text())
    txt = "\n".join(t_.issues)
    assert "0x809f8032" in txt and "half-created" in txt and "delete it in Settings → Saved Data" in txt
    assert not t_.suggestions and not hasattr(klog, "SAVEDATA_RO_FIX")


# ---- item 2: assert-aware triage ----------------------------------------------------------------------------
CRASH = DATA / "kh_prepare_assert.txt"


def test_real_crash_parses_without_game():
    t_ = klog.parse(CRASH.read_text())
    c = t_.crashes[0]
    assert c.rip == 0x49bd77 and c.reason == "general protection fault"
    assert c.frames[0].addr == 0x4b9b45 and getattr(c.module_at(c.rip), "name", "") == "eboot.bin"
    klog.diagnose(t_)
    assert not any("assertion" in d for d in t_.diagnosis)         # needs the binary to know


@needs_game
def test_real_crash_assert_diagnosis():
    t_ = klog.parse(CRASH.read_text())
    klog.symbolize(t_, G)
    klog.diagnose(t_)
    txt = t_.to_text()
    c = t_.crashes[0]
    assert c.abort["kind"] == "int 0x41" and c.abort["line"] == 0x38a and c.abort["checked_nid"] == "sDCBrmc61XU"
    assert any("libmcPS5.cpp:906" in d and "sceSaveDataPrepare returned an error" in d for d in t_.diagnosis)
    assert any("savedata-prepare" in s for s in t_.suggestions)
    assert "deliberate abort" in txt and "sceSaveDataMount3" in txt          # names in "function also calls"
    # item 5: the dump's own fakelib/libScePlayGo.sprx was not loaded; the system copy ran
    assert any("libScePlayGo.sprx" in d and "system copies" in d and "/common/lib/" in d for d in t_.diagnosis)


# ---- item 2: synthetic assert (generality) ----------------------------------------------------------------------
def assert_game(tmp, trap=b"\xcd\x41", with_args=True):
    """caller: call import; test eax,eax; je L; lea rdi,[file]; mov esi,0x38a; call helper; L: ... ;
    helper at 0x180 does `push rbp; mov rbp,rsp; <trap>`."""
    code = H("55 4889e5") + t.call(0x104, t.PLT0) + H("85c0 7411")
    lea = b"\x48\x8d\x3d" + struct.pack("<i", 0x1c0 - (0x10d + 7))
    code += lea + H("be 8a030000") + t.call(0x119, 0x180) + H("5d c3")
    helper = H("55 4889e5") + trap + H("5d c3")
    return t.game(tmp, t.mkspec([t.PREP], {0x100: code, 0x180: helper, 0x1c0: b"D:\\proj\\save.cpp\0"}))


def synth_log(ret=0x40011e, rip=0x400184):
    return (f"# A user thread receives a fatal signal\n#\n# reason: general protection fault\n# registers:\n"
            f"# rip: {rip:016x}  eflags: 00010206\n# backtrace:\n# {ret:016x}\n# 0000000000000000\n"
            "# dynamic libraries:\n# /app0/eboot.bin\n#  xotext: 0000000000400000:0000000000500000 nsegs: 4\n"
            "mDBG: Sending signal(pid: 1, tid: 1, signo: 0xa)\n")


@pytest.mark.parametrize("trap,kind", [(b"\xcd\x41", "int 0x41"), (b"\xcc", "int3"), (b"\x0f\x0b", "ud2")])
def test_synthetic_assert(tmp_path, trap, kind):
    g = assert_game(tmp_path, trap)
    t_ = klog.parse(synth_log())
    klog.symbolize(t_, g)
    klog.diagnose(t_)
    a = t_.crashes[0].abort
    assert a["kind"] == kind and a["file"] == "D:\\proj\\save.cpp" and a["line"] == 906
    assert a["checked_nid"] == "sDCBrmc61XU" and a["checked"] == "sceSaveDataPrepare"
    assert any("save.cpp:906" in d and "sceSaveDataPrepare returned an error" in d for d in t_.diagnosis)
    assert any("--rule savedata-prepare" in s for s in t_.suggestions)
    assert not any("CPU fault inside" in d for d in t_.diagnosis)


def test_synthetic_trap_without_assert_context_falls_back(tmp_path):
    g = assert_game(tmp_path)
    t_ = klog.parse(synth_log(ret=0x400200))               # return address in padding: no call before it
    klog.symbolize(t_, g)
    klog.diagnose(t_)
    assert t_.crashes[0].abort.get("kind") == "int 0x41" and "file" not in t_.crashes[0].abort
    assert any("deliberate abort" in d for d in t_.diagnosis)
    # rip on an ordinary instruction: no abort, the old CPU-fault text stays
    t_ = klog.parse(synth_log(rip=0x400180))
    klog.symbolize(t_, g)
    klog.diagnose(t_)
    assert not t_.crashes[0].abort and any("CPU fault inside game code" in d for d in t_.diagnosis)


# ---- item 5: fakelib note -------------------------------------------------------------------------------------
def _log_with_modules(extra: str) -> str:
    return (synth_log().replace("mDBG", "# /44GkqpXwyy/common/lib/libSceAgc.sprx\n#  xotext: 0000000804ed4000:"
                                        "0000000804eec000 nsegs: 4\n" + extra + "mDBG"))


def test_fakelib_note_lists_unloaded_fakelibs(tmp_path):
    game = tmp_path / "game"
    (game / "fakelib").mkdir(parents=True)
    for n in ("libSceAgc.sprx", "libSceFoo.sprx"):
        (game / "fakelib" / n).write_bytes(b"x")
    t_ = klog.parse(_log_with_modules(""))
    t_.layers = [game]
    klog.diagnose(t_)
    note = next(d for d in t_.diagnosis if d.startswith("(note)"))
    assert "libSceAgc.sprx, libSceFoo.sprx" in note and "system copies of libSceAgc.sprx" in note
    assert "libSceFoo.sprx not loaded at all" in note and "normal on a high firmware" in note
    assert "failed" not in note


def test_fakelib_note_generic_without_folder():
    t_ = klog.parse(_log_with_modules(""))
    klog.diagnose(t_)
    note = next(d for d in t_.diagnosis if d.startswith("(note)"))
    assert "system libraries were used" in note and "normal on a high firmware" in note
