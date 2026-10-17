"""Phase 10c-B: request/libc byte rules (gamepresets-28, tls-atexit, savedata-mount extension,
savedata-prepare, savedata-dirsearch, frostbite-8ch) on synthetic binaries, plus local-only
validation against community backports (PS5BP_DECKERR_TREE, skipped when absent)."""
import os
import struct
import zipfile
from pathlib import Path

import pytest

from ps5bp.core import dynamic
from ps5bp.core.binary import Binary
from ps5bp.core.evidence import EvidenceDB
from ps5bp.core.pipeline import BuildOptions, build, plan
from ps5bp.core.rules import registry
from synth import TEXT_VA, Spec, build_elf, build_self
from test_phase8 import put, spec_with

B = 0x400000
GP, MOUNT3, PREP = "-sD02mFDBh4", "ZP4e7rlzOUk", "sDCBrmc61XU"
SEARCH2, SEARCH = "PHnuI4LhuRk", "dyIhnXq-0SM"
IMPL, WRAP, LOCAL = "qBS714-Jr3g", "BKSCW2bCACA", "tsvEmnenz48"


def H(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


def call(at: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (at + 5))


PLT0 = 16                                  # text offset of the first import's PLT entry


def mkspec(imports, code_at: dict[int, bytes], size: int = 0x400, **kw) -> Spec:
    spec = spec_with(imports, **kw)
    t = bytearray(spec.text.ljust(size, b"\xcc"))
    for off, code in code_at.items():
        t[off:off + len(code)] = code
    spec.text = bytes(t)
    return spec


def game(tmp: Path, spec: Spec, rel: str = "eboot.bin", extra: dict[str, Spec] | None = None) -> Path:
    g = tmp / "PPSA99999"
    put(g / rel, spec, (0x07000038, 0x10590001))
    if rel != "eboot.bin":
        put(g / "eboot.bin", spec_with(["rTXw65xmLIA"]), (0x07000038, 0x10590001))
    for r, s in (extra or {}).items():
        put(g / r, s, (0x07000038, 0x10590001))
    (g / "sce_sys").mkdir(parents=True, exist_ok=True)
    (g / "sce_sys/param.json").write_text('{"titleId": "PPSA99999", "sdkVersion": "0x0700003800000000", '
                                          '"requiredSystemSoftwareVersion": "0x0700000000000000"}')
    return g


def run(g: Path, tmp: Path, rule: str, target: int = 4):
    db = EvidenceDB(tmp / "home")
    rep = build(g, BuildOptions(target=target, out=tmp / "out", rules={rule}, force=True), db, log=lambda m: None)
    return rep, [f for f in rep.findings if f["rule"] == rule]


def statuses(g: Path, rule: str, target: int = 4):
    p = plan(g, target)
    return [(f.data.get("status"), f) for f in p.findings if f.rule == rule]


def test_rules_listed_and_off_by_default():
    reg = registry()
    for n in ("gamepresets-28", "tls-atexit", "savedata-prepare", "savedata-dirsearch", "frostbite-8ch"):
        assert n in reg and not reg[n].default


# ---- gamepresets-28 ---------------------------------------------------------------------------------
def gp_code(pre: bytes, at: int = 0x100) -> bytes:
    return pre + call(at + len(pre), PLT0) + H("5d c3")


GP_PATCH = gp_code(H("55 4889e5 48c745b0 30000000 488d75b0 8b7b08"))
GP_DONE = gp_code(H("55 4889e5 48c745b0 28000000 488d75b0 8b7b08"))
GP_ALIAS = gp_code(H("55 4889e5 488d45b0 4889c6 48c70030000000 8b7b08"))
GP_UNKNOWN = gp_code(H("55 4889e5 48897db0 488d75b0 8b7b08"))
GP_TWICE = gp_code(H("55 4889e5 48c745b0 30000000 48c745b0 30000000 488d75b0 8b7b08"))


def test_gamepresets_patch_and_build(tmp_path):
    g = game(tmp_path, mkspec([GP], {0x100: GP_PATCH}))
    ((st, f),) = statuses(g, "gamepresets-28")
    assert st == "PATCH" and f.recommended and "0x30" in f.title
    rep, (fr,) = run(g, tmp_path, "gamepresets-28")
    assert fr["applied"] and rep.ok
    b = Binary.load(tmp_path / "out/eboot.bin")
    assert b.read(0x100 + 4, 8) == H("48c745b0 28000000")
    edits = [e for e in rep.edits if e.kind == "rule:gamepresets-28"]
    assert [(e.old, e.new) for e in edits] == [("30000000", "28000000")]


def test_gamepresets_recommendation_follows_declared_sdk(tmp_path):
    g = game(tmp_path, mkspec([GP], {0x100: GP_PATCH}))
    assert statuses(g, "gamepresets-28", 4)[0][1].recommended
    assert not statuses(g, "gamepresets-28", 6)[0][1].recommended


def test_gamepresets_alias_chain(tmp_path):
    g = game(tmp_path, mkspec([GP], {0x100: GP_ALIAS}))
    ((st, f),) = statuses(g, "gamepresets-28")
    assert st == "PATCH"
    assert f.data["edits"][0][1:3] == ("30000000", "28000000")


def test_gamepresets_done_and_refusals(tmp_path):
    g = game(tmp_path / "a", mkspec([GP], {0x100: GP_DONE}))
    ((st, f),) = statuses(g, "gamepresets-28")
    assert st == "DONE" and not f.applicable
    rep, _ = run(g, tmp_path / "a", "gamepresets-28")
    assert rep.edits == [] or all(e.kind != "rule:gamepresets-28" for e in rep.edits)
    assert not any("not applicable" in w for w in rep.warnings)            # DONE is not a warning
    for n, code in (("u", GP_UNKNOWN), ("t", GP_TWICE)):
        g = game(tmp_path / n, mkspec([GP], {0x100: code}))
        ((st, f),) = statuses(g, "gamepresets-28")
        assert st == "UNKNOWN" and not f.applicable
        rep, (fr,) = run(g, tmp_path / n, "gamepresets-28")
        assert not fr["applied"] and any("not applicable" in w for w in rep.warnings)


def test_gamepresets_encoding_guard(tmp_path):
    # mov qword [rbp-0x50], 0x30 spelled with a 4-byte immediate whose last byte differs is not matched
    code = gp_code(H("55 4889e5 48c745b0 30000000 488d75b0 8b7b08")).replace(H("30000000"), H("30000001"))
    g = game(tmp_path, mkspec([GP], {0x100: code}))
    assert statuses(g, "gamepresets-28")[0][0] == "UNKNOWN"


HELPER = H("55 4889e5 ba30000000 48c70730000000 5d c3")                     # memset length + size store
HELP_CALLER = (H("55 4889e5 4883ec30 488d7de0") + call(0x100 + 13, 0x180)
               + H("8b7de8 488b75e0"))                                   # edi/esi reloaded from [rbp-X]


def helper_game(tmp, helper=HELPER, caller_tail=None):
    cc = HELP_CALLER
    cc += call(0x100 + len(cc), PLT0) + H("5d c3") if caller_tail is None else caller_tail
    return game(tmp, mkspec([GP], {0x100: cc, 0x180: helper}))


def test_gamepresets_init_helper_form(tmp_path):
    g = helper_game(tmp_path / "p")
    ((st, f),) = statuses(g, "gamepresets-28")
    assert st == "PATCH" and "init-helper" in f.title
    assert f.data["edits"][0][0] == B + 0x180 + 4 + 5 + 3 and f.data["edits"][0][1] == "30000000"
    rep, (fr,) = run(g, tmp_path / "p", "gamepresets-28")
    b = Binary.load(tmp_path / "p/out/eboot.bin")
    assert fr["applied"] and rep.ok
    assert b.read(0x180 + 4, 5) == H("ba30000000")                  # the memset length is left alone
    assert b.read(0x180 + 9, 7) == H("48c70728000000")
    # helper already writes 0x28
    done = HELPER.replace(H("48c70730000000"), H("48c70728000000"))
    g2 = helper_game(tmp_path / "d", done)
    assert statuses(g2, "gamepresets-28")[0][0] == "DONE"
    # helper without the memset length / caller not followed by the import call: refused
    g3 = helper_game(tmp_path / "n", HELPER.replace(H("ba30000000"), H("ba20000000")))
    assert statuses(g3, "gamepresets-28")[0][0] == "UNKNOWN"


# ---- tls-atexit -------------------------------------------------------------------------------------
def libc_spec(wrapper: bytes, local_at: int = 0x140) -> Spec:
    s = mkspec([IMPL], {0x100: wrapper, local_at: H("c3")}, kind="module", module="libc",
               export_libs=["libc"], exports=[(WRAP, 0), (LOCAL, 0)], export_values=[0x100, local_at])
    return s


def tls_game(tmp, target_rel=PLT0, local_at=0x140, wrapper=None):
    w = wrapper or (H("55 4889e5") + call(0x104, target_rel) + H("5d c3"))
    return game(tmp, libc_spec(w, local_at), "sce_module/libc.prx")


def test_tls_atexit_patch_done_refuse(tmp_path):
    g = tls_game(tmp_path / "a")
    ((st, f),) = statuses(g, "tls-atexit", 4)
    assert st == "PATCH" and f.recommended
    assert not statuses(g, "tls-atexit", 11)[0][1].recommended
    rep, (fr,) = run(g, tmp_path / "a", "tls-atexit")
    b = Binary.load(tmp_path / "a/out/sce_module/libc.prx")
    assert fr["applied"] and rep.ok
    assert b.read(0x105, 4) == struct.pack("<i", 0x140 - 0x109)
    # the output is DONE; PLT entry and import stay
    assert statuses(tmp_path / "a/out", "tls-atexit")[0][0] == "DONE"
    assert IMPL in dynamic.parse(b).imported_nids()
    # wrapper with a different body, or a call into somewhere else: refused
    g2 = tls_game(tmp_path / "b", wrapper=H("55 4889e5 90") + call(0x105, PLT0) + H("5d c3"))
    assert statuses(g2, "tls-atexit")[0][0] == "UNKNOWN"
    g3 = tls_game(tmp_path / "c", target_rel=0x200)
    assert statuses(g3, "tls-atexit")[0][0] == "UNKNOWN"


def test_tls_atexit_ignores_libc_without_the_import(tmp_path):
    s = mkspec(["rTXw65xmLIA"], {0x100: H("55 4889e5 c3")}, kind="module", module="libc",
               export_libs=["libc"], exports=[(WRAP, 0), (LOCAL, 0)], export_values=[0x100, 0x140])
    assert statuses(game(tmp_path, s, "sce_module/libc.prx"), "tls-atexit") == []


# ---- savedata-mount extension -----------------------------------------------------------------------
def m3(pre: bytes, at: int = 0x100) -> bytes:
    return pre + call(at + len(pre), PLT0) + H("5d c3")


M3_ALIAS = m3(H("55 4889e5 488d4590 4889c7 4889c3 48897310 48c74318ffffffff"))
M3_ALIAS_NOBLK = m3(H("55 4889e5 488d4590 4889c7 4889c3 48c74318ffffffff"))
M3_ALIAS_DONE = m3(H("55 4889e5 488d4590 4889c7 4889c3 48897310 48c7431800000000"))
M3_TWO = m3(H("55 4889e5 488d4590 4889c7 4889c3 48897310 48c74318ffffffff 48c74318ffffffff"))
WRAPPER_FN = H("55 4889e5 4889f7") + call(0x180 + 7, PLT0) + H("5d c3")


def wrapper_game(tmp, sysblk=H("48c745d8 ffffffff"), blocks=H("488945d0"), extra_caller=False):
    c = H("55 4889e5 488d75c0") + blocks + sysblk
    c += call(0x100 + len(c), 0x180) + H("5d c3")
    code = {0x100: c, 0x180: WRAPPER_FN}
    if extra_caller:
        code[0x1c0] = H("55 4889e5 488d75c0") + call(0x1c0 + 8, 0x180) + H("5d c3")
    return game(tmp, mkspec([MOUNT3], code))


def test_mount_alias_chain_patch(tmp_path):
    g = game(tmp_path, mkspec([MOUNT3], {0x100: M3_ALIAS}))
    ((st, f),) = statuses(g, "savedata-mount")
    assert st == "PATCH" and f.recommended
    rep, (fr,) = run(g, tmp_path, "savedata-mount")
    assert fr["applied"] and rep.ok
    b = Binary.load(tmp_path / "out/eboot.bin")
    assert b.read(0x100 + 4 + 4 + 3 + 3 + 4, 8) == H("48c74318 00000000")
    assert [(e.old, e.new) for e in rep.edits if e.kind == "rule:savedata-mount"] == [("ffffffff", "00000000")]


def test_mount_alias_guards(tmp_path):
    for n, code, want in (("nb", M3_ALIAS_NOBLK, "UNKNOWN"), ("d", M3_ALIAS_DONE, "DONE"), ("t", M3_TWO, "UNKNOWN")):
        g = game(tmp_path / n, mkspec([MOUNT3], {0x100: code}))
        assert statuses(g, "savedata-mount")[0][0] == want, n
    # a different non-zero sentinel is left alone (neither PATCH nor reported as fixed)
    odd = M3_ALIAS.replace(H("48c74318ffffffff"), H("48c74318fffffffe"))
    g = game(tmp_path / "odd", mkspec([MOUNT3], {0x100: odd}))
    assert not [s for s, _ in statuses(g, "savedata-mount") if s in ("PATCH", "DONE")]


def test_mount_local_wrapper(tmp_path):
    g = wrapper_game(tmp_path / "w")
    fs = [(s, f) for s, f in statuses(g, "savedata-mount") if s]
    assert [s for s, _ in fs] == ["PATCH"] and "wrapper" in fs[0][1].title
    rep, _ = run(g, tmp_path / "w", "savedata-mount")
    b = Binary.load(tmp_path / "w/out/eboot.bin")
    assert rep.ok and b.read(0x100 + 4 + 4 + 4 + 4, 4) == H("00000000")
    # no blocks store at the caller -> refused
    g2 = wrapper_game(tmp_path / "x", blocks=b"")
    assert [s for s, _ in statuses(g2, "savedata-mount") if s] == ["UNKNOWN"]
    # a second caller that never stores +0x18 is not an error and not patched
    g3 = wrapper_game(tmp_path / "y", extra_caller=True)
    assert [s for s, _ in statuses(g3, "savedata-mount") if s] == ["PATCH"]


def test_mount_old_behaviour_unchanged(tmp_path):
    from test_phase9 import MODE_VAR, mount_game
    g, store = mount_game(tmp_path, MODE_VAR)
    fs = statuses(g, "savedata-mount")
    assert len(fs) == 1 and fs[0][0] is None and fs[0][1].data == {"va": B + TEXT_VA + store, "len": 8}


UNITY_ZERO = H("c5f057c9 c5fc118d60ffffff")
UNITY_R14 = H("c4c17810 4630 c5f81185 70ffffff")
UNITY_TAIL = H("488dbd60ffffff")


def unity_code(copy: bytes, zero: bytes = UNITY_ZERO, tail: bytes = UNITY_TAIL, at: int = 0x100) -> bytes:
    pre = H("55 4889e5") + zero + copy + tail
    return pre + call(at + len(pre), PLT0) + H("5d c3")


def unity_game(tmp, code, name="Media/Plugins/SaveData.prx"):
    spec = mkspec([MOUNT3], {0x100: code}, kind="module", module="SaveData")
    return game(tmp, spec, name)


def test_unity_vector_copy_r14(tmp_path):
    g = unity_game(tmp_path, unity_code(UNITY_R14))
    fs = [(s, f) for s, f in statuses(g, "savedata-mount") if s]
    assert [s for s, _ in fs] == ["PATCH"] and fs[0][1].recommended
    rep, _ = run(g, tmp_path, "savedata-mount")
    b = Binary.load(tmp_path / "out/Media/Plugins/SaveData.prx")
    va = 0x100 + 4 + len(UNITY_ZERO)
    assert rep.ok and b.read(va, 14) == H("498b4630 48898570ffffff 909090")
    assert [s for s, _ in statuses(tmp_path / "out", "savedata-mount") if s] == ["DONE"]


def test_unity_vector_copy_rbx_and_r15(tmp_path):
    rbx = unity_code(H("c5f81043 30 c5f81184 24 30000000"), H("c5f057c9 c5fc118c24 20000000"), H("488d7c2420"))
    g = unity_game(tmp_path / "b", rbx)
    ((st, f),) = [(s, f) for s, f in statuses(g, "savedata-mount") if s]
    assert st == "PATCH" and f.data["edits"][0][2] == "488b4330 4889842430000000 9090".replace(" ", "")
    r15 = unity_code(H("c4c17810 4730 c5f81185 70ffffff"))
    g = unity_game(tmp_path / "c", r15)
    ((st, f),) = [(s, f) for s, f in statuses(g, "savedata-mount") if s]
    assert st == "PATCH" and f.data["edits"][0][2] == "498b4730 48898570ffffff 909090".replace(" ", "")


def test_unity_vector_copy_refusals(tmp_path):
    # request not zero-initialised before the copy
    g = unity_game(tmp_path / "z", unity_code(UNITY_R14, zero=b""))
    assert [s for s, _ in statuses(g, "savedata-mount") if s] == ["UNKNOWN"]
    # copy does not land on request+0x10
    g = unity_game(tmp_path / "o", unity_code(UNITY_R14, tail=H("488dbd50ffffff")))
    assert [s for s, _ in statuses(g, "savedata-mount") if s] == ["UNKNOWN"]
    # two candidate copies -> ambiguous
    g = unity_game(tmp_path / "t", unity_code(UNITY_R14 + UNITY_R14))
    assert [s for s, _ in statuses(g, "savedata-mount") if s] == ["UNKNOWN"]
    # another binary name is not a Unity plugin: the vector form is left alone
    g = unity_game(tmp_path / "n", unity_code(UNITY_R14), "Media/Plugins/Other.prx")
    assert not [s for s, _ in statuses(g, "savedata-mount") if s]


# ---- savedata-prepare ---------------------------------------------------------------------------------
def prep(pre: bytes, at: int = 0x100) -> bytes:
    return pre + call(at + len(pre), PLT0) + H("5d c3")


def prep_game(tmp, code):
    return game(tmp, mkspec([PREP], {0x100: code}))


def test_prepare_mode_patch_and_done(tmp_path):
    g = prep_game(tmp_path / "2", prep(H("55 4889e5 c745e4 02000000 488d75e0")))
    ((st, f),) = statuses(g, "savedata-prepare")
    assert st == "PATCH" and f.recommended                     # declared SDK 4 (Phase 10j)
    assert not statuses(g, "savedata-prepare", 8)[0][1].recommended
    rep, (fr,) = run(g, tmp_path / "2", "savedata-prepare")
    b = Binary.load(tmp_path / "2/out/eboot.bin")
    assert rep.ok and b.read(0x100 + 4, 7) == H("c745e4 00000000")
    g = prep_game(tmp_path / "3", prep(H("55 4889e5 c5f857c0 c5fc1145e0 c745e4 03000000 488d75e0")))
    assert statuses(g, "savedata-prepare")[0][0] == "PATCH"
    g = prep_game(tmp_path / "d", prep(H("55 4889e5 c745e4 00000000 488d75e0")))
    assert statuses(g, "savedata-prepare")[0][0] == "DONE"


def test_prepare_refusals(tmp_path):
    cases = {
        "mode3-no-zero": prep(H("55 4889e5 c745e4 03000000 488d75e0")),
        "two": prep(H("55 4889e5 c745e4 02000000 c745e4 02000000 488d75e0")),
        "other-writer": prep(H("55 4889e5 c745e4 02000000 8945e4 488d75e0")),
    }
    for n, code in cases.items():
        assert statuses(prep_game(tmp_path / n, code), "savedata-prepare")[0][0] == "UNKNOWN", n
    # mode copied from a register: nothing to patch, nothing reported
    assert statuses(prep_game(tmp_path / "c", prep(H("55 4889e5 8945e4 488d75e0"))), "savedata-prepare") == []


# ---- savedata-dirsearch ---------------------------------------------------------------------------------
def set_got(path: Path, spec: Spec, slot: int, value: int) -> None:
    b = Binary.load(path)
    rva = build_elf(spec)[1]["got"][slot]
    b.patch(rva, b"\0" * 8, struct.pack("<Q", value))
    b.save(path)


def test_dirsearch_rename(tmp_path):
    g = game(tmp_path, mkspec([SEARCH2], {}))
    ((st, f),) = statuses(g, "savedata-dirsearch")
    assert st == "PATCH" and not f.recommended
    rep, (fr,) = run(g, tmp_path, "savedata-dirsearch")
    d = dynamic.parse(Binary.load(tmp_path / "out/eboot.bin"))
    assert rep.ok and fr["applied"] and d.imported_nids() == {SEARCH}
    # not evidenced above 4.xx: refused
    assert statuses(g, "savedata-dirsearch", 6)[0][0] == "UNKNOWN"


def test_dirsearch_forward_when_both_imported(tmp_path):
    spec = mkspec([SEARCH2, SEARCH], {})
    g = game(tmp_path, spec)
    p = g / "eboot.bin"
    set_got(p, spec, 0, 0x16)                          # lazy: PLT entry 0 (text+0x10) + 6
    set_got(p, spec, 1, 0x26)
    ((st, f),) = statuses(g, "savedata-dirsearch")
    assert st == "PATCH" and "forward" in f.title
    rep, _ = run(g, tmp_path, "savedata-dirsearch")
    b = Binary.load(tmp_path / "out/eboot.bin")
    assert rep.ok and b.u64(build_elf(spec)[1]["got"][0]) == 0x20            # Search's PLT entry (rva)
    assert statuses(tmp_path / "out", "savedata-dirsearch")[0][0] == "DONE"
    # a slot that is not lazy is refused
    spec2 = mkspec([SEARCH2, SEARCH], {})
    g2 = game(tmp_path / "x", spec2)
    set_got(g2 / "eboot.bin", spec2, 0, 0x1234)
    assert statuses(g2, "savedata-dirsearch")[0][0] == "UNKNOWN"


# ---- frostbite-8ch ----------------------------------------------------------------------------------------
ANCHOR = 0x200


def fb_text(name: str, size: int = 0x1000, anchor: int = ANCHOR, post: bool = False) -> bytearray:
    from ps5bp.core.rules.frostbite_8ch import VARIANTS
    v = next(v for v in VARIANTS if v["name"] == name)
    t = bytearray(b"\x90" * size)
    for rel, hx in v["guards"].items():
        t[anchor + rel:anchor + rel + len(hx) // 2] = H(hx)
    for rel, old, new in v["edits"]:
        t[anchor + rel:anchor + rel + len(old) // 2] = H(new if post else old)
    for rel, tgt in v["branches"].items():
        t[anchor + rel:anchor + rel + 6] = H("0f85") + struct.pack("<i", tgt - (rel + 6))
    return t


def fb_game(tmp, t: bytearray):
    spec = spec_with(["rTXw65xmLIA"])
    spec.text = bytes(t)
    return game(tmp, spec)


NAMES = ("EA_FORMAT_SLOT_RBP_M0xEC", "EA_FORMAT_SLOT_RBP_M0xF0", "EA_FORMAT_SLOT_RBP_M0xF0_STACKCHECK")


@pytest.mark.parametrize("name", NAMES)
def test_frostbite_variants_patch_then_done(tmp_path, name):
    g = fb_game(tmp_path, fb_text(name))
    fs = statuses(g, "frostbite-8ch")
    assert [s for s, _ in fs] == ["PATCH"] and name in fs[0][1].title and fs[0][1].recommended
    assert not statuses(g, "frostbite-8ch", 6)[0][1].recommended
    rep, (fr,) = run(g, tmp_path, "frostbite-8ch")
    out = Binary.load(tmp_path / "out/eboot.bin")
    want = fb_text(name, post=True)
    assert rep.ok and fr["applied"] and out.read(0, 0x1000) == bytes(want)
    assert [s for s, _ in statuses(tmp_path / "out", "frostbite-8ch")] == ["DONE"]


def test_frostbite_refusals(tmp_path):
    n = NAMES[0]
    t = fb_text(n)
    t[ANCHOR + 1890] = 0x90                              # branch missing -> no layout matches
    ((st, f),) = statuses(fb_game(tmp_path / "a", t), "frostbite-8ch")
    assert st == "UNKNOWN" and not f.applicable
    # one good anchor + one unknown anchor: nothing is patched
    t = fb_text(n, size=0x2000)
    two = bytearray(t)
    two[0x1200 - 10:0x1200 + 6] = H("c78514ffffff000c0000") + H("41b90c030000")
    rep, frs = run(fb_game(tmp_path / "b", two), tmp_path / "b", "frostbite-8ch")
    assert all(not x["applied"] for x in frs) and all("UNKNOWN" in x["title"] for x in frs)
    assert not [e for e in rep.edits if e.kind == "rule:frostbite-8ch"]
    # a stray mov r9d,0x30c without the 0xc00 store is not Frostbite-like: ignored
    t = bytearray(b"\x90" * 0x400)
    t[0x100:0x106] = H("41b90c030000")
    assert statuses(fb_game(tmp_path / "c", t), "frostbite-8ch") == []


# ---- SELF EX_INFO digest ---------------------------------------------------------------------------------
def test_ex_info_digest_left_as_input(tmp_path):
    """Edits never touch the SELF header / EX_INFO digest (build verification would fail otherwise);
    the digest is not recomputed - see README ("SELF digest")."""
    elf = build_elf(mkspec([GP], {0x100: GP_PATCH}))[0]
    raw = bytearray(build_self(elf))
    b0 = Binary(bytes(raw))
    o = b0.ex_info()["offset"]
    raw[o + 0x20:o + 0x40] = bytes(range(32))              # a recognisable digest
    g = game(tmp_path, mkspec([GP], {0x100: GP_PATCH}))
    (g / "eboot.bin").write_bytes(bytes(raw))
    rep, _ = run(g, tmp_path, "gamepresets-28")
    after = Binary.load(tmp_path / "out/eboot.bin")
    assert rep.ok and after.ex_info()["digest"] == bytes(range(32))
    assert Binary(bytes(raw)).ex_info() is not None and Binary(elf).ex_info() is None


# ---- local validation against community backports (skipped when the tree is absent) ---------------------
TREE = Path(os.environ.get("PS5BP_DECKERR_TREE", "/nonexistent"))
needs_tree = pytest.mark.skipif(not (TREE / "D").is_dir(), reason="needs PS5BP_DECKERR_TREE")


def find_zip(pat: str) -> Path:
    hits = sorted(TREE.rglob(pat))
    if not hits:
        pytest.skip(f"no zip {pat}")
    return hits[0]


def member(pat: str, name: str) -> bytes:
    with zipfile.ZipFile(find_zip(pat)) as z:
        return z.read(name)


LIBC_PAIRS = [
    ("*PPSA31162*Super Meat Boy 3D*", "*PPSA31162*Super Meat Boy 3D*", 0x7ECD5),
    ("*PPSA28416*Galactic Racer*", "*PPSA28416*Galactic Racer*", 0x7DD25),
    ("*PPSA30601*Resonance*", "*PPSA30601*Resonance*", 0x80AF5),
]


@needs_tree
@pytest.mark.parametrize("which", range(3))
def test_tls_real_libc_baseline_to_working(which):
    from ps5bp.core.rules import tls_atexit as t
    pat = LIBC_PAIRS[which][0]
    zips = sorted(TREE.rglob(pat.replace("*", "*") + ".zip"))
    base = [z for z in zips if "baselines" in str(z)]
    work = [z for z in zips if "baselines" not in str(z) and "test_builds" not in str(z)]
    if not base or not work:
        pytest.skip("baseline/working zip pair missing")
    nb = zipfile.ZipFile(base[0]).read("sce_module/libc.prx")
    nw = zipfile.ZipFile(work[0]).read("sce_module/libc.prx")
    b, w = Binary(nb), Binary(nw)
    s = t.site(b, 0)
    assert s["status"] == "PATCH" and s["va"] == LIBC_PAIRS[which][2]
    assert t.site(w, 0)["status"] == "DONE"
    b.patch(s["va"], bytes.fromhex(s["old"]), bytes.fromhex(s["new"]))
    assert b.read(s["va"], 4) == w.read(s["va"], 4)
    # what still differs from the community libc: the 32-byte EX_INFO digest, and (where the build
    # has them) the heap-flag edits `mov ecx,0x8000 -> xor ecx,ecx; nop*3`, which are mapflex-flags'
    # territory - and ps5bp's mapflex-flags finds exactly those sites
    from ps5bp.core.rules.mapflex_flags import sites as heap_sites
    assert len(nb) == len(nw)
    ex = Binary(nw).ex_info()["offset"] + 0x20
    seg = Binary(nb)
    rest = [i for i in range(len(nb)) if b.data[i] != nw[i] and not ex <= i < ex + 0x20]
    foffs = {seg.foff(va) + k for va in heap_sites(Binary(nb), 0) for k in range(5)}
    assert set(rest) <= foffs


GOW = "*GOD_OF_WAR_SONS_OF_SPARTA*V8.zip"


@needs_tree
def test_real_gow_eboot_gamepresets_done_and_roundtrip():
    from ps5bp.core.rules import gamepresets as g
    b = Binary(member(GOW, "eboot.bin"))
    (s,) = g.sites(b, B)
    assert s["status"] == "DONE" and s["va"] == 0x18CE4E4 and s["call"] == 0x18CE4F3
    b.patch(s["va"] + 4 - B, H("28000000"), H("30000000"))
    (s,) = g.sites(b, B)
    assert s["status"] == "PATCH" and s["va"] == 0x18CE4E4


@needs_tree
def test_real_gow_saveddata_plugin_done_and_roundtrip():
    from ps5bp.core.rules import savedata_mount as sm
    b = Binary(member(GOW, "Media/Plugins/SaveData.prx"))
    (s,) = sm.unity_sites(b, 0)
    assert s["status"] == "DONE" and s["va"] == 0x247A and s["form"] == "r14"
    done = b.read(0x247A, 14)
    b.patch(0x247A, done, H("c4c17810 4630 c5f81185 70ffffff"))
    (s,) = sm.unity_sites(b, 0)
    assert s["status"] == "PATCH" and bytes.fromhex(s["new"]) == done
    # prepare: the plugin copies the mode from the managed request, nothing to patch
    from ps5bp.core.rules import savedata_prepare as sp
    assert sp.sites(b, 0) == []
