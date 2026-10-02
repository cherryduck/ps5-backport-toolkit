import json
import struct

import pytest

from ps5bp.core import dynamic, nid, sdk
from ps5bp.core.binary import Binary, EncryptedError, FormatError
from ps5bp.core.scan import scan_game
from synth import Spec, build_elf, build_self


# ---- NID ---------------------------------------------------------------------
def test_nid_known_values():
    assert nid.nid("sceKernelAllocateDirectMemory") == "rTXw65xmLIA"
    assert nid.nid("exit") == "uMei1W9uyNo"
    assert nid.name_of("rTXw65xmLIA") == "sceKernelAllocateDirectMemory"


def test_nid_split():
    assert nid.split("rTXw65xmLIA#v#G") == ("rTXw65xmLIA", 47, 6)
    assert nid.split("plain") == ("plain", None, None)


# ---- Binary ------------------------------------------------------------------
@pytest.fixture(params=["elf", "self4", "self5"])
def binpair(request):
    elf, lay = build_elf(Spec())
    if request.param == "elf":
        return Binary(elf), elf, lay
    magic = bytes.fromhex("4f153d1d" if request.param == "self4" else "5414f5ee")
    return Binary(build_self(elf, magic)), elf, lay


def test_kind_and_read(binpair):
    b, elf, lay = binpair
    assert b.kind in ("elf", "self")
    assert b.read(0, 8) == Spec().text[:8]
    assert b.u32(lay["param"] + 8) == 0x4942524F


def test_to_elf_roundtrip(binpair):
    b, elf, lay = binpair
    assert b.to_elf() == elf


def test_patch_verifies_old_bytes(binpair):
    b, elf, lay = binpair
    with pytest.raises(ValueError):
        b.patch(0, b"\x00\x00", b"\x90\x90")
    b.patch(0, b"\x55\x48", b"\x90\x90")
    assert b.read(0, 2) == b"\x90\x90"


def test_grow_cave():
    elf, lay = build_elf(Spec())
    b = Binary(build_self(elf, slack=0x40))
    room = b.slack(0)
    assert room > 0
    cave = b.grow(0, b"\xc3" * 8)
    assert cave == lay["text_size"]
    assert b.read(cave, 8) == b"\xc3" * 8
    b2 = Binary(bytes(b.data))                 # reparse: sizes persisted in SELF entry + phdr
    assert b2.phdrs[0].filesz == lay["text_size"] + 8
    assert b2.read(cave, 8) == b"\xc3" * 8
    with pytest.raises(ValueError):
        b2.grow(0, b"\x90" * (room + 1))


def test_encrypted_and_garbage_rejected():
    elf, _ = build_elf(Spec())
    with pytest.raises(EncryptedError):
        Binary(build_self(elf, props_extra=0x2))
    with pytest.raises(FormatError):
        Binary(b"MZ" + b"\0" * 100)


# ---- SDK -----------------------------------------------------------------------
def test_sdk_find_and_set(binpair):
    b, _, _ = binpair
    p = sdk.find(b)
    assert (p.kind, p.ps5, p.ps4) == ("process", 0x07000038, 0x10590001)
    before, after = sdk.set_sdk(b, *sdk.SDK_PAIRS[4])
    assert (after.ps5, after.ps4) == (0x04000031, 0x09040001)
    assert sdk.find(Binary(bytes(b.data))).ps5 == 0x04000031


def test_fw_str():
    assert sdk.fw_str(0x04000031) == "4.00"
    assert sdk.fw_str(0x10000040) == "10.00"
    assert sdk.fw_major(0x10000040) == 10


# ---- dynamic -----------------------------------------------------------------
def test_dynamic_imports_exports():
    spec = Spec(module="libFoo", kind="module", export_libs=["libFoo"], exports=[("AAAAAAAAAAA", 0)])
    elf, lay = build_elf(spec)
    d = dynamic.parse(Binary(build_self(elf)))
    assert d.needed == ["libkernel.prx", "libc.prx"]
    assert d.module.name == "libFoo"
    assert {s.nid for s in d.imports()} == {"rTXw65xmLIA", "uMei1W9uyNo"}
    assert d.imports_by_lib() == {"libkernel": {"rTXw65xmLIA"}, "libc": {"uMei1W9uyNo"}}
    assert [s.nid for s in d.exports()] == ["AAAAAAAAAAA"]
    assert d.lib_name(d.exports()[0]) == "libFoo"
    assert d.plt[lay["got"][0]].startswith("rTXw65xmLIA#")


# ---- scan ----------------------------------------------------------------------
def test_scan_game(tmp_path):
    spec = Spec(imports=[("NH6xARDOVv8", 0), ("rTXw65xmLIA", 0)],
                import_libs=["libkernel", "libScePsml_mfsr2"], strings=b"KPN9_v070.psp\0")
    elf, _ = build_elf(spec)
    (tmp_path / "eboot.bin").write_bytes(build_self(elf))
    (tmp_path / "sce_module").mkdir()
    mod, _ = build_elf(Spec(kind="module", module="libc", ps5_sdk=0x06000038))
    (tmp_path / "sce_module" / "libc.prx").write_bytes(build_self(mod))
    (tmp_path / "sce_sys").mkdir()
    (tmp_path / "sce_sys" / "param.json").write_text(json.dumps({
        "titleId": "PPSA99999", "contentVersion": "01.000.000",
        "sdkVersion": "0x0700003800000000", "requiredSystemSoftwareVersion": "0x0700000000000000",
        "localizedParameters": {"defaultLanguage": "en-US", "en-US": {"titleName": "Test Game"}}}))
    (tmp_path / "data.bin").write_bytes(b"not an exe")
    gs = scan_game(tmp_path)
    assert (gs.title_id, gs.title) == ("PPSA99999", "Test Game")
    assert [b.path for b in gs.binaries] == ["eboot.bin", "sce_module/libc.prx"]
    assert gs.eboot.sdk_ps5 == 0x07000038
    assert set(gs.flags) >= {"pro-query", "pssr", "pssr2-model"}
    assert [b.path for b in gs.needs_downgrade(4)] == ["eboot.bin", "sce_module/libc.prx"]
    assert [b.path for b in gs.needs_downgrade(6)] == ["eboot.bin"]
    assert not gs.warnings
