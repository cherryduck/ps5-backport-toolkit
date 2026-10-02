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
