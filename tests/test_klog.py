import os
from pathlib import Path

import pytest

from ps5bp.core import klog

LOG = """\
<118>[SceLncService] launchApp(PPSA99999)
<118>[libSceSaveData] Failed to mount X(0x809f8022)
<129> EXEC /app0/eboot.bin [user], vm#1, dmem#1 abi=native category=native_game <1 msec>
#
# A user thread receives a fatal signal
#
# reason:  exit is called with non-zero
# thread name: eboot.bin
# proc name: eboot.bin
# registers:
# rax: 0000000000000000  rbx: 00000000ffffffff
# rip: 000000080000200c  eflags: 00000246
# backtrace:
# 0000000000400085
<118>noise in the middle
# 0000000080000010
# 0000000000000000
# dynamic libraries:
# /app0/eboot.bin
#  xotext: 0000000000400000:0000000000500000 nsegs: 4
<118>more noise
# /r9YluY9uwc/common/lib/libkernel.sprx
#  xotext: 0000000800000000:0000000800048000 nsegs: 4
# /app0/fakelib/libSceFoo.sprx
#  xotext: 0000000080000000:0000000080010000 nsegs: 4
mDBG: Sending signal(pid: 129, tid: 1, signo: 0xa0020004)
<118>[SceLncService] notifyAppCrash() titleId={PPSA99999}, crashReportMode={0}
"""


def test_parse_synthetic():
    t = klog.parse(LOG)
    assert t.title_id == "PPSA99999" and len(t.launches) == 1
    c = t.crashes[0]
    assert c.reason == "exit is called with non-zero" and c.signal == "0xa0020004"
    assert c.rip == 0x80000200C and c.module_at(c.rip).name == "libkernel.sprx"
    assert [f.where() for f in c.frames] == ["eboot.bin+0x85", "libSceFoo.sprx+0x10"]
    klog.diagnose(t)
    assert any("exit()" in d for d in t.diagnosis)
    assert any("libSceFoo.sprx" in d for d in t.diagnosis)       # fakelib on the stack
    assert any("save data" in n for n in t.noise)


def test_no_crash():
    t = klog.parse("<118>nothing here\n")
    klog.diagnose(t)
    assert not t.crashes and "no fatal-signal" in t.diagnosis[0]


ROOT = Path(os.environ.get("PS5BP_FIXTURES", "/nonexistent"))


@pytest.mark.skipif(not (ROOT / "klog-wolverine-1160.txt").is_file(), reason="needs PS5BP_FIXTURES")
def test_wolverine_klog_resolves_allocator():
    t = klog.parse((ROOT / "klog-wolverine-1160.txt").read_text())
    klog.symbolize(t, ROOT / "wolverine-orig-synth")
    klog.diagnose(t, ["pro-query", "pssr"])
    assert t.title_id == "PPSA03671"
    fr = t.crashes[0].frames
    assert fr[1].call == "exit" and fr[2].call == "function 0x3d77b40"
    assert "sceKernelAllocateDirectMemory" in fr[2].calls_in_fn
    assert any("pssr-memory" in s for s in t.suggestions)
