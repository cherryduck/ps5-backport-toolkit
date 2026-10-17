"""Integration of the 10c rules after merging: shared cave safety and NID ownership."""
from ps5bp.core.rules import common


class _Seg:
    def __init__(self, vaddr, is_exec=True):
        self.vaddr, self.is_exec = vaddr, is_exec


class _Bin:
    def __init__(self, seg: bytes):
        self._seg = seg

    def loads(self):
        return [_Seg(0x1000)]

    def segment_bytes(self, p):
        return self._seg


def test_int3_runs_skip_displacement_byte_and_branch_targets():
    pad = b"\xcc" * 16
    seg = (
        b"\xc3" + pad            # ret; padding            -> usable
        + b"\x90\xeb" + pad      # jmp rel8 whose disp byte is 0xcc: the "run" starts on the displacement
        + b"\x90" * 4
        + b"\xc3" + pad          # ret; padding, but a call below lands inside it -> unusable
        + b"\xe8" + b"\x00" * 4  # placeholder call, fixed below
    )
    seg = bytearray(seg)
    third = seg.index(b"\xc3" + pad, 1 + 16 + 2) + 1        # start of the third run
    call = len(seg) - 5
    rel = third + 4 - (call + 5)
    seg[call + 1:call + 5] = rel.to_bytes(4, "little", signed=True)
    runs = common.int3_runs(_Bin(bytes(seg)), [])
    assert runs == [(0x1000 + 1 + 1, 15)]                   # only the first run (its first byte left alone)


def test_compat_stubs_leaves_trinity_nids_to_trinity_gate():
    from ps5bp.core.rules import compat_stubs
    assert {"tU5e3f9gSiU", "yu17wG8L5FI"} <= compat_stubs.TRINITY_GATE_OWNED
