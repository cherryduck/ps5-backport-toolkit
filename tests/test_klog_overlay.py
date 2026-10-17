"""Crash-log symbolization against an overlay build: changed files from the overlay, the rest
from the game folder named in its backport-report.json."""
import json

from ps5bp.core import klog

from test_klog import LOG


class _FakeBin:
    def read(self, rva, n):
        return b"\x90" * n


def _spy(monkeypatch):
    seen = []

    def load(p):
        seen.append(p)
        return _FakeBin()
    monkeypatch.setattr("ps5bp.core.binary.Binary.load", staticmethod(load))
    monkeypatch.setattr("ps5bp.core.dynamic.parse", lambda b: None)
    return seen


def _overlay(tmp_path, mode="overlay"):
    game = tmp_path / "PPSA99999"
    (game / "fakelib").mkdir(parents=True)
    (game / "eboot.bin").write_bytes(b"orig eboot")
    out = tmp_path / "PPSA99999-backport"
    (out / "fakelib").mkdir(parents=True)
    (out / "fakelib/libSceFoo.sprx").write_bytes(b"kit fakelib")       # only in the overlay
    (out / "backport-report.json").write_text(json.dumps({"game": str(game), "mode": mode}))
    return game, out


def test_overlay_falls_back_to_the_game_folder(tmp_path, monkeypatch):
    game, out = _overlay(tmp_path)
    assert klog.game_layers(out) == [out, game]
    assert klog.has_game(out)                        # eboot.bin only in the game behind it
    seen = _spy(monkeypatch)
    t = klog.parse(LOG)
    klog.symbolize(t, out)
    assert set(seen) == {game / "eboot.bin", out / "fakelib/libSceFoo.sprx"}


def test_overlay_file_wins_over_the_game(tmp_path, monkeypatch):
    game, out = _overlay(tmp_path)
    (out / "eboot.bin").write_bytes(b"patched eboot")
    seen = _spy(monkeypatch)
    klog.symbolize(klog.parse(LOG), out)
    assert out / "eboot.bin" in seen and game / "eboot.bin" not in seen


def test_full_build_and_plain_folder_are_used_as_is(tmp_path):
    game, out = _overlay(tmp_path, mode="full")
    assert klog.game_layers(out) == [out]
    assert klog.game_layers(game) == [game]


def test_missing_base_folder_is_reported(tmp_path, monkeypatch):
    game, out = _overlay(tmp_path)
    import shutil
    shutil.rmtree(game)
    _spy(monkeypatch)
    t = klog.parse(LOG)
    klog.symbolize(t, out)
    assert any("missing" in s for s in t.suggestions)
