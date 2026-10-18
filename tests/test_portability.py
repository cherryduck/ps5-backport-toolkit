"""Portability: data folder per OS, copy fallback without fcntl, POSIX relative paths, CLI output encoding."""
import builtins
import io
import os
import sys

import pytest

from ps5bp.core import evidence, ledger, pipeline
from ps5bp.core.scan import scan_binary
from synth import Spec, build_elf, build_self


def test_home_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "x"))
    assert evidence.home() == tmp_path / "x"


@pytest.mark.skipif(os.name != "nt", reason="Windows data folder")
def test_home_windows(monkeypatch, tmp_path):
    monkeypatch.delenv("PS5BP_HOME", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert evidence.home() == tmp_path / "ps5bp"


@pytest.mark.skipif(os.name == "nt", reason="XDG data folder")
def test_home_xdg(monkeypatch, tmp_path):
    monkeypatch.delenv("PS5BP_HOME", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert evidence.home() == tmp_path / "ps5bp"
    monkeypatch.setenv("XDG_DATA_HOME", "")            # empty counts as unset (XDG spec)
    assert evidence.home() == evidence.Path.home() / ".local/share/ps5bp"


def test_clone_file_without_fcntl(monkeypatch, tmp_path):
    real_import = builtins.__import__

    def no_fcntl(name, *a, **kw):
        if name == "fcntl":
            raise ImportError("no fcntl here")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_fcntl)
    src = tmp_path / "a.bin"
    src.write_bytes(b"data")
    assert pipeline.clone_file(src, tmp_path / "sub" / "b.bin") == "copy"
    assert (tmp_path / "sub" / "b.bin").read_bytes() == b"data"


def test_relative_paths_are_posix(tmp_path):
    root = tmp_path / "game"
    p = root / "sce_module" / "deep" / "libfoo.prx"
    p.parent.mkdir(parents=True)
    elf, _ = build_elf(Spec(kind="module", module="libfoo", import_libs=["libkernel"], imports=[("4h6F1LLbTiw", 0)]))
    p.write_bytes(build_self(elf))
    assert scan_binary(p, root, "module").path == "sce_module/deep/libfoo.prx"


def test_resolve_member_is_posix(tmp_path):
    (tmp_path / "Sce_Module").mkdir()
    (tmp_path / "Sce_Module" / "LibC.prx").write_bytes(b"")
    assert ledger.resolve_member(tmp_path, "sce_module/libc.prx") in ("Sce_Module/LibC.prx", "sce_module/libc.prx")
    assert "\\" not in ledger.resolve_member(tmp_path, "missing/dir/file.prx")


def test_cli_output_survives_non_utf8_stdout(monkeypatch):
    """Windows pipes default to the ANSI code page; ★ / → / — must not raise UnicodeEncodeError."""
    from ps5bp import cli
    out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert out.encoding.lower() == "utf-8"
