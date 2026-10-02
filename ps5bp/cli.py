"""ps5bp command line."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import sdk
from .core.paramjson import fw64_str
from .core.scan import FLAGS, GameScan, scan_game


def _hex(v: int | None) -> str:
    return f"{v:#010x}" if v is not None else "-"


def print_scan(gs: GameScan, target: int | None) -> None:
    print(f"Game      : {gs.title or '?'}  [{gs.title_id or '?'}]  v{gs.content_version or '?'}")
    print(f"Folder    : {gs.root}")
    print(f"param.json: sdk {fw64_str(gs.param_sdk)}  requiredSystemSoftware {fw64_str(gs.param_required_fw)}")
    ms = gs.max_sdk()
    print(f"Built SDK : {sdk.fw_str(ms) if ms else '?'}"
          + ("   (already backported: fakelib/ present)" if gs.has_fakelib else ""))
    print()
    print(f"{'binary':44} {'kind':5} {'SDK':>5} {'imports':>7} {'exports':>7}  flags")
    for b in gs.binaries:
        flags = ",".join(b.flags) or ("ERROR " + b.error if b.error else "")
        print(f"{b.path[:44]:44} {b.kind:5} {b.sdk_str():>5} {b.n_imports:>7} {b.n_exports:>7}  {flags}")
    eb = gs.eboot
    if eb:
        print(f"\neboot needs {len(eb.needed)} libraries; imports from {len(eb.import_libs)} libs:")
        for lib, nids in sorted(eb.imports_by_lib.items(), key=lambda kv: -len(kv[1])):
            print(f"  {lib:36} v{eb.import_libs.get(lib, '?'):6} {len(nids):5} NIDs")
    if gs.extra_files:
        print(f"\nBackport extras present: {', '.join(gs.extra_files)}")
    if gs.flags:
        print("\nDetected:")
        for f in gs.flags:
            print(f"  [{f}] {FLAGS.get(f, '')}")
    if target:
        ps5, ps4 = sdk.SDK_PAIRS[target]
        todo = gs.needs_downgrade(target)
        print(f"\nTarget FW {target}.xx (SDK {_hex(ps5)} / PS4 {_hex(ps4)}): "
              f"{len(todo)} binar{'y' if len(todo) == 1 else 'ies'} need SDK downgrade")
        for b in todo:
            print(f"  {b.path}  {b.sdk_str()} -> {sdk.fw_str(ps5)}")
    for w in gs.warnings:
        print(f"WARNING: {w}")


def cmd_analyze(a) -> int:
    root = Path(a.game)
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    def prog(i, n, name):
        if not a.json and sys.stderr.isatty():
            print(f"\r[{i + 1}/{n}] {name[:60]:60}", end="", file=sys.stderr, flush=True)
    gs = scan_game(root, progress=prog)
    if not a.json and sys.stderr.isatty():
        print("\r" + " " * 72 + "\r", end="", file=sys.stderr)
    if a.json:
        json.dump(gs.to_dict(), sys.stdout, indent=1)
        print()
    else:
        print_scan(gs, a.target)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ps5bp", description="PS5 backport toolkit")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze", help="scan a game folder (read-only)")
    an.add_argument("game", help="game root (folder containing eboot.bin and sce_sys/)")
    an.add_argument("--target", type=int, choices=sdk.SUPPORTED_TARGETS, help="target firmware major")
    an.add_argument("--json", action="store_true", help="machine-readable output")
    an.set_defaults(func=cmd_analyze)
    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
