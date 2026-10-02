"""ps5bp command line."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import sdk
from .core.coverage import Coverage, analyze as coverage_analyze
from .core.evidence import EvidenceDB
from .core.nid import name_of as nidname
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


STATUS_ORDER = ["missing", "absent", "partial", "unverified", "fakelib", "system", "game"]


def print_coverage(cov: Coverage, gs: GameScan) -> None:
    print(f"\nImport coverage for FW {cov.target}.xx  (per module the game imports from)")
    print(f"  {'module':30} {'status':8} {'NIDs':>5} {'proven':>6} {'absent':>6} {'unproven':>8}  source")
    mods = sorted(cov.modules, key=lambda m: (STATUS_ORDER.index(m.status), m.module))
    for m in mods:
        src = ""
        if m.choice:
            c = m.choice
            src = f"{c.kit} (FW{c.kit_fw}) {c.relpath}"
            if c.missing:
                src += f"  MISSING {len(c.missing)}: {' '.join(c.missing[:4])}"
            if m.current:
                src += "  [same as current]" if m.current == c.sha256 else "  [differs from current]"
        elif m.status == "absent":
            src = "PROVEN ABSENT on target: " + " ".join(f"{n} {nidname(n)}".strip() for n in m.absent[:4])
        elif m.status == "unverified" and m.unproven:
            src = "no evidence for: " + " ".join(m.unproven[:4]) + (" ..." if len(m.unproven) > 4 else "")
        print(f"  {m.module:30} {m.status:8} {len(m.needed):5} {m.proven:6} {len(m.absent):6} "
              f"{len(m.unproven):8}  {src}")
    fl = cov.fakelibs()
    print(f"\n  => {len(fl)} fakelib(s): " + (", ".join(f"{m.module} from {m.choice.kit}" for m in fl) or "none"))
    for d in cov.deps:
        print(f"  dependency: {d}")
    ab = cov.by_status("absent")
    if ab:
        print(f"  !! {len(ab)} module(s) need NIDs proven absent on {cov.target}.xx and no fakelib can supply them;"
              " the game will fail to resolve them unless patched (see fix rules).")
    if cov.nonsystem_missing:
        print(f"  NOT FOUND (not system, not shipped by game): {', '.join(cov.nonsystem_missing)}")


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
        if a.target:
            db = EvidenceDB()
            if db.kits():
                print_coverage(coverage_analyze(gs, db, a.target), gs)
            else:
                print("\n(no kits ingested — `ps5bp kit add` to enable import coverage)")
    return 0


def cmd_build(a) -> int:
    from .core.pipeline import BuildError, BuildOptions, build
    opts = BuildOptions(target=a.target, mode=a.mode, out=Path(a.out) if a.out else None,
                        fakelibs=not a.no_fakelibs, retarget=not a.no_retarget, force=a.force,
                        strict=a.strict, dry_run=a.dry_run)
    db = EvidenceDB() if not a.no_fakelibs else None
    try:
        rep = build(Path(a.game), opts, db, log=lambda m: print(f"[ps5bp] {m}", file=sys.stderr))
    except BuildError as e:
        print(f"build failed: {e}", file=sys.stderr)
        return 1
    print(rep.to_text(), end="")
    return 0


def cmd_kit(a) -> int:
    db = EvidenceDB()
    if a.kit_cmd == "add":
        r = db.add_kit(a.path, a.fw, a.name, a.source or "", a.replace)
        print(f"added kit '{r['name']}' (FW {r['fw']}.xx, {r['title_id'] or 'no title id'}) from {r['root']}")
        print(f"  fakelibs: {', '.join(r['fakelibs'])}")
        if r["extras"]:
            print(f"  extras  : {', '.join(r['extras'])}")
        print(f"  evidence: {r['present']} present, {r['absent']} absent (stubbed) NID records")
    elif a.kit_cmd == "list":
        for k in db.kits():
            files = [f for f in db.kit_files(k.name) if f.role == "fakelib"]
            print(f"{k.name:32} FW{k.fw}  {k.title_id:10} {len(files)} fakelibs  {k.source}")
        if not db.kits():
            print("no kits")
    elif a.kit_cmd == "remove":
        print("removed" if db.remove_kit(a.name) else f"no kit '{a.name}'")
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
    bd = sub.add_parser("build", help="produce a backport")
    bd.add_argument("game")
    bd.add_argument("--target", type=int, required=True, choices=sdk.SUPPORTED_TARGETS)
    bd.add_argument("--out", help="output folder (required unless --mode inplace)")
    bd.add_argument("--mode", choices=["overlay", "full", "inplace"], default="overlay",
                    help="overlay: changed files + fakelib/ only (default); full: whole game, "
                         "unchanged files reflinked/copied; inplace: edit the game folder, keep .orig backups")
    bd.add_argument("--no-fakelibs", action="store_true", help="don't select/install fakelibs")
    bd.add_argument("--no-retarget", action="store_true", help="skip known NID retargets (libc patch)")
    bd.add_argument("--force", action="store_true", help="accept an input that already has fakelib/")
    bd.add_argument("--strict", action="store_true", help="fail on absent/missing/partial coverage")
    bd.add_argument("--dry-run", action="store_true", help="plan only, write nothing")
    bd.set_defaults(func=cmd_build)
    kit = sub.add_parser("kit", help="manage the fakelib kit library / evidence DB")
    ks = kit.add_subparsers(dest="kit_cmd", required=True)
    ka = ks.add_parser("add", help="ingest a backport kit (folder or .zip)")
    ka.add_argument("path")
    ka.add_argument("--fw", type=int, required=True, help="firmware major the kit targets")
    ka.add_argument("--name")
    ka.add_argument("--source", help="free text, e.g. DLPS / PSVIETHOA")
    ka.add_argument("--replace", action="store_true")
    ks.add_parser("list")
    kr = ks.add_parser("remove")
    kr.add_argument("name")
    kit.set_defaults(func=cmd_kit)
    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
