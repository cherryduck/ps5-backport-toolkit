"""ps5bp command line."""
from __future__ import annotations

import argparse
import json
import sys
import threading
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
          + ("   (fakelib/ present: " + ", ".join(sorted({b.module for b in gs.binaries if b.role == "fakelib"}))
             + ")" if gs.has_fakelib else ""))
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
        major, minor = target
        ps5, ps4 = sdk.target_pair(major, minor)
        todo = gs.needs_downgrade(major, minor)
        print(f"\nTarget FW {sdk.target_str(major, minor)} (SDK {_hex(ps5)} / PS4 {_hex(ps4)}): "
              f"{len(todo)} binar{'y' if len(todo) == 1 else 'ies'} need SDK downgrade")
        for b in todo:
            print(f"  {b.path}  {b.sdk_str()} -> {sdk.fw_str(ps5)}")
    for w in gs.warnings:
        print(f"WARNING: {w}")


STATUS_ORDER = ["missing", "absent", "stubbed", "partial", "unverified", "fakelib", "dump", "system", "game"]


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
        elif m.status == "stubbed":
            kits = sorted({k for n in m.stubbed for k, *_ in m.stub_src.get(n, [])})
            src = f"PLT-stubbed by {', '.join(kits)}: " + " ".join(m.stubbed[:4]) + (" ..." if len(m.stubbed) > 4 else "")
        elif m.status == "dump":
            src = m.note
        elif m.status == "unverified" and m.unproven:
            src = "no evidence for: " + " ".join(m.unproven[:4]) + (" ..." if len(m.unproven) > 4 else "")
        if m.choice and m.note:
            src += f"  ({m.note})"
        elif m.note and m.status != "dump":
            src += f"  ({m.note})"
        if m.conflict:
            src += f"  CONFLICT {len(m.conflict)}: present per one kit, stubbed/absent per another"
        print(f"  {m.module:30} {m.status:8} {len(m.needed):5} {m.proven:6} {len(m.absent):6} "
              f"{len(m.unproven):8}  {src}")
    fl = cov.fakelibs()
    print(f"\n  => {len(fl)} fakelib(s): " + (", ".join(f"{m.module} from {m.choice.kit}" for m in fl) or "none"))
    for d in cov.deps:
        print(f"  dependency: {d}")
    st = [m for m in cov.modules if m.stub_src and not m.choice]
    if st:
        print(f"  {sum(len(m.stub_src) for m in st)} imported NID(s) were PLT-stubbed by kits for this FW "
              "— `--rule kit-stubs` reuses those stubs")
    ab = cov.by_status("absent")
    if ab:
        print(f"  !! {len(ab)} module(s) need NIDs proven absent on {cov.target}.xx and no fakelib can supply them;"
              " the game will fail to resolve them unless patched (see fix rules).")
    if cov.nonsystem_missing:
        print(f"  NOT FOUND (not system, not shipped by game): {', '.join(cov.nonsystem_missing)}")


def _target(s: str) -> tuple[int, int]:
    try:
        return sdk.parse_target(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def _console_fw(s: str) -> str:
    try:
        sdk.fw_major_of_str(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None
    return s.strip()


def _also_targets(s: str) -> list[tuple[int, int]]:
    try:
        return [sdk.parse_target(x) for x in s.split(",") if x.strip()]
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def _replace_dump(a) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for x in getattr(a, "replace_dump_fakelib", []) or []:
        mod, _, kit = x.partition("=")
        out[mod] = kit or None
    return out


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
        from .core.pipeline import describe_ampr
        d = gs.to_dict()
        d["ampr"] = describe_ampr(root)
        json.dump(d, sys.stdout, indent=1)
        print()
    else:
        print_scan(gs, a.target)
        from .core.pipeline import ampr_describe_lines, describe_ampr
        for line in ampr_describe_lines(describe_ampr(root)):
            print(line)
        if a.target and a.console_fw:
            w = sdk.console_warning(a.target[0], a.target[1], a.console_fw)
            print(f"WARNING: {w}" if w else f"console FW {a.console_fw}: declared SDK "
                  f"{sdk.target_str(*a.target)} is close enough, no warning")
        if a.target:
            db = EvidenceDB()
            if db.kits():
                cov = coverage_analyze(gs, db, a.target[0], _replace_dump(a))
                print_coverage(cov, gs)
                from .core.advice import ampr_advice
                for line in ampr_advice(gs, cov):
                    print(f"ADVICE: {line}")
            else:
                print("\n(no kits ingested — `ps5bp kit add` to enable import coverage)")
    return 0


def cmd_build(a) -> int:
    from .core.pipeline import BuildError, BuildOptions, build
    opts = BuildOptions(target=a.target[0], target_minor=a.target[1], replace_dump=_replace_dump(a), stubs_from=list(a.stubs_from), seeds=list(a.seed), seed_plt_fallback=a.seed_plt_fallback, mode=a.mode, out=Path(a.out) if a.out else None, ampr_index=a.ampr_index,
                        fakelibs=not a.no_fakelibs, retarget=not a.no_retarget, force=a.force,
                        strict=a.strict, dry_run=a.dry_run, rules=set(a.rule), no_rules=set(a.no_rule),
                        patches=[Path(x) for x in a.patch], memfix=list(a.memfix),
                        klog=Path(a.klog) if a.klog else None, console_fw=a.console_fw,
                        also_targets=[t for grp in a.also_target for t in grp])
    db = EvidenceDB() if not a.no_fakelibs else None
    try:
        rep = build(Path(a.game), opts, db, log=lambda m: print(f"[ps5bp] {m}", file=sys.stderr))
    except BuildError as e:
        print(f"build failed: {e}", file=sys.stderr)
        return 1
    print(rep.to_text(), end="")
    return 0


def cmd_undo(a) -> int:
    from .core.undo import UndoError, apply_undo, plan_undo
    game = Path(a.game)
    try:
        up = plan_undo(game, [Path(r) for r in a.reports], force=a.force)
    except UndoError as e:
        print(f"undo refused: {e}", file=sys.stderr)
        return 1
    print(f"{up.count} edit(s) to reverse: {len(up.writes)} file(s) rewritten, {len(up.deletes)} removed, "
          f"{len(up.restores)} restored from .orig")
    for rel in sorted(up.writes):
        print(f"  restore {rel}")
    for rel in up.deletes:
        print(f"  delete  {rel}")
    for n in up.notes:
        print(f"  note: {n}")
    if a.dry_run:
        print("dry run — nothing written")
        return 0
    apply_undo(game, up)
    print("done")
    return 0


def cmd_klog(a) -> int:
    from .core import klog
    text = sys.stdin.read() if a.log == "-" else Path(a.log).read_text(errors="replace")
    t = klog.parse(text)
    flags: list[str] = []
    if a.game:
        klog.symbolize(t, Path(a.game))
        flags = scan_game(Path(a.game)).flags
    klog.diagnose(t, flags)
    print(t.to_text(), end="")
    return 0 if t.crashes else 3


def cmd_console(a) -> int:
    from .core import console
    if a.con_cmd == "send":
        try:
            n = console.send_payload(a.host, a.file, a.port)
        except (OSError, ValueError) as e:
            print(f"send failed: {e}", file=sys.stderr)
            return 1
        print(f"sent {n} bytes of {a.file} to {a.host}:{a.port}")
        return 0
    stop = threading.Event()
    lock = threading.Lock()

    def say(msg: str) -> None:
        with lock:
            print(msg, flush=True)

    watcher = None
    if a.con_cmd == "dumps" or a.dumps:
        out = Path(a.out if a.con_cmd == "dumps" else a.dumps)
        watcher = console.CoreDumpWatcher(
            a.host, out, port=a.ftp_port, on_event=lambda m: say(f"[dumps] {m}"),
            on_captured=lambda c: say(f"[dumps] captured {c.folder}: " + ", ".join(p.name for p in c.files)
                                      + ("" if c.complete else "  (incomplete)")))
        watcher.start()
    if a.con_cmd == "dumps":
        try:
            while not stop.wait(0.5):
                pass
        except KeyboardInterrupt:
            pass
        watcher.stop()
        watcher.join(5)
        return 0

    # klog
    logf = open(a.out, "a", buffering=1, encoding="utf-8") if a.out else None
    crash_dir = Path(a.out).resolve().parent if a.out else Path(".")
    flags: list[str] = []
    if a.game:
        flags = scan_game(Path(a.game)).flags
    det = console.CrashDetector()
    crashes = []

    def on_line(ln: str) -> None:
        with lock:
            print(ln, flush=True)
            if logf:
                logf.write(ln + "\n")
        if watcher and console.DUMP_ANNOUNCE.search(ln):
            watcher.wake()
        block = det.feed(ln)
        if block:
            saved = console.save_crash(block, crash_dir)
            say("\n==== crash detected ====\n" + console.triage_text(block, a.game, flags)
                + f"crash block saved to {saved}\n========================")
            crashes.append(saved)
            if a.exit_after_crash:
                stop.set()

    ks = console.KlogStream(a.host, a.port, on_line=on_line, on_status=lambda m: say(f"[klog] {m}"))
    ks.start()
    try:
        while not stop.wait(0.2):
            pass
    except KeyboardInterrupt:
        pass
    ks.stop()
    ks.join(5)
    if watcher:
        watcher.stop()
        watcher.join(5)
    if logf:
        logf.close()
    return 0


def cmd_memfix(a) -> int:
    from .core import memfix
    game = Path(a.game)
    gs = scan_game(game)
    tid = gs.title_id
    if a.from_console:
        from .core import console
        src = console.latest_crash(a.from_console)
        if src is None:
            print(f"no crash-*.txt in {a.from_console}", file=sys.stderr)
            return 2
        print(f"using crash log {src}")
        a.klog = str(src)
    kt = Path(a.klog).read_text(errors="replace") if a.klog else None
    if a.result is not None:
        if a.outcome not in ("works", "crash"):
            print("give the outcome: --result N works|crash", file=sys.stderr)
            return 2
        for line in memfix.record_result(game, tid, a.result, a.outcome == "works", kt):
            print(line)
        return 0
    if a.trials:
        for t in memfix.list_trials(tid):
            print(f"#{t['id']:<3} {t['time']}  FW{t['target']}  {t.get('result') or 'untested':8}  "
                  f"{' '.join(t['choices'])}  -> {t.get('out')}")
        return 0
    sc, sites = memfix.scan(game, a.file, kt)
    if kt and not memfix.crash_frames(kt, a.file):
        print(f"note: the log has no crash frames inside {a.file}", file=sys.stderr)
    shown = sites if a.all else [s for s in sites if s.score > 0] or sites
    print(f"{len(sites)} allocation site(s) in {a.file}" + ("" if a.all else f", {len(shown)} shown (--all for every one)"))
    for n, s in enumerate(shown, 1):
        flags = [x for x, on in (("CRASH PATH", s.on_crash_path), ("fatal", s.fatal)) if on]
        print(f"\n#{n} {s.id}  {s.api}  in fn {s.fn:#x}  score {s.score}" + (f"  [{', '.join(flags)}]" if flags else ""))
        if s.crash_callers:
            print("   crash-path caller(s): " + ", ".join(f"{c:#x}" for c in s.crash_callers))
        print(f"   length ({s.len_reg}): " + " ; ".join(s.len_desc[-4:]))
        print(f"   on failure: {s.fail_desc}")
        if s.hook is not None:
            print(f"   shrink hook {s.hook:#x} on {s.hook_reg}: {'safe' if s.shrink_safe else 'UNSAFE'} — {s.shrink_why}")
        else:
            print(f"   shrink: n/a — {s.shrink_why}")
        if s.page_split:
            ps = s.page_split
            print(f"   page-split: out={ps['out']} page={ps['page']} count={ps['count']} memtype={ps['memtype']}")
        vs = []
        for v in s.variants():
            if v == "shrink":
                vs += [f"{s.id}:shrink:{memfix.fmt_amount(x)}" for x in memfix.AMOUNTS]
            else:
                vs.append(f"{s.id}:{v}")
        print("   try: " + ("  ".join(vs) if vs else "(nothing safe)"))
    print("\nbuild a trial:  ps5bp build GAME --target N --out OUT --memfix SITE:VARIANT[:AMOUNT] [--klog LOG]")
    return 0


def cmd_rules(a) -> int:
    from .core.recipe import builtin
    from .core.rules import registry
    for r in registry().values():
        print(f"{r.name:18} {'on ' if r.default else 'off'}  {r.summary}"
              + (f"  [conflicts: {', '.join(r.conflicts)}]" if r.conflicts else ""))
    rs = builtin()
    if rs:
        print("\nbuilt-in recipes:")
        for r in rs:
            print(f"  {r.rule:12} {r.title_id or '*':10} {r.name}")
    return 0


def cmd_kit(a) -> int:
    db = EvidenceDB()
    if a.kit_cmd == "add":
        r = db.add_kit(a.path, a.fw, a.name, a.source or "", a.replace, a.tested_fw)
        print(f"added kit '{r['name']}' (FW {r['fw']}.xx, {r['title_id'] or 'no title id'}) from {r['root']}")
        print(f"  fakelibs: {', '.join(r['fakelibs'])}")
        if r["extras"]:
            print(f"  extras  : {', '.join(r['extras'])}")
        if r.get("psml_overlay"):
            print("  PSML overlay provider: libScePsml loads /app0/k9.psp and k9.psp is kept (rule psml-overlay)")
        print(f"  evidence: {r['present']} present (at FW {r['present_fw']}), {r['absent']} absent (bound to stubs), "
              f"{r['plt_stubs']} PLT stub(s)")
        if r.get("libc"):
            print(f"  libc    : identity {r['libc']['identity'][:16]}…"
                  + (f" (normalised: {'; '.join(r['libc']['notes'])})" if r['libc']['notes'] else ""))
    elif a.kit_cmd == "reindex":
        res = db.reindex(a.names or None)
        for n, m in res.items():
            print(f"{n:32} {m}")
        if not res:
            print("no kits")
    elif a.kit_cmd == "list":
        for k in db.kits():
            files = [f for f in db.kit_files(k.name) if f.role == "fakelib"]
            tf = f" (tested {k.tested_fw})" if k.tested_fw is not None else ""
            print(f"{k.name:32} FW{k.fw}{tf}  {k.title_id:10} {len(files)} fakelibs  {k.source}")
        if not db.kits():
            print("no kits")
    elif a.kit_cmd == "learn":
        from .core.learn import learn_report
        for line in learn_report(Path(a.original), Path(a.kit), a.recipe, Path(a.out)):
            print(line)
    elif a.kit_cmd == "remove":
        print("removed" if db.remove_kit(a.name) else f"no kit '{a.name}'")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ps5bp", description="PS5 backport toolkit")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze", help="scan a game folder (read-only)")
    an.add_argument("game", help="game root (folder containing eboot.bin and sce_sys/)")
    an.add_argument("--target", type=_target, help="target firmware: 4..13, or major.minor such as 4.03")
    an.add_argument("--console-fw", type=_console_fw, metavar="X.YY",
                    help="firmware of the console you will run on (advice: warns when --target is >=2 majors below)")
    an.add_argument("--replace-dump-fakelib", action="append", default=[], metavar="MODULE[=KIT]",
                    help="use a kit's build instead of the dump's own libSceAmpr / libScePlayGo")
    an.add_argument("--json", action="store_true", help="machine-readable output")
    an.set_defaults(func=cmd_analyze)
    bd = sub.add_parser("build", help="produce a backport")
    bd.add_argument("game")
    bd.add_argument("--target", type=_target, required=True, help="4..13, or major.minor such as 4.03")
    bd.add_argument("--console-fw", type=_console_fw, metavar="X.YY",
                    help="firmware of the console you will run on (advice: warns when --target is >=2 majors below)")
    bd.add_argument("--also-target", type=_also_targets, action="append", default=[], metavar="N[,N...]",
                    help="after the main build, write <out>-fwN siblings that differ only in SDK fields + "
                         "param.json (majors or major.minor, each higher than --target; not with --mode inplace)")
    bd.add_argument("--replace-dump-fakelib", action="append", default=[], metavar="MODULE[=KIT]",
                    help="use a kit's build instead of the dump's own libSceAmpr / libScePlayGo "
                         "(ampr_emu.index is kept or refreshed, see --ampr-index)")
    bd.add_argument("--ampr-index", choices=["auto", "regen", "keep"], default="auto",
                    help="ampr_emu.index of a game that carries the Ampr emulator: auto (default) writes one if "
                         "missing and refreshes a stale one, unless ampr_assets.index packs depend on it; regen "
                         "always rewrites it (refused if that would change the path set of a game with packs, "
                         "unless --force); keep never touches it, only reports staleness")
    bd.add_argument("--out", help="output folder (required unless --mode inplace)")
    bd.add_argument("--mode", choices=["overlay", "full", "inplace"], default="overlay",
                    help="overlay: changed files + fakelib/ only (default); full: whole game, "
                         "unchanged files reflinked/copied; inplace: edit the game folder, keep .orig backups")
    bd.add_argument("--no-fakelibs", action="store_true", help="don't select/install fakelibs")
    bd.add_argument("--no-retarget", action="store_true", help="skip known NID retargets (libc patch)")
    bd.add_argument("--force", action="store_true", help="accept an input whose eboot is already at/below the target SDK, or that already contains ps5bp output files (ledger)")
    bd.add_argument("--strict", action="store_true", help="fail on absent/missing/partial coverage")
    bd.add_argument("--dry-run", action="store_true", help="plan only, write nothing")
    bd.add_argument("--rule", action="append", default=[], metavar="NAME",
                    help="enable a fix rule (repeatable; see `ps5bp rules`)")
    bd.add_argument("--no-rule", action="append", default=[], metavar="NAME", help="disable a fix rule")
    bd.add_argument("--patch", action="append", default=[], metavar="FILE", help="apply a patch recipe (JSON)")
    bd.add_argument("--memfix", action="append", default=[], metavar="SITE:VARIANT[:AMOUNT]",
                    help="generated memory fix (see `ps5bp memfix GAME`); records a trial")
    bd.add_argument("--stubs-from", action="append", default=[], metavar="KIT",
                    help="kit-stubs: use only stubs from this kit (repeatable)")
    bd.add_argument("--seed", action="append", default=[], metavar="NID",
                    help="compat-stubs: seed this contract NID (also the manual-only ones); implies --rule compat-stubs")
    bd.add_argument("--seed-plt-fallback", action="store_true",
                    help="compat-stubs: where a GOT seed is refused, overwrite the PLT entry instead (never silent)")
    bd.add_argument("--klog", help="crash log: page-split hooks only the callers on its crash path")
    mf = sub.add_parser("memfix", help="find failing memory allocations, generate fixes, track console trials")
    mf.add_argument("game")
    mf.add_argument("--klog", help="crash log: ranks sites on the crash path first")
    mf.add_argument("--from-console", metavar="DIR_OR_FILE",
                    help="crash log saved by `ps5bp console klog`: a crash-*.txt, or a folder (newest is used); like --klog")
    mf.add_argument("--file", default="eboot.bin")
    mf.add_argument("--all", action="store_true", help="list every allocation site")
    mf.add_argument("--trials", action="store_true", help="list recorded trials for this title")
    mf.add_argument("--result", type=int, metavar="N", help="record the console result of trial N")
    mf.add_argument("outcome", nargs="?", help="works | crash (with --result)")
    mf.set_defaults(func=cmd_memfix)
    ud = sub.add_parser("undo", help="reverse builds applied to a game folder, using their reports")
    ud.add_argument("game", help="folder the build output was applied to")
    ud.add_argument("reports", nargs="+", help="backport-report.json (or its folder), NEWEST FIRST")
    ud.add_argument("--dry-run", action="store_true")
    ud.add_argument("--force", action="store_true",
                    help="undo even if game files don't match the hashes recorded in the report")
    ud.set_defaults(func=cmd_undo)
    kl = sub.add_parser("klog", help="triage a crash log (klog)")
    kl.add_argument("log", help="klog text file, or - for stdin")
    kl.add_argument("--game", help="game folder the log is from (resolves backtrace calls)")
    kl.set_defaults(func=cmd_klog)
    co = sub.add_parser("console", help="talk to the console: send a payload, live klog, crash-dump capture")
    cs = co.add_subparsers(dest="con_cmd", required=True)
    c1 = cs.add_parser("send", help="send an ELF to the loader (port 9021)")
    c1.add_argument("host", metavar="IP")
    c1.add_argument("file", help="payload .elf (you supply it; never bundled)")
    c1.add_argument("--port", type=int, default=9021)
    c2 = cs.add_parser("klog", help="stream klog (port 3232); triage crashes as they happen")
    c2.add_argument("host", metavar="IP")
    c2.add_argument("--port", type=int, default=3232)
    c2.add_argument("--out", help="append the stream to this file; crash blocks go to crash-<time>.txt beside it")
    c2.add_argument("--game", help="game folder: symbolize the crash backtrace")
    c2.add_argument("--dumps", metavar="DIR", help="also capture crash dumps over FTP into DIR")
    c2.add_argument("--ftp-port", type=int, default=2121)
    c2.add_argument("--exit-after-crash", action="store_true", help="stop after the first detected crash")
    c3 = cs.add_parser("dumps", help="download new crash-dump folders over FTP (port 2121)")
    c3.add_argument("host", metavar="IP")
    c3.add_argument("--out", required=True, metavar="DIR")
    c3.add_argument("--ftp-port", "--port", dest="ftp_port", type=int, default=2121)
    co.set_defaults(func=cmd_console)
    gu = sub.add_parser("gui", help="open the graphical interface")
    gu.set_defaults(func=lambda a: __import__("ps5bp.gui", fromlist=["main"]).main())
    rl = sub.add_parser("rules", help="list fix rules")
    rl.set_defaults(func=cmd_rules)
    bd.set_defaults(func=cmd_build)
    kit = sub.add_parser("kit", help="manage the fakelib kit library / evidence DB")
    ks = kit.add_subparsers(dest="kit_cmd", required=True)
    ka = ks.add_parser("add", help="ingest a backport kit (folder or .zip)")
    ka.add_argument("path")
    ka.add_argument("--fw", type=int, required=True, help="firmware major the kit targets")
    ka.add_argument("--name")
    ka.add_argument("--source", help="free text, e.g. DLPS / PSVIETHOA")
    ka.add_argument("--replace", action="store_true")
    ka.add_argument("--tested-fw", type=int, help="firmware the kit was actually run on, if not --fw "
                    "(its 'present' evidence is then recorded for that FW)")
    kx = ks.add_parser("reindex", help="recompute the libc cross-check records from the stored kit data")
    kx.add_argument("names", nargs="*", help="kit names (default: all)")
    kn = ks.add_parser("learn", help="explain a kit's edits; list the ones no generic rule covers")
    kn.add_argument("original", help="the original (un-backported) game dump")
    kn.add_argument("kit", help="the backport kit folder for the same game version")
    kn.add_argument("--recipe", action="store_true", help="also write the unexplained edits as a per-game recipe")
    kn.add_argument("--out", default=".", help="where to write the recipe JSON (default: .)")
    ks.add_parser("list")
    kr = ks.add_parser("remove")
    kr.add_argument("name")
    kit.set_defaults(func=cmd_kit)
    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
