# ps5bp — PS5 backport toolkit (Linux)

Point it at a decrypted PS5 game dump (fake-signed SELFs, e.g. from ps5-app-dumper)
and it builds a backport for firmware 4.xx–7.xx: SDK downgrade, `param.json`,
automatically chosen fakelibs, and optional fixes for known problems (PS5 Pro / PSSR).
When a backport crashes, `ps5bp klog` reads the console's crash log and tells you why.

Command line and PyQt6 GUI; the GUI is a thin layer over the same core.

## Install

```
pipx install '/path/to/ps5-backporter[gui]'       # ps5bp + ps5bp-gui on PATH
scripts/install-desktop.sh                         # optional: app-menu entry
```

Standalone bundle (no Python needed on the target machine):

```
scripts/build-bundle.sh                            # -> dist/ps5bp/{ps5bp,ps5bp-gui}
scripts/install-desktop.sh dist/ps5bp/ps5bp-gui
```

Development: `python -m venv .venv && .venv/bin/pip install -e '.[gui,dev]'`.

## Typical session

```
ps5bp kit add "DLPS-FW4xx-PPSA11386.zip" --fw 4 --name dlps-PPSA11386 --source DLPS
ps5bp kit add "PSVIETHOA-PPSA11386_FW6xx.zip" --fw 6 --name psviethoa-PPSA11386
ps5bp analyze /games/PPSA12345 --target 4          # what's needed, what's missing, which rules apply
ps5bp build   /games/PPSA12345 --target 4 --out /games/PPSA12345-fw4 [--rule ...]
# ...package + install, it crashes, capture klog...
ps5bp klog crash.txt --game /games/PPSA12345-fw4
```

Or `ps5bp-gui`: game folder → **Analyze** → tick rules → **Build backport**; the
Crash log tab does the klog triage.

## Kits and import coverage

A kit is an existing backport's files (folder or zip), labelled with the firmware its
author targeted. Its fakelibs are stored under `~/.local/share/ps5bp/kits/` (eboots
are not kept; `PS5BP_HOME` overrides the location) and it contributes evidence:

* every import its binaries make to the system      => that NID exists on that FW (and later FWs) —
  weak evidence, so `--tested-fw N` records it at the FW the kit was actually run on
* every import a backporter bound to a local stub    => that NID is absent on that FW (and earlier)
* every PLT entry a backporter overwrote in place    => a stub for that NID, with its exact code,
  reusable for other games (`--rule kit-stubs`); such imports never count as present

```
ps5bp kit add "ACE COMBAT 8 backport" --fw 4 --tested-fw 10    # built for 4.03, only run on 10.01
```

Ampr / PlayGo fakelibs are emulation layers that newer games need to load at all,
whatever the FW: in kits they are stored but give no FW evidence; in a dump they are
kept (status `dump`). Any other fakelib a dump ships is replaced by the kit-selected one.

`analyze --target N` classifies each module the game imports from as
`game` / `system` / `fakelib` / `dump` / `partial` / `absent` / `stubbed` / `unverified` /
`missing` (`stubbed`: a kit replaced some of its NIDs with PLT stubs for this FW; evidence
where one kit imports a NID and another stubs it is shown as CONFLICT, not as proof), picks
the best fakelib per module, and repairs cross-fakelib pairs (libSceAgc +
libSceAgcDriver must come from the same build). `unverified` means "no evidence yet",
not "broken" — it shrinks as kits are added. It also reports, per binary, format, SDK,
needed libraries and detected features (PS5 Pro path, PSSR/MFSR, PSSR 2 model, AudioOut2).

## Build

```
ps5bp build GAME --target 4 --out OUT              # overlay (default): changed files + fakelib/
ps5bp build GAME --target 4 --out OUT --mode full  # whole game, unchanged files reflinked/copied
ps5bp build GAME --target 4 --mode inplace         # edits GAME, keeps *.orig
ps5bp build ... --dry-run                          # plan only
ps5bp build GAME --target 4.03 --out OUT           # minor version: SDK 0x04030031, param 0x0403...
ps5bp build GAME ... --replace-dump-fakelib libSceAmpr[=KIT]   # swap the dump's Ampr emulator
```

Targets are 4..13 (`--target 11` etc.; SDK pairs 11-13 are not yet checked against a real binary).

```
ps5bp build GAME --target 4 --out OUT --console-fw 11.60       # advice: warns when the SDK trails the console
ps5bp build GAME --target 4 --out OUT --also-target 5,11       # + siblings OUT-fw5, OUT-fw11
```

`--console-fw X.YY` (also on `analyze`, and a remembered GUI field) only warns: with the
declared SDK 2+ majors below the console FW there is a reported black-screen / GPU-hang
risk at FW5+ with SDK-4 builds (Mortal Shell II, Minecraft Dungeons II on 9.00; STAR WARS
Galactic Racer on Pro 11.20 — fixed by SDK pair 5 builds). The warning is also in the report.
`--also-target` (majors or major.minor, each higher than `--target`; refused with `--mode
inplace`) writes, after the main build verified, `<out>-fwN` copies that differ **only** in
the SDK u32 pair of each binary and `param.json` sdkVersion / requiredSystemSoftwareVersion
(every file is diffed against the main output; any other byte deletes the sibling and fails).
Same fakelibs and rules as the main build; a plain `--target N` re-plans from scratch instead.
Overlay siblings get their own `<out>-fwN.originals`, so `ps5bp undo GAME OUT-fwN` works.

An input is "already backported" (needs `--force`) when its eboot's SDK is already at or
below the target — a `fakelib/` folder alone (dumps ship Ampr/PlayGo layers) doesn't count.
When the Ampr emulator is replaced, its `ampr_emu.index` is dropped (full), moved to
`.orig` (inplace) or listed for deletion (overlay).

SDK downgrade of every binary newer than the target (eboot, prx, sprx, chosen fakelibs),
known NID retargets (`ps5bp/data/nid_retarget.txt`), `param.json` sdkVersion /
requiredSystemSoftwareVersion (byte-exact, formatting kept), fakelib install, then the
enabled fix rules. SELFs are patched in place — no re-signing. Every output binary is
re-parsed and diffed against its input; a byte changed outside a recorded edit fails the
build. `backport-report.json/.txt` lists every edit. Packaging (sce_sys, PKG) is up to you.

**SELF digest.** A fake-signed SELF carries a 32-byte digest in its EX_INFO block (right after the
ELF header + program headers; `Binary.ex_info()`). It depends on the file content, but its algorithm
cannot be recovered from the SELF (it is not SHA-256 of any file range, segment subset or ELF image
rebuilt from the SELF — the original ELF has data the SELF does not keep), so ps5bp cannot recompute it
and leaves it as the input had it. That is deliberate and verified: the build checks that nothing
outside a recorded edit changes, so the digest stays stale after any edit — SDK downgrades included,
and ps5bp builds boot on a console (ACE COMBAT 8, 4.00 SDK build on a Pro 11.60), so the loader
does not enforce it. Community libc builds differ from a ps5bp-edited baseline libc in exactly those 32
bytes (plus heap-flag bytes where they patched them). If a signing flow elsewhere checks the digest,
re-sign the output there.

## Fix rules

```
ps5bp rules                                        # list rules + built-in recipes
ps5bp build GAME --target 4 --out OUT --rule pro-disable
ps5bp build GAME --target 4 --out OUT --rule pssr-memory
ps5bp build GAME --target 4 --out OUT --patch my-fix.json
ps5bp build GAME --target 4 --out OUT --rule compat-stubs --seed obuxdTiwkF8   # + a manual contract
```

Every rule is off by default; `build` / the GUI say which are recommended and why.

| rule | what it does |
|---|---|
| `pro-disable` | Pro hardware query (`NH6xARDOVv8`) -> base PS5 (both outputs 0, as DLPS's stub), `sceKernelIsTrinityMode` -> 0. The PLT entry becomes the stub; if the NID is proven absent on the target the import is bound locally. |
| `pssr-memory` | Keep Pro/PSSR, fit its startup allocations. Per-game recipes in `ps5bp/data/recipes/` (Wolverine 01.001.005 included — reproduces the DLPS FW4 eboot byte for byte). Conflicts with `pro-disable`. |
| `kit-stubs` | Every import some kit PLT-stubbed for this FW gets the same stub, in every game binary (eboot, prx, sprx); `--stubs-from KIT` limits the sources. Pro NIDs are left to pro-disable / pssr-memory when those are on. |
| `compat-stubs` | **GOT-seed** stubs from a per-NID contract table (`ps5bp/data/stub_contracts.json`): for imports the target FW lacks, a ≤15-byte stub goes into an int3 run (or a grown segment end) and the import's lazy GOT slot (`PLT+6`) is pointed at it. PLT entry, import symbol and relocation stay, so a firmware that exports the NID binds natively and the same build works on old and new FW. Contracts: OperationMode (`*rdi=2,*rsi=0`), IsTrinityMode, `scePadIsRemoteController` (writes the out-bool), VRR peg/unpeg, VRR status init/register/unregister (only if every caller ignores or error-checks the result), `GetVrrStatus` (zero-fills 0x40 bytes — only if every caller owns an initialised ≥0x40 frame buffer), WQHD, VideoOut latency ×2, `sceSaveDataConvert` (0x809F0008), Coredump user string, SharePlay prohibit, Np trials flag, Acm priority, write-throttling query (0x80020003; only if every caller compares it), libc thread-exit purge (libc.prx only), `sceAudioOut2Set3DLatency` below 6.00. Seeded when coverage proves the NID absent on the target, else when the declared SDK is below the table's first-exported lead. Status per site: PATCH / DONE / UNKNOWN (refused, reason shown — never silently falls back). `--seed NID` forces a contract (the only way for the manual ones: NetCtl link-down, Ambisonics coefficients); `--seed-plt-fallback` allows a PLT overwrite where a GOT seed is refused. Skips NIDs owned by an enabled `pro-disable` / `pssr-memory` / `kit-stubs`. Never recommended yet (no console result recorded). |
| `set3-nonfatal` | Targets 6–9 only: `sceAudioOut2Set3DLatency` exists but rejects mode>1 (0x80268001), which Wwise treats as fatal (no sound). At every call `call; test eax,eax; je X` → `jmp X`. All callers must have exactly that shape, else nothing is patched. Untested on 6–9 hardware. |
| `mapflex-flags` | Clear flag `0x8000` at libc's calls of the retargeted `sceKernelMapFlexibleMemory` (DLPS's AC8 fix; their older 11386 build kept it). |
| `savedata-mount` | `sceSaveDataMount3` param qword +0x18 (systemBlocks) = -1 -> 0. Finds the request through register alias chains and local wrapper functions (the request is the wrapper's argument: its callers are analysed), needs a non-zero store to the blocks field (+0x10) and an `ff ff ff ff`-ending encoding, refuses anything ambiguous. For Unity `SaveData.prx` plugins it also turns the 16-byte vector copy of blocks+systemBlocks into the 8-byte copy (rbx / r14 / r15 forms; the request must have been zeroed first, exactly one copy in the file). Fixes CE-107098-5 when saving on 4.xx (console-confirmed on ACE COMBAT 8). Recommended from kit evidence: DLPS FW4 kits set it to 0 (AC8, PPSA11386), PSVIETHOA's FW6 PPSA11386 kept -1. |
| `wwise-71` | Wwise `AkChannelConfig` 7.1.4 (12 ch) -> 7.1 where the game requests it (lookup tables left alone). Recommended on 4.xx: console-tested on ACE COMBAT 8 — no sound without it, sound with it (DLPS's FW4 PPSA11386 kit kept 7.1.4; console tests beat kit observations). |
| `gamepresets-28` | `sceUserServiceGetGamePresets` request size `0x30 -> 0x28` (imm32 of the size store, incl. the form where a helper initialises the request: its memset length is left alone). 4.xx rejects the 0x30 request with 0x80960005. Already `0x28` -> DONE; anything else -> UNKNOWN, refused. Recommended for a declared 4.xx target (observed working on 4.03/4.50 in community FW4 backports). |
| `tls-atexit` | libc `__cxa_thread_atexit` is `push rbp; mov rbp,rsp; call PLT(qBS714-Jr3g); pop rbp; ret` where the import exists only from 11.00; the call is retargeted to libc's own `__cxa_atexit` (destructors then run at process exit). Generic: needs both exports and exactly that body. Recommended for a declared target below 11. Validated on three libc builds of community FW4 backports. |
| `savedata-prepare` | `sceSaveDataPrepare` request mode (dword +4) 2 -> 0, or 3 -> 0 when the request was vector-zeroed first; exactly one store per call, a mode copied from elsewhere is left alone. Not recommended automatically. |
| `savedata-dirsearch` | 4.xx only: `sceSaveDataDirNameSearch2` imported without `DirNameSearch` -> the import is renamed to `DirNameSearch`; both imported -> the lazy GOT slot of Search2 is pointed at Search's PLT stub. A lead from community backports, not console-proved: never recommended automatically. |
| `frostbite-8ch` | EA/Frostbite AudioOut2 12 -> 8 channels (`mov r9d,0x30c -> 0x208`, the 0xC00 format store, the channel count) in the three layouts known from community FW4 backports; every anchor must match a layout completely or the binary is refused. Recommended for a declared 4.xx target. |
| `stub-absent` | Every other import proven absent on the target -> `return 0`, bound locally. Blunt. |
| `user-patch` | Apply recipe files (`--patch`). |

### Patch recipes

JSON, verifiable and shareable — format in the docstring of `ps5bp/core/recipe.py`. A
recipe lists byte signatures that must match (so it refuses the wrong game version or an
already-patched file), code caves appended to a segment (hex + `rel32`/`rel8`/`rip`
fixups; `nid:XXXX` = an import's PLT stub, `@label` = cave label), call retargets with
their expected old targets, and plain old->new byte edits.

## Kits are evidence, not prerequisites

ps5bp is meant for games nobody has backported. Every fix learned from a kit becomes a
generic rule with its own detector, and `kit add` records, per rule, whether each kit
shows the pattern fixed or unfixed — that is where the "recommended on 4.xx" stars come
from (the PPSA11386 kits make savedata-mount recommended for ACE COMBAT 8).

```
ps5bp kit learn ORIGINAL_DUMP KIT            # explain every change a kit made
```

Sorts each changed byte: SDK fields, import renames, PLT stubs, the libc flag, the
SaveData field and Wwise configs are all reproduced by generic handling. Anything left is
printed as a candidate for a new rule (`--recipe --out DIR` writes it as a per-game recipe,
a last resort). For DLPS's ACE COMBAT 8 4.03 build nothing is left: with `kit-stubs`,
`mapflex-flags`, `savedata-mount` and `wwise-71` the build reproduces all 58 game binaries,
`param.json` and DLPS's fakelib set byte for byte (ELF payload; their re-signer also
zeroes e_shnum — and their unused libScePsml isn't shipped).

## Rebuilding

Building again into the same output folder replaces the earlier build (the GUI asks
first); any other non-empty folder is refused. `<out>.originals/` is never deleted: if
an earlier overlay was copied over the game, it holds the only untouched copies.

Safety: every file ps5bp writes is hashed into a per-user ledger (`$PS5BP_HOME/applied.json`,
next to the kits). A build hashes the game's binaries, `param.json` and `fakelib/*` first and
refuses (`--force` overrides) if any is a known ps5bp output, i.e. an earlier overlay was copied over
the game and those files are not originals. A corrupt ledger is kept as `applied.json.bak` and
restarted. `--dry-run` records nothing. The input hashes go into `backport-report.json`.

## Undo

Overlay builds save the game's copy of every file they replace to `<out>.originals/`
(beside the output, so it isn't copied into the game). If an overlay was copied over the
game, `ps5bp undo GAME OUT [OLDER_OUT ...]` (newest first) restores it — from the saved
originals, or, for builds without them, by reversing every edit in the reports.
Before restoring, `undo` checks that every file it overwrites still has the build's output hash
and that the result has the recorded input hash; otherwise it refuses (`--force` overrides). Reports
written before this check have no hashes and undo as before. Game paths are matched
case-insensitively if the exact path is missing (an ambiguous match is an error).

## Memory fixes (`memfix`)

For games that exit on a failed startup allocation (typical for Pro/PSSR titles on low FW),
`memfix` finds the allocation, generates a fix and keeps track of what you tried on the console.

```
ps5bp memfix GAME --klog crash.txt                 # ranked allocation sites, crash path first
ps5bp build GAME --target 4 --out OUT --memfix 3d77bbc:page-split --memfix 4171888:shrink:128M --klog crash.txt
# install OUT, boot it ...
ps5bp memfix GAME --result 1 works                 # saved as a recipe; pssr-memory offers it from now on
ps5bp memfix GAME --result 1 crash --klog new.txt  # did the failure move? suggests the next step
ps5bp memfix GAME --trials
```

For each direct-memory allocation (known APIs, plus library wrappers recognised by taking
`sceKernelGetDirectMemorySize` as their search end) the scan traces how the length was
computed, whether failure is fatal, and which fixes apply:

| fix | what the generated cave does | offered when |
|---|---|---|
| `shrink[:AMOUNT]` | at the first call after the length is computed, requests >= 2 x AMOUNT lose AMOUNT (128M/256M/512M) | the length sits in a callee-saved register and no other copy of its inputs is used afterwards (otherwise the game would assume the original size: marked unsafe) |
| `page-split` | the allocation becomes a loop of 2 MB direct-memory pages filling the game's page array; other page sizes fall through to the original | the function has the page-array shape (len = count x page, one address stored per page). With a klog only the callers on the crash path are hooked |
| `retry-align` | if the allocation fails, retry once with 64 KB alignment (same size) | AllocateDirectMemory-style calls |

Generated recipes locate their patch points by wildcarded byte signatures rather than fixed
addresses, so a confirmed fix can carry over to another build of the game. Whether a fix
is *right* is only known from a console boot — the tool records trials, it does not
claim success. On the Wolverine 11.60 crash log, `shrink:128M` on the Ampr pool plus
`page-split` on the PSSR allocator (picked from the backtrace) regenerates DLPS's FW4 eboot
byte for byte.

## Crash-log triage

```
ps5bp klog crash.txt [--game GAME]                 # or: ... | ps5bp klog -
```

Finds the fatal-signal block, maps backtrace frames and `rip` to modules, filters the
usual noise (fake-signed mount, missing save, offline PSN errors, kstuff), and with
`--game` disassembles the call at each `/app0/` frame — e.g. for Wolverine on 11.60 it
lands on the startup allocator calling `sceKernelAllocateDirectMemory` before `exit()`
and suggests `pssr-memory` / `pro-disable`.

## Console (live log, crash dumps)

Talks to a console that runs your own payloads (elfldr / klogsrv / ftpsrv; none are
bundled, `*.elf` is gitignored). Pure standard library networking; the GUI has a
**Console** tab with the same features (IP is remembered).

```
ps5bp console send 192.168.1.50 klogsrv.elf              # raw ELF to the loader, TCP 9021 (--port)
ps5bp console klog 192.168.1.50 --out log.txt --game GAME --dumps dumps/
ps5bp console dumps 192.168.1.50 --out dumps/            # crash dumps only (FTP 2121)
ps5bp memfix GAME --result 1 crash --from-console dumps/ # newest crash-*.txt in the folder (or a file)
```

- `klog` streams klogsrv (TCP 3232) to stdout and `--out`, reconnecting when the console
  drops. When a fatal-signal block for an `/app0/` process completes, it runs the normal
  klog triage (symbolized with `--game`), prints the diagnosis and saves the block as
  `crash-<time>.txt` beside `--out` (or in `--dumps`/the current folder). Ctrl-C stops.
- Crash dumps: the console writes `/user/devlog/system/sce_coredumps.0/<TITLEID>_<n>/`
  (`report.log` first, the `.prosperodmp` later) and deletes it when the crash screen
  closes, so the watcher polls ftpsrv (LIST only, passive mode) and copies every **new**
  folder immediately (folders that existed at start are ignored; downloads go to
  `.partial` then rename; it waits up to 120 s for the core, and keeps what it has if the
  folder vanishes). The klog line `[CRS][coredump_seq] prepare() ... path=...` wakes it at once.
  Start the watcher *before* launching the game.
- `memfix --from-console` is `--klog` taking the file the console command saved.
- The GUI tab remembers the IP, payload paths and dump folder (QSettings); the CLI takes
  them as arguments. Extra option: `klog --exit-after-crash`.

## Tests

```
.venv/bin/pytest                                   # synthetic binaries/logs, no game data needed
PS5BP_FIXTURES=~/ps5bp-fixtures .venv/bin/pytest   # + real-folder tests (tests/test_fixtures.py)
```

No console binaries, game data, kits or logs are included or may be committed.

## Credits / prior art

Format knowledge is public and was re-derived independently: SELF/ELF layout,
PT_SCE_PROCPARAM SDK fields (idlesauce's SDK downgrade script), fakelib sideloading
(BestPig's BackPork). The Wolverine PSSR memory recipe encodes the technique of the
DLPS FW4 backport. No code from those projects is used.
