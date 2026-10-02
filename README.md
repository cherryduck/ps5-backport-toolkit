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

* every import its binaries resolve from the system => that NID exists on that FW (and later FWs)
* every import a backporter bound to a local stub    => that NID is absent on that FW (and earlier)

`analyze --target N` classifies each module the game imports from as
`game` / `system` / `fakelib` / `partial` / `absent` / `unverified` / `missing`, picks
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
```

SDK downgrade of every binary newer than the target (eboot, prx, sprx, chosen fakelibs),
known NID retargets (`ps5bp/data/nid_retarget.txt`), `param.json` sdkVersion /
requiredSystemSoftwareVersion (byte-exact, formatting kept), fakelib install, then the
enabled fix rules. SELFs are patched in place — no re-signing. Every output binary is
re-parsed and diffed against its input; a byte changed outside a recorded edit fails the
build. `backport-report.json/.txt` lists every edit. Packaging (sce_sys, PKG) is up to you.

## Fix rules

```
ps5bp rules                                        # list rules + built-in recipes
ps5bp build GAME --target 4 --out OUT --rule pro-disable
ps5bp build GAME --target 4 --out OUT --rule pssr-memory
ps5bp build GAME --target 4 --out OUT --patch my-fix.json
```

Every rule is off by default; `build` / the GUI say which are recommended and why.

| rule | what it does |
|---|---|
| `pro-disable` | Pro hardware query (`NH6xARDOVv8`) -> base PS5 (both outputs 0, as DLPS's stub), `sceKernelIsTrinityMode` -> 0. The PLT entry becomes the stub; if the NID is proven absent on the target the import is bound locally. |
| `pssr-memory` | Keep Pro/PSSR, fit its startup allocations. Per-game recipes in `ps5bp/data/recipes/` (Wolverine 01.001.005 included — reproduces the DLPS FW4 eboot byte for byte). Conflicts with `pro-disable`. |
| `stub-absent` | Every other import proven absent on the target -> `return 0`, bound locally. Blunt. |
| `user-patch` | Apply recipe files (`--patch`). |

### Patch recipes

JSON, verifiable and shareable — format in the docstring of `ps5bp/core/recipe.py`. A
recipe lists byte signatures that must match (so it refuses the wrong game version or an
already-patched file), code caves appended to a segment (hex + `rel32`/`rel8`/`rip`
fixups; `nid:XXXX` = an import's PLT stub, `@label` = cave label), call retargets with
their expected old targets, and plain old->new byte edits.

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
