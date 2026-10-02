# ps5bp — PS5 backport toolkit (Linux)

Point it at a decrypted PS5 game dump (fake-signed SELFs, e.g. from ps5-app-dumper)
and it analyzes — and, in later phases, builds — a backport for firmware 4.xx–7.xx.

Status: **phase 5 — CLI + PyQt6 GUI (analyze, kits, coverage, fix rules, build).**

```
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/ps5bp analyze /path/to/PPSA12345 --target 4
.venv/bin/ps5bp analyze /path/to/PPSA12345 --json > scan.json
```

## Kits and import coverage

```
ps5bp kit add "DLPS-FW4xx-PPSA11386.zip" --fw 4 --name dlps-PPSA11386 --source DLPS
ps5bp kit add "PSVIETHOA-PPSA11386_FW6xx.zip" --fw 6 --name psviethoa-PPSA11386
ps5bp kit list
ps5bp analyze /path/to/PPSA12345 --target 4
```

A kit is an existing backport's files (folder or zip), labelled with the firmware its
author targeted. Its fakelibs are stored under `~/.local/share/ps5bp/kits/` (eboots
are not kept) and it contributes evidence:

* every import its binaries resolve from the system => that NID exists on that FW (and later FWs)
* every import a backporter bound to a local stub    => that NID is absent on that FW (and earlier)

`analyze --target N` then classifies each module the game imports from as
`game` / `system` / `fakelib` / `partial` / `absent` / `unverified` / `missing`, picks
the best fakelib per module, and repairs cross-fakelib pairs (e.g. libSceAgc +
libSceAgcDriver must come from the same build). `PS5BP_HOME` overrides the data dir.

`analyze` reports, per binary: format, SDK version, needed libraries, import/export
counts and detected features (PS5 Pro code path, PSSR/MFSR, PSSR 2 model, AudioOut2),
plus which binaries need an SDK downgrade for the chosen target.

## Build

```
ps5bp build /path/to/PPSA12345 --target 4 --out /path/to/PPSA12345-fw4          # overlay (default)
ps5bp build /path/to/PPSA12345 --target 4 --out /path/to/full --mode full        # whole game, reflinked
ps5bp build /path/to/PPSA12345 --target 4 --mode inplace                         # edits game, keeps .orig
ps5bp build ... --dry-run                                                        # plan only
```

Steps: SDK downgrade of every binary newer than the target (eboot, prx, sprx, chosen
fakelibs), known NID retargets (`ps5bp/data/nid_retarget.txt`, e.g. the BackPork libc
patch), `param.json` sdkVersion / requiredSystemSoftwareVersion (byte-exact edit,
formatting preserved), fakelib install from the kit library. SELFs are patched in place
(no re-signing). Afterwards every output binary is re-parsed and diffed against its
input; any byte changed outside a recorded edit fails the build. A
`backport-report.json/.txt` lists every edit.

Overlay output contains only changed files + `fakelib/` — copy it over the game.

## GUI

```
pip install -e '.[gui]'
ps5bp-gui            # or: ps5bp gui
```

Pick the game folder and target FW, press **Analyze**: the Overview, Imports and Fix
rules tabs fill in (recommended rules are starred but never pre-ticked; ticking a
rule unticks anything it conflicts with). Choose overlay / full / in-place output and
**Build backport**. Kits are added and removed on the Kits tab. Analysis and builds run
in background threads; Cancel stops a build before it starts writing files.

## Fix rules

```
ps5bp rules                                            # list rules + built-in recipes
ps5bp build GAME --target 4 --out OUT --rule pro-disable
ps5bp build GAME --target 4 --out OUT --rule pssr-memory
ps5bp build GAME --target 4 --out OUT --patch my-fix.json
```

Every rule is off by default; `build` reports which ones are recommended and why.

| rule | what it does |
|---|---|
| `pro-disable` | Pro hardware query (`NH6xARDOVv8`) -> base PS5 (both outputs 0, as DLPS's stub), `sceKernelIsTrinityMode` -> 0. The PLT entry becomes the stub; if the NID is proven absent on the target the import is bound locally. |
| `pssr-memory` | Keep Pro/PSSR, fit its startup allocations. Per-game recipes in `ps5bp/data/recipes/` (Wolverine 01.001.005 included — reproduces the DLPS FW4 eboot byte for byte). Conflicts with `pro-disable`. |
| `stub-absent` | Every other import proven absent on the target -> `return 0`, bound locally. Blunt. |
| `user-patch` | Apply recipe files (`--patch`). |

### Patch recipes

JSON, verifiable and shareable — see the docstring in `ps5bp/core/recipe.py`. A recipe
lists byte signatures that must match (so it refuses the wrong game version or an
already-patched file), code caves appended to a segment (hex + `rel32`/`rel8`/`rip`
fixups, `nid:XXXX` resolves to an import's PLT stub, `@label` to cave labels), call
retargets with expected old targets, and plain old->new byte edits. Caves grow the
segment in place inside the SELF; the build's verification still covers every byte.

## Tests

```
.venv/bin/pytest                                  # synthetic binaries, no game data needed
PS5BP_FIXTURES=~/ps5bp-fixtures .venv/bin/pytest  # + real-folder tests (see tests/test_fixtures.py)
```

No console binaries, game data or fakelib kits are included or may be committed.

## Credits / prior art

Format knowledge is public and was re-derived independently: SELF/ELF layout,
PT_SCE_PROCPARAM SDK fields (idlesauce's SDK downgrade script), fakelib sideloading
(BestPig's BackPork). No code from those projects is used.
