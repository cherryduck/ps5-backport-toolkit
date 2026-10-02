# ps5bp — PS5 backport toolkit (Linux)

Point it at a decrypted PS5 game dump (fake-signed SELFs, e.g. from ps5-app-dumper)
and it analyzes — and, in later phases, builds — a backport for firmware 4.xx–7.xx.

Status: **phase 3 — analyze, kit library / import coverage, build.**

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
