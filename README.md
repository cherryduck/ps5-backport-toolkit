# ps5bp — PS5 backport toolkit (Linux)

**ps5bp turns a PS5 game dump into a *backport*: a version of the game that runs on a console
with older firmware than the game was made for.** It has a graphical app (`ps5bp-gui`) and a
command line (`ps5bp`); both do the same things.

What it does for you:

- **Lowers the game's firmware requirement.** Every game file declares the SDK (firmware) it was
  built with, and the console refuses to start anything newer than itself. ps5bp rewrites those
  version numbers in every executable and in `sce_sys/param.json`.
- **Supplies missing system libraries.** A new game calls functions an old firmware doesn't
  have. ps5bp works out which ones are missing and adds replacement libraries ("fakelibs")
  taken from other people's backports that you give it.
- **Applies known fixes.** Things like "no sound on 4.xx", "can't save on 4.xx" or "crashes on a
  PS5 Pro" have known byte-level fixes. ps5bp detects which apply to your game and offers them
  as tick-boxes ("fix rules").
- **Helps when it crashes.** It reads the console's crash log, tells you which part of the game
  died and why, and can capture logs and crash dumps live from the console.

What it does **not** do: decrypt games, make PKGs, or install anything on the console. You start
from a decrypted dump and copy the result onto the console your usual way.

> **Contents:** [Words you'll see](#words-youll-see) · [Install](#install) ·
> [Your first backport (app)](#your-first-backport-app) ·
> [Your first backport (command line)](#your-first-backport-command-line) ·
> [Which target firmware?](#which-target-firmware) · [Kits](#kits-why-and-how) ·
> [Fix rules](#fix-rules-which-to-tick) · [When it crashes](#when-it-crashes) ·
> [Output, safety and undo](#output-safety-and-undo) · [Command reference](#command-reference) ·
> [Technical reference](#technical-reference)

---

## Words you'll see

| Word | Meaning |
|---|---|
| **Dump** | The game's files, decrypted, as produced by a dumper such as ps5-app-dumper. A folder containing `eboot.bin` and `sce_sys/`. Its executables are *fake-signed SELFs*. |
| **Backport** | The modified files that let the dump run on older firmware. |
| **Target firmware** | The oldest firmware the backport should run on, e.g. `4` (4.xx) or `4.03`. |
| **SDK version** | The firmware version a file says it needs. The backport lowers it to the target. |
| **Import / NID** | A system function the game calls. Each has an 11-character ID (NID), e.g. `NH6xARDOVv8`. |
| **Fakelib** | A replacement system library placed in the game's `fakelib/` folder, supplying functions the old firmware lacks. |
| **Kit** | Someone else's finished backport (folder or zip) that you add to ps5bp's library. ps5bp takes fakelibs from kits and learns from them which functions each firmware has. |
| **Fix rule** | One known fix (e.g. `wwise-71` for missing sound). Off unless you tick it; ★ means "recommended for this game". |
| **klog** | The console's kernel log. When a game crashes, the reason is in here. |
| **Overlay** | The default output: only the files that changed, to be copied over the game. |
| **Ampr index** | `ampr_emu.index`: a list of every file in the game (name, size, date) that the Ampr emulator reads instead of asking the disk. Needed on read-only game images. |

---

## Install

You need a Linux PC. Pick one:

**Standalone app (no Python needed):**
```
scripts/build-bundle.sh                              # builds dist/ps5bp/ps5bp and dist/ps5bp/ps5bp-gui
scripts/install-desktop.sh dist/ps5bp/ps5bp-gui      # adds "PS5 Backporter" to your app menu
```
After pulling new changes, run `scripts/build-bundle.sh` again, or the app menu keeps starting
the old version.

**With pipx:**
```
pipx install '/path/to/ps5-backporter[gui]'          # puts ps5bp and ps5bp-gui on your PATH
scripts/install-desktop.sh                           # optional app-menu entry
```

**For development:** `python -m venv .venv && .venv/bin/pip install -e '.[gui,dev]'`

ps5bp keeps its data (kits, history) in `~/.local/share/ps5bp/`. Set `PS5BP_HOME` to use
another folder.

---

## Your first backport (app)

Start **PS5 Backporter** from the app menu (or run `ps5bp-gui`).

1. **Add at least one kit** (first time only). Open the **Kits** tab → *Add kit folder…* or
   *Add kit zip…* and pick an existing backport (any game). Say which firmware it was made for
   (e.g. 4). More kits = better choices; see [Kits](#kits-why-and-how).
2. **Pick the game.** *Game folder* at the top → the folder containing `eboot.bin`.
3. **Pick the firmware.** *Target FW* = the oldest firmware it should run on. Put your console's
   firmware in *Console FW* (e.g. `11.60`) so ps5bp can warn you about risky combinations.
4. **Press Analyze.** Nothing is written. Look at:
   - **Overview**: every executable in the game and any problems, with warnings and advice below.
   - **Imports**: every system library the game uses and where it will come from on the target
     (`system` = firmware has it, `fakelib` = a kit supplies it, `missing` = nobody does).
   - **Fix rules**: the fixes that apply to this game. ★ rows are recommended; tick those.
5. **Choose where the output goes.** The bottom row: mode *overlay* (default) and an output
   folder (defaults to `<game>-backport` next to the game).
6. **Press Build backport.** When it's done a dialog shows what was changed. The output folder
   has the changed files, the `fakelib/` folder and `backport-report.txt` listing every change.
7. **Copy the output over the game** (on the console or before packaging) and try it.
8. **If it crashes**, see [When it crashes](#when-it-crashes). The **Console** tab can catch the
   crash live, and the **Crash log** tab explains a saved log.

Other things in the app:
- **Also build for:** extra firmware versions to build at the same time (see
  [Which target firmware?](#which-target-firmware)).
- **Dump's fakelibs:** some dumps ship their own libSceAmpr / libScePlayGo. Keep them (default),
  or replace them with the best kit's copy or a specific kit's.
- **Rebuild existing backport:** tick this if ps5bp refuses because the folder already contains
  a backport (see [Output, safety and undo](#output-safety-and-undo)).
- **Undo applied backport…:** puts a game folder back to how it was before you copied a
  backport over it.
- **Memory fix** tab: for games that quit at start-up on low firmware; see [memfix](#3-the-game-quits-at-start-up-memfix).
- **Log** tab: everything ps5bp printed.

---

## Your first backport (command line)

```
# once: add kits (existing backports) to the library
ps5bp kit add "FW4xx PPSA11386 backport.zip" --fw 4 --source DLPS

# look before you leap: what's needed, what's missing, which fixes apply (writes nothing)
ps5bp analyze /games/PPSA12345 --target 4 --console-fw 11.60

# build, with the recommended fixes the analysis showed (★)
ps5bp build /games/PPSA12345 --target 4 --out /games/PPSA12345-backport --rule wwise-71 --rule savedata-mount

# copy /games/PPSA12345-backport over the game, run it; if it crashes, save the klog and:
ps5bp klog crash.txt --game /games/PPSA12345
```

`ps5bp rules` lists all fix rules; `ps5bp <command> --help` shows every option.

---

## Which target firmware?

**Target** = the oldest firmware the backport must run on. Lower reaches more consoles, but
it's riskier on high-firmware consoles.

There's a known catch: a build for **4.xx** run on a console **far newer** (e.g. 9.00, or a PS5
Pro on 11.xx) can show a **black screen or GPU hang** that the same build made for 5.xx doesn't.
So:

- Put your console's firmware in **Console FW** / `--console-fw 11.60`. ps5bp warns when the
  target is 2+ major versions below it.
- Use **Also build for** / `--also-target 5,11` to get extra copies (`<out>-fw5`, `<out>-fw11`)
  that are identical except for the version numbers. If the 4.xx build black-screens, try those.
- A plain `--target 9` is a full new build: it uses fewer fakelibs, because firmware 9 already
  has more functions.

Targets 4 to 13 are supported, with an optional minor version (`4.03`, `4.50`). The version
numbers for 11–13 haven't yet been checked against a real game built for them.

---

## Kits: why and how

ps5bp doesn't ship any Sony files. Everything it knows about which functions exist on which
firmware, and every fakelib it installs, comes from **kits**: existing backports of other games
that you add.

```
ps5bp kit add PATH --fw 4 [--name NAME] [--source WHO]   # PATH = backport folder or .zip
ps5bp kit add PATH --fw 4 --tested-fw 10                 # made for 4.03 but only ever run on 10.01
ps5bp kit list
ps5bp kit remove NAME
```

What a kit teaches ps5bp:
- **Functions the kit's game calls** exist on the kit's firmware (and later ones).
- **Functions the kit replaced** with its own stub are missing on that firmware, and the stub
  can be reused for other games (rule `kit-stubs`).
- **Its fakelibs** become candidates for your games. ps5bp picks the best one per library and
  keeps pairs that must match (libSceAgc + libSceAgcDriver) from the same kit.
- **Which known fixes the kit's author applied.** That's where the ★ recommendations come from.

In **Analyze → Imports**, `unverified` means "no kit has told us yet", not "broken". It shrinks
as you add kits. Only fakelibs (and `libc.prx`, `k9.psp`) are stored, never the kit's game
executables.

**Learning from a kit.** If you have both the original dump *and* someone's backport of the same
game version, `ps5bp kit learn ORIGINAL KIT` (app: Kits → *Learn from kit…*) explains every byte
they changed, by naming the ps5bp rule that makes the same change. Anything ps5bp can't explain
is listed as a candidate for a new fix (`--recipe --out DIR` saves it as a per-game patch file).

---

## Fix rules: which to tick

All rules are **off** unless you tick them (app: *Fix rules* tab; command line: `--rule NAME`).
Analyze marks the ones recommended for your game with ★ and explains why. Rules that would
conflict can't be ticked together. A rule that finds nothing to change does nothing.

**Start with the ★ ones.** Then use this table when something specific goes wrong:

| Symptom on the console | Rule(s) to try |
|---|---|
| No sound | `wwise-71` (Wwise games), `frostbite-8ch` (EA / Frostbite games), `set3-nonfatal` (targets 6–9) |
| Saving fails (e.g. CE-107098-5) | `savedata-mount`, then `savedata-prepare`, `savedata-dirsearch` |
| Crashes or exits at start on a **PS5 Pro**, or uses PSSR | `pro-disable` (simplest: runs as a base PS5), or `pssr-memory` (keeps PSSR; known games), or `psml-overlay` |
| Crash log says a function is missing / not resolved | `compat-stubs`, `kit-stubs`, last resort `stub-absent` |
| Exits at start with a failed memory allocation | the [memfix](#3-the-game-quits-at-start-up-memfix) workflow |
| Game settings / presets request rejected (0x80960005) | `gamepresets-28` |
| Crash in libc at thread exit (targets below 11) | `tls-atexit` |

All rules, in plain words:

| Rule | What it fixes | Recommended when |
|---|---|---|
| `wwise-71` | Wwise audio asks for 7.1.4 (12 speakers); old firmware only does 7.1 → no sound. | 4.xx (console-tested) |
| `frostbite-8ch` | Same problem in EA/Frostbite games (12 → 8 channels). | 4.xx |
| `set3-nonfatal` | On firmware 6–9 an audio latency call fails and the game gives up on sound; makes the failure harmless. | never automatically (untested on 6–9) |
| `savedata-mount` | Save-game mount request uses a value 4.xx rejects (error CE-107098-5). | when kits show it (console-tested) |
| `savedata-prepare` | Save "prepare" request uses a mode 4.xx doesn't know. | never automatically |
| `savedata-dirsearch` | Game uses a save-search function added in 5.02; switches it to the older one. | never automatically |
| `gamepresets-28` | Game-presets request is 8 bytes bigger than 4.xx accepts. | 4.xx |
| `tls-atexit` | libc uses a thread-exit function that only exists from 11.00; uses the older equivalent. | target below 11 |
| `mapflex-flags` | libc passes a memory flag the retargeted memory function doesn't accept. | whenever libc has those calls |
| `pro-disable` | The game runs as on a base PS5 (no Pro / PSSR path). Most reliable Pro fix; loses Pro features. | when kits prove the Pro query is missing on the target |
| `pssr-memory` | Keeps Pro/PSSR and shrinks its start-up memory use; uses per-game recipes (Wolverine included) and ones you confirm with memfix. | when a recipe matches this game version |
| `psml-overlay` | Ships a kit's PSSR model library + `k9.psp` for Pro titles whose model the firmware lacks. Needs a kit that has them. | never automatically |
| `trinity-hw-gate` | *Experimental.* One build that correctly detects base vs Pro, instead of forcing either. | never (needs console testing) |
| `compat-stubs` | Fills in ~23 specific functions old firmware lacks (pad, VRR, video, save convert…) with safe stand-ins. On newer firmware that has them, the real function is still used. `--seed NID` forces one. | never yet (needs console results) |
| `kit-stubs` | Reuses the stand-ins other backporters wrote for missing functions. | when a kit stubbed a function this game uses |
| `stub-absent` | Every remaining missing function returns 0. Blunt; prefer the rules above. | when kits prove a function missing and no other rule covers it |
| `sync-umtx` | *Experimental.* Replaces thread wait/wake functions added in 6.00/9.00 with the kernel call that existed before. | never |
| `user-patch` | Applies your own patch files (`--patch FILE.json` turns it on). | when your recipe matches the game |

Technical details of each rule are in the [technical reference](#rule-details).

---

## When it crashes

### 1. Get the crash log

**Easiest: live from the console.** Load `klogsrv` and `ftpsrv` with your payload loader (ps5bp
doesn't include payloads). Then:

- **App:** **Console** tab → enter the console's IP → optionally set the game folder and tick
  *Capture crash dumps* → *Start live log* → start the game on the console. When it crashes, ps5bp shows
  the diagnosis straight away and saves the crash as `crash-<time>.txt`.
- **Command line:**
  ```
  ps5bp console klog 192.168.1.50 --out log.txt --game /games/PPSA12345 --dumps dumps/
  ```

Start this **before** launching the game. The console deletes its crash-dump folder as soon as
you close the crash screen, so ps5bp copies it the moment it appears.

You can also send a payload from here: `ps5bp console send IP file.elf` (loader port 9021), or
the Send buttons in the Console tab.

**Or from a saved log file:** app **Crash log** tab, or `ps5bp klog crash.txt --game /games/PPSA12345`.

### 2. Read the diagnosis

ps5bp ignores the usual harmless noise (fake-signed mount messages, missing save data, offline
PSN errors), finds where the game died, and with the game folder disassembles the code at each
step of the backtrace. It names the function that failed and suggests a rule. Example: for
Wolverine on a Pro at 11.60 it finds the start-up memory allocation failing and suggests
`pssr-memory` or `pro-disable`. It also reads the Ampr emulator's own log lines (`[AMPR_EMU]`,
`apr.index …`, `indexed-path-missing`): a missing, stale, corrupt or unwritable `ampr_emu.index` is
named, with the fix (rebuild with `--ampr-index regen`, or run once from a writable location).

### 3. The game quits at start-up: memfix

Pro/PSSR games on low firmware often quit because a large memory allocation fails. `memfix`
finds that allocation, offers fixes, and keeps track of what you've tried. App: **Memory fix** tab.

```
ps5bp memfix GAME --klog crash.txt                    # ranked list of allocation sites, crash path first
ps5bp build GAME --target 4 --out OUT --memfix 3d77bbc:page-split --klog crash.txt   # build trial 1
# copy OUT over the game and try it, then record what happened:
ps5bp memfix GAME --result 1 works                    # saved as a recipe; pssr-memory offers it from now on
ps5bp memfix GAME --result 1 crash --from-console dumps/   # still crashing: did it move? suggests the next step
ps5bp memfix GAME --trials                            # history
```

The fixes it can generate:

| Fix | What it does | Offered when |
|---|---|---|
| `shrink[:128M]` | requests the allocation smaller (by 128M/256M/512M) | it's safe: the game doesn't rely on the original size afterwards |
| `page-split` | allocates the same memory as many 2 MB pieces instead of one big block | the game stores the memory as a page list |
| `retry-align` | if the allocation fails, tries once more with relaxed alignment | AllocateDirectMemory-style calls |

Only a console boot tells you whether a fix works; ps5bp records your results, it doesn't guess.

---

## Output, safety and undo

**Output modes** (bottom row of the app, or `--mode`):

| Mode | What you get |
|---|---|
| `overlay` (default) | Only changed files + `fakelib/`. Copy it over the game. |
| `full` | A complete copy of the game with the changes (unchanged files are reflinked when possible, so it's fast and doesn't double disk use). |
| `inplace` | Edits the game folder directly, keeping `.orig` backups. |

`--dry-run` shows what would happen without writing anything.

**Safety:**
- **Every build is verified.** Each changed file is re-read and compared with the original. Any
  byte that changed without being on the list of intended edits fails the build.
- **Original files are kept.** An overlay build saves the game's original copy of every file it
  replaces in `<out>.originals/`. That folder sits beside the output, so it isn't copied over
  the game.
- **Already-patched folders are refused.** ps5bp remembers every file it has written. If you
  point it at a game folder that already has a ps5bp backport copied over it, it refuses,
  because those files aren't originals any more. Tick *Rebuild existing backport* or pass
  `--force` if that's really what you want.
- **Rebuilding into the same output folder replaces the previous build.** The app asks first.
  ps5bp won't write into any other non-empty folder.

**The Ampr index (`ampr_emu.index`).** Some dumps ship an Ampr emulator (`fakelib/libSceAmpr.sprx`).
It trusts `ampr_emu.index` for file sizes, and builds the file itself on first start only if the
game folder is writable. ps5bp therefore **never deletes it**. When the finished game contains an
Ampr emulator, ps5bp looks at the index:
- **none** → it writes a fresh one (so games on a read-only image work);
- **matches** the final files (same names and sizes) → left alone;
- **stale** (a file was added, removed or resized) → rewritten;
- **the game has `ampr_assets.index` asset packs** → the packs are tied to the index's numbering, so
  the index is never rewritten on its own; ps5bp keeps yours and warns if it no longer matches.

Where it goes: in an overlay the new index is part of the overlay (the game's own is saved in
`<out>.originals/`, so *Undo* brings it back); in `full` it's in the output; in `inplace` the
old one becomes `ampr_emu.index.orig`. Choose the behaviour with *AMPR index* in the app or
`--ampr-index auto|regen|keep` (`regen` refuses a change of file names when packs exist unless
`--force`). The report lists the emulator version(s) (the dump's and the kit's) and what was done,
and `analyze` shows the same plus whether an index and packs exist. (`*.orig` backups and ps5bp's
own report files are not listed in the index.)

**Undo:** if you copied an overlay over a game and want the original back:
- App: *Undo applied backport…* → pick the game folder and the output folder(s), newest first →
  *Preview* → *Undo backport*.
- Command line: `ps5bp undo GAME OUT [OLDER_OUT ...]`

Undo first checks that the game's files are still exactly what the backport wrote. If something
else changed them since, it stops. *Force* / `--force` overrides that check.

---

## Command reference

| Command | Does |
|---|---|
| `ps5bp gui` | Open the app (same as `ps5bp-gui`). |
| `ps5bp analyze GAME --target N [--console-fw X.YY] [--json]` | Show what the game needs and which fixes apply. Writes nothing. |
| `ps5bp build GAME --target N --out OUT [options]` | Make the backport. Main options below. |
| `ps5bp rules` | List all fix rules and built-in recipes. |
| `ps5bp undo GAME OUT [OLDER_OUT ...] [--dry-run] [--force]` | Restore a game folder an overlay was copied over. |
| `ps5bp klog LOG [--game GAME]` | Explain a crash log (`-` reads from stdin). |
| `ps5bp console send IP FILE.elf` | Send a payload to the console's ELF loader (port 9021). |
| `ps5bp console klog IP [--out F] [--game G] [--dumps DIR]` | Live log with automatic crash diagnosis and crash-dump capture. |
| `ps5bp console dumps IP --out DIR` | Only capture crash dumps (FTP port 2121). |
| `ps5bp memfix GAME [--klog F \| --from-console D] [--result N works\|crash] [--trials]` | Memory-allocation fixes and trial tracking. |
| `ps5bp kit add PATH --fw N [--tested-fw N] [--name] [--source] [--replace]` | Add a kit. |
| `ps5bp kit list` / `kit remove NAME` | Show / delete kits. |
| `ps5bp kit learn ORIGINAL KIT [--recipe --out DIR]` | Explain what a kit changed. |
| `ps5bp kit reindex [NAME ...]` | Recompute stored libc records (after upgrading ps5bp). |

`build` options:

| Option | Meaning |
|---|---|
| `--target N` | Oldest firmware to support: 4–13, or e.g. `4.03`. |
| `--out OUT` / `--mode overlay\|full\|inplace` | Where and how to write. |
| `--rule NAME` / `--no-rule NAME` | Turn fix rules on/off (repeatable). |
| `--console-fw X.YY` | Your console's firmware (warnings only). |
| `--also-target 5,11` | Also write `<out>-fw5`, `<out>-fw11` (only version numbers differ). |
| `--replace-dump-fakelib libSceAmpr[=KIT]` | Use a kit's libSceAmpr/libScePlayGo instead of the dump's own (best kit, or the named one). |
| `--ampr-index auto\|regen\|keep` | `ampr_emu.index` of games with an Ampr emulator: write/refresh it when needed (default), always rewrite it, or never touch it. |
| `--patch FILE.json` | Apply your own patch recipe (turns on `user-patch`). |
| `--memfix SITE:VARIANT[:AMOUNT]` + `--klog F` | Apply a memory fix from `memfix`. |
| `--seed NID` / `--seed-plt-fallback` | `compat-stubs`: force a specific stand-in / allow the older delivery method. |
| `--stubs-from KIT` | `kit-stubs`: use only this kit's stubs. |
| `--force` | Accept a folder that already looks backported. |
| `--strict` | Fail if any library is missing/partial instead of warning. |
| `--dry-run` | Plan only. |
| `--no-fakelibs`, `--no-retarget` | Skip fakelib installation / the built-in function renames. |

---

## Technical reference

The rest of this file is for people who want to know exactly what ps5bp changes.

### What a build does

1. **SDK downgrade:** the PS5/PS4 SDK pair in `PT_SCE_PROCPARAM` / `PT_SCE_MODULE_PARAM` of every
   binary newer than the target (eboot, prx, sprx, chosen fakelibs) is lowered to the target's
   pair (4.xx = `0x04000031` / `0x09040001`; a minor such as 4.03 gives `0x04030031`).
2. **Known import renames** (`ps5bp/data/nid_retarget.txt`, e.g. libc's MapNamedFlexibleMemory → MapFlexibleMemory).
3. **`param.json`:** `sdkVersion` / `requiredSystemSoftwareVersion` patched byte-exactly (formatting kept).
4. **Fakelibs** selected from kits and installed under `fakelib/`.
5. **Enabled fix rules.**
6. **Verification:** every output binary is re-parsed and diffed against its input. Then
   `backport-report.json/.txt` is written: every edit, every fakelib and why, input and output
   hashes, warnings and the libc cross-check.

SELFs are patched **in place**; nothing is re-signed. An input counts as "already backported"
when its eboot's SDK is at or below the target. A `fakelib/` folder alone doesn't count, because
dumps ship Ampr/PlayGo layers. `ampr_emu.index` is never dropped: after the files are written it
is created, kept or regenerated for the final game (see *The Ampr index* above), recorded as a
`generated` edit with its hash like any other output, and verified by re-reading it against the tree.

**Siblings (`--also-target`).** These are written only after the main build has verified. Each
`<out>-fwN` copy differs from the main output **only** in each binary's SDK pair and
`param.json`'s two version fields. Every file is diffed against the main output, and any other
changed byte deletes the sibling and fails. Each sibling has its own report and, for overlays,
its own `<out>-fwN.originals`, so `undo` works for it.

**SELF digest.** A fake-signed SELF has a 32-byte content digest in its EX_INFO block (after the
ELF + program headers). Its algorithm can't be recovered from the SELF, so ps5bp leaves it as
the input had it, which means it is stale after any edit, SDK downgrades included. ps5bp builds
boot anyway (ACE COMBAT 8, 4.00-SDK build on a Pro at 11.60), so the loader doesn't check it.
If another signing flow does, re-sign the output there.

### Import coverage

`analyze` classifies every module the game imports from:

| Class | Meaning |
|---|---|
| `game` | provided by the game itself |
| `system` | the target firmware has every needed function (kit evidence) |
| `fakelib` | a kit's fakelib supplies it |
| `dump` | the dump ships its own (Ampr / PlayGo emulation layers are kept) |
| `partial` | some functions covered, some not |
| `stubbed` | a kit replaced some of its functions with stubs for this firmware |
| `absent` | functions proven missing on the target and nobody supplies them |
| `unverified` | no evidence yet, which is not the same as broken |
| `missing` | the library isn't available at all |

Evidence: a kit's imports prove a function exists on the kit's firmware and later ones. This is
weak evidence, so `--tested-fw` records it at the firmware the kit actually ran on. Imports a
backporter bound to a local stub prove absence. Where one kit imports a function and another
stubs it, the class is shown as CONFLICT, not proof. Ampr/PlayGo fakelibs in kits are stored but
give no firmware evidence.

**libc cross-check.** `kit add` stores the kit's `sce_module/libc.prx` and records an *identity*
hash that undoes ps5bp's own possible edits:
- SDK fields;
- retargeted import names;
- the flexible-memory flag forms (`b900800000` / `b900000000` / `31c9909090`);
- the tls-atexit call;
- contract GOT seeds;
- SyncOnAddress/`_umtx_op` slots and their cave code.

After a build, the report says how many kits ship a libc of the same identity, and whether yours
matches each. If not, it lists the first differing ranges, labelled with the ps5bp edit that
explains them or "not explained". It is a report only: a libc is never substituted. Kits added
before this feature: `ps5bp kit reindex`, or `kit add --replace`.

### Rule details

| Rule | Exact change and guards |
|---|---|
| `pro-disable` | Pro hardware query (`NH6xARDOVv8`) → both outputs 0 (base PS5); `sceKernelIsTrinityMode` → 0. The PLT entry becomes the stub; if the NID is proven absent on the target, the import is bound locally. Conflicts with `pssr-memory`. |
| `pssr-memory` | Keep Pro/PSSR; per-game recipes in `ps5bp/data/recipes/` shrink or split start-up allocations. The Wolverine 01.001.005 recipe reproduces the DLPS FW4 eboot byte for byte. Combines with `psml-overlay`. |
| `kit-stubs` | Every import some kit PLT-stubbed for this firmware gets the same stub, in every game binary; `--stubs-from KIT` limits sources. Pro NIDs are left to `pro-disable` / `pssr-memory` when on. |
| `compat-stubs` | **GOT-seed** stubs from `ps5bp/data/stub_contracts.json` (details below). |
| `set3-nonfatal` | Targets 6–9: `sceAudioOut2Set3DLatency` rejects mode>1 (0x80268001) and Wwise treats that as fatal. At every call, `test eax,eax; je X` → `jmp X`. All callers must have exactly that shape, else nothing is patched. |
| `mapflex-flags` | Clears flag `0x8000` at libc's calls of the retargeted `sceKernelMapFlexibleMemory`. |
| `savedata-mount` | `sceSaveDataMount3` request +0x18 (systemBlocks) −1 → 0. Follows register alias chains and local wrapper functions, requires a non-zero blocks (+0x10) store and an `ff ff ff ff`-ending encoding, and refuses ambiguity. Unity `SaveData.prx`: the 16-byte vector copy of blocks+systemBlocks becomes an 8-byte copy (rbx/r14/r15 forms; the request must be zeroed first; exactly one copy). Console-confirmed on ACE COMBAT 8. |
| `wwise-71` | Wwise `AkChannelConfig` 7.1.4 (12 ch) → 7.1 where requested; lookup tables untouched. Console-tested on ACE COMBAT 8. |
| `gamepresets-28` | `sceUserServiceGetGamePresets` request size store 0x30 → 0x28, including the helper-initialised form (its memset length is left alone). Already 0x28 → DONE; anything else is refused. |
| `tls-atexit` | libc `__cxa_thread_atexit` = `push rbp; mov rbp,rsp; call PLT(qBS714-Jr3g); pop rbp; ret` (import exists from 11.00) → the call is retargeted to libc's own `__cxa_atexit`. Needs both exports and exactly that body. |
| `savedata-prepare` | `sceSaveDataPrepare` request mode (dword +4) 2 → 0, or 3 → 0 after a vector zero; exactly one store per call. |
| `savedata-dirsearch` | 4.xx: DirNameSearch2 imported without DirNameSearch → import renamed; both imported → Search2's lazy GOT slot points at Search's PLT stub. |
| `frostbite-8ch` | EA/Frostbite AudioOut2 12 → 8 channels (`mov r9d,0x30c → 0x208`, the 0xC00 format store, the channel count) in three known layouts; every anchor must match a layout completely. |
| `sync-umtx` | libc / Unity `PS5Util.prx` importing SyncOnAddress Wait32/Wait64 (from 9.00) or Wake/Wait (from 6.00) on a lower target: PLT entries become shims onto FreeBSD `_umtx_op` (Wait32 op 11, Wait64/Wait op 2, Wake op 3). A helper turns the uint32 µs timeout pointer into a relative timespec, and import strings are renamed in place. Guards: no BIND_NOW, canonical lazy PLT entries, unique strings, no GOT references outside the PLT, cave space. Emulation-tested with unicorn. ABIs in the docstring of `ps5bp/core/rules/sync_umtx.py`. |
| `trinity-hw-gate` | `sceKernelIsTrinityMode` import → `sceKernelHasTrinityMode` (the real Pro SoC check; return-0 GOT seed below 7.00). Forced OperationMode mode-3 stubs → `*lowEnergy=0; *mode = 2 \| HasTrinityMode()` in a cave; forced AGC `GetIsTrinityMode` → `*out = HasTrinityMode()`; a forced-1 IsTrinityMode PLT is restored. Forced-Pro stubs are refused without the Pro stack (`psml-overlay`, or a dump already carrying a `/app0/k9.psp` PSML + k9.psp). Conflicts with `pro-disable`. |
| `psml-overlay` | A kit `fakelib/libScePsml.sprx` containing `/app0/k9.psp`, plus `k9.psp` at that kit's root, is an overlay provider. If it exports every libScePsml NID the game imports, it replaces the coverage's choice and `k9.psp` is copied next to `eboot.bin` (hash-checked; removed by `undo`). |
| `stub-absent` | Every other import proven absent → `return 0`, bound locally. |
| `user-patch` | Applies recipe files (`--patch`). |

**compat-stubs / GOT seeds.** For an import the target firmware lacks:
- **The stub:** a stub of at most 15 bytes goes into an int3 padding run. The run must follow a
  non-fall-through instruction and must not be a branch target. If no such run exists, it goes
  into a grown segment end.
- **The GOT slot:** the import's lazy GOT slot (value PLT+6) is pointed at the stub. The PLT
  entry, import and relocation stay unchanged, so a firmware that exports the function binds it
  natively.
- **The contracts:**
  - OperationMode (`*mode=2, *lowEnergy=0`) and IsTrinityMode.
  - `scePadIsRemoteController` (writes its out-bool).
  - VRR peg/unpeg. VRR status init/register/unregister only if every caller ignores or
    error-checks the result. `GetVrrStatus` zero-fills 0x40 bytes, only if every caller owns
    such a buffer.
  - WQHD, VideoOut latency ×2, `sceSaveDataConvert` (0x809F0008), Coredump user string,
    SharePlay prohibit, Np trials flag and Acm priority.
  - The write-throttling query (0x80020003, only if every caller compares it).
  - libc thread-exit purge (libc only), and `sceAudioOut2Set3DLatency` below 6.00.
  - NetCtl link-down and Ambisonics coefficients only with `--seed`.
- **When it applies:** a function is seeded when kit evidence proves it absent on the target, or
  else when the declared SDK is below the function's first-firmware lead.
- **Status per site:** PATCH / DONE / UNKNOWN. UNKNOWN is refused with a reason, never silently
  replaced by something else. `--seed-plt-fallback` allows a PLT overwrite where a GOT seed is
  refused.

**Recommendations** come from two sources. Console results always win over kit evidence. Kits
add evidence too: `kit add` records, per rule, whether each kit shows the pattern fixed or
unfixed, and recommendations follow the build's declared SDK.

### `kit learn` details

Every changed byte between an original dump and a kit is attributed to one of these, or reported
as unexplained:
- SDK fields;
- import renames;
- PLT stubs;
- or one of the rules above.

Byte-edit rules must match exactly: a different value at the same site stays unexplained, with
a note naming the rule. Cave-placing rules are matched by structure, so the kit's choice of cave
doesn't matter.

For DLPS's ACE COMBAT 8 4.03 build nothing is left unexplained. With `kit-stubs`,
`mapflex-flags`, `savedata-mount` and `wwise-71`, ps5bp reproduces all 58 game binaries,
`param.json` and the fakelib set byte for byte. The comparison is on the ELF payload: their
re-signer also zeroes e_shnum, and their unused libScePsml isn't shipped.

### Patch recipes

JSON files, verifiable and shareable; the format is in the docstring of `ps5bp/core/recipe.py`.
A recipe lists:
- byte signatures that must match, so it refuses the wrong game version or an already-patched file;
- code caves appended to a segment (hex with `rel32`/`rel8`/`rip` fixups, where `nid:XXXX` = an
  import's PLT stub and `@label` = a cave label);
- call retargets with their expected old targets;
- plain old → new byte edits.

memfix recipes find their patch points by wildcarded signatures, so a confirmed fix can carry
over to another build of the same game.

### Console protocol notes

- Payloads go raw over TCP to the loader (9021).
- klogsrv streams text lines on TCP 3232. ps5bp reconnects automatically. A crash block is
  complete at the `Sending signal` / `App Crash` line, and must belong to an `/app0/` process.
- Crash dumps live in `/user/devlog/system/sce_coredumps.0/<TITLEID>_<n>/`: `report.log` first,
  the `.prosperodmp` core later.
- ps5bp polls ftpsrv (port 2121, anonymous, LIST + passive mode) and copies every **new** folder.
  Folders that existed at start are ignored. Downloads go to `.partial`, then are renamed.
- It waits up to 120 s for the core and keeps what it has if the folder vanishes. The klog line
  `[CRS][coredump_seq] prepare()` wakes it immediately.

### Applied-output ledger

`$PS5BP_HOME/applied.json` holds the hash of every file ps5bp has written. A build hashes the
game's binaries, `param.json` and `fakelib/*` and refuses if any is a ps5bp output. A corrupt
ledger is kept as `applied.json.bak` and restarted. `--dry-run` records nothing. Undo matches
game paths case-insensitively when the exact path is missing; an ambiguous match is an error.

---

## Tests

```
.venv/bin/pytest                                     # synthetic binaries and logs; no game data needed
PS5BP_FIXTURES=~/ps5bp-fixtures .venv/bin/pytest     # + tests against real backport folders
```

No console binaries, game data, kits or logs are included, and none may be committed.

## Credits / prior art

Format knowledge is public and was re-derived independently: SELF/ELF layout, the
PT_SCE_PROCPARAM SDK fields (idlesauce's SDK downgrade script) and fakelib sideloading (BestPig's
BackPork). The Wolverine PSSR memory recipe encodes the technique of the DLPS FW4 backport.
Several rules re-implement techniques observed in community FW4 backports. No code from any of
these projects is used.
