# ps5bp — PS5 backport toolkit (Linux)

Point it at a decrypted PS5 game dump (fake-signed SELFs, e.g. from ps5-app-dumper)
and it analyzes — and, in later phases, builds — a backport for firmware 4.xx–7.xx.

Status: **phase 1 — `analyze` only (read-only).**

```
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/ps5bp analyze /path/to/PPSA12345 --target 4
.venv/bin/ps5bp analyze /path/to/PPSA12345 --json > scan.json
```

`analyze` reports, per binary: format, SDK version, needed libraries, import/export
counts and detected features (PS5 Pro code path, PSSR/MFSR, PSSR 2 model, AudioOut2),
plus which binaries need an SDK downgrade for the chosen target.

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
