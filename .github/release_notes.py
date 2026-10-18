"""Print the Markdown release notes for a tag (used by .github/workflows/build.yml).

usage: python .github/release_notes.py v0.2.0 0.2.0

Notes = optional hand-written text from .github/release-notes/<tag>.md, then the commit
subjects since the previous release tag, then download/install instructions.
"""
import subprocess
import sys
from pathlib import Path

tag, version = sys.argv[1], sys.argv[2]


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, encoding="utf-8").stdout.strip()


prev = git("describe", "--tags", "--abbrev=0", "--match", "v*", "HEAD")
parts: list[str] = []

manual = Path(__file__).parent / "release-notes" / f"{tag}.md"
if manual.is_file():
    parts.append(manual.read_text(encoding="utf-8").strip())

if prev:
    log = git("log", f"{prev}..HEAD", "--no-merges", "--format=- %s")
    parts.append(f"## Changes since {prev}\n\n{log or '- (no commits)'}")
elif not manual.is_file():
    parts.append("First release.")

parts.append(f"""## Download

| System | File |
|---|---|
| Windows 10/11 (64-bit) | `ps5bp-{version}-windows-x64.zip` |
| Linux (x86-64, glibc 2.35+) | `ps5bp-{version}-linux-x86_64.tar.gz` |

**Windows:** unzip anywhere and run `ps5bp-gui.exe` (the app) or `ps5bp.exe` (command line).
The files are not code-signed, so SmartScreen may warn the first time: *More info* → *Run anyway*.

**Linux:** `tar xf ps5bp-{version}-linux-x86_64.tar.gz` and run `ps5bp-gui` or `ps5bp` from the
folder. `scripts/install-desktop.sh` (from the source tree) adds a menu entry.

`SHA256SUMS` lists the checksums of both files.""")

print("\n\n".join(parts))
