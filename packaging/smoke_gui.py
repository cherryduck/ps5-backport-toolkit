"""CI smoke test for the frozen GUI: start it offscreen, require it to stay up for a few seconds.

usage: python packaging/smoke_gui.py dist/ps5bp/ps5bp-gui[.exe]
A missing Qt plugin / DLL / hidden import makes the bundle exit (or crash) right away; a healthy
GUI keeps running until we stop it.
"""
import os
import subprocess
import sys
import tempfile

exe = sys.argv[1]
env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PS5BP_HOME=tempfile.mkdtemp(prefix="ps5bp-smoke-"))
p = subprocess.Popen([exe], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    out, _ = p.communicate(timeout=8)
except subprocess.TimeoutExpired:
    p.kill()
    p.communicate()
    print("GUI stayed up for 8 s: ok")
    sys.exit(0)
print(out.decode(errors="replace"))
print(f"GUI exited early with code {p.returncode}")
sys.exit(1)
