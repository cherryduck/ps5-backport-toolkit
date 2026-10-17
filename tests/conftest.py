import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


import pytest


@pytest.fixture(autouse=True)
def _isolated_ps5bp_home(tmp_path, monkeypatch):
    """Never touch the real kit store / applied.json ledger."""
    monkeypatch.setenv("PS5BP_HOME", str(tmp_path / "home"))
