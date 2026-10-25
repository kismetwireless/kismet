"""`make -C celltools check` names PYTHON= when the interpreter has no pytest.

PYTHON defaults to python3, and on hosts whose system Python has no
pytest the target died with a bare "No module named pytest", exit 2. That
reads like a failing suite, or a broken celltools, rather than "point PYTHON at
an interpreter that has pytest". The guard target answers the real question
before anything runs.
"""
from __future__ import annotations

import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

CELLTOOLS = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(shutil.which("make") is None, reason="needs make")


def _make(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["make", "--no-print-directory", "-C", str(CELLTOOLS), *args],
                          capture_output=True, text=True, timeout=60)


def _python_without_pytest(tmp_path) -> str:
    """An 'interpreter' whose `-c 'import pytest'` fails, like a bare python3."""
    fake = tmp_path / "python3"
    fake.write_text("#!/bin/sh\necho \"No module named pytest\" >&2\nexit 1\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    return str(fake)


def test_an_interpreter_without_pytest_gets_a_hint_naming_python(tmp_path):
    r = _make("pytest-available", f"PYTHON={_python_without_pytest(tmp_path)}")
    assert r.returncode != 0
    assert "has no pytest" in r.stderr and "PYTHON=" in r.stderr


def test_check_refuses_before_running_anything(tmp_path):
    r = _make("check", f"PYTHON={_python_without_pytest(tmp_path)}")
    assert r.returncode != 0
    assert "PYTHON=" in r.stderr
    assert "-m pytest" not in r.stdout, "the suite must not be started"


def test_an_interpreter_with_pytest_passes_the_guard():
    """Positive control: the interpreter running this test has pytest."""
    r = _make("pytest-available", f"PYTHON={sys.executable}")
    assert r.returncode == 0, r.stderr
