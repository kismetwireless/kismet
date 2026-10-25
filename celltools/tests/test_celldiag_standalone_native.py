# SPDX-License-Identifier: Apache-2.0
"""``standalone.mk check-native``: the helper, built with no autoconf.

``standalone.mk`` is the dependency-free "stranger build": the helper with its
native decode legs linked in, on a tree that has never run ``./configure``.
These tests pin the four things that make ``check-native`` a gate rather than a
build:

* it is the file's DEFAULT goal: a bare
  ``make -f standalone.mk`` is what a stranger types;
* its C++ closure is Makefile.in's, name for name (two lists drift);
* a missing prerequisite (C++ compiler, Kaitai runtime, decode sources) stops it
  BEFORE anything compiles, with a message naming the fix;
* a real run builds the binary, reads it as native, and decodes the tree's own
  capture into exactly the committed expectation, and each of those checks
  fails when its input is wrong.

The positive run reuses the tree's ``build-native/`` (incremental), so it costs
a full compile only the first time.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

TREE = Path(__file__).resolve().parents[2]
CELLDIAG = TREE / "capture_cell_diag"
MAKEFILE_IN = CELLDIAG / "Makefile.in"
STANDALONE = CELLDIAG / "standalone.mk"
NATIVE_BIN = CELLDIAG / "build-native" / "kismet_cap_cell_diag"
EXPECTED = CELLDIAG / "fixtures" / "functional.native.ndjson"

needs_make = pytest.mark.skipif(shutil.which("make") is None or shutil.which("cc") is None,
                                reason="needs make and cc")
_NATIVE_TOOLS = (shutil.which("make") and shutil.which("cc") and shutil.which("c++")
                 and shutil.which("nm") and (TREE / "diagspec" / "generated" / "cpp").is_dir()
                 and (TREE / "kaitaistream.cc").is_file())
_NATIVE_SKIP = "needs make, cc, c++, nm, the tree's diagspec/ and its Kaitai runtime"


def _env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items()
            if k not in ("MAKEFLAGS", "MAKELEVEL", "MFLAGS")}


def _make(*args: str, timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["make", "--no-print-directory", "-C", str(CELLDIAG), "-f", "standalone.mk", *args],
        capture_output=True, text=True, timeout=timeout, env=_env())


def _block(text: str, var: str) -> list[str]:
    """The backslash-continued value of `var = ...`, as words."""
    out: list[str] = []
    collecting = False
    for line in text.splitlines():
        stripped = line.strip()
        if not collecting:
            if re.match(rf"^{var}[ \t]*=", stripped):
                collecting = True
                stripped = stripped.split("=", 1)[1].strip()
            else:
                continue
        more = stripped.endswith("\\")
        out.extend(stripped.rstrip("\\").split())
        if not more:
            break
    return out


# ── the default goal is the shipping build ───────────────────────────────────

@needs_make
def test_the_default_goal_is_check_native(tmp_path):
    """A bare `make -f standalone.mk` runs check-native. A dry run (-n) prints
    the recipe it WOULD run without building anything; the target's closing
    line names it."""
    r = _make("-n", f"NATIVE_DIR={tmp_path / 'bn'}", timeout=300)
    assert r.returncode == 0, r.stderr[-2000:]
    assert "PASS: check-native" in r.stdout, (
        f"the default goal is not check-native:\n{r.stdout[-2000:]}")


# ── the closure is Makefile.in's ─────────────────────────────────────────────

def test_the_native_closure_mirrors_makefile_ins():
    """A leg in Makefile.in's DIAGSPEC_SRCS and not in NATIVE_DIAGSPEC_SRCS still
    fails check-native's link (the shim calls it), but a swap of two names with
    the count unchanged is what this catches by name."""
    autoconf = _block(MAKEFILE_IN.read_text(), "DIAGSPEC_SRCS")
    native = _block(STANDALONE.read_text(), "NATIVE_DIAGSPEC_SRCS")
    assert autoconf and native, "could not parse one of the two lists"
    assert "../kaitaistream.cc" in autoconf, "the Kaitai runtime moved in Makefile.in"
    want = sorted(p.removeprefix("../diagspec/") for p in autoconf
                  if p != "../kaitaistream.cc")
    got = sorted(p.removeprefix("$(NATIVE_DIAGSPEC)/") for p in native)
    assert got == want, (
        f"only in Makefile.in: {sorted(set(want) - set(got))}\n"
        f"only in standalone.mk: {sorted(set(got) - set(want))}")
    count = re.search(r"^NATIVE_DIAGSPEC_SRCS_COUNT[ \t]*=[ \t]*(\d+)",
                      STANDALONE.read_text(), re.M)
    assert count and int(count.group(1)) == len(native)


# ── a missing prerequisite stops it first, and names the fix ─────────────────

@needs_make
@pytest.mark.parametrize("override,named", [
    ("NATIVE_DIAGSPEC=/nonexistent/diagspec", "decode sources"),
    ("NATIVE_KAITAI=/nonexistent/kaitai", "Kaitai runtime"),
    ("NATIVE_CXX=no-such-cxx-wS4", "C++ compiler"),
])
def test_a_missing_prerequisite_stops_check_native_before_anything_runs(tmp_path, override, named):
    ndir = tmp_path / "bn"
    r = _make("check-native", override, f"NATIVE_DIR={ndir}", timeout=300)
    assert r.returncode != 0
    assert "the build cannot start" in r.stderr and named in r.stderr, r.stderr
    assert override.split("=", 1)[1] in r.stderr, "the message does not name what is missing"
    # Stopped FIRST: neither the framework-free selftests nor a compile ran.
    assert "--- test_diag_hdlc" not in r.stdout, r.stdout[-2000:]
    assert not (ndir / "obj").exists() or not any((ndir / "obj").iterdir())


@needs_make
def test_a_compiler_that_cannot_build_cxx_is_named(tmp_path):
    """On PATH is not the same as usable: `false` stands in for a C++ compiler
    with no standard library. The probe fails before any leg compiles."""
    ndir = tmp_path / "bn"
    r = _make("native", "NATIVE_CXX=false", f"NATIVE_DIR={ndir}", timeout=300)
    assert r.returncode != 0
    assert "cannot build C++" in r.stderr, r.stderr
    assert not list(ndir.rglob("*.o")), "an object compiled after the probe failed"


# ── the real run ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def check_native():
    """One real run of the DEFAULT goal -- check-native -- in the
    tree's own build-native/. No target is named, so a default goal that is not
    check-native fails every test below, not only the dry-run one above."""
    if not _NATIVE_TOOLS:
        pytest.skip(_NATIVE_SKIP)
    jobs = str(max(1, (os.cpu_count() or 2) * 3 // 4))
    r = _make(f"-j{jobs}")
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-4000:]
    return r


def test_check_native_builds_checks_and_decodes(check_native):
    out = check_native.stdout
    assert "PASS: check-native" in out
    assert "OK: build-native/kismet_cap_cell_diag defines all" in out, \
        "the helper-role symbol guard did not run on the native link"
    assert "PASS: standalone celldiag selftests" in out, "check-native no longer includes check"
    assert re.search(r"\b4 observation\(s\), equal to fixtures/functional\.native\.ndjson", out), out


def test_the_native_build_really_is_the_cxx_link(check_native):
    """The native decode legs are C++: a helper with no libstdc++ linked has
    no legs in it, and is not the build that ships."""
    if shutil.which("ldd") is None:
        pytest.skip("no ldd")
    ldd = subprocess.run(["ldd", str(NATIVE_BIN)], capture_output=True, text=True)
    assert "libstdc++" in ldd.stdout, ldd.stdout


def _rerun(*overrides: str) -> subprocess.CompletedProcess:
    return _make("check-native", *overrides, timeout=600)


def test_a_wrong_expectation_fails_the_comparison(check_native, tmp_path):
    rows = EXPECTED.read_text().splitlines()
    rows[0] = rows[0].replace('"rsrp":-85.0', '"rsrp":-86.0')
    assert rows[0] != EXPECTED.read_text().splitlines()[0], "the mutation did not apply"
    bad = tmp_path / "wrong.ndjson"
    bad.write_text("\n".join(rows) + "\n")
    r = _rerun(f"NATIVE_FUNCTIONAL_EXPECTED={bad}")
    assert r.returncode != 0
    assert "differ from" in r.stderr and '"rsrp":-86.0' in r.stderr, r.stderr


def test_a_missing_row_fails_the_comparison(check_native, tmp_path):
    """A prefix of the right answer is not the right answer."""
    short = tmp_path / "short.ndjson"
    short.write_text("\n".join(EXPECTED.read_text().splitlines()[:-1]) + "\n")
    r = _rerun(f"NATIVE_FUNCTIONAL_EXPECTED={short}")
    assert r.returncode != 0 and "differ from" in r.stderr, r.stderr


def test_an_empty_expectation_is_refused_not_matched(check_native, tmp_path):
    empty = tmp_path / "empty.ndjson"
    empty.write_text("")
    r = _rerun(f"NATIVE_FUNCTIONAL_EXPECTED={empty}")
    assert r.returncode != 0 and "missing or empty" in r.stderr, r.stderr


def test_a_capture_with_no_records_fails_on_emptiness(check_native, tmp_path):
    """Zero observations must fail as zero, never compare equal to anything."""
    blank = tmp_path / "blank.hdlc"
    blank.write_bytes(b"\x7e" * 8)
    r = _rerun(f"FUNCTIONAL_FIXTURE={blank}")
    assert r.returncode != 0
    assert "NO observations" in r.stderr or "the replay exited" in r.stderr, r.stderr
