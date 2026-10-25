"""A capture build that refreshes the shared archive relinks its sibling.

Both capture directories delegate ``../libkismetdatasource.a`` to the top-level
build, which regenerates version.c and re-archives whenever it finds the
archive out of date (in practice after every new commit). The binary in the
OTHER capture directory, linked against the previous archive, is then
genuinely stale, and the celltools staleness guard fails every test that
pairs the two sources. So each directory's archive rule relinks the sibling.

Tested on the real recipes, without a Kismet build. The ``../libkismetdatasource.a``
rule is lifted verbatim out of each ``Makefile.in`` into a throwaway tree whose
top-level archive target re-makes the archive on every call (the case that
matters: an out-of-date archive), and whose binaries are stubs that only record how they were linked.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

_KP = Path(__file__).resolve().parents[2]
_DIRS = {"capture_cell_diag": "kismet_cap_cell_diag",
         "capture_cell_at": "kismet_cap_cell_at"}


def _archive_rule(makefile_in: Path) -> str:
    """The `../libkismetdatasource.a: FORCE` rule: its line and recipe."""
    lines = makefile_in.read_text().splitlines()
    start = lines.index("../libkismetdatasource.a: FORCE")
    out = [lines[start]]
    for ln in lines[start + 1:]:
        if not ln.startswith("\t"):
            break
        out.append(ln)
    return "\n".join(out) + "\n"


def _tree(tmp_path: Path) -> Path:
    if shutil.which("make") is None:
        pytest.skip("make not available")
    root = tmp_path / "tree"
    root.mkdir()
    # The top-level archive target: always re-made, like the real one.
    (root / "Makefile").write_text(
        "libkismetdatasource.a: FORCE\n"
        "\t@sleep 0.02; touch version.c libkismetdatasource.a\n"
        "FORCE:\n.PHONY: FORCE\n")
    for d, binary in _DIRS.items():
        (root / d).mkdir()
        (root / d / "Makefile").write_text(
            _archive_rule(_KP / d / "Makefile.in")
            + f"{binary}: ../libkismetdatasource.a\n"
            # A link that records itself and a monotonic stamp.
            + "\t@sleep 0.02; echo linked >> link.log; touch $@; chmod +x $@\n"
            + "FORCE:\n.PHONY: FORCE\n")
    return root


def _make(root: Path, d: str) -> None:
    subprocess.run(["make", "--no-print-directory", "-C", str(root / d), _DIRS[d]],
                   check=True, capture_output=True, text=True, timeout=60)


def _fresh(root: Path, d: str) -> bool:
    b = root / d / _DIRS[d]
    return b.exists() and b.stat().st_mtime >= (root / "libkismetdatasource.a").stat().st_mtime


@pytest.mark.parametrize("built,sibling", [("capture_cell_diag", "capture_cell_at"),
                                           ("capture_cell_at", "capture_cell_diag")])
def test_building_one_leaves_the_other_fresh(tmp_path, built, sibling):
    root = _tree(tmp_path)
    _make(root, sibling)
    _make(root, built)
    assert _fresh(root, built) and _fresh(root, sibling), (
        f"after `make -C {built}`, {sibling} is older than the archive it links")


def test_an_unbuilt_sibling_stays_unbuilt(tmp_path):
    root = _tree(tmp_path)
    _make(root, "capture_cell_diag")
    assert not (root / "capture_cell_at" / "kismet_cap_cell_at").exists()


def test_the_sibling_is_relinked_once_and_the_two_never_recurse(tmp_path):
    root = _tree(tmp_path)
    _make(root, "capture_cell_at")
    _make(root, "capture_cell_diag")
    (root / "capture_cell_at" / "link.log").write_text("")
    (root / "capture_cell_diag" / "link.log").write_text("")
    _make(root, "capture_cell_diag")
    assert len((root / "capture_cell_at" / "link.log").read_text().splitlines()) == 1
    assert len((root / "capture_cell_diag" / "link.log").read_text().splitlines()) == 1
