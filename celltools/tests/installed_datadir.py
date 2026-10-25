# SPDX-License-Identifier: Apache-2.0
"""Keep a COPIED capture binary from finding this host's installed data dir."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

#: A compiled-in installed data dir: a whole C string ending in /kismet/cell
#: (QMIFEED_DATADIR = "@datadir@/kismet/cell").
_DATADIR_RE = re.compile(rb"(?<=\x00)/[^\x00]*/kismet/cell(?=\x00)")


def forget_installed_datadir(binary: Path) -> list[str]:
    """Point a COPIED binary's compiled-in installed data dir at nowhere.

    An autoconf build compiles ``<datadir>/kismet/cell`` in as the LAST place
    to look for the QMI feed. On a host that ran ``make install`` that
    directory is real, so a "nothing beside this binary" test finds the
    INSTALLED copy and the open is accepted: a false RED that reads as a
    regression. Rewriting the path in the test's own copy (same length, so
    nothing moves) acts as a build-time data dir without a second link and
    without a runtime override in the shipped binary, which deliberately has
    none. The binary under test is otherwise byte-identical. Returns the paths
    it replaced; a build with none compiled in (``standalone.mk``) returns [].
    """
    data = binary.read_bytes()
    found = [m.group(0).decode() for m in _DATADIR_RE.finditer(data)]
    if not found:
        return []
    out = _DATADIR_RE.sub(lambda m: b"/" + b"_" * (len(m.group(0)) - 1), data)
    assert not Path("/" + "_" * (len(found[0]) - 1)).exists()
    binary.write_bytes(out)
    if sys.platform == "darwin":
        # A patched Mach-O loses its ad-hoc signature; arm64 kills it on exec.
        if shutil.which("codesign") is None:
            pytest.skip("cannot re-sign a patched binary: no codesign")
        subprocess.run(["codesign", "--force", "-s", "-", str(binary)],
                       check=True, capture_output=True)
    return found
