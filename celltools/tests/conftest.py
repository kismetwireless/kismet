# SPDX-License-Identifier: Apache-2.0
"""Make ``celltools/`` and this directory importable for the harnesses here.

The modules under ``celltools/`` (``cell_binaries``,
``check_binary_staleness``) are plain scripts, not an installed package: this
directory must run from a fresh checkout with nothing but pytest, so there is no
``pip install -e .`` step to lean on and no package name to import through.

pytest already prepends a test file's own directory under ``rootdir``-relative
collection, but that is an implementation detail of one invocation style. Doing
it here means ``pytest celltools/tests``, ``pytest <one file>``, and
``make -C celltools check`` all resolve imports identically -- a harness that
only imports under one of those is a harness that quietly does not run under the
others.
"""
from __future__ import annotations

import sys
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
_CELLTOOLS = _TESTS.parent
# The QMI feed ships as capture_cell_at/qmifeed/; its tests import it as
# the ``qmifeed`` package, the name it claims when the helper runs it by path.
_CAPTURE_CELL_AT = _CELLTOOLS.parent / "capture_cell_at"

for _p in (str(_TESTS), str(_CELLTOOLS), str(_CAPTURE_CELL_AT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


import os  # noqa: E402

import pytest  # noqa: E402


@pytest.fixture(autouse=True, scope="session")
def _private_identity_vouch_dir(tmp_path_factory):
    """Keep every helper a test starts OUT of the host's live vouch directory.

    A cellat source publishes an identity vouch for the AT port it holds, by
    default under /run/kismet-cell -- the directory a live capture on this host
    may be using at the same moment. Without this fixture a test run leaves
    stale ``_dev_pts_N.vouch`` files there; they are refused (dead writer), but a
    test suite must not write where a live capture keeps its records. Session-scoped so the Kismet servers the server
    tests start inherit it too; a test that wants its own dir still overrides
    it with monkeypatch.
    """
    d = tmp_path_factory.mktemp("identvouch")
    d.chmod(0o700)
    prior = os.environ.get("KISMET_CELL_VOUCH_DIR")
    os.environ["KISMET_CELL_VOUCH_DIR"] = str(d)
    yield d
    if prior is None:
        os.environ.pop("KISMET_CELL_VOUCH_DIR", None)
    else:
        os.environ["KISMET_CELL_VOUCH_DIR"] = prior
