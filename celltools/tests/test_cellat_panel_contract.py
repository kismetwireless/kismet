# SPDX-License-Identifier: Apache-2.0
"""The cellat readback's three-way contract: helper, server, panel.

A field has three ends, and checking them one at a time lets a field be
registered by the server, emitted by nobody, and rendered by the panel as a
confident zero. For cellat the three ends are

* **emitted** -- the keys ``capture_cell_at/cellat_stats.c`` can put on the
  ``cellat_stats`` line;
* **registered** -- the ``CELLAT_FIELDS`` table in ``datasource_cell_at.cc``,
  which registers AND parses every field (one table, so those two cannot
  disagree);
* **bound** -- the keys ``cellat_render_rows`` in
  ``http_data/js/kismet.ui.datasources.js`` reads.

and this file checks every direction:

=========================  ==============================================
emitted - registered       the server silently drops a measured value
registered - emitted       a dead field: registered, never set, reads as 0
bound - registered         a typo: jQuery renders ``undefined`` as blank
registered - bound         a measured value no operator can see
=========================  ==============================================

The last direction has an escape hatch, ``_DELIBERATELY_UNRENDERED``, where an
entry is a decision on the record rather than an omission.

Structural, and labelled as such: these read source text. They cannot tell
you the panel looks right (that is the browser test's job). They can tell you
it is not bound to nothing.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

TREE = Path(__file__).resolve().parents[2]
STATS_C = TREE / "capture_cell_at" / "cellat_stats.c"
DATASOURCE_CC = TREE / "datasource_cell_at.cc"
PANEL_JS = TREE / "http_data" / "js" / "kismet.ui.datasources.js"

#: Registered fields the panel does NOT render, each with the reason. An
#: unlisted unrendered field fails the test.
_DELIBERATELY_UNRENDERED: dict[str, str] = {}


def _emitted() -> set[str]:
    src = STATS_C.read_text()
    keys = set(re.findall(r'jw_(?:str|str_opt|u64|bool)\(&w, "([a-z0-9_]+)"', src))
    keys |= set(re.findall(r'jw_key\(&w, "([a-z0-9_]+)"\)', src))
    return keys


def _registered() -> set[str]:
    return set(re.findall(r'"kismet\.datasource\.cellat\.([a-z0-9_]+)"',
                          DATASOURCE_CC.read_text()))


def _panel_block() -> str:
    txt = PANEL_JS.read_text()
    start = txt.index("cellat operator panel")
    end = txt.index("/* Sidebar:  Channel coverage", start)
    return txt[start:end]


def _bound() -> set[str]:
    blk = _panel_block()
    # Same lookbehind as the celldiag contract test: without it, any
    # identifier ending in `g` followed by `('x')` would be read as a binding.
    b = set(re.findall(r"(?<![A-Za-z0-9_])g\('([a-z0-9_]+)'\)", blk))
    b |= set(re.findall(r"'kismet\.datasource\.cellat\.([a-z0-9_]+)'", blk))
    return b


def test_the_gauges_read_something():
    """A gauge that has never read positive cannot be read as negative."""
    assert len(_emitted()) >= 20, _emitted()
    assert len(_registered()) >= 20, _registered()
    assert len(_bound()) >= 15, _bound()


def test_every_emitted_key_is_registered():
    missing = _emitted() - _registered()
    assert not missing, (
        f"the helper sends {sorted(missing)} and the server has no field for "
        "them -- apply_cellat_stats_json walks CELLAT_FIELDS, so these are "
        "measured and then silently discarded")


def test_every_registered_field_is_emitted():
    dead = _registered() - _emitted()
    assert not dead, (
        f"{sorted(dead)} are registered and nothing ever sets them: they will "
        "serialize as 0/\"\" forever, indistinguishable from a real reading")


def test_every_field_the_panel_binds_is_registered():
    typos = _bound() - _registered()
    assert not typos, (
        f"the panel reads {sorted(typos)}, which no datasource registers -- "
        "jQuery renders the undefined as an empty cell, not an error")


def test_every_registered_field_is_rendered_or_excluded_on_the_record():
    unseen = _registered() - _bound() - set(_DELIBERATELY_UNRENDERED)
    assert not unseen, (
        f"{sorted(unseen)} reach the browser and no row shows them. Render "
        "them, or add each to _DELIBERATELY_UNRENDERED with the reason.")
    stale = set(_DELIBERATELY_UNRENDERED) & _bound()
    assert not stale, f"excluded but rendered anyway -- drop the entry: {stale}"


def test_the_panel_is_wired_into_the_source_detail():
    txt = PANEL_JS.read_text()
    assert "cellat_render_rows(source, sdiv, set_row" in txt, (
        "cellat_render_rows is defined and never called -- a panel nobody draws")


def test_the_stats_line_is_intercepted_by_its_own_type():
    """The helper routes the line as type "cellat_stats"; the server must
    intercept exactly that string, or every line falls through to the base
    handler and nothing is ever set."""
    assert '"cellat_stats"' in (TREE / "capture_cell_at" / "capture_cell_at.c").read_text()
    assert '== "cellat_stats"' in DATASOURCE_CC.read_text()


def test_the_panel_file_parses_as_an_es_module(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed on this host")
    mjs = tmp_path / "panel.mjs"
    mjs.write_text(PANEL_JS.read_text())
    r = subprocess.run([node, "--check", str(mjs)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
