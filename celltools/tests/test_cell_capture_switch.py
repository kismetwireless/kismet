# SPDX-License-Identifier: Apache-2.0
"""The capture switch and the disabled rendering, structurally.

``test_cellat_server_controls.py`` proves the ROUTE sequence works against
a real server. This file pins that the panel actually USES that sequence, and
the ways it must not deviate:

* the close comes FIRST and the reopen is ``.always()`` (if the update goes
  first, the route refuses a running source and a ``.then()`` reopen never
  chains -- a dead button);
* it never calls ``disable_source.cmd`` -- that is Kismet's OTHER "off", and a
  second control for it would disagree with the Active row's buttons;
* it reads nothing from the transport (a refused update still answers);
* celldiag's disabled branch runs BEFORE the helper row, which is the row that
  would otherwise render a disabled source as "DEAD".

Structural: these read the panel's source. The behavioural half runs against a
real server in ``test_cellat_server_controls.py``.
"""
from __future__ import annotations

import re
from pathlib import Path

PANEL_JS = Path(__file__).resolve().parents[2] / "http_data/js/kismet.ui.datasources.js"


def _switch() -> str:
    m = re.search(r"const cell_capture_switch_control = .*?\n\}", PANEL_JS.read_text(), re.S)
    assert m, "cell_capture_switch_control is gone or renamed"
    return m.group(0)


def test_the_switch_closes_first_updates_enabled_and_always_reopens():
    body = _switch()
    assert re.search(
        r"\$\.get\(base \+ 'close_source\.cmd'\)\s*\n\s*\.then\(\(\) => \$\.ajax\(\{"
        r".*?update_definition\.cmd.*?\}\)\)\s*\n\s*\.always\(\(\) => "
        r"\$\.get\(base \+ 'open_source\.cmd'\)\)", body, re.S), (
        "the switch is not close -> update_definition -> .always(open)")
    assert '"enabled": want' in body, "the switch does not post the enabled option"


def test_the_switch_is_not_kismets_disable():
    body = _switch()
    assert "disable_source.cmd" not in body, (
        "the switch drives Kismet's Disable -- a second control for the Active "
        "row's action, which it would disagree with")


def test_the_switch_confirms_and_reads_nothing_from_the_transport():
    body = _switch()
    assert "window.confirm" in body
    for handler in ("success:", "error:", ".done(", ".fail(", "statusCode"):
        assert handler not in body, f"the switch installs a {handler!r} handler"
    assert "message bus" in body


def test_celldiag_renders_disabled_before_the_helper_row():
    txt = PANEL_JS.read_text()
    start = txt.index("export const celldiag_render_rows")
    disabled = txt.index("f('mask_preset') === 'disabled'", start)
    helper = txt.index("f('helper_alive') ?", start)
    assert disabled < helper, (
        "the decoder row is rendered before the disabled check -- a disabled "
        "source would read as 'Decoder DEAD'")


def test_both_panels_render_the_switch_in_both_states():
    txt = PANEL_JS.read_text()
    for row in ("celldiag_capture", "cellat_capture"):
        calls = re.findall(
            rf"set_row\(sdiv, '{row}', '<b>Capture</b>',\s*\n\s*"
            r"cell_capture_switch_control\(source, (true|false)\)\)", txt)
        assert sorted(calls) == ["false", "true"], (row, calls)
