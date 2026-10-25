# SPDX-License-Identifier: Apache-2.0
"""The whole-modem switch: one modem's sources, off and on with one click.

A modem is usually two Kismet sources, ``cellat-<IMEI>`` and
``celldiag-<IMEI>``, and each has its own Capture switch. The panel shows,
on every cell source, the modem's sources with their state, and a button that
turns all of them off or on. Each source gets the Capture switch's
close -> update_definition {enabled} -> open, one after another, so two
bring-ups never race for one modem's ports.

Driven in a real browser against a real server: a fake AT modem for cellat,
and its celldiag sibling defined ``enabled=false`` (so no DIAG fixture is
needed). Skips without Playwright or a Chromium, as the sibling browser tests
do.
"""
from __future__ import annotations

import re
import time

import pytest

from fake_at_modem import QENG_SERVING, FakeAtModem
from test_cellat_server_fields import F, _await
from test_cell_enable_form import PANEL_JS

IMEI = "351234567890123"
D = "kismet.datasource.celldiag."


def test_the_whole_modem_helper_closes_first_and_always_reopens():
    """Structural: the sequence every per-source switch uses, and a failed
    update still reopens."""
    js = PANEL_JS.read_text()
    body = js.split("const cell_set_enabled = ", 1)[1].split("\n}\n", 1)[0]
    assert body.index("close_source.cmd") < body.index("update_definition.cmd"), body
    assert ".then(reopen, reopen)" in body, "a failed update must still reopen"


def _by_name(ks, prefix):
    return next(s for s in ks.get("datasource/all_sources.json")
                if s["kismet.datasource.name"].startswith(prefix))


def _wait(pred, timeout=60.0, what=""):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = pred()
        except StopIteration:
            last = None
        if last:
            return last
        time.sleep(0.5)
    raise AssertionError(f"never held: {what}; last={last!r}")


def test_the_modem_row_turns_both_sources_off_and_on(tmp_path, monkeypatch):
    pytest.importorskip("playwright.sync_api")
    from test_cell_web_ui_browser import _data_sources
    with FakeAtModem(imei=IMEI, extra={**QENG_SERVING, "AT+CGMM": "RM520N-GL"}) as modem:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", modem.port)
        monkeypatch.setenv("CELLAT_SCAN_PORTS", modem.port)
        srcs = [f"cellat-{IMEI}:atport={modem.port},debug=false",
                f"celldiag-{IMEI}:enabled=false,retry=false"]
        with _data_sources(tmp_path, srcs) as (ks, page):
            _wait(lambda: _by_name(ks, "cellat").get(F + "state") == "surveying",
                  what="cellat surveying")
            src = page.locator(".k-ds-source", has_text=f"cellat-{IMEI}").first
            src.wait_for(timeout=30000)
            src.click()
            row = page.locator("tr#cell_modem_group").first
            _wait(lambda: "capture off" in (row.inner_text() if row.count() else ""),
                  what="the group row")
            text = row.inner_text()
            assert re.search(rf"cellat-{IMEI} — AT commands: capturing", text), text
            assert re.search(rf"celldiag-{IMEI} — DIAG: capture off", text), text

            row.locator("button.cell-modem-off").click()
            _wait(lambda: _by_name(ks, "cellat").get(F + "state") == "disabled"
                  and "enabled=false" in _by_name(ks, "cellat")["kismet.datasource.definition"]
                  and "enabled=false" in _by_name(ks, "celldiag")["kismet.datasource.definition"],
                  what="both sources off")
            assert _by_name(ks, "celldiag").get(D + "mask_preset") == "disabled"

            _wait(lambda: page.locator("tr#cell_modem_group button.cell-modem-on").count() > 0,
                  what="the on button")
            page.locator("tr#cell_modem_group button.cell-modem-on").first.click()
            _wait(lambda: _by_name(ks, "cellat").get(F + "state") == "surveying"
                  and "enabled=true" in _by_name(ks, "cellat")["kismet.datasource.definition"]
                  and "enabled=true" in _by_name(ks, "celldiag")["kismet.datasource.definition"],
                  what="both sources on")


def test_the_modem_row_shows_the_lock_in_force(tmp_path):
    """The lock lives on the AT source; the modem row repeats it."""
    pytest.importorskip("playwright.sync_api")
    from test_cell_web_ui_browser import _data_sources
    from test_cellat_lock import LockableFakeModem
    with LockableFakeModem(extra={**QENG_SERVING, "AT+CGMM": "RM520N-GL"}) as modem:
        d = f"cellat-{IMEI}:atport={modem.port},debug=false,lockstate={tmp_path / 's'}"
        with _data_sources(tmp_path, d) as (ks, page):
            _wait(lambda: _by_name(ks, "cellat").get(F + "lock_channel") == "AUTO",
                  what="lock reported")
            src = page.locator(".k-ds-source", has_text=f"cellat-{IMEI}").first
            src.wait_for(timeout=30000)
            src.click()
            row = page.locator("tr#cell_modem_group").first
            _wait(lambda: "Band / RAT lock: AUTO" in (row.inner_text() if row.count() else ""),
                  what="the lock line")
