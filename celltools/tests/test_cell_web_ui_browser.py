# SPDX-License-Identifier: Apache-2.0
"""The cell source panels, driven in a REAL BROWSER against a REAL server.

The structural panel tests read the JavaScript source; this file is the
behavioural half. A headless Chromium logs into an isolated ``kismet`` (the
``KismetServer`` harness, serving this tree's ``http_data/``), opens Data
Sources exactly as an operator does, and asserts on what the panel SHOWS after
real clicks.

It pins two things no structural test can see:

* **Paths are not rendered as HTML entities.** The UI sanitises every
  datasource object (``/`` -> ``&#x2F;``), so a ``.text()`` row would print the
  entities: ``port &#x2F;dev&#x2F;pts&#x2F;5``. The value is right; only a
  browser shows whether its rendering is.
* **Controls are not rebuilt every second.** If the 1 s refresh replaced the
  row, a chosen-but-not-applied profile would snap back and a half-typed path
  would vanish. The same holds for the celldiag mask/F3 selectors and raw-tee
  input.

Skips (never fails) without Playwright or a Chromium: this is an operator-host
check, and the rest of ``celltools`` must stay runnable with pytest alone.
Set ``CELL_UI_CHROMIUM`` to a browser binary to override discovery.
"""
from __future__ import annotations

import os
import re
import shutil
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from fake_at_modem import QENG_SERVING, FakeAtModem
from test_cellat_server_fields import _fresh_server_or_skip
from test_celldiag_server_routes import KismetServer

playwright_api = pytest.importorskip("playwright.sync_api")

TREE = Path(__file__).resolve().parents[2]
IMEI = "351234567890123"
DIAG_IMEI = "000000000000000"


def _chromium_or_skip() -> "str | None":
    """A browser binary, or None to use Playwright's own download."""
    env = os.environ.get("CELL_UI_CHROMIUM")
    if env:
        return env
    for name in ("chromium", "chromium-browser", "google-chrome"):
        found = shutil.which(name)
        if found:
            return found
    # macOS keeps browsers in app bundles, never on PATH.
    for app in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium"):
        if os.access(app, os.X_OK):
            return app
    return None   # let Playwright try its managed build; launch() skips below


class _UiServer(KismetServer):
    """KismetServer that also serves THIS tree's web UI.

    The harness's copied conf keeps the stock ``httpd_home=%S/kismet/httpd/``,
    which in a build tree is the server binary, not a directory -- so / was a
    404. Pointing it at ``http_data/`` serves the code under test.
    """

    def __init__(self, tmp_path: Path, srcdef: str) -> None:
        super().__init__(tmp_path, srcdef)
        with (self.conf / "kismet_site.conf").open("a") as fp:
            fp.write(f"httpd_home={TREE / 'http_data'}/\n")


class _Panel:
    """The Data Sources panel of one logged-in page."""

    def __init__(self, page, source_name: str) -> None:
        self.page = page
        self.source_name = source_name

    def row(self, row_id: str) -> str:
        loc = self.page.locator(f"tr#{row_id}")
        return loc.inner_text() if loc.count() else ""

    def await_row(self, row_id: str, needle: str, timeout: float = 20.0) -> str:
        deadline = time.monotonic() + timeout
        text = ""
        while time.monotonic() < deadline:
            text = self.row(row_id)
            if needle in text:
                return text
            time.sleep(0.5)
        raise AssertionError(f"row {row_id} never showed {needle!r}; last: {text!r}")


@contextmanager
def _data_sources(tmp_path: Path, srcdef: "str | None"):
    """Server + browser + login + the Data Sources panel open: (server, page).

    ``srcdef=None`` starts the server with NO source, the discover-and-enable journey."""
    _fresh_server_or_skip()
    exe = _chromium_or_skip()
    with _UiServer(tmp_path, srcdef) as ks:
        with playwright_api.sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(executable_path=exe, headless=True,
                                             args=["--no-sandbox"])
            except Exception as e:  # no usable browser on this host
                pytest.skip(f"no launchable Chromium ({str(e).splitlines()[0][:120]})")
            try:
                page = browser.new_page(viewport={"width": 1400, "height": 1000})
                page.on("dialog", lambda d: d.accept())   # the controls' confirm()s
                page.goto(f"http://127.0.0.1:{ks.port}/", wait_until="networkidle")
                page.locator("input[type=text]").first.fill(ks.USER)
                page.fill("input[type=password]", ks.PASSWD)
                page.click("text=Log in")
                # Wait on the STATE, not a sleep: the menu opened before the
                # login dialog closed shows nothing clickable.
                page.locator("input[type=password]").wait_for(state="hidden", timeout=20000)
                # The menu ignores a click that lands while the UI is still
                # initialising after login, so retry "open, check visible"
                # rather than guessing a delay.
                item = page.locator("#datasource_sources2")
                for _ in range(20):
                    if item.is_visible():
                        break
                    page.locator(".fa-bars").first.click(timeout=15000)
                    time.sleep(1.0)
                assert item.is_visible(), "the sidebar never opened"
                item.click()
                yield ks, page
            finally:
                browser.close()


@contextmanager
def _panel(tmp_path: Path, srcdef: str, source_name: str):
    """Server + browser + login + Data Sources + the source expanded."""
    with _data_sources(tmp_path, srcdef) as (_ks, page):
        src = page.locator(".k-ds-source", has_text=source_name).first
        src.wait_for(timeout=30000)
        src.click()
        yield _Panel(page, source_name)


def test_the_cellat_panel_renders_its_readback(tmp_path):
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with _panel(tmp_path, f"cellat-{IMEI}:atport={modem.port},strategy=walking,"
                              "debug=false", f"cellat-{IMEI}") as ui:
            ui.await_row("cellat_state", "surveying")
            ui.await_row("cellat_profile", "Walking (walking)")
            ui.await_row("cellat_obs", "total")
            assert "off (no atlog= configured)" in ui.row("cellat_atlog")
            assert "none yet" in ui.row("cellat_anchor")
            modem_row = ui.await_row("cellat_modem", "port ")
            # Paths must not render as HTML entities.
            assert modem.port in modem_row and "&#x2F;" not in modem_row, modem_row
            # This fake modem has no full-scan command, so the profiles that
            # need one are offered but disabled.
            stationary = ui.page.locator("tr#cellat_profile option[value=stationary]")
            assert stationary.get_attribute("disabled") is not None


def test_an_edit_survives_the_one_second_refresh(tmp_path):
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with _panel(tmp_path, f"cellat-{IMEI}:atport={modem.port},strategy=walking,"
                              "debug=false", f"cellat-{IMEI}") as ui:
            ui.await_row("cellat_profile", "Walking")
            ui.page.locator("tr#cellat_profile select").select_option("serving_only")
            ui.page.locator("tr#cellat_atlog input").fill("/tmp/typed.jsonl")
            time.sleep(3.5)   # three refreshes
            assert ui.page.locator("tr#cellat_profile select").input_value() == "serving_only"
            assert ui.page.locator("tr#cellat_atlog input").input_value() == "/tmp/typed.jsonl"


def test_the_profile_is_switched_from_the_browser(tmp_path):
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with _panel(tmp_path, f"cellat-{IMEI}:atport={modem.port},strategy=walking,"
                              "debug=false", f"cellat-{IMEI}") as ui:
            ui.await_row("cellat_profile", "Walking")
            ui.page.locator("tr#cellat_profile select").select_option("serving_only")
            ui.page.locator("tr#cellat_profile button", has_text="Apply").click()
            text = ui.await_row("cellat_profile", "Serving cell only (serving_only)")
            assert "neighbors off" in text, text
            assert modem.commands.count("AT+CGSN") == 1, "the switch restarted the source"


def test_the_at_log_is_started_and_stopped_from_the_browser(tmp_path):
    target = tmp_path / "from-the-browser.jsonl"
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with _panel(tmp_path, f"cellat-{IMEI}:atport={modem.port},debug=false",
                    f"cellat-{IMEI}") as ui:
            ui.await_row("cellat_atlog", "off (no atlog= configured)")
            ui.page.locator("tr#cellat_atlog input").fill(str(target))
            ui.page.locator("tr#cellat_atlog button", has_text="Start AT log").click()
            ui.await_row("cellat_atlog", str(target))
            # Stop only once the row reports records, not the moment the path
            # appears: polls run every 2 s, so a start-then-immediate-stop can
            # legitimately write nothing (this test flaked exactly that way).
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                m = re.search(r"\((\d+) records", ui.row("cellat_atlog"))
                if m and int(m.group(1)) > 0:
                    break
                time.sleep(0.5)
            else:
                raise AssertionError(f"no records reported: {ui.row('cellat_atlog')!r}")
            ui.page.locator("tr#cellat_atlog button", has_text="Stop AT log").click()
            text = ui.await_row("cellat_atlog", ", stopped")
            assert str(target) in text, "a stopped log must keep its path"
            assert target.exists() and target.read_text().strip(), "nothing was written"


def test_a_disabled_source_is_enabled_from_the_browser(tmp_path):
    """The Capture switch turns a source defined disabled on, in the browser."""
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with _panel(tmp_path, f"cellat-{IMEI}:atport={modem.port},enabled=false,"
                              "debug=false", f"cellat-{IMEI}") as ui:
            ui.await_row("cellat_state", "disabled")
            assert modem.commands == []
            ui.page.locator("tr#cellat_capture button", has_text="Enable capture").click()
            ui.await_row("cellat_state", "surveying", timeout=40.0)
            assert "AT+CGSN" in modem.commands


def test_a_disabled_celldiag_source_does_not_read_as_dead(tmp_path):
    """A disabled celldiag source reads as disabled, not DEAD, in the browser."""
    with _panel(tmp_path, f"celldiag-{DIAG_IMEI}:enabled=false",
                f"celldiag-{DIAG_IMEI}") as ui:
        text = ui.await_row("celldiag_helper", "capture is disabled")
        assert "DEAD" not in text, text
        assert "Enable capture" in ui.row("celldiag_capture")
        assert ui.row("celldiag_obs") == "", "a disabled source rendered counters"
