"""The mask-preset round-trip, on a real modem.

**Why this cannot be done offline.** The route round trips over a replay
source drive the same ``update_definition`` route and measure the **F3**
selector end to end -- but a ``replay=`` source hard-codes ``mask_preset`` to
the literal ``"replay"`` (``capture_cell_diag.c``): there is no modem, so there
is no LOG_CONFIG handshake and no armed mask to report. The mask half needs
hardware.

This file runs that bench observation as a test. It skips cleanly when no
DIAG modem is attached.

**The two negative controls, both load-bearing.**

1. The pre-switch value is asserted to be ``wardrive`` and **not** ``full``
   *before* the switch. Without that, ``await_field("mask_preset", "full")``
   would pass on a source that reported ``full`` from the start and never
   moved.
2. The preset is switched **back**. A one-way test passes against a field
   that latches on first write; only a round trip shows the control is live
   in both directions.
"""

from __future__ import annotations

import re
import subprocess
import sys

from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_celldiag_server_routes import (  # noqa: E402
    KP_ROOT,
    KismetServer,
    _base,
    _server_or_skip,
)

HELPER = KP_ROOT / "capture_cell_diag" / "kismet_cap_cell_diag"

#: ``--list`` line shape: ``celldiag-<15 digits> (<desc>)``. Using the helper's
#: OWN enumerator rather than a private scan is deliberate -- it is the code
#: the source itself runs, so a modem this test can see is a modem the source
#: can open, and a discovery bug cannot make the test skip while the feature
#: works (or the reverse).
_LIST_RE = re.compile(r"^\s*(celldiag-(\d{15}))\s+\((.*)\)\s*$")


def _live_modem_or_skip() -> tuple[str, str]:
    """Return (interface, description) for the first attached DIAG modem."""
    if not HELPER.exists():
        pytest.skip(f"{HELPER} not built")
    try:
        p = subprocess.run([str(HELPER), "--list"], capture_output=True,
                           text=True, timeout=180)
    except subprocess.TimeoutExpired:  # pragma: no cover - bench flake
        pytest.skip("kismet_cap_cell_diag --list timed out")
    # `--list` writes to stderr, not stdout. Reading `.stdout` alone would make
    # this file skip with "no DIAG modem attached" with modems attached -- a
    # false absence that looks exactly like the honest one.
    out = (p.stderr or "") + (p.stdout or "")
    for line in out.splitlines():
        m = _LIST_RE.match(line)
        if m:
            return m.group(1), m.group(3)
    pytest.skip(f"no DIAG modem attached; --list said:\n{out}")


@pytest.fixture()
def live_server(tmp_path: Path):
    _server_or_skip()
    iface, desc = _live_modem_or_skip()
    # `retry=false` for the same reason the replay harness needs it: it makes
    # this test the only thing that opens the source, so "the reopen brought
    # it back" is attributable to the reopen.
    srcdef = (f"{iface}:mask=wardrive,f3=off,name=livemask,"
              f"retry=false")
    with KismetServer(tmp_path, srcdef) as srv:
        srv.modem_desc = desc  # type: ignore[attr-defined]
        srv.await_running(True)
        yield srv


def test_the_mask_preset_round_trips_on_a_real_modem(live_server):
    """wardrive -> full -> wardrive, measured on what the binary reports."""
    row = live_server.ensure_running()

    # ── negative control 1: the source starts on `wardrive`, NOT on `full` ──
    live_server.await_field("mask_preset", "wardrive")
    before = live_server.source()["kismet.datasource.celldiag.mask_preset"]
    assert before != "full", (
        "the source already reported 'full' before the switch, so the "
        "post-switch assertion below would prove nothing")
    assert before != "replay", (
        "this is supposed to be a live modem, but the source reported the "
        "replay sentinel -- the fixture picked a replay source somehow")

    base = _base(row)


    def switch(preset: str) -> None:
        """close -> update_definition -> open, the sequence the panel uses.

        The order matters: the route refuses a running source, so
        update-first returns 500 every time. See
        `test_update_definition_refuses_a_running_source`.

        The 200 is asserted but proves nothing about the mask: a refused
        celldiag setting returns success=1. The real assertion is the
        `await_field` at the call site, on what the binary reports.
        """
        live_server.get(base + "close_source.cmd")
        live_server.await_running(False)
        status, _ = live_server.post(base + "update_definition.cmd",
                                     {"options": {"mask": preset}})
        assert status == 200
        live_server.get(base + "open_source.cmd")
        live_server.await_running(True)

    # ── the switch under test ────────────────────────────────────────────
    switch("full")
    live_server.await_field("mask_preset", "full")

    # ── negative control 2: and back, so a latching field cannot pass ────
    switch("wardrive")
    live_server.await_field("mask_preset", "wardrive")
