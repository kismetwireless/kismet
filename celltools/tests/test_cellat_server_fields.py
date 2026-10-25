# SPDX-License-Identifier: Apache-2.0
"""cellat's readback through a REAL Kismet server.

``test_cellat_stats.py`` proves the helper sends the ``cellat_stats`` line;
``test_cellat_panel_contract.py`` proves the three ends agree on names.
Neither proves the thing the panel actually consumes: that a running server,
given a cellat source, puts the values into ``/datasource/all_sources.json``.
That is this file, driven the way the web UI reads it -- an isolated
``kismet`` (``KismetServer``, private home/conf, ephemeral port) with a cellat
source pointed at a fake modem.

What it pins:

* the fields are populated from the line (profile, intervals, port, counters);
* a thing the source never configured stays at the REGISTERED DEFAULT --
  ``atlog_path == ""`` for a source with no ``atlog=`` -- which is exactly the
  sentinel the panel reads as "off". If the server ever stamped something else
  there, the panel's absence rule would break from this side;
* the stats line builds no device: the only devices are real cells.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from fake_at_modem import QENG_SERVING, QSCAN_CAPABLE, FakeAtModem
from test_celldiag_server_routes import KP_ROOT, KismetServer, _server_or_skip

IMEI = "351234567890123"
#: the fake answers AT+QSCAN=? (QSCAN_CAPABLE), so fullscan_capable must arrive as
#: 1 -- a value the registered default (0) cannot fake. With an incapable modem
#: a broken boolean parse on the server would read identically to a real 0.
QSCAN_FIRMWARE = "RM500Q-GLAB-R13A03M4G"
F = "kismet.datasource.cellat."

#: The server's cellat code. `_server_or_skip` only checks the route files, so a
#: server built before datasource_cell_at changed would run the OLD field code
#: and report its absence as a failure of the code under test.
_CELLAT_SERVER_DEPS = ("datasource_cell_at.cc", "datasource_cell_at.h")


def _fresh_server_or_skip() -> Path:
    server = _server_or_skip()
    mtime = server.stat().st_mtime
    stale = [d for d in _CELLAT_SERVER_DEPS
             if (KP_ROOT / d).stat().st_mtime > mtime]
    if stale:
        pytest.skip(f"kismet is older than {', '.join(stale)} -- run `make kismet`")
    return server


def _await(ks: KismetServer, pred, timeout: float = 40.0) -> dict:
    deadline = time.monotonic() + timeout
    row = None
    while time.monotonic() < deadline:
        row = ks.source()
        if row is not None and pred(row):
            return row
        time.sleep(0.5)
    raise AssertionError(f"condition never held; last row fields: "
                         f"{ {k: v for k, v in (row or {}).items() if k.startswith(F)} }"
                         f"\n{ks.tail()}")


@pytest.fixture(scope="module")
def served(tmp_path_factory):
    _fresh_server_or_skip()
    tmp = tmp_path_factory.mktemp("cellat_server")
    with FakeAtModem(imei=IMEI, firmware=QSCAN_FIRMWARE,
                     extra={**QENG_SERVING, **QSCAN_CAPABLE}) as modem:
        with KismetServer(tmp, f"cellat-{IMEI}:atport={modem.port},"
                               "strategy=walking,debug=false") as ks:
            # state == surveying as well: this modem full-scans at start, and a
            # poll landing between the "full_scan" line and the one after it
            # would otherwise hand the tests a mid-scan row.
            row = _await(ks, lambda r: r.get(F + "stats_epoch", 0) > 0
                         and r.get(F + "obs_total", 0) > 0
                         and r.get(F + "state") == "surveying")
            devices = ks.get("devices/views/all/devices.json")
            yield row, devices, modem.port


def test_the_profile_and_intervals_reach_the_server(served):
    row, _, _ = served
    assert row[F + "state"] == "surveying"
    assert row[F + "strategy"] == "walking"
    assert row[F + "strategy_label"] == "Walking"
    assert row[F + "fullscan_interval_ms"] == 300000
    assert row[F + "serving_interval_ms"] == 2000


def test_the_counters_and_identity_reach_the_server(served):
    row, _, port = served
    assert row[F + "obs_total"] > 0
    assert row[F + "last_obs_epoch"] > 0
    assert row[F + "rawat_records"] > 0
    assert row[F + "at_port"] == port
    assert row[F + "stats_interval_s"] == 5
    # Probed and present. A JSON boolean on the wire, a uint8 here: a server
    # that type-tested it as a number would skip every emit and leave it 0.
    assert row[F + "fullscan_capable"] == 1


def test_an_unconfigured_tee_stays_at_the_sentinel_the_panel_reads(served):
    """The helper omits atlog_* when no atlog= was given; the server must
    leave the registered defaults alone, because `atlog_path === ""` is how
    the panel knows to say "off" instead of "0 records"."""
    row, _, _ = served
    assert row[F + "atlog_path"] == ""
    assert row[F + "atlog_active"] == 0
    assert row[F + "anchor_last_epoch"] == 0, (
        "the fake modem ERRORs AT+CCLK?, so no anchor was ever sent")


def test_the_stats_line_builds_no_device(served):
    _, devices, _ = served
    phys = {d.get("kismet.device.base.phyname") for d in devices}
    assert phys <= {"Cellular"}, phys
    assert devices, "the premise: the serving poll should have built a cell"
