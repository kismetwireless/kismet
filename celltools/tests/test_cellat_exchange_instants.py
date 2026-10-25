# SPDX-License-Identifier: Apache-2.0
"""cellat consumes the RawAT exchange instants, on the real binary.

Every RawAT row carries ``tx_done_ns`` / ``first_rx_ns`` / ``rx_done_ns``.
Two products use them:

1. **Every AT-derived observation names the exchange it came from.** Its
   ``prov`` block carries ``at_ts_mono_ns`` (the RawAT row's ``ts_mono_ns``,
   unique per exchange: the join key) and ``rx_done_ns`` (when the answer was
   complete). An offline tool can then geotag the observation at the moment the
   modem's answer was in, instead of at SQLite-insert time. Tagged at PARSE
   time: Telit's neighbour path sends ``AT#MONI=0`` after its parse, so "the
   last exchange" at emit time would name the wrong command.
2. **The AT ClockAnchor is stamped inside its own exchange,** transport-uniform
   with the DIAG anchor: ``host_mono_ns`` / ``host_utc`` are the
   MIDPOINT of ``[tx_done, first_rx]`` of the ``AT+CCLK?`` exchange -- the
   modem read its RTC after the command left the host and before the first
   byte of its answer -- and ``host_rtt_ns`` is that window's width, so the
   anchor is wrong by at most ``host_rtt_ns / 2``. A host instant taken
   before the command is sent would leave the whole exchange as unaccounted
   uncertainty.

The modem is a PTY fake with SCRIPTED think-times, so every interval has a
value the test chose (the positive control); no host port is touched.
"""
from __future__ import annotations

import calendar
import json
from datetime import datetime

import pytest

from fake_at_modem import QENG_SERVING, FakeAtModem
from kismet_capture_ipc import CaptureRun
from test_cellat_ipc import _binary_or_skip  # noqa: E402  (staleness-guarded)

IMEI = "351234567890123"
QENG = 'AT+QENG="servingcell"'
CCLK = "AT+CCLK?"
QENG_THINK_S, QENG_TRANSFER_S = 0.25, 0.15
CCLK_THINK_S = 0.30
MS = 1_000_000


def _utc_ns(iso: str) -> int:
    """``YYYY-MM-DDTHH:MM:SS.uuuuuuZ`` as UTC nanoseconds (timegm, never local)."""
    dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S.%fZ")
    return calendar.timegm(dt.timetuple()) * 1_000_000_000 + dt.microsecond * 1000


@pytest.fixture(scope="module")
def run():
    rows = lambda r: [json.loads(x) for x in r.raw_at]  # noqa: E731

    def done(r):
        qeng = [x for x in rows(r) if x["cmd"] == QENG and x.get("rx_done_ns")]
        obs = [o for o in r.observations if '"prov"' in o]
        return len(qeng) >= 3 and len(obs) >= 2 and r.clock_anchors

    with FakeAtModem(imei=IMEI, echo=True,
                     extra={**QENG_SERVING, CCLK: '+CCLK: "26/09/23,13:00:00-24"'},
                     pace={QENG: (QENG_THINK_S, QENG_TRANSFER_S),
                           CCLK: (CCLK_THINK_S, 0.0)}) as modem:
        r = CaptureRun(_binary_or_skip(), f"cellat-{IMEI}:atport={modem.port},debug=false",
                       timeout=40.0, stop_when=done).run()
    assert r.open_code == 1, r.open_message
    return r, rows(r)


def _observations(r):
    return [json.loads(o) for o in r.observations if '"prov"' in o]


def test_every_at_observation_names_the_exchange_it_came_from(run):
    r, rows = run
    by_key = {x["ts_mono_ns"]: x for x in rows}
    obs = _observations(r)
    assert obs, "no AT observation was relayed -- nothing below measured anything"
    for o in obs:
        p = o["prov"]
        assert "at_ts_mono_ns" in p, p
        row = by_key.get(p["at_ts_mono_ns"])
        assert row is not None, f"prov names no RawAT row: {p}"
        assert row["cmd"] == QENG, (row["cmd"], p)
        assert p["rx_done_ns"] == row["rx_done_ns"], (p, row)


def test_an_observation_is_complete_at_rx_done_not_at_ask_time(run):
    """Held to the script: the answer was complete think + transfer (400 ms)
    after the ask, which is exactly the gap between the two stamps it carries."""
    r, _ = run
    for o in _observations(r):
        p = o["prov"]
        gap = p["rx_done_ns"] - p["at_ts_mono_ns"]
        want = (QENG_THINK_S + QENG_TRANSFER_S) * 1e9
        assert 0.9 * want <= gap < want + 1e9, (gap / MS, p)


def _anchor_exchanges(r, rows):
    anchors = [json.loads(a) for a in r.clock_anchors]
    cclk = [x for x in rows if x["cmd"] == CCLK and x.get("first_rx_ns")]
    assert anchors and cclk, (len(anchors), len(cclk))
    out = []
    for a in anchors:
        row = [x for x in cclk if x["tx_done_ns"] <= a["host_mono_ns"] <= x["first_rx_ns"]]
        assert len(row) == 1, f"the anchor's host instant lies inside no CCLK exchange: {a}"
        out.append((a, row[0]))
    return out


def test_the_clock_anchor_is_the_midpoint_of_its_rtc_read_window(run):
    r, rows = run
    for a, x in _anchor_exchanges(r, rows):
        rtt = x["first_rx_ns"] - x["tx_done_ns"]
        assert a["host_rtt_ns"] == rtt, (a, x)
        assert abs(a["host_mono_ns"] - (x["tx_done_ns"] + rtt // 2)) <= 1, (a, x)
        # the window is the modem's scripted 300 ms of think, not the echo
        assert rtt >= 0.9 * CCLK_THINK_S * 1e9, rtt / MS


def test_the_anchor_wall_clock_moves_with_its_monotonic_instant(run):
    """host_utc is not the pre-send wall clock with a new host_mono_ns glued on:
    both moved by the same amount from the exchange's own (ts_utc, ts_mono_ns)."""
    r, rows = run
    for a, x in _anchor_exchanges(r, rows):
        d_wall = _utc_ns(a["host_utc"]) - _utc_ns(x["ts_utc"])
        d_mono = a["host_mono_ns"] - x["ts_mono_ns"]
        assert abs(d_wall - d_mono) < 2 * MS, (d_wall / MS, d_mono / MS, a, x)


def test_a_telit_neighbour_names_its_own_moni_exchange_not_the_reset():
    """Why the tag is taken at PARSE time: the Telit neighbour poll is
    AT#MONI=1, AT#MONI, AT#MONI=2, AT#MONI, then AT#MONI=0. Each MONI row must
    name the AT#MONI exchange it was parsed from -- never the =0 reset that is
    the last exchange when the observations are emitted."""
    from test_cellat_telit_pci_join import (  # noqa: E402
        IMEI as TELIT_IMEI, TELIT_FIRMWARE, _telit_responses)

    rows = lambda r: [json.loads(x) for x in r.raw_at]  # noqa: E731

    def done(r):
        return sum('"AT#MONI"' in o for o in r.observations) >= 2

    with FakeAtModem(imei=TELIT_IMEI, firmware=TELIT_FIRMWARE, manufacturer="Telit",
                     extra=_telit_responses()) as modem:
        r = CaptureRun(_binary_or_skip(), f"cellat-{TELIT_IMEI}:atport={modem.port},debug=false",
                       timeout=40.0, stop_when=done).run()
    assert r.open_code == 1, r.open_message
    by_key = {x["ts_mono_ns"]: x for x in rows(r)}
    named = {}
    for o in _observations(r):
        p = o["prov"]
        row = by_key.get(p.get("at_ts_mono_ns"))
        assert row is not None, f"prov names no RawAT row: {p}"
        named.setdefault(p["origin"], set()).add(row["cmd"])
    assert named.get("AT#MONI") == {"AT#MONI"}, named
    assert named.get("AT#RFSTS") == {"AT#RFSTS"}, named
