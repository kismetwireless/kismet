"""The celldiag host<->modem-ts64 clock anchor, end to end on a fake modem.

A live celldiag source asks its modem ``DIAG_TS_F`` at START, every
``clock_anchor_sec=`` and at END, and pairs each reply with the host clock as a
``type="ClockAnchor"`` row + a ``<rawlog>.clock_anchor.jsonl`` line. These tests
drive the REAL binary over the datasource IPC against two ptys --
:class:`FakeAtModem` for identity (``atport=``) and :class:`FakeDiagModem` for
DIAG (``diagport=``, ``nomask=true`` so there is no LOG_CONFIG to script) -- so
the scheduling, the in-stream reply scan, the host pairing and both delivery
paths are measured, not inferred from the unit test of the parts.

**The offset assertion is the load-bearing one.** The fake modem runs its
clock ``OFFSET_S`` ahead of the host. A row whose ``source_clock_value`` merely
round-trips the fake's reply proves the scanner works; only recovering
``OFFSET_S`` from ``(host_utc, source_clock_value)`` proves the row pairs the
modem clock with the host clock, which is the whole point of the anchor.

**The END anchor is tested on a graceful pipe close only, on purpose.** Kismet
stops a source with pipe-close + SIGTERM, and the capture framework leaves
SIGTERM at its default disposition, so a Kismet-driven stop runs no teardown at
all -- END included (see ``anchor_end`` in capture_cell_diag.c). The graceful
close is the path END is reachable on (a remote ``--connect`` capture losing its
server), and it is the path asserted here.
"""

from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import (  # noqa: E402
    DIAG_TS_F,
    FakeDiagModem,
    hdlc_frame,
    ts64_to_unix,
)
from celldiag_run import CellDiagRun, _binary_or_skip  # noqa: E402

IMEI = "123456789012347"
FIRMWARE = "RM520NGLAAR03A03M4G"
#: Modem clock minus host clock. Far enough from 0 that a row pairing the modem
#: value with the wrong clock (or with itself) cannot pass by accident.
OFFSET_S = 2.5


def _definition(at: FakeAtModem, dg: FakeDiagModem, **flags) -> str:
    parts = [f"atport={at.port}", f"diagport={dg.port}", "nomask=true",
             "defer=false", "stats_interval=0"]
    parts += [f"{k}={v}" for k, v in flags.items()]
    return f"celldiag-{IMEI}:" + ",".join(parts)


def _rows(run: CellDiagRun) -> list[dict]:
    return [json.loads(js) for js in run.clock_anchors]


def _host_unix(rec: dict) -> float:
    return datetime.fromisoformat(rec["host_utc"].replace("Z", "+00:00")).timestamp()


def _anchors(n: int):
    return lambda run: len(run.clock_anchors) >= n


def test_rows_pair_the_modem_clock_with_the_host_clock():
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(offset_s=OFFSET_S, filler_hz=50) as dg:
        run = CellDiagRun(binary, _definition(at, dg, clock_anchor_sec=1),
                          timeout=20.0, stop_when=_anchors(3)).run()
        replies = list(dg.replies)

    rows = _rows(run)
    assert len(rows) >= 3, (run.errors, run.messages)
    # Not observations: a clock pair must never be counted as a cell.
    assert not any("clock-anchor/1" in o for o in run.observations)

    assert [r["edge"] for r in rows[:3]] == ["start", "periodic", "periodic"]
    assert [r["seq"] for r in rows] == list(range(len(rows)))
    for r in rows:
        assert r["schema"] == "clock-anchor/1"
        assert r["transport"] == "diag"
        assert r["source_clock_kind"] == "modem_ts64"
        # A string, not a number: a GPS-epoch ts64 is past 2^53.
        assert isinstance(r["source_clock_value"], str)
        assert re.fullmatch(r"[0-9A-F-]{36}", r["source_name"]), r["source_name"]
        assert 0 < r["host_rtt_ns"] < 1_000_000_000

    # Every row is one of the modem's replies, in reply order.
    assert [int(r["source_clock_value"]) for r in rows] == replies[:len(rows)]

    # The measurement: host_utc and the modem value recover the fake's skew.
    for r in rows:
        offset = ts64_to_unix(int(r["source_clock_value"])) - _host_unix(r)
        assert offset == pytest.approx(OFFSET_S, abs=0.05), r


def test_periodic_rows_follow_the_cadence():
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, FakeDiagModem() as dg:
        run = CellDiagRun(binary, _definition(at, dg, clock_anchor_sec=1),
                          timeout=20.0, stop_when=_anchors(4)).run()
    gaps = [b["host_mono_ns"] - a["host_mono_ns"]
            for a, b in zip(_rows(run), _rows(run)[1:])]
    assert len(gaps) >= 3
    for g in gaps:
        # 1 s cadence; the loop polls every 250 ms, so a tick may land late.
        assert 0.95e9 <= g <= 1.6e9, gaps


def test_sidecar_carries_every_row_plus_the_end_anchor(tmp_path):
    binary = _binary_or_skip()
    rawlog = tmp_path / "cap.hdlc"
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(offset_s=OFFSET_S, filler_hz=50) as dg:
        run = CellDiagRun(binary, _definition(at, dg, clock_anchor_sec=1,
                                              rawlog=rawlog),
                          timeout=20.0, stop_when=_anchors(2),
                          graceful_close_s=8.0).run()
        replies = list(dg.replies)

    # It exited on EOF, not on the harness's SIGTERM -- else END never ran.
    assert run.exit_code is not None and run.exit_code >= 0, run.exit_code

    lines = (tmp_path / "cap.hdlc.clock_anchor.jsonl").read_text().splitlines()
    rows = [js.rstrip("\n") for js in run.clock_anchors]
    # Same bytes in both places: one formatter, two deliveries.
    assert lines[:len(rows)] == rows
    end = json.loads(lines[-1])
    assert end["edge"] == "end"
    assert end["seq"] == len(lines) - 1
    assert int(end["source_clock_value"]) == replies[-1]
    offset = ts64_to_unix(int(end["source_clock_value"])) - _host_unix(end)
    assert offset == pytest.approx(OFFSET_S, abs=0.05)

    # The replies themselves are in the .hdlc tee, byte-exact, END's included:
    # the rawlog stays a complete record of what the port produced.
    raw = rawlog.read_bytes()
    for ts64 in replies:
        assert hdlc_frame(bytes((DIAG_TS_F,)) + ts64.to_bytes(8, "little")) in raw


def test_a_modem_that_rejects_ts_f_is_asked_once():
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(answer="reject") as dg:
        run = CellDiagRun(binary, _definition(at, dg, clock_anchor_sec=1),
                          timeout=3.5).run()
        requests = dg.ts_f_requests()
    assert requests == 1
    assert run.clock_anchors == []
    assert any("rejected DIAG_TS_F" in m for m in run.messages), run.messages


def test_an_unanswered_modem_stops_being_asked():
    """Silence is not BAD_CMD: some parts drop an unknown command. Three
    unanswered requests (2 s timeout each) and the source stops asking, loudly."""
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(answer="silent") as dg:
        run = CellDiagRun(binary, _definition(at, dg, clock_anchor_sec=1),
                          timeout=9.0).run()
        requests = dg.ts_f_requests()
    assert requests == 3
    assert run.clock_anchors == []
    assert any("3 consecutive DIAG_TS_F requests went unanswered" in m
               for m in run.messages), run.messages


def test_clock_anchor_sec_zero_keeps_the_start_anchor_only():
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, FakeDiagModem() as dg:
        run = CellDiagRun(binary, _definition(at, dg, clock_anchor_sec=0),
                          timeout=3.0).run()
        requests = dg.ts_f_requests()
    assert [r["edge"] for r in _rows(run)] == ["start"]
    assert requests == 1


def test_an_invalid_cadence_is_reported_and_the_default_kept():
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, FakeDiagModem() as dg:
        run = CellDiagRun(binary, _definition(at, dg, clock_anchor_sec="soon"),
                          timeout=10.0, stop_when=_anchors(1)).run()
    assert any("ignoring invalid clock_anchor_sec='soon' (keeping 30s)" in m
               for m in run.messages), run.messages
    assert [r["edge"] for r in _rows(run)] == ["start"]


def test_a_replay_source_never_asks(tmp_path):
    """A file has no clock: no request, no row, no sidecar -- and it must not
    try, since replay has no DIAG fd to write the request into."""
    binary = _binary_or_skip()
    replay = tmp_path / "in.hdlc"
    replay.write_bytes(b"".join(hdlc_frame(bytes((0x10, 0x00)) + bytes(20))
                                for _ in range(50)))
    out = tmp_path / "out.hdlc"
    run = CellDiagRun(binary,
                      f"celldiag-{IMEI}:replay={replay},"
                      f"rawlog={out},clock_anchor_sec=1",
                      timeout=5.0).run()
    time.sleep(0.2)
    # Positive control first: the replay really ran through the read loop and
    # its tee -- otherwise "no anchors" would be true of a source that never
    # opened at all.
    assert out.read_bytes() == replay.read_bytes(), (run.errors, run.messages)
    assert run.clock_anchors == []
    assert not (tmp_path / "out.hdlc.clock_anchor.jsonl").exists()
