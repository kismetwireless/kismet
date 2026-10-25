# SPDX-License-Identifier: Apache-2.0
"""The RawAT record's exchange instants, end to end on the real binary.

``ts_mono_ns`` is taken before the command is sent and ``duration_ms`` is
collapsed. Alone, they cannot say when the answer arrived (a cell reported at
80 mph would be geotagged where it was asked for) or where the time went (a
slow ``AT+QENG`` could be a slow-thinking modem or a long reply). So three
instants follow ``err``: ``tx_done_ns``, ``first_rx_ns``, ``rx_done_ns``.

The formatter's bytes are pinned in ``capture_cell_at/test_atlog.c`` and the
stamping rules in ``capture_cell_at/test_at_serial.c``. This file is the wiring:
the compiled ``kismet_cap_cell_at`` against a PTY modem with a SCRIPTED
think-time and transfer time, so each measured interval has a known value to be
held to. That is the positive control -- an instrument read against delays the
test chose, not against itself.

The modem echoes every command (as a real one does before ``ATE0``). An echo
arrives before any thinking, so a ``first_rx_ns`` stamped on the echo would read
as ~0 think-time; the scripted 250 ms is what shows it is not.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from fake_at_modem import QENG_SERVING, FakeAtModem
from kismet_capture_ipc import CaptureRun

# The staleness-guarded lookup: a binary older than its sources fails instead
# of quietly testing code nobody built.
from test_cellat_ipc import _binary_or_skip  # noqa: E402

IMEI = "351234567890123"
QENG = 'AT+QENG="servingcell"'
CCLK = "AT+CCLK?"
THINK_S = 0.25
TRANSFER_S = 0.15
MS = 1_000_000

#: The six original RawAT keys, then the three exchange instants -- in this
#: order, because the line is reproduced byte for byte.
KEYS = ["ts_mono_ns", "ts_utc", "cmd", "response", "duration_ms", "err",
        "tx_done_ns", "first_rx_ns", "rx_done_ns"]


def _rows(run: CaptureRun) -> "list[dict]":
    return [json.loads(r) for r in run.raw_at]


@pytest.fixture(scope="module")
def paced(tmp_path_factory):
    """One run: QENG paced (think 250 ms, transfer 150 ms), every command echoed,
    AT+CCLK? hung so its exchange runs out its 3 s timeout. Stops once two
    completed QENG exchanges and the CCLK exchange have been emitted."""
    binary = _binary_or_skip()
    atlog = tmp_path_factory.mktemp("atlog") / "run.jsonl"

    def done(run):
        rows = _rows(run)
        qeng = [r for r in rows if r["cmd"] == QENG and r.get("rx_done_ns")]
        return len(qeng) >= 2 and any(r["cmd"] == CCLK for r in rows)

    with FakeAtModem(imei=IMEI, extra={**QENG_SERVING, CCLK: '+CCLK: "26/09/23,13:00:00-24"'},
                     pace={QENG: (THINK_S, TRANSFER_S)}, hang={CCLK},
                     echo=True) as modem:
        definition = (f"cellat-{IMEI}:atport={modem.port},debug=false,"
                      f"atlog={atlog}")
        run = CaptureRun(binary, definition, timeout=30.0, stop_when=done).run()
    return run, atlog


def test_the_premise_the_run_opened_and_emitted_rawat(paced):
    run, _ = paced
    assert run.open_code == 1, run.open_message
    rows = _rows(run)
    assert [r for r in rows if r["cmd"] == QENG and r.get("rx_done_ns")], (
        "no completed QENG exchange -- nothing below measured anything",
        [r["cmd"] for r in rows])


def test_every_row_carries_the_instants_after_the_original_keys(paced):
    for row in _rows(paced[0]):
        assert list(row) == KEYS, row


def test_think_time_and_transfer_time_come_out_separately(paced):
    """Held to the scripted delays. The echo lands at ~0 ms, so think-time at or
    above 250 ms is also the proof that the echo did not start the response."""
    qeng = [r for r in _rows(paced[0]) if r["cmd"] == QENG and r["rx_done_ns"]]
    assert qeng
    for r in qeng:
        think = r["first_rx_ns"] - r["tx_done_ns"]
        transfer = r["rx_done_ns"] - r["first_rx_ns"]
        assert THINK_S * 1e9 * 0.9 <= think < (THINK_S + 1.0) * 1e9, (think / MS, r)
        assert TRANSFER_S * 1e9 * 0.9 <= transfer < (TRANSFER_S + 1.0) * 1e9, (transfer / MS, r)
        assert r["tx_done_ns"] - r["ts_mono_ns"] < 50 * MS, r


def test_the_instants_are_ordered_and_inside_the_exchange(paced):
    """ts_mono_ns <= tx_done <= first_rx <= rx_done <= ts_mono_ns + duration.
    duration_ms is printed to 2 decimals, so the end allows its 5 us rounding."""
    rows = _rows(paced[0])
    assert rows
    for r in rows:
        seq = [r["ts_mono_ns"]] + [r[k] for k in ("tx_done_ns", "first_rx_ns", "rx_done_ns")
                                   if r[k] is not None]
        assert seq == sorted(seq), r
        end = r["ts_mono_ns"] + r["duration_ms"] * MS
        assert seq[-1] <= end + 10_000, r


def test_an_exchange_that_timed_out_has_no_rx_done(paced):
    """AT+CCLK? is hung: the modem echoes it and never answers. TX happened;
    the echo is not a response line, so first_rx is null too; and it never
    completed, so rx_done is null -- a reader can tell this from a completed
    exchange without parsing the response. (The positive control is the QENG
    rows above: the same run, the same code, rx_done set.)"""
    cclk = [r for r in _rows(paced[0]) if r["cmd"] == CCLK]
    assert cclk
    for r in cclk:
        assert r["tx_done_ns"] is not None, r
        assert r["first_rx_ns"] is None, r
        assert r["rx_done_ns"] is None, r
        assert r["duration_ms"] >= 2900, r


def test_an_immediate_error_reply_still_completes(paced):
    """Unscripted commands get an instant ERROR -- a terminal line, so rx_done
    is set and think-time is near zero (no pacing, only the echo before it)."""
    err = [r for r in _rows(paced[0]) if r["response"] == "ERROR"]
    assert err, "no unscripted command was sent -- the premise moved"
    for r in err:
        assert r["rx_done_ns"] is not None and r["first_rx_ns"] is not None, r
        assert r["first_rx_ns"] - r["tx_done_ns"] < 200 * MS, r


def _tee_violations(lines: "list[str]", rows: "list[str]") -> "list[tuple]":
    """Where the atlog= file disagrees with the RawAT rows; empty = consistent.

    The rows are an ordered SUPERSET of the file -- open-time probes precede the
    tee -- so each file line must equal a row, in order. One exception, the
    stop window: the helper writes the file line BEFORE it emits the
    row, and the harness stops the way Kismet does (pipe closed, SIGTERM at
    once), so an exchange that completes in that window has its line but no row.
    Such an orphan has no row with its ts_mono_ns at all, and it started after
    the LAST row the harness received -- so orphans can only trail the file. A
    line whose row is missing but that started earlier, a line whose row exists
    with other bytes, and rows out of order are all still violations."""
    out = []
    row_ts = [json.loads(r)["ts_mono_ns"] for r in rows]
    last = max(row_ts) if row_ts else None
    have = set(row_ts)
    matched = []
    for line in lines:
        ts = json.loads(line)["ts_mono_ns"]
        if ts in have:
            matched.append(line)
        elif last is None or ts <= last:
            out.append(("no RawAT row, and not in the stop window", line))
    it = iter(rows)
    for line in matched:
        if not any(line == row for row in it):
            out.append(("an atlog= line is not a RawAT row, in order", line))
            break
    return out


def test_the_file_tee_is_the_same_bytes_as_the_rawat_rows(paced):
    """One buffer, both sinks: the instants reach the atlog= line and the
    kismetdb row identically, compared per record (see _tee_violations for the
    stop-window tail). A short reply takes well under a millisecond, so the
    exchange after the stop condition often lands in that window."""
    run, atlog = paced
    lines = Path(atlog).read_text().splitlines(keepends=True)
    assert lines, "atlog= wrote nothing"
    assert run.raw_at, "no RawAT rows -- the premise moved"
    violations = _tee_violations(lines, run.raw_at)
    assert not violations, violations


def test_the_tee_comparison_still_rejects_a_real_mismatch():
    """The stop-window allowance must not blind the comparison.
    Synthetic records, no binary: a positive control for _tee_violations."""
    def rec(ts, response="OK"):
        return json.dumps({"ts_mono_ns": ts, "cmd": "AT", "response": response}) + "\n"
    rows = [rec(10), rec(20), rec(30)]
    assert not _tee_violations([rec(20), rec(30)], rows), "an ordered subset is consistent"
    assert not _tee_violations([rec(20), rec(30), rec(40)], rows), (
        "an orphan AFTER the last row is the stop window")
    assert _tee_violations([rec(20), rec(30, "ERROR")], rows), "same exchange, other bytes"
    assert _tee_violations([rec(15), rec(20)], rows), "a missing row BEFORE the last one"
    assert _tee_violations([rec(30), rec(20)], rows), "rows out of order"
