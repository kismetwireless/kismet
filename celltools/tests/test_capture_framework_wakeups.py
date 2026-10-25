# SPDX-License-Identifier: Apache-2.0
"""The capture framework's output-ring signalling: two wakeups that must not be lost.

Every ``kismet_cap_*`` helper hands its frames to ``capture_framework.c``'s
output ring and lets the framework's I/O thread write them to Kismet. Two
signals cross that ring:

**Helper -> I/O thread ("there is something to write").** ``cf_handler_loop()``
builds its write set *before* it blocks in ``select()`` for up to 500 ms, so
without an explicit wakeup a frame committed while it is parked sits in the
ring until the timeout or an unrelated server frame. Every frame would pay
0-500 ms of latency, and at a Kismet stop (pipe close + SIGTERM, no teardown)
whatever was still waiting would be lost: the last ~0.5-1 s of a live stream.

**I/O thread -> helper ("the ring has room again").**
``cf_handler_wait_ringbuffer()`` must wait on the flush condvar under its mutex
and with a predicate. Otherwise a flush that finishes between the caller's
failed send and its wait leaves it parked until some unrelated write
broadcasts again. On the celldiag and cellat helpers that caller is the thread
reading the modem.

The probe's modes and what a lost wakeup looks like in each:

====================  ==========================================================
commit-latency        every frame waits out the 500 ms select timeout
                      (lockstep: a source that commits just after each flush
                      always waits out the remainder). Woken: ~100 us.
wait-after-flush      the caller parks until the unrelated broadcast the probe
                      sends at 1 s. Woken: ~0.1 ms.
race                  callers still parked 50 ms after the flush finished.
                      Woken: none.
====================  ==========================================================

A third hazard sits in the same loop: a ``write()`` failing with EAGAIN/EINTR
must not fall through to a consume of ``(size_t) -1`` bytes, which would
discard the whole ring. It is pinned here by fault injection.

The probe (``cf_wakeup_probe.c``) links the tree's ``libkismetdatasource.a`` and
drives the framework's public calls directly: no server, no capture source, no
modem. The last two tests drive the real celldiag binary through the IPC
harness.
"""

from __future__ import annotations

import re
import shutil
import statistics
import subprocess
import time
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
TREE = TESTS.parents[1]
LIB = TREE / "libkismetdatasource.a"
PROBE_SRC = TESTS / "cf_wakeup_probe.c"
#: The sources the probe measures. A library older than any of them is a stale
#: artifact, and a green run against it reports on code nobody built.
LIB_SOURCES = ("capture_framework.c", "capture_framework.h", "simple_ringbuf_c.c",
               "simple_ringbuf_c.h")


def _makefile_var(name: str) -> str:
    text = (TREE / "Makefile.inc").read_text(errors="replace")
    hit = re.search(rf"^{name}\s*=\s*(.*)$", text, re.M)
    return hit.group(1).strip() if hit else ""


@pytest.fixture(scope="module")
def probe(tmp_path_factory) -> Path:
    """Build cf_wakeup_probe against the tree's datasource library.

    Skips on a tree nobody has configured and built (the library and config.h
    are build products); FAILS on a library older than its sources, for the
    same reason ``_fail_if_binary_is_stale`` does -- stale is rot, not absence.
    """
    if not LIB.exists() or not (TREE / "config.h").exists() or not (TREE / "Makefile.inc").exists():
        pytest.skip(f"{LIB.name} not built (run ./configure && make {LIB.name} in {TREE})")
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler to build cf_wakeup_probe")
    newest = max((TREE / s).stat().st_mtime for s in LIB_SOURCES)
    if LIB.stat().st_mtime < newest:
        pytest.fail(f"{LIB.name} is older than its sources ({', '.join(LIB_SOURCES)}): "
                    f"run `make {LIB.name}` in {TREE} and re-run")
    out = tmp_path_factory.mktemp("cfprobe") / "cf_wakeup_probe"
    libs = f"{_makefile_var('CAPLIBS')} {_makefile_var('PTHREAD_LIBS')} -lm".split()
    build = subprocess.run(
        [cc, "-O1", "-g", "-pthread", f"-I{TREE}", str(PROBE_SRC), str(LIB),
         "-o", str(out), *libs],
        capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, f"probe build failed:\n{build.stderr[-3000:]}"
    return out


def _run(probe: Path, *args: str, timeout: float = 120.0) -> tuple[dict, list[str]]:
    r = subprocess.run([str(probe), *args], capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, f"probe {args} exited {r.returncode}:\n{r.stdout}\n{r.stderr}"
    kv, lines = {}, r.stdout.splitlines()
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k] = v
    return kv, lines


# ── Wake the I/O loop on commit ───────────────────────────────────────────────

def test_a_committed_frame_reaches_the_pipe_without_waiting_out_the_select_timeout(probe):
    """No server traffic at all, so nothing but the commit itself can wake the
    loop. Pre-fix every frame took ~463 ms; 150 ms is still >2x under that floor
    and ~1000x over a working wakeup."""
    _kv, lines = _run(probe, "commit-latency", "20")
    lat_ms = [int(l.split("=", 1)[1]) / 1000 for l in lines if l.startswith("latency_us=")]
    assert len(lat_ms) == 20, lines
    assert all(x >= 0 for x in lat_ms), f"a frame never arrived: {lat_ms}"
    assert statistics.median(lat_ms) < 10, f"median {statistics.median(lat_ms):.1f} ms: {lat_ms}"
    assert max(lat_ms) < 150, f"worst {max(lat_ms):.1f} ms: {lat_ms}"


def test_the_wakeup_does_not_turn_an_idle_loop_into_a_busy_one(probe):
    """The classic self-pipe failure: a wake byte nobody reads keeps select()
    returning at once, forever. Every latency figure improves and the helper
    burns a core. With the loop idle for 500 ms the process must stay near 0
    CPU (a spinning loop reads ~500)."""
    kv, lines = _run(probe, "commit-latency", "3")
    assert float(kv["idle_cpu_ms"]) < 100, lines


def test_a_transient_write_failure_keeps_the_queued_frame(probe):
    """write() to the server failing with EAGAIN/EINTR must leave the ring
    alone. Falling through to ``kis_simple_ringbuf_read(..., (size_t) -1)``
    would read -- discard -- everything queued, with no message, and the frame
    below would never arrive."""
    kv, lines = _run(probe, "write-eagain")
    # Positive control: the fault really fired inside the loop's write.
    assert kv.get("eagain_injected") == "1", lines
    assert kv.get("intact") == "1", lines


# ── The flush wakeup ──────────────────────────────────────────────────────────

def test_a_wait_after_the_ring_has_drained_returns_instead_of_parking(probe):
    """The lost wakeup's end state, built rather than raced: the flush already
    happened and nothing will be written again. Pre-fix: parked the full 1000 ms
    until the probe's stand-in for an unrelated PONG."""
    kv, lines = _run(probe, "wait-after-flush")
    assert kv.get("woke_by") == "self", lines
    assert float(kv["parked_ms"]) < 100, lines


def test_a_wait_with_bytes_still_queued_parks_until_the_flush(probe):
    """The control for the test above. A 'fix' that never waits would pass it,
    and would turn every full-ring caller into a busy loop. With bytes queued the
    caller must stay parked, and a flush done the way the I/O loop does it must
    wake it at once. (This held pre-fix too: the defect is in the other case.)"""
    kv, lines = _run(probe, "wait-while-pending")
    assert kv.get("returned_while_pending") == "0", lines
    assert 0 <= float(kv["woke_after_flush_ms"]) < 100, lines


def test_the_failed_send_then_wait_race_never_parks_a_caller_past_a_flush(probe):
    """The field shape: a caller fails a send and waits while the I/O loop
    drains and broadcasts at a jittered moment. Pre-fix, 184 of 300 callers were
    still parked 50 ms after the flush. That rate is also this test's positive
    control: the 0-20 us jitter demonstrably spans the window between the failed
    send and the wait, so a zero here is a result, not an unreached branch."""
    kv, lines = _run(probe, "race", "300")
    assert kv.get("iterations") == "300", lines
    assert kv.get("parked_past_flush") == "0", lines


def test_the_io_loop_broadcasts_a_flush_only_under_the_flush_mutex(probe):
    """The race test above flushes with the probe's own (correct) broadcast, so
    it pins the WAITER. This pins the other side: the I/O loop's broadcast must
    take the mutex, or it can land between a waiter's ring check and its wait
    and be lost -- a window of a few hundred ns that no timing test hits
    reliably. Held by the probe, the mutex must stall the loop after frame A,
    so frame B arrives only once it is released."""
    kv, lines = _run(probe, "flush-signal-locked")
    assert kv.get("a_arrived") == "1", lines
    assert kv.get("b_while_held") == "0", lines
    assert kv.get("b_after_release") == "1", lines


# ── Commit wakeup end to end: the real celldiag binary over the IPC harness ──

def _data_slices(run) -> list[dict]:
    from test_celldiag_raw_packets import DLT, END, HDR
    out = []
    for p in run.raw_packets:
        assert p["dlt"] == DLT
        _magic, _ver, flags, hlen, _session, offset = HDR.unpack_from(p["content"])
        if flags & END:
            continue
        out.append({"offset": offset, "payload": p["content"][hlen:],
                    "ts": p["ts_s"] + p["ts_us"] / 1e6, "recv_wall": p["recv_wall"]})
    return out


def _live_celldiag(tmp_path: Path, stop_when, poll_s: float = 0.5, **fake):
    from fake_at_modem import FakeAtModem
    from fake_diag_modem import FakeDiagModem
    from test_celldiag_raw_packets import FIRMWARE, IMEI
    from celldiag_run import CellDiagRun, _binary_or_skip

    binary = _binary_or_skip()
    tee = tmp_path / "live.hdlc"
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, FakeDiagModem(**fake) as dg:
        definition = (f"celldiag-{IMEI}:atport={at.port},diagport={dg.port},nomask=true,"
                      f"defer=false,stats_interval=0,rawlog={tee}")
        run = CellDiagRun(binary, definition, timeout=30.0, poll_s=poll_s,
                          stop_when=lambda r: stop_when(r, dg)).run()
    return run, tee.read_bytes()


def test_a_live_celldiags_slices_reach_the_server_within_a_read_not_a_timeout(tmp_path):
    """Each slice carries the host time of the port read that produced it, and
    the harness stamps when it arrived; the difference is the time it waited in
    the capture's output ring. A 25 Hz port (one frame per read) and no server
    traffic -- the harness's first PING is 5 s out. Without the commit wakeup
    that wait is 0-500 ms per slice."""
    run, _tee = _live_celldiag(tmp_path, lambda r, _dg: len(r.raw_packets) >= 45,
                               filler_hz=25)
    slices = [s for s in _data_slices(run) if s["recv_wall"] is not None]
    # Positive control: enough slices to make a median mean something.
    assert len(slices) >= 40, (len(slices), run.errors, run.messages[-5:])
    waits_ms = sorted((s["recv_wall"] - s["ts"]) * 1e3 for s in slices)
    p90 = waits_ms[int(len(waits_ms) * 0.9)]
    assert statistics.median(waits_ms) < 50, f"median {statistics.median(waits_ms):.1f} ms: {waits_ms}"
    assert p90 < 150, f"p90 {p90:.1f} ms: {waits_ms}"


def test_a_kismet_shaped_stop_after_the_port_goes_quiet_loses_nothing(tmp_path):
    """The commit wakeup's acceptance, offline: stop the way Kismet does (pipe
    close + SIGTERM, no teardown, so no END slice) 60 ms after the port's last
    frame. Everything the capture read by then must already be in the delivered
    slices -- the in-db copy equals the rawlog= tee, byte for byte.

    Without the wakeup the last up-to-500 ms of reads are still in the ring at
    the stop, so this usually loses the tail. (Not always: the loop's 500 ms
    select timeout can happen to fire inside the 60 ms. The latency tests above
    are the deterministic checks.) ``poll_s`` makes the harness check the stop
    every 10 ms; at its 0.5 s default the stop can land up to 560 ms late,
    which lets a build with no wakeup at all pass."""
    from test_celldiag_raw_packets import _reassemble, _slices

    def quiet_for_60ms(_r, dg):
        return (dg.filler_sent >= 40 and dg.filler_last_wall is not None
                and time.time() - dg.filler_last_wall > 0.06)

    run, teed = _live_celldiag(tmp_path, quiet_for_60ms, poll_s=0.01,
                               filler_hz=25, filler_max=40)
    got = _reassemble(_slices(run))
    # Positive control: the port really streamed all 40 frames into the tee.
    assert len(teed) > 40 * 20, len(teed)
    assert got == teed, (f"delivered {len(got)} B of the {len(teed)}-byte tee: "
                         f"{len(teed) - len(got)} B still held at the stop")
