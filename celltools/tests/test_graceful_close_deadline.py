"""The graceful close's two DEADLINES and its drain-before-log-close ORDER.

Three guarantees of the graceful close that the other close tests cannot
break, because their modems answer promptly and their workloads never queue:

1. **The helper's own deadline** (``capture_framework.c``, ``cf_handler_loop``).
   After a CLOSEREQ, a capture thread that has not spun down within its
   advertised grace is abandoned: the loop spins down itself and logs ``did not
   finish its close within N ms``. Every existing close test used a modem that
   answers promptly, so the teardown always finished and the deadline never
   fired.
2. **The server's fallback** (``kis_datasource::abort_graceful_close``). A helper
   that does not exit at all by grace + 1 s is closed the old way: ``did not
   finish closing within its grace``.
3. **Drain before log close** (``log_tracker::trigger_deferred_shutdown`` calls
   ``packet_chain::drain_and_stop()`` before any ``close_log()``). Removing the
   call goes unnoticed by a behavioural test: the rows a closing source sends
   are processed within milliseconds in every workload a test can generate, so
   no backlog exists when the logs close.

How each is reached:

* (1) cellat's full band scan, ``AT+QSCAN=3,1``, blocks the capture thread for
  up to 120 s. ``strategy=stationary`` starts one on the first loop, on a fake
  that answers ``AT+QSCAN=?`` (which enables QSCAN) but never answers the scan
  itself (``hang=``). A CLOSEREQ sent then finds a thread that cannot reach its teardown
  for two minutes -- the "long AT command" case the deadline exists for.
* (2) the real server, with the helper's main thread ptrace-stopped before
  ``close_source``: it cannot read the CLOSEREQ, enforce its own deadline or exit,
  so only the server's timer can end it. (Not SIGSTOP: see ``PtraceFreeze``.)
* (3) is a SOURCE-ORDER ratchet, not a behavioural test, and says so. A
  behavioural one needs a backlog queued at log close, which needs a logging
  stage slower than the packet thread -- and nothing in the server can be made
  slow from outside without also changing what is measured. The ordering is a
  three-line fact about one function, so it is pinned as that fact.
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import QENG_SERVING, QSCAN_CAPABLE, FakeAtModem  # noqa: E402
from test_cellat_ipc import CellAtRun  # noqa: E402
from test_cellat_ipc import _binary_or_skip as _cellat_binary_or_skip  # noqa: E402
from test_celldiag_server_routes import KP_ROOT  # noqa: E402
from test_graceful_close_server import (  # noqa: E402
    LoggingKismetServer, _anchor_edges, _await_start_anchor, _built_or_skip)

IMEI = "351234567890126"
#: An RM500Q; the QSCAN capability itself comes from QSCAN_CAPABLE.
QSCAN_FIRMWARE = "RM500QAEAAR11A03M4G"
CCLK = {"AT+CCLK?": '+CCLK: "26/09/23,12:00:00+00"'}
FULL_SCAN = "AT+QSCAN=3,1"

#: cellat's advertised grace (CELLAT_CLOSE_GRACE_MS) and the server's margin.
CELLAT_GRACE_S = 8.0
SERVER_MARGIN_S = 1.0


def _edges(run) -> list[str]:
    return [json.loads(js)["edge"] for js in run.clock_anchors]


def test_a_capture_thread_stuck_in_a_scan_is_abandoned_at_the_helpers_deadline():
    """(1) The helper spins down at its own grace, not when the scan returns.

    RED without the deadline: the loop waits for the capture thread, which is in
    a 120 s AT+QSCAN, so the helper is still running when this harness times out
    at 40 s and has to SIGTERM it (exit code -15).
    """
    binary = _cellat_binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=QSCAN_FIRMWARE,
                     extra={**QENG_SERVING, **CCLK, **QSCAN_CAPABLE}, hang={FULL_SCAN}) as modem:

        def mid_scan(run) -> bool:
            # The scan is IN FLIGHT: the helper announced it and the modem got it.
            return (FULL_SCAN in modem.commands
                    and any("starting full band scan" in m for m in run.messages))

        run = CellAtRun(binary, f"cellat-{IMEI}:atport={modem.port},strategy=stationary",
                        timeout=40.0, close_when=mid_scan).run()
        cmds = list(modem.commands)

    # Positive control: the thread really was stuck in the scan at the CLOSEREQ.
    assert run.open_code == 1, (run.open_message, run.errors)
    assert run.close_sent_mono is not None, (
        f"the full scan never started, so there was nothing to be stuck in; "
        f"commands={cmds[-15:]} messages={run.messages[-5:]}")
    assert cmds.count(FULL_SCAN) == 1, cmds

    assert run.exit_code is not None and run.exit_code >= 0, (
        f"exit {run.exit_code}: the harness had to signal the helper -- it never "
        f"spun down on its own deadline")
    took = run.exit_mono - run.close_sent_mono
    assert CELLAT_GRACE_S - 0.5 <= took < CELLAT_GRACE_S + 3.0, (
        f"exited {took:.2f}s after the CLOSEREQ; its deadline is its "
        f"{CELLAT_GRACE_S:.0f} s grace, not the scan's 120 s")
    # The teardown never ran -- that is what "abandoned" means: no END exchange.
    assert "end" not in _edges(run), _edges(run)
    assert "AT+CCLK?" not in cmds[cmds.index(FULL_SCAN):], (
        "an END AT+CCLK? went out after the stuck scan: the teardown was not "
        "abandoned but ran")


class PtraceFreeze:
    """Stop ONE thread of a process with ptrace, invisibly to its parent.

    Not SIGSTOP: a stop signal is visible to the server's reaper, and a reaper
    that mistook a SIGSTOPped helper for an exited one would end the close
    before the fallback under test could run. A ptrace-stop is reported to the
    tracer only, so this test does not depend on the reaper's handling of stops
    at all. ``PTRACE_SEIZE`` +
    ``PTRACE_INTERRUPT`` on the helper's main thread freezes exactly the loop
    that would read the CLOSEREQ, enforce the helper's own deadline and exit.
    """

    PTRACE_DETACH, PTRACE_SEIZE, PTRACE_INTERRUPT = 17, 0x4206, 0x4207
    WALL = 0x40000000

    def __init__(self, pid: int) -> None:
        import ctypes
        self.pid = pid
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long,
                                      ctypes.c_void_p, ctypes.c_void_p]
        self.frozen = False

    def _call(self, req: int) -> None:
        import ctypes
        if self._libc.ptrace(req, self.pid, None, None) != 0:
            raise OSError(ctypes.get_errno(), f"ptrace({req:#x}, {self.pid})")

    def freeze(self) -> None:
        try:
            self._call(self.PTRACE_SEIZE)
        except OSError as exc:
            pytest.skip(f"ptrace not permitted here ({exc}); the fallback test "
                        f"needs a stop the server's reaper cannot see")
        self._call(self.PTRACE_INTERRUPT)
        os.waitpid(self.pid, self.WALL)          # the tracer's stop report
        self.frozen = True

    def release(self) -> None:
        if self.frozen:
            self.frozen = False
            try:
                self._call(self.PTRACE_DETACH)
            except OSError:
                pass


def test_the_server_closes_a_helper_that_never_finishes_at_grace_plus_margin(tmp_path):
    """(2) The server's fallback: a helper frozen before the CLOSEREQ can neither
    finish nor exit, so at grace + margin the server closes it the old way, and
    the kismetdb gets no END row.

    Timed from the fallback's own log line. ``running`` reads false the moment
    ``close_source`` returns, so it says nothing about when
    the close completed.

    Without the fallback timer the frozen helper holds the close forever and
    the line never appears.
    """
    _built_or_skip()
    fallback = "did not finish closing within its grace"
    with FakeAtModem(imei=IMEI, extra={**QENG_SERVING, **CCLK}) as modem:
        srv = LoggingKismetServer(tmp_path, f"cellat-{IMEI}:atport={modem.port},retry=false")
        with srv:
            row = srv.await_running(True)
            _await_start_anchor(modem)
            pid = int(srv.source()["kismet.datasource.ipc_pid"])
            assert pid > 0, "no helper pid to freeze"
            freeze = PtraceFreeze(pid)
            took = None
            try:
                freeze.freeze()
                t0 = time.monotonic()
                srv.get(f"datasource/by-uuid/{row['kismet.datasource.uuid']}/close_source.cmd")
                while time.monotonic() - t0 < CELLAT_GRACE_S + SERVER_MARGIN_S + 10:
                    if fallback in srv.tail(40000):
                        took = time.monotonic() - t0
                        break
                    time.sleep(0.1)
                alive_at_fallback = os.path.exists(f"/proc/{pid}")
            finally:
                freeze.release()
                try:
                    os.kill(pid, signal.SIGKILL)   # frozen through its SIGTERM
                except ProcessLookupError:
                    pass
            time.sleep(1.0)
            log = srv.tail(40000)
            srv.proc.send_signal(signal.SIGTERM)
            srv.proc.wait(30)
        db = srv.kismetdb()

    assert took is not None, (
        f"the server never fell back on a helper that could not finish: "
        f"{log[-3000:]}")
    assert alive_at_fallback, "the helper exited on its own; it was not frozen"
    assert "closed cleanly" not in log, (
        f"a frozen helper was reported as a clean close: {log[-3000:]}")
    assert CELLAT_GRACE_S + SERVER_MARGIN_S - 0.5 <= took < CELLAT_GRACE_S + SERVER_MARGIN_S + 2.0, (
        f"the fallback fired {took:.2f}s after close_source; it is grace "
        f"{CELLAT_GRACE_S:.0f} s + margin {SERVER_MARGIN_S:.0f} s")
    assert _anchor_edges(db) == ["start"], (
        f"a helper that never ran its teardown cannot have sent END: "
        f"{_anchor_edges(db)}")


def test_the_logs_close_only_after_the_packet_chain_has_drained():
    """(3) SOURCE-ORDER ratchet for the packet-chain drain (see the module docstring for
    why this one is not behavioural).

    ``trigger_deferred_shutdown`` must call ``drain_and_stop()`` before its first
    ``close_log()``. Deleting the call, or moving it below the close loop, would
    close the kismetdb with rows still queued -- silently, in exactly the
    backlogged shutdown no offline workload produces.
    """
    src = (KP_ROOT / "logtracker.cc").read_text()
    m = re.search(r"void log_tracker::trigger_deferred_shutdown\(\)\s*\{(.*?)\n\}", src, re.S)
    assert m, "log_tracker::trigger_deferred_shutdown() is gone or renamed"
    body = re.sub(r"//[^\n]*", "", m.group(1))          # code, not the comment about it
    drain = body.find("drain_and_stop()")
    close = body.find("close_log()")
    assert close >= 0, "trigger_deferred_shutdown() no longer closes the logs here"
    assert drain >= 0, (
        "trigger_deferred_shutdown() no longer drains the packet chain before it "
        "closes the logs")
    assert drain < close, (
        "the packet chain is drained AFTER the logs close: rows still queued at "
        "shutdown are lost")
