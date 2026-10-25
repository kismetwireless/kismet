# SPDX-License-Identifier: Apache-2.0
"""The server's child reaper tells a STOPPED helper from a DEAD one.

## The hazard

``ipc_tracker_v2`` reaps helpers with ``waitpid(-1, &status, WNOHANG |
WUNTRACED)``. ``WUNTRACED`` also reports a child that has merely STOPPED. A
reaper that treats every report as a death drops the pid from ``ipc_map`` and
tells the source ``Process exited with status {WEXITSTATUS(status)}``, which for
a stopped child is the stop signal: a helper SIGSTOPped during a
``close_source`` reads ``closed cleanly (Process exited with status 19)`` while
it sits in state T, untracked, where no SIGTERM or hard kill from the server
reaches it again.

``WEXITSTATUS`` also misreports a signal death: for a SIGKILLed child it is 0,
so the helper would read ``Process exited with status 0``.

## What is pinned

* Against a real server: a SIGSTOPped helper is not reported closed, stays alive
  and tracked, and its close completes normally once it is SIGCONTed.
* Against real wait statuses from forked children, through
  ``ipctracker_child_status.h``: an exit reads ``exited with status N``, a
  signal death ``killed by signal N``, and a stop is not an end.

Why the death TEXT is not measured through the server: a helper that dies
closes its IPC pipe as it goes, and the source sees that EOF -- event-driven --
before the reaper's 1 s timer reaps the pid, so the source reports ``IPC
connection closed`` and the reaper finds the pid already gone. The reaper's text reaches
an operator only when the pipe stays open, which is the stop case above.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from test_celldiag_server_routes import KP_ROOT, SERVER  # noqa: E402
from test_graceful_close_server import (  # noqa: E402
    LoggingKismetServer, _await_start_anchor, _built_or_skip)

IMEI = "351234567847471"   # 15 digits, deliberately NOT Luhn-valid: never a real device
CCLK = {"AT+CCLK?": '+CCLK: "26/09/23,12:00:00+00"'}

#: cellat's advertised close grace; the server falls back at grace + 1 s.
CELLAT_GRACE_S = 8.0


def _server_fresh_or_fail() -> None:
    """A server older than the reaper would measure the old reaper."""
    _built_or_skip()
    for name in ("ipctracker_v2.cc", "ipctracker_child_status.h"):
        src = KP_ROOT / name
        if src.stat().st_mtime > SERVER.stat().st_mtime:
            pytest.fail(f"{SERVER.name} is older than {src.name}; rebuild it "
                        f"(make -C {KP_ROOT} kismet) -- a stale server measures "
                        f"the old reaper")


def _state(pid: int) -> "str | None":
    """The process state letter from /proc/<pid>/stat, or None once it is gone."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    return stat.rsplit(")", 1)[1].split()[0]


def _await(pred, timeout: float, step: float = 0.1) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()


def _srcdef(modem: FakeAtModem) -> str:
    return f"cellat-{IMEI}:atport={modem.port},retry=false"


def test_a_stopped_helper_is_not_reported_closed_and_closes_once_continued(tmp_path):
    """The Accept: SIGSTOP -> no "closed cleanly", pid still tracked; SIGCONT ->
    the close completes. A reaper that treats the stop as a death reports
    ``closed cleanly (Process exited with status 19)`` within a fraction of a
    second, with the helper still in state T.
    """
    _server_fresh_or_fail()
    with FakeAtModem(imei=IMEI, extra={**QENG_SERVING, **CCLK}) as modem:
        srv = LoggingKismetServer(tmp_path, _srcdef(modem))
        with srv:
            row = srv.await_running(True)
            _await_start_anchor(modem)
            pid = int(srv.source()["kismet.datasource.ipc_pid"])
            assert pid > 0, "no helper pid"
            try:
                os.kill(pid, signal.SIGSTOP)
                assert _await(lambda: _state(pid) == "T", 5.0), _state(pid)
                srv.get(f"datasource/by-uuid/{row['kismet.datasource.uuid']}/close_source.cmd")
                # A broken reaper declares it closed almost at once; give it
                # 2.5 s, well inside the 9 s the server waits for a graceful close.
                time.sleep(2.5)
                log_while_stopped = srv.tail(40000)
                state_while_stopped = _state(pid)
                os.kill(pid, signal.SIGCONT)
                closed = _await(lambda: "closed cleanly" in srv.tail(40000),
                                CELLAT_GRACE_S)
                gone = _await(lambda: _state(pid) in (None, "Z"), 5.0)
            finally:
                if _state(pid) not in (None, "Z"):
                    os.kill(pid, signal.SIGCONT)
                    os.kill(pid, signal.SIGKILL)
            log = srv.tail(40000)
            srv.proc.send_signal(signal.SIGTERM)
            srv.proc.wait(30)

    assert "closed cleanly" not in log_while_stopped, (
        f"a STOPPED helper was reported as a clean close: "
        f"{log_while_stopped[-2000:]}")
    assert "status 19" not in log_while_stopped, (
        "the stop signal was reported as an exit status")
    assert state_while_stopped == "T", (
        f"the helper was not still stopped 2.5 s into the close: "
        f"{state_while_stopped!r}")
    assert f"helper pid {pid} was stopped by signal 19" in log_while_stopped, (
        f"the stop must be logged, naming the pid and signal: "
        f"{log_while_stopped[-2000:]}")
    assert closed, f"the close never completed after SIGCONT: {log[-3000:]}"
    assert "status 19" not in log, "the stop signal was reported as an exit status"
    assert gone, "the helper was still running after its close completed"
    assert "did not finish closing within its grace" not in log, (
        "the close completed through the server's fallback, not the helper's "
        "own exit -- the helper was not tracked through its stop")


def test_a_stopped_helper_that_is_never_continued_is_closed_at_the_grace(tmp_path):
    """The other half: nobody SIGCONTs it. The close must not hang and must not
    call it clean -- the server's own fallback closes it at grace + 1 s, and
    the helper is gone afterwards. A reaper that treats the stop as a death
    reports a clean close at once, the fallback never runs, and the helper sits
    in state T with nothing tracking it.
    """
    _server_fresh_or_fail()
    fallback = "did not finish closing within its grace"
    with FakeAtModem(imei=IMEI, extra={**QENG_SERVING, **CCLK}) as modem:
        srv = LoggingKismetServer(tmp_path, _srcdef(modem))
        with srv:
            row = srv.await_running(True)
            _await_start_anchor(modem)
            pid = int(srv.source()["kismet.datasource.ipc_pid"])
            try:
                os.kill(pid, signal.SIGSTOP)
                assert _await(lambda: _state(pid) == "T", 5.0), _state(pid)
                t0 = time.monotonic()
                srv.get(f"datasource/by-uuid/{row['kismet.datasource.uuid']}/close_source.cmd")
                fell_back = _await(lambda: fallback in srv.tail(40000),
                                   CELLAT_GRACE_S + 6.0)
                took = time.monotonic() - t0
                gone = _await(lambda: _state(pid) in (None, "Z"), 6.0)
            finally:
                if _state(pid) not in (None, "Z"):
                    os.kill(pid, signal.SIGCONT)
                    os.kill(pid, signal.SIGKILL)
            log = srv.tail(40000)
            srv.proc.send_signal(signal.SIGTERM)
            srv.proc.wait(30)
    assert "closed cleanly" not in log, f"a stopped helper read as a clean close: {log[-3000:]}"
    assert fell_back, f"the close never fell back on the stopped helper: {log[-3000:]}"
    assert CELLAT_GRACE_S + 0.5 <= took < CELLAT_GRACE_S + 3.0, (
        f"the fallback fired {took:.2f}s after close_source; expected grace + 1 s")
    assert gone, "the stopped helper outlived its own fallback close"


STATUS_PROBE = r"""
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "ipctracker_child_status.h"

/* One REAL wait status per case: a child that exits 3, one SIGKILLed, one
 * SIGSTOPped (reported because of WUNTRACED, exactly as the reaper waits). */
static void report(const char *label, int st) {
    printf("%s\t%d\t%s\n", label, ipc_child_only_stopped(st) ? 1 : 0,
           ipc_child_end_text(st).c_str());
}

int main() {
    int st;
    pid_t p = fork();
    if (p == 0) _exit(3);
    waitpid(p, &st, WUNTRACED);
    report("exit3", st);

    p = fork();
    if (p == 0) { for (;;) pause(); }
    kill(p, SIGKILL);
    waitpid(p, &st, WUNTRACED);
    report("sigkill", st);

    p = fork();
    if (p == 0) { for (;;) pause(); }
    kill(p, SIGSTOP);
    waitpid(p, &st, WUNTRACED);
    report("sigstop", st);
    kill(p, SIGKILL);
    waitpid(p, &st, 0);
    return 0;
}
"""


@pytest.fixture(scope="module")
def status_probe(tmp_path_factory) -> dict:
    cxx = shutil.which("c++") or shutil.which("g++")
    if not cxx:
        pytest.skip("no C++ compiler for the wait-status probe")
    d = tmp_path_factory.mktemp("status_probe")
    src, exe = d / "probe.cc", d / "probe"
    src.write_text(STATUS_PROBE)
    subprocess.run([cxx, "-std=c++17", f"-I{KP_ROOT}", "-o", str(exe), str(src)],
                   check=True, capture_output=True)
    out = subprocess.run([str(exe)], check=True, capture_output=True, text=True,
                         timeout=30).stdout
    rows = {}
    for line in out.splitlines():
        label, stopped, text = line.split("\t")
        rows[label] = (stopped == "1", text)
    assert set(rows) == {"exit3", "sigkill", "sigstop"}, out
    return rows


def test_an_exit_reads_exited_with_its_code(status_probe):
    assert status_probe["exit3"] == (False, "Process exited with status 3")


def test_a_signal_death_reads_killed_by_that_signal(status_probe):
    """WEXITSTATUS of a SIGKILLed child is 0; the text must name the signal,
    not "Process exited with status 0"."""
    stopped, text = status_probe["sigkill"]
    assert not stopped
    assert text.startswith("Process killed by signal 9 ("), text


def test_a_stop_is_not_an_end(status_probe):
    """A stop must not erase the pid or read as "Process exited with status
    19" -- the stop signal is not an exit code."""
    stopped, _text = status_probe["sigstop"]
    assert stopped
