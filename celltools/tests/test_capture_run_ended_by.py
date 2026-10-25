"""``CaptureRun`` says how a run ended, and a replay that hit its timeout fails.

A live NR-SA tee once wedged the offline replay at 0% CPU. The pump
returned at its timeout with a normal-looking, silently short ``observations``
list, and two runs being compared were cut at different points. That read as
one emitting 2.5x the other, a decode divergence that did not exist.

So the harness records WHY the pump stopped (``ended_by``), and the celldiag
replay driver refuses a run that ended by timeout when the run was an enabled
replay of a file, the one shape that must end on its own. Runs against a live
or stub port, and disabled sources, end by timeout by design and are untouched.

The "binaries" here are two-line shell scripts, so the contract is pinned
without a built ``kismet_cap_cell_diag``.
"""
from __future__ import annotations

import os
import stat

import pytest

from kismet_capture_ipc import CaptureRun


def _fake_binary(tmp_path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_a_binary_that_exits_ends_by_eof_not_by_timeout(tmp_path):
    run = CaptureRun(_fake_binary(tmp_path, "quits", "exit 0"),
                     "x:replay=/dev/null", timeout=10.0).run()
    assert run.ended_by in ("eof", "exit")
    assert run.timed_out is False


def test_a_binary_that_never_finishes_ends_by_timeout(tmp_path):
    run = CaptureRun(_fake_binary(tmp_path, "hangs", "exec sleep 30"),
                     "x:replay=/dev/null", timeout=1.0, poll_s=0.1).run()
    assert run.ended_by == "timeout"
    assert run.timed_out is True


def test_a_stop_predicate_is_not_reported_as_a_timeout(tmp_path):
    run = CaptureRun(_fake_binary(tmp_path, "hangs", "exec sleep 30"),
                     "x:replay=/dev/null", timeout=10.0, poll_s=0.1,
                     stop_when=lambda _run: True).run()
    assert run.ended_by == "stop_when"
    assert run.timed_out is False


@pytest.mark.parametrize("definition, must_end", [
    ("celldiag-1:replay=/f.hdlc", True),
    ("celldiag-1:replay=/f.hdlc,gsmtap=127.0.0.1:4729", True),
    ("celldiag-1:replay=/f.hdlc,enabled=true", True),
    ("celldiag-1:replay=/f.hdlc,enabled=false", False),   # idle by design
    ("celldiag-1:port=/dev/ttyUSB0", False),               # live: runs forever
    ("celldiag-1", False),
])
def test_which_runs_must_end_on_their_own(definition, must_end):
    from celldiag_run import replay_must_end
    assert replay_must_end(definition) is must_end


def test_a_replay_that_hits_its_timeout_fails_loudly(tmp_path):
    from celldiag_run import CellDiagRun
    hang = _fake_binary(tmp_path, "hangs", "exec sleep 30")
    with pytest.raises(pytest.fail.Exception, match="TIMEOUT"):
        CellDiagRun(hang, f"celldiag-1:replay={os.devnull}",
                    timeout=1.0, poll_s=0.1).run()


def test_a_disabled_replay_may_still_end_by_timeout(tmp_path):
    from celldiag_run import CellDiagRun
    hang = _fake_binary(tmp_path, "hangs", "exec sleep 30")
    run = CellDiagRun(hang, f"celldiag-1:replay={os.devnull},enabled=false",
                      timeout=1.0, poll_s=0.1).run()
    assert run.timed_out is True
