# SPDX-License-Identifier: Apache-2.0
"""FakeAtModem must tear down without closing a pty fd under a live read.

On Darwin, close() on a pty master waits for any read in flight on that fd. If
``__exit__`` closes the master while the responder thread sits in
``os.read(master)`` and the capture binary is gone, the read never returns and
pytest enters the uninterruptible ``U`` state, ignoring SIGTERM.

The discriminating tests run the fake in a subprocess with a timeout. If the
teardown regresses it never returns, so an in-process test would wedge the
test run -- the very failure it exists to catch -- instead of reporting it.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

import fake_at_modem
from fake_at_modem import FakeAtModem, FakeModemStuck

_HERE = Path(__file__).resolve().parent
_IMEI = "000000000000000"
_BOUND_S = 20.0


def _run_isolated(body: str) -> subprocess.CompletedProcess:
    code = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(_HERE)!r})
        from fake_at_modem import FakeAtModem
        t0 = time.monotonic()
        {textwrap.indent(textwrap.dedent(body), '        ').lstrip()}
        print(f"TEARDOWN_OK {{time.monotonic() - t0:.2f}}", flush=True)
    """)
    try:
        return subprocess.run([sys.executable, "-c", code], capture_output=True,
                              text=True, timeout=_BOUND_S)
    except subprocess.TimeoutExpired:
        pytest.fail(f"FakeAtModem teardown did not return within {_BOUND_S:.0f} s "
                    f"-- a pty fd closed under the responder's blocked read")


def test_exit_returns_while_the_responder_is_idle():
    """No client ever writes: the responder is parked waiting for input."""
    r = _run_isolated(f"""
        with FakeAtModem(imei={_IMEI!r}) as m:
            m.port
            time.sleep(0.2)
    """)
    assert r.returncode == 0, r.stderr
    assert "TEARDOWN_OK" in r.stdout


def test_unplug_returns_while_the_responder_is_idle():
    """unplug() closes the master mid-test -- the same hazard as __exit__."""
    r = _run_isolated(f"""
        with FakeAtModem(imei={_IMEI!r}) as m:
            time.sleep(0.2)
            m.unplug()
    """)
    assert r.returncode == 0, r.stderr
    assert "TEARDOWN_OK" in r.stdout


def test_a_responder_that_will_not_stop_fails_loudly_and_leaves_fds_open(
        monkeypatch):
    """The bound: a stuck responder is a FAILED test naming the step, and its
    fds are NOT closed under it (a leaked fd is recoverable; a process stuck in
    close() is not)."""
    release = threading.Event()

    def stubborn(self):                 # ignores _stop until released
        release.wait(timeout=30)

    monkeypatch.setattr(FakeAtModem, "_serve", stubborn)
    monkeypatch.setattr(fake_at_modem, "_STOP_GRACE_S", 0.2)
    m = FakeAtModem(imei=_IMEI)
    m.__enter__()
    master = m._master
    try:
        t0 = time.monotonic()
        with pytest.raises(FakeModemStuck, match=r"__exit__.*did not stop"):
            m.__exit__(None, None, None)
        assert time.monotonic() - t0 < 5
        import os
        os.fstat(master)                # still open: raises if it was closed
    finally:
        release.set()
        m._thread.join(timeout=5)
        m.__exit__(None, None, None)


@pytest.mark.parametrize("filler_hz", [0.0, 2000.0])
def test_the_diag_fake_tears_down_while_idle_or_flooding(filler_hz):
    """FakeDiagModem has the same close-under-read hazard, plus a filler whose
    blocking write parks forever once the slave's buffer fills (nobody reads
    the slave)."""
    r = _run_isolated(f"""
        from fake_diag_modem import FakeDiagModem
        with FakeDiagModem(filler_hz={filler_hz}) as m:
            m.port
            time.sleep(0.5)
    """)
    assert r.returncode == 0, r.stderr
    assert "TEARDOWN_OK" in r.stdout
