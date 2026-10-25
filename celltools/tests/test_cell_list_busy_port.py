# SPDX-License-Identifier: Apache-2.0
"""A lister waits out a port another lister is probing, briefly.

## The hazard

The server's ``list_interfaces`` runs the cellat and celldiag listers at the same
time. Each claims a port with ``flock(LOCK_EX|LOCK_NB)`` and SKIPS a port another
process holds. A modem with TWO AT ports survives that: the listers each find
a free one. The Foxconn T99W175 has ONE, so without a re-try the lister that reaches it second
would drop it, and the Sources panel would never show both of its entries.

A capture's OPEN rescans after a busy skip. A lister does the same: each lister
re-tries the ports it found busy until they are free or ONE
shared deadline (``CELL_LIST_BUSY_WAIT_MS``) passes. A lister's hold is sub-second,
so the wait ends almost at once. A port held by an OPEN capture is
held for good: it costs the deadline once per list, not once per port,
and is still skipped.

## How the listers are reached offline

``CELLAT_SCAN_PORTS`` / ``CELLDIAG_SCAN_PORTS`` REPLACE the scan universe with the
named PTYs, so no host tty is touched. The "other lister, mid-probe" is a
``flock(LOCK_EX)`` taken on the fake's slave path from this process -- the same
claim both listers take -- released on a timer.
"""
from __future__ import annotations

import fcntl
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from test_cellat_ipc import _binary_or_skip as _cellat_or_skip  # noqa: E402
from celldiag_run import _binary_or_skip as _celldiag_or_skip  # noqa: E402

IMEI = "123456789048020"   # not Luhn-valid: never reads as a real device
FIRMWARE = "T99W175.F0.1.0.0.9.GC.004"
#: The lister's shared deadline, mirrored from both drivers' CELL_LIST_BUSY_WAIT_MS.
BUSY_WAIT_S = 1.5

DRIVERS = {
    "cellat": ("CELLAT_SCAN_PORTS", _cellat_or_skip),
    "celldiag": ("CELLDIAG_SCAN_PORTS", _celldiag_or_skip),
}


class HeldClaim:
    """Another lister, mid-probe: the port's exclusive claim, from outside."""

    def __init__(self, path: str) -> None:
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            if self.fd >= 0:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
                os.close(self.fd)
                self.fd = -1


def _list(binary: str, env: dict) -> tuple[list[str], float]:
    t0 = time.monotonic()
    out = subprocess.run([binary, "--list"], capture_output=True, text=True,
                         timeout=60, env={**os.environ, **env})
    return ([ln.strip() for ln in (out.stdout + out.stderr).splitlines()],
            time.monotonic() - t0)


def _listed(lines: list[str], driver: str) -> bool:
    return any(ln.startswith(f"{driver}-{IMEI} ") for ln in lines)


@pytest.mark.parametrize("driver", sorted(DRIVERS))
def test_a_free_single_port_modem_is_listed(driver):
    """Positive control: without it, every 'not listed' below could be 'the
    lister never reached the PTY'."""
    env_key, binary = DRIVERS[driver]
    binary = binary()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at:
        lines, _ = _list(binary, {env_key: at.port})
    assert _listed(lines, driver), lines


@pytest.mark.parametrize("driver", sorted(DRIVERS))
def test_a_port_held_briefly_by_another_lister_is_still_listed(driver):
    """The busy port is re-tried, not skipped, so the modem is listed."""
    env_key, binary = DRIVERS[driver]
    binary = binary()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at:
        claim = HeldClaim(at.port)
        # ~ a lister's hold, and well inside the deadline.
        timer = threading.Timer(0.4, claim.release)
        timer.start()
        try:
            lines, took = _list(binary, {env_key: at.port})
        finally:
            timer.cancel()
            claim.release()
    assert _listed(lines, driver), (
        f"a port another lister held for 0.4 s dropped the modem: {lines}")
    assert took < BUSY_WAIT_S + 5.0, took


@pytest.mark.parametrize("driver", sorted(DRIVERS))
def test_a_port_held_for_good_is_skipped_after_one_bounded_wait(driver):
    """A port an OPEN capture holds is held for good: the lister gives up
    at the deadline, lists nothing for it, and never writes to it."""
    env_key, binary = DRIVERS[driver]
    binary = binary()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeAtModem(imei=IMEI[:-1] + "7", firmware=FIRMWARE) as at2:
        claims = [HeldClaim(at.port), HeldClaim(at2.port)]
        try:
            lines, took = _list(binary, {env_key: f"{at.port} {at2.port}"})
        finally:
            for c in claims:
                c.release()
        written = list(at.commands) + list(at2.commands)
    assert not _listed(lines, driver), lines
    assert written == [], f"a held port was written to: {written}"
    # TWO held ports cost ONE deadline, not two.
    assert BUSY_WAIT_S - 0.2 <= took < 2 * BUSY_WAIT_S, (
        f"two ports held for good took {took:.1f} s; want one "
        f"{BUSY_WAIT_S} s deadline shared by both")


@pytest.mark.parametrize("driver", sorted(DRIVERS))
def test_a_silent_port_is_not_busy_and_costs_no_wait(driver):
    """The gate: a port that is merely not a modem (it never answers AT) was not
    HELD, so it must not earn the busy wait -- or every list on a host with an
    NMEA or DIAG tty would pay the deadline."""
    env_key, binary = DRIVERS[driver]
    binary = binary()
    master, slave = os.openpty()
    try:
        lines, took = _list(binary, {env_key: os.ttyname(slave)})
        os.set_blocking(master, False)
        try:
            written = os.read(master, 65536)
        except BlockingIOError:
            written = b""
    finally:
        os.close(master)
        os.close(slave)
    assert not any(ln.startswith(f"{driver}-") for ln in lines), lines
    # Probed ONCE. A retry of a port that was never held is the defect in its
    # small form: each costs another AT timeout on every non-AT tty.
    assert written.count(b"AT\r") == 1, (
        f"a silent, unheld port was probed {written.count(b'AT' + bytes([13]))} times: {written!r}")
    assert took < BUSY_WAIT_S - 0.3, (
        f"a silent, unheld port cost {took:.1f} s: it was treated as busy")


def test_both_listers_started_together_list_a_single_port_modem():
    """The two listers started at once on a modem with ONE AT port both list
    it."""
    at_bin, diag_bin = _cellat_or_skip(), _celldiag_or_skip()
    for trial in range(3):
        with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at:
            env = {**os.environ, "CELLAT_SCAN_PORTS": at.port,
                   "CELLDIAG_SCAN_PORTS": at.port}
            procs = {d: subprocess.Popen([b, "--list"], stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, env=env)
                     for d, b in (("cellat", at_bin), ("celldiag", diag_bin))}
            outs = {d: p.communicate(timeout=60)[0].splitlines() for d, p in procs.items()}
        missing = [d for d, lines in outs.items()
                   if not _listed([ln.strip() for ln in lines], d)]
        assert not missing, f"trial {trial}: {missing} dropped the modem: {outs}"
