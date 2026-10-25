# SPDX-License-Identifier: Apache-2.0
"""celldiag's IMEI scan rescans once when a sibling held its target's port.

## The race

In a concurrent multi-source open every source's IMEI scan walks the same ttys
at the same time. A port a sibling is probing is **skipped**: its exclusive claim
is taken, and sharing it would split the reply bytes. A scan can therefore find
all of its own target's AT ports held that way, come back empty, and proceed on
the explicit ``diagport=`` "without AT identity", so the model reads ``unknown``
in the rawlog name and ``prov.model``.

cellat handles the same race the same way, and celldiag mirrors it: keep flock's
``EWOULDBLOCK`` across the close of the refused fd, count the busy ports, and
rescan **once** after a short pid-jittered pause when -- and only when -- the
pass skipped one. These tests pin that.

## How the scan is reached offline

The scan globs ``/dev/ttyUSB*`` + ``/dev/ttyACM*``, which no PTY can join.
``CELLDIAG_SCAN_PORTS`` **replaces** that universe with the named paths.
Replacing, not adding, is what keeps these tests hermetic: an additive hook would
let a scan that skipped the busy PTY walk on into the host's real modems and
write ``AT`` to every one of them.

The "sibling mid-probe" is modelled exactly: the test opens the fake's slave path
itself and takes ``flock(LOCK_EX)`` on it -- the same claim ``diag_port_claim()``
takes -- so the helper's ``serial_open()`` is refused with ``EWOULDBLOCK``.

The bring-up runs deferred here (the production default), not with
``defer=false``. Inline, the bring-up runs inside ``open_callback`` on the
helper's IPC loop thread, so none of its messages reaches the pipe until the open
returns: the "rescanning" notice and the rescan's verdict arrive in the same
batch, and a test that frees the port at the notice frees it too late.
Deferred, the bring-up runs on the capture thread and its messages flow live.

## What each test pins

* ``test_the_scan_reaches_a_pty_named_by_CELLDIAG_SCAN_PORTS`` -- the positive
  control. Without it, every negative below could be "the scan never saw the PTY".
* ``test_a_port_busy_in_the_first_pass_is_found_by_the_one_rescan`` -- the rescan.
* ``test_a_port_busy_through_the_rescan_costs_exactly_one_rescan`` -- the bound,
  the busy COUNT, and that a held port is never written to.
* ``test_a_silent_port_is_not_busy_and_earns_no_rescan`` -- the gate: "not a
  modem" must not cost a rescan.
"""
from __future__ import annotations

import fcntl
import os
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from celldiag_run import CellDiagRun, _binary_or_skip  # noqa: E402

IMEI = "353456789047370"
FIRMWARE = "RM500QAEAAR11A03M4G"
SIBLING_IMEI = "353456789047388"

#: What ``diag_at_rescan()`` says before its pause. It is also the test's cue to
#: free the port: the first pass is over, and the rescan has not started.
RESCAN_NOTICE = "rescanning once in"


def _definition(diagport: str) -> str:
    parts = [f"diagport={diagport}", "nomask=true",
             "stats_interval=0"]
    return f"celldiag-{IMEI}:" + ",".join(parts)


def _brought_up(run: CellDiagRun) -> bool:
    """The deferred bring-up finished, either way."""
    return any(("Cell DIAG source" in m and "opened (live" in m)
               or "bring-up failed" in m for m in run.messages)


def _resolved(run: CellDiagRun) -> bool:
    """The bring-up named the source after the modem's firmware -- the model."""
    return any(f"{FIRMWARE} IMEI:{IMEI} DIAG opened" in m for m in run.messages)


def _notices(run: CellDiagRun) -> list[str]:
    return [m for m in run.messages if RESCAN_NOTICE in m]


class HeldClaim:
    """A sibling source's scan, mid-probe: the port's exclusive claim, held from
    outside the helper. Same ``flock(LOCK_EX)`` as ``diag_port_claim()``, on its
    own open file description, so the helper's claim is refused."""

    def __init__(self, path: str) -> None:
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    @property
    def held(self) -> bool:
        return self.fd >= 0

    def release(self) -> None:
        if self.fd >= 0:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = -1


def test_the_scan_reaches_a_pty_named_by_CELLDIAG_SCAN_PORTS(monkeypatch):
    """Positive control: a free PTY modem is found by the scan, first pass.

    Every other test here reads the ABSENCE of an identity or of a message. That
    is only evidence if the scan demonstrably reaches the PTY when nothing is in
    the way, so this pins it: the fake saw ``AT+CGSN``, the source was named after
    the firmware, and no rescan was needed.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", at.port)
        run = CellDiagRun(binary, _definition(dg.port), timeout=25.0,
                          stop_when=_brought_up).run()
        cmds = list(at.commands)
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert "AT+CGSN" in cmds, (
        f"the scan never probed the PTY named by CELLDIAG_SCAN_PORTS; the fake "
        f"saw {cmds!r}")
    assert _resolved(run), (
        f"a free modem on the only scan port should resolve its model; "
        f"messages={run.messages!r}")
    assert not _notices(run), f"no port was busy, yet: {_notices(run)!r}"


def test_a_port_busy_in_the_first_pass_is_found_by_the_one_rescan(monkeypatch):
    """The target's port is held during the first pass and free by the rescan,
    so the modem's identity is recovered instead of read as 'unknown'.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, FakeDiagModem() as dg:
        port = at.port   # read inside the block: the PTY closes with it
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", port)
        claim = HeldClaim(port)
        released_after_notice = []

        def free_the_port_at_the_notice(run: CellDiagRun) -> bool:
            if claim.held and _notices(run):
                claim.release()
                released_after_notice.append(True)
            return _brought_up(run)

        try:
            # poll_s: the notice lands, then the helper sleeps >= 250 ms before
            # it rescans. The release has to happen inside that window.
            run = CellDiagRun(binary, _definition(dg.port), timeout=25.0,
                              stop_when=free_the_port_at_the_notice,
                              poll_s=0.05).run()
        finally:
            claim.release()
        cmds = list(at.commands)

    notices = _notices(run)
    assert len(notices) == 1, (
        f"expected ONE rescan notice after the busy first pass; got {notices!r}. "
        f"messages={run.messages!r}")
    assert "not found while 1 port(s) were held by another process" in notices[0]
    assert released_after_notice, "the port was never freed at the notice"
    assert any(f"AT identify rescan: found on {port}" in m
               for m in run.messages), run.messages
    assert "AT+CGSN" in cmds, "the rescan never reached the freed port"
    assert _resolved(run), (
        f"the rescan found the modem, so the model must resolve; "
        f"messages={run.messages!r}")
    assert not any("model/firmware unresolved" in m for m in run.messages), (
        "the 'opened without AT identity' fallback fired although the rescan "
        "found the modem")


def test_a_port_busy_through_the_rescan_costs_exactly_one_rescan(monkeypatch):
    """The bound: ports held through BOTH passes cost one rescan, then the
    bring-up proceeds on the explicit diagport=, model 'unknown'.

    Also pins the busy COUNT (two held ports -> "2 port(s)") and that a held
    port is SKIPPED, never shared: neither fake is written to at all.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeAtModem(imei=SIBLING_IMEI, firmware="EG25GGBR07A08M2G") as sib, \
            FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", f"{at.port} {sib.port}")
        claims = [HeldClaim(at.port), HeldClaim(sib.port)]
        try:
            run = CellDiagRun(binary, _definition(dg.port), timeout=25.0,
                              stop_when=_brought_up).run()
        finally:
            for c in claims:
                c.release()
        cmds = list(at.commands) + list(sib.commands)

    notices = _notices(run)
    assert len(notices) == 1, (
        f"a port busy through the rescan must cost exactly ONE rescan; got "
        f"{len(notices)}: {notices!r}")
    assert "not found while 2 port(s) were held by another process" in notices[0], (
        f"both held ports must be counted as busy: {notices[0]!r}")
    assert any("AT identify rescan: IMEI still not found" in m
               for m in run.messages), run.messages
    assert cmds == [], (
        f"a port whose claim is held must be skipped, never written to; the "
        f"fakes saw {cmds!r}")
    assert run.open_code == 1, (
        f"an explicit diagport= still opens without AT identity; got "
        f"{run.open_code} {run.open_message!r}")
    assert any("model/firmware unresolved" in m and "unknown" in m
               for m in run.messages), (
        f"proceeding without AT identity must say the model reads 'unknown'; "
        f"messages={run.messages!r}")


def test_a_silent_port_is_not_busy_and_earns_no_rescan(monkeypatch):
    """The gate: a port that is merely not a modem (a DIAG or NMEA function that
    never answers AT) is not busy, so an empty scan must NOT rescan -- "absent"
    and "busy" are the whole distinction the EWOULDBLOCK plumbing exists for."""
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, silent=True) as at, \
            FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", at.port)
        run = CellDiagRun(binary, _definition(dg.port), timeout=25.0,
                          stop_when=_brought_up).run()
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert not _notices(run), (
        f"a silent port is not a busy one, yet the scan rescanned: "
        f"{_notices(run)!r}")
    assert any("not on any scanned AT port" in m for m in run.messages), (
        f"the scan should have come back empty; messages={run.messages!r}")
