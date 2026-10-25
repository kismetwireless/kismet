# SPDX-License-Identifier: Apache-2.0
"""celldiag's first DIAG command survives junk a scanner left in the port.

## The hazard

cellat's IMEI scan writes ``AT\\r\\n`` into every tty it can claim -- a modem's
DIAG node included; only celldiag's own scan skips those. A DIAG node does not
answer AT, but its HDLC parser keeps the four bytes as the head of a frame. The
next frame to arrive -- celldiag's first command -- is glued onto them, fails
its CRC, and is never answered. On an EG25-G this leaves the SPC unlock
unanswered until its deadline; one lone ``0x7E`` after the probe clears it.

## The guard, and how this file sees it

``diag_capture_open()`` sends one lone ``0x7E`` once it holds the port's
claim: an empty frame the modem discards, which terminates whatever partial
frame was pending. ``FakeDiagModem`` behaves like the modem here -- it splits
on ``0x7E`` and drops a frame whose CRC fails -- so a scan probe written into
its port before celldiag opens it reproduces the hazard offline.

With ``nomask=true`` the first command celldiag sends is the START clock
anchor (``DIAG_TS_F``), and ``clock_anchor_sec=0`` asks for nothing after it,
so a lost first command shows as a run with no anchor at all.
"""
from __future__ import annotations

import fcntl
import json
import os
import sys
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from celldiag_run import CellDiagRun, _binary_or_skip  # noqa: E402

IMEI = "353456789047370"          # not Luhn-valid: never reads as a real device
FIRMWARE = "EG25GGBR07A08M2G"


def _definition(at: FakeAtModem, dg: FakeDiagModem) -> str:
    parts = [f"atport={at.port}", f"diagport={dg.port}", "nomask=true",
             "defer=false", "stats_interval=0", "clock_anchor_sec=0"]
    return f"celldiag-{IMEI}:" + ",".join(parts)


def _scan_probe(port: str) -> None:
    """What cellat's IMEI scan does to a port it can claim: open, claim, write
    ``AT\\r\\n``, close. On a DIAG node the modem keeps those four bytes."""
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, b"AT\r\n")
    finally:
        os.close(fd)


def _run(probe_first: bool):
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, FakeDiagModem() as dg:
        if probe_first:
            _scan_probe(dg.port)
            time.sleep(0.3)   # the fake has read the junk into its frame buffer
        run = CellDiagRun(binary, _definition(at, dg), timeout=6.0,
                          stop_when=lambda r: len(r.clock_anchors) >= 1).run()
        requests = dg.ts_f_requests()
    return [json.loads(js)["edge"] for js in run.clock_anchors], requests, run


def test_the_first_command_after_a_scan_probe_is_still_answered():
    """The resync flag ends the junk frame, so the START request is answered.
    Without it the request is glued to the probe's bytes, fails its CRC, and
    the run ends with no anchor."""
    edges, requests, run = _run(probe_first=True)
    assert edges == ["start"], (
        f"the first DIAG command after a scan probe was lost: anchors={edges}, "
        f"messages={run.messages[-6:]!r}")
    assert requests == 1


def test_without_a_probe_the_first_command_is_answered_too():
    """The positive control: the fake, the harness and the anchor all work on a
    clean port, so the test above measures the probe and nothing else."""
    edges, requests, _ = _run(probe_first=False)
    assert edges == ["start"] and requests == 1, (edges, requests)
