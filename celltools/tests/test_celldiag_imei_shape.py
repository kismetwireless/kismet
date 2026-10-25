# SPDX-License-Identifier: Apache-2.0
"""A malformed AT+CGSN read is never a confident IMEI mismatch in celldiag.

## The hazard

Taking any value line of an ``AT+CGSN`` reply as the IMEI is unsafe: a PCIe
RM520N-GL can return the modem's ``AT+CGMI`` answer (a reply another prober
left on the port), which would list it as ``cellat-Quectel``.

In celldiag the wrong value does more than mislabel a ``--list`` row. On an
IMEI-targeted open the read is compared with the wanted IMEI, and a non-empty
value that differs is a **confident** mismatch: the scan then skips every
remaining port of that USB device. A stale ``Quectel`` would make the scan
walk past the very modem it is looking for, and nothing would say why.

So a read that is not 15 ASCII digits (``modemident_imei_ok()``) is asked once
more -- the exchange flushes input first, so a stale reply is dropped -- and a
second bad read is treated as "this port did not answer": no mismatch, no
device skip, and a reason in the scan's port detail (open) or on stderr
(``--list``).

## How it is reached offline

``CELLDIAG_SCAN_PORTS`` names the scan's whole universe, so the scan
probes only the PTY fake and never a host tty. The fake's ``sequence=`` answers
``AT+CGSN`` with the stale ``Quectel`` first, then with its IMEI.

The device skip itself cannot be observed here: a PTY has no USB device id,
and the skip is keyed on one. What is observable, and is the same decision, is
that a malformed read does not end the probe of the target's own port.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from celldiag_run import CellDiagRun, _binary_or_skip  # noqa: E402

IMEI = "351234567890123"          # synthetic, same shape as an RM520N-GL IMEI
STALE = "Quectel"                 # its AT+CGMI answer, read as the IMEI
FIRMWARE = "RM520NGLAAR01A08M4G"

#: The scan's port-detail note for a port whose read was twice not an IMEI.
BAD_IMEI_NOTE = "answered AT+CGSN with no IMEI"


def _rm520n(**kw) -> FakeAtModem:
    return FakeAtModem(firmware=FIRMWARE, manufacturer="Quectel",
                       extra={"AT+CGMM": "RM520N-GL"}, **kw)


def _definition(diagport: str) -> str:
    return (f"celldiag-{IMEI}:diagport={diagport},nomask=true,"
            "stats_interval=0")


def _brought_up(run: CellDiagRun) -> bool:
    return any(("Cell DIAG source" in m and "opened (live" in m)
               or "bring-up failed" in m for m in run.messages)


def _resolved(run: CellDiagRun) -> bool:
    """The scan found the target and named the source after its firmware."""
    return any(f"{FIRMWARE} IMEI:{IMEI} DIAG opened" in m for m in run.messages)


def _open(binary: str, dg_port: str) -> CellDiagRun:
    return CellDiagRun(binary, _definition(dg_port), timeout=25.0,
                       stop_when=_brought_up).run()


def _list(binary: str) -> "tuple[list[str], str]":
    out = subprocess.run([binary, "--list"], capture_output=True, text=True,
                         timeout=90)
    lines = [ln.strip() for ln in (out.stdout + out.stderr).splitlines()]
    return lines, out.stderr


# --- the open path (the sharper half) ---------------------------------------

def test_a_well_formed_modem_is_found_and_asked_once(monkeypatch):
    """Positive control: the scan reaches the PTY and resolves the target with
    ONE AT+CGSN. Without it the tests below could pass because the scan never
    saw the fake, and the "exactly two" counts would have no baseline."""
    binary = _binary_or_skip()
    with _rm520n(imei=IMEI) as at, FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", at.port)
        run = _open(binary, dg.port)
        cmds = list(at.commands)
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert cmds.count("AT+CGSN") == 1, cmds
    assert _resolved(run), run.messages
    assert not any(BAD_IMEI_NOTE in m for m in run.messages), run.messages


def test_a_stale_first_reply_does_not_make_the_target_a_mismatch(monkeypatch):
    """A stale ``Quectel`` reply is re-asked, not taken as a confident
    mismatch: the probe goes on to AT+CGMR and the model resolves, instead of
    the bring-up falling back to the explicit diagport= without AT identity."""
    binary = _binary_or_skip()
    with _rm520n(imei=IMEI, sequence={"AT+CGSN": [STALE]}) as at, \
            FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", at.port)
        run = _open(binary, dg.port)
        cmds = list(at.commands)
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert cmds.count("AT+CGSN") == 2, cmds
    assert "AT+CGMR" in cmds, (
        f"the probe stopped at the stale IMEI instead of reading the "
        f"firmware; the fake saw {cmds!r}")
    assert _resolved(run), run.messages


def test_a_persistently_malformed_imei_is_no_answer_and_is_named(monkeypatch):
    """Twice not an IMEI: asked once more, never forever, and the scan's port
    detail says which port and what it answered, rather than the port being
    silently a mismatch."""
    binary = _binary_or_skip()
    with _rm520n(imei=STALE) as at, FakeDiagModem() as dg:
        port = at.port
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", port)
        run = _open(binary, dg.port)
        cmds = list(at.commands)
    assert cmds.count("AT+CGSN") == 2, cmds
    assert "AT+CGMR" not in cmds, cmds   # still not a match: no firmware read
    assert not _resolved(run), run.messages
    notes = [m for m in run.messages if BAD_IMEI_NOTE in m]
    assert notes, f"no message says why the port was passed over: {run.messages!r}"
    assert os.path.basename(port) in notes[0] and STALE in notes[0], notes


# --- the --list twin of test_cellat_imei_shape -------------------------

def test_list_re_asks_a_stale_reply_and_names_the_real_imei(monkeypatch):
    binary = _binary_or_skip()
    with _rm520n(imei=IMEI, sequence={"AT+CGSN": [STALE]}) as at:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", at.port)
        lines, _ = _list(binary)
        cmds = list(at.commands)
    assert cmds.count("AT+CGSN") == 2, cmds
    assert any(f"celldiag-{IMEI}" in ln for ln in lines), lines
    assert not any(f"celldiag-{STALE}" in ln or f"IMEI:{STALE}" in ln
                   for ln in lines), lines


def test_list_offers_no_source_for_a_persistently_malformed_imei(monkeypatch):
    binary = _binary_or_skip()
    with _rm520n(imei=STALE) as at:
        port = at.port
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", port)
        lines, err = _list(binary)
        cmds = list(at.commands)
    assert cmds.count("AT+CGSN") == 2, cmds
    assert not any("celldiag-" in ln and "DIAG" in ln for ln in lines), lines
    assert "not a 15-digit IMEI" in err, err
    assert port in err, err
