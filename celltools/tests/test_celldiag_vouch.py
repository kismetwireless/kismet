# SPDX-License-Identifier: Apache-2.0
"""A held AT port's holder vouches for the modem, so its DIAG pair opens.

## The problem

A typical setup runs a ``cellat-<imei>`` and a ``celldiag-<imei>`` source on
every modem. celldiag maps IMEI -> DIAG port by AT-probing the modem's ports,
and the paired cellat holds its AT port (an exclusive flock) for the whole run.
The claim carries no payload, so a scan that meets it learns only that the port
is busy. Without a vouch, a single-AT-port modem such as the Foxconn T99W175
never opens its DIAG source, and a two-port modem such as the RM500Q-AE opens
only when its second AT port happens not to be mid-probe.

## The mechanism

cellat publishes what it read on the port it holds (``diag_identvouch``); a
celldiag scan that meets a busy port accepts that record once it has validated
it -- same device node instance, writer alive -- and the identity it reports
says ``method: "vouched"``, never ``"at"``.

## How it is reached offline

As in ``test_celldiag_at_rescan``: ``CELLDIAG_SCAN_PORTS`` replaces the
scan's ``/dev/ttyUSB*`` universe with the fakes' PTYs, and an explicit
``diagport=`` names the fake DIAG node (a PTY has no USB sibling to resolve).
The holder is the **real** ``kismet_cap_cell_at`` against the same fake, so the
record under test is the one the shipping writer produces, and the vouch
directory is a per-test ``KISMET_CELL_VOUCH_DIR``.

## What each test pins

* ``..._the_paired_cellat_holds_the_port_and_celldiag_still_identifies`` -- the
  fix: identity recovered, marked ``vouched``, no rescan spent.
* ``..._without_a_vouch_the_same_hold_opens_without_identity`` -- the control:
  the same busy port held by a non-vouching process still yields
  ``definition``. Without it the first test could pass for another reason.
* ``..._cellat_withdraws_its_vouch_on_a_graceful_close`` -- lifecycle.
* ``..._a_dead_holders_vouch_is_refused`` -- a record left by a holder that was
  killed (Kismet's SIGTERM runs no teardown) must not vouch for anything.
* ``..._a_vouch_for_another_modem_costs_no_rescan`` -- a vouched mismatch settles
  the port like an AT mismatch would.
"""
from __future__ import annotations

import fcntl
import json
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from test_cellat_ipc import CellAtRun, _binary_or_skip as _cellat_or_skip  # noqa: E402
from celldiag_run import CellDiagRun  # noqa: E402
from celldiag_run import _binary_or_skip as _celldiag_or_skip  # noqa: E402

IMEI = "351234567847131"
OTHER_IMEI = "359876543247139"
#: A measured EG25-G identity (AT+CGMM answers `EG25`, verbatim).
MAKE, MODEL, FIRMWARE = "Quectel", "EG25", "EG25GGBR07A08M2G"
CGMM = {"AT+CGMM": MODEL}
VOUCH_NOTICE = "vouched for it"
RESCAN_NOTICE = "rescanning once in"


def _vouch_file(vdir: Path, port: str) -> Path:
    return vdir / (port.replace("/", "_") + ".vouch")


def _diag_definition(diagport: str) -> str:
    parts = [f"diagport={diagport}", "nomask=true", "stats_interval=0"]
    return f"celldiag-{IMEI}:" + ",".join(parts)


def _brought_up(run: CellDiagRun) -> bool:
    """The bring-up finished AND its ModemIdentity record has arrived.

    Not "the opened message arrived": the record is sent just AFTER it, so a
    predicate on the message alone can stop the run before the record arrives,
    giving a flaky "no ModemIdentity record"."""
    if any("bring-up failed" in m for m in run.messages):
        return True
    return bool(run.modem_identities) and any(
        "Cell DIAG source" in m and "opened (live" in m for m in run.messages)


def _identity(run: CellDiagRun) -> dict:
    recs = [json.loads(s) for s in run.modem_identities]
    assert recs, f"no ModemIdentity record; messages={run.messages!r}"
    return recs[-1]


class HeldClaim:
    """A process that holds the port's claim and vouches for NOTHING -- the
    shape of any other prober, or of a cellat that predates vouching."""

    def __init__(self, path: str) -> None:
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def release(self) -> None:
        if self.fd >= 0:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = -1


class CellatHolder:
    """The paired cellat source, running on its own thread for as long as the
    test needs the port held. ``graceful`` closes it the way a Kismet stop
    does (pipe EOF, teardown runs); otherwise the harness SIGTERMs it the
    way a crash or an old server would, and no teardown runs."""

    def __init__(self, binary: str, imei: str, port: str, vdir: Path,
                 graceful: bool) -> None:
        self._stop = threading.Event()
        self.record = _vouch_file(vdir, port)
        self.run = CellAtRun(binary, f"cellat-{imei}:atport={port}",
                             timeout=60.0, stop_when=lambda r: self._stop.is_set(),
                             graceful_close_s=5.0 if graceful else 0.0)
        self._t = threading.Thread(target=self.run.run, daemon=True)

    def __enter__(self) -> "CellatHolder":
        self._t.start()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not self.record.exists():
            if not self._t.is_alive():
                break
            time.sleep(0.05)
        assert self.record.exists(), (
            f"the holder never vouched: no {self.record.name}; open="
            f"{self.run.open_code} {self.run.open_message!r} errors={self.run.errors!r}")
        return self

    def stop(self) -> None:
        self._stop.set()
        self._t.join(timeout=30)

    def __exit__(self, *exc) -> None:
        self.stop()


def test_the_paired_cellat_holds_the_port_and_celldiag_still_identifies(
        monkeypatch, tmp_path):
    """The vouch recovers identity. Without it the busy port costs one rescan,
    the rescan finds it still busy, and the source opens as ``definition`` -- on
    a USB modem with no ``diagport=``, the bring-up fails outright."""
    diag_bin, at_bin = _celldiag_or_skip(), _cellat_or_skip()
    vdir = tmp_path / "vouch"
    monkeypatch.setenv("KISMET_CELL_VOUCH_DIR", str(vdir))
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra={**QENG_SERVING, **CGMM}) as at, FakeDiagModem() as dg:
        port = at.port
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", port)
        with CellatHolder(at_bin, IMEI, port, vdir, graceful=True):
            run = CellDiagRun(diag_bin, _diag_definition(dg.port), timeout=30.0,
                              stop_when=_brought_up).run()
    rec = _identity(run)
    assert rec["method"] == "vouched", rec
    assert (rec["imei"], rec["make"], rec["model"], rec["firmware"]) == (
        IMEI, MAKE, MODEL, FIRMWARE), rec
    assert rec["at_port"] == port, rec
    assert any(VOUCH_NOTICE in m for m in run.messages), run.messages
    assert not any(RESCAN_NOTICE in m for m in run.messages), (
        "a vouched port settled the scan; no rescan should be spent")
    assert any(f"{FIRMWARE} IMEI:{IMEI} DIAG opened" in m for m in run.messages), (
        f"the source should be named after the vouched firmware; {run.messages!r}")


def test_without_a_vouch_the_same_hold_opens_without_identity(monkeypatch, tmp_path):
    """The control: the same busy port, held by something that vouches for
    nothing, opens the source with ``definition`` identity and no vouch."""
    diag_bin = _celldiag_or_skip()
    vdir = tmp_path / "vouch"
    monkeypatch.setenv("KISMET_CELL_VOUCH_DIR", str(vdir))
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra=CGMM) as at, FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", at.port)
        claim = HeldClaim(at.port)
        try:
            run = CellDiagRun(diag_bin, _diag_definition(dg.port), timeout=30.0,
                              stop_when=_brought_up).run()
        finally:
            claim.release()
    assert _identity(run)["method"] == "definition", run.modem_identities
    assert not any(VOUCH_NOTICE in m for m in run.messages), run.messages


def test_cellat_withdraws_its_vouch_on_a_graceful_close(monkeypatch, tmp_path):
    at_bin = _cellat_or_skip()
    vdir = tmp_path / "vouch"
    monkeypatch.setenv("KISMET_CELL_VOUCH_DIR", str(vdir))
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra={**QENG_SERVING, **CGMM}) as at:
        with CellatHolder(at_bin, IMEI, at.port, vdir, graceful=True) as h:
            text = h.record.read_text()
            mode = h.record.stat().st_mode & 0o777
        record = h.record
    assert f"imei={IMEI}\n" in text and f"firmware={FIRMWARE}\n" in text, text
    assert mode == 0o600, oct(mode)
    assert (vdir.stat().st_mode & 0o777) == 0o700, oct(vdir.stat().st_mode)
    assert not record.exists(), "a graceful close must withdraw the vouch"


def test_a_dead_holders_vouch_is_refused(monkeypatch, tmp_path):
    """A holder killed without teardown leaves its record behind. It must not
    vouch for anything: the port is then held by someone ELSE, who said nothing."""
    diag_bin, at_bin = _celldiag_or_skip(), _cellat_or_skip()
    vdir = tmp_path / "vouch"
    monkeypatch.setenv("KISMET_CELL_VOUCH_DIR", str(vdir))
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra={**QENG_SERVING, **CGMM}) as at, FakeDiagModem() as dg:
        with CellatHolder(at_bin, IMEI, at.port, vdir, graceful=False) as h:
            record = h.record
        assert record.exists(), (
            "premise: a SIGTERMed holder leaves its record (else this test "
            "measures absence, not refusal)")
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", at.port)
        claim = HeldClaim(at.port)
        try:
            run = CellDiagRun(diag_bin, _diag_definition(dg.port), timeout=30.0,
                              stop_when=_brought_up).run()
        finally:
            claim.release()
    assert _identity(run)["method"] == "definition", run.modem_identities
    assert not any(VOUCH_NOTICE in m for m in run.messages), run.messages


def test_a_vouch_for_another_modem_costs_no_rescan(monkeypatch, tmp_path):
    """A busy port whose holder vouches for a DIFFERENT IMEI is settled -- it is
    not this modem -- exactly as an AT mismatch would settle it, rather than
    counting as busy and buying a rescan that cannot help."""
    diag_bin, at_bin = _celldiag_or_skip(), _cellat_or_skip()
    vdir = tmp_path / "vouch"
    monkeypatch.setenv("KISMET_CELL_VOUCH_DIR", str(vdir))
    with FakeAtModem(imei=OTHER_IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra={**QENG_SERVING, **CGMM}) as other, FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", other.port)
        with CellatHolder(at_bin, OTHER_IMEI, other.port, vdir, graceful=True):
            run = CellDiagRun(diag_bin, _diag_definition(dg.port), timeout=30.0,
                              stop_when=_brought_up).run()
    assert not any(RESCAN_NOTICE in m for m in run.messages), run.messages
    assert _identity(run)["method"] == "definition", run.modem_identities


def test_cellat_vouches_before_its_identity_read_completes(monkeypatch, tmp_path):
    """The early publish: the vouch exists while cellat's open is still running.

    A celldiag source opening at the SAME moment meets the claim, and its one
    rescan comes 250-775 ms later. The full record is written only after
    AT+CGMM, seconds into the open. So cellat publishes what its scan verified
    (IMEI + firmware) right after taking the claim. Here AT+CGMM never answers,
    which holds the open ~3 s on that read: the record must appear well before
    the open report, not with it.
    """
    at_bin = _cellat_or_skip()
    vdir = tmp_path / "vouch"
    monkeypatch.setenv("KISMET_CELL_VOUCH_DIR", str(vdir))
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra=QENG_SERVING, hang={"AT+CGMM"}) as at:
        record = _vouch_file(vdir, at.port)
        seen: dict[str, float] = {}

        def watch(run: CellAtRun) -> bool:
            now = time.monotonic()
            if "record" not in seen and record.exists():
                seen["record"] = now
            if "open" not in seen and run.open_code is not None:
                seen["open"] = now
            return "open" in seen

        run = CellAtRun(at_bin, f"cellat-{IMEI}:atport={at.port}", timeout=40.0,
                        stop_when=watch, poll_s=0.05, graceful_close_s=5.0).run()
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert "record" in seen, "cellat never vouched"
    lead = seen["open"] - seen["record"]
    assert lead >= 1.0, (
        f"the vouch appeared only {lead:.2f} s before the open report; the early "
        f"publish would put it ~3 s ahead (the hung AT+CGMM read)")
