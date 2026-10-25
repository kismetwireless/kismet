# SPDX-License-Identifier: Apache-2.0
"""An MHI/wwan celldiag source reads its model from the non-USB AT node.

## The problem

A celldiag source whose ``diagport=`` is an MHI or wwan node (the PCIe
RM520N-GL's ``/dev/mhi_DIAG``) has no ttyUSB to scan, and in a fused
cellat+celldiag capture its one AT node, ``/dev/mhi_DUN``, is held by the paired
cellat source. Skipping AT identity there leaves the model ``unknown`` -- in the
rawlog name, in ``prov.model``, in the opened line.

## The behavior

That branch scans the non-USB AT nodes only (``/dev/mhi_DUN``,
``/dev/wwan*at*``, filtered by the shared classifier), so it neither AT-probes
every USB modem's ports nor misses its own. A node the paired cellat holds is
refused ``EWOULDBLOCK`` and never shared: one rescan, then the
"without AT identity" fallback. The other half of that contention -- cellat's
own open meeting this probe's claim -- is handled by cellat's claim wait.

## How an MHI modem is built offline

The branch keys on the diagport's NAME (``diag_wwan_classify`` reads the
basename), so symlinks named ``mhi_DIAG`` and ``mhi_DUN`` pointing at PTY fakes
engage the real MHI path in the real binary. ``CELLDIAG_SCAN_PORTS`` names the
universe, and a decoy fake behind a ``ttyUSB``-named link is in it too: the
non-USB scope must not probe it.
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

IMEI = "866436060047480"
FIRMWARE = "RM520NGLAAR01A08M4G"
DECOY_IMEI = "353456789047481"

IDENTITY_NOTE = "AT identity from"
FALLBACK_NOTE = "no non-USB AT node answered as this IMEI"
RESCAN_NOTICE = "rescanning once in"


def _definition(diagport: Path) -> str:
    parts = [f"diagport={diagport}", "nomask=true", "stats_interval=0"]
    return f"celldiag-{IMEI}:" + ",".join(parts)


def _brought_up(run: CellDiagRun) -> bool:
    return any(("Cell DIAG source" in m and "opened (live" in m)
               or "bring-up failed" in m for m in run.messages)


class _Bench:
    """A PCIe modem's nodes as symlinks, plus a USB decoy, under one tmp dir."""

    def __init__(self, tmp: Path, at: FakeAtModem, dg: FakeDiagModem,
                 decoy: FakeAtModem) -> None:
        self.diag = tmp / "mhi_DIAG"
        self.dun = tmp / "mhi_DUN"
        self.decoy = tmp / "ttyUSB99"
        os.symlink(dg.port, self.diag)
        os.symlink(at.port, self.dun)
        os.symlink(decoy.port, self.decoy)


def test_an_mhi_diagport_source_resolves_its_model_from_mhi_DUN(tmp_path, monkeypatch):
    """The model is the firmware read on mhi_DUN, and the USB decoy in the
    same named universe is never probed."""
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeAtModem(imei=DECOY_IMEI, firmware="EG25GGBR07A08M2G") as decoy, \
            FakeDiagModem() as dg:
        bench = _Bench(tmp_path, at, dg, decoy)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", f"{bench.decoy} {bench.dun}")
        run = CellDiagRun(binary, _definition(bench.diag), timeout=25.0,
                          stop_when=_brought_up).run()
        at_cmds, decoy_cmds = list(at.commands), list(decoy.commands)
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert any(IDENTITY_NOTE in m and f"AT identity from {bench.dun}" in m
               for m in run.messages), run.messages
    assert any(f"{FIRMWARE} IMEI:{IMEI} DIAG opened" in m for m in run.messages), (
        f"the model must be the firmware read on mhi_DUN; messages={run.messages!r}")
    assert not any("model/firmware unresolved" in m for m in run.messages), (
        "the 'unknown' model fallback fired although mhi_DUN answered")
    assert "AT+CGSN" in at_cmds, at_cmds
    assert decoy_cmds == [], (
        f"the non-USB scope AT-probed a ttyUSB node: {decoy_cmds!r}")


def test_mhi_DUN_held_by_the_paired_cellat_falls_back_after_one_rescan(tmp_path, monkeypatch):
    """The contention case: the paired cellat source holds mhi_DUN for its
    whole session. The probe is refused, never
    shared -- one rescan, then the source still opens, model 'unknown', and
    mhi_DUN is never written to."""
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeAtModem(imei=DECOY_IMEI, firmware="X") as decoy, \
            FakeDiagModem() as dg:
        bench = _Bench(tmp_path, at, dg, decoy)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", str(bench.dun))
        fd = os.open(at.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            run = CellDiagRun(binary, _definition(bench.diag), timeout=25.0,
                              stop_when=_brought_up).run()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        at_cmds = list(at.commands)
    assert run.open_code == 1, (run.open_code, run.open_message)
    notices = [m for m in run.messages if RESCAN_NOTICE in m]
    assert len(notices) == 1 and "1 port(s) were held" in notices[0], notices
    assert any(FALLBACK_NOTE in m for m in run.messages), run.messages
    assert any("model/firmware unresolved" in m and "unknown" in m for m in run.messages), run.messages
    assert at_cmds == [], f"a held mhi_DUN was written to: {at_cmds!r}"


def test_a_ttyusb_diagport_source_still_scans_the_usb_fleet(tmp_path, monkeypatch):
    """The scope is keyed on the diagport: a ttyUSB-class diagport keeps the full
    scan, so a USB modem named only by a non-MHI path is still found. Guards the
    non-USB scope against leaking into the common case."""
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE) as at, FakeDiagModem() as dg:
        usb_at = tmp_path / "ttyUSB2"
        os.symlink(at.port, usb_at)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", str(usb_at))
        run = CellDiagRun(binary, _definition(Path(dg.port)), timeout=25.0,
                          stop_when=_brought_up).run()
        at_cmds = list(at.commands)
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert any(f"{FIRMWARE} IMEI:{IMEI} DIAG opened" in m for m in run.messages), (
        run.messages)
    assert not any(IDENTITY_NOTE in m for m in run.messages)
    assert "AT+CGSN" in at_cmds
