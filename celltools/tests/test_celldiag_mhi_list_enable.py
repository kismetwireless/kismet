# SPDX-License-Identifier: Apache-2.0
"""A PCIe/MHI modem is offered by ``--list`` and opens from a bare definition.

## The problem

A PCIe RM520N-GL has AT on ``/dev/mhi_DUN`` and DIAG on ``/dev/mhi_DIAG``. A
lister that walks only the USB ttys offers its AT source but never its DIAG
source. The non-USB AT nodes stay out of the USB pass on purpose (a USB source
must not AT-probe ``mhi_DUN`` first), so without a separate pass a bare
``celldiag-<imei>`` -- which is what the panel's Enable click sends -- fails
"not found on any serial port", and enabling DIAG means hand-writing
``atport=``/``diagport=``.

## The behavior

* ``--list`` runs a non-USB pass AFTER the USB one. A row is offered only when
  the DIAG node resolves unambiguously by name, and a held AT node is asked
  about through its holder's vouch.
* A bare definition falls back to the non-USB AT nodes only after the USB scan
  misses, and ``find_diag_port()`` resolves a non-USB AT sibling's DIAG node by
  name.

## How an MHI modem is built offline

As in ``test_celldiag_mhi_identity``: symlinks named ``mhi_DUN`` and
``mhi_DIAG`` point at PTY fakes, and ``CELLDIAG_SCAN_PORTS`` names the universe.
A named universe is the whole universe for the DIAG-by-name pick too, so these
tests never select the host's real ``/dev/mhi_*``, which may be a real modem.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from test_cellat_ipc import _binary_or_skip as _cellat_or_skip  # noqa: E402
from celldiag_run import CellDiagRun, _binary_or_skip  # noqa: E402
from test_celldiag_vouch import CellatHolder, HeldClaim  # noqa: E402

IMEI = "866436060049820"  # Luhn-INVALID on purpose: never a real device
FIRMWARE = "RM520NGLAAR01A08M4G"
DECOY_IMEI = "353456789049823"
CGMM = {"AT+CGMM": "RM520N-GL"}
FALLBACK_NOTE = "is not on any USB port; found on the non-USB AT node"


class _Bench:
    """A PCIe modem's nodes as symlinks, plus a USB-named decoy modem."""

    def __init__(self, tmp: Path, at: FakeAtModem, dg: FakeDiagModem,
                 decoy: FakeAtModem, extra_diag: "FakeDiagModem | None" = None):
        self.dun = tmp / "mhi_DUN"
        self.diag = tmp / "mhi_DIAG"
        self.decoy = tmp / "ttyUSB99"
        os.symlink(at.port, self.dun)
        os.symlink(dg.port, self.diag)
        os.symlink(decoy.port, self.decoy)
        self.universe = [self.decoy, self.dun, self.diag]
        if extra_diag is not None:          # a second modem's DIAG node
            self.qcdm = tmp / "wwan0qcdm0"
            os.symlink(extra_diag.port, self.qcdm)
            self.universe.append(self.qcdm)

    def env(self) -> str:
        return " ".join(str(p) for p in self.universe)


def _list(binary: str) -> str:
    r = subprocess.run([binary, "--list"], capture_output=True, text=True,
                       timeout=60)
    return r.stdout + r.stderr


def _modems():
    return (FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer="Quectel",
                        extra={**QENG_SERVING, **CGMM}),
            FakeDiagModem(),
            FakeAtModem(imei=DECOY_IMEI))


def test_list_offers_the_mhi_modem_after_the_usb_ones(tmp_path, monkeypatch):
    """Lister half: the MHI modem is listed, after the USB decoy."""
    binary = _binary_or_skip()
    at, dg, decoy = _modems()
    with at, dg, decoy:
        bench = _Bench(tmp_path, at, dg, decoy)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", bench.env())
        out = _list(binary)
    # Positive control: the USB pass ran and listed the decoy -- a lister that
    # listed nothing would pass the ordering assertion below vacuously.
    assert f"celldiag-{DECOY_IMEI}" in out, out
    assert f"celldiag-{IMEI}" in out, out
    row = next(ln for ln in out.splitlines() if f"celldiag-{IMEI}" in ln)
    assert "RM520N-GL" in row and row.rstrip().endswith("DIAG)"), row
    assert out.index(f"celldiag-{DECOY_IMEI}") < out.index(f"celldiag-{IMEI}"), out
    # The USB pass never reached mhi_DUN: exactly one identify there, the
    # non-USB pass's own (the reason it is kept out of SCAN_ALL_PORTS).
    assert at.commands.count("AT+CGSN") == 1, at.commands


def test_list_withholds_the_row_when_the_diag_node_is_ambiguous(tmp_path,
                                                                 monkeypatch):
    """Two modems' DIAG nodes by name, and no anchor to tell which is which: a
    row offered here could only open the wrong modem or fail, so none is."""
    binary = _binary_or_skip()
    at, dg, decoy = _modems()
    with at, dg, decoy, FakeDiagModem() as dg2:
        bench = _Bench(tmp_path, at, dg, decoy, extra_diag=dg2)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", bench.env())
        out = _list(binary)
    assert f"celldiag-{DECOY_IMEI}" in out, out
    assert f"celldiag-{IMEI}" not in out, out
    assert "not listing the non-USB modem" in out, out
    assert "mhi_DUN" not in "".join(at.commands), at.commands
    assert at.commands == [], "a withheld row must not cost an AT probe"


def test_list_reads_a_held_mhi_dun_through_its_holders_vouch(tmp_path, monkeypatch):
    """The paired cellat source holds mhi_DUN for as long as it runs; the DIAG
    row must not vanish exactly while the AT row is in use."""
    binary, at_bin = _binary_or_skip(), _cellat_or_skip()
    vdir = tmp_path / "vouch"
    monkeypatch.setenv("KISMET_CELL_VOUCH_DIR", str(vdir))
    at, dg, decoy = _modems()
    with at, dg, decoy:
        bench = _Bench(tmp_path, at, dg, decoy)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", bench.env())
        with CellatHolder(at_bin, IMEI, str(bench.dun), vdir, graceful=True):
            probes = at.commands.count("AT+CGSN")
            out = _list(binary)
            assert at.commands.count("AT+CGSN") == probes, (
                "the lister wrote to a held port")
    assert f"celldiag-{IMEI}" in out, out


def test_list_drops_a_held_node_that_nobody_vouches_for(tmp_path, monkeypatch):
    """Control for the vouch test: the same hold by a process that publishes
    nothing yields no row, after the bounded retries."""
    binary = _binary_or_skip()
    monkeypatch.setenv("KISMET_CELL_VOUCH_DIR", str(tmp_path / "vouch"))
    at, dg, decoy = _modems()
    with at, dg, decoy:
        bench = _Bench(tmp_path, at, dg, decoy)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", bench.env())
        hold = HeldClaim(str(bench.dun))
        try:
            out = _list(binary)
        finally:
            hold.release()
    assert f"celldiag-{DECOY_IMEI}" in out, out
    assert f"celldiag-{IMEI}" not in out, out


def test_list_never_offers_one_imei_twice(tmp_path, monkeypatch):
    """A modem the USB pass already listed is not listed again by the non-USB
    pass: one IMEI is one row, or the panel shows two Enable buttons for one
    modem. (Both names point at the SAME fake, so both passes identify it.)"""
    binary = _binary_or_skip()
    at, dg, decoy = _modems()
    with at, dg, decoy:
        bench = _Bench(tmp_path, at, dg, decoy)
        usb_alias = tmp_path / "ttyUSB98"
        os.symlink(at.port, usb_alias)
        bench.universe.append(usb_alias)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", bench.env())
        out = _list(binary)
    rows = [ln for ln in out.splitlines() if f"celldiag-{IMEI} " in ln]
    assert len(rows) == 1, out


def _brought_up(run: CellDiagRun) -> bool:
    if any("bring-up failed" in m for m in run.messages):
        return True
    return bool(run.modem_identities) and any(
        "Cell DIAG source" in m and "opened (live" in m for m in run.messages)


def test_a_bare_definition_opens_the_mhi_modem(tmp_path, monkeypatch):
    """Open half: exactly what the Enable click sends -- no atport=, no
    diagport= -- opens instead of failing 'not found on any serial port'."""
    binary = _binary_or_skip()
    at, dg, decoy = _modems()
    with at, dg, decoy:
        bench = _Bench(tmp_path, at, dg, decoy)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", bench.env())
        run = CellDiagRun(binary,
                          f"celldiag-{IMEI}:nomask=true,stats_interval=0",
                          timeout=30.0, stop_when=_brought_up).run()
    assert not any("bring-up failed" in m for m in run.messages), run.messages
    assert any(FALLBACK_NOTE in m and str(bench.dun) in m
               for m in run.messages), run.messages
    assert any(f"{FIRMWARE} IMEI:{IMEI} DIAG opened (live" in m
               for m in run.messages), run.messages
    # The DIAG node is the NAMED one, never the host's /dev/mhi_DIAG.
    assert any(str(bench.diag) in m for m in run.messages), run.messages
    assert not any("/dev/mhi_DIAG" in m for m in run.messages), run.messages
    # The USB decoy was scanned first and did not answer as this IMEI.
    assert decoy.commands, "the USB pass should have run before the fallback"


def test_a_vouched_mhi_bring_up_says_how_its_diag_node_was_chosen(tmp_path,
                                                                 monkeypatch):
    """The vouch message must not say "the DIAG port is resolved from that
    port's USB device" -- false for a node with no USB device."""
    binary, at_bin = _binary_or_skip(), _cellat_or_skip()
    vdir = tmp_path / "vouch"
    monkeypatch.setenv("KISMET_CELL_VOUCH_DIR", str(vdir))
    at, dg, decoy = _modems()
    with at, dg, decoy:
        bench = _Bench(tmp_path, at, dg, decoy)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", bench.env())
        with CellatHolder(at_bin, IMEI, str(bench.dun), vdir, graceful=True):
            run = CellDiagRun(binary,
                              f"celldiag-{IMEI}:nomask=true,stats_interval=0",
                              timeout=30.0, stop_when=_brought_up).run()
    vouch = [m for m in run.messages if "vouched for it" in m]
    assert len(vouch) == 1, run.messages
    assert "chosen by wwan/MHI node name" in vouch[0], vouch[0]
    assert "USB device" not in vouch[0], vouch[0]
    assert any(f"DIAG node selected by wwan/MHI name: {bench.diag}" in m
               for m in run.messages), run.messages


def test_a_bare_definition_for_an_absent_modem_still_fails_naming_both_scans(
        tmp_path, monkeypatch):
    binary = _binary_or_skip()
    at, dg, decoy = _modems()
    with at, dg, decoy:
        bench = _Bench(tmp_path, at, dg, decoy)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", bench.env())
        run = CellDiagRun(binary,
                          "celldiag-359999999999994:nomask=true,stats_interval=0",
                          timeout=30.0, stop_when=_brought_up).run()
    failed = [m for m in run.messages if "bring-up failed" in m]
    assert failed, run.messages
    assert "not found on any serial port or non-USB (MHI/wwan) AT node" in \
        " ".join(run.messages + run.errors), run.messages
