# SPDX-License-Identifier: Apache-2.0
"""Every cell source names its modem, from the modem, in the .kismet.

## Why

A Kismet cell drive writes ONE ``.kismet`` for every modem in the car. Without
this record the container keeps, per source, only the IMEI in the source name --
and a celldiag source's ``hardware`` stays at the bring-up placeholder
``"DIAG opening IMEI:<imei> DIAG"``, because the deferred bring-up learns the
firmware seconds after the open report. A reader could then say which modem a
stream came from only by looking the IMEI up in an inventory file -- and a
Kismet user does not have one. So the capture helpers read the identity
themselves and persist it, and the Sources panel shows it for
a modem that is not open yet.

## What this file pins, end to end

* **helper** (IPC harness, no server): each helper sends ONE ``ModemIdentity``
  record per open, carrying the modem's own AT+CGMI / +CGMM / +CGMR / +CGSN
  answers verbatim, and the list answer (``--list``, which the web UI's Sources
  panel shows for a source that is not open) names make / model / firmware.
  A celldiag source that could not ask the modem says so (``method:
  "definition"``) instead of presenting its addressed IMEI as a reading.
* **cost**: an IMEI-targeted open scan does not read the make/model of the
  modems it passes over.
* **server** (a real isolated ``kismet``, kismetdb logging on): the record sets
  ``kismet.datasource.cell.modem_*``, replaces the placeholder hardware, and
  lands in the kismetdb as a ``ModemIdentity`` data row; ``list_interfaces``
  names a modem no source has open.

Every modem here is a PTY fake (``fake_at_modem`` / ``fake_diag_modem``) reached
through the ``*_SCAN_PORTS`` overrides, so no host tty is touched.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from test_cellat_ipc import CellAtRun, _binary_or_skip as _cellat_or_skip  # noqa: E402
from celldiag_run import CellDiagRun  # noqa: E402
from celldiag_run import _binary_or_skip as _celldiag_or_skip  # noqa: E402
from test_celldiag_server_routes import KP_ROOT, SERVER  # noqa: E402
from test_graceful_close_server import LoggingKismetServer  # noqa: E402

IMEI = "351234567847131"
OTHER_IMEI = "359876543247139"
#: A real EG25-G identity (firmware EG25GGBR07A08M2G_01.003.01.003):
#: AT+CGMM answers `EG25`, NOT the product name `EG25-G` -- kept verbatim.
MAKE, MODEL, FIRMWARE = "Quectel", "EG25", "EG25GGBR07A08M2G"
CGMM = {"AT+CGMM": MODEL}
LABEL_AT = f"{MAKE} {MODEL} ({FIRMWARE}) IMEI:{IMEI}"
LABEL_DIAG = LABEL_AT + " DIAG"
TYPE = "ModemIdentity"


def _records(run) -> list[dict]:
    return [json.loads(s) for s in run.modem_identities]


def _identified(run) -> bool:
    return bool(run.modem_identities)


def _diag_definition(diagport: str) -> str:
    parts = [f"diagport={diagport}", "nomask=true", "stats_interval=0"]
    return f"celldiag-{IMEI}:" + ",".join(parts)


def _list(binary: str, env: dict) -> list[str]:
    """``<binary> --list``: the list answer, one ``    <iface> (<hardware>)`` line
    per modem (capture_framework.c prints it on stderr)."""
    out = subprocess.run([binary, "--list"], capture_output=True, text=True,
                         timeout=90, env={**os.environ, **env})
    return [ln.strip() for ln in (out.stdout + out.stderr).splitlines()]


# ── celldiag, helper only ─────────────────────────────────────────────────────

def test_celldiag_reports_the_modem_its_deferred_bringup_found(monkeypatch):
    """A deferred open reports the placeholder, then the bring-up
    sends the modem's own identity. The record is the ONLY way the real identity
    leaves the helper after the open report."""
    binary = _celldiag_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra=CGMM, echo=True) as at, FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", at.port)
        run = CellDiagRun(binary, _diag_definition(dg.port), timeout=30.0,
                          stop_when=_identified).run()
        at_port = at.port
    assert run.open_code == 1, (run.open_code, run.open_message)
    # What the open report carried -- and what the .kismet would otherwise keep.
    assert run.open_hardware == f"DIAG opening IMEI:{IMEI} DIAG", run.open_hardware
    recs = _records(run)
    assert len(recs) == 1, recs
    assert recs[0] == {
        "v": 1, "source_type": "celldiag", "method": "at", "imei": IMEI,
        "make": MAKE, "model": MODEL, "firmware": FIRMWARE, "at_port": at_port,
        "label": LABEL_DIAG,
    }, recs[0]


def test_celldiag_without_an_at_identity_says_so(monkeypatch, tmp_path):
    """No AT port answers as this IMEI, and an explicit diagport= lets the source
    proceed anyway (the fused MHI shape, where the paired cellat source holds the
    AT node). The record must say the IMEI is the ADDRESSED one and carry no
    make/model/firmware -- never an empty string that reads as a measurement."""
    binary = _celldiag_or_skip()
    with FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", str(tmp_path / "no-such-tty"))
        run = CellDiagRun(binary, _diag_definition(dg.port), timeout=30.0,
                          stop_when=_identified).run()
    assert run.open_code == 1, (run.open_code, run.open_message)
    recs = _records(run)
    assert recs == [{"v": 1, "source_type": "celldiag", "method": "definition",
                     "imei": IMEI, "label": f"IMEI:{IMEI} DIAG"}], recs


def test_celldiag_replay_sends_no_identity(tmp_path):
    """A replay reads a file, not a modem: it has no identity to report, and a
    record would attribute the file's bytes to whatever IMEI the operator typed."""
    binary = _celldiag_or_skip()
    replay = tmp_path / "empty.hdlc"
    replay.write_bytes(b"")
    defn = (f"celldiag-{IMEI}:replay={replay},nomask=true,stats_interval=0")
    run = CellDiagRun(binary, defn, timeout=8.0).run()
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert run.modem_identities == [], run.modem_identities


def test_celldiag_list_names_the_modem():
    """The Sources panel's answer for a source that is not open: make, model and
    firmware -- not the firmware alone, which is what an operator got before."""
    binary = _celldiag_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra=CGMM, echo=True) as at:
        lines = _list(binary, {"CELLDIAG_SCAN_PORTS": at.port})
    assert f"celldiag-{IMEI} ({LABEL_DIAG})" in lines, lines


def test_celldiag_open_scan_skips_make_model_of_other_modems(monkeypatch):
    """Cost pin: the IMEI-targeted scan leaves a non-target modem on its IMEI
    mismatch, before the firmware read and before make/model."""
    binary = _celldiag_or_skip()
    with FakeAtModem(imei=OTHER_IMEI, firmware=FIRMWARE, extra=CGMM) as other, \
            FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                        extra=CGMM) as at, FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", f"{other.port} {at.port}")
        run = CellDiagRun(binary, _diag_definition(dg.port), timeout=30.0,
                          stop_when=_identified).run()
        other_cmds, target_cmds = list(other.commands), list(at.commands)
    assert _records(run) and _records(run)[0]["model"] == MODEL, run.modem_identities
    assert "AT+CGSN" in other_cmds, f"positive control: other was probed: {other_cmds}"
    assert "AT+CGMI" not in other_cmds and "AT+CGMM" not in other_cmds, other_cmds
    assert "AT+CGMM" in target_cmds, target_cmds


# ── cellat, helper only ───────────────────────────────────────────────────────

def test_cellat_reports_the_modem_it_opened():
    """cellat opens synchronously, so its open report already names the modem,
    and the record follows at capture start."""
    binary = _cellat_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra={**QENG_SERVING, **CGMM}) as at:
        run = CellAtRun(binary, f"cellat-{IMEI}:atport={at.port}", timeout=30.0,
                        stop_when=_identified).run()
        at_port = at.port
    assert run.open_code == 1, (run.open_code, run.open_message)
    assert run.open_hardware == LABEL_AT, run.open_hardware
    recs = _records(run)
    assert len(recs) == 1, recs
    assert recs[0] == {
        "v": 1, "source_type": "cellat", "method": "at", "imei": IMEI,
        "make": MAKE, "model": MODEL, "firmware": FIRMWARE, "at_port": at_port,
        "label": LABEL_AT,
    }, recs[0]
    # The model exchange is also in the RawAT transcript, so the container keeps
    # the raw answer beside the record built from it. (The make is the answer
    # detect_vendor's AT+CGMI already had -- not asked for twice.)
    cmds = [json.loads(r).get("cmd") for r in run.raw_at]
    assert "AT+CGMM" in cmds, cmds


def test_cellat_list_names_the_modem():
    binary = _cellat_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra=CGMM) as at:
        lines = _list(binary, {"CELLAT_SCAN_PORTS": at.port})
    assert f"cellat-{IMEI} ({LABEL_AT})" in lines, lines


def test_cellat_open_scan_skips_make_model_of_other_modems(monkeypatch):
    """cellat's scan identifies every modem it passes (firmware + IMEI) before
    the callback compares IMEIs; make/model must not be added to that bill."""
    binary = _cellat_or_skip()
    with FakeAtModem(imei=OTHER_IMEI, firmware=FIRMWARE, extra=CGMM) as other, \
            FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                        extra={**QENG_SERVING, **CGMM}) as at:
        monkeypatch.setenv("CELLAT_SCAN_PORTS", f"{other.port} {at.port}")
        run = CellAtRun(binary, f"cellat-{IMEI}", timeout=40.0,
                        stop_when=_identified).run()
        other_cmds = list(other.commands)
    assert _records(run) and _records(run)[0]["model"] == MODEL, (
        run.open_message, run.modem_identities)
    assert "AT+CGSN" in other_cmds, f"positive control: other was probed: {other_cmds}"
    assert "AT+CGMM" not in other_cmds, other_cmds


# ── through a real server, into the kismetdb ──────────────────────────────────

#: Everything the server tests run through; a binary older than any of them
#: measures code nobody compiled -- skip, naming the rebuild.
_SERVER_DEPS = {
    SERVER: ("datasource_cell_at.cc", "datasource_cell_at.h",
             "datasource_cell_diag.cc", "datasource_cell_diag.h",
             "datasource_cell_modemident.h", "kis_datasource.cc"),
    KP_ROOT / "capture_cell_at" / "kismet_cap_cell_at": (
        "capture_cell_at/capture_cell_at.c", "capture_cell_diag/diag_modemident.c"),
    KP_ROOT / "capture_cell_diag" / "kismet_cap_cell_diag": (
        "capture_cell_diag/capture_cell_diag.c", "capture_cell_diag/diag_modemident.c"),
}


class CellOnlyServer(LoggingKismetServer):
    """A logging server that can launch ONLY this tree's two cell helpers.

    Two reasons, both about what a green run would otherwise mean:

    * ``kismet.conf`` searches ``%B`` (the install bindir) and a host may have
      OLDER cell helpers installed there, so a
      server test could exercise a helper nobody just compiled;
    * ``list_interfaces`` runs EVERY helper it finds, and some non-cell helpers
      open serial ports to list -- on a host with modems that is writing into real
      modems' AT ports from a unit test.

    So every ``helper_binary_path`` line is dropped from the copied confs and
    the search list is exactly this tree's ``capture_cell_at`` and
    ``capture_cell_diag``, whose own scans are confined to PTY fakes by the
    ``*_SCAN_PORTS`` overrides.
    """

    def __init__(self, tmp_path: Path, srcdef: str,
                 extra: "tuple[str, ...]" = ()) -> None:
        super().__init__(tmp_path, srcdef, extra=extra)
        for conf in self.conf.glob("*.conf"):
            kept = [ln for ln in conf.read_text().splitlines()
                    if not ln.strip().startswith("helper_binary_path")]
            conf.write_text("\n".join(kept) + "\n")
        with (self.conf / "kismet_site.conf").open("a") as fp:
            fp.write(f"helper_binary_path={KP_ROOT / 'capture_cell_at'}\n"
                     f"helper_binary_path={KP_ROOT / 'capture_cell_diag'}\n")


def _helper_is_this_trees(row: dict) -> None:
    """The source's live helper process is THIS tree's binary (Linux /proc)."""
    pid = row.get("kismet.datasource.ipc_pid")
    exe = Path(os.readlink(f"/proc/{pid}/exe")).resolve()
    assert KP_ROOT.resolve() in exe.parents, f"helper {exe} is not under {KP_ROOT}"


def _server_built_or_skip() -> None:
    for binary, deps in _SERVER_DEPS.items():
        if not binary.is_file():
            pytest.skip(f"no {binary.name} at {binary} -- build it in {KP_ROOT}")
        mtime = binary.stat().st_mtime
        stale = [d for d in deps if (KP_ROOT / d).stat().st_mtime > mtime]
        if stale:
            pytest.skip(f"{binary.name} is older than {', '.join(stale)} -- rebuild it")


def _await_row(srv, pred, timeout: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout
    row = None
    while time.monotonic() < deadline:
        row = srv.source()
        if row is not None and pred(row):
            return row
        time.sleep(0.5)
    raise AssertionError(f"no matching row in {timeout}s; last={row}\n{srv.tail()}")


def _db_rows(db: Path, sql: str, args=()) -> list:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def _blob(v) -> dict:
    return json.loads(bytes(v).decode() if isinstance(v, (bytes, memoryview)) else v)


F = "kismet.datasource.cell.modem_"


def _identity_fields(row: dict) -> dict:
    return {k[len(F):]: row.get(k) for k in (F + "make", F + "model", F + "firmware",
                                             F + "imei", F + "identity_method")}


def test_the_server_names_a_cellat_source_and_the_kismetdb_keeps_it(tmp_path):
    _server_built_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra={**QENG_SERVING, **CGMM}) as at:
        with CellOnlyServer(tmp_path, f"cellat-{IMEI}:atport={at.port},retry=false") as srv:
            row = _await_row(srv, lambda r: r.get(F + "identity_method") == "at")
            _helper_is_this_trees(row)
            uuid = row["kismet.datasource.uuid"]
        db = srv.kismetdb()

    assert _identity_fields(row) == {"make": MAKE, "model": MODEL, "firmware": FIRMWARE,
                                     "imei": IMEI, "identity_method": "at"}, row
    assert row["kismet.datasource.hardware"] == LABEL_AT, row["kismet.datasource.hardware"]

    recs = [(ds, _blob(js)) for ds, js in _db_rows(
        db, "SELECT datasource, json FROM data WHERE type = ?", (TYPE,))]
    assert len(recs) == 1, recs
    assert recs[0][0] == uuid, (recs[0][0], uuid)
    assert recs[0][1]["model"] == MODEL and recs[0][1]["label"] == LABEL_AT, recs
    # The source's own row: its hardware is the label (cellat reports it at open).
    ((ds_json,),) = _db_rows(db, "SELECT json FROM datasources WHERE uuid = ?", (uuid,))
    assert _blob(ds_json)["kismet.datasource.hardware"] == LABEL_AT


def test_a_deferred_celldiag_source_stops_reading_DIAG_opening(tmp_path, monkeypatch):
    """Without the record the hardware stays the bring-up placeholder for the
    source's whole life, and in the kismetdb. The record replaces it once the
    bring-up ends."""
    _server_built_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra=CGMM, echo=True) as at, FakeDiagModem() as dg:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", at.port)
        with CellOnlyServer(tmp_path, _diag_definition(dg.port) + ",retry=false") as srv:
            row = _await_row(srv, lambda r: r.get(F + "identity_method") == "at")
            _helper_is_this_trees(row)
            uuid = row["kismet.datasource.uuid"]
        db = srv.kismetdb()

    assert row["kismet.datasource.hardware"] == LABEL_DIAG, row["kismet.datasource.hardware"]
    assert _identity_fields(row) == {"make": MAKE, "model": MODEL, "firmware": FIRMWARE,
                                     "imei": IMEI, "identity_method": "at"}, row
    recs = [(ds, _blob(js)) for ds, js in _db_rows(
        db, "SELECT datasource, json FROM data WHERE type = ?", (TYPE,))]
    assert [(ds, r["label"]) for ds, r in recs] == [(uuid, LABEL_DIAG)], recs
    # And the source's own kismetdb row. It is rewritten only at open and
    # every kis_log_datasource_rate (30 s), and the shutdown rewrite does not
    # land -- so a session shorter than 30 s would persist "DIAG opening" and
    # empty modem fields unless the record re-logs the row when it lands.
    ((ds_json,),) = _db_rows(db, "SELECT json FROM datasources WHERE uuid = ?", (uuid,))
    ds_row = _blob(ds_json)
    assert ds_row["kismet.datasource.hardware"] == LABEL_DIAG, ds_row["kismet.datasource.hardware"]
    assert ds_row[F + "model"] == MODEL and ds_row[F + "identity_method"] == "at", ds_row


def test_list_interfaces_names_a_modem_no_source_has_open(tmp_path, monkeypatch):
    """Pulling up the Sources panel lists a modem
    that is NOT open with its make/model/firmware, read from the modem then."""
    _server_built_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra={**QENG_SERVING, **CGMM}) as opened, \
            FakeAtModem(imei=OTHER_IMEI, firmware="RM520NGLAAR01A08M4G",
                        manufacturer="Quectel", extra={"AT+CGMM": "RM520N-GL"}) as idle:
        # cellat lists ONLY the idle modem; the opened one is the server's source.
        monkeypatch.setenv("CELLAT_SCAN_PORTS", idle.port)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", str(tmp_path / "no-such-tty"))
        with CellOnlyServer(tmp_path, f"cellat-{IMEI}:atport={opened.port},retry=false") as srv:
            _helper_is_this_trees(srv.await_running(True))
            listed = srv.get("datasource/list_interfaces.json")
    rows = {r.get("kismet.datasource.probed.interface"):
            r.get("kismet.datasource.probed.hardware") for r in listed}
    want = f"Quectel RM520N-GL (RM520NGLAAR01A08M4G) IMEI:{OTHER_IMEI}"
    assert rows.get(f"cellat-{OTHER_IMEI}") == want, rows


def test_a_slow_lister_costs_its_own_entries_not_the_whole_list(tmp_path, monkeypatch):
    """The listing used to answer only when EVERY lister had, and nothing answered
    after its deadline: one slow lister left /datasource/list_interfaces blocked
    for good, which the web UI's 30 s ajax timeout rendered as "no interfaces".
    A cell lister is the slow kind -- it TALKS to every modem -- so this is the
    failure the Sources panel met. Now the deadline answers with what arrived."""
    _server_built_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra={**QENG_SERVING, **CGMM}) as opened, \
            FakeAtModem(imei=OTHER_IMEI, firmware="RM520NGLAAR01A08M4G",
                        extra={"AT+CGMM": "RM520N-GL"}) as fast, \
            FakeAtModem(imei="357777777777771", hang={"AT+CGMR", "AT+CGSN"}) as slow:
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", fast.port)   # answers in ms
        monkeypatch.setenv("CELLAT_SCAN_PORTS", slow.port)     # >= 3 s: past the deadline
        with CellOnlyServer(tmp_path, f"cellat-{IMEI}:atport={opened.port},retry=false",
                            extra=("datasource_list_timeout=2",)) as srv:
            _helper_is_this_trees(srv.await_running(True))
            t0 = time.monotonic()
            listed = srv.get("datasource/list_interfaces.json")
            took = time.monotonic() - t0
            slow_saw = list(slow.commands)
    rows = {r.get("kismet.datasource.probed.interface"):
            r.get("kismet.datasource.probed.hardware") for r in listed}
    assert "AT+CGMR" in slow_saw, f"positive control: the slow lister ran: {slow_saw}"
    assert took < 15, f"list_interfaces took {took:.1f}s against a 2 s deadline"
    assert rows.get(f"celldiag-{OTHER_IMEI}") == (
        f"Quectel RM520N-GL (RM520NGLAAR01A08M4G) IMEI:{OTHER_IMEI} DIAG"), rows
    assert not any(k.startswith("cellat-") for k in rows), rows
