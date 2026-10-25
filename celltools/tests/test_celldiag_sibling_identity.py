# SPDX-License-Identifier: Apache-2.0
"""A celldiag source whose only AT node its cellat sibling holds still
names its modem.

## The problem

A PCIe RM520N-GL has one AT node, ``/dev/mhi_DUN``. A drive opens a
``cellat-<imei>`` and a ``celldiag-<imei>`` source for it; cellat holds the node
for its whole capture, and celldiag needs it once, for its identity read. When
cellat gets there first, celldiag's rescan finds it still held and the source
opens on its address alone ("definition"): hardware ``unknown IMEI:...``, no
model or firmware in all_sources.json, the kismetdb ``datasources`` row or its
ModemIdentity row, and a rawlog companion reading ``model: "unknown"``.

Retrying longer cannot help -- the node is never released -- so the server
resolves it, where both readings meet. cellat's AT-read identity is published
by IMEI, and the unresolved celldiag source adopts it ("sibling") on its next
message. The companion, written by the helper at open, cannot learn the
identity; it says why it lacks one (``identity: unresolved-held-by-sibling``).

## The vouch: the helper usually never needs the server's adoption

cellat vouches for the node it holds (``diag_identvouch``), so celldiag's
scan resolves this exact shape itself: ``method: "vouched"``, a full label, a
companion naming make + product model, and no "definition" row at all
(``test_with_a_vouch_the_helper_names_the_modem_itself``). The server's
adoption stays as the fallback for when no vouch exists -- a cellat that
predates vouching, or a host whose vouch directory is unusable -- and the first
test pins it with vouching deliberately switched off.

## How "cellat wins" is made deterministic

The real server starts with the cellat source alone, on a PTY fake behind a
``mhi_DUN``-named link, and the test waits for its AT identity. Only then is the
celldiag source added over REST, so its scan (``CELLDIAG_SCAN_PORTS`` = that
link) always finds the node held.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from test_celldiag_server_routes import KP_ROOT, SERVER  # noqa: E402
from test_graceful_close_server import LoggingKismetServer  # noqa: E402

IMEI = "866436060048370"
MAKE, MODEL, FIRMWARE = "Quectel", "RM520N-GL", "RM520NGLAAR01A08M4G"
CELLAT_LABEL = f"{MAKE} {MODEL} ({FIRMWARE}) IMEI:{IMEI}"

_DEPS = {
    SERVER: ("datasource_cell_diag.cc", "datasource_cell_diag.h",
             "datasource_cell_at.cc", "datasource_cell_modemident.h",
             "capture_cell_diag/diag_modemident.h"),
    KP_ROOT / "capture_cell_diag" / "kismet_cap_cell_diag": (
        "capture_cell_diag/capture_cell_diag.c", "capture_cell_diag/diag_capmeta.c",
        "capture_cell_diag/diag_capmeta.h", "capture_cell_diag/diag_identvouch.c"),
    KP_ROOT / "capture_cell_at" / "kismet_cap_cell_at": (
        "capture_cell_at/capture_cell_at.c", "capture_cell_diag/diag_identvouch.c"),
}


def _built_or_skip() -> None:
    for binary, deps in _DEPS.items():
        if not binary.is_file():
            pytest.skip(f"no {binary.name} at {binary} -- build it in {KP_ROOT}")
        mtime = binary.stat().st_mtime
        stale = [d for d in deps if (KP_ROOT / d).stat().st_mtime > mtime]
        if stale:
            pytest.skip(f"{binary.name} is older than {', '.join(stale)} -- rebuild it")


def _row(srv, prefix: str) -> "dict | None":
    for r in srv.get("datasource/all_sources.json"):
        if r.get("kismet.datasource.name", "").startswith(prefix):
            return r
    return None


def _await_row(srv, prefix: str, pred, timeout: float, what: str) -> dict:
    deadline = time.monotonic() + timeout
    row = None
    while time.monotonic() < deadline:
        row = _row(srv, prefix)
        if row is not None and pred(row):
            return row
        time.sleep(0.5)
    ident = {k: v for k, v in (row or {}).items() if "modem" in k or "hardware" in k}
    raise AssertionError(f"{what} not seen in {timeout}s; row={ident}\n{srv.tail(6000)}")


def _method(row: dict) -> str:
    return row.get("kismet.datasource.cell.modem_identity_method", "")


def _identity_rows(db: Path, uuid: str) -> list[dict]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT json FROM data WHERE type = 'ModemIdentity' "
                           "AND datasource = ? ORDER BY ts_sec, ts_usec",
                           (uuid,)).fetchall()
    finally:
        con.close()
    return [json.loads(bytes(r[0]).decode() if isinstance(r[0], (bytes, memoryview))
                       else r[0]) for r in rows]


def _no_vouch(tmp_path: Path, monkeypatch) -> None:
    """Switch the cellat vouch off for this run: a directory others can read is
    refused by ``identvouch_dir``, so cellat publishes nothing and celldiag finds
    nothing -- the shape an older cellat, or an unusable host dir, produces."""
    d = tmp_path / "vouch-unusable"
    d.mkdir()
    d.chmod(0o750)
    monkeypatch.setenv("KISMET_CELL_VOUCH_DIR", str(d))


def test_a_celldiag_source_whose_at_node_cellat_holds_adopts_cellats_identity(
        tmp_path, monkeypatch):
    """The server fallback, with no vouch available (see the module docstring)."""
    _built_or_skip()
    _no_vouch(tmp_path, monkeypatch)
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra={"AT+CGMM": MODEL, **QENG_SERVING}) as at, FakeDiagModem() as dg:
        diag, dun = tmp_path / "mhi_DIAG", tmp_path / "mhi_DUN"
        os.symlink(dg.port, diag)
        os.symlink(at.port, dun)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", str(dun))
        rawlog = tmp_path / "r4837.hdlc"
        with LoggingKismetServer(tmp_path, f"cellat-{IMEI}:atport={dun},retry=false") as srv:
            cellat = _await_row(srv, "cellat", lambda r: _method(r) == "at", 60,
                                "the cellat source's AT identity")
            status, _ = srv.post("datasource/add_source.cmd", {"definition": (
                f"celldiag-{IMEI}:diagport={diag},nomask=true,stats_interval=1,"
                f"retry=false,rawlog={rawlog}")})
            assert status == 200
            row = _await_row(srv, "celldiag", lambda r: _method(r) == "sibling", 60,
                             "the celldiag source's adopted identity")
            log = srv.tail(60000)
            time.sleep(2)                         # let the db writer commit
        db = srv.kismetdb()

    # The premise: celldiag really was refused the node (else nothing below means
    # anything) -- one rescan, then the open without AT identity.
    assert "rescanning once in" in log and "proceeding without AT identity" in log, log[-4000:]

    # all_sources.json: the cellat reading, marked as adopted, on the DIAG label.
    assert row["kismet.datasource.hardware"] == CELLAT_LABEL + " DIAG", row["kismet.datasource.hardware"]
    assert row["kismet.datasource.cell.modem_model"] == MODEL
    assert row["kismet.datasource.cell.modem_firmware"] == FIRMWARE
    assert row["kismet.datasource.cell.modem_imei"] == IMEI
    assert row["kismet.datasource.cell.modem_at_port"] == str(dun)
    assert cellat["kismet.datasource.hardware"] == CELLAT_LABEL
    assert "adopted" in log and "as read over AT by a same-IMEI source" in log

    # kismetdb: the source's own "definition" row, THEN the adopted one.
    rows = _identity_rows(db, row["kismet.datasource.uuid"])
    assert [r["method"] for r in rows] == ["definition", "sibling"], rows
    assert rows[1]["firmware"] == FIRMWARE and rows[1]["source_type"] == "celldiag", rows[1]
    assert rows[1]["label"] == CELLAT_LABEL + " DIAG"
    # ...and the datasources row the server re-logged names the modem.
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        ds = [json.loads(r[0]) for r in con.execute(
            "SELECT json FROM datasources WHERE uuid = ?", (row["kismet.datasource.uuid"],))]
    finally:
        con.close()
    assert ds and ds[-1]["kismet.datasource.cell.modem_firmware"] == FIRMWARE, ds

    # The companion cannot know the identity; it says why it lacks one.
    meta = json.loads((tmp_path / "r4837.hdlc.capture_meta.json").read_text())
    assert meta["schema"] == "celldiag-capmeta/1"
    assert meta["identity"] == "unresolved-held-by-sibling", meta
    assert meta["firmware"] == "", meta


def test_with_a_vouch_the_helper_names_the_modem_itself(tmp_path, monkeypatch):
    """Vouching through the real server: the same cellat-holds-the-only-node
    shape, vouching on (the suite's private vouch dir). celldiag resolves the
    modem in its own scan -- no rescan, no "definition" row, no adoption -- and
    its rawlog companion names make + product model, not just the build."""
    _built_or_skip()
    with FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                     extra={"AT+CGMM": MODEL, **QENG_SERVING}) as at, FakeDiagModem() as dg:
        diag, dun = tmp_path / "mhi_DIAG", tmp_path / "mhi_DUN"
        os.symlink(dg.port, diag)
        os.symlink(at.port, dun)
        monkeypatch.setenv("CELLDIAG_SCAN_PORTS", str(dun))
        rawlog = tmp_path / "r4925.hdlc"
        with LoggingKismetServer(tmp_path, f"cellat-{IMEI}:atport={dun},retry=false") as srv:
            _await_row(srv, "cellat", lambda r: _method(r) == "at", 60,
                       "the cellat source's AT identity")
            status, _ = srv.post("datasource/add_source.cmd", {"definition": (
                f"celldiag-{IMEI}:diagport={diag},nomask=true,stats_interval=1,"
                f"retry=false,rawlog={rawlog}")})
            assert status == 200
            row = _await_row(srv, "celldiag", lambda r: _method(r) == "vouched", 60,
                             "the celldiag source's vouched identity")
            log = srv.tail(60000)
            time.sleep(2)                         # let the db writer commit
        db = srv.kismetdb()

    assert "vouched for it" in log and "read this modem over AT" in log, log[-4000:]
    assert "rescanning once in" not in log, "a vouched node settles the first pass"
    assert "adopted" not in log, "nothing was left for the server to adopt"
    assert row["kismet.datasource.hardware"] == CELLAT_LABEL + " DIAG"
    assert row["kismet.datasource.cell.modem_at_port"] == str(dun)

    rows = _identity_rows(db, row["kismet.datasource.uuid"])
    assert [r["method"] for r in rows] == ["vouched"], rows
    assert (rows[0]["make"], rows[0]["model"], rows[0]["firmware"]) == (MAKE, MODEL, FIRMWARE)

    meta = json.loads((tmp_path / "r4925.hdlc.capture_meta.json").read_text())
    assert meta["identity"] == "vouched", meta
    assert (meta["make"], meta["product_model"], meta["firmware"]) == (MAKE, MODEL, FIRMWARE), meta
