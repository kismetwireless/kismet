# SPDX-License-Identifier: Apache-2.0
"""Which kismetdb `data` row types ``kismetdb_to_cellndjson`` exports.

The reader filters the `data` table by ``type``. The filter must match the
type strings the SERVER actually writes, which are not always the strings the
capture sources send:

* A cell observation leaves ``kismet_cap_cell_at`` as ``type="CellModem"``, but
  once ``phy_cell`` accepts it the server logs it through a packet METABLOB
  typed ``"Cellular"`` (``phy_cell.cc`` ``set_data("Cellular", …)``;
  ``kis_databaselogfile.cc`` logs the metablob's type in preference to the
  JSON's). Only the observations ``phy_cell`` *rejects* keep ``"CellModem"``.
  A filter on ``"Cell"`` therefore exported the rejects and dropped every
  accepted cell observation.
* ``RawAT`` and ``ClockAnchor`` have no PHY handler, so they keep their own
  type.

The fixture is a synthetic SQLite file carrying only the columns the reader
selects, so the test needs a built reader and nothing else.
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

_KP = Path(__file__).resolve().parents[2]
_READER = _KP / "log_tools" / "kismetdb_to_cellndjson"
_SOURCE = _KP / "log_tools" / "kismetdb_to_cellndjson.cc"
UUID = "00000000-0000-0000-0000-00000000c0de"


def _reader_or_skip() -> str:
    if not _READER.exists():
        pytest.skip(f"{_READER} not built (make log_tools/kismetdb_to_cellndjson)")
    if _SOURCE.stat().st_mtime > _READER.stat().st_mtime:
        pytest.fail(f"{_READER} is STALE (older than {_SOURCE.name}); rebuild: "
                    f"(cd {_KP} && make log_tools/kismetdb_to_cellndjson)")
    return str(_READER)


ROWS = [
    ("Cellular", {"rat": "LTE", "pci": 236, "earfcn": 66786, "rsrp": -101}),
    ("CellModem", {"rat": "LTE", "earfcn": 900}),
    ("RawAT", {"ts_mono_ns": 1, "ts_utc": "t", "cmd": "AT+CCLK?",
               "response": '+CCLK: "26/09/22,18:43:54-24"\r\nOK',
               "duration_ms": 12, "err": 0}),
    ("ClockAnchor", {"schema": "clock-anchor/1", "transport": "at",
                     "source_name": UUID, "seq": 0, "edge": "start",
                     "host_utc": "2026-09-22T18:43:58.258004Z",
                     "host_mono_ns": 675537106368809,
                     "source_clock_kind": "modem_rtc_cclk",
                     "source_clock_value": "26/09/22,18:43:54-24"}),
    ("diag_stats", {"verdict": "FLOWING"}),
]


def _make_db(path: Path) -> Path:
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE KISMET (kismet_version TEXT, db_version INT, "
               "db_module TEXT)")
    db.execute("INSERT INTO KISMET VALUES ('test', 10, 'test')")
    db.execute("CREATE TABLE datasources (uuid TEXT, name TEXT)")
    db.execute("INSERT INTO datasources VALUES (?, 'RM520N')", (UUID,))
    db.execute("CREATE TABLE data (ts_sec INT, ts_usec INT, lat REAL, lon REAL, "
               "alt REAL, speed REAL, heading REAL, datasource TEXT, type TEXT, "
               "json BLOB)")
    for i, (typ, obj) in enumerate(ROWS):
        db.execute("INSERT INTO data VALUES (?,0,0,0,0,0,0,?,?,?)",
                   (1790028000 + i, UUID, typ, json.dumps(obj)))
    db.commit()
    db.close()
    return path


@pytest.fixture
def exported(tmp_path):
    reader = _reader_or_skip()
    db = _make_db(tmp_path / "t.kismet")
    out = tmp_path / "out.ndjson"
    subprocess.run([reader, "-i", str(db), "-o", str(out)], check=True,
                   capture_output=True, timeout=30)
    return [json.loads(l) for l in out.read_text().splitlines()]


def _types(recs):
    return sorted(r["type"] for r in recs)


def test_accepted_cell_observations_typed_cellular_are_exported(exported):
    cell = [r for r in exported if r["type"] == "Cellular"]
    assert len(cell) == 1
    assert cell[0]["obs"]["pci"] == 236


def test_clock_anchor_rows_are_exported_verbatim(exported):
    (anchor,) = [r for r in exported if r["type"] == "ClockAnchor"]
    assert anchor["obs"] == dict(ROWS[3][1])
    assert anchor["source_name"] == "RM520N"


def test_exported_set_is_the_cell_types_and_nothing_else(exported):
    assert _types(exported) == ["CellModem", "Cellular", "ClockAnchor", "RawAT"]
