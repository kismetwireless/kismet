# SPDX-License-Identifier: Apache-2.0
"""qmifeed='s tagged line types through a real Kismet server.

The capture child exports ``CELLAT_QMIFEED_PROTO=2`` to its feed. A feed that
sees it may write, beside its ``{...}`` observations:

* ``#rawqmi {json}`` -- one raw qmicli exchange, which must land in the
  kismetdb ``data`` table as ``type='RawQMI'``, byte for byte (the in-db twin of
  the feed's ``--qmilog`` file tee, as RawAT is of ``atlog=``);
* ``#msg info|error <text>`` -- an operator note, which must reach Kismet's
  message bus under the source's name instead of only its console log.

``test_cellat_qmifeed.c`` pins the framing; this file pins that the rows and
notes survive the real server into a real ``.kismet``, and that the stats line
counts them.
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from test_celldiag_server_routes import KP_ROOT, SERVER  # noqa: E402
from test_graceful_close_server import LoggingKismetServer  # noqa: E402

IMEI = "351234567890123"
RAW = {"schema": 1, "ts_mono_ns": 1, "rx_done_ns": 2, "ts_utc": "2026-09-26T00:00:00.000000Z",
       "argv": ["qmicli", "-d", "/dev/cdc-wdm0", "--nas-get-cell-location-info"],
       "rc": 0, "stdout": "[/dev/cdc-wdm0] Successfully got cell location info\n",
       "stderr": "", "err": None}
STATS_WAIT_S = 12.0     # > CELLAT_STATS_INTERVAL_S, so a line lands after the rows
NOTE = "polling /dev/cdc-wdm3 instead"

_DEPS = {
    SERVER: ("kis_datasource.cc", "datasourcetracker.cc", "logtracker.cc",
             "datasource_cell_at.cc"),
    KP_ROOT / "capture_cell_at" / "kismet_cap_cell_at": (
        "capture_framework.c", "capture_cell_at/capture_cell_at.c",
        "capture_cell_at/cellat_qmifeed.c", "capture_cell_at/cellat_qmifeed.h",
        "capture_cell_at/cellat_stats.c"),
}
QMILOG = KP_ROOT / "log_tools" / "kismetdb_to_qmilog"
ATLOG = KP_ROOT / "log_tools" / "kismetdb_to_atlog"


def _reader(tool: Path, db: Path) -> "list[str]":
    if not tool.is_file() or tool.stat().st_mtime < (KP_ROOT / "log_tools" / "kismetdb_to_atlog.cc").stat().st_mtime:
        pytest.skip(f"{tool.name} missing or older than kismetdb_to_atlog.cc -- rebuild it")
    r = subprocess.run([str(tool), "--in", str(db), "--out", "-"],
                       capture_output=True, text=True, check=True)
    return r.stdout.splitlines()


def _built_or_skip() -> None:
    for binary, deps in _DEPS.items():
        if not binary.is_file():
            pytest.skip(f"no {binary.name} at {binary} -- build it in {KP_ROOT}")
        mtime = binary.stat().st_mtime
        stale = [d for d in deps if (KP_ROOT / d).stat().st_mtime > mtime]
        if stale:
            pytest.skip(f"{binary.name} is older than {', '.join(stale)} -- rebuild it")


def _rows(db: Path, kind: str) -> "list[dict]":
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT json FROM data WHERE type = ?", (kind,)).fetchall()
    finally:
        con.close()
    return [json.loads(bytes(r[0]).decode() if isinstance(r[0], (bytes, memoryview))
                       else r[0]) for r in rows]


def _feed(tmp: Path, *, tagged_only_if_told: bool = True) -> Path:
    obs = {"rat": "LTE", "mcc": "311", "mnc": "480", "tac": 0xBBB, "cell_id": 0xBBB320,
           "pci": 221, "earfcn": 66536, "observation_type": "serving", "is_serving": True,
           "prov": {"src": "qmi", "origin": "nas-get-cell-location-info", "imei": IMEI}}
    raw = json.dumps(RAW, separators=(",", ":"))
    gate = '[ "$CELLAT_QMIFEED_PROTO" = 2 ] || { echo proto-missing >&2; exit 7; }\n' \
        if tagged_only_if_told else ""
    feed = tmp / "feed.sh"
    feed.write_text(gate +
                    f"printf '%s\\n' '#msg info {NOTE}'\n"
                    "while :; do\n"
                    f"  printf '%s\\n' '#rawqmi {raw}'\n"
                    f"  printf '%s\\n' '{json.dumps(obs)}'\n"
                    "  sleep 0.5\n"
                    "done\n")
    return feed


def test_rawqmi_rows_and_feed_notes_reach_the_kismetdb(tmp_path):
    _built_or_skip()
    feed = _feed(tmp_path)
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        srcdef = f"cellat-{IMEI}:atport={modem.port},debug=false,qmifeed=/bin/sh {feed}"
        with LoggingKismetServer(tmp_path, srcdef) as srv:
            deadline = time.monotonic() + 40.0
            while time.monotonic() < deadline and "qmifeed: " + NOTE not in srv.tail(200000):
                time.sleep(0.5)
            # Several raw rows, then a periodic stats line that counts them.
            time.sleep(STATS_WAIT_S)
            log = srv.tail(200000)
            sources = srv.get("datasource/all_sources.json")
        db = srv.kismetdb()

    assert "proto-missing" not in log, "the feed was not told CELLAT_QMIFEED_PROTO=2"
    # The note reached the bus under the source's name.
    assert f"IMEI:{IMEI} qmifeed: {NOTE}" in log, log[-3000:]

    # RawQMI rows, identical to what the feed wrote.
    raw = _rows(db, "RawQMI")
    assert len(raw) >= 2, f"{len(raw)} RawQMI row(s)\n{log[-3000:]}"
    assert all(r == RAW for r in raw), raw[0]
    # kismetdb_to_qmilog gives the rows back as --qmilog lines,
    # and the atlog reader it shares its source with still reads only RawAT.
    lines = _reader(QMILOG, db)
    assert [json.loads(l) for l in lines] == raw
    at_lines = _reader(ATLOG, db)
    assert len(at_lines) == len(_rows(db, "RawAT")) > 0
    assert not [l for l in at_lines if '"argv"' in l]
    # The tagged lines never leak into the observation lane.
    assert not [r for r in _rows(db, "CellModem") if "argv" in r]

    # The stats line counts them, and the server keeps the counts
    # on the source (the panel's "QMI feed" row reads these fields).
    (src,) = sources
    f = {k.rsplit(".", 1)[-1]: v for k, v in src.items()
         if k.startswith("kismet.datasource.cellat.")}
    assert f["qmifeed_configured"] == 1 and f["qmifeed_active"] == 1, f
    assert f["rawqmi_records"] >= 2 and f["rawqmi_dropped"] == 0, f
    assert f["qmifeed_sent"] >= 1 and f["qmifeed_msgs"] == 1, f
