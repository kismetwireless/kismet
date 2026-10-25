# SPDX-License-Identifier: Apache-2.0
"""Through the real server: a stream losing bytes is recorded in the
kismetdb and flagged on the source, not just printed.

``test_celldiag_crc_census.py`` drives the helper over the IPC and proves
the counts. This file proves they land: the server keeps the census as
``kismet.datasource.celldiag.crc_*`` fields, raises the source's warning when a
damage window is reported, and logs the helper's end-of-stream ``DiagCrcCensus``
row to the kismetdb ``data`` table under the source, carrying the raw stream's
session id -- the key a reader attaches it to a stream by.

The clean replay is the control: counted (``crc_reported`` = 1, every frame
checked), no warning. Without it, a server that never set the warning at all
would pass the "no warning" half of any test.
"""
from __future__ import annotations

import json
import sqlite3
import struct
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_diag_modem import hdlc_frame  # noqa: E402
from test_celldiag_raw_abort_server import (  # noqa: E402
    IMEI, _await, _sessions)
from test_celldiag_server_routes import KP_ROOT, SERVER  # noqa: E402
from test_graceful_close_server import LoggingKismetServer  # noqa: E402

N_FRAMES = 400
DAMAGED = 25

_DEPS = {
    SERVER: ("datasource_cell_diag.cc", "datasource_cell_diag.h"),
    KP_ROOT / "capture_cell_diag" / "kismet_cap_cell_diag": (
        "capture_cell_diag/capture_cell_diag.c", "capture_cell_diag/diag_logstream.c",
        "capture_cell_diag/diag_stats.c", "capture_cell_diag/diag_stats.h"),
}


def _built_or_skip() -> None:
    for binary, deps in _DEPS.items():
        if not binary.is_file():
            pytest.skip(f"no {binary.name} at {binary} -- build it in {KP_ROOT}")
        stale = [d for d in deps if (KP_ROOT / d).stat().st_mtime > binary.stat().st_mtime]
        if stale:
            pytest.skip(f"{binary.name} is older than {', '.join(stale)} -- rebuild it")


def _replay(tmp_path: Path, damaged: int) -> Path:
    """Filler LOG_F frames; `damaged` of them lose 6 bytes from the middle."""
    frames = []
    for k in range(1, N_FRAMES + 1):
        body = (bytes((0x10, 0x00)) + struct.pack("<HH", 40, 40) + struct.pack("<H", 0x0FFF)
                + struct.pack("<Q", k) + bytes(range(26)))
        frames.append(hdlc_frame(body))
    for k in (range(0, N_FRAMES, N_FRAMES // damaged)[:damaged] if damaged else ()):
        f = frames[k]
        frames[k] = f[:10] + f[16:]
    p = tmp_path / f"replay4934_{damaged}.hdlc"
    p.write_bytes(b"".join(frames))
    return p


def _drive(tmp_path: Path, damaged: int):
    replay = _replay(tmp_path, damaged)
    srcdef = (f"celldiag-{IMEI}:replay={replay},retry=false,stats_interval=0")
    with LoggingKismetServer(tmp_path, srcdef) as srv:
        _await(lambda: "END at offset" in srv.tail(20000), 30, "the replay's END", srv)
        _await(lambda: (srv.source() or {}).get("kismet.datasource.celldiag.crc_reported") == 1,
               20, "the census on the source", srv)
        time.sleep(1)
        src = srv.source()
    db = srv.kismetdb()
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT datasource, json FROM data WHERE type = 'DiagCrcCensus'"
                           ).fetchall()
    finally:
        con.close()
    rows = [(u, json.loads(bytes(j).decode() if isinstance(j, (bytes, memoryview)) else j))
            for u, j in rows]
    return src, rows, _sessions(db)


def test_a_damaged_stream_is_on_the_source_warned_and_in_the_kismetdb(tmp_path):
    _built_or_skip()
    src, rows, sessions = _drive(tmp_path, DAMAGED)

    f = "kismet.datasource.celldiag."
    assert (src[f + "crc_checked"], src[f + "crc_ok"], src[f + "crc_bad"]) == (
        N_FRAMES, N_FRAMES - DAMAGED, DAMAGED), {k: v for k, v in src.items() if "crc" in k}
    assert src[f + "crc_damage_alerts"] == 1
    warning = src.get("kismet.datasource.warning", "")
    assert "losing bytes" in warning and f"{DAMAGED} of {N_FRAMES}" in warning, warning

    assert len(rows) == 1, rows
    uuid, row = rows[0]
    assert uuid == src["kismet.datasource.uuid"], (uuid, src["kismet.datasource.uuid"])
    assert (row["crc_bad"], row["crc_ok"], row["damage_alerts"]) == (
        DAMAGED, N_FRAMES - DAMAGED, 1), row
    # The raw stream's session: what a reader attaches the row to a stream by.
    assert list(sessions) == [row["session_id"]], (sessions, row)


def test_a_clean_stream_is_counted_and_not_warned(tmp_path):
    _built_or_skip()
    src, rows, _ = _drive(tmp_path, 0)

    f = "kismet.datasource.celldiag."
    assert src[f + "crc_reported"] == 1
    assert (src[f + "crc_checked"], src[f + "crc_bad"], src[f + "crc_damage_alerts"]) == (
        N_FRAMES, 0, 0)
    assert "losing bytes" not in src.get("kismet.datasource.warning", "")
    assert len(rows) == 1 and rows[0][1]["crc_bad"] == 0, rows
