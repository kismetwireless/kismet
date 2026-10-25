# SPDX-License-Identifier: Apache-2.0
"""A celldiag source that DIES mid-stream leaves a witness the reader refuses.

## The blind spot

A capture helper exits when it has had no PING from the server for 15 s
(``capture_framework.c``). A server that stalls that long -- a ``SIGSTOP``, a
slow SQLite commit or a suspend -- therefore kills every celldiag helper. Each
takes its out-ring with it (up to 4 MiB, queued, not dropped), reaches no
teardown (no END), and writes no RawDiagDrop row. Kismet re-opens the sources
and the drive reads as healthy; without a witness, readers would pass the
stream under ``--strict`` with megabytes lost and nothing in the kismetdb to
say so.

## The witness

The helper cannot record its own death -- the server is not reading it -- so
the server's celldiag datasource does. It follows each raw session from the slice
headers, and when the source fails after data and before END (and the server is
not stopping), it writes one ``RawDiagAbort`` data row naming the session
(``capture_cell_diag/diag_rawpkt.h``). ``kismetdb_to_hdlc`` refuses such a
session under ``--strict``.

## What this file runs

The REAL ``kismet`` server, a celldiag source on a fake DIAG modem streaming
filler, and a real kismetdb. The server is ``SIGSTOP``ped past the watchdog,
then resumed; Kismet notices the dead helper, writes the row and re-opens the
source; a SIGTERM stop then ends the SECOND session gracefully, which is the
in-db control: same source, same db,
one session died and one did not.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_diag_modem import FakeDiagModem, hdlc_frame  # noqa: E402
from test_celldiag_server_routes import KP_ROOT, SERVER  # noqa: E402
from test_graceful_close_server import LoggingKismetServer  # noqa: E402

IMEI = "353456789047370"        # not Luhn-valid: never reads as a real device
READER = KP_ROOT / "log_tools" / "kismetdb_to_hdlc"
HDR = struct.Struct("<4sBBHQQ")  # the CDRH slice header (diag_rawpkt.h)
END_FLAG = 0x02
WATCHDOG_S = 15                  # capture_framework.c: time(NULL) - last_ping > 15
STALL_S = WATCHDOG_S + 6

#: Everything this measurement runs through; older binaries would measure code
#: nobody compiled -- skip, naming the rebuild.
_DEPS = {
    SERVER: ("datasource_cell_diag.cc", "datasource_cell_diag.h", "kis_datasource.cc",
             "kis_datasource.h", "capture_cell_diag/diag_rawpkt.h"),
    KP_ROOT / "capture_cell_diag" / "kismet_cap_cell_diag": (
        "capture_framework.c", "capture_cell_diag/capture_cell_diag.c",
        "capture_cell_diag/diag_rawpkt.c", "capture_cell_diag/diag_rawpkt.h"),
    READER: ("log_tools/kismetdb_to_hdlc.cc", "capture_cell_diag/diag_rawpkt.h"),
}


def _built_or_skip() -> None:
    for binary, deps in _DEPS.items():
        if not binary.is_file():
            pytest.skip(f"no {binary.name} at {binary} -- build it in {KP_ROOT}")
        mtime = binary.stat().st_mtime
        stale = [d for d in deps if (KP_ROOT / d).stat().st_mtime > mtime]
        if stale:
            pytest.skip(f"{binary.name} is older than {', '.join(stale)} -- rebuild it")


def _srcdef(dg: FakeDiagModem) -> str:
    return (f"celldiag-{IMEI}:diagport={dg.port},nomask=true,stats_interval=0")


def _await(pred, timeout: float, what: str, srv) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.25)
    raise AssertionError(f"{what} not seen in {timeout}s\n{srv.tail(6000)}")


def _sessions(db: Path) -> dict[int, dict]:
    """Per session: data slices, delivered end, END seen -- from the headers."""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT packet FROM packets WHERE dlt = 147").fetchall()
    finally:
        con.close()
    out: dict[int, dict] = {}
    for (blob,) in rows:
        blob = bytes(blob)
        magic, _ver, flags, hlen, session, offset = HDR.unpack_from(blob)
        assert magic == b"CDRH", magic
        s = out.setdefault(session, {"slices": 0, "end": False, "delivered_end": 0})
        if flags & END_FLAG:
            s["end"] = True
        else:
            s["slices"] += 1
            s["delivered_end"] = max(s["delivered_end"], offset + len(blob) - hlen)
    return out


def _abort_rows(db: Path) -> list[dict]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT json FROM data WHERE type = 'RawDiagAbort'").fetchall()
    finally:
        con.close()
    return [json.loads(bytes(r[0]).decode() if isinstance(r[0], (bytes, memoryview))
                       else r[0]) for r in rows]


def _reader(*args) -> subprocess.CompletedProcess:
    return subprocess.run([str(READER), *map(str, args)], capture_output=True,
                          text=True, timeout=120)


def test_a_helper_killed_by_the_ping_watchdog_leaves_a_witness_strict_refuses(tmp_path):
    _built_or_skip()
    with FakeDiagModem(filler_hz=200) as dg:
        with LoggingKismetServer(tmp_path, _srcdef(dg)) as srv:
            srv.await_running(True)
            _await(lambda: "opened (live" in srv.tail(20000), 30, "the live bring-up", srv)
            time.sleep(3)                          # slices flowing into the kismetdb

            os.kill(srv.proc.pid, signal.SIGSTOP)  # the server stall
            try:
                time.sleep(STALL_S)
            finally:
                os.kill(srv.proc.pid, signal.SIGCONT)

            _await(lambda: "failed in the middle of raw DIAG session" in srv.tail(40000),
                   30, "the server's raw-abort witness message", srv)
            # Kismet re-opens the source; its second session is the control.
            srv.await_running(True, timeout=60)
            time.sleep(3)
            log = srv.tail(60000)
        db = srv.kismetdb()                        # read only after the exit

    assert "did not get PING from Kismet" in log or "IPC" in log, log[-4000:]
    sessions = _sessions(db)
    aborts = _abort_rows(db)
    assert len(aborts) == 1, (aborts, sessions)
    row = aborts[0]
    assert row["schema"] == "raw-diag-abort/1", row
    died = row["session_id"]
    assert died in sessions, (row, sessions)
    assert not sessions[died]["end"], "the dead session cannot have an END"
    assert row["slices"] == sessions[died]["slices"] > 0, (row, sessions[died])
    assert row["delivered_end"] == sessions[died]["delivered_end"], (row, sessions[died])
    assert isinstance(row["reason"], str) and row["reason"], row

    later = [s for s in sessions if s > died]
    assert later, f"Kismet should have re-opened the source: {sessions}"
    nxt = min(later)
    assert sessions[nxt]["end"], "the graceful stop should END the re-opened session"

    r = _reader("-i", db, "-S", died, "-o", tmp_path / "died.hdlc", "--strict")
    assert r.returncode == 3, (r.returncode, r.stderr)
    assert "the source DIED mid-stream" in r.stderr, r.stderr
    assert not (tmp_path / "died.hdlc").exists()
    r = _reader("-i", db, "-S", nxt, "-o", tmp_path / "next.hdlc", "--strict")
    assert r.returncode == 0, (r.returncode, r.stderr)

    # Without the row the same session is the blind spot: --strict
    # passes it. The row is the whole difference.
    blind = tmp_path / "blind.kismet"
    shutil.copy2(db, blind)
    con = sqlite3.connect(blind)
    con.execute("DELETE FROM data WHERE type = 'RawDiagAbort'")
    con.commit()
    con.close()
    r = _reader("-i", blind, "-S", died, "-o", tmp_path / "blind.hdlc", "--strict")
    assert r.returncode == 0, (r.returncode, r.stderr)
    assert "no END slice" in r.stderr, r.stderr


def test_a_graceful_stop_writes_no_witness(tmp_path):
    """The other half of the contract: a stop the server asked for is not a
    death. REST close_source and then SIGTERM, no stall -- END lands and no
    RawDiagAbort row is written, so --strict passes."""
    _built_or_skip()
    with FakeDiagModem(filler_hz=200) as dg:
        with LoggingKismetServer(tmp_path, _srcdef(dg) + ",retry=false") as srv:
            row = srv.await_running(True)
            _await(lambda: "opened (live" in srv.tail(20000), 30, "the live bring-up", srv)
            time.sleep(3)
            srv.get(f"datasource/by-uuid/{row['kismet.datasource.uuid']}/close_source.cmd")
            srv.await_running(False)
            _await(lambda: "closed cleanly" in srv.tail(20000), 20, "the graceful close", srv)
            log = srv.tail(20000)
        db = srv.kismetdb()

    assert "failed in the middle of raw DIAG session" not in log, log[-3000:]
    assert _abort_rows(db) == []
    sessions = _sessions(db)
    assert len(sessions) == 1 and all(s["end"] for s in sessions.values()), sessions
    r = _reader("-i", db, "-o", tmp_path / "a.hdlc", "--strict")
    assert r.returncode == 0, (r.returncode, r.stderr)


def _replay_file(tmp_path: Path, n: int = 400) -> Path:
    """Filler LOG_F frames (the fake modem's own shape), HDLC-framed: a replay
    that nothing decodes but every slice boundary respects."""
    def body(k: int) -> bytes:
        return (bytes((0x10, 0x00)) + struct.pack("<HH", 20, 20) + struct.pack("<H", 0x0FFF)
                + struct.pack("<Q", k) + bytes((0x7E, 0x7D, 0x1D, 0x7E, 0x00, 0x7D, 0x5E, 0x1D)))
    p = tmp_path / "replay4703.hdlc"
    p.write_bytes(b"".join(hdlc_frame(body(k)) for k in range(1, n + 1)))
    return p


def test_a_source_that_ends_on_its_own_after_END_writes_no_witness(tmp_path):
    """A replay reaches EOF, sends END and its helper exits. The server sees a
    close it did not ask for -- the very error path a death takes -- but END is
    in, so the stream is confirmed and nothing may be witnessed. Without this,
    a witness that ignored END would pass every other test here."""
    _built_or_skip()
    replay = _replay_file(tmp_path)
    srcdef = (f"celldiag-{IMEI}:replay={replay},retry=false,stats_interval=0")
    with LoggingKismetServer(tmp_path, srcdef) as srv:
        _await(lambda: "END at offset" in srv.tail(20000), 30, "the replay's END", srv)
        _await(lambda: "encountered an error" in srv.tail(20000), 20,
               "the unrequested close", srv)
        time.sleep(2)
        log = srv.tail(20000)
    db = srv.kismetdb()

    # The error path ran (so the witness was consulted) ...
    assert "encountered an error" in log, log[-3000:]
    # ... and stayed silent, because END had arrived.
    assert "failed in the middle of raw DIAG session" not in log, log[-3000:]
    assert _abort_rows(db) == []
    sessions = _sessions(db)
    assert len(sessions) == 1, sessions
    (s,) = sessions.values()
    assert s["end"] and s["delivered_end"] == replay.stat().st_size, (s, replay.stat().st_size)
    r = _reader("-i", db, "-o", tmp_path / "a.hdlc", "--strict")
    assert r.returncode == 0, (r.returncode, r.stderr)
    assert (tmp_path / "a.hdlc").read_bytes() == replay.read_bytes()
