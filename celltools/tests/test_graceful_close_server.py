"""A Kismet-driven stop lands the END rows in the kismetdb.

``test_graceful_close`` drives each capture helper through the CLOSEREQ
handshake with a harness standing in for the server. This file closes the other
half: the REAL ``kismet`` server, a cellat source on a fake modem, a real
kismetdb, and the two ways a drive actually ends --

* ``close_source`` over REST, with the server still running (the web UI's
  capture switch);
* SIGTERM to the server (Ctrl-C at the end of a drive).

A plain close (pipe close + SIGTERM to the helper in the same call) leaves
**no** END ``ClockAnchor`` row on either stop. A server SIGTERM has a second
hazard: if the packet threads quit the moment the signal arrives, a row that
does reach the server after it can still be dropped before the log.

The kismetdb is read only after the server has exited: it commits in batches,
and the exit is what finishes the last one. The fake modem outlives the server
(it is the outer context), so the END ``AT+CCLK?`` always has someone to answer.
"""

from __future__ import annotations

import json
import signal
import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from test_celldiag_server_routes import KP_ROOT, SERVER, KismetServer  # noqa: E402

IMEI = "351234567890123"
CCLK = {"AT+CCLK?": '+CCLK: "26/09/22,20:00:00+00"'}

#: Everything this measurement runs through. A server or helper older than any
#: of them would measure code nobody compiled -- skip, naming the rebuild.
_DEPS = {
    SERVER: ("kis_datasource.cc", "kis_datasource.h", "datasourcetracker.cc",
             "packetchain.cc", "packetchain.h", "logtracker.cc", "kismet_server.cc",
             "kis_external_packet.h"),
    KP_ROOT / "capture_cell_at" / "kismet_cap_cell_at": (
        "capture_framework.c", "capture_framework.h", "capture_cell_at/capture_cell_at.c"),
}


def _built_or_skip() -> None:
    for binary, deps in _DEPS.items():
        if not binary.is_file():
            pytest.skip(f"no {binary.name} at {binary} -- build it in {KP_ROOT}")
        mtime = binary.stat().st_mtime
        stale = [d for d in deps if (KP_ROOT / d).stat().st_mtime > mtime]
        if stale:
            pytest.skip(f"{binary.name} is older than {', '.join(stale)} -- rebuild it")


class LoggingKismetServer(KismetServer):
    """``KismetServer`` with a kismetdb written into the test's own directory."""

    #: Replaced, not appended to: within one conf file the FIRST value of a key
    #: wins (``config_file::fetch_opt``), so a line appended after the base
    #: harness's own logging line would be ignored.
    _KEYS = ("enable_logging", "logging_enabled", "log_types", "log_prefix", "log_title")

    def __init__(self, tmp_path: Path, srcdef: str, extra: "tuple[str, ...]" = ()) -> None:
        super().__init__(tmp_path, srcdef, silent=False)
        self.logdir = tmp_path / "logs"
        self.logdir.mkdir()
        site = self.conf / "kismet_site.conf"
        kept = [ln for ln in site.read_text().splitlines()
                if ln.split("=", 1)[0].strip().lower() not in self._KEYS]
        kept += ["enable_logging=true", "log_types=kismet",
                 f"log_prefix={self.logdir}/", "log_title=grace4650", *extra]
        site.write_text("\n".join(kept) + "\n")

    def kismetdb(self) -> Path:
        dbs = sorted(self.logdir.glob("*.kismet"))
        assert len(dbs) == 1, f"want one kismetdb, got {dbs}\n{self.tail()}"
        return dbs[0]


def _anchor_edges(db: Path) -> list[str]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT json FROM data WHERE type = 'ClockAnchor' "
                           "ORDER BY ts_sec, ts_usec").fetchall()
    finally:
        con.close()
    return [json.loads(bytes(r[0]).decode() if isinstance(r[0], (bytes, memoryview))
                       else r[0])["edge"] for r in rows]


def _await_start_anchor(modem: FakeAtModem, timeout: float = 30.0) -> None:
    """The START anchor is the first AT+CCLK?; the stop must come after it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if "AT+CCLK?" in modem.commands:
            time.sleep(0.5)          # its reply and row, too
            return
        time.sleep(0.2)
    raise AssertionError(f"no START AT+CCLK? in {timeout}s: {modem.commands[-10:]}")


def _srcdef(modem: FakeAtModem) -> str:
    return f"cellat-{IMEI}:atport={modem.port},retry=false"


def test_rest_close_source_lands_the_end_anchor_in_the_kismetdb(tmp_path):
    _built_or_skip()
    with FakeAtModem(imei=IMEI, extra={**QENG_SERVING, **CCLK}) as modem:
        with LoggingKismetServer(tmp_path, _srcdef(modem)) as srv:
            row = srv.await_running(True)
            _await_start_anchor(modem)
            srv.get(f"datasource/by-uuid/{row['kismet.datasource.uuid']}/close_source.cmd")
            srv.await_running(False)
            # The close completes when the helper exits; the END row is sent
            # before that. Give it the helper's grace to arrive.
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and modem.commands.count("AT+CCLK?") < 2:
                time.sleep(0.2)
            time.sleep(1.0)
            log = srv.tail(20000)
        db = srv.kismetdb()

    assert modem.commands.count("AT+CCLK?") == 2, modem.commands[-20:]
    edges = _anchor_edges(db)
    assert edges == ["start", "end"], (edges, log[-3000:])
    # A requested close is not a failure: no error state, no retry.
    assert "closed cleanly" in log, log[-3000:]
    assert "encountered an error" not in log, log[-3000:]


def test_server_sigterm_lands_the_end_anchor_in_the_kismetdb(tmp_path):
    _built_or_skip()
    with FakeAtModem(imei=IMEI, extra={**QENG_SERVING, **CCLK}) as modem:
        srv = LoggingKismetServer(tmp_path, _srcdef(modem))
        with srv:
            srv.await_running(True)
            _await_start_anchor(modem)
            t0 = time.monotonic()
            srv.proc.send_signal(signal.SIGTERM)
            srv.proc.wait(30)
            took = time.monotonic() - t0
            log = srv.tail(20000)
        db = srv.kismetdb()

    assert srv.proc.returncode == 0, (srv.proc.returncode, log[-3000:])
    assert modem.commands.count("AT+CCLK?") == 2, modem.commands[-20:]
    edges = _anchor_edges(db)
    assert edges == ["start", "end"], (edges, log[-3000:])
    # Bounded: cellat's grace (8 s) + the server's margin (1 s) is the worst
    # case; a responsive modem closes in well under that.
    assert took < 9.0, f"shutdown took {took:.1f}s"
    assert "did not finish closing" not in log, log[-3000:]


def test_an_open_right_after_a_close_waits_for_it_and_keeps_its_end(tmp_path):
    """The web UI's restart and capture switch send close_source then open_source
    back to back. The close finishes asynchronously, so an open that attached
    a new helper while the old one was still closing would have the old close's
    completion land on the NEW session: the open would never answer (the HTTP
    request hangs) and the source would be lost.

    The open must wait for the close, so the old segment keeps its END and the
    new one starts clean.
    """
    _built_or_skip()
    with FakeAtModem(imei=IMEI, extra={**QENG_SERVING, **CCLK}) as modem:
        srv = LoggingKismetServer(tmp_path, _srcdef(modem))
        with srv:
            row = srv.await_running(True)
            _await_start_anchor(modem)
            base = f"datasource/by-uuid/{row['kismet.datasource.uuid']}/"
            srv.get(base + "close_source.cmd")
            t0 = time.monotonic()
            srv.get(base + "open_source.cmd")        # answers only once re-opened
            took = time.monotonic() - t0
            srv.await_running(True)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and modem.commands.count("AT+CCLK?") < 3:
                time.sleep(0.2)
            time.sleep(0.5)
            srv.proc.send_signal(signal.SIGTERM)
            srv.proc.wait(30)
            log = srv.tail(40000)
        db = srv.kismetdb()

    assert took < 9.0, f"the re-open took {took:.1f}s"
    # old segment: start + END; new segment: start + the SIGTERM's END
    assert _anchor_edges(db) == ["start", "end", "start", "end"], (
        _anchor_edges(db), log[-3000:])
    assert "did not finish closing" not in log, log[-3000:]


def test_one_packet_thread_still_logs_every_row_sent_after_the_signal(tmp_path):
    """The one-worker discriminator for the packet-thread drain.

    Packet threads that quit on ``spindown``, which the signal sets before any
    source closes, each finish at most the one packet they are blocked on. With
    the default 4+ threads that happens to cover the few rows a closing cellat
    sends -- which is why the SIGTERM test above cannot see the hazard. With ONE
    thread it cannot: the END exchange sends a RawAT row and then the
    ClockAnchor row, and a thread quitting after the first drops the second.
    The threads drain to a sentinel queued behind everything delivered.
    """
    _built_or_skip()
    with FakeAtModem(imei=IMEI, extra={**QENG_SERVING, **CCLK}) as modem:
        srv = LoggingKismetServer(tmp_path, _srcdef(modem),
                                  extra=("kismet_packet_threads=1",))
        with srv:
            srv.await_running(True)
            _await_start_anchor(modem)
            srv.proc.send_signal(signal.SIGTERM)
            srv.proc.wait(30)
            log = srv.tail(40000)
        db = srv.kismetdb()

    assert modem.commands.count("AT+CCLK?") == 2, modem.commands[-20:]
    assert _anchor_edges(db) == ["start", "end"], (_anchor_edges(db), log[-3000:])
    assert "did not finish its queue" not in log, log[-3000:]
