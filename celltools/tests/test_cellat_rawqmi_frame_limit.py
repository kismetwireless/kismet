# SPDX-License-Identifier: Apache-2.0
"""A RawQMI / RawAT row must never exceed the server's IPC frame.

Kismet refuses any external frame over ``MAX_EXTERNAL_FRAME_LEN`` (16384,
``kis_external.h``) and refuses it by erroring the whole SOURCE, which it then
reopens 5 s later into the same oversize row. The capture accepts a tagged feed
line of up to ``QMIFEED_RAW_MAX`` (64 KiB), and ``qmicli --verbose-full`` of
``--nas-get-cell-location-info`` alone can be ~19 KB, so forwarding a line whole
would kill the source in a loop.

The capture bounds every JSON data row at ``CELLAT_ROW_JSON_MAX``, the
same 4 KiB envelope headroom the DIAG raw slices keep, drops an oversize row as
a counted, announced drop, and exports the bound to its feed so the feed can
trim before it writes.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from fake_qmifeed import server_feed  # noqa: E402
from test_cellat_rawqmi_server import RAW, _built_or_skip, _rows  # noqa: E402
from test_celldiag_server_routes import KP_ROOT  # noqa: E402
from test_graceful_close_server import LoggingKismetServer  # noqa: E402

IMEI = "351234567890123"
STATS_WAIT_S = 12.0     # > CELLAT_STATS_INTERVAL_S, so a stats line lands after the rows
#: The v3 header, the msgpack map, the "RawQMI"/"RawAT" type string and the
#: optional fixed-GPS block with a caller-chosen name all ride the frame with
#: the JSON. The non-GPS overhead is tens of bytes; 4 KiB is the budget the
#: DIAG raw slices keep too (diag_rawpkt.h).
ENVELOPE_BUDGET = 4096


def _c_define(rel: str, name: str) -> int:
    text = (KP_ROOT / rel).read_text(errors="replace")
    hit = re.search(rf"^#define\s+{name}\s+\(?\s*(\d+)u?\s*\)?", text, re.M)
    assert hit, f"#define {name} not found in {rel}"
    return int(hit.group(1))


def test_the_row_bound_leaves_the_envelope_room_inside_the_server_frame():
    """The source is the authority on both numbers, so they cannot drift apart."""
    server = _c_define("kis_external.h", "MAX_EXTERNAL_FRAME_LEN")
    row = _c_define("capture_cell_at/cellat_qmifeed.h", "CELLAT_ROW_JSON_MAX")
    assert row + ENVELOPE_BUDGET <= server, (row, server)
    # ...and is not so small that a real record is trimmed for nothing: the
    # largest live RawQMI record once its verbose stdout is trimmed is ~1.8 KB,
    # and the largest live RawAT record (an AT+QSCAN=3,1 body) ~1.6 KB.
    assert row >= 8192, row


def _feed(tmp: Path, big: dict) -> Path:
    obs = {"rat": "LTE", "mcc": "311", "mnc": "480", "tac": 0xBBB, "cell_id": 0xBBB320,
           "pci": 221, "earfcn": 66536, "observation_type": "serving", "is_serving": True,
           "prov": {"src": "qmi", "origin": "nas-get-cell-location-info", "imei": IMEI}}
    small = json.dumps(RAW, separators=(",", ":"))
    large = json.dumps(big, separators=(",", ":"))
    (tmp / "big.line").write_text(f"#rawqmi {large}\n")
    feed = tmp / "feed.sh"
    feed.write_text(
        # The bound the capture exported, echoed back as a note so the test
        # can see the feed was told it.
        'printf "#msg info rawqmi-max=%s\\n" "$CELLAT_QMIFEED_RAWQMI_MAX"\n'
        "while :; do\n"
        f"  printf '%s\\n' '#rawqmi {small}'\n"
        f"  cat {tmp / 'big.line'}\n"
        f"  printf '%s\\n' '{json.dumps(obs)}'\n"
        "  sleep 0.5\n"
        "done\n")
    return feed


def test_an_oversize_rawqmi_row_is_a_counted_drop_not_a_dead_source(tmp_path):
    _built_or_skip()
    row_max = _c_define("capture_cell_at/cellat_qmifeed.h", "CELLAT_ROW_JSON_MAX")
    # The live shape: qmicli --verbose-full text is the bulk, well past 16 KiB.
    big = dict(RAW, stdout="[/dev/cdc-wdm0] QMUX ... " + "x" * 19000)
    feed = _feed(tmp_path, big)
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        srcdef = f"cellat-{IMEI}:atport={modem.port},debug=false,qmifeed=auto"
        with server_feed(LoggingKismetServer(tmp_path, srcdef), tmp_path, feed) as srv:
            deadline = time.monotonic() + 40.0
            while time.monotonic() < deadline and "rawqmi-max=" not in srv.tail(200000):
                time.sleep(0.5)
            time.sleep(STATS_WAIT_S)
            log = srv.tail(400000)
            sources = srv.get("datasource/all_sources.json")
        db = srv.kismetdb()

    # The bug: the server killed the source on the first oversize frame.
    assert "too large" not in log, log[-3000:]
    assert "has encountered an error" not in log, log[-3000:]

    # The feed was told the bound it must fit.
    assert f"qmifeed: rawqmi-max={row_max}" in log, log[-3000:]

    # The small rows keep arriving; the oversize one never reaches the db.
    raw = _rows(db, "RawQMI")
    assert len(raw) >= 2, f"{len(raw)} RawQMI row(s)\n{log[-3000:]}"
    assert all(r == RAW for r in raw), [len(json.dumps(r)) for r in raw]

    # ...and its loss is visible: counted, and said once on the bus with the size.
    (src,) = sources
    f = {k.rsplit(".", 1)[-1]: v for k, v in src.items()
         if k.startswith("kismet.datasource.cellat.")}
    assert f["rawqmi_dropped"] >= 1, f
    notes = [ln for ln in log.splitlines() if "RawQMI row" in ln and "server frame" in ln]
    assert len(notes) == 1, notes or log[-3000:]


def test_an_oversize_rawat_row_is_a_counted_drop_not_a_dead_source(tmp_path):
    """RawAT carries the whole AT response (AT_RESP_MAX is 128 KiB), so a long
    neighbour list or scan body can outgrow the frame the same way. The row is
    the atlog= file line too, which keeps it whole; only the in-db twin drops."""
    _built_or_skip()
    row = ('+QENG: "neighbourcell intra","LTE",66536,221,-11,-96,-65,0,29,'
           '-,-,-,-')
    big = "\n".join([row] * 220)          # ~17 KB before JSON escaping
    extra = dict(QENG_SERVING, **{'AT+QENG="neighbourcell"': big})
    with FakeAtModem(imei=IMEI, extra=extra) as modem:
        srcdef = f"cellat-{IMEI}:atport={modem.port},debug=false"
        with LoggingKismetServer(tmp_path, srcdef) as srv:
            deadline = time.monotonic() + 40.0
            while time.monotonic() < deadline and "RawAT row" not in srv.tail(200000):
                time.sleep(0.5)
            time.sleep(STATS_WAIT_S)
            log = srv.tail(400000)
            sources = srv.get("datasource/all_sources.json")
        db = srv.kismetdb()

    assert "too large" not in log, log[-3000:]
    assert "has encountered an error" not in log, log[-3000:]

    rawat = _rows(db, "RawAT")
    assert rawat, log[-3000:]
    assert any(r["cmd"] == 'AT+QENG="servingcell"' for r in rawat)
    assert not [r for r in rawat if r["cmd"] == 'AT+QENG="neighbourcell"'], (
        "an oversize RawAT row reached the db")

    (src,) = sources
    f = {k.rsplit(".", 1)[-1]: v for k, v in src.items()
         if k.startswith("kismet.datasource.cellat.")}
    assert f["rawat_dropped"] >= 1, f
    notes = [ln for ln in log.splitlines() if "RawAT row" in ln and "server frame" in ln]
    assert len(notes) == 1, notes or log[-3000:]
