# SPDX-License-Identifier: Apache-2.0
"""A qsh=on capture carries the modem's DIAGID-table reply in its stream.

``qsh=on`` asks the modem for its diag_id binding table (``0x4B 12 22 02 01``)
at bring-up. The bring-up's handshake reader consumes the reply, so unless it
relays the frame, the reply reaches neither the ``rawlog=`` tee nor the DLT-147
raw packets and an offline decode of the capture finds an empty binding (the
RM500Q-AE and RM520N-GL answer ``{1: APPS, 2: mdm/modem/root_pd}``). An HDLC
walk reads the binding from any in-stream reply frame, so the capture relays
the frame into the stream.

These run the REAL capture binary against a PTY DIAG responder that answers the
request with an SDX55-shaped table. No host port is touched.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem, hdlc_frame  # noqa: E402
from celldiag_run import CellDiagRun  # noqa: E402
from celldiag_run import _binary_or_skip  # noqa: E402

DIAG_IMEI = "123456789012348"   # not Luhn-valid: never reads as a real device
FIRMWARE = "RM520NGLAAR03A03M4G"

REQUEST = bytes((0x4B, 0x12, 0x22, 0x02, 0x01))
#: 0x4B / subsys 0x12 / cmd 0x0222 / version 1 / 2 entries, then per entry
#: diag_id, name length counting the NUL, name -- the QShrink4 binding table
#: shape, with the names measured on SDX55.
TABLE = (bytes((0x4B, 0x12, 0x22, 0x02, 0x01, 0x02))
         + bytes((0x01, 0x05)) + b"APPS\x00"
         + bytes((0x02, 0x12)) + b"mdm/modem/root_pd\x00")
HDR = struct.Struct("<4sBBHQQ")


def _run(tmp_path: Path, **flags):
    tee = tmp_path / "tee.hdlc"
    parts = ["nomask=true", "defer=false", "stats_interval=0", f"rawlog={tee}"]
    parts += [f"{k}={v}" for k, v in flags.items()]
    # Ack the other qsh arms (0x4B QSH-trace, 0x60 events) by echo, or each
    # waits out a 20 s deadline; the table request gets its scripted reply.
    with FakeAtModem(imei=DIAG_IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(echo_opcodes={0x4B, 0x60}, scripted={REQUEST: TABLE}) as dg:
        definition = (f"celldiag-{DIAG_IMEI}:atport={at.port},diagport={dg.port},"
                      + ",".join(parts))
        run = CellDiagRun(_binary_or_skip(), definition, timeout=40.0,
                          close_when=lambda r: r.open_code is not None).run()
        sent = list(dg.commands)
    return run, sent, tee.read_bytes() if tee.exists() else b""


def _raw_stream(run: CellDiagRun) -> bytes:
    """The DLT-147 slices, sorted by offset and concatenated (one session)."""
    data = []
    for p in run.raw_packets:
        c = p["content"]
        _m, _v, flags, hlen, _s, off = HDR.unpack_from(c)
        if not flags & 0x02:
            data.append((off, c[hlen:]))
    out = bytearray()
    for off, payload in sorted(data):
        assert off == len(out), f"gap/overlap at {off} (have {len(out)})"
        out += payload
    return bytes(out)


def test_the_binding_reply_rides_the_tee_and_the_raw_packets(tmp_path):
    run, sent, tee = _run(tmp_path, qsh="on")
    assert run.open_code == 1, (run.open_message, run.errors)
    assert REQUEST in sent, "the premise: the table request went out"
    frame = hdlc_frame(TABLE)
    assert tee.count(frame) == 1, (
        f"the DIAGID-table reply is not in the rawlog tee; tee={len(tee)} B")
    # It is the first thing in the stream: it was read before anything after it.
    assert tee.startswith(frame), tee[:64].hex()
    raw = _raw_stream(run)
    assert raw.count(frame) == 1, "the reply is not in the kismetdb raw packets"
    assert tee.startswith(raw[:len(frame)])
    # ...and the drive log records the result.
    msgs = " ".join(run.messages)
    assert "diag_id binding: table received, relayed into the stream" in msgs, msgs[-2000:]


def test_a_lean_capture_asks_for_no_table_and_relays_none(tmp_path):
    run, sent, tee = _run(tmp_path)
    assert run.open_code == 1, (run.open_message, run.errors)
    assert REQUEST not in sent
    assert hdlc_frame(TABLE) not in tee
