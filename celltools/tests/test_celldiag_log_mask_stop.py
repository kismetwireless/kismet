"""A celldiag capture clears the LOG mask it armed when it lets go of the modem.

The stop teardown disarms the QSH-trace latch, F3 and the ``0x60`` event
stream, and also the ``LOG_CONFIG`` (``0x73``) mask the bring-up armed. A mask
left armed keeps streaming indefinitely after the stop (megabytes per 15 s
after a ``mask=full`` run), and the next DIAG client on the modem inherits the
flood.

A capture that armed a mask sends ``LOG_CONFIG`` operation 0 (DISABLE) as it
lets go of the port: at the stop, and on every open failure after the mask went
out. These tests read the frames the capture wrote to the modem, on the real
binary against a PTY DIAG responder; no host port is touched.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from celldiag_run import CellDiagRun  # noqa: E402
from celldiag_run import _binary_or_skip  # noqa: E402

DIAG_IMEI = "123456789012347"
FIRMWARE = "RM520NGLAAR03A03M4G"      # no diag.spc in its profile: no SPC exchange

LOG_CONFIG_F = 0x73
#: "<3xI": 3 pad bytes, then the u32 operation.
RETRIEVE_RANGES = bytes((LOG_CONFIG_F,)) + struct.pack("<3xI", 1)
DISABLE = bytes((LOG_CONFIG_F,)) + struct.pack("<3xI", 0)
SET_MASK_OP = 3


def _ranges_reply() -> bytes:
    """A RETRIEVE_RANGES answer advertising log types 1 (0x1xxx GNSS) and 11
    (0xBxxx LTE/NR), which DIAG_TARGET_CODES live in: 0x73, 3 pad, u32 op,
    u32 status 0, then 16 u32 bit counts."""
    bits = [0] * 16
    bits[1] = bits[11] = 4096
    return (bytes((LOG_CONFIG_F,)) + struct.pack("<3xII", 1, 0)
            + struct.pack("<16I", *bits))


def _is_set_mask(c: bytes) -> bool:
    return len(c) >= 8 and c[0] == LOG_CONFIG_F and struct.unpack_from("<I", c, 4)[0] == SET_MASK_OP


def _run(filler_hz: float = 0.0, timeout: float = 40.0, **flags):
    parts = ["defer=false", "stats_interval=0"]
    parts += [f"{k}={v}" for k, v in flags.items()]
    with FakeAtModem(imei=DIAG_IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(scripted={RETRIEVE_RANGES: _ranges_reply()},
                          filler_hz=filler_hz) as dg:
        definition = (f"celldiag-{DIAG_IMEI}:atport={at.port},diagport={dg.port},"
                      + ",".join(parts))
        run = CellDiagRun(_binary_or_skip(), definition, timeout=timeout,
                          close_when=lambda r: r.open_code is not None).run()
        sent = list(dg.commands)
    return run, sent


def _after_last_set_mask(sent: "list[bytes]") -> "list[bytes]":
    idx = [i for i, c in enumerate(sent) if _is_set_mask(c)]
    assert idx, f"the mask never went out: {[c.hex() for c in sent]}"
    return sent[idx[-1] + 1:]


def test_a_masked_capture_clears_its_log_mask_at_the_stop():
    run, sent = _run()
    assert run.open_code == 1, (run.open_message, run.errors)
    assert DISABLE in _after_last_set_mask(sent), (
        "the stop left the LOG mask armed -- every later DIAG client on this "
        f"modem inherits it. Sent: {[c.hex() for c in sent]}")


def test_a_full_mask_capture_clears_it_too():
    run, sent = _run(mask="full")
    assert run.open_code == 1, (run.open_message, run.errors)
    assert DISABLE in _after_last_set_mask(sent), [c.hex() for c in sent]


def test_an_open_that_fails_after_the_mask_still_clears_it():
    """An F3 arm the modem never acks fails the open AFTER the handshake armed
    the mask (the fake answers no 0x7D), and Kismet may never get a working
    reopen: the mask must not outlive the failed open either. Filler traffic
    lets the handshake's 20 s deadline fire; a silent port would wait out the
    reader's 60 s idle timeout instead."""
    run, sent = _run(f3="all", filler_hz=20.0, timeout=60.0)
    assert run.open_code != 1, "the open was meant to fail"
    assert "EXT_MSG_CONFIG" in (run.open_message or ""), run.open_message
    assert DISABLE in _after_last_set_mask(sent), [c.hex() for c in sent]


def test_a_passive_capture_never_touches_the_log_mask():
    """Control: nomask=true arms nothing, so it must clear nothing -- a passive
    tap must not wipe a mask some other client set on purpose."""
    run, sent = _run(nomask="true")
    assert run.open_code == 1, (run.open_message, run.errors)
    assert not [c for c in sent if c[:1] == bytes((LOG_CONFIG_F,))], [c.hex() for c in sent]
