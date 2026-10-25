"""What a qsh=on celldiag capture leaves on the modem after a stop.

``qsh=on`` arms three things at bring-up: the QSH-trace ``0x9001`` maskset
(``0x9D``/``0x92``), the ``0x60`` event-report stream, and a diag_id binding
request. The stop teardown must disarm both the QSH-trace maskset and the
``0x60`` event stream; ``diag_config_disarm_latched`` alone sends only the
QSH-trace and F3 disarms, and an event stream left on is inherited by every
later tool on the modem.

These tests read the frames the capture wrote to the modem, on the real
binary against a PTY DIAG responder; no host port is touched.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from celldiag_run import CellDiagRun  # noqa: E402
from celldiag_run import _binary_or_skip  # noqa: E402

DIAG_IMEI = "123456789012347"
FIRMWARE = "RM520NGLAAR03A03M4G"

EVENTS_ON = bytes((0x60, 0x01))
EVENTS_OFF = bytes((0x60, 0x00))


def _is_qsh_maskset(payload: bytes, *, count: int) -> bool:
    """A QSH-trace 0x9001 maskset SET: 0x4B, subsys 0x44, and ``count`` pairs
    (40 for the golden arm, 0 for the disarm) at body offset 15."""
    return (len(payload) > 16 and payload[0] == 0x4B and payload[1] == 0x44
            and payload[16] == count)


def _run(**flags):
    parts = ["nomask=true", "defer=false", "stats_interval=0"]
    parts += [f"{k}={v}" for k, v in flags.items()]
    # Ack the arm's 0x4B / 0x60 commands, or each waits out a 20 s deadline.
    with FakeAtModem(imei=DIAG_IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(echo_opcodes={0x4B, 0x60}) as dg:
        definition = (f"celldiag-{DIAG_IMEI}:atport={at.port},diagport={dg.port},"
                      + ",".join(parts))
        run = CellDiagRun(_binary_or_skip(), definition, timeout=40.0,
                          close_when=lambda r: r.open_code is not None).run()
        sent = list(dg.commands)
    return run, sent


def test_a_qsh_stop_turns_the_event_stream_back_off():
    run, sent = _run(qsh="on")
    assert run.open_code == 1, (run.open_message, run.errors)
    # The premise: the arm really went out (else nothing below means anything).
    assert EVENTS_ON in sent, [c.hex() for c in sent]
    assert any(_is_qsh_maskset(c, count=40) for c in sent), "the QSH arm never went out"
    armed_at = sent.index(EVENTS_ON)
    after = sent[armed_at + 1:]
    assert any(_is_qsh_maskset(c, count=0) for c in after), (
        "the stop sent no QSH-trace disarm after the arm")
    assert EVENTS_OFF in after, (
        "the stop disarmed QSH but left the 0x60 event stream on -- every later "
        f"tool on this modem inherits it. Sent after the arm: {[c.hex() for c in after]}")


def test_a_lean_capture_never_touches_the_event_stream():
    """Control: qsh off arms no events, so its stop has none to turn off -- the
    default wardrive sends no 0x60 frame at all."""
    run, sent = _run()
    assert run.open_code == 1, (run.open_message, run.errors)
    assert not [c for c in sent if c[:1] == b"\x60"], [c.hex() for c in sent]
    # ...and its stop sends no QSH disarm either (nomask= also skips bring-up's).
    assert not any(_is_qsh_maskset(c, count=0) for c in sent), [c.hex() for c in sent]
