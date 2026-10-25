# SPDX-License-Identifier: Apache-2.0
"""A late final OK does not end the next ORDINARY read on cellat's open path.

An info read (AT+CGMR / +CGSN / +CGMI / +CGMM) may end on 200 ms of
silence after its value, for a modem that never sends the final OK. A modem
that DOES send it, but more than 200 ms after the value, sends it into the next
exchange. The info form never ends on such an OK, but an ordinary read could.
On cellat's open path the next exchange after ``detect_vendor()``'s AT+CGMI is
a capability probe -- ``AT+QENG="servingcell"`` on a Quectel -- so the probe
would read the previous command's OK as its whole reply, the capability would
come out unset, and a working modem would be refused as having "no known cell
survey command".

The fd remembers that a gap-ended info read may still owe its OK, and the
next ordinary read holds a leading bare OK until the gap says whose it is. The
reader rules are pinned in ``capture_cell_at/test_at_serial.c``; this file is
the wiring, on the compiled ``kismet_cap_cell_at`` against a PTY modem. No host
tty is touched.
"""
from __future__ import annotations

import json

from fake_at_modem import QENG_SERVING, FakeAtModem
from kismet_capture_ipc import CaptureRun
from test_cellat_ipc import _binary_or_skip  # noqa: E402  (staleness-guarded)

IMEI = "351234567847131"
QENG = 'AT+QENG="servingcell"'
CGMI = "AT+CGMI"
#: The value at once, its OK 450 ms later: past the 200 ms info gap, so the OK
#: lands inside the NEXT command's read, ahead of that command's answer.
LATE_OK = (0.0, 0.45)


def _opened(run) -> bool:
    return run.open_code is not None


def _run(modem: FakeAtModem):
    return CaptureRun(_binary_or_skip(), f"cellat-{IMEI}:atport={modem.port},debug=false",
                      timeout=25.0, stop_when=_opened).run()


def test_the_fake_really_terminates_cgmi_late():
    """Positive control: the modem below answers AT+CGMI with a value AND a
    final OK -- so any refusal is the reader's, not a modem that never answered."""
    with FakeAtModem(imei=IMEI, firmware="EG25GGBR07A08M2G", extra=QENG_SERVING,
                     pace={CGMI: LATE_OK}) as m:
        body = m.response_for(CGMI)
    assert "Quectel" in body and body.rstrip().endswith("OK")


def test_a_quectel_whose_cgmi_ok_is_late_still_opens():
    """End to end: the QENG probe must not end on the late CGMI OK, so the
    source opens."""
    with FakeAtModem(imei=IMEI, firmware="EG25GGBR07A08M2G", extra=QENG_SERVING,
                     pace={CGMI: LATE_OK}, echo=True) as modem:
        run = _run(modem)
        sent = list(modem.commands)
    assert CGMI in sent and QENG in sent, sent
    assert run.open_code == 1, (
        f"a Quectel whose AT+CGMI OK trails its value by 450 ms was refused: "
        f"{run.open_message!r}")

    # The QENG probe's own row carries its own answer, not the stray OK.
    rows = [json.loads(r) for r in run.raw_at]
    qeng = [r for r in rows if r["cmd"] == QENG]
    assert qeng, f"no RawAT row for the {QENG} probe: {[r['cmd'] for r in rows]}"
    first = qeng[0]
    assert first["response"].startswith("+QENG:"), first["response"]
    assert first["rx_done_ns"], "the probe did not end on a terminal line"


def test_a_prompt_modem_opens_exactly_as_before():
    """Control: the same modem terminating promptly -- nothing is owed, so no
    ordinary read holds anything, and the dialogue is the same one."""
    with FakeAtModem(imei=IMEI, firmware="EG25GGBR07A08M2G", extra=QENG_SERVING,
                     echo=True) as modem:
        run = _run(modem)
        sent = list(modem.commands)
    assert run.open_code == 1, run.open_message
    assert sent.index(CGMI) < sent.index(QENG), sent
