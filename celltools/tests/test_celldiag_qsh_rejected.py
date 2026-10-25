# SPDX-License-Identifier: Apache-2.0
"""A part that rejects the qsh=on requests opens at once.

``qsh=on`` sends three requests at bring-up -- the QSH-trace maskset (0x4B
subsys 0x44), the event-report enable (0x60) and the diag_id binding (0x4B
subsys 0x12). A part without them answers each with DIAG_BAD_CMD_F (0x13) plus
an echo of the request. The handshake reader must take that BAD_CMD as the
answer; a reader that waits only for the request's own opcode spends the full
20 s deadline on every rejection (and again on every reopen) while the modem
streams on.

These run the REAL capture binary against a PTY DIAG responder that rejects all
three, streaming filler frames the way a live port does. No host port is touched.
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from celldiag_run import CellDiagRun  # noqa: E402
from celldiag_run import _binary_or_skip  # noqa: E402

DIAG_IMEI = "123456789012348"   # not Luhn-valid: never reads as a real device
FIRMWARE = "EG25GGBR07A08M2G"

#: Three rejected requests at 20 s each would be 60 s. Well under one
#: deadline proves no rejection waited one out.
BOUND_S = 15.0


def _open_rejecting(*, deferred: bool):
    """``deferred``: the default bring-up after the open report (the path that
    reports per-phase times); else inside the open."""
    parts = ["nomask=true", "stats_interval=0", "qsh=on"]
    if not deferred:
        parts.append("defer=false")
    done = ((lambda r: any("bring-up took" in m for m in r.messages)) if deferred
            else (lambda r: r.open_code is not None))
    with FakeAtModem(imei=DIAG_IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(reject_opcodes={0x4B, 0x60}, filler_hz=20) as dg:
        definition = (f"celldiag-{DIAG_IMEI}:atport={at.port},diagport={dg.port},"
                      + ",".join(parts))
        t0 = time.monotonic()
        run = CellDiagRun(_binary_or_skip(), definition, timeout=90.0,
                          close_when=done).run()
        took = time.monotonic() - t0
        sent = list(dg.commands)
    return run, took, sent


def test_a_part_that_rejects_every_qsh_request_opens_without_waiting():
    run, took, sent = _open_rejecting(deferred=False)
    # Positive control: the three requests really went out and were rejected,
    # so this measures the rejection path, not a capture that skipped qsh.
    assert any(c[:2] == bytes((0x4B, 0x44)) for c in sent), sent
    assert any(c[:2] == bytes((0x4B, 0x12)) for c in sent), sent
    assert any(c[:1] == bytes((0x60,)) for c in sent), sent
    assert run.open_code == 1, (run.open_message, run.errors)
    assert took < BOUND_S, (
        f"opening took {took:.1f} s: a rejected qsh request waited out its "
        f"deadline instead of taking BAD_CMD as the answer")
    # The operator-facing account of it: armed-or-unsupported, no table.
    armed = [m for m in run.messages if "qsh=on: armed" in m]
    assert armed and "no table (BAD_CMD or timeout)" in armed[0], run.messages[:10]


def test_the_qsh_arm_phase_itself_is_short():
    """The bring-up's own per-phase timing report for the qsh arm."""
    run, _, _ = _open_rejecting(deferred=True)
    phases = [m for m in run.messages if "qsh_arm=" in m]
    assert phases, f"no bring-up phase report: {run.messages[:10]}"
    ms = int(re.search(r"qsh_arm=(\d+)ms", phases[-1]).group(1))
    assert ms < 5000, f"qsh_arm={ms}ms on a part that rejects all three requests"
