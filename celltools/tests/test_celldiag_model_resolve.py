# SPDX-License-Identifier: Apache-2.0
"""celldiag resolves (or explicitly names) the modem model, never a silent 'modem'.

## The hazard

The model that celldiag stamps into the raw-DIAG tee filename (rawlog ``%m``) and
into ``prov.model`` is the firmware string read by ``identify_modem`` (AT+CGMR).
On the EG25-G that read can come back empty while a ``cellat`` source holds a
sibling AT port and the ``at_scan`` is slow. The IMEI still matches (it is in the
source name), but with the firmware/model empty the tee filename would fall back
to the literal ``celldiag-modem-<imei>-<ts>.hdlc`` and the raw DIAG stream would
lose the model identity its siblings carry.

## The two guards, and what each test pins

* **Retry.** On an IMEI-targeted scan the IMEI already matched on the open port,
  so an empty AT+CGMR is a transient read under contention, not "no firmware".
  ``identify_modem`` retries AT+CGMR once.
  ``test_a_transient_empty_firmware_read_is_retried`` drives the real binary
  with an AT modem whose first AT+CGMR times out and whose second succeeds: the
  open succeeds and the model is resolved.

* **Explicit sentinel.** When celldiag proceeds without an AT identity at all
  (an MHI ``diagport=`` with no ``atport=`` — the intended fused-capture path),
  the model is stamped an explicit ``unknown`` and an INFO says so, instead of a
  blank that the rawlog turns into a modem literally named ``modem``.
  ``test_no_at_identity_stamps_an_explicit_unknown_not_a_silent_modem`` pins it.

## Scope

Verifies the open-time model decision against the real compiled binary via the
``fake_at_modem`` / ``fake_diag_modem`` PTY harness.
"""
from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from celldiag_run import CellDiagRun, _binary_or_skip  # noqa: E402

IMEI = "123456789012347"
FIRMWARE = "EG25GGBR07A08M2G"   # an EG25-G firmware string


class FlakyFirmwareModem(FakeAtModem):
    """A modem whose FIRST ``AT+CGMR`` read times out (empty) and whose second
    succeeds — the transient contention the retry must ride out.

    A no-response (``None``) models the real failure (a slow/busy tty read that
    hits the 3 s deadline with nothing), not an ``ERROR``: ``at_first_value_line``
    does not skip a bare ``ERROR`` line, so an ``ERROR`` would wrongly parse AS
    the firmware. The IMEI (AT+CGSN) always answers, so the port matches.
    """

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self._cgmr_seen = 0

    def response_for(self, cmd: str):
        if cmd == "AT+CGMR":
            self._cgmr_seen += 1
            if self._cgmr_seen == 1:
                return None          # first firmware read times out -> empty
        return super().response_for(cmd)   # 2nd AT+CGMR (+ all else) via script


def _definition(*, atport: str = "", diagport: str, **flags) -> str:
    parts = [f"diagport={diagport}", "nomask=true", "defer=false",
             "stats_interval=0"]
    if atport:
        parts.insert(0, f"atport={atport}")
    parts += [f"{k}={v}" for k, v in flags.items()]
    return f"celldiag-{IMEI}:" + ",".join(parts)


def _opened(run: CellDiagRun) -> bool:
    return run.open_code is not None


def test_a_transient_empty_firmware_read_is_retried():
    """A matched modem whose first AT+CGMR is empty must still resolve.

    The retry reads the firmware and the open succeeds — proof the model was
    resolved, since an explicit ``atport=`` fails the open hard
    (``open_code == 0``) when identify fails.
    """
    binary = _binary_or_skip()
    with FlakyFirmwareModem(imei=IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem() as dg:
        run = CellDiagRun(binary,
                          _definition(atport=at.port, diagport=dg.port),
                          timeout=25.0, stop_when=_opened).run()
        cgmr_calls = at.commands.count("AT+CGMR")
    assert run.open_code == 1, (
        f"a matched modem whose first AT+CGMR was empty should open after the "
        f"retry; got open_code={run.open_code} message={run.open_message!r}")
    assert cgmr_calls == 2, (
        f"the firmware read should have been retried exactly once; the modem "
        f"saw AT+CGMR {cgmr_calls} time(s)")


def test_no_at_identity_stamps_an_explicit_unknown_not_a_silent_modem():
    """Proceeding without any AT identity must name the model explicitly.

    An MHI ``diagport=`` with no ``atport=`` is the intended fused-capture path
    (the AT node is held by the cellat source), so celldiag proceeds without an
    AT identity. A nonexistent ``mhi_`` node exercises that branch without any
    hardware: ``diag_wwan_classify`` recognises it by name, so the scan is
    skipped and the bring-up reaches the model stamp before the (missing) DIAG
    node fails to open. The model must be an explicit ``unknown`` with an INFO
    note, never a silent blank that the rawlog renders as ``modem``.
    """
    binary = _binary_or_skip()
    defn = _definition(diagport="/dev/mhi_nonexistent_4663")

    def stop(run: CellDiagRun) -> bool:
        return (any("model/firmware unresolved" in m for m in run.messages)
                or run.open_code is not None)

    run = CellDiagRun(binary, defn, timeout=20.0, stop_when=stop).run()
    hits = [m for m in run.messages if "model/firmware unresolved" in m]
    assert hits, (
        "no INFO named the model fallback; a source opened without AT identity "
        f"should say the model reads 'unknown'. messages={run.messages!r}")
    assert any("unknown" in m for m in hits), (
        f"the fallback note must name the explicit 'unknown' sentinel; got {hits!r}")
