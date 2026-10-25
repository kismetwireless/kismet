"""The graceful datasource close, helper side, on the real binaries.

The server's plain way to stop a capture helper,
``kis_external_ipc::close_impl()``, closes the IPC pipe and SIGTERMs the helper
in the same call. The capture framework runs the capture thread
``PTHREAD_CANCEL_ASYNCHRONOUS`` and leaves SIGTERM at its default disposition,
so a stop like that runs **no teardown at all**:

* cellat's END ``AT+CCLK?`` anchor is never even issued;
* celldiag's END ``DIAG_TS_F`` anchor reaches only the rawlog sidecar, and
  only on a pipe-EOF stop the server never makes;
* celldiag's END raw slice never goes out, so the stream reads
  "no END: end unconfirmed";
* celldiag's QSH-trace disarm-at-stop never runs.

The graceful close is a handshake. The helper opts in by advertising a close grace in its
OPENREPORT (field 11). The server then stops a source by sending ``CLOSEREQ``
(command 20) instead of closing the pipe. The helper leaves its capture loop,
runs its teardown **with the pipe still open**, drains its out-ring and exits on
its own. The server treats that EOF as a clean close, not an error.

These tests drive each helper exactly as that server does: send one CLOSEREQ and
**never close the pipe**, then read what arrives before the helper exits. The
harness's own fallback (pipe close, then SIGTERM after ``graceful_close_s``) is
left at 0, so a helper that ignored the request would be SIGTERMed at timeout
and fail the exit-code assertion.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import QENG_SERVING, FakeAtModem  # noqa: E402
from fake_diag_modem import FakeDiagModem  # noqa: E402
from test_cellat_ipc import CellAtRun  # noqa: E402
from test_cellat_ipc import _binary_or_skip as _cellat_binary_or_skip  # noqa: E402
from test_celldiag_raw_packets import _end_of, _reassemble, _slices  # noqa: E402
from celldiag_run import CellDiagRun  # noqa: E402
from celldiag_run import _binary_or_skip as _celldiag_binary_or_skip  # noqa: E402

AT_IMEI = "351234567890123"
DIAG_IMEI = "123456789012347"
FIRMWARE = "RM520NGLAAR03A03M4G"
CCLK = {"AT+CCLK?": '+CCLK: "26/09/22,20:00:00+00"'}


def _edges(run) -> list[str]:
    return [json.loads(js)["edge"] for js in run.clock_anchors]


def _started(run) -> bool:
    """Close only once the START anchor is in: the END must follow a live capture."""
    return "start" in _edges(run)


def _assert_clean_self_exit(run) -> None:
    """The helper exited BY ITSELF, inside the grace it advertised.

    ``graceful_close_s`` is 0, so the harness never closes the pipe: an exit
    code of 0 can only come from the helper finishing on its own. A helper that
    ignored the CLOSEREQ would have run to ``timeout`` and been SIGTERMed (-15).
    """
    assert run.close_sent_mono is not None, "the CLOSEREQ was never sent"
    assert run.exit_code == 0, f"exit {run.exit_code}: did not exit by itself"
    assert run.exit_mono is not None
    took = run.exit_mono - run.close_sent_mono
    assert took < run.close_grace_ms / 1000.0, (
        f"took {took:.2f}s to exit, over its own {run.close_grace_ms} ms grace")


# ── cellat (the END AT+CCLK? anchor) ──────────────────────────────────────────

def test_cellat_advertises_a_close_grace_in_its_openreport():
    binary = _cellat_binary_or_skip()
    with FakeAtModem(imei=AT_IMEI, extra={**QENG_SERVING, **CCLK}) as modem:
        run = CellAtRun(binary, f"cellat-{AT_IMEI}:atport={modem.port}",
                        timeout=20.0,
                        stop_when=lambda r: r.open_code is not None).run()
    assert run.open_code == 1, (run.open_message, run.errors)
    # The server waits this long before it gives up and hard-closes, so it must
    # cover one AT round trip (the END +CCLK has a 3 s timeout) with headroom,
    # and must stay small enough that a Ctrl-C does not hang.
    assert run.close_grace_ms is not None, "no OPENREPORT field 11: not opted in"
    assert 3000 < run.close_grace_ms <= 10000, run.close_grace_ms


def test_cellat_closereq_issues_the_end_anchor_and_exits_by_itself():
    binary = _cellat_binary_or_skip()
    with FakeAtModem(imei=AT_IMEI, extra={**QENG_SERVING, **CCLK}) as modem:
        run = CellAtRun(binary, f"cellat-{AT_IMEI}:atport={modem.port}",
                        timeout=25.0, close_when=_started).run()
        cclk_sent = modem.commands.count("AT+CCLK?")

    _assert_clean_self_exit(run)
    # The measurement: END reached the SERVER, over the pipe, as a row.
    assert _edges(run)[0] == "start" and _edges(run)[-1] == "end", _edges(run)
    assert _edges(run).count("end") == 1, _edges(run)
    # ...because the modem was really asked: one CCLK per anchor.
    assert cclk_sent == len(run.clock_anchors), (cclk_sent, _edges(run))


def test_a_disabled_cellat_source_exits_promptly_on_closereq():
    """enabled=false idles with no port open; a close must not wait on it."""
    binary = _cellat_binary_or_skip()
    with FakeAtModem(imei=AT_IMEI) as modem:
        run = CellAtRun(binary, f"cellat-{AT_IMEI}:enabled=false,atport={modem.port}",
                        timeout=20.0,
                        close_when=lambda r: r.open_code is not None).run()
    assert run.open_code == 1, (run.open_message, run.errors)
    _assert_clean_self_exit(run)
    assert run.exit_mono - run.close_sent_mono < 2.0
    assert run.clock_anchors == []      # nothing was opened, nothing to anchor


# ── celldiag (the END DIAG_TS_F anchor and the END slice) ─────────────────────

def _diag_definition(at: FakeAtModem, dg: FakeDiagModem, **flags) -> str:
    parts = [f"atport={at.port}", f"diagport={dg.port}", "nomask=true",
             "defer=false", "stats_interval=0"]
    parts += [f"{k}={v}" for k, v in flags.items()]
    return f"celldiag-{DIAG_IMEI}:" + ",".join(parts)


def test_celldiag_advertises_a_close_grace_in_its_openreport():
    binary = _celldiag_binary_or_skip()
    with FakeAtModem(imei=DIAG_IMEI, firmware=FIRMWARE) as at, FakeDiagModem() as dg:
        run = CellDiagRun(binary, _diag_definition(at, dg), timeout=20.0,
                          stop_when=lambda r: r.open_code is not None).run()
    assert run.open_code == 1, (run.open_message, run.errors)
    assert run.close_grace_ms is not None, "no OPENREPORT field 11: not opted in"
    assert 1000 < run.close_grace_ms <= 10000, run.close_grace_ms


def test_celldiag_closereq_lands_end_anchor_and_end_slice_in_band(tmp_path):
    binary = _celldiag_binary_or_skip()
    rawlog = tmp_path / "cap.hdlc"
    with FakeAtModem(imei=DIAG_IMEI, firmware=FIRMWARE) as at, \
            FakeDiagModem(filler_hz=50) as dg:
        run = CellDiagRun(binary, _diag_definition(at, dg, rawlog=rawlog,
                                                   clock_anchor_sec=30),
                          timeout=25.0, close_when=_started).run()

    _assert_clean_self_exit(run)

    # END anchor: in band -- the row a plain close never delivers --
    # and the sidecar agrees with the in-band stream row for row.
    assert _edges(run) == ["start", "end"], _edges(run)
    side = (tmp_path / "cap.hdlc.clock_anchor.jsonl").read_text().splitlines()
    assert [json.loads(s)["edge"] for s in side] == ["start", "end"], side

    # END slice: the in-band stream CONFIRMS its own end, and is
    # byte-identical to the file tee -- nothing read before the close is lost.
    slices = _slices(run)
    data = rawlog.read_bytes()
    assert len(data) > 0
    assert _reassemble(slices) == data, "in-band stream differs from the rawlog tee"
    assert _end_of(slices) == len(data), (_end_of(slices), len(data))
