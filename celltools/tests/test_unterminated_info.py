"""A modem that never sends the final OK on info replies is identified fast.

A Foxconn T99W175 answers AT+CGMR / +CGSN / +CGMI / +CGMM with the value (in
about 50 ms) and no final ``OK``. A reader that ends an exchange only on OK /
ERROR / +CME ERROR runs every such read to its whole deadline, about 7 s per
``--list`` per unit, on every Sources-panel refresh and every open-time IMEI
scan.

The info reads end once a value line has arrived and the port has then been
idle for ``MODEMIDENT_INFO_IDLE_MS``. Two things must not change, and are pinned
here beside the speed-up:

* a well-behaved modem's dialogue -- the same commands, the same label;
* a slow modem that DOES terminate, but late: its OK must not be taken as the
  END of the next command's reply (a bare OK before any value line does not end
  an info read -- the idle gap does).

Every modem is a PTY fake reached through ``*_SCAN_PORTS``; no host tty is touched.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from test_cellat_ipc import _binary_or_skip as _cellat_or_skip  # noqa: E402
from celldiag_run import _binary_or_skip as _celldiag_or_skip  # noqa: E402

IMEI = "351234567847131"
#: The T99W175's own answers. CGMI is the
#: chipset vendor, not Foxconn -- kept verbatim, as the helpers keep it.
MAKE, MODEL = "QUALCOMM", "T99W175"
FIRMWARE = "T99W175.F0.1.0.0.9.GC.004  1  [Nov 10 2021 08:00:00]"
INFO = frozenset({"AT+CGMR", "AT+CGSN", "AT+CGMI", "AT+CGMM"})

#: Well under the ~7 s a --list cost per such unit, and well over what a
#: well-behaved PTY fake costs (process start + ~5 exchanges, ~0.1-0.3 s).
FAST_S = 1.5


def _list(binary: str, env: dict) -> "tuple[list[str], float]":
    t0 = time.monotonic()
    out = subprocess.run([binary, "--list"], capture_output=True, text=True,
                         timeout=90, env={**os.environ, **env})
    took = time.monotonic() - t0
    return [ln.strip() for ln in (out.stdout + out.stderr).splitlines()], took


def _t99w175(**kw) -> FakeAtModem:
    return FakeAtModem(imei=IMEI, firmware=FIRMWARE, manufacturer=MAKE,
                       extra={"AT+CGMM": MODEL}, echo=True, **kw)


def _label(suffix: str = "") -> str:
    return f"{MAKE} {MODEL} ({FIRMWARE}) IMEI:{IMEI}{suffix}"


# -- the fake itself ----------------------------------------------------------

def test_the_fake_can_answer_without_the_final_ok():
    """Positive control for everything below: the responder really builds the
    T99W175's shape (it appends OK to every other answer)."""
    with _t99w175(unterminated=INFO) as m:
        assert "OK" not in m.response_for("AT+CGMR")
        assert FIRMWARE in m.response_for("AT+CGMR")
        assert m.response_for("AT").strip() == "OK"     # not an info read
    with _t99w175() as m:
        assert m.response_for("AT+CGMR").strip().endswith("OK")


# -- the speed-up, both helpers ------------------------------------------------

def test_cellat_list_identifies_an_unterminated_modem_fast():
    binary = _cellat_or_skip()
    with _t99w175(unterminated=INFO) as at:
        lines, took = _list(binary, {"CELLAT_SCAN_PORTS": at.port})
    assert f"cellat-{IMEI} ({_label()})" in lines, lines
    assert took < FAST_S, f"cellat --list took {took:.2f}s on an unterminated modem"


def test_celldiag_list_identifies_an_unterminated_modem_fast():
    binary = _celldiag_or_skip()
    with _t99w175(unterminated=INFO) as at:
        lines, took = _list(binary, {"CELLDIAG_SCAN_PORTS": at.port})
    assert f"celldiag-{IMEI} ({_label(' DIAG')})" in lines, lines
    assert took < FAST_S, f"celldiag --list took {took:.2f}s on an unterminated modem"


# -- what must not change -------------------------------------------------------

def test_a_terminating_modem_dialogue_is_unchanged():
    """Same commands in the same order, same label, and still fast."""
    for binary, env_key, suffix, want in (
        (_cellat_or_skip(), "CELLAT_SCAN_PORTS", "",
         ["AT", "AT+CGMR", "AT+CGSN", "AT+CGMI", "AT+CGMM"]),
        (_celldiag_or_skip(), "CELLDIAG_SCAN_PORTS", " DIAG",
         ["AT", "AT+CGSN", "AT+CGMR", "AT+CGMI", "AT+CGMM"]),
    ):
        with _t99w175() as at:
            lines, took = _list(binary, {env_key: at.port})
            sent = list(at.commands)
        name = Path(binary).name
        assert any(ln.endswith(f"({_label(suffix)})") for ln in lines), (name, lines)
        assert sent == want, (name, sent)
        assert took < FAST_S, f"{name} --list took {took:.2f}s on a terminating modem"


def test_a_late_ok_does_not_end_the_next_reply():
    """A modem that terminates, but LATE: every info value is followed by its OK
    0.45 s later -- past the idle gap, so each info read returns on the gap, and
    that OK then arrives inside the NEXT command's read, ahead of its answer.
    Ending that read on the stray OK would empty the next value (the make, the
    firmware). A bare OK before any value line must not end an info read."""
    late = {c: (0.0, 0.45) for c in INFO}
    for binary, env_key, suffix in (
        (_cellat_or_skip(), "CELLAT_SCAN_PORTS", ""),
        (_celldiag_or_skip(), "CELLDIAG_SCAN_PORTS", " DIAG"),
    ):
        with _t99w175(pace=late) as at:
            lines, _took = _list(binary, {env_key: at.port})
        name = Path(binary).name
        assert any(ln.endswith(f"({_label(suffix)})") for ln in lines), (name, lines)
