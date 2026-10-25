"""A malformed AT+CGSN read never names a cellat source.

A PCIe RM520N-GL can answer AT+CGSN with ``Quectel``, the modem's AT+CGMI
answer, most likely a reply another prober left on the port. Taking any value
line as the IMEI would list it as ``cellat-Quectel (... IMEI:Quectel)``. The
IMEI is how a cellat source is addressed and it names the band-lock state
file, so a wrong one is not a cosmetic label.

A read that is not 15 ASCII digits is asked once more; a good retry is
used, a second bad read is dropped with a reason on stderr. A well-formed
modem's dialogue is unchanged -- that half is pinned by
``test_unterminated_info.test_a_terminating_modem_dialogue_is_unchanged``
(exactly one AT+CGSN).

Every modem is a PTY fake reached through ``CELLAT_SCAN_PORTS``; no host tty is
touched.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_at_modem import FakeAtModem  # noqa: E402
from test_cellat_ipc import _binary_or_skip  # noqa: E402

IMEI = "351234567890123"          # synthetic, same shape as an RM520N-GL's
STALE = "Quectel"                 # its AT+CGMI answer, read as the IMEI


def _list(binary: str, port: str) -> "tuple[list[str], str]":
    out = subprocess.run([binary, "--list"], capture_output=True, text=True,
                         timeout=90, env={**os.environ, "CELLAT_SCAN_PORTS": port})
    lines = [ln.strip() for ln in (out.stdout + out.stderr).splitlines()]
    return lines, out.stderr


def _rm520n(**kw) -> FakeAtModem:
    return FakeAtModem(firmware="RM520NGLAAR01A08M4G", manufacturer="Quectel",
                       extra={"AT+CGMM": "RM520N-GL"}, **kw)


def test_the_fake_answers_a_sequence_then_its_script():
    """Positive control: without it, a pass below could mean the fake never
    sent the stale answer at all."""
    with _rm520n(imei=IMEI, sequence={"AT+CGSN": [STALE]}) as m:
        assert STALE in m.response_for("AT+CGSN")
        assert IMEI in m.response_for("AT+CGSN")
        assert IMEI in m.response_for("AT+CGSN")


def test_a_stale_first_reply_is_re_asked_and_the_real_imei_names_the_source():
    binary = _binary_or_skip()
    with _rm520n(imei=IMEI, sequence={"AT+CGSN": [STALE]}) as m:
        lines, _ = _list(binary, m.port)
        sent = list(m.commands)
    assert sent.count("AT+CGSN") == 2, sent
    assert any(ln.startswith(f"cellat-{IMEI} ") for ln in lines), lines
    assert not any(f"cellat-{STALE}" in ln or f"IMEI:{STALE}" in ln
                   for ln in lines), lines


def test_a_persistently_malformed_imei_names_no_source_and_says_why():
    binary = _binary_or_skip()
    with _rm520n(imei=STALE) as m:
        port = m.port
        lines, err = _list(binary, port)
        sent = list(m.commands)
    assert sent.count("AT+CGSN") == 2, sent       # asked once more, not forever
    assert not any(ln.startswith("cellat-") for ln in lines), lines
    assert "not a 15-digit IMEI" in err, err
    assert port in err, err


def test_an_imeisv_length_read_is_not_published_either():
    """16 digits (an IMEISV) is IMEI-like, but ``cellat-<16 digits>`` is refused
    by the source-definition parser, so listing it would offer a name that
    cannot be opened."""
    binary = _binary_or_skip()
    with _rm520n(imei=IMEI + "1") as m:
        lines, err = _list(binary, m.port)
    assert not any(ln.startswith("cellat-") for ln in lines), lines
    assert "not a 15-digit IMEI" in err, err
