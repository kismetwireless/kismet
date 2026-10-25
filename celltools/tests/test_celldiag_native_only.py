# SPDX-License-Identifier: Apache-2.0
"""The helper decodes in process, natively, and nothing else.

Every record is decoded by the native legs linked into ``kismet_cap_cell_diag``;
there is no second decoder to select, start, or fall back to. These tests pin
what that means at the source definition and in the output:

* a ``helper=`` option, or a census producer the helper does not have, is
  REFUSED at open rather than accepted and ignored -- a definition that still
  asks for one would otherwise run with something it did not ask for (the
  retired ``nativedecode=`` / ``census=`` spellings are pinned in
  ``test_celldiag_replay_ab.py``);
* the census and the GSMTAP tap give pinned answers on synthetic records (no
  captured bytes), so their behaviour is checked with nothing outside the tree.
"""
from __future__ import annotations

import importlib.util
import json
import socket
import threading
import time
from pathlib import Path

import pytest

from celldiag_run import CellDiagRun, _binary_or_skip, _definition

_CELLDIAG = Path(__file__).resolve().parents[2] / "capture_cell_diag"
#: The tree's own synthetic capture (fixtures/make_functional_fixture.py).
_FUNCTIONAL = _CELLDIAG / "fixtures" / "functional.hdlc"


def _functional_fixture_module():
    path = _CELLDIAG / "fixtures" / "make_functional_fixture.py"
    if not path.is_file():
        pytest.skip(f"no fixture builder at {path}")
    spec = importlib.util.spec_from_file_location("make_functional_fixture", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _replay_or_skip() -> Path:
    if not _FUNCTIONAL.is_file():
        pytest.skip(f"no in-tree replay fixture at {_FUNCTIONAL}")
    return _FUNCTIONAL


def _opened(run) -> bool:
    return run.open_code in (1, None)


# ── the options that selected another decoder are refused ────────────────────

def test_an_unknown_census_producer_is_refused_by_name():
    """Not only the retired ``census=helper``: any producer but ``native`` is
    refused at open, and the refusal names the value so the operator can find
    the definition to fix."""
    binary = _binary_or_skip()
    run = CellDiagRun(binary, _definition(_replay_or_skip(), census="python"),
                      timeout=30.0).run()
    assert not _opened(run), f"census=python was accepted (code={run.open_code})"
    assert "census=python" in (run.open_message or ""), run.open_message


def test_helper_is_refused_not_silently_ignored(tmp_path):
    """The removed ``helper=`` option must not become a no-op: a definition
    that still names a decoder would otherwise quietly decode with another."""
    binary = _binary_or_skip()
    other = tmp_path / "elsewhere"
    other.mkdir()
    run = CellDiagRun(binary, _definition(_replay_or_skip(), helper=other),
                      timeout=30.0).run()
    assert not _opened(run), \
        f"helper= was accepted (code={run.open_code}) -- it is being ignored"
    blob = " | ".join([run.open_message or "", *run.messages, *run.errors])
    assert "helper= source option was removed" in blob, blob


# ── the census, on a record a native leg must refuse ─────────────────────────

#: A 0xB193 record with outer v1 and one subpacket (v36) whose declared size
#: (200) overruns the payload (16 B). The native 0xB193 leg exists, so it sees
#: the record, and must REFUSE it rather than claim it parsed.
_MALFORMED_B193 = (bytes([1, 1]) + (0).to_bytes(2, "little") + bytes([0, 36])
                   + (200).to_bytes(2, "little") + bytes(8))
_MALFORMED_COUNT = 4
#: code/ver, seen, decoded, dropped, ..., `u` = unrecognized.
_MALFORMED_ROW = f"0xB193/v1,{_MALFORMED_COUNT},0,{_MALFORMED_COUNT},0,0,u"


def _final_census_table(run) -> str | None:
    tables = []
    for js in run.control:
        try:
            o = json.loads(js)
        except json.JSONDecodeError:
            continue
        if isinstance(o, dict) and o.get("type") == "diag_census":
            tables.append(o["table"])
    return tables[-1] if tables else None


def test_a_malformed_leg_record_is_counted_dropped_not_decoded(tmp_path):
    """A record a native leg cannot parse is DROPPED in the census:
    `unrecognized`, never decoded.

    The census once read it as decoded (``0xB193/v1,4,4,0,0,0,s``), because a
    leg returned the same empty list for "refused" and "parsed, nothing to
    emit". Every leg now reports a refusal, and the census counts it dropped.
    """
    binary = _binary_or_skip()
    fx = _functional_fixture_module()
    data = b"\x7e" + b"".join(fx.log_f_frame(0xB193, 1000 + i, _MALFORMED_B193)
                              for i in range(_MALFORMED_COUNT))
    replay = tmp_path / "malformed_b193.hdlc"
    replay.write_bytes(data)

    run = CellDiagRun(binary, _definition(replay, census="native"),
                      timeout=120.0).run()
    assert _opened(run), f"OPENREPORT failed: {run.open_message!r}"
    table = _final_census_table(run)
    assert table is not None, "no diag_census table relayed"
    row = next((r for r in table.split(";")
                if r.split(",", 1)[0] == "0xB193/v1"), None)
    assert row == _MALFORMED_ROW, table


# ── the GSMTAP tap, on synthetic LTE NAS records ─────────────────────────────

GSMTAP_TYPE_LTE_NAS = 0x12

#: (code, payload) records of the synthetic NAS replay. EMM INFORMATION with no
#: optional IEs, behind the 01 09 05 00 log wrapper, is structurally complete
#: on every plain code; 0xB0E1 carries a security-protected PDU (sec_hdr 2 |
#: PD 7, MAC, SQN, inner); the 0xB0E2 Attach reject (07 44) lacks its
#: mandatory EMM cause, so the TS 24.301 structure check refuses it.
_SYNTH_NAS = [
    (0xB0E1, bytes.fromhex("01090500" "27" "00000000" "05" "5201c1")),
    (0xB0E2, bytes.fromhex("01090500" "0761")),
    (0xB0E3, bytes.fromhex("01090500" "0761")),
    (0xB0EC, bytes.fromhex("01090500" "0761")),
    (0xB0ED, bytes.fromhex("01090500" "0761")),
    (0xB0E2, bytes.fromhex("01090500" "0744")),     # truncated: refused
]
_SYNTH_NAS_FRAMED = 5

#: The datagrams the synthetic NAS replay must produce, in order. The truncated
#: 0xB0E2 produces none.
_SYNTH_NAS_GOLDEN = [bytes.fromhex(h) for h in (
    "020412004000000000000000010000002700000000055201c1",   # 0xB0E1 protected UL
    "020412000000000000000000000000000761",                 # 0xB0E2 DL
    "020412004000000000000000000000000761",                 # 0xB0E3 UL
    "020412000000000000000000000000000761",                 # 0xB0EC DL
    "020412004000000000000000000000000761",                 # 0xB0ED UL
)]


class _Listener:
    """A local UDP socket standing in for Wireshark on the GSMTAP port."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.datagrams: list[bytes] = []
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self._stop:
            try:
                self.datagrams.append(self.sock.recv(65535))
            except socket.timeout:
                continue

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        time.sleep(0.3)            # the last datagrams are still in flight
        self._stop = True
        self._t.join(timeout=2)
        self.sock.close()
        return False


def test_nas_datagrams_equal_the_pinned_golden(tmp_path):
    """Every NAS frame, byte- and order-equal to the pinned bytes, and the
    truncated record left unsent and counted declined."""
    binary = _binary_or_skip()
    fx = _functional_fixture_module()
    replay = tmp_path / "synthetic_nas.hdlc"
    replay.write_bytes(b"\x7e" + b"".join(
        fx.log_f_frame(code, 1000 + i, payload)
        for i, (code, payload) in enumerate(_SYNTH_NAS)))

    with _Listener() as lst:
        run = CellDiagRun(binary, _definition(
            replay, gsmtap=f"127.0.0.1:{lst.port}"), timeout=120.0).run()
    assert _opened(run), f"OPENREPORT failed: {run.open_message!r}"

    got = [d for d in lst.datagrams if len(d) >= 3 and d[2] == GSMTAP_TYPE_LTE_NAS]
    assert got == _SYNTH_NAS_GOLDEN, [d.hex() for d in got]

    reports = [m for m in run.messages if " gsmtap 127.0.0.1:" in m and "sent=" in m]
    report = reports[-1] if reports else ""
    assert (f"sent={_SYNTH_NAS_FRAMED} declined=1 errors=0" in report
            and "no native framer" not in report), report
    assert not any("NOT SENT" in m for m in run.messages if "gsmtap" in m)
