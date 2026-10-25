# SPDX-License-Identifier: Apache-2.0
"""The RawDiagAbort witness counts a raw slice where it enters the packetchain.

## The race

The base rx path (``kis_datasource::handle_packet_data_report_v3``) can still
return on ``cancelled`` after ``handle_rx_data_content()`` and before
``handle_rx_packet()``. ``trigger_error()`` sets ``cancelled`` from the IPC
reaper's timer thread without ``ext_mutex``, then waits on ``ext_mutex`` for the
in-flight report and runs the witness. A slice counted in
``handle_rx_data_content()`` can therefore be counted by the witness yet never
reach the packetchain, and the witness row names one slice more than the
kismetdb holds.

## How this file guards it

The natural window is a few instructions wide, so a stress loop cannot
reliably reproduce it; an injected delay between ``handle_rx_datalayer_v3()``
and its ``cancelled`` check does, but that needs a hook the server must not
ship. This file guards the shape instead: the count happens in
``handle_rx_packet()``, under the lock the witness snapshots under, and a
witnessed session takes no later slice.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_celldiag_server_routes import KP_ROOT  # noqa: E402

SRC = KP_ROOT / "datasource_cell_diag.cc"
HDR = KP_ROOT / "datasource_cell_diag.h"


def _body(name: str) -> str:
    """The brace-matched body of ``kis_datasource_cell_diag::<name>(...)``."""
    text = SRC.read_text()
    m = re.search(r"^\S[^\n]*\bkis_datasource_cell_diag::" + re.escape(name) + r"\(",
                  text, re.M)
    assert m, f"no definition of {name} in {SRC.name}"
    i = text.index("{", m.end())
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    raise AssertionError(f"unbalanced braces in {name}")


def _code(body: str) -> str:
    """The body without // comments, so prose naming a call cannot satisfy a check."""
    return re.sub(r"//[^\n]*", "", body)


def test_the_slice_is_not_counted_before_the_base_rx_path_can_still_drop_it():
    body = _code(_body("handle_rx_data_content"))
    assert "note_raw_slice(" not in body, (
        "a slice counted in handle_rx_data_content() can still be abandoned on "
        "`cancelled` before handle_rx_packet(), leaving the witness off by one")


def test_the_slice_is_counted_under_the_witness_lock_then_handed_over():
    body = _code(_body("handle_rx_packet"))
    lock = body.find("std::lock_guard<std::mutex> lk(raw_session_mutex)")
    count = body.find("note_raw_slice(")
    handoff = body.rfind("kis_datasource::handle_rx_packet(packet)")
    assert lock != -1, "the count must hold raw_session_mutex, the lock the witness takes"
    assert count != -1, "handle_rx_packet() must count the raw slice"
    assert lock < count < handoff, (lock, count, handoff)
    # A slice the witness already closed is dropped, not handed over.
    assert re.search(r"if\s*\(\s*!\s*note_raw_slice\([^;]*\)\s*\)\s*return;", body), body


def test_note_raw_slice_takes_no_lock_of_its_own():
    """std::mutex is not recursive: the caller holds it."""
    assert "lock_guard" not in _code(_body("note_raw_slice"))


def test_a_witnessed_session_takes_no_later_slice():
    note = _code(_body("note_raw_slice"))
    assert re.search(r"if\s*\(\s*raw_session\.witnessed\s*\)\s*return false;", note), note

    wit = _code(_body("witness_raw_abort"))
    # The decision and the mark are one critical section with the snapshot:
    # everything up to the lock scope's close brace.
    start = wit.index("std::lock_guard<std::mutex> lk(raw_session_mutex)")
    scope = wit[start:wit.index("\n    }\n", start)]
    assert "s = raw_session;" in scope
    assert "raw_session.witnessed = true;" in scope
    assert "s.witnessed" in scope, "a session is witnessed at most once"


def test_the_header_declares_the_override_and_the_flag():
    h = HDR.read_text()
    assert "virtual void handle_rx_packet(std::shared_ptr<kis_packet> packet) override;" in h
    assert "bool witnessed = false;" in h
    assert "bool note_raw_slice(const uint8_t *content, size_t content_sz);" in h
