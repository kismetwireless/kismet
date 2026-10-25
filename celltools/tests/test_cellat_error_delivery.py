# SPDX-License-Identifier: Apache-2.0
"""Post-open error reporting for ``kismet_cap_cell_at``.

## The server behaviour this works around

``cf_send_error()`` is silently discarded by the Kismet server under protocol
v3. There is no ``case KIS_EXTERNAL_V3_CMD_ERROR`` in either dispatcher:
``kis_external_interface::dispatch_rx_packet_v3`` handles MESSAGE / PING / PONG /
SHUTDOWN plus the WEB and EVT families and falls through to
``kis_datasource::dispatch_rx_packet_v3``, which handles the KDS reports and no
ERROR either. Both return ``false`` and the frame is dropped. From
``kis_datasource.cc:1084``::

    // v3 drops explicit error/warning reports and rolls them into the return
    // codes of the packet headers itself.  The error message is sent as a
    // message prior to the packet being sent.

``capture_cell_diag`` and ``capture_cell_at`` both have post-open error sites
that must not rely on that frame alone. This module covers the cellat side.

## Why the symptom is worse here than in celldiag

celldiag replays a file and exits, so a lost reason still ends the run. cellat
surveys forever: all four sites are inside the poll loop and ``goto done``,
where the source spins down and Kismet re-opens it 5 s later. Without a
delivered reason the operator gets an unbounded ladder of ``IPC connection
closed`` / ``SOURCEERROR ... (N failures)`` with the cause discarded on every
iteration.

## Why this unplugs a fake modem rather than using a bogus IMEI

Do not reproduce this by pointing cellat at an IMEI that matches nothing:
resolving an IMEI runs an AT scan across every serial port on the host, which
on a workstation with modems attached opens live modems and writes AT commands
to them. ``test_cellat_ipc`` documents that hazard.

The celldiag trigger does not carry over either: ``replay=<missing file>``
works there because DIAG is a byte stream and the open is answered before the
file is touched. AT is a dialogue, and every cheap failure ``FakeAtModem`` can
script (wrong IMEI, empty ``+CGMR``, ``silent=True``) is rejected inside
``open_callback``. Open-path errors ride the open report's return code, which
the server does deliver, so a test built on one would pass without the fix and
prove nothing.

``FakeAtModem.unplug()`` is the trigger that works: let the open succeed, then
close the pty master so the next serial read fails. That reaches
``capture_thread``'s error sites with no hardware, and it models the real
failure: a modem that enumerates, identifies, then drops off the bus
mid-survey.
"""
from __future__ import annotations

import pytest

import cell_binaries
from fake_at_modem import QENG_SERVING, FakeAtModem
from kismet_capture_ipc import CaptureRun

#: MSGFLAG_ERROR / MSGFLAG_INFO, from kis_external_packet.h. The point of the fix
#: is not just that the text arrives but that it arrives flagged as an error, so
#: the server renders it as ERROR rather than burying it among INFO status lines.
MSGFLAG_ERROR = 4
MSGFLAG_INFO = 2

#: A 15-digit synthetic IMEI. cellat validates the shape before it touches a
#: port, so an arbitrary string would fail for the wrong reason. Never resolved:
#: ``atport=`` names the port outright, which is what keeps the scan off the
#: operator's live modems.
IMEI = "351234567890123"

#: The reason text site 2 composes. Matched as a substring so the assertions
#: survive the surrounding format string gaining a field.
SERIAL_ERROR = "serial error on serving cell query"


def _binary_or_skip() -> str:
    found = cell_binaries.discover("cellat")
    if not found.ok:
        pytest.skip(found.skip_reason())
    return str(found.path)


class _Run(CaptureRun):
    """One offline cellat run. Empty for the same reason ``CellAtRun`` is."""


@pytest.fixture(scope="module")
def unplugged_run() -> CaptureRun:
    """Open against a fake modem, then yank its wire mid-survey.

    ``stop_when`` does double duty: it performs the unplug once the open has
    been answered (so the failure is provably post-open), then ends the run as
    soon as the reason lands — cellat surveys forever, so without a stop
    condition every test here would burn the full timeout.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware="RM520NGLAAR03A03M4G",
                     manufacturer="Quectel", extra=QENG_SERVING) as modem:
        state = {"unplugged": False}

        def stop_when(run: CaptureRun) -> bool:
            if run.open_code is not None and not state["unplugged"]:
                state["unplugged"] = True
                modem.unplug()
                return False
            return any(SERIAL_ERROR in m for m in run.messages) or \
                any(SERIAL_ERROR in e for e in run.errors)

        run = _Run(binary, f"cellat-{IMEI}:atport={modem.port}",
                   timeout=25.0, stop_when=stop_when).run()
    return run


def test_the_failure_is_post_open_not_an_open_rejection(unplugged_run):
    """Premise guard: the open SUCCEEDED, so this is the silent class.

    If the open were rejected instead, the reason would ride the OPENREPORT and
    the rest of this module would be testing a path that already works (see
    the module docstring on picking a cellat trigger).
    """
    assert unplugged_run.open_code == 1, (
        f"expected the open to be answered OK; got "
        f"code={unplugged_run.open_code} "
        f"message={unplugged_run.open_message!r}")


def test_post_open_failure_reason_is_delivered_as_a_message(unplugged_run):
    """The anchor: the failure reason, not just status lines, reaches MESSAGE."""
    hits = [m for m in unplugged_run.messages if SERIAL_ERROR in m]
    assert hits, (
        "the post-open failure reason never reached the MESSAGE channel -- the "
        "operator sees only 'IPC connection closed', once every 5 s, forever. "
        f"messages={unplugged_run.messages!r}")


def test_the_reason_is_flagged_as_an_error_not_info(unplugged_run):
    """Arriving as INFO would bury it between two status lines."""
    flags = [f for m, f in zip(unplugged_run.messages,
                               unplugged_run.message_flags)
             if SERIAL_ERROR in m]
    assert flags, "reason not present at all; see the anchor test"
    assert MSGFLAG_ERROR in flags, (
        f"reason arrived with flags {flags}, expected MSGFLAG_ERROR "
        f"({MSGFLAG_ERROR}); INFO is {MSGFLAG_INFO}")


def test_the_error_frame_is_still_emitted(unplugged_run):
    """``cf_send_error`` is kept, not replaced.

    It is the protocol-correct frame, it is what a v2 peer consumes, and it is
    what puts the source into the error state that drives Kismet's re-open. The
    message is sent in addition; a refactor that drops the error frame in favour of the
    message would be a different behaviour change and should fail here first.
    """
    assert any(SERIAL_ERROR in e for e in unplugged_run.errors), (
        "the ERROR frame is gone -- cellat_report_error must send BOTH. "
        f"errors={unplugged_run.errors!r}")


def test_every_post_open_error_site_routes_through_the_primitive():
    """No post-open site may call ``cf_send_error()`` directly.

    Four call sites are four chances for a fifth to be added as a bare
    ``cf_send_error()`` — which compiles, reads correctly, and is discarded at
    runtime. Read the source rather than trusting the one site the fixture
    happens to reach: the fixture proves the mechanism works, this proves nobody
    bypassed it.

    ``capture_thread`` is the post-open boundary. Before it, a bare
    ``cf_send_error`` would be an OPEN-path error, which must NOT be routed
    through the primitive (it would double-report against the open report's
    return code) -- so the assertion is deliberately scoped to the capture
    thread rather than the whole file.
    """
    src = _cellat_source_or_skip()
    body = src[src.index("void capture_thread(kis_capture_handler_t *caph) {"):]
    assert "cellat_report_error(caph" in body, "the primitive is not used at all"
    assert "cf_send_error(" not in body, (
        "a post-open site in capture_thread calls cf_send_error() directly; "
        "under v3 the server DISCARDS that frame, so the reason never reaches "
        "the operator. Use cellat_report_error().")


def test_open_path_errors_do_not_use_the_message_channel():
    """The asymmetry, asserted rather than described.

    Errors raised from the open path ride out on the open report's return code
    -- the idiom ``kis_datasource.cc:1084`` prescribes -- and are already
    legible. Converting them would double-report the same failure. cellat has no
    ``cf_send_error`` in its open path today; this pins that it stays that way,
    so a well-meaning sweep of "all four helpers" does not over-apply the fix.
    """
    src = _cellat_source_or_skip()
    head = src[:src.index("void capture_thread(kis_capture_handler_t *caph) {")]
    # The primitive's own definition and its comment live here; strip the one
    # real call (inside cellat_report_error) before asserting on the rest.
    head = head.replace("cf_send_error(caph, 0, msg);", "")
    assert "cf_send_error(caph" not in head, (
        "the open path gained a cf_send_error() -- open errors belong on the "
        "open report's return code, not the error frame")
    assert "cellat_report_error(caph" not in head, (
        "an open-path error was routed through cellat_report_error(), which "
        "double-reports against the open report")


def _cellat_source_or_skip() -> str:
    clone = cell_binaries.tree_root()
    if clone is None:
        pytest.skip("KP_ROOT does not point at a source tree")
    return (clone / "capture_cell_at/capture_cell_at.c").read_text()
