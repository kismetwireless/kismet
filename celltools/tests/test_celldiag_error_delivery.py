# SPDX-License-Identifier: Apache-2.0
"""Post-open error reporting for ``kismet_cap_cell_diag``.

## The hazard

Without a delivered reason, a celldiag source whose bring-up fails tells the
operator only this::

    INFO:  Cell DIAG source celldiag-<imei> accepted; opening modem in the background
    INFO:  celldiag stats: NODATA | port=closed bytes=0 | obs=0 | decoder=stopped
    ERROR: Data source '...' encountered an error: IPC connection closed
    ALERT: SOURCEERROR ... will attempt to re-open the source in 5 seconds. (1 failures)

...forever, once per 5 s. ``IPC connection closed`` reads like a modem or a
port problem, even when the helper has composed a precise, actionable sentence
(for example, naming the replay file it cannot open).

## Why: ``cf_send_error()`` is discarded under protocol v3

``cf_send_error()`` serialises a ``KIS_EXTERNAL_V3_CMD_ERROR`` frame, and **no
server dispatcher handles that command.**
``kis_external_interface::dispatch_rx_packet_v3`` has cases for MESSAGE / PING /
PONG / SHUTDOWN / the WEB and EVT families and falls through to
``kis_datasource::dispatch_rx_packet_v3``, which has cases for the KDS reports
and no ERROR either. Both return false and the frame is dropped. From
``kis_datasource.cc``::

    // v3 drops explicit error/warning reports and rolls them into the return
    // codes of the packet headers itself.  The error message is sent as a
    // message prior to the packet being sent.

So ``diag_report_error()`` also says it as a MESSAGE (which the server does
handle) carrying ``MSGFLAG_ERROR``.

## Why only *post-open* failures are affected

An error raised from ``open_callback`` rides out on the OPENREPORT's return code
and message -- the idiom the comment above describes -- and is always legible.
Only failures raised *after* the open was answered need the MESSAGE route:
deferred bring-up and replay/rawlog open. The premise guard below asserts that
the trigger used here really is post-open.

## Why this drives a replay source and not a bogus IMEI

The obvious reproduction -- point celldiag at an IMEI that matches nothing -- is
**not safe here** and must not be reintroduced. Resolving an IMEI runs an AT
scan across every serial port on the host, which on a wardriving workstation
means opening the operator's live modems and writing AT commands to them, from a
suite whose whole premise is that it needs no hardware. ``test_cellat_ipc``
documents the same hazard and the large slowdown that comes with it.

``replay=<missing file>`` reaches the identical code path -- ``capture_thread``,
after the open was answered, reporting through ``diag_report_error()`` -- while
opening no modem and scanning no ports. The failure mode under test is the
*delivery mechanism*, which is common to every post-open error, so the cheapest
and safest trigger is the correct one to use.
"""

from __future__ import annotations

import os

import pytest

# conftest.py puts both this directory and celltools/ on sys.path, so these
# resolve identically under `pytest <file>`, `pytest celltools/tests` and
# `make -C celltools check`.
from celldiag_run import _binary_or_skip
from kismet_capture_ipc import CaptureRun

#: MSGFLAG_ERROR, from kis_external_packet.h. The point is not just
#: that the text arrives but that it arrives flagged as an error, so the server
#: renders it as ERROR rather than burying it among INFO status lines.
MSGFLAG_ERROR = 4
MSGFLAG_INFO = 2

#: Any well-formed IMEI. Never resolved -- ``replay=`` short-circuits the modem
#: lookup entirely, which is precisely why this test needs no hardware.
IMEI = "123456789012345"

MISSING_REPLAY = "/nonexistent/celldiag-error-delivery-probe.hdlc"


def _run_env() -> dict[str, str]:
    """An allow-listed environment: ``PATH`` and nothing else, so nothing
    ambient can steer the run."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}


def _run_with_failing_replay() -> CaptureRun:
    binary = _binary_or_skip()
    definition = f"celldiag-{IMEI}:replay={MISSING_REPLAY}"
    return CaptureRun(binary, definition, timeout=20, env=_run_env()).run()


@pytest.fixture(scope="module")
def failed_run() -> CaptureRun:
    return _run_with_failing_replay()


def test_the_failure_is_post_open_not_an_open_rejection(failed_run):
    """Premise guard: the open SUCCEEDED, so this is the silent class.

    If the open were rejected instead, the reason would ride the OPENREPORT and
    the rest of this module would be testing the open-time path instead.
    """
    assert failed_run.open_code == 1, (
        f"expected the open to be answered OK; got code={failed_run.open_code} "
        f"message={failed_run.open_message!r}")


def test_post_open_failure_reason_is_delivered_as_a_message(failed_run):
    """The anchor: the reason, not just the status lines, is in the messages."""
    hits = [m for m in failed_run.messages if "cannot open replay file" in m]
    assert hits, (
        "the post-open failure reason never reached the MESSAGE channel -- the "
        "operator sees only 'IPC connection closed'. messages="
        f"{failed_run.messages!r}")


def test_the_reason_is_flagged_as_an_error_not_info(failed_run):
    """Arriving as INFO would bury it between two status lines."""
    flags = [f for m, f in zip(failed_run.messages, failed_run.message_flags)
             if "cannot open replay file" in m]
    assert flags, "reason not present at all; see the anchor test"
    assert MSGFLAG_ERROR in flags, (
        f"reason arrived with flags {flags}, expected MSGFLAG_ERROR "
        f"({MSGFLAG_ERROR}); INFO is {MSGFLAG_INFO}")


def test_the_error_frame_is_still_emitted(failed_run):
    """``cf_send_error`` is kept, not replaced.

    It is the protocol-correct frame, it is what a v2 peer consumes, and it is
    what drives the source error state. The message is added alongside it; a future
    refactor that drops the error frame in favour of the message would be a
    different behaviour change and should fail here first.
    """
    assert any("cannot open replay file" in e for e in failed_run.errors), (
        f"ERROR frame no longer emitted; errors={failed_run.errors!r}")
