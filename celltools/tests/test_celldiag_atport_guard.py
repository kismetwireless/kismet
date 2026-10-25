# SPDX-License-Identifier: Apache-2.0
"""celldiag ``atport=`` guard — refuse a non-AT wwan/MHI node.

``atport=`` names the AT-identify node explicitly so celldiag
can bring up an MHI/wwan modem the ttyUSB IMEI scan cannot glob (a PCIe
RM520N-GL: AT on ``/dev/mhi_DUN``, DIAG on ``/dev/mhi_DIAG``). The hazard the
guard closes: a mistyped ``atport=/dev/mhi_DIAG`` (or ``mhi_SAHARA`` / ``mhi_QDSS``)
would make celldiag write ``ATI`` into the DIAG / EDL / trace channel. The guard
runs in ``open_callback`` as a pure ``diag_wwanport`` classification, before any
port is opened or any AT scan runs, so this test needs no modem: a rejected
open comes back as ``open_code == 0`` with the refusal message, and that is the
whole assertion.

Unlike ``test_celldiag_error_delivery``'s bogus-IMEI hazard, these definitions
are safe by construction: the guard fires on the string classification of the
atport node before the bring-up touches hardware, so nothing is probed.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kismet_capture_ipc import CaptureRun  # noqa: E402

import cell_binaries  # noqa: E402

IMEI = "123456789012345"


def _binary_or_skip() -> str:
    found = cell_binaries.discover("celldiag")
    if not found.ok:
        pytest.skip(found.skip_reason())
    return str(found.path)


def _opened(run: CaptureRun) -> bool:
    return run.open_code is not None


# The nodes a wrong atport= would land on: the DIAG monitor itself, the EDL /
# firehose channel, and the QDSS trace channel. diag_wwan_is_at() returns 0 for
# each (they are recognized wwan/MHI nodes but not the AT surface), so the guard
# must refuse all three. mhi_DUN / wwan0at0 are the AT surface and are NOT here.
@pytest.mark.parametrize("bad_atport", [
    "/dev/mhi_DIAG",
    "/dev/mhi_SAHARA",
    "/dev/mhi_QDSS",
    "/dev/wwan0qcdm0",
])
def test_atport_on_a_non_at_wwan_node_is_refused_at_open(bad_atport):
    binary = _binary_or_skip()
    definition = f"celldiag-{IMEI}:atport={bad_atport},diagport=/dev/mhi_DIAG"
    run = CaptureRun(binary, definition, timeout=15, stop_when=_opened).run()

    assert run.open_code == 0, (
        f"atport={bad_atport} is not an AT surface and must be REFUSED at open; "
        f"got open_code={run.open_code} message={run.open_message!r}"
    )
    blob = f"{run.open_message or ''} {' '.join(run.messages)} {' '.join(run.errors)}"
    assert "AT surface" in blob or "AT/DUN" in blob, (
        f"the refusal must name WHY (not the AT surface / pass the AT/DUN node); "
        f"got {blob!r}"
    )


def test_the_guard_names_the_node_function():
    """The refusal tells the operator what the mistyped node actually is, so
    ``atport=/dev/mhi_DIAG`` is diagnosable as 'that is the DIAG node'."""
    binary = _binary_or_skip()
    definition = f"celldiag-{IMEI}:atport=/dev/mhi_DIAG,diagport=/dev/mhi_DIAG"
    run = CaptureRun(binary, definition, timeout=15, stop_when=_opened).run()
    assert run.open_code == 0
    blob = f"{run.open_message or ''} {' '.join(run.messages)} {' '.join(run.errors)}"
    assert "diag" in blob.lower(), (
        f"the message should name the node's function (diag); got {blob!r}"
    )
