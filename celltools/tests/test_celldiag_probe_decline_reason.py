"""An operator typing `-c celldiag` sees the helper's reason.

`capture_cell_diag` writes a specific decline message for a near-miss
definition -- "'celldiag' is not a celldiag interface - expected
celldiag-<15-digit IMEI> (the IMEI selects WHICH modem; a bare 'celldiag'
cannot)". The server's `complete_probe` surfaces that reason after the generic
"Unable to find driver ... make sure that any required plugins are loaded",
which alone reads the same for a typo, a missing helper package and an
unplugged radio.

This file runs the real server binary, without `--silent`, and asserts the
helper's text reaches the log; the decision logic itself is also pinned by a
header-only unit test that runs no server.

`silent=False` is required: `--silent` suppresses every message after startup,
so with the default harness settings an assertion that the reason is present
fails for the wrong reason and an assertion that it is absent passes vacuously.

The negative control is the more important half. The surfaced reason is scoped
by ownership -- the definition's interface must begin with the declining
driver's source type on a non-alphanumeric boundary -- because Kismet probes
every definition against every builder, and stock helpers write a reason for
any foreign definition (`capture_linux_wifi.c`, `capture_framework.c`). Without
that scoping, one mistyped `-c` would earn a paragraph from every helper on the
system. `test_a_foreign_definition_gains_no_chatter` pins that.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_celldiag_server_routes import (  # noqa: E402
    KismetServer,
    _server_or_skip,
)

#: The generic sentence stock Kismet emits when no builder claims a definition.
GENERIC = "Unable to find driver"

#: The prefix `datasourcetracker.cc` adds when a near-miss driver explained why.
CARRIER = "The closest matching driver said:"

#: A distinctive fragment of the celldiag helper's own text. Deliberately not
#: the whole sentence -- pinning every byte would make a wording tweak look
#: like a regression, while this fragment is the actual information the
#: operator was missing (that the IMEI is what selects the modem).
HELPER_TEXT = "a bare 'celldiag' cannot"

#: Probe completion is asynchronous; the messages arrive after HTTP is up.
DEADLINE = 45


def _await_log(srv: KismetServer, needle: str, deadline: int = DEADLINE) -> str:
    """Wait for `needle` in the server log; return the log either way."""
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        log = srv.logpath.read_text(errors="replace")
        if needle in log:
            return log
        time.sleep(0.5)
    return srv.logpath.read_text(errors="replace")


@pytest.fixture()
def declining_server(tmp_path: Path):
    """A server handed the bare `celldiag` definition (no IMEI)."""
    _server_or_skip()
    with KismetServer(tmp_path, "celldiag", silent=False) as srv:
        yield srv


def test_the_operator_sees_the_helpers_reason(declining_server):
    """The generic sentence, the carrier prefix and the helper's own text all
    reach the log."""
    log = _await_log(declining_server, HELPER_TEXT)

    assert GENERIC in log, (
        "the generic sentence never appeared -- the probe path did not "
        f"complete, so this test proves nothing about the reason:\n{log[-3000:]}")
    assert CARRIER in log, (
        f"the reason was still discarded by the server:\n{log[-3000:]}")
    assert HELPER_TEXT in log, (
        f"the carrier fired but the helper's own text is missing:\n{log[-3000:]}")


def test_a_foreign_definition_gains_no_chatter(tmp_path: Path):
    """The ownership rule, at the server level rather than in a unit test.

    `notacellsource0` is claimed by no builder, so the operator must get the
    generic sentence and nothing else. If this fails, every typo becomes a
    wall of text from every helper on the system.
    """
    _server_or_skip()
    with KismetServer(tmp_path, "notacellsource0", silent=False) as srv:
        log = _await_log(srv, GENERIC)

    assert GENERIC in log, f"no driver claimed it, so this must fire:\n{log[-3000:]}"
    assert CARRIER not in log, (
        f"a foreign definition earned per-binary chatter:\n{log[-3000:]}")
    assert HELPER_TEXT not in log, (
        f"the celldiag helper spoke about a definition that is not its:\n{log[-3000:]}")
