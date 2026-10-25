# SPDX-License-Identifier: Apache-2.0
"""``local->name`` must be assigned before anything formats it.

## The hazard

``capture_cell_at.c``'s transcript-open block passes ``local->name`` to a
``%s`` in all four of its messages. If the block runs before
``local->name = strdup(hw_desc)``, the operator sees::

    (null) AT transcript (auto) to /tmp/kismet_cellat_351234567890123.log

## Why this is a bug and not a cosmetic wart

1. **It is undefined behavior.** glibc renders ``NULL`` for ``%s`` as
   ``(null)`` as a courtesy; C does not require it and other libcs segfault.
   This tree builds on more than glibc.
2. **The name is the only per-source discriminator in the log.** Two cellat
   sources produce two identical ``(null) AT transcript (auto) to …`` lines,
   separable only by an IMEI buried in a path.
3. **It is on the debug path.** The auto branch is ``local->debug &&
   transcript_fd < 0``, which every ``debug=true`` source with no
   ``transcript=`` takes.

## Why the block sits below the assignment instead of using a ``? :`` fallback

A ternary makes the line safe while leaving it permanently less useful than
every message around it: the name would read ``unknown`` forever. Placing the
block below the assignment fixes all four sites at once and keeps the messages
as informative as their neighbours.

That placement is safe because no ``at_command_t()`` call sits between the
assignment and the block (the last before is ``ATE0``; the next after is
``AT+CPIN?``). So the transcript still opens before any AT I/O it could have
logged.

## Why the structural test reads the source

A run-based fixture reaches only the auto branch, but the explicit
``transcript=`` branch formats ``local->name`` twice more (success and
open-failure). The structural test below reads the source instead of trusting
what one run reaches.
"""
from __future__ import annotations

import pytest

import cell_binaries
from fake_at_modem import QENG_SERVING, FakeAtModem
from kismet_capture_ipc import CaptureRun

#: Same synthetic 15-digit IMEI the sibling modules use: cellat validates the
#: shape before touching a port, and ``atport=`` names the port outright so no
#: scan ever reaches the operator's live modems.
IMEI = "351234567890123"

#: The auto-transcript line's stable fragment. Substring-matched so the
#: assertions survive the format string gaining a field.
AUTO_LINE = "AT transcript (auto) to"


def _binary_or_skip() -> str:
    found = cell_binaries.discover("cellat")
    if not found.ok:
        pytest.skip(found.skip_reason())
    return str(found.path)


def _cellat_source_or_skip() -> str:
    clone = cell_binaries.tree_root()
    if clone is None:
        pytest.skip("KP_ROOT does not point at a source tree")
    return (clone / "capture_cell_at/capture_cell_at.c").read_text()


@pytest.fixture(scope="module")
def debug_run() -> CaptureRun:
    """One offline cellat run with ``debug=true``, stopped at the target line.

    ``debug=true`` with no ``transcript=`` is the path that reaches the auto
    branch (debug defaults off). The run is stopped as soon as the auto-transcript
    line lands — cellat surveys forever, so an unconditional stop would burn the
    full timeout for a message emitted during open.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware="RM520NGLAAR03A03M4G",
                     manufacturer="Quectel", extra=QENG_SERVING) as modem:

        def stop_when(run: CaptureRun) -> bool:
            return any(AUTO_LINE in m for m in run.messages)

        run = _Run(binary, f"cellat-{IMEI}:atport={modem.port},debug=true",
                   timeout=25.0, stop_when=stop_when).run()
    return run


class _Run(CaptureRun):
    """One offline cellat run. Empty for the same reason ``_Run`` is elsewhere."""


def test_the_auto_transcript_line_is_actually_emitted(debug_run):
    """Premise guard.

    If the fixture never reached the auto branch, every assertion below would
    pass vacuously against a binary with the bug fully intact — the trap that
    makes 'no ``(null)`` in the output' a dangerously cheap assertion.
    """
    hits = [m for m in debug_run.messages if AUTO_LINE in m]
    assert hits, (
        "the auto-transcript INFO line never arrived, so the branch carrying "
        f"the name-before-use hazard was not exercised. "
        f"messages={debug_run.messages!r}")


def test_the_auto_transcript_line_is_not_prefixed_with_null(debug_run):
    """The anchor: no ``(null)`` prefix, as glibc renders a NULL ``%s``."""
    hits = [m for m in debug_run.messages if AUTO_LINE in m]
    offenders = [m for m in hits if "(null)" in m]
    assert not offenders, (
        "the auto-transcript line formatted a NULL local->name -- undefined "
        f"behavior, rendered by glibc as '(null)'. lines={offenders!r}")


def test_the_auto_transcript_line_carries_the_source_name(debug_run):
    """Not merely non-NULL: the name must be the real one.

    A ``? :`` fallback would satisfy the anchor above while printing a constant
    placeholder forever. ``local->name`` is ``"<model> IMEI:<imei>"``, so the
    IMEI is present exactly when the genuine name was used.
    """
    hits = [m for m in debug_run.messages if AUTO_LINE in m]
    assert any(f"IMEI:{IMEI}" in m for m in hits), (
        "the line is non-NULL but does not carry local->name's "
        f"'<model> IMEI:<imei>' shape -- a placeholder fallback would look like "
        f"this and leave the message permanently uninformative. lines={hits!r}")


#: The assignment, verbatim. ``open_callback`` contains it twice; see the
#: guard below.
ASSIGN = "local->name = strdup(hw_desc);"


def test_no_message_in_the_open_path_formats_name_before_it_is_assigned():
    """No ``local->name`` use precedes its assignment, across all four sites.

    The run-based tests above reach only the auto branch. This reads the
    source instead: on ``open_callback``'s live path, no ``local->name`` may
    appear before ``local->name = strdup(hw_desc)``.

    Scoped to ``open_callback`` deliberately. ``local->name`` is used freely
    throughout ``capture_thread``, where it is long since assigned; asserting
    over the whole file would be permanently red for no reason.

    **Why this counts the assignments instead of just finding one.**
    ``open_callback`` assigns ``local->name`` twice: once in the
    ``enabled=false`` branch, which assigns and then ``return 1``s immediately,
    and once on the live path much later. A bare ``find()`` anchors on the
    first, shrinking the guarded region to the lines before the disabled
    branch, where nothing uses the name at all, and the test passes vacuously.

    So the region is built from the real control flow (after the disabled
    branch returns, up to the live assignment) and the count is pinned. If a
    third assignment appears, this fails loudly and demands a rethink rather
    than silently re-narrowing itself to nothing.
    """
    src = _cellat_source_or_skip()
    body = src[src.index("int open_callback("):]
    body = body[:body.index("void capture_thread(kis_capture_handler_t *caph) {")]

    sites = []
    at = body.find(ASSIGN)
    while at != -1:
        sites.append(at)
        at = body.find(ASSIGN, at + 1)

    assert len(sites) == 2, (
        f"expected exactly 2 '{ASSIGN}' sites in open_callback (the "
        f"enabled=false early return, and the live path); found {len(sites)}. "
        "The region this guard checks is derived from that shape -- update it "
        "deliberately rather than letting it narrow itself into a vacuous "
        "pass.")

    disabled_assign, live_assign = sites

    # The disabled branch assigns and returns; the live path starts after it.
    ret = body.find("return 1;", disabled_assign)
    assert -1 < ret < live_assign, (
        "the enabled=false branch no longer returns between its own "
        "local->name assignment and the live one, so 'the live path' cannot be "
        "delimited this way any more")

    before = body[ret:live_assign]
    assert "local->name" not in before, (
        "open_callback formats or reads local->name on the live path BEFORE "
        "it is assigned -- that is a NULL passed to %s, i.e. undefined "
        "behavior, not a cosmetic '(null)'. Move the emission below "
        "the strdup rather than adding a ternary fallback: the fallback "
        "prints a useless constant forever.")


def test_the_transcript_block_still_precedes_the_first_at_command():
    """The block's placement must not cost the transcript any AT I/O.

    Placing the block below ``local->name`` is only safe while no AT command
    sits between the assignment and the block. The last one before is ``ATE0``
    and the first one after is ``AT+CPIN?``. If someone inserts an
    ``at_command_t()`` above the transcript block, its dialogue silently stops
    being logged -- a regression that produces no error, just a shorter file.
    """
    src = _cellat_source_or_skip()
    body = src[src.index("int open_callback("):]
    body = body[:body.index("void capture_thread(kis_capture_handler_t *caph) {")]

    block = body.find('"transcript", definition')
    assert block != -1, "the transcript-open block moved or was renamed"

    after = body[block:]
    assert "at_command_t(" in after, (
        "no AT command follows the transcript block at all -- either the block "
        "drifted to the end of open_callback or the startup queries moved "
        "above it. Either way the transcript now logs nothing from open.")
