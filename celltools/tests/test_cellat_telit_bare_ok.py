# SPDX-License-Identifier: Apache-2.0
"""cellat opens an unregistered Telit whose survey commands answer bare OK.

## The hazard

A Telit LM960A18 with **no serving cell** (garage, basement, antenna not yet
connected) answers ``AT#RFSTS`` / ``AT#SERVINFO`` / ``AT#MONI`` with a bare
``OK`` — the command is supported, there is simply nothing to report. If the
Telit branch of ``open_callback`` set ``has_rfsts`` only when the response
contained ``#RFSTS:``, a bare ``OK`` would count as *refused*, and with every
other Telit probe also empty the open would be refused outright with

    Modem on … does not support any known cell survey command.

A drive that **starts** without signal would then never get its Telit source,
and — because every reopen repeats the same probe — the source would never
retry into success once the modem registered (no source, no ``ClockAnchor``).

## The rule

A final ``OK`` (no ``ERROR`` / ``+CME ERROR``) from a Telit survey command
means SUPPORTED-BUT-EMPTY: the capability is set and the poll loop finds cells
once the modem registers. A real ``ERROR`` is still refused. The refusal
message names the commands the detected vendor actually probed, not the generic
auto-detect list (``AT+QENG="servingcell", AT!GSTATUS?, …``), which a Telit is
never sent.

## Scope

This is the offline half. It verifies the OPEN DECISION — the source opens
instead of being refused, and the refusal message (when a modem truly supports
nothing) names the right commands. It does NOT verify cell decode; the fake
modem carries no cell state (see ``fake_at_modem``), so that needs a real
modem.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import cell_binaries
from fake_at_modem import FakeAtModem
from kismet_capture_ipc import CaptureRun

#: 15-digit synthetic IMEI. cellat validates the shape before it touches a port,
#: and ``atport=`` names the port outright, so the scan never reaches the
#: operator's live modems (the hazard the IPC harness documents).
IMEI = "351234567890123"

#: The commands the Telit branch of ``capture_cell_at.c`` sends at probe time,
#: each answered with a BARE ``OK`` (an empty body -> ``fake_at_modem`` appends
#: ``OK``). This is the unregistered-modem shape of the LM960A18:
#: ``#RFSTS``/``#SERVINFO``/``#MONI`` all return a bare ``OK``. ``AT+CGMM``
#: carries the model so the branch names the modem rather than "Telit ERROR".
TELIT_BARE_OK = {
    "AT#RFSTS": "",
    "AT#SERVINFO": "",
    "AT#MONI=0": "",
    "AT#MONI": "",
    "AT#CSURVC=?": "",
    "AT+CGMM": "LM960A18",
}


def _binary_or_skip() -> str:
    """The compiled ``kismet_cap_cell_at`` — absent SKIPS, stale FAILS.

    Same contract as ``test_cellat_ipc`` / the celldiag harness: a stale binary
    that happens to still agree would report green while testing code nobody has
    shipped.
    """
    found = cell_binaries.discover("cellat")
    if not found.ok:
        pytest.skip(found.skip_reason())
    binary = Path(found.path)
    deps = cell_binaries.link_dependencies(binary)
    try:
        bin_mtime = binary.stat().st_mtime
    except OSError:  # pragma: no cover
        return str(binary)
    newer = sorted(p.name for p in deps.sources
                   if p.exists() and p.stat().st_mtime > bin_mtime)
    if newer:
        shown = ", ".join(newer[:6]) + (f" +{len(newer) - 6} more"
                                        if len(newer) > 6 else "")
        pytest.fail(
            f"cellat binary is STALE: {binary} is older than its sources "
            f"({shown}). Rebuild: (cd {binary.parent.parent} && "
            f"make {binary.parent.name}/{binary.name})")
    return str(binary)


@pytest.fixture(scope="module")
def unregistered_telit():
    """Open cellat against a Telit answering bare ``OK`` to every survey command.

    Returns ``(run, commands)`` — the completed run plus the exact command list
    the modem received, snapshotted before the pty tears down. cellat surveys
    forever once open, so ``stop_when`` ends the run as soon as the OPENREPORT
    lands (either way).
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware="32.01.110",
                     manufacturer="Telit", extra=TELIT_BARE_OK) as modem:
        run = CaptureRun(binary, f"cellat-{IMEI}:atport={modem.port}",
                         timeout=25.0,
                         stop_when=lambda r: r.open_code is not None).run()
        commands = list(modem.commands)
    return run, commands


def test_the_telit_branch_actually_ran(unregistered_telit):
    """Premise guard: the vendor was detected as Telit and its probes were sent.

    Without this, a run that opened for some unrelated reason (or never reached
    the Telit branch) could pass the anchor below vacuously.
    """
    _run, commands = unregistered_telit
    assert "AT#RFSTS" in commands, (
        f"the Telit survey probe never went out; commands={commands!r}")


def test_unregistered_telit_bare_ok_opens_the_source(unregistered_telit):
    """The anchor. A bare ``OK`` from ``AT#RFSTS`` means *supported,
    currently empty* — the open must SUCCEED, not be refused.

    If the Telit branch required ``#RFSTS:`` in the response, a bare ``OK``
    would leave every capability unset and the open would be refused
    (``open_code == 0``, message "does not support any known cell survey
    command").
    """
    run, _commands = unregistered_telit
    assert run.open_code == 1, (
        f"an unregistered Telit answering bare OK should OPEN (supported, "
        f"empty); got code={run.open_code} message={run.open_message!r}")


def test_the_open_was_not_refused_as_no_known_command(unregistered_telit):
    """The specific refusal must be gone — a bare OK is not "no known command"."""
    run, _commands = unregistered_telit
    assert not (run.open_message and
                "does not support any known" in run.open_message), (
        f"still refused as unsupported: {run.open_message!r}")


def test_refusal_message_names_the_telit_commands_not_the_generic_list():
    """The message half. A Telit that truly
    supports nothing (every survey command ``ERROR``) must be refused with a
    message naming the commands the Telit branch actually SENT
    (``AT#RFSTS``/``AT#SERVINFO``/``AT#MONI``/``AT#CSURVC``), not the generic
    auto-detect list (``AT+QENG``/``AT!GSTATUS?``/``AT+CPSI?``/…) it was never
    sent — an operator reading that would audit the wrong commands.
    """
    binary = _binary_or_skip()
    # A Telit whose survey commands all ERROR (unknown_response default) — the
    # genuine no-support case where the refusal message is what an operator reads.
    with FakeAtModem(imei=IMEI, firmware="32.01.110", manufacturer="Telit",
                     extra={"AT+CGMM": "LM960A18"}) as modem:
        run = CaptureRun(binary, f"cellat-{IMEI}:atport={modem.port}",
                         timeout=25.0,
                         stop_when=lambda r: r.open_code is not None).run()
    assert run.open_code == 0, (
        f"a Telit that ERRORs every survey command must be refused; "
        f"got code={run.open_code} message={run.open_message!r}")
    msg = run.open_message or ""
    assert "#RFSTS" in msg, (
        f"refusal message should name the Telit commands actually probed; "
        f"got {msg!r}")
    assert "QENG" not in msg, (
        f"refusal message names generic auto-detect commands the Telit branch "
        f"never sent: {msg!r}")
