# SPDX-License-Identifier: Apache-2.0
"""Offline IPC harness for the Kismet ``kismet_cap_cell_at`` capture binary.

The AT-side counterpart to ``test_celldiag_replay_ab.py``. Drives the compiled
capture binary end to end — real ``open_callback``, real ``identify_modem``, real
``serial_open``/``at_command`` out of ``at_serial.inc`` — against a
:class:`fake_at_modem.FakeAtModem` on a pseudo-terminal, with no modem and no
running Kismet server.

## What this covers

``atport=`` is an explicit AT-port override. Kismet accepts unknown source
options silently, so an option that is parsed but not honoured looks like it
works. The option scanner is unit-tested in ``test_cellat_options``; this file
tests the open path, where the behaviour that matters lives: an ``atport=``
pointing at the wrong modem must fail, not survey it.

## The two failure modes this is aimed at

1. **Surveying the wrong modem under the right IMEI.** Auto-detect's only safety
   property is that it matches on IMEI. An override that merely opened the named
   path would discard that, and every observation's ``prov.imei`` would name a
   modem that produced none of it.
   ``test_atport_refuses_a_modem_with_a_different_imei`` is the pin.
2. **Silence.** A capture source that emits nothing looks exactly like "no cells
   in range". Every test here asserts on what the modem actually received
   (``modem.commands``), not only on what the helper reported, so a run that
   reports success while opening some other port cannot pass.

Scope: this harness verifies dialogue and control flow. It does not verify
cell-report decode; the fake modem has no cell state (see ``fake_at_modem``).

## Every test here must pass ``atport=``

Without ``atport=``, ``open_callback`` falls through to ``find_port_by_imei()``,
which scans every serial port on the host. On a workstation with real modems
attached, a test that omits ``atport=`` opens live hardware and sends it AT
commands, and the suite slows from about a second to minutes.

The malformed-IMEI tests are the deliberate exception: cellat validates the
IMEI's shape before it touches any port, so those never reach the scan.

## Negative controls

Each mutation below, applied to the C source, should fail the listed tests. A
control that fails nothing means the test does not test what it claims:

===================================================  ================================
mutation                                             result
===================================================  ================================
``atport=`` IMEI ``strcmp`` deleted                   1 fails: the refusal test
``if (atport_override[0])`` → ``if (0)``              6 fail (and the suite crawls)
unknown-option callback never invoked                 1 fails: the warning test
``"atport"`` removed from the known-options list      1 fails: the control test
===================================================  ================================

The last two are opposite halves of one feature and fail different tests: a
warning nobody checks the negative of will eventually fire on options that
work, and then be ignored.
"""
from __future__ import annotations

import pytest

import cell_binaries
from fake_at_modem import QENG_SERVING, FakeAtModem
from kismet_capture_ipc import CaptureRun

from pathlib import Path

#: A 15-digit synthetic IMEI. cellat validates the shape (15 digits) before it
#: touches a port, so an arbitrary string would fail for the wrong reason.
IMEI = "351234567890123"
OTHER_IMEI = "359876543210987"



class CellAtRun(CaptureRun):
    """One offline run of ``kismet_cap_cell_at``.

    Deliberately empty: the driver in ``kismet_capture_ipc`` is not
    celldiag-specific. celldiag needs a subclass only because two streams share
    its observation relay; cellat's relay carries cell observations alone.
    """


def _binary_or_skip() -> str:
    """The compiled ``kismet_cap_cell_at``, discovered rather than demanded.

    Same contract as the celldiag harness: an absent binary SKIPS with a message
    naming which silence it is, a stale one fails. A stale binary that happens
    to still agree reports green while testing code that is no longer current,
    and skipping past that would recreate the silence this harness exists to
    break.
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
        shown = ", ".join(newer[:6]) + (f" +{len(newer) - 6} more" if len(newer) > 6 else "")
        pytest.fail(
            f"KP_CELLAT_BIN is STALE: {binary} is older than its sources "
            f"({shown}). [dependency set: {deps.mode} — {deps.note}] Rebuild: "
            f"({cell_binaries.staleness('cellat', binary).rebuild_cmd()})")
    return str(binary)


def _opened(run: CellAtRun) -> bool:
    """True once the binary has answered the OPENREQ, either way.

    cellat surveys **forever** once open succeeds, so — unlike a celldiag replay,
    which ends when the file does — every test here needs an explicit stop.
    """
    return run.open_code is not None


# ── the atport= open path ──────────────────────────────────────────────────────
def test_atport_opens_the_named_port_and_verifies_its_imei():
    """``atport=`` opens exactly the named port and confirms the IMEI on it.

    The positive leg. ``modem.commands`` is the assertion that matters: it proves
    the AT identification dialogue reached this port, which a silently ignored
    option could never do.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        run = CellAtRun(binary, f"cellat-{IMEI}:atport={modem.port}",
                        timeout=20.0, stop_when=_opened).run()

        assert run.open_code == 1, (
            f"atport= with a matching IMEI should open; got code {run.open_code} "
            f"message {run.open_message!r}")
        assert "AT+CGSN" in modem.commands, (
            "the helper never asked THIS port for its IMEI — the option was "
            f"reported as honoured but reached no port. Saw: "
            f"{modem.commands}")
        assert any("atport=" in m and "auto-detect skipped" in m
                   for m in run.messages), (
            f"no message announced the override; messages were {run.messages}")


def test_atport_refuses_a_modem_with_a_different_imei():
    """The safety property: a wrong-modem ``atport=`` fails, loudly.

    Auto-detect matches on IMEI; an override that just opened the path would
    discard that and survey the wrong modem while stamping the requested IMEI
    into every observation's ``prov`` block. Deleting the ``strcmp`` in
    ``capture_cell_at.c`` fails this test and no other.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=OTHER_IMEI) as modem:
        run = CellAtRun(binary, f"cellat-{IMEI}:atport={modem.port}",
                        timeout=20.0, stop_when=_opened).run()

        assert run.open_code == 0, (
            f"atport= pointing at IMEI {OTHER_IMEI} while the source asked for "
            f"{IMEI} MUST fail open; got code {run.open_code}")
        assert run.open_message and OTHER_IMEI in run.open_message and \
            IMEI in run.open_message, (
            "the refusal must name BOTH IMEIs — the operator's next move depends "
            f"on which modem is actually on that port. Got: {run.open_message!r}")
        assert run.observations == [], (
            f"a refused source relayed {len(run.observations)} observations")
        # It did identify the modem; it just refused to use it.
        assert "AT+CGSN" in modem.commands


def test_atport_pointing_at_a_port_that_does_not_answer_at_fails():
    """A DIAG or NMEA port is openable and never answers ``AT``.

    That is how a typo'd ``atport=`` fails in the field — not with ENOENT, but
    with a port that opens fine and says nothing. The helper must time out and
    reject rather than proceed with an empty identity.
    """
    binary = _binary_or_skip()
    with FakeAtModem(silent=True) as modem:
        run = CellAtRun(binary, f"cellat-{IMEI}:atport={modem.port}",
                        timeout=20.0, stop_when=_opened).run()

        assert run.open_code == 0, (
            f"a silent port must fail open; got code {run.open_code}")
        assert run.open_message and "did not respond" in run.open_message.lower(), (
            f"the failure must say the port did not answer AT: {run.open_message!r}")
        assert modem.commands, (
            "the helper never even sent AT to the port it was told to use")


def test_atport_pointing_at_a_nonexistent_path_fails():
    """An unopenable path fails at open, not later and not silently."""
    binary = _binary_or_skip()
    run = CellAtRun(binary, f"cellat-{IMEI}:atport=/dev/does-not-exist-cellat",
                    timeout=20.0, stop_when=_opened).run()
    assert run.open_code == 0, (
        f"a nonexistent atport= must fail open; got code {run.open_code}")
    assert run.open_message, "the failure carried no message at all"


def test_atport_reports_the_modem_it_actually_found():
    """The announcement names the port that was opened, not the one requested.

    They are the same string here — which is the point. When a future change
    makes them differ (a symlink resolve, a retry on a sibling port), this test
    is what notices, because the announcement is the operator's only window into
    which device the survey is actually reading.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware="EG25GGBR07A08M2G",
                     extra=QENG_SERVING) as modem:
        run = CellAtRun(binary, f"cellat-{IMEI}:atport={modem.port}",
                        timeout=20.0, stop_when=_opened).run()
        assert run.open_code == 1, run.open_message
        assert any(modem.port in m for m in run.messages), (
            f"no message names the opened port {modem.port}: {run.messages}")
        assert "AT+CGMR" in modem.commands


# ── the unknown-option warning ─────────────────────────────────────────────────
def test_an_unknown_source_option_is_named_on_the_message_bus():
    """Kismet ignores unknown options silently; cellat must not.

    An option that is accepted, has no effect, and reports success is worse
    than a missing feature, because nothing tells the operator.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI) as modem:
        run = CellAtRun(binary,
                        f"cellat-{IMEI}:atport={modem.port},notarealoption=7",
                        timeout=20.0, stop_when=_opened).run()
        assert any("notarealoption" in m for m in run.messages), (
            f"an unknown option was accepted in silence: {run.messages}")


def test_a_known_option_produces_no_unknown_option_warning():
    """The control that decides whether the warning stays trustworthy.

    A warning that fires for options which *do* work is the failure mode most
    likely to get the whole check ignored — and it is invisible unless something
    asserts the negative. ``atport=`` is parsed and honoured, so it must never be
    named as unknown.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI) as modem:
        run = CellAtRun(binary, f"cellat-{IMEI}:atport={modem.port}",
                        timeout=20.0, stop_when=_opened).run()
        offenders = [m for m in run.messages if "atport" in m and "nknown" in m]
        assert not offenders, (
            f"atport= is a real, honoured option and must not warn: {offenders}")


# ── definition validation, reached with no port at all ─────────────────────────
@pytest.mark.parametrize("bad", ["cellat-12345", "cellat-abcdefghijklmno"])
def test_a_malformed_imei_is_rejected_before_any_port_is_touched(bad):
    """A bad IMEI fails on shape, before the helper scans or opens anything."""
    binary = _binary_or_skip()
    run = CellAtRun(binary, bad, timeout=20.0, stop_when=_opened).run()
    assert run.open_code == 0, f"{bad!r} should fail open; got {run.open_code}"
    assert run.open_message and "IMEI" in run.open_message


# ── enabled= lifecycle parity with celldiag ────────────────────────────────────
def test_enabled_false_registers_but_touches_no_port():
    """``enabled=false`` leaves cellat defined but idle.

    The operating model is a paired ``celldiag-<imei>`` + ``cellat-<imei>`` per
    modem, so the natural operator action for "stop capturing from this modem"
    is ``enabled=false`` on both. Both sources must honour it the same way:
    registered, with no port opened, no handshake and no helper I/O.

    ``modem.commands`` is the assertion that matters: it proves no AT dialogue
    reached the port. An ``atport=`` is supplied deliberately, so the disabled
    source is pointed straight at a live modem and must still not speak to it.
    "Does not open until enabled" has to mean the port is untouched, or a
    disabled source still contends for it against whatever else the operator is
    running on that modem.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI) as modem:
        run = CellAtRun(binary, f"cellat-{IMEI}:enabled=false,atport={modem.port}",
                        timeout=20.0, stop_when=_opened).run()

        assert run.open_code == 1, (
            f"a disabled source should still REGISTER; got code {run.open_code} "
            f"message {run.open_message!r}")
        assert modem.commands == [], (
            "a DISABLED source spoke to the modem — enabled=false must mean no "
            f"device I/O at all. Saw: {modem.commands}")
        assert any("DISABLED" in m and "enabled=false" in m
                   for m in run.messages + [run.open_message or ""]), (
            "nothing told the operator the source is intentionally idle; "
            f"messages={run.messages} open_message={run.open_message!r}")


def test_enabled_false_is_not_reported_as_an_unknown_option():
    """``enabled=`` must never be reported as an unknown option.

    "Unknown option" reads as "typo, harmless, ignored". But the option exists
    on the sibling celldiag source and disables it there, so such a warning
    would tell an operator who disabled the pair that they had disabled a modem
    when they had disabled half of one.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI) as modem:
        run = CellAtRun(binary, f"cellat-{IMEI}:enabled=false,atport={modem.port}",
                        timeout=20.0, stop_when=_opened).run()
        offenders = [m for m in run.messages
                     if "enabled" in m and "nknown" in m]
        assert not offenders, (
            "enabled= is now a real, honoured option and must not be reported "
            f"as unknown: {offenders}")


def test_enabled_true_still_opens_the_port():
    """The control without which the test above is unfalsifiable.

    A source that never opens anything trivially satisfies "touched no port".
    The same binary, same fixture, differing only in ``enabled=``, must reach
    the modem — and ``enabled=true`` must be indistinguishable from omitting it.
    """
    binary = _binary_or_skip()
    for defn in (f"cellat-{IMEI}:enabled=true,atport={{port}}",
                 f"cellat-{IMEI}:atport={{port}}"):
        with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
            run = CellAtRun(binary, defn.format(port=modem.port),
                            timeout=20.0, stop_when=_opened).run()
            assert run.open_code == 1, (
                f"{defn!r} should open; got {run.open_code} "
                f"message {run.open_message!r}")
            assert "AT+CGSN" in modem.commands, (
                f"{defn!r} reached no port; saw {modem.commands}")


@pytest.mark.parametrize("value", ["False", "TRUE", "maybe", "off"])
def test_a_bad_enabled_value_fails_open_and_names_the_whole_accepted_set(value):
    """A rejected ``enabled=`` value must name the rule the compare uses.

    ``False``, the spelling a Python-side config generator emits, is in the
    parameter list on purpose. Rejecting it is the right behaviour (fail loud,
    never guess: guessing is how a source ends up in a state the operator did
    not ask for while reporting success), but the operator has to be told that
    is the rule or the rejection reads as a bug in the helper.

    The message must name the full accepted set so the code that decides and
    the code that reports agree about one rule.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI) as modem:
        run = CellAtRun(binary, f"cellat-{IMEI}:enabled={value},atport={modem.port}",
                        timeout=20.0, stop_when=_opened).run()

        assert run.open_code == 0, (
            f"enabled={value!r} should fail open, not be guessed at; "
            f"got {run.open_code}")
        assert modem.commands == [], (
            f"a rejected definition still spoke to the modem: {modem.commands}")
        why = run.open_message or ""
        for want in ("true|1|yes", "false|0|no", "case-sensitive"):
            assert want in why, (
                f"the rejection does not name {want!r}: {why!r}")


# ── the zero-yield refusal ─────────────────────────────────────────────────────
def test_a_modem_with_no_survey_command_is_REFUSED_not_opened_empty():
    """Refusing to open beats opening and yielding nothing.

    ``capture_cell_at.c`` probes ``AT+QENG=``, ``AT#RFSTS``, ``AT!GSTATUS?``,
    ``AT+CPSI?``, ``AT^SCELLINFO`` and ``AT$QCRSRP?``, and if a modem answers
    none of them it fails the open with a message naming the vendor, the probes
    and the firmware string.

    A source that opens and sits at ``obs=0`` forever is indistinguishable from
    "no cells in range", so the refusal is load-bearing and is pinned here.

    The modem here answers its identity (``AT+CGMI``/``CGMR``/``CGSN``) and
    ``ERROR`` to every survey probe. Identifying fine and surveying not at all
    is a real shape: a SIM8202G-M2 identifies perfectly.

    The manufacturer is deliberately one no ``detect_vendor`` branch knows. A
    recognised vendor string is the *other* test (below): capability must come
    from what the modem ANSWERED, never from what it called itself.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, manufacturer="ACME WIRELESS",
                     firmware="ACME-0001") as modem:
        run = CellAtRun(binary, f"cellat-{IMEI}:atport={modem.port}",
                        timeout=20.0, stop_when=_opened).run()

        assert run.open_code == 0, (
            f"a modem supporting no survey command opened successfully "
            f"(code={run.open_code}); it will now sit at obs=0 forever, which "
            f"on a live source reads as 'no cells in range'")
        assert run.observations == [], (
            f"a refused source relayed {len(run.observations)} observations")

        why = run.open_message or ""
        # The diagnosis half: the message must say what was tried and what
        # the modem called itself, or the operator is told "no known commands"
        # and left to rediscover which ones "known" meant.
        for want in ("QENG", "CPSI", "RFSTS"):
            assert want in why, (
                f"the refusal does not name the {want} probe, so it cannot tell "
                f"an operator which commands 'known' meant: {why!r}")
        assert "ACME-0001" in why, (
            f"the refusal does not quote the firmware string, which is the one "
            f"fact that identifies WHICH modem to file a gap for: {why!r}")

        # It really did talk to this port -- otherwise the refusal above would
        # be satisfied by a source that never opened anything.
        assert "AT+CGSN" in modem.commands, (
            f"the refusal fired without the port ever being probed: "
            f"{modem.commands}")


def test_capability_comes_from_the_ANSWER_not_from_the_vendor_string():
    """The control, and the sharper half of the test above.

    A modem that *calls itself* Quectel and reports an RM520N firmware, while
    answering ``ERROR`` to every survey command, must STILL be refused. If the
    open succeeds here, capability is being taken from the identity strings —
    and every ``applicable_models`` entry in ``profiles/`` becomes a claim the
    modem never had to honour.

    Without this control the sibling test passes just as well against an
    implementation that refuses only *unrecognised* vendors, which is the more
    dangerous failure: it fires for the modems nobody has, and stays silent for
    the ones in the shipped profile set.
    """
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, manufacturer="Quectel",
                     firmware="RM520NGLAAR03A03M4G") as modem:
        run = CellAtRun(binary, f"cellat-{IMEI}:atport={modem.port}",
                        timeout=20.0, stop_when=_opened).run()

        assert run.open_code == 0, (
            "a modem that ANSWERS no survey command opened because it CLAIMED "
            f"to be an RM520N (code={run.open_code}, message="
            f"{run.open_message!r}). Capability must come from the response, "
            "not from AT+CGMI/AT+CGMR.")
