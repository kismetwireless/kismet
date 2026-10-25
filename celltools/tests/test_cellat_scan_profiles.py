# SPDX-License-Identifier: Apache-2.0
"""cellat scan profiles (``strategy=``): the vocabulary and its refusals.

A scan profile is cellat's equivalent of a Wi-Fi source's hop/lock mode: a
profile an operator picks by name (stationary survey / walking / driving).
The profile must be validated strictly. If an unknown value fell back to the
default, ``strategy=stationry`` would run a driving survey and report success:
a knob that looks like it worked while doing nothing, on the one option whose
entire job is to change what the source does. Validating after the AT bring-up
would also spend a modem probe on a typo.

What is pinned here, end to end through the compiled binary and a fake modem:

* an unknown or empty profile refuses the open, names every real profile,
  and does so before any AT reaches the port (``modem.commands == []``);
* the old ``wardrive`` spelling still opens, and reports the new name;
* a profile that wants a full band scan, on a modem with no full-scan command,
  says so instead of quietly surveying like ``driving``.

The table itself (intervals, aliases, labels) is unit-tested in
``capture_cell_at/test_cellat_options.c``; this file is the open path.
"""
from __future__ import annotations

import pytest

from fake_at_modem import QENG_SERVING, QSCAN_CAPABLE, FakeAtModem
from kismet_capture_ipc import CaptureRun

IMEI = "351234567890123"

#: Every canonical profile. The refusal message is generated from the C table,
#: so asserting each name appears is asserting the table and the message agree.
PROFILES = ("driving", "walking", "stationary", "serving_only")

#: cellat probes AT+QSCAN=?; a fake that does not script it answers
#: ERROR and so has NO full-scan command, which is the case the capability
#: warning is for. QSCAN_CAPABLE scripts the answer for the capable case.
QSCAN_FIRMWARE = "RM500Q-GLAB-R13A03M4G"

FULLSCAN_WARNING = "neither AT+QSCAN nor AT#CSURVC"


class _Run(CaptureRun):
    """One offline cellat run."""


# The staleness-guarded lookup, not a bare discover(): a binary older than its
# sources fails instead of quietly testing code nobody built. With a bare
# lookup, a mutation run can test the previous mutant's binary and attribute
# kills to the wrong layer.
from test_cellat_ipc import _binary_or_skip  # noqa: E402


def _opened(run: CaptureRun) -> bool:
    return run.open_code is not None


def _open_with(strategy_clause: str, **modem_kw) -> "tuple[_Run, list[str]]":
    """Open one source against a fresh fake modem; return (run, modem.commands)."""
    binary = _binary_or_skip()
    modem_kw.setdefault("extra", QENG_SERVING)
    with FakeAtModem(imei=IMEI, **modem_kw) as modem:
        definition = f"cellat-{IMEI}:atport={modem.port},debug=false"
        if strategy_clause:
            definition += "," + strategy_clause
        run = _Run(binary, definition, timeout=20.0, stop_when=_opened).run()
        return run, list(modem.commands)


# ── unknown values refuse, before I/O ──────────────────────────────────────────
@pytest.mark.parametrize("bad", ["stationry", "Stationary", "drive"])
def test_an_unknown_strategy_refuses_before_any_port_is_touched(bad):
    """An unknown profile name refuses the open; it never falls back.

    ``modem.commands == []`` is the half that proves the refusal
    happens on the definition, like the IMEI shape check, and not after a
    full bring-up the operator then has to wait out.
    """
    run, commands = _open_with(f"strategy={bad}")
    assert run.open_code == 0, (
        f"strategy={bad!r} must refuse the open; got code {run.open_code} "
        f"message {run.open_message!r}")
    msg = run.open_message or ""
    assert f"'{bad}'" in msg, f"the refusal does not name the bad value: {msg!r}"
    missing = [p for p in PROFILES if p not in msg]
    assert not missing, (
        f"the refusal must name every real profile so the operator can fix the "
        f"typo from the message alone; missing {missing}: {msg!r}")
    assert commands == [], (
        "an unknown strategy reached the modem before refusing -- it must be "
        f"rejected on the definition, before any AT. Saw: {commands}")
    assert run.observations == []


def test_an_empty_strategy_refuses_rather_than_meaning_the_default():
    """``strategy=`` with no value is malformed, not absent.

    cf_find_flag reports found-but-empty as length 0, which a ``> 0`` check
    reads as not-found -- so an empty value would quietly become the
    default, the same silent substitution the strict check exists to prevent.
    """
    run, commands = _open_with("strategy=")
    assert run.open_code == 0, (
        f"an empty strategy= must refuse; got {run.open_code} {run.open_message!r}")
    assert "driving" in (run.open_message or "")
    assert commands == []


def test_an_unknown_strategy_refuses_a_disabled_source_too():
    """A broken definition is broken whether or not the source is enabled.

    Accepting it on ``enabled=false`` would move the failure to the moment an
    operator re-enables the source from the UI -- far from the edit that
    broke it, and exactly when they expect it to start working.
    """
    run, commands = _open_with("enabled=false,strategy=bogus")
    assert run.open_code == 0, (
        f"enabled=false must not launder a bad strategy; got {run.open_code}")
    assert commands == []


# ── the names that work ────────────────────────────────────────────────────────
def test_wardrive_still_opens_and_reports_the_new_name():
    """The legacy spelling ``strategy=wardrive`` keeps working.

    Existing source definitions use it, and the open message reports ``driving`` -- the name the
    panel and the stats line use -- so the two spellings never appear as two
    different modes.
    """
    run, _ = _open_with("strategy=wardrive")
    assert run.open_code == 1, run.open_message
    assert any("(strategy: driving)" in m for m in run.messages), run.messages
    assert not any("(strategy: wardrive)" in m for m in run.messages)


@pytest.mark.parametrize("name", PROFILES)
def test_every_profile_opens_and_is_reported_by_its_canonical_name(name):
    run, commands = _open_with(f"strategy={name}")
    assert run.open_code == 1, f"strategy={name}: {run.open_message!r}"
    assert any(f"(strategy: {name})" in m for m in run.messages), run.messages
    assert "AT+CGSN" in commands, "the open never reached the modem"


def test_no_strategy_means_driving():
    run, _ = _open_with("")
    assert run.open_code == 1, run.open_message
    assert any("(strategy: driving)" in m for m in run.messages), run.messages


def test_strategy_is_not_reported_as_an_unknown_option():
    """The control for the unknown-option warning: strategy= is a real key."""
    run, _ = _open_with("strategy=walking")
    offenders = [m for m in run.messages if "strategy" in m and "nknown" in m]
    assert not offenders, offenders


# ── a profile the modem cannot run says so ─────────────────────────────────────
@pytest.mark.parametrize("name", ["stationary", "walking"])
def test_a_fullscan_profile_on_a_modem_without_fullscan_warns(name):
    """``strategy=stationary`` on a modem with no full-scan command.

    The capture loop gates the scan on the capability, so the source still
    runs -- as a driving survey. It must say so, or the operator who asked for
    a stationary survey gets something else with no word said.
    """
    run, _ = _open_with(f"strategy={name}")
    assert run.open_code == 1, run.open_message
    hits = [m for m in run.messages if FULLSCAN_WARNING in m]
    assert hits, (
        f"strategy={name} on a modem without AT+QSCAN/AT#CSURVC ran with no "
        f"warning; messages={run.messages}")
    assert name in hits[0]


def test_a_fullscan_profile_on_a_modem_with_qscan_does_not_warn():
    """The negative control. A warning that fires on the modems it is not
    about is the fastest way to get it ignored."""
    run, _ = _open_with("strategy=stationary", firmware=QSCAN_FIRMWARE,
                        extra={**QENG_SERVING, **QSCAN_CAPABLE})
    assert run.open_code == 1, run.open_message
    assert not [m for m in run.messages if FULLSCAN_WARNING in m], run.messages


@pytest.mark.parametrize("name", ["driving", "serving_only"])
def test_a_profile_without_fullscan_does_not_warn(name):
    run, _ = _open_with(f"strategy={name}")
    assert run.open_code == 1, run.open_message
    assert not [m for m in run.messages if FULLSCAN_WARNING in m], run.messages
