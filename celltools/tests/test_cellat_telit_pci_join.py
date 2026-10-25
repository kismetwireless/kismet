# SPDX-License-Identifier: Apache-2.0
"""The Telit PCI join exists, and the default strategy switches it off.

## Background

On a Telit the two fast-cadence AT sources share no identity field:

| source | cadence | PLMN | TAC | CID | PCI |
|---|---|---|---|---|---|
| ``AT#RFSTS`` / ``AT#SERVINFO`` | 2 s | yes | yes | yes | absent |
| ``AT#MONI`` row 1 (the same physical cell) | 5 s | no | no | no | yes |

``phy_cell``'s ``pci_promotion()`` needs a PCI on the full-identity
observation, so on a Telit that observation never has one and the two devices
are neither merged nor linked (``related=[]`` on both, where an equivalent
Quectel run links them reciprocally).

``capture_cell_at.c`` has a cached-PCI injection block that copies
``local->cached_pci`` into every RFSTS observation that lacks one. But
``cached_pci`` has exactly one writer, inside the ``AT#CSURVC`` full-scan
block, and that block is gated on ``fullscan_interval_ms > 0``, which the
default wardrive strategy sets to ``0``. So in the default profile the
injection is unreachable and the duplicate is permanent by configuration.

``AT#MONI`` never writes ``cached_pci``: the neighbor block (the ``has_moni``
branch of ``capture_cell_at.c``) only parses rows into observations, even though
the injection site was designed with MONI as a second producer. That is why the
gap reads as a Telit quirk rather than as a switched-off feature.

## What this module drives

A ``FakeAtModem`` answering as a Telit LM960A18, with a transcript recorded
from a real LM960A18: serving cell PLMN 310/260, TAC ``1A2B`` = 6699, CID
``1A2B302`` = 27439874, EARFCN 66786, PCI 236. ``AT#CSURVC`` binds all of it in
one line; ``#RFSTS`` omits the PCI; ``#MONI`` reports the PCI and nothing else
identifying.

Two runs, same responder, one option different:

* ``strategy=wardrive`` (the default) → the serving observation must carry no
  PCI, while a MONI observation in the same run carries 236. The second half is
  what makes this a statement about the join rather than about missing data.
* ``strategy=stationary`` → ``#CSURVC`` runs, ``cached_pci`` is written, and a
  later serving observation carries 236.

The wardrive expectation is not an assertion that the current behaviour is
correct. It pins the config gate so that a future fix (making ``#MONI`` row 1 a
verified second producer) has to come with a deliberate edit here, rather than
silently flipping a documented behaviour.
"""
from __future__ import annotations

import json

import pytest

import cell_binaries
from fake_at_modem import FakeAtModem
from kismet_capture_ipc import CaptureRun

IMEI = "123456789012345"

#: ``AT+CGMR`` on an LM960A18. Telit capability probing keys on the
#: ``AT+CGMI`` vendor string, not on this, but an empty firmware fails
#: ``identify_modem`` outright.
TELIT_FIRMWARE = "32.01.150"

#: Recorded transcript. Serving identity WITHOUT a PCI — field 6 of
#: ``#SERVINFO`` is DRX, not PCI, and ``parse_rfsts`` likewise emits no ``pci``.
RFSTS = ('#RFSTS: "310 260",66786,-101,-68,-13,1A2B,255,,640,1,0,1A2B302,'
         '"000000000000000","T-Mobile",3,66')
SERVINFO = '#SERVINFO: 66786,-68,"T-Mobile","310260",1A2B302,1A2B,640,3,-101'

#: ``AT#MONI`` after ``AT#MONI=1``. Row 1 is the serving cell — corroborated by
#: an exact three-value match against ``#RFSTS`` (RSRP −101, RSRQ
#: −13, PWR/RSSI −68) while row 2 differs on all three, and by ``#CSURVC``
#: independently reporting the serving PCI as 236. ``Id:`` is hex: 0xEC = 236.
MONI = ("#MONI: RSRP:-101 RSRQ:-13 Id:00000EC EARFCN:66786 PWR:-68dbm\n"
        "#MONI: RSRP:-107 RSRQ:-18 Id:0000142 EARFCN:66786 PWR:-79dbm")

#: ``AT#CSURVC`` — the one Telit query that binds PCI to full identity:
#: ``EARFCN,RSSI,MCC,MNC,CID,TAC,PCI,...``. CID and TAC match ``#RFSTS`` exactly,
#: which is what lets the cached-PCI injection match the row to the serving cell.
CSURVC = ("Network survey started ...\n\n"
          "66786,-68,310,260,27439874,6699,236,0,-103,-15,20\n\n\n"
          "Network survey ended")

#: The PCI every source above agrees on for the serving cell.
SERVING_PCI = 236

SERVING_ORIGIN = "AT#RFSTS"
NEIGHBOR_ORIGIN = "AT#MONI"


def _binary_or_skip() -> str:
    found = cell_binaries.discover("cellat")
    if not found.ok:
        pytest.skip(found.skip_reason())
    return str(found.path)


def _telit_responses() -> dict:
    return {
        "AT#RFSTS": RFSTS,
        "AT#SERVINFO": SERVINFO,
        "AT#MONI": MONI,
        "AT#MONI=0": "OK",
        "AT#MONI=1": "OK",
        "AT#MONI=2": "OK",
        "AT#CSURVC=?": "OK",
        "AT#CSURVC": CSURVC,
        "AT+CGMM": "LM960A18",
    }


class _Run(CaptureRun):
    """One offline cellat run against the scripted Telit."""


def _obs_with_origin(run: CaptureRun, origin: str) -> list:
    """Decoded observations stamped with ``origin``, and only those.

    ``inject_prov`` nests the stamp under ``"prov"``. Reading a top-level
    ``origin`` key finds nothing and filters every observation out — which looks
    identical to the gap under test and would make this module pass against a
    FIXED binary.
    """
    out = []
    for obs in run.observations:
        try:
            js = json.loads(obs) if isinstance(obs, str) else obs
        except (TypeError, ValueError):
            continue
        if not isinstance(js, dict):
            continue
        prov = js.get("prov") or {}
        if origin in str(prov.get("origin", "")):
            out.append(js)
    return out


def _run_cellat(*, strategy: str, stop_when, timeout: float) -> CaptureRun:
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=TELIT_FIRMWARE,
                     manufacturer="Telit",
                     extra=_telit_responses()) as modem:
        definition = (f"cellat-{IMEI}:atport={modem.port},"
                      f"strategy={strategy},debug=false")
        return _Run(binary, definition, timeout=timeout,
                    stop_when=stop_when).run()


def _serving_has_pci(run: CaptureRun) -> bool:
    return any("pci" in o for o in _obs_with_origin(run, SERVING_ORIGIN))


@pytest.fixture(scope="module")
def wardrive_run() -> CaptureRun:
    """Long enough to have run several serving+neighbor cycles (2 s / 5 s)."""
    return _run_cellat(strategy="wardrive", stop_when=None, timeout=14.0)


@pytest.fixture(scope="module")
def stationary_run() -> CaptureRun:
    """``fullscan_last_ms`` starts at 0 against an epoch clock, so ``#CSURVC``
    fires on the first loop iteration rather than 60 s in."""
    return _run_cellat(strategy="stationary", stop_when=_serving_has_pci,
                       timeout=25.0)


# --------------------------------------------------------------------------
# Premise guards — without these, an "assert no pci" passes for a source that
# never opened, never identified as Telit, or never surveyed anything.
# --------------------------------------------------------------------------

def test_the_wardrive_run_actually_produced_serving_observations(wardrive_run):
    obs = _obs_with_origin(wardrive_run, SERVING_ORIGIN)
    assert obs, (
        "cellat produced no AT#RFSTS observations, so every PCI assertion in "
        "this module would pass vacuously. The likely causes are a failed open "
        "or detect_vendor not reaching the Telit branch. "
        f"messages={wardrive_run.messages!r}")


def test_the_serving_observation_carries_full_identity(wardrive_run):
    """The other half of the asymmetry: RFSTS has PLMN+TAC+CID. If this ever
    fails, a missing PCI is not the interesting finding — the parse is."""
    obs = _obs_with_origin(wardrive_run, SERVING_ORIGIN)
    assert obs, "no serving observations; see the premise guard"
    o = obs[0]
    # As-broadcast digit strings, not integers: an integer MNC cannot carry its
    # digit count, and "07" and "007" are different networks. phy_cell's
    # plmn_from_json() takes the string form first.
    assert o.get("mcc") == "310" and o.get("mnc") == "260", o
    assert o.get("tac") == 0x1A2B, o          # 6699
    assert o.get("cell_id") == 0x1A2B302, o   # 27439874


# --------------------------------------------------------------------------
# The finding
# --------------------------------------------------------------------------

def test_wardrive_serving_observations_never_carry_a_pci(wardrive_run):
    """The anchor. In the default strategy, the full-identity observation
    has no PCI, so ``pci_promotion()`` can never fire for this modem.

    This is a *configuration* outcome, not a parse failure — see the control
    below, which finds PCI 236 in the very same run.
    """
    with_pci = [o for o in _obs_with_origin(wardrive_run, SERVING_ORIGIN)
                if "pci" in o]
    assert not with_pci, (
        "a wardrive-strategy serving observation carried a PCI. If this is an "
        "intended fix, the Telit PCI join now runs by default and this module "
        f"must be updated deliberately: {with_pci!r}")


def test_the_pci_was_available_in_that_same_wardrive_run(wardrive_run):
    """The control that makes the anchor mean something.

    Without it, "serving observations have no PCI" is equally consistent with
    "this modem reports no PCI anywhere" — a data problem — when the truth is
    that the PCI is right there on the neighbor cadence and simply never
    reaches the observation that could use it. That is why the fix is a join
    and not a capture change.
    """
    neighbors = _obs_with_origin(wardrive_run, NEIGHBOR_ORIGIN)
    assert neighbors, (
        "AT#MONI produced no observations, so this control proves nothing. "
        f"messages={wardrive_run.messages!r}")
    assert any(o.get("pci") == SERVING_PCI for o in neighbors), (
        f"no MONI observation reported the serving PCI {SERVING_PCI}; "
        f"got {[o.get('pci') for o in neighbors]!r}")


def test_stationary_injects_the_csurvc_pci_into_the_serving_observation(
        stationary_run):
    """The cached-PCI injection works; it is only ever reachable here.

    ``strategy=stationary`` is the one built-in strategy with
    ``fullscan_interval_ms = 60000``, so it is the only one that runs
    ``AT#CSURVC``, which is the only writer of ``cached_pci``.
    """
    obs = _obs_with_origin(stationary_run, SERVING_ORIGIN)
    assert obs, (
        "no serving observations in the stationary run at all. "
        f"messages={stationary_run.messages!r}")
    injected = [o for o in obs if o.get("pci") == SERVING_PCI]
    assert injected, (
        "AT#CSURVC ran but no serving observation received the cached PCI "
        f"{SERVING_PCI}. pci values seen: "
        f"{[o.get('pci') for o in obs]!r}; messages={stationary_run.messages!r}")


def test_the_injected_pci_keeps_the_full_identity_intact(stationary_run):
    """A join that produced a PCI-carrying observation but corrupted the
    identity fields would satisfy the assertion above and be useless to
    ``pci_promotion()``, which needs BOTH on one observation."""
    joined = [o for o in _obs_with_origin(stationary_run, SERVING_ORIGIN)
              if o.get("pci") == SERVING_PCI]
    assert joined, "no injected observation; see the test above"
    o = joined[0]
    assert o.get("mcc") == "310" and o.get("mnc") == "260", o   # digit strings
    assert o.get("tac") == 0x1A2B, o
    assert o.get("cell_id") == 0x1A2B302, o
    assert o.get("earfcn") == 66786, o
