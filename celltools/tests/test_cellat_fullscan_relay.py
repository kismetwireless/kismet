# SPDX-License-Identifier: Apache-2.0
"""Full-scan observations must reach Kismet regardless of ``debug=``.

## The hazard

``capture_cell_at.c``'s full-scan block sends a debug-only summary message
(``if (local->debug && obs_count > 0) { ... }``) next to the ``cf_send_json``
loop that relays the observations. If that ``if`` encloses the send loop, every
observation from ``AT+QSCAN=3,1`` / ``AT#CSURVC`` is relayed only when
``debug=`` is on. The serving and neighbor blocks have the same shape, so a
misplaced closing brace here reads correctly line by line.

``debug=`` defaults ON, so such a regression shows up only for an operator who
turned debug off, which is the normal setting for a production wardrive. It is
also silent: the scan is still performed (up to a 120 s ``AT+QSCAN``), an INFO
line still says *"starting full band scan"*, and the results are dropped. Full
scan exists to find the cells the serving and neighbor queries do not report,
so its output is not redundant with anything else the source emits.

## What this test drives

A ``FakeAtModem`` reporting ``RM500Q`` firmware, which is what sets
``has_qscan``, with ``strategy=stationary`` -- the one strategy that enables
full scan (``fullscan_interval_ms = 60000``; wardrive and serving_only set it
to 0). ``fullscan_last_ms`` starts at 0 against an epoch clock, so the scan
fires on the first loop iteration rather than 60 s in.

``debug=false`` is the load-bearing part of the source definition. With debug
left at its default the test would pass even with the relay gated on debug.
"""
from __future__ import annotations

import json

import pytest

import cell_binaries
from fake_at_modem import QENG_SERVING, QSCAN_CAPABLE, FakeAtModem
from kismet_capture_ipc import CaptureRun

IMEI = "351234567890123"

#: ``has_qscan`` is gated on a firmware prefix of RM500Q or RM502Q.
QSCAN_FIRMWARE = "RM500Q-GLAB-R13A03M4G"

#: One LTE row in the shape ``parse_qscan`` documents:
#: ``+QSCAN: "RAT",MCC,MNC,EARFCN,PCI,RSRP,RSRQ,?,band,cellID,TAC,...``
QSCAN_RESPONSE = '+QSCAN: "LTE",310,260,66886,123,-95,-11,0,2,12345678,9012'

#: What ``inject_prov`` stamps on a full-scan observation, and nothing else.
FULLSCAN_ORIGIN = "AT+QSCAN=3,1"


def _binary_or_skip() -> str:
    found = cell_binaries.discover("cellat")
    if not found.ok:
        pytest.skip(found.skip_reason())
    return str(found.path)


class _Run(CaptureRun):
    """One offline cellat run."""


def _run_a_fullscan(*, debug: str) -> CaptureRun:
    binary = _binary_or_skip()
    with FakeAtModem(imei=IMEI, firmware=QSCAN_FIRMWARE,
                     manufacturer="Quectel",
                     extra={**QENG_SERVING, **QSCAN_CAPABLE, "AT+QSCAN=3,1": QSCAN_RESPONSE}) as modem:
        def stop_when(run: CaptureRun) -> bool:
            return bool(_fullscan_observations(run))

        definition = (f"cellat-{IMEI}:atport={modem.port},"
                      f"strategy=stationary,debug={debug}")
        return _Run(binary, definition, timeout=25.0,
                    stop_when=stop_when).run()


def _fullscan_observations(run: CaptureRun) -> list:
    """The observations stamped with the full-scan origin, and only those.

    Filtering on origin rather than counting everything is what keeps this
    honest: the serving query runs on the same loop, so a bare
    ``run.observations`` would be non-empty even with the full scan discarded.
    """
    out = []
    for obs in run.observations:
        try:
            js = json.loads(obs) if isinstance(obs, str) else obs
        except (TypeError, ValueError):
            continue
        if not isinstance(js, dict):
            continue
        # `inject_prov` nests the stamp under "prov", NOT at the top level.
        # Reading js["origin"] finds nothing and every observation is filtered
        # out -- which looks exactly like the failure under test.
        prov = js.get("prov") or {}
        if FULLSCAN_ORIGIN in str(prov.get("origin", "")):
            out.append(js)
    return out


@pytest.fixture(scope="module")
def fullscan_without_debug() -> CaptureRun:
    return _run_a_fullscan(debug="false")


def test_the_scan_was_actually_performed(fullscan_without_debug):
    """Premise guard: distinguish "relayed nothing" from "never scanned".

    Without this, a regression that stops cellat reaching the full-scan branch
    at all (wrong strategy, has_qscan unset, interval never elapsing) would fail
    the anchor below with a message blaming the relay -- naming the wrong kind
    of problem.

    The INFO line is emitted before the AT command, outside any debug guard.
    """
    assert any("starting full band scan" in m
               for m in fullscan_without_debug.messages), (
        "cellat never reached the full-scan branch, so this module tested "
        f"nothing. messages={fullscan_without_debug.messages!r}")


def test_fullscan_observations_are_not_gated_on_debug(fullscan_without_debug):
    """The anchor. A debug flag must never gate DATA.

    If the relay is gated on debug, this list is empty with ``debug=false``
    and non-empty with the default, while both runs perform the same scan and
    log the same "starting full band scan" line.
    """
    obs = _fullscan_observations(fullscan_without_debug)
    assert obs, (
        "a full scan ran and produced no observations on the wire with "
        "debug=false -- the results were scanned for, then discarded. "
        f"messages={fullscan_without_debug.messages!r}")


def test_the_relayed_observation_carries_the_fullscan_provenance(
        fullscan_without_debug):
    """The origin stamp is how a consumer tells a full-scan cell from a
    neighbor one; a relay that dropped it would satisfy the anchor while
    making the data unattributable."""
    obs = _fullscan_observations(fullscan_without_debug)
    assert obs, "no full-scan observations at all; see the anchor test"
    assert any(str(o.get("earfcn")) == "66886" for o in obs), (
        f"the scanned cell did not survive the relay intact: {obs!r}")
