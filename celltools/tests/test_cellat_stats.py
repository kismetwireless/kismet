# SPDX-License-Identifier: Apache-2.0
"""cellat's readback: the ``cellat_stats`` control line, end to end.

The ``cellat_stats`` line is how a cellat source reports on itself: which scan
profile is armed, whether observations are flowing, whether the raw AT tee is
writing, and the helper's RawAT, atlog and clock-anchor counters. Without it the
web UI can say only "running".

What is pinned here, through the compiled binary and a fake modem:

* a surveying source reports its profile, the intervals actually in force,
  its port, identity and counters, on a periodic cadence;
* a value it has not measured is absent, not zero -- the first line has
  no ``last_obs_epoch``, a source with no ``atlog=`` sends no ``atlog_*`` keys,
  a modem that never answered ``AT+CCLK?`` sends no ``anchor_last_epoch``.
  Kismet serialises every registered field as 0/"" whether or not it was set,
  so the helper sending a zero it did not measure is the only way the panel's
  absence-vs-zero rule can be broken from this side;
* the counters count what was sent: ``obs_total`` never exceeds the
  observations the harness actually received;
* a blocking full scan is announced before it blocks (it silences every
  other line for up to 3 minutes), so a long scan is distinguishable from a
  hung source;
* a disabled source says ``disabled`` and nothing else -- never a row of zeros
  that reads as "running and seeing nothing";
* stats lines never reach ``observations``.

The formatter's omission rules are unit-tested in
``capture_cell_at/test_cellat_stats.c``; this file is the wiring.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from fake_at_modem import QENG_SERVING, QSCAN_CAPABLE, FakeAtModem
from kismet_capture_ipc import CaptureRun

IMEI = "351234567890123"
QSCAN_FIRMWARE = "RM500Q-GLAB-R13A03M4G"
QSCAN_RESPONSE = '+QSCAN: "LTE",310,260,66886,123,-95,-11,0,2,12345678,9012'
CCLK = {"AT+CCLK?": '+CCLK: "26/09/22,18:43:54-24"'}
PROFILES = ("driving", "walking", "stationary", "serving_only")


class _Run(CaptureRun):
    """One offline cellat run."""


# The staleness-guarded lookup, not a bare discover(): a binary older than its
# sources fails instead of quietly testing code nobody built. With a bare
# lookup, a mutation run can test the previous mutant's binary and attribute
# kills to the wrong layer.
from test_cellat_ipc import _binary_or_skip  # noqa: E402


def _stats(run: CaptureRun) -> "list[dict]":
    return [json.loads(s) for s in run.cellat_stats]


def _run(definition_tail: str, *, stop_when, timeout: float = 20.0,
         **modem_kw) -> "tuple[_Run, list[str], str]":
    binary = _binary_or_skip()
    modem_kw.setdefault("extra", {**QENG_SERVING, **CCLK})
    with FakeAtModem(imei=IMEI, **modem_kw) as modem:
        definition = f"cellat-{IMEI}:atport={modem.port},debug=false"
        if definition_tail:
            definition += "," + definition_tail
        run = _Run(binary, definition, timeout=timeout, stop_when=stop_when).run()
        return run, list(modem.commands), modem.port


# ── one surveying run shared by the readback tests ─────────────────────────────
@pytest.fixture(scope="module")
def surveying(tmp_path_factory):
    """walking profile + atlog= + a modem that answers AT+CCLK?.

    Stops once a PERIODIC line has arrived after the first observation, so the
    counters it carries have actually moved (the first line is sent before the
    first poll, by design). ~5-6 s: the periodic cadence is 5 s.
    """
    atlog = tmp_path_factory.mktemp("atlog") / "run.jsonl"

    def done(run):
        return any(s.get("obs_total", 0) > 0 and "obs_per_sec" in s
                   for s in _stats(run))

    run, commands, port = _run(f"strategy=walking,atlog={atlog}",
                               stop_when=done, timeout=25.0)
    return run, commands, port, atlog


def test_the_premise_a_stats_line_arrived(surveying):
    run, commands, _, _ = surveying
    assert run.open_code == 1, run.open_message
    assert run.cellat_stats, (
        "no cellat_stats line at all -- the source still has no readback. "
        f"messages={run.messages}")
    assert "AT+CGSN" in commands


def test_the_profile_and_the_intervals_in_force_are_reported(surveying):
    last = _stats(surveying[0])[-1]
    assert last["state"] == "surveying", last
    assert last["strategy"] == "walking", last
    assert last["strategy_label"] == "Walking", last
    assert last["serving_interval_ms"] == 2000, last
    assert last["neighbor_interval_ms"] == 5000, last
    assert last["fullscan_interval_ms"] == 300000, last
    assert last["stats_interval_s"] == 5, last


def test_the_vocabulary_names_every_profile_the_binary_accepts(surveying):
    """The panel's selector is built from this string, never from its own list."""
    rows = [r.split(",") for r in _stats(surveying[0])[-1]["strategies"].split(";")]
    assert [r[0] for r in rows] == list(PROFILES), rows
    assert all(len(r) == 3 for r in rows), rows
    assert dict((r[0], r[2]) for r in rows) == {
        "driving": "0", "walking": "300", "stationary": "60", "serving_only": "0"}


def test_capability_is_a_measurement_and_is_reported(surveying):
    """The fake modem's RM520N-GL firmware has no full-scan command, and cellat
    probed that -- so `false` is a measured answer and is SENT (unlike "not
    probed", which would be omitted)."""
    assert _stats(surveying[0])[-1]["fullscan_capable"] is False


def test_the_port_and_identity_are_reported(surveying):
    run, _, port, _ = surveying
    last = _stats(run)[-1]
    assert last["at_port"] == port, last
    assert "Quectel" in last.get("model", ""), last
    assert last.get("firmware"), last


def test_obs_total_counts_what_was_sent_not_what_was_parsed(surveying):
    run = surveying[0]
    last = _stats(run)[-1]
    assert 0 < last["obs_total"] <= len(run.observations), (
        f"obs_total={last['obs_total']} but the harness received "
        f"{len(run.observations)} observations")
    assert last["last_obs_epoch"] > 0
    assert last["obs_per_sec"] >= 0


def test_the_first_line_omits_what_it_has_not_measured(surveying):
    """The omission rule, on the wire. The first line goes out before the
    first poll: no observation exists yet, and no throughput window has
    elapsed. Zeros here would read as a measured "no cells"."""
    first = _stats(surveying[0])[0]
    assert first["obs_total"] == 0, first
    assert "last_obs_epoch" not in first, first
    assert "obs_per_sec" not in first, first


def test_rawat_and_the_atlog_tee_are_reported(surveying):
    run, _, _, atlog = surveying
    last = _stats(run)[-1]
    assert last["rawat_records"] > 0, last
    assert last["atlog_path"] == str(atlog), last
    assert last["atlog_active"] is True, last
    assert last["atlog_records"] > 0, last
    # The tee's own count agrees with the file it wrote.
    lines = Path(atlog).read_text().splitlines()
    assert last["atlog_records"] <= len(lines), (last["atlog_records"], len(lines))


def test_clock_anchors_are_counted(surveying):
    last = _stats(surveying[0])[-1]
    assert last["anchor_count"] >= 1, last
    assert last["anchor_last_epoch"] > 0, last


def test_stats_lines_never_reach_observations(surveying):
    run = surveying[0]
    leaked = [o for o in run.observations if "stats_epoch" in o]
    assert not leaked, leaked[:2]


# ── absence, from a source that has not configured the thing ───────────────────
def test_no_atlog_means_no_atlog_keys_and_no_cclk_means_no_anchor_time():
    """A source with no ``atlog=`` must not report ``atlog_records: 0`` -- that
    reads as "the tee is on and writing nothing". And a modem that ERRORs on
    ``AT+CCLK?`` has sent no anchor, so there is no anchor time to report."""
    run, _, _ = _run("strategy=driving", extra=QENG_SERVING,
                     stop_when=lambda r: bool(r.cellat_stats))
    assert run.open_code == 1, run.open_message
    first = _stats(run)[0]
    assert not [k for k in first if k.startswith("atlog")], first
    assert first["anchor_count"] == 0, first
    assert "anchor_last_epoch" not in first, first


# ── the blocking full scan ─────────────────────────────────────────────────────
def test_a_full_scan_is_announced_before_it_blocks_and_closed_after():
    """AT+QSCAN holds the port for up to 2 minutes (AT#CSURVC 3), and nothing
    else is sent meanwhile. The line announcing it is how the panel tells a
    long scan from a hang; the line after it is how it knows the scan ended."""
    def done(run):
        states = [s["state"] for s in _stats(run)]
        return "full_scan" in states and states[-1] == "surveying" and \
            states.index("full_scan") < len(states) - 1

    run, _, _ = _run("strategy=stationary", firmware=QSCAN_FIRMWARE,
                     extra={**QENG_SERVING, **QSCAN_CAPABLE, "AT+QSCAN=3,1": QSCAN_RESPONSE},
                     stop_when=done)
    assert run.open_code == 1, run.open_message
    st = _stats(run)
    scans = [s for s in st if s["state"] == "full_scan"]
    assert scans, [s["state"] for s in st]
    assert scans[0]["fullscan_started_epoch"] > 0, scans[0]
    assert scans[0]["fullscan_capable"] is True, scans[0]
    after = st[st.index(scans[0]) + 1:]
    assert after and after[0]["state"] == "surveying", [s["state"] for s in st]
    assert "fullscan_started_epoch" not in after[0], after[0]


# ── the disabled source ────────────────────────────────────────────────────────
def test_a_disabled_source_reports_disabled_and_no_counters():
    """A disabled cellat source still sends a stats line, so the panel can
    tell "intentionally idle" from "running and silent"."""
    run, commands, _ = _run("enabled=false,strategy=stationary",
                            stop_when=lambda r: bool(r.cellat_stats))
    assert run.open_code == 1, run.open_message
    assert commands == [], commands
    first = _stats(run)[0]
    assert first["state"] == "disabled", first
    assert first["strategy"] == "stationary", first
    for k in ("obs_total", "rawat_records", "anchor_count", "at_port",
              "fullscan_capable", "serving_interval_ms"):
        assert k not in first, (k, first)
