# SPDX-License-Identifier: Apache-2.0
"""cellat runtime settings through set_channel: profile, AT log, anchors.

The model is Wi-Fi parity: on a Wi-Fi source you switch hop/lock and channels
on a running adapter. cellat accepts runtime settings through its chancontrol
callback, so switching the AT profile or toggling raw AT logging does not need
a restart.

What is pinned here, through the compiled binary, a fake modem and the
CONFIGURE frame the server's ``set_channel`` route produces:

* ``strategy=`` switches the profile without a restart (one open, one IMEI
  read), and the stats line reports the new intervals;
* switching to a full-scan profile scans now (the last-run stamps are
  cleared) rather than a whole interval later;
* ``atlog=`` starts, stops and redirects the raw AT tee live; a stop keeps the
  path; a redirect to an unwritable path keeps the tee that was running;
* every refusal names its reason (unknown key / open-time only / bad value /
  a channel string) and the source keeps running;
* a runtime setting never becomes the source's channel: the CONFIGREPORT
  carries no channel for it, so the server neither shows ``strategy=walking``
  as "the channel" nor replays it after an error re-open.
"""
from __future__ import annotations

import json

import pytest

from fake_at_modem import QENG_SERVING, QSCAN_CAPABLE, FakeAtModem
from kismet_capture_ipc import CaptureRun
from test_cellat_ipc import _binary_or_skip

IMEI = "351234567890123"
QSCAN_FIRMWARE = "RM500Q-GLAB-R13A03M4G"
QSCAN_RESPONSE = '+QSCAN: "LTE",310,260,66886,123,-95,-11,0,2,12345678,9012'
CCLK = {"AT+CCLK?": '+CCLK: "26/09/22,18:43:54-24"'}


class _Run(CaptureRun):
    """One offline cellat run."""


def _stats(run: CaptureRun) -> "list[dict]":
    return [json.loads(s) for s in run.cellat_stats]


def _after_first_stats(run: CaptureRun) -> bool:
    return bool(run.cellat_stats)


def _msgs(run: CaptureRun) -> str:
    return "\n".join(run.messages + [m for _, m in run.config_results])


def _run(tail: str, *, configure, stop_when, timeout: float = 25.0, **modem_kw):
    binary = _binary_or_skip()
    modem_kw.setdefault("extra", {**QENG_SERVING, **CCLK})
    with FakeAtModem(imei=IMEI, **modem_kw) as modem:
        definition = f"cellat-{IMEI}:atport={modem.port},debug=false"
        if tail:
            definition += "," + tail
        run = _Run(binary, definition, timeout=timeout, stop_when=stop_when,
                   configure=configure).run()
        return run, list(modem.commands)


# ── the profile switch ─────────────────────────────────────────────────────────
def test_a_profile_switch_is_applied_without_a_restart():
    def done(run):
        return any(s.get("strategy") == "stationary" for s in _stats(run))

    run, commands = _run("strategy=walking",
                         configure=[(_after_first_stats, "strategy=stationary")],
                         stop_when=done)
    assert run.open_code == 1, run.open_message
    st = [s for s in _stats(run) if s.get("strategy") == "stationary"]
    assert st, f"the switch never reached the stats line: {_msgs(run)}"
    assert st[0]["fullscan_interval_ms"] == 60000, st[0]
    assert st[0]["strategy_label"] == "Stationary survey"
    # Not a restart: one bring-up, one IMEI read, the whole run.
    assert commands.count("AT+CGSN") == 1, commands
    assert "scan profile -> stationary" in _msgs(run)


def test_switching_to_a_full_scan_profile_scans_now():
    """driving -> stationary scans at once. This one does not discriminate
    the stamp-clearing on its own -- a driving source never scanned, so its
    fullscan stamp is already 0 -- it pins that the switch reaches the scan
    loop at all. The next test is the stamp-clearing pin."""
    def done(run):
        seen_switch = False
        for s in _stats(run):
            if s.get("strategy") == "stationary":
                seen_switch = True
            if seen_switch and s["state"] == "full_scan":
                return True
        return False

    run, commands = _run("strategy=driving", firmware=QSCAN_FIRMWARE,
                         extra={**QENG_SERVING, **QSCAN_CAPABLE, "AT+QSCAN=3,1": QSCAN_RESPONSE},
                         configure=[(_after_first_stats, "strategy=stationary")],
                         stop_when=done, timeout=20.0)
    assert run.open_code == 1, run.open_message
    assert "AT+QSCAN=3,1" in commands, (
        "the switch to stationary did not scan -- the last-run stamps were not "
        f"cleared, or the switch never applied: {_msgs(run)}")


def test_a_switch_clears_the_last_run_stamps():
    """Stamp clearing, pinned so it can fail: start stationary, let its first
    scan finish (the stamp is now 'just scanned'), then switch to walking.
    With the stamps cleared, walking scans at once; without, the next scan
    would be 300 s out and this test would time out."""
    def scan_done(run):
        states = [s["state"] for s in _stats(run)]
        return "full_scan" in states and states[-1] == "surveying"

    def done(run):
        return sum(1 for s in _stats(run) if s["state"] == "full_scan") >= 2

    run, commands = _run("strategy=stationary", firmware=QSCAN_FIRMWARE,
                         extra={**QENG_SERVING, **QSCAN_CAPABLE, "AT+QSCAN=3,1": QSCAN_RESPONSE},
                         configure=[(scan_done, "strategy=walking")],
                         stop_when=done, timeout=20.0)
    assert run.open_code == 1, run.open_message
    assert commands.count("AT+QSCAN=3,1") >= 2, (
        "switching profile did not restart the full-scan clock; the second "
        f"scan never came. {_msgs(run)}")
    walking = [s for s in _stats(run) if s.get("strategy") == "walking"]
    assert walking, "the switch to walking never applied"


def test_a_bad_profile_is_refused_and_the_source_keeps_its_profile():
    def done(run):
        return bool(run.config_results) and len(run.cellat_stats) >= 2

    run, _ = _run("strategy=walking",
                  configure=[(_after_first_stats, "strategy=stationry")],
                  stop_when=done)
    assert run.open_code == 1
    msgs = _msgs(run)
    assert "unknown strategy 'stationry'" in msgs, msgs
    assert "keeps its current profile" in msgs, msgs
    assert all(s.get("strategy") == "walking" for s in _stats(run)), _stats(run)


# ── the classification: each refusal says which kind it is ────────────────────
@pytest.mark.parametrize("setting, needle", [
    ("B71", "is a channel"),
    ("atport=/dev/ttyUSB9", "not settable while the source is running"),
    ("enabled=false", "Enable/Disable capture"),
    ("rawlog=/tmp/x", "no cellat option named 'rawlog'"),
    ("clock_anchor_sec=soon", "whole number"),
])
def test_every_refusal_names_its_reason_and_the_source_keeps_running(setting, needle):
    def done(run):
        return bool(run.config_results) and len(run.cellat_stats) >= 2

    run, _ = _run("", configure=[(_after_first_stats, setting)], stop_when=done)
    assert run.open_code == 1
    assert needle in _msgs(run), (setting, _msgs(run))
    # Still running: a stats line arrived after the refusal.
    assert len(run.cellat_stats) >= 2, "the source stopped reporting"


# ── a setting is not a channel ─────────────────────────────────────────────────
@pytest.mark.parametrize("setting", ["strategy=stationary", "clock_anchor_sec=60"])
def test_an_applied_setting_never_becomes_the_sources_channel(setting):
    """The framework records a string as the source's channel only when the
    control callback returns > 0, and the server REPLAYS that channel with
    set_channel after an error re-open. A setting recorded there would show on
    the panel as "the channel" and silently re-apply after every crash
    recovery -- and only the last one, since the channel is one string."""
    def done(run):
        return bool(run.config_results)

    run, _ = _run("strategy=walking", configure=[(_after_first_stats, setting)],
                  stop_when=done)
    assert run.config_results, "no CONFIGREPORT arrived"
    assert run.config_channels == [None], (
        f"{setting!r} came back as the source's channel {run.config_channels}")


# ── the raw AT log at runtime ──────────────────────────────────────────────────
def test_atlog_starts_stops_and_keeps_its_path(tmp_path):
    target = tmp_path / "live.jsonl"

    def tee_on(run):
        # Stop only once the tee has written a record, not the moment it
        # reports active: the serving poll runs every 2 s, so a stop sent on
        # the first "active" line could land before any exchange and leave an
        # empty file, failing the test's own final assert. The browser twin
        # waits the same way.
        return any(s.get("atlog_active") is True and s.get("atlog_records", 0) > 0
                   for s in _stats(run))

    def done(run):
        st = _stats(run)
        on = [i for i, s in enumerate(st) if s.get("atlog_active") is True]
        off = [i for i, s in enumerate(st) if s.get("atlog_active") is False]
        return bool(on) and any(i > on[0] for i in off)

    run, _ = _run("", configure=[(_after_first_stats, f"atlog={target}"),
                                  (tee_on, "atlog=off")],
                  stop_when=done)
    assert run.open_code == 1
    st = _stats(run)
    first = st[0]
    assert not [k for k in first if k.startswith("atlog")], (
        "a source with no atlog= reported atlog keys before one was started", first)
    on = next(s for s in st if s.get("atlog_active") is True)
    assert on["atlog_path"] == str(target), on
    off = [s for s in st if s.get("atlog_active") is False][-1]
    assert off["atlog_path"] == str(target), (
        "a stopped tee must keep its path so the operator can find the file", off)
    assert target.exists() and target.read_text().count("\n") >= 1
    assert "AT log now writing to" in _msgs(run) and "AT log stopped" in _msgs(run)


def test_a_redirect_to_an_unwritable_path_keeps_the_running_tee(tmp_path):
    good = tmp_path / "good.jsonl"

    def done(run):
        return bool(run.config_results) and len(run.cellat_stats) >= 2

    run, _ = _run(f"atlog={good}",
                  configure=[(_after_first_stats,
                              "atlog=/nonexistent-dir-4691/x.jsonl")],
                  stop_when=done)
    assert run.open_code == 1
    assert "untouched" in _msgs(run), _msgs(run)
    last = _stats(run)[-1]
    assert last["atlog_path"] == str(good) and last["atlog_active"] is True, last


# ── the clock-anchor cadence ───────────────────────────────────────────────────
def test_the_clock_anchor_cadence_changes_at_runtime():
    """Default cadence is 30 s; after clock_anchor_sec=1 the count must climb
    within a few seconds, which the default could not do."""
    def done(run):
        return any(s.get("anchor_count", 0) >= 3 for s in _stats(run))

    run, _ = _run("", configure=[(_after_first_stats, "clock_anchor_sec=1")],
                  stop_when=done, timeout=15.0)
    assert run.open_code == 1
    assert any(s.get("anchor_count", 0) >= 3 for s in _stats(run)), (
        f"anchors never reached 3: {[s.get('anchor_count') for s in _stats(run)]}")


# ── a disabled source has nothing to change ────────────────────────────────────
def test_a_disabled_source_refuses_runtime_settings():
    run, commands = _run("enabled=false",
                         configure=[(_after_first_stats, "strategy=stationary")],
                         stop_when=lambda r: bool(r.config_results))
    assert run.open_code == 1
    # On the CONFIGREPORT's own message, not _msgs(): the OPEN message of a
    # disabled source already says "enabled=false", so asserting on the pooled
    # text would pass with the refusal deleted.
    reply = run.config_results[0][1]
    assert "enabled=false" in reply and "nothing is being captured" in reply, reply
    assert "scan profile ->" not in _msgs(run), "the switch was accepted"
    assert commands == [], commands
