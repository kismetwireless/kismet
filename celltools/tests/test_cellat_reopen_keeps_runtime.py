# SPDX-License-Identifier: Apache-2.0
"""A cellat source's runtime choices survive a reopen.

## The hazard

The panel's runtime profile switch and AT-log Start/Stop are ``set_channel``
``key=value`` settings: applied live, and not part of the source definition a
reopen reads. Without a restore, switching the whole modem off and on would put
``cellat.strategy`` back to the definition's ``walking`` and the AT log back on
``atlog1``, losing the operator's ``driving`` and ``atlog2``. The same loss
would happen on Kismet's automatic ERROR reopen, silently, mid-drive. The
intended behaviour matches Wi-Fi: UI choices last until Kismet restarts.

## The restore, and the lock rule

The cellat datasource remembers which runtime keys the operator touched and
restores the helper's readback of them (what actually ran, so a refused
setting cannot poison the restore) after every open of an enabled definition.
A key the definition itself changed since the last open is the operator
re-specifying it, and the definition wins.

A band/RAT lock is re-applied after an ERROR reopen only, never after an
explicit Capture or whole-modem off/on, which comes back AUTO (the modem as
found). Kismet's own error-retry callback replays the source's channel, and an
explicit reopen uses the definition, which has none; these tests pin both.

## How the new session is told from the old one

The ``cellat.*`` fields persist across a reopen, so "strategy == stationary"
after a reopen could be the OLD session's value. Every wait below requires a
stats line stamped after the reopen (``stats_epoch``) from a new helper pid.
"""
from __future__ import annotations

import os
import signal
import time

from fake_at_modem import QENG_SERVING, FakeAtModem
from test_cellat_lock import ORIG, LockableFakeModem
from test_cellat_lock import IMEI as LOCK_IMEI
from test_cellat_server_fields import F, IMEI, _await, _fresh_server_or_skip
from test_celldiag_server_routes import KismetServer

RESTORE_NOTE = "re-applying its runtime choices"


def _uuid(row: dict) -> str:
    return row["kismet.datasource.uuid"]


def _set(ks: KismetServer, row: dict, setting: str) -> None:
    status, _ = ks.post(f"datasource/by-uuid/{_uuid(row)}/set_channel.cmd",
                        {"channel": setting})
    assert status == 200


def _stop(ks: KismetServer, uuid: str) -> None:
    ks.get(f"datasource/by-uuid/{uuid}/close_source.cmd")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and ks.source()["kismet.datasource.running"]:
        time.sleep(0.2)


def _reopen(ks: KismetServer, uuid: str) -> float:
    """The panel's Capture off/on. Returns the instant the old session was
    fully closed: no stats line stamped after it can be the OLD session's.

    Stamped after the stop, not before it. A `since` taken before the close
    lets the old session's last stats line -- already carrying the value under
    test -- satisfy a "new session" wait (e.g. a stale LTE after an explicit
    reopen that in fact came back AUTO)."""
    _stop(ks, uuid)
    t0 = time.time()
    ks.get(f"datasource/by-uuid/{uuid}/open_source.cmd")
    return t0


def _toggle_enabled(ks: KismetServer, uuid: str, want: str) -> float:
    """The panel's whole-modem switch: close, update_definition, open."""
    _stop(ks, uuid)
    t0 = time.time()
    status, _ = ks.post(f"datasource/by-uuid/{uuid}/update_definition.cmd",
                        {"options": {"enabled": want}})
    assert status == 200
    ks.get(f"datasource/by-uuid/{uuid}/open_source.cmd")
    return t0


def _new_session(ks: KismetServer, old_pid: int, since: float, pred=lambda r: True,
                 timeout: float = 60.0) -> dict:
    """A stats line from a NEW helper, stamped after `since`, matching `pred`."""
    return _await(ks, lambda r: r.get("kismet.datasource.running")
                  and r.get("kismet.datasource.ipc_pid") not in (None, 0, old_pid)
                  and r.get(F + "stats_epoch", 0) > since
                  and r.get(F + "state") in ("surveying", "full_scan")
                  and pred(r), timeout=timeout)


def _records(path) -> int:
    try:
        return sum(1 for _ in open(path))
    except FileNotFoundError:
        return 0


def test_capture_off_on_keeps_the_runtime_profile(tmp_path):
    _fresh_server_or_skip()
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with KismetServer(tmp_path, f"cellat-{IMEI}:atport={modem.port},"
                                    "strategy=walking,debug=false") as ks:
            row = _await(ks, lambda r: r.get(F + "strategy") == "walking")
            _set(ks, row, "strategy=stationary")
            row = _await(ks, lambda r: r.get(F + "strategy") == "stationary")
            pid = row["kismet.datasource.ipc_pid"]
            t0 = _reopen(ks, _uuid(row))
            row = _new_session(ks, pid, t0)
            # Positive control: the new session opened on the DEFINITION's
            # profile before the restore -- otherwise "stationary" below could
            # be a helper that never reset at all.
            assert modem.commands.count("AT+CGSN") >= 2, "the source never reopened"
            row = _new_session(ks, pid, t0, lambda r: r.get(F + "strategy") == "stationary")
            assert row["kismet.datasource.channel"] == "", (
                "the restore must not turn a setting into the source's channel")


def test_whole_modem_off_on_keeps_profile_and_at_log(tmp_path):
    """Definition walking + atlog1, runtime driving + atlog2, then the
    whole-modem switch off and on."""
    _fresh_server_or_skip()
    log1, log2 = tmp_path / "atlog1.jsonl", tmp_path / "atlog2.jsonl"
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with KismetServer(tmp_path, f"cellat-{IMEI}:atport={modem.port},"
                                    f"strategy=walking,atlog={log1},debug=false") as ks:
            row = _await(ks, lambda r: r.get(F + "atlog_path") == str(log1)
                         and r.get(F + "atlog_active") == 1)
            _set(ks, row, "strategy=driving")
            _set(ks, row, "atlog=off")
            _set(ks, row, f"atlog={log2}")
            row = _await(ks, lambda r: r.get(F + "strategy") == "driving"
                         and r.get(F + "atlog_path") == str(log2)
                         and r.get(F + "atlog_active") == 1)
            _toggle_enabled(ks, _uuid(row), "false")
            _await(ks, lambda r: r.get(F + "state") == "disabled")
            pid = ks.source()["kismet.datasource.ipc_pid"]
            t0 = _toggle_enabled(ks, _uuid(row), "true")
            row = _new_session(ks, pid, t0, lambda r: r.get(F + "strategy") == "driving"
                               and r.get(F + "atlog_path") == str(log2)
                               and r.get(F + "atlog_active") == 1)
            n1, n2 = _records(log1), _records(log2)
            time.sleep(5)
            assert _records(log2) > n2, "atlog2 stopped receiving after the reopen"
            assert _records(log1) == n1, (
                "atlog1 is receiving again: the reopen went back to the definition")


def test_a_runtime_at_log_stop_survives_a_reopen(tmp_path):
    _fresh_server_or_skip()
    log1 = tmp_path / "atlog1.jsonl"
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with KismetServer(tmp_path, f"cellat-{IMEI}:atport={modem.port},"
                                    f"atlog={log1},debug=false") as ks:
            row = _await(ks, lambda r: r.get(F + "atlog_active") == 1)
            _set(ks, row, "atlog=off")
            row = _await(ks, lambda r: r.get(F + "atlog_active") == 0
                         and r.get(F + "atlog_path") == str(log1))
            pid = row["kismet.datasource.ipc_pid"]
            t0 = _reopen(ks, _uuid(row))
            _new_session(ks, pid, t0, lambda r: r.get(F + "atlog_active") == 0)
            n = _records(log1)
            time.sleep(5)
            assert _records(log1) == n, "the stopped AT log restarted on reopen"


def test_a_refused_setting_does_not_poison_the_restore(tmp_path):
    """The success bit is 1 for applied AND refused settings, so the
    restore uses the helper's READBACK: the last profile that actually ran."""
    _fresh_server_or_skip()
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with KismetServer(tmp_path, f"cellat-{IMEI}:atport={modem.port},"
                                    "debug=false") as ks:
            row = _await(ks, lambda r: r.get(F + "strategy") == "driving")
            _set(ks, row, "strategy=stationary")
            row = _await(ks, lambda r: r.get(F + "strategy") == "stationary")
            _set(ks, row, "strategy=bogus")
            time.sleep(3)          # a stats interval: the refusal reports nothing new
            row = ks.source()
            pid = row["kismet.datasource.ipc_pid"]
            t0 = _reopen(ks, _uuid(row))
            _new_session(ks, pid, t0, lambda r: r.get(F + "strategy") == "stationary")


def test_an_explicit_definition_change_wins_over_the_remembered_choice(tmp_path):
    _fresh_server_or_skip()
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with KismetServer(tmp_path, f"cellat-{IMEI}:atport={modem.port},"
                                    "debug=false") as ks:
            row = _await(ks, lambda r: r.get(F + "strategy") == "driving")
            _set(ks, row, "strategy=stationary")
            row = _await(ks, lambda r: r.get(F + "strategy") == "stationary")
            pid = row["kismet.datasource.ipc_pid"]
            _stop(ks, _uuid(row))
            t0 = time.time()
            status, _ = ks.post(f"datasource/by-uuid/{_uuid(row)}/update_definition.cmd",
                                {"options": {"strategy": "walking"}})
            assert status == 200
            ks.get(f"datasource/by-uuid/{_uuid(row)}/open_source.cmd")
            row = _new_session(ks, pid, t0, lambda r: r.get(F + "strategy") == "walking")
            time.sleep(4)
            assert ks.source()[F + "strategy"] == "walking", (
                "the remembered runtime profile overrode an explicit definition change")


# ── the lock rule ────────────────────────────────────────────────────────────

def _lock_server(tmp_path, modem):
    return KismetServer(tmp_path, f"cellat-{LOCK_IMEI}:atport={modem.port},"
                                  f"debug=false,lockstate={tmp_path / 's'}")


def test_an_error_reopen_reapplies_the_lock_and_the_runtime_profile(tmp_path):
    """Kismet's automatic re-open after a helper dies: the operator's lock AND
    profile come back, exactly as a Wi-Fi source's locked channel does."""
    _fresh_server_or_skip()
    with LockableFakeModem(extra={**QENG_SERVING, "AT+CGMM": "RM520N-GL"}) as modem:
        with _lock_server(tmp_path, modem) as ks:
            row = _await(ks, lambda r: r.get(F + "lock_capable") == 1)
            _set(ks, row, "LTE")
            _set(ks, row, "strategy=stationary")
            row = _await(ks, lambda r: r.get(F + "lock_channel") == "LTE"
                         and r.get(F + "strategy") == "stationary")
            assert modem.levers["mode_pref"] == "LTE"
            pid = row["kismet.datasource.ipc_pid"]
            os.kill(pid, signal.SIGKILL)      # no teardown: the error path
            t0 = time.time()                  # a dead helper sends nothing after this
            row = _new_session(ks, pid, t0, lambda r: r.get(F + "lock_channel") == "LTE"
                               and r.get(F + "strategy") == "stationary",
                               timeout=90.0)
            assert modem.levers["mode_pref"] == "LTE", modem.levers


def test_capture_off_on_comes_back_auto_but_keeps_the_profile(tmp_path):
    """The lock rule's other half: an operator's explicit off means off. The
    modem comes back as found; the (harmless) profile choice is kept."""
    _fresh_server_or_skip()
    with LockableFakeModem(extra={**QENG_SERVING, "AT+CGMM": "RM520N-GL"}) as modem:
        with _lock_server(tmp_path, modem) as ks:
            row = _await(ks, lambda r: r.get(F + "lock_capable") == 1)
            _set(ks, row, "LTE")
            _set(ks, row, "strategy=stationary")
            row = _await(ks, lambda r: r.get(F + "lock_channel") == "LTE"
                         and r.get(F + "strategy") == "stationary")
            pid = row["kismet.datasource.ipc_pid"]
            t0 = _reopen(ks, _uuid(row))
            row = _new_session(ks, pid, t0, lambda r: r.get(F + "strategy") == "stationary"
                               and r.get(F + "lock_channel") == "AUTO")
            time.sleep(6)         # past one more stats interval: no late re-lock
            row = ks.source()
            assert row.get(F + "lock_channel") == "AUTO", row.get(F + "lock_channel")
            assert modem.levers == ORIG, modem.levers


# ── the browser: the operator's journey ──────────────────────────────────────

def test_the_panels_capture_switch_keeps_the_profile_applied_in_the_panel(tmp_path):
    """Apply a profile in the panel, switch Capture off and on in the panel:
    the panel still reads the applied profile, not the definition's Walking.
    (serving_only, not stationary: the panel disables a full-scan profile on
    a modem with no full scan, and the fake has none.)

    The panel row alone cannot prove it: after the re-enable it may still
    show the text it had BEFORE the disable. The REST witness is gated on a
    new helper pid and a stats line stamped after the re-enable; only then is
    the row read."""
    import pytest
    pytest.importorskip("playwright.sync_api")
    from test_cell_web_ui_browser import _Panel, _data_sources
    name = f"cellat-{IMEI}"
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with _data_sources(tmp_path, f"{name}:atport={modem.port},strategy=walking,"
                                     "debug=false") as (ks, page):
            src = page.locator(".k-ds-source", has_text=name).first
            src.wait_for(timeout=30000)
            src.click()
            ui = _Panel(page, name)
            ui.await_row("cellat_profile", "Walking")
            ui.page.locator("tr#cellat_profile select").select_option("serving_only")
            ui.page.locator("tr#cellat_profile button", has_text="Apply").click()
            ui.await_row("cellat_profile", "Serving cell only (serving_only)")
            ui.page.locator("tr#cellat_capture button", has_text="Disable capture").click()
            ui.await_row("cellat_state", "disabled", timeout=40.0)
            pid, t0 = ks.source()["kismet.datasource.ipc_pid"], time.time()
            ui.page.locator("tr#cellat_capture button", has_text="Enable capture").click()
            _new_session(ks, pid, t0, lambda r: r.get(F + "strategy") == "serving_only")
            ui.await_row("cellat_profile", "Serving cell only (serving_only)", timeout=40.0)
