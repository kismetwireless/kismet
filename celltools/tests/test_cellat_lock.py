# SPDX-License-Identifier: Apache-2.0
"""Band/RAT lock as the source's channels -- and never a modem left locked.

The Wi-Fi source's channel buttons, Lock and Hop, for a cell modem. What is
pinned here, through the compiled binary and a fake modem whose AT+QNWPREFCFG
levers are state (a read reports what the last write set):

* **Presets.** A Quectel that answers the lock probe reports its lock presets
  as the open report's channels (AUTO, LTE, NR5G, LTE-B<n>, NR-n<n>), current
  AUTO, and writes nothing at open; a modem that does not answer reports none.
* **Lock.** A channel is written bands-first, then the RAT, and only after the
  settings as found are on disk; the CONFIGREPORT carries it as the source's
  channel (unlike a runtime setting).
* **Restore.** A graceful close restores the modem and removes the state file;
  a killed helper leaves the file, and the next open restores from it; a file
  for another modem is never used and disables locking; a refused write is
  reported and does not stop the restore.

Every lever here lands in a real modem's NV, so every write is asserted
exactly -- the order, the values, and that the modem ends as found.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from fake_at_modem import QENG_SERVING, FakeAtModem
from kismet_capture_ipc import CaptureRun
from test_cellat_ipc import _binary_or_skip

IMEI = "351234567890123"
ORIG = {"mode_pref": "AUTO", "lte_band": "2:4:12:66:71", "nr5g_band": "41:71:77"}
CHANNELS = ["AUTO", "LTE", "NR5G", "LTE-B2", "LTE-B4", "LTE-B12", "LTE-B66",
            "LTE-B71", "NR-n41", "NR-n71", "NR-n77"]


class LockableFakeModem(FakeAtModem):
    """A FakeAtModem whose AT+QNWPREFCFG levers are state.

    Reads answer the current value in the captured RM520N-GL shape; writes
    change it and are recorded in ``writes`` in order. ``refuse`` names levers
    whose writes answer ERROR."""

    _RX = re.compile(r'AT\+QNWPREFCFG="(\w+)"(?:,(.*))?')

    def __init__(self, *, levers=None, refuse=(), **kw):
        kw.setdefault("extra", dict(QENG_SERVING))
        super().__init__(imei=IMEI, **kw)
        self.levers = dict(ORIG if levers is None else levers)
        self.writes: "list[tuple[str, str]]" = []
        self.refuse = set(refuse)

    def response_for(self, cmd: str):
        m = self._RX.fullmatch(cmd)
        if m and m.group(1) in self.levers:
            key, val = m.group(1), m.group(2)
            if val is None:
                return f'\r\n+QNWPREFCFG: "{key}",{self.levers[key]}\r\n\r\nOK\r\n'
            if key in self.refuse:
                return "\r\nERROR\r\n"
            self.writes.append((key, val))
            self.levers[key] = val
            return "\r\nOK\r\n"
        return super().response_for(cmd)


def _stats(run) -> "list[dict]":
    return [json.loads(s) for s in run.cellat_stats]


def _lock_is(ch):
    return lambda run: any(s.get("lock_channel") == ch for s in _stats(run))


def _run(modem, state: Path, *, configure=(), stop_when=None, close_when=None,
         timeout=25.0, tail=""):
    d = f"cellat-{IMEI}:atport={modem.port},debug=false,lockstate={state}"
    if tail:
        d += "," + tail
    return CaptureRun(_binary_or_skip(), d, timeout=timeout, stop_when=stop_when,
                      configure=list(configure), close_when=close_when).run()


def _first_stats(run):
    return bool(run.cellat_stats)


# ── presets ─────────────────────────────────────────────────────────────────
def test_a_lockable_modem_reports_its_presets_and_writes_nothing_at_open(tmp_path):
    with LockableFakeModem() as modem:
        run = _run(modem, tmp_path / "s", stop_when=_first_stats)
    assert run.open_code == 1, run.open_message
    assert run.open_channels == CHANNELS, run.open_channels
    assert run.open_channel == "AUTO"
    assert modem.writes == [], "an OPEN wrote to the modem's NV"
    st = _stats(run)[0]
    assert st["lock_capable"] is True and st["lock_channel"] == "AUTO", st
    assert not (tmp_path / "s").exists(), "a state file with nothing locked"


def test_a_quectel_that_errors_the_probe_has_no_channels(tmp_path):
    """The EG25-G shape: a Quectel whose firmware answers AT+QNWPREFCFG with
    ERROR (every EG25-G build seen so far does). Probed, not assumed from
    the vendor -- so it opens normally with no channels, and a channel sent to
    it is refused with the reason and writes nothing."""
    with LockableFakeModem(levers={}) as modem:
        run = _run(modem, tmp_path / "s", stop_when=lambda r: len(r.config_results) >= 1,
                   configure=[(_first_stats, "LTE-B66")])
    assert run.open_code == 1, run.open_message
    assert not run.open_channels, run.open_channels
    assert _stats(run)[0]["lock_capable"] is False
    assert modem.writes == []
    assert any("no band/RAT lock support" in m for _, m in run.config_results), \
        run.config_results


# ── lock and restore ────────────────────────────────────────────────────────
def test_a_lock_saves_first_writes_bands_then_rat_and_the_close_restores(tmp_path):
    state = tmp_path / "s"
    seen = {}

    def locked(run):
        if _lock_is("LTE-B66")(run) and "file" not in seen:
            seen["file"] = state.read_text() if state.exists() else None
        return _lock_is("LTE-B66")(run)

    with LockableFakeModem() as modem:
        run = _run(modem, state, configure=[(_first_stats, "LTE-B66")],
                   close_when=locked, timeout=30)
        assert modem.writes[:2] == [("lte_band", "66"), ("mode_pref", "LTE")], modem.writes
        # the settings AS FOUND were on disk while the modem was locked
        assert seen["file"] is not None, "locked with no state file"
        assert f"imei={IMEI}" in seen["file"] and "lte_band=2:4:12:66:71" in seen["file"]
        # the CONFIGREPORT carries it: this is the source's channel
        assert "LTE-B66" in run.config_channels, run.config_channels
        # the graceful close restored the modem, bands first, and removed the file
        assert modem.writes[2:] == [("lte_band", ORIG["lte_band"]),
                                    ("mode_pref", ORIG["mode_pref"])], modem.writes
        assert modem.levers == ORIG, modem.levers
    assert not state.exists(), "the restore left the state file behind"


def test_auto_restores_without_a_close(tmp_path):
    state = tmp_path / "s"
    with LockableFakeModem() as modem:
        run = _run(modem, state,
                   configure=[(_first_stats, "NR-n41"), (_lock_is("NR-n41"), "AUTO")],
                   stop_when=lambda r: _lock_is("NR-n41")(r) and
                   _stats(r)[-1].get("lock_channel") == "AUTO")
        assert modem.levers == ORIG, modem.levers
        assert modem.writes == [("nr5g_band", "41"), ("mode_pref", "NR5G"),
                                ("nr5g_band", ORIG["nr5g_band"]),
                                ("mode_pref", ORIG["mode_pref"])], modem.writes
    assert not state.exists()
    assert run.open_code == 1


def test_a_killed_session_is_restored_at_the_next_open(tmp_path):
    """The crash path: SIGTERM runs no teardown (Kismet's hard stop), so the
    modem stays locked and the state file stays -- and the next open restores
    from the FILE, because the modem's own reading is the locked one."""
    state = tmp_path / "s"
    with LockableFakeModem() as modem:
        _run(modem, state, configure=[(_first_stats, "LTE-B12")],
             stop_when=_lock_is("LTE-B12"))       # graceful_close_s=0: SIGTERM
        assert modem.levers["lte_band"] == "12" and modem.levers["mode_pref"] == "LTE"
        assert state.exists(), "a killed locked session left no state file"
        run2 = _run(modem, state, stop_when=_first_stats)
        assert modem.levers == ORIG, modem.levers
        assert not state.exists()
        assert any("restored the band/RAT settings" in m for m in run2.messages), run2.messages
        assert run2.open_channels == CHANNELS, "channels from the FILE's settings"
        assert _stats(run2)[0]["lock_channel"] == "AUTO"


def test_another_modems_state_file_is_never_used(tmp_path):
    state = tmp_path / "s"
    state.write_text("imei=999999999999999\nmode_pref=LTE\nlte_band=66\nnr5g_band=41\n")
    with LockableFakeModem() as modem:
        run = _run(modem, state, configure=[(_first_stats, "LTE-B66")],
                   stop_when=lambda r: len(r.config_results) >= 1)
        assert modem.writes == [], modem.writes
    assert "999999999999999" in state.read_text(), "the foreign file was replaced"
    assert _stats(run)[0]["lock_capable"] is False
    assert any("DISABLED" in m and "999999999999999" in m for m in run.messages), run.messages


def test_a_refused_write_is_reported_and_the_close_still_restores(tmp_path):
    state = tmp_path / "s"
    with LockableFakeModem(refuse={"mode_pref"}) as modem:
        run = _run(modem, state, configure=[(_first_stats, "LTE-B66")],
                   close_when=lambda r: any(s.get("lock_error") for s in _stats(r)),
                   timeout=30)
        err = next(s["lock_error"] for s in _stats(run) if s.get("lock_error"))
        assert 'mode_pref' in err and "ERROR" in err, err
        # the band write landed before the refusal; the close undid it
        assert modem.writes[0] == ("lte_band", "66")
        assert modem.levers == ORIG, modem.levers


def test_a_lock_error_clears_when_a_later_lock_succeeds(tmp_path):
    """The readback must not keep a stale failure: an omitted key keeps the
    server's previous value, so a cleared error has to be SENT as ""."""
    with LockableFakeModem(refuse={"mode_pref"}) as modem:
        def lift(run):
            if any(s.get("lock_error") for s in _stats(run)):
                modem.refuse.clear()
                return True
            return False
        run = _run(modem, tmp_path / "s",
                   configure=[(_first_stats, "LTE-B66"), (lift, "LTE-B12")],
                   stop_when=_lock_is("LTE-B12"))
    last = _stats(run)[-1]
    assert last["lock_channel"] == "LTE-B12", last
    assert last.get("lock_error") == "", f"a stale lock error: {last}"


def test_an_unknown_or_absent_band_is_refused_before_any_write(tmp_path):
    with LockableFakeModem() as modem:
        run = _run(modem, tmp_path / "s",
                   configure=[(_first_stats, "LTE-B99"), (_first_stats, "WCDMA")],
                   stop_when=lambda r: len(r.config_results) >= 2)
        assert modem.writes == []
    msgs = " | ".join(m for _, m in run.config_results)
    assert "LTE band 99" in msgs and "unknown channel 'WCDMA'" in msgs, msgs
    assert "LTE-B99" not in run.config_channels, "a refused channel became the channel"


# ── the panel (browser) ─────────────────────────────────────────────────────
def _browser():
    import pytest
    pytest.importorskip("playwright.sync_api")
    from test_cell_web_ui_browser import _data_sources
    return _data_sources


def _await(pred, timeout=40.0, what=""):
    import time
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = pred()
        if last:
            return last
        time.sleep(0.5)
    raise AssertionError(f"never held: {what}; last={last!r}")


AS_FOUND = "AUTO \u2014 the settings as found"


def _open_panel(page):
    src = page.locator(".k-ds-source", has_text=f"cellat-{IMEI}").first
    src.wait_for(timeout=30000)
    src.click()
    row = page.locator("tr#cellat_lock")
    # The status text, not the phrase: the row's help text also says "the
    # settings as found", so a bare-phrase wait would pass before anything landed.
    _await(lambda: AS_FOUND in (row.inner_text() if row.count() else ""),
           what="the lock row")
    return row


def test_lock_and_unlock_from_the_panel(tmp_path):
    data_sources = _browser()
    with LockableFakeModem(extra={**QENG_SERVING, "AT+CGMM": "RM520N-GL"}) as modem:
        d = f"cellat-{IMEI}:atport={modem.port},debug=false,lockstate={tmp_path / 's'}"
        with data_sources(tmp_path, d) as (ks, page):
            row = _open_panel(page)
            row.locator("select.cellat-lock-select").select_option("LTE-B66")
            row.locator("button.cellat-lock-button").click()
            _await(lambda: "locked to LTE-B66" in row.inner_text(), what="locked row")
            assert modem.levers == {**ORIG, "mode_pref": "LTE", "lte_band": "66"}
            # Kismet's own channel field agrees -- a lock IS the channel
            assert ks.source()["kismet.datasource.channel"] == "LTE-B66"
            row.locator("button.cellat-unlock-button").click()
            _await(lambda: AS_FOUND in row.inner_text() and modem.levers == ORIG,
                   what="unlocked row and restored modem")
            assert modem.levers == ORIG, modem.levers
            assert not (tmp_path / "s").exists()


def test_hop_from_the_panel_survives_a_profile_switch(tmp_path):
    """Hopping across lock channels: a runtime setting arrives on the same
    set_channel route as a channel, and must not cancel the hop."""
    data_sources = _browser()
    with LockableFakeModem(extra={**QENG_SERVING, "AT+CGMM": "RM520N-GL"}) as modem:
        d = f"cellat-{IMEI}:atport={modem.port},debug=false,lockstate={tmp_path / 's'}"
        with data_sources(tmp_path, d) as (ks, page):
            assert ks.source()["kismet.datasource.hopping"] in (0, False), \
                "a cell source was auto-hopped at open"
            row = _open_panel(page)
            row.locator("select.cellat-hop-select").select_option(["LTE-B2", "LTE-B66"])
            row.locator("input.cellat-hop-dwell").fill("5")
            row.locator("button.cellat-hop-button").click()
            _await(lambda: "hopping 2 channels" in row.inner_text(), what="hopping row")
            _await(lambda: {("lte_band", "2"), ("lte_band", "66")} <= set(modem.writes),
                   timeout=30, what="both hop locks written")
            # a profile switch mid-hop (serving_only: this fake has no full-scan
            # command, so the full-scan profiles are offered disabled)
            prof = page.locator("tr#cellat_profile")
            prof.locator("select").select_option("serving_only")
            prof.locator("button", has_text="Apply").click()
            _await(lambda: ks.source()["kismet.datasource.cellat.strategy"] == "serving_only",
                   what="profile switched")
            n = len(modem.writes)
            _await(lambda: len(modem.writes) > n + 1, timeout=20,
                   what="the hop kept writing after the profile switch")
            assert ks.source()["kismet.datasource.hopping"], "the setting stopped the hop"


# ── the RAT-only backends (Sierra AT!SELRAT, the Telit LM960's AT+WS46) ──────
_SELRAT_LIST = ("!SELRAT: Index, Name\r\n00, Automatic\r\n01, WCDMA Only\r\n06, LTE Only\r\n"
                "11, WCDMA and LTE Only\r\n20, NR 5G Only\r\n21, LTE and NR 5G Only\r\n"
                "22, WCDMA and NR 5G Only")       # EM9190 SWIX55C_03.17.04, as captured
_SELRAT_NAMES = {"00": "Automatic", "01": "WCDMA Only", "06": "LTE Only",
                 "20": "NR 5G Only", "21": "LTE and NR 5G Only"}


class SelratFake(FakeAtModem):
    """A Sierra whose AT!SELRAT is state; writes recorded in ``writes``."""

    def __init__(self, idx="00", **kw):
        kw.setdefault("extra", {"AT!GSTATUS?": "!GSTATUS: \nCurrent Time:  1\tTemperature: 40"})
        super().__init__(imei=IMEI, manufacturer="Sierra Wireless, Incorporated", **kw)
        self.idx = idx
        self.writes: "list[str]" = []

    def response_for(self, cmd: str):
        if cmd == "AT!SELRAT?":
            return f"\r\n!SELRAT: {self.idx}, {_SELRAT_NAMES.get(self.idx, '?')}\r\n\r\nOK\r\n"
        if cmd == "AT!SELRAT=?":
            return "\r\n" + _SELRAT_LIST + "\r\n\r\nOK\r\n"
        m = re.fullmatch(r"AT!SELRAT=([0-9A-Fa-f]{2})", cmd)
        if m:
            self.writes.append(m.group(1))
            self.idx = m.group(1)
            return "\r\nOK\r\n"
        return super().response_for(cmd)


class Ws46Fake(FakeAtModem):
    """A Telit LM960 whose AT+WS46 is state (its =? list is (22,28,31))."""

    def __init__(self, cur="31", **kw):
        kw.setdefault("extra", {"AT#RFSTS": ""})      # bare OK: a survey command
        super().__init__(imei=IMEI, manufacturer="Telit", **kw)
        self.cur = cur
        self.writes: "list[str]" = []

    def response_for(self, cmd: str):
        if cmd == "AT+WS46?":
            return f"\r\n+WS46: {self.cur}\r\n\r\nOK\r\n"
        if cmd == "AT+WS46=?":
            return "\r\n+WS46: (22,28,31)\r\n\r\nOK\r\n"
        m = re.fullmatch(r"AT\+WS46=(\d+)", cmd)
        if m:
            self.writes.append(m.group(1))
            self.cur = m.group(1)
            return "\r\nOK\r\n"
        return super().response_for(cmd)


def test_a_sierra_locks_the_rat_by_name_and_the_close_restores(tmp_path):
    state = tmp_path / "s"
    seen = {}

    def locked(run):
        if _lock_is("NR5G")(run) and "file" not in seen:
            seen["file"] = state.read_text() if state.exists() else None
        return _lock_is("NR5G")(run)

    with SelratFake() as modem:
        run = _run(modem, state, configure=[(_first_stats, "NR5G")],
                   close_when=locked, timeout=30)
        assert run.open_code == 1, run.open_message
        assert run.open_channels == ["AUTO", "LTE", "NR5G"], run.open_channels
        # "NR 5G Only" is 20 on this firmware -- read from =?, not assumed
        assert modem.writes == ["20", "00"], modem.writes
        assert modem.idx == "00"
    assert seen["file"] and "backend=selrat" in seen["file"] and "mode_pref=00" in seen["file"]
    assert not state.exists()


def test_a_telit_lm960_locks_lte_through_ws46_and_auto_restores(tmp_path):
    state = tmp_path / "s"
    with Ws46Fake() as modem:
        run = _run(modem, state,
                   configure=[(_first_stats, "LTE"), (_lock_is("LTE"), "AUTO")],
                   stop_when=lambda r: _lock_is("LTE")(r) and
                   _stats(r)[-1].get("lock_channel") == "AUTO")
        assert run.open_code == 1, run.open_message
        assert run.open_channels == ["AUTO", "LTE"], run.open_channels
        assert modem.writes == ["28", "31"], modem.writes
    assert not state.exists()


class CnmpFake(FakeAtModem):
    """A SIMCom SIM8202G-M2 whose AT+CNMP is state. The =? list and the refusal
    of 100 are as a SIM8202G-M2 (LE13B04SIM8202M44A-M2) answers them."""

    def __init__(self, cur="2", **kw):
        kw.setdefault("extra", {"AT+CPSI?": "+CPSI: NR5G_SA,Online,310-260,0x1A2B,"
                                            "123456789,260,NR5G_BAND41,521310,-940,-110,130"})
        super().__init__(imei=IMEI, manufacturer="SIMCOM INCORPORATED", **kw)
        self.cur = cur
        self.writes: "list[str]" = []

    def response_for(self, cmd: str):
        if cmd == "AT+CNMP?":
            return f"\r\n+CNMP: {self.cur}\r\n\r\nOK\r\n"
        if cmd == "AT+CNMP=?":
            return "\r\n+CNMP: (2,14,38,71,54,55,109,100)\r\n\r\nOK\r\n"
        m = re.fullmatch(r"AT\+CNMP=(\d+)", cmd)
        if m:
            if m.group(1) == "100":                 # listed in =?, refused on write
                return "\r\nERROR\r\n"
            self.writes.append(m.group(1))
            self.cur = m.group(1)
            return "\r\nOK\r\n"
        return super().response_for(cmd)


def test_a_simcom_locks_nr5g_through_cnmp_and_the_close_restores(tmp_path):
    state = tmp_path / "s"
    seen = {}

    def locked(run):
        if _lock_is("NR5G")(run) and "file" not in seen:
            seen["file"] = state.read_text() if state.exists() else None
        return _lock_is("NR5G")(run)

    with CnmpFake() as modem:
        run = _run(modem, state, configure=[(_first_stats, "NR5G")],
                   close_when=locked, timeout=30)
        assert run.open_code == 1, run.open_message
        assert run.open_channels == ["AUTO", "LTE", "NR5G"], run.open_channels
        assert modem.writes == ["71", "2"], modem.writes
        assert modem.cur == "2"
    assert seen["file"] and "backend=cnmp" in seen["file"] and "mode_pref=2" in seen["file"]
    assert not state.exists()


def test_a_simcom_found_at_cnmp_100_is_offered_no_lock(tmp_path):
    """100 ("UNKNOW") is a RAT mix with no CNMP mode. The modem lists it in =?
    but answers ERROR to AT+CNMP=100, so a lock from there could never be
    undone: no channels, nothing written, and the reason on the bus."""
    with CnmpFake(cur="100") as modem:
        run = _run(modem, tmp_path / "s", stop_when=_first_stats)
        assert run.open_code == 1, run.open_message
        assert not run.open_channels, run.open_channels
        assert modem.writes == [], modem.writes
    assert _stats(run)[0]["lock_capable"] is False
    assert any("AT+CNMP reads 100" in m for m in run.messages), run.messages


def test_a_state_file_is_never_restored_through_another_command_family(tmp_path):
    state = tmp_path / "s"
    state.write_text(f"imei={IMEI}\nbackend=selrat\nmode_pref=06\nlte_band=\nnr5g_band=\n"
                     "rat_lte=06\nrat_nr=20\n")
    with LockableFakeModem() as modem:          # a Quectel: QNWPREFCFG
        run = _run(modem, state, stop_when=_first_stats)
        assert modem.writes == [], modem.writes
    assert "backend=selrat" in state.read_text(), "the file was replaced"
    assert _stats(run)[0]["lock_capable"] is False
    assert any("command family" in m for m in run.messages), run.messages


class QcfgFake(FakeAtModem):
    """An EG25-G: QNWPREFCFG answers ERROR, AT+QCFG "nwscanmode"/"band" are state
    (the captured A0.301 shapes). ``writes`` records (lever, value)."""

    def __init__(self, **kw):
        kw.setdefault("extra", dict(QENG_SERVING))
        super().__init__(imei=IMEI, firmware="EG25GGBR07A08M2G", **kw)
        self.scanmode = "0"
        self.band = ("0xbff", "0x1e00b0e18df", "0x0")
        self.writes: "list[tuple[str, str]]" = []

    def response_for(self, cmd: str):
        if cmd == 'AT+QCFG="nwscanmode"':
            return f'\r\n+QCFG: "nwscanmode",{self.scanmode}\r\n\r\nOK\r\n'
        if cmd == 'AT+QCFG="band"':
            return '\r\n+QCFG: "band",{},{},{}\r\n\r\nOK\r\n'.format(*self.band)
        m = re.fullmatch(r'AT\+QCFG="nwscanmode",(\d+),1', cmd)
        if m:
            self.writes.append(("nwscanmode", m.group(1)))
            self.scanmode = m.group(1)
            return "\r\nOK\r\n"
        m = re.fullmatch(r'AT\+QCFG="band",([0-9A-Fa-fx]+),([0-9A-Fa-fx]+),([0-9A-Fa-fx]+),1', cmd)
        if m:
            gw, lte, tds = m.groups()
            self.writes.append(("band", f"{gw},{lte},{tds}"))
            # 0 = "no change" (QCFG manual §5.4)
            self.band = (self.band[0] if int(gw, 16) == 0 else "0x" + gw.lower().removeprefix("0x"),
                         self.band[1] if int(lte, 16) == 0 else "0x" + lte.lower().removeprefix("0x"),
                         self.band[2] if int(tds, 16) == 0 else "0x" + tds.lower().removeprefix("0x"))
            return "\r\nOK\r\n"
        return super().response_for(cmd)


def test_an_eg25g_locks_one_lte_band_through_qcfg_and_the_close_restores(tmp_path):
    state = tmp_path / "s"
    with QcfgFake() as modem:
        run = _run(modem, state, configure=[(_first_stats, "LTE-B12")],
                   close_when=_lock_is("LTE-B12"), timeout=30)
        assert run.open_code == 1, run.open_message
        assert run.open_channels[:3] == ["AUTO", "LTE", "LTE-B1"], run.open_channels
        assert "LTE-B41" in run.open_channels and not any(
            c.startswith("NR") for c in run.open_channels)
        # only the LTE mask is written (GSM/WCDMA and TDS = 0 = no change), band first
        assert modem.writes == [("band", "0,800,0"), ("nwscanmode", "3"),
                                ("band", "0,1e00b0e18df,0"), ("nwscanmode", "0")], modem.writes
        assert modem.band == ("0xbff", "0x1e00b0e18df", "0x0"), modem.band
        assert modem.scanmode == "0"
    assert not state.exists()
