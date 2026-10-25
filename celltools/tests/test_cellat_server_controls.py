# SPDX-License-Identifier: Apache-2.0
"""The cellat panel's controls, driven through a REAL Kismet server.

The panel's controls are HTTP calls; the IPC tests prove the helper side. This
file proves the server side, calling the routes exactly as the panel does:

* **the profile switch** -- ``POST set_channel.cmd {"channel":"strategy=…"}``
  reaches the running helper (``set_tune_capable(true)``), the reported
  profile changes, and ``kismet.datasource.channel`` stays EMPTY: a
  setting is not a channel, so the server has nothing to display as one and
  nothing to replay after an error re-open;
* **enable / disable capture** -- a source defined ``enabled=false``
  is turned ON from the UI by ``close_source -> update_definition
  {"options":{"enabled":"true"}} -> open_source``. Activate and Restart
  re-open the same definition, so this sequence is the only way to switch a
  source defined disabled on. And the reverse.

The controls deliberately read nothing from the transport (a refused
setting answers success), so these tests assert on the FIELDS, exactly as the
panel does.
"""
from __future__ import annotations

import time

from fake_at_modem import QENG_SERVING, FakeAtModem
from test_cellat_server_fields import F, IMEI, _await, _fresh_server_or_skip
from test_celldiag_server_routes import KismetServer


def _uuid(row: dict) -> str:
    return row["kismet.datasource.uuid"]


def test_set_channel_switches_the_profile_and_leaves_the_channel_empty(tmp_path):
    _fresh_server_or_skip()
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with KismetServer(tmp_path, f"cellat-{IMEI}:atport={modem.port},"
                                    "strategy=walking,debug=false") as ks:
            row = _await(ks, lambda r: r.get(F + "strategy") == "walking")
            status, _ = ks.post(
                f"datasource/by-uuid/{_uuid(row)}/set_channel.cmd",
                {"channel": "strategy=stationary"})
            assert status == 200
            row = _await(ks, lambda r: r.get(F + "strategy") == "stationary")
            assert row[F + "fullscan_interval_ms"] == 60000
            assert row["kismet.datasource.channel"] == "", (
                "a runtime SETTING was recorded as the source's channel: "
                f"{row['kismet.datasource.channel']!r}")
            assert modem.commands.count("AT+CGSN") == 1, (
                "the switch restarted the source; it must not")


def _toggle_enabled(ks: KismetServer, uuid: str, want: str) -> None:
    """The panel's sequence: close FIRST (the route refuses a running
    source), then the definition update, then the reopen."""
    base = f"datasource/by-uuid/{uuid}/"
    ks.get(base + "close_source.cmd")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and ks.source()["kismet.datasource.running"]:
        time.sleep(0.2)
    status, _ = ks.post(base + "update_definition.cmd", {"options": {"enabled": want}})
    assert status == 200
    ks.get(base + "open_source.cmd")


def test_a_source_defined_disabled_can_be_enabled_from_the_ui_and_back(tmp_path):
    """The anchor: the UI can turn a source defined `enabled=false` on, and
    back off."""
    _fresh_server_or_skip()
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with KismetServer(tmp_path, f"cellat-{IMEI}:atport={modem.port},"
                                    "enabled=false,debug=false") as ks:
            row = _await(ks, lambda r: r.get(F + "state") == "disabled")
            assert modem.commands == [], "a disabled source touched the modem"

            _toggle_enabled(ks, _uuid(row), "true")
            row = _await(ks, lambda r: r.get(F + "state") == "surveying"
                         and r.get(F + "obs_total", 0) > 0)
            assert row[F + "at_port"] == modem.port
            assert "AT+CGSN" in modem.commands

            _toggle_enabled(ks, _uuid(row), "false")
            row = _await(ks, lambda r: r.get(F + "state") == "disabled")
            # Counted AFTER the disabled source reported, so a poll that was in
            # flight during the close is not mistaken for the new one talking.
            before = len(modem.commands)
            time.sleep(2.5)   # a serving poll interval: nothing may reach the port
            assert len(modem.commands) == before, (
                "a source switched to enabled=false kept talking to the modem: "
                f"{modem.commands[before:]}")
