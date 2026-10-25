# SPDX-License-Identifier: Apache-2.0
"""qmifeed= through a REAL Kismet server: QMI and AT merge into ONE tower.

``test_cellat_qmifeed.py`` proves the capture child relays the feed's lines;
it plays the server itself, so it cannot see what ``phy_cell`` does with them.
This file runs an isolated ``kismet`` (``KismetServer``) with a cellat source on
a fake modem whose ``+QENG`` serving cell is 311/480 TAC 0xBBB CI 0xBBB320, and
a feed that reports that same tower over QMI. What it pins:

* the tower is ONE device, and its ``seen_via`` carries both ``at`` and
  ``qmi`` -- the merge is keyed on identity, not on which pipe saw it;
* QMI's own contributed fields are recorded under ``qmi``.

The merge needs the two pipes to agree on mcc/mnc byte for byte. A QMI parser
that reads qmicli's nibble-swapped BCD PLMN '311048' as 311/048 instead of
311/480 makes the server split this tower in two. The case below feeds the
CORRECT decode; the split case is pinned so a regression there is
seen here as two devices, not as a quiet loss of the QMI half.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from fake_at_modem import QENG_SERVING, FakeAtModem
from test_celldiag_server_routes import KismetServer
from test_cellat_server_fields import _fresh_server_or_skip

IMEI = "351234567890123"
TOWER_CI = 0xBBB320          # QENG_SERVING's cell id, 12301088


def _qmi_serving(mnc: str) -> dict:
    return {"rat": "LTE", "mcc": "311", "mnc": mnc, "tac": 0xBBB,
            "cell_id": TOWER_CI, "pci": 221, "earfcn": 66536, "rsrp": -96,
            "observation_type": "serving", "is_serving": True,
            "prov": {"src": "qmi", "origin": "nas-get-cell-location-info",
                     "imei": IMEI}}


def _seen_via(dev: dict) -> dict:
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "cellular.cell.seen_via":
                    yield v
                yield from walk(v)
        elif isinstance(o, list):
            for v in o:
                yield from walk(v)
    return next(walk(dev), {}) or {}


def _towers(devices: list) -> "list[dict]":
    return [d for d in devices if str(TOWER_CI) in json.dumps(d)
            and _seen_via(d)]


def _serve(tmp: Path, mnc: str, until) -> list:
    _fresh_server_or_skip()
    feed = tmp / "feed.sh"
    feed.write_text(f"while :; do echo '{json.dumps(_qmi_serving(mnc))}'; "
                    "sleep 1; done\n")
    with FakeAtModem(imei=IMEI, extra=QENG_SERVING) as modem:
        with KismetServer(tmp, f"cellat-{IMEI}:atport={modem.port},"
                               f"debug=false,qmifeed=/bin/sh {feed}") as ks:
            deadline = time.monotonic() + 40.0
            devices: list = []
            while time.monotonic() < deadline:
                devices = ks.get("devices/views/all/devices.json") or []
                if until(devices):
                    return devices
                time.sleep(0.5)
            raise AssertionError(
                f"condition never held; towers: "
                f"{[ (d.get('kismet.device.base.name'), sorted(_seen_via(d))) for d in _towers(devices)]}"
                f"\n{ks.tail()}")


def test_qmi_and_at_sightings_of_one_tower_merge_into_one_device(tmp_path):
    def merged(devices):
        return any({"at", "qmi"} <= set(_seen_via(d)) for d in _towers(devices))

    devices = _serve(tmp_path, "480", merged)
    towers = _towers(devices)
    assert len(towers) == 1, [d.get("kismet.device.base.name") for d in towers]
    via = _seen_via(towers[0])
    assert {"at", "qmi"} <= set(via), sorted(via)
    qmi = {k.split(".")[-1]: v for k, v in via["qmi"].items()}
    assert qmi["origin"] == "nas-get-cell-location-info", qmi
    assert {"mcc", "mnc", "cell_id", "tac"} <= set(qmi["fields"]), qmi


def test_a_scrambled_mnc_splits_the_tower_so_it_is_seen(tmp_path):
    # The wrong, non-swapped QMI decode (311/048). The server must not "helpfully" merge
    # it -- mnc is identity -- so the tower shows up twice, one per pipe.
    def split(devices):
        vias = [set(_seen_via(d)) for d in _towers(devices)]
        return {"at"} in [v & {"at", "qmi"} for v in vias] and \
               {"qmi"} in [v & {"at", "qmi"} for v in vias]

    devices = _serve(tmp_path, "048", split)
    assert len(_towers(devices)) == 2
