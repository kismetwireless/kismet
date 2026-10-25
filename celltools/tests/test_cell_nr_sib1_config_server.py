# SPDX-License-Identifier: Apache-2.0
"""An NR row's SIB1 cell config through a REAL Kismet server.

The DIAG leg stamps every NR row of a cell whose SIB1 it has decoded with that
SIB1's servingCellConfigCommon headline: ``band``, ``carrier_scs``,
``bandwidth_rb`` and ``bandwidth`` (both decode paths, byte for byte).
``phy_cell``'s ``json_to_cell`` maps observation keys onto the ``Cellular``
record without regard to the RAT, so two of them need no server change:

* ``band`` -> ``cellular.cell.band``;
* ``bandwidth`` (MHz) -> ``cellular.cell.bandwidth``.

``carrier_scs`` and ``bandwidth_rb`` have no tracked field (nor do the
existing ``scs`` and ``tx_antennas``). The server ignores them, which this pins
too: an unknown key must not cost the row. Giving them fields is a schema and UI
decision, still open.

The row goes in through cellat's ``qmifeed=`` relay, the one offline path that
hands ``phy_cell`` an arbitrary observation line. ``json_to_cell`` is the same
function for every cell source, so the pipe that carried the line does not
change what this pins. Identity values are synthetic (test PLMN 001/01).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from fake_at_modem import QENG_SERVING, FakeAtModem
from test_celldiag_server_routes import KismetServer
from test_cellat_server_fields import _fresh_server_or_skip

IMEI = "351234567890123"
NR_CI = 0x123456789          # a 36-bit NCI, synthetic


def _nr_row(**config) -> dict:
    row = {"rat": "NR", "mcc": "001", "mnc": "01", "tac": 1, "cell_id": NR_CI,
           "pci": 31, "earfcn": 521310, "observation_type": "serving",
           "is_serving": True, "rsrp": -90,
           "prov": {"src": "qmi", "origin": "test-5010", "imei": IMEI}}
    row.update(config)
    return row


def _fields(dev: dict) -> dict:
    """Every ``cellular.cell.*`` key anywhere in one device, flattened."""
    out: dict = {}

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k.startswith("cellular.cell."):
                    out.setdefault(k, v)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(dev)
    return out


def _nr_towers(devices: list) -> "list[dict]":
    return [d for d in devices if str(NR_CI) in json.dumps(d)]


def _serve(tmp: Path, row: dict, until) -> list:
    _fresh_server_or_skip()
    feed = tmp / "feed.sh"
    feed.write_text(f"while :; do echo '{json.dumps(row)}'; sleep 1; done\n")
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
                f"condition never held; NR towers: "
                f"{[_fields(d) for d in _nr_towers(devices)]}\n{ks.tail()}")


def test_nr_band_and_bandwidth_land_on_the_cellular_record(tmp_path):
    row = _nr_row(band=41, carrier_scs=30, bandwidth_rb=245, bandwidth=90)

    def landed(devices):
        return any(_fields(d).get("cellular.cell.band") == 41
                   for d in _nr_towers(devices))

    devices = _serve(tmp_path, row, landed)
    towers = _nr_towers(devices)
    assert len(towers) == 1, [d.get("kismet.device.base.name") for d in towers]
    f = _fields(towers[0])
    assert f["cellular.cell.rat"] == "NR"
    assert f["cellular.cell.band"] == 41
    assert f["cellular.cell.bandwidth"] == 90


def test_an_nr_row_without_mhz_leaves_bandwidth_unset(tmp_path):
    """A non-table N_RB: the decoders omit ``bandwidth`` and keep
    ``bandwidth_rb``. The record then keeps its registered default (0), never
    an RB count read as MHz."""
    row = _nr_row(band=41, carrier_scs=30, bandwidth_rb=200)

    def landed(devices):
        return any(_fields(d).get("cellular.cell.band") == 41
                   for d in _nr_towers(devices))

    devices = _serve(tmp_path, row, landed)
    f = _fields(_nr_towers(devices)[0])
    assert f["cellular.cell.bandwidth"] == 0
