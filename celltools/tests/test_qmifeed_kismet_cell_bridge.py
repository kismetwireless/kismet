#!/usr/bin/env python3
"""Tests for qmifeed.kismet_cell_bridge — QMI → Kismet cell_observation JSON.

Feeds real qmicli cell-location-info samples (shared with test_qmifeed_parse.py)
through parse_cell_location_info → cell_location_to_observations, and asserts
the emitted JSON matches the build_cell_json contract that
capture_cell_at / phy_cell consume.
"""

import json
import unittest

from qmifeed.parse import (
    CellLocationInfo,
    CellMeasurement,
    FrequencyInfo,
    RATSignal,
    SignalInfo,
    parse_cell_location_info,
)
from qmifeed.kismet_cell_bridge import (
    QMI_ORIGIN,
    cell_location_to_observations,
    observations_to_ndjson,
)

# Real qmicli output (same shape as qmifeed/test_qmifeed_parse.py).
CELL_LOCATION_LTE = """\
[/dev/cdc-wdm0] Successfully got cell location info
Intrafrequency LTE Info
\tUE In Idle: 'yes'
\tPLMN: '311048'
\tTracking Area Code: '3003'
\tGlobal Cell ID: '12301088'
\tEUTRA Absolute RF Channel Number: '2050' (E-UTRA band 4: AWS-1)
\tServing Cell ID: '221'
\tCell Reselection Priority: '6'
\tS Non Intra Search Threshold: '8'
\tServing Cell Low Threshold: '4'
\tS Intra Search Threshold: '255'
\tCell [0]:
\t\tPhysical Cell ID: '221'
\t\tRSRQ: '-10.4' dB
\t\tRSRP: '-102.2' dBm
\t\tRSSI: '-71.9' dBm
\t\tCell Selection RX Level: '21'
Interfrequency LTE Info
\tUE In Idle: 'yes'
\tFrequency [0]:
\t\tEUTRA Absolute RF Channel Number: '5230' (E-UTRA band 13: 700 c)
\t\tCell [0]:
\t\t\tPhysical Cell ID: '221'
\t\t\tRSRQ: '-11.1' dB
\t\t\tRSRP: '-97.9' dBm
\t\t\tRSSI: '-69.8' dBm
\t\tCell [1]:
\t\t\tPhysical Cell ID: '220'
\t\t\tRSRQ: '-17.3' dB
\t\t\tRSRP: '-110.9' dBm
\t\t\tRSSI: '-84.5' dBm
\tFrequency [1]:
\t\tEUTRA Absolute RF Channel Number: '975' (E-UTRA band 2: 1900 PCS)
\t\tCell [0]:
\t\t\tPhysical Cell ID: '221'
\t\t\tRSRQ: '-12.0' dB
\t\t\tRSRP: '-102.6' dBm
\t\t\tRSSI: '-82.9' dBm
LTE Timing Advance: 'unavailable'
"""


def _serving(observations):
    return [o for o in observations if o["is_serving"]]


def _neighbours(observations):
    return [o for o in observations if not o["is_serving"]]


class TestServingCell(unittest.TestCase):
    def setUp(self):
        cell = parse_cell_location_info(CELL_LOCATION_LTE)
        self.obs = cell_location_to_observations(
            cell, imei="359072060000000", captured_at=1712300000.5)

    def test_exactly_one_serving_cell(self):
        self.assertEqual(len(_serving(self.obs)), 1)

    def test_serving_identity_fields(self):
        s = _serving(self.obs)[0]
        self.assertEqual(s["rat"], "LTE")
        self.assertEqual(s["mcc"], "311")
        self.assertEqual(s["mnc"], "480")   # BCD PLMN: 311048 is MCC 311, MNC 480
        self.assertEqual(s["cell_id"], 12301088)
        self.assertEqual(s["pci"], 221)
        self.assertEqual(s["tac"], 3003)
        self.assertEqual(s["earfcn"], 2050)
        self.assertEqual(s["observation_type"], "serving")
        self.assertIs(s["is_serving"], True)

    def test_serving_signal_from_intra_measurement(self):
        # Serving signal comes from the intra Cell[0] with matching PCI 221,
        # rounded to the integer the schema types.
        s = _serving(self.obs)[0]
        self.assertEqual(s["rsrp"], -102)   # -102.2 → -102
        self.assertEqual(s["rsrq"], -10)    # -10.4  → -10
        self.assertEqual(s["rssi"], -72)    # -71.9  → -72

    def test_serving_prov_block(self):
        prov = _serving(self.obs)[0]["prov"]
        self.assertEqual(prov["src"], "qmi")
        self.assertEqual(prov["origin"], QMI_ORIGIN)
        self.assertEqual(prov["imei"], "359072060000000")
        self.assertEqual(prov["captured_at"], 1712300000.5)

    def test_no_band_key_emitted(self):
        # QMI must not emit a (possibly wrong) band; band derivation is
        # the consumer's job on a full-width channel.
        for o in self.obs:
            self.assertNotIn("band", o)

    def test_earfcn_ambiguous_flag_present(self):
        # EARFCN 2050 <= 0xFFFF ⇒ could be a 16-bit truncation.
        prov = _serving(self.obs)[0]["prov"]
        self.assertTrue(prov["earfcn_ambiguous"])


class TestNeighbours(unittest.TestCase):
    def setUp(self):
        cell = parse_cell_location_info(CELL_LOCATION_LTE)
        self.obs = cell_location_to_observations(cell)

    def test_neighbour_count(self):
        # Inter-freq: B13 has 2 cells (PCI 221, 220), B2 has 1 (PCI 221).
        # Intra has only the serving cell, so 0 intra neighbours. Total 3.
        self.assertEqual(len(_neighbours(self.obs)), 3)

    def test_serving_intra_cell_not_double_emitted(self):
        # PCI 221 on the SERVING earfcn 2050 must appear once, as the serving
        # cell — never also as a neighbour on 2050.
        on_serving_freq = [o for o in self.obs
                           if o.get("earfcn") == 2050 and o["pci"] == 221]
        self.assertEqual(len(on_serving_freq), 1)
        self.assertTrue(on_serving_freq[0]["is_serving"])

    def test_same_pci_different_earfcn_is_kept(self):
        # PCI 221 legitimately recurs on 5230 and 975 — distinct cells.
        pci221 = sorted(o["earfcn"] for o in self.obs if o["pci"] == 221)
        self.assertEqual(pci221, [975, 2050, 5230])

    def test_neighbours_have_no_identity(self):
        # QMI cell-location-info does not resolve neighbour MCC/MNC/CID/TAC.
        for n in _neighbours(self.obs):
            self.assertNotIn("mcc", n)
            self.assertNotIn("cell_id", n)
            self.assertNotIn("tac", n)
            self.assertEqual(n["observation_type"], "observation")

    def test_neighbour_signal_rounded(self):
        b13_220 = next(o for o in self.obs
                       if o.get("earfcn") == 5230 and o["pci"] == 220)
        self.assertEqual(b13_220["rsrp"], -111)   # -110.9 → -111
        self.assertEqual(b13_220["rssi"], -84)    # -84.5  → -84 (round-half-even)


class TestNR5GServing(unittest.TestCase):
    def test_nr_serving_cell_emitted(self):
        cell = CellLocationInfo(
            mcc="311", mnc="480",
            nr_pci=500, nci=7025029432, nr_tac=12345,
            nr_arfcn=650000, nr_rsrp=-88.0, nr_rsrq=-12.0, nr_sinr=15.0,
        )
        obs = cell_location_to_observations(cell, imei="X")
        nr = [o for o in obs if o["rat"] == "NR"]
        self.assertEqual(len(nr), 1)
        s = nr[0]
        self.assertEqual(s["cell_id"], 7025029432)   # NCI — AT#RFSTS omits it
        self.assertEqual(s["pci"], 500)
        self.assertEqual(s["earfcn"], 650000)
        self.assertEqual(s["rsrp"], -88)
        self.assertTrue(s["is_serving"])

    def test_nr_arfcn_ambiguous_false_when_wide(self):
        cell = CellLocationInfo(nr_pci=1, nr_arfcn=650000)
        obs = cell_location_to_observations(cell)
        # 650000 > 0xFFFF ⇒ definitely not truncated.
        self.assertFalse(obs[0]["prov"]["earfcn_ambiguous"])


class TestSignalFallback(unittest.TestCase):
    def test_serving_signal_backfilled_from_signal_info(self):
        # Identity present but no intra Cell[] measurement block.
        cell = CellLocationInfo(mcc="310", mnc="410", cid=100, pci=42,
                                tac=7, earfcn=2050)
        sig = SignalInfo(rats=[RATSignal(rat="lte", rsrp=-95.6, rsrq=-9.0,
                                         sinr=8.0, rssi=-65.0)])
        obs = cell_location_to_observations(cell, signal=sig)
        s = _serving(obs)[0]
        self.assertEqual(s["rsrp"], -96)
        self.assertEqual(s["sinr"], 8)


class TestNDJSON(unittest.TestCase):
    def test_each_line_is_valid_json_object(self):
        cell = parse_cell_location_info(CELL_LOCATION_LTE)
        obs = cell_location_to_observations(cell)
        text = observations_to_ndjson(obs)
        lines = text.split("\n")
        self.assertEqual(len(lines), len(obs))
        for line in lines:
            parsed = json.loads(line)   # raises if any line is malformed
            self.assertEqual(parsed["prov"]["src"], "qmi")

    def test_empty_input_yields_empty_string(self):
        self.assertEqual(observations_to_ndjson([]), "")


class TestEmptyCell(unittest.TestCase):
    def test_no_serving_pci_yields_no_lte_serving(self):
        # A cell with only neighbours (no serving identity) emits no serving.
        cell = CellLocationInfo(
            inter_frequencies=[FrequencyInfo(
                earfcn=5230, cells=[CellMeasurement(pci=7, rsrp=-100.0)])])
        obs = cell_location_to_observations(cell)
        self.assertEqual(_serving(obs), [])
        self.assertEqual(len(_neighbours(obs)), 1)


if __name__ == "__main__":
    unittest.main()
