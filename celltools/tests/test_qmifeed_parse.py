#!/usr/bin/env python3
"""Tests for qmifeed.parse — qmicli output parsers.

Uses real qmicli output samples captured from EM06-A (MDM9640, LTE)
and RM500Q-AE (SDX55, NR5G).
"""

import unittest

from qmifeed.parse import (
    CellLocationInfo,
    NetworkScanResult,
    ServingSystem,
    SignalInfo,
    SystemInfo,
    parse_cell_location_info,
    parse_network_scan,
    parse_serving_system,
    parse_signal_info,
    parse_system_info,
)

# ---------------------------------------------------------------------------
# Real qmicli output samples
# ---------------------------------------------------------------------------

SIGNAL_INFO_LTE = """\
[/dev/cdc-wdm0] Successfully got signal info
LTE:
\tRSSI: '-71 dBm'
\tRSRQ: '-11.0 dB'
\tRSRP: '-102.0 dBm'
\tSNR: '7.4 dB'
"""

SIGNAL_INFO_LTE_NR = """\
[/dev/cdc-wdm1] Successfully got signal info
LTE:
\tRSSI: '-65 dBm'
\tRSRQ: '-9.5 dB'
\tRSRP: '-95.0 dBm'
\tSNR: '12.0 dB'
5G:
\tRSRP: '-98.0 dBm'
\tSNR: '10.5 dB'
"""

SIGNAL_INFO_ERROR = """\
[/dev/cdc-wdm0] error: couldn't get signal info: QMI protocol error (26): 'NoNetwork'
"""

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
\t\tSelection RX Level Low Threshold: '4'
\t\tCell Selection RX Level High Threshold: '6'
\t\tCell Reselection Priority: '1'
\t\tCell [0]:
\t\t\tPhysical Cell ID: '221'
\t\t\tRSRQ: '-11.1' dB
\t\t\tRSRP: '-97.9' dBm
\t\t\tRSSI: '-69.8' dBm
\t\t\tCell Selection RX Level: '0'
\t\tCell [1]:
\t\t\tPhysical Cell ID: '220'
\t\t\tRSRQ: '-17.3' dB
\t\t\tRSRP: '-110.9' dBm
\t\t\tRSSI: '-84.5' dBm
\t\t\tCell Selection RX Level: '0'
\tFrequency [1]:
\t\tEUTRA Absolute RF Channel Number: '975' (E-UTRA band 2: 1900 PCS)
\t\tSelection RX Level Low Threshold: '4'
\t\tCell Selection RX Level High Threshold: '6'
\t\tCell Reselection Priority: '3'
\t\tCell [0]:
\t\t\tPhysical Cell ID: '221'
\t\t\tRSRQ: '-12.0' dB
\t\t\tRSRP: '-102.6' dBm
\t\t\tRSSI: '-82.9' dBm
\t\t\tCell Selection RX Level: '0'
LTE Info Neighboring GSM
\tUE In Idle: 'yes'
LTE Info Neighboring WCDMA
\tUE In Idle: 'yes'
LTE Timing Advance: 'unavailable'
"""

# NR5G cell location (synthesized from RM500Q survey data + qmicli format).
# PLMN is written as qmicli renders 310-260 (nibble-swapped BCD), not as the
# decimal MCC||MNC '310260'.
CELL_LOCATION_NR5G = """\
[/dev/cdc-wdm1] Successfully got cell location info
NR5G Serving Cell Info:
\tPLMN: '310026'
\tTracking Area Code: '1714944'
\tGlobal Cell ID: '7025029432'
\tNR-ARFCN: '521310'
\tPhysical Cell ID: '596'
\tRSRP: '-98.0' dBm
\tRSRQ: '-11.0' dB
\tSNR: '10.5' dB
"""

SYSTEM_INFO_LTE = """\
[/dev/cdc-wdm0] Successfully got system info
GSM:
\tService status: 'none'
WCDMA:
\tService status: 'none'
LTE:
\tService status: 'limited'
\tTrue service status: 'limited'
\tPreferred data path: 'no'
\tDomain: 'none'
\tRegistration state: 'registered'
\tRoaming: 'on'
\tMCC: '310'
\tMNC: '260'
\tTracking Area Code: '3003'
\tCell ID: '12301088'
"""

NETWORK_SCAN_OUTPUT = """\
[/dev/cdc-wdm0] Successfully scanned for networks
Network [0]:
\tMCC: '311'
\tMNC: '480'
\tStatus: 'current-serving, roaming'
\tDescription: 'Verizon'
\tAccess Technology: 'lte'
Network [1]:
\tMCC: '310'
\tMNC: '260'
\tStatus: 'available'
\tDescription: 'T-Mobile'
\tAccess Technology: 'lte'
Network [2]:
\tMCC: '312'
\tMNC: '530'
\tStatus: 'available'
\tDescription: 'Sprint'
\tAccess Technology: 'umts'
"""

SERVING_SYSTEM_OUTPUT = """\
[/dev/cdc-wdm0] Successfully got serving system:
\tRegistration state: 'registered'
\tCS: 'attached'
\tPS: 'attached'
\tSelected network: '3gpp'
\tData service capabilities [1]:
\t\tlte
\tCurrent PLMN:
\t\tMCC: '311'
\t\tMNC: '480'
\t\tDescription: 'Verizon'
\tRoaming status: 'off'
\tData service domain: 'cs-ps'
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParseSignalInfo(unittest.TestCase):

    def test_lte_only(self):
        info = parse_signal_info(SIGNAL_INFO_LTE)
        self.assertIsNone(info.error)
        self.assertEqual(len(info.rats), 1)
        lte = info.lte()
        self.assertIsNotNone(lte)
        self.assertAlmostEqual(lte.rssi, -71.0)
        self.assertAlmostEqual(lte.rsrp, -102.0)
        self.assertAlmostEqual(lte.rsrq, -11.0)
        self.assertAlmostEqual(lte.sinr, 7.4)

    def test_lte_plus_nr(self):
        info = parse_signal_info(SIGNAL_INFO_LTE_NR)
        self.assertIsNone(info.error)
        self.assertEqual(len(info.rats), 2)
        lte = info.lte()
        nr = info.nr5g()
        self.assertIsNotNone(lte)
        self.assertIsNotNone(nr)
        self.assertAlmostEqual(lte.rsrp, -95.0)
        self.assertAlmostEqual(nr.rsrp, -98.0)
        self.assertAlmostEqual(nr.sinr, 10.5)

    def test_best_rsrp(self):
        info = parse_signal_info(SIGNAL_INFO_LTE_NR)
        self.assertAlmostEqual(info.best_rsrp, -95.0)  # LTE is better

    def test_error_handling(self):
        info = parse_signal_info(SIGNAL_INFO_ERROR)
        self.assertIsNotNone(info.error)
        self.assertEqual(len(info.rats), 0)

    def test_empty_input(self):
        info = parse_signal_info("")
        self.assertIsNone(info.error)
        self.assertEqual(len(info.rats), 0)


class TestQmicliBcdPlmn(unittest.TestCase):
    """qmicli prints the TS 24.008 BCD PLMN bytes low-nibble first.

    Digits arrive as MCC1 MCC2 MCC3 MNC3 MNC1 MNC2, so '311048' is 311-480.
    Ground truth: an EG25-G NAS response frame
    carried TLV bytes 13 01 84 and qmicli printed '311048'; AT+QENG on the
    same tower said 311/480.
    """

    def _render(self, bcd: bytes) -> str:
        # What qmicli does to the TLV bytes: low nibble, then high nibble.
        digits = "0123456789*#abcF"
        return "".join(digits[b & 0xF] + digits[b >> 4] for b in bcd)

    def test_wire_bytes_render_as_qmicli_printed_them(self):
        self.assertEqual(self._render(bytes.fromhex("130184")), "311048")

    def test_three_digit_mnc(self):
        from qmifeed.parse import plmn_from_qmicli_bcd
        self.assertEqual(plmn_from_qmicli_bcd("311048"), ("311", "480"))
        self.assertEqual(plmn_from_qmicli_bcd("310026"), ("310", "260"))

    def test_round_trip_from_bytes(self):
        from qmifeed.parse import plmn_from_qmicli_bcd
        self.assertEqual(plmn_from_qmicli_bcd(self._render(bytes.fromhex("130184"))),
                         ("311", "480"))

    def test_two_digit_mnc_filler(self):
        from qmifeed.parse import plmn_from_qmicli_bcd
        # 262-01: bytes 62 F2 10 -> "26" "2F" "01" -> '262F01'
        self.assertEqual(plmn_from_qmicli_bcd(self._render(bytes.fromhex("62F210"))),
                         ("262", "01"))
        self.assertEqual(plmn_from_qmicli_bcd("262f01"), ("262", "01"))

    def test_unrecognisable_is_empty_not_a_guess(self):
        from qmifeed.parse import plmn_from_qmicli_bcd
        for s in ("", "310", "31004", "3110480", "31a048"):
            self.assertEqual(plmn_from_qmicli_bcd(s), ("", ""), s)


class TestParseCellLocationInfo(unittest.TestCase):

    def test_lte_serving_cell(self):
        cell = parse_cell_location_info(CELL_LOCATION_LTE)
        self.assertIsNone(cell.error)
        self.assertEqual(cell.plmn, "311048")
        self.assertEqual(cell.mcc, "311")
        self.assertEqual(cell.mnc, "480")   # Verizon; qmicli's string is nibble-swapped BCD
        self.assertEqual(cell.tac, 3003)
        self.assertEqual(cell.cid, 12301088)
        self.assertEqual(cell.earfcn, 2050)
        self.assertEqual(cell.pci, 221)

    def test_lte_intra_cells(self):
        cell = parse_cell_location_info(CELL_LOCATION_LTE)
        self.assertEqual(len(cell.intra_cells), 1)
        c = cell.intra_cells[0]
        self.assertEqual(c.pci, 221)
        self.assertAlmostEqual(c.rsrp, -102.2)
        self.assertAlmostEqual(c.rsrq, -10.4)
        self.assertAlmostEqual(c.rssi, -71.9)

    def test_lte_inter_frequencies(self):
        cell = parse_cell_location_info(CELL_LOCATION_LTE)
        self.assertEqual(len(cell.inter_frequencies), 2)

        freq0 = cell.inter_frequencies[0]
        self.assertEqual(freq0.earfcn, 5230)
        self.assertIn("band 13", freq0.band_description)
        self.assertEqual(len(freq0.cells), 2)
        self.assertEqual(freq0.cells[0].pci, 221)
        self.assertEqual(freq0.cells[1].pci, 220)
        self.assertAlmostEqual(freq0.cells[1].rsrp, -110.9)

        freq1 = cell.inter_frequencies[1]
        self.assertEqual(freq1.earfcn, 975)
        self.assertIn("band 2", freq1.band_description)
        self.assertEqual(len(freq1.cells), 1)

    def test_all_cells(self):
        cell = parse_cell_location_info(CELL_LOCATION_LTE)
        all_cells = cell.all_cells
        # 1 intra + 2 on EARFCN 5230 + 1 on EARFCN 975 = 4
        self.assertEqual(len(all_cells), 4)
        earfcns = [e for e, _ in all_cells]
        self.assertIn(2050, earfcns)
        self.assertIn(5230, earfcns)
        self.assertIn(975, earfcns)

    def test_nr5g_cell(self):
        cell = parse_cell_location_info(CELL_LOCATION_NR5G)
        self.assertIsNone(cell.error)
        self.assertEqual(cell.nr_arfcn, 521310)
        self.assertEqual(cell.nr_pci, 596)
        self.assertEqual(cell.nr_tac, 1714944)
        self.assertEqual(cell.nci, 7025029432)
        self.assertEqual((cell.mcc, cell.mnc), ("310", "260"))   # from nibble-swapped BCD
        self.assertAlmostEqual(cell.nr_rsrp, -98.0)
        self.assertAlmostEqual(cell.nr_rsrq, -11.0)
        self.assertAlmostEqual(cell.nr_sinr, 10.5)


class TestParseSystemInfo(unittest.TestCase):

    def test_lte_registered(self):
        info = parse_system_info(SYSTEM_INFO_LTE)
        self.assertIsNone(info.error)
        self.assertEqual(info.gsm_status, "none")
        self.assertEqual(info.wcdma_status, "none")
        self.assertEqual(info.lte_status, "limited")
        self.assertTrue(info.registered)
        self.assertTrue(info.roaming)
        self.assertEqual(info.mcc, "310")
        self.assertEqual(info.mnc, "260")
        self.assertEqual(info.tac, 3003)
        self.assertEqual(info.cid, 12301088)
        self.assertEqual(info.active_rat, "lte")


class TestParseNetworkScan(unittest.TestCase):

    def test_three_networks(self):
        results = parse_network_scan(NETWORK_SCAN_OUTPUT)
        self.assertEqual(len(results), 3)

        verizon = results[0]
        self.assertEqual(verizon.mcc, "311")
        self.assertEqual(verizon.mnc, "480")
        self.assertEqual(verizon.description, "Verizon")
        self.assertEqual(verizon.rat, "lte")
        self.assertIn("current-serving", verizon.status)
        self.assertIn("roaming", verizon.status)

        tmobile = results[1]
        self.assertEqual(tmobile.mcc, "310")
        self.assertEqual(tmobile.mnc, "260")
        self.assertEqual(tmobile.rat, "lte")
        self.assertIn("available", tmobile.status)

        sprint = results[2]
        self.assertEqual(sprint.rat, "umts")

    def test_error_returns_empty(self):
        results = parse_network_scan(
            "[/dev/cdc-wdm0] error: couldn't scan: QMI protocol error (3): 'InternalError'"
        )
        self.assertEqual(results, [])


class TestParseServingSystem(unittest.TestCase):

    def test_registered(self):
        ss = parse_serving_system(SERVING_SYSTEM_OUTPUT)
        self.assertIsNone(ss.error)
        self.assertEqual(ss.registration_state, "registered")
        self.assertEqual(ss.cs_attach_state, "attached")
        self.assertEqual(ss.ps_attach_state, "attached")
        self.assertEqual(ss.selected_network, "3gpp")
        self.assertEqual(ss.mcc, "311")
        self.assertEqual(ss.mnc, "480")
        self.assertEqual(ss.description, "Verizon")
        self.assertFalse(ss.roaming)


if __name__ == "__main__":
    unittest.main()
