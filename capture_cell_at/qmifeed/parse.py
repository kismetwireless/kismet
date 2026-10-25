#!/usr/bin/env python3
"""Parse qmicli text output into structured Python data.

qmicli (libqmi's CLI tool) returns human-readable indented text. This module
parses the output of key NAS commands into typed dataclasses suitable for
consumption by QMIEngine, the identity tracker, and the WiGLE pipeline.

Supported commands:
    --nas-get-signal-info        → SignalInfo
    --nas-get-cell-location-info → CellLocationInfo
    --nas-get-system-info        → SystemInfo
    --nas-network-scan           → list[NetworkScanResult]
    --nas-get-serving-system     → ServingSystem

Usage:
    from qmifeed.parse import parse_signal_info, parse_cell_location_info
    info = parse_signal_info(qmicli_stdout)
    cell = parse_cell_location_info(qmicli_stdout)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RATSignal:
    """Signal measurements for one RAT."""
    rat: str                        # "lte", "nr5g", "wcdma", "gsm", "cdma"
    rssi: Optional[float] = None    # dBm
    rsrp: Optional[float] = None    # dBm (LTE/NR)
    rsrq: Optional[float] = None    # dB (LTE/NR)
    sinr: Optional[float] = None    # dB (LTE SNR / NR SNR)
    rscp: Optional[float] = None    # dBm (WCDMA)
    ecio: Optional[float] = None    # dB (WCDMA)


@dataclass
class SignalInfo:
    """Parsed output of qmicli --nas-get-signal-info."""
    rats: list[RATSignal] = field(default_factory=list)
    error: Optional[str] = None

    def lte(self) -> Optional[RATSignal]:
        return next((r for r in self.rats if r.rat == "lte"), None)

    def nr5g(self) -> Optional[RATSignal]:
        return next((r for r in self.rats if r.rat == "nr5g"), None)

    @property
    def best_rsrp(self) -> Optional[float]:
        """Best (highest) RSRP across all RATs."""
        vals = [r.rsrp for r in self.rats if r.rsrp is not None]
        return max(vals) if vals else None


@dataclass
class CellMeasurement:
    """A single cell measurement from cell location info."""
    pci: Optional[int] = None
    rsrp: Optional[float] = None    # dBm
    rsrq: Optional[float] = None    # dB
    rssi: Optional[float] = None    # dBm


# ---------------------------------------------------------------------------
# QMI's 16-bit EARFCN TLV
# ---------------------------------------------------------------------------
#
# QMI carries EARFCN in a 16-bit TLV, so any true EARFCN >= 65536 arrives
# wrapped — and libqmi then prints a confidently-wrong band label for the
# wrapped value. Confirmed on three vendors and three chipset generations
# (Foxconn T99W175/SDX, Telit LM960/SDX20, Quectel RM520N-GL/SDX62).
#
# The nasty property is that a truncated value and a genuine one are
# **byte-identical**: `1375` is a real B3 channel *and* what `66911` (B66)
# wraps to. No single record can be audited. The only decidable thing is
# whether the value COULD have been truncated, which is what these carry —
# an explicit "maybe" beats a plausible wrong number.
#
# Every band whose EARFCN exceeds 65535 is affected: 66, 71, 46, 48 — i.e.
# exactly the bands the US carriers are actively deploying.
QMI_EARFCN_TLV_MAX = 0xFFFF


def earfcn_is_ambiguous(earfcn: Optional[int]) -> bool:
    """True if this QMI-sourced EARFCN might be a 16-bit truncation.

    **Only meaningful for QMI-sourced values.** AT and DIAG-RRC report
    the full 32-bit channel number, so a low value from those sources is
    simply a low EARFCN. (DIAG log code ``0xB197`` is a separate case —
    the *firmware* truncates there.)

    ``False`` is the only verdict that is certain: a value that survived
    the 16-bit boundary was never truncated. ``True`` means *undecided*,
    not *wrong* — resolving it needs a second source for the same cell.
    """
    return earfcn is not None and earfcn <= QMI_EARFCN_TLV_MAX


@dataclass
class FrequencyInfo:
    """Cells on a single frequency (EARFCN)."""
    earfcn: Optional[int] = None
    band_description: str = ""      # e.g. "E-UTRA band 4: AWS-1"
    cells: list[CellMeasurement] = field(default_factory=list)

    @property
    def earfcn_ambiguous(self) -> bool:
        """See :func:`earfcn_is_ambiguous` — this value may be truncated.

        When True, ``band_description`` is equally suspect: libqmi
        derives it from the same possibly-wrapped number, which is what
        makes this worse than a plain numeric error — the wrong band
        *name* is generated downstream and reads as authoritative.
        """
        return earfcn_is_ambiguous(self.earfcn)


@dataclass
class CellLocationInfo:
    """Parsed output of qmicli --nas-get-cell-location-info."""
    # Serving cell identity (from intrafrequency section)
    plmn: str = ""                  # e.g. "311048"
    mcc: str = ""
    mnc: str = ""
    tac: Optional[int] = None       # Tracking Area Code
    cid: Optional[int] = None       # Global Cell ID (E-UTRAN Cell ID)
    earfcn: Optional[int] = None    # Serving EARFCN
    pci: Optional[int] = None       # Serving Physical Cell ID

    # NR5G fields (from NR5G section if present)
    nr_arfcn: Optional[int] = None
    nr_pci: Optional[int] = None
    nr_tac: Optional[int] = None
    nci: Optional[int] = None       # NR Cell Identity (36-bit)
    nr_rsrp: Optional[float] = None
    nr_rsrq: Optional[float] = None
    nr_sinr: Optional[float] = None

    # Intrafrequency cells (serving + neighbors on same EARFCN)
    intra_cells: list[CellMeasurement] = field(default_factory=list)
    # Interfrequency neighbors (grouped by EARFCN)
    inter_frequencies: list[FrequencyInfo] = field(default_factory=list)

    timing_advance: Optional[int] = None
    error: Optional[str] = None

    @property
    def earfcn_ambiguous(self) -> bool:
        """Serving EARFCN may be a 16-bit truncation; see QMI_EARFCN_TLV_MAX."""
        return earfcn_is_ambiguous(self.earfcn)

    @property
    def nr_arfcn_ambiguous(self) -> bool:
        """NR ARFCN may be a 16-bit truncation.

        Far likelier to bite than the LTE case: NR-ARFCN runs to
        3,279,165, so on FR1 mid-band nearly every real value exceeds
        65535 and this is ``True`` for essentially any NR cell whose
        ARFCN survived as a small number.
        """
        return earfcn_is_ambiguous(self.nr_arfcn)

    @property
    def all_cells(self) -> list[tuple[int, CellMeasurement]]:
        """All observed cells as (earfcn, measurement) pairs.

        The EARFCNs here are bare ints and may be truncated — use
        :meth:`all_cells_annotated` when the consumer keys or joins on
        the frequency. Kept as-is for callers that only need the pairing.
        """
        return [(e, c) for e, c, _ in self.all_cells_annotated]

    @property
    def all_cells_annotated(self) -> list[tuple[int, CellMeasurement, bool]]:
        """All observed cells as ``(earfcn, measurement, ambiguous)``.

        The third element is the 16-bit truncation flag. Anything that
        **keys** on EARFCN — the wardrive identity DB keys ``(pci,
        earfcn)`` — needs it: a truncated value does not merely mislabel
        a band, it files the cell at the wrong frequency, where it can
        collide with an unrelated cell that genuinely lives there.
        """
        result: list[tuple[int, CellMeasurement, bool]] = []
        if self.earfcn is not None:
            amb = self.earfcn_ambiguous
            for c in self.intra_cells:
                result.append((self.earfcn, c, amb))
        for freq in self.inter_frequencies:
            if freq.earfcn is not None:
                for c in freq.cells:
                    result.append((freq.earfcn, c, freq.earfcn_ambiguous))
        return result


@dataclass
class SystemInfo:
    """Parsed output of qmicli --nas-get-system-info."""
    # Per-RAT service status
    gsm_status: str = ""
    wcdma_status: str = ""
    lte_status: str = ""
    nr5g_status: str = ""

    # Registration details (from the active RAT)
    registered: bool = False
    roaming: bool = False
    mcc: str = ""
    mnc: str = ""
    tac: Optional[int] = None
    cid: Optional[int] = None
    active_rat: str = ""            # "lte", "nr5g", "wcdma", etc.

    error: Optional[str] = None


@dataclass
class NetworkScanResult:
    """One network from qmicli --nas-network-scan."""
    mcc: str = ""
    mnc: str = ""
    description: str = ""
    status: list[str] = field(default_factory=list)  # "current", "available", "forbidden"
    rat: str = ""                   # "lte", "umts", "gsm", "nr5g"


@dataclass
class ServingSystem:
    """Parsed output of qmicli --nas-get-serving-system."""
    registration_state: str = ""    # "registered", "not-registered", etc.
    cs_attach_state: str = ""
    ps_attach_state: str = ""
    selected_network: str = ""      # "3gpp", "3gpp2"
    mcc: str = ""
    mnc: str = ""
    description: str = ""
    roaming: bool = False
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Low-level text parsing helpers
# ---------------------------------------------------------------------------

_QMICLI_BCD_PLMN_RE = re.compile(r"(\d{3})([\dFf])(\d{2})")


def plmn_from_qmicli_bcd(s: str) -> tuple[str, str]:
    """(mcc, mnc) from qmicli's rendering of a TS 24.008 BCD PLMN.

    qmicli prints the TLV's 3 PLMN bytes one at a time, LOW nibble first, so
    the six characters are MCC1 MCC2 MCC3 MNC3 MNC1 MNC2 -- not MCC||MNC.
    Bytes 13 01 84 (311-480, Verizon) print as '311048'; 13 00 62 (310-260,
    T-Mobile) as '310026'. MNC3 is 'F' filler for a two-digit MNC.

    Anything else returns ('', ''), never a guess. (Whether this qmicli
    renders the filler as 'F' or ends the string there is unverified; a
    short string reads as unknown.)
    """
    m = _QMICLI_BCD_PLMN_RE.fullmatch(s or "")
    if not m:
        return "", ""
    mcc, mnc3, mnc12 = m.groups()
    return mcc, mnc12 + ("" if mnc3 in "Ff" else mnc3)


def _extract_value(text: str) -> str:
    """Extract the single-quoted value from a qmicli output line.

    Examples:
        "RSRP: '-102.2' dBm"  → "-102.2"
        "UE In Idle: 'yes'"    → "yes"
        "PLMN: '311048'"      → "311048"
    """
    m = re.search(r"'([^']*)'", text)
    return m.group(1) if m else ""


def _parse_float(text: str) -> Optional[float]:
    """Parse a float from qmicli output, returning None on failure.

    Handles unit suffixes like "dBm", "dB", "degrees" that qmicli appends
    inside the quoted value (e.g., '-102.0 dBm' or '-11.0 dB').
    """
    val = _extract_value(text) if "'" in text else text.strip()
    if not val:
        return None
    # Extract leading numeric value, ignoring unit suffixes
    m = re.match(r"([+-]?\d+\.?\d*)", val)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def _parse_int(text: str) -> Optional[int]:
    """Parse an int from qmicli output, handling hex (0x...) notation."""
    val = _extract_value(text) if "'" in text else text.strip()
    if not val:
        return None
    # Handle "1714944 (0x1A2B00)" format — take the decimal part
    m = re.match(r"(\d+)", val)
    if m:
        return int(m.group(1))
    # Handle pure hex
    if val.startswith("0x"):
        return int(val, 16)
    return None


def _extract_earfcn_and_band(text: str) -> tuple[Optional[int], str]:
    """Parse EARFCN line, extracting both the number and band description.

    Input:  "EUTRA Absolute RF Channel Number: '2050' (E-UTRA band 4: AWS-1)"
    Output: (2050, "E-UTRA band 4: AWS-1")
    """
    earfcn = _parse_int(text)
    band = ""
    m = re.search(r"\(([^)]+)\)", text)
    if m:
        band = m.group(1)
    return earfcn, band


def _check_error(output: str) -> Optional[str]:
    """Check if qmicli output indicates an error."""
    if "error:" in output.lower() and "couldn't" in output.lower():
        return output.strip().splitlines()[0] if output.strip() else "unknown error"
    if "Operation failed" in output:
        return output.strip().splitlines()[0]
    return None


# ---------------------------------------------------------------------------
# Command-specific parsers
# ---------------------------------------------------------------------------

def parse_signal_info(output: str) -> SignalInfo:
    """Parse qmicli --nas-get-signal-info output.

    Example input:
        [/dev/cdc-wdm0] Successfully got signal info
        LTE:
            RSSI: '-71 dBm'
            RSRQ: '-11.0 dB'
            RSRP: '-102.0 dBm'
            SNR: '7.4 dB'
        5G:
            RSRP: '-98.0 dBm'
            SNR: '10.5 dB'
    """
    err = _check_error(output)
    if err:
        return SignalInfo(error=err)

    result = SignalInfo()
    current_rat: Optional[str] = None
    current_signal: Optional[RATSignal] = None

    # Map qmicli RAT headers to our normalized names
    rat_map = {
        "lte": "lte", "5g": "nr5g", "nr5g": "nr5g",
        "wcdma": "wcdma", "umts": "wcdma",
        "gsm": "gsm", "cdma 1x": "cdma1x", "cdma 1xevdo": "cdma_evdo",
        "hdr": "cdma_evdo",
    }

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Detect RAT section headers (e.g., "LTE:", "5G:", "WCDMA:")
        if stripped.endswith(":") and not stripped.startswith(("RSSI", "RSRP", "RSRQ", "SNR", "SINR", "ECIO", "RSCP", "IO")):
            rat_key = stripped[:-1].strip().lower()
            if rat_key in rat_map:
                current_rat = rat_map[rat_key]
                current_signal = RATSignal(rat=current_rat)
                result.rats.append(current_signal)
                continue

        if current_signal is None:
            continue

        key = stripped.split(":")[0].strip().upper() if ":" in stripped else ""

        if key == "RSSI":
            current_signal.rssi = _parse_float(stripped)
        elif key == "RSRP":
            current_signal.rsrp = _parse_float(stripped)
        elif key == "RSRQ":
            current_signal.rsrq = _parse_float(stripped)
        elif key in ("SNR", "SINR"):
            current_signal.sinr = _parse_float(stripped)
        elif key == "RSCP":
            current_signal.rscp = _parse_float(stripped)
        elif key in ("ECIO", "IO"):
            current_signal.ecio = _parse_float(stripped)

    return result


def parse_cell_location_info(output: str) -> CellLocationInfo:
    """Parse qmicli --nas-get-cell-location-info output.

    Handles both LTE and NR5G sections with nested frequency/cell structures.
    """
    err = _check_error(output)
    if err:
        return CellLocationInfo(error=err)

    result = CellLocationInfo()
    section = ""  # "intra", "inter", "nr5g", "gsm_neighbor", "wcdma_neighbor"
    current_freq: Optional[FrequencyInfo] = None
    current_cell: Optional[CellMeasurement] = None

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Detect top-level sections
        stripped_lower = stripped.lower()
        if "intrafrequency lte" in stripped_lower:
            section = "intra"
            continue
        elif "interfrequency lte" in stripped_lower:
            section = "inter"
            continue
        elif "neighboring gsm" in stripped_lower:
            section = "gsm_neighbor"
            continue
        elif "neighboring wcdma" in stripped_lower:
            section = "wcdma_neighbor"
            continue
        elif ("nr5g" in stripped_lower or "5gnr" in stripped_lower) and (
            "cell info" in stripped_lower or "serving" in stripped_lower
            or "cell information" in stripped_lower
        ):
            section = "nr5g"
            continue
        elif ("5gnr arfcn" in stripped_lower or "nr arfcn" in stripped_lower) and ":" in stripped:
            result.nr_arfcn = _parse_int(stripped)
            section = "nr5g"  # following lines are NR context
            continue
        elif "timing advance" in stripped_lower:
            if "unavailable" not in stripped_lower:
                result.timing_advance = _parse_int(stripped)
            continue

        # Parse fields based on current section
        if section == "intra":
            if "PLMN:" in stripped:
                result.plmn = _extract_value(stripped)
                result.mcc, result.mnc = plmn_from_qmicli_bcd(result.plmn)
            elif "Tracking Area Code:" in stripped:
                result.tac = _parse_int(stripped)
            elif "Global Cell ID:" in stripped:
                result.cid = _parse_int(stripped)
            elif "EUTRA Absolute RF Channel Number:" in stripped:
                result.earfcn, _ = _extract_earfcn_and_band(stripped)
            elif "Serving Cell ID:" in stripped:
                result.pci = _parse_int(stripped)
            elif stripped.startswith("Cell ["):
                current_cell = CellMeasurement()
                result.intra_cells.append(current_cell)
            elif current_cell is not None:
                if "Physical Cell ID:" in stripped:
                    current_cell.pci = _parse_int(stripped)
                elif "RSRP:" in stripped:
                    current_cell.rsrp = _parse_float(stripped)
                elif "RSRQ:" in stripped:
                    current_cell.rsrq = _parse_float(stripped)
                elif "RSSI:" in stripped:
                    current_cell.rssi = _parse_float(stripped)

        elif section == "inter":
            if stripped.startswith("Frequency ["):
                current_freq = FrequencyInfo()
                result.inter_frequencies.append(current_freq)
                current_cell = None
            elif current_freq is not None:
                if "EUTRA Absolute RF Channel Number:" in stripped:
                    current_freq.earfcn, current_freq.band_description = (
                        _extract_earfcn_and_band(stripped)
                    )
                elif stripped.startswith("Cell ["):
                    current_cell = CellMeasurement()
                    current_freq.cells.append(current_cell)
                elif current_cell is not None:
                    if "Physical Cell ID:" in stripped:
                        current_cell.pci = _parse_int(stripped)
                    elif "RSRP:" in stripped:
                        current_cell.rsrp = _parse_float(stripped)
                    elif "RSRQ:" in stripped:
                        current_cell.rsrq = _parse_float(stripped)
                    elif "RSSI:" in stripped:
                        current_cell.rssi = _parse_float(stripped)

        elif section == "nr5g":
            if "PLMN:" in stripped and not result.plmn:
                result.plmn = _extract_value(stripped)
                result.mcc, result.mnc = plmn_from_qmicli_bcd(result.plmn)
            elif "NR-ARFCN" in stripped or "NR ARFCN" in stripped:
                result.nr_arfcn = _parse_int(stripped)
            elif "Physical Cell ID:" in stripped or "PCI:" in stripped:
                result.nr_pci = _parse_int(stripped)
            elif "Tracking Area Code:" in stripped or "TAC:" in stripped:
                result.nr_tac = _parse_int(stripped)
            elif "Global Cell ID:" in stripped or "Cell Identity:" in stripped:
                result.nci = _parse_int(stripped)
            elif "RSRP:" in stripped:
                result.nr_rsrp = _parse_float(stripped)
            elif "RSRQ:" in stripped:
                result.nr_rsrq = _parse_float(stripped)
            elif "SNR:" in stripped or "SINR:" in stripped:
                result.nr_sinr = _parse_float(stripped)

    return result


def parse_system_info(output: str) -> SystemInfo:
    """Parse qmicli --nas-get-system-info output.

    Example input:
        [/dev/cdc-wdm0] Successfully got system info
        LTE:
            Service status: 'limited'
            True service status: 'limited'
            Preferred data path: 'no'
            Domain: 'none'
            ...
            MCC: '310'
            MNC: '260'
            TAC: '1714944'
            Cell ID: '12301088'
    """
    err = _check_error(output)
    if err:
        return SystemInfo(error=err)

    result = SystemInfo()
    current_rat = ""

    rat_map = {
        "lte": "lte", "5g": "nr5g", "nr5g": "nr5g",
        "wcdma": "wcdma", "gsm": "gsm",
        "cdma 1x": "cdma1x", "cdma 1xevdo": "cdma_evdo",
    }

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Detect RAT headers
        if stripped.endswith(":") and "\t" not in line and "  " not in line[:4]:
            rat_key = stripped[:-1].strip().lower()
            if rat_key in rat_map:
                current_rat = rat_map[rat_key]
                continue

        # Service status per RAT
        if "Service status:" in stripped and "True" not in stripped:
            status = _extract_value(stripped)
            if current_rat == "gsm":
                result.gsm_status = status
            elif current_rat == "wcdma":
                result.wcdma_status = status
            elif current_rat == "lte":
                result.lte_status = status
            elif current_rat == "nr5g":
                result.nr5g_status = status

        # Registration details (take from the first RAT that has them)
        if "Registration state:" in stripped or "Reg state:" in stripped:
            val = _extract_value(stripped).lower()
            if "registered" in val and not result.registered:
                result.registered = True
                result.active_rat = current_rat

        if "Roaming:" in stripped:
            val = _extract_value(stripped).lower()
            if val in ("on", "yes", "true"):
                result.roaming = True

        if "MCC:" in stripped and not result.mcc:
            result.mcc = _extract_value(stripped)
        if "MNC:" in stripped and not result.mnc:
            result.mnc = _extract_value(stripped)
        if ("TAC:" in stripped or "Tracking Area Code:" in stripped) and result.tac is None:
            result.tac = _parse_int(stripped)
        if "Cell ID:" in stripped and "Global" not in stripped and result.cid is None:
            result.cid = _parse_int(stripped)

    return result


def parse_network_scan(output: str) -> list[NetworkScanResult]:
    """Parse qmicli --nas-network-scan output.

    Example input:
        [/dev/cdc-wdm0] Successfully scanned for networks
        Network [0]:
            MCC: '311'
            MNC: '480'
            Status: 'current-serving, roaming, preferred'
            Description: 'Verizon'
            Access Technology: 'lte'
        Network [1]:
            MCC: '310'
            MNC: '260'
            Status: 'available'
            Description: 'T-Mobile'
            Access Technology: 'lte'
    """
    err = _check_error(output)
    if err:
        return []

    results: list[NetworkScanResult] = []
    current: Optional[NetworkScanResult] = None

    rat_map = {
        "lte": "lte", "umts": "umts", "gsm": "gsm",
        "5gnr": "nr5g", "nr5g": "nr5g",
    }

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("Network ["):
            current = NetworkScanResult()
            results.append(current)
            continue

        if current is None:
            continue

        if "MCC:" in stripped:
            current.mcc = _extract_value(stripped)
        elif "MNC:" in stripped:
            current.mnc = _extract_value(stripped)
        elif "Status:" in stripped:
            val = _extract_value(stripped)
            current.status = [s.strip() for s in val.split(",")]
        elif "Description:" in stripped:
            current.description = _extract_value(stripped)
        elif "Access Technology:" in stripped:
            val = _extract_value(stripped).lower().replace(" ", "").replace("-", "")
            current.rat = rat_map.get(val, val)

    return results


def parse_serving_system(output: str) -> ServingSystem:
    """Parse qmicli --nas-get-serving-system output.

    Example input:
        [/dev/cdc-wdm0] Successfully got serving system:
            Registration state: 'registered'
            CS: 'attached'
            PS: 'attached'
            Selected network: '3gpp'
            Data service capabilities: ...
            Current PLMN:
                MCC: '311'
                MNC: '480'
                Description: 'Verizon'
            Roaming status: 'off'
    """
    err = _check_error(output)
    if err:
        return ServingSystem(error=err)

    result = ServingSystem()

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if "Registration state:" in stripped:
            result.registration_state = _extract_value(stripped)
        elif stripped.startswith("CS:"):
            result.cs_attach_state = _extract_value(stripped)
        elif stripped.startswith("PS:"):
            result.ps_attach_state = _extract_value(stripped)
        elif "Selected network:" in stripped:
            result.selected_network = _extract_value(stripped)
        elif "MCC:" in stripped and not result.mcc:
            result.mcc = _extract_value(stripped)
        elif "MNC:" in stripped and not result.mnc:
            result.mnc = _extract_value(stripped)
        elif "Description:" in stripped and not result.description:
            result.description = _extract_value(stripped)
        elif "Roaming" in stripped:
            val = _extract_value(stripped).lower()
            if val in ("on", "yes", "true"):
                result.roaming = True

    return result
