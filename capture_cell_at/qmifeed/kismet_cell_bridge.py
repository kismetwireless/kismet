#!/usr/bin/env python3
"""Bridge QMI NAS cell-location-info → Kismet ``cell_observation`` JSON.

Rather than reimplement QMI decode inside the
Kismet capture source, reuse ``qmifeed/parse.py``'s typed
:class:`~qmifeed.parse.CellLocationInfo` and emit the *exact* JSON shape that
``capture_cell_at``'s ``build_cell_json()`` produces. Kismet's
``datasource_cell_at`` / ``phy_cell`` can then consume QMI-sourced cells and
merge them with the AT- and DIAG-sourced observations for the same tower.

The merge key is the ``prov`` block. Each source stamps its observations:

* AT   → ``{"src":"at","origin":"AT+QENG",...}``
* DIAG → ``{"src":"diag","origin":"0xB193",...}``
* QMI  → ``{"src":"qmi","origin":"nas-get-cell-location-info",...}``   (here)

so ``phy_cell`` can attribute which pipe supplied identity versus signal for
each cell and merge without duplicating towers.

Why QMI is worth the wiring: it carries data AT omits —
NR Cell Identity (NCI) where Telit ``AT#RFSTS`` drops it, full cell identity on
Sierra where ``AT+CEREG``/``AT+CSQ`` return ERROR, and neighbour PCI/EARFCN/RSRP
without polling.

The output schema (keys emitted only when the value is present), matching
``build_cell_json``::

    {"rat","duplex","mcc","mnc","cell_id","pci","tac","earfcn","band",
     "bandwidth","rsrp","rsrq","sinr","rssi","observation_type","is_serving",
     "operator_name","prov":{...}}

**EARFCN truncation.** QMI carries EARFCN/NR-ARFCN in a 16-bit TLV, so
any true channel ≥ 65536 arrives wrapped and libqmi then prints a
confidently-wrong band. A wrapped value is byte-identical to a genuine low one,
so no single record can be audited. This bridge does NOT emit a ``band`` for
QMI cells (leaving band derivation to the consumer, which for the AT source
runs ``earfcn_to_band`` only after a full-width channel), and it stamps the
``prov`` block with ``"earfcn_ambiguous": <bool>`` for every cell that has an
EARFCN — an explicit "maybe truncated" the consumer can act on, per parse.py's
own :func:`~qmifeed.parse.earfcn_is_ambiguous` boundary.

This module is deliberately transport-free: it turns parsed dataclasses into
dict/JSON. The poll loop is ``qmifeed/kismet_qmi_feed.py``; the Kismet side
is ``capture_cell_at``'s ``qmifeed=`` option (``cellat_qmifeed.c``).
"""

from __future__ import annotations

import json
from typing import Optional

from .parse import (
    CellLocationInfo,
    CellMeasurement,
    SignalInfo,
    earfcn_is_ambiguous,
)

QMI_ORIGIN = "nas-get-cell-location-info"


def _round_or_none(value: Optional[float]) -> Optional[int]:
    """Round a QMI float signal reading to the integer the schema expects.

    ``build_cell_json`` types rsrp/rsrq/sinr/rssi as ``long``; QMI reports
    them as floats (``-102.2``). Returns ``None`` unchanged so absent readings
    stay absent (the key is then omitted, exactly as in build_cell_json).
    """
    if value is None:
        return None
    return int(round(value))


def _prov(imei: Optional[str], captured_at: Optional[float],
          earfcn: Optional[int]) -> dict:
    """Build the QMI ``prov`` block mirroring the AT/DIAG source shape.

    ``earfcn_ambiguous`` is emitted only when the observation carries an
    EARFCN, and its value is the 16-bit truncation verdict for that channel.
    """
    block: dict = {"src": "qmi", "origin": QMI_ORIGIN, "imei": imei or ""}
    if captured_at is not None:
        block["captured_at"] = round(captured_at, 3)
    if earfcn is not None:
        block["earfcn_ambiguous"] = earfcn_is_ambiguous(earfcn)
    return block


def _observation(
    *,
    rat: str,
    is_serving: bool,
    imei: Optional[str],
    captured_at: Optional[float],
    mcc: Optional[str] = None,
    mnc: Optional[str] = None,
    cell_id: Optional[int] = None,
    pci: Optional[int] = None,
    tac: Optional[int] = None,
    earfcn: Optional[int] = None,
    rsrp: Optional[float] = None,
    rsrq: Optional[float] = None,
    sinr: Optional[float] = None,
    rssi: Optional[float] = None,
) -> dict:
    """Assemble one cell_observation dict, omitting absent keys.

    Key order mirrors ``build_cell_json`` for readability; JSON consumers
    (phy_cell via cJSON) do not depend on it.
    """
    obs: dict = {"rat": rat}
    if mcc:
        obs["mcc"] = mcc
    if mnc:
        obs["mnc"] = mnc
    if cell_id is not None:
        obs["cell_id"] = cell_id
    if pci is not None:
        obs["pci"] = pci
    if tac is not None:
        obs["tac"] = tac
    if earfcn is not None:
        obs["earfcn"] = earfcn
    for key, val in (("rsrp", rsrp), ("rsrq", rsrq),
                     ("sinr", sinr), ("rssi", rssi)):
        rounded = _round_or_none(val)
        if rounded is not None:
            obs[key] = rounded
    obs["observation_type"] = "serving" if is_serving else "observation"
    obs["is_serving"] = is_serving
    obs["prov"] = _prov(imei, captured_at, earfcn)
    return obs


def cell_location_to_observations(
    cell: CellLocationInfo,
    *,
    imei: Optional[str] = None,
    captured_at: Optional[float] = None,
    signal: Optional[SignalInfo] = None,
) -> list[dict]:
    """Convert a parsed :class:`CellLocationInfo` into Kismet cell_observations.

    Emits, in order:

    1. the **serving LTE** cell (identity + signal), when ``cell.pci`` is set;
    2. the **serving NR5G** cell, when ``cell.nr_pci`` is set (NCI, nr_arfcn,
       nr signal) — the headline reason to wire QMI at all;
    3. **neighbour** observations (``is_serving=false``) for every measured
       cell that is not the serving intra cell — intra-frequency neighbours
       and all inter-frequency cells.

    ``signal`` (from ``nas-get-signal-info``) is an optional fallback: QMI's
    per-cell measurements in cell-location-info are the primary source, but the
    serving cell's readings are backfilled from ``signal`` when the intra
    measurement list is empty (some firmwares report identity without a
    ``Cell [0]`` block).

    Neighbour cells carry PCI/EARFCN/signal only — QMI cell-location-info does
    not resolve their MCC/MNC/CID/TAC — matching how the AT source emits
    identity-less neighbour observations that ``phy_cell`` later enriches via
    its ``pci_to_full_identity`` map.
    """
    observations: list[dict] = []

    # --- serving LTE cell -------------------------------------------------
    serving_measurement: Optional[CellMeasurement] = None
    if cell.pci is not None:
        # The serving cell reappears as an intra Cell[] entry with the same
        # PCI on the serving EARFCN. Prefer its measured signal; fall back to
        # nas-get-signal-info.
        serving_measurement = next(
            (c for c in cell.intra_cells if c.pci == cell.pci), None)
        lte_sig = signal.lte() if signal else None
        observations.append(_observation(
            rat="LTE",
            is_serving=True,
            imei=imei,
            captured_at=captured_at,
            mcc=cell.mcc or None,
            mnc=cell.mnc or None,
            cell_id=cell.cid,
            pci=cell.pci,
            tac=cell.tac,
            earfcn=cell.earfcn,
            rsrp=(serving_measurement.rsrp if serving_measurement
                  else (lte_sig.rsrp if lte_sig else None)),
            rsrq=(serving_measurement.rsrq if serving_measurement
                  else (lte_sig.rsrq if lte_sig else None)),
            sinr=(lte_sig.sinr if lte_sig else None),
            rssi=(serving_measurement.rssi if serving_measurement
                  else (lte_sig.rssi if lte_sig else None)),
        ))

    # --- serving NR5G cell ------------------------------------------------
    if cell.nr_pci is not None:
        observations.append(_observation(
            rat="NR",
            is_serving=True,
            imei=imei,
            captured_at=captured_at,
            mcc=cell.mcc or None,
            mnc=cell.mnc or None,
            cell_id=cell.nci,
            pci=cell.nr_pci,
            tac=cell.nr_tac,
            earfcn=cell.nr_arfcn,
            rsrp=cell.nr_rsrp,
            rsrq=cell.nr_rsrq,
            sinr=cell.nr_sinr,
        ))

    # --- neighbour observations -------------------------------------------
    # Intra-frequency neighbours: every intra cell that is NOT the serving
    # cell (same EARFCN, different PCI).
    for measurement in cell.intra_cells:
        if serving_measurement is not None and measurement is serving_measurement:
            continue
        if measurement.pci is None:
            continue
        observations.append(_observation(
            rat="LTE",
            is_serving=False,
            imei=imei,
            captured_at=captured_at,
            pci=measurement.pci,
            earfcn=cell.earfcn,
            rsrp=measurement.rsrp,
            rsrq=measurement.rsrq,
            rssi=measurement.rssi,
        ))

    # Inter-frequency neighbours: grouped by EARFCN. Same PCI on a different
    # EARFCN is a genuinely distinct cell — keep it.
    for freq in cell.inter_frequencies:
        for measurement in freq.cells:
            if measurement.pci is None:
                continue
            observations.append(_observation(
                rat="LTE",
                is_serving=False,
                imei=imei,
                captured_at=captured_at,
                pci=measurement.pci,
                earfcn=freq.earfcn,
                rsrp=measurement.rsrp,
                rsrq=measurement.rsrq,
                rssi=measurement.rssi,
            ))

    return observations


def observations_to_ndjson(observations: list[dict]) -> str:
    """Render observations as newline-delimited JSON (one object per line).

    This is the form ``qmifeed/kismet_qmi_feed.py`` writes to stdout. The
    reader is ``kismet_cap_cell_at`` capture child (``qmifeed=`` source
    option), which forwards each line to the Kismet server as a ``CellModem``
    KDS record. ``datasource_cell_at`` itself speaks KDS, never NDJSON.
    """
    return "\n".join(json.dumps(obs, separators=(",", ":")) for obs in observations)


if __name__ == "__main__":  # pragma: no cover - manual smoke path
    import sys
    from .parse import parse_cell_location_info

    raw = sys.stdin.read()
    parsed = parse_cell_location_info(raw)
    print(observations_to_ndjson(
        cell_location_to_observations(parsed, imei="000000000000000")))
