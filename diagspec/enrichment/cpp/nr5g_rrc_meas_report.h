// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ NR5G RRC MeasurementReport decoder — port of the reference
// decoder's NR MeasurementReport decode. Part of the NR RRC
// C++ decoder suite, the NR counterpart of the LTE meas-report unit,
// lte_rrc_meas_report.{h,cpp}; this is the uplink UL-DCCH meas-report.
//
// Like the LTE unit this is a whole-message decoder: it walks the UL-DCCH-Message
// CHOICE tree from bit 0 and REJECTS (returns false) any message that is not an
// NR MeasurementReport, so the driver emits JSON null for the same inputs the
// reference decoder rejects. It rides the gap-1 UPER reader, uper.h, and the gap-2
// ASN.1 helpers, asn1_helpers.h: the per-entry extension skip is the
// shared skip_extension_additions — no re-derived §11.9 length logic. The
// RSRP/RSRQ/SINR range→physical conversions (TS 38.133 §10.1) are the only inline
// arithmetic and are pinned by the equivalence diff; they are inlined here
// rather than shared, keeping the unit self-contained.
//
// NR neighbor cells surfaced by this decoder carry only physCellId + the three
// signal quantities — CGI fields (mcc/mnc/nci/tac) are never populated on the
// MeasurementReport wire path, so they have no C++ analogue here and are never
// emitted for this message.
//
// Equivalence to the reference decoder is diffed at the FIELD-VALUE level
// (harness/nr5g_rrc_meas_report_verify.py).
#ifndef DIAGSPEC_NR5G_RRC_MEAS_REPORT_H
#define DIAGSPEC_NR5G_RRC_MEAS_REPORT_H

#include <cstdint>
#include <vector>

namespace diagspec {
namespace nr5g_rrc {

// A single NR neighbor-cell measurement result (MeasResultNR). Each signal
// quantity (rsrp dBm, rsrq dB, sinr dB) is OPTIONAL in MeasQuantityResults and
// carries a presence flag; an absent quantity is omitted entirely from the
// emitted record.
struct NrMeasResultCell {
  int pci = 0;         // physCellId INTEGER (0..1007); 0 when the OPTIONAL absent
  bool has_rsrp = false;
  double rsrp = 0.0;   // dBm (RSRP-Range - 156)
  bool has_rsrq = false;
  double rsrq = 0.0;   // dB ((RSRQ-Range - 87) / 2)
  bool has_sinr = false;
  double sinr = 0.0;   // dB ((SINR-Range - 46) / 2)
};

// A decoded NR MeasurementReport: the serving-cell (first MeasResultServMO)
// RSRP/RSRQ/SINR, the measId, and any neighbor-cell measurement results. The
// serving quantities are OPTIONAL exactly as the neighbor ones are.
struct NrMeasurementReport {
  int64_t log_time = 0;   // passthrough (not decoded from the wire)
  int meas_id = 0;        // INTEGER (1..maxMeasId=64)
  bool has_serving_rsrp = false;
  double serving_rsrp = 0.0;
  bool has_serving_rsrq = false;
  double serving_rsrq = 0.0;
  bool has_serving_sinr = false;
  double serving_sinr = 0.0;
  std::vector<NrMeasResultCell> neighbor_cells;
};

// Decode an NR MeasurementReport from a UL-DCCH UPER bitstream. Returns true and
// fills `out` on success; returns false (leaving `out` unspecified) for a
// too-short buffer (< 4 bytes) or any CHOICE that is not measurementReport —
// mirroring decode_nr_measurement_report's None returns. `log_time` is stored
// verbatim on the result.
//
// Navigates (3GPP TS 38.331 §6.2.2):
//   UL-DCCH-Message → message c1 (16 alts, measurementReport = 0)
//     → MeasurementReport → criticalExtensions (measurementReport = 0)
//       → MeasurementReport-IEs → MeasResults
//         → measId, measResultServingMOList { measResultServingCell },
//           measResultNeighCells CHOICE { measResultListNR, … } OPTIONAL
bool decode_measurement_report(int64_t log_time,
                               const std::vector<uint8_t>& msg_data,
                               NrMeasurementReport& out);

}  // namespace nr5g_rrc
}  // namespace diagspec

#endif  // DIAGSPEC_NR5G_RRC_MEAS_REPORT_H
