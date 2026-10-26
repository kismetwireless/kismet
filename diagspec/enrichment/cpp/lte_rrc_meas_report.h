// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ LTE RRC MeasurementReport decoder — port of the reference
// decoder's. Part of the LTE RRC decoder suite
// (SIBs + reconfig + meas-report); this is the uplink UL-DCCH meas-report unit.
//
// Like SIB1 (lte_rrc_sib.{h,cpp}) this is a whole-message decoder: it walks the
// UL-DCCH-Message CHOICE tree from bit 0 and REJECTS (returns false) any message
// that is not a MeasurementReport-r8, so the driver emits JSON null for the same
// inputs the reference decoder rejects. It rides the UPER reader (uper.h) and the
// ASN.1 helpers (asn1_helpers.h): PLMN decode is the shared
// decode_plmn_identity and the per-entry extension skip is the shared
// skip_extension_additions — no re-derived PLMN logic, no re-derived §11.9
// length logic. The RSRP/RSRQ range→physical conversions (TS 36.133 §9.1) are
// the only inline arithmetic and are pinned by the equivalence diff.
//
// Equivalence to the reference decoder is diffed at the FIELD-VALUE level
// (harness/lte_rrc_meas_report_verify.py).
#ifndef DIAGSPEC_LTE_RRC_MEAS_REPORT_H
#define DIAGSPEC_LTE_RRC_MEAS_REPORT_H

#include <cstdint>
#include <string>
#include <vector>

namespace diagspec {
namespace lte_rrc {

// A single neighbor-cell measurement result (MeasResultEUTRA). rsrp/rsrq are the
// converted physical values (dBm / dB) and carry a presence flag (OPTIONAL in
// the measResult SEQUENCE). The CGI block (mcc/mnc/cid/tac) is present only when
// the network enabled CGI reporting for the neighbor.
struct MeasResultCell {
  int pci = 0;
  bool has_rsrp = false;
  double rsrp = 0.0;   // dBm (RSRP-Range - 140)
  bool has_rsrq = false;
  double rsrq = 0.0;   // dB ((RSRQ-Range - 40) / 2)
  bool has_cgi = false;
  std::string mcc;
  std::string mnc;
  int cid = 0;         // CellIdentity BIT STRING (SIZE (28))
  int tac = 0;         // TrackingAreaCode BIT STRING (SIZE (16))
};

// A decoded MeasurementReport-r8: the serving-cell RSRP/RSRQ, the measId, and
// any neighbor-cell measurement results.
struct LteMeasurementReport {
  int64_t log_time = 0;   // passthrough (not decoded from the wire)
  int meas_id = 0;        // INTEGER (1..maxMeasId)
  double pcell_rsrp = 0.0;
  double pcell_rsrq = 0.0;
  std::vector<MeasResultCell> neighbor_cells;
};

// Decode a MeasurementReport from a UL-DCCH UPER bitstream. Returns true and
// fills `out` on a MeasurementReport-r8; returns false (leaving `out`
// unspecified) for a too-short buffer or any CHOICE that is not
// measurementReport-r8 — mirroring decode_measurement_report's None returns.
// `log_time` is stored verbatim on the result.
bool decode_measurement_report(int64_t log_time,
                               const std::vector<uint8_t>& msg_data,
                               LteMeasurementReport& out);

}  // namespace lte_rrc
}  // namespace diagspec

#endif  // DIAGSPEC_LTE_RRC_MEAS_REPORT_H
