// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ LTE RRC MeasurementReport decoder (see
// lte_rrc_meas_report.h). Ported behavior-for-behavior from the reference
// decoder's decode_measurement_report. Equivalence is
// diffed at the field-value level (harness/lte_rrc_meas_report_verify.py).
//
// ASN.1 path decoded (3GPP TS 36.331 §6.2.2):
//   UL-DCCH-Message → message c1 (16 alts, measurementReport = 1)
//     → MeasurementReport → criticalExtensions c1 (8 alts, r8 = 0)
//       → MeasurementReport-r8-IEs → MeasResults
//         → measId, measResultPCell { rsrp, rsrq },
//           measResultNeighCells CHOICE { measResultListEUTRA, … } OPTIONAL
#include "lte_rrc_meas_report.h"

#include "asn1_helpers.h"
#include "uper.h"

namespace diagspec {
namespace lte_rrc {

using asn1::PlmnIdentity;
using asn1::UnalignedPerReader;
using asn1::decode_plmn_identity;
using asn1::skip_extension_additions;

namespace {

// TS 36.331 ASN.1 bounds.
constexpr int kMaxMeasId = 32;        // INTEGER (1..maxMeasId)
constexpr int kMaxPhysCellId = 503;   // PhysCellId ::= INTEGER (0..503)
constexpr int kMaxCellReport = 8;     // maxCellReport
constexpr int kMaxRsrpRange = 97;     // RSRP-Range ::= INTEGER (0..97)
constexpr int kMaxRsrqRange = 34;     // RSRQ-Range ::= INTEGER (0..34)

// TS 36.133 §9.1.4 / §9.1.7 range→physical conversions.
double rsrp_to_dbm(int64_t val) { return static_cast<double>(val - 140); }
double rsrq_to_db(int64_t val) { return (static_cast<double>(val) - 40.0) / 2.0; }

// cgi-Info for an E-UTRA neighbor: CellGlobalIdEUTRA { plmn-Identity,
// cellIdentity BIT STRING(28) }, trackingAreaCode BIT STRING(16), plmn-
// IdentityList OPTIONAL. Fills the CGI fields on `cell`. Mirrors
// _decode_cgi_info_eutra.
void decode_cgi_info_eutra(UnalignedPerReader& r, MeasResultCell& cell) {
  const bool has_plmn_list = r.read_bool();  // cgi-Info OPTIONAL plmn-IdentityList

  const PlmnIdentity plmn = decode_plmn_identity(r);
  const int cell_identity = static_cast<int>(r.read_bits(28));
  const int tac = static_cast<int>(r.read_bits(16));

  if (has_plmn_list) {  // SEQUENCE (SIZE (1..5)) OF PLMN-Identity, discarded
    const int64_t num_plmns = r.read_constrained_int(1, 5);
    for (int64_t i = 0; i < num_plmns; ++i) {
      decode_plmn_identity(r);
    }
  }

  // The bits are always consumed above, but the CGI block is SURFACED only
  // when the decoded MCC is non-empty: an empty-MCC CellGlobalId advances the
  // cursor but leaves the neighbor's mcc/mnc/cid/tac absent. That is correct
  // per spec: TS 36.331 Cond MCC makes the MCC MANDATORY inside
  // CellGlobalIdEUTRA, so an absent one is a violation with nothing to inherit.
  if (!plmn.mcc.empty()) {
    cell.has_cgi = true;
    cell.mcc = plmn.mcc;
    cell.mnc = plmn.mnc;
    cell.cid = cell_identity;
    cell.tac = tac;
  }
}

// One MeasResultEUTRA entry: a NON-extensible SEQUENCE with 1 OPTIONAL
// (cgi-Info); only the inner measResult is extensible (rsrp/rsrq OPTIONALs).
// Do not read a top-level extension bit here: it shifts every real neighbour by
// one bit (PCI 442 decodes as 221 against tshark). A self-made fixture encoder
// that makes the same mistake agrees with the decoder, so validate against
// tshark or real captures. Mirrors _decode_meas_result_eutra.
MeasResultCell decode_meas_result_eutra(UnalignedPerReader& r) {
  MeasResultCell cell;
  const bool has_cgi = r.read_bool();   // OPTIONAL cgi-Info
  cell.pci = static_cast<int>(r.read_constrained_int(0, kMaxPhysCellId));

  if (has_cgi) {
    decode_cgi_info_eutra(r, cell);
  }

  const bool meas_ext = r.read_bool();  // measResult extension marker
  const bool has_rsrp = r.read_bool();
  const bool has_rsrq = r.read_bool();
  if (has_rsrp) {
    cell.has_rsrp = true;
    cell.rsrp = rsrp_to_dbm(r.read_constrained_int(0, kMaxRsrpRange));
  }
  if (has_rsrq) {
    cell.has_rsrq = true;
    cell.rsrq = rsrq_to_db(r.read_constrained_int(0, kMaxRsrqRange));
  }
  if (meas_ext) {
    skip_extension_additions(r);
  }
  return cell;
}

}  // namespace

bool decode_measurement_report(int64_t log_time,
                               const std::vector<uint8_t>& msg_data,
                               LteMeasurementReport& out) {
  if (msg_data.size() < 4) {
    return false;
  }

  UnalignedPerReader r(msg_data);

  // UL-DCCH-MessageType CHOICE { c1, messageClassExtension }.
  if (r.read_choice(2) != 0) {
    return false;
  }
  // c1 CHOICE of 16 alternatives; measurementReport = index 1.
  if (r.read_choice(16) != 1) {
    return false;
  }
  // criticalExtensions CHOICE { c1, criticalExtensionsFuture }.
  if (r.read_choice(2) != 0) {
    return false;
  }
  // c1 CHOICE { measurementReport-r8, spare7..spare1 } (8 alts); r8 = index 0.
  if (r.read_choice(8) != 0) {
    return false;
  }

  r.read_bool();  // MeasurementReport-r8-IEs extension marker
  r.read_bool();  // MeasResults extension marker
  const bool has_neigh = r.read_bool();  // OPTIONAL measResultNeighCells

  out.log_time = log_time;
  out.meas_id = static_cast<int>(r.read_constrained_int(1, kMaxMeasId));

  // measResultPCell { rsrpResult RSRP-Range, rsrqResult RSRQ-Range } — both
  // mandatory, no extension marker.
  out.pcell_rsrp = rsrp_to_dbm(r.read_constrained_int(0, kMaxRsrpRange));
  out.pcell_rsrq = rsrq_to_db(r.read_constrained_int(0, kMaxRsrqRange));

  if (has_neigh) {
    // measResultNeighCells CHOICE (extensible): measResultListEUTRA = index 0.
    const bool neigh_ext = r.read_bool();
    if (!neigh_ext) {
      const uint64_t neigh_choice = r.read_choice(4);
      if (neigh_choice == 0) {
        // MeasResultListEUTRA ::= SEQUENCE (SIZE (1..maxCellReport)).
        const int64_t count = r.read_constrained_int(1, kMaxCellReport);
        for (int64_t i = 0; i < count; ++i) {
          out.neighbor_cells.push_back(decode_meas_result_eutra(r));
        }
      }
      // UTRA / GERAN / CDMA2000 not decoded — left empty by design.
    }
  }

  return true;
}

}  // namespace lte_rrc
}  // namespace diagspec
