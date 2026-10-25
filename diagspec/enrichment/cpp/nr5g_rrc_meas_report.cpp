// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ NR5G RRC MeasurementReport decoder (see
// nr5g_rrc_meas_report.h). Ported behavior-for-behavior from the reference
// decoder. Equivalence is
// diffed at the field-value level (harness/nr5g_rrc_meas_report_verify.py).
//
// No exception guard: the UPER reader reads past end-of-buffer as 0 rather than
// throwing (see uper.h), so a
// truncated payload degrades into zero-filled fields — the same discipline the
// LTE meas-report unit (lte_rrc_meas_report.cpp) documents. Fixtures are
// well-formed; reject cases fail at a CHOICE or the length gate, never by
// running off the end mid-field.
#include "nr5g_rrc_meas_report.h"

#include "asn1_helpers.h"
#include "uper.h"

namespace diagspec {
namespace nr5g_rrc {

using asn1::UnalignedPerReader;
using asn1::skip_extension_additions;

namespace {

// TS 38.331 ASN.1 bounds.
constexpr int kMaxMeasId = 64;          // MeasId ::= INTEGER (1..maxMeasId)
constexpr int kMaxNrPhysCellId = 1007;  // PhysCellId ::= INTEGER (0..1007)
constexpr int kMaxCellReport = 8;       // maxCellReport
constexpr int kMaxRsrpRange = 127;      // RSRP-Range ::= INTEGER (0..127)
constexpr int kMaxRsrqRange = 127;      // RSRQ-Range ::= INTEGER (0..127)
constexpr int kMaxSinrRange = 127;      // SINR-Range ::= INTEGER (0..127)

// TS 38.133 §10.1 range→physical conversions, inlined:
// (val-156) / (val-87)/2 / (val-46)/2.
double rsrp_to_dbm(int64_t val) { return static_cast<double>(val - 156); }
double rsrq_to_db(int64_t val) { return (static_cast<double>(val) - 87.0) / 2.0; }
double sinr_to_db(int64_t val) { return (static_cast<double>(val) - 46.0) / 2.0; }

// Decoded MeasQuantityResults: rsrp/rsrq/sinr, each OPTIONAL.
struct MeasQuantityResults {
  bool has_rsrp = false;
  double rsrp = 0.0;
  bool has_rsrq = false;
  double rsrq = 0.0;
  bool has_sinr = false;
  double sinr = 0.0;
};

// MeasQuantityResults ::= SEQUENCE { rsrp OPTIONAL, rsrq OPTIONAL, sinr OPTIONAL }
// — a 3-bit presence bitmap (rsrp is the MSB) then each present RANGE integer.
// Mirrors _decode_nr_meas_result.
MeasQuantityResults decode_meas_quantity_results(UnalignedPerReader& r) {
  MeasQuantityResults q;
  const uint64_t opt = r.read_bits(3);
  if ((opt >> 2) & 1) {
    q.has_rsrp = true;
    q.rsrp = rsrp_to_dbm(r.read_constrained_int(0, kMaxRsrpRange));
  }
  if ((opt >> 1) & 1) {
    q.has_rsrq = true;
    q.rsrq = rsrq_to_db(r.read_constrained_int(0, kMaxRsrqRange));
  }
  if (opt & 1) {
    q.has_sinr = true;
    q.sinr = sinr_to_db(r.read_constrained_int(0, kMaxSinrRange));
  }
  return q;
}

// Skip rsIndexResults: ResultsPerSSB-IndexList and ResultsPerCSI-RS-IndexList,
// each a SEQUENCE OF a NON-extensible per-index SEQUENCE { index, OPTIONAL
// MeasQuantityResults } (TS 38.331 v17.17.0; no extension marker).
// The values are consumed but discarded. Mirrors _skip_rs_index_results.
void skip_rs_index_results(UnalignedPerReader& r) {
  const uint64_t opt = r.read_bits(2);  // resultsSSB-Indexes, resultsCSI-RS-Indexes

  if ((opt >> 1) & 1) {  // resultsSSB-Indexes SIZE (1..maxNrofSSBs=64)
    const int64_t num_ssb = r.read_constrained_int(1, 64);
    for (int64_t i = 0; i < num_ssb; ++i) {
      const bool has_results = r.read_bool();
      r.read_constrained_int(0, 63);  // ssb-Index
      if (has_results) decode_meas_quantity_results(r);
    }
  }

  if (opt & 1) {  // resultsCSI-RS-Indexes SIZE (1..maxNrofCSI-RS=64)
    const int64_t num_csi = r.read_constrained_int(1, 64);
    for (int64_t i = 0; i < num_csi; ++i) {
      const bool has_results = r.read_bool();
      r.read_constrained_int(0, 95);  // csi-RS-Index
      if (has_results) decode_meas_quantity_results(r);
    }
  }
}

// One MeasResultNR entry (extensible SEQUENCE, 1 base OPTIONAL physCellId). The
// inner measResult is NOT extensible: an OPTIONAL rsIndexResults after
// cellResults, which is itself a non-extensible SEQUENCE of two OPTIONAL
// MeasQuantityResults (resultsSSB-Cell, resultsCSI-RS-Cell). The cell's
// quantities are the SSB results; CSI-RS results are consumed only.
// Mirrors _decode_meas_result_nr.
NrMeasResultCell decode_meas_result_nr(UnalignedPerReader& r) {
  NrMeasResultCell cell;
  const bool has_ext = r.read_bool();   // MeasResultNR extension marker
  const bool has_pci = r.read_bool();   // OPTIONAL physCellId
  if (has_pci) {
    cell.pci = static_cast<int>(r.read_constrained_int(0, kMaxNrPhysCellId));
  }

  const bool has_rs_index = r.read_bool();   // measResult: OPTIONAL rsIndexResults

  // cellResults: resultsSSB-Cell OPTIONAL, resultsCSI-RS-Cell OPTIONAL.
  const uint64_t cell_opt = r.read_bits(2);
  if ((cell_opt >> 1) & 1) {
    const MeasQuantityResults q = decode_meas_quantity_results(r);
    cell.has_rsrp = q.has_rsrp;
    cell.rsrp = q.rsrp;
    cell.has_rsrq = q.has_rsrq;
    cell.rsrq = q.rsrq;
    cell.has_sinr = q.has_sinr;
    cell.sinr = q.sinr;
  }
  if (cell_opt & 1) decode_meas_quantity_results(r);  // CSI-RS: consume only

  if (has_rs_index) skip_rs_index_results(r);
  if (has_ext) skip_extension_additions(r);
  return cell;
}

// MeasResultListNR ::= SEQUENCE (SIZE (1..maxCellReport)) OF MeasResultNR.
// Mirrors _decode_meas_result_list_nr.
std::vector<NrMeasResultCell> decode_meas_result_list_nr(UnalignedPerReader& r) {
  const int64_t count = r.read_constrained_int(1, kMaxCellReport);
  std::vector<NrMeasResultCell> cells;
  cells.reserve(static_cast<size_t>(count));
  for (int64_t i = 0; i < count; ++i) {
    cells.push_back(decode_meas_result_nr(r));
  }
  return cells;
}

}  // namespace

bool decode_measurement_report(int64_t log_time,
                               const std::vector<uint8_t>& msg_data,
                               NrMeasurementReport& out) {
  if (msg_data.size() < 4) return false;

  UnalignedPerReader r(msg_data);

  // UL-DCCH-MessageType CHOICE { c1, messageClassExtension }.
  if (r.read_choice(2) != 0) return false;
  // c1 CHOICE of 16 alternatives; measurementReport = index 0 (NR — unlike LTE,
  // where it is index 1).
  if (r.read_choice(16) != 0) return false;
  // MeasurementReport → criticalExtensions CHOICE { measurementReport,
  // criticalExtensionsFuture }; measurementReport = index 0.
  if (r.read_choice(2) != 0) return false;

  // MeasurementReport-IEs is NOT extensible: two OPTIONAL presence bits
  // (lateNonCriticalExtension, nonCriticalExtension), both after measResults.
  r.read_bits(2);
  r.read_bool();  // MeasResults extension marker
  const bool has_neigh = r.read_bool();  // OPTIONAL measResultNeighCells

  NrMeasurementReport rep;
  rep.log_time = log_time;
  rep.meas_id = static_cast<int>(r.read_constrained_int(1, kMaxMeasId));

  // measResultServingMOList SEQUENCE (SIZE (1..maxNrofServingCells=32)).
  const int64_t num_serving = r.read_constrained_int(1, 32);
  for (int64_t i = 0; i < num_serving; ++i) {
    // MeasResultServMO ::= SEQUENCE { servCellId, measResultServingCell,
    //   measResultBestNeighCell OPTIONAL, ... } — extensible, 1 OPTIONAL.
    const bool smo_ext = r.read_bool();
    const bool has_best_neigh = r.read_bool();  // measResultBestNeighCell OPTIONAL
    r.read_constrained_int(0, 31);              // servCellId

    const NrMeasResultCell serv_cell = decode_meas_result_nr(r);
    if (i == 0) {  // keep the first serving cell (PCell) measurements
      rep.has_serving_rsrp = serv_cell.has_rsrp;
      rep.serving_rsrp = serv_cell.rsrp;
      rep.has_serving_rsrq = serv_cell.has_rsrq;
      rep.serving_rsrq = serv_cell.rsrq;
      rep.has_serving_sinr = serv_cell.has_sinr;
      rep.serving_sinr = serv_cell.sinr;
    }

    if (has_best_neigh) decode_meas_result_nr(r);  // consume but discard
    if (smo_ext) skip_extension_additions(r);
  }

  if (has_neigh) {
    // measResultNeighCells CHOICE (extensible) whose root holds ONE
    // alternative (measResultListNR), so the root index takes 0 bits.
    const bool neigh_ext = r.read_bool();
    if (!neigh_ext) {
      rep.neighbor_cells = decode_meas_result_list_nr(r);
    }
    // Inter-RAT extension alternatives are not decoded.
  }

  out = rep;
  return true;
}

}  // namespace nr5g_rrc
}  // namespace diagspec
