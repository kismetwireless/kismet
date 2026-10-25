// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ LTE RRC RRCConnectionReconfiguration
// measConfig decoder (see lte_rrc_reconfig.h). Ported behavior-for-behavior from
// the reference decoder's decode_rrc_reconfig_meas_config.
// Equivalence is diffed
// at the field-value level (harness/lte_rrc_reconfig_verify.py).
//
// ASN.1 path decoded (3GPP TS 36.331):
//   DL-DCCH-Message → message c1 (16 alts, rrcConnectionReconfiguration = 4)
//     → RRCConnectionReconfiguration { rrc-TransactionIdentifier,
//         criticalExtensions c1 (8 alts, r8 = 0) }
//       → RRCConnectionReconfiguration-r8-IEs (6 OPTIONALs, not extensible;
//         measConfig = bit 5, mobilityControlInfo = bit 4)
//         → MeasConfig → measObjectToAddModList → MeasObjectEUTRA (surfaced);
//           every other list/field is skip-decoded to advance the cursor.
#include "lte_rrc_reconfig.h"

#include "asn1_helpers.h"
#include "uper.h"

namespace diagspec {
namespace lte_rrc {

using asn1::UnalignedPerReader;
using asn1::kAllowedMeasBandwidthRbs;
using asn1::kQOffsetRangeDb;
using asn1::skip_extension_additions;

namespace {

// -- Q-OffsetRange / AllowedMeasBandwidth ENUMERATED → value, guarded as
// `table[idx] if idx < len(table) else 0`. read_enum can yield an ordinal past
// the last defined value (the enum's bit-width rounds up), so an out-of-range
// ordinal resolves to 0.
int q_offset_db(uint64_t idx) {
  return idx < kQOffsetRangeDb.size() ? kQOffsetRangeDb[idx] : 0;
}
int allowed_meas_bw_rbs(uint64_t idx) {
  return idx < kAllowedMeasBandwidthRbs.size() ? kAllowedMeasBandwidthRbs[idx] : 0;
}

// MeasObjectEUTRA (TS 36.331 §6.3.4): the one surfaced measObject variant.
// Mirrors _decode_meas_object_eutra.
EutraMeasObject decode_meas_object_eutra(UnalignedPerReader& r) {
  EutraMeasObject obj;
  const bool has_ext = r.read_bool();

  // 6 OPTIONAL/DEFAULT root fields: offsetFreq(DEFAULT), cellsToRemove,
  // cellsToAddMod, blackCellsToRemove, blackCellsToAddMod,
  // cellForWhichToReportCGI.
  const uint64_t opt = r.read_bits(6);
  const bool has_offset_freq = (opt >> 5) & 1;
  const bool has_cells_remove = (opt >> 4) & 1;
  const bool has_cells_add = (opt >> 3) & 1;
  const bool has_black_remove = (opt >> 2) & 1;
  const bool has_black_add = (opt >> 1) & 1;
  const bool has_cgi_cell = opt & 1;

  obj.earfcn = static_cast<int>(r.read_constrained_int(0, 65535));  // carrierFreq
  obj.bandwidth = allowed_meas_bw_rbs(r.read_enum(6));  // allowedMeasBandwidth
  r.read_bool();     // presenceAntennaPort1 BOOLEAN
  r.read_bits(2);    // neighCellConfig BIT STRING (SIZE (2))

  obj.offset = 0;    // offsetFreq DEFAULT dB0
  if (has_offset_freq) {
    obj.offset = q_offset_db(r.read_enum(31));
  }

  // cellsToRemoveList: SEQUENCE (SIZE (1..32)) OF INTEGER (1..32) — discarded.
  if (has_cells_remove) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      r.read_constrained_int(1, 32);
    }
  }

  // cellsToAddModList: SEQUENCE (SIZE (1..32)) OF CellsToAddMod — surfaced.
  if (has_cells_add) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      NeighborCellOffset cell;
      cell.cell_index = static_cast<int>(r.read_constrained_int(1, 32));
      cell.pci = static_cast<int>(r.read_constrained_int(0, 503));
      cell.cell_offset = q_offset_db(r.read_enum(31));  // cellIndividualOffset
      obj.cells.push_back(cell);
    }
  }

  // blackCellsToRemoveList: SEQUENCE (SIZE (1..32)) OF INTEGER (1..32) — discarded.
  if (has_black_remove) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      r.read_constrained_int(1, 32);
    }
  }

  // blackCellsToAddModList: SEQUENCE (SIZE (1..32)) OF BlackCellsToAddMod;
  // each { cellIndex, PhysCellIdRange { start, range ENUMERATED(16) OPTIONAL } }.
  if (has_black_add) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      r.read_constrained_int(1, 32);            // cellIndex
      const bool has_range = r.read_bool();      // PhysCellIdRange OPTIONAL range
      r.read_constrained_int(0, 503);            // start
      if (has_range) {
        r.read_enum(16);                         // range
      }
    }
  }

  if (has_cgi_cell) {
    r.read_constrained_int(0, 503);  // cellForWhichToReportCGI PhysCellId
  }

  if (has_ext) {
    skip_extension_additions(r);
  }
  return obj;
}

// -- skip-only measObject variants (cursor advance, nothing surfaced) ----------

// MeasObjectUTRA (measObject CHOICE index 1). Mirrors _skip_meas_object_utra.
void skip_meas_object_utra(UnalignedPerReader& r) {
  const bool has_ext = r.read_bool();
  const uint64_t opt = r.read_bits(4);  // offsetFreq(DEFAULT), cellsRemove,
                                        // cellsAdd, cellForWhichToReportCGI
  const bool has_offset = (opt >> 3) & 1;
  const bool has_cells_remove = (opt >> 2) & 1;
  const bool has_cells_add = (opt >> 1) & 1;
  const bool has_report_cgi = opt & 1;

  r.read_constrained_int(0, 16383);  // carrierFreq
  if (has_offset) {
    r.read_constrained_int(-15, 15);  // offsetFreq
  }
  if (has_cells_remove) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      r.read_constrained_int(1, 32);
    }
  }
  if (has_cells_add) {
    const uint64_t utra_choice = r.read_choice(2);  // FDD(0) / TDD(1)
    const int64_t pci_hi = (utra_choice == 0) ? 511 : 127;
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      r.read_constrained_int(1, 32);       // cellIndex
      r.read_constrained_int(0, pci_hi);   // physCellId
    }
  }
  if (has_report_cgi) {
    const uint64_t cgi_choice = r.read_choice(2);  // fdd(0) / tdd(1)
    r.read_constrained_int(0, cgi_choice == 0 ? 511 : 127);
  }
  if (has_ext) {
    skip_extension_additions(r);
  }
}

// MeasObjectGERAN (measObject CHOICE index 2). Mirrors _skip_meas_object_geran.
void skip_meas_object_geran(UnalignedPerReader& r) {
  const bool has_ext = r.read_bool();
  const uint64_t opt = r.read_bits(3);  // offsetFreq(DEFAULT), ncc-Permitted(DEFAULT),
                                        // cellForWhichToReportCGI
  const bool has_offset = (opt >> 2) & 1;
  const bool has_ncc = (opt >> 1) & 1;
  const bool has_report_cgi = opt & 1;

  // CarrierFreqsGERAN { startingARFCN, bandIndicator, followingARFCNs CHOICE(3) }.
  r.read_constrained_int(0, 1023);  // startingARFCN
  r.read_enum(2);                   // bandIndicator {dcs1800, pcs1900}
  const uint64_t following_choice = r.read_choice(3);
  if (following_choice == 0) {
    const int64_t num = r.read_constrained_int(0, 31);  // explicitListOfARFCNs
    for (int64_t i = 0; i < num; ++i) {
      r.read_constrained_int(0, 1023);
    }
  } else if (following_choice == 1) {
    r.read_constrained_int(1, 8);   // arfcn-Spacing
    r.read_constrained_int(0, 31);  // numberOfFollowingARFCNs
  } else {
    const int64_t length = r.read_constrained_int(1, 16);  // variableBitMapOfARFCNs
    r.skip_bits(static_cast<int>(length * 8));
  }

  if (has_offset) {
    r.read_constrained_int(-15, 15);
  }
  if (has_ncc) {
    r.read_bits(8);  // ncc-Permitted
  }
  if (has_report_cgi) {
    r.read_bits(3);  // PhysCellIdGERAN.ncc
    r.read_bits(3);  // PhysCellIdGERAN.bcc
  }
  if (has_ext) {
    skip_extension_additions(r);
  }
}

// MeasObjectCDMA2000 (measObject CHOICE index 3). Mirrors _skip_meas_object_cdma2000.
void skip_meas_object_cdma2000(UnalignedPerReader& r) {
  const bool has_ext = r.read_bool();
  // 5 OPTIONAL/DEFAULT: searchWindowSize (OPTIONAL, not mandatory),
  // offsetFreq(DEFAULT), cellsRemove, cellsAdd, cellForWhichToReportCGI.
  const uint64_t opt = r.read_bits(5);
  const bool has_search_window = (opt >> 4) & 1;
  const bool has_offset = (opt >> 3) & 1;
  const bool has_cells_remove = (opt >> 2) & 1;
  const bool has_cells_add = (opt >> 1) & 1;
  const bool has_report_cgi = opt & 1;

  r.read_enum(2);   // cdma2000-Type
  // CarrierFreqCDMA2000.bandClass — EXTENSIBLE ENUMERATED (32 root values).
  if (r.read_bool()) {
    r.read_bits(7);   // normally-small extension index
  } else {
    r.read_enum(32);
  }
  r.read_constrained_int(0, 2047);  // CarrierFreqCDMA2000.arfcn
  if (has_search_window) {
    r.read_constrained_int(0, 15);  // searchWindowSize
  }

  if (has_offset) {
    r.read_constrained_int(-15, 15);
  }
  if (has_cells_remove) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      r.read_constrained_int(1, 32);
    }
  }
  if (has_cells_add) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      r.read_constrained_int(1, 32);   // cellIndex
      r.read_constrained_int(0, 511);  // physCellId
    }
  }
  if (has_report_cgi) {
    r.read_constrained_int(0, 511);  // PhysCellIdCDMA2000
  }
  if (has_ext) {
    skip_extension_additions(r);
  }
}

// -- reportConfig / quantityConfig / measGap skip helpers ---------------------

void skip_extension_choice(UnalignedPerReader& r);

// FilterCoefficient: EXTENSIBLE ENUMERATED with 16 root values (fc0..fc19,
// spare1, ...) — 1 + 4 bits, not a plain 4-bit enum(15).
void skip_filter_coefficient(UnalignedPerReader& r) {
  if (r.read_bool()) {
    r.read_bits(7);  // normally-small extension index
  } else {
    r.read_enum(16);
  }
}

// ThresholdEUTRA CHOICE { threshold-RSRP(0..97), threshold-RSRQ(0..34) }.
void skip_threshold_eutra(UnalignedPerReader& r) {
  if (r.read_choice(2) == 0) {
    r.read_constrained_int(0, 97);
  } else {
    r.read_constrained_int(0, 34);
  }
}

// Event thresholds inside ReportConfigEUTRA. Mirrors _skip_event_id.
void skip_event_id(UnalignedPerReader& r, uint64_t event_idx) {
  if (event_idx == 0 || event_idx == 1 || event_idx == 3) {  // A1, A2, A4
    skip_threshold_eutra(r);
  } else if (event_idx == 2) {  // A3
    r.read_constrained_int(-30, 30);  // a3-Offset
    r.read_bool();                    // reportOnLeave
  } else if (event_idx == 4) {  // A5
    skip_threshold_eutra(r);
    skip_threshold_eutra(r);
  }
}

// Inter-RAT threshold CHOICE. Mirrors _skip_threshold_inter_rat.
void skip_threshold_inter_rat(UnalignedPerReader& r) {
  const uint64_t choice = r.read_choice(3);
  if (choice == 0) {  // ThresholdUTRA CHOICE
    if (r.read_choice(2) == 0) {
      r.read_constrained_int(-5, 91);  // utra-RSCP
    } else {
      r.read_constrained_int(0, 49);   // utra-EcN0
    }
  } else if (choice == 1) {
    r.read_constrained_int(0, 63);  // ThresholdGERAN
  } else {
    r.read_constrained_int(0, 63);  // ThresholdCDMA2000
  }
}

// ReportConfigEUTRA — extensible SEQUENCE. Mirrors _skip_report_config_eutra.
void skip_report_config_eutra(UnalignedPerReader& r) {
  const bool has_ext = r.read_bool();
  const uint64_t trigger_choice = r.read_choice(2);
  if (trigger_choice == 0) {  // event
    // eventId is an EXTENSIBLE CHOICE: eventA6-r10 .. eventH2-r15.
    if (r.read_bool()) {
      skip_extension_choice(r);
    } else {
      skip_event_id(r, r.read_choice(5));  // eventA1..eventA5
    }
    r.read_constrained_int(0, 30);  // hysteresis
    r.read_enum(16);                // timeToTrigger
  } else {  // periodical
    r.read_enum(2);  // purpose
  }
  r.read_enum(2);                 // triggerQuantity
  r.read_enum(2);                 // reportQuantity
  r.read_constrained_int(1, 8);   // maxReportCells
  r.read_enum(16);                // reportInterval
  r.read_enum(8);                 // reportAmount
  if (has_ext) {
    skip_extension_additions(r);
  }
}

// ReportConfigInterRAT — extensible SEQUENCE. Mirrors _skip_report_config_inter_rat.
void skip_report_config_inter_rat(UnalignedPerReader& r) {
  const bool has_ext = r.read_bool();
  const uint64_t trigger_choice = r.read_choice(2);
  if (trigger_choice == 0) {  // event
    // eventId is an EXTENSIBLE CHOICE: eventB1/B2-NR-r15.
    if (r.read_bool()) {
      skip_extension_choice(r);
    } else if (r.read_choice(2) == 0) {
      skip_threshold_inter_rat(r);   // eventB1
    } else {
      skip_threshold_eutra(r);       // eventB2 b2-Threshold1
      skip_threshold_inter_rat(r);   // eventB2 b2-Threshold2
    }
    r.read_constrained_int(0, 30);  // hysteresis
    r.read_enum(16);                // timeToTrigger
  } else {  // periodical
    r.read_enum(3);  // purpose
  }
  r.read_constrained_int(1, 8);   // maxReportCells
  r.read_enum(16);                // reportInterval
  r.read_enum(8);                 // reportAmount
  if (has_ext) {
    skip_extension_additions(r);
  }
}

// One ReportConfigToAddMod entry. Mirrors _skip_report_config.
void skip_report_config(UnalignedPerReader& r) {
  r.read_constrained_int(1, 32);  // reportConfigId
  if (r.read_choice(2) == 0) {
    skip_report_config_eutra(r);
  } else {
    skip_report_config_inter_rat(r);
  }
}

// QuantityConfig — extensible SEQUENCE, 4 OPTIONALs. Mirrors _skip_quantity_config.
void skip_quantity_config(UnalignedPerReader& r) {
  const bool has_ext = r.read_bool();
  const uint64_t opt = r.read_bits(4);

  if ((opt >> 3) & 1) {  // quantityConfigEUTRA — 2 DEFAULT fields
    const uint64_t eutra_opt = r.read_bits(2);
    if ((eutra_opt >> 1) & 1) {
      skip_filter_coefficient(r);  // filterCoefficientRSRP
    }
    if (eutra_opt & 1) {
      skip_filter_coefficient(r);  // filterCoefficientRSRQ
    }
  }
  if ((opt >> 2) & 1) {  // quantityConfigUTRA — 1 DEFAULT field
    const uint64_t qc_utra_opt = r.read_bits(1);
    r.read_enum(2);  // measQuantityUTRA-FDD
    r.read_enum(1);  // measQuantityUTRA-TDD (single value → 0 bits)
    if (qc_utra_opt & 1) {
      skip_filter_coefficient(r);
    }
  }
  if ((opt >> 1) & 1) {  // quantityConfigGERAN — 1 DEFAULT field
    const uint64_t qc_geran_opt = r.read_bits(1);
    r.read_enum(1);  // measQuantityGERAN (single value)
    if (qc_geran_opt & 1) {
      skip_filter_coefficient(r);
    }
  }
  if (opt & 1) {  // quantityConfigCDMA2000 — a plain SEQUENCE, not SetupRelease
    r.read_enum(2);  // measQuantityCDMA2000
  }
  if (has_ext) {
    skip_extension_additions(r);
  }
}

// MeasGapConfig setup body. Mirrors _skip_meas_gap_config_setup.
void skip_meas_gap_config_setup(UnalignedPerReader& r) {
  const bool gap_ext = r.read_bool();  // gapOffset extensible CHOICE marker
  if (!gap_ext) {
    if (r.read_choice(2) == 0) {
      r.read_constrained_int(0, 39);  // gp0
    } else {
      r.read_constrained_int(0, 79);  // gp1
    }
  } else {
    skip_extension_choice(r);  // gp2-r14, ...
  }
}

// An extension CHOICE alternative (open-type wrapper). Mirrors _skip_extension_choice.
void skip_extension_choice(UnalignedPerReader& r) {
  const uint64_t marker = r.read_bits(1);
  if (marker == 0) {
    r.read_bits(6);  // choice index
  } else {
    r.read_bits(8);  // semi-constrained
  }
  const uint64_t length = asn1::read_open_type_length(r);
  r.skip_bits(static_cast<int>(length * 8));
}

// -- MeasConfig ---------------------------------------------------------------

// Apply measObjectToAddModList-v9e0 positionally (same count, same order as
// measObjectToAddModList). `order[i]` indexes out.meas_objects, or -1 for a
// non-EUTRA entry. Mirrors _apply_v9e0.
void apply_v9e0(UnalignedPerReader& g, const std::vector<int>& order,
                LteMeasConfig& out) {
  if (!g.read_bool()) {
    return;  // measObjectToAddModList-v9e0 absent
  }
  const int64_t num = g.read_constrained_int(1, 32);
  for (int64_t i = 0; i < num; ++i) {
    if (!g.read_bool()) {
      continue;  // measObjectEUTRA-v9e0 absent
    }
    const int freq = static_cast<int>(g.read_constrained_int(65536, 262143));
    if (i < static_cast<int64_t>(order.size()) && order[i] >= 0) {
      EutraMeasObject& o = out.meas_objects[order[i]];
      o.has_carrier_freq_v9e0 = true;
      o.carrier_freq_v9e0 = freq;
      o.earfcn = freq;
    }
  }
}

// MeasConfig extension additions; group 1 is [[ measObjectToAddModList-v9e0 ]].
// Every group is consumed by its open-type length. Mirrors
// _decode_meas_config_extensions.
void decode_meas_config_extensions(UnalignedPerReader& r,
                                   const std::vector<int>& order,
                                   LteMeasConfig& out) {
  const uint64_t num_ext = r.read_bits(1) == 0 ? r.read_bits(6) : r.read_bits(8);
  const uint64_t bitmap = r.read_bits(static_cast<int>(num_ext + 1));
  for (uint64_t i = 0; i <= num_ext; ++i) {
    if (!((bitmap >> (num_ext - i)) & 1)) {
      continue;
    }
    const uint64_t length = asn1::read_open_type_length(r);
    std::vector<uint8_t> body;
    body.reserve(length);
    for (uint64_t b = 0; b < length; ++b) {
      body.push_back(static_cast<uint8_t>(r.read_bits(8)));
    }
    if (i == 0) {
      UnalignedPerReader g(body);
      apply_v9e0(g, order, out);
    }
  }
}

// Decode MeasConfig, surfacing EUTRA measObjects. Mirrors _decode_meas_config.
void decode_meas_config(UnalignedPerReader& r, LteMeasConfig& out) {
  const bool has_ext = r.read_bool();

  const uint64_t opt = r.read_bits(11);  // 11 OPTIONAL root fields
  const bool has_obj_add    = (opt >> 9) & 1;
  const bool has_rpt_remove = (opt >> 8) & 1;
  const bool has_rpt_add    = (opt >> 7) & 1;
  const bool has_id_remove  = (opt >> 6) & 1;
  const bool has_id_add     = (opt >> 5) & 1;
  const bool has_quant      = (opt >> 4) & 1;
  const bool has_gap        = (opt >> 3) & 1;
  const bool has_s_measure  = (opt >> 2) & 1;
  const bool has_prereg_hrpd = (opt >> 1) & 1;
  const bool has_speed_state = opt & 1;
  const bool has_obj_remove = (opt >> 10) & 1;

  std::vector<int> order;  // per measObjectToAddModList entry: index or -1

  // measObjectToRemoveList: SEQUENCE (SIZE (1..32)) OF MeasObjectId.
  if (has_obj_remove) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      out.meas_object_remove.push_back(static_cast<int>(r.read_constrained_int(1, 32)));
    }
  }

  // measObjectToAddModList: SEQUENCE (SIZE (1..32)) OF MeasObjectToAddMod.
  if (has_obj_add) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      const int obj_id = static_cast<int>(r.read_constrained_int(1, 32));
      bool is_eutra = false;

      const bool obj_ext = r.read_bool();  // measObject extensible CHOICE marker
      if (!obj_ext) {
        const uint64_t obj_choice = r.read_choice(4);
        if (obj_choice == 0) {
          EutraMeasObject o = decode_meas_object_eutra(r);
          o.meas_object_id = obj_id;
          out.meas_objects.push_back(o);
          is_eutra = true;
        } else if (obj_choice == 1) {
          skip_meas_object_utra(r);
        } else if (obj_choice == 2) {
          skip_meas_object_geran(r);
        } else if (obj_choice == 3) {
          skip_meas_object_cdma2000(r);
        }
      } else {
        skip_extension_choice(r);  // e.g. measObjectWLAN-r13 / measObjectNR-r15
      }
      if (is_eutra) {
        order.push_back(static_cast<int>(out.meas_objects.size()) - 1);
      } else {
        out.non_eutra_object_ids.push_back(obj_id);
        order.push_back(-1);
      }
    }
  }

  // reportConfigToRemoveList: SEQUENCE (SIZE (1..32)) OF ReportConfigId.
  if (has_rpt_remove) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      r.read_constrained_int(1, 32);
    }
  }

  // reportConfigToAddModList.
  if (has_rpt_add) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      skip_report_config(r);
    }
  }

  // measIdToRemoveList: SEQUENCE (SIZE (1..32)) OF MeasId.
  if (has_id_remove) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      out.meas_id_remove.push_back(static_cast<int>(r.read_constrained_int(1, 32)));
    }
  }

  // measIdToAddModList: SEQUENCE (SIZE (1..32)) OF MeasIdToAddMod.
  if (has_id_add) {
    const int64_t num = r.read_constrained_int(1, 32);
    for (int64_t i = 0; i < num; ++i) {
      MeasIdLink link;
      link.meas_id = static_cast<int>(r.read_constrained_int(1, 32));
      link.meas_object_id = static_cast<int>(r.read_constrained_int(1, 32));
      link.report_config_id = static_cast<int>(r.read_constrained_int(1, 32));
      out.meas_ids.push_back(link);
    }
  }

  // quantityConfig.
  if (has_quant) {
    skip_quantity_config(r);
  }

  // measGapConfig: CHOICE { release(0), setup(1) }.
  out.has_gap_config = false;
  if (has_gap) {
    if (r.read_choice(2) == 1) {
      out.has_gap_config = true;
      skip_meas_gap_config_setup(r);
    }
  }

  // s-Measure: RSRP-Range — INTEGER (0..97).
  out.has_s_measure = false;
  if (has_s_measure) {
    out.has_s_measure = true;
    out.s_measure = static_cast<int>(r.read_constrained_int(0, 97));
  }

  // preRegistrationInfoHRPD.
  if (has_prereg_hrpd) {
    const uint64_t prereg_opt = r.read_bits(2);
    r.read_bool();  // preRegistrationAllowed
    if ((prereg_opt >> 1) & 1) {
      r.read_constrained_int(0, 255);  // preRegistrationZoneId
    }
    if (prereg_opt & 1) {
      const int64_t num = r.read_constrained_int(1, 2);
      for (int64_t i = 0; i < num; ++i) {
        r.read_constrained_int(0, 255);
      }
    }
  }

  // speedStatePars: CHOICE { release(0), setup(1) }.
  if (has_speed_state) {
    if (r.read_choice(2) == 1) {  // setup
      r.read_enum(5);                // t-Evaluation
      r.read_enum(5);                // t-HystNormal
      r.read_constrained_int(1, 16);  // n-CellChangeMedium
      r.read_constrained_int(1, 16);  // n-CellChangeHigh
      r.read_enum(4);                // sf-Medium
      r.read_enum(4);                // sf-High
    }
  }

  if (has_ext) {
    decode_meas_config_extensions(r, order, out);
  }
}

}  // namespace

bool decode_rrc_reconfig_meas_config(int64_t log_time,
                                     const std::vector<uint8_t>& msg_data,
                                     LteMeasConfig& out) {
  if (msg_data.size() < 3) {
    return false;
  }

  UnalignedPerReader r(msg_data);

  // DL-DCCH-MessageType CHOICE { c1(0), messageClassExtension(1) }.
  if (r.read_choice(2) != 0) {
    return false;
  }
  // c1 CHOICE of 16; rrcConnectionReconfiguration = index 4.
  if (r.read_choice(16) != 4) {
    return false;
  }
  r.read_constrained_int(0, 3);  // rrc-TransactionIdentifier
  // criticalExtensions CHOICE { c1(0), criticalExtensionsFuture(1) }.
  if (r.read_choice(2) != 0) {
    return false;
  }
  // c1 CHOICE of 8; rrcConnectionReconfiguration-r8 = index 0.
  if (r.read_choice(8) != 0) {
    return false;
  }

  out.log_time = log_time;
  out.meas_objects.clear();
  out.has_gap_config = false;
  out.has_s_measure = false;
  out.meas_ids.clear();
  out.meas_id_remove.clear();
  out.meas_object_remove.clear();
  out.non_eutra_object_ids.clear();

  // RRCConnectionReconfiguration-r8-IEs: 6 OPTIONALs and NO extension marker
  // (later releases hang off nonCriticalExtension). measConfig is bit 5,
  // mobilityControlInfo bit 4.
  const uint64_t opt = r.read_bits(6);
  const bool has_meas_config = (opt >> 5) & 1;
  out.has_mobility_control = (opt >> 4) & 1;
  if (!has_meas_config) {
    return true;  // valid reconfiguration, but no measConfig — empty result
  }

  decode_meas_config(r, out);
  return true;
}

}  // namespace lte_rrc
}  // namespace diagspec
