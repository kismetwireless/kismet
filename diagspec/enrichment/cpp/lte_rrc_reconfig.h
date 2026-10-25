// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ LTE RRC RRCConnectionReconfiguration measConfig decoder — port of
// the reference decoder's. Part of the LTE RRC decoder suite
// (SIBs + reconfig + meas-report); this is the downlink DL-DCCH measConfig unit,
// reached live from the 0xB0C0 (LTE RRC OTA) path.
//
// Like SIB1 (lte_rrc_sib.{h,cpp}) and MeasurementReport (lte_rrc_meas_report),
// this is a whole-message decoder: it walks the DL-DCCH-Message CHOICE tree from
// bit 0 and REJECTS (returns false) any message that is not an
// RRCConnectionReconfiguration-r8, so the driver emits JSON null for the same
// inputs the reference decoder rejects. A well-formed reconfiguration that
// simply carries no measConfig decodes SUCCESSFULLY to an empty meas-object list
// (true, with meas_objects empty) — an early return that is distinct from the
// reject path.
//
// It rides the UPER reader (uper.h) and the ASN.1 helpers (asn1_helpers.h):
// the extension-additions skip is the shared
// skip_extension_additions and the ENUMERATED tables (AllowedMeasBandwidth,
// Q-OffsetRange) are the shared asn1_helpers tables — no re-derived §11.9 length
// logic, no re-hand-ported enum tables.
//
// The decoder is deliberately narrow: only measObjectEUTRA carrier
// frequencies are SURFACED; the UTRA / GERAN / CDMA2000 measObjects, every
// reportConfig / quantityConfig / measId / measGap body, and all remaining
// MeasConfig fields are decoded only far enough to advance the bit cursor to the
// next surfaced field (the "skip" helpers). Equivalence to the reference decoder
// is diffed at the FIELD-VALUE level (harness/lte_rrc_reconfig_verify.py).
#ifndef DIAGSPEC_LTE_RRC_RECONFIG_H
#define DIAGSPEC_LTE_RRC_RECONFIG_H

#include <cstdint>
#include <vector>

namespace diagspec {
namespace lte_rrc {

// One neighbor cell from cellsToAddModList inside a measObjectEUTRA
// (CellsToAddMod). cell_offset is the resolved Q-OffsetRange dB value.
struct NeighborCellOffset {
  int cell_index = 0;   // INTEGER (1..32)
  int pci = 0;          // PhysCellId (0..503)
  int cell_offset = 0;  // dB (Q-OffsetRange ENUMERATED → dB)
};

// One EUTRA measurement object — a carrier frequency the UE is told to measure
// (MeasObjectEUTRA), with any per-neighbor cell offsets.
//
// `earfcn` is the EFFECTIVE carrier: carrierFreq-v9e0 (65536..262143) when the
// MeasConfig v9e0 extension group signalled one — the base carrierFreq is then
// the placeholder 65535 — else the base carrierFreq.
struct EutraMeasObject {
  int meas_object_id = 0;  // MeasObjectId (1..32) — the measId join key
  int earfcn = 0;      // effective EARFCN (0..262143)
  int bandwidth = 0;   // allowedMeasBandwidth RBs (6/15/25/50/75/100), 0 if OOB
  int offset = 0;      // offsetFreq Q-OffsetRange dB (DEFAULT dB0 → 0)
  bool has_carrier_freq_v9e0 = false;
  int carrier_freq_v9e0 = 0;  // raw extension value when has_carrier_freq_v9e0
  std::vector<NeighborCellOffset> cells;
};

// measIdToAddModList entry: links a measId to its measObject.
struct MeasIdLink {
  int meas_id = 0;           // MeasId (1..32)
  int meas_object_id = 0;    // MeasObjectId (1..32)
  int report_config_id = 0;  // ReportConfigId (1..32)
};

// A decoded measConfig from an RRCConnectionReconfiguration. `has_s_measure`
// gates the OPTIONAL s_measure (RSRP threshold 0..97): the key is dropped when
// absent, so the C++ driver emits it only when has_s_measure is true.
struct LteMeasConfig {
  int64_t log_time = 0;   // passthrough (not decoded from the wire)
  std::vector<EutraMeasObject> meas_objects;
  bool has_gap_config = false;
  bool has_s_measure = false;
  int s_measure = 0;
  // measId → measObject join state; measConfig is a delta, so the
  // remove lists matter as much as the adds.
  std::vector<MeasIdLink> meas_ids;
  std::vector<int> meas_id_remove;
  std::vector<int> meas_object_remove;
  // measObjectIds (re)defined as a non-EUTRA object in this message.
  std::vector<int> non_eutra_object_ids;
  bool has_mobility_control = false;  // mobilityControlInfo present (handover)
};

// Decode a measConfig from a DL-DCCH RRCConnectionReconfiguration UPER
// bitstream. Returns true and fills `out` on an RRCConnectionReconfiguration-r8
// (even when it carries no measConfig — `out.meas_objects` is then empty);
// returns false (leaving `out` unspecified) for a < 3-byte buffer or any CHOICE
// that is not rrcConnectionReconfiguration-r8 — mirroring
// decode_rrc_reconfig_meas_config's None returns. `log_time` is stored verbatim.
bool decode_rrc_reconfig_meas_config(int64_t log_time,
                                     const std::vector<uint8_t>& msg_data,
                                     LteMeasConfig& out);

}  // namespace lte_rrc
}  // namespace diagspec

#endif  // DIAGSPEC_LTE_RRC_RECONFIG_H
