// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ NR5G RRC decoders — port of the reference decoder's MIB and
// SIB1-cell-identity paths. Gap 4 of the wigle C++ library-parity effort;
// the NR counterpart of the gap-3 LTE RRC unit, lte_rrc_sib.{h,cpp}, that
// the 0xB821 NR5G RRC OTA enrichment leaves to the shared ASN.1/UPER layer.
//
// This is OUR enrichment code, NOT kaitai-struct-compiler output and
// NOT the vendored MIT runtime — `.ksy` is layout-only and cannot express PER
// encoding. It rides the gap-1 UPER reader,
// uper.h, and the gap-2 ASN.1 helpers, asn1_helpers.h, so it
// re-derives no PLMN decode and no §11.9 length logic.
//
// Scope, matching the LTE unit: the two
// highest-value, wigle-relevant units of the NR RRC suite — MIB (the smallest
// fully-defined NR RRC message; carries SFN MSBs + PDCCH-ConfigSIB1) and SIB1
// cellAccessRelatedInfo (MCC/MNC/TAC/NCI). SI, MeasurementReport, reconfig, SMC,
// and DL-CCCH are not in this unit — they live in the sibling nr5g_rrc_*
// units.
//
// Equivalence to the reference decoder is diffed at the FIELD-VALUE level
// (harness/nr5g_rrc_verify.py), so identifiers are chosen for a C++ reader, not
// mechanically mirrored — the MIB struct is `NrMib`, and the SIB1 cell-identity
// entry point reads best as `decode_sib1_cell_id`.
#ifndef DIAGSPEC_NR5G_RRC_H
#define DIAGSPEC_NR5G_RRC_H

#include <cstdint>
#include <string>
#include <vector>

#include "asn1_helpers.h"
#include "nr_rrc_sib.h"  // servingCellConfigCommon walk
#include "uper.h"

namespace diagspec {
namespace nr5g_rrc {

// NR Master Information Block (3GPP TS 38.331 §6.2.2). All nine fields are
// mandatory fixed-width — no OPTIONALs, no extension marker — so every field is
// always populated on a successful decode. Enumerated fields keep both the
// on-wire ordinal and the spec label.
struct NrMib {
  // 6-bit field = bits 4..9 of the 10-bit SFN (the 2 LSBs ride the PBCH
  // scrambling sequence, outside the MIB). 0..63.
  uint8_t system_frame_number = 0;
  uint8_t sub_carrier_spacing_common = 0;          // 0=scs15or60, 1=scs30or120
  std::string sub_carrier_spacing_common_name;     // "scs15or60" | "scs30or120"
  uint8_t ssb_subcarrier_offset = 0;               // kSSB, INTEGER (0..15)
  uint8_t dmrs_type_a_position = 0;                // 0=pos2, 1=pos3
  std::string dmrs_type_a_position_name;           // "pos2" | "pos3"
  uint8_t control_resource_set_zero = 0;           // CORESET#0 index, 0..15
  uint8_t search_space_zero = 0;                   // SearchSpace#0 index, 0..15
  // cellBarred ENUMERATED { barred, notBarred }. `cell_barred` is true when the
  // cell is barred (the inverse of notBarred), matching the emitted
  // "cell_barred" key so the equivalence diff compares the same polarity.
  bool cell_barred = false;
  bool intra_freq_reselection_allowed = false;     // intraFreqReselection allowed(0)
  uint8_t spare = 0;                               // 1-bit BIT STRING, normally 0
};

// NR SIB1 cell identity from cellAccessRelatedInfo (3GPP TS 38.331 §6.2.2). The
// cell-identity fields only; the remaining SIB1 sub-structures (servingCellConfig,
// si-SchedulingInfo, …) are not decoded — the decode stops after cellAccessRelatedInfo.
struct NrSib1CellId {
  std::string mcc;                                  // 3-digit MCC (primary PLMN)
  std::string mnc;                                  // 2- or 3-digit MNC
  uint32_t tracking_area_code = 0;                  // 24-bit TAC (0 if OPTIONAL absent)
  // False when the primary PLMN-IdentityInfo OMITS the OPTIONAL
  // trackingAreaCode. TS 38.331: an absent TAC means the cell supports only
  // PSCell/SCell functionality -- an NSA-only cell. Without this flag an absent
  // TAC and a broadcast TAC of 0 are both `tac == 0`. Defaults true, so a
  // default-constructed struct does not claim absence.
  bool tac_present = true;
  uint64_t cell_identity = 0;                       // 36-bit NR Cell Identity (NCI)
  std::vector<asn1::PlmnIdentity> additional_plmns; // extra PLMNs across all entries
  // servingCellConfigCommon (band, SCS, carrier bandwidth, SSB, TDD).
  // One walk serves both C++ SIB1 decoders; it lives in nr_rrc_sib.cpp.
  nr_rrc::NrServingCellConfigCommon scc;
};

// Decode an NR BCCH-BCH-Message into a MIB. Returns true and fills `out` on
// success; returns false (leaving `out` untouched) when the payload is shorter
// than 3 bytes or the outer CHOICE is messageClassExtension (no MIB content) —
// mirrors decode_nr_mib returning None.
bool decode_mib(const std::vector<uint8_t>& msg_data, NrMib& out);

// Decode NR SIB1 cellAccessRelatedInfo from a BCCH-DL-SCH UPER bitstream.
// Returns true and fills `out` on success; returns false when the message is not
// SIB1 or fails the sanity checks (first MCC not 3 digits, or zero NCI) —
// mirrors decode_nr_sib1_uper returning None. Navigates:
//   BCCH-DL-SCH-Message → message → c1 → systemInformationBlockType1
//   → cellAccessRelatedInfo → plmn-IdentityInfoList → PLMN / TAC / cellIdentity
bool decode_sib1_cell_id(const std::vector<uint8_t>& msg_data, NrSib1CellId& out);

}  // namespace nr5g_rrc
}  // namespace diagspec

#endif  // DIAGSPEC_NR5G_RRC_H
