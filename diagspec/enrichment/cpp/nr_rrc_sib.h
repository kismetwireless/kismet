// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ NR (5G) RRC SIB1 cell-identity decoder — the NR sibling of
// lte_rrc_sib.h, ported behaviour-for-behaviour from the reference decoder's
// NR SIB1 decode.
//
// Why this exists: the 0xB821 C++ path (diag_0xb821_exported_pdu) frames the RRC
// PDU for Wireshark but never decodes SIB1, so this decoder is the only
// producer of NR MCC/MNC/TAC/NCI. NR 0xB97F cells get
// their identity from 0xB821, so without it cross-record enrichment would cover
// the LTE half only and NR identity would drop silently — with
// the observation count unchanged, which makes the loss easy to miss.
//
// This is hand-written enrichment code, not kaitai-struct-compiler output:
// `.ksy` is layout-only and cannot express PER.
// Zero dependencies beyond the STL, uper.h and asn1_helpers.h.
#ifndef DIAGSPEC_NR_RRC_SIB_H
#define DIAGSPEC_NR_RRC_SIB_H

#include <climits>
#include <cstdint>
#include <string>
#include <vector>

#include "asn1_helpers.h"
#include "uper.h"

namespace diagspec {
namespace nr_rrc {

// The "absent" value for the servingCellConfigCommon ints
// below. INT_MIN is outside every range those fields can take (the widest,
// ss-PBCH-BlockPower, is -60..50), so it cannot collide with a decoded value.
constexpr int kNrAbsent = INT_MIN;

// SCS-SpecificCarrier (TS 38.331): one numerology's carrier, in PRBs.
struct NrScsCarrier {
  int scs_khz = kNrAbsent;         // kNrAbsent for a spare SubcarrierSpacing
  int carrier_bandwidth_prb = 0;   // INTEGER (1..275)
  int offset_to_carrier = 0;       // INTEGER (0..2199), PRBs from point A
};

// TDD-UL-DL-Pattern (TS 38.331). periodicity_ms carries the -v1530 value
// (3 or 4 ms) when that extension is present.
struct NrTddPattern {
  double periodicity_ms = 0.0;
  int dl_slots = 0;
  int dl_symbols = 0;
  int ul_slots = 0;
  int ul_symbols = 0;
};

// SIB1.servingCellConfigCommon, ported from the reference decoder's walk.
// Every int field is kNrAbsent when absent. The walk fills the struct in stages: a
// stage's fields are set only once the reader is confirmed still inside the
// PDU after that stage. `walk_stopped_at` is "" on a complete walk; otherwise it
// names the IE being read, with ":overrun" appended when the walk ran off the
// end of the buffer.
struct NrServingCellConfigCommon {
  std::vector<int> bands;              // DL frequencyBandList freqBandIndicatorNRs
  int band = kNrAbsent;                // bands[0]
  int offset_to_point_a = kNrAbsent;   // INTEGER (0..2199)
  std::vector<NrScsCarrier> dl_carriers;
  int scs_khz = kNrAbsent;             // dl_carriers[0]
  int carrier_bandwidth_prb = kNrAbsent;
  int channel_bandwidth_mhz = kNrAbsent;  // TS 38.101-1/-2 Table 5.3.2-1
  int initial_dl_bwp_scs_khz = kNrAbsent;
  int ssb_in_one_group = kNrAbsent;    // BIT STRING (8), MSB = SSB 0
  int ssb_group_presence = kNrAbsent;  // BIT STRING (8), FR2 only
  int ssb_periodicity_ms = kNrAbsent;
  int tdd_reference_scs_khz = kNrAbsent;
  bool has_tdd_pattern1 = false;
  NrTddPattern tdd_pattern1;
  bool has_tdd_pattern2 = false;
  NrTddPattern tdd_pattern2;
  int ss_pbch_block_power_dbm = kNrAbsent;  // INTEGER (-60..50)
  std::string walk_stopped_at;
};

// Channel bandwidth in MHz for a carrier of `nrb` PRBs at `scs_khz` (TS
// 38.101-1 FR1 / 38.101-2 FR2 Table 5.3.2-1). FR1 unless `band` is an FR2 band
// (>= n257). kNrAbsent when either input is absent or the (SCS, N_RB) pair is
// not a table maximum configuration. Mirrors nr_channel_bandwidth_mhz().
int nr_channel_bandwidth_mhz(int scs_khz, int nrb, int band = kNrAbsent);

// Walk from the end of plmn-IdentityInfoList through servingCellConfigCommon.
// `r` must sit just past the last PLMN-IdentityInfo entry; `pdu_bits` is the
// PDU length in bits (the overrun gate). The three flags come from the SIB1
// root bitmap / CellAccessRelatedInfo. Never fails as a whole: a stop is
// recorded in out.walk_stopped_at and the fields already reached are kept.
void walk_serving_cell_config_common(asn1::UnalignedPerReader& r, size_t pdu_bits,
                                     bool cari_has_ext, bool has_conn_est,
                                     bool has_si_sched,
                                     NrServingCellConfigCommon& out);

// SIB1.cellAccessRelatedInfo, the cell-identity fields (TS 38.331 §6.2.2).
//
// The widths differ from LTE and the difference is load-bearing: NR's TAC is
// 24 bits (LTE 16) and the NR Cell Identity is 36 bits (LTE 28) — so `cell_id`
// MUST be 64-bit. A uint32_t here would silently truncate the top 4 bits of
// every NCI, producing a plausible-looking but wrong cell identity rather than a
// visible failure.
struct NrSib1CellId {
  std::string mcc;                   // 3-digit MCC ("" when never populated)
  std::string mnc;                   // 2- or 3-digit MNC
  uint32_t tac = 0;                  // TrackingAreaCode BIT STRING (SIZE (24))
  // False when the primary PLMN-IdentityInfo OMITS the OPTIONAL
  // trackingAreaCode. TS 38.331: an absent TAC means the cell supports only
  // PSCell/SCell functionality -- an NSA-only cell. Without this flag an absent
  // TAC and a broadcast TAC of 0 are both `tac == 0`. Defaults true, so a
  // default-constructed struct does not claim absence.
  bool tac_present = true;
  uint64_t cell_id = 0;              // CellIdentity BIT STRING (SIZE (36))
  std::vector<asn1::PlmnIdentity> additional_plmns;
  // servingCellConfigCommon (band, SCS, carrier bandwidth, SSB, TDD).
  // All-absent when SIB1 omits the OPTIONAL servingCellConfigCommon.
  NrServingCellConfigCommon scc;
};

// Decode NR SIB1 cell identity from a BCCH-DL-SCH UPER bitstream. Returns true
// and fills `out` on success; returns false (leaving `out` untouched) when the
// message is not SIB1 or fails the sanity checks. Navigates:
//   BCCH-DL-SCH-Message → message → c1 → systemInformationBlockType1
//   → cellAccessRelatedInfo → plmn-IdentityInfoList[0]
//   → plmn-IdentityList, trackingAreaCode, cellIdentity
//
// The sanity gate is `mcc.size() == 3 && cell_id != 0` — deliberately NOT
// `tac != 0` as in the LTE decoder. NR's trackingAreaCode is OPTIONAL (TS 38.331
// PLMN-IdentityInfo), so a legitimate SIB1 can carry tac == 0 and must be
// accepted. Adding a TAC gate here would silently drop real NR cells.
bool decode_nr_sib1(const std::vector<uint8_t>& msg_data, NrSib1CellId& out);

}  // namespace nr_rrc
}  // namespace diagspec

#endif  // DIAGSPEC_NR_RRC_SIB_H
