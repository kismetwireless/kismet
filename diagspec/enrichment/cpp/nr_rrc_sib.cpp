// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the diagspec C++ NR RRC SIB1 decoder (see nr_rrc_sib.h).
// Ported behaviour-for-behaviour from the reference decoder's NR SIB1 decode.
//
// ASN.1 shape decoded (3GPP TS 38.331 §6.2.2):
//   BCCH-DL-SCH-MessageType ::= CHOICE { c1 CHOICE { systemInformation,
//                                        systemInformationBlockType1 },
//                                        messageClassExtension SEQUENCE {} }
//   SIB1 ::= SEQUENCE {                 -- NOT extensible; see below
//     cellSelectionInfo        OPTIONAL,
//     cellAccessRelatedInfo    CellAccessRelatedInfo,   -- MANDATORY
//     connEstFailureControl    OPTIONAL, si-SchedulingInfo OPTIONAL,
//     servingCellConfigCommon  OPTIONAL, ims-EmergencySupport OPTIONAL,
//     eCallOverIMS-Support     OPTIONAL, ue-TimersAndConstants OPTIONAL,
//     uac-BarringInfo          OPTIONAL, useFullResumeID OPTIONAL,
//     lateNonCriticalExtension OPTIONAL, nonCriticalExtension OPTIONAL }
//   CellAccessRelatedInfo ::= SEQUENCE {
//     plmn-IdentityInfoList    SEQUENCE (SIZE (1..12)) OF PLMN-IdentityInfo,
//     cellReservedForOtherUse  ENUMERATED { true } OPTIONAL, ... }
//   PLMN-IdentityInfo ::= SEQUENCE {
//     plmn-IdentityList  SEQUENCE (SIZE (1..12)) OF PLMN-Identity,
//     trackingAreaCode   BIT STRING (SIZE (24)) OPTIONAL,
//     ranac              INTEGER (0..255)       OPTIONAL,
//     cellIdentity       BIT STRING (SIZE (36)),
//     cellReservedForOperatorUse ENUMERATED { reserved, notReserved }, ... }
#include "nr_rrc_sib.h"

#include <cstdint>
#include <string>
#include <vector>

namespace diagspec {
namespace nr_rrc {

using asn1::UnalignedPerReader;
using asn1::decode_plmn_identity;
using asn1::skip_extension_additions;

namespace {

// CellSelectionInfo ::= SEQUENCE { q-RxLevMin INTEGER (-70..-22),
//   q-RxLevMinOffset INTEGER (1..8) OPTIONAL, q-RxLevMinSUL OPTIONAL,
//   q-QualMin INTEGER (-43..-12) OPTIONAL, q-QualMinOffset OPTIONAL }
// Not extensible in the base spec, so there is no extension-presence bit. The
// values are read and discarded; only the bit ADVANCE matters — every field
// after cellSelectionInfo is mis-aligned if this skip is off by a bit.
void skip_nr_cell_selection_info(UnalignedPerReader& r) {
  const uint64_t opt = r.read_bits(4);
  r.read_constrained_int(-70, -22);              // q-RxLevMin (mandatory)
  if ((opt >> 3) & 1) r.read_constrained_int(1, 8);      // q-RxLevMinOffset
  if ((opt >> 2) & 1) r.read_constrained_int(-70, -22);  // q-RxLevMinSUL
  if ((opt >> 1) & 1) r.read_constrained_int(-43, -12);  // q-QualMin
  if (opt & 1)        r.read_constrained_int(1, 8);      // q-QualMinOffset
}

}  // namespace

bool decode_nr_sib1(const std::vector<uint8_t>& msg_data, NrSib1CellId& out) {
  // Cheap size reject (under 10 bytes). The
  // C++ UPER reader returns 0 past-end rather than throwing, so the size gate
  // and the sanity checks at the bottom carry the load an exception handler
  // would — exactly as in lte_rrc_sib.cpp.
  if (msg_data.size() < 10) return false;

  UnalignedPerReader r(msg_data);

  // BCCH-DL-SCH-MessageType: CHOICE { c1(0), messageClassExtension(1) }.
  if (r.read_choice(2) != 0) return false;  // not c1
  // c1: CHOICE { systemInformation(0), systemInformationBlockType1(1) }.
  //
  // TWO alternatives, encoded in 1 bit. NR has never had LTE's spare1/spare2;
  // reading 2 bits on that assumption mis-aligns every field after it. Keep
  // read_choice(2), not (4).
  if (r.read_choice(2) != 1) return false;  // not SIB1

  // NO extension-presence bit here, unlike LTE's SIB1. The published 38.331
  // ASN.1 gives SIB1 an explicit nonCriticalExtension chain rather than the
  // `...` marker, so the optional bitmap starts immediately. Verified against
  // pycrate's compiled grammar (_ext is None on SIB1). Reading a
  // phantom extension bit here shifts the whole record by one bit.
  //
  // 11 root OPTIONALs, MSB-first; bit 10 is cellSelectionInfo.
  // cellAccessRelatedInfo is MANDATORY and therefore NOT in the bitmap.
  const uint64_t opt_bitmap = r.read_bits(11);
  if ((opt_bitmap >> 10) & 1)
    skip_nr_cell_selection_info(r);

  // cellAccessRelatedInfo (MANDATORY): extensible SEQUENCE with 1 OPTIONAL.
  // The extension bit is kept: the servingCellConfigCommon walk must skip the
  // additions (Rel-16 npn-IdentityInfoList-r16, ...) to find what follows.
  const bool cari_has_ext = r.read_bool();
  r.read_bits(1);  // cellReservedForOtherUse presence (not decoded)

  const int64_t num_entries = r.read_constrained_int(1, 12);

  NrSib1CellId decoded;
  std::string primary_mcc;
  std::string primary_mnc;
  uint32_t primary_tac = 0;
  bool primary_tac_present = false;
  uint64_t primary_cell_id = 0;

  for (int64_t entry_idx = 0; entry_idx < num_entries; ++entry_idx) {
    // PLMN-IdentityInfo — extensible SEQUENCE, 2 OPTIONALs (TAC, ranac).
    const bool pii_has_ext = r.read_bool();
    const uint64_t pii_opt = r.read_bits(2);
    const bool has_tac = ((pii_opt >> 1) & 1) != 0;
    const bool has_ranac = (pii_opt & 1) != 0;

    const int64_t num_plmns = r.read_constrained_int(1, 12);
    std::vector<asn1::PlmnIdentity> plmns;
    plmns.reserve(static_cast<size_t>(num_plmns > 0 ? num_plmns : 0));
    for (int64_t i = 0; i < num_plmns; ++i)
      plmns.push_back(decode_plmn_identity(r));

    uint32_t tac = 0;
    if (has_tac)
      tac = static_cast<uint32_t>(r.read_bits(24));
    if (has_ranac)
      r.read_constrained_int(0, 255);

    // 36 bits — read into a uint64_t. See the header on why this width matters.
    const uint64_t cell_id = r.read_bits(36);

    r.read_enum(2);  // cellReservedForOperatorUse (discarded)

    if (pii_has_ext)
      skip_extension_additions(r);

    if (entry_idx == 0) {
      if (!plmns.empty()) {
        primary_mcc = plmns[0].mcc;
        primary_mnc = plmns[0].mnc;
        decoded.additional_plmns.insert(decoded.additional_plmns.end(),
                                        plmns.begin() + 1, plmns.end());
      }
      primary_tac = tac;
      primary_tac_present = has_tac;
      primary_cell_id = cell_id;
    } else {
      decoded.additional_plmns.insert(decoded.additional_plmns.end(),
                                      plmns.begin(), plmns.end());
    }
  }

  // Sanity, exactly: 3-digit MCC on the primary entry and a
  // non-zero NCI. There is deliberately no TAC gate (see the header): NR's
  // trackingAreaCode is OPTIONAL, so tac == 0 is a legitimate decode.
  if (primary_mcc.size() != 3 || primary_cell_id == 0)
    return false;

  decoded.mcc = primary_mcc;
  decoded.mnc = primary_mnc;
  decoded.tac = primary_tac;
  decoded.tac_present = primary_tac_present;
  decoded.cell_id = primary_cell_id;

  // Past the identity, a failure keeps the identity; the walk
  // records where it stopped instead of rejecting the SIB1. Bit 7 of the root
  // bitmap is servingCellConfigCommon; bits 9/8 are the two OPTIONALs before it.
  if ((opt_bitmap >> 7) & 1)
    walk_serving_cell_config_common(r, msg_data.size() * 8, cari_has_ext,
                                    ((opt_bitmap >> 9) & 1) != 0,
                                    ((opt_bitmap >> 8) & 1) != 0, decoded.scc);
  out = decoded;
  return true;
}

// ── servingCellConfigCommon ──────────────────────────────────────────────
//
// Ported function-for-function from the reference decoder's walk.
// Each helper is labelled with the walk step it implements; the ASN.1 each one
// walks is the TS 38.331 IE of the same name. The values of skipped
// IEs are discarded; only the bit ADVANCE matters, and a skip that is off by
// one bit mis-aligns every field after it.
//
// The walk throws and records the stage. The two exception
// types below are its two outcomes: WalkOverrun (the
// reader went past the PDU, which UnalignedPerReader reports
// only as zero bits), WalkInvalid (an ENUMERATED index
// past its value count). Both stay inside walk_serving_cell_config_common.
namespace {

using asn1::read_open_type_length;

struct WalkOverrun {};
struct WalkInvalid {};

// SubcarrierSpacing ENUMERATED { kHz15, kHz30, kHz60, kHz120, kHz240,
// spare3, spare2, spare1 }: 8 values, 3 bits. Spares decode to kNrAbsent.
int scs_khz_of(uint64_t code) {
  static const int kScs[] = {15, 30, 60, 120, 240};
  return code < 5 ? kScs[code] : kNrAbsent;
}

int read_scs(UnalignedPerReader& r) { return scs_khz_of(r.read_enum(8)); }

// _check_inside: UnalignedPerReader zero-pads past the end instead of failing,
// so an over-read (a grammar slip, or a truncated PDU) would otherwise decode
// as zeros.
void check_inside(const UnalignedPerReader& r, size_t pdu_bits) {
  if (r.bit_pos() > pdu_bits) throw WalkOverrun();
}

// _read_enum_checked
uint64_t read_enum_checked(UnalignedPerReader& r, uint64_t n_values) {
  const uint64_t v = r.read_enum(n_values);
  if (v >= n_values) throw WalkInvalid();
  return v;
}

// _skip_ext_seq_with_enum (BCCH-Config, ue-Specific search space)
void skip_ext_seq_with_enum(UnalignedPerReader& r, uint64_t n_values) {
  const bool ext = r.read_bool();
  r.read_enum(n_values);
  if (ext) skip_extension_additions(r);
}

// _skip_empty_ext_seq
void skip_empty_ext_seq(UnalignedPerReader& r) {
  if (r.read_bool()) skip_extension_additions(r);
}

// _skip_multi_freq_band_list_nr: returns the
// freqBandIndicatorNR values actually signalled.
std::vector<int> read_multi_freq_band_list_nr(UnalignedPerReader& r) {
  std::vector<int> bands;
  const int64_t n = r.read_constrained_int(1, 8);
  for (int64_t i = 0; i < n; ++i) {
    const uint64_t opt = r.read_bits(2);  // freqBandIndicatorNR, nr-NS-PmaxList
    if ((opt >> 1) & 1)
      bands.push_back(static_cast<int>(r.read_constrained_int(1, 1024)));
    if (opt & 1) {
      const int64_t n_pmax = r.read_constrained_int(1, 8);
      for (int64_t j = 0; j < n_pmax; ++j) {
        if (r.read_bool()) r.read_constrained_int(-30, 33);  // additionalPmax
        r.read_constrained_int(0, 7);  // additionalSpectrumEmission
      }
    }
  }
  return bands;
}

// _read_scs_carrier_list
std::vector<NrScsCarrier> read_scs_carrier_list(UnalignedPerReader& r) {
  std::vector<NrScsCarrier> out;
  const int64_t n = r.read_constrained_int(1, 5);
  for (int64_t i = 0; i < n; ++i) {
    const bool ext = r.read_bool();
    NrScsCarrier c;
    c.offset_to_carrier = static_cast<int>(r.read_constrained_int(0, 2199));
    c.scs_khz = read_scs(r);
    c.carrier_bandwidth_prb = static_cast<int>(r.read_constrained_int(1, 275));
    if (ext) skip_extension_additions(r);
    out.push_back(c);
  }
  return out;
}

// _read_bwp: not extensible; returns the SCS in kHz.
int read_bwp(UnalignedPerReader& r) {
  r.read_bits(1);  // cyclicPrefix presence; ENUMERATED {extended} is 0 bits
  r.read_constrained_int(0, 37949);  // locationAndBandwidth
  return read_scs(r);
}

// _read_setup_release: CHOICE { release NULL, setup X }; true on setup.
bool read_setup_release(UnalignedPerReader& r) { return r.read_choice(2) == 1; }

// _skip_time_domain_allocation_list (PDSCH and PUSCH forms share the shape)
void skip_time_domain_allocation_list(UnalignedPerReader& r) {
  const int64_t n = r.read_constrained_int(1, 16);
  for (int64_t i = 0; i < n; ++i) {
    if (r.read_bool()) r.read_constrained_int(0, 32);  // k0 | k2
    r.read_enum(2);                                    // mappingType
    r.read_constrained_int(0, 127);                    // startSymbolAndLength
  }
}

// _skip_control_resource_set
void skip_control_resource_set(UnalignedPerReader& r) {
  const bool ext = r.read_bool();
  const uint64_t opt = r.read_bits(4);
  r.read_constrained_int(0, 11);  // controlResourceSetId
  r.read_bits(45);                // frequencyDomainResources
  r.read_constrained_int(1, 3);   // duration
  if (r.read_choice(2) == 0) {    // cce-REG-MappingType: interleaved
    const bool has_shift = r.read_bool();
    r.read_enum(3);  // reg-BundleSize
    r.read_enum(3);  // interleaverSize
    if (has_shift) r.read_constrained_int(0, 274);
  }
  r.read_enum(2);  // precoderGranularity
  for (int bit = 3; bit >= 2; --bit) {  // tci-StatesPDCCH-ToAdd/ToReleaseList
    if ((opt >> bit) & 1) {
      const int64_t n = r.read_constrained_int(1, 64);
      for (int64_t i = 0; i < n; ++i) r.read_constrained_int(0, 127);
    }
  }
  // bit 1: tci-PresentInDCI ENUMERATED {enabled} -- zero bits
  if (opt & 1) r.read_constrained_int(0, 65535);  // pdcch-DMRS-ScramblingID
  if (ext) skip_extension_additions(r);
}

// _skip_search_space_common
void skip_search_space_common(UnalignedPerReader& r) {
  const uint64_t opt = r.read_bits(5);
  if ((opt >> 4) & 1) skip_empty_ext_seq(r);  // dci-Format0-0-AndFormat1-0
  if ((opt >> 3) & 1) {                       // dci-Format2-0
    const bool ext = r.read_bool();
    const uint64_t sfi = r.read_bits(5);
    for (int b = 0; b < 5; ++b)
      if ((sfi >> b) & 1) r.read_enum(2);
    if (ext) skip_extension_additions(r);
  }
  if ((opt >> 2) & 1) skip_empty_ext_seq(r);  // dci-Format2-1
  if ((opt >> 1) & 1) skip_empty_ext_seq(r);  // dci-Format2-2
  if (opt & 1) {                              // dci-Format2-3
    const bool ext = r.read_bool();
    if (r.read_bool()) r.read_enum(8);  // dummy1
    r.read_enum(2);                     // dummy2
    if (ext) skip_extension_additions(r);
  }
}

// _skip_search_space: NOT extensible.
void skip_search_space(UnalignedPerReader& r) {
  // monitoringSlotPeriodicityAndOffset: slot period per CHOICE alternative;
  // sl1 is NULL, slN carries INTEGER (0..N-1).
  static const int kPeriods[] = {1, 2, 4, 5, 8, 10, 16, 20, 40, 80, 160, 320,
                                 640, 1280, 2560};
  const uint64_t opt = r.read_bits(6);
  r.read_constrained_int(0, 39);  // searchSpaceId
  if ((opt >> 5) & 1) r.read_constrained_int(0, 11);  // controlResourceSetId
  if ((opt >> 4) & 1) {
    const int period = kPeriods[read_enum_checked(r, 15)];
    if (period > 1) r.read_constrained_int(0, period - 1);
  }
  if ((opt >> 3) & 1) r.read_constrained_int(2, 2559);  // duration
  if ((opt >> 2) & 1) r.read_bits(14);  // monitoringSymbolsWithinSlot
  if ((opt >> 1) & 1)
    for (int i = 0; i < 5; ++i) r.read_enum(8);  // nrofCandidates
  if (opt & 1) {  // searchSpaceType
    if (r.read_choice(2) == 0)
      skip_search_space_common(r);
    else
      skip_ext_seq_with_enum(r, 2);  // ue-Specific { dci-Formats, ... }
  }
}

// _skip_pdcch_config_common
void skip_pdcch_config_common(UnalignedPerReader& r) {
  const bool ext = r.read_bool();
  const uint64_t opt = r.read_bits(8);
  if ((opt >> 7) & 1) r.read_constrained_int(0, 15);  // controlResourceSetZero
  if ((opt >> 6) & 1) skip_control_resource_set(r);
  if ((opt >> 5) & 1) r.read_constrained_int(0, 15);  // searchSpaceZero
  if ((opt >> 4) & 1) {                               // commonSearchSpaceList
    const int64_t n = r.read_constrained_int(1, 4);
    for (int64_t i = 0; i < n; ++i) skip_search_space(r);
  }
  for (int bit = 3; bit >= 0; --bit)  // four SearchSpaceId OPTIONALs
    if ((opt >> bit) & 1) r.read_constrained_int(0, 39);
  if (ext) skip_extension_additions(r);
}

// _skip_bwp_downlink_common: returns the genericParameters SCS in kHz.
int skip_bwp_downlink_common(UnalignedPerReader& r) {
  const bool ext = r.read_bool();
  const uint64_t opt = r.read_bits(2);
  const int scs = read_bwp(r);
  if (((opt >> 1) & 1) && read_setup_release(r)) skip_pdcch_config_common(r);
  if ((opt & 1) && read_setup_release(r)) {
    // PDSCH-ConfigCommon { pdsch-TimeDomainAllocationList OPTIONAL, ... }
    const bool p_ext = r.read_bool();
    if (r.read_bool()) skip_time_domain_allocation_list(r);
    if (p_ext) skip_extension_additions(r);
  }
  if (ext) skip_extension_additions(r);
  return scs;
}

// _skip_pcch_config
void skip_pcch_config(UnalignedPerReader& r) {
  // firstPDCCH-MonitoringOccasionOfPO: INTEGER upper bound per alternative.
  static const int64_t kFirstPdcchMoHi[] = {139, 279, 559, 1119, 2239, 4479,
                                            8959, 17919};
  static const int64_t kNAndPfHi[] = {1, 3, 7, 15};  // halfT .. oneSixteenthT
  const bool ext = r.read_bool();
  const bool has_first = r.read_bool();
  r.read_enum(4);  // defaultPagingCycle
  const uint64_t n_and_pf = read_enum_checked(r, 5);
  if (n_and_pf) r.read_constrained_int(0, kNAndPfHi[n_and_pf - 1]);
  r.read_enum(3);  // ns
  if (has_first) {
    const int64_t hi = kFirstPdcchMoHi[r.read_choice(8)];
    const int64_t n = r.read_constrained_int(1, 4);
    for (int64_t i = 0; i < n; ++i) r.read_constrained_int(0, hi);
  }
  if (ext) skip_extension_additions(r);
}

// _skip_rach_config_generic
void skip_rach_config_generic(UnalignedPerReader& r) {
  const bool ext = r.read_bool();
  r.read_constrained_int(0, 255);     // prach-ConfigurationIndex
  r.read_enum(4);                     // msg1-FDM
  r.read_constrained_int(0, 274);     // msg1-FrequencyStart
  r.read_constrained_int(0, 15);      // zeroCorrelationZoneConfig
  r.read_constrained_int(-202, -60);  // preambleReceivedTargetPower
  r.read_enum(11);                    // preambleTransMax
  r.read_enum(4);                     // powerRampingStep
  r.read_enum(8);                     // ra-ResponseWindow
  if (ext) skip_extension_additions(r);
}

// _skip_rach_config_common
void skip_rach_config_common(UnalignedPerReader& r) {
  // ssb-perRACH-OccasionAndCB-PreamblesPerSSB: payload value count per
  // CHOICE alternative.
  static const uint64_t kSsbPerRachValues[] = {16, 16, 16, 16, 8, 16, 8, 4};
  const bool ext = r.read_bool();
  const uint64_t opt = r.read_bits(7);
  skip_rach_config_generic(r);
  if ((opt >> 6) & 1) r.read_constrained_int(1, 63);  // totalNumberOfRA-Preambles
  if ((opt >> 5) & 1) r.read_enum(kSsbPerRachValues[r.read_choice(8)]);
  if ((opt >> 4) & 1) {  // groupBconfigured
    r.read_enum(16);
    r.read_enum(8);
    r.read_constrained_int(1, 64);
  }
  r.read_enum(8);  // ra-ContentionResolutionTimer
  if ((opt >> 3) & 1) r.read_constrained_int(0, 127);  // rsrp-ThresholdSSB
  if ((opt >> 2) & 1) r.read_constrained_int(0, 127);  // rsrp-ThresholdSSB-SUL
  if (r.read_choice(2) == 0)  // prach-RootSequenceIndex
    r.read_constrained_int(0, 837);
  else
    r.read_constrained_int(0, 137);
  if ((opt >> 1) & 1) r.read_enum(8);  // msg1-SubcarrierSpacing
  r.read_enum(3);                      // restrictedSetConfig
  // bit 0: msg3-transformPrecoder ENUMERATED {enabled} -- zero bits
  if (ext) skip_extension_additions(r);
}

// _skip_bwp_uplink_common
void skip_bwp_uplink_common(UnalignedPerReader& r) {
  const bool ext = r.read_bool();
  const uint64_t opt = r.read_bits(3);
  read_bwp(r);
  if (((opt >> 2) & 1) && read_setup_release(r)) skip_rach_config_common(r);
  if (((opt >> 1) & 1) && read_setup_release(r)) {
    // PUSCH-ConfigCommon
    const bool p_ext = r.read_bool();
    const uint64_t p_opt = r.read_bits(4);
    if ((p_opt >> 2) & 1) skip_time_domain_allocation_list(r);
    if ((p_opt >> 1) & 1) r.read_constrained_int(-1, 6);   // msg3-DeltaPreamble
    if (p_opt & 1) r.read_constrained_int(-202, 24);       // p0-NominalWithGrant
    if (p_ext) skip_extension_additions(r);
  }
  if ((opt & 1) && read_setup_release(r)) {
    // PUCCH-ConfigCommon
    const bool p_ext = r.read_bool();
    const uint64_t p_opt = r.read_bits(3);
    if ((p_opt >> 2) & 1) r.read_constrained_int(0, 15);   // pucch-ResourceCommon
    r.read_enum(3);                                        // pucch-GroupHopping
    if ((p_opt >> 1) & 1) r.read_constrained_int(0, 1023); // hoppingId
    if (p_opt & 1) r.read_constrained_int(-202, 24);       // p0-nominal
    if (p_ext) skip_extension_additions(r);
  }
  if (ext) skip_extension_additions(r);
}

// _skip_uplink_config_common_sib: not extensible.
void skip_uplink_config_common_sib(UnalignedPerReader& r) {
  // FrequencyInfoUL-SIB (extensible, 4 OPTIONALs)
  const bool ext = r.read_bool();
  const uint64_t opt = r.read_bits(4);
  if ((opt >> 3) & 1) read_multi_freq_band_list_nr(r);
  if ((opt >> 2) & 1) r.read_constrained_int(0, 3279165);  // absoluteFrequencyPointA
  read_scs_carrier_list(r);
  if ((opt >> 1) & 1) r.read_constrained_int(-30, 33);  // p-Max
  // bit 0: frequencyShift7p5khz ENUMERATED {true} -- zero bits
  if (ext) skip_extension_additions(r);
  skip_bwp_uplink_common(r);  // initialUplinkBWP
  r.read_enum(8);             // timeAlignmentTimerCommon
}

// _read_first_extension_group: skip an extension-additions block, returning
// the first group's octets in `first` (true when that group is present). A
// group longer than the rest of the PDU throws WalkOverrun BEFORE any of it is
// read; on a corrupted length (up to 64K+ octets from the fragmented form)
// reading first would stall the bit-at-a-time reader.
bool read_first_extension_group(UnalignedPerReader& r, size_t pdu_bits,
                                std::vector<uint8_t>& first) {
  const uint64_t num_ext = (r.read_bits(1) == 0) ? r.read_bits(6) : r.read_bits(8);
  std::vector<uint8_t> present;
  present.reserve(static_cast<size_t>(num_ext) + 1);
  for (uint64_t i = 0; i <= num_ext; ++i)
    present.push_back(static_cast<uint8_t>(r.read_bits(1)));
  bool have_first = false;
  for (uint64_t i = 0; i <= num_ext; ++i) {
    if (!present[i]) continue;
    const uint64_t length = read_open_type_length(r);
    if (r.bit_pos() + length * 8 > pdu_bits) throw WalkOverrun();
    if (i == 0) {
      first.clear();
      for (uint64_t b = 0; b < length; ++b)
        first.push_back(static_cast<uint8_t>(r.read_bits(8)));
      have_first = true;
    } else {
      r.skip_bits(static_cast<int>(length * 8));
    }
  }
  return have_first;
}

// _read_tdd_pattern. The -v1530 extension, when present, replaces the root
// periodicity.
NrTddPattern read_tdd_pattern(UnalignedPerReader& r, size_t pdu_bits) {
  static const double kPeriodMs[] = {0.5, 0.625, 1.0, 1.25, 2.0, 2.5, 5.0, 10.0};
  static const double kPeriodV1530Ms[] = {3.0, 4.0};
  const bool ext = r.read_bool();
  NrTddPattern p;
  p.periodicity_ms = kPeriodMs[r.read_enum(8)];
  p.dl_slots = static_cast<int>(r.read_constrained_int(0, 320));
  p.dl_symbols = static_cast<int>(r.read_constrained_int(0, 13));
  p.ul_slots = static_cast<int>(r.read_constrained_int(0, 320));
  p.ul_symbols = static_cast<int>(r.read_constrained_int(0, 13));
  if (ext) {
    std::vector<uint8_t> v1530;
    if (read_first_extension_group(r, pdu_bits, v1530)) {
      // Group: SEQUENCE { dl-UL-TransmissionPeriodicity-v1530 OPTIONAL }
      UnalignedPerReader g(v1530);
      if (g.read_bool()) p.periodicity_ms = kPeriodV1530Ms[g.read_enum(2)];
    }
  }
  return p;
}

// _skip_conn_est_failure_control: not extensible.
void skip_conn_est_failure_control(UnalignedPerReader& r) {
  const bool has_offset = r.read_bool();
  r.read_enum(4);  // connEstFailCount
  r.read_enum(8);  // connEstFailOffsetValidity
  if (has_offset) r.read_constrained_int(0, 15);
}

// _skip_si_request_config: not extensible.
void skip_si_request_config(UnalignedPerReader& r) {
  const uint64_t opt = r.read_bits(2);
  if ((opt >> 1) & 1) {  // rach-OccasionsSI
    skip_rach_config_generic(r);
    r.read_enum(8);  // ssb-perRACH-Occasion
  }
  if (opt & 1) r.read_enum(8);  // si-RequestPeriod
  const int64_t n = r.read_constrained_int(1, 32);  // si-RequestResources
  for (int64_t i = 0; i < n; ++i) {
    const uint64_t res_opt = r.read_bits(2);
    r.read_constrained_int(0, 63);
    if ((res_opt >> 1) & 1) r.read_constrained_int(0, 15);
    if (res_opt & 1) r.read_constrained_int(0, 15);
  }
}

// _skip_si_scheduling_info. si-WindowLength has 9 values in Rel-15 and 11 in
// Rel-17; both fit the 4 bits read_enum(11) takes.
void skip_si_scheduling_info(UnalignedPerReader& r) {
  const bool ext = r.read_bool();
  const uint64_t opt = r.read_bits(3);
  const int64_t n_si = r.read_constrained_int(1, 32);  // schedulingInfoList
  for (int64_t i = 0; i < n_si; ++i) {
    r.read_enum(2);  // si-BroadcastStatus
    r.read_enum(7);  // si-Periodicity
    const int64_t n_sib = r.read_constrained_int(1, 31);  // sib-MappingInfo
    for (int64_t j = 0; j < n_sib; ++j) {
      const uint64_t t_opt = r.read_bits(2);
      if (r.read_bool()) {
        // Extended type value: normally-small non-negative number.
        if (r.read_bool()) throw WalkInvalid();  // > 63
        r.read_bits(6);
      } else {
        r.read_enum(16);
      }
      if ((t_opt >> 1) & 1) r.read_constrained_int(0, 31);  // valueTag
      // bit 0: areaScope ENUMERATED {true} -- zero bits
    }
  }
  r.read_enum(11);  // si-WindowLength
  if ((opt >> 2) & 1) skip_si_request_config(r);
  if ((opt >> 1) & 1) skip_si_request_config(r);
  if (opt & 1) r.read_bits(24);  // systemInformationAreaID
  if (ext) skip_extension_additions(r);
}

}  // namespace

int nr_channel_bandwidth_mhz(int scs_khz, int nrb, int band) {
  // TS 38.101-1 (FR1) / 38.101-2 (FR2) Table 5.3.2-1: maximum transmission
  // bandwidth configuration N_RB -> channel bandwidth MHz, keyed by SCS kHz.
  struct Row { int scs, nrb, mhz; };
  static const Row kFr1[] = {
      {15, 25, 5},   {15, 52, 10},  {15, 79, 15},  {15, 106, 20}, {15, 133, 25},
      {15, 160, 30}, {15, 188, 35}, {15, 216, 40}, {15, 242, 45}, {15, 270, 50},
      {30, 11, 5},   {30, 24, 10},  {30, 38, 15},  {30, 51, 20},  {30, 65, 25},
      {30, 78, 30},  {30, 92, 35},  {30, 106, 40}, {30, 119, 45}, {30, 133, 50},
      {30, 162, 60}, {30, 189, 70}, {30, 217, 80}, {30, 245, 90}, {30, 273, 100},
      {60, 11, 10},  {60, 18, 15},  {60, 24, 20},  {60, 31, 25},  {60, 38, 30},
      {60, 44, 35},  {60, 51, 40},  {60, 58, 45},  {60, 65, 50},  {60, 79, 60},
      {60, 93, 70},  {60, 107, 80}, {60, 121, 90}, {60, 135, 100},
  };
  static const Row kFr2[] = {
      {60, 66, 50},   {60, 132, 100},  {60, 264, 200},
      {120, 32, 50},  {120, 66, 100},  {120, 132, 200}, {120, 264, 400},
  };
  const int kFr2MinBand = 257;  // n257 is the first FR2 band (38.101-2 Table 5.2-1)
  if (scs_khz == kNrAbsent || nrb == kNrAbsent) return kNrAbsent;
  const bool fr2 = band != kNrAbsent && band >= kFr2MinBand;
  const Row* rows = fr2 ? kFr2 : kFr1;
  const size_t n = fr2 ? sizeof(kFr2) / sizeof(kFr2[0])
                       : sizeof(kFr1) / sizeof(kFr1[0]);
  for (size_t i = 0; i < n; ++i)
    if (rows[i].scs == scs_khz && rows[i].nrb == nrb) return rows[i].mhz;
  return kNrAbsent;
}

void walk_serving_cell_config_common(UnalignedPerReader& r, size_t pdu_bits,
                                     bool cari_has_ext, bool has_conn_est,
                                     bool has_si_sched,
                                     NrServingCellConfigCommon& res) {
  const char* stage = "cellAccessRelatedInfo";
  try {
    // CellAccessRelatedInfo's extension additions (Rel-16
    // cellReservedForFutureUse-r16 / npn-IdentityInfoList-r16, ...).
    if (cari_has_ext) skip_extension_additions(r);
    stage = "connEstFailureControl";
    if (has_conn_est) skip_conn_est_failure_control(r);
    stage = "si-SchedulingInfo";
    if (has_si_sched) skip_si_scheduling_info(r);

    // ServingCellConfigCommonSIB: extensible, 4 OPTIONALs (uplinkConfigCommon,
    // supplementaryUplink, n-TimingAdvanceOffset, tdd-UL-DL-ConfigurationCommon).
    stage = "frequencyInfoDL";
    r.read_bool();  // extension bit: Rel-16+ additions are not needed
    const uint64_t scc_opt = r.read_bits(4);
    const bool dl_ext = r.read_bool();  // DownlinkConfigCommonSIB extension bit
    // FrequencyInfoDL-SIB (not extensible): frequencyBandList, offsetToPointA,
    // scs-SpecificCarrierList.
    std::vector<int> bands = read_multi_freq_band_list_nr(r);
    const int offset_to_point_a = static_cast<int>(r.read_constrained_int(0, 2199));
    std::vector<NrScsCarrier> carriers = read_scs_carrier_list(r);
    check_inside(r, pdu_bits);
    res.bands = bands;
    res.band = bands.empty() ? kNrAbsent : bands[0];
    res.offset_to_point_a = offset_to_point_a;
    res.dl_carriers = carriers;
    if (!carriers.empty()) {
      res.scs_khz = carriers[0].scs_khz;
      res.carrier_bandwidth_prb = carriers[0].carrier_bandwidth_prb;
      res.channel_bandwidth_mhz = nr_channel_bandwidth_mhz(
          res.scs_khz, res.carrier_bandwidth_prb, res.band);
    }

    // Set BEFORE the next overrun check, deliberately: an
    // initialDownlinkBWP read from zero padding still reports its SCS.
    stage = "initialDownlinkBWP";
    res.initial_dl_bwp_scs_khz = skip_bwp_downlink_common(r);
    stage = "bcch-Config";
    skip_ext_seq_with_enum(r, 4);  // BCCH-Config { modificationPeriodCoeff, ... }
    stage = "pcch-Config";
    skip_pcch_config(r);
    if (dl_ext) skip_extension_additions(r);
    check_inside(r, pdu_bits);

    stage = "uplinkConfigCommon";
    if ((scc_opt >> 3) & 1) skip_uplink_config_common_sib(r);
    stage = "supplementaryUplink";
    if ((scc_opt >> 2) & 1) skip_uplink_config_common_sib(r);
    stage = "n-TimingAdvanceOffset";
    if ((scc_opt >> 1) & 1) r.read_enum(3);

    // ssb-PositionsInBurst SEQUENCE { inOneGroup BIT STRING (8),
    //   groupPresence BIT STRING (8) OPTIONAL }
    stage = "ssb-PositionsInBurst";
    const bool has_group_presence = r.read_bool();
    const int in_one_group = static_cast<int>(r.read_bits(8));
    const int group_presence =
        has_group_presence ? static_cast<int>(r.read_bits(8)) : kNrAbsent;
    static const int kSsbPeriodMs[] = {5, 10, 20, 40, 80, 160};
    const int periodicity = kSsbPeriodMs[read_enum_checked(r, 6)];

    // TDD-UL-DL-ConfigCommon (extensible): referenceSubcarrierSpacing,
    // pattern1, pattern2 OPTIONAL.
    stage = "tdd-UL-DL-ConfigurationCommon";
    bool has_tdd = false;
    int tdd_ref_scs = kNrAbsent;
    bool has_p2 = false;
    NrTddPattern p1, p2;
    if (scc_opt & 1) {
      has_tdd = true;
      const bool tdd_ext = r.read_bool();
      has_p2 = r.read_bool();
      tdd_ref_scs = read_scs(r);
      p1 = read_tdd_pattern(r, pdu_bits);
      if (has_p2) p2 = read_tdd_pattern(r, pdu_bits);
      if (tdd_ext) skip_extension_additions(r);
    }
    stage = "ss-PBCH-BlockPower";
    const int power = static_cast<int>(r.read_constrained_int(-60, 50));
    check_inside(r, pdu_bits);
    res.ssb_in_one_group = in_one_group;
    res.ssb_group_presence = group_presence;
    res.ssb_periodicity_ms = periodicity;
    if (has_tdd) {
      res.tdd_reference_scs_khz = tdd_ref_scs;
      res.has_tdd_pattern1 = true;
      res.tdd_pattern1 = p1;
      res.has_tdd_pattern2 = has_p2;
      if (has_p2) res.tdd_pattern2 = p2;
    }
    res.ss_pbch_block_power_dbm = power;
  } catch (const WalkOverrun&) {
    res.walk_stopped_at = std::string(stage) + ":overrun";
  } catch (const WalkInvalid&) {
    res.walk_stopped_at = stage;
  }
}

}  // namespace nr_rrc
}  // namespace diagspec
