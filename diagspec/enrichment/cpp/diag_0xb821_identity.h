// SPDX-License-Identifier: GPL-2.0-or-later
// 0xB821 (NR5G RRC OTA) → SIB1 cell IDENTITY leg — the NR analogue of
// diag_0xb0c0_observation.
//
// This is not an observation leg, and the difference is deliberate.
// diag_0xb0c0_observation emits a CellObservation because a SIB1-bearing 0xB0C0
// record self-emits an identity cell. A 0xB821 record does not: it contributes
// to the consumer's SIB1 identity map (sib1_map) and nothing else — it never
// produces a cell_observation of its own. Giving this leg an `observations()`
// surface would therefore ADD rows the datasource does not emit, a change in the
// direction that is hardest to notice (an observation count that grew, on a
// code nobody was counting).
//
// So the surface is `identity()`: zero-or-one map entry — key (pci, arfcn),
// value MCC/MNC/TAC/NCI — plus the same SIB1's cell config, the consumer's
// ("nr_cfg", pci, arfcn) cache entry.
#ifndef DIAGSPEC_DIAG_0XB821_IDENTITY_H
#define DIAGSPEC_DIAG_0XB821_IDENTITY_H

#include <climits>
#include <cstdint>
#include <string>

namespace diag_0xb821_identity {

// One (pci, arfcn) → identity entry recovered from a SIB1-bearing NR RRC OTA
// record. `valid` false means the record contributes nothing to the map — not
// BCCH-DL-SCH, empty PDU, or the SIB1 decode declined.
// Why observations() returned what it did. kRefused is exactly a record
// the 0xB821 parse refuses: the census counts it DROPPED. kNone is a
// completed parse, whatever its row count, and is counted decoded. The out-param
// is additive: `observations(payload)` behaves byte-for-byte as before.
enum class Decline {
    kNone = 0,
    kRefused,
};
bool is_refusal(Decline d);

// The "no value" marker for the CellConfig ints below. It is
// INT_MIN, the same value as nr_rrc::kNrAbsent the SIB1 decoder fills them from.
constexpr int kAbsent = INT_MIN;

// The SIB1 servingCellConfigCommon headline: the consumer's ("nr_cfg", pci, arfcn)
// cache entry, attached to every NR observation of the cell as band /
// carrier_scs / bandwidth_rb / bandwidth.
// Each field is kAbsent where the decode has no value for it: the walk did
// not reach FrequencyInfoDL-SIB (scc.walk_stopped_at), SIB1 has no
// servingCellConfigCommon, or, for bandwidth_mhz alone, the (SCS, N_RB) pair is
// not a TS 38.101 Table 5.3.2-1 entry. `valid` is "at least one field is set";
// an invalid config is not cached.
struct CellConfig {
    bool valid = false;
    int band = kAbsent;             // sib1_band: first DL freqBandIndicatorNR
    int carrier_scs_khz = kAbsent;  // sib1_scs_khz: first scs-SpecificCarrier
    int bandwidth_rb = kAbsent;     // sib1_carrier_bandwidth_prb
    int bandwidth_mhz = kAbsent;    // sib1_channel_bandwidth_mhz
};

struct CellIdentity {
    bool valid = false;
    int32_t pci = 0;
    int32_t arfcn = 0;       // NR-ARFCN; the sib1_map key's second component
    std::string mcc;
    std::string mnc;
    uint32_t tac = 0;        // 24-bit; 0 is LEGITIMATE (OPTIONAL in 38.331)
    uint64_t cell_id = 0;    // 36-bit NCI
    // From the same SIB1 decode. Meaningful only when `valid`: the consumer
    // caches it behind the same SIB1 gate as the identity.
    CellConfig config;
};

// Decode one log-code-stripped 0xB821 DIAG payload into a map entry.
//
// Gate:
//   channel_name(version, pdu_id) == "BCCH-DL-SCH"   (resolved off the
//     per-version pdu_id enum, never the raw integer)
//   AND msg_data non-empty
//   AND decode_nr_sib1 succeeds  (the PDU decodes as an NR SIB1)
// Any other outcome returns valid == false. Never throws: a malformed record
// declines, because a capture source must not abort its stream over one frame.
// A valid entry also carries `config`, filled from the decode's `scc`.
CellIdentity identity(const std::string& payload, Decline* why = nullptr);

// One (pci, arfcn) -> NR SSB subcarrier spacing entry, the SECOND 0xB821
// cache entry: keyed `("scs", pci, arfcn)` and attached as the SCS of every NR
// observation of that cell.
// `valid` false means the record carries no MIB SCS and contributes nothing.
struct CellScs {
    bool valid = false;
    int32_t pci = 0;
    int32_t arfcn = 0;
    int scs_khz = 0;         // 15 / 30 (FR1) or 60 / 120 (FR2)
};

// Decode one log-code-stripped 0xB821 payload's MIB subCarrierSpacingCommon.
//
// Gate:
//   channel_name(version, pdu_id) == "BCCH-BCH"
//   AND msg_data non-empty
//   AND decode_mib succeeds (its outer CHOICE is `mib`, not
//     messageClassExtension)
// The ENUMERATED value is resolved to kHz by the record's own NR-ARFCN:
// scs15or60 -> 15 (FR1) / 60 (FR2), scs30or120 -> 30 / 120, FR2 meaning
// arfcn >= 2016667 (TS 38.104). It is independent of identity(): the MIB rides
// on records that carry no SIB1, so this entry is cached regardless of the SIB1
// gate. Never throws.
CellScs mib_scs(const std::string& payload, Decline* why = nullptr);

}  // namespace diag_0xb821_identity

#endif  // DIAGSPEC_DIAG_0XB821_IDENTITY_H
