// SPDX-License-Identifier: GPL-2.0-or-later
// Linkable surface of the 0xB17F cell_observation enrichment leg.
//
// The datasource emits one LTE per-cell observation per 0xB17F record, and it
// is the DIAG path's per-cell `rssi` source. This leg produces those rows;
// without it those observations are dropped.
//
// EQUIVALENCE CONTRACT: for every payload, observations() equals the reference
// decoder's 0xB17F observations -- identity, presence of each optional
// measurement, and the values --
// over the committed lte_ml1_serving_b17f_*.bin fixtures (both layouts) and a
// truncation sweep. Pinned by tests/test_diag_0xb17f_observation_slice.py.
//
// NOTE: This leg reads the payload bytes directly rather than through the generated
// diag_0xb17f_t. The decode answers SHORT payloads with fallbacks (earfcn from
// byte 1 under the identity width, pci 0, measurements absent) that a Kaitai walk
// cannot express -- it throws on the first short read -- and every one of those
// answers is an emitted row when earfcn != 0. Reproducing them in bytes is
// the only way to keep the contract on the malformed tail, not just the happy path.
#ifndef DIAGSPEC_DIAG_0XB17F_OBSERVATION_H
#define DIAGSPEC_DIAG_0XB17F_OBSERVATION_H

#include <cstdint>
#include <string>
#include <vector>

namespace diag_0xb17f_observation {

// One LTE observation. rat is always "LTE" and is_serving always false: the
// record carries no serving flag, and guessing one from position is not allowed.
// Each measurement is present only when the layout's full record fits.
// Why observations() returned what it did. kRefused is exactly a record
// the reference parser refuses outright: the census counts it DROPPED. kNone is a
// completed parse, whatever its row count, and is counted decoded. The out-param
// is additive: `observations(payload)` behaves byte-for-byte as before.
enum class Decline {
    kNone = 0,
    kRefused,
};
bool is_refusal(Decline d);

struct CellObservation {
    int32_t pci;
    int32_t earfcn;
    bool has_rsrp;
    double rsrp;   // dBm
    bool has_rsrq;
    double rsrq;   // dB
    bool has_rssi;
    double rssi;   // dBm
};

// Decode a raw 0xB17F LOG_F payload (log-code-stripped) into zero or one
// observation. Empty when the version byte is not a known layout (0x03 / 0x04 / 0x05)
// or the payload is shorter than that layout, or the record's earfcn is 0
// (search mode: no groundable cell identity).
std::vector<CellObservation> observations(const std::string& payload,
                                          Decline* why = nullptr);

}  // namespace diag_0xb17f_observation

#endif  // DIAGSPEC_DIAG_0XB17F_OBSERVATION_H
