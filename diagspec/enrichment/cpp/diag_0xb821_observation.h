// SPDX-License-Identifier: GPL-2.0-or-later
// 0xB821 (NR5G RRC OTA) -> NR serving cell_observation leg.
//
// A UL-DCCH MeasurementReport carries the UE's own serving-cell RSRP/RSRQ/SINR
// AND the camped cell's (pci, arfcn) in the same record, so the leg emits
// one co-temporal NR serving observation per report. It is the only DIAG source
// of NR SINR (0xB97F carries none). Every other 0xB821 record contributes only
// cache entries (diag_0xb821_identity), never an observation.
//
// Output contract:
//   * emitted iff channel_name == "UL-DCCH", msg_data non-empty, and
//     decode_measurement_report succeeds (a measId was decoded),
//     AND 0 <= pci <= 1007 (38.211; outside it the row is dropped);
//   * rsrp / rsrq / sinr are the serving results, each OPTIONAL: absent stays
//     absent, never 0;
//   * observation_type "serving", is_serving true, rat "NR".
// Identity (enrich) and scs (add_nr_scs) are cross-record and attached by the
// consumer's cache, exactly as for 0xB97F rows.
#ifndef DIAGSPEC_DIAG_0XB821_OBSERVATION_H
#define DIAGSPEC_DIAG_0XB821_OBSERVATION_H

#include <cstdint>
#include <string>
#include <vector>

namespace diag_0xb821_observation {

// Why observations() returned what it did. kRefused is exactly a record
// the 0xB821 parse refuses: the census counts it DROPPED. kNone is a
// completed parse, whatever its row count, and is counted decoded. The out-param
// is additive: `observations(payload)` behaves byte-for-byte as before.
enum class Decline {
    kNone = 0,
    kRefused,
};
bool is_refusal(Decline d);

struct CellObservation {
    int32_t pci = 0;
    int32_t arfcn = 0;
    bool has_rsrp = false;
    double rsrp = 0.0;
    bool has_rsrq = false;
    double rsrq = 0.0;
    bool has_sinr = false;
    double sinr = 0.0;
};

// Zero or one NR serving observation from one log-code-stripped 0xB821 payload.
// Never throws: a malformed record declines.
std::vector<CellObservation> observations(const std::string& payload,
                                          Decline* why = nullptr);

}  // namespace diag_0xb821_observation

#endif  // DIAGSPEC_DIAG_0XB821_OBSERVATION_H
