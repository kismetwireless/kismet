// SPDX-License-Identifier: GPL-2.0-or-later
// 0x512F GSM RR signalling -> cell_observation, the native leg.
//
// At most ONE GSM identity cell per record, and only from System Information Type 3 on
// the BCCH -- the one broadcast that carries the full identity (MCC, MNC, LAC,
// CI) in a single record. Everything else emits nothing, deliberately:
//   * SI4 has a LAI but no CI: not a full identity.
//   * SI1 / SI2 / SI2bis / SI2quater / SI13 carry channel lists with no cell to
//     bind them to (SI1 names no cell; a modem reads NEIGHBOUR BCCHs during
//     reselection, so a cross-record join would put a wrong ARFCN on a real
//     tower).
//   * CCCH (Paging, Immediate Assignment) are not cell broadcasts, and paging
//     carries OTHER subscribers' TMSI/IMSI. Nothing from them may reach a row.
// The row is never serving: an SI3 does not say it is the camped cell.
//
// The rendered row (the capture helper's renderer) carries the constants this
// leg does not:
// rat "GSM", tac == lac (the generic area-code slot a device key is built
// from), observation_type "observation", is_serving false, and prov.
#ifndef DIAGSPEC_DIAG_0X512F_OBSERVATION_H
#define DIAGSPEC_DIAG_0X512F_OBSERVATION_H

#include <cstdint>
#include <string>
#include <vector>

namespace diag_0x512f_observation {

struct CellObservation {
    std::string mcc;   // TBCD digits, each nibble rendered in decimal
    std::string mnc;   // 2 digits when MNC digit 3 is 0xF, else 3
    int32_t lac;
    int32_t cell_id;
};

enum class Decline {
    kNone = 0,         // an SI3 identity was emitted
    kShortPayload,     // fewer than the 3 header bytes
    kLengthMismatch,   // byte[2] != len - 3 (record refused)
    kNotBcch,          // channel != 0x81: only BCCH broadcasts emit
    kNotRrL3,          // L2 pseudo length bits != '01', or PD != 6
    kNotSi3,           // an RR message that is not System Information 3
    kShortSi3,         // SI3 body under its 16 fixed octets (body_error)
    kThrew,            // the Kaitai walk threw; the catch answered
};

const char* decline_name(Decline d);
// A record the reference parser itself refuses (a length mismatch) or one the walk
// could not read, as opposed to a valid record that simply emits nothing.
bool is_refusal(Decline d);

std::vector<CellObservation> observations(const std::string& payload,
                                          Decline* why = nullptr);

}  // namespace diag_0x512f_observation

#endif  // DIAGSPEC_DIAG_0X512F_OBSERVATION_H
