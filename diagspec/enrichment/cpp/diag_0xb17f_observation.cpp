// SPDX-License-Identifier: GPL-2.0-or-later
// 0xB17F cell_observation enrichment leg -- see diag_0xb17f_observation.h.
//
// A line-for-line port of the reference decoder's 0xB17F parser (v13) and its
// observation rule. A payload shorter than its version's fixed size emits
// nothing (the record is refused).
//
//   v0x03 (32 B) / v0x04 (36 B)          v0x05 (40 B)
//     earfcn = u16@4                       earfcn = u32@4
//     pci    = u16@6 & 0x1FF               pci    = u32@8 & 0x1FF
//     rsrp = (u32@8  & 0xFFF)/16 - 180     rsrp = (u32@12 & 0xFFF)/16 - 180
//     rsrq = (u32@16 & 0x3FF)/16 - 30      rsrq = (u32@20 & 0x3FF)/16 - 30
//     rssi = ((u32@20>>10)&0xFFF)/16 - 110 rssi = ((u32@24>>10)&0xFFF)/16 - 110
//
// rsrq is bits 0..9 of its word; bits 20..29 are the parser's rsrq_avg.
// rsrp_avg / rsrq_avg are decoded by the parser but never reach an observation,
// so they are not read here. Every value is k/16 + integer, exact in a double, so no rounding
// separates this from the reference value.

#include "diag_0xb17f_observation.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace diag_0xb17f_observation {

namespace {

void note(Decline* why, Decline d) {
    if (why != nullptr)
        *why = d;
}

const uint8_t kV3 = 0x03;
const uint8_t kV4 = 0x04;
const uint8_t kV5 = 0x05;
const size_t kV3Size = 32;
const size_t kV4Size = 36;
const size_t kV5Size = 40;

uint32_t u16(const std::string& p, size_t off) {
    return static_cast<uint32_t>(static_cast<uint8_t>(p[off])) |
           static_cast<uint32_t>(static_cast<uint8_t>(p[off + 1])) << 8;
}

uint32_t u32(const std::string& p, size_t off) {
    return u16(p, off) | u16(p, off + 2) << 16;
}

double q4(uint32_t v, double bias) {
    return static_cast<double>(v & 0xFFFu) / 16.0 - bias;
}

}  // namespace

std::vector<CellObservation> observations(const std::string& payload, Decline* why) {
    note(why, Decline::kNone);
    std::vector<CellObservation> out;
    const size_t n = payload.size();
    if (n < 1)
        { note(why, Decline::kRefused); return out; }
    const uint8_t version = static_cast<uint8_t>(payload[0]);
    if (version != kV3 && version != kV4 && version != kV5)
        { note(why, Decline::kRefused); return out; }                      // unknown version -> refused
    const bool narrow = (version != kV5);   // 16-bit identity fields
    const size_t full = (version == kV3) ? kV3Size : (version == kV4) ? kV4Size : kV5Size;
    if (n < full)
        { note(why, Decline::kRefused); return out; }                      // truncated -> refused

    CellObservation o = {};
    o.earfcn = static_cast<int32_t>(narrow ? u16(payload, 4) : u32(payload, 4));
    o.pci = static_cast<int32_t>((narrow ? u16(payload, 6) : u32(payload, 8)) & 0x1FFu);
    const size_t base = narrow ? 8 : 12;   // offset of the rsrp word
    o.has_rsrp = true;
    o.rsrp = q4(u32(payload, base), 180.0);
    o.has_rsrq = true;
    o.rsrq = q4(u32(payload, base + 8) & 0x3FFu, 30.0);
    o.has_rssi = true;
    o.rssi = q4(u32(payload, base + 12) >> 10, 110.0);

    // Emit only when earfcn != 0 -- a search-mode record has no
    // groundable cell identity, so it emits nothing rather than a (0, pci) phantom.
    if (o.earfcn != 0)
        out.push_back(o);
    return out;
}

bool is_refusal(Decline d) {
    return d == Decline::kRefused;
}

}  // namespace diag_0xb17f_observation
