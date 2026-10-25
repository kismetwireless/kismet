// SPDX-License-Identifier: GPL-2.0-or-later
// 0x512F GSM RR signalling -> cell_observation. See the header.
#include "diag_0x512f_observation.h"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <vector>

#include "kaitai/kaitaistream.h"
#include "diag_0x512f.h"

namespace diag_0x512f_observation {

static const size_t kHeaderLen = 3;
static const uint8_t kChannelBcch = 0x81;
static const uint8_t kPdRr = 6;
static const uint8_t kMsgSi3 = 0x1B;
// The SI3 decode indexes 16 fixed octets past the 3-octet L3 header; a shorter
// SI3 leaves every SI3 field absent.
static const size_t kMinSi3L3 = 3 + 16;
static const uint8_t kTbcdFiller = 0xF;

bool is_refusal(Decline d) {
    switch (d) {
        case Decline::kShortPayload:
        case Decline::kLengthMismatch:
        case Decline::kThrew:
            return true;
        default:
            return false;
    }
}

const char* decline_name(Decline d) {
    switch (d) {
        case Decline::kNone:           return "none";
        case Decline::kShortPayload:   return "short_payload";
        case Decline::kLengthMismatch: return "length_mismatch";
        case Decline::kNotBcch:        return "not_bcch";
        case Decline::kNotRrL3:        return "not_rr_l3";
        case Decline::kNotSi3:         return "not_si3";
        case Decline::kShortSi3:       return "short_si3";
        case Decline::kThrew:          return "threw";
    }
    return "unknown";
}

static inline void note(Decline* why, Decline d) {
    if (why != nullptr)
        *why = d;
}

// One TBCD nibble rendered as its decimal integer, so a
// non-BCD nibble 0xA..0xE reads "10".."14" rather than a single character.
static std::string digit(uint64_t nibble) {
    return std::to_string(static_cast<unsigned>(nibble));
}

std::vector<CellObservation> observations(const std::string& payload,
                                          Decline* why) {
    std::vector<CellObservation> out;
    note(why, Decline::kNone);
    if (payload.size() < kHeaderLen) {
        note(why, Decline::kShortPayload);
        return out;
    }
    const size_t l3_len = static_cast<uint8_t>(payload[2]);
    if (l3_len != payload.size() - kHeaderLen) {
        note(why, Decline::kLengthMismatch);
        return out;
    }
    if (static_cast<uint8_t>(payload[0]) != kChannelBcch) {
        note(why, Decline::kNotBcch);
        return out;
    }
    // decode_ccch_block's own gates, before the walk: it needs three L3 octets
    // and an RR pseudo-length / PD.
    if (l3_len < 3 ||
        (static_cast<uint8_t>(payload[kHeaderLen]) & 0x3) != 0x1 ||
        (static_cast<uint8_t>(payload[kHeaderLen + 1]) & 0xF) != kPdRr) {
        note(why, Decline::kNotRrL3);
        return out;
    }
    if (static_cast<uint8_t>(payload[kHeaderLen + 2]) != kMsgSi3) {
        note(why, Decline::kNotSi3);
        return out;
    }
    if (l3_len < kMinSi3L3) {
        note(why, Decline::kShortSi3);
        return out;
    }
    try {
        kaitai::kstream ks(payload);
        diag_0x512f_t rec(&ks);
        if (rec.l3()->_is_null_body()) {   // unreachable past the gates above
            note(why, Decline::kNotSi3);
            return out;
        }
        diag_0x512f_t::si3_t* si3 =
            static_cast<diag_0x512f_t::si3_t*>(rec.l3()->body());
        CellObservation o;
        o.mcc = digit(si3->mcc_digit1()) + digit(si3->mcc_digit2()) +
                digit(si3->mcc_digit3());
        o.mnc = digit(si3->mnc_digit1()) + digit(si3->mnc_digit2());
        if (si3->mnc_digit3() != kTbcdFiller)
            o.mnc += digit(si3->mnc_digit3());
        o.lac = static_cast<int32_t>(si3->lac());
        o.cell_id = static_cast<int32_t>(si3->cell_identity());
        out.push_back(o);
    } catch (const std::exception&) {
        out.clear();
        note(why, Decline::kThrew);
    }
    return out;
}

}  // namespace diag_0x512f_observation
