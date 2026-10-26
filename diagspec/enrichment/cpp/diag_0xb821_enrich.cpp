// SPDX-License-Identifier: GPL-2.0-or-later
// 0xB821 (NR RRC OTA) C++ enrichment leg — the one liftable enrichment the
// NR→Exported-PDU adapter needs: the version-keyed pdu_id -> channel_name lookup
// (the NR counterpart of the 0xB0C0 leg).
//
// Like diag_0xb0c0_enrich.cpp, this STOPS at the opaque msg_data PER blob: the
// NR RRC / SIB / MIB / measConfig ASN.1 decode is a separate enrichment and is
// NOT done here — the Exported-PDU adapter (diag_0xb821_exported_pdu)
// wraps the RAW msg_data PDU and lets Wireshark's nr-rrc.<channel> dissector
// decode it, so channel_name() below is the only enrichment on that path.
#include <cstdint>
#include <string>

#include "diag_0xb821_enrich.h"

// The NR RRC pdu_id->name maps are generated
// into diagspec::nr_rrc from shared_data/enrichment_tables.yaml, with drift
// caught by the shared-table drift check.
#include "../../generated/cpp/enrichment_tables.h"

namespace diag_0xb821_enrich {

std::string channel_name(uint32_t version, uint8_t pdu_id) {
    const auto& byver = diagspec::nr_rrc::channel_names_by_version();
    auto vit = byver.find(static_cast<int>(version));
    if (vit == byver.end()) {
        return "";  // unsupported version -> unmapped signal
    }
    auto it = vit->second.find(static_cast<int>(pdu_id));
    if (it == vit->second.end()) {
        return "";  // pdu_id outside this version's map -> unmapped signal
    }
    return it->second;
}

bool record_refused(const std::string& payload) {
    // Per-version header size and msg_length offset.
    struct Hdr { uint32_t version; size_t header_size; size_t msg_len_off; };
    static const Hdr kHdrs[] = {
        {9, 24, 22}, {12, 23, 21}, {14, 23, 21}, {17, 31, 29}, {23, 35, 29}, {26, 35, 29},
    };
    auto byte = [&payload](size_t i) {
        return static_cast<uint32_t>(static_cast<unsigned char>(payload[i]));
    };
    if (payload.size() < 4)
        return true;
    const uint32_t version = byte(0) | (byte(1) << 8) | (byte(2) << 16) | (byte(3) << 24);
    for (const Hdr& h : kHdrs) {
        if (h.version != version)
            continue;
        if (payload.size() < h.header_size)
            return true;
        const size_t msg_length = byte(h.msg_len_off) | (byte(h.msg_len_off + 1) << 8);
        return payload.size() < h.header_size + msg_length;
    }
    return true;                         // unsupported version (v7 included)
}

}  // namespace diag_0xb821_enrich
