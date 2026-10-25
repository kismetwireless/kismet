// SPDX-License-Identifier: GPL-2.0-or-later
// 0xB195 cell_observation enrichment leg — see diag_0xb195_observation.h.
//
// Turns the generated Kaitai raw view (diag_0xb195_t) into the AT-parity
// (pci, earfcn) connected-mode neighbor-cell observations the celldiag datasource
// emits, in pure C++.
//
// Output contract (pinned by the equivalence harness over the 3 committed
// lte_ml1_conn_neighbor_b195_*.bin fixtures):
//   * pci    == cell.pci_raw & 0x1ff       (the .ksy computes this as cell.pci())
//   * earfcn == the .ksy's earfcn() (u16 on sp.v3, u32 & 0x3ffff elsewhere)
//   * count  == num_cells                  (the .ksy computes
//               `min(word & 0x7f, (body-hdr)/52)`, so
//               cells() is already the exact cell set)
//   * a record whose picked subpacket is NOT the id=31 response subpacket yields
//     zero observations — the whole record is refused, so no cells reach the
//     sink (guarded here on sp_id() == 31).
//
// No rsrp: 0xB195 carries AGC-flattened energy, not calibrated dBm.
//
// The three DECLINE gates below are the reference parser's early
// returns; see the twin block in diag_0xb192_observation.cpp for why they are the
// leg's job and not the .ksy's. The outer-version gate is the one that returns a
// wrong answer rather than throwing: 0xB195 declares
// field_invariants={"version": {"enum": [0x01]}}, and a v!=1 record decoded with
// v1 offsets emits plausible-looking PCIs read from the wrong place.
//
// As on 0xB192, the two structural guards are masked by the catch: removing
// either individually leaves the observation-list suite green. Kept for
// explicitness and a cheap, exception-free decline; the Decline out-param pins
// each path.

#include "diag_0xb195_observation.h"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <vector>

#include "kaitai/kaitaistream.h"
#include "diag_0xb195.h"

namespace diag_0xb195_observation {

// The id=31 subpacket is the response (measurement) subpacket; id=30 is the
// request/config. resp_idx picks it; if the picked subpacket is anything else,
// the record is refused and no observations are emitted.
static const int kResponseSpId = 31;

// Outer DIAG log version — any other value refuses the record, and it is
// declared a closed enum. CLOSED allowlist.
static const uint8_t kOuterVersion = 0x01;

// Records shorter than 8 bytes are refused.
static const size_t kMinPayload = 8;

bool is_refusal(Decline d) {
    switch (d) {
        case Decline::kShortPayload:
        case Decline::kOuterVersion:
        case Decline::kNumSubpackets:
        case Decline::kNotResponseSubpacket:
        case Decline::kThrew:
            return true;
        default:
            return false;
    }
}

const char* decline_name(Decline d) {
    switch (d) {
        case Decline::kNone:                 return "none";
        case Decline::kShortPayload:         return "short_payload";
        case Decline::kOuterVersion:         return "outer_version";
        case Decline::kNumSubpackets:        return "num_subpackets";
        case Decline::kNotResponseSubpacket: return "not_response_subpacket";
        case Decline::kNullCells:            return "null_cells";
        case Decline::kThrew:                return "threw";
    }
    return "unknown";
}

// Records the path taken, when the caller asked for it. A
// no-op when `why` is null, which is every shipping call site.
static inline void note(Decline* why, Decline d) {
    if (why != nullptr)
        *why = d;
}

std::vector<CellObservation> observations(const std::string& payload,
                                          Decline* why) {
    std::vector<CellObservation> out;
    note(why, Decline::kNone);

    // ---- decline gates, in the reference parser's order -----------------
    if (payload.size() < kMinPayload) {
        note(why, Decline::kShortPayload);
        return out;
    }
    if (static_cast<uint8_t>(payload[0]) != kOuterVersion) {
        note(why, Decline::kOuterVersion);
        return out;
    }
    if (static_cast<uint8_t>(payload[1]) < 1) {  // num_subpackets
        note(why, Decline::kNumSubpackets);
        return out;
    }

    // Truncated / internally-inconsistent records make the generated parser
    // throw; such a record is refused (= an empty list), so this leg answers
    // that at the LEG boundary rather than relying on the shim's catch-all.
    try {
        kaitai::kstream ks(payload);
        diag_0xb195_t rec(&ks);

        // Guard: no id=31 response subpacket -> record refused -> zero
        // observations. Reading resp() when the picked subpacket is a request
        // body would static_cast across incompatible types (the generated resp()
        // does an unchecked cast).
        diag_0xb195_t::subpacket_t* sp = rec.subpackets()->at(rec.resp_idx()).get();
        if (sp->sp_id() != kResponseSpId) {
            note(why, Decline::kNotResponseSubpacket);
            return out;
        }

        diag_0xb195_t::response_body_t* body = rec.resp();
        int32_t earfcn = body->earfcn();

        std::vector<std::unique_ptr<diag_0xb195_t::response_cell_t>>* cells =
            body->cells();
        if (cells == nullptr) {
            note(why, Decline::kNullCells);
            return out;
        }

        out.reserve(cells->size());
        for (const auto& cell : *cells) {
            CellObservation obs;
            obs.pci = cell->pci();
            obs.earfcn = earfcn;
            out.push_back(obs);
        }
    } catch (const std::exception&) {
        note(why, Decline::kThrew);
        out.clear();                 // malformed record -> refused -> []
    }
    return out;
}

}  // namespace diag_0xb195_observation
