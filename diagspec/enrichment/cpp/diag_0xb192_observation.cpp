// SPDX-License-Identifier: GPL-2.0-or-later
// 0xB192 cell_observation enrichment leg — see diag_0xb192_observation.h.
//
// Turns the generated Kaitai raw view (diag_0xb192_t) into the AT-parity
// (pci, earfcn) neighbor-cell observations the celldiag datasource emits, in
// pure C++.
//
// Output contract (pinned by the equivalence harness over the 6 committed
// lte_ml1_neighbor_b192_*.bin fixtures):
//   * pci    == cell.pci_raw & 0x1ff       (the .ksy computes this as cell.pci())
//   * earfcn == response_body carrier scalar (u16 on MDM9200 ver=2, u32-low18
//               elsewhere — the .ksy's earfcn() ternary)
//   * count  == min(num_cells, cells_fit)   (the length-derived clamp; the .ksy
//               sizes cells() to n_cells: a cell that does not fit ends the walk)
//   * a record whose resp_idx subpacket is NOT the id=27 response subpacket
//     yields zero observations — the whole record is refused, so no cells
//     reach the sink (guarded here on sp_id() == 27).
//
// No rsrp: 0xB192 carries AGC-flattened energy, not calibrated dBm.
//
// The three DECLINE gates below are the reference parser's early returns, and none of
// them is expressible in the .ksy — they are enrichment, in the layout/enrichment
// split. Every fixture is a well-formed v1 record, so the equivalence suite alone
// cannot see a missing gate. The outer-version gate matters most on live data:
// without it the leg returns a WRONG ANSWER rather than throwing, and
// 0xB192/0xB195 both declare field_invariants={"version": {"enum": [0x01]}} precisely because size
// invariance is not format invariance: a future firmware may ship a different
// per-cell layout under version=2 in the same byte count, and decoding it with
// v1 offsets emits plausible-looking PCIs read from the wrong place.
//
// By the observation list alone the gates are not independently pinned:
// removing either structural guard (min-payload, num_subpackets) leaves the
// equivalence suite green, because the catch absorbs the throw they pre-empt.
// The Decline out-param (see the header) is what pins each path.

#include "diag_0xb192_observation.h"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <vector>

#include "kaitai/kaitaistream.h"
#include "diag_0xb192.h"

namespace diag_0xb192_observation {

// The id=27 subpacket is the response (neighbor-cell) subpacket. resp_idx picks
// it; if the picked subpacket is anything else (e.g. a request-only id=26
// record), the record is refused and no observations are emitted.
static const int kResponseSpId = 27;

// Outer DIAG log version. 0x01 in every observed record, and
// the record is refused on any other value. CLOSED allowlist.
static const uint8_t kOuterVersion = 0x01;

// Records shorter than 8 bytes are refused — the outer header (version,
// num_subpackets, counter) plus a minimum 4-byte subpacket header.
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

    // A truncated or internally-inconsistent record makes the generated Kaitai
    // parser throw (short read, or a resp_idx that indexes past the subpacket
    // list). Such a record is refused, i.e. an EMPTY observation list — so this
    // leg must answer that too. The capture helper's shim
    // (diag_native_decode.cpp) has its own catch-all, but relying on it would put
    // the leg's contract one layer above the leg, where the equivalence harness
    // cannot check it. Same shape as the 0xB193 leg, which has always done this.
    try {
        kaitai::kstream ks(payload);
        diag_0xb192_t rec(&ks);

        // Guard: no response subpacket -> record refused -> zero observations.
        // Reading resp() when the picked subpacket is a request_body would
        // static_cast across incompatible types (the generated resp() does an
        // unchecked cast).
        diag_0xb192_t::subpacket_t* sp = rec.subpackets()->at(rec.resp_idx()).get();
        if (sp->sp_id() != kResponseSpId) {
            note(why, Decline::kNotResponseSubpacket);
            return out;
        }

        diag_0xb192_t::response_body_t* body = rec.resp();
        int32_t earfcn = body->earfcn();

        std::vector<std::unique_ptr<diag_0xb192_t::response_cell_t>>* cells =
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

}  // namespace diag_0xb192_observation
