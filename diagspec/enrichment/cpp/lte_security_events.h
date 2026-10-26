// SPDX-License-Identifier: GPL-2.0-or-later
// LTE cell security events -- the signalling patterns a cell-site simulator
// shows, after the heuristics of EFF's Rayhunter. Kismet raises its alerts
// from these.
//
//   kNullSecurity      an RRC or NAS security mode command selecting EEA0
//                      and/or EIA0
//   kRedirect          an RRCConnectionRelease redirecting the UE to another
//                      carrier; a GERAN target is the 2G downgrade
//   kIncompleteSib1    a SIB1 scheduling fewer than two SI messages
//   kIdentityRequest   an identity request outside a normal attach: after
//                      authentication, without a connection request, or
//                      followed by a disconnect without authentication
//
// Inputs are DIAG records: 0xB0C0 (LTE RRC OTA) and, when subscribed, 0xB0EC /
// 0xB0ED (EMM plain OTA, downlink / uplink). The NAS events need the latter.
#ifndef DIAGSPEC_LTE_SECURITY_EVENTS_H
#define DIAGSPEC_LTE_SECURITY_EVENTS_H

#include <cstdint>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "lte_rrc_security.h"

namespace lte_security_events {

enum class Kind : uint8_t {
    kNullSecurity,
    kRedirect,
    kIncompleteSib1,
    kIdentityRequest,
};

enum class Layer : uint8_t { kRrc, kNas };

enum class IdentityReason : uint8_t {
    kNone,
    kAfterAuth,              // after authentication completed
    kNoConnectionRequest,    // after a disconnect, with no new request
    kDisconnectNoAuth,       // answered, then disconnected without auth
    kAttachRejectNoAuth,     // as above, by an attach reject typical of an
                             // inactive SIM
};

struct Event {
    Kind kind = Kind::kNullSecurity;
    Layer layer = Layer::kRrc;

    // The serving cell: the record's own for RRC, the last RRC record's for NAS
    bool has_cell = false;
    int32_t pci = -1;
    int32_t earfcn = -1;

    // kIncompleteSib1
    bool has_identity = false;
    std::string mcc;
    std::string mnc;
    uint32_t tac = 0;
    uint32_t cell_id = 0;
    int scheduling_info_count = -1;

    // kNullSecurity
    int ciphering = -1;
    int integrity = -1;

    // kRedirect
    diagspec::lte_rrc::RedirectRat redirect = diagspec::lte_rrc::RedirectRat::kNone;
    int32_t redirect_arfcn = -1;
    int release_cause = -1;

    // kIdentityRequest
    IdentityReason reason = IdentityReason::kNone;
    int identity_type = -1;
};

const char *kind_name(Kind kind);
const char *reason_name(IdentityReason reason);

struct State {
    enum class Nas : uint8_t {
        kUnattached,
        kAttachRequest,
        kIdentityRequest,
        kAuthAccept,
        kDisconnect,
    };
    Nas nas = Nas::kUnattached;
    int last_identity_type = -1;

    bool has_cell = false;
    int32_t pci = -1;
    int32_t earfcn = -1;

    // Cells already reported for an incomplete SIB1; SIB1 repeats every 80 ms
    std::set<std::tuple<int32_t, int32_t, uint32_t>> sib1_reported;
};

// Bounds sib1_reported; past it the set restarts and a cell may report again.
constexpr std::size_t kMaxSib1Reported = 1024;

std::vector<Event> process(State& state, uint16_t log_code, const std::string& payload);

}  // namespace lte_security_events

#endif  // DIAGSPEC_LTE_SECURITY_EVENTS_H
