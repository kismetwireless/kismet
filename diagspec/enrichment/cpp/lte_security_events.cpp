// SPDX-License-Identifier: GPL-2.0-or-later
// LTE cell security events -- see the header.
//
// The identity request state machine follows Rayhunter's imsi_requested
// analyzer: a connection or attach request opens an exchange, authentication
// or attach complete closes it, and releases, rejects and detaches are a
// disconnect. Its no-follow-up timeout is not carried over.

#include "lte_security_events.h"

#include <exception>

#include "kaitai/kaitaistream.h"
#include "diag_0xb0c0.h"
#include "diag_0xb0c0_enrich.h"
#include "diag_0xb0ec.h"
#include "diag_0xb0ed.h"
#include "lte_nas_emm.h"
#include "lte_rrc_sib.h"

namespace lte_security_events {

namespace {

using diagspec::lte_nas::EmmMessage;
using diagspec::lte_nas::EmmType;
using Nas = State::Nas;

// EMM cause #8, "EPS services and non-EPS services not allowed": what an
// inactive SIM is refused with.
constexpr int kCauseEpsAndNonEpsNotAllowed = 8;

void set_cell(const State& state, Event& ev) {
    ev.has_cell = state.has_cell;
    ev.pci = state.pci;
    ev.earfcn = state.earfcn;
}

void identity_event(const State& state, IdentityReason reason,
                    std::vector<Event>& out) {
    Event ev;
    ev.kind = Kind::kIdentityRequest;
    ev.layer = Layer::kNas;
    ev.reason = reason;
    ev.identity_type = state.last_identity_type;
    set_cell(state, ev);
    out.push_back(ev);
}

// Rayhunter's transition table, on the states the events need.
void transition(State& state, Nas next, std::vector<Event>& out,
                bool likely_valid_reject = false) {
    if (next == Nas::kIdentityRequest) {
        if (state.nas == Nas::kAuthAccept)
            identity_event(state, IdentityReason::kAfterAuth, out);
        else if (state.nas == Nas::kDisconnect)
            identity_event(state, IdentityReason::kNoConnectionRequest, out);
    } else if (next == Nas::kDisconnect && state.nas == Nas::kIdentityRequest) {
        identity_event(state, likely_valid_reject ? IdentityReason::kAttachRejectNoAuth
                                                  : IdentityReason::kDisconnectNoAuth,
                       out);
    }
    state.nas = next;
}

void rrc_record(State& state, const std::string& payload, std::vector<Event>& out) {
    std::string chan;
    std::string pdu;
    int32_t pci;
    int32_t earfcn;
    try {
        kaitai::kstream ks(payload);
        diag_0xb0c0_t rec(&ks);
        if (static_cast<size_t>(rec.header_size()) + rec.msg_length() > payload.size())
            return;
        chan = diag_0xb0c0_enrich::channel_name(rec.version(), rec.channel_type());
        pdu = rec.msg_data();
        pci = static_cast<int32_t>(rec.pci());
        earfcn = static_cast<int32_t>(rec.earfcn());
    } catch (const std::exception&) {
        return;
    }
    if (pdu.empty())
        return;
    const std::vector<uint8_t> msg(pdu.begin(), pdu.end());

    if (chan == "BCCH-DL-SCH") {
        diagspec::lte_rrc::Sib1CellIdentity sib1;
        if (!diagspec::lte_rrc::decode_sib1_cell_access(msg, sib1) ||
                sib1.scheduling_info_count < 0 || sib1.scheduling_info_count >= 2)
            return;
        auto key = std::make_tuple(pci, earfcn, sib1.cell_identity);
        if (state.sib1_reported.size() >= kMaxSib1Reported)
            state.sib1_reported.clear();
        if (!state.sib1_reported.insert(key).second)
            return;
        Event ev;
        ev.kind = Kind::kIncompleteSib1;
        ev.has_cell = true;
        ev.pci = pci;
        ev.earfcn = earfcn;
        ev.has_identity = true;
        ev.mcc = sib1.plmn_list[0].mcc;
        ev.mnc = sib1.plmn_list[0].mnc;
        ev.tac = sib1.tracking_area_code;
        ev.cell_id = sib1.cell_identity;
        ev.scheduling_info_count = sib1.scheduling_info_count;
        out.push_back(ev);
        return;
    }

    if (chan == "UL-CCCH") {
        if (diagspec::lte_rrc::is_connection_request(msg))
            transition(state, Nas::kAttachRequest, out);
        return;
    }

    if (chan != "DL-DCCH")
        return;

    state.has_cell = true;
    state.pci = pci;
    state.earfcn = earfcn;

    diagspec::lte_rrc::SecurityAlgorithms alg;
    if (diagspec::lte_rrc::decode_security_mode_command(msg, alg)) {
        if (alg.ciphering == 0 || alg.integrity == 0) {
            Event ev;
            ev.kind = Kind::kNullSecurity;
            ev.layer = Layer::kRrc;
            set_cell(state, ev);
            ev.ciphering = alg.ciphering;
            ev.integrity = alg.integrity;
            out.push_back(ev);
        }
        return;
    }

    diagspec::lte_rrc::ConnectionRelease rel;
    if (diagspec::lte_rrc::decode_connection_release(msg, rel)) {
        if (rel.redirect != diagspec::lte_rrc::RedirectRat::kNone) {
            Event ev;
            ev.kind = Kind::kRedirect;
            ev.layer = Layer::kRrc;
            set_cell(state, ev);
            ev.redirect = rel.redirect;
            ev.redirect_arfcn = rel.arfcn;
            ev.release_cause = rel.release_cause;
            out.push_back(ev);
        }
        transition(state, Nas::kDisconnect, out);
    }
}

void nas_record(State& state, const std::string& pdu, bool uplink,
                std::vector<Event>& out) {
    EmmMessage m;
    if (!diagspec::lte_nas::classify_emm(reinterpret_cast<const uint8_t *>(pdu.data()),
                                         pdu.size(), m))
        return;

    if (uplink) {
        switch (m.type) {
            case EmmType::kAttachRequest:
            case EmmType::kExtServiceRequest:
                transition(state, Nas::kAttachRequest, out);
                break;
            case EmmType::kAttachComplete:
            case EmmType::kAuthResponse:
                transition(state, Nas::kAuthAccept, out);
                break;
            case EmmType::kDetachRequest:
                transition(state, Nas::kDisconnect, out);
                break;
            default:
                break;
        }
        return;
    }

    switch (m.type) {
        case EmmType::kSecurityModeCommand:
            if (m.ciphering == 0 || m.integrity == 0) {
                Event ev;
                ev.kind = Kind::kNullSecurity;
                ev.layer = Layer::kNas;
                set_cell(state, ev);
                ev.ciphering = m.ciphering;
                ev.integrity = m.integrity;
                out.push_back(ev);
            }
            break;
        case EmmType::kIdentityRequest:
            state.last_identity_type = m.identity_type;
            transition(state, Nas::kIdentityRequest, out);
            break;
        case EmmType::kAttachReject:
            transition(state, Nas::kDisconnect, out,
                       m.emm_cause == kCauseEpsAndNonEpsNotAllowed);
            break;
        case EmmType::kServiceReject:
        case EmmType::kTauReject:
        case EmmType::kDetachRequest:
            transition(state, Nas::kDisconnect, out);
            break;
        default:
            break;
    }
}

}  // namespace

const char *kind_name(Kind kind) {
    switch (kind) {
        case Kind::kNullSecurity: return "null_security";
        case Kind::kRedirect: return "redirect";
        case Kind::kIncompleteSib1: return "incomplete_sib1";
        case Kind::kIdentityRequest: return "identity_request";
    }
    return "unknown";
}

const char *reason_name(IdentityReason reason) {
    switch (reason) {
        case IdentityReason::kNone: return "none";
        case IdentityReason::kAfterAuth: return "after_auth";
        case IdentityReason::kNoConnectionRequest: return "no_connection_request";
        case IdentityReason::kDisconnectNoAuth: return "disconnect_without_auth";
        case IdentityReason::kAttachRejectNoAuth: return "attach_reject_without_auth";
    }
    return "unknown";
}

std::vector<Event> process(State& state, uint16_t log_code, const std::string& payload) {
    std::vector<Event> out;

    if (log_code == 0xB0C0) {
        rrc_record(state, payload, out);
        return out;
    }

    if (log_code != 0xB0EC && log_code != 0xB0ED)
        return out;

    std::string pdu;
    try {
        kaitai::kstream ks(payload);
        if (log_code == 0xB0EC) {
            diag_0xb0ec_t rec(&ks);
            pdu = rec.nas_pdu();
        } else {
            diag_0xb0ed_t rec(&ks);
            pdu = rec.nas_pdu();
        }
    } catch (const std::exception&) {
        return out;
    }
    nas_record(state, pdu, log_code == 0xB0ED, out);
    return out;
}

}  // namespace lte_security_events
