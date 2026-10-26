// SPDX-License-Identifier: GPL-2.0-or-later
// LTE MeasurementReport neighbour join -- see the header.
//
// Line-for-line port of the reference decoder's measConfig state update and
// MeasurementReport neighbour emit. Where the reference reads a parsed 0xB0C0
// field, this reads the same field off the generated Kaitai parse.

#include "lte_meas_join.h"

#include <exception>
#include <string>
#include <vector>

#include "kaitai/kaitaistream.h"
#include "diag_0xb0c0.h"
#include "diag_0xb0c0_enrich.h"
#include "lte_rrc_meas_report.h"
#include "lte_rrc_reconfig.h"

namespace lte_meas_join {

namespace {

// The (channel NAME, RRC PDU) pair every rule keys on. Returns false for a
// payload the Kaitai parse rejects, which both entry points ignore.
bool channel_and_pdu(const std::string& payload, std::string& chan,
                     std::string& pdu) {
    try {
        kaitai::kstream ks(payload);
        diag_0xb0c0_t rec(&ks);
        chan = diag_0xb0c0_enrich::channel_name(rec.version(), rec.channel_type());
        pdu = rec.msg_data();
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

void update(State& state, const std::string& payload) {
    std::string ch, md;
    if (!channel_and_pdu(payload, ch, md) || md.empty())
        return;
    const uint8_t b0 = static_cast<uint8_t>(md[0]);

    if (ch == "DL-CCCH" && (b0 >> 7) == 0) {
        const int c1 = (b0 >> 5) & 0x3;       // 0 reestablishment .. 3 setup
        if (c1 == 3) {
            state.objects.clear();
            state.links.clear();
        } else if (c1 == 0) {
            state.links.clear();
        }
        return;
    }
    if (ch != "DL-DCCH" || (b0 >> 7) != 0)
        return;
    const int c1 = (b0 >> 3) & 0xF;           // DL-DCCH c1 (16 alternatives)
    if (c1 == 3 || c1 == 5) {                 // mobilityFromEUTRACommand, release
        state.objects.clear();
        state.links.clear();
        return;
    }

    diagspec::lte_rrc::LteMeasConfig mc;
    try {
        const std::vector<uint8_t> msg(md.begin(), md.end());
        if (!diagspec::lte_rrc::decode_rrc_reconfig_meas_config(0, msg, mc))
            return;                            // not a (decodable) reconfiguration
    } catch (const std::exception&) {
        return;
    }

    if (mc.has_mobility_control)
        state.links.clear();
    for (int obj_id : mc.meas_object_remove) {
        state.objects.erase(obj_id);
        for (auto it = state.links.begin(); it != state.links.end();) {
            if (it->second == obj_id)
                it = state.links.erase(it);
            else
                ++it;
        }
    }
    for (int obj_id : mc.non_eutra_object_ids)
        state.objects[obj_id] = State::Object();
    for (const auto& obj : mc.meas_objects) {
        State::Object o;
        o.eutra = true;
        o.earfcn = obj.earfcn;
        state.objects[obj.meas_object_id] = o;
    }
    for (int meas_id : mc.meas_id_remove)
        state.links.erase(meas_id);
    for (const auto& link : mc.meas_ids)
        state.links[link.meas_id] = link.meas_object_id;
}

std::vector<Neighbour> neighbours(const State& state, const std::string& payload) {
    std::vector<Neighbour> out;
    std::string ch, md;
    if (!channel_and_pdu(payload, ch, md) || ch != "UL-DCCH" || md.empty())
        return out;

    diagspec::lte_rrc::LteMeasurementReport mr;
    try {
        const std::vector<uint8_t> msg(md.begin(), md.end());
        if (!diagspec::lte_rrc::decode_measurement_report(0, msg, mr))
            return out;
    } catch (const std::exception&) {
        return out;
    }

    bool mapped = false;
    int32_t earfcn = 0;
    auto link = state.links.find(mr.meas_id);
    if (link != state.links.end()) {
        auto obj = state.objects.find(link->second);
        if (obj != state.objects.end() && obj->second.eutra) {
            mapped = true;
            earfcn = obj->second.earfcn;
        }
    }

    for (const auto& n : mr.neighbor_cells) {
        // LTE PCI is 0..503; outside it the decode walked off its stride.
        if (n.pci < 0 || n.pci > 503)
            continue;
        // A CGI needs all of mcc, mnc, tac and cid present, and an empty MNC
        // counts as absent. MNC is mandatory in PLMN-Identity, so this is
        // belt-and-braces.
        const bool has_cgi = n.has_cgi && !n.mnc.empty();
        if (!mapped && !has_cgi)
            continue;
        Neighbour r;
        r.pci = n.pci;
        r.has_earfcn = mapped;
        r.earfcn = earfcn;
        r.has_rsrp = n.has_rsrp;
        r.rsrp = n.rsrp;
        r.has_rsrq = n.has_rsrq;
        r.rsrq = n.rsrq;
        if (has_cgi) {
            r.has_cgi = true;
            r.mcc = n.mcc;
            r.mnc = n.mnc;
            r.tac = static_cast<uint32_t>(n.tac);
            r.cell_id = static_cast<uint32_t>(n.cid);
        }
        out.push_back(r);
    }
    return out;
}

}  // namespace lte_meas_join
