/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include "config.h"

#include <string>
#include <sstream>

#include "phy_cell.h"
#include "phy_cell_decisions.h"
#include "devicetracker.h"
#include "macaddr.h"
#include "kis_httpd_registry.h"
#include "messagebus.h"

kis_cellular_phy::kis_cellular_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("Cellular");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    cell_device_entry_id =
        entrytracker->register_field("cellular.device",
                tracker_element_factory<kis_cellular_tracked_cell>(),
                "Cellular cell device");

    prov_source_entry_id =
        entrytracker->register_field("cellular.prov_source",
                tracker_element_factory<kis_cellular_tracked_prov_source>(),
                "Cellular per-source provenance record");

    pack_comp_common = packetchain->register_packet_component("COMMON");
    pack_comp_json = packetchain->register_packet_component("JSON");
    pack_comp_meta = packetchain->register_packet_component("METABLOB");
    pack_comp_gps = packetchain->register_packet_component("GPS");
    pack_comp_device = packetchain->register_packet_component("DEVICE");
    pack_comp_radiodata = packetchain->register_packet_component("RADIODATA");

    // Cache device type strings — "Cell" has full identity (MCC+MNC+CID),
    // "Cell (Partial)" has only PCI+EARFCN (observed via signal, no global cell identity).
    devtype_cell = devicetracker->get_cached_devicetype("Cell");
    devtype_cell_partial = devicetracker->get_cached_devicetype("Cell (Partial)");

    packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);

    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_cell", "js/kismet.ui.cell.js");
}

kis_cellular_phy::~kis_cellular_phy() {
    packetchain->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
}

mac_addr kis_cellular_phy::cellkey_to_mac(const std::string& cell_key) {
    // The derivation is a pure decision and lives with the others. It is not
    // an adler32 pair: that makes bytes[4..5] a constant offset from
    // bytes[2..3] and merges a large fraction of ordinary cells into one
    // another's device. See cell_key_to_mac_bytes' header for details.
    uint8_t bytes[6];

    cell_decisions::cell_key_to_mac_bytes(cell_key, bytes);

    return mac_addr(bytes, 6);
}

bool kis_cellular_phy::device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) {
    auto cell = dev->get_sub_as<kis_cellular_tracked_cell>(cell_device_entry_id);
    return (cell != nullptr);
}

std::shared_ptr<kis_cellular_tracked_cell> kis_cellular_phy::fetch_cell_record(
    const std::shared_ptr<kis_tracked_device_base>& dev) {
    return dev->get_sub_as<kis_cellular_tracked_cell>(cell_device_entry_id);
}

void kis_cellular_phy::load_phy_storage(
    shared_tracker_element in_storage, shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto celli = storage->find(cell_device_entry_id);

    if (celli != storage->end()) {
        auto celldev = std::make_shared<kis_cellular_tracked_cell>(
            cell_device_entry_id,
            std::static_pointer_cast<tracker_element_map>(
                celli->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(
            celldev);
    }
}

int kis_cellular_phy::packet_handler(CHAINCALL_PARMS) {
    kis_cellular_phy *cell_phy = (kis_cellular_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto json = in_pack->fetch<kis_json_packinfo>(cell_phy->pack_comp_json);
    if (json == NULL)
        return 0;

    if (json->type != "CellModem" && json->type != "Cellular")
        return 0;

    std::stringstream ss(json->json_string);
    nlohmann::json device_json;

    try {
        ss >> device_json;

        if (cell_phy->json_to_cell(device_json, in_pack)) {
            auto adata = in_pack->fetch_or_add<packet_metablob>(cell_phy->pack_comp_meta);
            adata->set_data("Cellular", json->json_string);
        }
    } catch (std::exception& e) {
        _MSG_DEBUG("Cellular JSON error: {}", e.what());
        return 0;
    }

    return 1;
}

/* Collect the observation fields this JSON object actually carried, so a
 * provenance source can advertise what it contributes (e.g. AT supplies
 * mcc/mnc/tac/cell_id, DIAG supplies rsrp/rsrq). Only keys present and
 * non-null are reported. */
static std::vector<std::string> prov_contributed_fields(nlohmann::json& json) {
    /* Which keys are present is a JSON question; which keys COUNT, and in what
     * order, is the decision layer's. */
    std::vector<std::string> present;
    for (const auto& k : cell_decisions::prov_field_keys()) {
        auto v = json[k];
        if (!v.is_null())
            present.push_back(k);
    }

    return cell_decisions::contributed_fields(present);
}

void kis_cellular_phy::update_seen_via(
    const std::shared_ptr<kis_cellular_tracked_cell>& celldev,
    const std::string& src, const std::string& origin,
    double captured_at, const std::vector<std::string>& fields) {

    auto seen_via = celldev->get_cell_seen_via();

    std::shared_ptr<kis_cellular_tracked_prov_source> rec;

    auto existing = seen_via->find(src);
    if (existing == seen_via->end()) {
        rec = entrytracker->get_shared_instance_as<kis_cellular_tracked_prov_source>(
                prov_source_entry_id);
        rec->set_prov_src(src);
        seen_via->insert(src, rec);
    } else {
        rec = std::static_pointer_cast<kis_cellular_tracked_prov_source>(existing->second);
    }

    if (cell_decisions::prov_origin_wins(origin))
        rec->set_prov_origin(origin);

    // Server time is always meaningful; prov.captured_at is retained verbatim
    // and its epoch-vs-tick normalization is not done here.
    rec->set_prov_last_seen((uint64_t) time(0));
    rec->set_prov_captured_at(captured_at);
    rec->set_prov_observation_count(rec->get_prov_observation_count() + 1);

    // Union the contributed field names into the record's field list (the
    // union semantics are cell_decisions::merge_prov_fields; the tracker
    // vector is just where the result is stored).
    auto fv = rec->get_prov_fields();
    std::vector<std::string> merged(fv->begin(), fv->end());
    const size_t before = merged.size();
    cell_decisions::merge_prov_fields(merged, fields);
    for (size_t i = before; i < merged.size(); i++)
        fv->push_back(merged[i]);
}

bool kis_cellular_phy::json_to_cell(nlohmann::json& json,
    const std::shared_ptr<kis_packet>& packet) {

    // RAT is required
    auto rat_j = json["rat"];
    if (rat_j.is_null() || !rat_j.is_string())
        return false;

    std::string rat = rat_j.get<std::string>();

    // Extract identity fields
    int64_t tac = -1, cid = -1, pci = -1;
    uint32_t earfcn = 0;
    bool have_earfcn = false;

    /* MCC/MNC arrive as strings on the DIAG leg, by design.
     *
     * The native decoder (capture_cell_diag/diag_native_decode.h) serialises
     * them as digit strings so the MNC's digit count survives. A consumer that accepts only
     * `is_number()` turns every DIAG-sourced SIB1 identity into mcc = mnc =
     * -1, derive_key() cannot form a full key, and the observation is demoted
     * to a PCI-only partial device.
     *
     * That demotion is silent downstream: the live WiGLE logger writes only
     * identity_level == "full" (kis_wiglecsvlogfile.cc), so the symptom is an
     * empty CSV with no logged reason.
     *
     * The string form is preferred because it is the lossless one; a number is
     * accepted for the AT leg, which destroyed its own digit count upstream
     * (see plmn_from_numbers). */
    const cell_decisions::plmn_t plmn = cell_decisions::plmn_from_json(json);

    auto tac_j = json["tac"];
    if (tac_j.is_number())
        tac = tac_j.get<int64_t>();

    auto cid_j = json["cell_id"];
    if (cid_j.is_number())
        cid = cid_j.get<int64_t>();

    auto pci_j = json["pci"];
    if (pci_j.is_number())
        pci = pci_j.get<int64_t>();

    auto earfcn_j = json["earfcn"];
    if (earfcn_j.is_number()) {
        earfcn = earfcn_j.get<uint32_t>();
        have_earfcn = true;
    }

    // Build cell key and determine identity level
    //
    // Two identity levels:
    //   "full"    — MCC + MNC + CellID known (globally unique cell identity)
    //               Minimum fields: mcc, mnc, cell_id (tac used if available)
    //               Sources: AT#RFSTS, AT#SERVINFO, AT+QENG="servingcell",
    //                        AT#CSURVC (11-field lines), AT+QSCAN
    //
    //   "partial" — Only PCI + EARFCN + RAT known (locally unique, not globally)
    //               Minimum fields: pci, earfcn
    //               Sources: AT#MONI, AT+QENG="neighbourcell", AT$QCRSRP?,
    //                        AT#CSURVC (6-field lines), AT!LTEINFO?
    //
    // Key derivation, signal policy, band/channel and naming all live in
    // cell_decisions (phy_cell_decisions.{h,cc}) so they are reachable by
    // test_phy_cell_decisions without linking the device tracker -- see that
    // header for why, and for what is deliberately not covered there.
    const auto derived = cell_decisions::derive_key(rat, plmn, tac, cid,
            pci, have_earfcn, earfcn);
    if (!derived.valid)
        return false;

    const std::string cell_key = derived.key;
    const bool is_full_identity = derived.full_identity;

    // Convert to pseudo-MAC
    mac_addr cell_mac = cellkey_to_mac(cell_key);

    if (cell_mac.error())
        return false;

    // Populate common info.
    //
    // This is the embedded kis_common_info on the packet, not a
    // fetch_or_add()'d packet component. Upstream Kismet moved common info
    // into kis_packet itself (`650aadfe8` / `085b5da08`), and devicetracker no
    // longer reads the RADIODATA/COMMON components. Writing to a
    // fetch_or_add()'d component still compiles and succeeds, but is never
    // read, so the cell PHY would silently produce devices with no MAC
    // classification, channel, or frequency. Do not restore the component
    // form.
    auto& common = packet->common_info;
    common.common_info_ok = true;

    // Cell observations are broadcast management info received from the tower.
    // Use packet_basic_mgmt → LLC/management packet counter (not data).
    // The tower MAC goes in dest so the device tracker counts RX packets.
    common.type = packet_basic_mgmt;
    common.phyid = fetch_phy_id();
    common.datasize = 0;

    // Source and transmitter must be non-zero MACs that don't match cell_mac.
    // "02:CE:11:00:00:00" — locally-administered placeholder, won't collide.
    mac_addr modem_placeholder("02:CE:11:00:00:00");
    common.source = modem_placeholder;
    common.transmitter = modem_placeholder;
    common.dest = cell_mac;

    if (have_earfcn)
        common.freq_khz = cell_decisions::arfcn_to_khz(rat, earfcn);

    // Build channel string from explicit band or EARFCN-derived band
    auto band_j = json["band"];
    const int explicit_band = band_j.is_number() ? band_j.get<int>() : 0;
    const int band_num = explicit_band > 0 ? explicit_band :
        ((have_earfcn && rat == "LTE") ? cell_decisions::earfcn_to_band(earfcn) : 0);
    common.channel = cell_decisions::channel_string(rat, explicit_band,
            have_earfcn, earfcn);

    // Extract RSRP early — used for both L1 signal info and cell-specific tracking.
    //
    // A missing/zero RSRP is NOT grounds to discard the observation. By this
    // point the key derivation above has already guaranteed either a full
    // identity (mcc+mnc+cid) or a partial one (pci+earfcn), and `band_num` /
    // `common.channel` are derived from the EARFCN — so the "no useful data
    // (zero RSRP, no band, no channel)" ghost-device case the old unconditional
    // `return false` guarded against cannot reach here.
    //
    // Dropping these rows would delete the entire DIAG leg on any modem whose
    // 0xB193 subpacket version has no grounded RSRP scale (v18, v22, v35, v36
    // and v48-RSRQ, roughly half of observed 0xB193 traffic; e.g. an EG25-G,
    // MDM9607, subpacket v18). The decoder deliberately emits those rows
    // identity-only (no rsrp key), and this layer must not drop them either.
    //
    // Signal population is conditional; identity always lands.
    auto rsrp_j = json["rsrp"];
    const bool have_rsrp = cell_decisions::have_usable_rsrp(rsrp_j.is_number(),
            rsrp_j.is_number() ? rsrp_j.get<int>() : 0);

    // Populate L1 radio info so the base signal tracker picks up RSRP.
    //
    // The consequence of `have_rsrp == false` does not stop at the signal. Two
    // facts, both invisible from this call site:
    //
    // 1. `UCD_UPDATE_SIGNAL` is a dead flag. It is set by several phys and
    //    read by none; the signal append in devicetracker.cc lives inside the
    //    UCD_UPDATE_FREQUENCIES block and is gated on `pack_l1info != nullptr`.
    //    What decides whether a cell gets signal data is the block below, not
    //    the flag word passed to update_common_device.
    //
    // 2. A packet with no l1info must still be geo-tagged when the operator
    //    sets a location signal threshold. conf/kismet_filter.conf documents
    //    that "packet types which do not report a signal level will use all
    //    packets"; that gate lives in
    //    device_location_policy::admits_location() (see that header). Roughly
    //    half of 0xB193 observations take the `!have_rsrp` path, so this
    //    matters.
    //
    // (1) is upstream-wide, harmless, and left as is. Both are recorded here
    // because this is where someone debugging "why do half my cells have no
    // location" will start.
    if (have_rsrp) {
        // Embedded signal info, not the RADIODATA component -- same reason as
        // common_info above. `data_ok` is what devicetracker gates
        // every signal read on, so omitting it is equivalent to writing
        // nothing at all.
        auto& l1info = packet->signal_info;

        l1info.data_ok = true;
        l1info.signal_type = kis_l1_signal_type_dbm;
        l1info.signal_dbm = rsrp_j.get<int>();

        if (common.freq_khz != 0)
            l1info.freq_khz = common.freq_khz;

        if (!common.channel.empty())
            l1info.channel = common.channel;
    }

    // Update common device.
    //
    // UCD_UPDATE_SIGNAL is passed unconditionally while the l1info above is
    // conditional. That is not a bug: the flag is never read (see above), and
    // every other phy passes it. Do not make the flag conditional: that would
    // suggest a behaviour difference the tracker cannot honour and hide the
    // real gate (pack_l1info's existence).
    //
    // Take the devicelist mutex before update_common_device, not after.
    // update_common_device publishes the base device into tracked_map and
    // releases the mutex on return, while the cell sub-record is inserted
    // further below. Locking only afterward leaves a window in which another
    // packet-chain thread sees the base device without its cell sub-record: a
    // concurrent full-identity observation's register_self links both related
    // edges but finds fetch_cell_record(pci_dev) == nullptr, and silently
    // skips the resolved-key stamp ("linked but resolved_key empty").
    // kis_mutex is recursive (std::recursive_timed_mutex), so holding it
    // across update_common_device (which re-locks it) is safe and makes
    // base-device creation plus cell-record insertion atomic, as
    // update_common_device's "the entire chain is perforce locked" comment
    // intends.
    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "cell_json_to_cell");

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->update_common_device(cell_mac, this, packet,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
                 UCD_UPDATE_LOCATION | UCD_UPDATE_SEENBY), "Cellular");

    // Fallback: if device has no channel yet, set generic
    if (basedev->get_channel().empty())
        basedev->set_channel("Cellular");

    // Set device type based on identity level.
    // Use KIS_DEVICE_BASICTYPE_AP to mark full-identity towers (like 802.11 APs)
    // so the conditional setter won't demote a cell back to partial.
    if (is_full_identity) {
        basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP);
        basedev->set_tracker_type_string(devtype_cell);
    } else {
        // Only set "Cell (Partial)" if not already a "Cell"
        auto cellular_phy = this;
        basedev->set_type_string_ifnotany([cellular_phy]() {
            return cellular_phy->devtype_cell_partial;
        }, KIS_DEVICE_BASICTYPE_AP);
    }

    basedev->set_devicename(cell_decisions::device_name(derived, rat, pci,
                earfcn, band_num));

    // Get or create cell tower sub-device
    auto celldev =
        basedev->get_sub_as<kis_cellular_tracked_cell>(cell_device_entry_id);

    if (celldev == NULL) {
        celldev = Globalreg::globalreg->entrytracker->get_shared_instance_as<kis_cellular_tracked_cell>(cell_device_entry_id);
        basedev->insert(celldev);

        if (is_full_identity) {
            _MSG_INFO("Detected new cell {} {}", rat, cell_key);
        } else {
            if (band_num > 0)
                _MSG_INFO("Detected new cell (partial) {} PCI {} B{} EARFCN {}",
                          rat, pci, band_num, earfcn);
            else
                _MSG_INFO("Detected new cell (partial) {} PCI {} EARFCN {}",
                          rat, pci, earfcn);
        }
    }

    // Update identity fields
    //
    // MCC/MNC are strings on the tracked device too, not just in the JSON. An
    // integer field would throw the MNC's digit count away after json_to_cell
    // preserved it, and the REST API and UI would see "15" and "015" as the
    // same network. `plmn` is the WiGLE operator token built from
    // the two, exposed directly so no consumer has to re-concatenate (and
    // re-pad) them.
    if (plmn.present) {
        celldev->set_cell_mcc(plmn.mcc);
        celldev->set_cell_mnc(plmn.mnc);
        celldev->set_cell_plmn(plmn.joined());
    }
    if (tac >= 0)
        celldev->set_cell_tac(tac);
    if (cid >= 0) {
        celldev->set_cell_cellid(cid);

        /* The LTE ECI split every engineer does by hand. NR is
         * deliberately not split -- the gNB-ID length is operator-configured,
         * so a guess here prints a confident wrong number. */
        if (rat == "LTE" && cid > 0) {
            celldev->set_cell_enb_id(cell_decisions::lte_enb_id(cid));
            celldev->set_cell_sector(cell_decisions::lte_sector(cid));
        }
    }
    if (pci >= 0)
        celldev->set_cell_pci(pci);

    celldev->set_cell_key(cell_key);
    celldev->set_cell_identity_level(is_full_identity ? "full" : "partial");

    // Operator token, hoisted here so pci_promotion can carry it onto a
    // resolved partial alongside the resolved key. Reused at the
    // set_cell_operator site below so this observation still parses it once.
    std::string cell_oper;
    {
        auto oper_j = json["operator_name"];
        if (oper_j.is_string())
            cell_oper = oper_j.get<std::string>();
    }

    // Related-device linking between full-identity and PCI-only devices.
    //
    // Two directions:
    // 1. Full-identity observation with PCI+EARFCN → register in lookup table,
    //    and link to any existing PCI-only device.
    // 2. PCI-only observation → check lookup table for a known full-identity
    //    tower with that PCI+EARFCN, and link if found.
    //
    // Which keys to consult, and whether to consult at all, is a pure decision.
    // The device tree below only resolves those keys to devices.
    auto promo = cell_decisions::pci_promotion(rat, pci, have_earfcn, earfcn,
            is_full_identity);

    // The two edges are also a decision, not just two calls: they must be
    // symmetric and carry the same relationship name. Kismet's related-device
    // map is keyed by that name, so a mismatch files the reverse edge under a
    // different relationship and produces a link resolving A->B but not B->A,
    // with nothing logged. cell_decisions::related_links() is the single source
    // of both.
    auto link_pair = [&](std::shared_ptr<kis_tracked_device_base> peer,
                         const device_key& peer_key) {
        for (const auto& e : cell_decisions::related_links(peer != nullptr)) {
            if (e.from_self)
                basedev->add_related_device(e.relationship, peer_key);
            else
                peer->add_related_device(e.relationship, basedev->get_key());
        }
    };

    if (promo.active) {
        if (promo.register_self) {
            // Registering this tower's RAT+PCI+EARFCN is a CLAIM on a slot that
            // may already be held. PCI is reused across a network every few km,
            // so (rat, pci, earfcn) is not guaranteed unique among full-identity
            // towers. An unconditional overwrite would silently link every later
            // PCI-only sighting to whichever tower was seen most recently. In
            // practice the map is usually injective, so a collision is rare,
            // not impossible; hence a report rather than a policy change.
            auto it = pci_to_full_identity.find(promo.map_key);
            auto claim = cell_decisions::pci_map_claim(
                    it != pci_to_full_identity.end(),
                    it != pci_to_full_identity.end() && it->second == basedev->get_key());

            if (claim == cell_decisions::map_claim_t::ambiguous) {
                // Do NOT relink and do NOT overwrite: guessing between two
                // towers is the coin flip diag_wwan_pick refuses to make for the
                // same reason. Say so once per key.
                _MSG_INFO("Cell PCI promotion: {} is claimed by more than one "
                          "full-identity cell (PCI reuse); no identity link will "
                          "be made for this PCI+ARFCN", promo.map_key);
            } else {
                pci_to_full_identity[promo.map_key] = basedev->get_key();

                // Link to existing PCI-only device if it exists
                mac_addr pci_mac = cellkey_to_mac(promo.peer_cell_key);

                if (!pci_mac.error()) {
                    device_key pci_devkey(fetch_phyname_hash(), pci_mac);
                    auto pci_dev = devicetracker->fetch_device_nr(pci_devkey);

                    // Promote this full identity onto the resolved partial:
                    // the live WiGLE logger emits that partial with this cell's
                    // key as the MAC and the resolved operator/plmn, keeping the
                    // partial's OWN arfcn/rat/rsrp (the neighbour's measured
                    // signal). Mirrors the offline exporter's resolved row.
                    if (pci_dev != nullptr) {
                        auto pci_cell = fetch_cell_record(pci_dev);
                        if (pci_cell != nullptr) {
                            pci_cell->set_cell_resolved_key(cell_key);
                            pci_cell->set_cell_resolved_operator(cell_oper);
                            if (plmn.present)
                                pci_cell->set_cell_resolved_plmn(plmn.joined());
                        } else {
                            // Tripwire: with the lock held across
                            // update_common_device, a resolved base device must
                            // carry its cell record. If this fires, something
                            // other than that race is at work; surface it
                            // rather than silently skipping the stamp.
                            _MSG_INFO("Cell PCI promotion: full identity {} found "
                                      "PCI-only peer device but it has no cell "
                                      "record; identity not stamped",
                                      promo.map_key);
                        }
                    }

                    link_pair(pci_dev, pci_devkey);
                }
            }
        } else if (promo.consult_map) {
            // PCI-only observation — check if we know the full identity
            auto it = pci_to_full_identity.find(promo.map_key);
            if (it != pci_to_full_identity.end()) {
                auto full_dev = devicetracker->fetch_device_nr(it->second);

                // Promote the resolved full identity onto this partial,
                // so the live WiGLE logger can emit it. See the register_self
                // branch above for the field split.
                if (full_dev != nullptr) {
                    auto full_cell = fetch_cell_record(full_dev);
                    if (full_cell != nullptr) {
                        celldev->set_cell_resolved_key(full_cell->get_cell_key());
                        celldev->set_cell_resolved_operator(full_cell->get_cell_operator());
                        celldev->set_cell_resolved_plmn(full_cell->get_cell_plmn());
                    } else {
                        // Tripwire, mirror of the register_self branch: a
                        // resolved full-identity device that carries no cell
                        // record should be impossible while the lock spans
                        // update_common_device. Surface it if it happens.
                        _MSG_INFO("Cell PCI promotion: partial found full-identity "
                                  "peer {} but it has no cell record; identity "
                                  "not stamped", promo.map_key);
                    }
                }

                link_pair(full_dev, it->second);
            }
        }
    }

    if (!cell_oper.empty())
        celldev->set_cell_operator(cell_oper);

    // Update network fields
    celldev->set_cell_rat(rat);

    auto duplex_j = json["duplex"];
    if (duplex_j.is_string())
        celldev->set_cell_duplex(duplex_j.get<std::string>());

    if (have_earfcn)
        celldev->set_cell_arfcn(earfcn);

    if (band_num > 0)
        celldev->set_cell_band(band_num);

    auto bw_j = json["bandwidth"];
    if (bw_j.is_number())
        celldev->set_cell_bandwidth(bw_j.get<int>());

    // Update signal fields
    if (rsrp_j.is_number()) {
        int16_t rsrp = rsrp_j.get<int16_t>();
        celldev->set_cell_rsrp(rsrp);

        // Track min/max RSRP
        if (celldev->get_cell_min_rsrp() == 0 || rsrp < celldev->get_cell_min_rsrp())
            celldev->set_cell_min_rsrp(rsrp);
        if (celldev->get_cell_max_rsrp() == 0 || rsrp > celldev->get_cell_max_rsrp())
            celldev->set_cell_max_rsrp(rsrp);
    }

    auto rsrq_j = json["rsrq"];
    if (rsrq_j.is_number())
        celldev->set_cell_rsrq(rsrq_j.get<int16_t>());

    auto sinr_j = json["sinr"];
    if (sinr_j.is_number())
        celldev->set_cell_sinr(sinr_j.get<int16_t>());

    auto rssi_j = json["rssi"];
    if (rssi_j.is_number())
        celldev->set_cell_rssi(rssi_j.get<int16_t>());

    // Update observation count
    celldev->set_cell_observation_count(celldev->get_cell_observation_count() + 1);

    // Update serving/neighbor flags
    auto serving_j = json["is_serving"];
    if (serving_j.is_boolean() && serving_j.get<bool>())
        celldev->set_cell_seen_serving(true);

    auto obs_type_j = json["observation_type"];
    if (obs_type_j.is_string() && obs_type_j.get<std::string>() == "observation")
        celldev->set_cell_seen_observed(true);

    // Provenance: record which capture pipe supplied this observation and
    // which fields it contributed, keyed by source name in celldev->seen_via.
    // Both capture_cell_at and capture_cell_diag stamp a prov block; a tower fed
    // by both ends up with two seen_via entries (identity from at, signal from diag).
    auto prov_j = json["prov"];
    if (prov_j.is_object()) {
        auto psrc_j = prov_j["src"];
        if (psrc_j.is_string()) {
            std::string psrc = psrc_j.get<std::string>();

            std::string porigin;
            auto porigin_j = prov_j["origin"];
            if (porigin_j.is_string())
                porigin = porigin_j.get<std::string>();

            double pcaptured = 0.0;
            auto pcap_j = prov_j["captured_at"];
            if (pcap_j.is_number())
                pcaptured = pcap_j.get<double>();

            update_seen_via(celldev, psrc, porigin, pcaptured,
                            prov_contributed_fields(json));
        }
    }

    return true;
}
