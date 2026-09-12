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

#ifndef __PHY_CELL_H__
#define __PHY_CELL_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <string>
#include <map>
#include <vector>

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "packet.h"
#include "gpstracker.h"
#include "uuid.h"

#include "devicetracker.h"
#include "devicetracker_component.h"
#include "phyhandler.h"

// Per-source provenance record (M3.3). One instance per capture pipe that has
// contributed to a tower (src = "at" or "diag"), stored as the values of
// kis_cellular_tracked_cell::cell_seen_via keyed by source name. Records when
// the source last contributed and the union of fields it has supplied, so the
// UI/detail view can show that (e.g.) identity came from AT while signal came
// from DIAG on the same merged tower.
class kis_cellular_tracked_prov_source : public tracker_component {
public:
    kis_cellular_tracked_prov_source() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    kis_cellular_tracked_prov_source(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_cellular_tracked_prov_source(int in_id,
        std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_cellular_tracked_prov_source");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(prov_src, std::string, std::string, std::string, prov_src);
    __Proxy(prov_origin, std::string, std::string, std::string, prov_origin);
    __Proxy(prov_last_seen, uint64_t, uint64_t, uint64_t, prov_last_seen);
    __Proxy(prov_captured_at, double, double, double, prov_captured_at);
    __Proxy(prov_observation_count, uint64_t, uint64_t, uint64_t, prov_observation_count);
    __ProxyTrackable(prov_fields, tracker_element_vector_string, prov_fields);

protected:
    virtual void register_fields() override {
        register_field("cellular.prov.src", "Provenance source (at or diag)", &prov_src);
        register_field("cellular.prov.origin",
            "Most recent origin (AT command or DIAG log code)", &prov_origin);
        register_field("cellular.prov.last_seen",
            "Server time (unix sec) this source last contributed", &prov_last_seen);
        register_field("cellular.prov.captured_at",
            "Raw prov.captured_at from the last observation", &prov_captured_at);
        register_field("cellular.prov.observation_count",
            "Observations contributed by this source", &prov_observation_count);
        register_field("cellular.prov.fields",
            "Distinct fields contributed by this source", &prov_fields);
    }

    std::shared_ptr<tracker_element_string> prov_src;
    std::shared_ptr<tracker_element_string> prov_origin;
    std::shared_ptr<tracker_element_uint64> prov_last_seen;
    std::shared_ptr<tracker_element_double> prov_captured_at;
    std::shared_ptr<tracker_element_uint64> prov_observation_count;
    std::shared_ptr<tracker_element_vector_string> prov_fields;
};

class kis_cellular_tracked_cell : public tracker_component {
public:
    kis_cellular_tracked_cell() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    kis_cellular_tracked_cell(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_cellular_tracked_cell(int in_id,
        std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_cellular_tracked_cell");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    // Identity
    __Proxy(cell_mcc, uint64_t, uint16_t, uint16_t, cell_mcc);
    __Proxy(cell_mnc, uint64_t, uint16_t, uint16_t, cell_mnc);
    __Proxy(cell_tac, uint64_t, uint32_t, uint32_t, cell_tac);
    __Proxy(cell_cellid, uint64_t, uint64_t, uint64_t, cell_cellid);
    __Proxy(cell_pci, uint64_t, uint16_t, uint16_t, cell_pci);
    __Proxy(cell_key, std::string, std::string, std::string, cell_key);
    __Proxy(cell_operator, std::string, std::string, std::string, cell_operator);

    // Network
    __Proxy(cell_rat, std::string, std::string, std::string, cell_rat);
    __Proxy(cell_duplex, std::string, std::string, std::string, cell_duplex);
    __Proxy(cell_arfcn, uint64_t, uint32_t, uint32_t, cell_arfcn);
    __Proxy(cell_band, uint64_t, uint16_t, uint16_t, cell_band);
    __Proxy(cell_bandwidth, uint64_t, uint16_t, uint16_t, cell_bandwidth);

    // Signal
    __Proxy(cell_rsrp, int64_t, int16_t, int16_t, cell_rsrp);
    __Proxy(cell_rsrq, int64_t, int16_t, int16_t, cell_rsrq);
    __Proxy(cell_sinr, int64_t, int16_t, int16_t, cell_sinr);
    __Proxy(cell_rssi, int64_t, int16_t, int16_t, cell_rssi);
    __Proxy(cell_min_rsrp, int64_t, int16_t, int16_t, cell_min_rsrp);
    __Proxy(cell_max_rsrp, int64_t, int16_t, int16_t, cell_max_rsrp);

    // Identity level: "full" (MCC+MNC+CID) or "partial" (PCI+EARFCN+RAT only)
    __Proxy(cell_identity_level, std::string, std::string, std::string, cell_identity_level);

    // Observation
    __Proxy(cell_observation_count, uint64_t, uint64_t, uint64_t, cell_observation_count);
    __Proxy(cell_seen_serving, uint8_t, bool, bool, cell_seen_serving);
    __Proxy(cell_seen_observed, uint8_t, bool, bool, cell_seen_observed);

    // Provenance (M3.3): per-source contribution map keyed by source name (at/diag)
    __ProxyTrackable(cell_seen_via, tracker_element_string_map, cell_seen_via);

protected:
    virtual void register_fields() override {
        // Identity
        register_field("cellular.cell.mcc", "Mobile Country Code", &cell_mcc);
        register_field("cellular.cell.mnc", "Mobile Network Code", &cell_mnc);
        register_field("cellular.cell.tac", "Tracking/Location Area Code", &cell_tac);
        register_field("cellular.cell.cellid", "Cell ID", &cell_cellid);
        register_field("cellular.cell.pci", "Physical Cell ID", &cell_pci);
        register_field("cellular.cell.key", "Cell Key (MCC+MNC+TAC+CID or PCI+EARFCN)", &cell_key);
        register_field("cellular.cell.operator", "Network operator name", &cell_operator);

        // Network
        register_field("cellular.cell.rat", "Radio Access Technology", &cell_rat);
        register_field("cellular.cell.duplex", "Duplex mode (FDD/TDD)", &cell_duplex);
        register_field("cellular.cell.arfcn", "Absolute Radio Frequency Channel Number", &cell_arfcn);
        register_field("cellular.cell.band", "Band number", &cell_band);
        register_field("cellular.cell.bandwidth", "Channel bandwidth MHz", &cell_bandwidth);

        // Signal
        register_field("cellular.cell.rsrp", "Last RSRP dBm", &cell_rsrp);
        register_field("cellular.cell.rsrq", "Last RSRQ dB", &cell_rsrq);
        register_field("cellular.cell.sinr", "Last SINR dB", &cell_sinr);
        register_field("cellular.cell.rssi", "Last RSSI dBm", &cell_rssi);
        register_field("cellular.cell.min_rsrp", "Minimum RSRP dBm seen", &cell_min_rsrp);
        register_field("cellular.cell.max_rsrp", "Maximum RSRP dBm seen", &cell_max_rsrp);

        // Identity level
        register_field("cellular.cell.identity_level", "Identity level: full or partial", &cell_identity_level);

        // Observation
        register_field("cellular.cell.observation_count", "Number of observations", &cell_observation_count);
        register_field("cellular.cell.seen_serving", "Seen as serving cell", &cell_seen_serving);
        register_field("cellular.cell.seen_observed", "Seen via signal observation (partial identity)", &cell_seen_observed);

        // Provenance
        register_field("cellular.cell.seen_via",
            "Provenance: capture sources that contributed to this tower", &cell_seen_via);
    }

    // Identity
    std::shared_ptr<tracker_element_uint64> cell_mcc;
    std::shared_ptr<tracker_element_uint64> cell_mnc;
    std::shared_ptr<tracker_element_uint64> cell_tac;
    std::shared_ptr<tracker_element_uint64> cell_cellid;
    std::shared_ptr<tracker_element_uint64> cell_pci;
    std::shared_ptr<tracker_element_string> cell_key;
    std::shared_ptr<tracker_element_string> cell_operator;

    // Network
    std::shared_ptr<tracker_element_string> cell_rat;
    std::shared_ptr<tracker_element_string> cell_duplex;
    std::shared_ptr<tracker_element_uint64> cell_arfcn;
    std::shared_ptr<tracker_element_uint64> cell_band;
    std::shared_ptr<tracker_element_uint64> cell_bandwidth;

    // Signal
    std::shared_ptr<tracker_element_int64> cell_rsrp;
    std::shared_ptr<tracker_element_int64> cell_rsrq;
    std::shared_ptr<tracker_element_int64> cell_sinr;
    std::shared_ptr<tracker_element_int64> cell_rssi;
    std::shared_ptr<tracker_element_int64> cell_min_rsrp;
    std::shared_ptr<tracker_element_int64> cell_max_rsrp;

    // Identity level
    std::shared_ptr<tracker_element_string> cell_identity_level;

    // Observation
    std::shared_ptr<tracker_element_uint64> cell_observation_count;
    std::shared_ptr<tracker_element_uint8> cell_seen_serving;
    std::shared_ptr<tracker_element_uint8> cell_seen_observed;

    // Provenance
    std::shared_ptr<tracker_element_string_map> cell_seen_via;
};

class kis_cellular_phy : public kis_phy_handler {
public:
    kis_cellular_phy() :
        kis_phy_handler() { }

    kis_cellular_phy(int in_phyid);

    virtual ~kis_cellular_phy();

    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_cellular_phy(in_phyid);
    }

    static int packet_handler(CHAINCALL_PARMS);

    bool json_to_cell(nlohmann::json& json, const std::shared_ptr<kis_packet>& packet);

    static mac_addr cellkey_to_mac(const std::string& cell_key);

    virtual bool device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) override;

    std::shared_ptr<kis_cellular_tracked_cell> fetch_cell_record(
        const std::shared_ptr<kis_tracked_device_base>& dev);

    // Provenance (M3.3): merge one observation's prov block into the tower's
    // per-source seen_via map (create-or-update the record for prov.src, refresh
    // last_seen/origin, and union in the field names this observation carried).
    void update_seen_via(const std::shared_ptr<kis_cellular_tracked_cell>& celldev,
            const std::string& src, const std::string& origin,
            double captured_at, const std::vector<std::string>& fields);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device) override;

    int pack_comp_common, pack_comp_json, pack_comp_meta, pack_comp_gps, pack_comp_device,
        pack_comp_radiodata;

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int cell_device_entry_id;

    // Entry id for minting per-source provenance records (kis_cellular_tracked_prov_source)
    // that live in each tower's cell_seen_via map (M3.3).
    int prov_source_entry_id;

    // Cached device type strings
    std::shared_ptr<tracker_element_string> devtype_cell;
    std::shared_ptr<tracker_element_string> devtype_cell_partial;

    // PCI+EARFCN → full-identity device key lookup.
    // Populated when a full-identity observation includes PCI+EARFCN
    // (from AT#SERVINFO, AT#CSURVC, AT+QENG serving with PCI, AT+QSCAN).
    // Consulted when a partial-identity observation arrives to create
    // related-device links.
    // Key: "{pci}_{earfcn}", Value: device_key of the full-identity device.
    std::map<std::string, device_key> pci_to_full_identity;
};

#endif
