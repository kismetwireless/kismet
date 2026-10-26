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

#ifndef __PHY_BTLE_H__
#define __PHY_BTLE_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "packet.h"
#include "gpstracker.h"
#include "uuid.h"

#include "devicetracker.h"
#include "devicetracker_component.h"

class btle_tracked_advertised_service : public tracker_component {
public:
    btle_tracked_advertised_service() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_advertised_service(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_advertised_service(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_advertised_service");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

protected:
    virtual void register_fields() override {
        // Manufacturer is added in dynamically
        tracker_component::register_fields();
        register_field("btle.short_service.uuid", "16bit service UUID", &short_uuid);
        register_field("btle.short_service.data", "Service data", &advertised_data);
    }

    std::shared_ptr<tracker_element_uint16> short_uuid;
    std::shared_ptr<tracker_element_byte_array> advertised_data;
};

// Location tracker (item finder) state decoded from the advertisements; only present
// on devices which advertised as a known tracker.  Vendor specific values are dynamic
// so a tracker type only carries the fields it advertises.
class btle_tracked_tracker : public tracker_component {
public:
    btle_tracked_tracker() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_tracker(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_tracker(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_tracker");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(tracker_type, std::string, std::string, std::string, tracker_type);
    __Proxy(state, uint8_t, uint8_t, uint8_t, state);
    __Proxy(state_name, std::string, std::string, std::string, state_name);
    __Proxy(separated, uint8_t, bool, bool, separated);
    __Proxy(battery, std::string, std::string, std::string, battery);
    __Proxy(flags, uint8_t, uint8_t, uint8_t, flags);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    __ProxyDynamic(uwb, uint8_t, bool, bool, uwb, uwb_id);
    __ProxyDynamic(aging_counter, uint32_t, uint32_t, uint32_t, aging_counter, aging_counter_id);
    __ProxyDynamic(privacy_id, std::string, std::string, std::string, privacy_id, privacy_id_id);
    __ProxyDynamic(subtype, std::string, std::string, std::string, subtype, subtype_id);
    __ProxyDynamic(ephemeral_id, std::string, std::string, std::string, ephemeral_id, ephemeral_id_id);
    __ProxyDynamic(network_id, uint8_t, uint8_t, uint8_t, network_id, network_id_id);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("btle.device.tracker.type",
                "Tracker type (samsung_smarttag, apple_findmy, google_fmdn, dult)", &tracker_type);
        register_field("btle.device.tracker.state", "Raw operating state advertised by the tracker",
                &state);
        register_field("btle.device.tracker.state_name",
                "Operating state (premature_offline, offline, overmature_offline, connected, "
                "separated, near_owner, normal, unwanted_tracking_protection, unknown)",
                &state_name);
        register_field("btle.device.tracker.separated",
                "Tracker advertises that it is away from its owner", &separated);
        register_field("btle.device.tracker.battery",
                "Battery level (full, medium, low, very_low, unknown)", &battery);
        register_field("btle.device.tracker.flags", "Raw flags byte advertised by the tracker", &flags);
        register_field("btle.device.tracker.last_time", "Last time a tracker advertisement was seen",
                &last_time);

        uwb_id =
            register_dynamic_field("btle.device.tracker.uwb", "Tracker supports UWB ranging", &uwb);
        aging_counter_id =
            register_dynamic_field("btle.device.tracker.aging_counter",
                    "Aging counter advertised by the tracker", &aging_counter);
        privacy_id_id =
            register_dynamic_field("btle.device.tracker.privacy_id",
                    "Rotating privacy ID advertised by the tracker (hex)", &privacy_id);
        subtype_id =
            register_dynamic_field("btle.device.tracker.subtype",
                    "Kind of device within the tracker type (airtag, findmy_accessory, airpods)",
                    &subtype);
        ephemeral_id_id =
            register_dynamic_field("btle.device.tracker.ephemeral_id",
                    "Ephemeral identifier advertised by the tracker, rotates every 1024 seconds (hex)",
                    &ephemeral_id);
        network_id_id =
            register_dynamic_field("btle.device.tracker.network_id",
                    "Finding network ID from the DULT advertisement", &network_id);
    }

    std::shared_ptr<tracker_element_string> tracker_type;
    std::shared_ptr<tracker_element_uint8> state;
    std::shared_ptr<tracker_element_string> state_name;
    std::shared_ptr<tracker_element_uint8> separated;
    std::shared_ptr<tracker_element_string> battery;
    std::shared_ptr<tracker_element_uint8> flags;
    std::shared_ptr<tracker_element_uint64> last_time;

    std::shared_ptr<tracker_element_uint8> uwb;
    uint16_t uwb_id;
    std::shared_ptr<tracker_element_uint32> aging_counter;
    uint16_t aging_counter_id;
    std::shared_ptr<tracker_element_string> privacy_id;
    uint16_t privacy_id_id;
    std::shared_ptr<tracker_element_string> subtype;
    uint16_t subtype_id;
    std::shared_ptr<tracker_element_string> ephemeral_id;
    uint16_t ephemeral_id_id;
    std::shared_ptr<tracker_element_uint8> network_id;
    uint16_t network_id_id;
};

// Future btle attributes
class btle_tracked_device : public tracker_component {
public:
    btle_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_device(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

   __Proxy(le_limited_discoverable, uint8_t, bool, bool, le_limited_discoverable);
   __Proxy(le_general_discoverable, uint8_t, bool, bool, le_general_discoverable);
   __Proxy(br_edr_unsupported, uint8_t, bool, bool, br_edr_unsupported);
   __Proxy(simultaneous_br_edr_controller, uint8_t, bool, bool, simultaneous_br_edr_controller);
   __Proxy(simultaneous_br_edr_host, uint8_t, bool, bool, simultaneous_br_edr_host);
   __Proxy(pdu_type, uint8_t, uint8_t, uint8_t, pdu_type);

   // Advertised 16/32/128-bit service UUIDs, accumulated across every
   // advertisement seen (as hex strings, not this codebase's uuid type).
   __ProxyTrackable(service_uuid_vec, tracker_element_vector_string, service_uuid_vec);

   // Manufacturer Specific Data from the most recent match; not
   // accumulated, unlike service_uuid_vec, since it commonly rotates.
   __Proxy(manuf_company_id, std::string, std::string, std::string, manuf_company_id);
   __Proxy(manuf_data, std::string, std::string, std::string, manuf_data);

   // Only created for devices advertising as a location tracker
   __ProxyDynamicTrackable(tracker, btle_tracked_tracker, tracker, tracker_id);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("btle.device.le_limited_discoverable", "BT LE limited discoverable mode",
                &le_limited_discoverable);
        register_field("btle.device.le_general_discoverable", "BT LE general discoverable mode",
                &le_general_discoverable);
        register_field("btle.device.br_edr_unsupported", "BT LE BR/EDR unsupported",
                &br_edr_unsupported);
        register_field("btle.device.simultaneous_br_edr_controller",
                "BT LE simultaneous BR/EDR controller mode",
                &simultaneous_br_edr_controller);
        register_field("btle.device.simultaneous_br_edr_host", "BT LE simultaneous BR/EDR host mode",
                &simultaneous_br_edr_host);
        register_field("btle.device.pdu_type", "BTLE advertising PDU type",
                &pdu_type);
        register_field("btle.device.service_uuid_vec", "advertised service UUIDs", &service_uuid_vec);
        register_field("btle.device.manuf_company_id", "manufacturer company ID", &manuf_company_id);
        register_field("btle.device.manuf_data", "manufacturer data payload", &manuf_data);

        tracker_id =
            register_dynamic_field("btle.device.tracker", "location tracker advertisement", &tracker);
    }

    std::shared_ptr<tracker_element_uint8> le_limited_discoverable;
    std::shared_ptr<tracker_element_uint8> le_general_discoverable;
    std::shared_ptr<tracker_element_uint8> br_edr_unsupported;
    std::shared_ptr<tracker_element_uint8> simultaneous_br_edr_controller;
    std::shared_ptr<tracker_element_uint8> simultaneous_br_edr_host;
    std::shared_ptr<tracker_element_uint8> pdu_type;
    std::shared_ptr<tracker_element_vector_string> service_uuid_vec;
    std::shared_ptr<tracker_element_string> manuf_company_id;
    std::shared_ptr<tracker_element_string> manuf_data;

    std::shared_ptr<btle_tracked_tracker> tracker;
    uint16_t tracker_id;
};

class kis_btle_phy : public kis_phy_handler {
public:
    kis_btle_phy() :
        kis_phy_handler() { }

    kis_btle_phy(int in_phyid);

    virtual ~kis_btle_phy();

    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_btle_phy(in_phyid);
    }

    static int dissector(CHAINCALL_PARMS);
    static int common_classifier(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device) override;

    static uint32_t ble_crc24(uint32_t crc_init, const char *data, size_t len);

    virtual bool device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) override;

    std::shared_ptr<btle_tracked_device> fetch_btle_record(const std::shared_ptr<kis_tracked_device_base>& dev) {
        return dev->get_sub_as<btle_tracked_device>(btle_device_id);
    }

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<alert_tracker> alertracker;

    int pack_comp_linkframe, pack_comp_decap, pack_comp_btle, pack_comp_remoteid;

    int btle_device_id, btle_uuid_id;

    std::unordered_map<uint16_t, std::shared_ptr<tracker_element_string>> btle_uuid_cache;

    bool ignore_random;

    int alert_bleedingtooth_ref, alert_flipper_ref;

    std::shared_ptr<tracker_element_string> devtype_tracker;
};

#endif

