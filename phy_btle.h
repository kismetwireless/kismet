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
    }

    std::shared_ptr<tracker_element_uint8> le_limited_discoverable;
    std::shared_ptr<tracker_element_uint8> le_general_discoverable;
    std::shared_ptr<tracker_element_uint8> br_edr_unsupported;
    std::shared_ptr<tracker_element_uint8> simultaneous_br_edr_controller;
    std::shared_ptr<tracker_element_uint8> simultaneous_br_edr_host;
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

    /* From the BTLE spec and Wireshark */
    static uint32_t calc_btle_crc(uint32_t crc_init, const char *data, size_t len);
    static uint32_t reverse_bits(const uint32_t val);

    virtual bool device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) override;

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<alert_tracker> alertracker;

    int pack_comp_common, pack_comp_linkframe, pack_comp_decap, pack_comp_btle;

    int btle_device_id, btle_uuid_id;

    std::unordered_map<uint16_t, std::shared_ptr<tracker_element_string>> btle_uuid_cache;

    bool ignore_random;

    int alert_bleedingtooth_ref, alert_flipper_ref;
};

#endif

