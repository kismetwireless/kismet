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

#ifndef __PHY_BLUETOOTH_H__
#define __PHY_BLUETOOTH_H__

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

class bluetooth_tracked_device;

class bluetooth_packinfo : public packet_component {
public:
    bluetooth_packinfo() {
        self_destruct = 1;
    }

    mac_addr address;
    std::string name;
    std::vector<uuid> service_uuid_vec;
    int txpower;
    int type;
};

class bluetooth_tracked_device : public tracker_component {
public:
    bluetooth_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    bluetooth_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bluetooth_tracked_device(int in_id, 
            std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {

        register_fields();
        reserve_fields(e);
    }

    bluetooth_tracked_device(const bluetooth_tracked_device *p) :
        tracker_component{p} {

        __ImportField(service_uuid_vec, p);
        __ImportField(solicitation_uuid_vec, p);
        __ImportField(scan_data_bytes, p);
        __ImportField(service_data_bytes, p);
        __ImportField(txpower, p);
        __ImportField(pathloss, p);

        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("bluetooth_tracked_device");
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
        return std::move(dup);
    }

    __ProxyTrackable(service_uuid_vec, tracker_element_vector, service_uuid_vec);
    __ProxyTrackable(solicitation_uuid_vec, tracker_element_vector, solicitation_uuid_vec);
    __ProxyTrackable(service_data_bytes, tracker_element_string_map, service_data_bytes);

    __Proxy(scan_data_bytes, std::string, std::string, std::string, scan_data_bytes);
    void set_scan_data_from_hex(const std::string& in) {
        scan_data_bytes->from_hex(in);
    }

    __Proxy(txpower, int16_t, int16_t, int16_t, txpower);
    __Proxy(pathloss, int16_t, int16_t, int16_t, pathloss);

protected:
    virtual void register_fields() override {
        register_field("bluetooth.device.service_uuid_vec", "advertised service UUIDs", &service_uuid_vec);
        register_field("bluetooth.device.solicitation_uuid_vec", 
				"advertised solicitation UUIDs", &solicitation_uuid_vec);

		register_field("bluetooth.device.scan_data_bytes", "scan result bytes", &scan_data_bytes);
        register_field("bluetooth.device.service_data_bytes", "per-service result bytes", &service_data_bytes);
        register_field("bluetooth.device.txpower", "advertised transmit power", &txpower);
        register_field("bluetooth.device.pathloss", "signal pathloss", &pathloss);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);
    }

    std::shared_ptr<tracker_element_vector> service_uuid_vec;
	std::shared_ptr<tracker_element_vector> solicitation_uuid_vec;

	std::shared_ptr<tracker_element_byte_array> scan_data_bytes;
    // UUIDs as string keys
	std::shared_ptr<tracker_element_string_map> service_data_bytes;

    std::shared_ptr<tracker_element_int16> txpower;
	std::shared_ptr<tracker_element_int16> pathloss;
};

class kis_bluetooth_phy : public kis_phy_handler {
public:
	// Stub
	virtual ~kis_bluetooth_phy();

	// Inherited functionality
	kis_bluetooth_phy(global_registry *in_globalreg) :
		kis_phy_handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(global_registry *in_globalreg,
											  int in_phyid) {
		return new kis_bluetooth_phy(in_globalreg, in_phyid);
	}

	// Strong constructor
	kis_bluetooth_phy(global_registry *in_globalreg, int in_phyid);

	// Bluetooth device record classifier to common for the devicetracker layer
	static int common_classifier_bluetooth(CHAINCALL_PARMS);

    static int packet_bluetooth_scan_json_classifier(CHAINCALL_PARMS);
   
    // Tracker entry
	static int packet_tracker_bluetooth(CHAINCALL_PARMS);

    // Load stored data
    virtual void load_phy_storage(shared_tracker_element in_storage, 
            shared_tracker_element in_device);

protected:
    std::shared_ptr<alert_tracker> alertracker;
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int bluetooth_device_entry_id;

	// Device components
	int dev_comp_bluetooth, dev_comp_common;

	// Packet components
	int pack_comp_btdevice, pack_comp_common, pack_comp_l1info, pack_comp_meta, pack_comp_json;
};

#endif
