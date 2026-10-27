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
#include "phy_btle.h"

#ifndef KDLT_BT_H4_LINUX
#define KDLT_BT_H4_LINUX        99
#endif

class bluetooth_tracked_device;

class bluetooth_packinfo : public packet_component {
public:
    bluetooth_packinfo() { }

    void reset() {
        address = mac_addr{0};
        name = "";
        service_uuid_vec.clear();
        txpower = 0;
        type = 0;
    }

    mac_addr address;
    std::string name;
    std::vector<uuid> service_uuid_vec;
    int txpower;
    int type;
};

enum class bt_device_type {
    bredr,
    btle,
    bt,
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

    virtual uint32_t get_signature() const override {
        return adler32_checksum("bluetooth_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
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
    __Proxy(bt_device_type, uint8_t, uint8_t, uint8_t, bt_device_type);

    __Proxy(connectable, uint8_t, uint8_t, uint8_t, connectable);

    // Advertised service UUIDs as hex strings; separate from
    // service_uuid_vec above, which holds real uuid objects and isn't
    // populated by the linuxbthci JSON path this one feeds.
    // manuf_company_id is the 4-hex-char BT SIG company ID; manuf_data is
    // the payload after it, as a hex string.
    __ProxyTrackable(service_uuid_strs, tracker_element_vector_string, service_uuid_strs);
    __Proxy(manuf_company_id, std::string, std::string, std::string, manuf_company_id);
    __Proxy(manuf_data, std::string, std::string, std::string, manuf_data);

    // Only created for devices advertising as a location tracker
    __ProxyDynamicTrackable(tracker, btle_tracked_tracker, tracker, tracker_id);
    __ProxyDynamicTrackable(battery, btle_tracked_battery, battery, battery_id);
    __ProxyDynamicTrackable(ranging, btle_tracked_ranging, ranging, ranging_id);
    __ProxyDynamicTrackable(beacon, btle_tracked_beacon, beacon, beacon_id);

    // Only created when the device advertises them
    __ProxyDynamic(class_of_device, uint32_t, uint32_t, uint32_t, class_of_device,
            class_of_device_id);
    __ProxyDynamic(major_class, std::string, std::string, std::string, device_major_class,
            major_class_id);
    __ProxyDynamic(minor_class, std::string, std::string, std::string, device_minor_class,
            minor_class_id);
    __ProxyDynamicTrackable(service_classes, tracker_element_vector_string, service_classes,
            service_classes_id);
    __ProxyDynamic(appearance, uint16_t, uint16_t, uint16_t, appearance, appearance_id);
    __ProxyDynamic(appearance_name, std::string, std::string, std::string, appearance_name,
            appearance_name_id);

protected:
    virtual void register_fields() override {
        register_field("bluetooth.device.type", "bt device type", &bt_device_type);

        class_of_device_id =
            register_dynamic_field("bluetooth.device.class", "BR/EDR class of device",
                    &class_of_device);
        major_class_id =
            register_dynamic_field("bluetooth.device.major_class", "bt major class",
                    &device_major_class);
        minor_class_id =
            register_dynamic_field("bluetooth.device.minor_class", "bt device minor class",
                    &device_minor_class);
        service_classes_id =
            register_dynamic_field("bluetooth.device.service_classes",
                    "BR/EDR service classes from the class of device", &service_classes);
        appearance_id =
            register_dynamic_field("bluetooth.device.appearance", "advertised appearance",
                    &appearance);
        appearance_name_id =
            register_dynamic_field("bluetooth.device.appearance_name",
                    "advertised appearance, as text", &appearance_name);

        register_field("bluetooth.device.service_uuid_vec", "advertised service UUIDs", &service_uuid_vec);
        register_field("bluetooth.device.solicitation_uuid_vec",
				"advertised solicitation UUIDs", &solicitation_uuid_vec);

		register_field("bluetooth.device.scan_data_bytes", "scan result bytes", &scan_data_bytes);
        register_field("bluetooth.device.service_data_bytes", "per-service result bytes", &service_data_bytes);
        register_field("bluetooth.device.txpower", "advertised transmit power", &txpower);
        register_field("bluetooth.device.pathloss", "signal pathloss", &pathloss);
        register_field("bluetooth.device.connectable", "device is connectable", &connectable);

        register_field("bluetooth.device.service_uuid_strs", "advertised service UUIDs, as hex strings",
                &service_uuid_strs);
        register_field("bluetooth.device.manuf_company_id", "manufacturer company ID", &manuf_company_id);
        register_field("bluetooth.device.manuf_data", "manufacturer data payload", &manuf_data);

        tracker_id =
            register_dynamic_field("bluetooth.device.tracker", "location tracker advertisement",
                    &tracker);
        battery_id =
            register_dynamic_field("bluetooth.device.battery", "advertised battery level",
                    &battery);
        ranging_id =
            register_dynamic_field("bluetooth.device.ranging", "estimated distance", &ranging);
        beacon_id =
            register_dynamic_field("bluetooth.device.beacon", "advertised beacon identity", &beacon);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);
    }

    std::shared_ptr<tracker_element_uint8> bt_device_type;

    std::shared_ptr<tracker_element_uint32> class_of_device;
    uint16_t class_of_device_id;
    std::shared_ptr<tracker_element_string> device_major_class;
    uint16_t major_class_id;
    std::shared_ptr<tracker_element_string> device_minor_class;
    uint16_t minor_class_id;
    std::shared_ptr<tracker_element_vector_string> service_classes;
    uint16_t service_classes_id;
    std::shared_ptr<tracker_element_uint16> appearance;
    uint16_t appearance_id;
    std::shared_ptr<tracker_element_string> appearance_name;
    uint16_t appearance_name_id;

    std::shared_ptr<tracker_element_vector> service_uuid_vec;
	std::shared_ptr<tracker_element_vector> solicitation_uuid_vec;

	std::shared_ptr<tracker_element_byte_array> scan_data_bytes;
    // UUIDs as string keys
	std::shared_ptr<tracker_element_string_map> service_data_bytes;

    std::shared_ptr<tracker_element_int16> txpower;
	std::shared_ptr<tracker_element_int16> pathloss;

    std::shared_ptr<tracker_element_uint8> connectable;

    std::shared_ptr<tracker_element_vector_string> service_uuid_strs;
    std::shared_ptr<tracker_element_string> manuf_company_id;
    std::shared_ptr<tracker_element_string> manuf_data;

    std::shared_ptr<btle_tracked_tracker> tracker;
    uint16_t tracker_id;
    std::shared_ptr<btle_tracked_battery> battery;
    uint16_t battery_id;
    std::shared_ptr<btle_tracked_ranging> ranging;
    uint16_t ranging_id;
    std::shared_ptr<btle_tracked_beacon> beacon;
    uint16_t beacon_id;
};

class kis_bluetooth_phy : public kis_phy_handler {
public:
	// Stub
	virtual ~kis_bluetooth_phy();

	// Inherited functionality
	kis_bluetooth_phy() :
		kis_phy_handler() { };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
		return new kis_bluetooth_phy(in_phyid);
	}

	// Strong constructor
	kis_bluetooth_phy(int in_phyid);

	// Bluetooth device record classifier to common for the devicetracker layer
	static int common_classifier_bluetooth(CHAINCALL_PARMS);

    static int packet_bluetooth_scan_json_classifier(CHAINCALL_PARMS);

    static int packet_bluetooth_hci_json_classifier(CHAINCALL_PARMS);

    // Tracker entry
	static int packet_tracker_bluetooth(CHAINCALL_PARMS);

    // H4 Linux DLT parser
    static int packet_tracker_h4_linux(CHAINCALL_PARMS);

    // Load stored data
    virtual void load_phy_storage(shared_tracker_element in_storage, 
            shared_tracker_element in_device) override;

    virtual bool device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) override;

    std::shared_ptr<bluetooth_tracked_device> fetch_bluetooth_record(const std::shared_ptr<kis_tracked_device_base>& dev);

protected:
    std::shared_ptr<alert_tracker> alertracker;
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int bluetooth_device_entry_id;

	// Device components
	int dev_comp_bluetooth, dev_comp_common;

	// Packet components
	int pack_comp_btdevice, pack_comp_meta, pack_comp_json,
        pack_comp_linkframe, pack_comp_remoteid;

    std::shared_ptr<tracker_element_string> btdev_bredr;
    std::shared_ptr<tracker_element_string> btdev_btle;
    std::shared_ptr<tracker_element_string> btdev_bt;
    std::shared_ptr<tracker_element_string> btdev_tracker;

    int alert_flipper_ref, alert_trackerfollow_ref;

    double distance_exponent;
};

#endif
