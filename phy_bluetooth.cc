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

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <memory>

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "phy_bluetooth.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "alertracker.h"

#include "bluetooth_types.h"


#define h4_direction_sent                       0x00
#define h4_direction_recv                       0x01

#define h4_hci_event                            0x04

#define h4_extended_inquiry_result              0x2f
#define h4_remote_name_req_complete             0x07
#define h4_remote_supported_features            0x3d
#define h4_ec_le_meta                           0x3e

#define h4_ec_le_meta_sub_advertising_report    0x02

#define h4_ext_data_16bit_uuid                  0x03
#define h4_ext_data_32bit_uuid                  0x05
#define h4_ext_data_128bit_uuid                 0x07
#define h4_ext_data_devicename                  0x09
#define h4_ext_data_deviceid                    0x10
#define h4_ext_data_txpower                     0x0a

kis_bluetooth_phy::kis_bluetooth_phy(int in_phyid) : 
    kis_phy_handler(in_phyid) {

    alertracker =
        Globalreg::fetch_mandatory_global_as<alert_tracker>();
    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    set_phy_name("Bluetooth");

    bluetooth_device_entry_id =
        entrytracker->register_field("bluetooth.device", 
                tracker_element_factory<bluetooth_tracked_device>(),
                "Bluetooth device");

    packetchain->register_handler(&common_classifier_bluetooth, this, CHAINPOS_CLASSIFIER, -100);
    packetchain->register_handler(&packet_tracker_bluetooth, this, CHAINPOS_TRACKER, -100);
    packetchain->register_handler(&packet_tracker_h4_linux, this, CHAINPOS_TRACKER, -100);
    packetchain->register_handler(&packet_bluetooth_scan_json_classifier, this, CHAINPOS_CLASSIFIER, -99);
    packetchain->register_handler(&packet_bluetooth_hci_json_classifier, this, CHAINPOS_CLASSIFIER, -99);

    pack_comp_btdevice = packetchain->register_packet_component("BTDEVICE");
	pack_comp_common = packetchain->register_packet_component("COMMON");
    pack_comp_l1info = packetchain->register_packet_component("RADIODATA");
    pack_comp_meta = packetchain->register_packet_component("METABLOB");
    pack_comp_json = packetchain->register_packet_component("JSON");
    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");

    btdev_bredr = devicetracker->get_cached_devicetype("BR/EDR");
    btdev_btle = devicetracker->get_cached_devicetype("BTLE");
    btdev_bt = devicetracker->get_cached_devicetype("BT");

    alert_flipper_ref =
        alertracker->activate_configured_alert("FLIPPERZERO",
                "PROBE", kis_alert_severity::high,
                "Flipper Zero devices can be used to generate spoofed "
                "BTLE events which can act as denial of service attacks "
                "or cause other problems with some Bluetooth devices.", phyid);

    // Register js module for UI
    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_bluetooth", "js/kismet.ui.bluetooth.js");
}

kis_bluetooth_phy::~kis_bluetooth_phy() {
    packetchain->remove_handler(&common_classifier_bluetooth, CHAINPOS_CLASSIFIER);
}

bool kis_bluetooth_phy::device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) {
    return (dev->get_sub_as<bluetooth_tracked_device>(bluetooth_device_entry_id) != nullptr);
}

std::shared_ptr<bluetooth_tracked_device> kis_bluetooth_phy::fetch_bluetooth_record(const std::shared_ptr<kis_tracked_device_base>& dev) {
    return dev->get_sub_as<bluetooth_tracked_device>(bluetooth_device_entry_id);
}

int kis_bluetooth_phy::common_classifier_bluetooth(CHAINCALL_PARMS) {
    auto btphy = static_cast<kis_bluetooth_phy *>(auxdata);

    auto btpi = in_pack->fetch<bluetooth_packinfo>(btphy->pack_comp_btdevice);

    if (btpi == NULL) {
        return 0;
    }

    auto ci = in_pack->fetch_or_add<kis_common_info>(btphy->pack_comp_common);

    ci->phyid = btphy->fetch_phy_id();
    ci->type = packet_basic_mgmt;
    ci->direction = packet_direction_from;
    ci->source = btpi->address;
    ci->transmitter = btpi->address;
    ci->channel = "FHSS";
    ci->freq_khz = 2400000;

    return 0;
}

int kis_bluetooth_phy::packet_bluetooth_hci_json_classifier(CHAINCALL_PARMS) {
    kis_bluetooth_phy *btphy = (kis_bluetooth_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto pack_json =
        in_pack->fetch<kis_json_packinfo>(btphy->pack_comp_json);

    if (pack_json == nullptr)
        return 0;

    if (pack_json->type != "linuxbthci") {
        return 0;
    }

    auto commoninfo =
        in_pack->fetch<kis_common_info>(btphy->pack_comp_common);

    if (commoninfo != nullptr) {
        return 0;
    }

    try {
        std::stringstream newdevstr;
        std::stringstream ss(pack_json->json_string);
        nlohmann::json json;
        ss >> json;

        // auto new_device = false;

        const auto btaddr_j = json["addr"];

        if (btaddr_j.is_null())
            throw std::runtime_error("no btaddr in scan report");

        auto btaddr_mac = mac_addr(btaddr_j.get<std::string>());
        if (btaddr_mac.state.error)
            throw std::runtime_error("invalid btaddr MAC");

        commoninfo = std::make_shared<kis_common_info>();
        commoninfo->phyid = btphy->fetch_phy_id();
        commoninfo->type = packet_basic_mgmt;
        commoninfo->source = btaddr_mac;
        commoninfo->transmitter = btaddr_mac;
        commoninfo->channel = "FHSS";
        commoninfo->freq_khz = 2400000;

        in_pack->insert(btphy->pack_comp_common, commoninfo);

        kis_lock_guard<kis_mutex> lk(btphy->devicetracker->get_devicelist_mutex(),
                "packet_bluetooth_hci_json_classifier");

        auto basedev =
            btphy->devicetracker->update_common_device(commoninfo,
                    btaddr_mac, btphy, in_pack,
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                     UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                     UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                    "Bluetooth Device");

        auto btdev =
            basedev->get_sub_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

        // Mapped to base name
        auto devname_j = json["name"];

        if (devname_j.is_string())
            basedev->set_devicename(munge_to_printable(devname_j));

        if (btdev == nullptr) {
            std::stringstream ss;
            ss << "Detected new Bluetooth device " << btaddr_mac;
            if (basedev->get_devicename().length() > 0)
                ss << " (" << basedev->get_devicename() << ")";
            _MSG(ss.str(), MSGFLAG_INFO);

            btdev =
                Globalreg::globalreg->entrytracker->get_shared_instance_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

            basedev->insert(btdev);
        }

        // Mapped to base type, a combination of android major/minor
        auto devtype_j = json["type"];

        if (devtype_j.is_number()) {
            switch (devtype_j.get<unsigned int>()) {
                case 0:
                    basedev->set_tracker_type_string(btphy->btdev_bredr);
                    btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::bredr));
                    break;
                case 1:
                    basedev->set_tracker_type_string(btphy->btdev_btle);
                    btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::btle));
                    break;
                case 2:
                    basedev->set_tracker_type_string(btphy->btdev_btle);
                    btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::btle));
                    break;
                default:
                    basedev->set_tracker_type_string(btphy->btdev_bt);
                    btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::bt));
                    break;
            }
        }
    } catch (const std::exception& e) {
        in_pack->error = true;
        return 0;
    }

    return 1;
}

int kis_bluetooth_phy::packet_bluetooth_scan_json_classifier(CHAINCALL_PARMS) {
    kis_bluetooth_phy *btphy = (kis_bluetooth_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto pack_json =
        in_pack->fetch<kis_json_packinfo>(btphy->pack_comp_json);

    if (pack_json == nullptr)
        return 0;

    if (pack_json->type != "BLUETOOTHSCAN") { 
        return 0;
    }

    auto commoninfo =
        in_pack->fetch<kis_common_info>(btphy->pack_comp_common);

    if (commoninfo != nullptr) { 
        return 0;
    }

    try {
        std::stringstream newdevstr;
        std::stringstream ss(pack_json->json_string);
        nlohmann::json json;
        ss >> json;

        auto btaddr_j = json["btaddr"];

        auto new_device = false;

        if (btaddr_j.is_null()) 
            throw std::runtime_error("no btaddr in scan report");

        auto btaddr_mac = mac_addr(btaddr_j.get<std::string>());
        if (btaddr_mac.state.error)
            throw std::runtime_error("invalid btaddr MAC");

        commoninfo = std::make_shared<kis_common_info>();
        commoninfo->phyid = btphy->fetch_phy_id();
        commoninfo->type = packet_basic_mgmt;
        commoninfo->source = btaddr_mac;
        commoninfo->transmitter = btaddr_mac;
        commoninfo->channel = "FHSS";
        commoninfo->freq_khz = 2400000;

        in_pack->insert(btphy->pack_comp_common, commoninfo);

        kis_lock_guard<kis_mutex> lk(btphy->devicetracker->get_devicelist_mutex(),
                "packet_bluetooth_scan_json_classifier");

        auto btdev =
            btphy->devicetracker->update_common_device(commoninfo,
                    btaddr_mac, btphy, in_pack,
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                     UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                     UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                    "Bluetooth Device");

        // Mapped to base name
        auto devname_j = json["name"]; 

        // Mapped to base type, a combination of android major/minor
        auto devtype_j = json["devicetype"];

        auto powerlevel_j = json["txpowerlevel"];
        auto pathloss_j = json["pathloss"];

        // Mapped to base signal
        auto signal_j = json["signal"];

        // Scan bytes, hex string, optional
        auto scan_bytes_j = json["scan_data"];

        // Service data bytes, hex string, optional
        auto service_bytes_map_j = json["service_data"];

        if (devname_j.is_string())
            btdev->set_devicename(munge_to_printable(devname_j));

        if (devtype_j.is_string())
            btdev->set_tracker_type_string(btphy->devicetracker->get_cached_devicetype(munge_to_printable(devtype_j)));

        auto btdev_bluetooth =
            btdev->get_sub_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

        if (btdev_bluetooth == nullptr) {
            newdevstr << "Detected new HCI Bluetooth device " << btaddr_mac; 

            if (btdev->get_devicename().length() > 0)
                newdevstr << " (" << btdev->get_devicename() << ")";

            if (devtype_j.is_string())
                newdevstr << " " << btdev->get_type_string();

            _MSG_INFO("{}", newdevstr.str());

            btdev_bluetooth = 
                Globalreg::globalreg->entrytracker->get_shared_instance_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

            btdev->insert(btdev_bluetooth);

            new_device = true;
        }

        if (powerlevel_j.is_number())
            btdev_bluetooth->set_txpower(powerlevel_j.get<int>());

        if (pathloss_j.is_number())
            btdev_bluetooth->set_pathloss(pathloss_j.get<int>());

        if (scan_bytes_j.is_string())
            btdev_bluetooth->set_scan_data_from_hex(scan_bytes_j);

        if (service_bytes_map_j.is_object()) {
            for (const auto& u : service_bytes_map_j.items()) {
                auto v = u.value();

                if (!v.is_string())
                    throw std::runtime_error("expected string in service_data map");

                auto bytehex = 
                    std::make_shared<tracker_element_byte_array>();
                bytehex->from_hex(v);

                btdev_bluetooth->get_service_data_bytes()->insert(u.key(), bytehex);
            }
        }

        if (new_device) {
            if (commoninfo->source.OUI() == mac_addr::OUI((uint8_t *) "\x80\xe1\x26") ||
                    commoninfo->source.OUI() == mac_addr::OUI((uint8_t *) "\x80\xe1\x27")) {
                auto al = fmt::format("A BTLE advertisement packet with a source address "
                        "matching a Flipper Zero device was seen; The Flipper device is "
                        "capable of generating BTLE packets which may cause a denial of "
                        "service or other problems with some BTLE devices.");
                btphy->alertracker->raise_alert(btphy->alert_flipper_ref, in_pack,
                        mac_addr{}, btdev->get_macaddr(), mac_addr{}, mac_addr{},
                        "FHSS", al);

            }
        }

    } catch (const std::exception& e) {
        _MSG_ERROR("Invalid phybluetooth/BT/BTLE scan report: {}", e.what());
        in_pack->error = true;
        return 0;
    }

    return 1;
}

int kis_bluetooth_phy::packet_tracker_h4_linux(CHAINCALL_PARMS) {
    /* Decode the Linux H4 packet stream from sniffing bluetoothN devices */

    typedef struct {
        uint8_t event_code;
        uint8_t total_length;
        
        uint8_t data[0];
    } __attribute__((packed)) bt_h4_event;

    typedef struct {
        uint8_t num_responses;
        uint8_t bdaddr[6];
        uint8_t scan_repetition;
        uint8_t reserved;
        uint8_t minor_class; // 6 bits minor class
        uint16_t service_major_class; // Major service mask and major class
        uint16_t clock_offset;
        uint8_t rssi;

        uint8_t data[0];
    } __attribute__((packed)) bt_h4_ext_inq_result;

    typedef struct {
        uint8_t status;
        uint8_t bdaddr[6];
        uint8_t remote_name[0];
    } __attribute__((packed)) bt_h4_remote_name_complete;

    typedef struct {
        uint8_t length;
        uint8_t type;

        uint8_t data[0];
    } __attribute__((packed)) bt_h4_extended_data;

    auto mphy = static_cast<kis_bluetooth_phy *>(auxdata);

    if (in_pack->error || in_pack->filtered)
        return 0;

    auto linkchunk = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (linkchunk == nullptr)
        return 0;

    if (linkchunk->dlt != KDLT_BT_H4_LINUX)
        return 0;

    // We only care about events
    if (linkchunk->length() < sizeof(bt_h4_event) + 1)
        return 0;

    if (linkchunk->data()[0] != h4_hci_event)
        return 0;

    auto event = reinterpret_cast<const bt_h4_event *>(&linkchunk->data()[1]);

    if (event->total_length > linkchunk->length() - 1) {
        _MSG_DEBUG("Event length too long for frame");
        return 0;
    }

    if (event->event_code == h4_extended_inquiry_result) {
        if (event->total_length < sizeof(bt_h4_ext_inq_result)) {
            _MSG_DEBUG("Event length too short for ext_inq_result");
            return 0;
        }

        auto inquiry = reinterpret_cast<const bt_h4_ext_inq_result *>(event->data);

        uint8_t minor_class = inquiry->minor_class >> 2;
        uint16_t major_group = kis_letoh16(inquiry->service_major_class);
        uint8_t major_class = major_group & 0x1F;

        auto commoninfo = in_pack->fetch_or_add<kis_common_info>(mphy->pack_comp_common);
        commoninfo->phyid = mphy->fetch_phy_id();
        commoninfo->type = packet_basic_mgmt;
        commoninfo->source = mac_addr(inquiry->bdaddr, 6);
        commoninfo->transmitter = commoninfo->source;
        commoninfo->channel = "FHSS";
        commoninfo->freq_khz = 2400000;

        auto l1info = in_pack->fetch_or_add<kis_layer1_packinfo>(mphy->pack_comp_l1info);
        l1info->signal_type = kis_l1_signal_type_dbm;
        l1info->freq_khz = 2400000;
        l1info->channel = "FHSS";

    }

    return 1;
}


int kis_bluetooth_phy::packet_tracker_bluetooth(CHAINCALL_PARMS) {
    kis_bluetooth_phy *btphy = (kis_bluetooth_phy *) auxdata;

    auto btpi = in_pack->fetch<bluetooth_packinfo>(btphy->pack_comp_btdevice);

    if (btpi == nullptr)
        return 0;

    auto ci = in_pack->fetch<kis_common_info>(btphy->pack_comp_common);

    if (ci == nullptr)
        return 0;

    kis_lock_guard<kis_mutex> lk(btphy->devicetracker->get_devicelist_mutex(), 
            "packet_tracker_bluetooth");

    std::shared_ptr<kis_tracked_device_base> basedev =
        btphy->devicetracker->update_common_device(ci, ci->source, btphy, in_pack, 
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "Bluetooth");

    if (basedev == nullptr)
        return 0;

    auto btdev =
        basedev->get_sub_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

    if (btdev == nullptr) {
        std::stringstream ss;
        ss << "Detected new Bluetooth device " << btpi->address.mac_to_string();
        if (btpi->name.length() > 0) 
            ss << " (" << btpi->name << ")";
        _MSG(ss.str(), MSGFLAG_INFO);

        btdev = 
            Globalreg::globalreg->entrytracker->get_shared_instance_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

        basedev->insert(btdev);
    }

    basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

    if (btpi->type == 0) {
        basedev->set_tracker_type_string(btphy->btdev_bredr);
        btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::bredr));
    } else if (btpi->type == 1) {
        basedev->set_tracker_type_string(btphy->btdev_btle);
        btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::btle));
    } else if (btpi->type == 2) {
        basedev->set_tracker_type_string(btphy->btdev_btle);
        btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::btle));
    } else {
        basedev->set_tracker_type_string(btphy->btdev_bt);
        btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::bt));
    }

    // Always set the name, but don't forget a name we used to know
    if (btpi->name.length() > 0)
        basedev->set_devicename(btpi->name);
    else if (basedev->get_devicename().length() == 0) {
        basedev->set_devicename(basedev->get_macaddr().mac_to_string());
    }

    // Set the new tx power
    btdev->set_txpower(btpi->txpower);

    // Reset the service UUID vector
    auto uuid_vec = btdev->get_service_uuid_vec();

    uuid_vec->clear();

    for (auto u : btpi->service_uuid_vec) {
        auto tu = std::make_shared<tracker_element_uuid>(0, u);
        uuid_vec->push_back(tu);
    }

    return 0;
}

void kis_bluetooth_phy::load_phy_storage(shared_tracker_element in_storage, 
        shared_tracker_element in_device) {

    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    // Does the imported record have bt?
    auto btdevi = storage->find(bluetooth_device_entry_id);

    // Adopt it into a dot11
    if (btdevi != storage->end()) {
        auto btdev = 
            std::make_shared<bluetooth_tracked_device>(bluetooth_device_entry_id, 
                    std::static_pointer_cast<tracker_element_map>(btdevi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(btdev);
    }
}

