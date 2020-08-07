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

kis_bluetooth_phy::kis_bluetooth_phy(global_registry *in_globalreg, int in_phyid) : 
    kis_phy_handler(in_globalreg, in_phyid) {

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
    packetchain->register_handler(&packet_bluetooth_scan_json_classifier, this, CHAINPOS_CLASSIFIER, -99);
    
    pack_comp_btdevice = packetchain->register_packet_component("BTDEVICE");
	pack_comp_common = packetchain->register_packet_component("COMMON");
    pack_comp_l1info = packetchain->register_packet_component("RADIODATA");
    pack_comp_meta = packetchain->register_packet_component("METABLOB");
    pack_comp_json = packetchain->register_packet_component("JSON");

    // Register js module for UI
    auto httpregistry = 
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_bluetooth", 
            "js/kismet.ui.bluetooth.js");
}

kis_bluetooth_phy::~kis_bluetooth_phy() {
    packetchain->remove_handler(&common_classifier_bluetooth, CHAINPOS_CLASSIFIER);
}

int kis_bluetooth_phy::common_classifier_bluetooth(CHAINCALL_PARMS) {
    auto btphy = static_cast<kis_bluetooth_phy *>(auxdata);

    bluetooth_packinfo *btpi = 
        (bluetooth_packinfo *) in_pack->fetch(btphy->pack_comp_btdevice);

    if (btpi == NULL) {
        return 0;
    }

    kis_common_info *ci = (kis_common_info *) in_pack->fetch(btphy->pack_comp_common);

    if (ci == NULL) {
        ci = new kis_common_info();
        in_pack->insert(btphy->pack_comp_common, ci);
    }

    ci->phyid = btphy->fetch_phy_id();
    ci->type = packet_basic_mgmt;
    ci->direction = packet_direction_from;
    ci->source = btpi->address;
    ci->transmitter = btpi->address;
    ci->channel = "FHSS";
    ci->freq_khz = 2400000;

    return 0;
}

int kis_bluetooth_phy::packet_bluetooth_scan_json_classifier(CHAINCALL_PARMS) {
    kis_bluetooth_phy *btphy = (kis_bluetooth_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto pack_json =
        in_pack->fetch<kis_json_packinfo>(btphy->pack_comp_json);

    if (pack_json == nullptr)
        return 0;

    auto pack_l1info =
        in_pack->fetch<kis_layer1_packinfo>(btphy->pack_comp_l1info);

    auto commoninfo =
        in_pack->fetch<kis_common_info>(btphy->pack_comp_common);

    if (commoninfo != nullptr || pack_l1info == nullptr)
        return 0;

    try {
        std::stringstream newdevstr;
        std::stringstream ss(pack_json->json_string);
        Json::Value json;
        ss >> json;

        auto btaddr_j = json["btaddr"];

        if (btaddr_j.isNull()) 
            throw std::runtime_error("no btaddr in scan report");

        auto btaddr_mac = mac_addr(btaddr_j.asString());
        if (btaddr_mac.state.error)
            throw std::runtime_error("invalid btaddr MAC");

        commoninfo = new kis_common_info();
        commoninfo->phyid = btphy->fetch_phy_id();
        commoninfo->type = packet_basic_mgmt;
        commoninfo->source = btaddr_mac;
        commoninfo->transmitter = btaddr_mac;
        commoninfo->channel = "FHSS";
        commoninfo->freq_khz = 2400000;

        in_pack->insert(btphy->pack_comp_common, commoninfo);

        auto btdev =
            btphy->devicetracker->update_common_device(commoninfo,
                    btaddr_mac, btphy, in_pack,
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                     UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                     UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                    "Bluetooth Device");

        local_locker btlocker(&(btdev->device_mutex));

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

        if (devname_j.isString())
            btdev->set_devicename(munge_to_printable(devname_j.asString()));

        if (devtype_j.isString())
            btdev->set_tracker_type_string(btphy->devicetracker->get_cached_devicetype(munge_to_printable(devtype_j.asString())));

        auto btdev_bluetooth =
            btdev->get_sub_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

        if (btdev_bluetooth == nullptr) {
            newdevstr << "Detected new Bluetooth device " << btaddr_mac; 

            if (btdev->get_devicename().length() > 0)
                newdevstr << " (" << btdev->get_devicename() << ")";

            if (devtype_j.isString())
                newdevstr << " " << btdev->get_type_string();

            _MSG_INFO(newdevstr.str());

            btdev_bluetooth = 
                std::make_shared<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

            btdev->insert(btdev_bluetooth);
        }

        if (powerlevel_j.isNumeric())
            btdev_bluetooth->set_txpower(powerlevel_j.asInt());

        if (pathloss_j.isNumeric())
            btdev_bluetooth->set_pathloss(pathloss_j.asInt());

        if (scan_bytes_j.isString())
            btdev_bluetooth->set_scan_data_from_hex(scan_bytes_j.asString());

        if (service_bytes_map_j.isObject()) {
            for (const auto& u : service_bytes_map_j.getMemberNames()) {
                auto v = service_bytes_map_j[u];

                if (!v.isString())
                    throw std::runtime_error("expected string in service_data map");

                auto bytehex = 
                    std::make_shared<tracker_element_byte_array>();
                bytehex->from_hex(v.asString());

                btdev_bluetooth->get_service_data_bytes()->insert(u, bytehex);
            }
        }

    } catch (const std::exception& e) {
        _MSG_ERROR("Invalid phybluetooth/BT/BTLE scan report: {}", e.what());
        in_pack->error = true;
        return 0;
    }

    return 1;
}

int kis_bluetooth_phy::packet_tracker_bluetooth(CHAINCALL_PARMS) {
    kis_bluetooth_phy *btphy = (kis_bluetooth_phy *) auxdata;

    bluetooth_packinfo *btpi = 
        (bluetooth_packinfo *) in_pack->fetch(btphy->pack_comp_btdevice);

    if (btpi == NULL)
        return 0;

    kis_common_info *ci = (kis_common_info *) in_pack->fetch(btphy->pack_comp_common);

    if (ci == NULL)
        return 0;

    std::shared_ptr<kis_tracked_device_base> basedev =
        btphy->devicetracker->update_common_device(ci, ci->source, btphy, in_pack, 
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "Bluetooth");

    if (basedev == nullptr)
        return 0;

    local_locker bssidlock(&(basedev->device_mutex));

    auto btdev =
        basedev->get_sub_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

    if (btdev == nullptr) {
        std::stringstream ss;
        ss << "Detected new Bluetooth device " << btpi->address.mac_to_string();
        if (btpi->name.length() > 0) 
            ss << " (" << btpi->name << ")";
        _MSG(ss.str(), MSGFLAG_INFO);

        btdev =
            std::make_shared<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

        basedev->insert(btdev);
    }

    basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

    if (btpi->type == 0)
        basedev->set_tracker_type_string(btphy->devicetracker->get_cached_devicetype("BR/EDR"));
    else if (btpi->type == 1)
        basedev->set_tracker_type_string(btphy->devicetracker->get_cached_devicetype("BTLE"));
    else if (btpi->type == 2)
        basedev->set_tracker_type_string(btphy->devicetracker->get_cached_devicetype("BTLE"));
    else
        basedev->set_tracker_type_string(btphy->devicetracker->get_cached_devicetype("BT"));

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

