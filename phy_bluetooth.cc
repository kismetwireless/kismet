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

Kis_Bluetooth_Phy::Kis_Bluetooth_Phy(global_registry *in_globalreg, int in_phyid) : 
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

    packetchain->register_handler(&CommonClassifierBluetooth, this, CHAINPOS_CLASSIFIER, -100);
    packetchain->register_handler(&PacketTrackerBluetooth, this, CHAINPOS_TRACKER, -100);
    
    pack_comp_btdevice = packetchain->register_packet_component("BTDEVICE");
	pack_comp_common = packetchain->register_packet_component("COMMON");
    pack_comp_l1info = packetchain->register_packet_component("RADIODATA");
    pack_comp_meta = packetchain->register_packet_component("METABLOB");

    // Register js module for UI
    auto httpregistry = 
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_bluetooth", 
            "js/kismet.ui.bluetooth.js");
}

Kis_Bluetooth_Phy::~Kis_Bluetooth_Phy() {
    packetchain->remove_handler(&CommonClassifierBluetooth, CHAINPOS_CLASSIFIER);
}

int Kis_Bluetooth_Phy::CommonClassifierBluetooth(CHAINCALL_PARMS) {
    auto btphy = static_cast<Kis_Bluetooth_Phy *>(auxdata);

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
    ci->source = btpi->address;
    ci->transmitter = btpi->address;
    ci->channel = "FHSS";
    ci->freq_khz = 2400000;

    return 0;
}

int Kis_Bluetooth_Phy::PacketTrackerBluetooth(CHAINCALL_PARMS) {
    Kis_Bluetooth_Phy *btphy = (Kis_Bluetooth_Phy *) auxdata;

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
        basedev->set_type_string("BR/EDR");
    else if (btpi->type == 1)
        basedev->set_type_string("BTLE");
    else if (btpi->type == 2)
        basedev->set_type_string("BTLE");
    else
        basedev->set_type_string("BT");

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

void Kis_Bluetooth_Phy::load_phy_storage(shared_tracker_element in_storage, 
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

