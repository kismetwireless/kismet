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

Kis_Bluetooth_Phy::Kis_Bluetooth_Phy(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
        int in_phyid) : Kis_Phy_Handler(in_globalreg, in_tracker, in_phyid) {
    globalreg = in_globalreg;

    alertracker = 
        Globalreg::FetchGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");
    packetchain = 
        Globalreg::FetchGlobalAs<Packetchain>(globalreg, "PACKETCHAIN");
    entrytracker = 
        Globalreg::FetchGlobalAs<EntryTracker>(globalreg, "ENTRY_TRACKER");
    devicetracker = 
        Globalreg::FetchGlobalAs<Devicetracker>(globalreg, "DEVICE_TRACKER");

    SetPhyName("Bluetooth");

    bluetooth_device_entry_id =
        entrytracker->RegisterField("bluetooth.device", 
                shared_ptr<bluetooth_tracked_device>(new bluetooth_tracked_device(globalreg, 0)),
                "Bluetooth device");

    packetchain->RegisterHandler(&CommonClassifierBluetooth, this, CHAINPOS_CLASSIFIER, -100);
    packetchain->RegisterHandler(&PacketTrackerBluetooth, this, CHAINPOS_TRACKER, -100);
    
    pack_comp_btdevice = packetchain->RegisterPacketComponent("BTDEVICE");
	pack_comp_common = packetchain->RegisterPacketComponent("COMMON");
    pack_comp_l1info = packetchain->RegisterPacketComponent("RADIODATA");

    // Register js module for UI
    shared_ptr<Kis_Httpd_Registry> httpregistry = 
        Globalreg::FetchGlobalAs<Kis_Httpd_Registry>(globalreg, "WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_bluetooth", 
            "/js/kismet.ui.bluetooth.js");
}

Kis_Bluetooth_Phy::~Kis_Bluetooth_Phy() {
    packetchain->RemoveHandler(&CommonClassifierBluetooth, CHAINPOS_CLASSIFIER);
}

int Kis_Bluetooth_Phy::CommonClassifierBluetooth(CHAINCALL_PARMS) {
    Kis_Bluetooth_Phy *btphy = (Kis_Bluetooth_Phy *) auxdata;

    devicelist_scope_locker listlock(btphy->devicetracker);

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

    ci->phyid = btphy->FetchPhyId();
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

    shared_ptr<kis_tracked_device_base> basedev =
        btphy->devicetracker->UpdateCommonDevice(ci, ci->source, btphy, in_pack, 
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION));

    if (basedev == NULL)
        return 0;

    shared_ptr<bluetooth_tracked_device> btdev =
        static_pointer_cast<bluetooth_tracked_device>(basedev->get_map_value(btphy->bluetooth_device_entry_id));

    if (btdev == NULL) {
        stringstream ss;
        ss << "Detected new Bluetooth device " << btpi->address.Mac2String();
        if (btpi->name.length() > 0) 
            ss << " (" << btpi->name << ")";
        _MSG(ss.str(), MSGFLAG_INFO);

        btdev.reset(new bluetooth_tracked_device(globalreg, btphy->bluetooth_device_entry_id));
        basedev->add_map(btdev);
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
        basedev->set_devicename(basedev->get_macaddr().Mac2String());
    }

    // Set the new tx power
    btdev->set_txpower(btpi->txpower);

    // Reset the service UUID vector
    TrackerElementVector sv(btdev->get_tracker_service_uuid_vec());
    sv.clear();

    for (auto u : btpi->service_uuid_vec) {
        SharedTrackerElement tu(new TrackerElement(TrackerUuid));
        tu->set(u);

        sv.push_back(tu);
    }

    return 0;
}

void Kis_Bluetooth_Phy::LoadPhyStorage(SharedTrackerElement in_storage, 
        SharedTrackerElement in_device) {

    if (in_storage == NULL || in_device == NULL)
        return;

    // Does the imported record have bt?
    auto btdevi = in_storage->find(bluetooth_device_entry_id);

    // Adopt it into a dot11
    if (btdevi != in_storage->end()) {
        shared_ptr<bluetooth_tracked_device> btdev(new bluetooth_tracked_device(globalreg, bluetooth_device_entry_id, btdevi->second));
        in_device->add_map(btdev);
    }
}

