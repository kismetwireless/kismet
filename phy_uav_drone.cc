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

#include "phy_uav_drone.h"
#include "phy_80211.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"

Kis_UAV_Phy::Kis_UAV_Phy(GlobalRegistry *in_globalreg,
        Devicetracker *in_tracker, int in_phyid) :
    Kis_Phy_Handler(in_globalreg, in_tracker, in_phyid) {

    phyname = "UAV";

    packetchain =
        Globalreg::FetchGlobalAs<Packetchain>(globalreg, "PACKETCHAIN");
    entrytracker =
        Globalreg::FetchGlobalAs<EntryTracker>(globalreg, "ENTRY_TRACKER");

	pack_comp_common = 
		packetchain->RegisterPacketComponent("COMMON");
    pack_comp_80211 =
        packetchain->RegisterPacketComponent("PHY80211");
    pack_comp_device =
        packetchain->RegisterPacketComponent("DEVICE");

    uav_device_id =
        entrytracker->RegisterField("uav.device",
                std::shared_ptr<uav_tracked_device>(new uav_tracked_device(globalreg, 0)),
                "UAV device");

    // Tag into the packet chain at the very end so we've gotten all the other tracker
    // elements already
    packetchain->RegisterHandler(Kis_UAV_Phy::CommonClassifier, 
            this, CHAINPOS_TRACKER, 65535);

    // Register js module for UI
    shared_ptr<Kis_Httpd_Registry> httpregistry = 
        Globalreg::FetchGlobalAs<Kis_Httpd_Registry>(globalreg, "WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_uav", "/js/kismet.ui.uav.js");
}

Kis_UAV_Phy::~Kis_UAV_Phy() {

}


void Kis_UAV_Phy::LoadPhyStorage(SharedTrackerElement in_storage,
        SharedTrackerElement in_device) {
    if (in_storage == NULL || in_device == NULL)
        return;

    // Does the imported record have UAV?
    auto devi = in_storage->find(uav_device_id);

    if (devi != in_storage->end()) {
        shared_ptr<uav_tracked_device> uavdev(new uav_tracked_device(globalreg, uav_device_id, devi->second));
        in_device->add_map(uavdev);
    }
}

int Kis_UAV_Phy::CommonClassifier(CHAINCALL_PARMS) {
    Kis_UAV_Phy *uavphy = (Kis_UAV_Phy *) auxdata;

    devicelist_scope_locker listlocker(uavphy->devicetracker);

	kis_common_info *commoninfo =
		(kis_common_info *) in_pack->fetch(uavphy->pack_comp_common);

    dot11_packinfo *dot11info = 
        (dot11_packinfo *) in_pack->fetch(uavphy->pack_comp_80211);

	kis_tracked_device_info *devinfo =
		(kis_tracked_device_info *) in_pack->fetch(uavphy->pack_comp_device);

	if (devinfo == NULL) {
        return 1;
	}

    if (commoninfo == NULL || dot11info == NULL)
        return 1;

    // Try to pull the existing basedev, we don't want to re-parse
    for (auto di : devinfo->devrefs) {
        std::shared_ptr<kis_tracked_device_base> basedev = di.second;

        if (basedev == NULL)
            return 1;

        if (dot11info->droneid != NULL) {
            shared_ptr<uav_tracked_device> uavdev = 
                std::static_pointer_cast<uav_tracked_device>(basedev->get_map_value(uavphy->uav_device_id));

            if (uavdev == NULL) {
                uavdev.reset(new uav_tracked_device(globalreg, uavphy->uav_device_id));
                basedev->add_map(uavdev);
            }

            // TODO add alerts for serial # change etc
            if (dot11info->droneid->subcommand() == 0x10) {
                dot11_ie_221_dji_droneid_t::flight_reg_info_t *flightinfo = 
                    dot11info->droneid->record();

                if (flightinfo->state_info()->serial_valid()) {
                    uavdev->set_uav_serialnumber(flightinfo->serialnumber());
                }

                std::shared_ptr<uav_tracked_telemetry> telem = uavdev->new_telemetry();
                telem->from_droneid_flight_reg(flightinfo);
                telem->set_telem_timestamp(ts_to_double(in_pack->ts));

                uavdev->set_tracker_last_telem_loc(telem);

                TrackerElementVector tvec(uavdev->get_tracker_uav_telem_history());
                tvec.push_back(telem);

                if (tvec.size() > 128)
                    tvec.erase(tvec.begin());

                uavdev->set_uav_match_type("DroneID");

                // Set the home location
                if (flightinfo->home_lat() != 0 && flightinfo->home_lon() != 0) {
                    shared_ptr<kis_tracked_location_triplet> homeloc = uavdev->get_home_location();
                    homeloc->set(flightinfo->home_lat(), flightinfo->home_lon());
                }
            }
        }
    }

    return 1;
}


