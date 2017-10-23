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

    uav_device_id =
        entrytracker->RegisterField("kismet.uav.device",
                std::shared_ptr<uav_tracked_device>(new uav_tracked_device(globalreg, 0)),
                "UAV device");

    // Tag into the packet chain at the very end so we've gotten all the other tracker
    // elements already
    packetchain->RegisterHandler(Kis_UAV_Phy::CommonClassifier, 
            this, CHAINPOS_TRACKER, 65535);
}

Kis_UAV_Phy::~Kis_UAV_Phy() {

}

int Kis_UAV_Phy::CommonClassifier(CHAINCALL_PARMS) {
    return 1;
}


