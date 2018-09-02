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
#include "phy_nrf_mousejack.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"

Kis_Mousejack_Phy::Kis_Mousejack_Phy(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
        int in_phyid) :
    Kis_Phy_Handler(in_globalreg, in_tracker, in_phyid) {

    globalreg = in_globalreg;

    SetPhyName("NrfMousejack");

    packetchain = 
        Globalreg::FetchMandatoryGlobalAs<Packetchain>(globalreg, "PACKETCHAIN");
    entrytracker = 
        Globalreg::FetchMandatoryGlobalAs<EntryTracker>(globalreg, "ENTRYTRACKER");
    devicetracker = 
        Globalreg::FetchMandatoryGlobalAs<Devicetracker>(globalreg, "DEVICETRACKER");

    mousejack_device_entry_id =
        entrytracker->RegisterField("nrfmousejack.device",
                TrackerElementFactory<mousejack_tracked_device>(),
                "NRF Mousejack device");

    pack_comp_common = packetchain->RegisterPacketComponent("COMMON");

    packetchain->RegisterHandler(&CommonClassifierMousejack, this, CHAINPOS_CLASSIFIER, -100);

    auto httpregistry = 
        Globalreg::FetchMandatoryGlobalAs<Kis_Httpd_Registry>("WEBREGISTRY");
}

Kis_Mousejack_Phy::~Kis_Mousejack_Phy() {
    packetchain->RemoveHandler(&CommonClassifierMousejack, CHAINPOS_CLASSIFIER);
}

int Kis_Mousejack_Phy::CommonClassifierMousejack(CHAINCALL_PARMS) {
    auto mphy = static_cast<Kis_Mousejack_Phy *>(auxdata);

}

void Kis_Mousejack_Phy::LoadPhyStorage(SharedTrackerElement in_storage,
        SharedTrackerElement in_device) {
    if (in_storage == nullptr | in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<TrackerElementMap>(in_storage);

    auto nrfdevi = storage->find(mousejack_device_entry_id);

    if (nrfdevi != storage->end()) {
        auto nrfdev =
            std::make_shared<mousejack_tracked_device>(mousejack_device_entry_id,
                    std::static_pointer_cast<TrackerElementMap>(nrfdevi->second));
        std::static_pointer_cast<TrackerElementMap>(in_device)->insert(nrfdev);
    }
}

