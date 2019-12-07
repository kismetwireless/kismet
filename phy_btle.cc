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
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "dlttracker.h"
#include "manuf.h"

#include "phy_btle.h"

kis_btle_phy::kis_btle_phy(global_registry *in_globalreg, int in_phyid) :
    kis_phy_handler(in_globalreg, in_phyid) {

    set_phy_name("BTLE");

    packetchain = 
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker = 
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    pack_comp_common = packetchain->register_packet_component("COMMON");
	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");

    dlt = DLT_BLUETOOTH_LE_LL;

    packetchain->register_handler(&dissector, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&common_classifier, this, CHAINPOS_CLASSIFIER, -100);

    btle_device_id = 
        entrytracker->register_field("btle.device",
                tracker_element_factory<btle_tracked_device>(),
                "BTLE device");
}

kis_btle_phy::~kis_btle_phy() {
    packetchain->remove_handler(&common_classifier, CHAINPOS_CLASSIFIER);
    packetchain->remove_handler(&dissector, CHAINPOS_LLCDISSECT);
}

int kis_btle_phy::dissector(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_btle_phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == NULL)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt)
        return 0;

    // Do we have enough data for an OUI?
    if (packdata->length < 6)
        return 0;

    // get the mac address
    unsigned char l_mac[6];
    memset(l_mac, 0x00, 6);
    l_mac[0] = packdata->data[11];
    l_mac[1] = packdata->data[10];
    l_mac[2] = packdata->data[9];
    l_mac[3] = packdata->data[8];
    l_mac[4] = packdata->data[7];
    l_mac[5] = packdata->data[6];

    // Did something already classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common != NULL)
        return 0;

    common = new kis_common_info;

    //printf("chan :%d\n",(packdata->data[packdata->length-1] & 0x7f));

    common->phyid = mphy->fetch_phy_id();
    common->channel = int_to_string(packdata->data[packdata->length-1] & 0x7f);
    common->basic_crypt_set = crypt_none;
    common->type = packet_basic_mgmt;
    common->source = mac_addr(l_mac, 6);//mac_addr(packdata->data, 6);
    common->transmitter = mac_addr(l_mac, 6);//mac_addr(packdata->data, 6);

    in_pack->insert(mphy->pack_comp_common, common);

    return 1;
}

int kis_btle_phy::common_classifier(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_btle_phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == nullptr)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt)
        return 0;
/**/
    // Did we classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common == NULL)
        return 0;

    // Update with all the options in case we can add signal and frequency
    // in the future
    auto device = 
        mphy->devicetracker->update_common_device(common,
                common->source, mphy, in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "BTLE Device");
    auto ticc2540 =
        device->get_sub_as<btle_tracked_device>(mphy->btle_device_id);

    if (ticc2540 == NULL) {
        _MSG_INFO("Detected new BTLE device {}",
                common->source.mac_to_string());
        ticc2540 = std::make_shared<btle_tracked_device>(mphy->btle_device_id);
        device->insert(ticc2540);
    }
/**/
    return 1;
}

void kis_btle_phy::load_phy_storage(shared_tracker_element in_storage,
        shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto nrfdevi = storage->find(btle_device_id);

    if (nrfdevi != storage->end()) {
        auto nrfdev =
            std::make_shared<btle_tracked_device>(btle_device_id,
                    std::static_pointer_cast<tracker_element_map>(nrfdevi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(nrfdev);
    }
}

