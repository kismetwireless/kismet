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
#include "dlttracker.h"
#include "manuf.h"
#include "messagebus.h"

Kis_Mousejack_Phy::Kis_Mousejack_Phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("NrfMousejack");

    packetchain = 
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker = 
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    mousejack_device_entry_id =
        entrytracker->register_field("nrfmousejack.device",
                tracker_element_factory<mousejack_tracked_device>(),
                "NRF Mousejack device");

    pack_comp_common = packetchain->register_packet_component("COMMON");
	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");

    // Extract the dynamic DLT
    auto dltt = 
        Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");
    dlt = dltt->register_linktype("NRFMOUSEJACK");

    /*
    auto httpregistry = 
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>("WEBREGISTRY");
        */

    // Make the manuf string
    mj_manuf_amazon = Globalreg::globalreg->manufdb->make_manuf("Amazon");
    mj_manuf_logitech = Globalreg::globalreg->manufdb->make_manuf("Logitech");
    mj_manuf_microsoft = Globalreg::globalreg->manufdb->make_manuf("Microsoft");
    mj_manuf_nrf = Globalreg::globalreg->manufdb->make_manuf("nRF/Mousejack HID");

    packetchain->register_handler(&DissectorMousejack, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&CommonClassifierMousejack, this, CHAINPOS_CLASSIFIER, -100);
}

Kis_Mousejack_Phy::~Kis_Mousejack_Phy() {
    packetchain->remove_handler(&CommonClassifierMousejack, CHAINPOS_CLASSIFIER);
}

int Kis_Mousejack_Phy::DissectorMousejack(CHAINCALL_PARMS) {
    auto mphy = static_cast<Kis_Mousejack_Phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == NULL)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt)
        return 0;

    // Do we have enough data for an OUI?
    if (packdata->length() < 6)
        return 0;

    // Did something already classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common != NULL)
        return 0;

    common = std::make_shared<kis_common_info>();

    common->phyid = mphy->fetch_phy_id();
    common->basic_crypt_set = crypt_none;
    common->type = packet_basic_data;
    common->source = mac_addr(packdata->data(), 6);

    in_pack->insert(mphy->pack_comp_common, common);

    return 1;
}

int Kis_Mousejack_Phy::CommonClassifierMousejack(CHAINCALL_PARMS) {
    auto mphy = static_cast<Kis_Mousejack_Phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == nullptr)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt)
        return 0;

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
                "KB/Mouse");

    kis_lock_guard<kis_mutex> lk(mphy->devicetracker->get_devicelist_mutex(), "common_classifier_mousejack");

    // Figure out what we think it could be; this isn't very precise.  Fingerprinting
    // based on methods in mousejack python.
    if (packdata->length() == 6) {
        device->set_manuf(mphy->mj_manuf_amazon);
    } else if (packdata->length() == 10 && packdata->data()[0] == 0x00 && packdata->data()[1] == '\xc2') {
        // Logitech mouse movement
        device->set_manuf(mphy->mj_manuf_logitech);
    } else if (packdata->length() == 22 && packdata->data()[0] == 0x00 && packdata->data()[1] == '\xd3') {
        // Logitech keyboard 
        device->set_manuf(mphy->mj_manuf_logitech);
    } else if (packdata->length() == 5 && packdata->data()[0] == 0x00 && packdata->data()[1] == 0x40) {
        // Logitech keepalive
        device->set_manuf(mphy->mj_manuf_logitech);
    } else if (packdata->length() == 10 && packdata->data()[0] == 0x00 && packdata->data()[1] == 0x4F) {
        // Logitech sleep timer
        device->set_manuf(mphy->mj_manuf_logitech);
    } else if (packdata->length() == 19 && 
            (packdata->data()[0] == 0x08 || packdata->data()[0] == 0x0c) &&
            packdata->data()[6] == 0x40) {
        device->set_manuf(mphy->mj_manuf_microsoft);
    } else if (packdata->length() == 19 && packdata->data()[0] == 0x0a) {
        device->set_manuf(mphy->mj_manuf_microsoft);
    } else {
        device->set_manuf(mphy->mj_manuf_nrf);
    }

    auto nrf =
        device->get_sub_as<mousejack_tracked_device>(mphy->mousejack_device_entry_id);

    if (nrf == NULL) {
        _MSG_INFO("Detected new nRF cordless input device (mouse, keyboard, etc) {}",
                common->source.mac_to_string());
        nrf = Globalreg::globalreg->entrytracker->get_shared_instance_as<mousejack_tracked_device>(mphy->mousejack_device_entry_id);
        device->insert(nrf);
    }

    return 1;
}

void Kis_Mousejack_Phy::load_phy_storage(shared_tracker_element in_storage,
        shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto nrfdevi = storage->find(mousejack_device_entry_id);

    if (nrfdevi != storage->end()) {
        auto nrfdev =
            std::make_shared<mousejack_tracked_device>(mousejack_device_entry_id,
                    std::static_pointer_cast<tracker_element_map>(nrfdevi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(nrfdev);
    }
}

