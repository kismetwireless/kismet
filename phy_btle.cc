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

#include "kaitai/kaitaistream.h"
#include "bluetooth_parsers/btle.h"

#ifndef KDLT_BLUETOOTH_LE_LL
#define KDLT_BLUETOOTH_LE_LL        251
#endif

#ifndef KDLT_BTLE_RADIO
#define KDLT_BTLE_RADIO             256
#endif

class btle_packinfo : public packet_component {
public:
    btle_packinfo() {
        self_destruct = 1;
    }

    std::shared_ptr<bluetooth_btle> btle_decode;
};

#define BTLE_ADVDATA_FLAGS                      0x01
#define BTLE_ADVDATA_SERVICE_UUID_INCOMPLETE    0x02
#define BTLE_ADVDATA_DEVICE_NAME                0x09

#define BTLE_ADVDATA_FLAG_LIMITED_DISCOVERABLE      (1 << 0)
#define BTLE_ADVDATA_FLAG_GENERAL_DISCOVERABLE      (1 << 1)
#define BTLE_ADVDATA_FLAG_BREDR_NONSUPP             (1 << 2)
#define BTLE_ADVDATA_FLAG_SIMUL_BREDR_CONTROLLER    (1 << 3)
#define BTLE_ADVDATA_FLAG_SIMUL_BREDR_HOST          (1 << 4)


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
    pack_comp_decap = packetchain->register_packet_component("DECAP");
    pack_comp_btle = packetchain->register_packet_component("BTLE");

    packetchain->register_handler(&dissector, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&common_classifier, this, CHAINPOS_CLASSIFIER, -100);

    btle_device_id = 
        entrytracker->register_field("btle.device",
                tracker_element_factory<btle_tracked_device>(),
                "BTLE device");

    ignore_random =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("btle_ignore_random", false);

    if (ignore_random)
        _MSG_INFO("Ignoring BTLE devices with random MAC addresses");

    // Register js module for UI
    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_btle", "js/kismet.ui.btle.js");
}

kis_btle_phy::~kis_btle_phy() {
    packetchain->remove_handler(&common_classifier, CHAINPOS_CLASSIFIER);
    packetchain->remove_handler(&dissector, CHAINPOS_LLCDISSECT);
}

int kis_btle_phy::dissector(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_btle_phy *>(auxdata);

    // Don't reclassify something that's already been seen
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);
    if (common != NULL)
        return 0;

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == NULL || (packdata != NULL && packdata->dlt != KDLT_BLUETOOTH_LE_LL))
        packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_decap);

    if (packdata == NULL || (packdata != NULL && packdata->dlt != KDLT_BLUETOOTH_LE_LL))
        return 0;

    membuf btle_membuf((char *) packdata->data, (char *) &packdata->data[packdata->length]);
    std::istream btle_istream(&btle_membuf);
    auto btle_stream = 
        std::make_shared<kaitai::kstream>(&btle_istream);

    common = new kis_common_info();
    common->phyid = mphy->fetch_phy_id();
    common->basic_crypt_set = crypt_none;
    common->type = packet_basic_mgmt;

    auto btle_info = new btle_packinfo();

    try {
        auto btle = std::make_shared<bluetooth_btle>();
        btle->parse(btle_stream);

        common->source = btle->advertising_address();
        common->transmitter = btle->advertising_address();
        // We don't set the channel or freq because it's already in l1info and gets picked 
        // up from there automatically

        btle_info->btle_decode = btle;

        in_pack->insert(mphy->pack_comp_common, common);
        in_pack->insert(mphy->pack_comp_btle, btle_info);
    } catch (const std::exception& e) {
        delete(common);
        delete(btle_info);
        return 0;
    }

    return 0;
}

int kis_btle_phy::common_classifier(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_btle_phy *>(auxdata);

    auto btle_info = in_pack->fetch<btle_packinfo>(mphy->pack_comp_btle);
    if (btle_info == nullptr)
        return 0;

    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);
    if (common == nullptr)
        return 0;

    if (btle_info->btle_decode == nullptr)
        return 0;

    // Drop randoms 
    if (btle_info->btle_decode->is_txaddr_random() && mphy->ignore_random)
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

    auto btle_dev =
        device->get_sub_as<btle_tracked_device>(mphy->btle_device_id);

    if (btle_dev == nullptr) {
        _MSG_INFO("Detected new BTLE device {}", common->source.mac_to_string());

        btle_dev = std::make_shared<btle_tracked_device>(mphy->btle_device_id);
        device->insert(btle_dev);
    }

    if (btle_info->btle_decode->is_txaddr_random())
        device->set_manuf(Globalreg::globalreg->manufdb->get_random_manuf());

    for (auto ad : *btle_info->btle_decode->advertised_data()) {
        if (ad->type() == BTLE_ADVDATA_FLAGS && ad->length() == 2) {
            uint8_t flags = ad->data().data()[0];

            btle_dev->set_le_limited_discoverable(flags & BTLE_ADVDATA_FLAG_LIMITED_DISCOVERABLE);
            btle_dev->set_le_general_discoverable(flags & BTLE_ADVDATA_FLAG_GENERAL_DISCOVERABLE);
            btle_dev->set_br_edr_unsupported(flags & BTLE_ADVDATA_FLAG_BREDR_NONSUPP);
            btle_dev->set_simultaneous_br_edr_host(flags & BTLE_ADVDATA_FLAG_SIMUL_BREDR_HOST);
            btle_dev->set_simultaneous_br_edr_controller(flags & BTLE_ADVDATA_FLAG_SIMUL_BREDR_CONTROLLER);

        } else if (ad->type() == BTLE_ADVDATA_DEVICE_NAME && ad->length() >= 2) {
            device->set_devicename(munge_to_printable(ad->data()));
        }
    }

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

