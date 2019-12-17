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

uint32_t btle_crc_lut[] = {
    0x000000, 0x01b4c0, 0x036980, 0x02dd40, 0x06d300, 0x0767c0, 0x05ba80, 0x040e40,
    0x0da600, 0x0c12c0, 0x0ecf80, 0x0f7b40, 0x0b7500, 0x0ac1c0, 0x081c80, 0x09a840,
    0x1b4c00, 0x1af8c0, 0x182580, 0x199140, 0x1d9f00, 0x1c2bc0, 0x1ef680, 0x1f4240,
    0x16ea00, 0x175ec0, 0x158380, 0x143740, 0x103900, 0x118dc0, 0x135080, 0x12e440,
    0x369800, 0x372cc0, 0x35f180, 0x344540, 0x304b00, 0x31ffc0, 0x332280, 0x329640,
    0x3b3e00, 0x3a8ac0, 0x385780, 0x39e340, 0x3ded00, 0x3c59c0, 0x3e8480, 0x3f3040,
    0x2dd400, 0x2c60c0, 0x2ebd80, 0x2f0940, 0x2b0700, 0x2ab3c0, 0x286e80, 0x29da40,
    0x207200, 0x21c6c0, 0x231b80, 0x22af40, 0x26a100, 0x2715c0, 0x25c880, 0x247c40,
    0x6d3000, 0x6c84c0, 0x6e5980, 0x6fed40, 0x6be300, 0x6a57c0, 0x688a80, 0x693e40,
    0x609600, 0x6122c0, 0x63ff80, 0x624b40, 0x664500, 0x67f1c0, 0x652c80, 0x649840,
    0x767c00, 0x77c8c0, 0x751580, 0x74a140, 0x70af00, 0x711bc0, 0x73c680, 0x727240,
    0x7bda00, 0x7a6ec0, 0x78b380, 0x790740, 0x7d0900, 0x7cbdc0, 0x7e6080, 0x7fd440,
    0x5ba800, 0x5a1cc0, 0x58c180, 0x597540, 0x5d7b00, 0x5ccfc0, 0x5e1280, 0x5fa640,
    0x560e00, 0x57bac0, 0x556780, 0x54d340, 0x50dd00, 0x5169c0, 0x53b480, 0x520040,
    0x40e400, 0x4150c0, 0x438d80, 0x423940, 0x463700, 0x4783c0, 0x455e80, 0x44ea40,
    0x4d4200, 0x4cf6c0, 0x4e2b80, 0x4f9f40, 0x4b9100, 0x4a25c0, 0x48f880, 0x494c40,
    0xda6000, 0xdbd4c0, 0xd90980, 0xd8bd40, 0xdcb300, 0xdd07c0, 0xdfda80, 0xde6e40,
    0xd7c600, 0xd672c0, 0xd4af80, 0xd51b40, 0xd11500, 0xd0a1c0, 0xd27c80, 0xd3c840,
    0xc12c00, 0xc098c0, 0xc24580, 0xc3f140, 0xc7ff00, 0xc64bc0, 0xc49680, 0xc52240,
    0xcc8a00, 0xcd3ec0, 0xcfe380, 0xce5740, 0xca5900, 0xcbedc0, 0xc93080, 0xc88440,
    0xecf800, 0xed4cc0, 0xef9180, 0xee2540, 0xea2b00, 0xeb9fc0, 0xe94280, 0xe8f640,
    0xe15e00, 0xe0eac0, 0xe23780, 0xe38340, 0xe78d00, 0xe639c0, 0xe4e480, 0xe55040,
    0xf7b400, 0xf600c0, 0xf4dd80, 0xf56940, 0xf16700, 0xf0d3c0, 0xf20e80, 0xf3ba40,
    0xfa1200, 0xfba6c0, 0xf97b80, 0xf8cf40, 0xfcc100, 0xfd75c0, 0xffa880, 0xfe1c40,
    0xb75000, 0xb6e4c0, 0xb43980, 0xb58d40, 0xb18300, 0xb037c0, 0xb2ea80, 0xb35e40,
    0xbaf600, 0xbb42c0, 0xb99f80, 0xb82b40, 0xbc2500, 0xbd91c0, 0xbf4c80, 0xbef840,
    0xac1c00, 0xada8c0, 0xaf7580, 0xaec140, 0xaacf00, 0xab7bc0, 0xa9a680, 0xa81240,
    0xa1ba00, 0xa00ec0, 0xa2d380, 0xa36740, 0xa76900, 0xa6ddc0, 0xa40080, 0xa5b440,
    0x81c800, 0x807cc0, 0x82a180, 0x831540, 0x871b00, 0x86afc0, 0x847280, 0x85c640,
    0x8c6e00, 0x8ddac0, 0x8f0780, 0x8eb340, 0x8abd00, 0x8b09c0, 0x89d480, 0x886040,
    0x9a8400, 0x9b30c0, 0x99ed80, 0x985940, 0x9c5700, 0x9de3c0, 0x9f3e80, 0x9e8a40,
    0x972200, 0x9696c0, 0x944b80, 0x95ff40, 0x91f100, 0x9045c0, 0x929880, 0x932c40
};

uint32_t kis_btle_phy::calc_btle_crc(uint32_t crc_init, uint8_t *data, size_t len) {
    uint32_t state = crc_init & 0xFFFFFF;
    uint32_t mask = 0x5A6000;

    for (size_t i = 0; i < len; ++i) {
        auto cur = data[i];

        for (unsigned int j = 0; j < 8; ++j) {
            cur >>= 1;
            state >>= 1;

            if ((state ^ cur) & 1) {
                state |= (1 << 23);
                state ^= mask;
            }
        }
    }

    return state;
}

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

