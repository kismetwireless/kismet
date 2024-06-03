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
#include "messagebus.h"
#include "alertracker.h"

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
    btle_packinfo() { }

    void reset() {
        btle_decode.reset();
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

/*
 * Implements Bluetooth Vol 6, Part B, Section 3.1.1 (ref Figure 3.2)
 *
 * At entry: tvb is entire BTLE packet without preamble
 *           payload_len is the Length field from the BTLE PDU header
 *           crc_init as defined in the specifications
 *
 * This implementation operates on nibbles and is therefore
 * endian-neutral.
 *
 * Taken from the Wireshark implementation
 */
uint32_t kis_btle_phy::calc_btle_crc(uint32_t crc_init, const char *payload, size_t len) {
    static const uint16_t btle_crc_next_state_flips[256] = {
        0x0000, 0x32d8, 0x196c, 0x2bb4, 0x0cb6, 0x3e6e, 0x15da, 0x2702,
        0x065b, 0x3483, 0x1f37, 0x2def, 0x0aed, 0x3835, 0x1381, 0x2159,
        0x065b, 0x3483, 0x1f37, 0x2def, 0x0aed, 0x3835, 0x1381, 0x2159,
        0x0000, 0x32d8, 0x196c, 0x2bb4, 0x0cb6, 0x3e6e, 0x15da, 0x2702,
        0x0cb6, 0x3e6e, 0x15da, 0x2702, 0x0000, 0x32d8, 0x196c, 0x2bb4,
        0x0aed, 0x3835, 0x1381, 0x2159, 0x065b, 0x3483, 0x1f37, 0x2def,
        0x0aed, 0x3835, 0x1381, 0x2159, 0x065b, 0x3483, 0x1f37, 0x2def,
        0x0cb6, 0x3e6e, 0x15da, 0x2702, 0x0000, 0x32d8, 0x196c, 0x2bb4,
        0x196c, 0x2bb4, 0x0000, 0x32d8, 0x15da, 0x2702, 0x0cb6, 0x3e6e,
        0x1f37, 0x2def, 0x065b, 0x3483, 0x1381, 0x2159, 0x0aed, 0x3835,
        0x1f37, 0x2def, 0x065b, 0x3483, 0x1381, 0x2159, 0x0aed, 0x3835,
        0x196c, 0x2bb4, 0x0000, 0x32d8, 0x15da, 0x2702, 0x0cb6, 0x3e6e,
        0x15da, 0x2702, 0x0cb6, 0x3e6e, 0x196c, 0x2bb4, 0x0000, 0x32d8,
        0x1381, 0x2159, 0x0aed, 0x3835, 0x1f37, 0x2def, 0x065b, 0x3483,
        0x1381, 0x2159, 0x0aed, 0x3835, 0x1f37, 0x2def, 0x065b, 0x3483,
        0x15da, 0x2702, 0x0cb6, 0x3e6e, 0x196c, 0x2bb4, 0x0000, 0x32d8,
        0x32d8, 0x0000, 0x2bb4, 0x196c, 0x3e6e, 0x0cb6, 0x2702, 0x15da,
        0x3483, 0x065b, 0x2def, 0x1f37, 0x3835, 0x0aed, 0x2159, 0x1381,
        0x3483, 0x065b, 0x2def, 0x1f37, 0x3835, 0x0aed, 0x2159, 0x1381,
        0x32d8, 0x0000, 0x2bb4, 0x196c, 0x3e6e, 0x0cb6, 0x2702, 0x15da,
        0x3e6e, 0x0cb6, 0x2702, 0x15da, 0x32d8, 0x0000, 0x2bb4, 0x196c,
        0x3835, 0x0aed, 0x2159, 0x1381, 0x3483, 0x065b, 0x2def, 0x1f37,
        0x3835, 0x0aed, 0x2159, 0x1381, 0x3483, 0x065b, 0x2def, 0x1f37,
        0x3e6e, 0x0cb6, 0x2702, 0x15da, 0x32d8, 0x0000, 0x2bb4, 0x196c,
        0x2bb4, 0x196c, 0x32d8, 0x0000, 0x2702, 0x15da, 0x3e6e, 0x0cb6,
        0x2def, 0x1f37, 0x3483, 0x065b, 0x2159, 0x1381, 0x3835, 0x0aed,
        0x2def, 0x1f37, 0x3483, 0x065b, 0x2159, 0x1381, 0x3835, 0x0aed,
        0x2bb4, 0x196c, 0x32d8, 0x0000, 0x2702, 0x15da, 0x3e6e, 0x0cb6,
        0x2702, 0x15da, 0x3e6e, 0x0cb6, 0x2bb4, 0x196c, 0x32d8, 0x0000,
        0x2159, 0x1381, 0x3835, 0x0aed, 0x2def, 0x1f37, 0x3483, 0x065b,
        0x2159, 0x1381, 0x3835, 0x0aed, 0x2def, 0x1f37, 0x3483, 0x065b,
        0x2702, 0x15da, 0x3e6e, 0x0cb6, 0x2bb4, 0x196c, 0x32d8, 0x0000
    };

    uint8_t offset = 4;
    uint32_t state = crc_init;

    for (size_t pos = offset; pos < len; pos++) {
        uint8_t byte = payload[pos];
        uint8_t nibble = (byte & 0xF);
        uint8_t byte_index = ((state >> 16) & 0xF0) | nibble;

        state = ((state << 4) ^ btle_crc_next_state_flips[byte_index]) & 0xFFFFFF;
        nibble = ((byte >> 4) & 0xF);
        byte_index = ((state >> 16) & 0xF0) | nibble;
        state = ((state << 4) ^ btle_crc_next_state_flips[byte_index]) & 0xFFFFFF;
    }

    return state;
}

/*
 * Reverses the bits in each byte of a 32-bit word.
 *
 * Needed because CRCs are transmitted in bit-reversed order compared
 * to the rest of the BTLE packet.  See BT spec, Vol 6, Part B,
 * Section 1.2.
 *
 * Taken from the Wireshark implementation
 */
uint32_t kis_btle_phy::reverse_bits(const uint32_t val) {
    const uint8_t nibble_rev[16] = {
        0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
        0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf
    };

    uint32_t retval = 0;
    unsigned byte_index;
    for (byte_index=0; byte_index<4; byte_index++) {
        uint32_t shiftA = byte_index*8;
        uint32_t shiftB = shiftA+4;

        retval |= (nibble_rev[((val >> shiftA) & 0xf)] << shiftB);
        retval |= (nibble_rev[((val >> shiftB) & 0xf)] << shiftA);
    }

    return retval;
}


kis_btle_phy::kis_btle_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("BTLE");

    packetchain = 
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker = 
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();
    alertracker =
        Globalreg::fetch_mandatory_global_as<alert_tracker>();

    pack_comp_common = packetchain->register_packet_component("COMMON");
	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_decap = packetchain->register_packet_component("DECAP");
    pack_comp_btle = packetchain->register_packet_component("BTLE");

    alert_bleedingtooth_ref =
        alertracker->activate_configured_alert("BLEEDINGTOOTH",
                "EXPLOIT", kis_alert_severity::high,
                "The BleedingTooth attack (CVE-2020-24490) exploits the lack of bounds "
                "checking in the BlueZ stack and may lead to execution in the kernel.  "
                "BleedingTooth attacks use over-sized advertisement packets.",
                phyid);

    alert_flipper_ref =
        alertracker->activate_configured_alert("FLIPPERZERO",
                "PROBE", kis_alert_severity::high,
                "Flipper Zero devices can be used to generate spoofed "
                "BTLE events which can act as denial of service attacks "
                "or cause other problems with some Bluetooth devices.", phyid);

    packetchain->register_handler(&dissector, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&common_classifier, this, CHAINPOS_CLASSIFIER, -100);

    btle_device_id = 
        entrytracker->register_field("btle.device",
                tracker_element_factory<btle_tracked_device>(),
                "BTLE device");

    btle_uuid_id = 
        entrytracker->register_field("btle.common.uuid_vendor",
                tracker_element_factory<tracker_element_string>(),
                "UUID vendor");

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

bool kis_btle_phy::device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) {
    return (dev->get_sub_as<btle_tracked_device>(btle_device_id) != nullptr);
}

int kis_btle_phy::dissector(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_btle_phy *>(auxdata);

    if (in_pack->duplicate || in_pack->filtered) {
        return 1;
    }

    // Don't reclassify something that's already been seen
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);
    if (common != NULL)
        return 0;

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_decap, mphy->pack_comp_linkframe);

    if (packdata == NULL || (packdata != NULL && packdata->dlt != KDLT_BLUETOOTH_LE_LL))
        return 0;

    // If this packet hasn't been checksummed already at the capture layer, 
    // do a checksum now.  We assume the last 3 bytes are the checksum.
    // ticc and nrf don't provide an in-packet checksum, and we rely on the
    // crc_ok from the firmware-specific radio headers that get turned into the
    // bt_radio dlt.
    if (!in_pack->crc_ok) {
        // We need at least the AA, header, and CRC bytes
        if (packdata->length() < (4 + 2 + 3)) {
            in_pack->error = 1;
            return 0;
        }

        uint32_t line_crc;
        line_crc = 
            packdata->data()[packdata->length() - 3] << 16 |
            packdata->data()[packdata->length() - 2] << 8 |
            packdata->data()[packdata->length() - 1];

        // Get the CRC as if it was a broadcast; we'll redo this later if we get
        // data packets
        uint32_t packet_crc = 
            calc_btle_crc(0x555555, packdata->data(), packdata->length() - 3);

        if (reverse_bits(packet_crc) != line_crc) {
            in_pack->error = 1;
            return 0;
        }
    }

    membuf btle_membuf((char *) packdata->data(), (char *) &packdata->data()[packdata->length()]);
    std::istream btle_istream(&btle_membuf);
    auto btle_stream = std::make_shared<kaitai::kstream>(&btle_istream);

    common = mphy->packetchain->new_packet_component<kis_common_info>();
    common->phyid = mphy->fetch_phy_id();
    common->basic_crypt_set = crypt_none;
    common->type = packet_basic_mgmt;

    auto btle_info = mphy->packetchain->new_packet_component<btle_packinfo>();

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
    } catch (...) {
        return 0;
    }

    return 0;
}

int kis_btle_phy::common_classifier(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_btle_phy *>(auxdata);

    if (in_pack->filtered)
        return 1;

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

    if (in_pack->duplicate) {
        auto device = 
            mphy->devicetracker->update_common_device(common,
                    common->source, mphy, in_pack,
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                     UCD_UPDATE_LOCATION | UCD_UPDATE_SEENBY),
                    "BTLE Device");
        return 1;
    }


    // Update with all the options in case we can add signal and frequency
    // in the future
    auto device = 
        mphy->devicetracker->update_common_device(common,
                common->source, mphy, in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "BTLE Device");

    kis_lock_guard<kis_mutex> lk(mphy->devicetracker->get_devicelist_mutex(), "btle_common_classifier");

    auto new_dev = false;

    auto btle_dev =
        device->get_sub_as<btle_tracked_device>(mphy->btle_device_id);

    if (btle_dev == nullptr) {
        btle_dev = Globalreg::globalreg->entrytracker->get_shared_instance_as<btle_tracked_device>(mphy->btle_device_id);
        device->insert(btle_dev);

        new_dev = true;
    }

    if (btle_info->btle_decode->is_txaddr_random())
        device->set_manuf(Globalreg::globalreg->manufdb->get_random_manuf());

    for (auto ad : *btle_info->btle_decode->advertised_data()) {
        if (btle_info->btle_decode->pdu_type() == btle_info->btle_decode->pdu_adv_ind() ||
                btle_info->btle_decode->pdu_type() == btle_info->btle_decode->pdu_adv_scan_ind()) {
            if (ad->length() > 31) {
                auto al = fmt::format("Saw a BTLE advertisement packet with an advertised content "
                        "over 31 bytes; this may indicate a BleedingTooth style attack on the "
                        "Linux BTLE drivers.");
                mphy->alertracker->raise_alert(mphy->alert_bleedingtooth_ref, in_pack,
                        mac_addr{}, device->get_macaddr(), mac_addr{}, mac_addr{},
                        "FHSS", al);
            }
        }

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

    if (new_dev) {
        if (device->get_devicename().length() > 0) 
            _MSG_INFO("Detected new BTLE device {} {}", common->source, device->get_devicename());
        else
            _MSG_INFO("Detected new BTLE device {}", common->source);

        if (common->source.OUI() == mac_addr::OUI((uint8_t *) "\x80\xe1\x26") ||
                common->source.OUI() == mac_addr::OUI((uint8_t *) "\x80\xe1\x27")) {
            auto al = fmt::format("A BTLE advertisement packet with a source address "
                    "matching a Flipper Zero device was seen; The Flipper device is "
                    "capable of generating BTLE packets which may cause a denial of "
                    "service or other problems with some BTLE devices.");
            mphy->alertracker->raise_alert(mphy->alert_flipper_ref, in_pack,
                    mac_addr{}, device->get_macaddr(), mac_addr{}, mac_addr{},
                    "FHSS", al);
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

