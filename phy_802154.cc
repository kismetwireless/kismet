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

#include "devicetracker_component.h"
#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "dlttracker.h"
#include "manuf.h"
#include "messagebus.h"

#include "phy_802154.h"

#define BEACON_802154   0x00
#define DATA_802154     0x01
#define ACK_802154      0x02
#define CMD_802154      0x03

uint8_t chan = 0;
uint8_t sigstr = 0;

// 802.15.4 header
struct _802_15_4_fcf {
    unsigned char type : 3;
    unsigned char security : 1;
    unsigned char pending : 1;
    unsigned char ack_req : 1;
    unsigned char pan_id_comp : 1;
    unsigned char reserved : 1;
    unsigned char sns : 1;
    unsigned char iep : 1;
    unsigned char dest_addr_mode : 2;
    unsigned char frame_ver : 2;
    unsigned char src_addr_mode : 2;
};

uint8_t dest[2] = {0x00, 0x00};
uint8_t dest_pan[2] = {0x00, 0x00};
uint8_t src[2] = {0x00, 0x00};
uint8_t src_pan[2] = {0x00, 0x00};

uint8_t ext_dest[8];
uint8_t ext_source[8];


kis_802154_phy::kis_802154_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("802.15.4");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    kis_802154_device_entry_id =
        entrytracker->register_field("802154.device",
                tracker_element_factory<kis_802154_tracked_device>(),
                "802.15.4 device");

    pack_comp_common = packetchain->register_packet_component("COMMON");
	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_l1info = packetchain->register_packet_component("RADIODATA");

    // Extract the dynamic DLT
    auto dltt =
        Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");
    dlt = KDLT_IEEE802_15_4_NOFCS;

    packetchain->register_handler(&dissector802154, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&commonclassifier802154, this, CHAINPOS_CLASSIFIER, -100);

    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_802_15_4", "js/kismet.ui.802_15_4.js");
}

kis_802154_phy::~kis_802154_phy() {
    packetchain->remove_handler(&dissector802154, CHAINPOS_LLCDISSECT);
    packetchain->remove_handler(&commonclassifier802154, CHAINPOS_CLASSIFIER);
}

int kis_802154_phy::dissector802154(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_802154_phy *>(auxdata);

    if (in_pack->duplicate || in_pack->filtered)
        return 1;

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);
    _802_15_4_tap *tap_header = nullptr;

    unsigned short fcf = 0;
    auto hdr_802_15_4_fcf = reinterpret_cast<_802_15_4_fcf *>(&fcf);

    if (packdata == nullptr) {
        return 0;
    }

    // Is it a packet we care about?
    if (packdata->dlt != KDLT_IEEE802_15_4_NOFCS && packdata->dlt != KDLT_IEEE802_15_4_TAP) {
        return 0;
    }

    // Do we have enough data for an OUI? and are within the Zigbee spec
    if (packdata->length() < 6 || packdata->length() > 128)
        return 0;

    // Did something already classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common != nullptr) {
        return 0;
    }

    // the tap header could contain multiple packets in a single frame, but
    // we probably only handle the first one right now
    unsigned int pkt_ctr = 0;
    if (packdata->dlt == KDLT_IEEE802_15_4_TAP) {
        uint64_t tap_header_size = sizeof(_802_15_4_tap);
        uint8_t tmp_header[32];
        memset(tmp_header, 0x00, 32);
        memcpy(tmp_header, &packdata->data()[pkt_ctr], tap_header_size);
        tap_header = (_802_15_4_tap *) &tmp_header;

        // Really we are going to want to iterate through them to pull them
        // correctly.
        chan = kis_letoh32(tap_header->tlv[2].value);
        sigstr = kis_letoh32(tap_header->tlv[1].value);
        pkt_ctr += tap_header_size;
    }

    // Are we more than just a header?
    if (pkt_ctr >= packdata->length())
        return 0;

    if (packdata->dlt == KDLT_IEEE802_15_4_NOFCS ||
        packdata->dlt == KDLT_IEEE802_15_4_TAP) {

        // Do we have enough for the frame control field?
        if (pkt_ctr + 2 >= packdata->length())
            return 0;

        fcf = (((short) packdata->data()[pkt_ctr + 1]) << 8) |
            (0x00ff & packdata->data()[pkt_ctr]);

        pkt_ctr += 2;

        // only parsing specific types of packets
        if (hdr_802_15_4_fcf->type > 0x03) {
            return 0;
        }

        // Check if the specific packet types are actually valid

        // Look for an invalid Beacon
        if (hdr_802_15_4_fcf->type == BEACON_802154) {
            // Beacon should not have security enabled
            if (hdr_802_15_4_fcf->security == 0x01)
                return 0;

            // Beacon should not have a dest
            if (hdr_802_15_4_fcf->dest_addr_mode != 0x00)
                return 0;

            // sns not valid for this header type
            if (hdr_802_15_4_fcf->sns)
                return 0;

            // Frame version not valid for this header type
            if (hdr_802_15_4_fcf->frame_ver == 0x03)
                return 0;
        }

        // Look for invalid Data packet
        if (hdr_802_15_4_fcf->type == DATA_802154) {
            // Data should not have a dest 0x01
            if (hdr_802_15_4_fcf->dest_addr_mode == 0x01)
                return 0;

            // Frame version not valid for this header type
            if (hdr_802_15_4_fcf->frame_ver == 0x03)
                return 0;
        }

        // Look for invalid Ack packet
        if (hdr_802_15_4_fcf->type == ACK_802154) {
            // Ack needs a source
            if (hdr_802_15_4_fcf->src_addr_mode <= 0x01)
                return 0;

            // Ack should not have a dest 0x01
            if (hdr_802_15_4_fcf->dest_addr_mode == 0x01)
                return 0;

            // Ack should not have security enabled
            if (hdr_802_15_4_fcf->security == 0x01)
                return 0;

            // sns not valid for this header type
            if (hdr_802_15_4_fcf->sns && hdr_802_15_4_fcf->frame_ver == 0x00)
                return 0;
        }

        // Look for invalid Cmd packet
        if (hdr_802_15_4_fcf->type == CMD_802154) {
            // Command needs a source
            if (hdr_802_15_4_fcf->src_addr_mode <= 0x01)
                return 0;

            // sns not valid for this header type
            if (hdr_802_15_4_fcf->sns)
                return 0;

            // Frame version not valid for this header type
            if (hdr_802_15_4_fcf->frame_ver == 0x03)
                return 0;
        }

        if (!hdr_802_15_4_fcf->sns) {
            pkt_ctr++;
        } else {
            // sns not valid for this header type
            return 0;
        }

        // dest address
        if (hdr_802_15_4_fcf->dest_addr_mode == 0x01) {
            // This address mode is not valid under this spec
            return 0;
        } else if (hdr_802_15_4_fcf->dest_addr_mode == 0x02) {
            // We would go past the end to check this
            if ((pkt_ctr + 4) >= packdata->length())
                return 0;

	    dest_pan[1] = packdata->data()[pkt_ctr];
            dest_pan[0] = packdata->data()[pkt_ctr + 1];
            pkt_ctr += 2;

            dest[1] = packdata->data()[pkt_ctr];
            dest[0] = packdata->data()[pkt_ctr + 1];
            pkt_ctr += 2;
        } else if (hdr_802_15_4_fcf->dest_addr_mode == 0x03) {
            // We would go past the end to check this
            if ((pkt_ctr + 10) >= packdata->length())
                return 0;

            // Length means we actually have an extended dest
            dest_pan[1] = packdata->data()[pkt_ctr];
            dest_pan[0] = packdata->data()[pkt_ctr + 1];
            pkt_ctr += 2;

            // Extended dest which is what were are looking for
            ext_dest[7] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_dest[6] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_dest[5] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_dest[4] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_dest[3] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_dest[2] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_dest[1] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_dest[0] = packdata->data()[pkt_ctr];
            pkt_ctr++;
        }

        // src address
        if (hdr_802_15_4_fcf->src_addr_mode == 0x01) {
            // This address mode is not valid under this spec
            return 0;
        } else if (hdr_802_15_4_fcf->src_addr_mode == 0x02) {
            if (!hdr_802_15_4_fcf->pan_id_comp) {
                // We would go past the end to check this
                if ((pkt_ctr + 2) >= packdata->length())
                    return 0;
                // src pan
                src_pan[1] = packdata->data()[pkt_ctr];
                src_pan[0] = packdata->data()[pkt_ctr + 1];
                pkt_ctr += 2;
            }

            // We would go past the end to check this
            if ((pkt_ctr + 2) >= packdata->length())
                return 0;

            src[1] = packdata->data()[pkt_ctr];
            src[0] = packdata->data()[pkt_ctr + 1];
            pkt_ctr += 2;
        } else if (hdr_802_15_4_fcf->src_addr_mode == 0x03) {
            // srcpan
            // extended source
            if (!hdr_802_15_4_fcf->pan_id_comp) {
                // We would go past the end to check this
                if ((pkt_ctr + 2) >= packdata->length())
                    return 0;

                src_pan[1] = packdata->data()[pkt_ctr];
                src_pan[0] = packdata->data()[pkt_ctr + 1];
                pkt_ctr += 2;
            }

            // We would go past the end to check this
            if ((pkt_ctr + 8) >= packdata->length())
                return 0;

            // extended source which is what were are looking for
            ext_source[7] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_source[6] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_source[5] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_source[4] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_source[3] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_source[2] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_source[1] = packdata->data()[pkt_ctr];
            pkt_ctr++;
            ext_source[0] = packdata->data()[pkt_ctr];
            pkt_ctr++;
        }
    }

    if (hdr_802_15_4_fcf->src_addr_mode >= 0x02 ||
        hdr_802_15_4_fcf->dest_addr_mode >= 0x02) {

        if (common == nullptr) {
            common = mphy->packetchain->new_packet_component<kis_common_info>();
        }

        common->phyid = mphy->fetch_phy_id();
        common->type = packet_basic_data;

        if (hdr_802_15_4_fcf->security) {
            common->basic_crypt_set = KIS_DEVICE_BASICCRYPT_ENCRYPTED | KIS_DEVICE_BASICCRYPT_L2;
        }

        if (hdr_802_15_4_fcf->src_addr_mode == 0x03) {
            common->source = mac_addr(ext_source, 8);
        } else if (hdr_802_15_4_fcf->src_addr_mode == 0x02 &&
            hdr_802_15_4_fcf->pan_id_comp) {
            common->source = mac_addr(src, 2);
        } else if (hdr_802_15_4_fcf->src_addr_mode == 0x02) {
            common->source = mac_addr(src, 2);
        }

        if (hdr_802_15_4_fcf->dest_addr_mode == 0x03) {
            common->dest = mac_addr(ext_dest, 8);
        } else if (hdr_802_15_4_fcf->dest_addr_mode == 0x02) {
            common->dest = mac_addr(dest, 2);
        }

        in_pack->insert(mphy->pack_comp_common, common);
    }

    return 1;
}

int kis_802154_phy::commonclassifier802154(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_802154_phy *>(auxdata);

    if (in_pack->filtered)
        return 1;

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == nullptr)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt &&
        (packdata->dlt != KDLT_IEEE802_15_4_NOFCS && packdata->dlt != KDLT_IEEE802_15_4_TAP))
        return 0;

    // Did we classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common == NULL)
        return 0;

    if (in_pack->duplicate) {
        auto source_dev = mphy->devicetracker->update_common_device(common,
                common->source, mphy, in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_LOCATION | UCD_UPDATE_SEENBY),
                "802.15.4");
    }

    // as source
    // Update with all the options in case we can add signal and frequency
    // in the future
    auto source_dev = mphy->devicetracker->update_common_device(common,
        common->source, mphy, in_pack,
        (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
            UCD_UPDATE_LOCATION | UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
        "802.15.4");

    auto source_kis_802154 = source_dev->get_sub_as<kis_802154_tracked_device>(
        mphy->kis_802154_device_entry_id);

    if (source_kis_802154 == NULL) {
        _MSG_INFO(
            "Detected new 802.15.4 device {}", common->source.mac_to_string());
        source_kis_802154 = Globalreg::globalreg->entrytracker->get_shared_instance_as<kis_802154_tracked_device>(mphy->kis_802154_device_entry_id);
        source_dev->insert(source_kis_802154);
    }

    // as destination
    // Update with all the options in case we can add signal and frequency
    // in the future
    auto dest_dev = mphy->devicetracker->update_common_device(common,
        common->dest, mphy, in_pack,
        (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
            UCD_UPDATE_LOCATION | UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
        "802.15.4");

    auto dest_kis_802154 = dest_dev->get_sub_as<kis_802154_tracked_device>(
        mphy->kis_802154_device_entry_id);

    if (dest_kis_802154 == NULL) {
        _MSG_INFO(
            "Detected new 802.15.4 device {}", common->dest.mac_to_string());
        dest_kis_802154 = Globalreg::globalreg->entrytracker->get_shared_instance_as<kis_802154_tracked_device>(mphy->kis_802154_device_entry_id);
        dest_dev->insert(dest_kis_802154);
    }

    return 1;
}

void kis_802154_phy::load_phy_storage(
    shared_tracker_element in_storage, shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto kis_802154devi = storage->find(kis_802154_device_entry_id);

    if (kis_802154devi != storage->end()) {
        auto kis_802154dev = std::make_shared<kis_802154_tracked_device>(
            kis_802154_device_entry_id,
            std::static_pointer_cast<tracker_element_map>(
                kis_802154devi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(
            kis_802154dev);
    }
}

