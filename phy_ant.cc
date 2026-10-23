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

#include <string>
#include <memory>

#include "globalregistry.h"
#include "packetchain.h"
#include "phy_ant.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "manuf.h"
#include "messagebus.h"

kis_ant_phy::kis_ant_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("ANT");

    packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

    ant_device_entry_id =
        entrytracker->register_field("ant.device",
                tracker_element_factory<ant_tracked_device>(),
                "ANT / ANT+ device");

    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_ant = packetchain->register_packet_component("ANT");

    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_ant", "js/kismet.ui.ant.js");

    ant_manuf = Globalreg::globalreg->manufdb->make_manuf("ANT");

    packetchain->register_handler(&dissector_ant, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&classifier_ant, this, CHAINPOS_CLASSIFIER, -100);
}

kis_ant_phy::~kis_ant_phy() {
    packetchain->remove_handler(&dissector_ant, CHAINPOS_LLCDISSECT);
    packetchain->remove_handler(&classifier_ant, CHAINPOS_CLASSIFIER);
}

// ANT+ device profiles by device type (without the pairing bit)
static std::string ant_type_name(unsigned int t) {
    switch (t) {
        case 120: return "Heart rate monitor";
        case 121: return "Bike speed and cadence sensor";
        case 122: return "Bike cadence sensor";
        case 123: return "Bike speed sensor";
        case 124: return "Stride sensor (foot pod)";
        case 11: return "Bike power meter";
        case 17: return "Fitness equipment";
        case 119: return "Weight scale";
        case 25: return "Temperature sensor";
        case 40: return "Bike radar";
        case 35: return "Bike light";
        default: return "";
    }
}

// ANT+ manufacturer IDs (the FIT manufacturer list): the common ones
static std::string ant_manuf_name(unsigned int m) {
    switch (m) {
        case 1: return "Garmin";
        case 6: return "SRM";
        case 7: return "Quarq";
        case 15: return "Dynastream";
        case 23: return "Suunto";
        case 32: return "Wahoo Fitness";
        case 40: return "Concept2";
        case 69: return "Stages Cycling";
        case 89: return "Tacx";
        case 123: return "Polar";
        default: return "";
    }
}

/*
 * A pcap packet of user link type 148 with the "ANT" header (phy_ant.h); one whose CRC failed is
 * counted as an error and not attributed; anything without the header is left alone. The device is
 * its network address, device number, device type and transmission type: the six octets an ANT
 * channel pairs on, as its MAC.
 */
int kis_ant_phy::dissector_ant(CHAINCALL_PARMS) {
    auto aphy = static_cast<kis_ant_phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(aphy->pack_comp_linkframe);

    if (packdata == nullptr || packdata->dlt != ant_dlt)
        return 0;

    if (in_pack->common_info.common_info_ok)
        return 0;

    const auto *d = reinterpret_cast<const uint8_t *>(packdata->data());
    const size_t len = packdata->length();

    if (len < ant_hdr_len || d[0] != 'A' || d[1] != 'N' || d[2] != 'T' || d[3] != 1)
        return 0;

    const unsigned int alen = d[8], plen = d[9];

    if (alen != 2 || (plen != 8 && plen != 16 && plen != 24) ||
            len != ant_hdr_len + ant_pkt_hdr_len + plen + 2 || d[4] > 124)
        return 0;

    if (!(d[5] & 0x02)) {
        in_pack->error = 1;
        return 0;
    }

    const uint8_t *p = d + ant_hdr_len;

    // The length octet names the payload and CRC (10 for the usual 8-octet message): one that does
    // not is another protocol's packet whose bits passed the 16-bit CRC by chance
    if (p[6] != plen + 2)
        return 0;

    auto pi = aphy->packetchain->new_packet_component<kis_ant_packinfo>();

    pi->network = (unsigned int) p[0] << 8 | p[1];
    pi->ant_plus = p[0] == 0xa6 && p[1] == 0xc5;
    pi->device_number = (unsigned int) p[2] | (unsigned int) p[3] << 8;
    pi->device_type = p[4] & 0x7f;
    pi->pairing = (p[4] & 0x80) != 0;
    pi->trans_type = p[5];
    pi->rf_channel = d[4];
    pi->payload.assign(reinterpret_cast<const char *>(p + ant_pkt_hdr_len), plen);

    if (!in_pack->signal_info.data_ok) {
        auto& si = in_pack->signal_info;

        si.signal_type = kis_l1_signal_type_dbm;
        si.signal_dbm = (int8_t) d[7];
        si.channel = fmt::format("{}", d[4]);
        si.freq_khz = (2400 + d[4]) * 1000.0;
        si.data_ok = true;
    }

    const uint8_t key[6] = { p[0], p[1], p[2], p[3], (uint8_t) (p[4] & 0x7f), p[5] };

    in_pack->common_info.common_info_ok = true;
    in_pack->common_info.phyid = aphy->fetch_phy_id();
    in_pack->common_info.basic_crypt_set = KIS_DEVICE_BASICCRYPT_NONE;
    in_pack->common_info.type = packet_basic_data;
    in_pack->common_info.source = mac_addr(key, 6);

    in_pack->insert(aphy->pack_comp_ant, pi);

    return 1;
}

int kis_ant_phy::classifier_ant(CHAINCALL_PARMS) {
    auto aphy = static_cast<kis_ant_phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(aphy->pack_comp_linkframe);

    if (packdata == nullptr || packdata->dlt != ant_dlt || !in_pack->common_info.common_info_ok)
        return 0;

    auto pi = in_pack->fetch<kis_ant_packinfo>(aphy->pack_comp_ant);

    if (pi == nullptr)
        return 0;

    const auto type_name = ant_type_name(pi->device_type);
    const std::string kind = pi->ant_plus && !type_name.empty() ? "ANT+ " + type_name :
        pi->ant_plus ? "ANT+ device" : "ANT device";

    auto device =
        aphy->devicetracker->update_common_device(in_pack->common_info.source,
                aphy, in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                kind);

    kis_lock_guard<kis_mutex> lk(aphy->devicetracker->get_devicelist_mutex(), "classifier_ant");

    auto ant = device->get_sub_as<ant_tracked_device>(aphy->ant_device_entry_id);

    if (ant == nullptr) {
        _MSG_INFO("Detected new {} {}, device number {}, network {:02X}:{:02X}", kind,
                in_pack->common_info.source.mac_to_string(), pi->device_number,
                pi->network >> 8, pi->network & 0xff);
        ant = Globalreg::globalreg->entrytracker->get_shared_instance_as<ant_tracked_device>(aphy->ant_device_entry_id);
        device->insert(ant);
        device->set_manuf(aphy->ant_manuf);
        device->set_crypt_string("None");
        ant->set_network(fmt::format("{:02X}:{:02X}", pi->network >> 8, pi->network & 0xff));
        ant->set_ant_plus(pi->ant_plus);
        ant->set_device_number((uint16_t) pi->device_number);
        ant->set_device_type((uint8_t) pi->device_type);
        // Device types only name an ANT+ device profile on the ANT+ network
        if (pi->ant_plus)
            ant->set_device_type_name(type_name);
        ant->set_trans_type((uint8_t) pi->trans_type);
        device->set_devicename(fmt::format("{} {}",
                    pi->ant_plus && !type_name.empty() ? type_name : "ANT device", pi->device_number));
    }

    ant->set_rf_channel((int16_t) pi->rf_channel);
    if (pi->pairing)
        ant->set_pairing_seen(true);

    const auto& p = pi->payload;
    std::string hex;
    for (auto c : p)
        hex += fmt::format("{:02X}", (uint8_t) c);
    ant->set_last_payload(hex);

    /*
     * ANT+ data pages (8-octet payloads): the heart-rate monitor's (a page number in bits 0-6 of the
     * first octet, bit 7 toggling every four messages; the heart rate in the last octet), and the
     * common pages every newer profile sends: 80 manufacturer's information, 81 product information,
     * 82 battery status. Speed-and-cadence sensors (121) send no pages.
     */
    if (pi->ant_plus && p.length() == 8 && pi->device_type != 121) {
        auto b = [&p](size_t i) -> unsigned int { return (uint8_t) p[i]; };
        const bool toggled = pi->device_type == 120 || pi->device_type == 122 || pi->device_type == 123;
        const unsigned int page = toggled ? b(0) & 0x7f : b(0);

        ant->set_last_page((int16_t) page);

        if (pi->device_type == 120 && b(7) > 0)
            ant->set_heart_rate((uint16_t) b(7));

        if (pi->device_type == 120 && page == 2) {
            // manufacturer's ID, the serial number's upper 16 bits
            ant->set_manufacturer_id((uint16_t) b(1));
            ant->set_manufacturer(ant_manuf_name(b(1)));
        } else if (pi->device_type == 120 && page == 3) {
            ant->set_hw_version((uint16_t) b(1));
            ant->set_sw_version(fmt::format("{}", b(2)));
            ant->set_model((uint16_t) b(3));
        } else if (page == 80) {
            const unsigned int m = b(4) | b(5) << 8;

            ant->set_hw_version((uint16_t) b(3));
            ant->set_manufacturer_id((uint16_t) m);
            ant->set_manufacturer(ant_manuf_name(m));
            ant->set_model((uint16_t) (b(6) | b(7) << 8));
        } else if (page == 81) {
            ant->set_sw_version(b(2) == 0xff ? fmt::format("{}", b(3)) : fmt::format("{}.{}", b(3), b(2)));
            ant->set_serial(b(4) | b(5) << 8 | b(6) << 16 | b(7) << 24);
        } else if (page == 82) {
            static const char *const status[8] = { "Reserved", "New", "Good", "OK", "Low", "Critical", "Reserved", "Invalid" };

            ant->set_battery_status(status[(b(7) >> 4) & 7]);
        }

        // the device's manufacturer, once its ID names one
        if ((page == 80 || (pi->device_type == 120 && page == 2)) && !ant->get_manufacturer().empty() &&
                (device->get_manuf() == nullptr || device->get_manuf()->get() != ant->get_manufacturer()))
            device->set_manuf(Globalreg::globalreg->manufdb->make_manuf(ant->get_manufacturer()));
    }

    return 1;
}

void kis_ant_phy::load_phy_storage(shared_tracker_element in_storage,
        shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto antdevi = storage->find(ant_device_entry_id);

    if (antdevi != storage->end()) {
        auto antdev =
            std::make_shared<ant_tracked_device>(ant_device_entry_id,
                    std::static_pointer_cast<tracker_element_map>(antdevi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(antdev);
    }
}
