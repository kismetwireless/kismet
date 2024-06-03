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

#include "globalregistry.h"
#include "util.h"
#include "endian_magic.h"
#include "messagebus.h"
#include "packet.h"
#include "packetchain.h"

#include "kis_datasource.h"

#include "kis_dlt_btle_radio.h"

kis_dlt_btle_radio::kis_dlt_btle_radio() :
    kis_dlt_handler() {

    dlt_name = "BTLE_RADIO";
    dlt = KDLT_BTLE_RADIO;

    _MSG("Registering support for DLT_BTLE_RADIO packet header decoding", MSGFLAG_INFO);
}

int kis_dlt_btle_radio::handle_packet(const std::shared_ptr<kis_packet>& in_pack) {
    typedef struct {
        uint8_t monitor_channel;
        int8_t signal;
        int8_t noise;
        uint8_t access_offenses;
        uint8_t reference_access_address[4];
        uint16_t flags_le;
        uint8_t payload[0];
    } __attribute__((packed)) btle_rf;

    // const uint16_t btle_rf_flag_dewhitened = (1 << 0);
    const uint16_t btle_rf_flag_signalvalid = (1 << 1);
    const uint16_t btle_rf_flag_noisevalid = (1 << 2);
    // const uint16_t btle_rf_flag_reference_access_valid = (1 << 5);
    const uint16_t btle_rf_crc_checked = (1 << 10);
    const uint16_t btle_rf_crc_valid = (1 << 11);

    if (in_pack->has(pack_comp_decap)) {
        return 1;
    }

    // Get the link
    auto linkchunk = in_pack->fetch<kis_datachunk>(pack_comp_linkframe);
    if (linkchunk == nullptr) {
        return 1;
    }

    if (linkchunk->dlt != dlt) {
        return 1;
    }

    // Make sure the packet can hold the rf_ll and a little extra - 6 seems good,
    // that's the size of the advertised address info and a packet header
    if (linkchunk->length() < sizeof(btle_rf) + 6)
        return 1;

    const auto rf_ll = reinterpret_cast<const btle_rf *>(linkchunk->data());
    auto flags = kis_letoh16(rf_ll->flags_le);

    if (flags & btle_rf_crc_checked) {
        // Throw out invalid packets if the capture source knew the CRC was invalid
        if (!(flags & btle_rf_crc_valid)) {
            in_pack->error = 1;
            return 1;
        }

        // Flag that we know the CRC is good
        in_pack->crc_ok = 1;
    }

    // Generate a l1 radio header and a decap header since we have it computed already
    auto radioheader = std::make_shared<kis_layer1_packinfo>();
    radioheader->signal_type = kis_l1_signal_type_dbm;

    if (flags & btle_rf_flag_signalvalid)
        radioheader->signal_dbm = rf_ll->signal;
    if (flags & btle_rf_flag_noisevalid)
        radioheader->noise_dbm = rf_ll->noise;

    if (rf_ll->monitor_channel == 37) {
        radioheader->channel = "37";
        radioheader->freq_khz = (2402 * 1000);
    } else if (rf_ll->monitor_channel == 38) {
        radioheader->channel = "38";
        radioheader->freq_khz = (2426 * 1000);
    } else if (rf_ll->monitor_channel == 39) {
        radioheader->channel = "39";
        radioheader->freq_khz = (2480 * 1000);
    }  else if (rf_ll->monitor_channel <= 10) {
        radioheader->channel = fmt::format("{}", rf_ll->monitor_channel);
        radioheader->freq_khz = (2404 + (rf_ll->monitor_channel * 2)) * 1000;
    } else if (rf_ll->monitor_channel <= 36) {
        radioheader->channel = fmt::format("{}", rf_ll->monitor_channel);
        radioheader->freq_khz = (2428 + ((rf_ll->monitor_channel - 11) * 2)) * 1000;
    } else {
        radioheader->channel = "0";
        radioheader->freq_khz = 0;
    }

    in_pack->insert(pack_comp_radiodata, radioheader);

    // TODO handle dewhitening
    
    auto decapchunk = std::make_shared<kis_datachunk>();
    decapchunk->set_data(in_pack->data.substr(sizeof(btle_rf), in_pack->data.length() - sizeof(btle_rf)));
    decapchunk->dlt = KDLT_BLUETOOTH_LE_LL;
    in_pack->insert(pack_comp_decap, decapchunk);

    return 1;
}


