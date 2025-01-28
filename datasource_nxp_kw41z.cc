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

#include "endian_magic.h"

#include "datasource_nxp_kw41z.h"

int kis_datasource_nxpkw41z::handle_rx_data_content(kis_packet *packet, 
        kis_datachunk *datachunk, const uint8_t *content, size_t content_sz) {

    typedef struct {
        uint8_t monitor_channel;
        int8_t signal;
        int8_t noise;
        uint8_t access_offenses;
        uint8_t reference_access_address[4];
        uint16_t flags_le;
        uint8_t payload[0];
    } __attribute__((packed)) btle_rf;

    // Subset of flags we set
    const uint16_t btle_rf_flag_dewhitened = (1 << 0);
    const uint16_t btle_rf_flag_signalvalid = (1 << 1);
    const uint16_t btle_rf_flag_reference_access_valid = (1 << 5);
    const uint16_t btle_rf_crc_checked = (1 << 10);
    const uint16_t btle_rf_crc_valid = (1 << 11);

    if (content_sz < 10) {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }

//we may have to redo the checksum...
/**
    if (!checksum(nxp_chunk->data, nxp_chunk->length)) {
        delete (packet);
        return;
    }
**/
    // check what type of packet we are
    if (content[0] == 0x02 && content[1] == '\x86' && content[2] == 0x03) {
        uint32_t rssi = content[5];
        uint16_t nxp_payload_len = content[10];
        uint8_t channel = content[4];

        // We can make a valid payload from this much
        auto conv_buf_len = sizeof(_802_15_4_tap) + nxp_payload_len;
        char conv_buf[conv_buf_len];

        _802_15_4_tap *conv_header = reinterpret_cast<_802_15_4_tap *>(conv_buf);
        memset(conv_header, 0, conv_buf_len);

        if (content_sz <= 11 || (content_sz - 11 < nxp_payload_len)) {
            packet->error = 1;
            // error, but preserve the packet for logging
            packet->set_data((const char *) content, content_sz);
            datachunk->set_data(packet->data);
            return 1;
        }

        // Copy the actual packet payload into the header
        memcpy(conv_header->payload, &content[11], nxp_payload_len);

        conv_header->version = kis_htole16(0);// currently only one version
        conv_header->reserved = kis_htole16(0);// must be set to 0

         // fcs setting
        conv_header->tlv[0].type = kis_htole16(0);
        conv_header->tlv[0].length = kis_htole16(1);
        conv_header->tlv[0].value = kis_htole32(0);

        // rssi
        conv_header->tlv[1].type = kis_htole16(10);
        conv_header->tlv[1].length = kis_htole16(1);
        conv_header->tlv[1].value = kis_htole32(rssi);

        // channel
        conv_header->tlv[2].type = kis_htole16(3);
        conv_header->tlv[2].length = kis_htole16(3);
        conv_header->tlv[2].value = kis_htole32(channel);

        // size
        conv_header->length = sizeof(_802_15_4_tap); 

        datachunk->dlt = KDLT_IEEE802_15_4_TAP;

        packet->set_data((const char *) conv_buf, conv_buf_len);
        datachunk->set_data(packet->data);

        auto radioheader = packetchain->new_packet_component<kis_layer1_packinfo>();
        radioheader->signal_type = kis_l1_signal_type_rssi;
        radioheader->signal_rssi = rssi * -1;
        //radioheader->freq_khz = (2400 + (channel)) * 1000;
        radioheader->channel = fmt::format("{}", (channel));
        packet->insert(pack_comp_radiodata, radioheader);

        return 1;
    } else if (content[0] == 0x02 && content[1] == 0x4E && content[2] == 0x7F) {
        // Convert the channel for the btlell header
        auto bt_channel = content[5];
        uint8_t channel = content[5];

        switch (channel) {
            case 37:
                bt_channel = 0;
                break;
            case 38:
                bt_channel = 12;
                break;
            case 39:
                bt_channel = 39;
                break;
            default:
                bt_channel = channel - 2;
        };

        if (content_sz <= 13) {
            packet->error = 1;
            // error, but preserve the packet for logging
            packet->set_data((const char *) content, content_sz);
            datachunk->set_data(packet->data);
            return 1;
        }

        unsigned int nxp_payload_len = content_sz - 13;  // minus header and checksum

        // We can make a valid payload from this much
        auto conv_buf_len = sizeof(btle_rf) + nxp_payload_len;
        char conv_buf[conv_buf_len];
        btle_rf *conv_header = reinterpret_cast<btle_rf *>(conv_buf);

        // Copy the actual packet payload into the header
        memcpy(conv_header->payload, &content[12], nxp_payload_len);

        // Set the converted channel
        conv_header->monitor_channel = bt_channel;

        // RSSI not sure yet
        conv_header->signal = content[6];

        uint16_t bits = btle_rf_crc_checked;
        // if (true)//not sure yet
        //    bits += btle_rf_crc_valid;

        // Right now we have no way to validate the packets from this firmware; either we
        // allow all or allow none, which is pointless
        bits += btle_rf_crc_valid;
        packet->crc_ok = true;

        if (nxp_payload_len >= 4) {
            memcpy(conv_header->reference_access_address, conv_header->payload, 4);
            bits += btle_rf_flag_reference_access_valid;
        }

        conv_header->flags_le =
            kis_htole16(bits + btle_rf_flag_signalvalid + btle_rf_flag_dewhitened);


        datachunk->dlt = KDLT_BTLE_RADIO;

        packet->set_data((const char *) conv_buf, conv_buf_len);
        datachunk->set_data(packet->data);


        // Generate a l1 radio header and a decap header since we have it
        // computed already
        auto radioheader = packetchain->new_packet_component<kis_layer1_packinfo>();
        radioheader->signal_type = kis_l1_signal_type_dbm;
        radioheader->signal_dbm = conv_header->signal;
        radioheader->freq_khz = (2400 + (channel)) * 1000;
        radioheader->channel = fmt::format("{}", (channel));
        packet->insert(pack_comp_radiodata, radioheader);


        auto decapchunk = packetchain->new_packet_component<kis_datachunk>();
        decapchunk->dlt = KDLT_BLUETOOTH_LE_LL;
        decapchunk->set_data(packet->data.substr(sizeof(btle_rf), nxp_payload_len));
        packet->insert(pack_comp_decap, decapchunk);

        return 1;
    } else {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }
}
