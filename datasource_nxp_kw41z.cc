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

void kis_datasource_nxpkw41z::handle_rx_packet(kis_packet *packet) {
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
    // const uint16_t btle_rf_crc_valid = (1 << 11);

    auto nxp_chunk = packet->fetch<kis_datachunk>(pack_comp_linkframe);

    // If we can't validate the basics of the packet at the phy capture level,
    // throw it out. We don't get rid of invalid btle contents, but we do get
    // rid of invalid USB frames that we can't decipher - we can't even log them
    // sanely!

    if (nxp_chunk->length < 10) {
        // fmt::print(stderr, "debug - nxp kw41z too short ({} < 10)\n",
        // nxp_chunk->length);
        delete (packet);
        return;
    }

//we may have to redo the checksum...
/**
    if (!checksum(nxp_chunk->data, nxp_chunk->length)) {
        delete (packet);
        return;
    }
**/
    // check what type of packet we are
    if (nxp_chunk->data[0] == 0x02 && nxp_chunk->data[1] == 0x86 &&
        nxp_chunk->data[2] == 0x03) {

        uint32_t rssi = nxp_chunk->data[5];
        uint16_t nxp_payload_len = nxp_chunk->data[10];
        uint8_t channel = nxp_chunk->data[4];
        // We can make a valid payload from this much
        auto conv_buf_len = sizeof(_802_15_4_tap) + nxp_payload_len;
        _802_15_4_tap *conv_header =
            reinterpret_cast<_802_15_4_tap *>(new uint8_t[conv_buf_len]);
        memset(conv_header, 0, conv_buf_len);

        // Copy the actual packet payload into the header
        memcpy(conv_header->payload, &nxp_chunk->data[11], nxp_payload_len);

        conv_header->version = 0;   // currently only one version
        conv_header->reserved = 0;  // must be set to 0

        // fcs setting
        conv_header->tlv[0].type = 0;
        conv_header->tlv[0].length = 1;
        conv_header->tlv[0].value = 0;

        // rssi
        conv_header->tlv[1].type = 10;
        conv_header->tlv[1].length = 1;
        conv_header->tlv[1].value = rssi;

        // channel
        conv_header->tlv[2].type = 3;
        conv_header->tlv[2].length = 3;
        conv_header->tlv[2].value = channel;  // need to try to pull from some where

        // size
        conv_header->length =
            sizeof(conv_header) + sizeof(conv_header->tlv) - 4;
        nxp_chunk->set_data((uint8_t *) conv_header, conv_buf_len, false);
        nxp_chunk->dlt = KDLT_IEEE802_15_4_TAP;

        auto radioheader = new kis_layer1_packinfo();
        radioheader->signal_type = kis_l1_signal_type_rssi;
        radioheader->signal_rssi = rssi * -1;
        //radioheader->freq_khz = (2400 + (channel)) * 1000;
        radioheader->channel = fmt::format("{}", (channel));
        packet->insert(pack_comp_radiodata, radioheader);

        // Pass the packet on
        kis_datasource::handle_rx_packet(packet);

    } else if (nxp_chunk->data[0] == 0x02 && nxp_chunk->data[1] == 0x4E &&
               nxp_chunk->data[2] == 0x7F) {
        // Convert the channel for the btlell header
        auto bt_channel = nxp_chunk->data[5];
        uint8_t channel = nxp_chunk->data[5];

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

        unsigned int nxp_payload_len =
            nxp_chunk->length - 13;  // minus header and checksum
        // We can make a valid payload from this much
        auto conv_buf_len = sizeof(btle_rf) + nxp_payload_len;
        btle_rf *conv_header =
            reinterpret_cast<btle_rf *>(new uint8_t[conv_buf_len]);
        memset(conv_header, 0, conv_buf_len);

        // Copy the actual packet payload into the header
        memcpy(conv_header->payload, &nxp_chunk->data[12], nxp_payload_len);

        // Set the converted channel
        conv_header->monitor_channel = bt_channel;

        // RSSI not sure yet
        conv_header->signal = nxp_chunk->data[6];

        uint16_t bits = btle_rf_crc_checked;
        // if (true)//not sure yet
        //    bits += btle_rf_crc_valid;

        if (nxp_payload_len >= 4) {
            memcpy(conv_header->reference_access_address, conv_header->payload,
                   4);
            bits += btle_rf_flag_reference_access_valid;
        }

        conv_header->flags_le =
            kis_htole16(bits + btle_rf_flag_signalvalid + btle_rf_flag_dewhitened);

        // Replace the existing packet data with this and update the DLT
        nxp_chunk->set_data((uint8_t *) conv_header, conv_buf_len, false);
        nxp_chunk->dlt = KDLT_BTLE_RADIO;

        // Generate a l1 radio header and a decap header since we have it
        // computed already
        auto radioheader = new kis_layer1_packinfo();
        radioheader->signal_type = kis_l1_signal_type_dbm;
        radioheader->signal_dbm = conv_header->signal;
        radioheader->freq_khz = (2400 + (channel)) * 1000;
        radioheader->channel = fmt::format("{}", (channel));
        packet->insert(pack_comp_radiodata, radioheader);

        auto decapchunk = new kis_datachunk;
        decapchunk->set_data(conv_header->payload, nxp_payload_len, false);
        decapchunk->dlt = KDLT_BLUETOOTH_LE_LL;
        packet->insert(pack_comp_decap, decapchunk);

        kis_datasource::handle_rx_packet(packet);
    } else {
        delete (packet);
        return;
    }
}
