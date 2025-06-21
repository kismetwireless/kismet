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

#include "datasource_ti_cc_2531.h"

int kis_datasource_ticc2531::handle_rx_data_content(kis_packet *packet, kis_datachunk *datachunk,
        const uint8_t *content, size_t content_sz) {

    // If we can't validate the basics of the packet at the phy capture level, throw it out.

    if (content_sz < 8) {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }

    unsigned int cc_len = content[1];
    if (cc_len != content_sz - 3) {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }

    unsigned int cc_payload_len = content[7] - 0x02;
    if ((cc_payload_len + 8 != content_sz - 2) || (cc_payload_len > 104)) {
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }

    uint8_t fcs1 = content[content_sz - 2];
    uint8_t fcs2 = content[content_sz - 1];
    uint8_t crc_ok = fcs2 & (1 << 7);

    uint8_t channel = content[2];

    // check the CRC and check to see if the length, somehow matches the first byte of what should be the fcf
    if (crc_ok > 0 && (content[7] != content[8])) {
        int rssi = (fcs1 + (int) pow(2, 7)) % (int) pow(2, 8) - (int) pow(2, 7) - 73;

        // We can make a valid payload from this much
        auto conv_buf_len = sizeof(_802_15_4_tap) + cc_payload_len;
        char conv_buf[conv_buf_len];

        _802_15_4_tap *conv_header = reinterpret_cast<_802_15_4_tap *>(conv_buf);
        memset(conv_header, 0, conv_buf_len);

        // Copy the actual packet payload into the header
        memcpy(conv_header->payload, &content[8], cc_payload_len);

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

        //size
        conv_header->length = sizeof(_802_15_4_tap);

        datachunk->dlt = KDLT_IEEE802_15_4_TAP;

        packet->original_len = conv_buf_len;
        packet->set_data((const char *) conv_buf, conv_buf_len);
        datachunk->set_data(packet->data);

        auto radioheader = packetchain->new_packet_component<kis_layer1_packinfo>();
        radioheader->signal_type = kis_l1_signal_type_dbm;
        radioheader->signal_dbm = rssi;
        radioheader->freq_khz = (2405 + ((channel - 11) * 5)) * 1000;
        radioheader->channel = fmt::format("{}", (channel));
        packet->insert(pack_comp_radiodata, radioheader);

        return 1;
    } else {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }
}

