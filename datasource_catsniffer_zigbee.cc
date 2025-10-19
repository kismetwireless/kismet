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

#include "datasource_catsniffer_zigbee.h"

int kis_datasource_catsniffer_zigbee::handle_rx_data_content(kis_packet *packet,
        kis_datachunk *datachunk, const uint8_t *content, size_t content_sz) {

    // If we can't validate the basics of the packet at the phy capture level, throw it out.
    if (content_sz < 8) {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }

    size_t cc_len = content[4];
    // printf("Extracted cc_len: %u (raw byte: %02X)\n", cc_len, rxdata[4]);

    // Add 8 bytes to the expected frame length; this includes 4 total bytes for SOF/EOF (2 each), 1 byte for message type, 1 byte for channel value, 1 byte for the frame length byte & 1 byte for FCS OK
    if (cc_len + 8 != content_sz) {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }

    size_t cc_payload_len = content[12];
    //Payload or packet length indicator is at the 13th byte
    //Add 12 leading bytes, 1 byte for payload length, 1 byte for RSSI, 1 byte for FCS OK, 2 bytes for EOF.
    if ((cc_payload_len + 17 != content_sz) || (cc_payload_len > 104)) {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }

    //Check the FCS OK byte
    uint8_t crc_ok = content[content_sz - 3];

    uint8_t channel = content[0];

    // check the CRC and make sure that bytes 13 and 14 (FCF) don't match (maybe they could match??)
	if (crc_ok > 0 && (content[13] != content[14])) {
	    int8_t rssi = (int8_t) content[content_sz - 4];

	    auto conv_buf_len = sizeof(_802_15_4_tap) + cc_payload_len;

	    char conv_buf[conv_buf_len];
	    _802_15_4_tap *conv_header = reinterpret_cast<_802_15_4_tap *>(conv_buf);
	    memset(conv_header, 0, conv_buf_len);

	    memcpy(conv_header->payload, &content[13], cc_payload_len);

	    conv_header->version = kis_htole16(0);
	    conv_header->reserved = kis_htole16(0);

	    auto datachunk = packetchain->new_packet_component<kis_datachunk>();

	    datachunk->dlt = KDLT_IEEE802_15_4_TAP;

	    packet->original_len = conv_buf_len;
	    packet->set_data(conv_buf, conv_buf_len);
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

