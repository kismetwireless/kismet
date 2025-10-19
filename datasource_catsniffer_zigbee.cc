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

void kis_datasource_catsniffer_zigbee::handle_rx_datalayer(std::shared_ptr<kis_packet> packet, 
        const KismetDatasource::SubPacket& report) {

    fprintf(stderr, "Datasource_catsniffer_zigbee: Entering handle_rx_datalayer...\n");

    if (!report.has_data()) {
        printf("No data in report, exiting...\n");
        return;
    }

    auto& rxdata = report.data();
    printf("Received data of length: %zu\n", rxdata.length());

    // Print the entire rxdata before the cc_len check
    printf("rxdata: ");
    for (size_t i = 0; i < rxdata.length(); ++i) {
        printf("%02X ", static_cast<unsigned char>(rxdata[i]));
    }
    printf("\n");

    // If we can't validate the basics of the packet at the phy capture level, throw it out.
    if (rxdata.length() < 8) {
        printf("Packet too short, marking as error and exiting...\n");
        packet->error = 1;
        return;
    }

    uint8_t cc_len = rxdata[4];
    printf("Extracted cc_len: %u (raw byte: %02X)\n", cc_len, rxdata[4]);
    //Add 8 bytes to the expected frame length; this includes 4 total bytes for SOF/EOF (2 each), 1 byte for message type, 1 byte for channel value, 1 byte for the frame length byte & 1 byte for FCS OK
    if (cc_len + 8 != static_cast<int>(rxdata.length())) {
        printf("cc_len mismatch, exiting...\n");
        return;
    }

    unsigned int cc_payload_len = rxdata[12];
    printf("cc_payload_len: %u\n", cc_payload_len);
    //Payload or packet length indicator is at the 13th byte
    //Add 12 leading bytes, 1 byte for payload length, 1 byte for RSSI, 1 byte for FCS OK, 2 bytes for EOF.
    if ((cc_payload_len + 17 != rxdata.length()) || (cc_payload_len > 104)) {
        printf("Payload length mismatch or too large, exiting...\n");
        return;
    }

    //uint8_t fcs1 = rxdata[rxdata.length() - 2];
    //uint8_t fcs2 = rxdata[rxdata.length() - 1];
    //uint8_t crc_ok = fcs2 & (1 << 7);
    //printf("fcs1: %02X, fcs2: %02X, crc_ok: %u\n", fcs1, fcs2, crc_ok);
    //Check the FCS OK byte
    uint8_t crc_ok = rxdata[rxdata.length() - 3];
    printf("crc_ok: %02X\n", crc_ok);
    
    

    uint8_t channel = rxdata[0];
    printf("Channel: %u\n", channel);

    // check the CRC and make sure that bytes 13 and 14 (FCF) don't match (maybe they could match??)
	if (crc_ok > 0 && (rxdata[13] != rxdata[14])) {
	    printf("CRC OK and mismatch between rxdata[13] (%02X) and rxdata[14] (%02X), proceeding...\n", 
		   rxdata[13], rxdata[14]);

	    int8_t rssi = (int8_t) rxdata[rxdata.length() - 4];
	    printf("RSSI: %d dBm (extracted from rxdata[%zu])\n", rssi, rxdata.length() - 4);

	    auto conv_buf_len = sizeof(_802_15_4_tap) + cc_payload_len;
	    printf("Calculated conv_buf_len: %zu\n", conv_buf_len);

	    char conv_buf[conv_buf_len];
	    _802_15_4_tap *conv_header = reinterpret_cast<_802_15_4_tap *>(conv_buf);
	    memset(conv_header, 0, conv_buf_len);
	    printf("conv_buf initialized to zero.\n");

	    memcpy(conv_header->payload, &rxdata.data()[13], cc_payload_len);
	    printf("Copied %u bytes of payload into conv_buf.\n", cc_payload_len);

		// Print the copied payload data in hex format
		printf("Payload data: ");
		for (size_t i = 0; i < cc_payload_len; ++i) {
		    printf("%02X ", static_cast<unsigned char>(conv_header->payload[i]));
		}
		printf("\n");

	    conv_header->version = kis_htole16(0);
	    conv_header->reserved = kis_htole16(0);
	    printf("Constructed _802_15_4_tap header with length: %zu.\n", sizeof(_802_15_4_tap));

	    auto datachunk = packetchain->new_packet_component<kis_datachunk>();
	    printf("Created new datachunk component.\n");

	    if (clobber_timestamp && get_source_remote()) {
		gettimeofday(&(packet->ts), NULL);
		printf("Timestamp clobbered, set to current time.\n");

		// Print the current time
		char buffer[26];
		struct tm* tm_info;
		tm_info = localtime(&(packet->ts.tv_sec));
		strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
		printf("Current time: %s.%06ld\n", buffer, packet->ts.tv_usec);
	    } else {
		packet->ts.tv_sec = report.time_sec();
		packet->ts.tv_usec = report.time_usec();
		printf("Timestamp set from report: %ld.%06ld\n", packet->ts.tv_sec, packet->ts.tv_usec);
	    }

	    datachunk->dlt = KDLT_IEEE802_15_4_TAP;
	    printf("Set datachunk DLT to KDLT_IEEE802_15_4_TAP.\n");

	    packet->original_len = conv_buf_len;
	    packet->set_data(conv_buf, conv_buf_len);
	    datachunk->set_data(packet->data);
	    printf("Packet data set with length: %zu.\n", conv_buf_len);

	    get_source_packet_size_rrd()->add_sample(conv_buf_len, time(0));
	    printf("Added sample to source packet size RRD.\n");

	    packet->insert(pack_comp_linkframe, datachunk);
	    printf("Inserted datachunk into packet as pack_comp_linkframe.\n");

	    // Print datachunk details (assuming it's a simple object, otherwise you need to format it properly)
	    printf("datachunk: %p\n", datachunk.get());

	    auto radioheader = packetchain->new_packet_component<kis_layer1_packinfo>();
	    radioheader->signal_type = kis_l1_signal_type_dbm;
	    radioheader->signal_dbm = rssi;
	    radioheader->freq_khz = (2405 + ((channel - 11) * 5)) * 1000;
	    radioheader->channel = fmt::format("{}", (channel));
	    packet->insert(pack_comp_radiodata, radioheader);
	    printf("Inserted radioheader into packet as pack_comp_radiodata.\n");

	    // Print all radioheader values
		printf("radioheader: signal_type=%d, signal_dbm=%d, freq_khz=%.2f, channel=%s\n", 
		       radioheader->signal_type, radioheader->signal_dbm, 
		       radioheader->freq_khz, radioheader->channel.c_str());

	    printf("Inserted packet components, exiting handle_rx_datalayer...\n");

	} else {
	    printf("CRC check failed or length mismatch, marking packet as error...\n");
	    packet->error = 1;
	    return;
	}
}

