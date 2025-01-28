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

#include "datasource_ubertooth_one.h"

int kis_datasource_ubertooth_one::handle_rx_data_content(kis_packet *packet, kis_datachunk *datachunk,
            const uint8_t *content, size_t content_sz) {
    typedef struct {
        uint8_t monitor_channel;
        int8_t signal;
        int8_t noise;
        uint8_t access_offenses;
        uint8_t reference_access_address[4];
        uint16_t flags_le;
        uint8_t payload[0];
    } __attribute__((packed)) btle_rf;

    // Ubertooth usb rx struct
#define DMA_SIZE 50
    typedef struct {
        uint8_t  pkt_type;
        uint8_t  status;
        uint8_t  channel;
        uint8_t  clkn_high;
        uint32_t clk100ns;
        int8_t   rssi_max;   // Max RSSI seen while collecting symbols in this packet
        int8_t   rssi_min;   // Min ...
        int8_t   rssi_avg;   // Average ...
        uint8_t  rssi_count; // Number of ... (0 means RSSI stats are invalid)
        uint8_t  reserved[2];
        uint8_t  data[DMA_SIZE];
    } usb_pkt_rx;

    // Subset of flags we set
    const uint16_t btle_rf_flag_dewhitened = (1 << 0);
    const uint16_t btle_rf_flag_signalvalid = (1 << 1);
    const uint16_t btle_rf_flag_reference_access_valid = (1 << 5);
    /*
    const uint16_t btle_rf_crc_checked = (1 << 10);
    const uint16_t btle_rf_crc_valid = (1 << 11);
    */

    if (content_sz != sizeof(usb_pkt_rx)) {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }

    const auto usb_rx = reinterpret_cast<const usb_pkt_rx *>(content);

    auto payload_len = (usb_rx->data[5] & 0x3F) + 6 + 3;

    if (payload_len > DMA_SIZE) {
        packet->error = 1;
        // error, but preserve the packet for logging
        packet->set_data((const char *) content, content_sz);
        datachunk->set_data(packet->data);
        return 1;
    }


    auto conv_buf_len = sizeof(btle_rf) + payload_len;
    char conv_buf[conv_buf_len];

    btle_rf *conv_header = reinterpret_cast<btle_rf *>(conv_buf);

    // Copy the actual packet payload into the header
    memcpy(conv_header->payload, usb_rx->data, payload_len);

    // Set the converted channel
    int bt_channel = int(usb_rx->channel) + 2402; 

	if (bt_channel == 2402) {
		bt_channel = 37;
	} else if (bt_channel < 2426) {
		bt_channel = (bt_channel - 2404) / 2;
	} else if (bt_channel == 2426) {
		bt_channel = 38;
	} else if (bt_channel < 2480) {
		bt_channel = 11 + (bt_channel - 2428) / 2;
	} else {
		bt_channel = 39;
	}

    conv_header->monitor_channel = bt_channel;
    conv_header->signal = usb_rx->rssi_min - 54;

    uint16_t bits = 0;

    if (payload_len >= 4) {
        memcpy(conv_header->reference_access_address, conv_header->payload, 4);
        bits += btle_rf_flag_reference_access_valid;
    }

    conv_header->flags_le =
        kis_htole16(bits + btle_rf_flag_signalvalid + btle_rf_flag_dewhitened);

    // We always override the ubertooth DLT since we don't get it from the ds
    datachunk->dlt = get_source_override_linktype();

    packet->set_data((const char *) conv_buf, conv_buf_len);
    datachunk->set_data(packet->data);

    // Generate a l1 radio header and a decap header since we have it computed already
    auto radioheader = packetchain->new_packet_component<kis_layer1_packinfo>();
    radioheader->signal_type = kis_l1_signal_type_dbm;
    radioheader->signal_dbm = conv_header->signal;
    radioheader->freq_khz = (usb_rx->channel + 2402) * 1000;
    radioheader->channel = fmt::format("{}", conv_header->monitor_channel);
    packet->insert(pack_comp_radiodata, radioheader);


    auto decapchunk = packetchain->new_packet_component<kis_datachunk>();
    decapchunk->dlt = KDLT_BLUETOOTH_LE_LL;
    decapchunk->set_data(packet->data.substr(sizeof(btle_rf), payload_len));
    packet->insert(pack_comp_decap, decapchunk);

    return 1;
}

