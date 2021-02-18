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

void kis_datasource_ubertooth_one::handle_rx_packet(kis_packet *packet) {
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

    auto u1_chunk = 
        packet->fetch<kis_datachunk>(pack_comp_linkframe);

    // If we can't validate the basics of the packet at the phy capture level, throw it out.
    // We don't get rid of invalid btle contents, but we do get rid of invalid USB frames that
    // we can't decipher - we can't even log them sanely!
    
    if (u1_chunk->length != sizeof(usb_pkt_rx)) {
        delete(packet);
        return;
    }

    auto usb_rx = reinterpret_cast<usb_pkt_rx *>(u1_chunk->data);

    auto payload_len = (usb_rx->data[5] & 0x3F) + 6 + 3;

    if (payload_len > DMA_SIZE) {
        delete(packet);
        return;
    }


    auto conv_buf_len = sizeof(btle_rf) + payload_len;
    btle_rf *conv_header = reinterpret_cast<btle_rf *>(new uint8_t[conv_buf_len]);
    memset(conv_header, 0, conv_buf_len);

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
   
    // Replace the existing packet data with this and update the DLT
    u1_chunk->set_data((uint8_t *) conv_header, conv_buf_len, false);
    u1_chunk->dlt = KDLT_BTLE_RADIO;

    // Generate a l1 radio header and a decap header since we have it computed already
    auto radioheader = new kis_layer1_packinfo();
    radioheader->signal_type = kis_l1_signal_type_dbm;
    radioheader->signal_dbm = conv_header->signal;
    radioheader->freq_khz = (usb_rx->channel + 2402) * 1000;
    radioheader->channel = fmt::format("{}", conv_header->monitor_channel);
    packet->insert(pack_comp_radiodata, radioheader);

    auto decapchunk = new kis_datachunk;
    decapchunk->set_data(conv_header->payload, payload_len, false);
    decapchunk->dlt = KDLT_BLUETOOTH_LE_LL;
    packet->insert(pack_comp_decap, decapchunk);

    kis_datasource::handle_rx_packet(packet);
}

