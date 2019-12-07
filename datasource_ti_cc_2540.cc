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

#include "datasource_ti_cc_2540.h"

void kis_datasource_ticc2540::handle_rx_packet(kis_packet *packet) {
    typedef struct {
        uint8_t monitor_channel;
        int8_t signal;
        int8_t noise;
        uint8_t access_offenses;
        uint32_t reference_access_address_le;
        uint16_t flags_le;
        uint8_t payload[0];
    } __attribute__((packed)) btle_rf;

    // Subset of flags we set
    const uint16_t btle_rf_flag_dewhitened = (1 << 0);
    const uint16_t btle_rf_flag_signalvalid = (1 << 1);
    const uint16_t btle_rf_flag_reference_access_valid = (1 << 5);
    const uint16_t btle_rf_crc_checked = (1 << 10);
    const uint16_t btle_rf_crc_valid = (1 << 11);

    auto cc_chunk = 
        packet->fetch<kis_datachunk>(pack_comp_linkframe);

    // If we can't validate the basics of the packet at the phy capture level, throw it out.
    // We don't get rid of invalid btle contents, but we do get rid of invalid USB frames that
    // we can't decipher - we can't even log them sanely!
    
    if (cc_chunk->length < 8) {
        fmt::print(stderr, "debug - cc2540 too short ({} < 8)\n", cc_chunk->length);
        delete(packet);
        return;
    }

    unsigned int cc_len = cc_chunk->data[1];
    if (cc_len != cc_chunk->length - 3) {
        fmt::print(stderr, "debug - cc2540 invalid packet length ({} != {})\n", cc_len, cc_chunk->length - 3);
        delete(packet);
        return;
    }

    unsigned int cc_payload_len = cc_chunk->data[7] - 0x02;
    if (cc_payload_len + 8 != cc_chunk->length - 2) {
        fmt::print(stderr, "debug - cc2540 invalid payload length ({} != {})\n", cc_payload_len + 8, cc_chunk->length - 2);
        delete(packet);
        return;
    }

    uint8_t fcs1 = cc_chunk->data[cc_chunk->length - 2];
    uint8_t fcs2 = cc_chunk->data[cc_chunk->length - 1];

    // Convert the channel for the btlell header
    auto bt_channel = fcs2 & 0x7F;
    switch (bt_channel) {
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
            bt_channel = bt_channel - 2;
    };

    // We can make a valid payload from this much
    auto conv_buf_len = sizeof(btle_rf) + cc_payload_len;
    btle_rf *conv_header = reinterpret_cast<btle_rf *>(new uint8_t[conv_buf_len]);
    memset(conv_header, 0, conv_buf_len);

    // Copy the actual packet payload into the header
    memcpy(conv_header->payload, &cc_chunk->data[8], cc_payload_len);

    // Set the converted channel
    conv_header->monitor_channel = bt_channel;

    // RSSI is a signed value at fcs1; convert it from the CC value to signed dbm
    conv_header->signal = (fcs1 + (int) pow(2, 7)) % (int) pow(2, 8) - (int) pow(2, 7) - 73;

    uint16_t crcbits = btle_rf_crc_checked;
    if (fcs2 & (1 << 7))
        crcbits += btle_rf_crc_valid;

    conv_header->flags_le = 
        htole16(crcbits + btle_rf_flag_signalvalid + btle_rf_flag_dewhitened);
   
    // Replace the existing packet data with this and update the DLT
    cc_chunk->set_data((uint8_t *) conv_header, conv_buf_len, false);
    cc_chunk->dlt = KDLT_BTLE_RADIO;

    // Pass the packet on
    packetchain->process_packet(packet);
}

