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

#define TLVHEADER

void kis_datasource_ticc2531::handle_rx_packet(kis_packet *packet) {

    auto cc_chunk = packet->fetch<kis_datachunk>(pack_comp_linkframe);

    // If we can't validate the basics of the packet at the phy capture level, throw it out.
    // We don't get rid of invalid btle contents, but we do get rid of invalid USB frames that
    // we can't decipher - we can't even log them sanely!
    
    if (cc_chunk->length < 8) {
        // fmt::print(stderr, "debug - cc2531 too short ({} < 8)\n", cc_chunk->length);
        delete(packet);
        return;
    }

    unsigned int cc_len = cc_chunk->data[1];
    if (cc_len != cc_chunk->length - 3) {
        // fmt::print(stderr, "debug - cc2531 invalid packet length ({} != {})\n", cc_len, cc_chunk->length - 3);
        delete(packet);
        return;
    }

    unsigned int cc_payload_len = cc_chunk->data[7] - 0x02;
    if ((cc_payload_len + 8 != cc_chunk->length - 2) || (cc_payload_len > 104)) {
        // fmt::print(stderr, "debug - cc2531 invalid payload length ({} != {})\n", cc_payload_len + 8, cc_chunk->length - 2);
        delete(packet);
        return;
    }
//printf("cc_len:%d cc_chunk->data[1]:%d \n",cc_len,cc_chunk->data[1]);
//printf("cc_payload_len:%d \n",cc_payload_len);
//printf("cc_payload_len + 8:%d cc_chunk->length - 2:%d \n",(cc_payload_len + 8),(cc_chunk->length - 2));
/**
printf("datasource----");
for(int xp = 0;xp <= cc_len;xp++)
{
    if(xp == 7)
        printf(" ");
    printf("%02X",cc_chunk->data[xp]);
}
printf("\n");
**/
    uint8_t fcs1 = cc_chunk->data[cc_chunk->length - 2];
    uint8_t fcs2 = cc_chunk->data[cc_chunk->length - 1];
    uint8_t crc_ok = fcs2 & (1 << 7);
    uint8_t crc_ok2 = fcs2 & (1 << 6);
    uint8_t corr = fcs2 & 0x7f;
    uint8_t channel = cc_chunk->data[2];
    //uint8_t channel = 11;
//printf("fcs1:%02X fcs2:%02X\n",fcs1,fcs2);
//printf("crc_ok:%d crc_ok2:%d\n",crc_ok,crc_ok2);
    if (crc_ok > 0) {

        int rssi = (fcs1 + (int) pow(2, 7)) % (int) pow(2, 8) - (int) pow(2, 7) - 73;

        #ifdef TLVHEADER
        // We can make a valid payload from this much
        auto conv_buf_len = sizeof(_802_15_4_tap) + cc_payload_len;// + (sizeof(tap_tlv))-2;// - 2;
        _802_15_4_tap *conv_header = reinterpret_cast<_802_15_4_tap *>(new uint8_t[conv_buf_len]);
        memset(conv_header, 0, conv_buf_len);

        // Copy the actual packet payload into the header
        memcpy(conv_header->payload, &cc_chunk->data[8], cc_payload_len);

        conv_header->version = 0;// currently only one version
        conv_header->reserved = 0;// must be set to 0

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
        conv_header->tlv[2].value = channel;//need to try to pull from some where, but it is not in the packet
        
        // size
        conv_header->length = sizeof(conv_header)+sizeof(conv_header->tlv)-4;
        cc_chunk->set_data((uint8_t *)conv_header, conv_buf_len, false);
        cc_chunk->dlt = KDLT_IEEE802_15_4_TAP; 	
        #else
        uint8_t payload[256];
        memset(payload, 0x00, 256);
        memcpy(payload, &cc_chunk->data[8], cc_payload_len);
        // Replace the existing packet data with this and update the DLT
        cc_chunk->set_data(payload, cc_payload_len, false);
        cc_chunk->dlt = KDLT_IEEE802_15_4_NOFCS;
        #endif
/**/
        auto radioheader = new kis_layer1_packinfo();
        radioheader->signal_type = kis_l1_signal_type_dbm;
        radioheader->signal_dbm = rssi;
        radioheader->freq_khz = (2405 + ((channel - 11) * 5)) * 1000;
        radioheader->channel = fmt::format("{}", (channel));
        packet->insert(pack_comp_radiodata, radioheader);
/**/
        // Pass the packet on
        packetchain->process_packet(packet);

    } else {
        //printf("delete packet\n");
        delete (packet);
        return;
    }
}

