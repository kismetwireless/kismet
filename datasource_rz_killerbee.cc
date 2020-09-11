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

#include "datasource_rz_killerbee.h"

#define TLVHEADER

void kis_datasource_rzkillerbee::handle_rx_packet(kis_packet *packet) {

    typedef struct {
        uint16_t type; //type identifier
        uint16_t length; // number of octets for type in value field (not including padding
        uint32_t value; // data for type
    } tap_tlv;

    typedef struct {
        uint8_t version; // currently zero
        uint8_t reserved; // must be zero
        uint16_t length; // total length of header and tlvs in octets, min 4 and must be multiple of 4
        tap_tlv tlv[3];//tap tlvs
        uint8_t payload[0];	        
        ////payload + fcs per fcs type
    } zigbee_tap;

    auto rz_chunk = 
        packet->fetch<kis_datachunk>(pack_comp_linkframe);

    if(rz_chunk->data[7])
    {
        int rz_payload_len = rz_chunk->data[8];
#ifdef TLVHEADER
        int rssi = rz_chunk->data[6];
        uint8_t channel = rz_chunk->data[5];
	// We can make a valid payload from this much
        auto conv_buf_len = sizeof(zigbee_tap) + rz_payload_len;
        zigbee_tap *conv_header = reinterpret_cast<zigbee_tap *>(new uint8_t[conv_buf_len]);
        memset(conv_header, 0, conv_buf_len);

        // Copy the actual packet payload into the header
        memcpy(conv_header->payload, &rz_chunk->data[9], rz_payload_len);

        conv_header->version = 0;//currently only one version
        conv_header->reserved = 0;//must be set to 0

        //fcs setting
        conv_header->tlv[0].type = 0;
        conv_header->tlv[0].length = 1;
        conv_header->tlv[0].value = 0;

        //rssi
        conv_header->tlv[1].type = 10;
        conv_header->tlv[1].length = 1;
        conv_header->tlv[1].value = rssi;

        //channel
        conv_header->tlv[2].type = 3;
        conv_header->tlv[2].length = 3;
        conv_header->tlv[2].value = channel;

        //size
        conv_header->length = sizeof(conv_header)+sizeof(conv_header->tlv)-4;//remove 4 bytes for the length in the header

        rz_chunk->set_data((uint8_t *)conv_header, conv_buf_len, false);
        rz_chunk->dlt = KDLT_IEEE802_15_4_TAP; 	
#else	
        //so this works
        uint8_t payload[256]; memset(payload,0x00,256);
        memcpy(payload,&rz_chunk->data[9],rz_payload_len);	
        // Replace the existing packet data with this and update the DLT
        rz_chunk->set_data(payload, rz_payload_len, false);
        rz_chunk->dlt = KDLT_IEEE802_15_4_NOFCS; 
	
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
    }
    else
    {
        delete(packet);
        return;
    }
}
