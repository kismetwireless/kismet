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

#include "datasource_nrf_52840.h"

unsigned char hextobytel(char s);

void kis_datasource_nrf52840::handle_rx_packet(kis_packet *packet) {

    auto nrf_chunk = 
        packet->fetch<kis_datachunk>(pack_comp_linkframe);

    uint8_t c_payload[255];
    memset(c_payload, 0x00, 255);

    uint8_t payload[255];
    memset(payload, 0x00, 255);

    char tmp[16];
    memset(tmp, 0x00, 16);

    int16_t rssi = 0;
    int16_t loc[4] = {0, 0, 0, 0};
    uint8_t li = 0;

    /*
    These packets are ascii with labels for each field.
    The below finds where the : are so we can better try to split everything apart.
    */

    //printf("nrf52840 datasource got a packet\n");
    for (unsigned int i = 0; i < nrf_chunk->length; i++) {
        if (nrf_chunk->data[i] == ':') {
            loc[li] = i;
            li++;
            if (li > 4)
                break;
        }
    }

    // copy over the packet
    unsigned int chunk_start = loc[0] + 2;
    unsigned int chunk_str_len = (loc[1] - loc[0] - 1 - (strlen("payload")));
    unsigned int payload_len = chunk_str_len;
    if (chunk_start > nrf_chunk->length || chunk_str_len >= nrf_chunk->length) {
        delete (packet);
        return;
    }
    memcpy(c_payload, &nrf_chunk->data[chunk_start], chunk_str_len);

    // copy over the power/rssi
    chunk_start = loc[1] + 2;
    chunk_str_len = (loc[2] - loc[1] - 2 - (strlen("lqi")));
    if (chunk_start > nrf_chunk->length || chunk_str_len >= nrf_chunk->length) {
        delete (packet);
        return;
    }

    memcpy(tmp, &nrf_chunk->data[chunk_start], chunk_str_len);
    rssi = atoi(tmp);
    memset(tmp, 0x00, 16);

    // convert the string payload to bytes
    unsigned char tmpc[2];
    int c = 0;
    int nrf_payload_len = 0;

    for (int i = 0; i < (int) payload_len; i++) {
        tmpc[0] = hextobytel(c_payload[i]);
        i++;
        tmpc[1] = hextobytel(c_payload[i]);
        payload[c] = ((tmpc[0] << 4) | tmpc[1]);
        c++;
    }

    nrf_payload_len = c;
    uint8_t channel = nrf_chunk->data[2];

    // No good way to do packet validation that I know of at the moment.

    // We can make a valid payload from this much
    auto conv_buf_len = sizeof(_802_15_4_tap) + nrf_payload_len;
    _802_15_4_tap *conv_header = reinterpret_cast<_802_15_4_tap *>(new uint8_t[conv_buf_len]);
    memset(conv_header, 0, conv_buf_len);

    // Copy the actual packet payload into the header
    memcpy(conv_header->payload, payload, nrf_payload_len);

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
    conv_header->length = kis_htole16(sizeof(_802_15_4_tap)); 
    nrf_chunk->set_data((uint8_t *) conv_header, conv_buf_len, false);
    nrf_chunk->dlt = KDLT_IEEE802_15_4_TAP;

    auto radioheader = new kis_layer1_packinfo();
    radioheader->signal_type = kis_l1_signal_type_dbm;
    radioheader->signal_dbm = rssi;
    radioheader->freq_khz = (2405 + ((channel - 11) * 5)) * 1000;
    radioheader->channel = fmt::format("{}", (channel));
    packet->insert(pack_comp_radiodata, radioheader);

	// Pass the packet on
    kis_datasource::handle_rx_packet(packet);    
}

unsigned char hextobytel(char s)
{
    if(s == '0')
        return 0x0;
    else if(s == '1')
        return 0x1;
    else if(s == '2')
        return 0x2;
    else if(s == '3')
        return 0x3;
    else if(s == '4')
        return 0x4;
    else if(s == '5')
        return 0x5;
    else if(s == '6')
        return 0x6;
    else if(s == '7')
        return 0x7;
    else if(s == '8')
        return 0x8;
    else if(s == '9')
        return 0x9;
    else if(s == 'A')
        return 0xA;
    else if(s == 'B')
        return 0xB;
    else if(s == 'C')
        return 0xC;
    else if(s == 'D')
        return 0xD;
    else if(s == 'E')
        return 0xE;
    else if(s == 'F')
        return 0xF;
    else
	return 0x0;
}
